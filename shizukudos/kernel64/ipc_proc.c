/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 Windows process model: process exit ordering (NtTerminateProcess(NULL)), process creation with handle
 * inheritance and job membership (NtShzCreateUserProcess), opening processes and threads by id, cross-process memory
 * access, remote and suspended threads, suspend/resume/terminate of other threads, cross-process handle duplication,
 * process/thread information, and job objects.
 *
 * Security: this single-user system has no access tokens; a handle carries the access mask it was opened with, and the
 * operations here check that mask (PROCESS_VM_READ for NtReadVirtualMemory, PROCESS_DUP_HANDLE for duplication, ...),
 * so code that opens a handle with too few rights fails as it would on Windows.
 */
#include "ipc.h"
#include "auth_policy.h"
#include "../kcommon/nt_process_priority.h"

#define PROCESS_CREATE_THREAD 0x0002u
#define PROCESS_CREATE_PROCESS 0x0080u
#define THREAD_TERMINATE 0x0001u
#define MAXIMUM_ALLOWED_ACCESS 0x02000000u
#define JOB_OBJECT_ASSIGN_PROCESS 0x0001u
#define JOB_OBJECT_SET_ATTRIBUTES 0x0002u
#define JOB_OBJECT_QUERY 0x0004u
#define JOB_OBJECT_TERMINATE 0x0008u
#define DUPLICATE_CLOSE_SOURCE 1u
#define DUPLICATE_SAME_ACCESS 2u
#define DUPLICATE_SAME_ATTRIBUTES 4u
#define STATUS_SUSPEND_COUNT_EXCEEDED ((int32_t)0xC000004A)
#define STATUS_QUOTA_EXCEEDED ((int32_t)0xC0000044)
#define STATUS_NAME_TOO_LONG_LOCAL ((int32_t)0xC0000106)
#define MAX_SUSPEND 127

extern int32_t sys_extended(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);

/* ---------------------------------------------------------------- NtTerminateProcess(NULL, status) */
/* First half of RtlExitUserProcess (ExitProcess): every thread of the calling process except the caller ends, and the call
 * returns only once they are all gone, so DLL_PROCESS_DETACH then runs with no other thread alive, as on Windows. The
 * caller becomes the process's exit owner: from now on no new thread starts in the process, and a second thread that also
 * tries to exit the process is simply one of the victims. Threads blocked in interruptible waits (object waits, delays,
 * alert-by-thread-id, I/O and port waits, suspensions) are woken to die; threads spinning in user mode die at the next
 * timer tick; threads inside a kernel-internal wait (a kernel mutex or semaphore) die when that wait ends and they leave
 * the kernel. */
int32_t process_terminate_others(process_t *p, int32_t code)
{
    thread_t *me = thread_current();
    uint64_t f = irq_save();
    if (p->exit_owner && p->exit_owner != me) {         /* another thread is already exiting the process: we are a victim */
        irq_restore(f);
        return STATUS_THREAD_IS_TERMINATING;            /* check_kill() ends this thread on the way out */
    }
    p->exit_owner = me;
    p->exit_code = code;                                /* the victims' exit code (reported once the process ends) */
    irq_restore(f);
    /* until every victim has completed thread_exit() - not merely left the thread count - so its thread object is
     * signaled before DLL_PROCESS_DETACH can look at it */
    while ((p->threads_alive > 1 || ipc_live_threads(p, me)) && !p->terminated) {
        ipc_process_terminating(p);                     /* repeated: a victim may block again before it notices */
        thread_sleep_ms(1);
    }
    return STATUS_SUCCESS;
}

/* NtTerminateProcess(handle, status): the caller's own process (NtCurrentProcess() or a handle to it) ends at once, with
 * the caller; another process is terminated asynchronously (its threads die as described above; wait on its handle for
 * the end). A process that has already ended reports STATUS_PROCESS_IS_TERMINATING (Win32: ERROR_ACCESS_DENIED). */
int32_t process_terminate_handle(process_t *p, uint64_t h, int32_t code)
{
    process_t *t;
    kobject_t *o;
    int32_t st = ipc_ref_process(p, h, PROCESS_TERMINATE, &t, &o);
    if (st) return st;
    if (t != p && (t->terminated || t->teardown)) { ob_deref(o); return STATUS_PROCESS_IS_TERMINATING; }
    process_terminate(t, (int64_t)code, 0);
    ob_deref(o);
    if (t == p) {
        thread_current()->exit_code = code;
        process_thread_gone(p);
        thread_exit(code);
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- handle-table helpers */
static uint32_t handle_flags_of(process_t *p, uint64_t h)
{
    if (!h || (h & 3) || h > (uint64_t)p->handle_cap * 4ull) return 0;
    return p->handles[h / 4 - 1].inherit;
}

/* Inserts `o` at a given handle value (inheritance keeps handle values). The caller keeps its own reference. */
static int32_t handle_insert_at(process_t *p, uint64_t value, kobject_t *o, uint32_t access, uint32_t flags)
{
    uint64_t f;
    handle_entry_t *e;
    if (!value || (value & 3) || value > (uint64_t)p->handle_cap * 4ull) return STATUS_INVALID_HANDLE;
    f = irq_save();
    e = &p->handles[value / 4 - 1];
    if (e->obj) { irq_restore(f); return STATUS_OBJECT_NAME_COLLISION; }
    e->obj = o;
    e->access = access;
    e->inherit = flags;
    ++o->refs;
    ++p->handle_count;
    ipc_handle_opened(o);                               /* inherited table entry and ioctx count have one publication */
    irq_restore(f);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- jobs */
#define JOB_MAX_MEMBERS 16
#define JOB_OBJECT_LIMIT_ACTIVE_PROCESS 0x8u
#define JOB_OBJECT_LIMIT_BREAKAWAY_OK 0x800u
#define JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK 0x1000u
#define JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE 0x2000u
#define JOB_MSG_ACTIVE_PROCESS_LIMIT 3u
#define JOB_MSG_ACTIVE_PROCESS_ZERO 4u
#define JOB_MSG_NEW_PROCESS 6u
#define JOB_MSG_EXIT_PROCESS 7u
#define JOB_MSG_ABNORMAL_EXIT_PROCESS 8u

struct job {
    uint32_t handles;                   /* first member: handle count (ipc_core.c) */
    kobject_t *obj;                     /* back pointer, no reference */
    uint32_t limit_flags, active_limit, ui_restrictions, priority_class, scheduling_class;
    uint64_t process_memory_limit, job_memory_limit, affinity;
    int64_t per_process_user_time, per_job_user_time;
    uint64_t min_ws, max_ws;
    kobject_t *port;                    /* JobObjectAssociateCompletionPortInformation (referenced) */
    uint64_t port_key;
    uint32_t total, terminated_count;
    process_t *members[JOB_MAX_MEMBERS];
    int closed;                         /* last handle gone */
};

static unsigned job_active(job_t *j)
{
    unsigned i, n = 0;
    for (i = 0; i < JOB_MAX_MEMBERS; ++i) if (j->members[i]) ++n;
    return n;
}

static void job_post(job_t *j, uint32_t msg, uint64_t pid)
{
    if (j->port) iocp_post(j->port, j->port_key, pid, STATUS_SUCCESS, msg);
}

/* Puts process `p` in job `jo` (referenced by the caller). One job per process (the pre-nesting model). */
static int32_t job_assign(kobject_t *jo, process_t *p)
{
    job_t *j = jo->u.file.file;
    ipc_proc_t *ip = ipc_proc(p, 1);
    uint64_t f;
    unsigned i;
    if (!ip) return STATUS_INSUFFICIENT_RESOURCES;
    if (p->terminated || p->teardown) return STATUS_PROCESS_IS_TERMINATING;
    f = irq_save();
    if (ip->job) { irq_restore(f); return ip->job == j ? STATUS_SUCCESS : STATUS_ACCESS_DENIED; }
    if ((j->limit_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS) && job_active(j) >= j->active_limit) {
        irq_restore(f);
        job_post(j, JOB_MSG_ACTIVE_PROCESS_LIMIT, 0);
        return STATUS_QUOTA_EXCEEDED;
    }
    for (i = 0; i < JOB_MAX_MEMBERS && j->members[i]; ++i) { }
    if (i == JOB_MAX_MEMBERS) { irq_restore(f); return STATUS_INSUFFICIENT_RESOURCES; }
    j->members[i] = p;
    ip->job = j;
    ++j->total;
    ob_ref(jo);                                         /* the member keeps the job alive */
    irq_restore(f);
    job_post(j, JOB_MSG_NEW_PROCESS, (uint64_t)p->pid);
    if (j->closed && (j->limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)) process_terminate(p, 0, 0);
    return STATUS_SUCCESS;
}

/* Process teardown (ipc_core.c): the process leaves its job, with the exit notifications. */
void job_process_exited(process_t *p)
{
    ipc_proc_t *ip = p->ipc;
    job_t *j;
    uint64_t f;
    unsigned i, left;
    if (!ip || !ip->job) return;
    f = irq_save();
    j = ip->job;
    ip->job = 0;
    for (i = 0; i < JOB_MAX_MEMBERS; ++i) if (j->members[i] == p) j->members[i] = 0;
    ++j->terminated_count;
    left = job_active(j);
    irq_restore(f);
    job_post(j, ((uint32_t)p->exit_code >= 0xC0000000u) ? JOB_MSG_ABNORMAL_EXIT_PROCESS : JOB_MSG_EXIT_PROCESS,
             (uint64_t)p->pid);
    if (!left) job_post(j, JOB_MSG_ACTIVE_PROCESS_ZERO, 0);
    ob_deref(j->obj);
}

static void job_kill_all(job_t *j, int64_t code)
{
    unsigned i;
    for (i = 0; i < JOB_MAX_MEMBERS; ++i) {
        process_t *m;
        const uint64_t f = irq_save();
        m = j->members[i];
        irq_restore(f);
        if (m && !m->terminated) process_terminate(m, code, 0);
    }
}

void job_handle_closed(kobject_t *o)
{
    job_t *j = o->u.file.file;
    if (!j) return;
    j->closed = 1;
    if (j->limit_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) job_kill_all(j, 0);
}

void job_free(kobject_t *o)
{
    job_t *j = o->u.file.file;
    if (!j) return;
    o->u.file.file = 0;
    if (j->port) ob_deref(j->port);
    kfree(j);
    --ipc_stat_jobs;
}

/* Parent -> child job inheritance at creation (a breakaway needs JOB_OBJECT_LIMIT_BREAKAWAY_OK). */
int32_t job_inherit(process_t *parent, process_t *child)
{
    ipc_proc_t *ip = parent->ipc;
    job_t *j = ip ? ip->job : 0;
    if (!j) return STATUS_SUCCESS;
    if (j->limit_flags & JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) return STATUS_SUCCESS;
    return job_assign(j->obj, child);
}

static int32_t named_open_or_collide(process_t *p, uint32_t type, const char *name, uint32_t oattrs, uint64_t access,
                                     uint64_t ph, int *done)
{
    const uint64_t f = irq_save();
    kobject_t *ex = ob_find_named(type, name);
    int32_t st;
    if (ex) ob_ref(ex);
    irq_restore(f);
    *done = ex != 0;
    if (!ex) return 0;
    if (ex->type != type) { ob_deref(ex); return STATUS_OBJECT_TYPE_MISMATCH; }
    if (!(oattrs & 0x80u)) { ob_deref(ex); return STATUS_OBJECT_NAME_COLLISION; }       /* OBJ_OPENIF */
    st = ipc_give_handle(p, ex, (uint32_t)access, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
    return st ? st : STATUS_OBJECT_NAME_EXISTS;
}

static int32_t sys_create_job(process_t *p, uint64_t ph, uint64_t access, uint64_t oa)
{
    char name[48];
    uint32_t oattrs = 0;
    kobject_t *o;
    job_t *j;
    int done = 0;
    int32_t st = ipc_name_from_oa(p, oa, name, sizeof name, &oattrs);
    if (st) return st;
    if (name[0]) {
        st = named_open_or_collide(p, OB_JOB, name, oattrs, access, ph, &done);
        if (done) return st;
    }
    j = kzalloc(sizeof *j);
    o = j ? ob_create(OB_JOB, name) : 0;
    if (!o) { kfree(j); return STATUS_INSUFFICIENT_RESOURCES; }
    j->obj = o;
    o->u.file.file = j;
    ++ipc_stat_jobs;
    return ipc_give_handle(p, o, (uint32_t)access, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

static int32_t get_job(process_t *p, uint64_t h, uint32_t need, kobject_t **o)
{
    uint32_t access = 0;
    int32_t st = ipc_ref_handle(p, h, OB_JOB, o, &access);
    if (st) return st;
    if ((access & need) != need) { ob_deref(*o); return STATUS_ACCESS_DENIED; }
    return STATUS_SUCCESS;
}

static int32_t sys_assign_job(process_t *p, uint64_t hjob, uint64_t hproc)
{
    kobject_t *jo, *po;
    process_t *t;
    int32_t st = get_job(p, hjob, JOB_OBJECT_ASSIGN_PROCESS, &jo);
    if (st) return st;
    st = ipc_ref_process(p, hproc, PROCESS_TERMINATE, &t, &po);
    if (st) { ob_deref(jo); return st; }
    st = job_assign(jo, t);
    ob_deref(po);
    ob_deref(jo);
    return st;
}

/* JOBOBJECT_BASIC_LIMIT_INFORMATION (x64, 64 bytes) */
struct basic_limit {
    int64_t per_process_user_time, per_job_user_time;
    uint32_t limit_flags, pad0;
    uint64_t min_ws, max_ws;
    uint32_t active_limit, pad1;
    uint64_t affinity;
    uint32_t priority_class, scheduling_class;
};

static void fill_basic_limit(job_t *j, struct basic_limit *b)
{
    memset(b, 0, sizeof *b);
    b->per_process_user_time = j->per_process_user_time;
    b->per_job_user_time = j->per_job_user_time;
    b->limit_flags = j->limit_flags;
    b->min_ws = j->min_ws; b->max_ws = j->max_ws;
    b->active_limit = j->active_limit;
    b->affinity = j->affinity;
    b->priority_class = j->priority_class;
    b->scheduling_class = j->scheduling_class;
}

static void take_basic_limit(job_t *j, const struct basic_limit *b)
{
    j->limit_flags = b->limit_flags;
    j->per_process_user_time = b->per_process_user_time;
    j->per_job_user_time = b->per_job_user_time;
    j->min_ws = b->min_ws; j->max_ws = b->max_ws;
    j->active_limit = b->active_limit;
    j->affinity = b->affinity;
    j->priority_class = b->priority_class;
    j->scheduling_class = b->scheduling_class;
}

#define JOB_BASIC_LIMITS 0x3fffu                          /* JOB_OBJECT_LIMIT_* valid with the basic class */
#define JOB_EXTENDED_LIMITS 0x7fffu                       /* ... and with the extended class */
static int32_t sys_set_job(process_t *p, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    kobject_t *o;
    job_t *j;
    int32_t st = get_job(p, h, JOB_OBJECT_SET_ATTRIBUTES, &o);
    if (st) return st;
    j = o->u.file.file;
    switch (cls) {
    case 2: {                                            /* JobObjectBasicLimitInformation */
        struct basic_limit b;
        if (len != sizeof b) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
        if (copy_from_user(p, &b, buf, sizeof b)) { st = STATUS_ACCESS_VIOLATION; break; }
        if (b.limit_flags & ~JOB_BASIC_LIMITS) { st = STATUS_INVALID_PARAMETER; break; }
        take_basic_limit(j, &b);
        break;
    }
    case 9: {                                            /* JobObjectExtendedLimitInformation (144 bytes) */
        uint8_t e[144];
        struct basic_limit b;
        if (len != sizeof e) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
        if (copy_from_user(p, e, buf, sizeof e)) { st = STATUS_ACCESS_VIOLATION; break; }
        memcpy(&b, e, sizeof b);
        if (b.limit_flags & ~JOB_EXTENDED_LIMITS) { st = STATUS_INVALID_PARAMETER; break; }
        take_basic_limit(j, &b);
        memcpy(&j->process_memory_limit, e + 112, 8);
        memcpy(&j->job_memory_limit, e + 120, 8);
        break;
    }
    case 4: {                                            /* JobObjectBasicUIRestrictions */
        uint32_t v;
        if (len != 4) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
        if (copy_from_user(p, &v, buf, 4)) { st = STATUS_ACCESS_VIOLATION; break; }
        if (v & ~0xffu) { st = STATUS_INVALID_PARAMETER; break; }
        j->ui_restrictions = v;
        break;
    }
    case 7: {                                            /* JobObjectAssociateCompletionPortInformation {key, port} */
        uint64_t v[2];
        kobject_t *port;
        if (len != 16) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
        if (copy_from_user(p, v, buf, 16)) { st = STATUS_ACCESS_VIOLATION; break; }
        if (j->port) { st = STATUS_INVALID_PARAMETER; break; }       /* one association for the life of the job */
        st = ipc_ref_handle(p, v[1], OB_IOCP, &port, 0);
        if (st) break;
        j->port = port;
        j->port_key = v[0];
        break;
    }
    default: st = STATUS_INVALID_INFO_CLASS; break;
    }
    ob_deref(o);
    return st;
}

static int32_t sys_query_job(process_t *p, struct regs *r, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    const uint64_t pret = (uint64_t)stack_arg(p, r, 5);
    kobject_t *o;
    job_t *j;
    uint8_t out[160];
    uint32_t n = 0;
    int32_t st;
    process_t *members[JOB_MAX_MEMBERS];
    unsigned i, active = 0;
    if (h == 0) {                                        /* NULL: the job of the calling process */
        const uint64_t f = irq_save();
        ipc_proc_t *ip = p->ipc;
        o = ip && ip->job ? ip->job->obj : 0;
        if (o) ob_ref(o);
        irq_restore(f);
        if (!o) return STATUS_ACCESS_DENIED;
    } else {
        st = get_job(p, h, JOB_OBJECT_QUERY, &o);
        if (st) return st;
    }
    j = o->u.file.file;
    {
        const uint64_t f = irq_save();
        for (i = 0; i < JOB_MAX_MEMBERS; ++i) { members[i] = j->members[i]; if (members[i]) ++active; }
        irq_restore(f);
    }
    memset(out, 0, sizeof out);
    st = STATUS_SUCCESS;
    switch (cls) {
    case 1: {                                            /* JobObjectBasicAccountingInformation */
        uint32_t *u = (uint32_t *)(out + 32);
        u[1] = j->total; u[2] = active; u[3] = j->terminated_count;
        n = 48;
        break;
    }
    case 2: { struct basic_limit b; fill_basic_limit(j, &b); memcpy(out, &b, sizeof b); n = sizeof b; break; }
    case 9: {
        struct basic_limit b;
        fill_basic_limit(j, &b);
        memcpy(out, &b, sizeof b);
        memcpy(out + 112, &j->process_memory_limit, 8);
        memcpy(out + 120, &j->job_memory_limit, 8);
        n = 144;
        break;
    }
    case 4: memcpy(out, &j->ui_restrictions, 4); n = 4; break;
    case 3: {                                            /* JobObjectBasicProcessIdList */
        const uint32_t cap = len >= 8 ? (uint32_t)((len - 8) / 8) : 0;
        uint32_t listed = 0;
        if (len < 8) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
        ((uint32_t *)out)[0] = active;
        for (i = 0; i < JOB_MAX_MEMBERS; ++i)
            if (members[i] && listed < cap) { const uint64_t id = (uint64_t)members[i]->pid; memcpy(out + 8 + 8 * listed++, &id, 8); }
        ((uint32_t *)out)[1] = listed;
        n = 8 + 8 * listed;
        if (listed < active) st = STATUS_BUFFER_OVERFLOW;
        break;
    }
    default: st = STATUS_INVALID_INFO_CLASS; break;
    }
    ob_deref(o);
    if (st && st != STATUS_BUFFER_OVERFLOW) return st;
    if (len < n) return STATUS_INFO_LENGTH_MISMATCH;
    if (copy_to_user(p, buf, out, n)) return STATUS_ACCESS_VIOLATION;
    if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_terminate_job(process_t *p, uint64_t h, uint64_t code)
{
    kobject_t *o;
    int32_t st = get_job(p, h, JOB_OBJECT_TERMINATE, &o);
    if (st) return st;
    job_kill_all(o->u.file.file, (int64_t)(int32_t)code);
    ob_deref(o);
    return STATUS_SUCCESS;
}

/* NtIsProcessInJob(Process, Job): STATUS_PROCESS_IN_JOB / STATUS_PROCESS_NOT_IN_JOB; Job NULL = any job. */
static int32_t sys_is_in_job(process_t *p, uint64_t hproc, uint64_t hjob)
{
    process_t *t;
    kobject_t *po, *jo = 0;
    ipc_proc_t *ip;
    int32_t st = ipc_ref_process(p, hproc, 0, &t, &po);
    if (st) return st;
    if (hjob) {
        st = get_job(p, hjob, JOB_OBJECT_QUERY, &jo);
        if (st) { ob_deref(po); return st; }
    }
    ip = t->ipc;
    st = (ip && ip->job && (!jo || ip->job == jo->u.file.file)) ? STATUS_PROCESS_IN_JOB : STATUS_PROCESS_NOT_IN_JOB;
    if (jo) ob_deref(jo);
    ob_deref(po);
    return st;
}

/* ---------------------------------------------------------------- process creation */
typedef struct {                        /* SHZ_CREATE_PROCESS (win64/include/nt_ipc.h), x64 layout */
    uint32_t version, flags;
    uint64_t image; uint32_t image_chars, pad0;
    uint64_t cmdline; uint32_t cmdline_chars, pad1;
    uint64_t cwd; uint32_t cwd_chars, pad2;
    uint64_t env; uint32_t env_chars;
    uint32_t handle_count, job_count, pad3;
    uint64_t std[3];
    uint64_t handle_list, job_list, parent;
    uint32_t process_access, thread_access;
    uint64_t out_process, out_thread;
    uint32_t out_pid, out_tid;
} cup_t;

#define CUP_SUSPENDED 0x1u
#define CUP_INHERIT 0x2u
#define CUP_STD 0x4u
#define CUP_BREAKAWAY 0x8u
#define CUP_HANDLE_LIST 0x10u
#define CUP_MAX_LIST 64

typedef struct {
    process_t *from;                    /* inheritance source (the caller, or PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) */
    uint32_t flags;
    uint64_t list[CUP_MAX_LIST];
    uint32_t list_count;
    kobject_t *jobs[8];
    uint32_t job_count;
} cup_ctx_t;

/* Runs inside the loader before the child's own console handles exist: inherited handles keep their values. */
static int32_t cup_prepare(process_t *child, void *vctx)
{
    cup_ctx_t *c = vctx;
    ipc_proc_t *fip = c->from->ipc;
    int32_t st;
    uint32_t i;
    if (c->flags & CUP_INHERIT) {
        for (i = 0; i < c->from->handle_cap; ++i) {
            kobject_t *o;
            uint32_t access, flags;
            const uint64_t value = (i + 1) * 4ull;
            const uint64_t f = irq_save();
            o = c->from->handles[i].obj;
            access = c->from->handles[i].access;
            flags = c->from->handles[i].inherit;
            if (o) ob_ref(o);
            irq_restore(f);
            if (!o) continue;
            if (flags & HANDLE_FLAG_INHERIT_BIT) {
                int listed = !(c->flags & CUP_HANDLE_LIST);
                uint32_t k;
                for (k = 0; k < c->list_count && !listed; ++k) listed = c->list[k] == value;
                if (listed) {
                    st = handle_insert_at(child, value, o, access, HANDLE_FLAG_INHERIT_BIT);
                    if (st) { ob_deref(o); return st; }
                }
            }
            ob_deref(o);
        }
    }
    if (!(c->flags & CUP_BREAKAWAY)) {
        st = job_inherit(c->from, child);
        if (st) return st;
    } else if (fip && fip->job &&
               !(fip->job->limit_flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK))) {
        return STATUS_ACCESS_DENIED;                     /* CREATE_BREAKAWAY_FROM_JOB is not allowed by the job */
    }
    for (i = 0; i < c->job_count; ++i) {
        st = job_assign(c->jobs[i], child);
        if (st) return st;
    }
    return STATUS_SUCCESS;
}

static int32_t copy_wstr_in(process_t *p, uint64_t va, uint32_t chars, uint32_t max, uint16_t **out)
{
    *out = 0;
    if (!va) return STATUS_SUCCESS;
    if (chars > max) return STATUS_NAME_TOO_LONG_LOCAL;
    *out = kmalloc(chars * 2ull + 2);
    if (!*out) return STATUS_INSUFFICIENT_RESOURCES;
    if (chars && copy_from_user(p, *out, va, chars * 2ull)) { kfree(*out); *out = 0; return STATUS_ACCESS_VIOLATION; }
    (*out)[chars] = 0;
    return STATUS_SUCCESS;
}

/* NtShzCreateUserProcess(SHZ_CREATE_PROCESS *): CreateProcessW's kernel half. */
static int32_t sys_create_user_process(process_t *p, uint64_t arg)
{
    cup_t c;
    cup_ctx_t ctx;
    ldr_create_ex_t ex;
    uint16_t *image = 0, *cmd = 0, *cwd = 0, *env = 0;
    char path[300];
    kobject_t *parent_obj = 0;
    process_t *np = 0;
    thread_t *nt = 0;
    uint32_t hp = 0, ht = 0, i;
    int32_t st;
    if (copy_from_user(p, &c, arg, sizeof c)) return STATUS_ACCESS_VIOLATION;
    if (c.version != 1) return STATUS_INVALID_PARAMETER;
    if (c.handle_count > CUP_MAX_LIST || c.job_count > 8) return STATUS_INVALID_PARAMETER;
    if (p->exit_owner) return STATUS_PROCESS_IS_TERMINATING;
    memset(&ctx, 0, sizeof ctx);
    memset(&ex, 0, sizeof ex);
    ctx.flags = c.flags;
    ctx.from = p;
    if (c.parent) {
        st = ipc_ref_process(p, c.parent, PROCESS_CREATE_PROCESS, &ctx.from, &parent_obj);
        if (st) return st;
        if (ctx.from->teardown || ctx.from->terminated) { ob_deref(parent_obj); return STATUS_PROCESS_IS_TERMINATING; }
    }
    st = copy_wstr_in(p, c.image, c.image_chars, 259, &image);
    if (!st) st = copy_wstr_in(p, c.cmdline, c.cmdline_chars, 8191, &cmd);
    if (!st) st = copy_wstr_in(p, c.cwd, c.cwd_chars, 259, &cwd);
    if (!st) st = copy_wstr_in(p, c.env, c.env_chars, 32767, &env);
    if (!st && !image) st = STATUS_INVALID_PARAMETER;
    if (!st && (c.flags & CUP_HANDLE_LIST)) {
        ctx.list_count = c.handle_count;
        if (copy_from_user(p, ctx.list, c.handle_list, c.handle_count * 8ull)) st = STATUS_ACCESS_VIOLATION;
        for (i = 0; !st && i < ctx.list_count; ++i)      /* every listed handle must exist and be inheritable */
            if (!(handle_flags_of(ctx.from, ctx.list[i]) & HANDLE_FLAG_INHERIT_BIT) ||
                !ctx.from->handles[ctx.list[i] / 4 - 1].obj)
                st = STATUS_INVALID_PARAMETER;
    }
    if (!st && c.job_count) {
        uint64_t hs[8];
        if (copy_from_user(p, hs, c.job_list, c.job_count * 8ull)) st = STATUS_ACCESS_VIOLATION;
        for (i = 0; !st && i < c.job_count; ++i) {
            st = get_job(p, hs[i], JOB_OBJECT_ASSIGN_PROCESS, &ctx.jobs[i]);
            if (!st) ctx.job_count = i + 1;
        }
    }
    if (!st) {                                           /* the loader takes a UTF-8 DOS path */
        const uint16_t *w = image;
        uint32_t n = c.image_chars;
        if (n >= 4 && w[0] == '\\' && w[1] == '?' && w[2] == '?' && w[3] == '\\') { w += 4; n -= 4; }
        if (utf16_to_utf8(w, n, path, sizeof path) < 0) st = STATUS_OBJECT_NAME_INVALID;
    }
    if (!st) {
        ex.cmdline = cmd; ex.cmdline_chars = cmd ? c.cmdline_chars : 0;
        ex.cwd = cwd; ex.cwd_chars = cwd ? c.cwd_chars : 0;
        ex.env = env; ex.env_chars = env ? c.env_chars : 0;
        if (c.flags & CUP_STD) {
            ex.use_std_handles = 1;
            ex.std_handles[0] = c.std[0]; ex.std_handles[1] = c.std[1]; ex.std_handles[2] = c.std[2];
        }
        ex.suspended = (c.flags & CUP_SUSPENDED) != 0;
        ex.prepare = cup_prepare;
        ex.prepare_ctx = &ctx;
        st = ldr_create_process_ex(ctx.from, path, "", "", &ex, &np, &nt);
    }
    if (!st) {
        ob_ref(np->object);
        st = ipc_give_handle(p, np->object, c.process_access ? c.process_access : PROCESS_ALL_ACCESS, 0, 0, &hp);
        if (!st) {
            ob_ref(nt->object);
            st = ipc_give_handle(p, nt->object, c.thread_access ? c.thread_access : THREAD_ALL_ACCESS, 0, 0, &ht);
        }
        if (!st) {
            const uint64_t v[2] = { hp, ht };
            const uint32_t ids[2] = { (uint32_t)np->pid, (uint32_t)nt->tid };
            if (copy_to_user(p, arg + __builtin_offsetof(cup_t, out_process), v, 16) ||
                copy_to_user(p, arg + __builtin_offsetof(cup_t, out_pid), ids, 8))
                st = STATUS_ACCESS_VIOLATION;
        }
        if (st) {                                        /* the caller cannot learn about the child: do not leave it running */
            process_terminate(np, st, 0);
            if (hp) handle_close(p, hp);
            if (ht) handle_close(p, ht);
            if (nt->suspend_count) { nt->suspend_count = 0; thread_resume(nt); }   /* lets a suspended child die */
        }
        thread_creator_release(nt);                      /* from here on only the thread object is used */
    }
    for (i = 0; i < ctx.job_count; ++i) ob_deref(ctx.jobs[i]);
    if (parent_obj) ob_deref(parent_obj);
    kfree(image); kfree(cmd); kfree(cwd); kfree(env);
    return st;
}

/* ---------------------------------------------------------------- opening processes and threads by id */
struct client_id { uint64_t pid, tid; };
struct tid_search { uint64_t want; thread_t *found; };

static void find_tid_cb(thread_t *t, void *vctx)
{
    struct tid_search *s = vctx;
    if (!s->found && t->proc && t->tid == s->want && t->object) s->found = t;
}

/* Thread by its (system-wide unique) id; takes a reference on its thread object. */
static kobject_t *thread_object_by_tid(uint64_t tid)
{
    struct tid_search s = { tid, 0 };
    kobject_t *o = 0;
    uint64_t f;
    if (!tid) return 0;
    thread_reap_exited();                                /* exited threads are no longer found by id (their objects keep
                                                            answering through open handles) */
    sched_for_each_thread(find_tid_cb, &s);
    f = irq_save();
    if (s.found && s.found->tid == tid && s.found->object) { o = s.found->object; ob_ref(o); }
    irq_restore(f);
    return o;
}

static uint32_t max_allowed(uint32_t access, uint32_t all) { return (access & MAXIMUM_ALLOWED_ACCESS) ? all : access; }

/* NtOpenProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) */
static int32_t sys_open_process(process_t *p, uint64_t ph, uint64_t access, uint64_t oa, uint64_t pcid)
{
    struct client_id cid;
    struct ipc_objattr a;
    kobject_t *o = 0;
    if (!pcid || copy_from_user(p, &cid, pcid, sizeof cid)) return STATUS_ACCESS_VIOLATION;
    memset(&a, 0, sizeof a);
    if (oa && copy_from_user(p, &a, oa, sizeof a)) return STATUS_ACCESS_VIOLATION;
    if (cid.tid) {                                       /* by thread id: that thread's process (must match pid if given) */
        kobject_t *to = thread_object_by_tid(cid.tid);
        if (to) {
            const uint64_t f = irq_save();              /* the thread may be reclaimed at any preemption: its object keeps the pid */
            thread_t *th = to->u.thr.t;
            if (th && th->proc && (!cid.pid || to->u.thr.pid == cid.pid)) { o = th->proc->object; ob_ref(o); }
            irq_restore(f);
            ob_deref(to);
        }
    } else {
        const uint64_t f = irq_save();
        process_t *t = cid.pid > 0 && cid.pid < 0x7fffffffull ? process_by_pid((int)cid.pid) : 0;
        if (t) { o = t->object; ob_ref(o); }
        irq_restore(f);
    }
    if (!o) return STATUS_INVALID_CID;
    if(!shz_auth_process_access(p,o->u.proc.p)){ob_deref(o);return STATUS_ACCESS_DENIED;}
    return ipc_give_handle(p, o, max_allowed((uint32_t)access, PROCESS_ALL_ACCESS), (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* NtOpenThread(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) */
static int32_t sys_open_thread(process_t *p, uint64_t ph, uint64_t access, uint64_t oa, uint64_t pcid)
{
    struct client_id cid;
    struct ipc_objattr a;
    kobject_t *o;
    if (!pcid || copy_from_user(p, &cid, pcid, sizeof cid)) return STATUS_ACCESS_VIOLATION;
    memset(&a, 0, sizeof a);
    if (oa && copy_from_user(p, &a, oa, sizeof a)) return STATUS_ACCESS_VIOLATION;
    o = thread_object_by_tid(cid.tid);
    if (!o) return STATUS_INVALID_CID;
    if (cid.pid && o->u.thr.pid != cid.pid) { ob_deref(o); return STATUS_INVALID_CID; }
    if(!shz_auth_thread_access(p,o->u.thr.pid)){ob_deref(o);return STATUS_ACCESS_DENIED;}
    return ipc_give_handle(p, o, max_allowed((uint32_t)access, THREAD_ALL_ACCESS), (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* ---------------------------------------------------------------- cross-process memory */
/* NtReadVirtualMemory / NtWriteVirtualMemory(Process, BaseAddress, Buffer, Size, PSIZE_T Transferred). Page-sized chunks
 * through a kernel buffer; a fault on the other process's side ends the copy with STATUS_PARTIAL_COPY and the count of
 * bytes that did move, a fault on the caller's side with STATUS_ACCESS_VIOLATION. */
static int32_t sys_rw_vm(process_t *p, struct regs *r, uint64_t hproc, uint64_t addr, uint64_t buf, uint64_t len, int write)
{
    const uint64_t pdone = (uint64_t)stack_arg(p, r, 5);
    process_t *t;
    kobject_t *o;
    uint8_t *tmp;
    uint64_t done = 0;
    int32_t st = ipc_ref_process(p, hproc, write ? PROCESS_VM_WRITE : PROCESS_VM_READ, &t, &o);
    if (st) return st;
    if (t->teardown) { ob_deref(o); return STATUS_PROCESS_IS_TERMINATING; }
    tmp = kmalloc(PAGE_SIZE);
    if (!tmp) { ob_deref(o); return STATUS_INSUFFICIENT_RESOURCES; }
    while (done < len) {
        const uint64_t src = write ? buf + done : addr + done, dst = write ? addr + done : buf + done;
        uint64_t n = PAGE_SIZE - (src & (PAGE_SIZE - 1));
        const uint64_t m = PAGE_SIZE - (dst & (PAGE_SIZE - 1));
        if (n > m) n = m;
        if (n > len - done) n = len - done;
        if (copy_from_user(write ? p : t, tmp, src, n)) { st = write ? STATUS_ACCESS_VIOLATION : STATUS_PARTIAL_COPY; break; }
        if (copy_to_user(write ? t : p, dst, tmp, n)) { st = write ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION; break; }
        done += n;
    }
    kfree(tmp);
    ob_deref(o);
    if (pdone && copy_to_user(p, pdone, &done, 8)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- threads */
/* NtCreateThreadEx(PHANDLE, ACCESS, OA, Process, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize,
 * AttributeList): threads in the caller's or another process (CreateRemoteThread), optionally created suspended. */
static int32_t sys_create_thread(process_t *p, struct regs *r, uint64_t ph, uint64_t access, uint64_t oa, uint64_t hproc)
{
    const uint64_t start = (uint64_t)stack_arg(p, r, 5), arg = (uint64_t)stack_arg(p, r, 6);
    const uint32_t flags = (uint32_t)stack_arg(p, r, 7);
    const uint64_t stack = (uint64_t)stack_arg(p, r, 9), max_stack = (uint64_t)stack_arg(p, r, 10);
    struct ipc_objattr a;
    process_t *t;
    kobject_t *po;
    thread_t *nt = 0;
    kobject_t *to;
    uint64_t size;
    int32_t st;
    if (!start) return STATUS_INVALID_PARAMETER;
    memset(&a, 0, sizeof a);
    if (oa && copy_from_user(p, &a, oa, sizeof a)) return STATUS_ACCESS_VIOLATION;
    st = ipc_ref_process(p, hproc, PROCESS_CREATE_THREAD, &t, &po);
    if (st) return st;
    if (t->terminated || t->teardown || t->exit_owner) { ob_deref(po); return STATUS_PROCESS_IS_TERMINATING; }
    if (!t->ntdll_thread_start) { ob_deref(po); return STATUS_NOT_SUPPORTED; }     /* not started by the PE loader */
    size = max_stack > stack ? max_stack : stack;
    if (!size) size = 1u << 20;                          /* the default reservation of a Windows thread stack */
    if (process_start_thread3(t, t->ntdll_thread_start, start, arg, size, (flags & 1) != 0, &nt)) {
        st = t->terminated || t->exit_owner ? STATUS_PROCESS_IS_TERMINATING : STATUS_INSUFFICIENT_RESOURCES;
        ob_deref(po);
        return st;
    }
    ob_deref(po);
    to = nt->object;
    ob_ref(to);
    thread_creator_release(nt);                          /* from here on only the thread object is used */
    return ipc_give_handle(p, to, max_allowed((uint32_t)access ? (uint32_t)access : THREAD_ALL_ACCESS, THREAD_ALL_ACCESS),
                           (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* A thread handle with `need` access; referenced. The object's thread (u.thr.t) is reclaimed once it has exited (sched.c) at
 * any preemption, so callers read it with interrupts off: attached_thread(). */
static int32_t ref_thread(process_t *p, uint64_t h, uint32_t need, kobject_t **obj)
{
    uint32_t access = 0;
    int32_t st = ipc_ref_handle(p, h, OB_THREAD, obj, &access);
    if (st) return st;
    if ((access & need) != need) { ob_deref(*obj); return STATUS_ACCESS_DENIED; }
    return STATUS_SUCCESS;
}

/* Interrupts off: the object's thread while it has not finished exiting, else 0. */
static thread_t *attached_thread(kobject_t *o)
{
    thread_t *t = o->u.thr.t;
    return t && t->state != TS_ZOMBIE && t->state != TS_FREE && t->proc ? t : 0;
}

/* NtSuspendThread / NtResumeThread(Thread, PULONG PreviousSuspendCount) */
static int32_t sys_suspend_resume(process_t *p, uint64_t h, uint64_t pprev, int suspend)
{
    thread_t *t;
    kobject_t *o;
    uint32_t prev;
    uint64_t f;
    int32_t st = ref_thread(p, h, THREAD_SUSPEND_RESUME, &o);
    if (st) return st;
    f = irq_save();
    t = attached_thread(o);
    if (!t || thread_must_die(t)) { irq_restore(f); ob_deref(o); return STATUS_THREAD_IS_TERMINATING; }
    prev = (uint32_t)t->suspend_count;
    if (suspend) {
        if (prev >= MAX_SUSPEND) { irq_restore(f); ob_deref(o); return STATUS_SUSPEND_COUNT_EXCEEDED; }
        ++t->suspend_count;
    } else if (prev) {
        if (--t->suspend_count == 0) {
            if (t->state == TS_NEW) thread_resume(t);                   /* CREATE_SUSPENDED: its first run */
            else if (t->state == TS_BLOCKED && t->suspended) thread_wake(t);
        }
    }
    irq_restore(f);
    ob_deref(o);
    if (pprev && copy_to_user(p, pprev, &prev, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* NtTerminateThread(Thread, ExitStatus) for another thread (the caller's own exit is syscall.c's): asynchronous, like
 * process termination - the thread dies at its next return to user mode, interruptible waits end for it. */
static int32_t sys_terminate_thread(process_t *p, uint64_t h, int32_t code)
{
    thread_t *t;
    kobject_t *o;
    uint64_t f;
    int32_t st = ref_thread(p, h, THREAD_TERMINATE, &o);
    if (st) return st;
    if (o->u.thr.t == thread_current()) {
        t = thread_current();
        ob_deref(o);
        t->exit_code = code;
        process_thread_gone(p);
        thread_exit(code);
    }
    f = irq_save();
    t = attached_thread(o);
    if (t && !t->kill_pending) {
        t->kill_code = code;
        t->kill_pending = 1;
        ipc_kill_started();
        ipc_wake_to_die(t);
    }
    irq_restore(f);
    ob_deref(o);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- handle duplication */
/* NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, PHANDLE TargetHandle, DesiredAccess, HandleAttributes,
 * Options), within or across processes. */
/* Bounded opt-in observations; object rights and duplication behavior stay unchanged. */
static void duplicate_failure_trace(process_t *p, process_t *src, process_t *dst, kobject_t *o,
                                    uint64_t hsrc, uint32_t access, uint32_t desired,
                                    uint32_t attrs, uint32_t options, int32_t status)
{
    static int enabled = -1;
    static unsigned count;
    unsigned emit = 0;
    uint64_t saved;
    if (!status || ((uint32_t)status >> 30) != 3u) return;
    if (enabled < 0) enabled = k64_cmdline_has("shz.ipcdiag");
    if (!enabled) return;
    saved = irq_save();
    if (count < 32u) { ++count; emit = 1; }
    irq_restore(saved);
    if (emit)
        kprintf("K64 duplicate failure: pid=%d src=%d dst=%d handle=%llx type=%u granted=%x desired=%x attrs=%x options=%x status=%x\n",
                p->pid, src ? src->pid : 0, dst ? dst->pid : 0, hsrc, o ? (unsigned)o->type : 0u,
                access, desired, attrs, options, (uint32_t)status);
}

static int32_t sys_duplicate(process_t *p, struct regs *r, uint64_t hsp, uint64_t hsrc, uint64_t htp, uint64_t pout)
{
    const uint32_t desired = (uint32_t)stack_arg(p, r, 5), attrs = (uint32_t)stack_arg(p, r, 6);
    const uint32_t options = (uint32_t)stack_arg(p, r, 7);
    process_t *src, *dst = 0;
    kobject_t *spo, *dpo = 0, *o = 0;
    uint32_t access = 0, flags = 0, h = 0;
    int32_t st = ipc_ref_process(p, hsp, PROCESS_DUP_HANDLE, &src, &spo);
    if (st) return st;
    if (hsrc == CURRENT_PROCESS_HANDLE) { o = src->object; ob_ref(o); access = PROCESS_ALL_ACCESS; }
    else if (hsrc == CURRENT_THREAD_HANDLE) {
        if (src != p) { ob_deref(spo); return STATUS_INVALID_HANDLE; }
        o = thread_current()->object; ob_ref(o); access = THREAD_ALL_ACCESS;
    } else {
        st = src->teardown ? STATUS_INVALID_HANDLE : handle_ref(src, hsrc & ~3ull, 0, &o, &access);
        if (st) { ob_deref(spo); return st; }
        flags = handle_flags_of(src, hsrc & ~3ull);
    }
    if (htp || !(options & DUPLICATE_CLOSE_SOURCE)) {
        st = ipc_ref_process(p, htp, PROCESS_DUP_HANDLE, &dst, &dpo);
        if (!st && dst->teardown) { st = STATUS_PROCESS_IS_TERMINATING; ob_deref(dpo); dpo = 0; dst = 0; }
    }
    if (!st && dst) {
        uint32_t a = (options & DUPLICATE_SAME_ACCESS) ? access : desired;
        const int inherit = (options & DUPLICATE_SAME_ATTRIBUTES) ? (flags & HANDLE_FLAG_INHERIT_BIT) != 0
                                                                   : (attrs & OBJ_INHERIT_ATTR) != 0;
        if (o->type == OB_SECTION && !(options & DUPLICATE_SAME_ACCESS)) {
            /* Existing rights can be duplicated without reopening the object;
             * any expansion must pass its current security descriptor. */
            if (a & MAXIMUM_ALLOWED_ACCESS) a = access | (a & ~MAXIMUM_ALLOWED_ACCESS);
            st = ipc_section_duplicate_access(o, access, &a);
        }
        if(!st&&o->type!=OB_SECTION&&!(options&DUPLICATE_SAME_ACCESS)) {
            if(a&MAXIMUM_ALLOWED_ACCESS)a=(a&~MAXIMUM_ALLOWED_ACCESS)|access;
            if(a&~access)st=STATUS_ACCESS_DENIED;
        }
        if (!st) {
            ob_ref(o);
            st = ipc_give_handle(dst, o, a, inherit, 0, &h);
        }
        if (!st && pout) {
            const uint64_t v = h;
            if (copy_to_user(p, pout, &v, 8)) { handle_close(dst, h); st = STATUS_ACCESS_VIOLATION; }
        }
    }
    if ((options & DUPLICATE_CLOSE_SOURCE) && hsrc != CURRENT_PROCESS_HANDLE && hsrc != CURRENT_THREAD_HANDLE && !src->teardown)
        handle_close(src, hsrc & ~3ull);                 /* closed whether or not the duplication worked, as on NT */
    duplicate_failure_trace(p, src, dst, o, hsrc, access, desired, attrs, options, st);
    ob_deref(o);
    if (dpo) ob_deref(dpo);
    ob_deref(spo);
    return st;
}

/* ---------------------------------------------------------------- information */
struct thread_basic { int64_t exit_status; uint64_t teb, pid, tid, affinity; int32_t prio, base; };

/* ThreadBasicInformation with the thread's own process id and its unique thread id (the TEB's ClientId). */
static int32_t sys_query_thread(process_t *p, struct regs *r, uint64_t h, uint64_t buf, uint64_t len)
{
    const uint64_t pret = (uint64_t)stack_arg(p, r, 5);
    struct thread_basic b;
    const uint32_t n = sizeof b;
    thread_t *t;
    kobject_t *o;
    int32_t st;
    if (len < sizeof b) {
        if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    st = ref_thread(p, h, THREAD_QUERY_INFORMATION, &o);
    if (st) return st;
    memset(&b, 0, sizeof b);
    {
        const uint64_t f = irq_save();                   /* an exited thread is reclaimed at any preemption (sched.c) */
        t = o->u.thr.t;
        if (t) {
            b.exit_status = t->state == TS_ZOMBIE || t->state == TS_FREE ? t->exit_code : 0x103;
            b.teb = t->state == TS_ZOMBIE || t->state == TS_FREE ? 0 : t->teb;
        } else {
            b.exit_status = o->u.thr.exit_code;          /* reclaimed: the object kept the exit status and the ids */
        }
        b.pid = o->u.thr.pid;
        b.tid = o->u.thr.tid;
        b.affinity = 1;                         /* fixed single-CPU contract */
        b.prio = (int32_t)(t ? t->sched_priority : o->u.thr.last_sched_priority);
        b.base = o->u.thr.nt_base_increment;     /* relative, not absolute native priority */
        irq_restore(f);
    }
    ob_deref(o);
    if (copy_to_user(p, buf, &b, sizeof b)) return STATUS_ACCESS_VIOLATION;
    if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* Partial NT user-thread policy: ThreadBasePriority (3, LONG) and
 * ThreadAffinityMask (4, 64-bit KAFFINITY). Quantum remains native policy.
 * Absolute ThreadPriority (2), realtime and background modes are unsupported. */
static int32_t sys_set_thread(process_t *p, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    kobject_t *o;
    thread_t *t;
    sched_policy_t policy;
    shz_nt_sched_projection_t projection;
    shz_nt_sched_result_t result;
    int32_t increment = 0, st;
    uint64_t mask = 1, f;
    if (cls == 2) return STATUS_NOT_SUPPORTED;
    if (cls != 3 && cls != 4) return STATUS_INVALID_INFO_CLASS;
    if (len != (cls == 3 ? sizeof increment : sizeof mask)) return STATUS_INFO_LENGTH_MISMATCH;
    st = ref_thread(p, h, THREAD_SET_INFORMATION, &o);
    if (st) return st;
    if (copy_from_user(p, cls == 3 ? (void *)&increment : (void *)&mask, buf, len)) {
        ob_deref(o);
        return STATUS_ACCESS_VIOLATION;
    }
    f = irq_save();
    t = attached_thread(o);
    if (!t || t->object != o || !t->proc->used || t->proc->teardown ||
        (uint64_t)t->proc->pid != o->u.thr.pid || thread_must_die(t)) {
        st = STATUS_THREAD_IS_TERMINATING;
    } else if (thread_get_sched_policy(t, &policy)) {
        st = STATUS_THREAD_IS_TERMINATING;
    } else if (cls == 4) {
        st = mask != 1 ? STATUS_INVALID_PARAMETER :
             thread_set_sched_policy(t, policy.priority, policy.quantum_ticks, mask) ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
    } else {
        const uint32_t pc = t->proc->priority_class ? t->proc->priority_class : SHZ_NT_PROCESS_NORMAL;
        result = shz_nt_sched_from_base_increment(pc, increment, &projection);
        st = result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED :
             result != SHZ_NT_SCHED_OK ? STATUS_INVALID_PARAMETER :
             thread_set_sched_policy(t, projection.absolute_priority, policy.quantum_ticks, policy.cpu_mask) ?
             STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
        if (!st) {
            o->u.thr.nt_base_increment = projection.nt_base_increment;
            o->u.thr.last_sched_priority = projection.absolute_priority;
        }
    }
    irq_restore(f);
    ob_deref(o);
    return st;
}

extern int64_t shz_filetime_now_ipc(void);

/* The native class-18 transport shares the private Win32 retarget core.
 * Foreground scheduling and realtime/resource-background policies are outside
 * this UP backend; a successful call only changes supported base priorities. */
static int32_t sys_set_process_priority(process_t *cur, uint64_t h, uint64_t buf, uint64_t len)
{
    process_t *p;
    kobject_t *o;
    shz_nt_process_priority_t value;
    shz_nt_sched_result_t result;
    uint32_t cls;
    int32_t st;
    if (len != sizeof value) return STATUS_INFO_LENGTH_MISMATCH;
    st = ipc_ref_process(cur, h, PROCESS_SET_INFORMATION, &p, &o);
    if (st) return st;
    if (copy_from_user(cur, &value, buf, sizeof value)) {
        st = STATUS_ACCESS_VIOLATION;
    } else if (value.Foreground) {
        st = STATUS_NOT_SUPPORTED;
    } else {
        result = shz_nt_process_class_from_native(value.PriorityClass, &cls);
        st = result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED :
             result != SHZ_NT_SCHED_OK ? STATUS_INVALID_PARAMETER :
             ipc_set_process_priority_class(p, o, cls);
    }
    ob_deref(o);
    return st;
}

/* ProcessBasicInformation (0), ProcessTimes (4), ProcessPriorityClass (18),
 * ProcessHandleCount (20), ProcessSessionInformation (24),
 * ProcessImageFileName (27) and ProcessImageFileNameWin32 (43); other classes stay with sysx.c. */
static int32_t sys_query_process(process_t *p, struct regs *r, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    const uint64_t pret = (uint64_t)stack_arg(p, r, 5);
    process_t *t;
    kobject_t *o;
    uint8_t out[600];
    uint32_t n = 0;
    int32_t st;
    if (cls == SHZ_NT_PROCESS_PRIORITY_INFO_CLASS) {
        uint32_t access = 0;
        n = sizeof(shz_nt_process_priority_t);
        if (len != n) {
            if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        st = ipc_ref_handle(p, h, OB_PROCESS, &o, &access);
        if (st) return st;
        /* GetPriorityClass's modern contract permits either query right. */
        if (!(access & (PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION))) {
            ob_deref(o);
            return STATUS_ACCESS_DENIED;
        }
        t = o->u.proc.p;
    } else {
        st = ipc_ref_process(p, h, 0, &t, &o);
    }
    if (st) return st;
    memset(out, 0, sizeof out);
    switch (cls) {
    case 0: {
        struct { int64_t exit_status; uint64_t peb, affinity; int64_t base_priority; uint64_t pid, ppid; } b;
        shz_nt_sched_projection_t projection;
        shz_nt_sched_result_t result;
        const uint64_t f = irq_save();
        if (!t || !t->used || t->object != o) {
            st = STATUS_INVALID_HANDLE;
            irq_restore(f);
            break;
        }
        result = shz_nt_sched_from_win32(t->priority_class ? t->priority_class : SHZ_NT_PROCESS_NORMAL, 0, &projection);
        if (result != SHZ_NT_SCHED_OK) {
            st = result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
            irq_restore(f);
            break;
        }
        b.exit_status = o->signaled ? t->exit_code : 0x103;     /* STILL_ACTIVE until the last thread is gone */
        b.peb = t->teardown ? 0 : t->peb; b.affinity = 1;
        b.base_priority = projection.absolute_priority; b.pid = (uint64_t)t->pid;
        b.ppid = t->parent_pid;
        irq_restore(f);
        memcpy(out, &b, sizeof b);
        n = sizeof b;
        break;
    }
    case SHZ_NT_PROCESS_PRIORITY_INFO_CLASS: {
        shz_nt_process_priority_t value;
        shz_nt_sched_result_t result;
        const uint64_t f = irq_save();
        if (!t || !t->used || t->object != o) {
            st = STATUS_INVALID_HANDLE;
        } else {
            result = shz_nt_process_class_to_native(t->priority_class ? t->priority_class : SHZ_NT_PROCESS_NORMAL, &value);
            st = result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED :
                 result != SHZ_NT_SCHED_OK ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;
            if (!st) memcpy(out, &value, sizeof value);
        }
        irq_restore(f);
        break;
    }
    case 4: {                                            /* KERNEL_USER_TIMES: create, exit, kernel, user */
        const int64_t now = shz_filetime_now_ipc();
        const int64_t create = now - (int64_t)((ticks_now() - t->create_tick) * TICK_US * 10u);
        memcpy(out, &create, 8);
        if (t->terminated) memcpy(out + 8, &now, 8);
        n = 32;
        break;
    }
    case 20: { const uint32_t c = t->teardown ? 0 : t->handle_count; memcpy(out, &c, 4); n = 4; break; }
    case 24: n = 4; break;                               /* session 0: this system has one session */
    case 27: case 43: {                                  /* UNICODE_STRING followed by the path (ImagePathName) */
        uint16_t *w = (uint16_t *)(out + 16);
        uint32_t k = 0;
        if (!t->teardown && t->params_va) {
            struct ipc_ustr u;
            if (!copy_from_user(t, &u, t->params_va + 0x60, sizeof u) && u.length < 500 &&
                !copy_from_user(t, w, u.buffer, u.length))
                k = u.length / 2;
        }
        if (!k) { const char *s = t->name; while (s[k] && k < 240) { w[k] = (uint8_t)s[k]; ++k; } }
        w[k] = 0;
        {
            const struct ipc_ustr u = { (uint16_t)(k * 2), (uint16_t)(k * 2 + 2), 0, buf + 16 };
            memcpy(out, &u, 16);
        }
        n = 16 + k * 2 + 2;
        break;
    }
    default: break;
    }
    ob_deref(o);
    if (st) return st;
    if (len < n) {
        if (pret) copy_to_user(p, pret, &n, 4);
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    if (copy_to_user(p, buf, out, n)) return STATUS_ACCESS_VIOLATION;
    if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- inheritable handles from the base object calls */
/* NtCreateEvent / NtCreateMutant / NtCreateSemaphore (sysx.c) do not look at OBJ_INHERIT: run them, then mark the new
 * handle inheritable when the attributes asked for it. */
static int32_t create_with_inherit(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                                   uint64_t a4)
{
    struct ipc_objattr a;
    int32_t st = sys_extended(p, r, num, a1, a2, a3, a4);
    uint64_t h = 0;
    if ((st != STATUS_SUCCESS && st != STATUS_OBJECT_NAME_EXISTS) || !a3) return st;
    if (copy_from_user(p, &h, a1, 8) || !h || (h & 3) || h > (uint64_t)p->handle_cap * 4ull) return st;
    if (num == SYS_NtCreateFile || num == SYS_NtOpenFile)
        ipc_file_created(p, h, (uint32_t)stack_arg(p, r, num == SYS_NtOpenFile ? 6 : 9));
    if (copy_from_user(p, &a, a3, sizeof a) || !(a.attributes & OBJ_INHERIT_ATTR)) return st;
    {
        const uint64_t f = irq_save();
        if (p->handles[h / 4 - 1].obj) p->handles[h / 4 - 1].inherit |= HANDLE_FLAG_INHERIT_BIT;
        irq_restore(f);
    }
    return st;
}

/* ---------------------------------------------------------------- routing */
int32_t ipc_proc_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtShzCreateUserProcess: return sys_create_user_process(p, a1);
    case SYS_NtOpenProcess: return sys_open_process(p, a1, a2, a3, a4);
    case SYS_NtOpenThread: return sys_open_thread(p, a1, a2, a3, a4);
    case SYS_NtReadVirtualMemory: return sys_rw_vm(p, r, a1, a2, a3, a4, 0);
    case SYS_NtWriteVirtualMemory: return sys_rw_vm(p, r, a1, a2, a3, a4, 1);
    case SYS_NtCreateThreadEx: return sys_create_thread(p, r, a1, a2, a3, a4);
    case SYS_NtSuspendThread: return sys_suspend_resume(p, a1, a2, 1);
    case SYS_NtResumeThread: return sys_suspend_resume(p, a1, a2, 0);
    case SYS_NtTerminateThread:
        if (a1 == 0 || a1 == CURRENT_THREAD_HANDLE) break;            /* the caller's own exit: syscall.c */
        return sys_terminate_thread(p, a1, (int32_t)a2);
    case SYS_NtDuplicateObject: return sys_duplicate(p, r, a1, a2, a3, a4);
    case SYS_NtQueryInformationThread:
        if (a2 != 0) break;                                           /* ThreadBasicInformation only */
        return sys_query_thread(p, r, a1, a3, a4);
    case SYS_NtSetInformationThread: return sys_set_thread(p, a1, a2, a3, a4);
    case SYS_NtQueryInformationProcess:
        if (a2 != 0 && a2 != 4 && a2 != SHZ_NT_PROCESS_PRIORITY_INFO_CLASS &&
            a2 != 20 && a2 != 24 && a2 != 27 && a2 != 43) break;
        return sys_query_process(p, r, a1, a2, a3, a4);
    case SYS_NtSetInformationProcess:
        if (a2 != SHZ_NT_PROCESS_PRIORITY_INFO_CLASS) break;
        return sys_set_process_priority(p, a1, a3, a4);
    case SYS_NtCreateEvent: case SYS_NtCreateMutant: case SYS_NtCreateSemaphore: case SYS_NtCreateFile: case SYS_NtOpenFile:
        return create_with_inherit(p, r, num, a1, a2, a3, a4);
    case SYS_NtCreateJobObject: return sys_create_job(p, a1, a2, a3);
    case SYS_NtOpenJobObject: return ipc_open_named(p, OB_JOB, a1, a2, a3);
    case SYS_NtAssignProcessToJobObject: return sys_assign_job(p, a1, a2);
    case SYS_NtSetInformationJobObject: return sys_set_job(p, a1, a2, a3, a4);
    case SYS_NtQueryInformationJobObject: return sys_query_job(p, r, a1, a2, a3, a4);
    case SYS_NtTerminateJobObject: return sys_terminate_job(p, a1, a2);
    case SYS_NtIsProcessInJob: return sys_is_in_job(p, a1, a2);
    default: break;
    }
    *handled = 0;
    return 0;
}
