/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system calls 0x95-0x9e for kernel32/advapi32 (routed by sysk32.c) plus the NT process/thread services of the
 * base list that kernel32 needs (NtOpenProcess, NtOpenThread, NtSuspendThread, NtResumeThread, NtDuplicateObject across
 * processes, NtCreateThreadEx in another process):
 *
 *  - sections (section.c), I/O completion ports (iocp.c), named pipes (npfs.c): argument decoding only;
 *  - NtReadVirtualMemory / NtWriteVirtualMemory: copies between two address spaces through a kernel bounce buffer,
 *    STATUS_PARTIAL_COPY when the range ends in unmapped memory;
 *  - job objects: membership (children join their parent's job unless they break away), TerminateJobObject,
 *    JOB_OBJECT_LIMIT_ACTIVE_PROCESS and JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE are enforced, DIE_ON_UNHANDLED_EXCEPTION and
 *    the breakaway flags are honoured. Limits the kernel cannot enforce (CPU time, working set, memory, priority,
 *    affinity, UI restrictions) are refused with STATUS_NOT_SUPPORTED instead of being recorded and ignored;
 *  - access tokens: one primary token per process (medium integrity, session 1, a fresh LUID) and duplicates of it;
 *    advapi32 renders the Windows information classes from shz_token_info. Thread impersonation records which token a
 *    thread impersonates (OpenThreadToken reports it); Kernel64 performs no access checks, so impersonation changes
 *    nothing else;
 *  - security descriptors: stored per object as the self-relative blob advapi32 composes (not enforced: Kernel64 has no
 *    access checks), returned by the query.
 */
#include "fs.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
extern int32_t section_create(file_t *file, uint64_t max_size, uint32_t prot, uint32_t attrs, const char *name, kobject_t **out);
extern int32_t section_map(kobject_t *o, process_t *p, uint64_t *base, uint64_t offset, uint64_t *size, uint32_t alloc_type,
                           uint32_t prot);
extern int32_t section_flush(process_t *p, uint64_t addr, uint64_t len, uint64_t *base_out, uint64_t *len_out);
extern int32_t section_query(kobject_t *o, uint64_t out[3]);
extern int32_t vad_unmap_view(process_t *p, uint64_t addr);
extern kobject_t *iocp_create(uint32_t concurrency);
extern int32_t iocp_post(kobject_t *o, uint64_t key, uint64_t ctx, int32_t status, uint64_t info);
extern int32_t iocp_remove(process_t *p, kobject_t *o, uint64_t *out, unsigned max, unsigned *got, int64_t timeout, int alertable);
extern uint32_t iocp_depth(kobject_t *o);
extern int32_t npfs_create(process_t *p, struct regs *r, uint64_t phandle, uint64_t access, uint64_t oa_va, uint64_t iosb);
extern int npfs_fsctl(process_t *p, struct regs *r, uint64_t handle, int32_t *st_out);
extern int npfs_cancel(kobject_t *fo, uint64_t iosb_match, int any, int this_thread);

#define STATUS_PARTIAL_COPY ((int32_t)0x8000000D)
#define STATUS_NO_TOKEN ((int32_t)0xC000007C)
#define STATUS_SUSPEND_COUNT_EXCEEDED ((int32_t)0xC000004A)
#define STATUS_PROCESS_IN_JOB ((int32_t)0x00000124)
#define STATUS_PROCESS_NOT_IN_JOB ((int32_t)0x00000123)
#define STATUS_QUOTA_EXCEEDED ((int32_t)0xC0000044)
#define STATUS_NOT_FOUND ((int32_t)0xC0000225)
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#endif

struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };

/* ---------------------------------------------------------------- helpers */
static process_t *proc_ref_of(process_t *cur, uint64_t h, kobject_t **ref)
{
    kobject_t *o;
    process_t *t;
    *ref = 0;
    if (h == CURRENT_PROCESS_HANDLE) return cur;
    if (handle_ref(cur, h, OB_PROCESS, &o, 0)) return 0;
    t = o->u.proc.p;
    if (!t || !t->used || t->object != o) { ob_deref(o); return 0; }        /* reaped: the slot may be reused */
    *ref = o;
    return t;
}

static void proc_unref(kobject_t *ref) { if (ref) ob_deref(ref); }

/* Object name from OBJECT_ATTRIBUTES (UTF-8, empty when unnamed); *inherit = OBJ_INHERIT. */
static int32_t oa_name(process_t *p, uint64_t oa_va, char *out, size_t cap, int *inherit)
{
    struct objattr oa;
    struct ustr u;
    uint16_t w[OB_NAME_MAX];
    out[0] = 0;
    if (inherit) *inherit = 0;
    if (!oa_va) return STATUS_SUCCESS;
    if (copy_from_user(p, &oa, oa_va, sizeof oa)) return STATUS_ACCESS_VIOLATION;
    if (inherit) *inherit = (oa.attributes & 2) != 0;
    if (!oa.name) return STATUS_SUCCESS;
    if (copy_from_user(p, &u, oa.name, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if ((u.length & 1) || u.length / 2 >= OB_NAME_MAX) return STATUS_OBJECT_NAME_INVALID;
    if (u.length && copy_from_user(p, w, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
    return utf16_to_utf8(w, u.length / 2, out, cap) < 0 ? STATUS_OBJECT_NAME_INVALID : STATUS_SUCCESS;
}

/* Inserts `o` (the caller's reference is consumed) and writes the handle to user memory. */
static int32_t give_handle(process_t *p, kobject_t *o, uint64_t user_ptr, uint32_t access, int inherit)
{
    uint32_t h;
    uint64_t v;
    int32_t st = handle_insert(p, o, access, &h);
    ob_deref(o);
    if (st) return st;
    if (inherit) p->handles[h / 4 - 1].inherit |= 1;
    v = h;
    if (copy_to_user(p, user_ptr, &v, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- sections */
static int32_t sys_section(process_t *p, struct regs *r, uint64_t op, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (op) {
    case SHZ_SEC_CREATE: {
        const uint32_t attrs = (uint32_t)stack_arg(p, r, 5), access = (uint32_t)stack_arg(p, r, 8);
        const uint64_t hfile = (uint64_t)stack_arg(p, r, 6), oa = (uint64_t)stack_arg(p, r, 7);
        char name[OB_NAME_MAX];
        uint64_t max = 0;
        kobject_t *fo = 0, *o;
        int inherit;
        int32_t st = oa_name(p, oa, name, sizeof name, &inherit);
        if (st) return st;
        if (a3 && copy_from_user(p, &max, a3, 8)) return STATUS_ACCESS_VIOLATION;
        if (name[0] && (o = ob_find_named(OB_SECTION, name))) {
            if (o->type != OB_SECTION) return STATUS_OBJECT_TYPE_MISMATCH;
            ob_ref(o);
            st = give_handle(p, o, a2, access, inherit);
            return st ? st : (int32_t)0x40000000;                        /* STATUS_OBJECT_NAME_EXISTS */
        }
        if (hfile && (st = handle_ref(p, hfile, OB_FILE, &fo, 0))) return st;
        st = section_create(fo ? (file_t *)fo->u.file.file : 0, max, (uint32_t)a4, attrs, name, &o);
        if (fo) ob_deref(fo);
        if (st) return st;
        if (a3) { uint64_t sz = 0; extern uint64_t section_size(kobject_t *); sz = section_size(o); copy_to_user(p, a3, &sz, 8); }
        return give_handle(p, o, a2, access, inherit);
    }
    case SHZ_SEC_OPEN: {
        char name[OB_NAME_MAX];
        kobject_t *o;
        int inherit;
        int32_t st = oa_name(p, a4, name, sizeof name, &inherit);
        if (st) return st;
        if (!name[0]) return STATUS_OBJECT_NAME_INVALID;
        o = ob_find_named(OB_SECTION, name);
        if (!o) return STATUS_OBJECT_NAME_NOT_FOUND;
        if (o->type != OB_SECTION) return STATUS_OBJECT_TYPE_MISMATCH;
        ob_ref(o);
        return give_handle(p, o, a2, (uint32_t)a3, inherit);
    }
    case SHZ_SEC_MAP: {
        const uint64_t offset = (uint64_t)stack_arg(p, r, 5), psize = (uint64_t)stack_arg(p, r, 6);
        const uint32_t type = (uint32_t)stack_arg(p, r, 7), prot = (uint32_t)stack_arg(p, r, 8);
        kobject_t *so, *pref;
        process_t *t;
        uint64_t base = 0, size = 0;
        int32_t st = handle_ref(p, a2, OB_SECTION, &so, 0);
        if (st) return st;
        t = proc_ref_of(p, a3, &pref);
        if (!t) { ob_deref(so); return STATUS_INVALID_HANDLE; }
        if (copy_from_user(p, &base, a4, 8) || (psize && copy_from_user(p, &size, psize, 8))) st = STATUS_ACCESS_VIOLATION;
        else st = section_map(so, t, &base, offset, &size, type, prot);
        if (!st && (copy_to_user(p, a4, &base, 8) || (psize && copy_to_user(p, psize, &size, 8)))) {
            vad_unmap_view(t, base);
            st = STATUS_ACCESS_VIOLATION;
        }
        proc_unref(pref);
        ob_deref(so);
        return st;
    }
    case SHZ_SEC_UNMAP: {
        kobject_t *pref;
        process_t *t = proc_ref_of(p, a2, &pref);
        int32_t st;
        if (!t) return STATUS_INVALID_HANDLE;
        st = vad_unmap_view(t, a3);
        proc_unref(pref);
        return st;
    }
    case SHZ_SEC_FLUSH: {
        kobject_t *pref;
        process_t *t = proc_ref_of(p, a2, &pref);
        uint64_t base = 0, size = 0, ob = 0, ol = 0;
        int32_t st;
        if (!t) return STATUS_INVALID_HANDLE;
        if (copy_from_user(p, &base, a3, 8) || copy_from_user(p, &size, a4, 8)) st = STATUS_ACCESS_VIOLATION;
        else st = section_flush(t, base, size, &ob, &ol);
        if (!st && (copy_to_user(p, a3, &ob, 8) || copy_to_user(p, a4, &ol, 8))) st = STATUS_ACCESS_VIOLATION;
        proc_unref(pref);
        return st;
    }
    case SHZ_SEC_QUERY: {
        kobject_t *so;
        uint64_t info[3];
        int32_t st = handle_ref(p, a2, OB_SECTION, &so, 0);
        if (st) return st;
        st = section_query(so, info);
        ob_deref(so);
        if (st) return st;
        if (a4 < 24) return STATUS_INFO_LENGTH_MISMATCH;
        return copy_to_user(p, a3, info, 24) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- I/O completion ports */
static int32_t sys_iocp(process_t *p, struct regs *r, uint64_t op, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (op) {
    case SHZ_IOC_CREATE: {
        char name[OB_NAME_MAX];
        int inherit;
        kobject_t *o;
        int32_t st = oa_name(p, a4, name, sizeof name, &inherit);
        if (st) return st;
        if (name[0]) return STATUS_NOT_SUPPORTED;                          /* named completion ports are not provided */
        o = iocp_create((uint32_t)a3);
        if (!o) return STATUS_NO_MEMORY;
        return give_handle(p, o, a2, 0x1f0003, inherit);
    }
    case SHZ_IOC_SET: {
        kobject_t *o;
        int32_t st = handle_ref(p, a2, OB_IOCP, &o, 0);
        if (st) return st;
        st = iocp_post(o, a3, a4, (int32_t)stack_arg(p, r, 5), (uint64_t)stack_arg(p, r, 6));
        ob_deref(o);
        return st;
    }
    case SHZ_IOC_REMOVE: {
        const uint64_t premoved = (uint64_t)stack_arg(p, r, 5), pto = (uint64_t)stack_arg(p, r, 6);
        const int alertable = (int)(stack_arg(p, r, 7) & 0xff);
        uint64_t out[4 * 16];
        unsigned max = (unsigned)a4, got = 0;
        int64_t to = INT64_MAX;
        kobject_t *o;
        int32_t st;
        if (!max) return STATUS_INVALID_PARAMETER;
        if (max > 16) max = 16;                                            /* per call; callers loop */
        if (pto && copy_from_user(p, &to, pto, 8)) return STATUS_ACCESS_VIOLATION;
        if (pto && to > 0) {                                               /* absolute FILETIME deadline -> relative */
            extern int64_t filetime_now(void);
            const int64_t now = filetime_now();
            to = to > now ? now - to : 0;
        }
        st = handle_ref(p, a2, OB_IOCP, &o, 0);
        if (st) return st;
        st = iocp_remove(p, o, out, max, &got, to, alertable);
        ob_deref(o);
        if (st) return st;
        if (copy_to_user(p, a3, out, got * 32ull)) return STATUS_ACCESS_VIOLATION;
        if (premoved && copy_to_user(p, premoved, &got, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SHZ_IOC_CANCEL: {
        kobject_t *fo;
        int n;
        int32_t st = handle_ref(p, a2, OB_FILE, &fo, 0);
        if (st) return st;
        n = npfs_cancel(fo, a3, a3 == 0, a4 == 1);
        ob_deref(fo);
        return n ? STATUS_SUCCESS : STATUS_NOT_FOUND;                      /* CancelIoEx: ERROR_NOT_FOUND when nothing was pending */
    }
    case SHZ_IOC_QUERY: {
        kobject_t *o;
        uint32_t depth;
        int32_t st = handle_ref(p, a2, OB_IOCP, &o, 0);
        if (st) return st;
        depth = iocp_depth(o);
        ob_deref(o);
        return copy_to_user(p, a3, &depth, 4) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- process memory */
static int32_t sys_rw_vm(process_t *cur, struct regs *r, uint64_t hproc, uint64_t addr, uint64_t buf, uint64_t size, int write)
{
    const uint64_t pdone = (uint64_t)stack_arg(cur, r, 5);
    kobject_t *pref;
    process_t *t = proc_ref_of(cur, hproc, &pref);
    uint8_t *tmp;
    uint64_t done = 0;
    int32_t st = STATUS_SUCCESS;
    if (!t) return STATUS_INVALID_HANDLE;
    tmp = kmalloc(PAGE_SIZE);
    if (!tmp) { proc_unref(pref); return STATUS_NO_MEMORY; }
    while (done < size) {
        uint64_t n = PAGE_SIZE - ((addr + done) & (PAGE_SIZE - 1));
        if (n > size - done) n = size - done;
        if (write) {
            if (copy_from_user(cur, tmp, buf + done, n)) { st = STATUS_ACCESS_VIOLATION; break; }
            if (copy_to_user(t, addr + done, tmp, n)) { st = done ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION; break; }
        } else {
            if (copy_from_user(t, tmp, addr + done, n)) { st = done ? STATUS_PARTIAL_COPY : STATUS_ACCESS_VIOLATION; break; }
            if (copy_to_user(cur, buf + done, tmp, n)) { st = STATUS_ACCESS_VIOLATION; break; }
        }
        done += n;
    }
    kfree(tmp);
    proc_unref(pref);
    if (pdone) copy_to_user(cur, pdone, &done, 8);
    return st;
}

/* ---------------------------------------------------------------- jobs */
#define JOB_MAX_PROCS 64
#define JL_ACTIVE_PROCESS 0x8u
#define JL_DIE_ON_UNHANDLED 0x400u
#define JL_BREAKAWAY_OK 0x800u
#define JL_SILENT_BREAKAWAY 0x1000u
#define JL_KILL_ON_CLOSE 0x2000u
#define JL_ENFORCED (JL_ACTIVE_PROCESS | JL_DIE_ON_UNHANDLED | JL_BREAKAWAY_OK | JL_SILENT_BREAKAWAY | JL_KILL_ON_CLOSE)

typedef struct job {
    int pids[JOB_MAX_PROCS];
    process_t *procs[JOB_MAX_PROCS];
    unsigned n;
    uint32_t limit_flags, active_limit;
    uint64_t total, terminated_count;
    kobject_t *port;
    uint64_t port_key;
} job_t;

static void job_notify(job_t *j, uint32_t msg, uint64_t pid)
{
    if (j->port) iocp_post(j->port, j->port_key, pid, (int32_t)msg, 0);   /* JOB_OBJECT_MSG_*: ApcContext = process id */
}

static void job_remove(job_t *j, process_t *p)
{
    unsigned i;
    for (i = 0; i < j->n; ++i)
        if (j->procs[i] == p && j->pids[i] == p->pid) {
            j->procs[i] = j->procs[--j->n];
            j->pids[i] = j->pids[j->n];
            if (!j->n) job_notify(j, 4, 0);                                  /* JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO */
            return;
        }
}

void job_object_free(kobject_t *o)
{
    job_t *j = o->u.job.j;
    if (!j) return;
    if (j->port) ob_deref(j->port);
    kfree(j);
    o->u.job.j = 0;
}

void job_process_gone(process_t *p)
{
    kobject_t *jo = p->job;
    if (!jo) return;
    p->job = 0;
    if (jo->u.job.j) {
        job_notify(jo->u.job.j, 3, (uint64_t)p->pid);                        /* JOB_OBJECT_MSG_EXIT_PROCESS */
        job_remove(jo->u.job.j, p);
    }
    ob_deref(jo);
}

static void job_terminate_all(job_t *j, int64_t code)
{
    unsigned i;
    for (i = 0; i < j->n; ++i) {
        process_t *t = j->procs[i];
        if (t && t->used && t->pid == j->pids[i] && !t->terminated) {
            process_terminate(t, code, 0);
            ++j->terminated_count;
        }
    }
}

void job_handles_gone(kobject_t *o)
{
    job_t *j = o->u.job.j;
    if (j && (j->limit_flags & JL_KILL_ON_CLOSE)) job_terminate_all(j, 0);
}

static int32_t job_add(kobject_t *jo, process_t *t)
{
    job_t *j = jo->u.job.j;
    if (t->job) return t->job == jo ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;   /* nested jobs are not provided */
    if (j->n >= JOB_MAX_PROCS) return STATUS_INSUFFICIENT_RESOURCES;
    if ((j->limit_flags & JL_ACTIVE_PROCESS) && j->n >= j->active_limit) {
        job_notify(j, 5, (uint64_t)t->pid);                                   /* JOB_OBJECT_MSG_ACTIVE_PROCESS_LIMIT */
        return STATUS_QUOTA_EXCEEDED;
    }
    j->procs[j->n] = t;
    j->pids[j->n++] = t->pid;
    ++j->total;
    ob_ref(jo);
    t->job = jo;
    job_notify(j, 6, (uint64_t)t->pid);                                       /* JOB_OBJECT_MSG_NEW_PROCESS */
    return STATUS_SUCCESS;
}

/* A new process of `parent`: it joins the parent's job unless it may break away and asked to (CREATE_BREAKAWAY_FROM_JOB). */
int32_t job_inherit(process_t *parent, process_t *child, int breakaway)
{
    job_t *j;
    if (!parent || !parent->job || !(j = parent->job->u.job.j)) return STATUS_SUCCESS;
    if (j->limit_flags & JL_SILENT_BREAKAWAY) return STATUS_SUCCESS;
    if (breakaway) return (j->limit_flags & JL_BREAKAWAY_OK) ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
    return job_add(parent->job, child);
}

static int32_t sys_job(process_t *p, struct regs *r, uint64_t op, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (op) {
    case SHZ_JOB_CREATE: case SHZ_JOB_OPEN: {
        char name[OB_NAME_MAX];
        int inherit;
        kobject_t *o;
        job_t *j;
        int32_t st = oa_name(p, a4, name, sizeof name, &inherit);
        if (st) return st;
        if (name[0] && (o = ob_find_named(OB_JOB, name))) {
            if (o->type != OB_JOB) return STATUS_OBJECT_TYPE_MISMATCH;
            ob_ref(o);
            st = give_handle(p, o, a2, (uint32_t)a3, inherit);
            return st ? st : op == SHZ_JOB_CREATE ? (int32_t)0x40000000 : STATUS_SUCCESS;
        }
        if (op == SHZ_JOB_OPEN) return name[0] ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_NAME_INVALID;
        j = kzalloc(sizeof *j);
        o = j ? ob_create(OB_JOB, name) : 0;
        if (!o) { kfree(j); return STATUS_NO_MEMORY; }
        o->u.job.j = j;
        return give_handle(p, o, a2, (uint32_t)a3, inherit);
    }
    case SHZ_JOB_ASSIGN: {
        kobject_t *jo, *pref;
        process_t *t;
        int32_t st = handle_ref(p, a2, OB_JOB, &jo, 0);
        if (st) return st;
        t = proc_ref_of(p, a3, &pref);
        if (!t) st = STATUS_INVALID_HANDLE;
        else if (t->terminated) st = STATUS_PROCESS_IS_TERMINATING;
        else st = job_add(jo, t);
        proc_unref(pref);
        ob_deref(jo);
        return st;
    }
    case SHZ_JOB_TERMINATE: {
        kobject_t *jo;
        int32_t st = handle_ref(p, a2, OB_JOB, &jo, 0);
        if (st) return st;
        job_terminate_all(jo->u.job.j, (int64_t)(int32_t)a3);
        ob_deref(jo);
        return STATUS_SUCCESS;
    }
    case SHZ_JOB_IS_IN_JOB: {
        kobject_t *pref, *jo = 0;
        process_t *t = proc_ref_of(p, a2, &pref);
        uint8_t in = 0;
        int32_t st = STATUS_SUCCESS;
        if (!t) return STATUS_INVALID_HANDLE;
        if (a3) st = handle_ref(p, a3, OB_JOB, &jo, 0);
        if (!st) in = jo ? t->job == jo : t->job != 0;
        if (jo) ob_deref(jo);
        proc_unref(pref);
        if (st) return st;
        return copy_to_user(p, a4, &in, 1) ? STATUS_ACCESS_VIOLATION : (in ? STATUS_PROCESS_IN_JOB : STATUS_PROCESS_NOT_IN_JOB);
    }
    case SHZ_JOB_QUERY: case SHZ_JOB_SET: {
        const uint64_t len = (uint64_t)stack_arg(p, r, 5), pret = op == SHZ_JOB_QUERY ? (uint64_t)stack_arg(p, r, 6) : 0;
        uint8_t b[144];
        uint32_t n = 0;
        kobject_t *jo;
        job_t *j;
        int32_t st;
        if (!a2) {                                                          /* NULL: the caller's job */
            if (!p->job) return STATUS_ACCESS_DENIED;
            jo = p->job;
            ob_ref(jo);
        } else if ((st = handle_ref(p, a2, OB_JOB, &jo, 0))) {
            return st;
        }
        j = jo->u.job.j;
        memset(b, 0, sizeof b);
        st = STATUS_SUCCESS;
        if (op == SHZ_JOB_QUERY) {
            switch (a3) {
            case 1:                                                         /* JobObjectBasicAccountingInformation */
            case 8: {                                                       /* ...AndIoAccountingInformation (+ IO_COUNTERS) */
                unsigned i;
                uint32_t active = 0;
                for (i = 0; i < j->n; ++i) if (j->procs[i]->used && j->procs[i]->pid == j->pids[i] && !j->procs[i]->terminated) ++active;
                *(uint32_t *)(b + 32) = 0;                                  /* TotalPageFaultCount */
                *(uint32_t *)(b + 36) = (uint32_t)j->total;                 /* TotalProcesses */
                *(uint32_t *)(b + 40) = active;                             /* ActiveProcesses */
                *(uint32_t *)(b + 44) = (uint32_t)j->terminated_count;      /* TotalTerminatedProcesses */
                n = a3 == 1 ? 48 : 96;
                break;
            }
            case 2: case 9:                                                 /* Basic / Extended limit information */
                *(uint32_t *)(b + 16) = j->limit_flags;
                *(uint32_t *)(b + 40) = j->active_limit;
                n = a3 == 2 ? 64 : 144;
                break;
            case 3: {                                                       /* JobObjectBasicProcessIdList */
                unsigned i, k = 0;
                const unsigned cap = len >= 8 ? (unsigned)((len - 8) / 8) : 0;
                uint32_t hdr[2];
                if (len < 8) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
                for (i = 0; i < j->n; ++i) {
                    if (!(j->procs[i]->used && j->procs[i]->pid == j->pids[i] && !j->procs[i]->terminated)) continue;
                    if (k < cap) { uint64_t pid = (uint64_t)j->pids[i]; copy_to_user(p, a4 + 8 + k * 8ull, &pid, 8); }
                    ++k;
                }
                hdr[0] = k;
                hdr[1] = k < cap ? k : cap;
                copy_to_user(p, a4, hdr, 8);
                if (pret) { uint32_t w = 8 + hdr[1] * 8; copy_to_user(p, pret, &w, 4); }
                ob_deref(jo);
                return k > cap ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
            }
            case 4:                                                         /* JobObjectBasicUIRestrictions */
                n = 4;
                break;
            default:
                st = STATUS_INVALID_INFO_CLASS;
            }
            if (!st) {
                if (len < n) st = STATUS_INFO_LENGTH_MISMATCH;
                else if (copy_to_user(p, a4, b, n)) st = STATUS_ACCESS_VIOLATION;
                if (pret) copy_to_user(p, pret, &n, 4);
            }
        } else {
            switch (a3) {
            case 2: case 9: {
                uint32_t flags;
                n = a3 == 2 ? 64 : 144;
                if (len < n) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
                if (copy_from_user(p, b, a4, n)) { st = STATUS_ACCESS_VIOLATION; break; }
                flags = *(uint32_t *)(b + 16);
                if (flags & ~JL_ENFORCED) { st = STATUS_NOT_SUPPORTED; break; }   /* a limit Kernel64 cannot enforce */
                if ((flags & JL_ACTIVE_PROCESS) && !*(uint32_t *)(b + 40)) { st = STATUS_INVALID_PARAMETER; break; }
                j->limit_flags = flags;
                j->active_limit = *(uint32_t *)(b + 40);
                break;
            }
            case 4: {                                                       /* UI restrictions: only "none" is honest here */
                uint32_t ui;
                if (len < 4) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
                if (copy_from_user(p, &ui, a4, 4)) { st = STATUS_ACCESS_VIOLATION; break; }
                if (ui) st = STATUS_NOT_SUPPORTED;
                break;
            }
            case 7: {                                                       /* JobObjectAssociateCompletionPortInformation */
                uint64_t v[2];
                kobject_t *port;
                if (len < 16) { st = STATUS_INFO_LENGTH_MISMATCH; break; }
                if (copy_from_user(p, v, a4, 16)) { st = STATUS_ACCESS_VIOLATION; break; }
                if (j->port) { st = STATUS_INVALID_PARAMETER; break; }
                if ((st = handle_ref(p, v[1], OB_IOCP, &port, 0))) break;
                j->port = port;
                j->port_key = v[0];
                break;
            }
            default:
                st = STATUS_INVALID_INFO_CLASS;
            }
        }
        ob_deref(jo);
        return st;
    }
    default: return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- tokens */
typedef struct shz_token_info {
    uint32_t type, imp_level, integrity_rid, flags;
    uint64_t id, modified_id, auth_id;
    uint32_t session, elevation_type;
    uint64_t owner_pid;
} shz_token_info;

static uint64_t next_luid = 0x10000;

void token_object_free(kobject_t *o)
{
    if (o->u.token.t) { kfree(o->u.token.t); o->u.token.t = 0; }
}

static kobject_t *token_new(const shz_token_info *from, uint64_t owner_pid)
{
    shz_token_info *t = kzalloc(sizeof *t);
    kobject_t *o = t ? ob_create(OB_TOKEN, 0) : 0;
    if (!o) { kfree(t); return 0; }
    if (from) *t = *from;
    else {
        t->type = 1;                                                        /* TokenPrimary */
        t->integrity_rid = 0x2000;                                          /* SECURITY_MANDATORY_MEDIUM_RID */
        t->session = 1;
        t->elevation_type = 1;                                              /* TokenElevationTypeDefault */
        t->auth_id = 0x3e7 + 0x100;                                         /* the interactive logon session */
    }
    t->id = ++next_luid;
    t->modified_id = t->id;
    t->owner_pid = owner_pid;
    o->u.token.t = t;
    return o;
}

static kobject_t *process_token(process_t *t)
{
    if (!t->token) t->token = token_new(0, (uint64_t)t->pid);
    return t->token;
}

static int32_t sys_token(process_t *p, struct regs *r, uint64_t op, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r;
    switch (op) {
    case SHZ_TOK_OPEN_PROCESS: {
        kobject_t *pref, *tok;
        process_t *t = proc_ref_of(p, a2, &pref);
        int32_t st;
        if (!t) return STATUS_INVALID_HANDLE;
        tok = process_token(t);
        if (!tok) { proc_unref(pref); return STATUS_NO_MEMORY; }
        ob_ref(tok);
        st = give_handle(p, tok, a4, (uint32_t)a3, 0);
        proc_unref(pref);
        return st;
    }
    case SHZ_TOK_OPEN_THREAD: {
        thread_t *t = 0;
        kobject_t *to = 0, *tok;
        uint64_t f;
        if (a2 == CURRENT_THREAD_HANDLE) t = thread_current();
        else if (handle_ref(p, a2, OB_THREAD, &to, 0)) return STATUS_INVALID_HANDLE;
        f = irq_save();
        if (to) t = to->u.thr.t;
        tok = t ? t->impersonation : 0;
        if (tok) ob_ref(tok);
        irq_restore(f);
        if (to) ob_deref(to);
        if (!tok) return STATUS_NO_TOKEN;
        return give_handle(p, tok, a4, (uint32_t)a3, 0);
    }
    case SHZ_TOK_QUERY: {
        kobject_t *tok;
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, 0);
        if (st) return st;
        if (a4 < sizeof(shz_token_info)) st = STATUS_INFO_LENGTH_MISMATCH;
        else if (copy_to_user(p, a3, tok->u.token.t, sizeof(shz_token_info))) st = STATUS_ACCESS_VIOLATION;
        ob_deref(tok);
        return st;
    }
    case SHZ_TOK_SET: {
        kobject_t *tok;
        shz_token_info *t;
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, 0);
        if (st) return st;
        t = tok->u.token.t;
        if (a3 == SHZ_TOKF_INTEGRITY) {
            if (a4 > t->integrity_rid) st = STATUS_ACCESS_DENIED;          /* integrity can only be lowered (no privilege to raise it) */
            else { t->integrity_rid = (uint32_t)a4; t->modified_id = ++next_luid; }
        } else if (a3 == SHZ_TOKF_SESSION) {
            if (a4 != t->session) st = STATUS_ACCESS_DENIED;               /* needs SeTcbPrivilege, which nobody holds here */
        } else if (a3 == SHZ_TOKF_PRIVS) {
            t->flags = (uint32_t)a4;                                       /* advapi32's enabled-privilege toggles (token.c) */
            t->modified_id = ++next_luid;
        } else {
            st = STATUS_INVALID_INFO_CLASS;
        }
        ob_deref(tok);
        return st;
    }
    case SHZ_TOK_DUPLICATE: {
        kobject_t *tok, *nt;
        shz_token_info copy;
        int32_t st = handle_ref(p, a2, OB_TOKEN, &tok, 0);
        if (st) return st;
        copy = *(shz_token_info *)tok->u.token.t;
        ob_deref(tok);
        copy.type = (uint32_t)(a3 & 0xff) ? (uint32_t)(a3 & 0xff) : copy.type;
        copy.imp_level = (uint32_t)(a3 >> 8) & 0xff;
        if (copy.type != 1 && copy.type != 2) return STATUS_INVALID_PARAMETER;
        nt = token_new(&copy, copy.owner_pid);
        if (!nt) return STATUS_NO_MEMORY;
        return give_handle(p, nt, a4, 0xf01ff, 0);
    }
    case SHZ_TOK_IMPERSONATE: {
        thread_t *t = 0;
        kobject_t *to = 0, *tok = 0, *old;
        uint64_t f;
        if (a3) {
            int32_t st = handle_ref(p, a3, OB_TOKEN, &tok, 0);
            if (st) return st;
            if (((shz_token_info *)tok->u.token.t)->type != 2) { ob_deref(tok); return (int32_t)0xC000005C; }   /* STATUS_BAD_TOKEN_TYPE */
        }
        if (!a2 || a2 == CURRENT_THREAD_HANDLE) t = thread_current();
        else if (handle_ref(p, a2, OB_THREAD, &to, 0)) { if (tok) ob_deref(tok); return STATUS_INVALID_HANDLE; }
        f = irq_save();
        if (to) t = to->u.thr.t;
        if (!t) { irq_restore(f); if (to) ob_deref(to); if (tok) ob_deref(tok); return STATUS_THREAD_IS_TERMINATING; }
        old = t->impersonation;
        t->impersonation = tok;                                             /* the reference moves to the thread */
        irq_restore(f);
        if (old) ob_deref(old);
        if (to) ob_deref(to);
        return STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- security descriptors */
static int32_t sys_security(process_t *p, struct regs *r, uint64_t op, uint64_t h, uint64_t buf, uint64_t len)
{
    kobject_t *o;
    int32_t st;
    if (h == CURRENT_PROCESS_HANDLE) { o = p->object; ob_ref(o); }
    else if (h == CURRENT_THREAD_HANDLE) { o = thread_current()->object; ob_ref(o); }
    else if ((st = handle_ref(p, h, 0, &o, 0))) return st;
    if (op == SHZ_SOB_QUERY) {
        const uint64_t pneed = (uint64_t)stack_arg(p, r, 5);
        void *sd;
        uint32_t n;
        const uint64_t f = irq_save();
        sd = o->sd;
        n = o->sd_len;
        irq_restore(f);
        if (!sd) st = STATUS_NOT_FOUND;                                     /* never set: advapi32 reports the default */
        else {
            uint8_t *copy = kmalloc(n);
            if (!copy) st = STATUS_NO_MEMORY;
            else {
                const uint64_t f2 = irq_save();
                if (o->sd && o->sd_len == n) memcpy(copy, o->sd, n); else n = 0;
                irq_restore(f2);
                if (pneed) copy_to_user(p, pneed, &n, 4);
                if (!n) st = STATUS_NOT_FOUND;
                else if (len < n) st = STATUS_BUFFER_TOO_SMALL;
                else st = copy_to_user(p, buf, copy, n) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
                kfree(copy);
            }
        }
    } else if (op == SHZ_SOB_SET) {
        uint8_t *copy;
        void *old;
        if (len < 20 || len > 65536) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
        copy = kmalloc(len);
        if (!copy) st = STATUS_NO_MEMORY;
        else if (copy_from_user(p, copy, buf, len)) { kfree(copy); st = STATUS_ACCESS_VIOLATION; }
        else {
            const uint64_t f = irq_save();
            old = o->sd;
            o->sd = copy;
            o->sd_len = (uint32_t)len;
            irq_restore(f);
            kfree(old);
            st = STATUS_SUCCESS;
        }
    } else {
        st = STATUS_INVALID_PARAMETER;
    }
    ob_deref(o);
    return st;
}

/* ---------------------------------------------------------------- dispatch 0x95-0x9e */
int32_t sys_ext_k32_obj(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (num) {
    case SYS_NtShzSection: return sys_section(p, r, a1, a2, a3, a4);
    case SYS_NtShzIoCompletion: return sys_iocp(p, r, a1, a2, a3, a4);
    case SYS_NtCreateNamedPipeFile: return npfs_create(p, r, a1, a2, a3, a4);
    case SYS_NtFsControlFile: {
        int32_t st;
        if (npfs_fsctl(p, r, a1, &st)) return st;
        return handle_lookup(p, a1, 0) ? STATUS_INVALID_DEVICE_REQUEST : STATUS_INVALID_HANDLE;
    }
    case SYS_NtReadVirtualMemory: return sys_rw_vm(p, r, a1, a2, a3, a4, 0);
    case SYS_NtWriteVirtualMemory: return sys_rw_vm(p, r, a1, a2, a3, a4, 1);
    case SYS_NtShzJob: return sys_job(p, r, a1, a2, a3, a4);
    case SYS_NtSetInformationObject: {                                     /* (handle, class, buffer, length) */
        uint8_t v[2];
        if (a2 != 4) return STATUS_INVALID_INFO_CLASS;                     /* ObjectHandleFlagInformation only */
        if (a4 < 2) return STATUS_INFO_LENGTH_MISMATCH;
        if ((a1 & 3) || !a1 || a1 > MAX_HANDLES * 4ull || !p->handles[a1 / 4 - 1].obj) return STATUS_INVALID_HANDLE;
        if (copy_from_user(p, v, a3, 2)) return STATUS_ACCESS_VIOLATION;
        p->handles[a1 / 4 - 1].inherit = (v[0] ? 1u : 0u) | (v[1] ? 2u : 0u);
        return STATUS_SUCCESS;
    }
    case SYS_NtShzToken: return sys_token(p, r, a1, a2, a3, a4);
    case SYS_NtShzSecurityObject: return sys_security(p, r, a1, a2, a3, a4);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}

/* ---------------------------------------------------------------- base NT services (numbers < 0x50, from sysx.c) */
/* Parks the current thread while it is suspended (called on the way back to user mode: syscall exit, timer tick). */
void thread_park_if_suspended(void)
{
    thread_t *t = thread_current();
    uint64_t f;
    if (!t->suspend_count || !t->proc || t->proc->terminated) return;
    f = irq_save();
    while (t->suspend_count && !t->proc->terminated) {
        t->parked = 1;
        thread_block_current();
        t->parked = 0;
    }
    irq_restore(f);
}

static thread_t *thread_of_handle(process_t *p, uint64_t h, kobject_t **ref)
{
    *ref = 0;
    if (h == CURRENT_THREAD_HANDLE) return thread_current();
    if (handle_ref(p, h, OB_THREAD, ref, 0)) return 0;
    return (*ref)->u.thr.t;
}

int32_t sys_k32_base(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r;
    switch (num) {
    case SYS_NtOpenProcess: {                                              /* (PHANDLE, ACCESS, OA, CLIENT_ID *) */
        uint64_t cid[2];
        process_t *t;
        int inherit = 0;
        char name[4];
        if (!a4 || copy_from_user(p, cid, a4, 16)) return STATUS_INVALID_PARAMETER;
        oa_name(p, a3, name, sizeof name, &inherit);
        t = process_by_pid((int)cid[0]);
        if (!t || !t->object) return STATUS_INVALID_CID;
        ob_ref(t->object);
        return give_handle(p, t->object, a1, (uint32_t)a2, inherit);
    }
    case SYS_NtOpenThread: {                                               /* (PHANDLE, ACCESS, OA, CLIENT_ID *) */
        uint64_t cid[2];
        unsigned i;
        thread_t *t;
        kobject_t *o = 0;
        int inherit = 0;
        char name[4];
        uint64_t f;
        if (!a4 || copy_from_user(p, cid, a4, 16)) return STATUS_INVALID_PARAMETER;
        oa_name(p, a3, name, sizeof name, &inherit);
        f = irq_save();
        for (i = 0; (t = thread_slot(i)) != 0; ++i)
            if (t->proc && t->tid == cid[1] && t->state != TS_FREE && t->state != TS_ZOMBIE && t->object &&
                (!cid[0] || (uint64_t)t->proc->pid == cid[0])) { o = t->object; ob_ref(o); break; }
        irq_restore(f);
        if (!o) return STATUS_INVALID_CID;
        return give_handle(p, o, a1, (uint32_t)a2, inherit);
    }
    case SYS_NtSuspendThread: case SYS_NtResumeThread: {                   /* (ThreadHandle, PULONG PreviousSuspendCount) */
        kobject_t *ref;
        thread_t *t = thread_of_handle(p, a1, &ref);
        uint32_t prev;
        uint64_t f;
        if (!t) { if (ref) ob_deref(ref); return ref ? STATUS_THREAD_IS_TERMINATING : STATUS_INVALID_HANDLE; }
        f = irq_save();
        if (t->state == TS_ZOMBIE || t->state == TS_FREE) { irq_restore(f); if (ref) ob_deref(ref); return STATUS_THREAD_IS_TERMINATING; }
        prev = t->suspend_count;
        if (num == SYS_NtSuspendThread) {
            if (prev >= 127) { irq_restore(f); if (ref) ob_deref(ref); return STATUS_SUSPEND_COUNT_EXCEEDED; }
            ++t->suspend_count;
        } else if (prev) {
            if (--t->suspend_count == 0) {
                if (t->state == TS_NEW) thread_resume(t);                   /* created suspended: first run */
                else if (t->parked && t->state == TS_BLOCKED) thread_wake(t);
            }
        }
        irq_restore(f);
        if (ref) ob_deref(ref);
        if (a2 && copy_to_user(p, a2, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        if (num == SYS_NtSuspendThread && t == thread_current()) thread_park_if_suspended();
        return STATUS_SUCCESS;
    }
    default: return STATUS_NOT_IMPLEMENTED;
    }
}

/* NtDuplicateObject(SourceProcess, SourceHandle, TargetProcess, PHANDLE Target, Access, HandleAttributes, Options) */
int32_t sys_duplicate_object(process_t *p, struct regs *r, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    uint32_t access = (uint32_t)stack_arg(p, r, 5);
    const uint32_t attrs = (uint32_t)stack_arg(p, r, 6), options = (uint32_t)stack_arg(p, r, 7);
    kobject_t *sref, *tref = 0, *o;
    process_t *src = proc_ref_of(p, a1, &sref), *dst = 0;
    int32_t st = STATUS_SUCCESS;
    uint32_t h;
    if (!src) return STATUS_INVALID_HANDLE;
    if (a2 == CURRENT_PROCESS_HANDLE) { o = src->object; ob_ref(o); access = (options & 2) ? 0x1fffff : access; }
    else if (a2 == CURRENT_THREAD_HANDLE && src == p) { o = thread_current()->object; ob_ref(o); access = (options & 2) ? 0x1fffff : access; }
    else {
        uint32_t sacc = 0;
        st = handle_ref(src, a2, 0, &o, &sacc);
        if (st) { proc_unref(sref); return st; }
        if (options & 2) access = sacc;                                    /* DUPLICATE_SAME_ACCESS */
    }
    if (a3) {
        dst = proc_ref_of(p, a3, &tref);
        if (!dst) st = STATUS_INVALID_HANDLE;
    }
    if (!st && dst && a4) {
        st = handle_insert(dst, o, access, &h);
        if (!st) {
            uint64_t v = h;
            uint32_t inh = (attrs & 2) ? 1 : 0;
            if ((options & 4) && !(a2 & 3) && a2 != CURRENT_PROCESS_HANDLE && a2 != CURRENT_THREAD_HANDLE)
                inh = src->handles[a2 / 4 - 1].inherit & 1;                 /* DUPLICATE_SAME_ATTRIBUTES */
            dst->handles[h / 4 - 1].inherit = inh;
            if (copy_to_user(p, a4, &v, 8)) { handle_close(dst, h); st = STATUS_ACCESS_VIOLATION; }
        }
    } else if (!st && !a4 && !(options & 1)) {
        st = STATUS_INVALID_PARAMETER;
    }
    ob_deref(o);
    if ((options & 1) && !(a2 & 3) && a2 != CURRENT_PROCESS_HANDLE && a2 != CURRENT_THREAD_HANDLE)
        handle_close(src, a2);                                             /* DUPLICATE_CLOSE_SOURCE: whatever happened */
    proc_unref(tref);
    proc_unref(sref);
    return st;
}
