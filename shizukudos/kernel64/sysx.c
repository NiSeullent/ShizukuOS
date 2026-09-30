/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system calls for kernel objects, threads, information queries, time and process
 * creation. Structures use the Windows x64 layouts the ntdll layer expects.
 */
#include "fs.h"
#include "pci.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
extern int32_t sysfile_dispatch(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                                uint64_t a4, int *handled);
extern void process_thread_gone(process_t *p);
extern void ob_register_timer(kobject_t *o);
extern int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread);
extern int32_t sysext_dispatch(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
extern int32_t ldr_load_module_runtime(process_t *p, const char *name, uint32_t flags, const char *dirs, uint64_t *base_out);
extern uint64_t ldr_module_export(process_t *p, uint64_t base, const char *symbol, uint64_t ordinal);

struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };

static int32_t object_name(process_t *p, uint64_t oa_va, char *out, size_t cap)
{
    struct objattr oa;
    struct ustr u;
    uint16_t tmp[OB_NAME_MAX];
    out[0] = 0;
    if (!oa_va) return STATUS_SUCCESS;
    if (copy_from_user(p, &oa, oa_va, sizeof oa)) return STATUS_ACCESS_VIOLATION;
    if (!oa.name) return STATUS_SUCCESS;
    if (copy_from_user(p, &u, oa.name, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if (u.length / 2 >= OB_NAME_MAX) return STATUS_OBJECT_NAME_INVALID;
    if (u.length && copy_from_user(p, tmp, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
    return utf16_to_utf8(tmp, u.length / 2, out, cap) < 0 ? STATUS_OBJECT_NAME_INVALID : STATUS_SUCCESS;
}

static int32_t give_handle(process_t *p, kobject_t *o, uint64_t user_ptr, uint32_t access)
{
    uint32_t h;
    int32_t st = handle_insert(p, o, access, &h);
    uint64_t v = h;
    ob_deref(o);
    if (st) return st;
    if (copy_to_user(p, user_ptr, &v, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

/* give_handle for a created or opened object whose OBJECT_ATTRIBUTES (at oa_va, may be 0) can ask for OBJ_INHERIT (0x2):
 * the handle is then marked inheritable (CreateEventW & co. with SECURITY_ATTRIBUTES.bInheritHandle). */
static int32_t give_handle_oa(process_t *p, kobject_t *o, uint64_t user_ptr, uint32_t access, uint64_t oa_va)
{
    struct objattr oa;
    uint64_t v = 0;
    int32_t st;
    if (oa_va && copy_from_user(p, &oa, oa_va, sizeof oa)) { ob_deref(o); return STATUS_ACCESS_VIOLATION; }
    st = give_handle(p, o, user_ptr, access);
    if (st || !oa_va || !(oa.attributes & 2)) return st;
    if (copy_from_user(p, &v, user_ptr, 8) == 0 && v && !(v & 3) && v <= MAX_HANDLES * 4ull) p->handles[v / 4 - 1].inherit |= 1;
    return STATUS_SUCCESS;
}

static kobject_t *object_for_handle(process_t *p, uint64_t h)
{
    if (h == CURRENT_PROCESS_HANDLE) { ob_ref(p->object); return p->object; }
    if (h == CURRENT_THREAD_HANDLE) { ob_ref(thread_current()->object); return thread_current()->object; }
    {
        kobject_t *o = handle_lookup(p, h, 0);
        if (o) ob_ref(o);
        return o;
    }
}

int64_t filetime_now(void)
{
    /* FILETIME epoch 1601; wall clock comes from the Supervisor (real RTC in the platform). */
    hcreg_t secs = 0;
    shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
    return (int64_t)(secs + 11644473600ull) * 10000000ll + (int64_t)((shz_time_ns() % 1000000000ull) / 100);
}

int32_t sys_extended(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int handled = 0;
    int32_t st = sysfile_dispatch(p, r, num, a1, a2, a3, a4, &handled);
    if (handled) return st;
    switch (num) {
    case SYS_NtCreateEvent: {                              /* (PHANDLE, ACCESS, OA, EVENT_TYPE, BOOLEAN initial) */
        char name[OB_NAME_MAX];
        kobject_t *o;
        st = object_name(p, a3, name, sizeof name);
        if (st) return st;
        if (name[0] && (o = ob_find_named(OB_EVENT, name))) {
            if (o->type != OB_EVENT) return STATUS_OBJECT_TYPE_MISMATCH;
            ob_ref(o);
            st = give_handle_oa(p, o, a1, (uint32_t)a2, a3);
            return st ? st : (int32_t)0x40000000;          /* STATUS_OBJECT_NAME_EXISTS */
        }
        o = ob_create(OB_EVENT, name);
        if (!o) return STATUS_NO_MEMORY;
        o->u.event.manual = a4 == 0;                       /* NotificationEvent = manual reset */
        o->signaled = (int)(stack_arg(p, r, 5) & 0xff) != 0;
        return give_handle_oa(p, o, a1, (uint32_t)a2, a3);
    }
    case SYS_NtSetEvent: case SYS_NtResetEvent: {
        kobject_t *o = handle_lookup(p, a1, OB_EVENT);
        int32_t prev;
        if (!o) return STATUS_INVALID_HANDLE;
        prev = o->signaled;
        if (num == SYS_NtSetEvent) ob_signal_event(o); else ob_reset_event(o);
        if (a2 && copy_to_user(p, a2, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SYS_NtQueryEvent: {
        kobject_t *o = handle_lookup(p, a1, OB_EVENT);
        uint32_t v[2];
        if (!o) return STATUS_INVALID_HANDLE;
        v[0] = o->u.event.manual ? 0 : 1; v[1] = (uint32_t)o->signaled;
        if (a4 < 8 && a3) return STATUS_BUFFER_TOO_SMALL;
        return copy_to_user(p, a3, v, 8) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    case SYS_NtCreateMutant: {                              /* (PHANDLE, ACCESS, OA, BOOLEAN initial owner) */
        char name[OB_NAME_MAX];
        kobject_t *o;
        st = object_name(p, a3, name, sizeof name);
        if (st) return st;
        if (name[0] && (o = ob_find_named(OB_MUTANT, name))) {
            ob_ref(o);
            st = give_handle_oa(p, o, a1, (uint32_t)a2, a3);
            return st ? st : (int32_t)0x40000000;
        }
        o = ob_create(OB_MUTANT, name);
        if (!o) return STATUS_NO_MEMORY;
        o->signaled = 1;
        if (a4 & 0xff) { o->u.mutant.owner = thread_current(); o->u.mutant.recursion = 1; o->signaled = 0; }
        return give_handle_oa(p, o, a1, (uint32_t)a2, a3);
    }
    case SYS_NtReleaseMutant: {
        kobject_t *o = handle_lookup(p, a1, OB_MUTANT);
        uint64_t f;
        int32_t prev;
        if (!o) return STATUS_INVALID_HANDLE;
        f = irq_save();
        if (o->u.mutant.owner != thread_current()) { irq_restore(f); return STATUS_MUTANT_NOT_OWNED; }
        prev = o->u.mutant.recursion;
        if (--o->u.mutant.recursion == 0) {
            o->u.mutant.owner = 0;
            o->signaled = 1;
            ob_release_check(o);
        }
        irq_restore(f);
        if (a2 && copy_to_user(p, a2, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SYS_NtCreateSemaphore: {                           /* (PHANDLE, ACCESS, OA, LONG initial, LONG max) */
        char name[OB_NAME_MAX];
        kobject_t *o;
        const int32_t initial = (int32_t)a4, maxc = (int32_t)stack_arg(p, r, 5);
        if (maxc <= 0 || initial < 0 || initial > maxc) return STATUS_INVALID_PARAMETER;
        st = object_name(p, a3, name, sizeof name);
        if (st) return st;
        if (name[0] && (o = ob_find_named(OB_SEMAPHORE, name))) {
            ob_ref(o);
            st = give_handle_oa(p, o, a1, (uint32_t)a2, a3);
            return st ? st : (int32_t)0x40000000;
        }
        o = ob_create(OB_SEMAPHORE, name);
        if (!o) return STATUS_NO_MEMORY;
        o->u.sem.count = initial;
        o->u.sem.max = maxc;
        o->signaled = initial > 0;
        return give_handle_oa(p, o, a1, (uint32_t)a2, a3);
    }
    case SYS_NtReleaseSemaphore: {                          /* (handle, LONG count, PLONG previous) */
        kobject_t *o = handle_lookup(p, a1, OB_SEMAPHORE);
        int32_t prev;
        uint64_t f;
        if (!o) return STATUS_INVALID_HANDLE;
        if ((int32_t)a2 <= 0) return STATUS_INVALID_PARAMETER;
        f = irq_save();
        prev = o->u.sem.count;
        if (o->u.sem.count + (int32_t)a2 > o->u.sem.max || o->u.sem.count + (int32_t)a2 < o->u.sem.count) {
            irq_restore(f);
            return STATUS_SEMAPHORE_LIMIT_EXCEEDED;
        }
        o->u.sem.count += (int32_t)a2;
        o->signaled = 1;
        {
            int32_t n;
            for (n = 0; n < (int32_t)a2 && o->u.sem.count > 0; ++n)
                ob_release_check(o);
        }
        irq_restore(f);
        if (a3 && copy_to_user(p, a3, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SYS_NtCreateTimer: {                               /* (PHANDLE, ACCESS, OA, TIMER_TYPE 0=notification 1=sync) */
        char name[OB_NAME_MAX];
        kobject_t *o;
        extern void ob_register_timer(kobject_t *);
        st = object_name(p, a3, name, sizeof name);
        if (st) return st;
        if (a4 > 1) return STATUS_INVALID_PARAMETER;
        if (name[0] && (o = ob_find_named(OB_TIMER, name))) {
            if (o->type != OB_TIMER) return STATUS_OBJECT_TYPE_MISMATCH;
            ob_ref(o);
            st = give_handle_oa(p, o, a1, (uint32_t)a2, a3);
            return st ? st : (int32_t)0x40000000;          /* STATUS_OBJECT_NAME_EXISTS */
        }
        o = ob_create(OB_TIMER, name);
        if (!o) return STATUS_NO_MEMORY;
        o->u.timer.manual = a4 == 0;
        ob_register_timer(o);
        return give_handle_oa(p, o, a1, (uint32_t)a2, a3);
    }
    case SYS_NtSetTimer: {
        /* (handle, PLARGE_INTEGER due, ApcRoutine, ApcContext, BOOLEAN resume, LONG period ms, PBOOLEAN previous state).
         * due < 0: relative (100 ns), due > 0: absolute FILETIME, due == 0: now. Completion routines need APCs, which Kernel64
         * does not deliver: a non-NULL routine is refused. The resume flag has no meaning without a sleep state. */
        kobject_t *o = handle_lookup(p, a1, OB_TIMER);
        int64_t due;
        const int32_t period = (int32_t)stack_arg(p, r, 6);
        const uint64_t pprev = (uint64_t)stack_arg(p, r, 7);
        uint64_t ms, f;
        uint8_t prev;
        if (!o) return STATUS_INVALID_HANDLE;
        if (a3) return STATUS_NOT_SUPPORTED;
        if (period < 0) return STATUS_INVALID_PARAMETER;
        if (copy_from_user(p, &due, a2, 8)) return STATUS_ACCESS_VIOLATION;
        if (due < 0) ms = ((uint64_t)(-due) + 9999) / 10000;
        else if (due > 0) { const int64_t now = filetime_now(); ms = due > now ? ((uint64_t)(due - now) + 9999) / 10000 : 0; }
        else ms = 0;
        f = irq_save();
        prev = (uint8_t)o->signaled;
        o->signaled = 0;
        o->u.timer.period_ms = period > 0 ? (uint64_t)period : 0;
        o->u.timer.due_tick = ticks_now() + (ms ? ms : 1);
        o->u.timer.armed = 1;
        irq_restore(f);
        if (pprev) copy_to_user(p, pprev, &prev, 1);
        return STATUS_SUCCESS;
    }
    case SYS_NtCancelTimer: {                               /* (handle, PBOOLEAN current state) */
        kobject_t *o = handle_lookup(p, a1, OB_TIMER);
        uint8_t cur;
        if (!o) return STATUS_INVALID_HANDLE;
        o->u.timer.armed = 0;
        cur = (uint8_t)o->signaled;
        if (a2) copy_to_user(p, a2, &cur, 1);
        return STATUS_SUCCESS;
    }
    case SYS_NtWaitForSingleObject: {                       /* (handle, BOOLEAN alertable, PLARGE_INTEGER timeout) */
        kobject_t *o = object_for_handle(p, a1);
        int64_t to = INT64_MAX;
        if (!o) return STATUS_INVALID_HANDLE;
        if (a3 && copy_from_user(p, &to, a3, 8)) { ob_deref(o); return STATUS_ACCESS_VIOLATION; }
        if (a3 && to > 0) to = -to;                          /* absolute times are not supported: treat as relative */
        st = ob_wait(p, &o, 1, 0, to, (int)(a2 & 0xff));
        ob_deref(o);
        return st;
    }
    case SYS_NtWaitForMultipleObjects: {                    /* (count, handles, type 0=all 1=any, alertable, timeout) */
        uint64_t hs[64];
        kobject_t *objs[64];
        unsigned i, n = (unsigned)a1;
        int64_t to = INT64_MAX;
        const uint64_t pto = (uint64_t)stack_arg(p, r, 5);
        if (!n || n > 64) return STATUS_INVALID_PARAMETER;
        if (copy_from_user(p, hs, a2, n * 8ull)) return STATUS_ACCESS_VIOLATION;
        if (pto && copy_from_user(p, &to, pto, 8)) return STATUS_ACCESS_VIOLATION;
        if (pto && to > 0) to = -to;
        for (i = 0; i < n; ++i) {
            objs[i] = object_for_handle(p, hs[i]);
            if (!objs[i]) { while (i--) ob_deref(objs[i]); return STATUS_INVALID_HANDLE; }
        }
        st = ob_wait(p, objs, n, a3 == 0, to, (int)(a4 & 0xff));
        for (i = 0; i < n; ++i) ob_deref(objs[i]);
        return st;
    }
    case SYS_NtDuplicateObject: {                           /* (srcproc, srchandle, dstproc, PHANDLE dst, access, attrs, options) */
        extern int32_t sys_duplicate_object(process_t *p, struct regs *r, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
        return sys_duplicate_object(p, r, a1, a2, a3, a4);  /* sysk32_obj.c: any source and target process */
    }
    case SYS_NtCreateThreadEx: {
        /* (PHANDLE, ACCESS, OA, ProcessHandle, StartRoutine, Argument, Flags, ZeroBits, StackSize, MaxStack, Attr) */
        /* Flags: THREAD_CREATE_FLAGS_CREATE_SUSPENDED (1) leaves the thread suspended until NtResumeThread. The target may be
         * another process (CreateRemoteThread): the thread starts at ntdll's thread entry of that process. */
        thread_t *t = 0;
        const uint64_t start = (uint64_t)stack_arg(p, r, 5), arg = (uint64_t)stack_arg(p, r, 6);
        const uint64_t flags = (uint64_t)stack_arg(p, r, 7);
        extern int process_start_thread3(process_t *p, uint64_t rip, uint64_t rcx, uint64_t rdx, uint64_t stack_size, int suspended,
                                         thread_t **out);
        process_t *target = a4 == CURRENT_PROCESS_HANDLE ? p : 0;
        kobject_t *pref = 0;
        int rc;
        if (!target) {
            if (handle_ref(p, a4, OB_PROCESS, &pref, 0)) return STATUS_INVALID_HANDLE;
            target = pref->u.proc.p;
            if (!target || !target->used || target->object != pref) { ob_deref(pref); return STATUS_INVALID_HANDLE; }
            if (target->terminated) { ob_deref(pref); return STATUS_PROCESS_IS_TERMINATING; }
        }
        if (!start) { if (pref) ob_deref(pref); return STATUS_INVALID_PARAMETER; }
        if (!target->ntdll_thread_start) { if (pref) ob_deref(pref); return STATUS_NOT_SUPPORTED; }   /* not started by the loader */
        rc = process_start_thread3(target, target->ntdll_thread_start, start, arg, (uint64_t)stack_arg(p, r, 9), (flags & 1) != 0, &t);
        if (pref) ob_deref(pref);
        if (rc) return STATUS_NO_MEMORY;
        {
            kobject_t *to = t->object;
            ob_ref(to);
            thread_creator_release(t);                      /* from here on only the object is used */
            return give_handle(p, to, a1, (uint32_t)a2);
        }
    }
    case SYS_NtQuerySystemTime: {
        int64_t t = filetime_now();
        return copy_to_user(p, a1, &t, 8) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    case SYS_NtQueryInformationProcess: {                   /* (handle, class, buf, len, retlen) */
        process_t *t = a1 == CURRENT_PROCESS_HANDLE ? p : 0;
        if (!t) { kobject_t *o = handle_lookup(p, a1, OB_PROCESS); t = o ? o->u.proc.p : 0; }
        if (!t) return STATUS_INVALID_HANDLE;
        if (a2 == 0) {                                      /* ProcessBasicInformation */
            struct { int64_t exit_status; uint64_t peb; uint64_t affinity; int64_t base_priority; uint64_t pid; uint64_t ppid; } b;
            if (a4 < sizeof b) return STATUS_BUFFER_TOO_SMALL;
            b.exit_status = t->terminated ? t->exit_code : 0x103;      /* STATUS_PENDING == STILL_ACTIVE */
            b.peb = t->peb; b.affinity = 1; b.base_priority = 8; b.pid = (uint64_t)t->pid; b.ppid = t->parent_pid;
            if (copy_to_user(p, a3, &b, sizeof b)) return STATUS_ACCESS_VIOLATION;
            if (stack_arg(p, r, 5)) { uint32_t n = sizeof b; copy_to_user(p, (uint64_t)stack_arg(p, r, 5), &n, 4); }
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_INFO_CLASS;
    }
    case SYS_NtQueryInformationThread: {
        thread_t *t = a1 == CURRENT_THREAD_HANDLE ? thread_current() : 0;
        kobject_t *to = 0;
        if (!t && !(to = handle_lookup(p, a1, OB_THREAD))) return STATUS_INVALID_HANDLE;
        if (a2 == 0) {                                      /* ThreadBasicInformation */
            struct { int64_t exit_status; uint64_t teb; uint64_t pid, tid; uint64_t affinity; int32_t prio, base; } b;
            uint64_t f;
            if (a4 < sizeof b) return STATUS_BUFFER_TOO_SMALL;
            f = irq_save();                                 /* an exited thread may be reclaimed (sched.c) at any preemption */
            if (to) t = to->u.thr.t;
            if (t) {
                b.exit_status = t->state == TS_ZOMBIE ? t->exit_code : 0x103;
                b.teb = t->teb; b.pid = t->proc ? (uint64_t)t->proc->pid : (uint64_t)p->pid; b.tid = t->tid;
            } else {                                        /* exited and reclaimed: the object kept what is still defined */
                b.exit_status = to->u.thr.exit_code;
                b.teb = 0; b.pid = to->u.thr.pid; b.tid = to->u.thr.tid;
            }
            irq_restore(f);
            b.affinity = 1; b.prio = 8; b.base = 8;
            if (copy_to_user(p, a3, &b, sizeof b)) return STATUS_ACCESS_VIOLATION;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_INFO_CLASS;
    }
    case SYS_NtSetInformationProcess: return STATUS_INVALID_INFO_CLASS;   /* nothing settable yet; entry points come from ntdll exports */
    case SYS_NtSetInformationThread: return STATUS_SUCCESS;             /* priorities, names: accepted, no effect */
    case SYS_NtCreateProcessEx: {
        /* (PHANDLE proc, PHANDLE thread, PUNICODE path, PUNICODE cmd, PUNICODE cwd, struct shz_process_ex *ext). The extension
         * block (kernel32 CreateProcessW) carries: flags 1 CREATE_SUSPENDED, 2 inherit handles, 4 break away from the job,
         * 8 standard handles given; the environment block; PROC_THREAD_ATTRIBUTE_HANDLE_LIST; the three standard handles. */
        struct { uint32_t size, flags; uint64_t env, env_bytes, handle_list; uint32_t handle_count, pad; uint64_t std[3]; } ext;
        const uint64_t pcwd = (uint64_t)stack_arg(p, r, 5), pext = (uint64_t)stack_arg(p, r, 6);
        enum { CMD_MAX = 4096 };
        struct ustr u;
        uint16_t *w = kmalloc(CMD_MAX * 2 + 2);
        char *path = kmalloc(600), *cmd = kmalloc(CMD_MAX * 3 + 1), cwd[260];
        uint16_t *env = 0;
        uint64_t hl[64];
        ldr_proc_opts_t opts;
        process_t *np = 0;
        thread_t *nt = 0;
        cwd[0] = 0;
        memset(&opts, 0, sizeof opts);
        st = STATUS_SUCCESS;
        if (!w || !path || !cmd) { st = STATUS_NO_MEMORY; goto cp_done; }
        if (copy_from_user(p, &u, a3, sizeof u) || u.length > 598 || copy_from_user(p, w, u.buffer, u.length)) { st = STATUS_ACCESS_VIOLATION; goto cp_done; }
        if (utf16_to_utf8(w, u.length / 2, path, 600) < 0) { st = STATUS_OBJECT_NAME_INVALID; goto cp_done; }
        cmd[0] = 0;
        if (a4) {
            if (copy_from_user(p, &u, a4, sizeof u) || u.length > CMD_MAX * 2) { st = STATUS_ACCESS_VIOLATION; goto cp_done; }
            if (u.length && copy_from_user(p, w, u.buffer, u.length)) { st = STATUS_ACCESS_VIOLATION; goto cp_done; }
            if (utf16_to_utf8(w, u.length / 2, cmd, CMD_MAX * 3 + 1) < 0) { st = STATUS_INVALID_PARAMETER; goto cp_done; }
        }
        if (pcwd) {
            if (copy_from_user(p, &u, pcwd, sizeof u) || u.length > 500 || (u.length && copy_from_user(p, w, u.buffer, u.length))) {
                st = STATUS_ACCESS_VIOLATION;
                goto cp_done;
            }
            if (utf16_to_utf8(w, u.length / 2, cwd, sizeof cwd) < 0) { st = STATUS_OBJECT_PATH_NOT_FOUND; goto cp_done; }
        }
        if (pext) {
            if (copy_from_user(p, &ext, pext, sizeof ext) || ext.size < sizeof ext) { st = STATUS_INVALID_PARAMETER; goto cp_done; }
            opts.suspended = (ext.flags & 1) != 0;
            opts.inherit = (ext.flags & 2) != 0;
            opts.breakaway = (ext.flags & 4) != 0;
            opts.use_std = (ext.flags & 8) != 0;
            opts.std[0] = ext.std[0]; opts.std[1] = ext.std[1]; opts.std[2] = ext.std[2];
            if (ext.env) {
                if (ext.env_bytes < 4 || ext.env_bytes > 65536 || (ext.env_bytes & 1)) { st = STATUS_INVALID_PARAMETER; goto cp_done; }
                env = kmalloc(ext.env_bytes);
                if (!env) { st = STATUS_NO_MEMORY; goto cp_done; }
                if (copy_from_user(p, env, ext.env, ext.env_bytes)) { st = STATUS_ACCESS_VIOLATION; goto cp_done; }
                opts.env = env;
                opts.env_chars = ext.env_bytes / 2;
            }
            if (ext.handle_list) {
                if (ext.handle_count > 64) { st = STATUS_INVALID_PARAMETER; goto cp_done; }
                if (copy_from_user(p, hl, ext.handle_list, ext.handle_count * 8ull)) { st = STATUS_ACCESS_VIOLATION; goto cp_done; }
                opts.handle_list = hl;
                opts.handle_count = ext.handle_count;
            }
        }
        st = ldr_create_process_ex(p, path, cmd, cwd, pext ? &opts : 0, &np, &nt);
        if (st) goto cp_done;
        {
            kobject_t *to = nt->object;
            ob_ref(to);
            thread_creator_release(nt);                     /* from here on only the thread object is used */
            ob_ref(np->object);
            st = give_handle(p, np->object, a1, 0x1fffff);
            if (!st && a2) { ob_ref(to); st = give_handle(p, to, a2, 0x1fffff); }
            ob_deref(to);
        }
cp_done:
        kfree(w); kfree(path); kfree(cmd); kfree(env);
        return st;
    }
    case SYS_NtLoadImage: {
        /* (PUNICODE name, PULONG64 base_out, ULONG flags, PUNICODE dirs): runtime LoadLibrary. flags: LoadLibraryExW
         * flags plus the ntdll search bits of kernel64/ldr.c; dirs: ';'-separated user directories or NULL. */
        struct ustr u;
        uint16_t w[260];
        char name[300], *dirs = 0;
        uint64_t base = 0;
        if (copy_from_user(p, &u, a1, sizeof u) || u.length > sizeof w - 2) return STATUS_ACCESS_VIOLATION;
        if (u.length && copy_from_user(p, w, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
        if (utf16_to_utf8(w, u.length / 2, name, sizeof name) < 0) return STATUS_OBJECT_NAME_INVALID;
        if (a4) {
            uint16_t *wd;
            if (copy_from_user(p, &u, a4, sizeof u) || u.length > 1024) return STATUS_ACCESS_VIOLATION;
            wd = kzalloc(1026);
            dirs = kzalloc(1040);
            if (!wd || !dirs) { kfree(wd); kfree(dirs); return STATUS_NO_MEMORY; }
            if ((u.length && copy_from_user(p, wd, u.buffer, u.length)) || utf16_to_utf8(wd, u.length / 2, dirs, 1040) < 0) {
                kfree(wd); kfree(dirs);
                return STATUS_OBJECT_NAME_INVALID;
            }
            kfree(wd);
        }
        st = ldr_load_module_runtime(p, name, (uint32_t)a3, dirs, &base);
        kfree(dirs);
        if (st) return st;
        return copy_to_user(p, a2, &base, 8) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    case SYS_NtQuerySystemInformation: {                    /* class 0 basic: processors=1, page size; 0x100 Shizuku memory */
        if (a1 == 0) {
            struct { uint32_t reserved, timer_res, page_size, phys_pages, low_page, high_page, alloc_gran; uint64_t min_addr, max_addr, affinity; uint8_t nproc; } b;
            if (a3 < sizeof b) return STATUS_BUFFER_TOO_SMALL;
            memset(&b, 0, sizeof b);
            b.timer_res = 10000; b.page_size = 4096; b.phys_pages = (uint32_t)(mem_ram_top() / 4096); b.alloc_gran = 65536;
            b.low_page = 1; b.high_page = (uint32_t)(mem_ram_top() / 4096);
            b.min_addr = 0x10000; b.max_addr = 0x7ffffffeffffull; b.affinity = 1; b.nproc = 1;
            return copy_to_user(p, a2, &b, sizeof b) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
        }
        if (a1 == 5) {                                      /* SystemProcessInformation (sysk32_proc.c) */
            extern int32_t k32_system_process_information(process_t *cur, uint64_t buf, uint64_t len, uint64_t retlen);
            return k32_system_process_information(p, a2, a3, a4);
        }
        if (a1 == 0x100) {                                  /* private: {total pages, free pages} for GlobalMemoryStatusEx */
            uint64_t m[2];
            if (a3 < sizeof m) return STATUS_BUFFER_TOO_SMALL;
            m[0] = mem_ram_top() / 4096;                    /* RAM the machine has, not only the allocator pool */
            m[1] = pmm_free_count();
            return copy_to_user(p, a2, m, sizeof m) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
        }
        if (a1 == 0x101) {                                  /* private: PCI functions and the kernel driver bound to each */
            uint32_t n = 0;
#ifdef SHZ_STANDALONE                                       /* under the Supervisor the config ports trap: nothing to list */
            struct { uint8_t bus, dev, fn, class_code, subclass, prog_if, irq, pad; uint16_t vendor, device; uint32_t pad2;
                     char driver[24]; } e;
            pci_dev_t all[32];
            const unsigned cnt = pci_enumerate(all, 32);
            unsigned i;
            for (i = 0; i < cnt; ++i) {
                const char *drv = pci_claimed_by(&all[i]);
                unsigned k = 0;
                if ((uint64_t)(n + 1) * sizeof e > a3) return STATUS_BUFFER_TOO_SMALL;
                memset(&e, 0, sizeof e);
                e.bus = all[i].bus; e.dev = all[i].dev; e.fn = all[i].fn;
                e.class_code = all[i].class_code; e.subclass = all[i].subclass; e.prog_if = all[i].prog_if;
                e.irq = all[i].irq_line; e.vendor = all[i].vendor; e.device = all[i].device;
                while (drv && drv[k] && k < sizeof e.driver - 1) { e.driver[k] = drv[k]; ++k; }
                if (copy_to_user(p, a2 + (uint64_t)n * sizeof e, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
                ++n;
            }
#endif
            if (a4 && copy_to_user(p, a4, &n, 4)) return STATUS_ACCESS_VIOLATION;   /* ReturnLength = entry count */
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_INFO_CLASS;
    }
    case SYS_NtContinue: case SYS_NtRaiseException: {
        extern int32_t user_exception_continue(process_t *p, struct regs *r, uint64_t context_va, uint64_t record_va, int is_raise);
        return user_exception_continue(p, r, a1, a2, num == SYS_NtRaiseException);
    }
    case SYS_NtAlertThreadByThreadId: {                     /* (ThreadId) */
        thread_t *t = thread_find_tid(p, a1);
        uint64_t f;
        if (!t) return STATUS_INVALID_CID;
        f = irq_save();
        t->alerted = 1;
        if (t->state == TS_BLOCKED && t->alert_wait)
            thread_wake(t);
        irq_restore(f);
        return STATUS_SUCCESS;
    }
    case SYS_NtWaitForAlertByThreadId: {                    /* (Address, PLARGE_INTEGER timeout) */
        thread_t *t = thread_current();
        int64_t to = INT64_MAX;
        uint64_t f;
        int32_t res;
        if (a2 && copy_from_user(p, &to, a2, 8)) return STATUS_ACCESS_VIOLATION;
        f = irq_save();
        if (t->alerted) { t->alerted = 0; irq_restore(f); return STATUS_ALERTED; }
        if (to == 0) { irq_restore(f); return STATUS_TIMEOUT; }
        t->alert_wait = 1;
        t->wake_tick = (to != INT64_MAX && to < 0) ? ticks_now() + ((uint64_t)(-to) / 10000 * 1000u + TICK_US - 1) / TICK_US + 1 : 0;
        thread_block_current();
        t->alert_wait = 0;
        t->wake_tick = 0;
        if (t->alerted) { t->alerted = 0; res = STATUS_ALERTED; } else res = STATUS_TIMEOUT;
        irq_restore(f);
        return res;
    }
    case SYS_NtGetContextThread: {                          /* (ThreadHandle, PCONTEXT): sysk32.c */
        extern int32_t k32_get_context_thread(process_t *p, uint64_t handle, uint64_t context_va);
        return k32_get_context_thread(p, a1, a2);
    }
    case SYS_NtShzGetTeb: return (int32_t)0;
    default:
        if (num >= 0x50) return sysext_dispatch(p, r, num, a1, a2, a3, a4);
        {   /* NtOpenProcess, NtOpenThread, NtSuspendThread, NtResumeThread (sysk32_obj.c) */
            extern int32_t sys_k32_base(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
            return sys_k32_base(p, r, num, a1, a2, a3, a4);
        }
    }
}
