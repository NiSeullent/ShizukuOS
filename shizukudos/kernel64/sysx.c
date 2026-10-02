/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system calls for kernel objects, threads, information queries, time and process
 * creation. Structures use the Windows x64 layouts the ntdll layer expects.
 */
#include "fs.h"
#include "auth_policy.h"
#include "pci.h"
#include "office_sync_rights.h"

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
extern int32_t ldr_lifetime_control(process_t *, uint64_t, uint64_t, uint64_t, uint64_t);
extern int32_t ldr_lifetime_commit(process_t *, uint64_t);
extern int32_t ipc_section_duplicate_access(kobject_t *, uint32_t, uint32_t *);

struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };

static int32_t object_name(process_t *p, uint64_t oa_va, char *out, size_t cap)
{
    struct objattr oa;
    struct ustr u;
    uint16_t tmp[64];
    out[0] = 0;
    if (!oa_va) return STATUS_SUCCESS;
    if (copy_from_user(p, &oa, oa_va, sizeof oa)) return STATUS_ACCESS_VIOLATION;
    if (!oa.name) return STATUS_SUCCESS;
    if (copy_from_user(p, &u, oa.name, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if (u.length / 2 >= 64) return STATUS_OBJECT_NAME_INVALID;
    if (u.length && copy_from_user(p, tmp, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
    if (u.length / 2 > 6 && (tmp[0] | 32) == 'l' && (tmp[1] | 32) == 'o' && (tmp[2] | 32) == 'c' && (tmp[3] | 32) == 'a' &&
        (tmp[4] | 32) == 'l' && tmp[5] == '\\')          /* "Local\" is this single session's namespace: "x" == "Local\x" */
    { if(utf16_to_utf8(tmp+6,u.length/2-6,out,cap)<0)return STATUS_OBJECT_NAME_INVALID; }
    else if(utf16_to_utf8(tmp,u.length/2,out,cap)<0)return STATUS_OBJECT_NAME_INVALID;
    return shz_auth_object_name(p,out,cap);
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

static kobject_t *object_for_handle_access(process_t *p,uint64_t h,uint32_t *access)
{
    kobject_t *o;
    if(h==CURRENT_PROCESS_HANDLE){if(access)*access=0x1fffffu;ob_ref(p->object);return p->object;}
    if(h==CURRENT_THREAD_HANDLE){if(access)*access=0x1fffffu;ob_ref(thread_current()->object);return thread_current()->object;}
    if(handle_ref(p,h,0,&o,access))return 0;
    if((o->type==OB_PROCESS&&!shz_auth_process_access(p,o->u.proc.p))||
       (o->type==OB_THREAD&&!shz_auth_thread_access(p,o->u.thr.pid))){ob_deref(o);return 0;}
    return o;
}
static kobject_t *object_for_wait(process_t *p,uint64_t h,int32_t *status)
{
    uint32_t access=0;kobject_t *o=object_for_handle_access(p,h,&access);
    if(!o){*status=STATUS_INVALID_HANDLE;return 0;}
    if((o->type==OB_EVENT || o->type==OB_SEMAPHORE) && !shz_sync_rights_present(access,SHZ_SYNCHRONIZE)){
        ob_deref(o);*status=STATUS_ACCESS_DENIED;return 0;
    }
    *status=STATUS_SUCCESS;return o;
}
static int32_t sync_attributes(process_t *p,uint64_t pointer,uint32_t *attributes)
{
    struct objattr oa;*attributes=0;
    if(!pointer)return STATUS_SUCCESS;
    if(copy_from_user(p,&oa,pointer,sizeof oa))return STATUS_ACCESS_VIOLATION;
    if(oa.length!=sizeof oa)return STATUS_INVALID_PARAMETER;
    if(oa.sd)return STATUS_NOT_SUPPORTED; /* never ignore a caller's DACL */
    *attributes=oa.attributes;return STATUS_SUCCESS;
}
static int32_t give_sync_handle(process_t *p,kobject_t *o,uint64_t output,uint32_t access,uint32_t attributes)
{
    uint32_t h;int32_t status=handle_insert(p,o,access,&h);uint64_t value;
    ob_deref(o);if(status)return status;
    if(attributes & 2u){uint64_t f=irq_save();p->handles[h/4-1].inherit|=1u;irq_restore(f);}
    value=h;if(copy_to_user(p,output,&value,8)){handle_close(p,h);return STATUS_ACCESS_VIOLATION;}
    return STATUS_SUCCESS;
}

int64_t filetime_now(void)
{
    /* FILETIME epoch 1601; wall clock comes from the Supervisor (real RTC in the platform), read once: the time then advances
     * with the monotonic nanosecond clock. Adding that clock's sub-second part to each fresh whole-second RTC reading made
     * the result jump by up to a second either way (the two clocks' seconds do not start together), so a time taken later
     * could read earlier. */
    static int64_t base;                                /* FILETIME at shz_time_ns() == 0 */
    const uint64_t ns = shz_time_ns();
    if (!base) {
        hcreg_t secs = 0;
        int64_t b;
        uint64_t f;
        shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
        b = (int64_t)(secs + 11644473600ull) * 10000000ll - (int64_t)(ns / 100);
        f = irq_save();
        if (!base) base = b;
        irq_restore(f);
    }
    return base + (int64_t)(ns / 100);
}

int32_t sys_extended(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int handled = 0;
    int32_t st = sysfile_dispatch(p, r, num, a1, a2, a3, a4, &handled);
    if (handled) return st;
    switch (num) {
    case SYS_NtCreateEvent: {
        char name[48];kobject_t *o;uint32_t access,attributes;
        if(a4>1)return STATUS_INVALID_PARAMETER;
        if(!shz_sync_map_access((uint32_t)a2,&access))return STATUS_ACCESS_DENIED;
        st=sync_attributes(p,a3,&attributes);if(st)return st;
        st=object_name(p,a3,name,sizeof name);if(st)return st;
        {
            uint64_t f=irq_save();o=name[0]?ob_find_named(OB_EVENT,name):0;
            if(o){
                if(o->type!=OB_EVENT){irq_restore(f);return STATUS_OBJECT_TYPE_MISMATCH;}
                if(o->sd){irq_restore(f);return STATUS_NOT_SUPPORTED;}
                ob_ref(o);irq_restore(f);
                st=give_sync_handle(p,o,a1,access,attributes);return st?st:(int32_t)0x40000000;
            }
            /* Kernel heap allocation is IRQ-safe; lookup, publication and
             * initial state remain atomic against competing named creators. */
            o=ob_create(OB_EVENT,name);
            if(o){o->u.event.manual=a4==0;o->signaled=(int)(stack_arg(p,r,5)&0xff)!=0;}
            irq_restore(f);if(!o)return STATUS_NO_MEMORY;
        }
        return give_sync_handle(p,o,a1,access,attributes);
    }
    case SYS_NtSetEvent: case SYS_NtResetEvent: {
        kobject_t *o;uint32_t access;int32_t prev;
        st=handle_ref(p,a1,OB_EVENT,&o,&access);if(st)return st;
        if(!shz_sync_rights_present(access,SHZ_SYNC_MODIFY)){ob_deref(o);return STATUS_ACCESS_DENIED;}
        { uint64_t f=irq_save();prev=o->signaled;if(num==SYS_NtSetEvent)ob_signal_event(o);else ob_reset_event(o);irq_restore(f); }
        ob_deref(o);return a2&&copy_to_user(p,a2,&prev,4)?STATUS_ACCESS_VIOLATION:STATUS_SUCCESS;
    }
    case SYS_NtQueryEvent: {
        kobject_t *o;uint32_t access,v[2];
        st=handle_ref(p,a1,OB_EVENT,&o,&access);if(st)return st;
        if(!shz_sync_rights_present(access,SHZ_SYNC_QUERY)){ob_deref(o);return STATUS_ACCESS_DENIED;}
        v[0]=o->u.event.manual?0:1;v[1]=(uint32_t)o->signaled;ob_deref(o);
        if(a4<8&&a3)return STATUS_BUFFER_TOO_SMALL;
        return copy_to_user(p,a3,v,8)?STATUS_ACCESS_VIOLATION:STATUS_SUCCESS;
    }
    case SYS_NtCreateMutant: {                              /* (PHANDLE, ACCESS, OA, BOOLEAN initial owner) */
        char name[48];
        kobject_t *o;
        uint64_t f;
        const int initial = (a4 & 0xff) != 0;
        st = object_name(p, a3, name, sizeof name);
        if (st) return st;
        f = irq_save();
        if (name[0] && (o = ob_find_named(OB_MUTANT, name))) {
            if (o->type != OB_MUTANT) { irq_restore(f); return STATUS_OBJECT_TYPE_MISMATCH; }
            ob_ref(o);
            irq_restore(f);
            st = give_handle(p, o, a1, (uint32_t)a2);
            return st ? st : (int32_t)0x40000000;
        }
        o = ob_create(OB_MUTANT, name);
        if (!o) { irq_restore(f); return STATUS_NO_MEMORY; }
        o->signaled = 1;
        if (initial) ob_mutant_initial_owner(o, thread_current());
        ob_ref(o);                           /* retain through failed handle publication */
        irq_restore(f);
        st = give_handle(p, o, a1, (uint32_t)a2);
        if (st && initial) (void)ob_mutant_release(o, thread_current(), 0);
        ob_deref(o);
        return st;
    }
    case SYS_NtReleaseMutant: {
        kobject_t *o;
        int32_t prev;
        st = handle_ref(p, a1, OB_MUTANT, &o, 0);
        if (st) return st;
        st = ob_mutant_release(o, thread_current(), &prev);
        ob_deref(o);
        if (st) return st;
        if (a2 && copy_to_user(p, a2, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SYS_NtCreateSemaphore: {
        char name[48];kobject_t *o;uint32_t access,attributes;
        const int32_t initial=(int32_t)a4,maxc=(int32_t)stack_arg(p,r,5);
        if(maxc<=0 || initial<0 || initial>maxc)return STATUS_INVALID_PARAMETER;
        if(!shz_sync_map_access((uint32_t)a2,&access))return STATUS_ACCESS_DENIED;
        st=sync_attributes(p,a3,&attributes);if(st)return st;
        st=object_name(p,a3,name,sizeof name);if(st)return st;
        {
            uint64_t f=irq_save();o=name[0]?ob_find_named(OB_SEMAPHORE,name):0;
            if(o){
                if(o->type!=OB_SEMAPHORE){irq_restore(f);return STATUS_OBJECT_TYPE_MISMATCH;}
                if(o->sd){irq_restore(f);return STATUS_NOT_SUPPORTED;}
                ob_ref(o);irq_restore(f);
                st=give_sync_handle(p,o,a1,access,attributes);return st?st:(int32_t)0x40000000;
            }
            /* Kernel heap allocation is IRQ-safe; lookup, publication and
             * initial state remain atomic against competing named creators. */
            o=ob_create(OB_SEMAPHORE,name);
            if(o){o->u.sem.count=initial;o->u.sem.max=maxc;o->signaled=initial>0;}
            irq_restore(f);if(!o)return STATUS_NO_MEMORY;
        }
        return give_sync_handle(p,o,a1,access,attributes);
    }
    case SYS_NtReleaseSemaphore: {                          /* (handle, LONG count, PLONG previous) */
        kobject_t *o;
        uint32_t access;
        int32_t prev;
        uint64_t f;
        st = handle_ref(p, a1, OB_SEMAPHORE, &o, &access);
        if (st) return st;
        if (!shz_sync_rights_present(access, SHZ_SYNC_MODIFY)) { ob_deref(o); return STATUS_ACCESS_DENIED; }
        if ((int32_t)a2 <= 0) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
        f = irq_save();
        prev = o->u.sem.count;
        if ((int32_t)a2 > o->u.sem.max - o->u.sem.count) {
            irq_restore(f);
            ob_deref(o);
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
        ob_deref(o);
        if (a3 && copy_to_user(p, a3, &prev, 4)) return STATUS_ACCESS_VIOLATION;
        return STATUS_SUCCESS;
    }
    case SYS_NtCreateTimer: {                               /* (PHANDLE, ACCESS, OA, TIMER_TYPE 0=notification 1=sync) */
        kobject_t *o = ob_create(OB_TIMER, 0);
        extern void ob_register_timer(kobject_t *);
        if (!o) return STATUS_NO_MEMORY;
        o->u.timer.manual = a4 == 0;
        ob_register_timer(o);
        return give_handle(p, o, a1, (uint32_t)a2);
    }
    case SYS_NtSetTimer: {                                  /* (handle, PLARGE_INTEGER due, ..., ..., BOOLEAN, LONG period) */
        kobject_t *o = handle_lookup(p, a1, OB_TIMER);
        int64_t due;
        const int32_t period = (int32_t)stack_arg(p, r, 6);
        if (!o) return STATUS_INVALID_HANDLE;
        if (copy_from_user(p, &due, a2, 8)) return STATUS_ACCESS_VIOLATION;
        o->signaled = 0;
        o->u.timer.period_ms = period > 0 ? (uint64_t)period : 0;
        o->u.timer.due_tick = ticks_now() + (due < 0 ? (uint64_t)(-due) / 10000 : 1) + 1;
        o->u.timer.armed = 1;
        return STATUS_SUCCESS;
    }
    case SYS_NtCancelTimer: {
        kobject_t *o = handle_lookup(p, a1, OB_TIMER);
        if (!o) return STATUS_INVALID_HANDLE;
        o->u.timer.armed = 0;
        return STATUS_SUCCESS;
    }
    case SYS_NtWaitForSingleObject: {                       /* (handle, BOOLEAN alertable, PLARGE_INTEGER timeout) */
        kobject_t *o = object_for_wait(p, a1, &st);
        int64_t to = INT64_MAX;
        if (!o) return st;
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
            objs[i] = object_for_wait(p, hs[i], &st);
            if (!objs[i]) { while (i--) ob_deref(objs[i]); return st; }
        }
        st = ob_wait(p, objs, n, a3 == 0, to, (int)(a4 & 0xff));
        for (i = 0; i < n; ++i) ob_deref(objs[i]);
        return st;
    }
    case SYS_NtDuplicateObject: {                           /* (srcproc, srchandle, dstproc, PHANDLE dst, access, attrs, options) */
        uint32_t granted = 0;
        kobject_t *o = object_for_handle_access(p, a2, &granted);
        uint32_t access = (uint32_t)stack_arg(p, r, 5);
        const uint32_t options = (uint32_t)stack_arg(p, r, 7);
        if (!o) return STATUS_INVALID_HANDLE;
        if (options & 2) access = granted;                 /* DUPLICATE_SAME_ACCESS */
        st = STATUS_SUCCESS;
        if (o->type == OB_SECTION && !(options & 2)) {
            /* Apply the same current-descriptor policy as the IPC route. */
            if (access & 0x02000000u) access = granted | (access & ~0x02000000u);
            st = ipc_section_duplicate_access(o, granted, &access);
        }
        if(!st&&o->type!=OB_SECTION&&!(options&2)) {
            if(access&0x02000000u)access=(access&~0x02000000u)|granted;
            if(access&~granted)st=STATUS_ACCESS_DENIED;
        }
        if (!st) st = give_handle(p, o, a4, access);
        else ob_deref(o);
        if ((options & 1) && !(a2 & 3)) handle_close(p, a2); /* DUPLICATE_CLOSE_SOURCE: also on failure */
        return st;
    }
    case SYS_NtCreateThreadEx: {
        /* (PHANDLE, ACCESS, OA, ProcessHandle, StartRoutine, Argument, Flags, ZeroBits, StackSize, MaxStack, Attr) */
        thread_t *t = 0;
        const uint64_t start = (uint64_t)stack_arg(p, r, 5), arg = (uint64_t)stack_arg(p, r, 6);
        const uint64_t flags = (uint64_t)stack_arg(p, r, 7);
        process_t *target = a4 == CURRENT_PROCESS_HANDLE ? p : 0;
        (void)flags;
        if (!target || !start) return STATUS_INVALID_PARAMETER;
        if (!target->ntdll_thread_start) return STATUS_NOT_SUPPORTED;      /* processes not started by the loader */
        if (process_start_thread2(target, target->ntdll_thread_start, start, arg, (uint64_t)stack_arg(p, r, 9), &t))
            return STATUS_NO_MEMORY;
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
    case SYS_NtQueryInformationThread: return STATUS_INVALID_INFO_CLASS; /* class 0 is owned by ipc_proc.c */
    case SYS_NtSetInformationProcess: return STATUS_INVALID_INFO_CLASS;   /* nothing settable yet; entry points come from ntdll exports */
    case SYS_NtSetInformationThread: return STATUS_INVALID_INFO_CLASS;   /* validated policy classes are owned by ipc_proc.c */
    case SYS_NtCreateProcessEx: {                           /* (PHANDLE proc, PHANDLE thread, PUNICODE path, PUNICODE cmd, PUNICODE cwd) */
        struct ustr u;
        uint16_t w[260];
        char path[300], cmd[300], cwd[128];
        process_t *np = 0;
        thread_t *nt = 0;
        cwd[0] = 0;
        if (copy_from_user(p, &u, a3, sizeof u) || u.length > sizeof w - 2) return STATUS_ACCESS_VIOLATION;
        if (copy_from_user(p, w, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
        if (utf16_to_utf8(w, u.length / 2, path, sizeof path) < 0) return STATUS_OBJECT_NAME_INVALID;
        if (a4) {
            if (copy_from_user(p, &u, a4, sizeof u) || u.length > sizeof w - 2) return STATUS_ACCESS_VIOLATION;
            if (u.length && copy_from_user(p, w, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
            if (utf16_to_utf8(w, u.length / 2, cmd, sizeof cmd) < 0) return STATUS_INVALID_PARAMETER;
        } else {
            cmd[0] = 0;
        }
        st = ldr_create_process(p, path, cmd, cwd, &np, &nt);
        if (st) return st;
        {
            kobject_t *to = nt->object;
            ob_ref(to);
            thread_creator_release(nt);                     /* from here on only the thread object is used */
            ob_ref(np->object);
            st = give_handle(p, np->object, a1, 0x1fffff);
            if (!st && a2) { ob_ref(to); st = give_handle(p, to, a2, 0x1fffff); }
            ob_deref(to);
        }
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
    case SYS_NtShzLoaderControl: return ldr_lifetime_control(p, a1, a2, a3, a4);
    case SYS_NtShzLoaderCommit: return ldr_lifetime_commit(p, a1);
    case SYS_NtQuerySystemInformation: {                    /* class 0 basic: processors=1, page size; 0x100 Shizuku memory */
        extern int32_t shz_query_processor_times(process_t *,uint64_t,uint64_t,uint64_t);
        if (a1 == 0x102) return shz_query_processor_times(p,a2,a3,a4);
        if (a1 == 0x103) { extern int32_t shz_query_pnp_catalog(process_t *,uint64_t,uint64_t,uint64_t); return shz_query_pnp_catalog(p,a2,a3,a4); }
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
    default: return num >= 0x50 ? sysext_dispatch(p, r, num, a1, a2, a3, a4) : STATUS_NOT_IMPLEMENTED;
    }
}
