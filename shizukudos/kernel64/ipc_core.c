/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 IPC core: system-call routing for the IPC / process-model subsystem, object and handle lifetime hooks, the
 * recycling of exited threads and dead processes, user-mode APCs and alertable waits.
 *
 * Lifetimes follow NT: a process's address space and handle table are released when its last thread exits (before the
 * process object is signaled), while the process object - and with it the pid, exit status and slot - lives until the
 * last handle and the last thread object referencing it are gone. An exited thread gives its kernel stack back at the
 * next reap point; its slot stays until its thread object is freed, so thread handles keep reporting the exit code.
 *
 * APCs: a user APC is delivered when its thread performs an alertable wait (NtWaitForSingleObject/Multiple, NtDelayExecution,
 * NtRemoveIoCompletionEx with Alertable) or NtTestAlert. Delivery rewrites the system call's return frame: the interrupted
 * context (RAX = STATUS_USER_APC) is saved as a CONTEXT on the user stack and the thread enters ntdll!KiUserApcDispatcher,
 * which calls the routine and resumes through NtContinue(context, TestAlert = TRUE) so every queued APC runs before the wait
 * returns, as on Windows.
 */
#include "ipc.h"

extern uint64_t ticks_now(void);

uint32_t ipc_stat_sections, ipc_stat_views, ipc_stat_pipes, ipc_stat_irps, ipc_stat_packets, ipc_stat_jobs;

/* ---------------------------------------------------------------- per-process / per-thread state */
ipc_proc_t *ipc_proc(process_t *p, int create)
{
    if (!p->ipc && create) p->ipc = kzalloc(sizeof(ipc_proc_t));
    return p->ipc;
}

ipc_thread_t *ipc_thread(thread_t *t, int create)
{
    if (!t->ipc && create) t->ipc = kzalloc(sizeof(ipc_thread_t));
    return t->ipc;
}

/* ---------------------------------------------------------------- names and handles */
int32_t ipc_read_ustr16(process_t *p, uint64_t ustr_va, uint16_t *out, uint32_t cap_chars, uint32_t *chars)
{
    struct ipc_ustr u;
    if (copy_from_user(p, &u, ustr_va, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if (u.length & 1) return STATUS_OBJECT_NAME_INVALID;
    if (u.length / 2u >= cap_chars) return STATUS_OBJECT_NAME_INVALID;
    if (u.length && copy_from_user(p, out, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
    out[u.length / 2] = 0;
    *chars = u.length / 2u;
    return STATUS_SUCCESS;
}

/* Object-namespace name of an OBJECT_ATTRIBUTES (UTF-8, empty when unnamed). "Local\" names the session namespace, which
 * is the only one this single-session system has, so it is removed; "Global\" stays part of the name. */
int32_t ipc_name_from_oa(process_t *p, uint64_t oa_va, char *out, size_t cap, uint32_t *attributes)
{
    struct ipc_objattr oa;
    uint16_t w[64];
    uint32_t n = 0, skip = 0;
    int32_t st;
    out[0] = 0;
    if (attributes) *attributes = 0;
    if (!oa_va) return STATUS_SUCCESS;
    if (copy_from_user(p, &oa, oa_va, sizeof oa)) return STATUS_ACCESS_VIOLATION;
    if (attributes) *attributes = oa.attributes;
    if (!oa.name) return STATUS_SUCCESS;
    st = ipc_read_ustr16(p, oa.name, w, 64, &n);
    if (st) return st;
    if (n >= 6 && (w[0] | 32) == 'l' && (w[1] | 32) == 'o' && (w[2] | 32) == 'c' && (w[3] | 32) == 'a' &&
        (w[4] | 32) == 'l' && w[5] == '\\')
        skip = 6;
    if (n - skip == 0 && n) return STATUS_OBJECT_NAME_INVALID;
    return utf16_to_utf8(w + skip, n - skip, out, cap) < 0 ? STATUS_OBJECT_NAME_INVALID : STATUS_SUCCESS;
}

void ipc_handle_opened(kobject_t *o)
{
    switch (o->type) {
    case OB_NPIPE: case OB_IOCP: case OB_JOB: {
        uint32_t *count = o->u.file.file;               /* each private struct starts with its handle count */
        const uint64_t f = irq_save();
        if (count) ++*count;
        irq_restore(f);
        break;
    }
    default: break;
    }
}

int32_t ipc_give_handle(process_t *p, kobject_t *o, uint32_t access, int inherit, uint64_t user_ptr, uint32_t *h_out)
{
    uint32_t h;
    uint64_t v;
    int32_t st = handle_insert(p, o, access, &h);
    if (st) { ob_deref(o); return st; }
    ipc_handle_opened(o);
    ob_deref(o);                                        /* the handle table now holds the object */
    if (inherit) {
        const uint64_t f = irq_save();
        p->handles[h / 4 - 1].inherit |= HANDLE_FLAG_INHERIT_BIT;
        irq_restore(f);
    }
    v = h;
    if (user_ptr && copy_to_user(p, user_ptr, &v, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    if (h_out) *h_out = h;
    return STATUS_SUCCESS;
}

int32_t ipc_ref_handle(process_t *p, uint64_t h, uint32_t type, kobject_t **out, uint32_t *access)
{
    kobject_t *o;
    if (h == CURRENT_PROCESS_HANDLE || h == CURRENT_THREAD_HANDLE) {
        o = h == CURRENT_PROCESS_HANDLE ? p->object : thread_current()->object;
        if (type && o->type != type) return STATUS_OBJECT_TYPE_MISMATCH;
        ob_ref(o);
        *out = o;
        if (access) *access = 0x1fffff;
        return STATUS_SUCCESS;
    }
    if (h > 0xffffffffull) return STATUS_INVALID_HANDLE;
    return handle_ref(p, h & ~3ull, type, out, access);   /* the two low bits are tag bits, ignored as on NT */
}

int32_t ipc_ref_process(process_t *cur, uint64_t h, uint32_t need_access, process_t **out, kobject_t **obj)
{
    kobject_t *o;
    uint32_t access = 0;
    int32_t st = ipc_ref_handle(cur, h, OB_PROCESS, &o, &access);
    if (st) return st;
    if ((access & need_access) != need_access) { ob_deref(o); return STATUS_ACCESS_DENIED; }
    *out = o->u.proc.p;
    *obj = o;
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- object / handle hooks (objects.c) */
void ipc_handle_closed(process_t *p, kobject_t *o)
{
    uint32_t *count;
    uint64_t f;
    int last;
    (void)p;
    if (o->type != OB_NPIPE && o->type != OB_IOCP && o->type != OB_JOB) return;
    count = o->u.file.file;
    if (!count) return;
    f = irq_save();
    last = *count && --*count == 0;
    irq_restore(f);
    if (!last) return;
    if (o->type == OB_NPIPE) npfs_handle_closed(o);
    else if (o->type == OB_IOCP) iocp_handle_closed(o);
    else job_handle_closed(o);
}

void ipc_object_free(kobject_t *o)
{
    switch (o->type) {
    case OB_SECTION: section_free(o); break;
    case OB_NPIPE: npfs_free(o); ioctx_free(o); break;
    case OB_IOCP: iocp_free(o); break;
    case OB_JOB: job_free(o); break;
    case OB_FILE: ioctx_free(o); break;
    case OB_THREAD: {                                   /* the exited thread's slot and its process reference */
        thread_t *t = o->u.thr.t;
        process_t *pp;
        uint64_t f;
        if (!t) break;
        pp = t->proc;
        f = irq_save();
        t->object = 0;
        if (t->state == TS_ZOMBIE && !t->stack_base) t->state = TS_FREE;
        irq_restore(f);
        if (pp) ob_deref(pp->object);
        break;
    }
    case OB_PROCESS: {                                  /* nothing references the process any more: recycle its slot */
        process_t *pp = o->u.proc.p;
        if (!pp || pp->teardown != 2) {
            if (pp) kprintf("K64 ipc: process object of pid %d freed before teardown\n", pp->pid);
            break;
        }
        vad_destroy(pp);
        kfree(pp->handles);
        pp->handles = 0;
        pp->used = 0;
        break;
    }
    default: break;
    }
}

/* ---------------------------------------------------------------- thread / process lifecycle hooks (proc.c) */
static void reap_one(thread_t *t, void *ctx)
{
    (void)ctx;
    if (t->state != TS_ZOMBIE || !t->teb || t == thread_current() || !t->stack_base) return;
    kfree((void *)t->stack_base);                       /* it never runs again: its kernel stack is free */
    t->stack_base = 0;
    if (t->object) ob_deref(t->object);                 /* the thread's own reference; the slot follows the object */
    else t->state = TS_FREE;
}

void ipc_reap(void) { sched_for_each_thread(reap_one, 0); }

void ipc_thread_exit(thread_t *t)
{
    ipc_io_thread_exit(t);
    apc_free_all(t);
    if (t->ipc) { kfree(t->ipc); t->ipc = 0; }
}

static void kill_wake(thread_t *t, void *ctx)
{
    ipc_thread_t *it = t->ipc;
    if (t->proc != ctx || t == thread_current()) return;
    if (t->state == TS_NEW) { thread_resume(t); return; }          /* exits at its first instruction (user_thread_main) */
    if (t->state != TS_BLOCKED) return;
    if ((it && (it->waiting || it->alertable)) || t->wait_multi || t->alert_wait || (!t->wait_sem && t->wake_tick))
        thread_wake(t);                                              /* returns to the syscall exit, where check_kill ends it */
}

void ipc_process_terminating(process_t *p) { sched_for_each_thread(kill_wake, p); }

void ipc_process_teardown(process_t *p)
{
    ipc_io_teardown(p);
    views_teardown(p);
    job_process_exited(p);
    if (p->ipc) { kfree(p->ipc); p->ipc = 0; }
}

/* ---------------------------------------------------------------- APCs */
#define CONTEXT_SIZE 0x4d0
#define CONTEXT_AMD64 0x100000u

int apc_pending(thread_t *t) { return t->ipc && ((ipc_thread_t *)t->ipc)->apc_head != 0; }

void apc_queue(thread_t *t, uint64_t routine, uint64_t a1, uint64_t a2, uint64_t a3)
{
    ipc_thread_t *it = ipc_thread(t, 1);
    apc_t *a = kzalloc(sizeof *a);
    uint64_t f;
    if (!it || !a) { kfree(a); return; }
    a->routine = routine; a->arg1 = a1; a->arg2 = a2; a->arg3 = a3;
    f = irq_save();
    if (it->apc_tail) it->apc_tail->next = a; else it->apc_head = a;
    it->apc_tail = a;
    if (it->alertable && t->state == TS_BLOCKED) thread_wake(t);
    irq_restore(f);
}

void apc_free_all(thread_t *t)
{
    ipc_thread_t *it = t->ipc;
    apc_t *a, *n;
    uint64_t f;
    if (!it) return;
    f = irq_save();
    a = it->apc_head;
    it->apc_head = it->apc_tail = 0;
    irq_restore(f);
    for (; a; a = n) { n = a->next; kfree(a); }
}

static void put64(uint8_t *c, unsigned off, uint64_t v) { memcpy(c + off, &v, 8); }

int32_t apc_deliver(process_t *p, struct regs *r, int32_t status)
{
    thread_t *t = thread_current();
    ipc_thread_t *it = t->ipc;
    static uint8_t ctx[CONTEXT_SIZE];                   /* built with interrupts off: one static buffer is enough */
    ipc_proc_t *ip = ipc_proc(p, 1);
    uint64_t f, sp, ctx_va, dispatcher;
    apc_t *a;
    if (!it || !ip) return status;
    if (!ip->apc_dispatcher) ip->apc_dispatcher = ldr_ntdll_export(p, "KiUserApcDispatcher");
    dispatcher = ip->apc_dispatcher;
    if (!dispatcher) return status;
    f = irq_save();
    a = it->apc_head;
    if (!a) { irq_restore(f); return status; }
    it->apc_head = a->next;
    if (!it->apc_head) it->apc_tail = 0;
    memset(ctx, 0, sizeof ctx);
    put64(ctx, 0x00, a->arg1);                          /* P1Home..P3Home: arguments, P4Home: routine */
    put64(ctx, 0x08, a->arg2);
    put64(ctx, 0x10, a->arg3);
    put64(ctx, 0x18, a->routine);
    *(uint32_t *)(ctx + 0x30) = CONTEXT_AMD64 | 1 | 2 | 4 | 8;       /* CONTROL | INTEGER | SEGMENTS | FLOATING_POINT */
    *(uint16_t *)(ctx + 0x38) = 0x23;
    *(uint16_t *)(ctx + 0x3a) = 0x1b;
    *(uint16_t *)(ctx + 0x3c) = 0x1b;
    *(uint16_t *)(ctx + 0x42) = 0x1b;
    *(uint32_t *)(ctx + 0x44) = (uint32_t)r->rflags;
    put64(ctx, 0x78, (uint64_t)(int64_t)status); put64(ctx, 0x80, r->rcx); put64(ctx, 0x88, r->rdx);
    put64(ctx, 0x90, r->rbx); put64(ctx, 0x98, r->rsp); put64(ctx, 0xa0, r->rbp); put64(ctx, 0xa8, r->rsi);
    put64(ctx, 0xb0, r->rdi); put64(ctx, 0xb8, r->r8); put64(ctx, 0xc0, r->r9); put64(ctx, 0xc8, r->r10);
    put64(ctx, 0xd0, r->r11); put64(ctx, 0xd8, r->r12); put64(ctx, 0xe0, r->r13); put64(ctx, 0xe8, r->r14);
    put64(ctx, 0xf0, r->r15); put64(ctx, 0xf8, r->rip);
    __asm__ volatile("fxsave (%0)" :: "r"(ctx + 0x100) : "memory");  /* the live registers are the user's (-mgeneral-regs-only) */
    *(uint32_t *)(ctx + 0x34) = *(uint32_t *)(ctx + 0x100 + 24);     /* MxCsr */
    sp = ((r->rsp - 0x80) & ~0xfull) - CONTEXT_SIZE;
    sp &= ~0xfull;
    ctx_va = sp;
    sp -= 0x28;                                         /* shadow space and the return-address slot of a call */
    sp &= ~0xfull;
    sp -= 8;
    if (sp < USER_MIN || copy_to_user(p, ctx_va, ctx, sizeof ctx)) {
        irq_restore(f);
        kfree(a);
        return status;                                  /* no room on the user stack: the APC is dropped */
    }
    r->rip = dispatcher;
    r->rcx = ctx_va;
    r->rsp = sp;
    r->rflags = 0x202;
    irq_restore(f);
    kfree(a);
    return STATUS_FRAME_REWRITTEN;
}

/* ---------------------------------------------------------------- alertable waits */
static uint64_t deadline_from(int64_t timeout)            /* NT relative timeout (100 ns, negative) -> tick; 0 = never */
{
    uint64_t ms;
    if (timeout == INT64_MAX) return 0;
    ms = timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;
    return ticks_now() + (ms * 1000u + TICK_US - 1) / TICK_US + 1;
}

static int64_t remaining_100ns(uint64_t deadline)
{
    const uint64_t now = ticks_now();
    if (!deadline) return INT64_MAX;
    if (now >= deadline) return 0;
    return -(int64_t)((deadline - now) * TICK_US * 10u);   /* one tick = TICK_US microseconds = TICK_US * 10 x 100 ns */
}

static int32_t read_timeout(process_t *p, uint64_t pto, int64_t *to)
{
    *to = INT64_MAX;
    if (!pto) return STATUS_SUCCESS;
    if (copy_from_user(p, to, pto, 8)) return STATUS_ACCESS_VIOLATION;
    if (*to > 0) *to = -*to;                            /* absolute times are treated as relative, like sysx.c */
    return STATUS_SUCCESS;
}

static int32_t wait_alertable(process_t *p, struct regs *r, kobject_t **objs, unsigned n, int all, int64_t timeout)
{
    thread_t *t = thread_current();
    ipc_thread_t *it = ipc_thread(t, 1);
    const uint64_t deadline = timeout == 0 ? 1 : deadline_from(timeout);
    int64_t to = timeout;
    int32_t st;
    if (!it) return STATUS_NO_MEMORY;
    for (;;) {
        const uint64_t f = irq_save();
        if (apc_pending(t)) { irq_restore(f); return apc_deliver(p, r, STATUS_USER_APC); }
        it->alertable = 1;
        st = ob_wait(p, objs, n, all, to, 1);           /* blocks with interrupts off: an APC queued meanwhile wakes it */
        it->alertable = 0;
        irq_restore(f);
        if (st != STATUS_TIMEOUT) return st;
        if (apc_pending(t)) return apc_deliver(p, r, STATUS_USER_APC);
        if (p->terminated || timeout == 0) return st;
        to = remaining_100ns(deadline);
        if (to == 0) return st;
    }
}

static int32_t delay_alertable(process_t *p, struct regs *r, uint64_t pinterval)
{
    thread_t *t = thread_current();
    ipc_thread_t *it = ipc_thread(t, 1);
    int64_t iv;
    uint64_t deadline;
    if (copy_from_user(p, &iv, pinterval, 8)) return STATUS_ACCESS_VIOLATION;
    if (!it) return STATUS_NO_MEMORY;
    if (apc_pending(t)) return apc_deliver(p, r, STATUS_USER_APC);
    if (iv >= 0) { thread_yield(); return apc_pending(t) ? apc_deliver(p, r, STATUS_USER_APC) : STATUS_SUCCESS; }
    deadline = iv == INT64_MIN + 1 ? 0 : deadline_from(iv);   /* Sleep(INFINITE) */
    for (;;) {
        const uint64_t f = irq_save();
        if (apc_pending(t)) { irq_restore(f); return apc_deliver(p, r, STATUS_USER_APC); }
        it->alertable = 1;
        t->wake_tick = deadline;
        thread_block_current();
        t->wake_tick = 0;
        it->alertable = 0;
        irq_restore(f);
        if (apc_pending(t)) return apc_deliver(p, r, STATUS_USER_APC);
        if (p->terminated || (deadline && ticks_now() >= deadline)) return STATUS_SUCCESS;
    }
}

static int32_t sys_wait_single_alertable(process_t *p, struct regs *r, uint64_t h, uint64_t pto)
{
    kobject_t *o;
    int64_t to;
    int32_t st = read_timeout(p, pto, &to);
    if (st) return st;
    st = ipc_ref_handle(p, h, 0, &o, 0);
    if (st) return st == STATUS_OBJECT_TYPE_MISMATCH ? STATUS_INVALID_HANDLE : st;
    st = wait_alertable(p, r, &o, 1, 0, to);
    ob_deref(o);
    return st;
}

static int32_t sys_wait_multiple_alertable(process_t *p, struct regs *r, uint64_t n, uint64_t hs_va, uint64_t type,
                                           uint64_t pto)
{
    uint64_t hs[64];
    kobject_t *objs[64];
    unsigned i;
    int64_t to;
    int32_t st;
    if (!n || n > 64) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, hs, hs_va, n * 8ull)) return STATUS_ACCESS_VIOLATION;
    st = read_timeout(p, pto, &to);
    if (st) return st;
    for (i = 0; i < n; ++i) {
        st = ipc_ref_handle(p, hs[i], 0, &objs[i], 0);
        if (st) { while (i--) ob_deref(objs[i]); return STATUS_INVALID_HANDLE; }
    }
    st = wait_alertable(p, r, objs, (unsigned)n, type == 0, to);
    for (i = 0; i < n; ++i) ob_deref(objs[i]);
    return st;
}

/* NtQueueApcThread(ThreadHandle, ApcRoutine, Argument1, Argument2, Argument3) */
static int32_t sys_queue_apc(process_t *p, struct regs *r, uint64_t h, uint64_t routine, uint64_t a1, uint64_t a2)
{
    kobject_t *o;
    thread_t *t;
    uint32_t access = 0;
    const uint64_t a3 = (uint64_t)stack_arg(p, r, 5);
    int32_t st = ipc_ref_handle(p, h, OB_THREAD, &o, &access);
    if (st) return st;
    if (!(access & THREAD_SET_CONTEXT)) { ob_deref(o); return STATUS_ACCESS_DENIED; }
    t = o->u.thr.t;
    if (!routine) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
    if (!t || t->state == TS_ZOMBIE || t->state == TS_FREE || !t->proc || t->proc->terminated) {
        ob_deref(o);
        return STATUS_UNSUCCESSFUL;
    }
    apc_queue(t, routine, a1, a2, a3);
    ob_deref(o);
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- kernel statistics (leak checks in the tests) */
struct kstats {
    uint64_t pmm_free, kheap_used, threads, zombies, sections, views, pipes, irps, packets, jobs, reserved[6];
};
static void count_thread(thread_t *t, void *ctx)
{
    struct kstats *k = ctx;
    ++k->threads;
    if (t->state == TS_ZOMBIE) ++k->zombies;
}

static int32_t sys_kernel_stats(process_t *p, uint64_t buf, uint64_t len)
{
    struct kstats k;
    if (len < sizeof k) return STATUS_INFO_LENGTH_MISMATCH;
    ipc_reap();
    memset(&k, 0, sizeof k);
    sched_for_each_thread(count_thread, &k);
    k.pmm_free = pmm_free_count();
    k.kheap_used = kheap_used();
    k.sections = ipc_stat_sections; k.views = ipc_stat_views; k.pipes = ipc_stat_pipes;
    k.irps = ipc_stat_irps; k.packets = ipc_stat_packets; k.jobs = ipc_stat_jobs;
    return copy_to_user(p, buf, &k, sizeof k) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- handle flags (NtSetInformationObject / NtQueryObject 4) */
static int32_t handle_flags(process_t *p, uint64_t h, uint64_t buf, uint64_t len, uint64_t pret, int set)
{
    uint8_t v[2];
    uint64_t f;
    handle_entry_t *e;
    if (h == CURRENT_PROCESS_HANDLE || h == CURRENT_THREAD_HANDLE || (h & 3) || !h || h > MAX_HANDLES * 4ull)
        return STATUS_INVALID_HANDLE;
    if (len < 2) return STATUS_INFO_LENGTH_MISMATCH;
    if (set && copy_from_user(p, v, buf, 2)) return STATUS_ACCESS_VIOLATION;
    f = irq_save();
    e = &p->handles[h / 4 - 1];
    if (!e->obj) { irq_restore(f); return STATUS_INVALID_HANDLE; }
    if (set) {
        e->inherit = (v[0] ? HANDLE_FLAG_INHERIT_BIT : 0) | (v[1] ? HANDLE_FLAG_PROTECT_BIT : 0);
    } else {
        v[0] = (e->inherit & HANDLE_FLAG_INHERIT_BIT) != 0;
        v[1] = (e->inherit & HANDLE_FLAG_PROTECT_BIT) != 0;
    }
    irq_restore(f);
    if (!set) {
        const uint32_t n = 2;
        if (copy_to_user(p, buf, v, 2)) return STATUS_ACCESS_VIOLATION;
        if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- routing */
static int32_t route(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                     int *handled)
{
    int32_t st;
    *handled = 0;
    st = npfs_syscall(p, r, num, a1, a2, a3, a4, handled);
    if (*handled) return st;
    st = ipc_io_syscall(p, r, num, a1, a2, a3, a4, handled);
    if (*handled) return st;
    st = ipc_proc_syscall(p, r, num, a1, a2, a3, a4, handled);
    if (*handled) return st;
    return ipc_section_syscall(p, r, num, a1, a2, a3, a4, handled);
}

int ipc_syscall_override(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int32_t *st)
{
    int handled = 0;
    switch (num) {
    case SYS_NtWaitForSingleObject:                     /* (handle, BOOLEAN alertable, PLARGE_INTEGER timeout) */
        if (!(a2 & 0xff)) return 0;
        *st = sys_wait_single_alertable(p, r, a1, a3);
        return 1;
    case SYS_NtWaitForMultipleObjects:                  /* (count, handles, WaitAll=0/WaitAny=1, alertable, timeout) */
        if (!(a4 & 0xff)) return 0;
        *st = sys_wait_multiple_alertable(p, r, a1, a2, a3, (uint64_t)stack_arg(p, r, 5));
        return 1;
    case SYS_NtDelayExecution:                          /* (BOOLEAN alertable, PLARGE_INTEGER interval) */
        if (!(a1 & 0xff)) return 0;
        *st = delay_alertable(p, r, a2);
        return 1;
    case SYS_NtContinue:                                /* (PCONTEXT, BOOLEAN TestAlert): run the next queued APC too */
        if (!(a2 & 0xff)) return 0;
        *st = user_exception_continue(p, r, a1, 0, 0);
        if (*st == STATUS_FRAME_REWRITTEN && apc_pending(thread_current()))
            apc_deliver(p, r, (int32_t)r->rax);
        return 1;
    case SYS_NtClose:
        if (!(a1 & 3) && a1 && a1 <= MAX_HANDLES * 4ull && p->handles[a1 / 4 - 1].obj &&
            (p->handles[a1 / 4 - 1].inherit & HANDLE_FLAG_PROTECT_BIT)) {
            *st = STATUS_HANDLE_NOT_CLOSABLE;
            return 1;
        }
        return 0;
    case SYS_NtQueryObject:                             /* (HANDLE, CLASS, PVOID, ULONG, PULONG): class 4 is ours */
        if (a2 != 4) return 0;
        *st = handle_flags(p, a1, a3, a4, (uint64_t)stack_arg(p, r, 5), 0);
        return 1;
    default:
        break;
    }
    *st = route(p, r, num, a1, a2, a3, a4, &handled);
    return handled;
}

static int32_t ext_common(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int handled = 0;
    int32_t st;
    switch (num) {
    case SYS_NtQueueApcThread: return sys_queue_apc(p, r, a1, a2, a3, a4);
    case SYS_NtTestAlert:
        return apc_pending(thread_current()) ? apc_deliver(p, r, STATUS_SUCCESS) : STATUS_SUCCESS;
    case SYS_NtShzQueryKernelStats: return sys_kernel_stats(p, a1, a2);
    case SYS_NtSetInformationObject:                    /* (HANDLE, CLASS, PVOID, ULONG) */
        if (a2 != 4) return STATUS_INVALID_INFO_CLASS;
        return handle_flags(p, a1, a3, a4, 0, 1);
    default: break;
    }
    st = route(p, r, num, a1, a2, a3, a4, &handled);
    return handled ? st : STATUS_INVALID_SYSTEM_SERVICE;
}

int32_t sys_ext_misc(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    return ext_common(p, r, num, a1, a2, a3, a4);
}

int32_t sys_ext_ipc(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    return ext_common(p, r, num, a1, a2, a3, a4);
}
