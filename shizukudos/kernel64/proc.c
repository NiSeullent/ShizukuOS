/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 processes and user threads: address-space creation, TEB/PEB allocation,
 * user thread entry, termination, and fault handling (page-fault population, kill on
 * unhandled exceptions when no user-mode dispatcher is registered).
 */
#include "proc_internal.h"

extern void enter_user(uint64_t rip, uint64_t rsp, uint64_t arg, uint64_t arg2);
extern void vm_set_demand_range(uint64_t lo, uint64_t hi);

#define MAX_PROCS 64                    /* slots are freed only by proc_wait(); user-created children leak one until reaping lands (P-ipc) */
#define USER_STACK_BYTES (1024 * 1024)
#define TEB_BYTES 0x2000
#define PEB_BYTES 0x1000

static process_t procs[MAX_PROCS + 1];
static int next_pid = 1;
static uint64_t syscalls;
uint64_t user_syscall_count(void) { return syscalls; }
void count_syscall(void) { ++syscalls; }

uint64_t proc_pml4(process_t *p) { return p->pml4; }
process_t *current_process(void) { return thread_current()->proc; }

process_t *process_by_pid(int pid)
{
    unsigned i;
    for (i = 1; i <= MAX_PROCS; ++i)
        if (procs[i].used && procs[i].pid == pid)
            return &procs[i];
    return 0;
}

process_t *process_create_empty(const char *name)
{
    process_t *p = 0;
    unsigned i, k;
    for (i = 1; i <= MAX_PROCS; ++i)
        if (!procs[i].used) { p = &procs[i]; break; }
    if (!p) {
        kprintf("K64: process table full (%u slots)\n", (unsigned)MAX_PROCS);
        return 0;
    }
    memset(p, 0, sizeof *p);
    p->pml4 = vm_new_space();
    if (!p->pml4)
        return 0;
    p->handles = kzalloc(sizeof(handle_entry_t) * MAX_HANDLES);
    if (!p->handles) { vm_free_space(p->pml4); return 0; }
    vad_init(p);
    p->pid = next_pid++ * 4;
    for (k = 0; name[k] && k < sizeof p->name - 1; ++k) p->name[k] = name[k];
    sem_init(&p->exited, 0);
    p->object = ob_create(OB_PROCESS, 0);
    p->object->u.proc.p = p;
    p->mmap_hint = 0x0000000010000000ull;
    p->next_tid = 4;                    /* thread ids are multiples of 4, like NT */
    p->create_tick = ticks_now();
    p->used = 1;
    return p;
}

/* Windows x64 TEB layout (documented offsets). */
struct __attribute__((packed)) teb64 {
    uint64_t exception_list;            /* 0x00 NtTib.ExceptionList */
    uint64_t stack_base;                /* 0x08 */
    uint64_t stack_limit;               /* 0x10 */
    uint64_t sub_system_tib;            /* 0x18 */
    uint64_t fiber_data;                /* 0x20 */
    uint64_t arbitrary_user_pointer;    /* 0x28 */
    uint64_t self;                      /* 0x30 NtTib.Self */
    uint64_t environment_pointer;       /* 0x38 */
    uint64_t client_pid;                /* 0x40 ClientId.UniqueProcess */
    uint64_t client_tid;                /* 0x48 ClientId.UniqueThread */
    uint64_t active_rpc_handle;         /* 0x50 */
    uint64_t tls_pointer;               /* 0x58 ThreadLocalStoragePointer */
    uint64_t peb;                       /* 0x60 ProcessEnvironmentBlock */
    uint32_t last_error;                /* 0x68 */
    uint32_t count_owned_locks;         /* 0x6c */
    uint8_t pad0[0x1480 - 0x70];
    uint64_t tls_slots[64];             /* 0x1480 */
    uint64_t tls_expansion;             /* 0x1680 */
};

uint64_t proc_alloc_teb(process_t *p, uint64_t stack_base, uint64_t stack_limit)
{
    uint64_t base = 0, size = TEB_BYTES, off, pa;
    struct teb64 *t;
    thread_t *cur = thread_current();
    if (vad_alloc(p, &base, &size, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE, VK_TEB))
        return 0;
    for (off = 0; off < TEB_BYTES; off += PAGE_SIZE) {
        pa = pmm_alloc();
        if (!pa || vm_map(p->pml4, base + off, pa, prot_to_ptflags(PAGE_READWRITE))) return 0;
    }
    t = (struct teb64 *)p2v(vm_lookup(p->pml4, base, 0));
    t->self = base;
    t->stack_base = stack_base;
    t->stack_limit = stack_limit;
    t->client_pid = (uint64_t)p->pid;
    t->client_tid = p->next_tid;
    t->peb = p->peb;
    (void)cur;
    return base;
}

void proc_alloc_peb(process_t *p)
{
    uint64_t base = 0, size = PEB_BYTES, pa;
    uint64_t *peb;
    if (vad_alloc(p, &base, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, VK_PRIVATE))
        kpanic("PEB allocation failed");
    pa = pmm_alloc();
    KASSERT(pa && vm_map(p->pml4, base, pa, prot_to_ptflags(PAGE_READWRITE)) == 0);
    peb = (uint64_t *)p2v(pa);
    /* PEB fields filled later by the loader (ImageBaseAddress at +0x10, Ldr at +0x18, ...). */
    peb[0] = 0;
    p->peb = base;
}

/* Kernel thread body of every user thread. */
static void user_thread_main(void *arg)
{
    thread_t *t = thread_current();
    process_t *p = t->proc;
    (void)arg;
    write_cr3(p->pml4);
    tss_set_rsp0(t->stack_base + KSTACK_BYTES);
    g_kstack_top = t->stack_base + KSTACK_BYTES;
    wrmsr(MSR_GS_BASE, t->teb);                 /* GS:[0x30] is the TEB self pointer, as on Windows x64 */
    enter_user(t->user_rip, t->user_rsp, t->user_arg, t->user_arg2);
}

static int start_thread_common(process_t *p, uint64_t rip, uint64_t rsp, uint64_t arg, uint64_t arg2,
                               uint64_t stack_size, thread_t **out)
{
    uint64_t stack_base = 0;
    thread_t *t;
    kobject_t *tobj;
    if (rsp == 0) {
        if (vad_alloc(p, &stack_base, &stack_size, MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN, PAGE_READWRITE, VK_STACK))
            return -1;
        rsp = stack_base + stack_size - 0x40;   /* leaves shadow space + alignment headroom */
        rsp &= ~0xfull;
        rsp -= 8;                               /* as if entered by CALL: RSP % 16 == 8 */
    } else {
        stack_base = rsp - 0x10000;
        stack_size = 0x10000;
    }
    /* Suspended: the timer tick can preempt this function at any instruction, and a READY thread whose proc, user_rip,
     * teb and user_gs_base are still zero would fault in user_thread_main (NULL proc, RIP 0, GS base 0). */
    t = thread_create_suspended(p->name, user_thread_main, 0);
    if (!t) return -1;
    t->proc = p;
    t->user_rip = rip;
    t->user_rsp = rsp;
    t->user_arg = arg;
    t->user_arg2 = arg2;
    t->tid = p->next_tid;                       /* the TEB reports this same id in ClientId */
    t->teb = proc_alloc_teb(p, stack_base + stack_size, stack_base);
    if (!t->teb) { thread_discard(t); return -1; }
    t->user_gs_base = t->teb;
    tobj = ob_create(OB_THREAD, 0);
    if (!tobj) { thread_discard(t); return -1; }
    tobj->u.thr.t = t;
    tobj->u.thr.tid = t->id * 4ull;             /* the id NtQueryInformationThread reports (sysx.c) */
    tobj->u.thr.pid = (uint64_t)p->pid;
    t->object = tobj;
    t->creator_hold = out != 0;                 /* the caller reads t->object after the thread may already have run */
    ++p->threads_alive;
    p->next_tid += 4;
    if (!p->main_thread) p->main_thread = t;
    thread_user_tls_init(p, t);
    if (out) *out = t;
    thread_resume(t);                           /* fully initialised: now it may run */
    return 0;
}

int process_start_thread(process_t *p, uint64_t rip, uint64_t rsp, uint64_t arg, thread_t **out)
{
    return start_thread_common(p, rip, rsp, arg, 0, USER_STACK_BYTES, out);
}

int process_start_thread2(process_t *p, uint64_t rip, uint64_t rcx, uint64_t rdx, uint64_t stack_size, thread_t **out)
{
    if (stack_size < 65536) stack_size = 65536;
    if (stack_size > (64ull << 20)) stack_size = 64ull << 20;
    return start_thread_common(p, rip, 0, rcx, rdx, (stack_size + 4095) & ~4095ull, out);
}

/* Called when a process's last thread has exited. */
static void process_reap_signal(process_t *p)
{
    p->terminated = 1;
    p->object->signaled = 1;
    {
        uint64_t f = irq_save();
        ob_release_check(p->object);
        irq_restore(f);
    }
    sem_post(&p->exited);
}

void process_thread_gone(process_t *p)
{
    if (--p->threads_alive <= 0)
        process_reap_signal(p);
}

void process_terminate(process_t *p, int64_t code, int faulted)
{
    p->exit_code = code;
    if (faulted) p->faulted = 1;
    p->terminated = 1;
    /* Other threads are killed at their next kernel entry/exit (see check_kill). */
}

void check_kill(void)
{
    thread_t *t = thread_current();
    process_t *p = t->proc;
    if (p && p->terminated) {
        process_thread_gone(p);
        thread_exit(p->exit_code);
    }
}

int proc_create_flat(const char *name, const uint8_t *image, uint64_t size, int *pid_out)
{
    process_t *p = process_create_empty(name);
    uint64_t base = 0x400000, len = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1), off;
    if (!p) return -1;
    proc_alloc_peb(p);
    if (vad_alloc(p, &base, &len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, VK_IMAGE))
        return -1;
    for (off = 0; off < len; off += PAGE_SIZE) {
        const uint64_t pa = pmm_alloc();
        const uint64_t n = size - off < PAGE_SIZE ? size - off : PAGE_SIZE;
        if (!pa || vm_map(p->pml4, base + off, pa, prot_to_ptflags(PAGE_EXECUTE_READWRITE))) return -1;
        if (off < size) memcpy((void *)p2v(pa), image + off, n);
    }
    p->image_base = base;
    p->entry = base;
    if (process_start_thread(p, p->entry, 0, 0, 0))
        return -1;
    if (pid_out) *pid_out = p->pid;
    return 0;
}

int proc_wait(int pid, int64_t *exit_code, int *faulted)
{
    process_t *p = process_by_pid(pid);
    if (!p) return -1;
    while (!p->terminated || p->threads_alive > 0) {
        thread_sleep_ms(1);
    }
    thread_sleep_ms(2);                                 /* let the last thread finish thread_exit */
    if (exit_code) *exit_code = p->exit_code;
    if (faulted) *faulted = p->faulted;
    handles_close_all(p);
    thread_reap_process(p);                             /* its exited threads' slots and kernel stacks */
    write_cr3(kernel_pml4());
    vm_free_space(p->pml4);
    vad_destroy(p);
    ldr_release_modules(p);                             /* loader records (and lazily mapped image statistics) */
    kfree(p->handles);
    ob_deref(p->object);
    p->used = 0;
    return 0;
}

/* ---------------------------------------------------------------- faults */
extern int user_exception_dispatch(struct regs *r, uint32_t code, uint64_t info0, uint64_t info1);

int user_page_fault(struct regs *r, uint64_t addr)
{
    process_t *p = current_process();
    int st;
    if (!p)
        return 0;
    st = user_fault_in(p, addr, (r->error & 2) != 0, (r->error & 16) != 0);
    if (st == 0)
        return 1;                                       /* page populated; restart the instruction */
    if (st == STATUS_NO_MEMORY) {
        kprintf("K64: out of memory populating %llx for pid %d\n", addr, p->pid);
    }
    /* Deliver to the user-mode exception dispatcher if one is registered. */
    if (user_exception_dispatch(r, (uint32_t)st, (r->error & 2) ? 1 : (r->error & 16) ? 8 : 0, addr))
        return 1;
    return 0;                                           /* falls through to user_fault(): kill */
}

int user_fault(struct regs *r)
{
    process_t *p = current_process();
    uint32_t code;
    if (!p)
        return 0;
    switch (r->vector) {
    case 0: code = (uint32_t)STATUS_INTEGER_DIVIDE_BY_ZERO; break;
    case 1: code = (uint32_t)STATUS_SINGLE_STEP; break;
    case 3: code = (uint32_t)STATUS_BREAKPOINT; break;
    case 5: code = (uint32_t)STATUS_ARRAY_BOUNDS_EXCEEDED; break;
    case 6: code = (uint32_t)STATUS_ILLEGAL_INSTRUCTION; break;
    case 13: code = (uint32_t)STATUS_ACCESS_VIOLATION; break;
    case 14: code = (uint32_t)STATUS_ACCESS_VIOLATION; break;
    case 17: code = (uint32_t)STATUS_DATATYPE_MISALIGNMENT; break;
    default: code = 0xC0000000u | r->vector; break;
    }
    if (r->vector == 13 && !(r->error & 0xfff))
        code = (uint32_t)STATUS_PRIVILEGED_INSTRUCTION;        /* GP with no selector: privileged/non-canonical */
    if (user_exception_dispatch(r, code, r->vector == 14 ? ((r->error & 2) ? 1 : 0) : 0, r->vector == 14 ? read_cr2() : 0))
        return 1;
    kprintf("K64: process %s (pid %d) killed: vector %d error %llx rip %llx cr2 %llx status %x\n", p->name, p->pid,
            (int)r->vector, r->error, r->rip, r->vector == 14 ? read_cr2() : 0, code);
    process_terminate(p, (int64_t)(int32_t)code, 1);
    process_thread_gone(p);
    thread_exit((int32_t)code);
}

/* No user-mode dispatcher yet in this stage: report "not delivered". */
int __attribute__((weak)) user_exception_dispatch(struct regs *r, uint32_t code, uint64_t info0, uint64_t info1)
{
    (void)r; (void)code; (void)info0; (void)info1;
    return 0;
}
