/* SPDX-License-Identifier: GPL-2.0-only
 * Ring-3 processes for Kernel32: private address spaces, an int 0x80 system-call
 * gate, argument validation, and containment of user faults.
 */
#include "k32.h"
#include "smp_native.h"

extern void enter_user(uint32_t entry, uint32_t user_esp);

#define USER_BASE 0x40000000u
#define USER_STACK_TOP 0x40800000u
#define MAX_PROCS 8

enum { SYS_WRITE = 1, SYS_EXIT = 2, SYS_GETPID = 3, SYS_YIELD = 4, SYS_EVIDENCE = 5, SYS_SLEEP = 6, SYS_TICKS = 7 };

struct proc {
    int used, pid, done, faulted, exit_code;
    uint32_t pd, entry;
    thread_t *thread;
    ksem_t exited;
    char name[16];
};
static struct proc procs[MAX_PROCS + 1];
static uint32_t syscalls;

extern uint32_t kernel_space(void);
uint32_t user_syscall_count(void) { return syscalls; }

uint32_t proc_page_directory(uint32_t proc_id)
{
    return proc_id && proc_id <= MAX_PROCS && procs[proc_id].used ? procs[proc_id].pd : 0;
}

static struct proc *current_proc(void)
{
    const uint32_t id = thread_current()->proc;
    return id ? &procs[id] : 0;
}

static void proc_thread(void *arg)
{
    struct proc *p = arg;
    /* The thread trampoline enables IRQs. Keep CPU identity and CR3/TSS
     * publication indivisible through enter_user's GS change; IRETD restores
     * user IF from its 0x202 frame after the privilege transition. */
    cli();
    write_cr3(p->pd);
    tss_set_kernel_stack(thread_current()->stack_base + 16384);
    enter_user(p->entry, USER_STACK_TOP - 16);
    thread_exit(-1);
}

int proc_create(const char *name, const uint8_t *image, uint32_t size, int *pid_out)
{
    if(k32_ap_active() || arch_cpu_id()!=0) return -1;
    struct proc *p = 0;
    unsigned i, k;
    uint32_t off, f;
    for (i = 1; i <= MAX_PROCS; ++i)
        if (!procs[i].used) { p = &procs[i]; break; }
    if (!p || !size || size > 0x100000)
        return -1;
    memset(p, 0, sizeof *p);
    p->pid = (int)i;
    for (k = 0; name[k] && k < 15; ++k) p->name[k] = name[k];
    sem_init(&p->exited, 0);
    p->pd = vm_new_space();
    if (!p->pd)
        return -1;
    /* code + data: user-accessible writable pages holding the program image */
    for (off = 0; off < size; off += PAGE_SIZE) {
        const uint32_t pa = pmm_alloc();
        uint32_t n = size - off < PAGE_SIZE ? size - off : PAGE_SIZE;
        if (!pa || vm_map(p->pd, USER_BASE + off, pa, PTE_U | PTE_W)) { vm_free_space(p->pd); return -1; }
        memcpy((void *)pa, image + off, n);
    }
    if (vm_map_range(p->pd, USER_STACK_TOP - 2 * PAGE_SIZE, 2 * PAGE_SIZE, PTE_U | PTE_W)) {
        vm_free_space(p->pd);
        return -1;
    }
    p->entry = USER_BASE;
    /* thread_create publishes READY and restores its caller's interrupt state.
     * Keep the UP timer masked until both ownership links are published. */
    f = irq_save();
    p->used = 1;
    p->thread = thread_create(p->name, proc_thread, p);
    if (!p->thread) {
        const uint32_t pd = p->pd;
        p->used = 0;
        p->pd = 0;
        irq_restore(f);
        vm_free_space(pd);
        return -1;
    }
    p->thread->proc = (uint32_t)p->pid;
    if (pid_out) *pid_out = p->pid;
    irq_restore(f);
    return 0;
}

int proc_wait(int pid, int *exit_code, int *faulted)
{
    struct proc *p;
    if (pid < 1 || pid > MAX_PROCS || !procs[pid].used)
        return -1;
    p = &procs[pid];
    sem_wait(&p->exited);
    if (exit_code) *exit_code = p->exit_code;
    if (faulted) *faulted = p->faulted;
    thread_join(p->thread);
    p->thread = 0;
    write_cr3(kernel_space());
    vm_free_space(p->pd);
    p->used = 0;
    return 0;
}

static int user_range_ok(struct proc *p, uint32_t va, uint32_t len)
{
    uint32_t a;
    if (va < USER_BASE || va + len < va || va + len > USER_STACK_TOP)
        return 0;
    for (a = va & ~0xfffu; a < va + len; a += PAGE_SIZE) {
        const uint32_t pde = *((uint32_t *)p->pd + (a >> 22));
        uint32_t pte;
        if (!(pde & PTE_P)) return 0;
        pte = ((uint32_t *)(pde & ~0xfffu))[(a >> 12) & 0x3ff];
        if (!(pte & PTE_P) || !(pte & PTE_U)) return 0;
    }
    return 1;
}

static void finish(struct proc *p, int code, int faulted)
{
    p->exit_code = code;
    p->faulted = faulted;
    p->done = 1;
    sem_post(&p->exited);
    thread_exit(code);
}

void user_syscall(struct regs *r)
{
    struct proc *p = current_proc();
    ++syscalls;
    if (!p) {
        r->eax = (uint32_t)-1;
        return;
    }
    switch (r->eax) {
    case SYS_WRITE: {
        char buf[121];
        uint32_t n = r->ecx, i;
        if (n > 120 || !user_range_ok(p, r->ebx, n)) { r->eax = (uint32_t)-1; break; }
        for (i = 0; i < n; ++i)
            buf[i] = *(char *)vm_translate(p->pd, r->ebx + i);
        buf[n] = 0;
        kprintf("[user %s pid %d] %s", p->name, p->pid, buf);
        r->eax = n;
        break;
    }
    case SYS_EXIT: finish(p, (int)r->ebx, 0); break;
    case SYS_GETPID: r->eax = (uint32_t)p->pid; break;
    case SYS_YIELD: thread_yield(); r->eax = 0; break;
    case SYS_EVIDENCE:
        if (r->ebx >= 16 && r->ebx < 24) { shz_evidence(r->ebx, r->ecx); r->eax = 0; }
        else r->eax = (uint32_t)-1;
        break;
    case SYS_SLEEP: thread_sleep_ms(r->ebx); r->eax = 0; break;
    case SYS_TICKS: r->eax = (uint32_t)ticks_now(); break;
    default: r->eax = (uint32_t)-38; break;         /* ENOSYS */
    }
}

/* A fault from ring 3 kills only that process; the kernel keeps running. */
int user_fault(struct regs *r)
{
    struct proc *p = current_proc();
    if (!p)
        return 0;
    kprintf("K32: process %s (pid %d) killed: vector %d error %x eip %x cr2 %x\n", p->name, p->pid, (int)r->vector,
            r->error, r->eip, r->vector == 14 ? read_cr2() : 0);
    finish(p, (int)(0x80000000u | r->vector), 1);
    return 1;
}
