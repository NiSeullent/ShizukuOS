/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 CPU setup: GDT/TSS (with an IST stack for double faults), IDT, SYSCALL MSRs,
 * interrupt dispatch and exception reporting.
 */
#include "k64.h"
#include "smp_boot.h"
#include "../dead_screen/native.h"

extern void load_gdt(void *gdtr, uint16_t tss_sel);
extern void load_idt(void *idtr);
extern void syscall_entry(void);
extern const uint64_t isr_stub_table[256];
#ifdef SHZ_STANDALONE
extern void standalone_eoi(void);
extern void standalone_eoi_irq(unsigned vector);
#endif

struct __attribute__((packed)) dtr { uint16_t limit; uint64_t base; };
struct __attribute__((packed)) idt_gate { uint16_t lo, sel; uint8_t ist, type; uint16_t mid; uint32_t hi, zero; };
struct __attribute__((packed)) tss64 {
    uint32_t reserved0;
    uint64_t rsp[3];
    uint64_t reserved1;
    uint64_t ist[7];
    uint64_t reserved2;
    uint16_t reserved3, iomap;
};

static uint64_t gdt[7];
static struct tss64 tss;
static struct idt_gate idt[256];
static uint8_t df_stack[8192] __attribute__((aligned(16)));
static uint8_t nmi_stack[8192] __attribute__((aligned(16)));
static uint32_t exception_count[32];
static uint64_t timer_irqs;
static void (*irq_handlers[256])(struct regs *);

extern volatile int pma_sched_trace_enabled;
void __attribute__((weak)) pma_sched_trace_irq(uint64_t rip, uint64_t flags)
{ (void)rip; (void)flags; }

/* Device interrupt handlers (standalone profile: legacy PIC vectors 0x20..0x2f). The handler runs with interrupts off in
 * the interrupted thread's context; the PIC EOI is sent after it returns, so it must not schedule away. */
void irq_register(unsigned vector, void (*handler)(struct regs *)) { if (vector < 256) irq_handlers[vector] = handler; }
irq_handler_t irq_handler_get(unsigned vector) { return vector < 256 ? irq_handlers[vector] : 0; }

void tss_set_rsp0(uint64_t rsp0) { tss.rsp[0] = rsp0; }
_Static_assert(offsetof(shz_smp_cpu_t, syscall_kstack) == 0 &&
               offsetof(shz_smp_cpu_t, syscall_user_rsp) == 8, "SWAPGS anchor ABI");
static int entry_stack_valid(uint64_t top)
{
    return (top >> 48) == 0xffff && ((top >> 47) & 1) && !(top & 15) && top >= KSTACK_BYTES;
}
int arch_sched_entry_bind(uint32_t cpu, uint64_t top)
{
    if (cpu >= SHZ_SMP_MAX_CPUS || shz_smp_this_cpu() != cpu || !entry_stack_valid(top)) return -1;
    if (cpu) return -2;                     /* AP private TSS/IDT handoff not admitted */
    const uint64_t flags = irq_save();
    if (flags & 0x200) { irq_restore(flags); return -1; }
    shz_smp_cpus[cpu].syscall_kstack = top;
    shz_smp_cpus[cpu].syscall_user_rsp = 0;
    wrmsr(MSR_KERNEL_GS_BASE, (uint64_t)&shz_smp_cpus[cpu]);
    tss_set_rsp0(top);
    irq_restore(flags);
    return 0;
}
int arch_sched_entry_set_stack(uint32_t cpu, uint64_t top)
{
    if (cpu >= SHZ_SMP_MAX_CPUS || shz_smp_this_cpu() != cpu || !entry_stack_valid(top)) return -1;
    if (cpu) return -2;
    const uint64_t flags = irq_save();
    if ((flags & 0x200) || rdmsr(MSR_KERNEL_GS_BASE) != (uint64_t)&shz_smp_cpus[cpu]) {
        irq_restore(flags);
        return -1;
    }
    shz_smp_cpus[cpu].syscall_kstack = top;
    tss_set_rsp0(top);
    irq_restore(flags);
    return 0;
}
uint64_t arch_timer_irqs(void) { return timer_irqs; }
uint32_t arch_exception_count(unsigned v) { return v < 32 ? exception_count[v] : 0; }

void arch_init(void)
{
    struct dtr gdtr, idtr;
    const uint64_t tss_base = (uint64_t)&tss;
    unsigned i;
    memset(&tss, 0, sizeof tss);
    tss.iomap = sizeof tss;
    tss.ist[0] = (uint64_t)df_stack + sizeof df_stack;
    tss.ist[1] = (uint64_t)nmi_stack + sizeof nmi_stack;
    gdt[0] = 0;
    gdt[1] = 0x00af9b000000ffffull;             /* 0x08 kernel code (L=1) */
    gdt[2] = 0x00cf93000000ffffull;             /* 0x10 kernel data */
    gdt[3] = 0x00cff3000000ffffull;             /* 0x18 user data (DPL 3) */
    gdt[4] = 0x00affb000000ffffull;             /* 0x20 user code 64-bit (DPL 3) */
    /* 0x28: 64-bit available TSS, 16-byte descriptor */
    gdt[5] = (sizeof tss - 1) | ((tss_base & 0xffffffull) << 16) | (0x89ull << 40) | (((tss_base >> 24) & 0xff) << 56);
    gdt[6] = tss_base >> 32;
    gdtr.limit = sizeof gdt - 1;
    gdtr.base = (uint64_t)gdt;
    for (i = 0; i < 256; ++i) {
        const uint64_t h = isr_stub_table[i];
        idt[i].lo = (uint16_t)h;
        idt[i].mid = (uint16_t)(h >> 16);
        idt[i].hi = (uint32_t)(h >> 32);
        idt[i].sel = 0x08;
        idt[i].ist = i == 8 ? 1 : (i == 2 ? 2 : 0);
        idt[i].type = i == 3 ? 0xee : 0x8e;         /* #BP gate DPL 3: INT3 in ring 3 is a breakpoint (a DPL-0 gate turns it into #GP) */
        idt[i].zero = 0;
    }
    idtr.limit = sizeof idt - 1;
    idtr.base = (uint64_t)idt;
    load_gdt(&gdtr, 0x28);
    load_idt(&idtr);

    /* SYSCALL: STAR[47:32] = kernel CS (0x08); STAR[63:48] = 0x10 so SYSRET yields SS = 0x18|3
     * and CS = 0x20|3. SFMASK clears IF, DF, TF and AC on entry. EFER.SCE|NXE are enabled
     * through the Supervisor's validated WRMSR path. */
    wrmsr(MSR_EFER, rdmsr(MSR_EFER) | 1 | (1ull << 11));
    wrmsr(MSR_STAR, (0x10ull << 48) | (0x08ull << 32));
    wrmsr(MSR_LSTAR, (uint64_t)syscall_entry);
    wrmsr(MSR_SFMASK, 0x40700);
    /* SSE for user threads: OSFXSR | OSXMMEXCPT, and clear CR0.EM / set MP. */
    write_cr4(read_cr4() | (1ull << 9) | (1ull << 10));
    /* CR0.WP: ring 0 must honour read-only pages (copy_to_user, protection faults) whatever the loader left set. */
    write_cr0((read_cr0() & ~4ull) | 2ull | (1ull << 16));
}

static const char *const names[32] = {
    "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM", "#DF", "CSO", "#TS", "#NP", "#SS", "#GP", "#PF", "rsv",
    "#MF", "#AC", "#MC", "#XM", "#VE", "#CP", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "#SX", "rsv"};

/* Kernel-mode demand paging window for the #PF self-test. */
static uint64_t demand_lo, demand_hi;
uint64_t demand_faults;
void vm_set_demand_range(uint64_t lo, uint64_t hi) { demand_lo = lo; demand_hi = hi; }

void isr_dispatch(struct regs *r)
{
    if (r->vector < 32)
        ++exception_count[r->vector];
    else
        krandom_irq(r->vector, r->rip);            /* interrupt arrival times feed the entropy pool */
    /* Emergency IST frames cannot pass through driver/user recovery hooks:
     * those hooks may wait or dispatch on a stack shared by later interrupts. */
    if (r->vector == 2 || r->vector == 8) goto fatal_exception;
    switch (r->vector) {
    case VEC_TIMER:
        if (pma_sched_trace_enabled) pma_sched_trace_irq(r->rip, r->rflags);
        ++timer_irqs;
#ifdef SHZ_STANDALONE
        standalone_eoi();                   /* PIT IRQ0 through the 8259: acknowledge before any context switch */
#endif
        sched_tick_from((r->cs & 3) == 3);  /* CPU-time accounting charges the tick to user or kernel mode */
        if (r->cs & 3) {                    /* a thread preempted in ring 3 of a killed/exiting process ends here, so */
            extern void check_kill(void);   /* TerminateProcess also stops threads that never enter the kernel */
            extern int current_thread_must_stop(void);
            if (current_thread_must_stop()) {   /* die, or park while suspended (NtSuspendThread) */
                sti();                      /* like a system call: teardown work runs preemptible (the frame is ring 3) */
                check_kill();
            }
        }
        return;
    case VEC_DOORBELL: {
        extern void ipc64_doorbell_irq(void);
#ifdef SHZ_STANDALONE
        if (irq_handlers[r->vector]) {      /* standalone: 0x21 = PIC base + 1 is IRQ 1 (the i8042 keyboard), no doorbell exists */
            irq_handlers[r->vector](r);
            standalone_eoi_irq(r->vector);
            return;
        }
#endif
        ipc64_doorbell_irq();
        return;
    }
    default:
        if (r->vector >= 0x20 && irq_handlers[r->vector]) {
            irq_handlers[r->vector](r);
#ifdef SHZ_STANDALONE
            standalone_eoi_irq(r->vector);
#endif
            return;
        }
        break;
    }
    if (r->vector == 14) {
        const uint64_t addr = read_cr2();
        if (!(r->cs & 3) && addr >= KWIN_BASE && addr < KWIN_BASE + KWIN_SIZE && !(r->error & 1)) {
            extern int kwin_fault(uint64_t addr);       /* kernel file view page (kwin.c) */
            if (kwin_fault(addr))
                return;
        }
        if (!(r->cs & 3) && addr >= demand_lo && addr < demand_hi && !(r->error & 1)) {
            const uint64_t pa = pmm_alloc();
            KASSERT(pa);
            KASSERT(vm_map(kernel_pml4(), addr & ~0xfffull, pa, PT_W | PT_NX) == 0);
            ++demand_faults;
            return;
        }
        {
            extern int user_page_fault(struct regs *r, uint64_t addr);
            if ((r->cs & 3) && user_page_fault(r, addr))
                return;
        }
    }
    {
        extern int ntdrv_kernel_exception(struct regs *r);   /* ntdrv_seh.c: a fault inside a hosted driver goes to its SEH handlers */
        if (!(r->cs & 3) && ntdrv_kernel_exception(r))
            return;
    }
    if (r->cs & 3) {
        if (user_fault(r))
            return;
    }
fatal_exception:
    kprintf("K64 EXCEPTION %s (vec %d) err=%llx rip=%llx cs=%llx rflags=%llx rsp=%llx cr2=%llx cr3=%llx\n",
            r->vector < 32 ? names[r->vector] : "??", (int)r->vector, r->error, r->rip, r->cs, r->rflags, r->rsp,
            read_cr2(), read_cr3());
    kprintf("  rax=%llx rbx=%llx rcx=%llx rdx=%llx rsi=%llx rdi=%llx rbp=%llx\n", r->rax, r->rbx, r->rcx, r->rdx,
            r->rsi, r->rdi, r->rbp);
    shz_evidence(31, 0xdead0000ull | r->vector);
    if (!(r->cs & 3)) ds_native_exception(r);
    shz_exit(98);
}

/* Overridden by ipc64.c when the IPC endpoint is linked in. */
void __attribute__((weak)) ipc64_doorbell_irq(void) { }
