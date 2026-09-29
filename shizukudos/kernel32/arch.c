/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 CPU setup: its own GDT, TSS and IDT, interrupt dispatch and exception
 * reporting. Nothing from the Supervisor's boot GDT survives.
 */
#include "k32.h"

extern void gdt_flush(void *gdtr, uint16_t tss_sel);
extern void idt_load(void *idtr);
extern const uint32_t isr_stub_table[256];

struct __attribute__((packed)) dtr { uint16_t limit; uint32_t base; };
struct __attribute__((packed)) idt_gate { uint16_t lo; uint16_t sel; uint8_t zero; uint8_t type; uint16_t hi; };
struct __attribute__((packed)) tss32 {
    uint32_t link, esp0, ss0, esp1, ss1, esp2, ss2, cr3, eip, eflags;
    uint32_t eax, ecx, edx, ebx, esp, ebp, esi, edi;
    uint32_t es, cs, ss, ds, fs, gs, ldt;
    uint16_t trap, iomap;
};

static uint64_t gdt[6];
static struct tss32 tss;
static struct idt_gate idt[256];
static uint32_t exception_count[32];
static uint64_t timer_irqs;

static uint64_t gdt_entry(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
{
    return (uint64_t)(limit & 0xffff) | ((uint64_t)(base & 0xffffff) << 16) | ((uint64_t)access << 40) |
           ((uint64_t)(((limit >> 16) & 0xf) | (flags << 4)) << 48) | ((uint64_t)(base >> 24) << 56);
}

void tss_set_kernel_stack(uint32_t esp0) { tss.esp0 = esp0; }

void arch_init(void)
{
    struct dtr gdtr, idtr;
    unsigned i;
    memset(&tss, 0, sizeof tss);
    tss.ss0 = 0x10;
    tss.iomap = sizeof tss;
    gdt[0] = 0;
    gdt[1] = gdt_entry(0, 0xfffff, 0x9a, 0xc);      /* 0x08 kernel code */
    gdt[2] = gdt_entry(0, 0xfffff, 0x92, 0xc);      /* 0x10 kernel data */
    gdt[3] = gdt_entry(0, 0xfffff, 0xfa, 0xc);      /* 0x18 user code (DPL 3) */
    gdt[4] = gdt_entry(0, 0xfffff, 0xf2, 0xc);      /* 0x20 user data (DPL 3) */
    gdt[5] = gdt_entry((uint32_t)&tss, sizeof tss - 1, 0x89, 0x0);   /* 0x28 available 32-bit TSS */
    gdtr.limit = sizeof gdt - 1;
    gdtr.base = (uint32_t)gdt;
    for (i = 0; i < 256; ++i) {
        const uint32_t h = isr_stub_table[i];
        idt[i].lo = (uint16_t)h;
        idt[i].hi = (uint16_t)(h >> 16);
        idt[i].sel = 0x08;
        idt[i].zero = 0;
        idt[i].type = i == VEC_SYSCALL ? 0xee : 0x8e;   /* int 0x80 callable from ring 3 */
    }
    idtr.limit = sizeof idt - 1;
    idtr.base = (uint32_t)idt;
    gdt_flush(&gdtr, 0x28);
    idt_load(&idtr);
}

uint64_t arch_timer_irqs(void) { return timer_irqs; }
uint32_t arch_exception_count(unsigned v) { return v < 32 ? exception_count[v] : 0; }

/* Demand-paged kernel range for the #PF self-test. */
static uint32_t demand_lo, demand_hi;
uint32_t demand_faults;
void vm_set_demand_range(uint32_t lo, uint32_t hi) { demand_lo = lo; demand_hi = hi; }

static const char *const names[32] = {
    "#DE", "#DB", "NMI", "#BP", "#OF", "#BR", "#UD", "#NM", "#DF", "CSO", "#TS", "#NP", "#SS", "#GP", "#PF", "rsv",
    "#MF", "#AC", "#MC", "#XM", "#VE", "#CP", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "rsv", "#SX", "rsv"};

void isr_dispatch(struct regs *r)
{
    if (r->vector < 32)
        ++exception_count[r->vector];
    switch (r->vector) {
    case VEC_TIMER:
        ++timer_irqs;
#ifdef SHZ_STANDALONE
        {
            extern void standalone_eoi(void);
            standalone_eoi();                   /* 8259 EOI before a possible context switch */
        }
#endif
        sched_tick();
        return;
    case VEC_DOORBELL: {
        extern void ipc_doorbell_irq(void);
        ipc_doorbell_irq();
        return;
    }
    case VEC_SYSCALL:
        user_syscall(r);
        return;
    default:
        break;
    }
    if (r->vector == 14 && !(r->cs & 3)) {
        const uint32_t addr = read_cr2();
        if (addr >= demand_lo && addr < demand_hi && !(r->error & 1)) {
            const uint32_t pa = pmm_alloc();
            KASSERT(pa);
            KASSERT(vm_map(read_cr3(), addr & ~0xfffu, pa, PTE_W) == 0);
            ++demand_faults;
            return;
        }
    }
    if (r->cs & 3) {
        if (user_fault(r))
            return;
    }
    kprintf("K32 EXCEPTION %s (vec %d) err=%x eip=%x cs=%x eflags=%x cr2=%x cr3=%x\n",
            r->vector < 32 ? names[r->vector] : "??", (int)r->vector, r->error, r->eip, r->cs, r->eflags,
            read_cr2(), read_cr3());
    kprintf("  eax=%x ebx=%x ecx=%x edx=%x esi=%x edi=%x ebp=%x\n", r->eax, r->ebx, r->ecx, r->edx, r->esi, r->edi, r->ebp);
    shz_evidence(31, 0xdead0000u | r->vector);
    shz_exit(98);
}
