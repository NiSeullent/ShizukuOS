/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 CPU setup: its own GDT, TSS and IDT, interrupt dispatch and exception
 * reporting. Nothing from the Supervisor's boot GDT survives.
 */
#include "k32.h"
#include "smp_native.h"

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

/* Selector0x30 is private kernel data, absent from the user descriptor set.
 * APs need their own GDT/TSS/anchor before any online handshake. */
static struct { uint32_t magic, id; } bsp_identity = { 0x32435055u, 0 };
static uint64_t gdt[7];
static struct tss32 tss __attribute__((aligned(16)));
static struct idt_gate idt[256];
static uint32_t exception_count[32];
static uint64_t timer_irqs;
struct ap_arch { uint64_t gdt[7]; struct tss32 tss; struct idt_gate idt[256]; struct {uint32_t magic,id;} anchor; };
_Static_assert(sizeof(struct ap_arch)<=4096,"private32 tables fit owned page");
_Static_assert(offsetof(struct ap_arch,tss)%4==0 && offsetof(struct tss32,esp0)==4,"owning TSS esp0 is aligned");
static void tss_publish(struct tss32 *p,uint32_t esp)
{ *(volatile uint32_t *)((uint8_t *)p+offsetof(struct tss32,esp0))=esp; }
static struct ap_arch *private_arch[K32_AP_MAX];

static uint64_t gdt_entry(uint32_t base, uint32_t limit, uint8_t access, uint8_t flags)
{
    return (uint64_t)(limit & 0xffff) | ((uint64_t)(base & 0xffffff) << 16) | ((uint64_t)access << 40) |
           ((uint64_t)(((limit >> 16) & 0xf) | (flags << 4)) << 48) | ((uint64_t)(base >> 24) << 56);
}

uint32_t arch_cpu_id(void)
{
    uint16_t selector;
    uint32_t magic, id;
    __asm__ volatile("mov %%gs, %0" : "=r"(selector));
    if (selector != 0x30) return UINT32_MAX;
    __asm__ volatile("movl %%gs:0, %0; movl %%gs:4, %1" : "=r"(magic), "=r"(id));
    if(magic!=0x32435055u || id>=K32_AP_MAX)return UINT32_MAX;
    if(!id)return 0;
    struct dtr gdtr;__asm__ volatile("sgdt %0":"=m"(gdtr));
    struct ap_arch *a=private_arch[id];
    return a && gdtr.base==(uint32_t)a->gdt && gdtr.limit==55 &&
        (a->gdt[6]&~(1ull<<40))==gdt_entry((uint32_t)&a->anchor,7,0x92,0x4) &&
        k32_ap_identity(id) ? id : UINT32_MAX;
}
void tss_set_kernel_stack(uint32_t esp0)
{
    unsigned cpu=arch_cpu_id();KASSERT(cpu<K32_AP_MAX && !(k32_flags()&0x200));
    if(!cpu)tss_publish(&tss,esp0);
    else tss_publish(&private_arch[cpu]->tss,esp0);
}

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
    gdt[6] = gdt_entry((uint32_t)&bsp_identity, sizeof bsp_identity - 1, 0x92, 0x4); /* 0x30 CPU anchor */
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
    const unsigned cpu=arch_cpu_id();
    if(cpu) { k32_ap_interrupt(r,cpu);return; }
    if(k32_ap_active() && r->vector==K32_AP_SPURIOUS)return;
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

int k32_ap_arch_prepare(unsigned cpu)
{
    if(!cpu || cpu>=k32_ap_count() || arch_cpu_id()!=0 || k32_ap_started() || private_arch[cpu])return -1;
    const uint32_t page=pmm_alloc();if(!page)return -1;
    private_arch[cpu]=(struct ap_arch *)page;k32_ap_cpus[cpu].arch=page;
    struct ap_arch *a=private_arch[cpu];a->tss.ss0=0x10;a->tss.iomap=sizeof a->tss;
    a->tss.esp0=k32_ap_cpus[cpu].boot+K32_AP_STACK;
    a->gdt[1]=gdt_entry(0,0xfffff,0x9a,0xc);a->gdt[2]=gdt_entry(0,0xfffff,0x92,0xc);
    a->gdt[5]=gdt_entry((uint32_t)&a->tss,sizeof a->tss-1,0x89,0);
    a->anchor.magic=0x32435055u;a->anchor.id=cpu;
    a->gdt[6]=gdt_entry((uint32_t)&a->anchor,7,0x92,4);
    for(unsigned i=0;i<256;i++) {
        uint32_t h=isr_stub_table[i];a->idt[i]=(struct idt_gate){(uint16_t)h,8,0,0x8e,(uint16_t)(h>>16)};
    }
    return 0;
}
uint32_t k32_ap_arch_anchor(unsigned cpu)
{ return cpu<K32_AP_MAX && private_arch[cpu]?(uint32_t)&private_arch[cpu]->anchor:0; }
void k32_ap_arch_tss(unsigned cpu,uint32_t top)
{ if(cpu && cpu<K32_AP_MAX && private_arch[cpu] && arch_cpu_id()==cpu && !(k32_flags()&0x200))tss_publish(&private_arch[cpu]->tss,top); }
int k32_ap_arch_enter(unsigned cpu)
{
    if(!cpu || cpu>=k32_ap_count() || !private_arch[cpu] || !k32_ap_identity(cpu) ||
       (k32_flags()&0x200) || read_cr3()!=kernel_space() || (read_cr4()&0x20))return -1;
    struct ap_arch *a=private_arch[cpu];
    struct dtr gdtr={sizeof a->gdt-1,(uint32_t)a->gdt},idtr={sizeof a->idt-1,(uint32_t)a->idt};
    gdt_flush(&gdtr,0x28);idt_load(&idtr);
    struct dtr actual_g,actual_i;uint16_t tr,cs;
    __asm__ volatile("sgdt %0; sidt %1; str %2; mov %%cs,%3":"=m"(actual_g),"=m"(actual_i),"=r"(tr),"=r"(cs));
    uint32_t sp=k32_stack_pointer(),base=k32_ap_cpus[cpu].boot;
    if(memcmp(&actual_g,&gdtr,sizeof gdtr) || memcmp(&actual_i,&idtr,sizeof idtr) || tr!=0x28 || cs!=8 ||
       sp<base || sp>=base+K32_AP_STACK || arch_cpu_id()!=cpu)return -1;
    k32_ap_cpu_t *record=&k32_ap_cpus[cpu];
    record->actual_id=arch_cpu_id();record->actual_apic=k32_ap_physical_id();record->actual_root=read_cr3();
    record->actual_gdt=actual_g.base;record->actual_idt=actual_i.base;record->actual_tr=tr;record->actual_cs=cs;
    record->actual_boot_sp=sp;record->actual_flags=k32_flags();
    return 0;
}
