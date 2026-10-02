/* SPDX-License-Identifier: GPL-2.0-only
 * Private architecture for native AP bringup workers. AP interrupts never
 * enter the UP scheduler, its singleton TSS/syscall scratch or device handlers.
 */
#include "cpu_arch_bringup.h"
#include "pci.h"
_Static_assert(TICK_US==1000u,"native cohort PIT2 calibration is one millisecond");
static shz_cpu_arch_tables_t *tables[SHZ_SMP_MAX_CPUS];
static unsigned allocated_count;
static uint32_t entered_mask, scheduler_gate_mask;
#ifdef SHZ_STANDALONE
static volatile uint32_t *scheduler_lapic;
static uint32_t scheduler_timer_count;
#endif
extern const uint64_t isr_stub_table[256];
extern void load_gdt(void *,uint16_t);
extern void load_idt(void *);
struct cpu_iret_frame { uint64_t rip,cs,flags,rsp,ss; };

static void fault(void)
{
    const unsigned cpu=shz_smp_this_cpu();
    shz_cpu_arch_fault(cpu);
    if(cpu<SHZ_SMP_MAX_CPUS)
        __atomic_store_n(&shz_smp_cpus[cpu].state,SHZ_SMP_CPU_FAILED,__ATOMIC_RELEASE);
    for(;;) __asm__ volatile("cli; hlt");
}
static void __attribute__((interrupt)) fault_no_error(struct cpu_iret_frame *frame)
{ (void)frame; fault(); }
static void __attribute__((interrupt)) fault_error(struct cpu_iret_frame *frame,uint64_t error)
{ (void)frame;(void)error;fault(); }
static void __attribute__((interrupt)) wake(struct cpu_iret_frame *frame)
{ uint64_t local=0;(void)frame;shz_cpu_arch_ipi(0,(uint64_t)&local);shz_smp_apic_eoi(); }
static void __attribute__((interrupt)) verify(struct cpu_iret_frame *frame)
{ uint64_t local=0;(void)frame;shz_cpu_arch_ipi(1,(uint64_t)&local);shz_smp_apic_eoi(); }
/* Masking the LVT does not retract a timer already in local IRR. After stop,
 * retain a private non-scheduling drain gate rather than faulting that vector. */
static void __attribute__((interrupt)) quiesced_timer(struct cpu_iret_frame *frame)
{ (void)frame;shz_smp_apic_eoi(); }
static void __attribute__((interrupt)) spurious(struct cpu_iret_frame *frame)
{ (void)frame; }
static int high_stack(uint64_t top,uint64_t bytes)
{ return (top>>48)==0xffff && ((top>>47)&1) && !(top&15) && top>=bytes; }
static int overlaps(uint64_t a,uint64_t as,uint64_t b,uint64_t bs)
{ return a-as<b && b-bs<a; }
static void gate(shz_cpu_gate_t *g,uint64_t entry,unsigned ist)
{
    g->lo=(uint16_t)entry;g->mid=(uint16_t)(entry>>16);g->hi=(uint32_t)(entry>>32);
    g->selector=8;g->ist=(uint8_t)ist;g->type=0x8e;g->zero=0;
}
int shz_cpu_arch_build_tables(shz_cpu_arch_tables_t *t,uint64_t boot,uint64_t irq,uint64_t df)
{
    const uint64_t base=(uintptr_t)t;
    /* The pure builder uses the actual member address, also for host controls.
     * Native ownership/canonical mapping is validated before INIT. Reject the
     * full retained resource's overlap before touching any descriptors. */
    if(!t || (base&15) || base>UINT64_MAX-SHZ_CPU_ARCH_BYTES ||
       !high_stack(boot,KSTACK_BYTES) || !high_stack(irq,KSTACK_BYTES) || !high_stack(df,8192) ||
       overlaps(base+SHZ_CPU_ARCH_BYTES,SHZ_CPU_ARCH_BYTES,boot,KSTACK_BYTES) ||
       overlaps(base+SHZ_CPU_ARCH_BYTES,SHZ_CPU_ARCH_BYTES,irq,KSTACK_BYTES) ||
       overlaps(base+SHZ_CPU_ARCH_BYTES,SHZ_CPU_ARCH_BYTES,df,8192) ||
       overlaps(boot,KSTACK_BYTES,irq,KSTACK_BYTES) || overlaps(boot,KSTACK_BYTES,df,8192) ||
       overlaps(irq,KSTACK_BYTES,df,8192)) return -1;
    memset(t,0,sizeof *t);
    t->gdt[1]=0x00af9b000000ffffull;t->gdt[2]=0x00cf93000000ffffull;
    const uint64_t tss_base=(uint64_t)&t->tss;
    t->gdt[5]=(sizeof t->tss-1)|((tss_base&0xffffffull)<<16)|(0x89ull<<40)|(((tss_base>>24)&0xff)<<56);
    t->gdt[6]=tss_base>>32;
    t->tss.rsp[0]=boot;t->tss.ist[0]=irq;t->tss.ist[1]=df;t->tss.iomap=sizeof t->tss;
    t->tss.ist[2]=(uintptr_t)t->nmi_stack+sizeof t->nmi_stack;
    for(unsigned i=0;i<256;i++) {
        const int error=i==8 || i==10 || i==11 || i==12 || i==13 || i==14 || i==17 || i==21 || i==29 || i==30;
        gate(&t->idt[i],error?(uint64_t)fault_error:(uint64_t)fault_no_error,i==8?2:i==2?3:1);
    }
    gate(&t->idt[SHZ_SMP_VEC_RESCHEDULE],(uint64_t)wake,1);
    gate(&t->idt[SHZ_SMP_VEC_TLB],(uint64_t)verify,1);
    gate(&t->idt[SHZ_SMP_VEC_SPURIOUS],(uint64_t)spurious,0);
    return 0;
}
int shz_cpu_arch_allocate(unsigned count)
{
    if(allocated_count || !count || count>SHZ_SMP_MAX_CPUS) return -1;
    for(unsigned i=1;i<count;i++) {
        const uint64_t pa=pmm_alloc_contig(SHZ_CPU_ARCH_PAGES);
        if(!pa) {
            for(unsigned j=1;j<i;j++) { pmm_free_contig((uint64_t)tables[j]-phys_base_va,SHZ_CPU_ARCH_PAGES);tables[j]=0; }
            return -1;
        }
        tables[i]=(shz_cpu_arch_tables_t *)p2v(pa);
    }
    allocated_count=count;
    /* After the first INIT, all these pages are retained even on failure. */
    return 0;
}
int shz_cpu_arch_enter(unsigned cpu)
{
    if(!cpu || cpu>=allocated_count || shz_smp_this_cpu()!=cpu || !tables[cpu]) return -1;
    shz_cpu_arch_tables_t *t=tables[cpu];
    if(shz_cpu_arch_build_tables(t,shz_smp_cpus[cpu].boot_stack_top,
        shz_smp_cpus[cpu].irq_stack_top,shz_smp_cpus[cpu].df_stack_top)) return -1;
    shz_cpu_dtr_t gdtr={sizeof t->gdt-1,(uint64_t)t->gdt},idtr={sizeof t->idt-1,(uint64_t)t->idt};
    load_gdt(&gdtr,0x28);load_idt(&idtr);
    /* No AP may use the BSP's global SYSCALL stack/current-thread scratch. */
    wrmsr(MSR_EFER,rdmsr(MSR_EFER)&~1ull);
    shz_cpu_dtr_t actual_gdt,actual_idt;uint16_t tr;
    __asm__ volatile("sgdt %0":"=m"(actual_gdt));__asm__ volatile("sidt %0":"=m"(actual_idt));
    __asm__ volatile("str %0":"=r"(tr));
    if(actual_gdt.base!=gdtr.base || actual_gdt.limit!=gdtr.limit ||
       actual_idt.base!=idtr.base || actual_idt.limit!=idtr.limit || tr!=0x28 ||
       (rdmsr(MSR_EFER)&1)) return -1;
    __atomic_fetch_or(&entered_mask,1u<<cpu,__ATOMIC_RELEASE);
    return 0;
}
uint64_t shz_cpu_arch_resource(unsigned cpu)
{ return cpu && cpu<allocated_count && tables[cpu] ? (uint64_t)tables[cpu]-phys_base_va:0; }
int shz_cpu_arch_describe(unsigned cpu,uint64_t *gdt,uint64_t *idt,uint64_t *tss)
{
    shz_cpu_dtr_t gdtr,idtr;uint16_t tr;
    if(!gdt || !idt || !tss || shz_smp_this_cpu()!=cpu) return -1;
    __asm__ volatile("sgdt %0":"=m"(gdtr));__asm__ volatile("sidt %0":"=m"(idtr));
    __asm__ volatile("str %0":"=r"(tr));
    const unsigned index=(tr&~7u)/8;
    if((tr&7) || gdtr.limit<index*8+15 || idtr.limit!=4095) return -1;
    const uint64_t *entries=(const uint64_t *)gdtr.base;
    *gdt=gdtr.base;*idt=idtr.base;
    *tss=((entries[index]>>16)&0xffffff)|((entries[index]>>32)&0xff000000)|(entries[index+1]<<32);
    return 0;
}

/* The strong provider and verified private table entry are admission facts.
 * Ordinary GS_BASE is deliberately untouched; AP syscall remains disabled. */
int shz_cpu_arch_sched_stack(unsigned cpu,uint64_t top,int bind)
{
    if(!cpu || cpu>=allocated_count || shz_smp_this_cpu()!=cpu || !high_stack(top,KSTACK_BYTES)) return -1;
    if(!(__atomic_load_n(&entered_mask,__ATOMIC_ACQUIRE)&(1u<<cpu)) || !tables[cpu] ||
       __atomic_load_n(&shz_smp_cpus[cpu].state,__ATOMIC_ACQUIRE)!=SHZ_SMP_CPU_ONLINE) return -2;
    const uint64_t flags=irq_save();
    if((flags&0x200) || (rdmsr(MSR_EFER)&1) ||
       (!bind && rdmsr(MSR_KERNEL_GS_BASE)!=(uint64_t)&shz_smp_cpus[cpu])) {
        irq_restore(flags);return -1;
    }
    if(bind) {
        shz_smp_cpus[cpu].syscall_user_rsp=0;
        wrmsr(MSR_KERNEL_GS_BASE,(uint64_t)&shz_smp_cpus[cpu]);
    }
    shz_smp_cpus[cpu].syscall_kstack=top;
    tables[cpu]->tss.rsp[0]=top;
    irq_restore(flags);return 0;
}
int shz_cpu_arch_sched_install(unsigned cpu)
{
    if(!cpu || cpu>=allocated_count || shz_smp_this_cpu()!=cpu || !tables[cpu] ||
       !(__atomic_load_n(&entered_mask,__ATOMIC_ACQUIRE)&(1u<<cpu))) return -1;
    const uint64_t flags=irq_save();
    if((flags&0x200) || rdmsr(MSR_KERNEL_GS_BASE)!=(uint64_t)&shz_smp_cpus[cpu] ||
       (rdmsr(MSR_EFER)&1)) { irq_restore(flags);return -1; }
    /* No suspended schedulable context ever resides on F1's private IST. */
    gate(&tables[cpu]->idt[SHZ_SMP_VEC_RESCHEDULE],isr_stub_table[SHZ_SMP_VEC_RESCHEDULE],0);
    gate(&tables[cpu]->idt[SHZ_SMP_VEC_TIMER],isr_stub_table[SHZ_SMP_VEC_TIMER],0);
    __atomic_fetch_or(&scheduler_gate_mask,1u<<cpu,__ATOMIC_RELEASE);
    irq_restore(flags);return 0;
}

int shz_cpu_arch_sched_restore(unsigned cpu)
{
    if(!cpu || cpu>=allocated_count || shz_smp_this_cpu()!=cpu || !tables[cpu]) return -1;
    const uint64_t flags=irq_save();
    if(flags&0x200) { irq_restore(flags);return -1; }
    gate(&tables[cpu]->idt[SHZ_SMP_VEC_RESCHEDULE],(uint64_t)wake,1);
    gate(&tables[cpu]->idt[SHZ_SMP_VEC_TIMER],(uint64_t)quiesced_timer,1);
    __atomic_fetch_and(&scheduler_gate_mask,~(1u<<cpu),__ATOMIC_RELEASE);
    irq_restore(flags);return 0;
}
int shz_cpu_arch_sched_timer_prepare(volatile uint32_t *apic)
{
#ifndef SHZ_STANDALONE
    (void)apic;return -2;
#else
    if(!apic || shz_smp_this_cpu()!=0 || scheduler_lapic) return -1;
    const uint64_t flags=irq_save();
    if(flags&0x200) { irq_restore(flags);return -1; }
    const uint32_t lvt=apic[0x320/4],div=apic[0x3e0/4];
    /* BSP is PIT-owned; never commandeer an active local timer owner. */
    if(!(lvt&(1u<<16)) || apic[0x380/4]) { irq_restore(flags);return -1; }
    const uint8_t saved=k_inb(0x61);unsigned spins=0;
    apic[0x320/4]=(1u<<16)|SHZ_SMP_VEC_TIMER;apic[0x3e0/4]=3; /* divide16 */
    k_outb(0x61,(uint8_t)(saved&~3u));k_outb(0x43,0xb0);
    k_outb(0x42,(uint8_t)11932);k_outb(0x42,(uint8_t)(11932>>8));
    apic[0x380/4]=UINT32_MAX;
    k_outb(0x61,(uint8_t)((saved&~2u)|1u));
    while(!(k_inb(0x61)&0x20) && ++spins<10000000u) __asm__ volatile("pause");
    const uint32_t elapsed=UINT32_MAX-apic[0x390/4];
    apic[0x380/4]=0;apic[0x3e0/4]=div;apic[0x320/4]=lvt;k_outb(0x61,saved);
    if(spins>=10000000u || elapsed<10 || elapsed==UINT32_MAX) { irq_restore(flags);return -1; }
    scheduler_timer_count=(uint32_t)(((uint64_t)elapsed+5u)/10u); /* measured10ms -> one1ms local tick */
    scheduler_lapic=apic;irq_restore(flags);return 0;
#endif
}
int shz_cpu_arch_sched_timer(unsigned cpu,int enable)
{
#ifndef SHZ_STANDALONE
    (void)cpu;(void)enable;return -2;
#else
    if(!cpu || cpu>=allocated_count || shz_smp_this_cpu()!=cpu || !scheduler_lapic || !scheduler_timer_count ||
       !(__atomic_load_n(&scheduler_gate_mask,__ATOMIC_ACQUIRE)&(1u<<cpu))) return -1;
    const uint64_t flags=irq_save();
    if(flags&0x200) { irq_restore(flags);return -1; }
    scheduler_lapic[0x320/4]=(1u<<16)|SHZ_SMP_VEC_TIMER;
    scheduler_lapic[0x380/4]=0;
    if(enable) {
        scheduler_lapic[0x3e0/4]=3;
        scheduler_lapic[0x320/4]=(1u<<17)|SHZ_SMP_VEC_TIMER;
        scheduler_lapic[0x380/4]=scheduler_timer_count;
    }
    irq_restore(flags);return 0;
#endif
}
void shz_cpu_arch_sched_irq(struct regs *r)
{
    const unsigned cpu=shz_smp_this_cpu();
    thread_t *t=thread_current();
    const uint64_t at=(uint64_t)r,top=t?t->stack_base+KSTACK_BYTES:0;
    if(!cpu || cpu>=allocated_count || !r || !t || !t->ap_kernel_cohort || t->proc ||
       t->teb || t->object || t->ipc || t->wait_sem || t->wait_multi || t->state!=TS_RUNNING ||
       !(t->cpu_mask&(1ull<<cpu)) || top<=t->stack_base ||
       t->on_cpu!=cpu || !(__atomic_load_n(&scheduler_gate_mask,__ATOMIC_ACQUIRE)&(1u<<cpu)) ||
       (r->cs&3) || at<t->stack_base || at>top-sizeof *r ||
       r->rsp<t->stack_base || r->rsp>=top ||
       (r->vector!=SHZ_SMP_VEC_TIMER && r->vector!=SHZ_SMP_VEC_RESCHEDULE)) fault();
    /* Local APIC in-service state is released before any task-stack transfer. */
    shz_smp_apic_eoi();
    if(r->vector==SHZ_SMP_VEC_TIMER) {
        ++shz_smp_cpus[cpu].timer_irqs;sched_tick_from(0);
    } else {
        ++shz_smp_cpus[cpu].reschedule_ipis;sched_ap_reschedule();
    }
}
