/* SPDX-License-Identifier: GPL-2.0-only
 * Private architecture for native AP bringup workers. AP interrupts never
 * enter the UP scheduler, its singleton TSS/syscall scratch or device handlers.
 */
#include "cpu_arch_bringup.h"
static shz_cpu_arch_tables_t *tables[SHZ_SMP_MAX_CPUS];
static unsigned allocated_count;
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
    if(!t || !high_stack(boot,KSTACK_BYTES) || !high_stack(irq,KSTACK_BYTES) || !high_stack(df,8192) ||
       overlaps(boot,KSTACK_BYTES,irq,KSTACK_BYTES) || overlaps(boot,KSTACK_BYTES,df,8192) ||
       overlaps(irq,KSTACK_BYTES,df,8192)) return -1;
    memset(t,0,sizeof *t);
    t->gdt[1]=0x00af9b000000ffffull;t->gdt[2]=0x00cf93000000ffffull;
    const uint64_t base=(uint64_t)&t->tss;
    t->gdt[5]=(sizeof t->tss-1)|((base&0xffffffull)<<16)|(0x89ull<<40)|(((base>>24)&0xff)<<56);
    t->gdt[6]=base>>32;
    t->tss.rsp[0]=boot;t->tss.ist[0]=irq;t->tss.ist[1]=df;t->tss.iomap=sizeof t->tss;
    for(unsigned i=0;i<256;i++) {
        const int error=i==8 || i==10 || i==11 || i==12 || i==13 || i==14 || i==17 || i==21 || i==29 || i==30;
        gate(&t->idt[i],error?(uint64_t)fault_error:(uint64_t)fault_no_error,i==8?2:1);
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
        const uint64_t pa=pmm_alloc_contig(2);
        if(!pa) {
            for(unsigned j=1;j<i;j++) { pmm_free_contig((uint64_t)tables[j]-phys_base_va,2);tables[j]=0; }
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
    return actual_gdt.base==gdtr.base && actual_gdt.limit==gdtr.limit &&
           actual_idt.base==idtr.base && actual_idt.limit==idtr.limit && tr==0x28 &&
           !(rdmsr(MSR_EFER)&1) ? 0:-1;
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
