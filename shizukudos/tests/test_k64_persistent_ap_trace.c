/* Reuses the unchanged actual architecture adapters; additionally consumes
 * the real record/EOI/retained-copy path. Logical AP identity is a host fixture. */
#define main original_arch_controls
#include "test_k64_ap_dispatch_arch.c"
#undef main
int main(void)
{
    /* The original executable remains a separate gate. This fixture sets the
     * same private table/identity adapters without claiming hardware entry. */
    identity(1);allocated_count=2;static shz_cpu_arch_tables_t own;tables[1]=&own;
    const uint64_t boot=0xffff800012348000ull,irq=boot+KSTACK_BYTES,df=irq+8192;
    check("retained tables still include real dedicated NMI member",!shz_cpu_arch_build_tables(&own,boot,irq,df) && own.idt[2].ist==3 && own.tss.ist[2]==(uintptr_t)own.nmi_stack+sizeof own.nmi_stack && sizeof own<=16384);
    identity(0);check("count mismatch refuses pre-INIT architecture availability",!shz_cpu_arch_work_available(3) && shz_cpu_arch_work_available(2));identity(1);
    shz_cpu_gate_t f1=own.idt[SHZ_SMP_VEC_TLB];
    entered_mask=2;shz_smp_cpus[1].state=SHZ_SMP_CPU_ONLINE;kgs=(uintptr_t)&shz_smp_cpus[1];
    identity(0);check("entered private resource cannot be activated for another service lifetime",!shz_cpu_arch_work_available(2));identity(1);
    check("private task IRQ installation precedes trace fixture",!shz_cpu_arch_sched_install(1));
    identity(0);check("private scheduler gate without work admission has zero service mask",shz_cpu_arch_work_online_mask()==0);identity(1);
    work_trace_mask=2; /* explicit post-install host control; no native snapshot is fabricated */
    identity(0);check("entered physical ONLINE plus task gates publishes exact private mask",shz_cpu_arch_work_online_mask()==2);
    shz_smp_cpus[1].state=SHZ_SMP_CPU_ENTERED;check("physical entered without ONLINE cannot authorize migration",shz_cpu_arch_work_online_mask()==0);shz_smp_cpus[1].state=SHZ_SMP_CPU_ONLINE;
    identity(1);check("AP cannot borrow BSP architecture migration reader",shz_cpu_arch_work_online_mask()==0);
    struct regs r={0};memset(&irq_thread,0,sizeof irq_thread);
    irq_thread.id=39;irq_thread.ap_kernel_cohort=K64_AP_WORKER_CLASS;irq_thread.on_cpu=1;
    irq_thread.state=TS_RUNNING;irq_thread.cpu_mask=2;
    irq_thread.stack_base=((uintptr_t)&r&~4095ull)-4096;
    own.tss.rsp[0]=irq_thread.stack_base+KSTACK_BYTES;
    r.vector=SHZ_SMP_VEC_TIMER;r.rip=0x123456;r.rflags=0x202;r.rsp=(uintptr_t)&r+sizeof r;r.cs=8;lapic=fake_apic;fake_apic[0xb0/4]=7;
    shz_cpu_arch_sched_irq(&r);
    check("pre-EOI raw record binds real supplied frame and stack bounds",own.work_trace.count==2 && own.work_trace.record[0].kind==1 && own.work_trace.record[0].frame==(uintptr_t)&r && own.work_trace.record[0].rip==r.rip && own.work_trace.record[0].flags==r.rflags && own.work_trace.record[0].rsp0==own.tss.rsp[0]);
    check("post-EOI record precedes actual scheduler callback",own.work_trace.record[1].kind==2 && own.work_trace.record[0].eoi==0 && own.work_trace.record[1].eoi==1 && tick_calls==1 && eoi_before_tick);
    shz_cpu_arch_work_complete(1);
    check("completion records actual current host RSP in owned span",own.work_trace.record[2].kind==3 && own.work_trace.record[2].rsp>=irq_thread.stack_base && own.work_trace.record[2].rsp<own.tss.rsp[0] && own.work_trace.complete==1 && own.work_trace.record[2].eoi==1);
    identity(0);check("BSP cannot copy still-live AP ring",shz_cpu_arch_work_report(1)==-1 && !shz_cpu_arch_work_ready(1));identity(1);
    for(unsigned i=0;i<20;i++)shz_cpu_arch_sched_irq(&r);
    check("raw ring remains bounded while total EOI epochs advance",own.work_trace.count==32 && own.work_trace.dropped==11 && own.work_trace.eoi==21 && own.work_trace.sequence==43);
    check("scheduler gate restore preserves F1 and dedicated NMI gate",!shz_cpu_arch_sched_restore(1) && !memcmp(&f1,&own.idt[SHZ_SMP_VEC_TLB],sizeof f1) && own.idt[2].ist==3);
    identity(0);check("restored private gates cannot authorize another migration",shz_cpu_arch_work_online_mask()==0);identity(1);
    shz_cpu_arch_work_finish(1);identity(0);
    check("BSP copy is admitted only after actual finish release",shz_cpu_arch_work_ready(1) && !shz_cpu_arch_work_report(1));
    identity(1);check("AP cannot call BSP trace reader",shz_cpu_arch_work_report(1)==-1);
    printf("checks=%u failures=%u scope=actual_arch_C_raw_ring_host_adapters_no_AP_NMI\n",checks,failures);return failures?1:0;
}
