/* SPDX-License-Identifier: GPL-2.0-only
 * Normal native AP architecture/work/IPI integration. Scheduler CPUs remain1.
 * All resource validation/allocation occurs before INIT and AP work release.
 */
#include "cpu_bringup.h"
#include "cpu_firmware.h"
#include "cpu_memory_owner.h"
#include "cpu_arch_bringup.h"
#include "cpu_memory_stress.h"
#include "cpu_tlb.h"
#include "cpu_tlb_stress.h"
#include "pci.h"
#include "../boot_profile/win98_foundation.h"
extern uint64_t arch_timer_irqs(void);
static shz_cpu_firmware_t firmware;
static const shz_bootinfo_t *owner_boot;
static uint64_t initial_root;
static unsigned admitted,resources_owned;
static int backend_result;
static unsigned dispatch_count,dispatch_mode;
static unsigned workers_mode;
#ifdef SHZ_STANDALONE
static unsigned workers_attempted;
#endif
static uint64_t dispatch_rsdp;
static volatile uint32_t release_work,cancel_work,ipi_turn,fatal;
static struct {
    uint32_t actual,apic,progress,checkpoint,parked,bsp_seen,ap_seen,done,ping_done,bad,hash,wake,verify,verify_delivered;
    uint64_t cr3,stack,gdt,idt,tss,irq_stack;
} jobs[SHZ_SMP_MAX_CPUS];
static int owned_span(uint64_t pa,uint64_t bytes)
{
    if(!owner_boot || !bytes || (pa&4095) || (bytes&4095) || bytes>UINT32_MAX ||
       pa>mem_ram_top() || bytes>mem_ram_top()-pa ||
       !shz_native_firmware_ram_covers(&firmware.native,pa,(uint32_t)bytes)) return 0;
    for(uint64_t p=pa;p<pa+bytes;p+=PAGE_SIZE)
        if(!shz_cpu_pmm_page_owned(p,owner_boot)) return 0;
    return 1;
}
static int tlb_owned(void *ctx,uint64_t pa,uint64_t bytes)
{ (void)ctx;return owned_span(pa,bytes); }
static int table_read(void *ctx,uint64_t pa,void *out,size_t bytes)
{
    (void)ctx;const uint64_t page=pa&~4095ull;
    if(!out || !bytes || bytes>4096-(pa&4095) ||
       !shz_native_firmware_ram_covers(&firmware.native,page,4096)) return -1;
    if(page<SHZ_K64_PMM_GPA) {
        if(initial_root!=0x1000 || (page!=0x1000 && page!=0x2000 && page!=0x4000)) return -1;
    } else if(!owned_span(page,PAGE_SIZE)) return -1;
    memcpy(out,(const void *)p2v(pa),bytes);return 0;
}
static int kernel_contract(void)
{
    shz_cpu_dtr_t gdt,idt;
    __asm__ volatile("sgdt %0":"=m"(gdt));__asm__ volatile("sidt %0":"=m"(idt));
    /* The boot GDT/IDT live in the kernel image: [SHZ_K64_KERNEL_GPA, SHZ_K64_KERNEL_END) of standalone/memholes.h,
     * the same window every loader zeroes and link.ld bounds (image + bss end at or below the heap). */
    const uint64_t low=K64_VIRT_BASE+SHZ_K64_KERNEL_GPA,high=K64_VIRT_BASE+SHZ_K64_KERNEL_END;
    if(!owner_boot || (owner_boot->flags&SHZ_BIF_UEFI_DIRECT) || initial_root!=0x1000 ||
       gdt.limit!=55 || idt.limit!=4095 || gdt.base<low || gdt.base>high-56 ||
       idt.base<low || idt.base>high-4096 ||
       !shz_native_firmware_ram_covers(&firmware.native,0x1000,4096)) return 0;
    return shz_smp_boot_pages_safe(table_read,0,initial_root,read_cr3(),kernel_pml4(),mem_ram_top())==0;
}
static int bootstrap_shape(uint64_t root)
{
    const uint64_t mask=0x000ffffffffff000ull;
    const uint64_t *pml4=(const uint64_t *)p2v(root),*final=(const uint64_t *)p2v(kernel_pml4());
    const uint64_t pdpt=pml4[0]&mask;
    if(!owned_span(pdpt,4096)) return 0;
    const uint64_t *p=(const uint64_t *)p2v(pdpt);const uint64_t pd=p[0]&mask;
    if(!owned_span(pd,4096)) return 0;
    const uint64_t *d=(const uint64_t *)p2v(pd);const uint64_t pt=d[0]&mask;
    if(!owned_span(pt,4096) || root==pdpt || root==pd || root==pt || pdpt==pd || pdpt==pt || pd==pt) return 0;
    const uint64_t *t=(const uint64_t *)p2v(pt);
    if(pml4[0]!=(pdpt|3) || p[0]!=(pd|3) || d[0]!=(pt|3)) return 0;
    for(unsigned i=0;i<512;i++) {
        if(i && i<256 && pml4[i]) return 0;
        if(i>=256 && ((pml4[i]^final[i])&~0x20ull)) return 0;
        if(i && (p[i] || d[i])) return 0;
        if(t[i]!=(i==1?0x1003ull:0)) return 0;
    }
    return 1;
}
static int overlap(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{ return a<b+m && b<a+n; }
static int resources_check(unsigned count,uint64_t bootstrap)
{
    uint64_t path[4]={0};unsigned budget=4096;const uint64_t stack_bytes=KSTACK_BYTES*2+8192;
    if(!admitted || !count || count>SHZ_SMP_MAX_CPUS || bootstrap==kernel_pml4() || bootstrap>UINT32_MAX ||
       !kernel_contract() || shz_smp_guard_walk(table_read,0,bootstrap,4,mem_ram_top(),path,&budget) ||
       !bootstrap_shape(bootstrap)) return -1;
    for(unsigned i=0;i<count;i++) {
        const uint64_t top=shz_smp_cpus[i].boot_stack_top;
        if(top<phys_base_va+KSTACK_BYTES) return -1;
        const uint64_t stack=top-phys_base_va-KSTACK_BYTES,arch=i?shz_cpu_arch_resource(i):0;
        if(shz_smp_cpus[i].irq_stack_top!=top+KSTACK_BYTES || shz_smp_cpus[i].df_stack_top!=top+KSTACK_BYTES+8192 ||
           !owned_span(stack,stack_bytes) || (i && (!owned_span(arch,SHZ_CPU_ARCH_BYTES) || overlap(stack,stack_bytes,arch,SHZ_CPU_ARCH_BYTES)))) return -1;
        if(workers_mode) {
            uint64_t bytes=0;const uint64_t pool=sched_ap_work_resource(&bytes);
            if(!pool || !owned_span(pool,bytes) || overlap(pool,bytes,stack,stack_bytes) ||
               (i && overlap(pool,bytes,arch,SHZ_CPU_ARCH_BYTES)) ||
               sched_ap_work_overlaps(stack,stack_bytes) || (i && sched_ap_work_overlaps(arch,SHZ_CPU_ARCH_BYTES)))return -1;
        }
        for(unsigned j=0;j<i;j++) {
            const uint64_t prior=shz_smp_cpus[j].boot_stack_top-phys_base_va-KSTACK_BYTES,prior_arch=j?shz_cpu_arch_resource(j):0;
            if(overlap(stack,stack_bytes,prior,stack_bytes) || (j && overlap(stack,stack_bytes,prior_arch,SHZ_CPU_ARCH_BYTES)) ||
               (i && overlap(arch,SHZ_CPU_ARCH_BYTES,prior,stack_bytes)) || (i && j && overlap(arch,SHZ_CPU_ARCH_BYTES,prior_arch,SHZ_CPU_ARCH_BYTES))) return -1;
        }
    }
    if(dispatch_mode && (count!=dispatch_count || sched_ap_cohort_resources(owned_span))) return -1;
    resources_owned=count;
    kprintf("SMP-RESOURCE: owned=%u final_cr3=%llx bootstrap_cr3=%llx identity_bytes=4096 before_INIT=1\n",count,kernel_pml4(),bootstrap);
    return 0;
}
static unsigned apic_id(void)
{ uint32_t a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));return b>>24; }
void shz_cpu_arch_fault(unsigned cpu)
{ if(cpu<SHZ_SMP_MAX_CPUS) __atomic_add_fetch(&jobs[cpu].bad,1,__ATOMIC_RELEASE);else __atomic_add_fetch(&fatal,1,__ATOMIC_RELEASE); }
void shz_cpu_arch_ipi(unsigned reason,uint64_t stack)
{
    const unsigned cpu=shz_smp_this_cpu();
    if(cpu>=SHZ_SMP_MAX_CPUS) { __atomic_add_fetch(&fatal,1,__ATOMIC_RELEASE);return; }
    jobs[cpu].irq_stack=stack;
    if(cpu && (stack>=shz_smp_cpus[cpu].irq_stack_top || stack<shz_smp_cpus[cpu].irq_stack_top-KSTACK_BYTES)) shz_cpu_arch_fault(cpu);
    if(reason) {
        shz_cpu_tlb_ipi();
        __atomic_add_fetch(&jobs[cpu].verify_delivered,1,__ATOMIC_RELEASE);
        if(cpu==1 && k64_cmdline_has("shz.smp=withhold-verify")) return;
    }
    __atomic_add_fetch(reason?&jobs[cpu].verify:&jobs[cpu].wake,1,__ATOMIC_RELEASE);
}
static void bsp_wake(struct regs *r) { uint64_t local=0;(void)r;shz_cpu_arch_ipi(0,(uint64_t)&local);shz_smp_apic_eoi(); }
static void bsp_verify(struct regs *r) { uint64_t local=0;(void)r;shz_cpu_arch_ipi(1,(uint64_t)&local);shz_smp_apic_eoi(); }
static int wait_for(uint32_t *value,uint32_t expected)
{
    const uint64_t deadline=arch_timer_irqs()+2000;unsigned spins=0;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)<expected) {
        if(arch_timer_irqs()>=deadline || ++spins==100000000u) return -1;
        __asm__ volatile("pause");
    }
    return 0;
}
static uint32_t work_hash(unsigned cpu,unsigned loops)
{
    uint32_t value=0x5a17c0deu^cpu;
    for(unsigned i=0;i<loops;i++) {
        value=(value<<5)|(value>>27);value^=0x9e3779b9u;value+=i;
        if(!(i&0x3fff)) __atomic_add_fetch(&jobs[cpu].progress,1,__ATOMIC_RELEASE);
        if(cpu && i==500000) {
            const uint32_t first=__atomic_load_n(&jobs[0].progress,__ATOMIC_ACQUIRE);unsigned spins=0;
            __atomic_store_n(&jobs[cpu].checkpoint,1,__ATOMIC_RELEASE);
            while(__atomic_load_n(&jobs[0].progress,__ATOMIC_ACQUIRE)<=first && ++spins<100000000u &&
                  !__atomic_load_n(&cancel_work,__ATOMIC_ACQUIRE)) __asm__ volatile("pause");
            jobs[cpu].ap_seen=first>0 && spins<100000000u && !__atomic_load_n(&cancel_work,__ATOMIC_ACQUIRE);
            if(!jobs[cpu].ap_seen) shz_cpu_arch_fault(cpu);
        }
        if(!cpu && i==1000000) {
            for(unsigned j=1;j<(unsigned)backend_result;j++) {
                if(wait_for(&jobs[j].checkpoint,1) || __atomic_load_n(&jobs[j].progress,__ATOMIC_ACQUIRE)<2) shz_cpu_arch_fault(j);
                else jobs[j].bsp_seen=1;
            }
        }
        if(i==(cpu?750000u:1250000u) && k64_cmdline_has("shz.memory=test"))
            if(shz_cpu_memory_stress(cpu)) shz_cpu_arch_fault(cpu);
        if(i==(cpu?1500000u:2000000u) && k64_cmdline_has("shz.tlb=test"))
            if(shz_cpu_tlb_stress(cpu)) shz_cpu_arch_fault(cpu);
    }
    return value;
}
static void ap_entry(unsigned cpu)
{
    volatile uint64_t canary=0x534d50415053544bull^cpu;
    if(shz_cpu_arch_enter(cpu)) { shz_cpu_arch_fault(cpu);return; }
    jobs[cpu].actual=shz_smp_this_cpu();jobs[cpu].apic=apic_id();jobs[cpu].cr3=read_cr3();jobs[cpu].stack=(uint64_t)&canary;
    if(shz_cpu_arch_describe(cpu,&jobs[cpu].gdt,&jobs[cpu].idt,&jobs[cpu].tss) || jobs[cpu].actual!=cpu ||
       jobs[cpu].apic!=shz_smp_cpus[cpu].apic_id || jobs[cpu].cr3!=kernel_pml4() || shz_smp_cpu_online(cpu)) {
        shz_cpu_arch_fault(cpu);return;
    }
    if(dispatch_mode) {
        if(sched_ap_cohort_enter(cpu)) { shz_cpu_arch_fault(cpu);return; }
        /* Dispatch stopped on the retained bootstrap stack; private F1 stays
         * live for the established architecture/TLB resource lifetime. */
        for(;;) __asm__ volatile("sti; hlt; cli":::"memory");
    }
    if(k64_cmdline_has("shz.smp=return-ap")) return;
    for(;;) {
        cli();if(__atomic_load_n(&release_work,__ATOMIC_ACQUIRE)) { sti();break; }
        __atomic_store_n(&jobs[cpu].parked,1,__ATOMIC_RELEASE);
        __asm__ volatile("sti; hlt");
    }
    unsigned spins=0;
    while(!__atomic_load_n(&jobs[0].progress,__ATOMIC_ACQUIRE) && ++spins<100000000u &&
          !__atomic_load_n(&cancel_work,__ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    if(spins==100000000u || __atomic_load_n(&cancel_work,__ATOMIC_ACQUIRE)) {
        shz_cpu_arch_fault(cpu);for(;;) __asm__ volatile("cli; hlt");
    }
    jobs[cpu].hash=work_hash(cpu,2000000);
    if(canary!=(0x534d50415053544bull^cpu)) shz_cpu_arch_fault(cpu);
    __atomic_store_n(&jobs[cpu].done,1,__ATOMIC_RELEASE);
    for(;;) {
        cli();if(__atomic_load_n(&cancel_work,__ATOMIC_ACQUIRE)) for(;;) __asm__ volatile("cli; hlt");
        if(__atomic_load_n(&ipi_turn,__ATOMIC_ACQUIRE)==cpu && !__atomic_load_n(&jobs[cpu].ping_done,__ATOMIC_ACQUIRE)) {
            sti();if(shz_smp_send_ipi(0,SHZ_SMP_VEC_RESCHEDULE) || shz_smp_send_ipi(0,SHZ_SMP_VEC_TLB)) shz_cpu_arch_fault(cpu);
            __atomic_store_n(&jobs[cpu].ping_done,1,__ATOMIC_RELEASE);
        } else __asm__ volatile("sti; hlt");
    }
}
static void report_abort(int error)
{
    const uint64_t flags=irq_save();
    const int retry=shz_smp_boot_start_with_reader(firmware.rsdp,ap_entry,shz_cpu_firmware_read,&firmware,initial_root);
    const unsigned retained=shz_cpu_pmm_page_owned(shz_smp_cpus[1].boot_stack_top-phys_base_va-KSTACK_BYTES,owner_boot);
    irq_restore(flags);
    kprintf("SMP-AP aborted: discovered=%u arch_online=%u state1=%u retained=%u retry=%d error=%d\n",
            shz_smp_topology()->count,shz_smp_online_count(),shz_smp_cpus[1].state,retained,retry,error);
}
void shz_cpu_bringup_prepare(const shz_bootinfo_t *bi,uint64_t initial_cr3)
{
    if(k64_cmdline_has("smp=off") || (!k64_cmdline_has("shz.smp=workers") && !k64_cmdline_has("shz.smp=dispatch") && !k64_cmdline_has("shz.smp=bringup") && !k64_cmdline_has("shz.smp=firmware-test") &&
       !k64_cmdline_has("shz.smp=no-ipi") && !k64_cmdline_has("shz.smp=return-ap") && !k64_cmdline_has("shz.smp=withhold-verify"))) return;
    workers_mode=k64_cmdline_has("shz.smp=workers");
    if(workers_mode && (shz_win98_foundation_policy(bi)!=0 || k64_cmdline_has("shz.smp=dispatch")))return;
    dispatch_mode=workers_mode || k64_cmdline_has("shz.smp=dispatch");
    owner_boot=bi;initial_root=initial_cr3;
    const int rc=shz_cpu_firmware_prepare(bi,&firmware);
    if(rc!=1) { kprintf("SMP-BRINGUP: firmware unavailable rc=%d, scheduler CPUs=1\n",rc);return; }
    admitted=kernel_contract();
    kprintf("SMP-BRINGUP: page1000=%u initial_cr3=%llx final_cr3=%llx scheduler CPUs=1\n",admitted,initial_root,read_cr3());
    if(k64_cmdline_has("shz.smp=firmware-test")) {
        unsigned reads=0;uint8_t header[36];
        for(unsigned i=0;i<firmware.native.count;i++) {
            const shz_native_firmware_range_t *r=&firmware.native.range[i];
            if(r->type==2 && r->base>=mem_ram_top() && r->length>=sizeof header && shz_qemu_firmware_covers(&firmware.qemu,&firmware.native,r->base,sizeof header)) {
                if(shz_cpu_firmware_read(&firmware,r->base,header,sizeof header)) break;
                ++reads;kprintf("SMP-FIRMWARE: native_read pa=%llx bytes=%u checksum_byte=%u\n",r->base,(unsigned)sizeof header,header[0]);
            }
        }
        kprintf("SMP-FIRMWARE: test page_admitted=%u reserved_reads=%u\n",admitted,reads);return;
    }
    if(!admitted) return;
    uint64_t rsdp=0;shz_smp_topology_t found;
    if(shz_smp_acpi_find_bios(shz_cpu_firmware_read,&firmware,&rsdp) || shz_cpu_firmware_finish_discovery(&firmware,rsdp) ||
       shz_smp_acpi_probe(shz_cpu_firmware_read,&firmware,rsdp,apic_id(),&found)) {
        kprintf("SMP-BRINGUP: ACPI unavailable, scheduler CPUs=1\n");return;
    }
    volatile uint32_t *endpoint=pci_bsp_lapic_acquire(found.lapic_pa,apic_id());
    if(!endpoint || shz_cpu_arch_allocate(found.count) || !kernel_contract()) return;
    if(dispatch_mode) {
        if(found.count<2 || k64_cmdline_has("shz.memory=test") || k64_cmdline_has("shz.tlb=test") ||
           shz_cpu_arch_sched_timer_prepare(endpoint)) return;
        dispatch_count=found.count;dispatch_rsdp=rsdp;
        if(workers_mode)kprintf("SMP-WORK prepared: cpus=%u INIT_deferred=1 after_UP_QA=required scheduler_cpus=1\n",found.count);
        else kprintf("SMP-DISPATCH prepared: cpus=%u INIT_deferred=1 scheduler_cpus=1\n",found.count);
        return;                            /* sched_init has not run yet */
    }
    if(k64_cmdline_has("shz.tlb=test") && shz_cpu_tlb_stress_prepare(found.count,tlb_owned,0)) return;
    const uint64_t scratch=pmm_alloc();if(!scratch || !owned_span(scratch,PAGE_SIZE)) return;
    pmm_free(scratch);if(shz_cpu_pmm_page_owned(scratch,owner_boot)) return;
    irq_register(SHZ_SMP_VEC_RESCHEDULE,bsp_wake);irq_register(SHZ_SMP_VEC_TLB,bsp_verify);
    if(shz_smp_boot_set_resource_check(resources_check)) return;
    backend_result=shz_smp_boot_start_with_reader(rsdp,ap_entry,shz_cpu_firmware_read,&firmware,initial_root);
    kprintf("SMP-BRINGUP: backend=%d owned=%u scheduler CPUs=1\n",backend_result,resources_owned);
    if(backend_result<0 && resources_owned) report_abort(backend_result);
}
void shz_cpu_bringup_verify(void)
{
    if(workers_mode)return; /* QA must run with no AP INIT or scheduler admission. */
    if(dispatch_mode && !k64_cmdline_has("smp=off")) {
        int rc=-1;
        const uint64_t flags=irq_save();
        if(dispatch_count && !sched_ap_cohort_prepare(dispatch_count) &&
           !shz_smp_boot_set_resource_check(resources_check)) {
            backend_result=shz_smp_boot_start_with_reader(dispatch_rsdp,ap_entry,shz_cpu_firmware_read,&firmware,initial_root);
            /* Provider reset precedes this rebind, and IF is still clear. */
            thread_t *bsp=thread_current();
            KASSERT(bsp && arch_sched_entry_bind(0,bsp->stack_base+KSTACK_BYTES)==0);
            if(backend_result==(int)dispatch_count) rc=0;
        }
        irq_restore(flags);
        if(!rc) rc=sched_ap_cohort_finish();
        kprintf("SMP-DISPATCH admission: backend=%d owned=%u result=%d\n",backend_result,resources_owned,rc);
        if(rc) shz_exit(98);                /* explicit cohort cannot silently pass UP */
        return;
    }
    if(k64_cmdline_has("smp=off") || backend_result<=0) return;
    const unsigned count=(unsigned)backend_result;unsigned completed=0,bad=__atomic_load_n(&fatal,__ATOMIC_ACQUIRE);
    const uint64_t deadline=arch_timer_irqs()+2000;unsigned spins=0;
    while(shz_smp_online_count()!=count && arch_timer_irqs()<deadline && ++spins<100000000u) __asm__ volatile("pause");
    if(shz_smp_online_count()!=count || resources_owned!=count) {
        __atomic_store_n(&cancel_work,1,__ATOMIC_RELEASE);bad=1;report_abort(-7);goto report;
    }
    volatile uint64_t canary=0x534d50415053544bull;
    jobs[0].actual=shz_smp_this_cpu();jobs[0].apic=apic_id();jobs[0].cr3=read_cr3();jobs[0].stack=(uint64_t)&canary;
    if(shz_cpu_arch_describe(0,&jobs[0].gdt,&jobs[0].idt,&jobs[0].tss)) bad=1;
    for(unsigned i=1;i<count;i++) if(wait_for(&jobs[i].parked,1)) bad=1;
    __atomic_store_n(&release_work,1,__ATOMIC_RELEASE);
    for(unsigned i=1;i<count;i++) {
        const int sent=k64_cmdline_has("shz.smp=no-ipi")?0:shz_smp_send_ipi(i,SHZ_SMP_VEC_RESCHEDULE);
        if(sent || wait_for(&jobs[i].wake,1)) bad=1;
    }
    if(bad) { __atomic_store_n(&cancel_work,1,__ATOMIC_RELEASE);goto report; }
    jobs[0].hash=work_hash(0,16000000);
    for(unsigned i=1;i<count;i++) {
        if(wait_for(&jobs[i].done,1)) { bad=1;continue; }++completed;
        __atomic_store_n(&ipi_turn,i,__ATOMIC_RELEASE);
        if(shz_smp_send_ipi(i,SHZ_SMP_VEC_TLB) || wait_for(&jobs[i].verify,1) || wait_for(&jobs[i].ping_done,1) ||
           wait_for(&jobs[0].wake,i) || wait_for(&jobs[0].verify,i)) bad=1;
    }
    if(canary!=0x534d50415053544bull) bad=1;
    if(k64_cmdline_has("shz.memory=test")) shz_cpu_memory_stress_report();
    if(k64_cmdline_has("shz.tlb=test")) shz_cpu_tlb_stress_report();
report:
    for(unsigned i=0;i<count;i++) {
        bad+=__atomic_load_n(&jobs[i].bad,__ATOMIC_ACQUIRE);
        kprintf("SMP-AP CPU: cpu=%u apic=%u actual=%u cr3=%llx stack=%llx gdt=%llx idt=%llx tss=%llx hash=%x loops=%u progress=%u bsp_seen=%u ap_seen=%u\n",
                i,jobs[i].apic,jobs[i].actual,jobs[i].cr3,jobs[i].stack,jobs[i].gdt,jobs[i].idt,jobs[i].tss,jobs[i].hash,
                i?2000000u:16000000u,jobs[i].progress,jobs[i].bsp_seen,jobs[i].ap_seen);
        kprintf("SMP-AP IPI: cpu=%u wake=%u verify=%u irqstack=%llx delivered=%u\n",i,jobs[i].wake,jobs[i].verify,jobs[i].irq_stack,jobs[i].verify_delivered);
    }
    kprintf("SMP-AP summary: discovered=%u arch_online=%u completed=%u bad=%u scheduler_cpus=1\n",count,shz_smp_online_count(),completed,bad);
}
int shz_cpu_workers_requested(void)
{ return workers_mode && !k64_cmdline_has("smp=off"); }
int shz_cpu_workers_start(void)
{
#ifndef SHZ_STANDALONE
    return -2;
#else
    if(!shz_cpu_workers_requested() || workers_attempted || shz_smp_this_cpu()!=0 ||
       !dispatch_count || !kernel_contract() || sched_ap_work_quiescent())return -1;
    const uint64_t flags=irq_save();workers_attempted=1;
    int rc=-1;
    if(!sched_ap_work_prepare(dispatch_count) && !shz_smp_boot_set_resource_check(resources_check)) {
        backend_result=shz_smp_boot_start_with_reader(dispatch_rsdp,ap_entry,shz_cpu_firmware_read,&firmware,initial_root);
        thread_t *bsp=thread_current();
        KASSERT(bsp && arch_sched_entry_bind(0,bsp->stack_base+KSTACK_BYTES)==0);
        if(backend_result==(int)dispatch_count)rc=0;
    }
    irq_restore(flags);
    if(!rc)rc=sched_ap_work_start();
    kprintf("SMP-WORK admission: backend=%d owned=%u result=%d retained_on_failure=1\n",backend_result,resources_owned,rc);
    return rc;
#endif
}
