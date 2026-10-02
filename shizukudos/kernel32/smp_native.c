/* SPDX-License-Identifier: GPL-2.0-only
 * Closed native32 kernel-thread cohort. Pre-INIT rollback is permitted;
 * after FIRST INIT every AP-visible boot/table/root resource is retained.
 * No Supervisor vAP, user/MM/object/device admission is granted. */
#include "smp_native.h"
k32_ap_cpu_t k32_ap_cpus[K32_AP_MAX];
static k32_ap_firmware_t firmware;
static unsigned requested,active,started;
#ifdef SHZ_STANDALONE
static k32_native_handoff_t handoff;
static shz_smp_topology_t topology;
static unsigned attempted,scheduler_reclaimed;
static volatile uint32_t release_workers,stop_workers;
static uint32_t lapic,lapic_count,heap_before,pages_before,map_pages;
static uint32_t bsp_lint0,bsp_svr;
static uint32_t cache_ids[48];static uint64_t cache_values[48];static unsigned cache_count;
#endif
static int token(const char *s,unsigned n,const char *want)
{ return strlen(want)==n && !memcmp(s,want,n); }
int k32_ap_policy(const shz_bootinfo_t *bi,unsigned *count)
{
    if(!bi || !count)return -1;
    *count=0;
    if(bi->size<offsetof(shz_bootinfo_t,cmdline_size)+sizeof bi->cmdline_size)return 0;
    unsigned n=bi->cmdline_size;
    if(n>=SHZ_CMDLINE_MAX || bi->size<offsetof(shz_bootinfo_t,cmdline)+n+1 || bi->cmdline[n])return -1;
    if(!n)return 0;
    unsigned seen=0,off=0,wanted=0;
    for(unsigned i=0;i<n;) {
        if(bi->cmdline[i]==' ') { ++i;continue; }
        unsigned begin=i;while(i<n && bi->cmdline[i]!=' ') {
            if((unsigned char)bi->cmdline[i]<0x21 || (unsigned char)bi->cmdline[i]>0x7e)return -1;
            ++i;
        }
        unsigned len=i-begin;
        if(token(bi->cmdline+begin,len,"shz.k32-ap=2") || token(bi->cmdline+begin,len,"shz.k32-ap=4")) {
            if(seen++)return -1;
            wanted=bi->cmdline[begin+11]-'0';
        } else if(token(bi->cmdline+begin,len,"smp=off")) { if(off++)return -1; }
        else return 0; /* unchanged strict foundation/service parser handles other profiles */
    }
    if(!seen && !off)return 0;
#ifdef SHZ_STANDALONE
    if(bi->flags || bi->channel_count || bi->initrd_size)return -1;
    *count=off?0:wanted;return 1;
#else
    (void)wanted;return -1;
#endif
}
int k32_ap_snapshot(const shz_bootinfo_t *bi,unsigned count)
{
    if(!count)return 0;
#ifdef SHZ_STANDALONE
    extern char __bss_end[];
    if((count!=2 && count!=4) || !bi || bi->flags || bi->channel_count || bi->initrd_size ||
       bi->ram_size<64u*1024*1024 || bi->ram_size>128u*1024*1024 ||
       bi->kernel_gpa!=0x100000 || bi->kernel_size>0x100000 || (uintptr_t)__bss_end>=0x200000)return -1;
    memcpy(&handoff,(const void *)K32_NATIVE_HANDOFF_GPA,sizeof handoff);
    memcpy(&firmware.native,(const void *)SHZ_NATIVE_FIRMWARE_GPA,sizeof firmware.native);
    if(!k32_native_handoff_valid(&handoff) || !shz_native_firmware_valid(&firmware.native,1) ||
       !shz_native_firmware_ram_covers(&firmware.native,0x1000,0x7000) ||
       !shz_native_firmware_ram_covers(&firmware.native,0x100000,(uint32_t)bi->ram_size-0x100000))return -1;
    firmware.ram=(uint32_t)bi->ram_size;requested=count;return 0;
#else
    (void)bi;return -1;
#endif
}
int k32_ap_active(void) { return __atomic_load_n(&active,__ATOMIC_ACQUIRE); }
int k32_ap_started(void) { return __atomic_load_n(&started,__ATOMIC_ACQUIRE); }
unsigned k32_ap_count(void) { return requested; }
uint32_t k32_ap_physical_id(void)
{
    uint32_t a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));return b>>24;
}
int k32_ap_identity(unsigned cpu)
{
    return k32_ap_active() && cpu && cpu<requested && cpu<K32_AP_MAX &&
        k32_ap_cpus[cpu].arch && k32_ap_cpus[cpu].apic<255 &&
        k32_ap_physical_id()==k32_ap_cpus[cpu].apic;
}
int k32_ap_owned(uint32_t base,uint32_t bytes,int heap)
{
    if(!bytes || bytes>UINT32_MAX-base || !shz_native_firmware_ram_covers(&firmware.native,base,bytes))return 0;
    if(heap)return k32_heap_owned(base,bytes);
    if((base&4095) || (bytes&4095))return 0;
    for(uint32_t p=base;p<base+bytes;p+=4096)if(!k32_pmm_owned(p))return 0;
    return 1;
}
int k32_ap_root_owned(void)
{
    /* Full ownership traversal occurs before INIT. APs only check the sealed,
     * retained root and its non-PAE shape; no allocator callback on AP. */
    if(!k32_ap_active() || read_cr3()!=kernel_space() || (read_cr4()&0x20))return 0;
    if(k32_ap_started())return 1;
    if(!k32_vm_native_root_owned())return 0;
    const uint32_t *pd=(const uint32_t *)kernel_space();
    for(uint32_t p=0;p<firmware.ram;p+=4096) {
        const uint32_t table=pd[p>>22];if(!(table&1))return 0;
        const uint32_t pte=((const uint32_t *)(table&~4095u))[(p>>12)&1023];
        if((pte&~0x60u)!=(p|3u))return 0;
    }
    return 1;
}
#ifdef SHZ_STANDALONE
static inline void outb(uint16_t p,uint8_t v) { __asm__ volatile("outb %0,%1"::"a"(v),"Nd"(p)); }
static inline uint8_t inb(uint16_t p) { uint8_t v;__asm__ volatile("inb %1,%0":"=a"(v):"Nd"(p));return v; }
static uint64_t msr(uint32_t id)
{ uint32_t a,d;__asm__ volatile("rdmsr":"=a"(a),"=d"(d):"c"(id));return (uint64_t)d<<32|a; }
static uint32_t apic_read(uint32_t off) { return *(volatile uint32_t *)(lapic+off); }
static void apic_write(uint32_t off,uint32_t value)
{ *(volatile uint32_t *)(lapic+off)=value;(void)apic_read(0x20); }
static int cpuid_available(void)
{
    uint32_t before=k32_flags(),after;
    __asm__ volatile("push %0; popf"::"r"(before^(1u<<21)):"memory","cc");after=k32_flags();
    __asm__ volatile("push %0; popf"::"r"(before):"memory","cc");return !!((before^after)&(1u<<21));
}
static int cache_prepare(void)
{
    uint32_t a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    if((d&((1u<<5)|(1u<<9)|(1u<<12)|(1u<<16)))!=((1u<<5)|(1u<<9)|(1u<<12)|(1u<<16)))return -1;
    const uint64_t cap=msr(0xfe),def=msr(0x2ff),pat=msr(0x277);
    if((cap&255)>16 || !(def&(1u<<11)) || ((pat>>24)&255)!=0 || (read_cr0()&0x60000000u))return -1;
    cache_ids[cache_count++]=0xfe;cache_ids[cache_count++]=0x2ff;cache_ids[cache_count++]=0x277;
    if(cap&(1u<<8)) {
        cache_ids[cache_count++]=0x250;cache_ids[cache_count++]=0x258;cache_ids[cache_count++]=0x259;
        for(unsigned i=0;i<8;i++)cache_ids[cache_count++]=0x268+i;
    }
    for(unsigned i=0;i<(cap&255)*2;i++)cache_ids[cache_count++]=0x200+i;
    for(unsigned i=0;i<cache_count;i++)cache_values[i]=msr(cache_ids[i]);
    return 0;
}
static int cache_enter(void)
{
    uint32_t a=1,b,c,d;__asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    if((d&((1u<<5)|(1u<<9)|(1u<<12)|(1u<<16)))!=((1u<<5)|(1u<<9)|(1u<<12)|(1u<<16)))return -1;
    for(unsigned i=0;i<cache_count;i++)if(msr(cache_ids[i])!=cache_values[i])return -1;
    __asm__ volatile("wbinvd":::"memory");write_cr0(read_cr0()&~0x60000000u);return 0;
}
/* PIT2 is borrowed only when gate/speaker are inactive; BSP serializes it. */
static int delay_us(unsigned us)
{
    if(!us || us>10000)return -1;
    const uint8_t old=inb(0x61);if(old&3)return -1;
    const unsigned ticks=(unsigned)(((uint64_t)us*1193182u+999999u)/1000000u);
    outb(0x61,old&~3u);outb(0x43,0xb0);outb(0x42,(uint8_t)ticks);outb(0x42,(uint8_t)(ticks>>8));
    outb(0x61,(old&~2u)|1u);unsigned spins=0;
    while(!(inb(0x61)&0x20) && ++spins<10000000u)__asm__ volatile("pause");
    outb(0x61,old);return spins<10000000u?0:-1;
}
static int calibration(void)
{
    uint32_t lvt=apic_read(0x320),divide=apic_read(0x3e0),initial=apic_read(0x380);
    if(!(lvt&0x10000) && initial)return -1; /* do not borrow a live BSP LAPIC timer */
    apic_write(0x320,0x10000|K32_AP_TIMER);apic_write(0x3e0,3);apic_write(0x380,0xffffffff);
    int rc=delay_us(10000);uint32_t elapsed=0xffffffff-apic_read(0x390);
    apic_write(0x380,0);apic_write(0x3e0,divide);apic_write(0x320,lvt);apic_write(0x380,initial);
    if(rc || elapsed<10000 || elapsed>100000000)return -1;
    lapic_count=elapsed/10;return 0;
}
static int icr(uint32_t physical,uint32_t command)
{
    if(physical>=255)return -1;
    const uint32_t f=irq_save();unsigned n=0;
    while((apic_read(0x300)&0x1000) && ++n<1000000)__asm__ volatile("pause");
    if(n==1000000) { irq_restore(f);return -1; }
    apic_write(0x280,0);apic_write(0x310,physical<<24);apic_write(0x300,command);n=0;
    while((apic_read(0x300)&0x1000) && ++n<1000000)__asm__ volatile("pause");
    int rc=n==1000000 || apic_read(0x280)?-1:0;irq_restore(f);return rc;
}
static int wait_value(volatile uint32_t *value,uint32_t wanted)
{
    unsigned spins=0;const uint64_t limit=ticks_now()+3000;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)!=wanted) {
        for(unsigned c=1;c<requested;c++)if(__atomic_load_n(&k32_ap_cpus[c].fatal,__ATOMIC_ACQUIRE))return -1;
        if(ticks_now()>=limit || ++spins==100000000u)return -1;
        __asm__ volatile("pause");
    }
    return 0;
}
static int overlap(uint32_t a,uint32_t n,uint32_t b,uint32_t m)
{ return a<b+m && b<a+n; }
static int resource_check(void)
{
    if(!k32_native_handoff_valid(&handoff) || !k32_ap_root_owned())return -1;
    for(unsigned c=1;c<requested;c++) {
        k32_ap_cpu_t *p=&k32_ap_cpus[c];
        uint32_t bases[4]={p->boot,p->idle_base,p->worker[0]->stack_base,p->worker[1]->stack_base};
        if(!k32_ap_owned(p->arch,4096,0))return -1;
        for(unsigned i=0;i<4;i++) {
            if(!k32_ap_owned(bases[i],K32_AP_STACK,1) || overlap(bases[i],K32_AP_STACK,p->arch,4096))return -1;
            for(unsigned j=0;j<i;j++)if(overlap(bases[i],K32_AP_STACK,bases[j],K32_AP_STACK))return -1;
            for(unsigned d=1;d<c;d++) {
                k32_ap_cpu_t *q=&k32_ap_cpus[d];uint32_t prior[4]={q->boot,q->idle_base,q->worker[0]->stack_base,q->worker[1]->stack_base};
                if(overlap(bases[i],K32_AP_STACK,q->arch,4096))return -1;
                for(unsigned j=0;j<4;j++)if(overlap(bases[i],K32_AP_STACK,prior[j],K32_AP_STACK))return -1;
            }
        }
        for(unsigned d=1;d<c;d++)if(p->arch==k32_ap_cpus[d].arch)return -1;
    }
    return 0;
}
static uint32_t payload(unsigned cpu,unsigned lane,unsigned loops)
{
    uint32_t v=0x3217c0deu^cpu^lane;
    for(unsigned i=0;i<loops;i++) { v=(v<<5)|(v>>27);v^=0x9e3779b9u;v+=i; }
    return v;
}
static void worker(void *arg)
{
    unsigned number=(uintptr_t)arg,cpu=number/2,lane=number&1;
    k32_ap_cpu_t *c=&k32_ap_cpus[cpu];thread_t *t=thread_current();uint32_t sp=k32_stack_pointer();
    if(cpu!=arch_cpu_id() || !t || t!=c->worker[lane] || sp<t->stack_base || sp>=t->stack_base+K32_AP_STACK)
        k32_ap_fault(cpu,0x801);
    c->stack[lane]=sp;
    while(!__atomic_load_n(&release_workers,__ATOMIC_ACQUIRE))__asm__ volatile("pause");
    uint32_t v=0x3217c0deu^cpu^lane;
    /* Neither lane voluntarily yields. Real LAPIC preemption must give the
     * other pinned lane useful execution before either can finish. */
    for(unsigned i=0;i<2000000;i++) {
        v=(v<<5)|(v>>27);v^=0x9e3779b9u;v+=i;
        if(!(i&0x3fff))__atomic_add_fetch(&c->progress[lane],1,__ATOMIC_RELEASE);
        if(i==1000000) {
            unsigned spins=0;
            while(!__atomic_load_n(&c->progress[lane^1],__ATOMIC_ACQUIRE) &&
                  !__atomic_load_n(&stop_workers,__ATOMIC_ACQUIRE) && ++spins<100000000)__asm__ volatile("pause");
            if(spins==100000000 || __atomic_load_n(&stop_workers,__ATOMIC_ACQUIRE))k32_ap_fault(cpu,0x802);
            c->peer[lane]=1;
        }
    }
    if(v!=payload(cpu,lane,2000000))k32_ap_fault(cpu,0x803);
    c->hash[lane]=v;__atomic_store_n(&c->done[lane],1,__ATOMIC_RELEASE);
}
static void ap_entry(unsigned cpu)
{
    if(!k32_ap_identity(cpu) || cache_enter() || k32_ap_arch_enter(cpu))k32_ap_fault(cpu,0x804);
    uint64_t base=msr(0x1b);
    if(!(base&(1u<<11)) || (base&(1u<<10)) || (base&0xfffff000ull)!=lapic || (apic_read(0x20)>>24)!=k32_ap_cpus[cpu].apic)
        k32_ap_fault(cpu,0x805);
    const unsigned max=(apic_read(0x30)>>16)&255;
    apic_write(0x320,0x10000|K32_AP_TIMER);apic_write(0x350,0x10000);apic_write(0x360,0x10000);
    if(max>=3)apic_write(0x340,0x10000);
    if(max>=4)apic_write(0x330,0x10000);
    if(max>=5)apic_write(0x370,0x10000);
    if(max>=6)apic_write(0x2f0,0x10000);
    apic_write(0x80,0);apic_write(0xf0,0x100|K32_AP_SPURIOUS);
    __atomic_store_n(&k32_ap_cpus[cpu].phase,1,__ATOMIC_RELEASE);
    k32_ap_stack_enter(&k32_ap_cpus[cpu].saved_boot,k32_ap_cpus[cpu].idle_base+K32_AP_STACK,cpu);
    /* Returns only after destination bootstrap withdrawal; no live scheduler
     * stack is touched here. F0/F2 remain an EOI-only drain domain. */
    for(;;)__asm__ volatile("sti; hlt; cli":::"memory");
}
#endif
void k32_ap_fault(unsigned cpu,uint32_t reason)
{
    if(cpu<K32_AP_MAX)__atomic_store_n(&k32_ap_cpus[cpu].fatal,reason,__ATOMIC_RELEASE);
    for(;;)__asm__ volatile("cli; hlt":::"memory");
}
void k32_ap_eoi(void)
{
#ifdef SHZ_STANDALONE
    apic_write(0xb0,0);
#endif
}
int k32_ap_send(unsigned cpu)
{
#ifdef SHZ_STANDALONE
    if(!k32_ap_active() || !k32_ap_started() || !cpu || cpu>=requested || (k32_ap_cpus[cpu].phase!=2 && k32_ap_cpus[cpu].phase!=3))return -1;
    return icr(k32_ap_cpus[cpu].apic,K32_AP_RESCHEDULE);
#else
    (void)cpu;return -1;
#endif
}
void k32_ap_interrupt(struct regs *r,unsigned cpu)
{
    if(!cpu || cpu>=requested || !k32_ap_identity(cpu) || (r->cs&3))k32_ap_fault(cpu,0x810|r->vector);
    if(r->vector==K32_AP_SPURIOUS)return; /* spurious never needs EOI */
    if(r->vector!=K32_AP_TIMER && r->vector!=K32_AP_RESCHEDULE)k32_ap_fault(cpu,0x900|r->vector);
    k32_ap_cpu_t *c=&k32_ap_cpus[cpu];
    const uint32_t phase=__atomic_load_n(&c->phase,__ATOMIC_ACQUIRE),frame=(uint32_t)(uintptr_t)r;
    uint32_t base=c->boot;
    if(phase==2) {
        thread_t *t=thread_current();
        if(!t || t->native_tag!=K32_AP_TAG || t->proc)k32_ap_fault(cpu,0x911);
        base=t->stack_base;
    } else if(phase!=3)k32_ap_fault(cpu,0x912);
    if(frame<base || frame>base+K32_AP_STACK-68)k32_ap_fault(cpu,0x913);
    c->irq_sp=frame;
    if(r->vector==K32_AP_TIMER)__atomic_add_fetch(&c->ticks,1,__ATOMIC_RELAXED);
    else __atomic_add_fetch(&c->ipis,1,__ATOMIC_RELAXED);
    k32_ap_eoi(); /* hardware completion BEFORE any destination-stack switch */
    if(__atomic_load_n(&c->phase,__ATOMIC_ACQUIRE)==2)k32_ap_sched_tick(cpu,r->vector==K32_AP_RESCHEDULE);
}
void k32_ap_idle_main(unsigned cpu)
{
#ifdef SHZ_STANDALONE
    k32_ap_cpu_t *c=&k32_ap_cpus[cpu];
    if(k32_ap_sched_online(cpu,k32_stack_pointer()))k32_ap_fault(cpu,0x820);
    tss_set_kernel_stack(c->idle_base+K32_AP_STACK);
    apic_write(0x3e0,3);apic_write(0x320,0x20000|K32_AP_TIMER);apic_write(0x380,lapic_count);
    for(;;) {
        cli();
        if(__atomic_load_n(&stop_workers,__ATOMIC_ACQUIRE) && k32_ap_sched_terminal(cpu)) {
            apic_write(0x320,0x10000|K32_AP_TIMER);apic_write(0x380,0);
            __atomic_store_n(&c->phase,3,__ATOMIC_RELEASE); /* pending IRR gets EOI, never reschedules */
            k32_ap_arch_tss(cpu,c->boot+K32_AP_STACK);
            k32_ap_stack_leave(c->saved_boot,cpu);
        }
        /* Pending F0/F2 atomically closes the CLI -> STI;HLT wake window. */
        __asm__ volatile("sti; hlt":::"memory");
    }
#else
    k32_ap_fault(cpu,0x821);
#endif
}
void k32_ap_stack_leave_complete(unsigned cpu)
{
    if(k32_ap_sched_withdraw(cpu,k32_stack_pointer()))k32_ap_fault(cpu,0x822);
}
int k32_ap_run(void)
{
    if(!requested)return 0;
#ifdef SHZ_STANDALONE
    if(attempted++ || arch_cpu_id()!=0 || (k32_flags()&0x200))return -1;
    __atomic_store_n(&active,1,__ATOMIC_RELEASE);heap_before=(uint32_t)kheap_used();pages_before=pmm_free_count();
    if(!cpuid_available() || cache_prepare() || k32_ap_firmware_prepare(&firmware))goto before_fail;
    uint64_t rsdp;
    if(shz_smp_acpi_find_bios(k32_ap_firmware_read,&firmware,&rsdp) || k32_ap_firmware_finish(&firmware,rsdp) ||
       shz_smp_acpi_probe(k32_ap_firmware_read,&firmware,rsdp,k32_ap_physical_id(),&topology) || topology.count!=requested ||
       !topology.pcat_compat || topology.lapic_pa>UINT32_MAX || topology.lapic_pa<firmware.ram)goto before_fail;
    const uint64_t apic_base=msr(0x1b);
    if(!(apic_base&(1u<<11)) || (apic_base&(1u<<10)) || (apic_base&0xfffff000ull)!=topology.lapic_pa)goto before_fail;
    lapic=(uint32_t)topology.lapic_pa;if(k32_vm_native_map(lapic,1))goto before_fail;
    if((apic_read(0x20)>>24)!=topology.apic_id[topology.bsp_index])goto before_fail;
    bsp_svr=apic_read(0xf0);bsp_lint0=apic_read(0x350);
    apic_write(0x350,0x700);apic_write(0xf0,0x100|K32_AP_SPURIOUS);
    if(calibration())goto restore_before_fail;
    map_pages=pages_before-pmm_free_count();
    unsigned logical=1;
    for(unsigned i=0;i<topology.count;i++)if(i!=topology.bsp_index) {
        k32_ap_cpu_t *c=&k32_ap_cpus[logical];c->apic=topology.apic_id[i];
        c->boot=(uint32_t)kmalloc(K32_AP_STACK);
        if(!c->boot || k32_ap_arch_prepare(logical) || k32_ap_sched_prepare(logical,worker))goto restore_before_fail;
        ++logical;
    }
    if(resource_check())goto restore_before_fail;
    size_t blob=(size_t)(k32_ap_blob_end-k32_ap_blob_start);
    if(!blob || blob>0x7fc)goto restore_before_fail;
    memcpy((void *)0x1000,k32_ap_blob_start,blob);
    struct params { uint32_t root,cpu,apic,claim,top,entry; };
    volatile struct params *p=(volatile struct params *)0x1800;
    /* Every target record is immutable before FIRST INIT. A late/wrong-id
     * entrant cannot claim a subsequently repurposed parameter/stack slot. */
    for(unsigned c=1;c<requested;c++)
        p[c-1]=(struct params){kernel_space(),c,k32_ap_cpus[c].apic,0,k32_ap_cpus[c].boot+K32_AP_STACK,(uint32_t)ap_entry};
    *(volatile uint32_t *)0x17fc=requested-1;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    for(unsigned c=1;c<requested;c++) {
        __atomic_store_n(&started,1,__ATOMIC_RELEASE); /* FIRST attempted INIT closes all rollback/retry paths */
        if(icr(k32_ap_cpus[c].apic,0xc500) || delay_us(10000) || icr(k32_ap_cpus[c].apic,0x8500) ||
           icr(k32_ap_cpus[c].apic,0x601) || delay_us(200) || icr(k32_ap_cpus[c].apic,0x601))goto after_fail;
        sti();int result=wait_value(&k32_ap_cpus[c].phase,2);cli();
        if(result || !__atomic_load_n(&p[c-1].claim,__ATOMIC_ACQUIRE))goto after_fail;
    }
    uint64_t clock=ticks_now();sti();
    unsigned wall_spins=0;
    while(ticks_now()==clock && ++wall_spins<100000000u)__asm__ volatile("pause");
    if(wall_spins==100000000u)goto after_fail; /* physical BSP PIC/PIT route progress */
    if(sched_cpu_online_mask()!=((1u<<requested)-1))goto after_fail;
    __atomic_store_n(&release_workers,1,__ATOMIC_RELEASE);
    for(unsigned c=1;c<requested;c++) {
        if(k32_ap_send(c))goto after_fail;
        for(unsigned lane=0;lane<2;lane++)if(wait_value(&k32_ap_cpus[c].done[lane],1))goto after_fail;
        k32_ap_cpu_t *p=&k32_ap_cpus[c];
        if(!p->peer[0] || !p->peer[1] || p->ticks<2 || !p->ipis || __atomic_load_n(&p->ack,__ATOMIC_ACQUIRE)!=__atomic_load_n(&p->request,__ATOMIC_ACQUIRE) ||
           !p->stack[0] || !p->stack[1] || p->stack[0]==p->stack[1] || p->actual_id!=c ||
           p->actual_apic!=p->apic || p->actual_root!=kernel_space() || p->actual_gdt!=p->arch ||
           p->actual_tr!=0x28 || p->actual_cs!=8 || (p->actual_flags&0x200))goto after_fail;
    }
    __atomic_store_n(&stop_workers,1,__ATOMIC_RELEASE);
    for(unsigned c=1;c<requested;c++) {
        if(k32_ap_send(c) || wait_value(&k32_ap_cpus[c].withdrawn,1))goto after_fail;
    }
    cli();
    for(unsigned c=1;c<requested;c++) {
        if(k32_ap_sched_discard(c))goto after_fail;
        ++scheduler_reclaimed;
    }
    if(sched_cpu_online_mask()!=1 || sched_validate() ||
       kheap_used()!=heap_before+(requested-1)*K32_AP_STACK ||
       pmm_free_count()!=pages_before-map_pages-(requested-1))goto after_fail;
    kprintf("K32-NATIVE-AP: CPUs=%u actual_dispatch=1 withdrawn=1 retained_boot=%u retained_arch=%u retained_map=%u heap=%u free=%u; component-only\n",
        requested,requested-1,requested-1,map_pages,(uint32_t)kheap_used(),pmm_free_count());
    for(unsigned c=1;c<requested;c++) {
        k32_ap_cpu_t *p=&k32_ap_cpus[c];
        kprintf("K32-NATIVE-CPU: cpu=%u physical=%u arch=%x boot=%x ticks=%u ipis=%u request=%u ack=%u progress=%u/%u peer=%u/%u stack=%x/%x withdrawn=%u fatal=%x\n",
            c,p->actual_apic,p->arch,p->boot,p->ticks,p->ipis,p->request,p->ack,p->progress[0],p->progress[1],p->peer[0],p->peer[1],p->stack[0],p->stack[1],p->withdrawn,p->fatal);
        kprintf("K32-NATIVE-ARCH: cpu=%u actual=%u expected_physical=%u CR3=%x GDT=%x IDT=%x TR=%x CS=%x entry_flags=%x boot_ESP=%x idle_ESP=%x withdraw_ESP=%x IRQ_ESP=%x cache_equal=1 UC_PAT3=1\n",
            c,p->actual_id,p->apic,p->actual_root,p->actual_gdt,p->actual_idt,p->actual_tr,p->actual_cs,
            p->actual_flags,p->actual_boot_sp,p->idle_sp,p->withdraw_sp,p->irq_sp);
    }
    /* Retained private EOI drain remains active. General MM stays refused;
     * this explicit component ends before old UP user/MM self-tests. */
    return 1;
restore_before_fail:
    apic_write(0x350,bsp_lint0);apic_write(0xf0,bsp_svr);
before_fail:
    for(unsigned c=1;c<requested;c++) {
        (void)k32_ap_sched_discard(c);
        if(k32_ap_cpus[c].boot)kfree((void *)k32_ap_cpus[c].boot);
        if(k32_ap_cpus[c].arch)pmm_free(k32_ap_cpus[c].arch);
    }
    k32_vm_native_rollback();__atomic_store_n(&active,0,__ATOMIC_RELEASE);
    if(kheap_used()!=heap_before || pmm_free_count()!=pages_before)return -2;
    return -1;
after_fail:
    __atomic_store_n(&stop_workers,1,__ATOMIC_RELEASE);cli();
    kprintf("K32-NATIVE-AP: FAIL post_INIT=1 retained_boot_arch_root=1 scheduler_reclaimed=%u retained_all=%u retries_refused=1\n",scheduler_reclaimed,scheduler_reclaimed==0);return -2;
#else
    return -1;
#endif
}
