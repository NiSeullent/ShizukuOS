/* SPDX-License-Identifier: GPL-2.0-only
 * Actual MM / physical CPU identity / completion C. Host boundaries are only
 * privileged registers, INVLPG and physical IPI delivery; translation caches
 * deliberately retain old frames until the real consumer invalidates them.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include "../kernel64/k64.h"
#include "../kernel64/smp_boot.h"
static _Thread_local uint64_t host_flags=512;
static uint64_t host_root,cached[2];
static unsigned instructions[2],order_errors,send_failure;
static uint64_t host_irq_save(void) { uint64_t f=host_flags;host_flags&=~512ull;return f; }
static void host_irq_restore(uint64_t f) { host_flags=f; }
static void host_write_cr3(uint64_t pa) { host_root=pa; }
static uint64_t host_read_cr3(void) { return host_root; }
static uint64_t host_read_cr4(void) { return 0x620; }
static void host_invlpg(uint64_t va);
static void host_evidence(unsigned kind,uint64_t value) { (void)kind;(void)value; }
#define irq_save host_irq_save
#define irq_restore host_irq_restore
#define write_cr3 host_write_cr3
#define read_cr3 host_read_cr3
#define read_cr4 host_read_cr4
#define invlpg host_invlpg
#define shz_evidence host_evidence
#undef K64_VIRT_BASE
#undef DIRECT_MAP
#define K64_VIRT_BASE 0x30000000ull
#define DIRECT_MAP K64_VIRT_BASE
#define SHZ_STANDALONE 1
#include "../kernel64/mem.c"
#define ap_entry host_boot_consumer
#include "../kernel64/smp_boot.c"
#undef ap_entry
static int host_send_ipi(unsigned cpu,unsigned vector);
static unsigned traced_identity(void);
#define shz_smp_send_ipi host_send_ipi
#define shz_smp_this_cpu traced_identity
#include "../kernel64/cpu_tlb_aperture.c"
#include "../kernel64/cpu_tlb.c"
#include "../kernel64/cpu_bringup.c"
#undef shz_smp_this_cpu
static unsigned checks;
#define CHECK(x) do { ++checks;if(!(x)) { fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x);exit(1); } } while(0)
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...)
{ va_list ap;va_start(ap,fmt);vfprintf(stderr,fmt,ap);va_end(ap);_Exit(3); }
int k64_cmdline_has(const char *word) { (void)word;return 0; }
static int linux_cpus[2];
static shz_bootinfo_t boot;
static shz_tlb_aperture_t aperture;
static _Thread_local int pause_duplicate;
static pthread_barrier_t duplicate_enter,duplicate_release;
static unsigned traced_identity(void)
{
    const unsigned actual=shz_smp_this_cpu(); /* Actual CPUID topology provider. */
    if(pause_duplicate) {
        pause_duplicate=0;int rc=pthread_barrier_wait(&duplicate_enter);
        CHECK(!rc || rc==PTHREAD_BARRIER_SERIAL_THREAD);
        rc=pthread_barrier_wait(&duplicate_release);CHECK(!rc || rc==PTHREAD_BARRIER_SERIAL_THREAD);
    }
    return actual;
}
static void pin(int cpu)
{ cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);CHECK(!pthread_setaffinity_np(pthread_self(),sizeof set,&set)); }
static int own(void *ctx,uint64_t pa,uint64_t bytes)
{
    (void)ctx;if(!bytes || (pa&4095) || (bytes&4095) || pa>boot.ram_size || bytes>boot.ram_size-pa) return 0;
    for(uint64_t p=pa;p<pa+bytes;p+=PAGE_SIZE) if(!shz_cpu_pmm_page_owned(p,&boot)) return 0;
    return 1;
}
static void host_invlpg(uint64_t va)
{
    const unsigned cpu=shz_smp_this_cpu();if(cpu>=2) _Exit(3);
    if(va==SHZ_TLB_APERTURE_VA) {
        if(__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE) && tlb.ack[cpu]==tlb.request) ++order_errors;
        cached[cpu]=0;++instructions[cpu];
    }
}
static int host_send_ipi(unsigned cpu,unsigned vector)
{
    CHECK(shz_smp_this_cpu()==0 && host_flags==512 && cpu==1 && vector==SHZ_SMP_VEC_TLB);
    if(send_failure) return -1;
    pin(linux_cpus[cpu]);host_flags=0;uint64_t stack=0;shz_smp_cpus[cpu].irq_stack_top=(uint64_t)&stack+128;
    shz_cpu_arch_ipi(1,(uint64_t)&stack);host_flags=512;pin(linux_cpus[0]);return 0;
}
static uint64_t read_alias(unsigned cpu)
{ if(!cached[cpu]) cached[cpu]=vm_lookup(kernel_pml4(),SHZ_TLB_APERTURE_VA,0);CHECK(cached[cpu]);return *(uint64_t *)p2v(cached[cpu]); }
static void setup(void)
{
    cpu_set_t allowed;unsigned n=0;CHECK(!sched_getaffinity(0,sizeof allowed,&allowed));
    for(int cpu=0;cpu<CPU_SETSIZE && n<2;cpu++) if(CPU_ISSET(cpu,&allowed)) {
        pin(cpu);unsigned raw=initial_apic_id();if(!n || raw!=topology.apic_id[0]) { linux_cpus[n]=cpu;topology.apic_id[n++]=raw; }
    }
    CHECK(n==2);topology.count=2;pin(linux_cpus[0]);CHECK(shz_smp_this_cpu()==0);
    CHECK(mmap((void *)K64_VIRT_BASE,32*1024*1024,PROT_READ|PROT_WRITE,
               MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void *)K64_VIRT_BASE);
    boot.ram_size=32*1024*1024;boot.initrd_gpa=PMM_BASE+128*PAGE_SIZE;boot.initrd_size=PAGE_SIZE;mem_init(&boot);
    uint64_t seed=pmm_alloc();CHECK(seed);
    CHECK(!vm_map(kernel_pml4(),SHZ_TLB_APERTURE_VA,seed,PT_W|PT_NX));
    CHECK(!vm_unmap(kernel_pml4(),SHZ_TLB_APERTURE_VA,0));pmm_free(seed);
    shz_smp_cpus[0].state=shz_smp_cpus[1].state=SHZ_SMP_CPU_ONLINE;
}
static void prepare(unsigned fault)
{
    CHECK(!shz_tlb_aperture_prepare(&aperture,kernel_pml4(),own,0));
    CHECK(own(0,aperture.frame[0],PAGE_SIZE) && own(0,aperture.frame[1],PAGE_SIZE));
    CHECK(!shz_cpu_tlb_prepare(&aperture,2,fault));CHECK(!shz_cpu_tlb_enroll());
    pin(linux_cpus[1]);CHECK(!shz_cpu_tlb_enroll());pin(linux_cpus[0]);
    *(uint64_t *)p2v(aperture.frame[0])=0x1111222233334444ull;
    *(uint64_t *)p2v(aperture.frame[1])=0xaaaabbbbccccddddull;
    CHECK(read_alias(0)==0x1111222233334444ull && read_alias(1)==0x1111222233334444ull);
    instructions[0]=instructions[1]=0;order_errors=0;
}
static void replacement(void)
{
    prepare(0);const uint64_t free=pmm_free_count();
    for(unsigned round=1;round<=16;round++) {
        uint64_t gen=0;unsigned index=round&1;CHECK(!shz_cpu_tlb_begin(index,&gen) && gen==round);
        CHECK(!shz_cpu_tlb_dispatch(gen));CHECK(!shz_cpu_tlb_finish(gen));
        CHECK(read_alias(0)==*(uint64_t *)p2v(aperture.frame[index]));
        CHECK(read_alias(1)==*(uint64_t *)p2v(aperture.frame[index]));
        CHECK(tlb.ack[0]==gen && tlb.ack[1]==gen && instructions[0]==round && instructions[1]==round);
        const uint64_t old=aperture.frame[index^1];*(uint64_t *)p2v(old)=0xdead000000000000ull+round;
        CHECK(read_alias(1)!=*(uint64_t *)p2v(old));CHECK(pmm_free_count()==free && !order_errors && host_flags==512);
    }
}
static void pending(unsigned fault,int fail_send)
{
    prepare(fault);uint64_t gen=0;const uint64_t free=pmm_free_count();CHECK(!shz_cpu_tlb_begin(1,&gen));
    send_failure=fail_send;int rc=shz_cpu_tlb_dispatch(gen);CHECK(fail_send?rc<0:rc==0);
    CHECK(shz_cpu_tlb_finish(gen)!=0);shz_cpu_tlb_poison(gen);
    CHECK(shz_cpu_tlb_finish(gen)<0);uint64_t next=0;CHECK(shz_cpu_tlb_begin(0,&next)<0 && !next);
    CHECK(own(0,aperture.frame[0],PAGE_SIZE) && own(0,aperture.frame[1],PAGE_SIZE) && pmm_free_count()==free);
    CHECK(vm_lookup(kernel_pml4(),SHZ_TLB_APERTURE_VA,0)==aperture.frame[1]);
    pin(linux_cpus[1]);shz_cpu_tlb_ipi();pin(linux_cpus[0]);CHECK(shz_cpu_tlb_finish(gen)<0);
}
static void busy(void)
{
    prepare(0);uint64_t gen=0,next=0;CHECK(!shz_cpu_tlb_begin(1,&gen));
    uint64_t pte=*aperture.leaf;CHECK(shz_cpu_tlb_begin(0,&next)<0 && !next && *aperture.leaf==pte);
    pin(linux_cpus[1]);CHECK(shz_cpu_tlb_begin(0,&next)<0 && *aperture.leaf==pte);pin(linux_cpus[0]);
    CHECK(!shz_cpu_tlb_dispatch(gen) && !shz_cpu_tlb_finish(gen));
}
static void descriptor(void)
{
    prepare(0);uint64_t gen=0;CHECK(!shz_cpu_tlb_begin(1,&gen));
    tlb.ack[1]=gen+1;CHECK(shz_cpu_tlb_finish(gen)==1);tlb.ack[1]=0;
    uint64_t va=tlb.ap.va;tlb.ap.va+=PAGE_SIZE;pin(linux_cpus[1]);shz_cpu_tlb_ipi();pin(linux_cpus[0]);
    CHECK(!instructions[1] && !tlb.ack[1] && shz_cpu_tlb_finish(gen)<0);tlb.ap.va=va;
    CHECK(own(0,aperture.frame[0],PAGE_SIZE));
}
static void future(void)
{
    prepare(0);uint64_t gen=0;CHECK(!shz_cpu_tlb_begin(1,&gen));
    __atomic_store_n(&tlb.request,gen+1,__ATOMIC_RELEASE);
    pin(linux_cpus[1]);shz_cpu_tlb_ipi();pin(linux_cpus[0]);
    CHECK(!instructions[1] && !tlb.ack[1] && shz_cpu_tlb_finish(gen+1)<0);
    CHECK(own(0,aperture.frame[0],PAGE_SIZE) && own(0,aperture.frame[1],PAGE_SIZE));
}
static void mask_negative(void)
{
    prepare(0);uint64_t gen=0;CHECK(!shz_cpu_tlb_begin(1,&gen));tlb.target=1;
    pin(linux_cpus[1]);shz_cpu_tlb_ipi();pin(linux_cpus[0]);
    CHECK(!instructions[1] && !tlb.ack[1] && shz_cpu_tlb_finish(gen)<0);
}
static void preconditions(void)
{
    prepare(0);uint64_t gen=0,old=*aperture.leaf,free=pmm_free_count();
    host_flags=0;CHECK(shz_cpu_tlb_begin(1,&gen)<0 && !gen && *aperture.leaf==old && !host_flags);host_flags=512;
    uint64_t root=host_root;host_root+=PAGE_SIZE;
    CHECK(shz_cpu_tlb_begin(1,&gen)<0 && !gen && *aperture.leaf==old);host_root=root;
    unsigned raw=topology.apic_id[0];topology.apic_id[0]=topology.apic_id[1];
    CHECK(shz_smp_this_cpu()==SHZ_SMP_MAX_CPUS && shz_cpu_tlb_begin(1,&gen)<0 && !gen && *aperture.leaf==old);
    topology.apic_id[0]=raw;tlb.generation=UINT64_MAX;
    CHECK(shz_cpu_tlb_begin(1,&gen)<0 && !gen && *aperture.leaf==old && pmm_free_count()==free && host_flags==512);
}
static void *duplicate_worker(void *unused)
{
    (void)unused;pin(linux_cpus[1]);host_flags=0;pause_duplicate=1;shz_cpu_tlb_ipi();return 0;
}
static void duplicate_race(void)
{
    prepare(0);uint64_t first=0,next=0;CHECK(!shz_cpu_tlb_begin(1,&first));CHECK(!shz_cpu_tlb_dispatch(first));
    CHECK(!pthread_barrier_init(&duplicate_enter,0,2) && !pthread_barrier_init(&duplicate_release,0,2));
    pthread_t thread;CHECK(!pthread_create(&thread,0,duplicate_worker,0));
    int rc=pthread_barrier_wait(&duplicate_enter);CHECK(!rc || rc==PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(!shz_cpu_tlb_finish(first));CHECK(!shz_cpu_tlb_begin(0,&next) && next==2);
    rc=pthread_barrier_wait(&duplicate_release);CHECK(!rc || rc==PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(!pthread_join(thread,0));CHECK(shz_cpu_tlb_finish(next)==1 && tlb.ack[1]!=next);
    shz_cpu_tlb_poison(first);CHECK(shz_cpu_tlb_finish(next)==1);
    CHECK(!shz_cpu_tlb_dispatch(next) && !shz_cpu_tlb_finish(next));
    CHECK(read_alias(1)==0x1111222233334444ull && !order_errors);
}
static void aperture_negative(void)
{
    const uint64_t free=pmm_free_count();uint64_t *root=(void *)p2v(kernel_pml4());uint64_t saved=root[256];
    root[256]|=0x80;CHECK(shz_tlb_aperture_prepare(&aperture,kernel_pml4(),own,0)<0 && pmm_free_count()==free);root[256]=saved;
    CHECK(shz_tlb_aperture_prepare(&aperture,boot.initrd_gpa,own,0)<0 && pmm_free_count()==free);
    uint64_t seed=pmm_alloc();CHECK(seed);CHECK(!vm_map(kernel_pml4(),SHZ_TLB_APERTURE_VA,seed,PT_W|PT_NX));
    CHECK(shz_tlb_aperture_prepare(&aperture,kernel_pml4(),own,0)<0 && vm_lookup(kernel_pml4(),SHZ_TLB_APERTURE_VA,0)==seed);
}
int main(int argc,char **argv)
{
    CHECK(argc==2);setup();
    if(!strcmp(argv[1],"replacement") || !strcmp(argv[1],"ack-order")) replacement();
    else if(!strcmp(argv[1],"busy")) busy();
    else if(!strcmp(argv[1],"descriptor")) descriptor();
    else if(!strcmp(argv[1],"future")) future();
    else if(!strcmp(argv[1],"mask")) mask_negative();
    else if(!strcmp(argv[1],"preconditions")) preconditions();
    else if(!strcmp(argv[1],"duplicate-race")) duplicate_race();
    else if(!strcmp(argv[1],"timeout")) pending(SHZ_TLB_WITHHOLD_ACK,0);
    else if(!strcmp(argv[1],"send-failure")) pending(0,1);
    else if(!strcmp(argv[1],"ownership")) pending(SHZ_TLB_SKIP_INVALIDATE,0);
    else if(!strcmp(argv[1],"aperture")) aperture_negative();
    else return 3;
    printf("PASS %s: %u checks, actual frame/table ownership and persistent translation model\n",argv[1],checks);return 0;
}
