/* SPDX-License-Identifier: GPL-2.0-only
 * Baseline RED: actual mem.c replaces a PTE and the actual legacy F1 consumer
 * acknowledges delivery, but an AP's warmed translation still names old RAM.
 * Only privileged instructions and the host direct-map address are boundaries.
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
static _Thread_local uint64_t host_flags=1ull<<9;
static uint64_t cached[2];
static uint64_t host_irq_save(void) { uint64_t f=host_flags;host_flags&=~512ull;return f; }
static void host_irq_restore(uint64_t f) { host_flags=f; }
static void host_write_cr3(uint64_t pa) { (void)pa; }
static void host_invlpg(uint64_t va) { (void)va;cached[shz_smp_this_cpu()]=0; }
static void host_evidence(unsigned kind,uint64_t value) { (void)kind;(void)value; }
#define irq_save host_irq_save
#define irq_restore host_irq_restore
#define write_cr3 host_write_cr3
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
#include "../kernel64/cpu_bringup.c"
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...)
{ va_list ap;va_start(ap,fmt);vfprintf(stderr,fmt,ap);va_end(ap);_Exit(3); }
int k64_cmdline_has(const char *word) { (void)word;return 0; }
#define REQUIRE(x) do { if(!(x)) { fprintf(stderr,"fixture error line%u: %s\n",__LINE__,#x);exit(3); } } while(0)
enum { BYTES=32*1024*1024 };
static const uint64_t alias=0xffff802000000000ull;
static unsigned warm,release_read,observed;
static uint64_t old_frame,new_frame;
static int linux_cpus[2];
static void pin(int cpu)
{ cpu_set_t set;CPU_ZERO(&set);CPU_SET(cpu,&set);REQUIRE(!pthread_setaffinity_np(pthread_self(),sizeof set,&set)); }
static uint64_t read_alias(unsigned cpu)
{ if(!cached[cpu]) cached[cpu]=vm_lookup(kernel_pml4(),alias,0);return *(uint64_t *)p2v(cached[cpu]); }
static void *ap_worker(void *unused)
{
    (void)unused;pin(linux_cpus[1]);REQUIRE(shz_smp_this_cpu()==1);
    REQUIRE(read_alias(1)==0x1111222233334444ull);
    __atomic_store_n(&warm,1,__ATOMIC_RELEASE);
    while(!__atomic_load_n(&release_read,__ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    uint64_t stack=0;shz_smp_cpus[1].irq_stack_top=(uint64_t)&stack+128;
    shz_cpu_arch_ipi(1,(uint64_t)&stack); /* Actual production F1 consumer. */
    const uint64_t value=read_alias(1);
    printf("actual F1 verify=%u delivered=%u; cached=%llx current_PTE=%llx payload=%llx\n",
           jobs[1].verify,jobs[1].verify_delivered,(unsigned long long)cached[1],
           (unsigned long long)vm_lookup(kernel_pml4(),alias,0),(unsigned long long)value);
    __atomic_store_n(&observed,value==0xaaaabbbbccccddddull?1:2,__ATOMIC_RELEASE);
    return 0;
}
int main(void)
{
    cpu_set_t allowed;unsigned n=0;REQUIRE(!sched_getaffinity(0,sizeof allowed,&allowed));
    for(int cpu=0;cpu<CPU_SETSIZE && n<2;cpu++) if(CPU_ISSET(cpu,&allowed)) {
        pin(cpu);unsigned raw=initial_apic_id();
        if(!n || raw!=topology.apic_id[0]) { linux_cpus[n]=cpu;topology.apic_id[n++]=raw; }
    }
    REQUIRE(n==2);topology.count=2;pin(linux_cpus[0]);REQUIRE(shz_smp_this_cpu()==0);
    REQUIRE(mmap((void *)K64_VIRT_BASE,BYTES,PROT_READ|PROT_WRITE,
                 MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)==(void *)K64_VIRT_BASE);
    shz_bootinfo_t boot={0};boot.ram_size=BYTES;mem_init(&boot);
    old_frame=pmm_alloc();new_frame=pmm_alloc();REQUIRE(old_frame && new_frame);
    *(uint64_t *)p2v(old_frame)=0x1111222233334444ull;
    *(uint64_t *)p2v(new_frame)=0xaaaabbbbccccddddull;
    REQUIRE(!vm_map(kernel_pml4(),alias,old_frame,PT_W|PT_NX));
    pthread_t thread;REQUIRE(!pthread_create(&thread,0,ap_worker,0));
    while(!__atomic_load_n(&warm,__ATOMIC_ACQUIRE)) __asm__ volatile("pause");
    REQUIRE(!vm_map(kernel_pml4(),alias,new_frame,PT_W|PT_NX));
    REQUIRE(vm_lookup(kernel_pml4(),alias,0)==new_frame);
    __atomic_store_n(&release_read,1,__ATOMIC_RELEASE);REQUIRE(!pthread_join(thread,0));
    if(observed!=1) { puts("FAIL: delivery-only F1 ACK left the actual AP translation on the retired frame");return 1; }
    return 0;
}
