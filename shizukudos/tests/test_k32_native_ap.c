/* SPDX-License-Identifier: GPL-2.0-only
 * Actual scheduler bodies. Privileged instructions and heap are host adapters;
 * no physical identity/INIT/SIPI/online execution is certified by this test. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <setjmp.h>
#define SHZ_STANDALONE
#define irq_save native_irq_save
#define irq_restore native_irq_restore
#define read_cr3 native_read_cr3
#define write_cr3 native_write_cr3
#define sti native_sti
#define cli native_cli
#define read_cr0 native_read_cr0
#define read_cr4 native_read_cr4
#define write_cr0 native_write_cr0
#define invlpg native_invlpg
#define k32_flags native_k32_flags
#define k32_stack_pointer native_k32_stack_pointer
#include "../kernel32/k32.h"
#undef irq_save
#undef irq_restore
#undef read_cr3
#undef write_cr3
#undef sti
#undef cli
#undef read_cr0
#undef read_cr4
#undef write_cr0
#undef invlpg
#undef k32_flags
#undef k32_stack_pointer
#include "../kernel32/smp_native.h"
static uint32_t host_cpu, flags=0x246, root=0x4000, host_sp;
static unsigned failures,checks;
static uint32_t irq_save(void) { uint32_t f=flags;flags&=~0x200u;return f; }
static void irq_restore(uint32_t f) { flags=f; }
static uint32_t read_cr3(void) { return root; }
static void write_cr3(uint32_t v) { root=v; }
static void sti(void) { flags|=0x200; }
static void cli(void) { flags&=~0x200u; }
static uint32_t k32_flags(void) { return flags; }
static uint32_t k32_stack_pointer(void) { return host_sp; }

static uint32_t cr0,cr4;
static uint32_t read_cr0(void) { return cr0; }
static uint32_t read_cr4(void) { return cr4; }
static void write_cr0(uint32_t v) { cr0=v; }
static void invlpg(uint32_t v) { (void)v; }
#include "generated_sched.inc"
#ifndef K32_CAPABILITY_RED
#include "generated_mem.inc"
#include "generated_policy.inc"
#endif
k32_ap_cpu_t k32_ap_cpus[K32_AP_MAX];
static unsigned active,started;
int k32_ap_active(void) { return active; }
int k32_ap_root_owned(void) { return root==kernel_space(); }
int k32_ap_started(void) { return started; }
unsigned k32_ap_count(void) { return 2; }
static jmp_buf fault_env;static int expected_fault;
void k32_ap_fault(unsigned c,uint32_t reason) { (void)c;(void)reason;if(expected_fault)longjmp(fault_env,1);abort(); }
uint32_t arch_cpu_id(void) { return host_cpu; }
#ifdef K32_CAPABILITY_RED
static unsigned char pool[512*1024] __attribute__((aligned(16)));static unsigned used;
void *kmalloc(size_t n) { if(n>sizeof pool-used)return 0;void *p=pool+used;used+=(unsigned)n;return p; }
void kfree(void *p) { (void)p; }
uint32_t kernel_space(void) { return 0x4000; }
#endif
uint32_t proc_page_directory(uint32_t p) { (void)p;return 0; }
void tss_set_kernel_stack(uint32_t s) { (void)s; }
static unsigned transfer_calls;
static int transfer_defer;
void switch_stacks(uint32_t *s,uint32_t d)
{
    if(runqueues.lock.next!=runqueues.lock.owner || (flags&0x200) || !runqueues.cpu[host_cpu].outgoing)abort();
    *s=host_sp;host_sp=d;++transfer_calls;
    if(!transfer_defer)sched_switch_complete();
}
void kpanic(const char *s,...) { fprintf(stderr,"PANIC %s\n",s);abort(); }
static void check(int ok) { ++checks;if(!ok)++failures; }
static void worker(void *p) { (void)p; }
int main(int argc,char **argv)
{
    (void)argc; (void)argv; (void)host_sp;(void)read_cr0;(void)read_cr4;(void)write_cr0;(void)invlpg;(void)worker;
#ifndef K32_CAPABILITY_RED
    if(mmap((void *)0x200000,0x200000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)!=(void *)0x200000 ||
       mmap((void *)0x10000000,0x400000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE,-1,0)!=(void *)0x10000000)abort();
    pma_ticket_init(&pmm_lock);pma_ticket_init(&heap_lock);pmm_pages=pmm_free_pages=1024;heap_init();
    kernel_pd=pmm_alloc();root=kernel_pd;
#endif
    sched_init();
    check(sched_cpu_register(1)==-2);
    uint64_t before=ticks_now();host_cpu=1;sched_tick();host_cpu=0;
    check(ticks_now()==before && sched_cpu_online_mask()==1);
#ifdef K32_CAPABILITY_RED
    /* A real existing provider cannot admit/start AP dispatch. This expected
     * capability RED is immutable; the general public refusal stays valid. */
    printf("K32_AP_BASELINE public_rc=%d ignored_ap_tick=%u online=%u checks=%u failures=%u; host-only\n",
        sched_cpu_register(1),(unsigned)(ticks_now()==before),sched_cpu_online_mask(),checks,failures);
    return failures?2:1;
#else
    flags&=~0x200u;
    uint32_t free_before=pmm_free_count();size_t heap_initial=kheap_used();
    check(k32_pmm_owned(kernel_pd));check(!k32_pmm_owned(kernel_pd+1));check(!k32_pmm_owned(0x1000));
    uint32_t page=pmm_alloc();check(k32_pmm_owned(page));pmm_free(page);check(!k32_pmm_owned(page));
    void *block=kmalloc(128);check(k32_heap_owned((uint32_t)(uintptr_t)block,128));
    check(!k32_heap_owned((uint32_t)(uintptr_t)block+16,16));check(!k32_heap_owned((uint32_t)(uintptr_t)block,129));
    struct hblock *forged=(struct hblock *)((unsigned char *)block+32);forged->size=16;forged->used=1;forged->magic=HMAGIC;forged->next=0;
    check(!k32_heap_owned((uint32_t)(uintptr_t)(forged+1),16));kfree(block);
    check(kheap_used()==heap_initial);
    flags|=0x200;check(k32_vm_native_map(0x30000000,1)==-1);flags&=~0x200u;
    check(k32_vm_native_map(0x30000000,1)==0);
    check(k32_vm_native_root_owned());
    uint32_t pde=((uint32_t *)(uintptr_t)kernel_pd)[0x30000000>>22];
    check(((uint32_t *)(uintptr_t)(pde&~4095u))[0]==0x3000001b);
    cr4=0x20;check(!k32_vm_native_root_owned());cr4=0;
    started=1;check(k32_vm_native_map(0x30001000,0)==-1);started=0;
    ((uint32_t *)(uintptr_t)kernel_pd)[1]=pde;check(!k32_vm_native_root_owned());((uint32_t *)(uintptr_t)kernel_pd)[1]=0;
    k32_vm_native_rollback();check(pmm_free_count()==free_before && k32_vm_native_root_owned());
    shz_bootinfo_t bi={0};bi.size=sizeof bi;unsigned count=99;
    check(k32_ap_policy(&bi,&count)==0 && count==0);
    const char *options[]={"shz.k32-ap=2","shz.k32-ap=4","smp=off","shz.k32-ap=4 smp=off","shz.k32-ap=2 shz.k32-ap=4","smp=off smp=off","shz.k32-ap=2 unknown"};
    const int rc[]={1,1,1,1,-1,-1,0};const unsigned counts[]={2,4,0,0,0,0,0};
    for(unsigned i=0;i<7;i++) { memset(bi.cmdline,0,sizeof bi.cmdline);strcpy(bi.cmdline,options[i]);bi.cmdline_size=(uint32_t)strlen(options[i]);check(k32_ap_policy(&bi,&count)==rc[i] && count==counts[i]); }
    strcpy(bi.cmdline,"shz.k32-ap=2");bi.cmdline_size=13;check(k32_ap_policy(&bi,&count)==-1);
    bi.cmdline_size=12;bi.channel_count=1;check(k32_ap_policy(&bi,&count)==-1);bi.channel_count=0;
    k32_native_handoff_t h={K32_NATIVE_MAGIC,1,sizeof h,K32_NATIVE_WRITER,32,0x1000,0x7000,1,0};h.checksum=0-k32_native_checksum(&h);
    check(k32_native_handoff_valid(&h));h.writer++;check(!k32_native_handoff_valid(&h));h.writer--;h.low++;check(!k32_native_handoff_valid(&h));h.low--;h.checksum++;check(!k32_native_handoff_valid(&h));
    active=1;
    check(k32_ap_sched_prepare(1,worker)==0);
    check(!k32_ap_cpus[1].idle->ready_queued && k32_ap_cpus[1].idle->state==TS_ALLOCATING);
    check(k32_ap_cpus[1].worker[0]->state==TS_ALLOCATING && !k32_ap_cpus[1].worker[0]->ready_queued);
    size_t staged_bytes=kheap_used();k32_ap_cpus[1].worker[1]->native_tag=0;
    check(k32_ap_sched_discard(1)==-1 && kheap_used()==staged_bytes && k32_ap_cpus[1].idle->state==TS_ALLOCATING);
    k32_ap_cpus[1].worker[1]->native_tag=K32_AP_TAG;
    host_cpu=1;k32_ap_cpus[1].phase=1;host_sp=k32_ap_cpus[1].idle_base+128;
#ifdef K32_PREINIT_RED
    const int preinit=k32_ap_sched_online(1,host_sp);
    printf("K32_PREINIT_GATE rc=%d mask=%u; actual-C host-only\n",preinit,sched_cpu_online_mask());
    return preinit==-1?0:1;
#endif
    check(k32_ap_sched_online(1,host_sp)==-1 && sched_cpu_online_mask()==1);
    started=1;
    check(k32_ap_sched_online(1,host_sp-16384)==-1 && sched_cpu_online_mask()==1);
    flags|=0x200;check(k32_ap_sched_online(1,host_sp)==-1 && sched_cpu_online_mask()==1);flags&=~0x200u;
    host_cpu=0;check(k32_ap_sched_online(1,host_sp)==-1 && sched_cpu_online_mask()==1);host_cpu=1;
    root=kernel_space()+4096;check(k32_ap_sched_online(1,host_sp)==-1 && sched_cpu_online_mask()==1);root=kernel_space();
    k32_ap_cpus[1].worker[0]->proc=3;
    check(k32_ap_sched_online(1,host_sp)==-1 && !k32_ap_cpus[1].worker[0]->ready_queued);
    k32_ap_cpus[1].worker[0]->proc=0;
    check(k32_ap_sched_online(1,host_sp)==0 && sched_cpu_online_mask()==3);
    check(k32_ap_cpus[1].worker[0]->ready_queued && k32_ap_cpus[1].worker[1]->ready_queued);
    check(k32_ap_sched_online(1,host_sp)==-1);
    check(sched_validate()==0);
    check(thread_create("public",worker,0)==0);
    ksem_t sem_before={17,0},sem=sem_before;kmutex_t mutex_before={0,0,0,0},mutex=mutex_before;
    for(unsigned probe=0;probe<5;probe++) {
        expected_fault=1;
        if(!setjmp(fault_env)) {
            switch(probe) {
            case 0:sem_init(&sem,1);break;
            case 1:sem_post(&sem);break;
            case 2:mutex_init(&mutex);break;
            case 3:mutex_lock(&mutex);break;
            default:(void)thread_join(k32_ap_cpus[1].idle);break;
            }
            check(0);
        } else check(!memcmp(&sem,&sem_before,sizeof sem) && !memcmp(&mutex,&mutex_before,sizeof mutex) && runqueues.lock.next==runqueues.lock.owner);
        expected_fault=0;
    }
    check(thread_set_affinity(&threads[0],2)==-1 && threads[0].affinity_mask==1);
    check(k32_ap_sched_withdraw(1,host_sp)==-1 && sched_cpu_online_mask()==3);
    /* Actual schedule and destination completion, with only ESP changed by
     * the qualified host adapter. A live outgoing stack cannot be reaped. */
    transfer_defer=1;schedule();
    check(transfer_calls==1 && runqueues.cpu[1].current==k32_ap_cpus[1].worker[0]);
    check(runqueues.cpu[1].outgoing==k32_ap_cpus[1].idle && k32_ap_cpus[1].idle->on_cpu==1);
    check(!k32_rq_reapable_locked(&runqueues,k32_ap_cpus[1].idle));
    host_cpu=0;check(k32_ap_sched_discard(1)==-1);host_cpu=1;
    sched_switch_complete();check(!runqueues.cpu[1].outgoing && k32_ap_cpus[1].idle->on_cpu==K32_CPU_NONE);
    transfer_defer=0;uint64_t wall=ticks_now(),charged=thread_current()->run_ticks;
    k32_ap_sched_tick(1,1);check(ticks_now()==wall && k32_ap_cpus[1].ack==k32_ap_cpus[1].request);
    check(k32_ap_cpus[1].worker[0]->run_ticks==charged);
    thread_t *timer_current=thread_current();charged=timer_current->run_ticks;
    k32_ap_sched_tick(1,0);check(timer_current->run_ticks==charged+1 && ticks_now()==wall);
    check(sched_validate()==0);
    k32_ap_cpus[1].boot=(uint32_t)(uintptr_t)kmalloc(K32_AP_STACK);k32_ap_cpus[1].phase=3;
    check(k32_ap_sched_withdraw(1,k32_ap_cpus[1].boot+128)==-1 && sched_cpu_online_mask()==3);
    /* Model only inactive terminal records under the actual ticket schema;
     * real ESP transfer is checked separately by the ELF32 assembly control. */
    for(unsigned i=0;i<2;i++) {
        thread_t *t=thread_current();check(t==k32_ap_cpus[1].worker[0] || t==k32_ap_cpus[1].worker[1]);
        t->state=TS_ZOMBIE;schedule();
    }
    check(thread_current()==k32_ap_cpus[1].idle && !runqueues.cpu[1].outgoing);
    check(k32_ap_sched_terminal(1));
#ifdef K32_WITHDRAW_RED
    const int withdraw=k32_ap_sched_withdraw(1,k32_ap_cpus[1].boot+128);
    printf("K32_WITHDRAW_GATE rc=%d mask=%u actual_ESP_on_idle=%u; actual-C host-only\n",withdraw,sched_cpu_online_mask(),(unsigned)(host_sp>=k32_ap_cpus[1].idle_base && host_sp<k32_ap_cpus[1].idle_base+K32_AP_STACK));
    return withdraw==-1?0:1;
#endif
    check(k32_ap_sched_withdraw(1,k32_ap_cpus[1].boot+128)==-1 && sched_cpu_online_mask()==3);
    host_sp=k32_ap_cpus[1].boot+128;
    check(k32_ap_sched_withdraw(1,host_sp)==0 && sched_cpu_online_mask()==1);
    check(k32_ap_sched_withdraw(1,k32_ap_cpus[1].boot+128)==-1);
    check(sched_validate()==0);
    host_cpu=0;started=1;check(k32_ap_sched_discard(1)==0);kfree((void *)(uintptr_t)k32_ap_cpus[1].boot);
    check(kheap_used()==heap_initial);
    printf("K32_AP_HOST checks=%u failures=%u; host-only\n",checks,failures);
    return failures?1:0;
#endif
}
