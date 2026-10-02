/* SPDX-License-Identifier: GPL-2.0-only
 * Include actual scheduler C. Only IRQ/CR/TSS/stack/allocation boundaries differ.
 */
#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "../kernel32/k32.h"
static unsigned host_cpu, failures, checks, switches_seen, freed;
static int boundary_mode;
static ksem_t *boundary_sem;
static jmp_buf exit_boundary;
static void expect(const char *,int);
static unsigned host_flags = 0x246;
static uint32_t hi_save(void) { unsigned f=host_flags; host_flags &= ~0x200u; return f; }
static void hi_restore(uint32_t f) { host_flags=f; }
static uint32_t hi_cr3(void) { return 0x1000; }
static void hi_setcr3(uint32_t f) { (void)f; }
static void hi_sti(void) { host_flags |= 0x200; }
static void hi_cli(void) { host_flags &= ~0x200u; }
extern uint32_t sched_cpu_online_mask(void) __attribute__((weak));
extern int sched_cpu_register(uint32_t) __attribute__((weak));
extern int thread_set_affinity(thread_t *, uint32_t) __attribute__((weak));
extern uint32_t thread_get_affinity(thread_t *) __attribute__((weak));
#define irq_save hi_save
#define irq_restore hi_restore
#define read_cr3 hi_cr3
#define write_cr3 hi_setcr3
#define sti hi_sti
#define cli hi_cli
#include "../kernel32/sched.c"
#undef irq_save
#undef irq_restore
#undef read_cr3
#undef write_cr3
#undef sti
#undef cli
static unsigned char heap[65536] __attribute__((aligned(16)));
static size_t allocated;
void *kmalloc(size_t n) { if(allocated+n>sizeof heap) return 0; void *p=heap+allocated; allocated+=n; return p; }
void kfree(void *p) { (void)p; ++freed; }
uint32_t arch_cpu_id(void) { return host_cpu; }
uint32_t kernel_space(void) { return 0x1000; }
uint32_t proc_page_directory(uint32_t p) { (void)p; return 0; }
void tss_set_kernel_stack(uint32_t s) { (void)s; }
void kprintf(const char *f, ...) { (void)f; }
void kpanic(const char *f, ...) { va_list a; va_start(a,f); vfprintf(stderr,f,a); va_end(a); abort(); }
void switch_stacks(uint32_t *p,uint32_t n) {
    (void)n; ++switches_seen;
    thread_t *old=runqueues.cpu[0].outgoing;
    uint32_t token;
    int unlocked=pma_ticket_trylock(&runqueues.lock,&token);
    expect("ticket released before hardware stack boundary",unlocked && !(host_flags&0x200));
    if(unlocked) k32_rq_unlock(&runqueues,token);
    expect("outgoing identity remains active and unreachable",old && p==&old->esp && old->on_cpu==0 && !old->ready_queued);
    if(boundary_mode==1) {
        sem_post(boundary_sem);
        expect("wake during stack handoff does not queue active context",old->state==TS_READY && !old->ready_queued && old->on_cpu==0);
    }
    if(boundary_mode==2) {
        token=k32_rq_lock(&runqueues);
        expect("join cannot reclaim zombie while stack is active",old->state==TS_ZOMBIE && !k32_rq_reapable_locked(&runqueues,old) && !freed);
        k32_rq_unlock(&runqueues,token);
    }
    sched_switch_complete();
    expect("completion clears ownership on destination stack",old->on_cpu==K32_CPU_NONE && !runqueues.cpu[0].outgoing);
    if(boundary_mode==1) {
        expect("completion queues a concurrent wake exactly once",old->ready_queued && runqueues.cpu[0].queued==1 && runqueues.cpu[0].head==old && runqueues.cpu[0].tail==old);
    }
    if(boundary_mode==2) longjmp(exit_boundary,1);
}
static void fn(void *p) { (void)p; }
static void expect(const char *name,int c) { ++checks; printf("%s: %s\n",c?"PASS":"FAIL",name); failures += !c; }
int main(void) {
    volatile uintptr_t interfaces[]={(uintptr_t)sched_cpu_online_mask,(uintptr_t)sched_cpu_register,(uintptr_t)thread_set_affinity,(uintptr_t)thread_get_affinity};
    expect("production per-CPU API exists", interfaces[0] && interfaces[1] && interfaces[2] && interfaces[3]);
    if(failures) return 1;
    sched_init();
    thread_t *main_thread=thread_current(), *t=thread_create("cpu-policy",fn,0), foreign={0};
    expect("real UP online mask and default affinity", sched_cpu_online_mask()==1 && thread_get_affinity(t)==1);
    expect("AP registration is unsupported without owner handshake", sched_cpu_register(1)==-2 && sched_cpu_online_mask()==1);
    expect("invalid CPU registration rejects without mutation", sched_cpu_register(32)==-1 && sched_cpu_online_mask()==1);
    expect("offline and zero affinity reject without mutation", thread_set_affinity(t,2)==-1 && thread_set_affinity(t,0)==-1 && thread_get_affinity(t)==1);
    expect("foreign TCB rejected", thread_set_affinity(&foreign,1)==-1 && thread_get_affinity(&foreign)==0);
    expect("valid affinity preserves IRQ state", thread_set_affinity(t,1)==0 && host_flags==0x246);
    uint64_t ticks=ticks_now(), runs=main_thread->run_ticks;
    host_cpu=1; sched_tick();
    expect("unonline interrupt owner cannot charge BSP or switch", ticks_now()==ticks && main_thread->run_ticks==runs && !switches_seen);
    host_cpu=32; sched_tick();
    expect("invalid interrupt identity fails closed", ticks_now()==ticks && !thread_current());
    host_cpu=0;
    expect("BSP current remains authoritative", thread_current()==main_thread);
    /* Exercise actual selection/completion with a wake injected between scheduler
     * admission and stack-save completion. No guest stack execution is claimed. */
    uint32_t f=hi_save(), token=k32_rq_lock(&runqueues);
    k32_rq_remove_locked(&runqueues,t);t->state=TS_BLOCKED;
    ksem_t sem;sem_init(&sem,0);sem.waiters=main_thread;
    main_thread->state=TS_BLOCKED;main_thread->wait_sem=&sem;
    k32_rq_unlock(&runqueues,token);boundary_sem=&sem;boundary_mode=1;
    schedule();hi_restore(f);
    expect("real wake preserved semaphore token accounting",!sem.count && !sem.waiters && !main_thread->wait_sem);
    boundary_mode=0;f=hi_save();schedule();hi_restore(f);
    expect("saved outgoing stack is selected once after completion",thread_current()==main_thread && main_thread->state==TS_RUNNING && !main_thread->ready_queued);
    boundary_mode=2;
    if(!setjmp(exit_boundary))thread_exit(77);
    boundary_mode=0;hi_restore(0x246);
    expect("actual join reclaims terminal stack only after completion",thread_join(main_thread)==77 && freed==1 && main_thread->state==TS_FREE);
    printf("checks=%u failures=%u\n",checks,failures); return failures?1:0;
}
