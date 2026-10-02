/* SPDX-License-Identifier: GPL-2.0-only
 * Real CPU0/AP simultaneous outstanding allocation controls. Every barrier is
 * outside allocator locks. No process mapping/wait/syscall/TLB mutation here.
 */
#include "k64.h"
#include "smp_boot.h"
#include "cpu_memory_stress.h"
extern uint64_t arch_timer_irqs(void);
enum { ROUNDS=128 };
static volatile uint32_t go,checked,release_free,cancelled;
static uint64_t pages_before,pages_after,heap_before,heap_after;
static unsigned duplicate,corrupt,overlap_rounds;
static struct __attribute__((aligned(64))) {
    uint32_t ready,published,verified,freed,complete,actual,rounds,singles,run_pages,heaps,bad,irq_ok;
    uint64_t single,run,heap,bytes;
    unsigned pages;
} work[SHZ_SMP_MAX_CPUS];
static int wait_value(volatile uint32_t *value,unsigned expected,unsigned cpu)
{
    const uint64_t deadline=cpu?0:arch_timer_irqs()+2000;unsigned spins=0;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)<expected) {
        if(__atomic_load_n(&cancelled,__ATOMIC_ACQUIRE) || ++spins==100000000u ||
           (!cpu && arch_timer_irqs()>=deadline)) {
            __atomic_store_n(&cancelled,1,__ATOMIC_RELEASE);return -1;
        }
        __asm__ volatile("pause");
    }
    return 0;
}
static unsigned interrupts_on(void)
{ uint64_t f;__asm__ volatile("pushfq; pop %0":"=r"(f));return (unsigned)((f>>9)&1); }
static int overlaps(uint64_t a,uint64_t n,uint64_t b,uint64_t m)
{ return a<b+m && b<a+n; }
static int inspect(unsigned count)
{
    unsigned bad=0;
    for(unsigned i=0;i<count;i++) {
        if(!work[i].single || !work[i].run || !work[i].heap || work[i].actual!=i ||
           (work[i].single&4095) || (work[i].run&4095) || (work[i].heap&15) ||
           work[i].pages!=1+i%4 || work[i].bytes!=257+i*113) bad=1;
        if(overlaps(work[i].single,PAGE_SIZE,work[i].run,work[i].pages*PAGE_SIZE)) bad=1;
        for(unsigned j=0;j<i;j++) {
            if(overlaps(work[i].single,PAGE_SIZE,work[j].single,PAGE_SIZE) ||
               overlaps(work[i].single,PAGE_SIZE,work[j].run,work[j].pages*PAGE_SIZE) ||
               overlaps(work[i].run,work[i].pages*PAGE_SIZE,work[j].single,PAGE_SIZE) ||
               overlaps(work[i].run,work[i].pages*PAGE_SIZE,work[j].run,work[j].pages*PAGE_SIZE) ||
               overlaps(work[i].heap,work[i].bytes,work[j].heap,work[j].bytes)) bad=1;
        }
    }
    if(bad) ++duplicate;else ++overlap_rounds;
    return bad?-1:0;
}
int shz_cpu_memory_stress(unsigned cpu)
{
    const unsigned count=shz_smp_topology()->count;
    if(!count || cpu>=count || shz_smp_this_cpu()!=cpu || !interrupts_on() ||
       __atomic_load_n(&shz_smp_cpus[cpu].state,__ATOMIC_ACQUIRE)!=SHZ_SMP_CPU_ONLINE) return -1;
    work[cpu].actual=shz_smp_this_cpu();work[cpu].irq_ok=1;
    __atomic_store_n(&work[cpu].ready,1,__ATOMIC_RELEASE);
    if(!cpu) {
        for(unsigned i=0;i<count;i++) if(wait_value(&work[i].ready,1,0)) goto failure;
        pages_before=pmm_free_count();heap_before=kheap_used();
    }
    for(unsigned round=1;round<=ROUNDS;round++) {
        if(!cpu) __atomic_store_n(&go,round,__ATOMIC_RELEASE);
        else if(wait_value(&go,round,cpu)) goto failure;
        work[cpu].single=pmm_alloc();work[cpu].pages=1+cpu%4;
        work[cpu].run=pmm_alloc_contig(work[cpu].pages);work[cpu].bytes=257+cpu*113;
        work[cpu].heap=(uint64_t)kzalloc(work[cpu].bytes);
        if(!work[cpu].single || !work[cpu].run || !work[cpu].heap || !interrupts_on()) goto failure;
        unsigned char *single=(void *)p2v(work[cpu].single),*run=(void *)p2v(work[cpu].run),*heap=(void *)work[cpu].heap;
        for(unsigned i=0;i<PAGE_SIZE;i++) if(single[i]) goto failure;
        for(unsigned i=0;i<work[cpu].pages*PAGE_SIZE;i++) if(run[i]) goto failure;
        for(unsigned i=0;i<work[cpu].bytes;i++) if(heap[i]) goto failure;
        const unsigned char pattern=(unsigned char)(cpu+round);
        memset(single,pattern,PAGE_SIZE);memset(run,pattern,work[cpu].pages*PAGE_SIZE);memset(heap,pattern,work[cpu].bytes);
        __atomic_store_n(&work[cpu].published,round,__ATOMIC_RELEASE);
        if(!cpu) {
            for(unsigned i=0;i<count;i++) if(wait_value(&work[i].published,round,0)) goto failure;
            if(inspect(count)) goto failure;
            __atomic_store_n(&checked,round,__ATOMIC_RELEASE);
        } else if(wait_value(&checked,round,cpu)) goto failure;
        if(single[0]!=pattern || single[PAGE_SIZE-1]!=pattern || run[0]!=pattern ||
           run[work[cpu].pages*PAGE_SIZE-1]!=pattern || heap[0]!=pattern || heap[work[cpu].bytes-1]!=pattern) goto failure;
        __atomic_store_n(&work[cpu].verified,round,__ATOMIC_RELEASE);
        if(!cpu) {
            for(unsigned i=0;i<count;i++) if(wait_value(&work[i].verified,round,0)) goto failure;
            __atomic_store_n(&release_free,round,__ATOMIC_RELEASE);
        } else if(wait_value(&release_free,round,cpu)) goto failure;
        pmm_free(work[cpu].single);pmm_free_contig(work[cpu].run,work[cpu].pages);kfree(heap);
        if(!interrupts_on()) goto failure;
        ++work[cpu].rounds;++work[cpu].singles;work[cpu].run_pages+=work[cpu].pages;++work[cpu].heaps;
        __atomic_store_n(&work[cpu].freed,round,__ATOMIC_RELEASE);
        if(!cpu) for(unsigned i=0;i<count;i++) if(wait_value(&work[i].freed,round,0)) goto failure;
    }
    __atomic_store_n(&work[cpu].complete,1,__ATOMIC_RELEASE);
    if(!cpu) {
        for(unsigned i=0;i<count;i++) if(wait_value(&work[i].complete,1,0)) goto failure;
        pages_after=pmm_free_count();heap_after=kheap_used();
        if(pages_before!=pages_after || heap_before!=heap_after) goto failure;
    }
    return 0;
failure:
    __atomic_add_fetch(&work[cpu].bad,1,__ATOMIC_RELEASE);
    __atomic_store_n(&cancelled,1,__ATOMIC_RELEASE);return -1;
}
void shz_cpu_memory_stress_report(void)
{
    const unsigned count=shz_smp_topology()->count;unsigned ready=0,complete=0,bad=0;
    for(unsigned i=0;i<count;i++) {
        ready+=__atomic_load_n(&work[i].ready,__ATOMIC_ACQUIRE);
        complete+=__atomic_load_n(&work[i].complete,__ATOMIC_ACQUIRE);bad+=__atomic_load_n(&work[i].bad,__ATOMIC_ACQUIRE);
        kprintf("SMP-MEM CPU: cpu=%u actual=%u rounds=%u singles=%u run_pages=%u heaps=%u IF=%u bad=%u\n",
                i,work[i].actual,work[i].rounds,work[i].singles,work[i].run_pages,work[i].heaps,work[i].irq_ok,work[i].bad);
    }
    if(__atomic_load_n(&cancelled,__ATOMIC_ACQUIRE)) ++corrupt;
    kprintf("SMP-MEM summary: cpus=%u ready=%u complete=%u pages=%llu/%llu heap=%llu/%llu overlap_rounds=%u duplicate=%u corrupt=%u bad=%u scheduler_cpus=1\n",
            count,ready,complete,pages_before,pages_after,heap_before,heap_after,overlap_rounds,duplicate,corrupt,bad);
}
