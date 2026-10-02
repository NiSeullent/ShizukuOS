/* SPDX-License-Identifier: GPL-2.0-only
 * Actual physical APs keep a warm alias while its actual leaf is replaced.
 * The retired frame is poisoned only after completion AND all new-frame reads.
 * No frames/tables are freed, even on successful QA completion.
 */
#include "cpu_tlb_stress.h"
extern uint64_t arch_timer_irqs(void);
enum { TLB_ROUNDS=16 };
static shz_tlb_aperture_t aperture;
static shz_tlb_owned_fn owns;
static void *owner_context;
static unsigned cpu_count,prepared,retirements;
static uint64_t pages_before,pages_after;
static volatile uint32_t warm_go,read_go,check_go,round_done,cancelled;
static struct __attribute__((aligned(64))) {
    uint32_t ready,warm,read,checked,bad,actual,reads;
    uint64_t value;
} work[SHZ_SMP_MAX_CPUS];
static uint64_t pattern(unsigned round) { return 0x544c420000000000ull+round; }
static uint64_t sample(void)
{ return *(volatile uint64_t *)(uintptr_t)SHZ_TLB_APERTURE_VA; }
static int wait_for(volatile uint32_t *value,unsigned expected,unsigned cpu)
{
    const uint64_t deadline=cpu?0:arch_timer_irqs()+2000;unsigned spins=0;
    while(__atomic_load_n(value,__ATOMIC_ACQUIRE)<expected) {
        if(__atomic_load_n(&cancelled,__ATOMIC_ACQUIRE) || ++spins==100000000u ||
           (!cpu && arch_timer_irqs()>=deadline)) return -1;
        __asm__ volatile("pause");
    }
    return 0;
}
int shz_cpu_tlb_stress_prepare(unsigned count,shz_tlb_owned_fn reader,void *ctx)
{
    unsigned fault=0;
    if(prepared || !reader) return -1;
    if(k64_cmdline_has("shz.tlb=no-invalidate")) fault=SHZ_TLB_SKIP_INVALIDATE;
    if(k64_cmdline_has("shz.tlb=withhold-completion")) fault=SHZ_TLB_WITHHOLD_ACK;
    if(shz_tlb_aperture_prepare(&aperture,kernel_pml4(),reader,ctx) ||
       shz_cpu_tlb_prepare(&aperture,count,fault)) return -1;
    owns=reader;owner_context=ctx;cpu_count=count;
    *(uint64_t *)p2v(aperture.frame[0])=pattern(0);
    *(uint64_t *)p2v(aperture.frame[1])=pattern(1);
    prepared=1;return 0;
}
static int collect(unsigned stage,unsigned round)
{
    for(unsigned i=1;i<cpu_count;i++) {
        volatile uint32_t *word=stage==0?&work[i].warm:stage==1?&work[i].read:&work[i].checked;
        if(wait_for(word,round,0)) return -1;
    }
    return 0;
}
int shz_cpu_tlb_stress(unsigned cpu)
{
    if(!prepared || cpu>=cpu_count || shz_smp_this_cpu()!=cpu || shz_cpu_tlb_enroll()) return -1;
    work[cpu].actual=shz_smp_this_cpu();__atomic_store_n(&work[cpu].ready,1,__ATOMIC_RELEASE);
    if(!cpu) {
        for(unsigned i=1;i<cpu_count;i++) if(wait_for(&work[i].ready,1,0)) goto failure;
        pages_before=pmm_free_count();
    }
    for(unsigned round=1;round<=TLB_ROUNDS;round++) {
        const unsigned index=round&1;int completed=1;
        if(!cpu) {
            *(uint64_t *)p2v(aperture.frame[index])=pattern(round);
            __atomic_store_n(&warm_go,round,__ATOMIC_RELEASE);
        } else if(wait_for(&warm_go,round,cpu)) goto failure;
        work[cpu].value=sample();++work[cpu].reads;
        if(work[cpu].value!=pattern(round-1)) ++work[cpu].bad;
        /* A tiny working set on each private AP; no CR3 reload or local timer
         * intervenes between this warming read and the F1 invalidation. */
        for(unsigned i=0;i<64;i++) if(sample()!=pattern(round-1)) ++work[cpu].bad;
        __atomic_store_n(&work[cpu].warm,round,__ATOMIC_RELEASE);
        uint64_t generation=0;
        if(!cpu) {
            if(collect(0,round) || shz_cpu_tlb_begin(index,&generation)) goto failure;
            if(shz_cpu_tlb_dispatch(generation)) completed=0;
            const uint64_t deadline=arch_timer_irqs()+2000;unsigned spins=0;
            int status;
            while((status=shz_cpu_tlb_finish(generation))==1 && arch_timer_irqs()<deadline && ++spins<100000000u)
                __asm__ volatile("pause");
            if(status || !completed) { completed=0;shz_cpu_tlb_poison(generation); }
            /* Negative controls also release readers: old/new frames remain
             * live, so their observed stale translation is safe evidence. */
            __atomic_store_n(&read_go,round,__ATOMIC_RELEASE);
        } else if(wait_for(&read_go,round,cpu)) goto failure;
        work[cpu].value=sample();++work[cpu].reads;
        if(work[cpu].value!=pattern(round)) ++work[cpu].bad;
        __atomic_store_n(&work[cpu].read,round,__ATOMIC_RELEASE);
        if(!cpu) {
            if(collect(1,round)) goto failure;
            for(unsigned i=0;i<cpu_count;i++) if(work[i].bad) completed=0;
            if(completed) {
                /* Only completed generation + new-frame observations permit
                 * repurposing old payload. There is no unpin/free here. */
                *(uint64_t *)p2v(aperture.frame[index^1])=0xdead000000000000ull+round;
                ++retirements;
            }
            __atomic_store_n(&check_go,round,__ATOMIC_RELEASE);
        } else if(wait_for(&check_go,round,cpu)) goto failure;
        work[cpu].value=sample();++work[cpu].reads;
        if(work[cpu].value!=pattern(round)) ++work[cpu].bad;
        __atomic_store_n(&work[cpu].checked,round,__ATOMIC_RELEASE);
        if(!cpu) {
            if(collect(2,round)) goto failure;
            if(!completed) goto failure;
            __atomic_store_n(&round_done,round,__ATOMIC_RELEASE);
        } else if(wait_for(&round_done,round,cpu)) goto failure;
    }
    if(!cpu) pages_after=pmm_free_count();
    return 0;
failure:
    if(!cpu) {
        shz_cpu_tlb_observation_t state;shz_cpu_tlb_observe(0,&state);shz_cpu_tlb_poison(state.request);
        pages_after=pmm_free_count();__atomic_store_n(&cancelled,1,__ATOMIC_RELEASE);
    }
    return -1;
}
void shz_cpu_tlb_stress_report(void)
{
    unsigned ready=0,bad=0;shz_cpu_tlb_observation_t state={0};
    for(unsigned cpu=0;cpu<cpu_count;cpu++) {
        shz_cpu_tlb_observe(cpu,&state);ready+=__atomic_load_n(&work[cpu].ready,__ATOMIC_ACQUIRE);bad+=work[cpu].bad;
        kprintf("SMP-TLB CPU: cpu=%u actual=%u warm=%u reads=%u ack=%llu inv=%llu bad=%u value=%llx\n",
                cpu,work[cpu].actual,work[cpu].warm,work[cpu].reads,state.ack,state.invalidations,work[cpu].bad,work[cpu].value);
    }
    unsigned retained=prepared && owns(owner_context,aperture.frame[0],PAGE_SIZE) &&
        owns(owner_context,aperture.frame[1],PAGE_SIZE) && shz_tlb_aperture_valid(&aperture);
    if(prepared) for(unsigned i=0;i<4;i++) retained=retained && owns(owner_context,aperture.table[i],PAGE_SIZE);
    if(__atomic_load_n(&cancelled,__ATOMIC_ACQUIRE) || !retained) ++bad;
    kprintf("SMP-TLB summary: cpus=%u ready=%u request=%llu completed=%llu retirements=%u poisoned=%u retained=%u pages=%llu/%llu bad=%u scheduler_cpus=1\n",
            cpu_count,ready,state.request,state.completed,retirements,state.poisoned,retained,pages_before,pages_after,bad);
}
