/* SPDX-License-Identifier: GPL-2.0-only
 * A sole-BSP-writer, immutable-generation shared-root invalidation domain.
 * No allocator, scheduler, locks, waits, user GS or FX state in IPI service.
 */
#include "cpu_tlb.h"
enum { TLB_IDLE,TLB_PUBLISHING,TLB_PENDING,TLB_POISONED };
static struct {
    shz_tlb_aperture_t ap;
    uint64_t generation,request,completed,phase,ack[SHZ_SMP_MAX_CPUS],invalidations[SHZ_SMP_MAX_CPUS];
    uint32_t count,target,ready,index,diagnostic;
} tlb;
/* One 64-bit CAS binds state to its exact generation. A stale operation can
 * neither poison nor complete its successor. Reserve two state bits; wrap is
 * rejected before any leaf change. Native x86-64 has atomic 64-bit CAS. */
static uint64_t phase_value(uint64_t generation,unsigned state)
{ return (generation<<2)|state; }
static uint32_t full_mask(unsigned count)
{ return count==32?UINT32_MAX:count && count<32?(1u<<count)-1:0; }
static int arch_compatible(void)
{ return read_cr3()==tlb.ap.root && !(read_cr4()&((1ull<<17)|(1ull<<12)|(1ull<<7))); }
static int descriptor_valid(uint64_t generation)
{
    return tlb.ap.va==SHZ_TLB_APERTURE_VA && tlb.target==full_mask(tlb.count) &&
           generation && generation==__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE) &&
           generation==__atomic_load_n(&tlb.generation,__ATOMIC_ACQUIRE) &&
           shz_smp_topology()->count==tlb.count;
}
int shz_cpu_tlb_prepare(const shz_tlb_aperture_t *ap,unsigned count,unsigned diagnostic)
{
    if(tlb.ap.prepared || !full_mask(count) || diagnostic>SHZ_TLB_WITHHOLD_ACK ||
       !shz_tlb_aperture_valid(ap)) return -1;
    tlb.ap=*ap;tlb.count=count;tlb.target=full_mask(count);tlb.diagnostic=diagnostic;
    return 0;
}
int shz_cpu_tlb_enroll(void)
{
    const uint64_t flags=irq_save();const unsigned cpu=shz_smp_this_cpu();int result=-1;
    if(tlb.ap.prepared && cpu<tlb.count && (flags&512) && arch_compatible() &&
       shz_smp_topology()->count==tlb.count &&
       __atomic_load_n(&shz_smp_cpus[cpu].state,__ATOMIC_ACQUIRE)==SHZ_SMP_CPU_ONLINE &&
       !__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE) &&
       (__atomic_load_n(&tlb.phase,__ATOMIC_ACQUIRE)&3)==TLB_IDLE) {
        __atomic_fetch_or(&tlb.ready,1u<<cpu,__ATOMIC_RELEASE);result=0;
    }
    irq_restore(flags);return result;
}
int shz_cpu_tlb_begin(unsigned index,uint64_t *generation)
{
    if(!generation) return -1;
    const uint64_t flags=irq_save();const unsigned cpu=shz_smp_this_cpu();
    const uint64_t previous=__atomic_load_n(&tlb.generation,__ATOMIC_RELAXED);
    uint64_t idle=phase_value(previous,TLB_IDLE);
    if(cpu || !(flags&512) || !tlb.ap.prepared || index>=2 || index==tlb.index ||
       !arch_compatible() || previous>=(UINT64_MAX>>2) ||
       __atomic_load_n(&tlb.ready,__ATOMIC_ACQUIRE)!=tlb.target ||
       !__atomic_compare_exchange_n(&tlb.phase,&idle,phase_value(previous,TLB_PUBLISHING),0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        irq_restore(flags);return -1;
    }
    if(!shz_tlb_aperture_valid(&tlb.ap) || shz_smp_topology()->count!=tlb.count) goto unchanged;
    const uint64_t expected=tlb.ap.frame[tlb.index]|PT_P|PT_W|PT_NX;
    uint64_t actual=__atomic_load_n(tlb.ap.leaf,__ATOMIC_ACQUIRE);
    if((actual&~0x60ull)!=expected) goto unchanged;
    const uint64_t replacement=tlb.ap.frame[index]|PT_P|PT_W|PT_NX;
    if(!__atomic_compare_exchange_n(tlb.ap.leaf,&actual,replacement,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) goto unchanged;
    tlb.index=index;const uint64_t issued=__atomic_add_fetch(&tlb.generation,1,__ATOMIC_RELAXED);
    /* The actual leaf update precedes the release publication. No subsequent
     * generation can overwrite the immutable descriptor until all completions. */
    __atomic_store_n(&tlb.request,issued,__ATOMIC_RELEASE);
    invlpg(tlb.ap.va);
    __atomic_add_fetch(&tlb.invalidations[0],1,__ATOMIC_RELAXED);
    __atomic_store_n(&tlb.ack[0],issued,__ATOMIC_RELEASE);
    __atomic_store_n(&tlb.phase,phase_value(issued,TLB_PENDING),__ATOMIC_RELEASE);
    *generation=issued;irq_restore(flags);return 0;
unchanged:
    __atomic_store_n(&tlb.phase,phase_value(previous,TLB_IDLE),__ATOMIC_RELEASE);irq_restore(flags);return -1;
}
void shz_cpu_tlb_poison(uint64_t generation)
{
    /* Only the sole BSP writer poisons or advances domain lifetime. A late
     * duplicate recipient cannot race a next publication into false poison. */
    if(shz_smp_this_cpu() || !generation || generation>(UINT64_MAX>>2)) return;
    uint64_t expected=phase_value(generation,TLB_PENDING);
    __atomic_compare_exchange_n(&tlb.phase,&expected,phase_value(generation,TLB_POISONED),0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}
int shz_cpu_tlb_dispatch(uint64_t generation)
{
    if(shz_smp_this_cpu() || generation!=__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE) ||
       __atomic_load_n(&tlb.phase,__ATOMIC_ACQUIRE)!=phase_value(generation,TLB_PENDING)) return -1;
    const uint64_t flags=irq_save();irq_restore(flags);
    if(!(flags&512)) { shz_cpu_tlb_poison(generation);return -1; }
    for(unsigned cpu=1;cpu<tlb.count;cpu++) if(shz_smp_send_ipi(cpu,SHZ_SMP_VEC_TLB)) {
        shz_cpu_tlb_poison(generation);return -1;
    }
    return 0;
}
void shz_cpu_tlb_ipi(void)
{
    const uint64_t phase=__atomic_load_n(&tlb.phase,__ATOMIC_ACQUIRE);
    if((phase&3)!=TLB_PENDING) return;
    const uint64_t generation=phase>>2;
    const unsigned cpu=shz_smp_this_cpu();
    if(cpu>=tlb.count) return;
    if(__atomic_load_n(&tlb.ack[cpu],__ATOMIC_ACQUIRE)==generation) return;
    if(!descriptor_valid(generation) || !arch_compatible() ||
       __atomic_load_n(&shz_smp_cpus[cpu].state,__ATOMIC_ACQUIRE)!=SHZ_SMP_CPU_ONLINE) {
        return; /* No ACK. The writer's exact completion gate fails closed. */
    }
    if(cpu==1 && tlb.diagnostic==SHZ_TLB_SKIP_INVALIDATE) {
        return; /* Fault control retains the warm old translation, without ACK. */
    }
    invlpg(tlb.ap.va);
    __atomic_add_fetch(&tlb.invalidations[cpu],1,__ATOMIC_RELAXED);
    if(cpu==1 && tlb.diagnostic==SHZ_TLB_WITHHOLD_ACK) return;
    /* This is completion, distinct from legacy physical delivery counters. */
    __atomic_store_n(&tlb.ack[cpu],generation,__ATOMIC_RELEASE);
}
int shz_cpu_tlb_finish(uint64_t generation)
{
    if(shz_smp_this_cpu() || !generation || generation!=__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE)) return -1;
    uint64_t phase=__atomic_load_n(&tlb.phase,__ATOMIC_ACQUIRE);
    if(phase==phase_value(generation,TLB_IDLE) && __atomic_load_n(&tlb.completed,__ATOMIC_ACQUIRE)==generation) return 0;
    if(phase!=phase_value(generation,TLB_PENDING)) return -1;
    if(!descriptor_valid(generation)) { shz_cpu_tlb_poison(generation);return -1; }
    for(unsigned cpu=0;cpu<tlb.count;cpu++)
        if(__atomic_load_n(&tlb.ack[cpu],__ATOMIC_ACQUIRE)!=generation) return 1;
    if(!__atomic_compare_exchange_n(&tlb.phase,&phase,phase_value(generation,TLB_IDLE),0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return -1;
    __atomic_store_n(&tlb.completed,generation,__ATOMIC_RELEASE);
    return 0;
}
void shz_cpu_tlb_observe(unsigned cpu,shz_cpu_tlb_observation_t *out)
{
    if(!out || cpu>=SHZ_SMP_MAX_CPUS) return;
    out->request=__atomic_load_n(&tlb.request,__ATOMIC_ACQUIRE);
    out->completed=__atomic_load_n(&tlb.completed,__ATOMIC_ACQUIRE);
    out->ack=__atomic_load_n(&tlb.ack[cpu],__ATOMIC_ACQUIRE);
    out->invalidations=__atomic_load_n(&tlb.invalidations[cpu],__ATOMIC_ACQUIRE);
    out->ready=__atomic_load_n(&tlb.ready,__ATOMIC_ACQUIRE);out->target=tlb.target;
    out->poisoned=(__atomic_load_n(&tlb.phase,__ATOMIC_ACQUIRE)&3)==TLB_POISONED;
}
