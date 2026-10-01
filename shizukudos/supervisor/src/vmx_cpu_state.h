/* SPDX-License-Identifier: GPL-2.0-only
 * Immutable CPU identities and monotonic VMX ownership. No AP startup, hotplug
 * or VMCS migration. Descriptor fields remain retained even after failure.
 */
#ifndef SHZ_VMX_CPU_STATE_H
#define SHZ_VMX_CPU_STATE_H
#include <stdint.h>
#include <stddef.h>
#include "../../abi/shz_abi.h"
#define VMX_CPU_MAX 32u
#define VMX_CPU_INVALID UINT32_MAX
enum { VMX_CPU_NEW, VMX_CPU_INIT, VMX_CPU_PUBLISHING, VMX_CPU_TABLES,
       VMX_CPU_ONLINE, VMX_CPU_FAILED, VMX_CPU_RETIRED };
typedef struct {
    uint32_t sealed, count, apic[VMX_CPU_MAX], state[VMX_CPU_MAX];
    uint64_t gdt[VMX_CPU_MAX], idt[VMX_CPU_MAX], tss[VMX_CPU_MAX];
} vmx_cpu_topology_t;
static inline int vmx_cpu_tss_decode(uint64_t low,uint64_t high,uint64_t *base)
{
    if(!base || ((low>>40)&0xffu)!=0x8b || ((low>>52)&0xfu) || high>>32 ||
       ((low&0xffffu)|((low>>32)&0xf0000u))!=103) return -1;
    *base=((low>>16)&0xffffffu)|((low>>32)&0xff000000u)|(high<<32);
    return 0;
}
/* 0 virgin, 2 retained construction owner, 1 fully initialized. A failed
 * hardware construction never returns to virgin or becomes loadable. */
static inline int vmx_cpu_claim_binding(uint32_t *binding)
{
    uint32_t expected=0;
    return binding && __atomic_compare_exchange_n(binding,&expected,2,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)?0:-1;
}
static inline int vmx_cpu_topology_init(vmx_cpu_topology_t *t, const uint32_t *ids,
                                       unsigned count, uint32_t actual_bsp)
{
    uint32_t copy[VMX_CPU_MAX], expected=0;
    if(!t || !ids || !count || count>VMX_CPU_MAX || actual_bsp==VMX_CPU_INVALID) return -1;
    for(unsigned i=0;i<count;++i) copy[i]=ids[i];
    if(copy[0]!=actual_bsp) return -1;
    for(unsigned i=0;i<count;++i) {
        if(copy[i]==VMX_CPU_INVALID) return -1;
        for(unsigned j=0;j<i;++j) if(copy[i]==copy[j]) return -1;
    }
    if(!__atomic_compare_exchange_n(&t->sealed,&expected,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return -1;
    for(unsigned i=0;i<count;++i) t->apic[i]=copy[i];
    t->count=count;
    __atomic_store_n(&t->sealed,2,__ATOMIC_RELEASE);
    return 0;
}
static inline uint32_t vmx_cpu_find(const vmx_cpu_topology_t *t, uint32_t actual)
{
    if(!t || actual==VMX_CPU_INVALID || __atomic_load_n(&t->sealed,__ATOMIC_ACQUIRE)!=2) return VMX_CPU_INVALID;
    for(unsigned i=0;i<t->count;++i) if(t->apic[i]==actual) return i;
    return VMX_CPU_INVALID;
}
static inline int vmx_cpu_valid(const vmx_cpu_topology_t *t, unsigned cpu)
{
    return t && __atomic_load_n(&t->sealed,__ATOMIC_ACQUIRE)==2 && cpu<t->count;
}
static inline int vmx_cpu_transition(vmx_cpu_topology_t *t,unsigned cpu,uint32_t from,uint32_t to)
{
    if(!vmx_cpu_valid(t,cpu)) return -1;
    return __atomic_compare_exchange_n(&t->state[cpu],&from,to,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)?0:-1;
}
static inline int vmx_cpu_begin(vmx_cpu_topology_t *t,unsigned cpu)
{
    return vmx_cpu_transition(t,cpu,VMX_CPU_NEW,VMX_CPU_INIT);
}
static inline int vmx_cpu_spans_overlap(uint64_t a,uint64_t an,uint64_t b,uint64_t bn)
{
    return a<b+bn && b<a+an;
}
static inline int vmx_cpu_publish_tables(vmx_cpu_topology_t *t,unsigned cpu,uint64_t gdt,uint64_t idt,uint64_t tss)
{
    /* The current Supervisor architecture owns exactly 64/4096/104 bytes.
     * Check whole spans, including cross-kind aliases, before publication. */
    const uint64_t starts[3]={gdt,idt,tss}, sizes[3]={64,4096,104};
    for(unsigned i=0;i<3;++i) {
        if(!starts[i] || starts[i]>UINT64_MAX-sizes[i]) return -1;
        for(unsigned j=0;j<i;++j)
            if(vmx_cpu_spans_overlap(starts[i],sizes[i],starts[j],sizes[j])) return -1;
    }
    if(vmx_cpu_transition(t,cpu,VMX_CPU_INIT,VMX_CPU_PUBLISHING)) return -1;
    __atomic_store_n(&t->gdt[cpu],gdt,__ATOMIC_RELAXED);
    __atomic_store_n(&t->idt[cpu],idt,__ATOMIC_RELAXED);
    __atomic_store_n(&t->tss[cpu],tss,__ATOMIC_RELAXED);
    /* Sequential ordering is required for the cross-CPU uniqueness scan:
     * release stores alone permit both CPUs to miss each other's publish. */
    __atomic_store_n(&t->state[cpu],VMX_CPU_TABLES,__ATOMIC_SEQ_CST);
    for(unsigned i=0;i<t->count;++i) {
        if(i==cpu || __atomic_load_n(&t->state[i],__ATOMIC_SEQ_CST)<VMX_CPU_TABLES) continue;
        const uint64_t peer[3]={__atomic_load_n(&t->gdt[i],__ATOMIC_RELAXED),
                               __atomic_load_n(&t->idt[i],__ATOMIC_RELAXED),
                               __atomic_load_n(&t->tss[i],__ATOMIC_RELAXED)};
        for(unsigned a=0;a<3;++a) for(unsigned b=0;b<3;++b)
            if(vmx_cpu_spans_overlap(starts[a],sizes[a],peer[b],sizes[b])) {
                __atomic_store_n(&t->state[cpu],VMX_CPU_FAILED,__ATOMIC_RELEASE);return -1;
            }
    }
    return 0;
}
static inline int vmx_cpu_online(vmx_cpu_topology_t *t,unsigned cpu)
{
    return vmx_cpu_transition(t,cpu,VMX_CPU_TABLES,VMX_CPU_ONLINE);
}
static inline int vmx_cpu_ready(const vmx_cpu_topology_t *t,unsigned cpu)
{
    return vmx_cpu_valid(t,cpu) && __atomic_load_n(&t->state[cpu],__ATOMIC_ACQUIRE)==VMX_CPU_ONLINE?0:-1;
}
static inline int vmx_cpu_bind_allowed(const vmx_cpu_topology_t *t,unsigned actual,unsigned owner,uint64_t domain)
{
    return actual==owner && domain>SHZ_DOM_SUPERVISOR && domain<SHZ_DOM_MAX && (domain!=SHZ_DOM_WIN98 || owner==0) && !vmx_cpu_ready(t,actual)?0:-1;
}
static inline int vmx_cpu_retire(vmx_cpu_topology_t *t,unsigned cpu)
{
    return vmx_cpu_transition(t,cpu,VMX_CPU_ONLINE,VMX_CPU_RETIRED);
}
#endif
