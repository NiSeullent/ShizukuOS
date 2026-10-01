/* SPDX-License-Identifier: GPL-2.0-only
 * Native xAPIC startup for Kernel64. Does not invoke the UP scheduler on APs.
 * All physical allocation/mapping is complete before the first INIT is sent.
 */
#include "k64.h"
#include "smp_boot.h"
#include "pci.h"
shz_smp_cpu_t shz_smp_cpus[SHZ_SMP_MAX_CPUS];
static shz_smp_topology_t topology;
static volatile uint32_t *lapic;

static uint32_t initial_apic_id(void)
{
    uint32_t a=1,b,c,d;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    return b>>24;
}
unsigned shz_smp_this_cpu(void)
{
    unsigned i; uint32_t id;
    if(!topology.count) return 0;
    id=initial_apic_id();
    for(i=0;i<topology.count;i++) if(topology.apic_id[i]==id) return i;
    /* An unknown CPU is never allowed to borrow the BSP scheduler identity. */
    return SHZ_SMP_MAX_CPUS;
}
unsigned shz_smp_online_count(void)
{
    unsigned i,n=0;
    if(!topology.count) return 1;
    for(i=0;i<topology.count;i++) n+=__atomic_load_n(&shz_smp_cpus[i].state,__ATOMIC_ACQUIRE)==SHZ_SMP_CPU_ONLINE;
    return n;
}
const shz_smp_topology_t *shz_smp_topology(void) { return &topology; }
int shz_smp_cpu_online(unsigned cpu)
{
    uint32_t expected=SHZ_SMP_CPU_ENTERED;
    if(cpu>=topology.count || shz_smp_this_cpu()!=cpu) return -1;
    return __atomic_compare_exchange_n(&shz_smp_cpus[cpu].state,&expected,SHZ_SMP_CPU_ONLINE,0,__ATOMIC_RELEASE,__ATOMIC_RELAXED)?0:-1;
}
void shz_smp_apic_eoi(void) { if(lapic) lapic[0xb0/4]=0; }

#ifdef SHZ_STANDALONE
extern const uint8_t shz_smp_trampoline_start[],shz_smp_trampoline_end[];
static uint64_t final_cr3;
static shz_smp_ap_entry_fn ap_entry;
static int started;
/* The normal production consumer supplies an owning reader for every table,
 * stack and private architecture resource. The isolated baseline component
 * retains its existing documented optional-hook scope. Called before INIT. */
static shz_smp_resource_check_fn resource_check;
int shz_smp_boot_set_resource_check(shz_smp_resource_check_fn check)
{ if(started || !check) return SHZ_SMP_ACPI_INVALID;resource_check=check;return 0; }
enum { APIC_ICR_LO=0x300,APIC_ICR_HI=0x310,APIC_ESR=0x280 };
struct trampoline_params { uint32_t cr3,cpu,apic_id,claim; uint64_t stack,entry; };
_Static_assert(sizeof(struct trampoline_params)==32,"AP trampoline parameter size");

/* PIT2 supplies the actual architectural10ms/200us delays with IRQs off; no
 * reliance on a nominal QEMU TSC frequency. It is not a scheduling clock. */
static int delay_us(unsigned us)
{
    const uint8_t saved=k_inb(0x61); unsigned spin=0;
    const uint32_t count=((uint64_t)us*1193182u+999999u)/1000000u;
    if(!count || count>65535) return -1;
    k_outb(0x61,(uint8_t)(saved&~3u));
    k_outb(0x43,0xb0); k_outb(0x42,(uint8_t)count); k_outb(0x42,(uint8_t)(count>>8));
    k_outb(0x61,(uint8_t)((saved&~2u)|1u));
    while(!(k_inb(0x61)&0x20) && ++spin<10000000u) __asm__ volatile("pause");
    k_outb(0x61,saved);
    return spin<10000000u?0:-1;
}
static int icr_idle(void)
{
    unsigned spin=0;
    while((lapic[APIC_ICR_LO/4]&(1u<<12)) && ++spin<10000000u) __asm__ volatile("pause");
    return spin<10000000u?0:-1;
}
static int send(unsigned id,uint32_t value)
{
    if(id>255 || icr_idle()) return -1;
    lapic[APIC_ESR/4]=0; (void)lapic[APIC_ESR/4];
    lapic[APIC_ICR_HI/4]=id<<24;
    lapic[APIC_ICR_LO/4]=value;
    if(icr_idle() || lapic[APIC_ESR/4]) return -1;
    return 0;
}
static int phys_read(void *ctx,uint64_t pa,void *dst,size_t n)
{
    (void)ctx;
    if(pa>mem_ram_top() || n>mem_ram_top()-pa) return -1;
    memcpy(dst,(const void *)p2v(pa),n); return 0;
}
static uint64_t bootstrap_space(void)
{
    const uint64_t pml4=pmm_alloc(),pdpt=pmm_alloc(),pd=pmm_alloc(),pt=pmm_alloc();
    if(!pml4 || !pdpt || !pd || !pt || pml4>UINT32_MAX) {
        if(pt) pmm_free(pt);
        if(pd) pmm_free(pd);
        if(pdpt) pmm_free(pdpt);
        if(pml4) pmm_free(pml4);
        return 0;
    }
    memcpy((uint64_t *)p2v(pml4)+256,(const uint64_t *)p2v(final_cr3)+256,PAGE_SIZE/2);
    ((uint64_t *)p2v(pml4))[0]=pdpt|PT_P|PT_W;
    ((uint64_t *)p2v(pdpt))[0]=pd|PT_P|PT_W;
    ((uint64_t *)p2v(pd))[0]=pt|PT_P|PT_W;
    ((uint64_t *)p2v(pt))[SHZ_SMP_TRAMPOLINE_PA/PAGE_SIZE]=SHZ_SMP_TRAMPOLINE_PA|PT_P|PT_W;
    return pml4;
}
static void free_bootstrap_space(uint64_t pml4)
{
    const uint64_t pdpt=((uint64_t *)p2v(pml4))[0]&0x000ffffffffff000ull;
    const uint64_t pd=((uint64_t *)p2v(pdpt))[0]&0x000ffffffffff000ull;
    const uint64_t pt=((uint64_t *)p2v(pd))[0]&0x000ffffffffff000ull;
    pmm_free(pt); pmm_free(pd); pmm_free(pdpt); pmm_free(pml4);
}
void shz_smp_boot_ap_entry(unsigned cpu)
{
    if(cpu>=topology.count || shz_smp_this_cpu()!=cpu) for(;;) __asm__ volatile("cli; hlt");
    write_cr3(final_cr3);
    lapic[0x80/4]=0;
    lapic[0x320/4]=1u<<16; /* timer stays masked until CPU-private IDT is installed */
    lapic[0x350/4]=1u<<16; /* no PIC/ExtINT delivery on APs */
    lapic[0x360/4]=1u<<16;
    lapic[0xf0/4]=0x100|SHZ_SMP_VEC_SPURIOUS;
    /* Low parameter storage is no longer needed after this release store, so
     * the BSP may safely reuse it for the next, distinct target AP. */
    __atomic_store_n(&shz_smp_cpus[cpu].state,SHZ_SMP_CPU_ENTERED,__ATOMIC_RELEASE);
    ap_entry(cpu);
    /* A returned consumer cannot remain ONLINE with IRQs disabled. It may
     * have published ONLINE before failing, so revoke IPI admission and retain
     * its stack/bootstrap resources for the parked or late processor. */
    __atomic_store_n(&shz_smp_cpus[cpu].state,SHZ_SMP_CPU_FAILED,__ATOMIC_RELEASE);
    for(;;) __asm__ volatile("cli; hlt");
}
int shz_smp_boot_start_with_reader(uint64_t rsdp_pa,shz_smp_ap_entry_fn entry,shz_smp_phys_read_fn read,void *ctx,uint64_t initial_cr3)
{
    uint64_t base,boot_cr3,flags; unsigned i; uint32_t a=1,b,c,d; int rc;
    shz_smp_topology_t found;
    struct trampoline_params *params=(struct trampoline_params *)p2v(SHZ_SMP_TRAMPOLINE_PA+0x800);
    __asm__ volatile("pushfq; pop %0":"=r"(flags));
    if(!entry || !read || started || (flags&(1ull<<9))) return SHZ_SMP_ACPI_INVALID;
    if(shz_smp_boot_pages_safe(read,ctx,initial_cr3,read_cr3(),kernel_pml4(),mem_ram_top()))
        return SHZ_SMP_ACPI_INVALID;
    __asm__ volatile("cpuid":"+a"(a),"=b"(b),"=c"(c),"=d"(d));
    if(!(d&(1u<<9))) return SHZ_SMP_ACPI_UNSUPPORTED;
    base=rdmsr(0x1b);
    if(!(base&(1ull<<11)) || (base&(1ull<<10))) return SHZ_SMP_ACPI_UNSUPPORTED;
    if(!rsdp_pa && (rc=shz_smp_acpi_find_bios(read,ctx,&rsdp_pa))) return rc;
    rc=shz_smp_acpi_probe(read,ctx,rsdp_pa,b>>24,&found);
    if(rc) return rc;
    if(found.lapic_pa!=(base&0x000ffffffffff000ull)) return SHZ_SMP_ACPI_INVALID;
    /* The BSP occupies logical slot0 independently of firmware enumeration. */
    if(found.bsp_index) {
        const unsigned j=found.bsp_index;
        const uint32_t id=found.apic_id[0],uid=found.acpi_uid[0];
        found.apic_id[0]=found.apic_id[j]; found.acpi_uid[0]=found.acpi_uid[j];
        found.apic_id[j]=id; found.acpi_uid[j]=uid; found.bsp_index=0;
    }
    lapic=pci_bsp_lapic_acquire(found.lapic_pa,found.apic_id[0]);
    if(!lapic || (lapic[0x20/4]>>24)!=found.apic_id[0]) return SHZ_SMP_ACPI_INVALID;
    if((size_t)(shz_smp_trampoline_end-shz_smp_trampoline_start)>PAGE_SIZE) return SHZ_SMP_ACPI_LIMIT;
    final_cr3=kernel_pml4(); boot_cr3=bootstrap_space();
    if(!boot_cr3) return SHZ_SMP_ACPI_LIMIT;
    memset(shz_smp_cpus,0,sizeof shz_smp_cpus);
    for(i=0;i<found.count;i++) {
        const uint64_t stack=pmm_alloc_contig((KSTACK_BYTES*2+8192)/PAGE_SIZE);
        if(!stack) {
            unsigned j;
            for(j=0;j<i;j++) pmm_free_contig(shz_smp_cpus[j].boot_stack_top-phys_base_va-KSTACK_BYTES,
                                           (KSTACK_BYTES*2+8192)/PAGE_SIZE);
            memset(shz_smp_cpus,0,sizeof shz_smp_cpus);
            free_bootstrap_space(boot_cr3);
            return SHZ_SMP_ACPI_LIMIT;
        }
        shz_smp_cpus[i].logical_id=i; shz_smp_cpus[i].apic_id=found.apic_id[i];
        shz_smp_cpus[i].boot_stack_top=p2v(stack)+KSTACK_BYTES;
        shz_smp_cpus[i].irq_stack_top=p2v(stack)+KSTACK_BYTES*2;
        shz_smp_cpus[i].df_stack_top=p2v(stack)+KSTACK_BYTES*2+8192;
        shz_smp_cpus[i].syscall_kstack=shz_smp_cpus[i].boot_stack_top;
    }
    topology=found; ap_entry=entry;
    if(resource_check && resource_check(found.count,boot_cr3)) {
        for(i=0;i<found.count;i++)
            pmm_free_contig(shz_smp_cpus[i].boot_stack_top-phys_base_va-KSTACK_BYTES,
                            (KSTACK_BYTES*2+8192)/PAGE_SIZE);
        free_bootstrap_space(boot_cr3);memset(shz_smp_cpus,0,sizeof shz_smp_cpus);
        memset(&topology,0,sizeof topology);ap_entry=0;return SHZ_SMP_ACPI_INVALID;
    }
    shz_smp_cpus[0].state=SHZ_SMP_CPU_ONLINE;
    memcpy((void *)p2v(SHZ_SMP_TRAMPOLINE_PA),shz_smp_trampoline_start,
           (size_t)(shz_smp_trampoline_end-shz_smp_trampoline_start));
    /* Publish the retained bootstrap root even on the one-CPU control; no
     * INIT/SIPI is issued unless an actual targetAP exists. */
    params->cr3=(uint32_t)boot_cr3; params->cpu=0; params->apic_id=found.apic_id[0]; params->claim=0;
    params->stack=shz_smp_cpus[0].boot_stack_top; params->entry=(uint64_t)shz_smp_boot_ap_entry;
    lapic[0x80/4]=0; lapic[0xf0/4]=0x100|SHZ_SMP_VEC_SPURIOUS;
    started=1; /* after this point partial failures retain all AP-visible pages */
    for(i=1;i<found.count;i++) {
        unsigned wait;
        params->cr3=(uint32_t)boot_cr3; params->cpu=i; params->apic_id=found.apic_id[i]; params->claim=0;
        params->stack=shz_smp_cpus[i].boot_stack_top; params->entry=(uint64_t)shz_smp_boot_ap_entry;
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if(send(found.apic_id[i],0xc500) || delay_us(10000) || send(found.apic_id[i],0x8500) ||
           delay_us(200) || send(found.apic_id[i],0x4600|(SHZ_SMP_TRAMPOLINE_PA>>12)) || delay_us(200) ||
           send(found.apic_id[i],0x4600|(SHZ_SMP_TRAMPOLINE_PA>>12))) return -5;
        for(wait=0;wait<2000;wait++) {
            const uint32_t state=__atomic_load_n(&shz_smp_cpus[i].state,__ATOMIC_ACQUIRE);
            if(state==SHZ_SMP_CPU_ENTERED || state==SHZ_SMP_CPU_ONLINE) break;
            if(state==SHZ_SMP_CPU_FAILED) return -7;
            if(delay_us(1000)) return -5;
        }
        if(wait==2000) return -6;
    }
    return (int)found.count;
}
int shz_smp_boot_start(uint64_t rsdp_pa,shz_smp_ap_entry_fn entry,uint64_t initial_cr3)
{ return shz_smp_boot_start_with_reader(rsdp_pa,entry,phys_read,0,initial_cr3); }
int shz_smp_send_ipi(unsigned cpu,unsigned vector)
{
    if(cpu>=topology.count || vector<0x30 || vector>0xfe || !lapic ||
       __atomic_load_n(&shz_smp_cpus[cpu].state,__ATOMIC_ACQUIRE)!=SHZ_SMP_CPU_ONLINE) return -1;
    /* ICR registers are CPU-local. Disable local IRQs to prevent nested writers. */
    const uint64_t flags=irq_save();
    const int rc=send(topology.apic_id[cpu],0x4000|vector);
    irq_restore(flags);
    return rc;
}
#else
int shz_smp_boot_set_resource_check(shz_smp_resource_check_fn check)
{ (void)check;return SHZ_SMP_ACPI_UNSUPPORTED; }
int shz_smp_boot_start(uint64_t rsdp_pa,shz_smp_ap_entry_fn entry,uint64_t initial_cr3)
{ (void)rsdp_pa;(void)entry;(void)initial_cr3; return SHZ_SMP_ACPI_UNSUPPORTED; }
int shz_smp_boot_start_with_reader(uint64_t rsdp_pa,shz_smp_ap_entry_fn entry,shz_smp_phys_read_fn read,void *ctx,uint64_t initial_cr3)
{ (void)rsdp_pa;(void)entry;(void)read;(void)ctx;(void)initial_cr3; return SHZ_SMP_ACPI_UNSUPPORTED; }
int shz_smp_send_ipi(unsigned cpu,unsigned vector)
{ (void)cpu;(void)vector; return SHZ_SMP_ACPI_UNSUPPORTED; }
#endif
