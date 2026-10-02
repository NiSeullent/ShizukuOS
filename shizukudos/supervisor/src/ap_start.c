/* SPDX-License-Identifier: GPL-2.0-only
 * Directed physical AP startup, one attempt per retained CPU slot. This is
 * component integrity work in VMX root mode; guest domains remain on the BSP.
 */
#include "ap_start.h"
#include "../include/ap_boot.h"
#include "platform.h"
#include "cpu.h"
#include "caps.h"
#include "domain.h"
#include "console.h"
#include "ap_trampoline_image.h"
static shz_ap_boot_t *boot;
static shz_info_t private_info[SHZ_SMP_MAX_CPUS];
static const uint8_t *work_data;
static uint64_t tsc_hz;
static unsigned started;
static volatile uint32_t *lapic;
static uint64_t host_pat;
static uint32_t cache_msr[80];
static uint64_t cache_value[80];
static unsigned cache_count;
static int capture_cache(void) {
    struct cpuid_regs f=cpuid(1);
    if(!(f.edx&(1u<<12))) return -1;
    uint64_t cap=rdmsr(0xfe);
    unsigned vars=cap&255;
    if(vars>32) return -1;
    cache_msr[cache_count++]=0xfe;
    cache_msr[cache_count++]=0x2ff;
    for(unsigned i=0;i<2*vars;i++) cache_msr[cache_count++]=0x200+i;
    if(cap&(1u<<8)) {
        cache_msr[cache_count++]=0x250;
        cache_msr[cache_count++]=0x258;
        cache_msr[cache_count++]=0x259;
        for(unsigned i=0;i<8;i++) cache_msr[cache_count++]=0x268+i;
    }
    for(unsigned i=0;i<cache_count;i++) cache_value[i]=rdmsr(cache_msr[i]);
    return 0;
}
static int read_final(void *ctx,uint64_t pa,void *dst,size_t bytes) {
    shz_info_t *info=ctx;
    if(!shz_ap_map_covers((void *)(uintptr_t)info->memmap_base,info->memmap_bytes,
                          info->memmap_desc_size,pa,bytes,0)) return -1;
    memcpy(dst,(void *)(uintptr_t)pa,bytes); return 0;
}
static uint32_t actual_id(void) {
    return cpuid_count(1,0).ebx>>24;
}
static unsigned state(unsigned cpu) { return __atomic_load_n(&boot->cpu[cpu].state,__ATOMIC_ACQUIRE); }
static int wait_us(unsigned us) {
    uint64_t begin=rdtsc(),ticks=(tsc_hz/1000000)*us;
    if(!ticks) return -1;
    for(unsigned i=0;i<100000000;i++) { if(rdtsc()-begin>=ticks) return 0; pause_cpu(); }
    return -1;
}
static int icr_wait(void) {
    uint64_t begin=rdtsc();
    for(unsigned i=0;i<10000000;i++) {
        if(!(lapic[0x300/4]&(1u<<12))) return 0;
        if(rdtsc()-begin>tsc_hz/10) break;
        pause_cpu();
    }
    return -1;
}
static int ipi(unsigned id,uint32_t command) {
    if(id>=255 || icr_wait()) return -1;
    lapic[0x280/4]=0; (void)lapic[0x280/4];
    lapic[0x310/4]=id<<24;
    lapic[0x300/4]=command;
    if(icr_wait()) return -1;
    return (lapic[0x280/4]&0xefu) ? -1:0;
}
static void ap_entry(unsigned cpu) __attribute__((noreturn));
static void ap_entry(unsigned cpu) {
    if(!boot || !cpu || cpu>=boot->requested) goto park;
    shz_ap_record_t *r=&boot->cpu[cpu];
    if(actual_id()!=r->apic_id || !shz_ap_advance(r,SHZ_AP_STARTING,SHZ_AP_ENTERED)) goto park;
    if(platform_ap_enter(cpu,&r->gdt,&r->idt,&r->tss)) { shz_ap_fail(r,SHZ_AP_FAIL_START); goto park; }
    if(rdmsr(0x277)!=host_pat) { shz_ap_fail(r,SHZ_AP_FAIL_START); goto park; }
    if(!(cpuid(1).edx&(1u<<12))) { shz_ap_fail(r,SHZ_AP_FAIL_START); goto park; }
    for(unsigned i=0;i<cache_count;i++) if(rdmsr(cache_msr[i])!=cache_value[i]) {
        shz_ap_fail(r,SHZ_AP_FAIL_START); goto park;
    }
    /* INIT preserves MTRRs/cache contents (SDM v3A 11.5). Compare every
     * supported bank with BSP before enabling caches or entering VMX. */
    __asm__ volatile("wbinvd" ::: "memory");
    write_cr0(read_cr0()&~((1ull<<30)|(1ull<<29)));
    shz_caps_t caps;
    shz_probe_caps(&caps);
    /* Only this AP writes this info block; no BSP stage/control races. BSP
     * waits silently until VMX init/console output has completed. */
    if(!caps.vmx_usable || vmx_hw_init(&private_info[cpu],&caps)) {
        shz_ap_fail(r,SHZ_AP_FAIL_CAP); goto park;
    }
    r->cr0=read_cr0(); r->cr3=read_cr3(); r->cr4=read_cr4(); r->efer=rdmsr(MSR_IA32_EFER);
    if(!shz_ap_advance(r,SHZ_AP_ENTERED,SHZ_AP_VMX)) goto park;
    for(unsigned i=0;i<1000000000;i++) {
        if(__atomic_load_n(&boot->release,__ATOMIC_ACQUIRE)) break;
        if(state(cpu)==SHZ_AP_FAILED) goto park;
        pause_cpu();
        if(i==999999999) { shz_ap_fail(r,SHZ_AP_FAIL_WORK); goto park; }
    }
    if(!shz_ap_advance(r,SHZ_AP_VMX,SHZ_AP_WORKING)) goto park;
    r->hash=shz_ap_hash(work_data,SHZ_AP_WORK_BYTES,SHZ_AP_WORK_ROUNDS);
    r->work=(uint64_t)SHZ_AP_WORK_BYTES*SHZ_AP_WORK_ROUNDS;
    if(!shz_ap_advance(r,SHZ_AP_WORKING,SHZ_AP_DONE)) goto park;
park:
    for(;;) { cli(); hlt(); }
}
int shz_ap_seal(shz_info_t *info) {
    if(!info->reserved_in[0] && !info->reserved_in[1]) {
        uint32_t id=actual_id();
        return vmx_hw_prepare_cpus(&id,1);
    }
    uint64_t pa=info->reserved_in[0],bytes=info->reserved_in[1];
    if((info->loader_flags&SHZ_LOADER_NATIVE_WIN98) || bytes!=sizeof(shz_ap_boot_t) ||
       !shz_ap_map_covers((void *)(uintptr_t)info->memmap_base,info->memmap_bytes,info->memmap_desc_size,pa,SHZ_AP_PAGE,2))
        return -1;
    shz_ap_boot_t *b=(shz_ap_boot_t *)(uintptr_t)pa;
    if(!shz_ap_boot_valid(b,pa,bytes,(void *)(uintptr_t)info->memmap_base,info->memmap_bytes,
                         info->memmap_desc_size,info->region_base,info->region_size) ||
       b->topology.apic_id[0]!=actual_id() || b->topology.lapic_pa>UINT32_MAX) return -1;
    uint64_t apic_base=rdmsr(MSR_IA32_APIC_BASE);
    if(!shz_ap_lapic_base_ok(apic_base,b->topology.lapic_pa) ||
       info->tsc_hz<1000000 || info->tsc_hz>UINT64_C(10000000000)) return -1;
    /* Re-read firmware tables through the final retained map. No unchecked
     * firmware pointer or earlier map is used after ExitBootServices. */
    shz_smp_topology_t final;
    if(shz_smp_acpi_probe(read_final,info,info->acpi_rsdp,actual_id(),&final)) return -1;
    unsigned bsp=final.bsp_index;
    uint32_t id=final.apic_id[0],uid=final.acpi_uid[0];
    final.apic_id[0]=final.apic_id[bsp]; final.acpi_uid[0]=final.acpi_uid[bsp];
    final.apic_id[bsp]=id; final.acpi_uid[bsp]=uid; final.bsp_index=0;
    if(memcmp(&final,&b->topology,sizeof final)) return -1;
    struct cpuid_regs features=cpuid(1);
    if(!(features.edx&(1u<<16))) return -1;
    host_pat=rdmsr(0x277);
    if((host_pat&255)!=6 || ((host_pat>>24)&255)!=0) return -1;
    if(capture_cache() || !platform_apic_uncached(b->topology.lapic_pa) ||
       info->disk_size<SHZ_AP_WORK_BYTES ||
       !shz_ap_map_covers((void *)(uintptr_t)info->memmap_base,info->memmap_bytes,
                          info->memmap_desc_size,info->disk_base,SHZ_AP_WORK_BYTES,2)) return -1;
    work_data=(const uint8_t *)(uintptr_t)info->disk_base;
    for(unsigned cpu=1;cpu<b->requested;cpu++) {
        uint64_t page=b->low_base+(cpu-1)*SHZ_AP_PAGE;
        const uint8_t *code=(void *)(uintptr_t)page;
        for(unsigned offset=0;offset<SHZ_AP_PAGE;offset++) {
            unsigned patch=offset>=18 && offset<22 ? 18 : offset>=24 && offset<28 ? 24 :
                           offset>=32 && offset<36 ? 32 : 0;
            uint8_t expected=ap_trampoline_image[offset];
            if(patch) {
                uint32_t target=patch==18 ? 384 : patch==24 ? 128:256;
                expected=(uint8_t)((page+target)>>(8*(offset-patch)));
            }
            if(code[offset]!=expected) return -1;
        }
    }
    if(vmx_hw_prepare_cpus(b->topology.apic_id,b->requested)) return -1;
    boot=b; boot->sealed=1; tsc_hz=info->tsc_hz;
    lapic=(volatile uint32_t *)(uintptr_t)b->topology.lapic_pa;
    if((lapic[0x20/4]>>24)!=actual_id() || !(lapic[0x30/4]&255)) return -1;
    for(unsigned cpu=0;cpu<boot->requested;cpu++) boot->cpu[cpu].apic_id=boot->topology.apic_id[cpu];
    kprintf("SHZ-AP: sealed topology=%u requested=%u low=%llx pages=%llu\n",
            boot->topology.count,boot->requested,boot->low_base,boot->low_pages);
    return 0;
}
int shz_ap_start(shz_info_t *info) {
    (void)info;
    if(!boot) { kprintf("SHZ-AP: UP default; guest domains remain CPU0\n"); return 0; }
    if(started++) return -1;
    for(unsigned cpu=1;cpu<boot->requested;cpu++) {
        shz_ap_record_t *r=&boot->cpu[cpu];
        uint64_t page=boot->low_base+(cpu-1)*SHZ_AP_PAGE;
        shz_ap_params_t *p=(shz_ap_params_t *)(uintptr_t)(page+SHZ_AP_PARAMS);
        uint64_t root,stack;
        if(platform_ap_prepare(cpu,&root,&stack)) { shz_ap_fail(r,SHZ_AP_FAIL_START); return -1; }
        r->cr3=root; r->stack=stack;
        p->cr3=(uint32_t)root; p->cpu=cpu; p->apic_id=r->apic_id;
        p->stack=stack; p->entry=(uint64_t)(uintptr_t)ap_entry;
        if(!shz_ap_advance(r,SHZ_AP_NEW,SHZ_AP_STARTING)) return -1;
        /* SDM v3A 11.4.4: directed INIT, 10ms, SIPI, 200us, second SIPI
         * only when the AP has not claimed its own page. No startup retry. */
        if(ipi(r->apic_id,0x4500) || wait_us(10000) || ipi(r->apic_id,0x4600|(uint32_t)(page>>12)) ||
           wait_us(200) || (!__atomic_load_n(&p->claim,__ATOMIC_ACQUIRE) && ipi(r->apic_id,0x4600|(uint32_t)(page>>12)))) {
            shz_ap_fail(r,SHZ_AP_FAIL_START); return -1;
        }
        uint64_t begin=rdtsc();
        while(state(cpu)!=SHZ_AP_VMX && state(cpu)!=SHZ_AP_FAILED) {
            if(rdtsc()-begin>tsc_hz*2) { shz_ap_fail(r,SHZ_AP_FAIL_START); return -1; }
            pause_cpu();
        }
        if(state(cpu)!=SHZ_AP_VMX) return -1;
    }
    __atomic_store_n(&boot->release,1,__ATOMIC_RELEASE);
    boot->bsp_hash=shz_ap_hash(work_data,SHZ_AP_WORK_BYTES,SHZ_AP_WORK_ROUNDS);
    uint64_t begin=rdtsc();
    for(unsigned cpu=1;cpu<boot->requested;cpu++) {
        while(state(cpu)!=SHZ_AP_DONE && state(cpu)!=SHZ_AP_FAILED) {
            if(rdtsc()-begin>tsc_hz*2) { shz_ap_fail(&boot->cpu[cpu],SHZ_AP_FAIL_WORK); return -1; }
            pause_cpu();
        }
        shz_ap_record_t *r=&boot->cpu[cpu];
        if(state(cpu)!=SHZ_AP_DONE || r->hash!=boot->bsp_hash) return -1;
        kprintf("SHZ-AP: cpu=%u apic=%u VMXON work=%llu hash=%llx cr3=%llx stack=%llx gdt=%llx idt=%llx tss=%llx\n",
                cpu,r->apic_id,r->work,r->hash,r->cr3,r->stack,r->gdt,r->idt,r->tss);
    }
    kprintf("SHZ-AP: completed=%u hash=%llx guest-domains=CPU0\n",boot->requested,boot->bsp_hash);
    return 0;
}
