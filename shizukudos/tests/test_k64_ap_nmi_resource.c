/* SPDX-License-Identifier: GPL-2.0-only
 * Exact resources_check/overlap production bodies are captured and inserted by
 * the helper. Surrounding firmware/PMM/provider facts are bounded host adapters;
 * this does not execute actual INIT, page-table hardware, firmware or NMI.
 */
#include <stdio.h>
#include <string.h>
#include "../kernel64/cpu_arch_bringup.h"
static unsigned admitted=1,resources_owned,dispatch_mode,dispatch_count;
uint64_t phys_base_va=0xffff800000000000ull;
shz_smp_cpu_t shz_smp_cpus[SHZ_SMP_MAX_CPUS];
static uint64_t arch_pa[SHZ_SMP_MAX_CPUS],owned_limit=16384,last_arch_bytes;
uint64_t kernel_pml4(void) { return 0x2000000; }
uint64_t mem_ram_top(void) { return 0x8000000; }
static int kernel_contract(void) { return 1; }
static int bootstrap_shape(uint64_t p) { (void)p;return 1; }
static int table_read(void *c,uint64_t p,void *out,size_t n)
{ (void)c;(void)p;memset(out,0,n);return 0; }
static int owned_span(uint64_t p,uint64_t n)
{
    if((p&4095) || (n&4095))return 0;
    for(unsigned cpu=1;cpu<SHZ_SMP_MAX_CPUS;cpu++)if(arch_pa[cpu] && arch_pa[cpu]==p){last_arch_bytes=n;return n<=owned_limit;}
    return 1;
}
uint64_t shz_cpu_arch_resource(unsigned cpu) { return arch_pa[cpu]; }
int sched_ap_cohort_resources(int (*owned)(uint64_t,uint64_t)) { (void)owned;return 0; }
void kprintf(const char *fmt,...) { (void)fmt; }
#include "ap_nmi_resource_body.h"
static unsigned checks,failures;
static void check(const char *name,int yes)
{ ++checks;failures+=!yes;printf("%s: %s\n",yes?"PASS":"FAIL",name); }
static void setup(unsigned count)
{
    memset(shz_smp_cpus,0,sizeof shz_smp_cpus);memset(arch_pa,0,sizeof arch_pa);
    resources_owned=last_arch_bytes=0;owned_limit=16384;
    for(unsigned cpu=0;cpu<count;cpu++) {
        const uint64_t base=phys_base_va+0x1000000+cpu*0x100000;
        shz_smp_cpus[cpu].boot_stack_top=base+KSTACK_BYTES;
        shz_smp_cpus[cpu].irq_stack_top=base+KSTACK_BYTES*2;
        shz_smp_cpus[cpu].df_stack_top=base+KSTACK_BYTES*2+8192;
        if(cpu)arch_pa[cpu]=0x3000000+cpu*0x100000;
    }
}
int main(void)
{
    setup(2);
    check("actual pre-INIT validator owns the full sixteen KiB resource",!resources_check(2,0x4000000) && resources_owned==2 && last_arch_bytes==16384);
    setup(2);owned_limit=8192;
    check("missing ownership of the upper two pages refuses admission",resources_check(2,0x4000000)==-1 && !resources_owned);
    setup(2);arch_pa[1]=0x1000000-8192;
    check("upper-half overlap with prior bootstrap stack refuses admission",resources_check(2,0x4000000)==-1 && !resources_owned);
    setup(3);arch_pa[2]=arch_pa[1]+8192;
    check("upper-half overlap with prior AP descriptor resource refuses admission",resources_check(3,0x4000000)==-1 && !resources_owned);
    printf("checks=%u failures=%u scope=actual_preINIT_resource_checker_C_host_boundary_adapters_no_INIT\n",checks,failures);
    return failures?1:0;
}
