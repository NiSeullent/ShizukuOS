/* SPDX-License-Identifier: GPL-2.0-only
 * Executes the actual VMCS loader admission; only VMPTRLD is substituted.
 * CPUID is real. The runner pins its own process to one permitted host CPU.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/cpu.h"
static unsigned checks, loads;
#define CHECK(x) do {++checks;if(!(x)){fprintf(stderr,"FAIL %s:%u %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
static int host_vmptrld(uint64_t pa) { ++loads; CHECK(pa==0x1000); return 0; }
#define vmptrld host_vmptrld
#include "../src/vmx.c"
#undef vmptrld
int main(void)
{
    vcpu_t vc={0}, original;
    const uint32_t actual=current_apic_id();
    CHECK(actual!=VMX_CPU_INVALID);
    CHECK(vmx_vcpu_load(NULL)<0 && loads==0);
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    CHECK(vmx_hw_prepare_cpus(&actual,1)==0);
    CHECK(current_cpu()==0);
    CHECK(vmx_hw_prepare_cpus(&actual,1)<0);
    vc.domain_id=SHZ_DOM_KERNEL32;vc.vmcs_pa=0x1000;
    vc.cpu_binding_valid=1;original=vc;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    CHECK(memcmp(&original,&vc,sizeof vc)==0);
    CHECK(vmx_cpu_begin(&cpu_topology,0)==0);
    CHECK(vmx_cpu_publish_tables(&cpu_topology,0,0x1000,0x2000,0x3000)==0);
    CHECK(vmx_cpu_online(&cpu_topology,0)==0);
    vc.owner_cpu=1;original=vc;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    CHECK(memcmp(&original,&vc,sizeof vc)==0);
    vc.owner_cpu=VMX_CPU_INVALID;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.owner_cpu=0;vc.cpu_binding_valid=0;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.cpu_binding_valid=2;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.cpu_binding_valid=1;vc.vmcs_pa=0;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.vmcs_pa=0x1001;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.vmcs_pa=0x1000;vc.domain_id=SHZ_DOM_SUPERVISOR;
    CHECK(vmx_vcpu_load(&vc)<0 && loads==0);
    vc.domain_id=SHZ_DOM_KERNEL32;
    CHECK(vmx_vcpu_load(&vc)==0 && loads==1);
    vc.domain_id=SHZ_DOM_WIN98;
    CHECK(vmx_vcpu_load(&vc)==0 && loads==2);
    CHECK(vmx_cpu_retire(&cpu_topology,0)==0);
    CHECK(vmx_vcpu_load(&vc)<0 && loads==2);
    CHECK(vmx_cpu_begin(&cpu_topology,0)<0);
    printf("VMCS actual CPU/load admission: %u checks passed\n",checks);
    return 0;
}
