/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/vmx_cpu_state.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL %s:%u %s\n",__FILE__,__LINE__,#x);exit(1); } } while(0)
int main(void)
{
    vmx_cpu_topology_t t={0}, bad={0};
    const uint32_t ids[]={11,97,300,0xfffffffeu}, dup[]={11,97,11};
    CHECK(vmx_cpu_find(&t,11)==VMX_CPU_INVALID);
    CHECK(vmx_cpu_topology_init(&bad,NULL,1,11)<0);
    CHECK(vmx_cpu_topology_init(&bad,ids,0,11)<0);
    CHECK(vmx_cpu_topology_init(&bad,ids,VMX_CPU_MAX+1,11)<0);
    CHECK(vmx_cpu_topology_init(&bad,ids,4,97)<0);
    CHECK(vmx_cpu_topology_init(&bad,dup,3,11)<0);
    CHECK(vmx_cpu_find(&bad,11)==VMX_CPU_INVALID);
    CHECK(vmx_cpu_topology_init(&t,ids,4,11)==0);
    for(unsigned i=0;i<4;++i) CHECK(vmx_cpu_find(&t,ids[i])==i);
    CHECK(vmx_cpu_find(&t,12)==VMX_CPU_INVALID);
    CHECK(vmx_cpu_find(&t,UINT32_MAX)==VMX_CPU_INVALID);
    CHECK(vmx_cpu_topology_init(&t,ids,4,11)<0);
    CHECK(vmx_cpu_begin(&t,4)<0);
    CHECK(vmx_cpu_publish_tables(&t,0,UINT64_MAX-32,0x2000,0x3000)<0);
    CHECK(vmx_cpu_publish_tables(&t,0,0x1000,0x1010,0x3000)<0);
    CHECK(vmx_cpu_begin(&t,0)==0);
    CHECK(vmx_cpu_begin(&t,0)<0);
    CHECK(vmx_cpu_publish_tables(&t,0,0,0x2000,0x3000)<0);
    CHECK(vmx_cpu_publish_tables(&t,0,0x1000,0x2000,0x3000)==0);
    CHECK(vmx_cpu_ready(&t,0)<0);
    CHECK(vmx_cpu_bind_allowed(&t,0,0,SHZ_DOM_KERNEL32)<0);
    CHECK(vmx_cpu_online(&t,0)==0);
    CHECK(vmx_cpu_ready(&t,0)==0);
    CHECK(vmx_cpu_online(&t,0)<0);
    CHECK(vmx_cpu_bind_allowed(&t,0,0,SHZ_DOM_KERNEL32)==0);
    CHECK(vmx_cpu_bind_allowed(&t,0,1,SHZ_DOM_KERNEL32)<0);
    CHECK(vmx_cpu_bind_allowed(&t,1,1,SHZ_DOM_KERNEL32)<0);
    CHECK(vmx_cpu_bind_allowed(&t,VMX_CPU_INVALID,0,SHZ_DOM_KERNEL32)<0);
    CHECK(vmx_cpu_bind_allowed(&t,0,0,0)<0);
    CHECK(vmx_cpu_bind_allowed(&t,0,0,SHZ_DOM_SUPERVISOR)<0);
    CHECK(vmx_cpu_bind_allowed(&t,0,0,SHZ_DOM_MAX)<0);
    CHECK(vmx_cpu_begin(&t,1)==0);
    CHECK(vmx_cpu_publish_tables(&t,1,0x1000,0x5000,0x6000)<0);
    CHECK(vmx_cpu_online(&t,1)<0);
    CHECK(vmx_cpu_begin(&t,1)<0); /* failed resources stay retained */
    CHECK(vmx_cpu_begin(&t,2)==0);
    CHECK(vmx_cpu_publish_tables(&t,2,0x7000,0x2000,0x9000)<0);
    CHECK(vmx_cpu_begin(&t,3)==0);
    CHECK(vmx_cpu_publish_tables(&t,3,0xa000,0xb000,0xc000)==0);
    CHECK(vmx_cpu_online(&t,3)==0);
    CHECK(vmx_cpu_bind_allowed(&t,3,3,SHZ_DOM_KERNEL32)==0);
    CHECK(vmx_cpu_bind_allowed(&t,3,3,SHZ_DOM_WIN98)<0); /* native Win98 CPU0 */
    CHECK(vmx_cpu_bind_allowed(&t,0,0,SHZ_DOM_WIN98)==0);
    CHECK(vmx_cpu_retire(&t,3)==0);
    CHECK(vmx_cpu_ready(&t,3)<0);
    CHECK(vmx_cpu_bind_allowed(&t,3,3,SHZ_DOM_KERNEL32)<0);
    CHECK(vmx_cpu_begin(&t,3)<0);
    CHECK(vmx_cpu_retire(&t,3)<0);
    printf("VMX CPU ownership: %u checks passed\n",checks);
    return 0;
}
