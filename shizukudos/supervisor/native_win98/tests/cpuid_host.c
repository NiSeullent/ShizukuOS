/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the actual per-domain CPUID handler, without executing VMX or guest.
 */
#include <stdio.h>
#include <stdlib.h>
#include "../../src/cpu.h"
static struct cpuid_regs seed;
static unsigned calls,checks,writes;
static uint64_t rip=0x1234;
static struct cpuid_regs modeled_cpuid(uint32_t leaf,uint32_t sub)
{(void)leaf;(void)sub;++calls;return seed;}
static uint64_t modeled_read(uint64_t field)
{return field==0x681e?rip:field==0x440c?2:0;}
static void modeled_write(uint64_t field,uint64_t value)
{if(field!=0x681e){fprintf(stderr,"unexpected VMCS write\n");exit(2);}++writes;rip=value;}
#define cpuid_count modeled_cpuid
#define vmread modeled_read
#define vmwrite modeled_write
#include "../../src/domain.c"
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL %u %s\n",__LINE__,#v);exit(2);}}while(0)
int main(void)
{
 domain_t d={0};seed=(struct cpuid_regs){0x12345678,0xffffffffu,0xffffffffu,0xffffffffu};
 for(unsigned kind=0;kind<=3;++kind){
  d.kind=(dom_kind_t)kind;d.vc.gpr[GPR_RAX]=1;d.vc.gpr[GPR_RCX]=0;
  unsigned old=calls,old_writes=writes;uint64_t old_rip=rip;handle_cpuid(&d);
  CHECK(calls==old+1 && writes==old_writes+1 && rip==old_rip+2);
  CHECK(d.vc.gpr[GPR_RAX]==seed.eax);
  CHECK((d.vc.gpr[GPR_RBX]>>16)==1);
  CHECK(d.vc.gpr[GPR_RCX]&(1u<<31));
  CHECK(!(d.vc.gpr[GPR_RDX]&(1u<<9))); /* Local APIC already unsupported. */
  CHECK(!!(d.vc.gpr[GPR_RDX]&(1u<<12))==(kind!=DK_WIN98));
  CHECK(!!(d.vc.gpr[GPR_RDX]&(1u<<17))==(kind!=DK_WIN98));
  CHECK(d.vc.gpr[GPR_RDX]&(1u<<5)); /* Supported generic MSR model remains. */
  CHECK(d.vc.gpr[GPR_RDX]&(1u<<16)); /* Existing PAT model remains. */
 }
 d.kind=DK_WIN98;
 /* Zero-host feature vectors cannot acquire fabricated native capabilities. */
 seed=(struct cpuid_regs){0};d.vc.gpr[GPR_RAX]=1;d.vc.gpr[GPR_RCX]=0;handle_cpuid(&d);
 CHECK(d.vc.gpr[GPR_RDX]==0 && d.vc.gpr[GPR_RAX]==0);
 /* Other leaves and the existing hypervisor signature are preserved. */
 seed=(struct cpuid_regs){1,2,3,4};d.vc.gpr[GPR_RAX]=2;handle_cpuid(&d);
 CHECK(d.vc.gpr[GPR_RAX]==1 && d.vc.gpr[GPR_RBX]==2 && d.vc.gpr[GPR_RCX]==3 && d.vc.gpr[GPR_RDX]==4);
 unsigned old=calls;d.vc.gpr[GPR_RAX]=0x40000000;handle_cpuid(&d);
 CHECK(calls==old && d.vc.gpr[GPR_RAX]==0x40000001 && d.vc.gpr[GPR_RBX]==0x5a485353);
 printf("PASS %u actual CPUID native/other-domain/absent-host/RIP controls; no VM\n",checks);
 return 0;
}
