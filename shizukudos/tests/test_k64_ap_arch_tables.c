/* SPDX-License-Identifier: GPL-2.0-only
 * Decode actual production AP descriptors according to x86 field layouts.
 * No privileged instruction or interrupt entry executes in this host test.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/k64.h"
#include "../kernel64/cpu_arch_bringup.h"
extern int shz_cpu_arch_build_tables(shz_cpu_arch_tables_t *,uint64_t,uint64_t,uint64_t) __attribute__((weak));
shz_smp_cpu_t shz_smp_cpus[SHZ_SMP_MAX_CPUS];
unsigned shz_smp_this_cpu(void) { abort(); }
void shz_smp_apic_eoi(void) { abort(); }
void shz_cpu_arch_ipi(unsigned why,uint64_t stack) { (void)why;(void)stack;abort(); }
void shz_cpu_arch_fault(unsigned cpu) { (void)cpu;abort(); }
static unsigned checks;
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x);exit(1);} } while(0)
static uint64_t gate_address(const shz_cpu_gate_t *g)
{ return g->lo|((uint64_t)g->mid<<16)|((uint64_t)g->hi<<32); }
int main(void)
{
    int (*volatile build)(shz_cpu_arch_tables_t *,uint64_t,uint64_t,uint64_t)=shz_cpu_arch_build_tables;
    shz_cpu_arch_tables_t t; const uint64_t boot=DIRECT_MAP+0x1008000,irq=boot+KSTACK_BYTES,df=irq+8192;
    CHECK(build!=0);
    memset(&t,0xaa,sizeof t); CHECK(build(&t,boot,irq,df)==0);
    CHECK(t.gdt[0]==0 && t.gdt[3]==0 && t.gdt[4]==0);
    CHECK(((t.gdt[1]>>40)&255)==0x9b && ((t.gdt[1]>>53)&1)==1);
    CHECK(((t.gdt[2]>>40)&255)==0x93);
    CHECK(((t.gdt[5]>>40)&255)==0x89 && (t.gdt[5]&0xffff)==103);
    const uint64_t base=((t.gdt[5]>>16)&0xffffff)|((t.gdt[5]>>32)&0xff000000)|(t.gdt[6]<<32);
    CHECK(base==(uint64_t)&t.tss);
    CHECK(t.tss.rsp[0]==boot && t.tss.rsp[1]==0 && t.tss.rsp[2]==0);
    CHECK(t.tss.ist[0]==irq && t.tss.ist[1]==df && t.tss.ist[2]==0);
    CHECK(t.tss.iomap==104);
    for(unsigned i=0;i<256;i++) {
        const shz_cpu_gate_t *g=&t.idt[i];
        CHECK(g->selector==8 && g->type==0x8e && g->zero==0 && gate_address(g)!=0);
        CHECK(g->ist==(i==8?2:i==255?0:1));
    }
    CHECK(gate_address(&t.idt[SHZ_SMP_VEC_RESCHEDULE])!=gate_address(&t.idt[SHZ_SMP_VEC_TLB]));
    CHECK(build(0,boot,irq,df)!=0); CHECK(build(&t,boot+1,irq,df)!=0);
    CHECK(build(&t,boot,boot,df)!=0); CHECK(build(&t,boot,irq,irq)!=0);
    CHECK(build(&t,0x8000,irq,df)!=0);
    printf("PASS production private AP descriptor tables: %u checks\n",checks);
    return 0;
}
