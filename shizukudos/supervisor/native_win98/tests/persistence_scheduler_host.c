/* SPDX-License-Identifier: GPL-2.0-only
 * Actual scheduler/run_slice implementation. Privileged CPU/VMCS operations
 * and native hook internals are modeled; no hardware, disk or guest executes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/cpu.h"
#include "../../src/domain.h"
#include "../../src/devices.h"
static unsigned checks,group,loads,entries,begins,ends,housekeeping,finished,running;
static uint64_t ticks,host_cr2=0xabc;
#define CHECK(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL scheduler group%u line%u: %s\n",group,__LINE__,#v);exit(2);}}while(0)
static uint64_t fake_tsc(void){return ++ticks;}
static uint64_t fake_msr(uint32_t n){CHECK(n==MSR_IA32_VMX_MISC);return 0;}
static uint64_t fake_read(uint64_t field){return field==VMCS_EXIT_REASON?EXIT_TRIPLE_FAULT:0;}
static int fake_write(uint64_t field,uint64_t value){(void)field;(void)value;return 0;}
static uint64_t fake_cr2(void){return host_cr2;}
static void fake_set_cr2(uint64_t value){host_cr2=value;}
#define rdtsc fake_tsc
#define rdmsr fake_msr
#define vmread fake_read
#define vmwrite fake_write
#define read_cr2 fake_cr2
#define write_cr2 fake_set_cr2
#include "../../src/domain.c"
#undef rdtsc
#undef rdmsr
#undef vmread
#undef vmwrite
#undef read_cr2
#undef write_cr2
void kprintf(const char *format,...){(void)format;}
void log_capture_v(char *out,unsigned n,const char *format,va_list ap)
{(void)format;(void)ap;if(n)out[0]=0;}
int vmx_vcpu_load(vcpu_t *v){CHECK(v==&g_dom[group?SHZ_DOM_WIN98:SHZ_DOM_KERNEL64].vc);++loads;return group<2?-1:0;}
int vmx_enter(vcpu_t *v){CHECK(v==&g_dom[SHZ_DOM_WIN98].vc && begins==1 && !ends && running);++entries;return group==2?1:0;}
int win98_execution_begin(domain_t *d){CHECK(d==&g_dom[SHZ_DOM_WIN98] && loads==1 && !entries);++begins;if(group==4)return -1;running=1;return 0;}
int win98_execution_end(domain_t *d){CHECK(d==&g_dom[SHZ_DOM_WIN98] && entries==1 && running);++ends;if(group==5)return -1;running=0;return 0;}
void win98_housekeeping(void){++housekeeping;CHECK(g_dom[SHZ_DOM_WIN98].state==SHZ_DS_FAILED);if(!running)finished=1;}
void win98_observe_exit(domain_t *d,uint32_t reason){CHECK(d==&g_dom[SHZ_DOM_WIN98] && reason==EXIT_TRIPLE_FAULT && ends==1 && !running);}
int win98_handle_exit(domain_t *d,uint32_t reason){(void)d;(void)reason;CHECK(0);return 0;}
int win98_ready(domain_t *d,uint64_t now){(void)d;(void)now;CHECK(0);return 0;}
void vmx_snapshot(shz_vmcs_snapshot_t *s){(void)s;}
void vmx_set_interrupt_window(vcpu_t *v,int on){(void)v;(void)on;CHECK(0);}
int vmx_guest_interruptible(void){CHECK(0);return 0;}
void vmx_inject_external(uint8_t v){(void)v;CHECK(0);}
void vmx_inject_exception(uint8_t v,int has,uint32_t error){(void)v;(void)has;(void)error;CHECK(0);}
void dev_poll(uint64_t now){(void)now;}
int dev_irq_pending(void){return 0;}
int dev_ack_irq(void){CHECK(0);return -1;}
uint64_t dev_next_event_tsc(void){return 0;}
uint8_t dev_cmos_read(uint8_t reg){(void)reg;CHECK(0);return 0;}
int dos_handle_exit(domain_t *d,uint32_t reason){(void)d;(void)reason;CHECK(0);return 0;}
int dos_ready(domain_t *d,uint64_t now){(void)d;(void)now;CHECK(0);return 0;}
void dos_housekeeping(void){CHECK(0);}
void bios_poll_input(void){CHECK(0);}
int main(int argc,char **argv)
{
    CHECK(argc==2);group=(unsigned)strtoul(argv[1],NULL,10);CHECK(group<=5);
    shz_info_t info={0};domain_t *d=&g_dom[group?SHZ_DOM_WIN98:SHZ_DOM_KERNEL64];
    info.tsc_hz=1000000000;info.loader_flags=SHZ_LOADER_NATIVE_WIN98;
    d->id=group?SHZ_DOM_WIN98:SHZ_DOM_KERNEL64;d->kind=group?DK_WIN98:DK_KERNEL64;
    d->name="mocked-execution";d->state=SHZ_DS_RUNNABLE;
    d->fx[0]=0x7f;d->fx[1]=3;d->fx[24]=0x80;d->fx[25]=0x1f;
    CHECK(!sched_run(&info) && d->state==SHZ_DS_FAILED && loads==1 && host_cr2==0xabc);
    if(!group)CHECK(!begins && !ends && !housekeeping && !finished);
    if(group==1)CHECK(!begins && !entries && !ends && housekeeping==1 && finished);
    if(group==2)CHECK(begins==1 && entries==1 && ends==1 && housekeeping==1 && finished);
    if(group==3)CHECK(begins==1 && entries==1 && ends==1 && housekeeping==2 && finished);
    if(group==4)CHECK(begins==1 && !entries && !ends && housekeeping==1 && finished);
    if(group==5)CHECK(begins==1 && entries==1 && ends==1 && housekeeping==1 && !finished && running);
    printf("PASS %u real scheduler/run_slice hook controls group%u; CPU/VMX/native hook models only\n",checks,group);return 0;
}
