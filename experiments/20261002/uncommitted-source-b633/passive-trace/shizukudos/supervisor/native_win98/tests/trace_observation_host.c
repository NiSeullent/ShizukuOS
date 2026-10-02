/* SPDX-License-Identifier: GPL-2.0-only
 * Production observer/PIO paths and legacy devices. VMCS/TSC/serial are host
 * boundaries; anonymous RAM and ATA bytes are owned tiny fixtures, not media.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef W98_OBS_DEVICE_BACKEND
#define SHZ_CPU_H
extern uint64_t fixture_now;
extern void fixture_forbidden(void);
static uint64_t rdtsc(void){return fixture_now;}
static uint8_t inb(uint16_t p){(void)p;fixture_forbidden();return 0;}
static void outb(uint16_t p,uint8_t v){(void)p;(void)v;fixture_forbidden();}
#include "../../src/devices.c"
#else
#include "../../src/cpu.h"
static unsigned checks,forbidden;
uint64_t fixture_now;
static uint64_t fields[0x7000];
static char serial[131072];
static unsigned serial_bytes;
void fixture_forbidden(void){++forbidden;fprintf(stderr,"FAIL: privileged/device side effect\n");exit(3);}
static uint64_t fixture_vmread(uint64_t field){if(field>=0x7000)fixture_forbidden();return fields[field];}
static int fixture_vmwrite(uint64_t f,uint64_t v) __attribute__((unused));
static int fixture_vmwrite(uint64_t f,uint64_t v){(void)f;(void)v;fixture_forbidden();return -1;}
static uint64_t fixture_tsc(void){return fixture_now;}
#define vmread fixture_vmread
#define vmwrite fixture_vmwrite
#define rdtsc fixture_tsc
#include "../win98.c"
#include "../trace_observation.h"
#undef vmread
#undef vmwrite
#undef rdtsc
domain_t g_dom[SHZ_MAX_DOMAINS];guest_t G;shz_info_t *g_info;uint64_t g_tsc_hz;
static shz_info_t information;
static uint8_t ram[2u<<20],bios[256u<<10],disk[1024];
static shz_blob_t bios_blob;
#define CHECK(v) do{++checks;if(!(v)){fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#v);exit(2);}}while(0)
void serial_putc(char c){CHECK(serial_bytes+1<sizeof serial);serial[serial_bytes++]=c;serial[serial_bytes]=0;}
void kprintf(const char *fmt,...)
{
    char text[1024];va_list ap;va_start(ap,fmt);int n=vsnprintf(text,sizeof text,fmt,ap);va_end(ap);
    CHECK(n>=0 && (unsigned)n<sizeof text);for(int i=0;i<n;++i)serial_putc(text[i]);
}
void log_capture(char *dst,unsigned n,const char *fmt,...)
{va_list ap;va_start(ap,fmt);vsnprintf(dst,n,fmt,ap);va_end(ap);}
void log_capture_v(char *dst,unsigned n,const char *fmt,va_list ap)
{vsnprintf(dst,n,fmt,ap);}
void dom_fail(domain_t *d,const char *fmt,...){(void)d;(void)fmt;fixture_forbidden();}
uint8_t *dom_gpa_ptr(domain_t *d,uint64_t gpa,uint64_t n)
{if(gpa>d->ram_size || n>d->ram_size-gpa)return NULL;return (uint8_t *)(uintptr_t)(d->ram_base+gpa);}
static void irq(void *unused){(void)unused;fixture_forbidden();}
static void observe_at(uint64_t seconds,unsigned reason)
{fixture_now=1000+seconds*1000000ull;win98_observe_exit(w98,reason);}
static unsigned occurrences(const char *text)
{unsigned n=0;for(const char *p=serial;(p=strstr(p,text));p+=strlen(text))++n;return n;}
static void setup(void)
{
    memset(&information,0,sizeof information);memset(ram,0,sizeof ram);memset(bios,0xcc,sizeof bios);
    w98=&g_dom[SHZ_DOM_WIN98];memset(w98,0,sizeof *w98);w98->id=SHZ_DOM_WIN98;w98->kind=DK_WIN98;w98->state=SHZ_DS_RUNNABLE;
    w98->ram_base=(uintptr_t)ram;w98->ram_size=sizeof ram;
    bios_blob.base=(uintptr_t)bios;bios_blob.size=sizeof bios;rom=&bios_blob;
    G=(guest_t){.vc=&w98->vc,.ram_base=(uintptr_t)ram,.ram_size=sizeof ram,.info=&information,.tsc_hz=1000000};g_info=&information;g_tsc_hz=1000000;
    fields[VMCS_GUEST_CR0]=0x30;fields[VMCS_GUEST_CS_SEL]=0x70;fields[VMCS_GUEST_CS_BASE]=0x700;
    fields[VMCS_GUEST_RIP]=0x222;fields[VMCS_GUEST_SS_BASE]=0x1000;fields[VMCS_GUEST_RSP]=0x200;fields[VMCS_GUEST_RFLAGS]=0x202;
    ram[0x922]=0x90;ram[0x1200]=0x5a;for(unsigned i=0;i<2000;++i){ram[0xb8000+i*2]='A'+i%26;ram[0xb8001+i*2]=7;}
    fixture_now=1000;dev_init(1000000,sizeof ram);dev_native_win98_enable();
    CHECK(!w98_ata_init(&ata,disk,sizeof disk,irq,NULL));
    win98_observe_exit(w98,EXIT_PREEMPTION_TIMER);
}
static void helper(void)
{
    w98_observation_t o;w98_obs_init(&o,7,1000000);CHECK(o.started);
    CHECK(!w98_obs_exit(&o,60000006,52));CHECK(w98_obs_exit(&o,60000007,52)==1);
    CHECK(!w98_obs_exit(&o,239000007,12));CHECK(w98_obs_exit(&o,240000007,12)==2);
    CHECK(!w98_obs_exit(&o,UINT64_MAX,99));CHECK(o.other_reason==1 && o.reasons[52]==2);
    w98_obs_init(&o,100,1000000);CHECK(!w98_obs_exit(&o,99,1));CHECK(o.clock_refused && !w98_obs_exit(&o,UINT64_MAX,1));
    w98_obs_init(&o,0,999999);CHECK(!o.started && !w98_obs_exit(&o,UINT64_MAX,1));
    w98_obs_init(&o,0,1000000);for(unsigned n=0;n<100;++n)w98_obs_pio(&o,n,0x64,1,1,n);
    CHECK(o.pio_count==100 && o.pio[99%32].sequence==100 && o.pio[68%32].sequence==69);
    o.controller_f[14]=UINT64_MAX;w98_obs_pio(&o,100,0x64,1,1,0xfe);CHECK(o.controller_f[14]==UINT64_MAX);
    o.reasons[12]=UINT64_MAX;w98_obs_exit(&o,101,12);CHECK(o.reasons[12]==UINT64_MAX);
    while(w98_obs_line(&o,100)){}CHECK(o.serial_bytes<=W98_OBS_SERIAL_BYTES-64);CHECK(!w98_obs_line(&o,UINT32_MAX));
}
int main(int argc,char **argv)
{
    CHECK(argc==2);setup();const char *name=argv[1];
    if(!strcmp(name,"helper"))helper();
    else if(!strcmp(name,"runnable")){
        observe_at(59,EXIT_PREEMPTION_TIMER);CHECK(!occurrences("W98OBS snapshot="));
        observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(occurrences("W98OBS snapshot=")==1);
        observe_at(239,EXIT_HLT);CHECK(occurrences("W98OBS snapshot=")==1);
        observe_at(240,EXIT_HLT);observe_at(999,EXIT_HLT);CHECK(occurrences("W98OBS snapshot=")==2);
    }else if(!strcmp(name,"late-pio")){
        for(unsigned n=0;n<100;++n){CHECK(output(NULL,0x64,1,n&1?0xad:0xae));}
        CHECK(dev_native_observation()->kbc_count==64 && dev_native_observation()->kbc_dropped>0);
        CHECK(output(NULL,0x64,1,0xfe));CHECK(output(NULL,0x64,1,0xd1));CHECK(output(NULL,0x60,1,2));CHECK(output(NULL,0x92,1,3));
        observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"fE=1") && strstr(serial,"d1-bit0-clear=1") && strstr(serial,"port92-bit0-set=1"));
    }else if(!strcmp(name,"terminal")){
        observe_at(60,EXIT_PREEMPTION_TIMER);observe_at(61,EXIT_TRIPLE_FAULT);observe_at(62,EXIT_TRIPLE_FAULT);
        CHECK(occurrences("W98TRACE paused-VMCS")==1);
    }else if(!strcmp(name,"default")){
        domain_t other={0};other.kind=DK_KERNEL64;fixture_now=UINT64_MAX;win98_observe_exit(&other,EXIT_TRIPLE_FAULT);CHECK(!serial_bytes);
        dev_init(1000000,sizeof ram);CHECK(!dev_native_observation());
    }else if(!strcmp(name,"passivity")){
        const domain_t before=*w98;const w98_ata_t before_ata=ata;const guest_t before_g=G;const dev_native_observation_t before_dev=*dev_native_observation();
        uint8_t copy[sizeof ram];memcpy(copy,ram,sizeof ram);observe_at(60,EXIT_PREEMPTION_TIMER);
        CHECK(!memcmp(&before,w98,sizeof before) && !memcmp(&before_ata,&ata,sizeof ata) && !memcmp(&before_g,&G,sizeof G));
        CHECK(!memcmp(&before_dev,dev_native_observation(),sizeof before_dev) && !memcmp(copy,ram,sizeof ram) && !forbidden);
    }else if(!strcmp(name,"paging")){
        fields[VMCS_GUEST_CR0]|=0x80000000;observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"paging-unsupported"));
    }else if(!strcmp(name,"boundary")){
        fields[VMCS_GUEST_CS_BASE]=UINT64_MAX-1;fields[VMCS_GUEST_RIP]=64;
        fields[VMCS_GUEST_SS_BASE]=0xfffffff0;fields[VMCS_GUEST_RSP]=0;
        observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"linear-overflow") && strstr(serial,"unmapped"));
    }else if(!strcmp(name,"overlay")){
        vga.active=1;vga.aperture_pointer=(void *)(uintptr_t)1;fields[VMCS_GUEST_CS_BASE]=0xa0000;fields[VMCS_GUEST_RIP]=0;
        observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"overlay-unsupported"));
    }else if(!strcmp(name,"aliases")){
        CHECK(output(NULL,0x92,1,0));fields[VMCS_GUEST_CS_BASE]=0x100700;
        observe_at(60,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"code linear=100922 bus=922 bytes=64 90"));
        fields[VMCS_GUEST_CS_BASE]=0xffff0;fields[VMCS_GUEST_RIP]=0;
        observe_at(240,EXIT_PREEMPTION_TIMER);CHECK(strstr(serial,"A20-span-discontinuous"));
    }else if(!strcmp(name,"ivt-rom")){
        ram[0x4c]=0x78;ram[0x4d]=0x56;ram[0x4e]=0x34;ram[0x4f]=0x12;
        fields[VMCS_GUEST_CS_BASE]=0xfffc0000;fields[VMCS_GUEST_RIP]=0;
        observe_at(60,EXIT_PREEMPTION_TIMER);
        CHECK(strstr(serial,"code linear=fffc0000 bus=fffc0000 bytes=64 cc"));
        CHECK(strstr(serial,"ivt=13 linear=4c bus=4c bytes=4 78 56 34 12"));
    }else if(!strcmp(name,"chronology")){
        for(unsigned n=1;n<=100;++n){fixture_now=1000+n;fields[VMCS_GUEST_RIP]=n;win98_observe_exit(w98,EXIT_PREEMPTION_TIMER);}
        observe_at(60,EXIT_HLT);CHECK(strstr(serial,"seq=71 ") && strstr(serial,"seq=102 "));
        CHECK(!strstr(serial,"seq=70 "));
    }else if(!strcmp(name,"budget")){
        observe_at(60,EXIT_PREEMPTION_TIMER);observe_at(240,EXIT_PREEMPTION_TIMER);CHECK(serial_bytes<=W98_OBS_SERIAL_BYTES && occurrences("W98OBS snapshot=")==2);
        for(unsigned n=0;n<1000;++n)observe_at(241+n,EXIT_PREEMPTION_TIMER);CHECK(serial_bytes<=W98_OBS_SERIAL_BYTES);
    }else{fprintf(stderr,"unknown control\n");return 3;}
    CHECK(!forbidden);printf("PASS %s: %u actual observer/helper/device checks; VMCS/time modeled, no guest\n",name,checks);return 0;
}
#endif
