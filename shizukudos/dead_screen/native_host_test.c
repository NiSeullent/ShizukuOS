/* SPDX-License-Identifier: GPL-2.0-only
 * Real native.c calls, privileged I/O/CLI/HLT replaced only in host build.
 * This proves branch/control semantics, never guest hardware acceptance.
 */
#include "native.h"
#include "../kernel64/k64.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static jmp_buf stop;
static unsigned checks,iterations,halted,serial_count,port_reads;
static const char *mode;
static char output[4096];static size_t output_len;
static uint32_t pixels[640*480];
static const ds_state *last;
static ds_fault original;
static uint8_t gate;
static uint16_t pitch=1810;
static unsigned sample,pitch_phase,poll_count;
static uint32_t model_cpu;
static unsigned secondary_port_reads;
static size_t secondary_output_len;
static uint32_t secondary_pixels;
static uint32_t initial_pixels;
uint32_t sched_cpu_identity(void){return model_cpu;}
static int nyan_mode(void){return !strncmp(mode,"nyan-",5);}
int ds_pcm_panic_begin(void){return !strcmp(mode,"nyan-pcm")||!strcmp(mode,"nyan-degrade")?0:-1;}
int ds_pcm_panic_poll(void){return !strcmp(mode,"nyan-degrade") && ++poll_count>=2 ? -1:0;}
void ds_pcm_panic_stop(void){ }
#define CHECK(c) do{++checks;if(!(c)){fprintf(stderr,"FAIL native host %s line %u: %s\n",mode,__LINE__,#c);exit(1);}}while(0)
uint64_t ds_test_cr2(void){return 0xdeadbeef;}
uint64_t ds_test_cr3(void){return 0x1000;}
uint64_t ds_test_flags(void){return 0x46;}
void ds_test_halt(void){halted=1;longjmp(stop,1);}
static uint32_t pixel_digest(void)
{
    uint32_t hash=2166136261u;
    for(size_t i=0;i<sizeof pixels/sizeof pixels[0];++i)hash=(hash^pixels[i])*16777619u;
    return hash;
}
uint8_t ds_test_inb(uint16_t p)
{
    ++port_reads;
    if(p==0x3fd)return !strcmp(mode,"uartfail")?0:0x21;
    if(p==0x3f8){++serial_count;return serial_count==1?'1':serial_count==2?' ':serial_count==62?'2':'?';}
    if(p==0x64)return 0; /* no unconfigured keyboard device is invented */
    if(p==0x40){static unsigned hi;const uint16_t count=(uint16_t)(1193-(iterations*500)%1193);
        unsigned b=hi?count>>8:count&255;hi^=1;return (uint8_t)b;}
    if(p==0x61){
        if(!strcmp(mode,"nyan-fixed-loss") && iterations)return 0xff;
        return nyan_mode() && strcmp(mode,"nyan-silent") ? (uint8_t)(gate|((++sample&1)<<5)):0;
    }
    if(p==0x42){unsigned high=pitch_phase++&1;return (uint8_t)(high?(pitch-1)>>8:(pitch-1)&255);}
    return 0;
}
void ds_test_outb(uint16_t p,uint8_t v)
{
    if(p==0x61 && nyan_mode())gate=v&3;
    if(p==0x43 && (v==0xb6 || v==0x80))pitch_phase=0;
    if(p==0x42){if(!(pitch_phase++&1))pitch=v;else pitch|=(uint16_t)v<<8;}
    if(p==0x3f8 && halted==0 && (v<128) && (v>=10)){
        CHECK(output_len+1<sizeof output);output[output_len++]=(char)v;output[output_len]=0;
    }
}
void ds_test_iteration(const ds_state *s)
{
    last=s;++iterations;
    if(nyan_mode()) {
        if(iterations==1)original=s->fault;
        CHECK(s->latched && s->mode==DS_MENU && !memcmp(&original,&s->fault,sizeof original));
        if(iterations==4)longjmp(stop,1);
        return;
    }
    if(iterations==1){original=s->fault;CHECK(s->mode==DS_TETRIS);}
    CHECK(!memcmp(&original,&s->fault,sizeof original));
    CHECK(!s->graphics_failed);
    if(!strcmp(mode,"cross-cpu-reentry")) {
        secondary_port_reads=port_reads;secondary_output_len=output_len;secondary_pixels=pixel_digest();
        model_cpu=1;
        struct regs second={0};second.rip=7;second.vector=8;
        ds_native_exception(&second);
    }
    if(!strcmp(mode,"reentry")) {
        struct regs second={0};second.rip=7;second.vector=8;
        ds_native_exception(&second);
    }
    if(!strcmp(mode,"corrupt-game")) {
        ((ds_state *)s)->tetris.piece=99; /* next actual input/renderer must fall back */
    }
    if(iterations>=100){CHECK(s->mode==DS_SUIKA);CHECK(s->ticks>=2);longjmp(stop,1);}
}
int main(int argc,char **argv)
{
    if(argc!=2)return 2;
    mode=argv[1];ds_native_init();
    if(strcmp(mode,"fallback") && strcmp(mode,"uartfail"))ds_native_bind(pixels,640,480,2560,sizeof pixels,0);
    if(!strcmp(mode,"small"))ds_native_bind(pixels,320,200,1280,sizeof pixels,0);
    if(!strcmp(mode,"force-text"))ds_native_force_text();
    if(nyan_mode())ds_native_force_nyan(!strcmp(mode,"nyan-silent")?0:!strcmp(mode,"nyan-fixed")||!strcmp(mode,"nyan-fixed-loss")?1:!strcmp(mode,"nyan-pitched")?2:3);
    ds_native_context(0,400,404);
    ds_native_timer_ready();
    initial_pixels=pixel_digest();
    if(!strcmp(mode,"other-cpu-first"))model_cpu=1;
    if(!strcmp(mode,"unknown-cpu"))model_cpu=UINT32_MAX;
    if(!setjmp(stop)) {
        if(!strcmp(mode,"capture-exception")) {
            ds_native_capture_begin();ds_native_capture_char('A');
            struct regs second={0};second.rip=7;second.vector=8;
            ds_native_exception(&second);
        }
        if(!strcmp(mode,"capture-other-cpu")) {
            ds_native_capture_begin();ds_native_capture_char('A');
            model_cpu=1;ds_native_capture_char('B');
            model_cpu=0;ds_native_panic(0x12345678,0x87654321,0x98765432);
        }
        if(!strcmp(mode,"panic")) {
            ds_native_capture_begin();for(unsigned i=0;i<300;++i)ds_native_capture_char((char)('A'+i%26));
            ds_native_panic(0x12345678,0x87654321,0x98765432);
        }
        struct regs r={0};r.rip=0x123456789; r.rsp=0xabcdef; r.rbp=0xbcdef;
        r.vector=14;r.error=3;r.cs=8;r.rflags=0x246;r.rax=91;r.r15=92;
        ds_native_exception(&r);
    }
    if(nyan_mode()) {
        CHECK(strstr(output,"Your computer was trashed."));
        if(!strcmp(mode,"nyan-silent"))CHECK(halted && !iterations && strstr(output,"No verified audio output"));
        else if(!strcmp(mode,"nyan-fixed-loss")) {
            CHECK(halted && iterations==1 && last && last->latched);
            CHECK(strstr(output,"Fixed tone gate only"));
            CHECK(strstr(output,"No verified audio output"));
            CHECK(!memcmp(&original,&last->fault,sizeof original));
        }
        else {
            CHECK(iterations==4 && !halted);
            CHECK(strstr(output,!strcmp(mode,"nyan-fixed")?"Fixed tone gate only":!strcmp(mode,"nyan-pitched")?"PIT pitched beep":"PCM DMA progressing"));
            if(!strcmp(mode,"nyan-degrade"))CHECK(strstr(output,"PIT pitched beep"));
        }
    } else if(!strcmp(mode,"unknown-cpu") || !strcmp(mode,"capture-exception")) {
        CHECK(halted && !iterations && !last);
        CHECK(!port_reads && !output_len && pixel_digest()==initial_pixels);
    } else if(!strcmp(mode,"fallback") || !strcmp(mode,"uartfail") || !strcmp(mode,"small") || !strcmp(mode,"force-text")) {
        CHECK(halted && !iterations);
        if(strcmp(mode,"uartfail")){CHECK(strstr(output,"Your computer was trashed.\nEnglish traceback:"));
            CHECK(strstr(output,"IP=0x0000000123456789"));CHECK(strstr(output,"CR2=0x00000000deadbeef"));}
        else {CHECK(port_reads>=1000000 && port_reads<=1120050);CHECK(!strstr(output,"English traceback:"));}
        if(!strcmp(mode,"small") || !strcmp(mode,"force-text")) {
            unsigned nonzero=0;for(unsigned i=0;i<640*480;++i)nonzero+=pixels[i]!=0;CHECK(nonzero>100);
        }
    } else {
        CHECK(last && last->latched);
        if(!strcmp(mode,"panic") || !strcmp(mode,"capture-other-cpu")){
            CHECK(!strcmp(mode,"panic")?strlen(last->fault.reason)==159:!strcmp(last->fault.reason,"A"));
            CHECK(!last->fault.registers_valid);
            CHECK(last->fault.ip==0x12345678 && last->fault.sp==0x87654321 && last->fault.flags==0x46);}
        else {CHECK(last->fault.ip==0x123456789 && last->fault.registers_valid);
            CHECK(last->fault.reg[0]==91 && last->fault.reg[14]==92 && last->fault.reg[15]==8);}
        CHECK(last->fault.cr2==0xdeadbeef && last->fault.cr3==0x1000);
        if(!strcmp(mode,"other-cpu-first"))CHECK(last->fault.cpu==1 && !last->fault.context_valid && !last->fault.pid && !last->fault.tid);
        else CHECK(last->fault.cpu==0 && last->fault.context_valid && last->fault.pid==400 && last->fault.tid==404);
        if(!strcmp(mode,"reentry") || !strcmp(mode,"corrupt-game")){CHECK(halted && iterations==1);CHECK(strstr(output,"Your computer was trashed."));
            CHECK(!memcmp(&original,&last->fault,sizeof original));}
        else if(!strcmp(mode,"cross-cpu-reentry")) {
            CHECK(halted && iterations==1 && !strstr(output,"Your computer was trashed."));
            CHECK(!memcmp(&original,&last->fault,sizeof original));
            CHECK(port_reads==secondary_port_reads && output_len==secondary_output_len && pixel_digest()==secondary_pixels);
        }
        else CHECK(!halted && iterations==100);
    }
    printf("{\"status\":\"PASS\",\"mode\":\"%s\",\"checks\":%u,\"native_execution\":false}\n",mode,checks);
    return 0;
}
