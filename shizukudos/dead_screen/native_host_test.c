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
#define CHECK(c) do{++checks;if(!(c)){fprintf(stderr,"FAIL native host %s line %u: %s\n",mode,__LINE__,#c);exit(1);}}while(0)
uint64_t ds_test_cr2(void){return 0xdeadbeef;}
uint64_t ds_test_cr3(void){return 0x1000;}
uint64_t ds_test_flags(void){return 0x46;}
void ds_test_halt(void){halted=1;longjmp(stop,1);}
uint8_t ds_test_inb(uint16_t p)
{
    ++port_reads;
    if(p==0x3fd)return !strcmp(mode,"uartfail")?0:0x21;
    if(p==0x3f8){++serial_count;return serial_count==1?'1':serial_count==2?' ':serial_count==62?'2':'?';}
    if(p==0x64)return 0; /* no unconfigured keyboard device is invented */
    if(p==0x40){static unsigned hi;const uint16_t count=(uint16_t)(1193-(iterations*500)%1193);
        unsigned b=hi?count>>8:count&255;hi^=1;return (uint8_t)b;}
    return 0;
}
void ds_test_outb(uint16_t p,uint8_t v)
{
    if(p==0x3f8 && halted==0 && (v<128) && (v>=10)){
        CHECK(output_len+1<sizeof output);output[output_len++]=(char)v;output[output_len]=0;
    }
}
void ds_test_iteration(const ds_state *s)
{
    last=s;++iterations;
    if(iterations==1){original=s->fault;CHECK(s->mode==DS_TETRIS);}
    CHECK(!memcmp(&original,&s->fault,sizeof original));
    CHECK(!s->graphics_failed);
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
    ds_native_timer_ready();
    if(!setjmp(stop)) {
        if(!strcmp(mode,"panic")) {
            ds_native_capture_begin();for(unsigned i=0;i<300;++i)ds_native_capture_char((char)('A'+i%26));
            ds_native_panic(0x12345678,0x87654321,0x98765432);
        }
        struct regs r={0};r.rip=0x123456789; r.rsp=0xabcdef; r.rbp=0xbcdef;
        r.vector=14;r.error=3;r.cs=8;r.rflags=0x246;r.rax=91;r.r15=92;
        ds_native_exception(&r);
    }
    if(!strcmp(mode,"fallback") || !strcmp(mode,"uartfail") || !strcmp(mode,"small") || !strcmp(mode,"force-text")) {
        CHECK(halted && !iterations);
        if(strcmp(mode,"uartfail")){CHECK(strstr(output,"You session got wasted\nEnglish traceback:"));
            CHECK(strstr(output,"IP=0x0000000123456789"));CHECK(strstr(output,"CR2=0x00000000deadbeef"));}
        else {CHECK(port_reads>=1000000 && port_reads<=1000010);CHECK(!strstr(output,"English traceback:"));}
        if(!strcmp(mode,"small") || !strcmp(mode,"force-text")) {
            unsigned nonzero=0;for(unsigned i=0;i<640*480;++i)nonzero+=pixels[i]!=0;CHECK(nonzero>100);
        }
    } else {
        CHECK(last && last->latched);
        if(!strcmp(mode,"panic")){CHECK(strlen(last->fault.reason)==159);CHECK(!last->fault.registers_valid);
            CHECK(last->fault.ip==0x12345678 && last->fault.sp==0x87654321 && last->fault.flags==0x46);}
        else {CHECK(last->fault.ip==0x123456789 && last->fault.registers_valid);
            CHECK(last->fault.reg[0]==91 && last->fault.reg[14]==92 && last->fault.reg[15]==8);}
        CHECK(last->fault.cr2==0xdeadbeef && last->fault.cr3==0x1000);
        if(!strcmp(mode,"reentry") || !strcmp(mode,"corrupt-game")){CHECK(halted && iterations==1);CHECK(strstr(output,"You session got wasted"));
            CHECK(!memcmp(&original,&last->fault,sizeof original));}
        else CHECK(!halted && iterations==100);
    }
    printf("{\"status\":\"PASS\",\"mode\":\"%s\",\"checks\":%u,\"native_execution\":false}\n",mode,checks);
    return 0;
}
