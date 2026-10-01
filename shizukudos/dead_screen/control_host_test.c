/* SPDX-License-Identifier: GPL-2.0-only */
#include "native.h"
#include "../kernel64/k64.h"
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static jmp_buf stopped;
static unsigned selected,prepared,forced,panicked,ud,checks;
#define CHECK(c) do{++checks;if(!(c)){fprintf(stderr,"control failure %u: %s\n",__LINE__,#c);exit(1);}}while(0)
int k64_cmdline_has(const char *s)
{
    return (selected==1 && !strcmp(s,"shz.dead-screen-panic-control")) ||
           (selected==2 && !strcmp(s,"shz.dead-screen-ud-control")) ||
           (selected==3 && !strcmp(s,"shz.dead-screen-text-control"));
}
int ds_native_control_prepare_gui(void){++prepared;return 0;}
void ds_native_force_text(void){CHECK(prepared==1);++forced;}
void kprintf(const char *fmt,...){CHECK(strstr(fmt,"DEAD SCREEN CONTROL:"));}
void kpanic(const char *fmt,...){CHECK(strstr(fmt,"not a Win98/VMM fault"));++panicked;longjmp(stopped,1);}
void ds_test_ud(void){CHECK(prepared==1 && !forced);++ud;longjmp(stopped,1);}
int main(void)
{
    for(selected=0;selected<4;++selected){prepared=forced=panicked=ud=0;
        if(!setjmp(stopped))ds_native_control();
        if(!selected){CHECK(!prepared && !forced && !panicked && !ud);}
        else {CHECK(prepared==1);CHECK(forced==(selected==3));CHECK(ud==(selected==2));CHECK(panicked==(selected!=2));}
    }
    printf("{\"status\":\"PASS\",\"cases\":4,\"checks\":%u,\"native_execution\":false}\n",checks);
    return 0;
}
