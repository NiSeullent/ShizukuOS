/* SPDX-License-Identifier: GPL-2.0-only -- host structural/page fault controls. */
#include "win98_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
static void check(int good){checks++;if(!good){fprintf(stderr,"FAIL %u\n",checks);exit(1);}}
static void read_header(const char *path,unsigned char data[4096])
{FILE *f=fopen(path,"rb");check(f!=NULL);check(fread(data,1,4096,f)==4096);check(fclose(f)==0);}
int main(int argc,char **argv)
{
 unsigned char kernel[4096],exe[4096],bad[4096];px_image k,m,changed;px_page code,data,stack;unsigned i;
 static const uint32_t protection[]={0,1,2,4,8,0x10,0x20,0x40,0x80,0x102,0x202,0x402,0xffffffffu};
 check(argc==3);read_header(argv[1],kernel);read_header(argv[2],exe);
 check(px_kernel_image(&k,kernel,4096,0xbff70000u));check(px_main_image(&m,exe,4096,0x400000u));
 check(!px_kernel_image(&changed,exe,4096,0x400000u));check(!px_main_image(&changed,kernel,4096,0xbff70000u));
 /* Exact observed Win98 code metadata, without executing either native file. */
 code=(px_page){0xbff70000u,0xbff8d000u,0x39000u,0x1000u,2u};
 check(px_guard_code(&k,0xbff8d6a1u,&code,1));check(!px_guard_code(&k,0xbff8d6a1u,&code,0));
 for(i=0;i<sizeof(protection)/sizeof(protection[0]);i++){
  code.protection=protection[i];check(px_guard_code(&k,0xbff8d6a1u,&code,1)==(protection[i]==2||protection[i]==0x10||protection[i]==0x20));
  check(px_guard_code(&k,0xbff8d6a1u,&code,0)==(protection[i]==0x10||protection[i]==0x20));
 }
 code=(px_page){0x400000u,0x401000u,0x1000u,0x1000u,2u};data=(px_page){0x400000u,0x402000u,0x1000u,0x1000u,4u};
 check(px_guard_code(&m,0x401003u,&code,1));check(!px_guard_code(&m,0x401003u,&code,0));check(px_guard_data(&m,0x402000u,4,&data));
 for(i=0;i<sizeof(protection)/sizeof(protection[0]);i++){
  data.protection=protection[i];check(px_guard_data(&m,0x402000u,4,&data)==(protection[i]==4||protection[i]==8));
 }
 data.protection=4;
 stack=(px_page){0x530000u,0x73f000u,0x1000u,0x1000u,4u};check(!px_guard_data(&m,0x73fd88u,4,&stack));
 check(!px_guard_data(&m,0x401003u,1,&code));check(!px_guard_code(&m,0x402000u,&data,1));
 code.allocation=0x530000u;check(!px_guard_code(&m,0x401003u,&code,1));code.allocation=m.base;
 code.state=0x2000;check(!px_guard_code(&m,0x401003u,&code,1));code.state=0x1000;
 code.base=0x401004;check(!px_guard_code(&m,0x401003u,&code,1));code.base=0x401000;
 code.bytes=3;check(!px_guard_code(&m,0x401003u,&code,1));code.bytes=0x1000;
 data.bytes=3;check(!px_guard_data(&m,0x402000u,4,&data));data.bytes=0x1000;
 data.base=0x402001;check(!px_guard_data(&m,0x402000u,4,&data));data.base=0x402000;
 check(!px_guard_data(&m,0x402000u,0,&data));check(!px_guard_data(&m,0x402000u,SIZE_MAX,&data));
 changed=m;changed.sections[0].flags|=0x80000000;check(!px_guard_code(&changed,0x401003u,&code,1));
 changed=m;changed.sections[0].flags|=0x02000000;check(!px_guard_code(&changed,0x401003u,&code,1));
 changed=m;changed.sections[0].flags&=~0x20000000u;check(!px_guard_code(&changed,0x401003u,&code,1));
 changed=m;changed.sections[0].flags&=~0x40000000u;check(!px_guard_code(&changed,0x401003u,&code,1));
 changed=m;changed.sections[1].flags|=0x02000000;check(!px_guard_data(&changed,0x402000u,4,&data));
 changed=m;changed.sections[1].flags|=0x20000000;check(!px_guard_data(&changed,0x402000u,4,&data));
 check(!px_kernel_image(&changed,kernel,63,0xbff70000u));check(!px_kernel_image(&changed,kernel,4096,0));
 memcpy(bad,kernel,4096);bad[0]=0;check(!px_kernel_image(&changed,bad,4096,0xbff70000u));
 memcpy(bad,kernel,4096);memset(bad+60,255,4);check(!px_kernel_image(&changed,bad,4096,0xbff70000u));
 check(!px_kernel_image(&changed,kernel,4096,UINTPTR_MAX-100));
 printf("PASS %u Win98 PE/page ownership fault checks; native_executed=false\n",checks);return 0;
}
