/* SPDX-License-Identifier: GPL-2.0-only -- independent raw/bounds controls. */
#include "snapshot.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks,cases;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);exit(1);}} while(0)
static void flags(void)
{
 mp_status m={32,50,0x80000000u,0x40000000u,0xf0000000u,0x70000000u,0x80000000u,0x12345678u},copy=m;
 cases++;CHECK(mp_flags(&m)==0);CHECK(memcmp(&copy,&m,sizeof(m))==0);
 cases++;m.length=31;CHECK(mp_flags(&m)==MP_BAD_LENGTH);m.length=32;m.load=101;CHECK(mp_flags(&m)==MP_BAD_LOAD);m.load=100;CHECK(mp_flags(&m)==0);
 cases++;m.avail_phys=m.total_phys+1;CHECK(mp_flags(&m)==MP_PHYS_RELATION);m=copy;m.avail_page=m.total_page+1;CHECK(mp_flags(&m)==MP_PAGE_RELATION);m=copy;m.avail_virtual=m.total_virtual+1;CHECK(mp_flags(&m)==MP_VIRTUAL_RELATION);
 cases++;m=copy;m.total_phys=UINT32_MAX;CHECK(mp_flags(&m)==MP_DWORD_MAX);m.avail_phys=UINT32_MAX;CHECK(mp_flags(&m)==MP_DWORD_MAX);m.total_page=0;m.avail_page=UINT32_MAX;CHECK(mp_flags(&m)==(MP_PAGE_RELATION|MP_DWORD_MAX));
 cases++;memset(&m,0,sizeof(m));m.length=32;CHECK(mp_flags(&m)==0);CHECK(mp_flags(NULL)==MP_BAD_LENGTH);
 cases++;CHECK(mp_tick_delta(UINT32_MAX-4,3)==8);CHECK(mp_tick_delta(0,UINT32_MAX)==UINT32_MAX);CHECK(mp_tick_delta(55,55)==0);
}
static void formatting(void)
{
 struct {unsigned char before;char out[64];unsigned char after;} b;char old[64],name[49];size_t n;unsigned i;
 memset(&b,0xa5,sizeof(b));memcpy(old,b.out,64);
 cases++;n=mp_line(b.out,64,"RAW_0",UINT32_MAX);CHECK(n==16);CHECK(memcmp(b.out,"RAW_0=FFFFFFFF\r\n",16)==0);CHECK(b.before==0xa5&&b.after==0xa5);CHECK((unsigned char)b.out[16]==0xa5);
 cases++;for(i=0;i<16;i++){memcpy(b.out,old,64);CHECK(mp_line(b.out,i,"RAW_0",UINT32_MAX)==0);CHECK(memcmp(b.out,old,64)==0);CHECK(b.before==0xa5&&b.after==0xa5);}
 cases++;memcpy(b.out,old,64);CHECK(mp_line(b.out,64,"",0)==0);CHECK(mp_line(b.out,64,"BAD=KEY",0)==0);CHECK(mp_line(b.out,64,"low",0)==0);CHECK(mp_line(b.out,64,NULL,0)==0);CHECK(mp_line(NULL,64,"VALID",0)==0);CHECK(memcmp(b.out,old,64)==0);
 cases++;memset(name,'Z',48);name[48]=0;CHECK(mp_line(b.out,64,name,0)==0);CHECK(memcmp(b.out,old,64)==0);name[47]=0;CHECK(mp_line(b.out,58,name,0)==58);CHECK(b.before==0xa5&&b.after==0xa5);
 cases++;n=mp_line(b.out,64,"ZERO",0);CHECK(n==15&&memcmp(b.out,"ZERO=00000000\r\n",15)==0);n=mp_line(b.out,64,"VALUE",0x1234abcd);CHECK(n==16&&memcmp(b.out,"VALUE=1234ABCD\r\n",16)==0);
}
int main(void){flags();formatting();printf("RESULT PASS cases=%u checks=%u native_pending=true application_success=false\n",cases,checks);return 0;}
