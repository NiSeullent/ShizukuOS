/* SPDX-License-Identifier: GPL-2.0-only
 * Owned synthetic PE image. No Microsoft or application bytes are included.
 */
#include "delay_fixture.h"
void df_put32(uint8_t *p,uint32_t v)
{p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);p[2]=(uint8_t)(v>>16);p[3]=(uint8_t)(v>>24);}
static void put16(uint8_t *p,uint16_t v){p[0]=(uint8_t)v;p[1]=(uint8_t)(v>>8);}
static void string(uint8_t *p,const char *s){while(*s)*p++=(uint8_t)*s++;*p=0;}
void df_build(uint8_t *file,uint8_t *mapped,uint32_t base)
{
 uint32_t i;uint8_t *o=file+0x98,*sections=file+0x178,*data=file+1024;
 for(i=0;i<DF_FILE_BYTES;i++)file[i]=0;for(i=0;i<DF_IMAGE_BYTES;i++)mapped[i]=0;
 file[0]='M';file[1]='Z';df_put32(file+60,0x80);df_put32(file+0x80,0x4550);
 put16(file+0x84,0x14c);put16(file+0x86,2);put16(file+0x94,224);put16(file+0x96,0x102);
 put16(o,0x10b);df_put32(o+16,0x1000);df_put32(o+28,DF_BASE);df_put32(o+32,4096);df_put32(o+36,512);
 put16(o+40,4);put16(o+48,4);put16(o+50,10);df_put32(o+56,DF_IMAGE_BYTES);df_put32(o+60,512);put16(o+68,2);df_put32(o+92,16);
 df_put32(o+96+13*8,DF_DESCRIPTOR);df_put32(o+100+13*8,64);
 string(sections,".text");df_put32(sections+8,512);df_put32(sections+12,0x1000);df_put32(sections+16,512);df_put32(sections+20,512);df_put32(sections+36,0x60000020);
 string(sections+40,".data");df_put32(sections+48,1024);df_put32(sections+52,0x2000);df_put32(sections+56,1024);df_put32(sections+60,1024);df_put32(sections+76,0xc0000040);
 file[512]=0xc3;file[513]=0xc3;file[514]=0xc3;
 df_put32(data,1);df_put32(data+4,0x2160);df_put32(data+8,DF_HANDLE);df_put32(data+12,DF_IAT);df_put32(data+16,0x2120);
 df_put32(data+0x100,DF_BASE+0x1000);df_put32(data+0x104,DF_BASE+0x1001);df_put32(data+0x108,DF_BASE+0x1002);
 df_put32(data+0x120,0x2180);df_put32(data+0x124,0x21a0);df_put32(data+0x128,0x80000007);
 string(data+0x160,"KERNEL32.DLL");string(data+0x182,"GetTickCount");string(data+0x1a2,"lstrlenA");
 for(i=0;i<512;i++)mapped[i]=file[i];for(i=0;i<512;i++)mapped[0x1000+i]=file[512+i];for(i=0;i<1024;i++)mapped[0x2000+i]=file[1024+i];
 df_put32(mapped+DF_IAT,base+0x1000);df_put32(mapped+DF_IAT+4,base+0x1001);df_put32(mapped+DF_IAT+8,base+0x1002);
}
