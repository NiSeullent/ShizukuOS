/* SPDX-License-Identifier: GPL-2.0-only -- loaded EAT identity fault controls. */
#include "win98_export.h"
#include "win98_guard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;static unsigned char memory[0x73000],original[0x73000];
typedef struct context {px_image image;int deny;} context;
static void check(int good){checks++;if(!good){fprintf(stderr,"FAIL %u\n",checks);exit(1);}}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static void put(unsigned char *p,uint32_t n){unsigned i;for(i=0;i<4;i++)p[i]=(unsigned char)(n>>(i*8));}
static const unsigned char *read_image(void *opaque,uintptr_t at,size_t n)
{
 context *c=opaque;if(c->deny||at<c->image.base||at-c->image.base>sizeof(memory)||n>sizeof(memory)-(at-c->image.base))return NULL;
 return memory+(at-c->image.base);
}
int main(int argc,char **argv)
{
 FILE *file;context c;uintptr_t address;uint32_t opt,rva,functions,names,orders;unsigned i;
 check(argc==2);file=fopen(argv[1],"rb");check(file!=NULL);check(fread(memory,1,sizeof(memory),file)==sizeof(memory));check(fgetc(file)==EOF);check(fclose(file)==0);
 memcpy(original,memory,sizeof(memory));check(px_kernel_image(&c.image,memory,4096,0xbff70000u));c.deny=0;
 opt=u32(memory+60)+24;rva=u32(memory+opt+96);functions=u32(memory+rva+28);names=u32(memory+rva+32);orders=u32(memory+rva+36);
 check(px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address)&&address==0xbff917aau);
 check(px_named_export(&c.image,memory,4096,"ExitProcess",read_image,&c,&address)&&address==0xbff8d6a1u);
 check(address!=0xbff917aau); /* same-module wrong export cannot bootstrap */
 check(!px_named_export(&c.image,memory,4096,"NoSuchOEMExport",read_image,&c,&address));
 check(!px_named_export(&c.image,memory,4096,"",read_image,&c,&address));
 check(!px_named_export(&c.image,memory,4096,NULL,read_image,&c,&address));
 check(!px_named_export(&c.image,memory,4096,"GetVersionExA",NULL,&c,&address));
 check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,NULL));
 c.deny=1;check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));c.deny=0;
 for(i=0;i<104;i++)check(!px_named_export(&c.image,memory,i,"GetVersionExA",read_image,&c,&address));
 memory[0]=0;check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 for(i=20;i<=36;i+=4){
  put(memory+rva+i,0xffffffffu);check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 }
 put(memory+rva+20,0);check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 put(memory+rva+24,0);check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 put(memory+names,sizeof(memory));check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 memory[orders]=255;memory[orders+1]=255;check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 /* Replace every target with a forwarder RVA: version identity is refused. */
 for(i=0;i<u32(memory+rva+20);i++)put(memory+functions+i*4,rva);
 check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));memcpy(memory,original,sizeof(memory));
 put(memory+opt+56,sizeof(memory)-4096);check(!px_named_export(&c.image,memory,4096,"GetVersionExA",read_image,&c,&address));
 printf("PASS %u loaded named-export identity fault checks; native_executed=false\n",checks);return 0;
}
