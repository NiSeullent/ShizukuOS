/* SPDX-License-Identifier: GPL-2.0-only -- bounded loaded-image export identity.
 * Every indirect read uses the supplied committed native ownership reader.
 */
#include "win98_export.h"
static uint16_t u16(const unsigned char *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int range(size_t n,size_t at,size_t bytes){return at<=n&&bytes<=n-at;}
static const unsigned char *read_rva(const px_image *image,uint32_t rva,size_t bytes,px_read_image read,void *opaque)
{if(!range(image->bytes,rva,bytes))return NULL;return read(opaque,image->base+rva,bytes);}
int px_named_export(const px_image *image,const void *header,size_t available,const char *name,
                    px_read_image read,void *opaque,uintptr_t *address)
{
 const unsigned char *h=header,*d,*names,*orders,*functions;uint32_t nt,opt,rva,bytes,nf,nn,i,found=0;size_t length=0;
 if(address)*address=0;if(!image||!h||!name||!read||!address||!range(available,0,64)||u16(h)!=0x5a4d)return 0;
 while(name[length]){if(length==127)return 0;length++;}if(!length)return 0;
 nt=u32(h+60);if(!range(available,nt,24)||u32(h+nt)!=0x4550||u16(h+nt+4)!=0x14c)return 0;opt=nt+24;
 if(u16(h+nt+20)<104||!range(available,opt,u16(h+nt+20))||u16(h+opt)!=0x10b||u32(h+opt+92)<1||u32(h+opt+56)!=image->bytes)return 0;
 rva=u32(h+opt+96);bytes=u32(h+opt+100);if(!rva||bytes<40||!range(image->bytes,rva,bytes)||(d=read_rva(image,rva,40,read,opaque))==NULL)return 0;
 nf=u32(d+20);nn=u32(d+24);if(!nf||nf>4096||!nn||nn>nf)return 0;
 functions=read_rva(image,u32(d+28),nf*4u,read,opaque);names=read_rva(image,u32(d+32),nn*4u,read,opaque);orders=read_rva(image,u32(d+36),nn*2u,read,opaque);
 if(!functions||!names||!orders)return 0;
 for(i=0;i<nn;i++){
  const unsigned char *s;uint32_t name_rva=u32(names+i*4u),target;uint16_t index=u16(orders+i*2u);size_t j;
  if(index>=nf||(s=read_rva(image,name_rva,length+1,read,opaque))==NULL)return 0;
  for(j=0;j<length&&s[j]==(unsigned char)name[j];j++){}
  if(j!=length||s[length])continue;
  target=u32(functions+index*4u);if(found++||!target||target>=image->bytes||(target>=rva&&target-rva<bytes))return 0;
  *address=image->base+target;
 }
 return found==1;
}
