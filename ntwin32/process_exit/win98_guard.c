/* SPDX-License-Identifier: GPL-2.0-only
 * Win98 native evidence: committed executable PE sections report PAGE_READONLY.
 * PE execution/ownership and page immutability are independent requirements.
 */
#include "win98_guard.h"
static uint16_t u16(const unsigned char *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int range(size_t n,size_t at,size_t bytes){return at<=n&&bytes<=n-at;}
int px_kernel_image(px_image *out,const void *memory,size_t available,uintptr_t base)
{
 const unsigned char *p=memory;px_image image;uint32_t nt,opt,table,size,headers,i,j;uint16_t count;
 if(!out||!p||!base||!range(available,0,64)||u16(p)!=0x5a4d)return 0;
 nt=u32(p+60);if(nt<64||!range(available,nt,24)||u32(p+nt)!=0x4550||u16(p+nt+4)!=0x14c||!(u16(p+nt+22)&0x2000))return 0;
 count=u16(p+nt+6);opt=nt+24;
 if(!count||count>PX_SECTIONS||u16(p+nt+20)<96||!range(available,opt,u16(p+nt+20))||u16(p+opt)!=0x10b)return 0;
 size=u32(p+opt+56);headers=u32(p+opt+60);table=opt+u16(p+nt+20);
 if(size<headers||size>16u*1024u*1024u||!headers||headers>available||base>UINTPTR_MAX-size||!range(headers,table,count*40u))return 0;
 image.base=base;image.bytes=size;image.count=count;
 for(i=0;i<count;i++){
  const unsigned char *s=p+table+40*i;px_section *d=&image.sections[i];
  d->start=u32(s+12);d->bytes=u32(s+8);d->flags=u32(s+36);
  if(!d->bytes||d->start<headers||d->start>size||d->bytes>size-d->start)return 0;
  for(j=0;j<i;j++)if(d->start<image.sections[j].start+image.sections[j].bytes&&image.sections[j].start<d->start+d->bytes)return 0;
 }
 *out=image;return 1;
}
static int owned(const px_image *image,uintptr_t address,size_t bytes,const px_page *page)
{
 return image&&page&&bytes&&address>=image->base&&address-image->base<image->bytes&&bytes<=image->bytes-(address-image->base)&&
  page->allocation==image->base&&page->state==0x1000u&&address>=page->base&&address-page->base<page->bytes&&bytes<=page->bytes-(address-page->base);
}
int px_guard_code(const px_image *image,uintptr_t address,const px_page *page,int verified_win98)
{
 uint32_t i;if(!owned(image,address,1,page))return 0;
 /* Exact protection values reject modifiers, guard/noaccess, unknown bits and
  * every writable code page. READONLY is exclusive to proven Win98 callers. */
 if(page->protection!=0x10u&&page->protection!=0x20u&&!(verified_win98&&page->protection==2u))return 0;
 for(i=0;i<image->count;i++){
  const px_section *s=&image->sections[i];uintptr_t rva=address-image->base;
  if(rva>=s->start&&rva-s->start<s->bytes&&(s->flags&0x60000000u)==0x60000000u&&!(s->flags&0x82000000u))return 1;
 }return 0;
}
int px_guard_data(const px_image *image,uintptr_t address,size_t bytes,const px_page *page)
{
 uint32_t i;if(!owned(image,address,bytes,page)||(page->protection!=4u&&page->protection!=8u))return 0;
 for(i=0;i<image->count;i++){
  const px_section *s=&image->sections[i];uintptr_t rva=address-image->base;
  if(rva>=s->start&&rva-s->start<s->bytes&&bytes<=s->bytes-(rva-s->start)&&(s->flags&0x80000000u)&&!(s->flags&0x22000000u))return 1;
 }return 0;
}
