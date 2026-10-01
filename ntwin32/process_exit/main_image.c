/* SPDX-License-Identifier: GPL-2.0-only */
#include "main_image.h"
static uint16_t u16(const unsigned char *p){return (uint16_t)(p[0]|p[1]<<8);}
static uint32_t u32(const unsigned char *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int range(size_t n,size_t start,size_t bytes){return start<=n&&bytes<=n-start;}
int px_main_image(px_image *out,const void *memory,size_t available,uintptr_t base)
{
 const unsigned char *p=memory;px_image image;uint32_t nt,opt,table,size,headers,i,j;uint16_t count;
 if(!out||!p||!base||!range(available,0,64)||u16(p)!=0x5a4d)return 0;
 nt=u32(p+60);if(nt<64||!range(available,nt,24)||u32(p+nt)!=0x4550||u16(p+nt+4)!=0x14c||(u16(p+nt+22)&0x2000))return 0;
 count=u16(p+nt+6);opt=nt+24;
 if(!count||count>PX_SECTIONS||u16(p+nt+20)<96||!range(available,opt,u16(p+nt+20))||u16(p+opt)!=0x10b)return 0;
 size=u32(p+opt+56);headers=u32(p+opt+60);table=opt+u16(p+nt+20);
 if(size<headers||size>256u*1024u*1024u||!headers||headers>available||base>UINTPTR_MAX-size||!range(headers,table,count*40u))return 0;
 image.base=base;image.bytes=size;image.count=count;
 for(i=0;i<count;i++){
  const unsigned char *s=p+table+40*i;px_section *d=&image.sections[i];
  d->start=u32(s+12);d->bytes=u32(s+8);d->flags=u32(s+36);
  if(!d->bytes||d->start<headers||d->start>size||d->bytes>size-d->start)return 0;
  for(j=0;j<i;j++)if(d->start<image.sections[j].start+image.sections[j].bytes&&image.sections[j].start<d->start+d->bytes)return 0;
 }
 *out=image;return 1;
}
int px_main_callback(const px_image *m,uintptr_t code,uintptr_t context,size_t bytes)
{
 uint32_t i;int have_code=0,have_data=0;
 if(!m||!bytes||code<m->base||context<m->base||code-m->base>=m->bytes||context-m->base>=m->bytes||bytes>m->bytes-(context-m->base))return 0;
 for(i=0;i<m->count;i++){
  const px_section *s=&m->sections[i];uintptr_t c=code-m->base,d=context-m->base;
  if(c>=s->start&&c-s->start<s->bytes&&(s->flags&0x20000000u)&&!(s->flags&(0x80000000u|0x02000000u)))have_code=1;
  if(d>=s->start&&d-s->start<s->bytes&&bytes<=s->bytes-(d-s->start)&&(s->flags&0x80000000u)&&!(s->flags&(0x20000000u|0x02000000u)))have_data=1;
 }
 return have_code&&have_data;
}
