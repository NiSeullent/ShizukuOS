/* SPDX-License-Identifier: GPL-2.0-only
 * File-backed PE32 validation, shared by the real native loader and host tests.
 * Bounds are checked before every indirect read; this file executes no code.
 */
#include "pe.h"
uint16_t np_u16(const uint8_t *p){return (uint16_t)(p[0]|((uint16_t)p[1]<<8));}
uint32_t np_u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static int range(uint32_t at,uint32_t n,uint32_t limit){return at<=limit&&n<=limit-at;}
static int fail(const char **e,const char *s){if(e)*e=s;return 0;}
static int power(uint32_t x){return x&&!(x&(x-1));}
static int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
const uint8_t *np_raw(const np_image *p,uint32_t at,uint32_t n)
{
 unsigned i;if(range(at,n,p->headers))return p->file+at;
 for(i=0;i<p->sections;i++){const np_section *s=&p->section[i];
  if(at>=s->va&&range(at-s->va,n,s->bytes))return p->file+s->raw+at-s->va;
 }return 0;
}
int np_memory(const np_image *p,uint32_t at,uint32_t n,int kind)
{
 unsigned i;for(i=0;i<p->sections;i++){const np_section *s=&p->section[i];
  if(at>=s->va&&range(at-s->va,n,s->span)){
   if(kind==1)return !!(s->flags&0x20000000u);
   if(kind==2)return (s->flags&0x40000000u)&&!(s->flags&0x20000000u);
   if(kind==3)return (s->flags&0x80000000u)&&!(s->flags&0x20000000u);
   return 1;
  }
 }return 0;
}
static const char *string(const np_image *p,uint32_t rva,uint32_t limit)
{
 const uint8_t *first=np_raw(p,rva,1);uint32_t n;if(!first)return 0;
 for(n=0;n<limit;n++){const uint8_t *q;if(rva>0xffffffffu-n)return 0;
  q=np_raw(p,rva+n,1);if(!q||q!=first+n)return 0;
  if(!*q)return (const char *)first;
  if(*q<32||*q>126)return 0;
 }return 0;
}
static int module_name(const char *s)
{
 unsigned n;if(!s||!*s)return 0;for(n=0;s[n];n++){
  unsigned c=(unsigned char)s[n];if(n>=127||c=='/'||c=='\\'||c==':'||c=='"'||c=='*'||c=='?'||c==' '||(c=='.'&&s[n+1]=='.'))return 0;
 }return 1;
}
static int parse_bounds(np_image *p,const void *data,uint32_t length,
                        uint32_t file_limit,uint32_t image_limit,const char **error)
{
 const uint8_t *f=data,*o;uint32_t pe,opt,table,filealign,dirs,i,j;uint16_t os;
 if(error)*error=0;
 if(!p||!f||length<64||length>file_limit)return fail(error,"FILE_SIZE");
 if(f[0]!='M'||f[1]!='Z')return fail(error,"DOS_MAGIC");
 pe=np_u32(f+60);if(pe<64||!range(pe,24,length)||np_u32(f+pe)!=0x4550)return fail(error,"PE_HEADER");
 if(np_u16(f+pe+4)!=0x14c)return fail(error,"MACHINE_I386");
 p->sections=np_u16(f+pe+6);os=np_u16(f+pe+20);p->characteristics=np_u16(f+pe+22);
 if(!(p->characteristics&2)||!p->sections||p->sections>NP_SECTIONS)return fail(error,"COFF_IMAGE");
 opt=pe+24;if(os<96||!range(opt,os,length))return fail(error,"OPTIONAL_HEADER");o=f+opt;
 if(np_u16(o)!=0x10b)return fail(error,"PE32_MAGIC");
 dirs=np_u32(o+92);if(dirs>16||dirs>(os-96u)/8u)return fail(error,"DIRECTORY_COUNT");
 p->file=f;p->bytes=length;p->base=np_u32(o+28);p->size=np_u32(o+56);p->headers=np_u32(o+60);
 p->entry=np_u32(o+16);p->section_align=np_u32(o+32);filealign=np_u32(o+36);
 p->subsystem=np_u16(o+68);p->subsystem_major=np_u16(o+48);p->subsystem_minor=np_u16(o+50);
 if(!power(filealign)||filealign<512||filealign>65536||!power(p->section_align)||
    p->section_align<4096||p->section_align<filealign)return fail(error,"ALIGNMENT");
 if(!p->size||p->size>image_limit||p->size%p->section_align||p->base%65536||
    p->base>0xffffffffu-p->size||!p->headers||p->headers%filealign||p->headers>p->size||
    p->headers>length)return fail(error,"IMAGE_BOUNDS");
 table=opt+os;if(!range(table,p->sections*40u,p->headers))return fail(error,"SECTION_TABLE");
 for(i=0;i<p->sections;i++){
  const uint8_t *s=f+table+i*40;np_section *v=&p->section[i];uint32_t vs=np_u32(s+8),aligned;
  v->va=np_u32(s+12);v->bytes=np_u32(s+16);v->raw=np_u32(s+20);v->flags=np_u32(s+36);
  v->span=vs>v->bytes?vs:v->bytes;
  if(!v->span||v->va<p->headers||v->va%p->section_align||!range(v->va,v->span,p->size))return fail(error,"SECTION_VIRTUAL");
  if(v->span>0xffffffffu-(p->section_align-1))return fail(error,"SECTION_OVERFLOW");
  aligned=(v->span+p->section_align-1)&~(p->section_align-1);
  if(!range(v->va,aligned,p->size))return fail(error,"SECTION_PAGE_BOUNDS");
  if(v->bytes&&(v->raw<p->headers||v->raw%filealign||v->bytes%filealign||!range(v->raw,v->bytes,length)))return fail(error,"SECTION_RAW");
  for(j=0;j<i;j++){const np_section *old=&p->section[j];uint32_t oldspan=(old->span+p->section_align-1)&~(p->section_align-1);
   if(v->va<old->va+oldspan&&old->va<v->va+aligned)return fail(error,"SECTION_OVERLAP");
   if(v->bytes&&old->bytes&&v->raw<old->raw+old->bytes&&old->raw<v->raw+v->bytes)return fail(error,"RAW_OVERLAP");
  }
 }
 if(p->entry&&!np_memory(p,p->entry,1,1))return fail(error,"ENTRY_EXECUTABLE");
 for(i=0;i<16;i++){
  uint32_t r=i<dirs?np_u32(o+96+i*8):0,n=i<dirs?np_u32(o+100+i*8):0;
  p->directory[i][0]=r;p->directory[i][1]=n;
  if(!!r!=!!n)return fail(error,"DIRECTORY_PAIR");
  if(r&&(i==4?!range(r,n,length):!np_raw(p,r,n)))return fail(error,"DIRECTORY_BOUNDS");
 }
 if(p->directory[15][0])return fail(error,"RESERVED_DIRECTORY");
 return 1;
}
int np_parse(np_image *p,const void *data,uint32_t length,const char **error)
{
 return parse_bounds(p,data,length,NP_FILE_LIMIT,NP_IMAGE_LIMIT,error);
}
int np_parse_limited(np_image *p,const void *data,uint32_t length,
                     const np_parse_limits *limits,const char **error)
{
 if(error)*error=0;
 if(!limits||limits->file_bytes<64||limits->file_bytes>NP_LARGE_FILE_LIMIT||
    limits->image_bytes<4096||limits->image_bytes>NP_LARGE_IMAGE_LIMIT||
    limits->total_bytes<4160||limits->total_bytes>NP_LARGE_TOTAL_LIMIT)
  return fail(error,"PARSE_BUDGET_BOUNDS");
 if(!parse_bounds(p,data,length,limits->file_bytes,limits->image_bytes,error))return 0;
 /* Subtraction prevents wraparound in the file plus mapped-image budget. */
 if(length>limits->total_bytes||p->size>limits->total_bytes-length)
  return fail(error,"PARSE_TOTAL_BUDGET");
 return 1;
}
static int imports_at(const np_image *p,int delay,np_import_fn fn,void *context,uint32_t *total,uint32_t *claimed,const char **error)
{
 uint32_t r=p->directory[delay?13:1][0],size=p->directory[delay?13:1][1],stride=delay?32:20,i,j;
 if(!r)return 1;
 for(i=0;i<size/stride&&i<512;i++){
  const uint8_t *d=np_raw(p,r+i*stride,stride);uint32_t sum=0,k,lookup,iat,name,stamp;
  const char *dll;for(k=0;k<stride;k+=4)sum|=np_u32(d+k);if(!sum)return 1;
  if(delay){if(np_u32(d)!=1)return fail(error,"DELAY_VA_UNSUPPORTED");name=np_u32(d+4);iat=np_u32(d+12);lookup=np_u32(d+16);stamp=np_u32(d+28);
   if(!lookup)return fail(error,"DELAY_LOOKUP");
  }else{lookup=np_u32(d);stamp=np_u32(d+4);name=np_u32(d+12);iat=np_u32(d+16);}
  dll=string(p,name,128);if(!module_name(dll)||!iat||iat%4||(lookup&&lookup%4)||(!lookup&&stamp))return fail(error,"IMPORT_DESCRIPTOR");
  if(!lookup)lookup=iat;
  for(j=0;j<NP_IMPORTS;j++){
   const uint8_t *q;uint32_t value,slot;uint16_t ordinal=0;const char *symbol=0;
   if(lookup>0xffffffffu-j*4||iat>0xffffffffu-j*4)return fail(error,"IMPORT_OVERFLOW");
   q=np_raw(p,lookup+j*4,4);slot=iat+j*4;
   if(!q||!np_raw(p,slot,4)||!np_memory(p,slot,4,2))return fail(error,"IMPORT_THUNK_BOUNDS");
   value=np_u32(q);if(!value)break;
   for(k=0;k<*total;k++)if(claimed[k]==slot)return fail(error,"IAT_OVERLAP");
   if(*total>=NP_IMPORTS)return fail(error,"IMPORT_LIMIT");claimed[(*total)++]=slot;
   if(value&0x80000000u){if(value&0x7fff0000u)return fail(error,"IMPORT_ORDINAL");ordinal=(uint16_t)value;if(!ordinal)return fail(error,"IMPORT_ORDINAL_ZERO");}
   else {if(value>0xfffffffdu||!np_raw(p,value,2)||(symbol=string(p,value+2,512))==0||!*symbol)return fail(error,"IMPORT_NAME");}
   if(fn&&!fn(context,dll,symbol,ordinal,slot,delay))return fail(error,"IMPORT_RESOLVER");
  }
  if(j==NP_IMPORTS)return fail(error,"IMPORT_UNTERMINATED");
 }
 return fail(error,"IMPORT_DIRECTORY_UNTERMINATED");
}
int np_imports(const np_image *p,int include_delay,np_import_fn fn,void *context,uint32_t *count,const char **error)
{
 uint32_t n=0,claimed[NP_IMPORTS];if(error)*error=0;
 if(!imports_at(p,0,fn,context,&n,claimed,error)|| (include_delay&&!imports_at(p,1,fn,context,&n,claimed,error)))return 0;
 if(count)*count=n;return 1;
}
static int relocations_bounds(const np_image *p,np_reloc_fn fn,void *context,
                              uint32_t maximum,const char **error)
{
 uint32_t r=p->directory[5][0],size=p->directory[5][1],at=0,count=0,previous=0;uint8_t occupied[4099],carry[3]={0,0,0};int have_previous=0;
 if(error)*error=0;if(!r)return 1;
 while(at<size){const uint8_t *b;uint32_t page,bytes,n;
  if(size-at<8||(b=np_raw(p,r+at,8))==0)return fail(error,"RELOC_HEADER");page=np_u32(b);bytes=np_u32(b+4);
  if(page%4096||bytes<8||bytes%4||bytes>size-at)return fail(error,"RELOC_BLOCK");
  if(have_previous&&page<=previous)return fail(error,"RELOC_PAGE_ORDER_UNSUPPORTED");
  for(n=0;n<4099;n++)occupied[n]=0;
  if(have_previous&&previous<=0xffffefffu&&page==previous+4096)for(n=0;n<3;n++)occupied[n]=carry[n];
  for(n=8;n<bytes;n+=2){uint16_t v=np_u16(np_raw(p,r+at+n,2));uint32_t target,k,offset=v&4095u;
   if(!(v>>12))continue;if((v>>12)!=3)return fail(error,"RELOC_TYPE");
   if(page>0xffffffffu-(v&4095u))return fail(error,"RELOC_OVERFLOW");target=page+(v&4095u);
   if(!np_memory(p,target,4,0))return fail(error,"RELOC_TARGET");
   for(k=0;k<4;k++){if(occupied[offset+k])return fail(error,"RELOC_OVERLAP");occupied[offset+k]=1;}
   if(count++>=maximum)return fail(error,"RELOC_LIMIT");
   if(fn&&!fn(context,target))return fail(error,"RELOC_APPLY");
  }for(n=0;n<3;n++)carry[n]=occupied[4096+n];previous=page;have_previous=1;at+=bytes;
 }return 1;
}
int np_relocations(const np_image *p,np_reloc_fn fn,void *context,const char **error)
{
 return relocations_bounds(p,fn,context,NP_RELOC_LIMIT,error);
}
int np_relocations_limited(const np_image *p,np_reloc_fn fn,void *context,
                           uint32_t maximum,const char **error)
{
 if(error)*error=0;
 if(!p||!maximum||maximum>NP_LARGE_RELOC_LIMIT)return fail(error,"RELOC_WORK_BUDGET");
 return relocations_bounds(p,fn,context,maximum,error);
}
int np_export(const np_image *p,const char *name,uint16_t ordinal,uint32_t *result,const char **forward,const char **error)
{
 uint32_t r=p->directory[0][0],size=p->directory[0][1],n,base,nf,nn,index=0xffffffffu;const uint8_t *d,*functions,*names,*orders;
 if(error)*error=0;if(result)*result=0;if(forward)*forward=0;
 if(!r)return 1;if(size<40||(d=np_raw(p,r,40))==0)return fail(error,"EXPORT_DIRECTORY");
 base=np_u32(d+16);nf=np_u32(d+20);nn=np_u32(d+24);
 if(nf>NP_IMPORTS||nn>NP_IMPORTS||nn>nf||(nf&&(functions=np_raw(p,np_u32(d+28),nf*4))==0))return fail(error,"EXPORT_FUNCTIONS");
 functions=nf?np_raw(p,np_u32(d+28),nf*4):0;names=nn?np_raw(p,np_u32(d+32),nn*4):0;orders=nn?np_raw(p,np_u32(d+36),nn*2):0;
 if(nn&&(!names||!orders))return fail(error,"EXPORT_NAMES");
 for(n=0;n<nn;n++){const char *s=string(p,np_u32(names+n*4),512);uint16_t k=np_u16(orders+n*2);
  if(!s||!*s||k>=nf)return fail(error,"EXPORT_NAME_BOUNDS");
  if(name&&same(s,name)){if(index!=0xffffffffu)return fail(error,"EXPORT_DUPLICATE");index=k;}
 }
 for(n=0;n<nf;n++){uint32_t target=np_u32(functions+n*4);
  if(!target)continue;
  if(target>=r&&target-r<size){const char *f=string(p,target,size-(target-r));if(!f||!*f)return fail(error,"EXPORT_FORWARDER");}
  else if(!np_memory(p,target,1,0))return fail(error,"EXPORT_TARGET");
 }
 if(!name&&ordinal>=base&&ordinal-base<nf)index=ordinal-base;
 if(index==0xffffffffu)return 1;
 *result=np_u32(functions+index*4);if(*result>=r&&*result-r<size&&forward)*forward=string(p,*result,size-(*result-r));
 return 1;
}
int np_execution_profile(const np_image *p,const char **error)
{
 static const unsigned blocked[]={3,7,9,10,11,13,14};unsigned n;
 if(!p->entry)return fail(error,"EXECUTION_ENTRY_MISSING");
 if(p->subsystem!=2&&p->subsystem!=3)return fail(error,"EXECUTION_SUBSYSTEM");
 for(n=0;n<sizeof(blocked)/sizeof(blocked[0]);n++)if(p->directory[blocked[n]][0])return fail(error,"EXECUTION_RUNTIME_DIRECTORY");
 return 1;
}
static int tls_va(const np_image *p,uint32_t va,uint32_t n,uint32_t *rva,int kind)
{
 if(va<p->base||!np_memory(p,va-p->base,n,kind))return 0;
 *rva=va-p->base;return 1;
}
int np_tls(const np_image *p,np_tls_info *t,const char **error)
{
 const uint8_t *d;uint32_t start,end,index,callbacks,flags,align,n;
 if(error)*error=0;if(!t)return fail(error,"TLS_OUTPUT_NULL");
 for(n=0;n<sizeof(*t);n++)((uint8_t *)t)[n]=0;
 if(!p->directory[9][0])return 1;
 if(p->directory[9][1]!=24||(d=np_raw(p,p->directory[9][0],24))==0)return fail(error,"TLS_DIRECTORY_SIZE");
 start=np_u32(d);end=np_u32(d+4);index=np_u32(d+8);callbacks=np_u32(d+12);
 t->zero_bytes=np_u32(d+16);flags=np_u32(d+20);align=(flags>>20)&15u;
 if(flags&~0x00f00000u||align==15)return fail(error,"TLS_CHARACTERISTICS");
 t->alignment=align?1u<<(align-1):16;
 if(!!start!=!!end||end<start||end-start>1048576u||t->zero_bytes>1048576u-(end-start))return fail(error,"TLS_TEMPLATE_SIZE");
 t->template_bytes=end-start;
 if(start){
  if(start<p->base||end>p->base+p->size||!tls_va(p,start,t->template_bytes?t->template_bytes:1,&t->template_rva,0)||
     (t->template_bytes&&!np_raw(p,t->template_rva,t->template_bytes)))return fail(error,"TLS_TEMPLATE_BOUNDS");
 }
 if(!index||index%4||!tls_va(p,index,4,&t->index_rva,3))return fail(error,"TLS_INDEX_WRITABLE");
 if(t->template_bytes&&t->index_rva<t->template_rva+t->template_bytes&&t->template_rva<t->index_rva+4)return fail(error,"TLS_INDEX_TEMPLATE_OVERLAP");
 if(callbacks){
  if(callbacks%4||callbacks<p->base)return fail(error,"TLS_CALLBACK_ARRAY");
  t->callbacks_rva=callbacks-p->base;
  for(n=0;n<=NP_TLS_CALLBACKS;n++){
   const uint8_t *q;uint32_t va;
   if(t->callbacks_rva>0xffffffffu-n*4||(q=np_raw(p,t->callbacks_rva+n*4,4))==0)return fail(error,"TLS_CALLBACK_ARRAY");
   va=np_u32(q);if(!va)break;
   if(n==NP_TLS_CALLBACKS)return fail(error,"TLS_CALLBACK_LIMIT");
   if(!tls_va(p,va,1,&t->callback[n],1))return fail(error,"TLS_CALLBACK_EXECUTABLE");
   t->count++;
  }
  if(t->index_rva>=t->callbacks_rva&&t->index_rva<t->callbacks_rva+(t->count+1)*4)return fail(error,"TLS_INDEX_CALLBACK_OVERLAP");
 }
 t->present=1;return 1;
}
int np_runtime_profile(const np_image *p,const char **error)
{
 static const unsigned blocked[]={3,7,10,11,13,14};unsigned n;np_tls_info tls;
 if(!p->entry&&!(p->characteristics&0x2000))return fail(error,"EXECUTION_ENTRY_MISSING");
 if(p->subsystem!=2&&p->subsystem!=3)return fail(error,"EXECUTION_SUBSYSTEM");
 for(n=0;n<sizeof(blocked)/sizeof(blocked[0]);n++)if(p->directory[blocked[n]][0])return fail(error,"EXECUTION_RUNTIME_DIRECTORY");
 return np_tls(p,&tls,error);
}
