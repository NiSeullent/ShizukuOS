/* SPDX-License-Identifier: GPL-2.0-only
 * Original implementation of the documented PE32 delay descriptor contract.
 * This is a source-linkable resolver core, not an NT exception dispatcher or
 * a claim that the unchanged Chromium delay helper is already intercepted.
 */
#include "delay_runtime.h"

static int failure(const char **error,const char *message)
{if(error)*error=message;return 0;}
static void zero(void *out,uint32_t bytes)
{uint32_t i;for(i=0;i<bytes;i++)((uint8_t *)out)[i]=0;}
static void copy(void *out,const void *in,uint32_t bytes)
{uint32_t i;for(i=0;i<bytes;i++)((uint8_t *)out)[i]=((const uint8_t *)in)[i];}
static int same(const uint8_t *a,const uint8_t *b,uint32_t bytes)
{uint32_t i;for(i=0;i<bytes;i++)if(a[i]!=b[i])return 0;return 1;}
static void put32(uint8_t *where,uint32_t value)
{
 /* Linker thunks dispatch without taking our lock. PE32 slots and the mapping
  * are aligned before publication, so one x86 store prevents a torn address.
  * The memory clobber publishes initialized resolver ownership first.
  */
#if defined(__i386__) || defined(__x86_64__)
 __asm__ __volatile__("movl %1,%0" : "=m"(*(uint32_t *)(void *)where) : "r"(value) : "memory");
#else
#error Native Windows98 PE32 delay publication requires the x86 target.
#endif
}
static int overlap(uint32_t a,uint32_t an,uint32_t b,uint32_t bn)
{return an&&bn&&a<b+bn&&b<a+an;}
static const char *text_at(const np_image *image,uint32_t rva,uint32_t limit,uint32_t *bytes)
{
 const uint8_t *first=np_raw(image,rva,1);uint32_t i;
 if(!first)return 0;
 for(i=0;i<limit;i++){
  const uint8_t *p;if(rva>0xffffffffu-i)return 0;p=np_raw(image,rva+i,1);
  if(!p||p!=first+i)return 0;
  if(!*p){if(!i)return 0;*bytes=i+1;return (const char *)first;}
  if(*p<32||*p>126)return 0;
 }return 0;
}
static int stash(ntw_delay_context *ctx,const char *name,uint32_t bytes,uint32_t *offset)
{
 if(bytes>NTW_DELAY_NAMES-ctx->names_used)return 0;
 *offset=ctx->names_used;copy(ctx->names+ctx->names_used,name,bytes);ctx->names_used+=bytes;return 1;
}
static int safe_write(const np_image *image,uint32_t rva)
{
 uint32_t i;
 if(!rva||rva%4||!np_raw(image,rva,4)||!np_memory(image,rva,4,3))return 0;
 for(i=0;i<16;i++)if(i!=4&&i!=8&&i!=12&&overlap(rva,4,image->directory[i][0],image->directory[i][1]))return 0;
 return 1;
}
typedef struct check_imports {ntw_delay_context *ctx;const np_image *image;int valid;} check_imports;
static int inspect_import(void *opaque,const char *dll,const char *name,uint16_t ordinal,uint32_t slot,int delay)
{
 check_imports *check=opaque;uint32_t i;(void)dll;(void)name;(void)ordinal;(void)delay;
 for(i=0;i<check->ctx->module_count;i++)if(overlap(slot,4,check->ctx->module[i].handle_rva,4)){check->valid=0;return 0;}
 return 1;
}
static int no_metadata_overlap(const np_image *image,const ntw_delay_context *ctx)
{
 uint32_t i,j,k;
 for(i=0;i<ctx->module_count;i++){
  const ntw_delay_module *module=&ctx->module[i];const uint8_t *d=module->descriptor;
  uint32_t lookup=np_u32(d+16),name=np_u32(d+4),bytes,dll_bytes;const char *dll;
  dll=text_at(image,name,128,&dll_bytes);if(!dll)return 0;
  for(j=0;j<ctx->entry_count+ctx->module_count;j++){
   uint32_t write=j<ctx->entry_count?ctx->entry[j].slot_rva:ctx->module[j-ctx->entry_count].handle_rva;
   if(overlap(write,4,name,dll_bytes))return 0;
   for(k=0;k<NP_IMPORTS;k++){
    const uint8_t *q;uint32_t value,at;
    if(lookup>0xffffffffu-k*4)return 0;at=lookup+k*4;q=np_raw(image,at,4);if(!q)return 0;
    if(overlap(write,4,at,4))return 0;value=np_u32(q);if(!value)break;
    if(!(value&0x80000000u)){
     const char *symbol=text_at(image,value+2,512,&bytes);if(!symbol)return 0;
     if(overlap(write,4,value,bytes+2))return 0;
    }
   }if(k==NP_IMPORTS)return 0;
  }
 }return 1;
}
static int tls_overlap(const np_tls_info *tls,uint32_t slot)
{
 return tls->present&&(overlap(slot,4,tls->index_rva,4)||overlap(slot,4,tls->template_rva,tls->template_bytes)||overlap(slot,4,tls->callbacks_rva,tls->callbacks_rva?(tls->count+1)*4:0));
}
int ntw_delay_init(ntw_delay_context *ctx,const np_image *image,uint8_t *mapped,uint32_t mapped_bytes,uint32_t loaded_base,const ntw_delay_ops *ops,const char **error)
{
 uint32_t at,limit,i,j;int terminal=0;check_imports check;const char *why=0;np_tls_info tls;
 if(error)*error=0;
 if(!ctx||ctx->magic||!image||!mapped||(uintptr_t)mapped%4||mapped_bytes!=image->size||!loaded_base||loaded_base>0xffffffffu-image->size||!ops||!ops->enter||!ops->leave||!ops->open||!ops->find||!ops->close)return failure(error,"DELAY_ARGUMENT");
 zero(ctx,sizeof(*ctx));ctx->mapped=mapped;ctx->mapped_bytes=mapped_bytes;ctx->loaded_base=loaded_base;ctx->ops=*ops;
 if(!np_imports(image,1,0,0,0,&why)||!np_relocations(image,0,0,&why)||!np_tls(image,&tls,&why))goto invalid;
 limit=image->directory[13][1];
 if(!limit){ctx->magic=NTW_DELAY_MAGIC;return 1;}
 if(limit%32||limit<32){why="DELAY_DIRECTORY_SIZE";goto invalid;}
 for(at=0;at<limit;at+=32){
  uint32_t rva=image->directory[13][0]+at,sum=0,n,bytes,lookup,iat,handle;
  const uint8_t *d=np_raw(image,rva,32);const char *name;ntw_delay_module *module;
  if(!d){why="DELAY_DESCRIPTOR_BOUNDS";goto invalid;}
  for(i=0;i<32;i+=4)sum|=np_u32(d+i);
  if(!sum){terminal=1;for(j=at+32;j<limit;j++)if(*np_raw(image,image->directory[13][0]+j,1)){why="DELAY_TRAILING_DATA";goto invalid;}break;}
  if(ctx->module_count==NTW_DELAY_MODULES){why="DELAY_MODULE_LIMIT";goto invalid;}
  if(np_u32(d)!=1||np_u32(d+20)||np_u32(d+24)||np_u32(d+28)){why="DELAY_BOUND_UNLOAD_UNSUPPORTED";goto invalid;}
  handle=np_u32(d+8);iat=np_u32(d+12);lookup=np_u32(d+16);
  if(!safe_write(image,handle)||tls_overlap(&tls,handle)||np_u32(mapped+handle)||np_u32(np_raw(image,handle,4))){why="DELAY_HANDLE_SLOT";goto invalid;}
  for(i=0;i<ctx->module_count;i++)if(ctx->module[i].handle_rva==handle){why="DELAY_SHARED_HANDLE_SLOT";goto invalid;}
  if(!same(d,mapped+rva,32)){why="DELAY_DESCRIPTOR_CHANGED";goto invalid;}
  module=&ctx->module[ctx->module_count];module->descriptor_rva=rva;module->handle_rva=handle;copy(module->descriptor,d,32);
  name=text_at(image,np_u32(d+4),128,&bytes);
  if(!name||!stash(ctx,name,bytes,&module->name)){why="DELAY_DLL_NAME";goto invalid;}
  for(n=0;n<NP_IMPORTS;n++){
   const uint8_t *q;uint32_t value,slot;ntw_delay_entry *entry;
   if(lookup>0xffffffffu-n*4||iat>0xffffffffu-n*4){why="DELAY_THUNK_OVERFLOW";goto invalid;}
   q=np_raw(image,lookup+n*4,4);slot=iat+n*4;
   if(!q||!np_raw(image,slot,4)){why="DELAY_THUNK_BOUNDS";goto invalid;}
   value=np_u32(q);if(!value){if(np_u32(mapped+slot)){why="DELAY_IAT_TERMINATOR";goto invalid;}break;}
   if(ctx->entry_count==NP_IMPORTS||!safe_write(image,slot)){why="DELAY_IAT_SLOT";goto invalid;}
   {uint32_t original=np_u32(np_raw(image,slot,4));
    if(original<image->base||!np_memory(image,original-image->base,1,1)||np_u32(mapped+slot)!=loaded_base+(original-image->base)){why="DELAY_IAT_CHANGED";goto invalid;}
   }
   if(tls_overlap(&tls,slot)){why="DELAY_TLS_OVERLAP";goto invalid;}
   entry=&ctx->entry[ctx->entry_count++];entry->slot_rva=slot;entry->initial=np_u32(mapped+slot);entry->module=(uint16_t)ctx->module_count;
   if(value&0x80000000u){entry->ordinal=(uint16_t)value;}
   else{
    name=text_at(image,value+2,512,&bytes);if(!name||!stash(ctx,name,bytes,&entry->name)){why="DELAY_SYMBOL_NAME";goto invalid;}
   }
  }if(n==NP_IMPORTS){why="DELAY_THUNK_LIMIT";goto invalid;}ctx->module_count++;
 }
 if(!terminal){why="DELAY_DIRECTORY_UNTERMINATED";goto invalid;}
 check.ctx=ctx;check.image=image;check.valid=1;
 if(!np_imports(image,1,inspect_import,&check,0,&why)||!check.valid||!no_metadata_overlap(image,ctx)){why="DELAY_METADATA_OVERLAP";goto invalid;}
 ctx->magic=NTW_DELAY_MAGIC;return 1;
invalid:
 zero(ctx,sizeof(*ctx));return failure(error,why?why:"DELAY_INVALID_IMAGE");
}
static int mapping_unchanged(const ntw_delay_context *ctx)
{
 uint32_t i;
 for(i=0;i<ctx->entry_count;i++)if(np_u32(ctx->mapped+ctx->entry[i].slot_rva)!=(ctx->entry[i].address?ctx->entry[i].address:ctx->entry[i].initial))return 0;
 for(i=0;i<ctx->module_count;i++)if(!same(ctx->mapped+ctx->module[i].descriptor_rva,ctx->module[i].descriptor,32)||np_u32(ctx->mapped+ctx->module[i].handle_rva)!=(ctx->module[i].published?ctx->module[i].handle:0))return 0;
 return 1;
}
int ntw_delay_resolve(ntw_delay_context *ctx,uint32_t descriptor,uint32_t slot,uint32_t *result,const char **error)
{
 uint32_t i,address=0,opened=0;ntw_delay_entry *entry=0;ntw_delay_module *module=0;const char *why=0;
 if(error)*error=0;if(result)*result=0;
 if(!ctx||ctx->magic!=NTW_DELAY_MAGIC||!result)return failure(error,"DELAY_CONTEXT");
 if(!ctx->ops.enter(ctx->ops.opaque))return failure(error,"DELAY_LOCK");
 if(ctx->busy){ctx->ops.leave(ctx->ops.opaque);return failure(error,"DELAY_REENTRANT_UNSUPPORTED");}
 ctx->busy=1;
 if(ctx->state){why="DELAY_CONTEXT_CLOSING";goto done;}
 for(i=0;i<ctx->entry_count;i++)if(ctx->entry[i].slot_rva==slot&&ctx->module[ctx->entry[i].module].descriptor_rva==descriptor){entry=&ctx->entry[i];module=&ctx->module[entry->module];break;}
 if(!entry){why="DELAY_UNKNOWN_SLOT";goto done;}
 if(!mapping_unchanged(ctx)){
  why="DELAY_MAPPING_CHANGED";goto done;
 }
 if(entry->address){*result=entry->address;goto done;}
 if(!module->handle){opened=ctx->ops.open(ctx->ops.opaque,ctx->names+module->name);
  if(!mapping_unchanged(ctx)){why="DELAY_MAPPING_CHANGED";ctx->state=1;goto rollback;}
  if(!opened){why="DELAY_LOAD_LIBRARY_FAILED";goto done;}
 }
 address=ctx->ops.find(ctx->ops.opaque,opened?opened:module->handle,entry->ordinal?0:ctx->names+entry->name,entry->ordinal);
 if(!mapping_unchanged(ctx)){why="DELAY_MAPPING_CHANGED";ctx->state=1;goto rollback;}
 if(!address){
  why="DELAY_GET_PROC_FAILED";
  goto rollback;
 }
 if(opened){module->handle=opened;module->published=1;put32(ctx->mapped+module->handle_rva,opened);}
 entry->address=address;put32(ctx->mapped+slot,address);*result=address;
 goto done;
rollback:
 if(opened&&!ctx->ops.close(ctx->ops.opaque,opened)){module->handle=opened;ctx->state=1;why="DELAY_ROLLBACK_CLOSE_FAILED";}
 else if(!mapping_unchanged(ctx)){ctx->state=1;why="DELAY_MAPPING_CHANGED";}
done:
 ctx->busy=0;ctx->ops.leave(ctx->ops.opaque);return why?failure(error,why):1;
}
int ntw_delay_dispose(ntw_delay_context *ctx,int quiescent,const char **error)
{
 uint32_t i;int okay=1;const char *why=0;
 if(error)*error=0;
 if(!ctx||ctx->magic!=NTW_DELAY_MAGIC||quiescent!=1)return failure(error,"DELAY_DISPOSE_REQUIRES_QUIESCENCE");
 if(!ctx->ops.enter(ctx->ops.opaque))return failure(error,"DELAY_LOCK");
 if(ctx->busy){ctx->ops.leave(ctx->ops.opaque);return failure(error,"DELAY_REENTRANT_UNSUPPORTED");}
 ctx->busy=1;
 if(!mapping_unchanged(ctx)){why="DELAY_MAPPING_CHANGED";goto failed;}
 if(ctx->state!=2){
  for(i=0;i<ctx->entry_count;i++){put32(ctx->mapped+ctx->entry[i].slot_rva,ctx->entry[i].initial);ctx->entry[i].address=0;}
  for(i=0;i<ctx->module_count;i++){put32(ctx->mapped+ctx->module[i].handle_rva,0);ctx->module[i].published=0;}
  ctx->state=2;
 }
 for(i=ctx->module_count;i;i--){ntw_delay_module *module=&ctx->module[i-1];
  if(module->handle){if(ctx->ops.close(ctx->ops.opaque,module->handle))module->handle=0;else{okay=0;why="DELAY_DISPOSE_CLOSE_FAILED";}}
  if(!mapping_unchanged(ctx)){why="DELAY_MAPPING_CHANGED";goto failed;}
 }
 ctx->busy=0;ctx->ops.leave(ctx->ops.opaque);
 if(!okay)return failure(error,why);
 zero(ctx,sizeof(*ctx));return 1;
failed:
 ctx->busy=0;ctx->ops.leave(ctx->ops.opaque);return failure(error,why);
}
