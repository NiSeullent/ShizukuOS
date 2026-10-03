/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_sys.h"
#include "setup_native_abi.h"
#include "setup_native_release.h"
#include "blk_authority.h"
#define OWNERS 16u
struct source { uint64_t token; archive_source_t *cap; archive_source_info_t info; unsigned admitted,role; };
struct owner {
 process_t *process; int pid; unsigned retired;
 struct source sources[2];
 uint64_t claim_token; blk_authority_claim_t *claim; blk_authority_identity_t target;
};
static struct owner owners[OWNERS];
static kmutex_t lock;static volatile unsigned lock_state;static uint64_t sequence;
static uint8_t bounce[SHZ_NATIVE_SYS_IO_MAX];
static void acquire(void)
{
 unsigned expected=0;
 if(__atomic_compare_exchange_n(&lock_state,&expected,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)){
  mutex_init(&lock);__atomic_store_n(&lock_state,2,__ATOMIC_RELEASE);
 }
 while(__atomic_load_n(&lock_state,__ATOMIC_ACQUIRE)!=2)__asm__ volatile("pause");
 mutex_lock(&lock);
}
static int terminated(const char *p,unsigned n)
{unsigned i;for(i=0;i<n;i++)if(!p[i])return 1;return 0;}
static uint64_t token(void){return sequence==UINT64_MAX?0:++sequence;}
static struct owner *owner_for(process_t *p,int create)
{
 unsigned i;struct owner *empty=0;
 for(i=0;i<OWNERS;i++){
  if(!owners[i].retired&&owners[i].process==p&&owners[i].pid==p->pid)return &owners[i];
  if(!owners[i].process&&!owners[i].retired&&!empty)empty=&owners[i];
 }
 if(!create||!empty)return 0;
 empty->process=p;empty->pid=p->pid;return empty;
}
static struct source *source_for(struct owner *o,uint64_t t)
{
 unsigned i;if(!o||!t)return 0;
 for(i=0;i<2;i++)if(o->sources[i].token==t&&o->sources[i].cap)return &o->sources[i];
 return 0;
}
static blk_dev_t *device(unsigned index)
{unsigned i;for(i=0;i<blk_count();i++)if(i==index)return blk_get(i);return 0;}
static int pair(struct owner *o,const shz_native_call_v1 *r,blk_authority_source_t pins[2])
{
 struct source *a=source_for(o,r->handle),*b=source_for(o,r->other_handle);archive_source_info_t infos[2];
 if(!a||!b||a==b||!a->admitted||a->role!=0||!b->admitted||b->role!=1||archive_source_info(o,a->cap,&a->info,&infos[0])||archive_source_info(o,b->cap,&b->info,&infos[1])||
  setup_native_release_pair(infos)||blk_authority_pin_archive(o,a->cap,&a->info,&pins[0])||
  blk_authority_pin_archive(o,b->cap,&b->info,&pins[1]))return -1;
 return 0;
}
static int claim_matches(struct owner *o,const shz_native_call_v1 *r)
{return o&&o->claim&&r->handle==o->claim_token&&!memcmp(&r->target,&o->target,sizeof o->target);}
static void tidy(struct owner *o)
{if(o&&!o->claim&&!o->sources[0].cap&&!o->sources[1].cap)memset(o,0,sizeof *o);}
_Static_assert(sizeof(blk_authority_identity_t)==sizeof(shz_native_target_v1),"target wire/kernel identity");
int32_t setup_native_syscall(process_t *p,uint64_t user,uint64_t bytes)
{
 shz_native_call_v1 r;struct owner *o=0;struct source *s=0;blk_authority_source_t pins[2];
 blk_authority_identity_t identity;unsigned i;int rc=-1;int32_t status=STATUS_ACCESS_DENIED;
 uint64_t new_token=0;unsigned created_source=0,created_claim=0;
 if(!p||p->teardown)return STATUS_ACCESS_DENIED;
 if(bytes!=sizeof r)return STATUS_INFO_LENGTH_MISMATCH;
 if(copy_from_user(p,&r,user,sizeof r))return STATUS_ACCESS_VIOLATION;
 if(r.version!=SHZ_NATIVE_SYS_VERSION||r.bytes!=sizeof r||r.reserved||r.tail_reserved||r.operation>SHZ_NATIVE_ADMIT)
  return STATUS_INVALID_PARAMETER;
 acquire();if(p->teardown)goto done;
 if(r.operation==SHZ_NATIVE_CAPS){
  r.max_source_bytes=SHZ_NATIVE_SYS_SOURCE_MAX;r.max_io_bytes=SHZ_NATIVE_SYS_IO_MAX;
  r.producer_admission_available=setup_native_release_available();status=STATUS_SUCCESS;goto publish;
 }
 o=owner_for(p,r.operation==SHZ_NATIVE_OPEN);if(!o){status=STATUS_INVALID_HANDLE;goto done;}
 switch(r.operation){
 case SHZ_NATIVE_OPEN:
  if(o->claim||!terminated(r.path,sizeof r.path)||!r.path[0]){status=STATUS_INVALID_PARAMETER;break;}
  for(i=0;i<2;i++)if(!o->sources[i].cap){s=&o->sources[i];break;}
  if(!s||!(new_token=token())){status=STATUS_INSUFFICIENT_RESOURCES;break;}
  rc=archive_source_open(o,r.path,&s->cap,&s->info);
  if(!rc){s->token=new_token;r.handle=new_token;memcpy(&r.source,&s->info,sizeof r.source);created_source=1;}
  break;
 case SHZ_NATIVE_INFO:
 case SHZ_NATIVE_ADMIT:
 case SHZ_NATIVE_READ:
 case SHZ_NATIVE_CLOSE:
  s=source_for(o,r.handle);if(!s){status=STATUS_INVALID_HANDLE;break;}
  if(r.operation==SHZ_NATIVE_ADMIT){
   archive_source_info_t info;
   if(r.index>1||(s->admitted&&s->role!=r.index))break;
   rc=archive_source_info(o,s->cap,&s->info,&info);
   if(!rc)rc=setup_native_release_source(&info,r.index);
   if(!rc){s->admitted=1;s->role=r.index;memcpy(&r.source,&info,sizeof r.source);}
  }
  else if(r.operation==SHZ_NATIVE_INFO){archive_source_info_t info;rc=archive_source_info(o,s->cap,&s->info,&info);if(!rc)memcpy(&r.source,&info,sizeof r.source);}
  else if(r.operation==SHZ_NATIVE_CLOSE){rc=archive_source_close(o,s->cap,&s->info);if(!rc)memset(s,0,sizeof *s);}
  else{
   if(!r.length||r.length>sizeof bounce){status=STATUS_INVALID_PARAMETER;break;}
   rc=archive_source_read(o,s->cap,&s->info,r.offset,bounce,r.length);
   if(!rc&&copy_to_user(p,r.buffer,bounce,r.length)){status=STATUS_ACCESS_VIOLATION;goto done;}
  }
  break;
 case SHZ_NATIVE_REVIEW:
 case SHZ_NATIVE_CLAIM:
  if(o->claim||pair(o,&r,pins))break;
  if(r.operation==SHZ_NATIVE_REVIEW){rc=blk_authority_review(device(r.index),pins,&identity);if(!rc)memcpy(&r.target,&identity,sizeof identity);}
  else{
   if(!(new_token=token())){status=STATUS_INSUFFICIENT_RESOURCES;break;}
   memcpy(&identity,&r.target,sizeof identity);
   rc=blk_authority_claim_target(o,device(r.index),&identity,pins,&o->claim);
   if(!rc){o->target=identity;o->claim_token=new_token;r.handle=new_token;created_claim=1;}
  }
  break;
 case SHZ_NATIVE_CHECK:
 case SHZ_NATIVE_TARGET_READ:
 case SHZ_NATIVE_TARGET_WRITE:
 case SHZ_NATIVE_FLUSH:
 case SHZ_NATIVE_RELEASE:
  if(!claim_matches(o,&r)){status=STATUS_INVALID_HANDLE;break;}
  if(r.operation==SHZ_NATIVE_CHECK)rc=blk_authority_check(o,o->claim,&o->target);
  else if(r.operation==SHZ_NATIVE_FLUSH)rc=blk_authority_flush(o,o->claim,&o->target);
  else if(r.operation==SHZ_NATIVE_RELEASE){rc=blk_authority_release(o,o->claim,&o->target);if(!rc){o->claim=0;o->claim_token=0;}}
  else{
   if(!r.length||r.length>sizeof bounce||r.length%512){status=STATUS_INVALID_PARAMETER;break;}
   if(r.operation==SHZ_NATIVE_TARGET_WRITE){
    if(copy_from_user(p,bounce,r.buffer,r.length)){status=STATUS_ACCESS_VIOLATION;goto done;}
    rc=blk_authority_write(o,o->claim,&o->target,r.offset,r.length/512,bounce);
   }else{
    rc=blk_authority_read(o,o->claim,&o->target,r.offset,r.length/512,bounce);
    if(!rc&&copy_to_user(p,r.buffer,bounce,r.length)){status=STATUS_ACCESS_VIOLATION;goto done;}
   }
  }
  break;
 default:status=STATUS_INVALID_PARAMETER;
 }
 if(!rc)status=STATUS_SUCCESS;
publish:
 if(status==STATUS_SUCCESS&&copy_to_user(p,user,&r,sizeof r)){
  status=STATUS_ACCESS_VIOLATION;
  if(created_source&&!archive_source_close(o,s->cap,&s->info))memset(s,0,sizeof *s);
  if(created_claim&&!blk_authority_release(o,o->claim,&o->target)){o->claim=0;o->claim_token=0;}
 }
done:
 memset(bounce,0,sizeof bounce);tidy(o);mutex_unlock(&lock);return status;
}
void setup_native_process_teardown(process_t *p)
{
 struct owner *o;unsigned i;if(!p)return;acquire();o=owner_for(p,0);
 if(o){
  if(o->claim&&!blk_authority_release(o,o->claim,&o->target)){o->claim=0;o->claim_token=0;}
  for(i=0;i<2;i++)if(o->sources[i].cap&&!archive_source_close(o,o->sources[i].cap,&o->sources[i].info))memset(&o->sources[i],0,sizeof o->sources[i]);
  /* Poisoned claim retains snapshot references and kernel owner address. This
   * slot cannot be reused by a recycled process pointer/PID until reboot. */
  if(o->claim||o->sources[0].cap||o->sources[1].cap){o->retired=1;o->process=0;}
  else memset(o,0,sizeof *o);
 }
 mutex_unlock(&lock);
}
