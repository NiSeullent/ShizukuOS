/* SPDX-License-Identifier: GPL-2.0-only */
#include "setup_native_sys.h"
#include "setup_native_abi.h"
#include "setup_target_abi.h"
#include "setup_native_release.h"
#include "blk_authority.h"
#define OWNERS 16u
struct source { uint64_t token; archive_source_t *cap; archive_source_info_t info; unsigned admitted,role; };
struct owner {
 process_t *process; int pid; unsigned retired,service; uint64_t generation;
 struct source sources[2];
 uint64_t claim_token; blk_authority_claim_t *claim; blk_authority_identity_t target;
};
static struct owner owners[OWNERS];
#define TARGET_IMAGE "\\SHZ\\SETUP\\SHZSETUP.EXE"
#define TARGET_MANIFEST "\\SHZ\\SETUP\\PAYLOAD\\manifest.json"
#define TARGET_ESP "\\SHZ\\SETUP\\PAYLOAD\\ESP.SIM"
#define TARGET_SYSTEM "\\SHZ\\SETUP\\PAYLOAD\\SYSTEM.ARC"
static const char *const target_paths[4]={TARGET_IMAGE,TARGET_MANIFEST,TARGET_ESP,TARGET_SYSTEM};
struct prepared_target {
 process_t *process; int pid; uint64_t generation;
 fsnode_t *nodes[4]; const void *data[4]; uint64_t sizes[4];
};
static struct prepared_target prepared[OWNERS];
static kmutex_t lock;static volatile unsigned lock_state;static uint64_t sequence;
/* Allocate only when a real source/target transfer needs it. Keeping 64 KiB in
 * image BSS crosses the fixed 3 MiB loader/heap boundary in the disk profile.
 * The existing syscall mutex serializes allocation and use; retain this one
 * kernel buffer for the boot lifetime, including uncertain driver completion. */
static uint8_t *bounce;
static int transfer_buffer(void)
{if(!bounce)bounce=kmalloc(SHZ_NATIVE_SYS_IO_MAX);return bounce?0:-1;}
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
static struct owner *owner_for(process_t *p,int create,unsigned service)
{
 unsigned i;struct owner *empty=0;
 for(i=0;i<OWNERS;i++){
  if(!owners[i].retired&&owners[i].process==p&&owners[i].pid==p->pid&&owners[i].generation==p->saw_generation&&owners[i].service==service)return &owners[i];
  if(!owners[i].process&&!owners[i].retired&&!empty)empty=&owners[i];
 }
 if(!create||!empty)return 0;
 empty->process=p;empty->pid=p->pid;empty->generation=p->saw_generation;empty->service=service;return empty;
}
static struct prepared_target *prepared_for(process_t *p)
{
 unsigned i;for(i=0;i<OWNERS;i++)if(prepared[i].process==p&&prepared[i].pid==p->pid&&
   prepared[i].generation==p->saw_generation)return &prepared[i];
 return 0;
}
static int preparation_valid(struct prepared_target *g)
{
 unsigned i;if(!g)return 0;
 for(i=0;i<4;i++){
  fsnode_t *node=archive_source_bound_node(target_paths[i]);
  if(!node||node!=g->nodes[i]||node->data!=g->data[i]||node->size!=g->sizes[i])return 0;
 }
 return 1;
}
int32_t setup_target_prepare(process_t *p,void *actual_image)
{
 struct prepared_target candidate,*g=0;unsigned i;int32_t status=STATUS_ACCESS_DENIED;
 if(!p||p->teardown||!p->saw_generation||!actual_image)return status;
 memset(&candidate,0,sizeof candidate);candidate.process=p;candidate.pid=p->pid;candidate.generation=p->saw_generation;
 acquire();
 if(prepared_for(p))goto done;
 for(i=0;i<4;i++){
  fsnode_t *node=archive_source_bound_node(target_paths[i]);
  if(!node||(i==0&&node!=actual_image))goto done;
  candidate.nodes[i]=node;candidate.data[i]=node->data;candidate.sizes[i]=node->size;
 }
 if(!blk_authority_roles_ready())goto done;
 for(i=0;i<OWNERS;i++)if(!prepared[i].process){g=&prepared[i];break;}
 if(!g){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}
 *g=candidate;status=STATUS_SUCCESS;
done:mutex_unlock(&lock);return status;
}
int setup_target_prepared(process_t *p)
{
 int okay=0;if(!p||p->teardown)return 0;acquire();okay=preparation_valid(prepared_for(p));mutex_unlock(&lock);return okay;
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
  (!o->service&&setup_native_release_pair(infos))||blk_authority_pin_archive(o,a->cap,&a->info,&pins[0])||
  blk_authority_pin_archive(o,b->cap,&b->info,&pins[1]))return -1;
 return 0;
}
static int claim_matches(struct owner *o,const shz_native_call_v1 *r)
{return o&&o->claim&&r->handle==o->claim_token&&!memcmp(&r->target,&o->target,sizeof o->target);}
static void tidy(struct owner *o)
{if(o&&!o->claim&&!o->sources[0].cap&&!o->sources[1].cap)memset(o,0,sizeof *o);}
_Static_assert(sizeof(blk_authority_identity_t)==sizeof(shz_native_target_v1),"target wire/kernel identity");
static int32_t storage_syscall(process_t *p,uint64_t user,uint64_t bytes,unsigned service)
{
 shz_native_call_v1 r;struct owner *o=0;struct source *s=0;blk_authority_source_t pins[2];
 blk_authority_identity_t identity;unsigned i;int rc=-1;int32_t status=STATUS_ACCESS_DENIED;
 uint64_t new_token=0;unsigned created_source=0,created_claim=0;
 if(!p||p->teardown)return STATUS_ACCESS_DENIED;
 if(bytes!=sizeof r)return STATUS_INFO_LENGTH_MISMATCH;
 if(copy_from_user(p,&r,user,sizeof r))return STATUS_ACCESS_VIOLATION;
 if(r.version!=SHZ_NATIVE_SYS_VERSION||r.bytes!=sizeof r||r.reserved||r.tail_reserved||r.operation>SHZ_NATIVE_RELEASE_INFO)
  return STATUS_INVALID_PARAMETER;
 acquire();if(p->teardown||(service&&!preparation_valid(prepared_for(p))))goto done;
 if(r.operation==SHZ_NATIVE_CAPS){
  r.max_source_bytes=SHZ_NATIVE_KERNEL_SOURCE_MAX;r.max_io_bytes=SHZ_NATIVE_SYS_IO_MAX;
  r.producer_admission_available=service?(unsigned)blk_authority_roles_ready():setup_native_release_state();status=STATUS_SUCCESS;goto publish;
 }
 if(r.operation==SHZ_NATIVE_RELEASE_INFO){
  unsigned role=r.index;
  if(service){status=STATUS_INVALID_PARAMETER;goto done;}
  if(role>1){status=STATUS_INVALID_PARAMETER;goto done;}
  /* A readonly reply contains no caller-supplied apparent handles/authority. */
  memset(&r,0,sizeof r);r.version=SHZ_NATIVE_SYS_VERSION;r.bytes=sizeof r;
  r.operation=SHZ_NATIVE_RELEASE_INFO;r.index=role;
  if(setup_native_release_info(role,&r.source.bytes,r.source.sha256))goto done;
  status=STATUS_SUCCESS;goto publish;
 }
 o=owner_for(p,r.operation==SHZ_NATIVE_OPEN,service);if(!o){status=STATUS_INVALID_HANDLE;goto done;}
 switch(r.operation){
 case SHZ_NATIVE_OPEN:
  if(o->claim||!terminated(r.path,sizeof r.path)||!r.path[0]){status=STATUS_INVALID_PARAMETER;break;}
  if(service){
   fsnode_t *node=archive_source_bound_node(r.path);
   struct prepared_target *g=prepared_for(p);
   if(!node||!g||(node!=g->nodes[1]&&node!=g->nodes[2]))break;
  }
  for(i=0;i<2;i++)if(!o->sources[i].cap){s=&o->sources[i];break;}
  if(!s||!(new_token=token())){status=STATUS_INSUFFICIENT_RESOURCES;break;}
  rc=archive_source_open(o,r.path,&s->cap,&s->info);
  if(!rc){s->token=new_token;r.handle=new_token;memcpy(&r.source,&s->info,sizeof r.source);created_source=1;
   if(service){s->role=archive_source_bound_node(r.path)==prepared_for(p)->nodes[1]?0u:1u;}
  }
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
   if(!rc)rc=service?(s->role==r.index?0:-1):setup_native_release_source(&info,r.index);
   if(!rc){s->admitted=1;s->role=r.index;memcpy(&r.source,&info,sizeof r.source);}
  }
  else if(r.operation==SHZ_NATIVE_INFO){archive_source_info_t info;rc=archive_source_info(o,s->cap,&s->info,&info);if(!rc)memcpy(&r.source,&info,sizeof r.source);}
  else if(r.operation==SHZ_NATIVE_CLOSE){rc=archive_source_close(o,s->cap,&s->info);if(!rc)memset(s,0,sizeof *s);}
  else{
   if(!r.length||r.length>SHZ_NATIVE_SYS_IO_MAX){status=STATUS_INVALID_PARAMETER;break;}
   if(transfer_buffer()){status=STATUS_INSUFFICIENT_RESOURCES;break;}
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
   if(!r.length||r.length>SHZ_NATIVE_SYS_IO_MAX||r.length%512){status=STATUS_INVALID_PARAMETER;break;}
   if(transfer_buffer()){status=STATUS_INSUFFICIENT_RESOURCES;break;}
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
 if(bounce)memset(bounce,0,SHZ_NATIVE_SYS_IO_MAX);
 tidy(o);mutex_unlock(&lock);return status;
}
int32_t setup_native_syscall(process_t *p,uint64_t user,uint64_t bytes)
{return storage_syscall(p,user,bytes,0);}
int32_t setup_target_syscall(process_t *p,uint64_t user,uint64_t bytes)
{return storage_syscall(p,user,bytes,1);}
_Static_assert(sizeof(shz_setup_target_call_v1)==sizeof(shz_native_call_v1),"shared storage wire size");
_Static_assert(offsetof(shz_setup_target_call_v1,target_authority_available)==offsetof(shz_native_call_v1,producer_admission_available),"shared capabilities offset");
void setup_native_process_teardown(process_t *p)
{
 unsigned i,j;if(!p)return;acquire();
 for(i=0;i<OWNERS;i++){
  struct owner *o=&owners[i];
  if(o->retired||o->process!=p||o->pid!=p->pid||o->generation!=p->saw_generation)continue;
  if(o->claim&&!blk_authority_release(o,o->claim,&o->target)){o->claim=0;o->claim_token=0;}
  for(j=0;j<2;j++)if(o->sources[j].cap&&!archive_source_close(o,o->sources[j].cap,&o->sources[j].info))memset(&o->sources[j],0,sizeof o->sources[j]);
  /* Poisoned claim retains snapshot refs and kernel owner identity until reboot. */
  if(o->claim||o->sources[0].cap||o->sources[1].cap){o->retired=1;o->process=0;}
  else memset(o,0,sizeof *o);
 }
 for(i=0;i<OWNERS;i++)if(prepared[i].process==p&&prepared[i].pid==p->pid&&prepared[i].generation==p->saw_generation)
   memset(&prepared[i],0,sizeof prepared[i]);
 mutex_unlock(&lock);
}
