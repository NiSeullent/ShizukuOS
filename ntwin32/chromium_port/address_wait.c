/* SPDX-License-Identifier: GPL-2.0-only */
#include "address_wait.h"
#define AW_MAGIC 0x41575731u
static int fail(uint32_t *error,uint32_t value){if(error)*error=value;return 0;}
static uint32_t native_error(aw_context *c){uint32_t e=c->ops.error(c->ops.opaque);return e?e:AW_BAD_BACKEND;}
int aw_init(aw_context *c,const aw_ops *ops)
{
 unsigned i;aw_ops saved;
 if(!c||!ops||!ops->enter||!ops->leave||!ops->create||!ops->signal||!ops->wait||!ops->close||!ops->error)return 0;
 saved=*ops;for(i=0;i<sizeof(*c);i++)((unsigned char *)c)[i]=0;
 c->ops=saved;c->head=c->tail=-1;c->magic=AW_MAGIC;return 1;
}
static int equal(volatile void *address,const void *compare,size_t size)
{
 const volatile unsigned char *a=address;const unsigned char *b=compare;size_t i;
 for(i=0;i<size;i++)if(a[i]!=b[i])return 0;return 1;
}
static void unlink_slot(aw_context *c,unsigned index)
{
 int prev=-1,it=c->head;while(it!=(int)index){prev=it;it=c->slots[it].next;}
 if(prev<0)c->head=c->slots[index].next;else c->slots[prev].next=c->slots[index].next;
 if(c->tail==(int)index)c->tail=prev;c->active--;
}
int aw_wait(aw_context *c,volatile void *address,const void *compare,size_t size,uint32_t timeout,uint32_t *error)
{
 unsigned i;uint32_t result,wait_error=0,close_error=0;int success;aw_slot *slot;
 if(error)*error=0;
 if(!c||c->magic!=AW_MAGIC||!address||!compare||(size!=1&&size!=2&&size!=4&&size!=8))return fail(error,AW_INVALID_PARAMETER);
 c->ops.enter(c->ops.opaque);
 if(!equal(address,compare,size)){c->ops.leave(c->ops.opaque);return 1;}
 if(!timeout){c->ops.leave(c->ops.opaque);return fail(error,AW_TIMEOUT);}
 for(i=0;i<AW_CAPACITY;i++)if(!c->slots[i].state)break;
 if(i==AW_CAPACITY){c->ops.leave(c->ops.opaque);return fail(error,AW_NO_MEMORY);}
 slot=&c->slots[i];slot->event=c->ops.create(c->ops.opaque);
 if(!slot->event){uint32_t e=native_error(c);c->ops.leave(c->ops.opaque);return fail(error,e);}
 slot->state=1;slot->address=address;slot->next=-1;slot->signaled=0;
 if(c->tail<0)c->head=(int)i;else c->slots[c->tail].next=(int)i;
 c->tail=(int)i;c->active++;
 c->ops.leave(c->ops.opaque);
 result=c->ops.wait(c->ops.opaque,slot->event,timeout);
 if(result==AW_WAIT_FAILED)wait_error=native_error(c);
 else if(result!=0&&result!=258)wait_error=AW_BAD_BACKEND;
 c->ops.enter(c->ops.opaque);
 /* Wake and timeout linearize under the same lock. A wake committed before
  * unlinking may turn a simultaneous timeout into an allowed early wake. */
 success=!wait_error&&(result==0||slot->signaled);
 unlink_slot(c,i);slot->state=2;slot->address=0;
 if(!c->ops.close(c->ops.opaque,slot->event)){close_error=native_error(c);c->retained++;}
 else {slot->event=0;slot->state=0;}
 c->ops.leave(c->ops.opaque);
 if(wait_error)return fail(error,wait_error);
 if(close_error)return fail(error,close_error);
 return success?1:fail(error,AW_TIMEOUT);
}
int aw_wake(aw_context *c,const void *address,int all,uint32_t *error)
{
 int it,okay=1;uint32_t first_error=0;
 if(error)*error=0;
 if(!c||c->magic!=AW_MAGIC||!address||(all!=0&&all!=1))return fail(error,AW_INVALID_PARAMETER);
 c->ops.enter(c->ops.opaque);
 for(it=c->head;it>=0;it=c->slots[it].next){aw_slot *s=&c->slots[it];
  if(s->address!=address||s->signaled)continue;
  if(c->ops.signal(c->ops.opaque,s->event))s->signaled=1;
  else {okay=0;if(!first_error)first_error=native_error(c);}
  if(!all)break;
 }
 c->ops.leave(c->ops.opaque);return okay?1:fail(error,first_error);
}
int aw_cleanup(aw_context *c,int quiescent,uint32_t *error)
{
 unsigned i;uint32_t first=0;
 if(error)*error=0;
 if(!c||c->magic!=AW_MAGIC)return fail(error,AW_INVALID_PARAMETER);
 if(quiescent!=1)return fail(error,AW_BUSY);
 c->ops.enter(c->ops.opaque);
 if(c->active){c->ops.leave(c->ops.opaque);return fail(error,AW_BUSY);}
 for(i=0;i<AW_CAPACITY;i++)if(c->slots[i].state==2){aw_slot *s=&c->slots[i];
  if(c->ops.close(c->ops.opaque,s->event)){s->event=0;s->state=0;c->retained--;}
  else if(!first)first=native_error(c);
 }
 c->ops.leave(c->ops.opaque);return first?fail(error,first):1;
}
unsigned aw_pending(aw_context *c)
{
 unsigned count;if(!c||c->magic!=AW_MAGIC)return 0;
 c->ops.enter(c->ops.opaque);count=c->active;c->ops.leave(c->ops.opaque);return count;
}
