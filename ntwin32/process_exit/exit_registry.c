/* SPDX-License-Identifier: GPL-2.0-only */
#include "exit_registry.h"
#define PX_MAGIC UINT32_C(0x50584531)
static int fail(uint32_t *e,uint32_t n){if(e)*e=n;return 0;}
int px_init(px_registry *r,const px_ops *ops)
{
 size_t i;px_ops copy;
 if(!r||!ops||!ops->load||!ops->cas||!ops->validate)return 0;
 copy=*ops;for(i=0;i<sizeof(*r);i++)((unsigned char *)r)[i]=0;
 r->ops=copy;r->magic=PX_MAGIC;r->next_snapshot=1;r->next_token=1;return 1;
}
static int begin(px_registry *r,uint32_t *old,uint32_t *e)
{
 if(e)*e=0;if(!r||r->magic!=PX_MAGIC)return fail(e,PX_INVALID);
 if(r->ops.cas(r->ops.opaque,&r->mutating,0,1))return fail(e,PX_BUSY);
 *old=r->ops.load(r->ops.opaque,&r->current);
 if(*old&PX_CLOSED){r->ops.cas(r->ops.opaque,&r->mutating,1,0);return fail(e,PX_BUSY);}
 return 1;
}
static int finish(px_registry *r,uint32_t old,uint32_t fresh,uint32_t *e)
{
 uint32_t seen=r->ops.cas(r->ops.opaque,&r->current,old,fresh);
 r->ops.cas(r->ops.opaque,&r->mutating,1,0);
 return seen==old?1:fail(e,PX_BUSY);
}
static int cancel(px_registry *r,uint32_t *e,uint32_t code)
{r->ops.cas(r->ops.opaque,&r->mutating,1,0);return fail(e,code);}
int px_register(px_registry *r,px_callback cb,void *context,size_t bytes,uint32_t *token,uint32_t *e)
{
 uint32_t old,fresh,i,id;px_snapshot *out,*in;
 if(e)*e=0;if(!token||!cb||!context||!bytes)return fail(e,PX_INVALID);
 if(!begin(r,&old,e))return 0;
 if(!r->ops.validate(r->ops.opaque,cb,context,bytes))return cancel(r,e,PX_INVALID);
 in=&r->snapshots[old];
 if(in->count==PX_CALLBACKS||r->next_snapshot==PX_SNAPSHOTS||!r->next_token)return cancel(r,e,PX_NO_MEMORY);
 fresh=r->next_snapshot++;id=r->next_token++;out=&r->snapshots[fresh];
 for(i=0;i<in->count;i++)out->records[i]=in->records[i];
 out->records[i].callback=cb;out->records[i].context=context;out->records[i].bytes=bytes;out->records[i].token=id;
 out->count=in->count+1;
 if(!finish(r,old,fresh,e))return 0;*token=id;return 1;
}
int px_unregister(px_registry *r,uint32_t token,uint32_t *e)
{
 uint32_t old,fresh,i,j=0,found=0;px_snapshot *out,*in;
 if(e)*e=0;if(!token)return fail(e,PX_INVALID);if(!begin(r,&old,e))return 0;
 in=&r->snapshots[old];for(i=0;i<in->count;i++)if(in->records[i].token==token)found=1;
 if(!found)return cancel(r,e,PX_NOT_FOUND);
 if(r->next_snapshot==PX_SNAPSHOTS)return cancel(r,e,PX_NO_MEMORY);
 fresh=r->next_snapshot++;out=&r->snapshots[fresh];
 for(i=0;i<in->count;i++)if(in->records[i].token!=token)out->records[j++]=in->records[i];
 out->count=j;return finish(r,old,fresh,e);
}
int px_terminate(px_registry *r,uint32_t reason,uintptr_t reserved,uint32_t *e)
{
 uint32_t old,seen,i;const px_snapshot *s;
 if(e)*e=0;if(!r||r->magic!=PX_MAGIC||reason||!reserved)return fail(e,PX_INVALID);
 old=r->ops.load(r->ops.opaque,&r->current);
 for(i=0;i<PX_SNAPSHOTS;i++){
  if(old&PX_CLOSED)return fail(e,PX_BUSY);
  seen=r->ops.cas(r->ops.opaque,&r->current,old,old|PX_CLOSED);
  if(seen==old)break;old=seen;
 }
 if(i==PX_SNAPSHOTS)return fail(e,PX_BUSY);
 s=&r->snapshots[old];for(i=s->count;i;i--){const px_record *p=&s->records[i-1];p->callback(p->context,reason,reserved);}
 return 1;
}
uint32_t px_count(px_registry *r)
{
 uint32_t index;if(!r||r->magic!=PX_MAGIC)return 0;
 index=r->ops.load(r->ops.opaque,&r->current)&~PX_CLOSED;return r->snapshots[index].count;
}
