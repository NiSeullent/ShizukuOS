/* SPDX-License-Identifier: GPL-2.0-only -- real module-owned resource registry. */
#include "bridge.h"
#include "sha256.h"
#include "graph_pins.h"
static void zero(void *v,uint32_t n){uint8_t *p=v;while(n--)*p++=0;}
static int valid(const nrb_registry *r){return r&&r->self==r&&r->initialized&&r->adapter.self==&r->adapter;}
int nrb_init(nrb_registry *r,nra_read read,nra_error error,void *opaque)
{if(!r)return 0;zero(r,sizeof(*r));if(!nra_init(&r->adapter,read,error,opaque))return 0;r->self=r;r->initialized=1;return 1;}
int nrb_owned(const nrb_registry *r,const void *owner,const void *base)
{unsigned i;if(!valid(r)||!owner||!base)return 0;
 for(i=0;i<NRA_MODULES;i++)if(r->owner[i]==owner&&r->base[i]==base)return 1;return 0;}
int nrb_add(nrb_registry *r,const void *owner,const np_image *image,const void *base,int root,const char **error)
{
 unsigned i,slot=NRA_MODULES;
 if(!valid(r)||r->bound||!owner||!image||!base)return 0;
 for(i=0;i<NRA_MODULES;i++){if(r->owner[i]==owner||r->base[i]==base)return 0;if(!r->owner[i]&&slot==NRA_MODULES)slot=i;}
 if(slot==NRA_MODULES||!nr_parse(image,&r->resource[slot],error))return 0;
 if(!nra_register(&r->adapter,&r->resource[slot],base,image->size,root)){zero(&r->resource[slot],sizeof(r->resource[slot]));return 0;}
 r->owner[slot]=owner;r->base[slot]=base;return 1;
}
int nrb_remove(nrb_registry *r,const void *owner)
{
 unsigned i;if(!valid(r)||!owner)return 0;
 for(i=0;i<NRA_MODULES;i++)if(r->owner[i]==owner){
  if(!nra_unregister(&r->adapter,r->base[i]))return 0;
  r->owner[i]=0;r->base[i]=0;zero(&r->resource[i],sizeof(r->resource[i]));return 1;
 }return 0;
}
int nrb_publish(nrb_registry *r)
{if(!valid(r)||r->bound||!nra_bind(&r->adapter))return 0;r->bound=1;return 1;}
int nrb_dispose(nrb_registry *r)
{
 unsigned i;if(!r)return 0;if(!r->initialized)return r->self==r||!r->self;
 if(!valid(r))return 0;
 for(i=0;i<NRA_MODULES;i++)if(r->owner[i]&&!nrb_remove(r,r->owner[i]))return 0;
 if(r->bound)nra_unbind(&r->adapter);r->bound=0;r->initialized=0;return 1;
}
static int same_name(const char *a,const char *b)
{while(*a&&*b){unsigned x=(uint8_t)*a++,y=(uint8_t)*b++;if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;if(x!=y)return 0;}return *a==*b;}
int nrb_verify_file(const char *name,const void *file,uint32_t bytes)
{
 unsigned i,j;uint8_t digest[32];char actual[65];sha256_ctx hash;
 for(i=0;i<NRB_GRAPH_FILES;i++)if(same_name(name,nrb_graph_pins[i].name)&&bytes==nrb_graph_pins[i].bytes){
  sha256_init(&hash);sha256_update(&hash,file,bytes);sha256_final(&hash,digest);sha256_hex(digest,actual);
  for(j=0;j<64;j++)if(actual[j]!=nrb_graph_pins[i].sha[j])return 0;return 1;
 }return 0;
}
