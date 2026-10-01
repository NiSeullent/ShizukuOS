/* SPDX-License-Identifier: GPL-2.0-only
 * Original project resource ownership/state code. Reviewed, not copied:
 * Wine11.0 db11d0fe6a169c457e23d007e20404643d067aa8 wined3d/texture.c;
 * ReactOS9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8 directx/wine/ddraw/surface.c.
 * Rendering uses the real independently pinned Mesa26.2.3 TGSI port.
 */
#include "backend.h"
#include "fp64.h"
#include <string.h>
typedef struct {
 ntg_resource id; uint32_t refs,bindings,mapped,kind,width,height,pitch,shader;
 void *pixels; size_t bytes;
} object;
typedef struct {
 uint32_t id; size_t bytes; m98_sp_callbacks cb;
 object objects[NTG_MAX_RESOURCES]; ntg_resource binding[3];
} device;
static device devices[NTG_MAX_DEVICES];
static volatile uint32_t locked;
static uint32_t device_serial;
static uint64_t resource_serial;
static ntg_fp_scope caller_fp;
static int enter(void){if(__sync_val_compare_and_swap(&locked,0,1))return 0;ntg_fp_enter(&caller_fp);return 1;}
static void leave(void){ntg_fp_leave(&caller_fp);__sync_lock_release(&locked);}
static device *find_device(uint32_t id){unsigned i;for(i=0;i<NTG_MAX_DEVICES;i++)if(id&&devices[i].id==id)return &devices[i];return NULL;}
/* Isolate every nested provider, as well as the external caller. Mesa's
 * arithmetic must not inherit a callback's changed rounding/mask state. */
static void *provider_allocate(void *user,size_t bytes){device *d=user;ntg_fp_scope fp;void *p;ntg_fp_enter(&fp);p=d->cb.allocate(d->cb.user,bytes);ntg_fp_leave(&fp);return p;}
static void provider_deallocate(void *user,void *p){device *d=user;ntg_fp_scope fp;ntg_fp_enter(&fp);d->cb.deallocate(d->cb.user,p);ntg_fp_leave(&fp);}
static int provider_math(void *user,uint32_t op,double x,double y,double *out){device *d=user;ntg_fp_scope fp;int rc;ntg_fp_enter(&fp);rc=d->cb.math(d->cb.user,op,x,y,out);ntg_fp_leave(&fp);return rc;}
static object *find(device *d,ntg_resource id){unsigned i;if(!d||!id)return NULL;for(i=0;i<NTG_MAX_RESOURCES;i++)if(d->objects[i].id==id)return &d->objects[i];return NULL;}
static object *slot(device *d){unsigned i;for(i=0;i<NTG_MAX_RESOURCES;i++)if(!d->objects[i].id)return &d->objects[i];return NULL;}
static int finite(float x){union{float f;uint32_t u;}b;b.f=x;return (b.u&0x7f800000u)!=0x7f800000u;}
static void dispose(device *d,object *o){
 if(o->shader)m98_sp_close(&o->shader);
 if(o->pixels){provider_deallocate(d,o->pixels);d->bytes-=o->bytes;}
 memset(o,0,sizeof(*o));
}
static void unbind(device *d){unsigned i;for(i=0;i<3;i++){object *o=find(d,d->binding[i]);d->binding[i]=0;if(o){o->bindings--;if(!o->refs&&!o->bindings)dispose(d,o);}}}
uint32_t ntg_abi(void){return 1;}
int ntg_create(const m98_sp_callbacks *input,uint32_t *out){m98_sp_callbacks cb;unsigned i;int rc=NTG_LIMIT;
 if(!input||!out)return NTG_INVALID;if(!enter())return NTG_BUSY;cb=*input;
 if(cb.abi!=1||cb.reserved||!cb.allocate||!cb.deallocate||!cb.math){rc=NTG_INVALID;goto done;}
 if(device_serial==UINT32_MAX)goto done;
 for(i=0;i<NTG_MAX_DEVICES;i++)if(!devices[i].id){devices[i].cb=cb;devices[i].id=++device_serial;*out=devices[i].id;rc=NTG_OK;break;}
done:leave();return rc;
}
int ntg_destroy(uint32_t *id){device *d;unsigned i;int rc=NTG_OK;
 if(!id)return NTG_INVALID;if(!enter())return NTG_BUSY;if(!*id)goto done;
 d=find_device(*id);if(!d){rc=NTG_STALE;goto done;}
 for(i=0;i<NTG_MAX_RESOURCES;i++)if(d->objects[i].mapped){rc=NTG_BUSY;goto done;}
 unbind(d);for(i=0;i<NTG_MAX_RESOURCES;i++)if(d->objects[i].id)dispose(d,&d->objects[i]);memset(d,0,sizeof(*d));*id=0;
done:leave();return rc;
}
int ntg_texture_create(uint32_t id,const ntg_texture_desc *input,ntg_resource *out){ntg_texture_desc desc;device *d;object *o;void *pixels;size_t bytes;uint32_t pitch;int rc=NTG_INVALID;
 if(!input||!out)return rc;if(!enter())return NTG_BUSY;desc=*input;
 d=find_device(id);if(!d){rc=NTG_STALE;goto done;}
 if(desc.abi!=1||!desc.width||!desc.height)goto done;
 if(desc.width>NTG_MAX_SIZE||desc.height>NTG_MAX_SIZE){rc=NTG_LIMIT;goto done;}
 if((desc.format!=NTG_RGBA8&&desc.format!=NTG_D32)||desc.flags||desc.mip_levels!=1||desc.array_size!=1||desc.samples!=1){rc=NTG_UNSUPPORTED;goto done;}
 pitch=desc.pitch?desc.pitch:desc.width*4;
 if(pitch<desc.width*4||pitch>4096||(desc.format==NTG_D32&&pitch%4))goto done;
 bytes=(size_t)pitch*desc.height;
 if(bytes>NTG_TEXTURE_MEMORY_LIMIT-d->bytes||resource_serial==UINT64_MAX||!(o=slot(d))){rc=NTG_LIMIT;goto done;}
 pixels=provider_allocate(d,bytes);if(!pixels){rc=NTG_NOMEM;goto done;}
 if(desc.format==NTG_D32&&(uintptr_t)pixels%sizeof(float)){provider_deallocate(d,pixels);goto done;}
 memset(pixels,0,bytes);o->id=++resource_serial;o->refs=1;o->kind=desc.format;o->width=desc.width;o->height=desc.height;o->pitch=pitch;o->pixels=pixels;o->bytes=bytes;d->bytes+=bytes;*out=o->id;rc=NTG_OK;
done:leave();return rc;
}
int ntg_shader_create(uint32_t id,const m98_sp_program *input,ntg_resource *out){device *d;object *o;uint32_t cookie=0;int rc;m98_sp_callbacks cb={0};
 if(!input||!out)return NTG_INVALID;if(!enter())return NTG_BUSY;
 d=find_device(id);if(!d){rc=NTG_STALE;goto done;}
 if(resource_serial==UINT64_MAX||!(o=slot(d))){rc=NTG_LIMIT;goto done;}
 cb.abi=1;cb.user=d;cb.allocate=provider_allocate;cb.deallocate=provider_deallocate;cb.math=provider_math;
 rc=m98_sp_open(input,&cb,&cookie);if(rc)goto done;
 o->id=++resource_serial;o->refs=1;o->kind=NTG_SHADER;o->shader=cookie;*out=o->id;
done:leave();return rc;
}
int ntg_retain(uint32_t id,ntg_resource resource){device *d;object *o;int rc=NTG_STALE;
 if(!enter())return NTG_BUSY;d=find_device(id);o=find(d,resource);if(o&&o->refs){if(o->refs==UINT32_MAX)rc=NTG_LIMIT;else{o->refs++;rc=NTG_OK;}}leave();return rc;
}
int ntg_release(uint32_t id,ntg_resource *resource){device *d;object *o;int rc=NTG_OK;
 if(!resource)return NTG_INVALID;if(!enter())return NTG_BUSY;d=find_device(id);if(!d){rc=NTG_STALE;goto done;}
 if(!*resource)goto done;o=find(d,*resource);if(!o||!o->refs){rc=NTG_STALE;goto done;}
 if(o->mapped&&o->refs==1){rc=NTG_BUSY;goto done;}o->refs--;*resource=0;if(!o->refs&&!o->bindings)dispose(d,o);
done:leave();return rc;
}
int ntg_map(uint32_t id,ntg_resource resource,ntg_mapping *out){device *d;object *o;ntg_mapping map;int rc=NTG_STALE;
 if(!out)return NTG_INVALID;if(!enter())return NTG_BUSY;d=find_device(id);o=find(d,resource);if(!o||!o->refs)goto done;
 if(o->kind==NTG_SHADER){rc=NTG_UNSUPPORTED;goto done;}if(o->mapped||o->bindings){rc=NTG_BUSY;goto done;}
 map.pixels=o->pixels;map.bytes=o->bytes;map.width=o->width;map.height=o->height;map.pitch=o->pitch;map.format=o->kind;o->mapped=1;*out=map;rc=NTG_OK;
done:leave();return rc;
}
int ntg_unmap(uint32_t id,ntg_resource resource){device *d;object *o;int rc=NTG_STALE;
 if(!enter())return NTG_BUSY;d=find_device(id);o=find(d,resource);if(o){if(!o->mapped)rc=NTG_INVALID;else{o->mapped=0;rc=NTG_OK;}}leave();return rc;
}
int ntg_clear_color(uint32_t id,ntg_resource resource,const uint8_t rgba[4]){device *d;object *o;uint8_t value[4];unsigned x,y;int rc=NTG_STALE;
 if(!rgba)return NTG_INVALID;if(!enter())return NTG_BUSY;memcpy(value,rgba,4);d=find_device(id);o=find(d,resource);if(!o)goto done;
 if(o->kind!=NTG_RGBA8){rc=NTG_UNSUPPORTED;goto done;}if(o->mapped){rc=NTG_BUSY;goto done;}
 for(y=0;y<o->height;y++)for(x=0;x<o->width;x++)memcpy((uint8_t*)o->pixels+y*o->pitch+4*x,value,4);rc=NTG_OK;
done:leave();return rc;
}
int ntg_clear_depth(uint32_t id,ntg_resource resource,float value){device *d;object *o;unsigned x,y;int rc=NTG_STALE;
 if(!enter())return NTG_BUSY;
 /* COMISS on a subnormal can set or trap the caller's unmasked denormal
  * exception. Perform every FP comparison only inside the owned scope. */
 if(!finite(value)||value<0||value>1){rc=NTG_INVALID;goto done;}
 d=find_device(id);o=find(d,resource);if(!o)goto done;
 if(o->kind!=NTG_D32){rc=NTG_UNSUPPORTED;goto done;}if(o->mapped){rc=NTG_BUSY;goto done;}
 for(y=0;y<o->height;y++)for(x=0;x<o->width;x++)((float*)o->pixels)[y*(o->pitch/4)+x]=value;rc=NTG_OK;
done:leave();return rc;
}
int ntg_copy(uint32_t id,ntg_resource source,ntg_resource target){device *d;object *s,*t;unsigned y;int rc=NTG_STALE;
 if(!enter())return NTG_BUSY;d=find_device(id);s=find(d,source);t=find(d,target);if(!s||!t)goto done;
 if(s->kind==NTG_SHADER||s->kind!=t->kind){rc=NTG_UNSUPPORTED;goto done;}
 if(s->width!=t->width||s->height!=t->height){rc=NTG_INVALID;goto done;}if(s->mapped||t->mapped){rc=NTG_BUSY;goto done;}
 if(s!=t)for(y=0;y<s->height;y++)memcpy((uint8_t*)t->pixels+y*t->pitch,(uint8_t*)s->pixels+y*s->pitch,4*s->width);rc=NTG_OK;
done:leave();return rc;
}
int ntg_bind(uint32_t id,ntg_resource color,ntg_resource depth,ntg_resource shader){device *d;object *o[3];unsigned i;int rc=NTG_STALE;
 if(!enter())return NTG_BUSY;d=find_device(id);if(!d)goto done;
 if(!color&&!depth&&!shader){unbind(d);rc=NTG_OK;goto done;}
 o[0]=find(d,color);o[1]=find(d,depth);o[2]=find(d,shader);
 if(!o[0]||!o[1]||!o[2]||!o[0]->refs||!o[1]->refs||!o[2]->refs)goto done;
 if(o[0]->kind!=NTG_RGBA8||o[1]->kind!=NTG_D32||o[2]->kind!=NTG_SHADER){rc=NTG_UNSUPPORTED;goto done;}
 if(o[0]->width!=o[1]->width||o[0]->height!=o[1]->height){rc=NTG_INVALID;goto done;}
 for(i=0;i<3;i++)if(o[i]->mapped){rc=NTG_BUSY;goto done;}
 /* Retain the incoming bindings before dropping the previous ones. */
 for(i=0;i<3;i++)o[i]->bindings++;unbind(d);
 d->binding[0]=color;d->binding[1]=depth;d->binding[2]=shader;rc=NTG_OK;
done:leave();return rc;
}
static int raster_status(int rc){
 if(rc>=M98_R_SHADER_ERROR_BASE+M98_SP_INVALID&&rc<=M98_R_SHADER_ERROR_BASE+M98_SP_BACKEND)return rc-M98_R_SHADER_ERROR_BASE;
 switch(rc){case M98_R_OK:return NTG_OK;case M98_R_INVALID:return NTG_INVALID;case M98_R_LIMIT:return NTG_LIMIT;case M98_R_NOMEM:return NTG_NOMEM;case M98_R_UNSUPPORTED:return NTG_UNSUPPORTED;case M98_R_BUSY:return NTG_BUSY;default:return NTG_BACKEND;}
}
int ntg_draw(uint32_t id,const ntg_draw_desc *input,m98_r_stats *stats){device *d;object *c,*z,*s;ntg_draw_desc desc;m98_r_draw draw={0};m98_r_ops ops={0};int rc=NTG_INVALID;
 if(!input||!stats)return rc;if(!enter())return NTG_BUSY;desc=*input;d=find_device(id);if(!d){rc=NTG_STALE;goto done;}
 if(desc.abi!=1||desc.reserved[0]||desc.reserved[1])goto done;
 c=find(d,d->binding[0]);z=find(d,d->binding[1]);s=find(d,d->binding[2]);if(!c||!z||!s){rc=NTG_STALE;goto done;}
 draw.abi=1;draw.shader_cookie=s->shader;draw.varying_count=desc.varying_count;draw.quad_budget=desc.quad_budget;draw.depth_test=desc.depth_test;draw.depth_write=desc.depth_write;draw.blend=desc.blend;
 draw.surface.width=c->width;draw.surface.height=c->height;draw.surface.color=c->pixels;draw.surface.color_stride=c->pitch;draw.surface.color_capacity=(uint32_t)c->bytes;draw.surface.depth=z->pixels;draw.surface.depth_stride=z->pitch/4;draw.surface.depth_capacity=(uint32_t)(z->bytes/4);
 memcpy(draw.vertex,desc.vertex,sizeof(draw.vertex));memcpy(draw.constant,desc.constant,sizeof(draw.constant));
 ops.abi=1;ops.user=d;ops.allocate=provider_allocate;ops.deallocate=provider_deallocate;ops.run_shader=m98_sp_run;
 rc=raster_status(m98_raster_draw(&draw,&ops,stats));
done:leave();return rc;
}
#ifdef _WIN32
int __attribute__((stdcall)) ntg_dll_entry(void *module,unsigned long reason,void *reserved){(void)module;(void)reason;(void)reserved;return 1;}
#endif
/* Genuine immutable relocated metadata; no borrowed OS/CRT imports. */
static const char profile[]="NTG private software resources, genuine Mesa TGSI";
const char *const ntg_profile=profile;
