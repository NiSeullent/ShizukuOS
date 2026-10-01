/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_softpipe_raster.h"
#include <string.h>
#include <float.h>
#ifndef _WIN32
#include <fenv.h>
#endif
_Static_assert(sizeof(float)==4&&sizeof(double)==8&&FLT_RADIX==2&&FLT_MANT_DIG==24&&DBL_MANT_DIG==53,"IEEE float profile");
_Static_assert(sizeof(m98_r_vertex)==76&&sizeof(m98_r_stats)==24,"fixed raster records");
#ifdef _WIN32
_Static_assert(sizeof(m98_r_surface)==32&&sizeof(m98_r_ops)==24&&sizeof(m98_r_draw)==420,"native x86 raster ABI");
#endif
static volatile uint32_t locked;
typedef struct {
#ifdef _WIN32
 unsigned char state[108];
#else
 fenv_t state;
#endif
} fp_scope;
static void fp_enter(fp_scope *s){
#ifdef _WIN32
 unsigned short cw=0x037f;__asm__ volatile("fnsave %0\n\tfwait\n\tfldcw %1":"=m"(s->state):"m"(cw):"memory");
#else
 feholdexcept(&s->state);fesetround(FE_TONEAREST);
#endif
}
static void fp_leave(fp_scope *s){
#ifdef _WIN32
 __asm__ volatile("frstor %0"::"m"(s->state):"memory");
#else
 fesetenv(&s->state);
#endif
}
/* A callback cannot change the arithmetic mode or x87 stack used afterwards. */
static void *allocate(const m98_r_ops *ops,size_t bytes){fp_scope fp;void *p;fp_enter(&fp);p=ops->allocate(ops->user,bytes);fp_leave(&fp);return p;}
static void deallocate(const m98_r_ops *ops,void *p){fp_scope fp;fp_enter(&fp);ops->deallocate(ops->user,p);fp_leave(&fp);}
static int shader(const m98_r_ops *ops,uint32_t cookie,const m98_sp_io *io,m98_sp_result *result){fp_scope fp;int rc;fp_enter(&fp);rc=ops->run_shader(cookie,io,result);fp_leave(&fp);return rc;}
static int overlap(uintptr_t a,size_t an,uintptr_t b,size_t bn){return a<b+bn&&b<a+an;}
static int finite(float v){union {float f;uint32_t u;} b;b.f=v;return (b.u&0x7f800000u)!=0x7f800000u;}
static unsigned bits(unsigned v){unsigned n=0;while(v){n+=v&1;v>>=1;}return n;}
static int64_t edge(const m98_r_vertex *a,const m98_r_vertex *b,int32_t x,int32_t y){return (int64_t)(b->x16-a->x16)*(y-a->y16)-(int64_t)(b->y16-a->y16)*(x-a->x16);}
static int inclusive(const m98_r_vertex *a,const m98_r_vertex *b){return b->y16<a->y16||(b->y16==a->y16&&b->x16>a->x16);}
static unsigned coverage(const m98_r_draw *d,unsigned x,unsigned y){unsigned lane,mask=0,j;
 for(lane=0;lane<4;lane++){unsigned px=x+(lane&1),py=y+(lane>>1);int inside=1;if(px>=d->surface.width||py>=d->surface.height)continue;
  for(j=0;j<3;j++){const m98_r_vertex *a=&d->vertex[j],*b=&d->vertex[(j+1)%3];int64_t e=edge(a,b,(int32_t)(16*px+8),(int32_t)(16*py+8));if(e<0||(e==0&&!inclusive(a,b))){inside=0;break;}}
  if(inside)mask|=1u<<lane;
 }return mask;
}
static int validate(const m98_r_draw *d,const m98_r_ops *ops,const m98_r_stats *stats){unsigned i,j,k;const m98_r_surface *s=&d->surface;uint32_t color_need,depth_need;size_t depth_bytes;uintptr_t ca=(uintptr_t)s->color,da=(uintptr_t)s->depth,sa=(uintptr_t)stats;
 if(d->abi!=1||d->reserved||!d->shader_cookie||ops->abi!=1||ops->reserved||!ops->allocate||!ops->deallocate||!ops->run_shader)return M98_R_INVALID;
 if(!s->width||!s->height||!s->color||!s->depth||((uintptr_t)s->depth%sizeof(float)))return M98_R_INVALID;
 if(s->width>M98_R_MAX_WIDTH||s->height>M98_R_MAX_HEIGHT||d->varying_count>M98_SP_MAX_INPUTS||!d->quad_budget||d->quad_budget>M98_R_MAX_QUADS)return M98_R_LIMIT;
 if(s->color_stride<4*s->width||s->color_stride>M98_R_MAX_COLOR_STRIDE||s->depth_stride<s->width||s->depth_stride>M98_R_MAX_DEPTH_STRIDE)return M98_R_INVALID;
 color_need=(s->height-1)*s->color_stride+4*s->width;depth_need=(s->height-1)*s->depth_stride+s->width;
 if(s->color_capacity<color_need||s->depth_capacity<depth_need)return M98_R_INVALID;
 if((uint64_t)s->depth_capacity*sizeof(float)>UINTPTR_MAX)return M98_R_INVALID;
 depth_bytes=(size_t)s->depth_capacity*sizeof(float);
 if(ca>UINTPTR_MAX-s->color_capacity||da>UINTPTR_MAX-depth_bytes||sa>UINTPTR_MAX-sizeof(*stats))return M98_R_INVALID;
 if(overlap(ca,s->color_capacity,da,depth_bytes)||overlap(ca,s->color_capacity,sa,sizeof(*stats))||overlap(da,depth_bytes,sa,sizeof(*stats)))return M98_R_INVALID;
 if(d->depth_write>1)return M98_R_INVALID;
 if(d->depth_test>M98_R_DEPTH_ALWAYS||d->blend>M98_R_SOURCE_OVER)return M98_R_UNSUPPORTED;
 for(i=0;i<3;i++){
  const m98_r_vertex *v=&d->vertex[i];
  if(v->x16 < -M98_R_MAX_COORD16||v->x16>M98_R_MAX_COORD16||v->y16 < -M98_R_MAX_COORD16||v->y16>M98_R_MAX_COORD16)return M98_R_LIMIT;
  if(!finite(v->z)||v->z<0||v->z>1)return M98_R_INVALID;
  for(j=0;j<d->varying_count;j++)for(k=0;k<4;k++)if(!finite(v->varying[j][k]))return M98_R_INVALID;
 }
 for(j=0;j<M98_SP_MAX_CONSTANTS;j++)for(k=0;k<4;k++)if(!finite(d->constant[j][k]))return M98_R_INVALID;
 for(i=0;i<s->height;i++)for(j=0;j<s->width;j++){float z=s->depth[i*s->depth_stride+j];if(!finite(z)||z<0||z>1)return M98_R_INVALID;}
 return M98_R_OK;
}
static int plane(const m98_r_draw *d,float a,float b,float c,int64_t area,float *a0,float *dx,float *dy){
 double x0=d->vertex[0].x16/16.0,y0=d->vertex[0].y16/16.0;
 double x1=(d->vertex[1].x16-d->vertex[0].x16)/16.0,y1=(d->vertex[1].y16-d->vertex[0].y16)/16.0;
 double x2=(d->vertex[2].x16-d->vertex[0].x16)/16.0,y2=(d->vertex[2].y16-d->vertex[0].y16)/16.0;
 double denominator=area/256.0,u=(((double)b-a)*y2-((double)c-a)*y1)/denominator;
 double v=(x1*((double)c-a)-x2*((double)b-a))/denominator,t=(double)a-u*x0-v*y0;
 if(u>FLT_MAX||u < -FLT_MAX||v>FLT_MAX||v < -FLT_MAX||t>FLT_MAX||t < -FLT_MAX)return M98_R_INVALID;
 *a0=(float)t;*dx=(float)u;*dy=(float)v;
 if(!finite(*a0)||!finite(*dx)||!finite(*dy))return M98_R_INVALID;
 return M98_R_OK;
}
static uint8_t unorm(float v){if(v<=0)return 0;if(v>=1)return 255;return (uint8_t)(v*255.0f+0.5f);}
static void source_over(uint8_t *dst,const uint8_t *src){unsigned j,sa=src[3],da=dst[3],denominator=sa*255+da*(255-sa);uint8_t result[4];
 if(!denominator){memset(dst,0,4);return;}
 for(j=0;j<3;j++){uint32_t n=(uint32_t)src[j]*sa*255+(uint32_t)dst[j]*da*(255-sa);result[j]=(uint8_t)((n+denominator/2)/denominator);}
 result[3]=(uint8_t)((denominator+127)/255);memcpy(dst,result,4);
}
static int execute(m98_r_draw *d,const m98_r_ops *ops,m98_r_stats *out){
 const m98_r_surface *s=&d->surface;int64_t area=edge(&d->vertex[0],&d->vertex[1],d->vertex[2].x16,d->vertex[2].y16);
 m98_r_stats stats={0};m98_sp_io io={0};uint8_t *color=NULL;float *depth=NULL,z0,zdx,zdy;unsigned x,y,lane,j,k,required=0;int rc;
 if(area<0){m98_r_vertex swap=d->vertex[1];d->vertex[1]=d->vertex[2];d->vertex[2]=swap;area=-area;}
 if(!area){*out=stats;return M98_R_OK;}
 for(y=0;y<s->height;y+=2)for(x=0;x<s->width;x+=2){unsigned mask=coverage(d,x,y);if(mask)required++;stats.covered_samples+=bits(mask);}
 if(required>d->quad_budget)return M98_R_LIMIT;
 if(!required){*out=stats;return M98_R_OK;}
 io.abi=1;memcpy(io.constant,d->constant,sizeof(io.constant));
 for(j=0;j<d->varying_count;j++)for(k=0;k<4;k++){rc=plane(d,d->vertex[0].varying[j][k],d->vertex[1].varying[j][k],d->vertex[2].varying[j][k],area,&io.input[j].a0[k],&io.input[j].dx[k],&io.input[j].dy[k]);if(rc)return rc;}
 rc=plane(d,d->vertex[0].z,d->vertex[1].z,d->vertex[2].z,area,&z0,&zdx,&zdy);if(rc)return rc;
 stats.scratch_bytes=8*s->width*s->height;
 color=allocate(ops,4*s->width*s->height);if(!color)return M98_R_NOMEM;
 depth=allocate(ops,sizeof(float)*s->width*s->height);if(!depth){deallocate(ops,color);return M98_R_NOMEM;}
 if((uintptr_t)depth%sizeof(float)){rc=M98_R_INVALID;goto done;}
 for(y=0;y<s->height;y++){memcpy(color+4*y*s->width,s->color+y*s->color_stride,4*s->width);memcpy(depth+y*s->width,s->depth+y*s->depth_stride,sizeof(float)*s->width);}
 for(y=0;y<s->height;y+=2)for(x=0;x<s->width;x+=2){
  unsigned mask=coverage(d,x,y),alive;float z[4];m98_sp_result result;if(!mask)continue;
  io.quad_x=(float)x+0.5f;io.quad_y=(float)y+0.5f;
  for(lane=0;lane<4;lane++)if(mask&(1u<<lane)){
   unsigned px=x+(lane&1),py=y+(lane>>1),index=py*s->width+px;float previous=depth[index];
   z[lane]=z0+zdx*((float)px+0.5f)+zdy*((float)py+0.5f);
   if(!finite(z[lane])){rc=M98_R_BAD_OUTPUT;goto done;}
   if(z[lane]<0)z[lane]=0;
   if(z[lane]>1)z[lane]=1;
   if((d->depth_test==M98_R_DEPTH_LESS&&!(z[lane]<previous))||(d->depth_test==M98_R_DEPTH_LEQUAL&&!(z[lane]<=previous))){mask&=~(1u<<lane);stats.depth_rejected_samples++;}
  }
  if(!mask)continue;
  io.live_mask=mask;memset(&result,0xa5,sizeof(result));rc=shader(ops,d->shader_cookie,&io,&result);
  if(rc){rc=rc>=1&&rc<=M98_SP_BACKEND?M98_R_SHADER_ERROR_BASE+rc:M98_R_BAD_OUTPUT;goto done;}
  stats.shader_quads++;
  if(result.output_count!=1){rc=M98_R_UNSUPPORTED;goto done;}
  if(result.live_mask&~mask){rc=M98_R_BAD_OUTPUT;goto done;}
  alive=result.live_mask;stats.discarded_samples+=bits(mask)-bits(alive);
  for(lane=0;lane<4;lane++)if(alive&(1u<<lane)){
   unsigned px=x+(lane&1),py=y+(lane>>1),index=py*s->width+px;uint8_t rgba[4];
   for(j=0;j<4;j++){float value=result.output[0][j][lane];if(!finite(value)){rc=M98_R_BAD_OUTPUT;goto done;}rgba[j]=unorm(value);}
   if(d->blend==M98_R_SOURCE_OVER)source_over(color+4*index,rgba);else memcpy(color+4*index,rgba,4);
   if(d->depth_write)depth[index]=z[lane];
   stats.written_samples++;
  }
 }
 rc=M98_R_OK;
done:
 if(!rc){for(y=0;y<s->height;y++){memcpy(s->color+y*s->color_stride,color+4*y*s->width,4*s->width);memcpy(s->depth+y*s->depth_stride,depth+y*s->width,sizeof(float)*s->width);}*out=stats;}
 deallocate(ops,depth);deallocate(ops,color);return rc;
}
int m98_raster_draw(const m98_r_draw *input,const m98_r_ops *table,m98_r_stats *stats){m98_r_draw draw;m98_r_ops ops;fp_scope fp;int rc;
 if(!input||!table||!stats)return M98_R_INVALID;
 if(__sync_val_compare_and_swap(&locked,0,1))return M98_R_BUSY;
 fp_enter(&fp);draw=*input;ops=*table;rc=validate(&draw,&ops,stats);if(!rc)rc=execute(&draw,&ops,stats);fp_leave(&fp);__sync_lock_release(&locked);return rc;
}
uint32_t m98_raster_abi(void){return 1;}
#ifdef _WIN32
int __attribute__((stdcall)) m98_raster_dll_entry(void *module,unsigned long reason,void *reserved){(void)module;(void)reason;(void)reserved;return 1;}
#endif
