/* SPDX-License-Identifier: GPL-2.0-only
 * Every successful shader dispatch below calls genuine frozen Mesa TGSI.
 * Literal pixel/depth tables are independently specified, never rendered by
 * another copy of the rasterizer to manufacture the oracle.
 */
#include "m98_softpipe_raster.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#undef cosf
#undef sinf
#undef logf
#undef powf
#undef sqrtf
#undef floorf
#undef ceilf
#undef ldexpf
#undef truncf
#undef rintf
#undef fabsf
#undef fmaxf
#undef fminf
#undef lrintf
#undef ffs
#undef floor
#undef sqrt
#undef ldexp
#undef rint
#undef fmin
#undef fmax
static unsigned checks;
#define C(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL raster line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
typedef struct {uint8_t color[8+8*40+8];float depth[4+8*12+4];} frame;
typedef struct {
 void *blocks[128];unsigned calls,live,fail_at,reenter,mutate,fail_math,fp_mutate;
 m98_r_draw *draw;m98_r_ops *ops;unsigned nested;
} owner;
static owner *raster_owner,*shader_owner;
static m98_sp_io observed[64];static unsigned returned[64],dispatches,fail_quad;
static void nested(owner *o){m98_r_stats s,b;memset(&s,0xa5,sizeof(s));b=s;o->nested=m98_raster_draw(o->draw,o->ops,&s);C(o->nested==M98_R_BUSY&&!memcmp(&s,&b,sizeof(s)));}
static void *allocate(void *u,size_t n){owner *o=u;unsigned i;void *p;o->calls++;
 if(o->reenter&&o->draw)nested(o);
 if(o->mutate&&o->draw){o->draw->vertex[0].x16=INT32_MAX;o->draw->shader_cookie=0;o->ops->run_shader=NULL;o->draw->constant[0][0]=0;}
 if(o->fp_mutate){C(fegetround()==FE_TONEAREST);fesetround(FE_UPWARD);feraiseexcept(FE_INVALID);}
 if(o->calls==o->fail_at)return NULL;p=malloc(n);C(p!=NULL);for(i=0;i<128;i++)if(!o->blocks[i]){o->blocks[i]=p;break;}C(i<128);o->live++;return p;
}
static void deallocate(void *u,void *p){owner *o=u;unsigned i;if(!p)return;if(o->reenter&&o->draw)nested(o);if(o->fp_mutate){C(fegetround()==FE_TONEAREST);fesetround(FE_UPWARD);feraiseexcept(FE_INVALID);}for(i=0;i<128;i++)if(o->blocks[i]==p)break;C(i<128);o->blocks[i]=NULL;o->live--;free(p);}
static int math_provider(void *u,uint32_t op,double x,double y,double *r){owner *o=u;if(o->fail_math){fesetround(FE_UPWARD);return 1;}
 switch(op){case M98_SP_MATH_COS:*r=cos(x);break;case M98_SP_MATH_SIN:*r=sin(x);break;case M98_SP_MATH_LOG:*r=log(x);break;case M98_SP_MATH_POW:*r=pow(x,y);break;case M98_SP_MATH_SQRT:*r=sqrt(x);break;case M98_SP_MATH_FLOOR:*r=floor(x);break;case M98_SP_MATH_CEIL:*r=ceil(x);break;case M98_SP_MATH_LDEXP:*r=ldexp(x,(int)y);break;default:return 1;}return 0;}
static int dispatch(uint32_t cookie,const m98_sp_io *io,m98_sp_result *r){unsigned call=dispatches++;int rc;if(call<64)observed[call]=*io;if(raster_owner&&raster_owner->reenter)nested(raster_owner);if(raster_owner&&raster_owner->fp_mutate)C(fegetround()==FE_TONEAREST);if(fail_quad&&dispatches==fail_quad)shader_owner->fail_at=shader_owner->calls+1;
 rc=m98_sp_run(cookie,io,r);if(!rc&&call<64)returned[call]=r->live_mask;if(raster_owner&&raster_owner->fp_mutate){fesetround(FE_UPWARD);feraiseexcept(FE_INVALID);}return rc;
}
static m98_r_ops ops(owner *o){m98_r_ops t={0};t.abi=1;t.user=o;t.allocate=allocate;t.deallocate=deallocate;t.run_shader=dispatch;return t;}
static void init(frame *f,unsigned w,unsigned h,const uint8_t bg[4],float z){unsigned x,y;memset(f->color,0xa5,sizeof(f->color));for(y=0;y<sizeof(f->depth)/sizeof(float);y++)f->depth[y]=123456;
 for(y=0;y<h;y++)for(x=0;x<w;x++){memcpy(f->color+8+y*40+4*x,bg,4);f->depth[4+y*12+x]=z;}}
static void guards(const frame *f,unsigned w,unsigned h){unsigned x,y;for(x=0;x<8;x++){C(f->color[x]==0xa5);C(f->color[sizeof(f->color)-8+x]==0xa5);}for(x=0;x<4;x++){C(f->depth[x]==123456);C(f->depth[sizeof(f->depth)/sizeof(float)-4+x]==123456);}
 for(y=0;y<8;y++){for(x=y<h?4*w:0;x<40;x++)C(f->color[8+y*40+x]==0xa5);for(x=y<h?w:0;x<12;x++)C(f->depth[4+y*12+x]==123456);}}
static m98_r_draw draw(frame *f,unsigned w,unsigned h,uint32_t cookie){m98_r_draw d={0};unsigned i;d.abi=1;d.shader_cookie=cookie;d.varying_count=1;d.quad_budget=1024;d.depth_test=M98_R_DEPTH_LESS;d.depth_write=1;
 d.surface.width=w;d.surface.height=h;d.surface.color=f->color+8;d.surface.color_stride=40;d.surface.color_capacity=8*40;d.surface.depth=f->depth+4;d.surface.depth_stride=12;d.surface.depth_capacity=8*12;
 d.vertex[1].x16=64;d.vertex[2].y16=64;
 for(i=0;i<3;i++){d.vertex[i].z=.5f;d.vertex[i].varying[0][2]=.25f;d.vertex[i].varying[0][3]=1;}
 d.vertex[1].varying[0][0]=1;d.vertex[2].varying[0][1]=1;d.constant[0][0]=1;d.constant[0][3]=1;return d;
}
static m98_sp_source source(unsigned file,unsigned index){m98_sp_source s={0};unsigned i;s.file=file;s.index=index;for(i=0;i<4;i++)s.swizzle[i]=i;return s;}
#define S(f,i) source(f,i)
#define Z ((m98_sp_source){0})
static m98_sp_instruction instruction(unsigned op,unsigned file,unsigned index,unsigned n,m98_sp_source a,m98_sp_source b){m98_sp_instruction s={0};s.opcode=op;s.dst_file=file;s.dst_index=index;s.source_count=n;if(n)s.source[0]=a;if(n>1)s.source[1]=b;return s;}
#define I(op,f,i,n,a,b) instruction(op,f,i,n,a,b)
static uint32_t shader(owner *o,m98_sp_instruction *code,unsigned n,unsigned in,unsigned cn,unsigned temp,unsigned out){m98_sp_callbacks cb={0};m98_sp_program p={0};uint32_t cookie=0;cb.abi=1;cb.user=o;cb.allocate=allocate;cb.deallocate=deallocate;cb.math=math_provider;p.abi=1;p.instructions=code;p.instruction_count=n;p.input_count=in;p.constant_count=cn;p.temp_count=temp;p.output_count=out;C(m98_sp_open(&p,&cb,&cookie)==0&&cookie);return cookie;}
static uint32_t solid(owner *o){m98_sp_instruction code[2];code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z);code[1]=I(M98_SP_END,0,0,0,Z,Z);return shader(o,code,2,0,1,0,1);}
static int render(m98_r_draw *d,m98_r_ops *t,m98_r_stats *s){raster_owner=t->user;dispatches=0;return m98_raster_draw(d,t,s);}
static const char *mask6[8]={"11100000","11000000","10000000","00000000","00000000","00000000","00000000","00000000"};
static void pixels(const frame *f,unsigned w,unsigned h,const char *const mask[8],const uint8_t rgba[4],const uint8_t bg[4],float depth,float initial){unsigned x,y;for(y=0;y<h;y++)for(x=0;x<w;x++){const uint8_t *expected=mask[y][x]=='1'?rgba:bg;C(!memcmp(f->color+8+y*40+4*x,expected,4));C(f->depth[4+y*12+x]==(mask[y][x]=='1'?depth:initial));}guards(f,w,h);}

static void coverage_changes(void){owner a={0},r={0};m98_r_ops t=ops(&r);uint32_t cookie=solid(&a);frame f,before;m98_r_draw d;m98_r_stats s;const uint8_t bg[]={3,7,11,255},red[]={255,0,0,255},blue[]={0,0,255,255};
 shader_owner=&a;init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);C(render(&d,&t,&s)==0);C(s.covered_samples==6&&s.shader_quads==3&&s.written_samples==6&&s.discarded_samples==0&&s.depth_rejected_samples==0&&s.scratch_bytes==512);pixels(&f,8,8,mask6,red,bg,.5f,1);
 C(observed[0].quad_x==.5f&&observed[0].quad_y==.5f&&observed[0].live_mask==15);C(observed[1].quad_x==2.5f&&observed[1].quad_y==.5f&&observed[1].live_mask==1);C(observed[2].quad_x==.5f&&observed[2].quad_y==2.5f&&observed[2].live_mask==1);
 before=f;init(&f,8,8,bg,1);d.constant[0][0]=0;d.constant[0][2]=1;C(render(&d,&t,&s)==0);pixels(&f,8,8,mask6,blue,bg,.5f,1);C(memcmp(before.color,f.color,sizeof(f.color))!=0);
 init(&f,8,8,bg,1);{m98_r_vertex swap=d.vertex[1];d.vertex[1]=d.vertex[2];d.vertex[2]=swap;}C(render(&d,&t,&s)==0);C(!memcmp(before.depth,f.depth,sizeof(f.depth)));pixels(&f,8,8,mask6,blue,bg,.5f,1);
 C(m98_sp_close(&cookie)==0&&!a.live&&!r.live);
}
static void varying_derivative_discard(void){owner a={0},r={0};m98_r_ops t=ops(&r);m98_sp_instruction code[5];uint32_t cookie;frame f;m98_r_draw d;m98_r_stats st;unsigned x,y;const uint8_t bg[]={0,0,0,255};const uint8_t coordinate[]={32,96,159};
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_INPUT,0),Z);code[1]=I(M98_SP_END,0,0,0,Z,Z);cookie=shader(&a,code,2,1,0,0,1);shader_owner=&a;init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);C(render(&d,&t,&st)==0);
 for(y=0;y<8;y++)for(x=0;x<8;x++)if(mask6[y][x]=='1'){uint8_t v[]={coordinate[x],coordinate[y],64,255};C(!memcmp(f.color+8+y*40+4*x,v,4));}guards(&f,8,8);C(observed[0].input[0].dx[0]==.25f&&observed[0].input[0].dy[1]==.25f);C(m98_sp_close(&cookie)==0);
 code[0]=I(M98_SP_MUL,M98_SP_OUTPUT,0,2,S(M98_SP_INPUT,0),S(M98_SP_CONSTANT,0));cookie=shader(&a,code,2,1,1,0,1);init(&f,8,8,bg,1);d.shader_cookie=cookie;d.constant[0][0]=2;d.constant[0][1]=1;d.constant[0][2]=1;d.constant[0][3]=1;C(render(&d,&t,&st)==0);
 {const uint8_t red[]={64,191,255};for(y=0;y<8;y++)for(x=0;x<8;x++)if(mask6[y][x]=='1'){uint8_t v[]={red[x],coordinate[y],64,255};C(!memcmp(f.color+8+y*40+4*x,v,4));}}C(m98_sp_close(&cookie)==0);
 code[0]=I(M98_SP_DDX,M98_SP_TEMP,0,1,S(M98_SP_INPUT,0),Z);code[1]=I(M98_SP_DDY,M98_SP_TEMP,1,1,S(M98_SP_INPUT,0),Z);code[2]=I(M98_SP_ADD,M98_SP_TEMP,0,2,S(M98_SP_TEMP,0),S(M98_SP_TEMP,1));code[3]=I(M98_SP_ADD,M98_SP_OUTPUT,0,2,S(M98_SP_TEMP,0),S(M98_SP_CONSTANT,0));code[4]=I(M98_SP_END,0,0,0,Z,Z);cookie=shader(&a,code,5,1,1,2,1);init(&f,8,8,bg,1);d.shader_cookie=cookie;memset(d.constant,0,sizeof(d.constant));d.constant[0][3]=1;C(render(&d,&t,&st)==0);{const uint8_t v[]={64,64,0,255};pixels(&f,8,8,mask6,v,bg,.5f,1);}C(returned[1]==1&&returned[2]==1);C(m98_sp_close(&cookie)==0);
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_INPUT,0),Z);code[1]=I(M98_SP_ADD,M98_SP_TEMP,0,2,S(M98_SP_INPUT,0),S(M98_SP_CONSTANT,0));code[2]=I(M98_SP_KILL_IF,0,0,1,S(M98_SP_TEMP,0),Z);code[3]=I(M98_SP_END,0,0,0,Z,Z);cookie=shader(&a,code,4,1,1,1,1);init(&f,8,8,bg,1);d.shader_cookie=cookie;memset(d.constant,0,sizeof(d.constant));d.constant[0][0]=-.375f;C(render(&d,&t,&st)==0);C(st.covered_samples==6&&st.written_samples==3&&st.discarded_samples==3&&st.shader_quads==3);C(returned[0]==10&&returned[1]==1&&returned[2]==0);
 {const char *alive[8]={"01100000","01000000","00000000","00000000","00000000","00000000","00000000","00000000"};for(y=0;y<8;y++)for(x=0;x<8;x++){if(alive[y][x]=='1'){uint8_t v[]={coordinate[x],coordinate[y],64,255};C(!memcmp(f.color+8+y*40+4*x,v,4));C(f.depth[4+y*12+x]==.5f);}else{C(!memcmp(f.color+8+y*40+4*x,bg,4));C(f.depth[4+y*12+x]==1);}}}guards(&f,8,8);C(m98_sp_close(&cookie)==0&&!a.live&&!r.live);
}
static void depth_blend(void){owner a={0},r={0};m98_r_ops t=ops(&r);uint32_t cookie=solid(&a);frame f,before;m98_r_draw d;m98_r_stats st;unsigned i,x,y;const uint8_t bg[]={0,0,255,255},red[]={255,0,0,255},blue[]={0,0,255,255};shader_owner=&a;
 init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);C(render(&d,&t,&st)==0);before=f;d.constant[0][0]=0;d.constant[0][2]=1;for(i=0;i<3;i++)d.vertex[i].z=.75f;C(render(&d,&t,&st)==0);C(st.depth_rejected_samples==6&&!st.shader_quads&&!st.written_samples&&!memcmp(&f,&before,sizeof(f)));
 for(i=0;i<3;i++)d.vertex[i].z=.5f;C(render(&d,&t,&st)==0);C(st.depth_rejected_samples==6&&!st.shader_quads&&!memcmp(&f,&before,sizeof(f)));d.depth_test=M98_R_DEPTH_LEQUAL;C(render(&d,&t,&st)==0);pixels(&f,8,8,mask6,blue,bg,.5f,1);
 d.constant[0][0]=1;d.constant[0][2]=0;d.depth_test=M98_R_DEPTH_LESS;d.depth_write=0;for(i=0;i<3;i++)d.vertex[i].z=.25f;C(render(&d,&t,&st)==0);pixels(&f,8,8,mask6,red,bg,.5f,1);
 init(&f,8,8,bg,.3f);d.depth_write=1;d.vertex[0].z=.125f;d.vertex[1].z=.625f;d.vertex[2].z=.375f;C(render(&d,&t,&st)==0);C(st.written_samples==2&&st.depth_rejected_samples==4&&st.shader_quads==1&&observed[0].live_mask==5);C(f.depth[4]==.21875f&&f.depth[4+12]==.28125f);guards(&f,8,8);
 init(&f,8,8,bg,1);d.depth_test=M98_R_DEPTH_ALWAYS;C(render(&d,&t,&st)==0);{const float z[3][3]={{.21875f,.34375f,.46875f},{.28125f,.40625f,1},{.34375f,1,1}};for(y=0;y<3;y++)for(x=0;x<3;x++)if(mask6[y][x]=='1')C(f.depth[4+y*12+x]==z[y][x]);}
 d.depth_test=M98_R_DEPTH_OFF;d.depth_write=0;d.blend=M98_R_SOURCE_OVER;d.constant[0][3]=.5f;init(&f,8,8,bg,1);C(render(&d,&t,&st)==0);{const uint8_t v[]={128,0,127,255};pixels(&f,8,8,mask6,v,bg,1,1);}
 {const uint8_t transparent[]={22,33,44,0},v[]={255,0,0,128};init(&f,8,8,transparent,1);C(render(&d,&t,&st)==0);pixels(&f,8,8,mask6,v,transparent,1,1);}
 {const uint8_t green[]={0,255,0,128},v[]={170,85,0,192};init(&f,8,8,green,1);C(render(&d,&t,&st)==0);pixels(&f,8,8,mask6,v,green,1,1);}
 d.constant[0][3]=0;init(&f,8,8,bg,1);before=f;C(render(&d,&t,&st)==0);C(!memcmp(&f,&before,sizeof(f)));
 {const uint8_t transparent[]={22,33,44,0},v[]={0,0,0,0};init(&f,8,8,transparent,1);C(render(&d,&t,&st)==0);pixels(&f,8,8,mask6,v,transparent,1,1);}C(m98_sp_close(&cookie)==0&&!a.live&&!r.live);
}
static void ties_clip_noop(void){owner a={0},r={0};m98_r_ops t=ops(&r);uint32_t cookie=solid(&a);frame f,before;m98_r_draw d;m98_r_stats st;unsigned x,y,calls;const uint8_t bg[]={0,0,0,0},red[]={255,0,0,128};shader_owner=&a;
 init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);d.blend=M98_R_SOURCE_OVER;d.depth_test=M98_R_DEPTH_OFF;d.depth_write=0;d.constant[0][3]=.5f;C(render(&d,&t,&st)==0&&st.written_samples==6);
 d.vertex[0].x16=64;d.vertex[0].y16=0;d.vertex[1].x16=64;d.vertex[1].y16=64;d.vertex[2].x16=0;d.vertex[2].y16=64;C(render(&d,&t,&st)==0&&st.written_samples==10);
 for(y=0;y<8;y++)for(x=0;x<8;x++)C(!memcmp(f.color+8+y*40+4*x,x<4&&y<4?red:bg,4));guards(&f,8,8);
 init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);d.vertex[0].x16=8;d.vertex[0].y16=8;d.vertex[1].x16=72;d.vertex[1].y16=8;d.vertex[2].x16=8;d.vertex[2].y16=72;C(render(&d,&t,&st)==0&&st.written_samples==10);{const char *m[8]={"11110000","11100000","11000000","10000000","00000000","00000000","00000000","00000000"};const uint8_t opaque[]={255,0,0,255};pixels(&f,8,8,m,opaque,bg,.5f,1);}
 init(&f,4,4,bg,1);d=draw(&f,4,4,cookie);d.vertex[0].x16=-16;d.vertex[0].y16=-16;d.vertex[1].x16=144;d.vertex[1].y16=-16;d.vertex[2].x16=-16;d.vertex[2].y16=144;C(render(&d,&t,&st)==0&&st.written_samples==16);{const char *m[8]={"1111","1111","1111","1111"};const uint8_t v[]={255,0,0,255};pixels(&f,4,4,m,v,bg,.5f,1);}
 init(&f,4,4,bg,1);d=draw(&f,4,4,cookie);d.vertex[0].x16=-32;d.vertex[1].x16=32;d.vertex[2].x16=-32;C(render(&d,&t,&st)==0&&st.written_samples==1);{const char *m[8]={"1000","0000","0000","0000"};const uint8_t v[]={255,0,0,255};pixels(&f,4,4,m,v,bg,.5f,1);}
 init(&f,4,4,bg,1);before=f;calls=r.calls;d=draw(&f,4,4,cookie);d.vertex[0].x16=-64;d.vertex[0].y16=-64;d.vertex[1].x16=-32;d.vertex[1].y16=-64;d.vertex[2].x16=-64;d.vertex[2].y16=-32;C(render(&d,&t,&st)==0&&!st.covered_samples&&!st.shader_quads&&!r.live&&r.calls==calls&&!memcmp(&f,&before,sizeof(f)));
 d.vertex[0].x16=160;d.vertex[0].y16=160;d.vertex[1].x16=192;d.vertex[1].y16=160;d.vertex[2].x16=160;d.vertex[2].y16=192;C(render(&d,&t,&st)==0&&!st.covered_samples&&r.calls==calls&&!memcmp(&f,&before,sizeof(f)));
 d=draw(&f,4,4,cookie);d.vertex[1].x16=32;d.vertex[1].y16=32;d.vertex[2].x16=64;d.vertex[2].y16=64;C(render(&d,&t,&st)==0&&!st.covered_samples&&r.calls==calls&&!memcmp(&f,&before,sizeof(f)));C(m98_sp_close(&cookie)==0&&!a.live&&!r.live);
}
static void expect_failure(m98_r_draw *d,m98_r_ops *t,frame *f,int error){frame before=*f;m98_r_stats st,old;memset(&st,0xa5,sizeof(st));old=st;C(render(d,t,&st)==error);C(!memcmp(f,&before,sizeof(*f))&&!memcmp(&st,&old,sizeof(st)));C(!((owner*)t->user)->live);}
static void failures_reentry_fp(void){owner a={0},r={0};m98_r_ops t=ops(&r);uint32_t cookie=solid(&a),stale;frame f;m98_r_draw d,saved;m98_r_stats st;unsigned i,calls;int rounding;const uint8_t bg[]={4,5,6,255};union {float f;uint32_t u;} bad;shader_owner=&a;bad.u=0x7fc00000;
 init(&f,8,8,bg,1);d=draw(&f,8,8,cookie);saved=d;calls=r.calls;
 for(i=0;i<15;i++){d=saved;switch(i){case 0:d.surface.width=65;break;case 1:d.surface.height=65;break;case 2:d.surface.width=0;break;case 3:d.surface.color_stride=31;break;case 4:d.surface.depth_stride=7;break;case 5:d.surface.color_capacity=311;break;case 6:d.surface.depth_capacity=91;break;case 7:d.vertex[0].x16=INT32_MAX;break;case 8:d.vertex[0].y16=INT32_MIN;break;case 9:d.vertex[0].z=-1;break;case 10:d.vertex[0].varying[0][0]=bad.f;break;case 11:d.constant[7][3]=bad.f;break;case 12:d.abi=2;break;case 13:d.reserved=1;break;default:d.depth_write=2;break;}expect_failure(&d,&t,&f,i<2||i==7||i==8?M98_R_LIMIT:M98_R_INVALID);C(!dispatches&&r.calls==calls);}
 d=saved;d.depth_test=4;expect_failure(&d,&t,&f,M98_R_UNSUPPORTED);d=saved;d.blend=2;expect_failure(&d,&t,&f,M98_R_UNSUPPORTED);d=saved;d.quad_budget=2;expect_failure(&d,&t,&f,M98_R_LIMIT);C(!dispatches&&r.calls==calls);
 d=saved;d.surface.depth=(float*)(f.color+8);expect_failure(&d,&t,&f,M98_R_INVALID);d=saved;d.surface.depth=(float*)((uint8_t*)saved.surface.depth+1);expect_failure(&d,&t,&f,M98_R_INVALID);
 d=saved;d.surface.color=(uint8_t*)(UINTPTR_MAX-1);expect_failure(&d,&t,&f,M98_R_INVALID);d=saved;d.surface.depth=(float*)(UINTPTR_MAX-3);expect_failure(&d,&t,&f,M98_R_INVALID);
 {frame old=f;C(m98_raster_draw(&saved,&t,(m98_r_stats*)saved.surface.color)==M98_R_INVALID);C(!memcmp(&old,&f,sizeof(f)));C(m98_raster_draw(&saved,&t,(m98_r_stats*)saved.surface.depth)==M98_R_INVALID);C(!memcmp(&old,&f,sizeof(f)));}
 /* A stats record must not overwrite trailing row padding or capacity suffix. */
 {frame old=f;d=saved;d.surface.width=1;d.surface.height=1;C(m98_raster_draw(&d,&t,(m98_r_stats*)(d.surface.color+4))==M98_R_INVALID);C(!memcmp(&old,&f,sizeof(f)));C(m98_raster_draw(&d,&t,(m98_r_stats*)(d.surface.depth+1))==M98_R_INVALID);C(!memcmp(&old,&f,sizeof(f)));}
 f.depth[4]=bad.f;d=saved;expect_failure(&d,&t,&f,M98_R_INVALID);f.depth[4]=1;C(!dispatches&&r.calls==calls);
 d=saved;for(i=1;i<=2;i++){r.fail_at=r.calls+i;expect_failure(&d,&t,&f,M98_R_NOMEM);r.fail_at=0;C(!dispatches);}
 a.fail_at=a.calls+1;expect_failure(&d,&t,&f,M98_R_SHADER_ERROR_BASE+M98_SP_NOMEM);a.fail_at=0;C(a.live==1);fail_quad=2;expect_failure(&d,&t,&f,M98_R_SHADER_ERROR_BASE+M98_SP_NOMEM);fail_quad=0;a.fail_at=0;C(a.live==1&&dispatches==2);
 r.draw=&d;r.ops=&t;r.reenter=1;C(render(&d,&t,&st)==0&&r.nested==M98_R_BUSY&&st.written_samples==6);r.reenter=0;r.draw=NULL;r.ops=NULL;
 init(&f,8,8,bg,1);d=saved;r.draw=&d;r.ops=&t;r.mutate=1;C(render(&d,&t,&st)==0&&st.written_samples==6&&f.color[8]==255);C(d.vertex[0].x16==INT32_MAX&&!t.run_shader&&!d.shader_cookie);r.mutate=0;r.draw=NULL;r.ops=NULL;t=ops(&r);d=saved;
 init(&f,8,8,bg,1);rounding=fegetround();C(fesetround(FE_DOWNWARD)==0);feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);r.fp_mutate=1;C(render(&d,&t,&st)==0&&st.written_samples==6&&f.color[8]==255);C(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);r.fp_mutate=0;C(fesetround(rounding)==0);feclearexcept(FE_ALL_EXCEPT);
 stale=cookie;C(m98_sp_close(&cookie)==0&&!a.live);d.shader_cookie=stale;init(&f,8,8,bg,1);expect_failure(&d,&t,&f,M98_R_SHADER_ERROR_BASE+M98_SP_STALE);
 {m98_sp_instruction code[3];code[0]=I(M98_SP_SQRT,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z);code[1]=I(M98_SP_END,0,0,0,Z,Z);cookie=shader(&a,code,2,0,1,0,1);d=saved;d.shader_cookie=cookie;d.constant[0][0]=-1;expect_failure(&d,&t,&f,M98_R_BAD_OUTPUT);d.constant[0][0]=.25f;
 rounding=fegetround();C(fesetround(FE_DOWNWARD)==0);feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);C(render(&d,&t,&st)==0);C(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);init(&f,8,8,bg,1);a.fail_math=1;expect_failure(&d,&t,&f,M98_R_SHADER_ERROR_BASE+M98_SP_BACKEND);C(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);a.fail_math=0;C(m98_sp_close(&cookie)==0);fesetround(rounding);feclearexcept(FE_ALL_EXCEPT);
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z);code[1]=I(M98_SP_MOV,M98_SP_OUTPUT,1,1,S(M98_SP_CONSTANT,0),Z);code[2]=I(M98_SP_END,0,0,0,Z,Z);cookie=shader(&a,code,3,0,1,0,2);d=saved;d.shader_cookie=cookie;expect_failure(&d,&t,&f,M98_R_UNSUPPORTED);C(m98_sp_close(&cookie)==0);}
 C(!a.live&&!r.live);C(m98_raster_draw(NULL,&t,&st)==M98_R_INVALID);
}
static void maximum_odd_targets(void){owner a={0},r={0};m98_r_ops t=ops(&r);uint32_t cookie=solid(&a);m98_r_draw d={0};m98_r_stats st,old;unsigned x,y,i,calls;
 static uint8_t color[8+64*264+8],copy[sizeof(color)];static float depth[4+64*65+4],depthcopy[sizeof(depth)/sizeof(float)];const uint8_t bg[]={0,0,255,255},red[]={255,0,0,255};shader_owner=&a;
 memset(color,0xa5,sizeof(color));for(i=0;i<sizeof(depth)/sizeof(float);i++)depth[i]=123456;
 for(y=0;y<64;y++)for(x=0;x<64;x++){memcpy(color+8+264*y+4*x,bg,4);depth[4+65*y+x]=1;}
 d.abi=1;d.shader_cookie=cookie;d.quad_budget=1023;d.depth_test=M98_R_DEPTH_LESS;d.depth_write=1;d.constant[0][0]=1;d.constant[0][3]=1;
 d.surface=(m98_r_surface){64,64,264,64*264,65,64*65,color+8,depth+4};d.vertex[0].x16=-1024;d.vertex[0].y16=-1024;d.vertex[1].x16=3072;d.vertex[1].y16=-1024;d.vertex[2].x16=-1024;d.vertex[2].y16=3072;for(i=0;i<3;i++)d.vertex[i].z=.5f;
 memcpy(copy,color,sizeof(color));memcpy(depthcopy,depth,sizeof(depth));memset(&st,0xa5,sizeof(st));old=st;calls=r.calls;C(render(&d,&t,&st)==M98_R_LIMIT&&!dispatches&&r.calls==calls);C(!memcmp(&st,&old,sizeof(st))&&!memcmp(copy,color,sizeof(color))&&!memcmp(depthcopy,depth,sizeof(depth)));
 d.quad_budget=1024;C(render(&d,&t,&st)==0&&dispatches==1024&&st.covered_samples==4096&&st.written_samples==4096&&st.shader_quads==1024&&st.scratch_bytes==32768);
 for(y=0;y<64;y++){for(x=0;x<64;x++){C(!memcmp(color+8+264*y+4*x,red,4));C(depth[4+65*y+x]==.5f);}for(x=256;x<264;x++)C(color[8+264*y+x]==0xa5);C(depth[4+65*y+64]==123456);}
 for(i=0;i<8;i++){C(color[i]==0xa5&&color[sizeof(color)-8+i]==0xa5);}for(i=0;i<4;i++)C(depth[i]==123456&&depth[sizeof(depth)/sizeof(float)-4+i]==123456);
 {frame f;init(&f,3,3,bg,1);d=draw(&f,3,3,cookie);d.vertex[0].x16=-16;d.vertex[0].y16=-16;d.vertex[1].x16=144;d.vertex[1].y16=-16;d.vertex[2].x16=-16;d.vertex[2].y16=144;C(render(&d,&t,&st)==0&&st.written_samples==9&&st.shader_quads==4);C(observed[0].live_mask==15&&observed[1].live_mask==5&&observed[2].live_mask==3&&observed[3].live_mask==1);{const char *m[8]={"111","111","111"};pixels(&f,3,3,m,red,bg,.5f,1);}}
 C(m98_sp_close(&cookie)==0&&!a.live&&!r.live);
}
int main(void){C(m98_raster_abi()==1);coverage_changes();varying_derivative_discard();depth_blend();ties_clip_noop();failures_reentry_fp();maximum_odd_targets();printf("PASS genuine TGSI triangle raster: %u assertions; native/WebGL/WebGPU/browser unverified\n",checks);return 0;}
