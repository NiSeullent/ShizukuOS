/* SPDX-License-Identifier: GPL-2.0-only
 * Literal independent triangle/padding oracle; successful shaders are Mesa.
 */
#include "backend.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
#include <float.h>
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
#define C(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL graphics line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
typedef struct {void *blocks[256];unsigned live,calls,fail_at,reenter,rounding;uint32_t device;} owner;
static unsigned mxcsr(void){unsigned value;__asm__ volatile("stmxcsr %0":"=m"(value));return value;}
static void set_mxcsr(unsigned value){__asm__ volatile("ldmxcsr %0"::"m"(value):"memory");}
static float subnormal(void){union{uint32_t u;float f;}v;v.u=1;return v.f;}
static void nested(owner *o){uint32_t id=o->device;unsigned state=mxcsr();C(ntg_destroy(&id)==NTG_BUSY&&id==o->device);C(ntg_clear_depth(id,0,subnormal())==NTG_BUSY);C(mxcsr()==state);}
static void *allocate(void *u,size_t n){owner *o=u;unsigned i;void *p;o->calls++;if(o->reenter)nested(o);
 if(o->rounding){C(fegetround()==FE_TONEAREST);fesetround(FE_UPWARD);feraiseexcept(FE_INVALID);}
 if(o->calls==o->fail_at)return NULL;p=malloc(n);C(p!=NULL);for(i=0;i<256;i++)if(!o->blocks[i]){o->blocks[i]=p;break;}C(i<256);o->live++;return p;
}
static void deallocate(void *u,void *p){owner *o=u;unsigned i;if(!p)return;if(o->reenter)nested(o);for(i=0;i<256;i++)if(o->blocks[i]==p)break;C(i<256);o->blocks[i]=NULL;o->live--;free(p);}
static int math_provider(void *u,uint32_t op,double x,double y,double *out){owner *o=u;
 if(o->rounding){C(fegetround()==FE_TONEAREST);fesetround(FE_UPWARD);feraiseexcept(FE_INVALID);}
 switch(op){case M98_SP_MATH_COS:*out=cos(x);break;case M98_SP_MATH_SIN:*out=sin(x);break;case M98_SP_MATH_LOG:*out=log(x);break;case M98_SP_MATH_POW:*out=pow(x,y);break;case M98_SP_MATH_SQRT:*out=sqrt(x);break;case M98_SP_MATH_FLOOR:*out=floor(x);break;case M98_SP_MATH_CEIL:*out=ceil(x);break;case M98_SP_MATH_LDEXP:*out=ldexp(x,(int)y);break;default:return 1;}return 0;
}
static uint32_t create(owner *o){m98_sp_callbacks cb={1,0,o,allocate,deallocate,math_provider};uint32_t id=0;C(ntg_create(&cb,&id)==NTG_OK&&id);o->device=id;return id;}
static ntg_texture_desc desc(unsigned kind,unsigned w,unsigned h,unsigned pitch){ntg_texture_desc d={1,w,h,kind,pitch,1,1,1,0};return d;}
static ntg_resource texture(uint32_t id,unsigned kind,unsigned w,unsigned h,unsigned pitch){ntg_texture_desc d=desc(kind,w,h,pitch);ntg_resource r=0;C(ntg_texture_create(id,&d,&r)==NTG_OK&&r);return r;}
static ntg_resource shader(uint32_t id,int varying){m98_sp_instruction code[2]={{0}};m98_sp_program p={0};ntg_resource r=0;unsigned i;
 code[0].opcode=M98_SP_MOV;code[0].dst_file=M98_SP_OUTPUT;code[0].source_count=1;code[0].source[0].file=varying?M98_SP_INPUT:M98_SP_CONSTANT;for(i=0;i<4;i++)code[0].source[0].swizzle[i]=i;code[1].opcode=M98_SP_END;p.abi=1;p.input_count=varying?1:0;p.constant_count=varying?0:1;p.output_count=1;p.instructions=code;p.instruction_count=2;
 C(ntg_shader_create(id,&p,&r)==NTG_OK&&r);return r;
}
static ntg_draw_desc draw(void){ntg_draw_desc d={0};unsigned i;d.abi=1;d.varying_count=1;d.quad_budget=1024;d.depth_test=M98_R_DEPTH_LESS;d.depth_write=1;d.vertex[1].x16=64;d.vertex[2].y16=64;
 for(i=0;i<3;i++){d.vertex[i].z=.5f;d.vertex[i].varying[0][2]=.25f;d.vertex[i].varying[0][3]=1;}d.vertex[1].varying[0][0]=1;d.vertex[2].varying[0][1]=1;d.constant[0][0]=1;d.constant[0][3]=1;return d;
}
static void pixels(uint32_t id,ntg_resource r,int varying,int red){ntg_mapping m;unsigned x,y,j;const uint8_t bg[4]={3,7,11,255};const unsigned coord[3]={32,96,159};C(ntg_map(id,r,&m)==NTG_OK);C(m.width==8&&m.height==8&&m.pitch==40&&m.bytes==320);
 for(y=0;y<8;y++)for(x=0;x<8;x++){uint8_t expected[4];memcpy(expected,bg,4);if(x+y<3){expected[0]=varying?(uint8_t)coord[x]:(red?255:0);expected[1]=varying?(uint8_t)coord[y]:0;expected[2]=varying?64:(red?0:255);expected[3]=255;}C(!memcmp((uint8_t*)m.pixels+y*m.pitch+4*x,expected,4));}
 for(y=0;y<8;y++)for(j=32;j<40;j++)C(((uint8_t*)m.pixels)[y*40+j]==0xa5);C(ntg_unmap(id,r)==NTG_OK);
}
static void real_render(void){owner o={0};uint32_t id=create(&o);ntg_resource c=texture(id,NTG_RGBA8,8,8,40),z=texture(id,NTG_D32,8,8,48),copy=texture(id,NTG_RGBA8,8,8,40),s=shader(id,1);ntg_mapping m;m98_r_stats stats,before;ntg_draw_desc d=draw();unsigned y,x;const uint8_t bg[4]={3,7,11,255};
 C(ntg_map(id,c,&m)==0);memset(m.pixels,0xa5,m.bytes);C(ntg_unmap(id,c)==0);C(ntg_map(id,copy,&m)==0);memset(m.pixels,0xa5,m.bytes);C(ntg_unmap(id,copy)==0);C(ntg_map(id,z,&m)==0);for(x=0;x<m.bytes/4;x++)((float*)m.pixels)[x]=123456;C(ntg_unmap(id,z)==0);
 C(ntg_clear_color(id,c,bg)==0);C(ntg_clear_depth(id,z,1)==0);C(ntg_bind(id,c,z,s)==0);memset(&m,0xa5,sizeof(m));{ntg_mapping original=m;C(ntg_map(id,c,&m)==NTG_BUSY&&!memcmp(&m,&original,sizeof(m)));}
 C(ntg_draw(id,&d,&stats)==0);C(stats.covered_samples==6&&stats.written_samples==6&&stats.shader_quads==3);C(ntg_copy(id,c,copy)==0);pixels(id,copy,1,0);
 before=stats;for(x=0;x<3;x++)d.vertex[x].z=.75f;C(ntg_draw(id,&d,&stats)==0);C(stats.depth_rejected_samples==6&&!stats.written_samples&&!stats.shader_quads);C(ntg_copy(id,c,copy)==0);pixels(id,copy,1,0);
 /* A failed draw preserves the resource bytes and caller statistics. */
 stats=before;d.blend=99;C(ntg_draw(id,&d,&stats)==M98_R_UNSUPPORTED&&!memcmp(&stats,&before,sizeof(stats)));C(ntg_copy(id,c,copy)==0);pixels(id,copy,1,0);
 C(ntg_bind(id,0,0,0)==0);C(ntg_map(id,z,&m)==0);for(y=0;y<8;y++){for(x=0;x<8;x++)C(((float*)m.pixels)[y*12+x]==(x+y<3?.5f:1));for(x=8;x<12;x++)C(((float*)m.pixels)[y*12+x]==123456);}C(ntg_unmap(id,z)==0);
 C(ntg_release(id,&s)==0&&!s);s=shader(id,0);d=draw();C(ntg_clear_depth(id,z,1)==0);C(ntg_bind(id,c,z,s)==0);C(ntg_draw(id,&d,&stats)==0);C(ntg_copy(id,c,copy)==0);pixels(id,copy,0,1);
 C(ntg_bind(id,0,0,0)==0);C(ntg_clear_depth(id,z,1)==0);d.constant[0][0]=0;d.constant[0][2]=1;C(ntg_bind(id,c,z,s)==0);C(ntg_draw(id,&d,&stats)==0);C(ntg_copy(id,c,copy)==0);pixels(id,copy,0,0);
 /* Binding references survive removal of each external resource reference. */
 {ntg_resource oldc=c,oldz=z,olds=s;C(ntg_release(id,&c)==0&&!c);C(ntg_release(id,&z)==0&&!z);C(ntg_release(id,&s)==0&&!s);C(ntg_retain(id,oldc)==NTG_STALE);C(ntg_draw(id,&d,&stats)==0);C(ntg_bind(id,0,0,0)==0);C(ntg_copy(id,oldc,copy)==NTG_STALE);C(ntg_release(id,&oldz)==NTG_STALE);C(ntg_release(id,&olds)==NTG_STALE);}
 C(ntg_destroy(&id)==0&&!id&&!o.live);
}
static void contract_failure(void){owner o={0},other={0};uint32_t id=create(&o),id2=create(&other),stale=id;ntg_resource r=texture(id,NTG_RGBA8,8,8,40),foreign=texture(id2,NTG_RGBA8,8,8,40),out=UINT64_C(0x123456789abcdef0),saved=out;ntg_mapping m,b;ntg_texture_desc d=desc(NTG_RGBA8,8,8,0);const uint8_t color[4]={1,2,3,255};
 C(ntg_map(id,foreign,&m)==NTG_STALE);C(ntg_map(id,r,&m)==0);b=m;C(ntg_map(id,r,&m)==NTG_BUSY&&!memcmp(&m,&b,sizeof(m)));C(ntg_clear_color(id,r,color)==NTG_BUSY);C(ntg_copy(id,r,r)==NTG_BUSY);C(ntg_release(id,&r)==NTG_BUSY&&r);C(ntg_destroy(&id)==NTG_BUSY&&id);C(ntg_unmap(id,r)==0);C(ntg_unmap(id,r)==NTG_INVALID);C(ntg_copy(id,r,r)==0);
 d.samples=4;C(ntg_texture_create(id,&d,&out)==NTG_UNSUPPORTED&&out==saved);d.samples=1;d.mip_levels=2;C(ntg_texture_create(id,&d,&out)==NTG_UNSUPPORTED&&out==saved);d.mip_levels=1;d.width=65;C(ntg_texture_create(id,&d,&out)==NTG_LIMIT&&out==saved);d.width=8;d.pitch=31;C(ntg_texture_create(id,&d,&out)==NTG_INVALID&&out==saved);d.pitch=0;
 o.fail_at=o.calls+1;C(ntg_texture_create(id,&d,&out)==NTG_NOMEM&&out==saved);o.fail_at=0;C(ntg_clear_depth(id,r,1)==NTG_UNSUPPORTED);C(ntg_clear_depth(id,r,NAN)==NTG_INVALID);
 C(ntg_destroy(&id)==0&&!o.live);C(ntg_destroy(&stale)==NTG_STALE&&stale);C(ntg_map(stale,r,&m)==NTG_STALE);C(ntg_destroy(&id2)==0&&!other.live);
}
static void exhaustion_and_fp(void){owner o={0};uint32_t id=create(&o);ntg_resource r[16],out=UINT64_MAX,old;ntg_texture_desc d=desc(NTG_RGBA8,8,8,0);unsigned i;
 o.reenter=1;for(i=0;i<16;i++)r[i]=texture(id,NTG_RGBA8,8,8,0);C(ntg_texture_create(id,&d,&out)==NTG_LIMIT&&out==UINT64_MAX);old=r[3];C(ntg_release(id,&r[3])==0);r[3]=texture(id,NTG_RGBA8,8,8,0);C(r[3]!=old&&ntg_retain(id,old)==NTG_STALE);C(ntg_retain(id,r[0])==0);{ntg_resource alias=r[0];C(ntg_release(id,&alias)==0&&r[0]);}
 C(ntg_destroy(&id)==0&&!o.live);
 id=create(&o);o.reenter=0;o.rounding=1;C(fesetround(FE_DOWNWARD)==0);feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);r[0]=texture(id,NTG_RGBA8,8,8,0);C(fegetround()==FE_DOWNWARD);C((fetestexcept(FE_ALL_EXCEPT)&(FE_DIVBYZERO|FE_INVALID))==FE_DIVBYZERO);C(ntg_destroy(&id)==0&&!o.live);C(fegetround()==FE_DOWNWARD);C(fesetround(FE_TONEAREST)==0);feclearexcept(FE_ALL_EXCEPT);
 o.rounding=0;id=create(&o);r[0]=texture(id,NTG_D32,8,8,0);
 {unsigned saved=mxcsr(),unmasked=0x1f80u&~(1u<<8);ntg_mapping m;set_mxcsr(unmasked);C(ntg_clear_depth(id,r[0],subnormal())==0);C(mxcsr()==unmasked);C(ntg_clear_depth(id,r[0],2)==NTG_INVALID);C(mxcsr()==unmasked);C(ntg_clear_depth(0,0,subnormal())==NTG_STALE);C(mxcsr()==unmasked);C(ntg_map(id,r[0],&m)==0);C(((uint32_t*)m.pixels)[0]==1);C(mxcsr()==unmasked);C(ntg_unmap(id,r[0])==0);C(mxcsr()==unmasked);set_mxcsr(saved);}
 C(ntg_destroy(&id)==0&&!o.live);
}
static void actual_bad_output_and_nomem(void){owner o={0};uint32_t id=create(&o);ntg_resource c=texture(id,NTG_RGBA8,8,8,40),z=texture(id,NTG_D32,8,8,48),stage=texture(id,NTG_RGBA8,8,8,40),s=0;ntg_draw_desc d=draw();m98_sp_instruction code[2]={{0}};m98_sp_program p={0};m98_r_stats stats,before;unsigned i;const uint8_t bg[4]={3,7,11,255};ntg_mapping m;
 C(ntg_clear_color(id,c,bg)==0&&ntg_clear_depth(id,z,1)==0);code[0].opcode=M98_SP_MUL;code[0].dst_file=M98_SP_OUTPUT;code[0].source_count=2;code[0].source[0].file=M98_SP_INPUT;code[0].source[1].file=M98_SP_CONSTANT;for(i=0;i<4;i++)code[0].source[0].swizzle[i]=code[0].source[1].swizzle[i]=i;code[1].opcode=M98_SP_END;p.abi=1;p.input_count=p.constant_count=p.output_count=1;p.instruction_count=2;p.instructions=code;C(ntg_shader_create(id,&p,&s)==0&&s);C(ntg_bind(id,c,z,s)==0);for(i=0;i<3;i++)d.vertex[i].varying[0][0]=2;d.constant[0][0]=FLT_MAX;memset(&stats,0xa5,sizeof(stats));before=stats;
 C(ntg_draw(id,&d,&stats)==NTG_BACKEND&&!memcmp(&stats,&before,sizeof(stats)));C(ntg_copy(id,c,stage)==0);C(ntg_map(id,stage,&m)==0);for(i=0;i<8*8;i++)C(!memcmp((uint8_t*)m.pixels+(i/8)*m.pitch+4*(i%8),bg,4));C(ntg_unmap(id,stage)==0);
 for(i=1;i<=3;i++){o.fail_at=o.calls+i;C(ntg_draw(id,&d,&stats)==NTG_NOMEM&&!memcmp(&stats,&before,sizeof(stats)));o.fail_at=0;}C(ntg_destroy(&id)==0&&!o.live);
}
static void nested_provider_fp_drift(void){owner o={0};uint32_t id=create(&o);ntg_resource c=texture(id,NTG_RGBA8,8,8,40),z=texture(id,NTG_D32,8,8,48),s=0;ntg_draw_desc d=draw();m98_sp_instruction code[2]={{0}};m98_sp_program p={0};m98_r_stats stats;ntg_mapping m;unsigned i,x,y,state;const uint8_t bg[4]={3,7,11,255},gray[4]={128,128,128,128};
 C(ntg_clear_color(id,c,bg)==0&&ntg_clear_depth(id,z,1)==0);code[0].opcode=M98_SP_SQRT;code[0].dst_file=M98_SP_OUTPUT;code[0].source_count=1;code[0].source[0].file=M98_SP_CONSTANT;for(i=0;i<4;i++)code[0].source[0].swizzle[i]=i;code[1].opcode=M98_SP_END;p.abi=1;p.constant_count=p.output_count=1;p.instruction_count=2;p.instructions=code;o.reenter=1;o.rounding=1;
 C(ntg_shader_create(id,&p,&s)==0&&s);C(ntg_bind(id,c,z,s)==0);for(i=0;i<4;i++)d.constant[0][i]=.25f;state=mxcsr();C(ntg_draw(id,&d,&stats)==0&&stats.written_samples==6);C(mxcsr()==state);C(ntg_bind(id,0,0,0)==0);C(ntg_map(id,c,&m)==0);for(y=0;y<8;y++)for(x=0;x<8;x++)C(!memcmp((uint8_t*)m.pixels+y*m.pitch+4*x,x+y<3?gray:bg,4));C(ntg_unmap(id,c)==0);C(ntg_destroy(&id)==0&&!o.live);C(mxcsr()==state);
}
int main(void){C(ntg_abi()==1&&m98_sp_abi()==1&&m98_raster_abi()==1);real_render();contract_failure();exhaustion_and_fp();actual_bad_output_and_nomem();nested_provider_fp_drift();printf("PASS genuine Mesa resource backend: %u assertions; DirectX and guest rendering remain unverified\n",checks);return 0;}
