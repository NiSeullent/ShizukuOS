/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_softpipe_shader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <fenv.h>
/* Test oracles use the host's actual independent math provider. */
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
#undef floor
#undef sqrt
#undef ldexp
#undef rint
#undef fmin
#undef fmax
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL softpipe line %d\n",__LINE__);exit(1);}}while(0)
typedef struct {
 struct {void *p;size_t n;} blocks[128];unsigned calls,frees,live,peak,fail_at;
 unsigned math_calls,fail_math,reenter,mutate;int nested;
 uint32_t *cookie; m98_sp_instruction *original;m98_sp_io *io;
} owner;
static void *allocate(void *u,size_t n)
{
 owner *o=u;void *p;unsigned i;o->calls++;
 if(o->reenter&&o->cookie)o->nested=m98_sp_close(o->cookie);
 if(o->mutate&&o->original)o->original[0].opcode=M98_SP_TEXTURE;
 if(o->mutate&&o->io){o->io->constant[0][0]=999;o->io->live_mask=1;}
 if(o->fail_at==o->calls)return NULL;
 p=malloc(n);CHECK(p!=NULL);
 for(i=0;i<128;i++)if(!o->blocks[i].p){o->blocks[i].p=p;o->blocks[i].n=n;break;}
 CHECK(i<128);o->live++;if(o->live>o->peak)o->peak=o->live;return p;
}
static void deallocate(void *u,void *p)
{
 owner *o=u;unsigned i;if(!p)return;
 if(o->reenter&&o->cookie)o->nested=m98_sp_close(o->cookie);
 for(i=0;i<128;i++)if(o->blocks[i].p==p)break;
 CHECK(i<128);o->blocks[i].p=NULL;o->live--;o->frees++;free(p);
}
static int math_provider(void *u,uint32_t op,double x,double y,double *r)
{
 owner *o=u;o->math_calls++;
 if(o->reenter&&o->cookie)o->nested=m98_sp_close(o->cookie);
 if(o->fail_math){fesetround(FE_UPWARD);return 1;}
 switch(op){case M98_SP_MATH_COS:*r=cos(x);break;case M98_SP_MATH_SIN:*r=sin(x);break;
 case M98_SP_MATH_LOG:*r=log(x);break;case M98_SP_MATH_POW:*r=pow(x,y);break;
 case M98_SP_MATH_SQRT:*r=sqrt(x);break;case M98_SP_MATH_FLOOR:*r=floor(x);break;
 case M98_SP_MATH_CEIL:*r=ceil(x);break;case M98_SP_MATH_LDEXP:*r=ldexp(x,(int)y);break;
 default:return 1;}return 0;
}
static m98_sp_callbacks callbacks(owner *o){m98_sp_callbacks cb={0};cb.abi=1;cb.user=o;cb.allocate=allocate;cb.deallocate=deallocate;cb.math=math_provider;return cb;}
static m98_sp_source source(unsigned file,unsigned index){m98_sp_source s={0};unsigned i;s.file=file;s.index=index;for(i=0;i<4;i++)s.swizzle[i]=i;return s;}
#define S(f,i) source(f,i)
#define Z ((m98_sp_source){0})
static m98_sp_instruction instruction(unsigned op,unsigned file,unsigned index,unsigned n,m98_sp_source a,m98_sp_source b,m98_sp_source c){m98_sp_instruction in={0};in.opcode=op;in.dst_file=file;in.dst_index=index;in.source_count=n;in.source[0]=a;in.source[1]=b;in.source[2]=c;return in;}
#define I(op,f,i,n,a,b,c) instruction(op,f,i,n,a,b,c)
static m98_sp_program program(m98_sp_instruction *code,unsigned n,unsigned inputs,unsigned constants,unsigned temps,unsigned outputs){m98_sp_program p={0};p.abi=1;p.instruction_count=n;p.input_count=inputs;p.constant_count=constants;p.temp_count=temps;p.output_count=outputs;p.instructions=code;return p;}
static m98_sp_io io(void){m98_sp_io in={0};in.abi=1;in.live_mask=15;return in;}
static void poison(m98_sp_result *r){memset(r,0xa7,sizeof(*r));}
static void quad(const m98_sp_result *r,unsigned output,const float expected[4][4]){unsigned j,k;for(j=0;j<4;j++)for(k=0;k<4;k++)CHECK(r->output[output][j][k]==expected[j][k]);}
static void branch_uniform(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[10];m98_sp_program p; m98_sp_io in=io();m98_sp_result r;uint32_t cookie=0,old;unsigned j,k;
 const float expected[4][4]={{36,20,36,20},{27,12,27,12},{18,6,18,6},{9,2,9,2}};
 const float derivative[4][4]={{-7,-7,-7,-7},{-12,-12,-12,-12},{-15,-15,-15,-15},{-16,-16,-16,-16}};
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,3),Z,Z);
 code[1]=I(M98_SP_SLT,M98_SP_TEMP,0,2,S(M98_SP_INPUT,0),S(M98_SP_CONSTANT,0),Z);
 code[2]=I(M98_SP_IF,0,0,1,S(M98_SP_TEMP,0),Z,Z);
 code[3]=I(M98_SP_ADD,M98_SP_TEMP,1,2,S(M98_SP_INPUT,0),S(M98_SP_CONSTANT,1),Z);
 code[4]=I(M98_SP_ELSE,0,0,0,Z,Z,Z);
 code[5]=I(M98_SP_MUL,M98_SP_TEMP,1,2,S(M98_SP_INPUT,0),S(M98_SP_CONSTANT,2),Z);
 code[6]=I(M98_SP_ENDIF,0,0,0,Z,Z,Z);
 code[7]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_TEMP,1),Z,Z);
 for(j=0;j<4;j++)code[7].source[0].swizzle[j]=3-j;
 code[8]=I(M98_SP_DDX,M98_SP_OUTPUT,1,1,S(M98_SP_TEMP,1),Z,Z);
 code[9]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,10,1,4,2,2);
 for(j=0;j<4;j++){in.input[0].a0[j]=-(float)(j+1);in.input[0].dx[j]=2*(float)(j+1);in.constant[1][j]=10*(float)(j+1);in.constant[2][j]=(float)(j+2);in.constant[3][j]=99;}
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);CHECK(cookie!=0);poison(&r);CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.live_mask==15&&r.output_count==2);quad(&r,0,expected);quad(&r,1,derivative);
 in.constant[1][3]=80;CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.output[0][0][0]==76&&r.output[0][0][1]==20);
 /* Original instruction mutation cannot modify retained genuine tokens. */
 code[7].opcode=M98_SP_TEXTURE;CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.output[0][0][0]==76);
 old=cookie;CHECK(m98_sp_close(&cookie)==0&&cookie==0);CHECK(o.live==0);CHECK(m98_sp_run(old,&in,&r)==M98_SP_STALE);CHECK(m98_sp_close(&cookie)==0);
 for(k=0;k<4;k++)CHECK(r.output[0][k][0]!=99);
}
static void planes_and_discard(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[3];m98_sp_program p;m98_sp_io in=io();m98_sp_result r;uint32_t cookie=0;unsigned j;
 const float dx[4][4]={{2,2,2,2},{4,4,4,4},{8,8,8,8},{16,16,16,16}};
 const float dy[4][4]={{3,3,3,3},{6,6,6,6},{12,12,12,12},{24,24,24,24}};
 code[0]=I(M98_SP_DDX,M98_SP_OUTPUT,0,1,S(M98_SP_INPUT,0),Z,Z);code[1]=I(M98_SP_DDY,M98_SP_OUTPUT,1,1,S(M98_SP_INPUT,0),Z,Z);code[2]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,3,1,0,0,2);
 for(j=0;j<4;j++){in.input[0].a0[j]=(float)(j+1);in.input[0].dx[j]=(float)(2u<<j);in.input[0].dy[j]=(float)(3u<<j);}in.quad_x=19;in.quad_y=23;
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);poison(&r);CHECK(m98_sp_run(cookie,&in,&r)==0);quad(&r,0,dx);quad(&r,1,dy);CHECK(m98_sp_close(&cookie)==0);
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_INPUT,0),Z,Z);code[1]=I(M98_SP_KILL_IF,0,0,1,S(M98_SP_INPUT,0),Z,Z);p=program(code,3,1,0,0,1);in=io();
 for(j=0;j<4;j++){in.input[0].a0[j]=-1;in.input[0].dx[j]=2;in.input[0].dy[j]=2;}
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);poison(&r);CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.live_mask==14);for(j=0;j<4;j++){CHECK(r.output[0][j][0]==-1);CHECK(r.output[0][j][1]==1);CHECK(r.output[0][j][2]==1);CHECK(r.output[0][j][3]==3);}
 in.live_mask=5;CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.live_mask==4);
 for(j=0;j<4;j++){in.input[0].dx[j]=0;in.input[0].dy[j]=0;}CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.live_mask==0);CHECK(m98_sp_close(&cookie)==0&&o.live==0);
}
static void errors_oom_lifetime(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[128];m98_sp_program p;m98_sp_io in=io();m98_sp_result r,before;uint32_t cookie=0,held[16],sentinel;unsigned i,delta,calls,live;
 for(i=0;i<127;i++)code[i]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[127]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,128,0,1,0,1);in.constant[0][0]=7;
 sentinel=0xfedcba98;o.fail_at=o.calls+1;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_NOMEM&&sentinel==0xfedcba98&&o.live==0);o.fail_at=0;
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);calls=o.calls;CHECK(m98_sp_run(cookie,&in,&r)==0);delta=o.calls-calls;CHECK(delta>10);live=o.live;
 for(i=1;i<=delta;i++){o.fail_at=o.calls+i;poison(&r);before=r;CHECK(m98_sp_run(cookie,&in,&r)==M98_SP_NOMEM);CHECK(memcmp(&before,&r,sizeof(r))==0);CHECK(o.live==live);o.fail_at=0;CHECK(m98_sp_run(cookie,&in,&r)==0&&r.output[0][0][0]==7);}
 o.reenter=1;o.cookie=&cookie;CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(o.nested==M98_SP_BUSY&&cookie);o.reenter=0;
 o.mutate=1;o.io=&in;in.constant[0][0]=7;in.live_mask=15;CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(r.output[0][0][0]==7&&r.live_mask==15);CHECK(in.constant[0][0]==999&&in.live_mask==1);o.mutate=0;o.io=NULL;
 poison(&r);before=r;in.live_mask=0;CHECK(m98_sp_run(cookie,&in,&r)==M98_SP_INVALID&&memcmp(&before,&r,sizeof(r))==0);in.live_mask=15;
 CHECK(m98_sp_close(&cookie)==0&&o.live==0);for(i=0;i<16;i++)CHECK(m98_sp_open(&p,&cb,&held[i])==0);sentinel=0xfedcba98;calls=o.calls;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_LIMIT&&sentinel==0xfedcba98&&o.calls==calls);
 for(i=0;i<16;i++){uint32_t stale=held[i];CHECK(m98_sp_close(&held[i])==0);poison(&r);before=r;CHECK(m98_sp_run(stale,&in,&r)==M98_SP_STALE&&memcmp(&r,&before,sizeof(r))==0);sentinel=stale;CHECK(m98_sp_close(&sentinel)==M98_SP_STALE&&sentinel==stale);}CHECK(o.live==0);
 /* Callback mutation at first allocation cannot change the validated snapshot. */
 o.mutate=1;o.original=code;CHECK(m98_sp_open(&p,&cb,&cookie)==0);o.mutate=0;o.original=NULL;CHECK(code[0].opcode==M98_SP_TEXTURE);CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(m98_sp_close(&cookie)==0&&o.live==0);
}
static void invalid_programs(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[40],saved;m98_sp_program p;uint32_t sentinel;unsigned i;
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[1]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,2,0,1,0,1);saved=code[0];
 for(i=0;i<12;i++){code[0]=saved;switch(i){case 0:code[0].source[0].index=1;break;case 1:code[0].source[0].swizzle[2]=4;break;case 2:code[0].source_count=4;break;case 3:code[0].dst_index=2;break;case 4:code[0].source[0].file=M98_SP_TEMP;break;case 5:code[0].reserved=1;break;case 6:code[0].source[1].file=M98_SP_CONSTANT;break;case 7:code[0].saturate=2;break;case 8:code[0].source[0].negate=2;break;case 9:code[0].dst_file=M98_SP_INPUT;break;case 10:code[0].opcode=M98_SP_END;code[0].source_count=0;memset(code[0].source,0,sizeof(code[0].source));code[0].dst_file=0;break;default:code[0].opcode=M98_SP_ENDIF;code[0].source_count=0;memset(code[0].source,0,sizeof(code[0].source));code[0].dst_file=0;break;}sentinel=0xabcdef;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_INVALID&&sentinel==0xabcdef&&o.live==0);}
 for(i=M98_SP_LOOP;i<=M98_SP_FMA;i++){code[0]=saved;code[0].opcode=i;sentinel=0xabcdef;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_UNSUPPORTED&&sentinel==0xabcdef);}
 code[0]=saved;p.instruction_count=129;sentinel=0xabcdef;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_LIMIT&&sentinel==0xabcdef);p.instruction_count=2;
 code[0]=I(M98_SP_IF,0,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[1]=I(M98_SP_MOV,M98_SP_TEMP,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[2]=I(M98_SP_ENDIF,0,0,0,Z,Z,Z);code[3]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_TEMP,0),Z,Z);code[4]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,5,0,1,1,1);sentinel=0xabcdef;CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_INVALID&&sentinel==0xabcdef);
 for(i=0;i<17;i++)code[i]=I(M98_SP_IF,0,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[17]=saved;for(i=18;i<35;i++)code[i]=I(M98_SP_ENDIF,0,0,0,Z,Z,Z);code[35]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,36,0,1,0,1);CHECK(m98_sp_open(&p,&cb,&sentinel)==M98_SP_LIMIT);
 CHECK(o.calls==0&&o.live==0);CHECK(m98_sp_close(NULL)==M98_SP_INVALID);
}
static void math_fenv(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[3];m98_sp_program p;m98_sp_io in=io();m98_sp_result r,before;uint32_t cookie=0;unsigned j,k;int old_round;union {float f;uint32_t u;} bits;
 const float expected[4]={0,1,0,-1};const float rounding[4]={0,2,-2,-0.0f};
 code[0]=I(M98_SP_SIN,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[1]=I(M98_SP_ROUND_EVEN,M98_SP_OUTPUT,1,1,S(M98_SP_CONSTANT,1),Z,Z);code[2]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,3,0,2,0,2);
 in.constant[0][0]=0;in.constant[0][1]=1.5707963267948966f;in.constant[0][2]=3.1415926535897932f;in.constant[0][3]=-1.5707963267948966f;in.constant[1][0]=.5f;in.constant[1][1]=1.5f;in.constant[1][2]=-2.5f;in.constant[1][3]=-.5f;
 old_round=fegetround();CHECK(fesetround(FE_DOWNWARD)==0);feclearexcept(FE_ALL_EXCEPT);feraiseexcept(FE_DIVBYZERO);CHECK(m98_sp_open(&p,&cb,&cookie)==0);CHECK(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);
 o.cookie=&cookie;o.reenter=1;poison(&r);CHECK(m98_sp_run(cookie,&in,&r)==0);CHECK(o.nested==M98_SP_BUSY&&o.math_calls==16);CHECK(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);o.reenter=0;
 for(j=0;j<4;j++)for(k=0;k<4;k++){CHECK(fabs((double)r.output[0][j][k]-expected[j])<0.000002);CHECK(r.output[1][j][k]==rounding[j]);}
 bits.f=r.output[1][3][0];CHECK(bits.u==0x80000000u);bits.f=r.output[1][0][0];CHECK(bits.u==0);
 o.fail_math=1;poison(&r);before=r;CHECK(m98_sp_run(cookie,&in,&r)==M98_SP_BACKEND&&memcmp(&r,&before,sizeof(r))==0);CHECK(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);o.fail_math=0;CHECK(m98_sp_run(cookie,&in,&r)==0);
 CHECK(m98_sp_close(&cookie)==0&&o.live==0);CHECK(fegetround()==FE_DOWNWARD&&fetestexcept(FE_ALL_EXCEPT)==FE_DIVBYZERO);fesetround(old_round);feclearexcept(FE_ALL_EXCEPT);
}
static void vector_math_and_identity(void)
{
 owner o={0};m98_sp_callbacks cb=callbacks(&o);m98_sp_instruction code[128];m98_sp_program p;m98_sp_io in=io();m98_sp_result r;uint32_t cookie=0;unsigned i,j,k;
 const unsigned operations[]={M98_SP_ADD,M98_SP_MUL,M98_SP_MAD,M98_SP_MIN,M98_SP_MAX,M98_SP_DP3,M98_SP_DP4,M98_SP_SLT,M98_SP_FLOOR,M98_SP_CEIL,M98_SP_TRUNC,M98_SP_SQRT,M98_SP_POW};
 const float a[4]={1,4,9,16},b[4]={2,3,4,5},c[4]={10,20,30,40};
 const float expected[][4]={{3,7,13,21},{2,12,36,80},{12,32,66,120},{1,3,4,5},{2,4,9,16},{50,50,50,50},{130,130,130,130},{1,0,0,0},{1,4,9,16},{1,4,9,16},{1,4,9,16},{1,2,3,4},{1,64,6561,1048576}};
 for(j=0;j<4;j++){in.constant[0][j]=a[j];in.constant[1][j]=b[j];in.constant[2][j]=c[j];}
 for(i=0;i<sizeof(operations)/sizeof(operations[0]);i++){
  unsigned n=operations[i]==M98_SP_MAD?3:operations[i]==M98_SP_FLOOR||operations[i]==M98_SP_CEIL||operations[i]==M98_SP_TRUNC||operations[i]==M98_SP_SQRT?1:2;
  code[0]=I(operations[i],M98_SP_OUTPUT,0,n,S(M98_SP_CONSTANT,0),n>1?S(M98_SP_CONSTANT,1):Z,n>2?S(M98_SP_CONSTANT,2):Z);code[1]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,2,0,3,0,1);
  CHECK(m98_sp_open(&p,&cb,&cookie)==0);poison(&r);CHECK(m98_sp_run(cookie,&in,&r)==0&&r.live_mask==15);
  for(j=0;j<4;j++)for(k=0;k<4;k++)CHECK(r.output[0][j][k]==expected[i][j]);CHECK(m98_sp_close(&cookie)==0&&o.live==0);
 }
 /* A self-swizzled scalar math destination must use the original full vec4,
  * not values overwritten by earlier scalar instructions in the lowering. */
 code[0]=I(M98_SP_MOV,M98_SP_TEMP,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[1]=I(M98_SP_SQRT,M98_SP_TEMP,0,1,S(M98_SP_TEMP,0),Z,Z);
 for(j=0;j<4;j++)code[1].source[0].swizzle[j]=3-j;
 code[2]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_TEMP,0),Z,Z);code[3]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,4,0,1,1,1);
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);CHECK(m98_sp_run(cookie,&in,&r)==0);for(j=0;j<4;j++)for(k=0;k<4;k++)CHECK(r.output[0][j][k]==(float)(4-j));CHECK(m98_sp_close(&cookie)==0&&o.live==0);
 /* Maximum public instruction stream exercises scalar expansion/reallocation
  * without requiring a source compiler or admitting loop instructions. */
 for(i=0;i<127;i++)code[i]=I(M98_SP_SQRT,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[127]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,128,0,1,0,1);
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);CHECK(m98_sp_run(cookie,&in,&r)==0);for(j=0;j<4;j++)for(k=0;k<4;k++)CHECK(r.output[0][j][k]==(float)(j+1));CHECK(m98_sp_close(&cookie)==0&&o.live==0);
 /* Modifiers and saturation are processed by genuine TGSI arithmetic. */
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[0].source[0].absolute=1;code[0].source[0].negate=1;code[0].saturate=1;code[1]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,2,0,1,0,1);
 in.constant[0][0]=-9;in.constant[0][1]=-0.25f;in.constant[0][2]=0.75f;in.constant[0][3]=5;
 CHECK(m98_sp_open(&p,&cb,&cookie)==0);CHECK(m98_sp_run(cookie,&in,&r)==0);for(j=0;j<4;j++)for(k=0;k<4;k++)CHECK(r.output[0][j][k]==0);CHECK(m98_sp_close(&cookie)==0&&o.live==0);
}
static void context_isolation(void)
{
 owner a={0},b={0};m98_sp_callbacks ca=callbacks(&a),cb=callbacks(&b);m98_sp_instruction code[2];m98_sp_program p;m98_sp_io in=io();m98_sp_result r;uint32_t first=0,second=0,stale;
 code[0]=I(M98_SP_MOV,M98_SP_OUTPUT,0,1,S(M98_SP_CONSTANT,0),Z,Z);code[1]=I(M98_SP_END,0,0,0,Z,Z,Z);p=program(code,2,0,1,0,1);
 CHECK(m98_sp_open(&p,&ca,&first)==0);CHECK(m98_sp_open(&p,&cb,&second)==0&&first!=second);in.constant[0][0]=11;CHECK(m98_sp_run(first,&in,&r)==0&&r.output[0][0][0]==11);in.constant[0][0]=19;CHECK(m98_sp_run(second,&in,&r)==0&&r.output[0][0][0]==19);
 stale=first;CHECK(m98_sp_close(&first)==0&&a.live==0&&b.live==1);CHECK(m98_sp_run(second,&in,&r)==0&&r.output[0][0][0]==19);CHECK(m98_sp_run(stale,&in,&r)==M98_SP_STALE);CHECK(m98_sp_close(&second)==0&&b.live==0);
}
int main(void){CHECK(m98_sp_abi()==1);branch_uniform();planes_and_discard();errors_oom_lifetime();invalid_programs();vector_math_and_identity();context_isolation();math_fenv();printf("PASS genuine Mesa TGSI foundation: %u assertions; no native/GLES/WebGL/WebGPU claim\n",checks);return 0;}
