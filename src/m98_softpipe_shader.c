/* SPDX-License-Identifier: GPL-2.0-only */
#include "m98_softpipe_shader.h"
#include <string.h>
#include <limits.h>
#include <float.h>
_Static_assert(sizeof(float)==4&&sizeof(double)==8&&FLT_RADIX==2&&FLT_MANT_DIG==24&&DBL_MANT_DIG==53,"IEEE binary32/binary64 profile required");
#ifndef _WIN32
#include <fenv.h>
#endif
#include "tgsi/tgsi_build.h"
#include "tgsi/tgsi_exec.h"

typedef struct {
 m98_sp_callbacks cb; uint32_t cookie,inputs,constants,temps,outputs,instructions;
 struct tgsi_token *tokens; size_t bytes; int fault;
} context;
typedef struct { void *raw; size_t raw_bytes,payload; context *owner; uint32_t magic; } heap_header;
static context contexts[M98_SP_MAX_CONTEXTS];
static context *active;
static volatile uint32_t locked;
static uint32_t serial;
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
 fegetenv(&s->state);fesetround(FE_TONEAREST);feclearexcept(FE_ALL_EXCEPT);
#endif
}
static void fp_leave(fp_scope *s){
#ifdef _WIN32
 __asm__ volatile("frstor %0"::"m"(s->state):"memory");
#else
 fesetenv(&s->state);
#endif
}
enum { TOKENS=4096,HEAP_MAGIC=0x38535048 };
static int enter(void){return __sync_val_compare_and_swap(&locked,0,1)==0;}
static void leave(void){active=NULL;__sync_lock_release(&locked);}
static context *find(uint32_t cookie){unsigned i;for(i=0;i<M98_SP_MAX_CONTEXTS;i++)if(cookie&&contexts[i].cookie==cookie)return &contexts[i];return NULL;}
static void fault(int e){if(active&&!active->fault)active->fault=e;}

void *m98_sp_heap_aligned(size_t n,size_t alignment)
{
 void *raw; uintptr_t aligned; heap_header *h; size_t total;
 if(!active||!n||alignment<sizeof(void*)||alignment>4096||(alignment&(alignment-1))){fault(M98_SP_INVALID);return NULL;}
 if(n>SIZE_MAX-sizeof(*h)-(alignment-1)){fault(M98_SP_LIMIT);return NULL;}
 total=n+sizeof(*h)+alignment-1;
 if(total>M98_SP_MEMORY_LIMIT-active->bytes){fault(M98_SP_LIMIT);return NULL;}
 raw=active->cb.allocate(active->cb.user,total);
 if(!raw){fault(M98_SP_NOMEM);return NULL;}
 aligned=((uintptr_t)raw+sizeof(*h)+alignment-1)&~(uintptr_t)(alignment-1);
 h=(heap_header*)aligned-1;h->raw=raw;h->raw_bytes=total;h->payload=n;h->owner=active;h->magic=HEAP_MAGIC;
 active->bytes+=total;return (void*)aligned;
}
void *m98_sp_heap_alloc(size_t n){return m98_sp_heap_aligned(n,16);}
void *m98_sp_heap_calloc(size_t n,size_t each){void *p;if(each&&n>SIZE_MAX/each){fault(M98_SP_LIMIT);return NULL;}p=m98_sp_heap_alloc(n*each);if(p)memset(p,0,n*each);return p;}
void m98_sp_heap_free(void *p){heap_header *h;context *owner;void *raw;if(!p)return;h=(heap_header*)p-1;owner=h->owner;raw=h->raw;if(h->magic!=HEAP_MAGIC||owner!=active||h->raw_bytes>owner->bytes){fault(M98_SP_BACKEND);return;}owner->bytes-=h->raw_bytes;h->magic=0;owner->cb.deallocate(owner->cb.user,raw);}
void *m98_sp_heap_realloc(void *p,size_t n){void *q;size_t old;if(!p)return m98_sp_heap_alloc(n);if(!n){m98_sp_heap_free(p);return NULL;}old=((heap_header*)p-1)->payload;q=m98_sp_heap_alloc(n);if(q){memcpy(q,p,old<n?old:n);m98_sp_heap_free(p);}return q;}

typedef union {float f;uint32_t u;} fbits;
typedef union {double d;uint64_t u;} dbits;
static double nan_double(void){dbits b;b.u=UINT64_C(0x7ff8000000000000);return b.d;}
static double math_call(uint32_t op,double x,double y){double r=nan_double();if(!active||active->fault)return r;if(active->cb.math(active->cb.user,op,x,y,&r)!=0){fault(M98_SP_BACKEND);return nan_double();}return r;}
float m98_sp_math_cosf(float x){return (float)math_call(M98_SP_MATH_COS,x,0);}
float m98_sp_math_sinf(float x){return (float)math_call(M98_SP_MATH_SIN,x,0);}
float m98_sp_math_logf(float x){return (float)math_call(M98_SP_MATH_LOG,x,0);}
float m98_sp_math_powf(float x,float y){return (float)math_call(M98_SP_MATH_POW,x,y);}
float m98_sp_math_sqrtf(float x){return (float)math_call(M98_SP_MATH_SQRT,x,0);}
float m98_sp_math_floorf(float x){return (float)math_call(M98_SP_MATH_FLOOR,x,0);}
float m98_sp_math_ceilf(float x){return (float)math_call(M98_SP_MATH_CEIL,x,0);}
float m98_sp_math_ldexpf(float x,int n){return (float)math_call(M98_SP_MATH_LDEXP,x,n);}
double m98_sp_math_floor(double x){return math_call(M98_SP_MATH_FLOOR,x,0);}
double m98_sp_math_sqrt(double x){return math_call(M98_SP_MATH_SQRT,x,0);}
double m98_sp_math_ldexp(double x,int n){return math_call(M98_SP_MATH_LDEXP,x,n);}
float m98_sp_math_fabsf(float x){fbits b;b.f=x;b.u&=0x7fffffffu;return b.f;}
float m98_sp_math_truncf(float x){fbits b;int e;b.f=x;e=(int)((b.u>>23)&255)-127;if(e<0)b.u&=0x80000000u;else if(e<23)b.u&=~((1u<<(23-e))-1);return b.f;}
float m98_sp_math_rintf(float x){fbits b;uint32_t sign,a,mask,half;int e;b.f=x;sign=b.u&0x80000000u;a=b.u&0x7fffffffu;e=(int)(a>>23)-127;if(e<0){b.u=sign|(a>0x3f000000u?0x3f800000u:0);return b.f;}if(e>=23)return x;mask=(1u<<(23-e))-1;half=(mask+1)>>1;if((a&mask)>half||((a&mask)==half&&((a>>(23-e))&1)))a+=mask+1;b.u=sign|(a&~mask);return b.f;}
double m98_sp_math_rint(double x){dbits b;uint64_t sign,a,mask,half;int e;b.d=x;sign=b.u&UINT64_C(0x8000000000000000);a=b.u&UINT64_C(0x7fffffffffffffff);e=(int)(a>>52)-1023;if(e<0){b.u=sign|(a>UINT64_C(0x3fe0000000000000)?UINT64_C(0x3ff0000000000000):0);return b.d;}if(e>=52)return x;mask=(UINT64_C(1)<<(52-e))-1;half=(mask+1)>>1;if((a&mask)>half||((a&mask)==half&&((a>>(52-e))&1)))a+=mask+1;b.u=sign|(a&~mask);return b.d;}
/* Genuine x87 integer rounding under the owned nearest/masked scope. Mesa's
 * scalar half-conversion helper needs lrintf even though half ops are excluded
 * from this public IR. FISTP keeps IEEE exception/indefinite integer behavior. */
long m98_sp_math_lrintf(float x){long result;
#ifdef _WIN32
 __asm__ volatile("flds %1\n\tfistpl %0":"=m"(result):"m"(x):"memory");
#else
 __asm__ volatile("flds %1\n\tfistpq %0":"=m"(result):"m"(x):"memory");
#endif
 return result;
}
int m98_sp_ffs(int x){unsigned v=(unsigned)x;int n=1;if(!v)return 0;while(!(v&1)){v>>=1;++n;}return n;}
static int isnanf_bits(float x){fbits b;b.f=x;return (b.u&0x7fffffffu)>0x7f800000u;}
static int isnand_bits(double x){dbits b;b.d=x;return (b.u&UINT64_C(0x7fffffffffffffff))>UINT64_C(0x7ff0000000000000);}
float m98_sp_math_fminf(float x,float y){fbits a,b;if(isnanf_bits(x))return y;if(isnanf_bits(y))return x;a.f=x;b.f=y;if(x==0&&y==0){a.u|=b.u;return a.f;}return x<y?x:y;}
float m98_sp_math_fmaxf(float x,float y){fbits a,b;if(isnanf_bits(x))return y;if(isnanf_bits(y))return x;a.f=x;b.f=y;if(x==0&&y==0){a.u&=b.u;return a.f;}return x>y?x:y;}
double m98_sp_math_fmin(double x,double y){dbits a,b;if(isnand_bits(x))return y;if(isnand_bits(y))return x;a.d=x;b.d=y;if(x==0&&y==0){a.u|=b.u;return a.d;}return x<y?x:y;}
double m98_sp_math_fmax(double x,double y){dbits a,b;if(isnand_bits(x))return y;if(isnand_bits(y))return x;a.d=x;b.d=y;if(x==0&&y==0){a.u&=b.u;return a.d;}return x>y?x:y;}

typedef struct {uint32_t op;enum tgsi_opcode tgsi;unsigned sources,destination;} opcode;
static const opcode ops[]={
 {M98_SP_MOV,TGSI_OPCODE_MOV,1,1},{M98_SP_ADD,TGSI_OPCODE_ADD,2,1},
 {M98_SP_MUL,TGSI_OPCODE_MUL,2,1},{M98_SP_MAD,TGSI_OPCODE_MAD,3,1},
 {M98_SP_MIN,TGSI_OPCODE_MIN,2,1},{M98_SP_MAX,TGSI_OPCODE_MAX,2,1},
 {M98_SP_DP3,TGSI_OPCODE_DP3,2,1},{M98_SP_DP4,TGSI_OPCODE_DP4,2,1},
 {M98_SP_DDX,TGSI_OPCODE_DDX_FINE,1,1},{M98_SP_DDY,TGSI_OPCODE_DDY_FINE,1,1},
 {M98_SP_SLT,TGSI_OPCODE_SLT,2,1},{M98_SP_IF,TGSI_OPCODE_IF,1,0},
 {M98_SP_ELSE,TGSI_OPCODE_ELSE,0,0},{M98_SP_ENDIF,TGSI_OPCODE_ENDIF,0,0},
 {M98_SP_KILL_IF,TGSI_OPCODE_KILL_IF,1,0},{M98_SP_END,TGSI_OPCODE_END,0,0},
 {M98_SP_SIN,TGSI_OPCODE_SIN,1,1},{M98_SP_COS,TGSI_OPCODE_COS,1,1},
 {M98_SP_SQRT,TGSI_OPCODE_SQRT,1,1},{M98_SP_FLOOR,TGSI_OPCODE_FLR,1,1},
 {M98_SP_CEIL,TGSI_OPCODE_CEIL,1,1},{M98_SP_TRUNC,TGSI_OPCODE_TRUNC,1,1},
 {M98_SP_ROUND_EVEN,TGSI_OPCODE_ROUND,1,1},{M98_SP_POW,TGSI_OPCODE_POW,2,1}};
static const opcode *operation(uint32_t n){unsigned i;for(i=0;i<sizeof(ops)/sizeof(ops[0]);i++)if(ops[i].op==n)return &ops[i];return NULL;}
static int scalar_math(uint32_t op){return op==M98_SP_SIN||op==M98_SP_COS||op==M98_SP_SQRT||op==M98_SP_POW;}
static unsigned tgsi_file(unsigned n){switch(n){case M98_SP_INPUT:return TGSI_FILE_INPUT;case M98_SP_CONSTANT:return TGSI_FILE_CONSTANT;case M98_SP_TEMP:return TGSI_FILE_TEMPORARY;case M98_SP_OUTPUT:return TGSI_FILE_OUTPUT;default:return TGSI_FILE_NULL;}}
static int zero_source(const m98_sp_source *s){static const m98_sp_source zero={0};return memcmp(s,&zero,sizeof(*s))==0;}
static int validate(const m98_sp_program *p)
{
 struct {uint32_t before,then_bits;unsigned otherwise;} stack[M98_SP_MAX_DEPTH];
 uint32_t initialized=0;unsigned depth=0,i,j,k;
 if(!p||p->abi!=1||p->reserved[0]||p->reserved[1]||!p->instructions||!p->instruction_count||!p->output_count)return M98_SP_INVALID;
 if(p->instruction_count>M98_SP_MAX_INSTRUCTIONS||p->input_count>M98_SP_MAX_INPUTS||p->constant_count>M98_SP_MAX_CONSTANTS||p->temp_count>M98_SP_MAX_TEMPS||p->output_count>M98_SP_MAX_OUTPUTS)return M98_SP_LIMIT;
 for(i=0;i<p->instruction_count;i++){
  const m98_sp_instruction *in=&p->instructions[i];const opcode *op=operation(in->opcode);
  if(!op)return M98_SP_UNSUPPORTED;
  if(in->reserved||in->source_count!=op->sources||in->saturate>1||(!op->destination&&in->saturate))return M98_SP_INVALID;
  if(!op->destination&&(in->dst_file||in->dst_index))return M98_SP_INVALID;
  for(j=0;j<3;j++){
   const m98_sp_source *s=&in->source[j];
   if(j>=in->source_count){if(!zero_source(s))return M98_SP_INVALID;continue;}
   if(s->negate>1||s->absolute>1)return M98_SP_INVALID;
   for(k=0;k<4;k++)if(s->swizzle[k]>3)return M98_SP_INVALID;
   switch(s->file){case M98_SP_INPUT:if(s->index>=p->input_count)return M98_SP_INVALID;break;
    case M98_SP_CONSTANT:if(s->index>=p->constant_count)return M98_SP_INVALID;break;
    case M98_SP_TEMP:if(s->index>=p->temp_count||!(initialized&(1u<<s->index)))return M98_SP_INVALID;break;
    default:return M98_SP_INVALID;}
  }
  if(in->opcode==M98_SP_IF){if(depth==M98_SP_MAX_DEPTH)return M98_SP_LIMIT;stack[depth].before=initialized;stack[depth].otherwise=0;depth++;}
  else if(in->opcode==M98_SP_ELSE){if(!depth||stack[depth-1].otherwise)return M98_SP_INVALID;stack[depth-1].otherwise=1;stack[depth-1].then_bits=initialized;initialized=stack[depth-1].before;}
  else if(in->opcode==M98_SP_ENDIF){if(!depth)return M98_SP_INVALID;depth--;initialized&=stack[depth].otherwise?stack[depth].then_bits:stack[depth].before;}
  else if(in->opcode==M98_SP_END){if(depth||i+1!=p->instruction_count)return M98_SP_INVALID;}
  else if((in->opcode==M98_SP_DDX||in->opcode==M98_SP_DDY)&&depth)return M98_SP_UNSUPPORTED;
  if(op->destination){unsigned bit;
   if(in->dst_file==M98_SP_TEMP){if(in->dst_index>=p->temp_count)return M98_SP_INVALID;bit=in->dst_index;}
   else if(in->dst_file==M98_SP_OUTPUT){if(in->dst_index>=p->output_count)return M98_SP_INVALID;bit=M98_SP_MAX_TEMPS+in->dst_index;}
   else return M98_SP_INVALID;
   initialized|=1u<<bit;
  }
 }
 if(p->instructions[p->instruction_count-1].opcode!=M98_SP_END||depth)return M98_SP_INVALID;
 for(i=0;i<p->output_count;i++)if(!(initialized&(1u<<(M98_SP_MAX_TEMPS+i))))return M98_SP_INVALID;
 return M98_SP_OK;
}

static unsigned declaration(struct tgsi_token *tokens,unsigned at,struct tgsi_header *h,unsigned file,unsigned count)
{
 struct tgsi_full_declaration d=tgsi_default_full_declaration();unsigned n;if(!count)return at;
 d.Declaration.File=file;d.Range.First=0;d.Range.Last=count-1;
 if(file==TGSI_FILE_INPUT){d.Declaration.Interpolate=1;d.Interp.Interpolate=TGSI_INTERPOLATE_LINEAR;d.Declaration.Semantic=1;d.Semantic.Name=TGSI_SEMANTIC_GENERIC;}
 if(file==TGSI_FILE_OUTPUT){d.Declaration.Semantic=1;d.Semantic.Name=TGSI_SEMANTIC_COLOR;}
 n=tgsi_build_full_declaration(&d,tokens+at,h,TOKENS-at);return n?at+n:0;
}
static int build(context *c,const m98_sp_program *p)
{
 struct tgsi_header *h;struct tgsi_processor processor;unsigned at=2,i,j,n,k,extra=0;
 for(i=0;i<p->instruction_count;i++)if(scalar_math(p->instructions[i].opcode))extra=1;
 c->temps=p->temp_count+extra;c->instructions=0;
 c->tokens=m98_sp_heap_calloc(TOKENS,sizeof(*c->tokens));if(!c->tokens)return c->fault;
 h=(struct tgsi_header*)c->tokens;*h=tgsi_build_header();processor=tgsi_build_processor(MESA_SHADER_FRAGMENT,h);memcpy(c->tokens+1,&processor,4);
 at=declaration(c->tokens,at,h,TGSI_FILE_INPUT,p->input_count);if(!at)return M98_SP_BACKEND;
 at=declaration(c->tokens,at,h,TGSI_FILE_CONSTANT,p->constant_count);if(!at)return M98_SP_BACKEND;
 at=declaration(c->tokens,at,h,TGSI_FILE_TEMPORARY,c->temps);if(!at)return M98_SP_BACKEND;
 at=declaration(c->tokens,at,h,TGSI_FILE_OUTPUT,p->output_count);if(!at)return M98_SP_BACKEND;
 for(i=0;i<p->instruction_count;i++){
  const m98_sp_instruction *in=&p->instructions[i];const opcode *op=operation(in->opcode);struct tgsi_full_instruction t=tgsi_default_full_instruction();
  if(!op)return M98_SP_UNSUPPORTED;
  t.Instruction.Opcode=op->tgsi;t.Instruction.NumDstRegs=op->destination;t.Instruction.NumSrcRegs=op->sources;t.Instruction.Saturate=in->saturate;
  if(op->destination){t.Dst[0].Register.File=tgsi_file(in->dst_file);t.Dst[0].Register.Index=in->dst_index;t.Dst[0].Register.WriteMask=15;}
  for(j=0;j<op->sources;j++){const m98_sp_source *s=&in->source[j];struct tgsi_src_register *r=&t.Src[j].Register;r->File=tgsi_file(s->file);r->Index=s->index;r->SwizzleX=s->swizzle[0];r->SwizzleY=s->swizzle[1];r->SwizzleZ=s->swizzle[2];r->SwizzleW=s->swizzle[3];r->Negate=s->negate;r->Absolute=s->absolute;}
  if(scalar_math(in->opcode)){
   /* TGSI SIN/COS/SQRT/POW are scalar-X ops. Lower four independent
    * components into a private scratch before the destination write so
    * overlapping/self-swizzled temporary sources keep their original value. */
   struct tgsi_full_instruction move=tgsi_default_full_instruction();
   t.Dst[0].Register.File=TGSI_FILE_TEMPORARY;t.Dst[0].Register.Index=p->temp_count;
   for(k=0;k<4;k++){
    t.Dst[0].Register.WriteMask=1u<<k;
    for(j=0;j<op->sources;j++)t.Src[j].Register.SwizzleX=in->source[j].swizzle[k];
    n=tgsi_build_full_instruction(&t,c->tokens+at,h,TOKENS-at);if(!n)return M98_SP_BACKEND;at+=n;c->instructions++;
   }
   move.Instruction.Opcode=TGSI_OPCODE_MOV;move.Instruction.NumDstRegs=1;move.Instruction.NumSrcRegs=1;
   move.Dst[0].Register.File=tgsi_file(in->dst_file);move.Dst[0].Register.Index=in->dst_index;move.Dst[0].Register.WriteMask=15;
   move.Src[0].Register.File=TGSI_FILE_TEMPORARY;move.Src[0].Register.Index=p->temp_count;
   move.Src[0].Register.SwizzleX=0;move.Src[0].Register.SwizzleY=1;move.Src[0].Register.SwizzleZ=2;move.Src[0].Register.SwizzleW=3;
   n=tgsi_build_full_instruction(&move,c->tokens+at,h,TOKENS-at);if(!n)return M98_SP_BACKEND;at+=n;c->instructions++;
  }else{n=tgsi_build_full_instruction(&t,c->tokens+at,h,TOKENS-at);if(!n)return M98_SP_BACKEND;at+=n;c->instructions++;}
 }
 if(h->HeaderSize+h->BodySize!=at)return M98_SP_BACKEND;
 return M98_SP_OK;
}
int m98_sp_open(const m98_sp_program *p,const m98_sp_callbacks *cb,uint32_t *cookie)
{
 context *c=NULL;unsigned i;int rc;fp_scope scope;m98_sp_program snapshot;m98_sp_instruction code[M98_SP_MAX_INSTRUCTIONS];
 if(!cookie||!cb||cb->abi!=1||cb->reserved||!cb->allocate||!cb->deallocate||!cb->math)return M98_SP_INVALID;
 if(!enter())return M98_SP_BUSY;
 fp_enter(&scope);
 if(!p){rc=M98_SP_INVALID;goto done;}
 snapshot=*p;
 if(!snapshot.instructions||!snapshot.instruction_count){rc=M98_SP_INVALID;goto done;}
 if(snapshot.instruction_count>M98_SP_MAX_INSTRUCTIONS){rc=M98_SP_LIMIT;goto done;}
 memcpy(code,snapshot.instructions,snapshot.instruction_count*sizeof(*code));snapshot.instructions=code;p=&snapshot;
 rc=validate(p);if(rc)goto done;
 for(i=0;i<M98_SP_MAX_CONTEXTS;i++)if(!contexts[i].cookie){c=&contexts[i];break;}
 if(!c||serial>=0x07ffffffu){rc=M98_SP_LIMIT;goto done;}
 memset(c,0,sizeof(*c));c->cb=*cb;active=c;
 rc=build(c,p);if(rc){m98_sp_heap_free(c->tokens);memset(c,0,sizeof(*c));goto done;}
 c->inputs=p->input_count;c->constants=p->constant_count;c->outputs=p->output_count;c->cookie=++serial;*cookie=c->cookie;
done:fp_leave(&scope);leave();return rc;
}

static int finite_float(float x){fbits b;b.f=x;return (b.u&0x7f800000u)!=0x7f800000u;}
static int execute(context *c,const m98_sp_io *io,m98_sp_result *out)
{
 struct tgsi_exec_machine *m=NULL;struct tgsi_interp_coef coef[M98_SP_MAX_INPUTS];struct tgsi_exec_consts_info constant; m98_sp_result result;m98_sp_io snapshot;unsigned i,j,k,count;int rc=M98_SP_OK;
 if(!io||!out)return M98_SP_INVALID;
 snapshot=*io;io=&snapshot;
 if(io->abi!=1||!io->live_mask||io->live_mask>15||io->reserved[0]||io->reserved[1]||!finite_float(io->quad_x)||!finite_float(io->quad_y))return M98_SP_INVALID;
 for(i=0;i<c->inputs;i++)for(j=0;j<4;j++)if(!finite_float(io->input[i].a0[j])||!finite_float(io->input[i].dx[j])||!finite_float(io->input[i].dy[j]))return M98_SP_INVALID;
 c->fault=0;m=tgsi_exec_machine_create(MESA_SHADER_FRAGMENT);if(!m){rc=c->fault?c->fault:M98_SP_NOMEM;goto done;}
 if(!m98_tgsi_bind_checked(m,c->tokens,NULL,NULL,NULL)||c->fault){rc=c->fault?c->fault:M98_SP_BACKEND;goto done;}
 count=(c->inputs!=0)+(c->constants!=0)+(c->temps!=0)+(c->outputs!=0);
 if(m->NumInstructions!=c->instructions||m->NumDeclarations!=count||!m->Instructions||!m->Declarations||m->Tokens!=c->tokens||m->ShaderType!=MESA_SHADER_FRAGMENT||m->ImmLimit){rc=M98_SP_BACKEND;goto done;}
 memset(m->Inputs,0,sizeof(struct tgsi_exec_vector)*PIPE_MAX_SHADER_INPUTS);memset(m->Outputs,0xa5,sizeof(struct tgsi_exec_vector)*PIPE_MAX_SHADER_OUTPUTS);
 for(i=0;i<c->inputs;i++)for(j=0;j<4;j++){coef[i].a0[j]=io->input[i].a0[j];coef[i].dadx[j]=io->input[i].dx[j];coef[i].dady[j]=io->input[i].dy[j];}
 m->InterpCoefs=coef;m->NonHelperMask=io->live_mask;
 for(k=0;k<4;k++){m->QuadPos.xyzw[0].f[k]=io->quad_x+(float)(k&1);m->QuadPos.xyzw[1].f[k]=io->quad_y+(float)(k>>1);m->QuadPos.xyzw[3].f[k]=1;}
 memset(&constant,0,sizeof(constant));constant.ptr=io->constant;constant.size=c->constants*4*sizeof(float);tgsi_exec_set_constant_buffers(m,1,&constant);
 memset(&result,0,sizeof(result));result.live_mask=tgsi_exec_machine_run(m,0)&io->live_mask&15;result.output_count=c->outputs;
 if(c->fault){rc=c->fault;goto done;}
 for(i=0;i<c->outputs;i++)for(j=0;j<4;j++)for(k=0;k<4;k++)result.output[i][j][k]=m->Outputs[i].xyzw[j].f[k];
done:tgsi_exec_machine_destroy(m);if(!rc&&c->fault)rc=c->fault;if(!rc)*out=result;return rc;
}
int m98_sp_run(uint32_t cookie,const m98_sp_io *io,m98_sp_result *out){context *c;fp_scope scope;int rc;if(!enter())return M98_SP_BUSY;c=find(cookie);if(!c){leave();return M98_SP_STALE;}active=c;fp_enter(&scope);rc=execute(c,io,out);fp_leave(&scope);leave();return rc;}
int m98_sp_close(uint32_t *cookie){context *c;fp_scope scope;int rc=M98_SP_OK;if(!cookie)return M98_SP_INVALID;if(!enter())return M98_SP_BUSY;fp_enter(&scope);if(!*cookie)goto done;c=find(*cookie);if(!c){rc=M98_SP_STALE;goto done;}active=c;m98_sp_heap_free(c->tokens);memset(c,0,sizeof(*c));*cookie=0;done:fp_leave(&scope);leave();return rc;}
uint32_t m98_sp_abi(void){return 1;}
