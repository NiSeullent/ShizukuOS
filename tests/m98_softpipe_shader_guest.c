/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine native component trial, no drawing/network/browser claim.
 * Requires a fresh adjacent DLL/log and a separate actual child observer.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <string.h>
#include "m98_softpipe_shader.h"
#include "selected.h"
_Static_assert(sizeof(m98_sp_source)==32&&sizeof(m98_sp_instruction)==120,"typed source/instruction ABI");
_Static_assert(sizeof(m98_sp_program)==36&&sizeof(m98_sp_callbacks)==24,"native pointer/callback ABI");
_Static_assert(sizeof(m98_sp_io)==344&&sizeof(m98_sp_result)==136,"native quad/result ABI");

typedef int (*open_fn)(const m98_sp_program *,const m98_sp_callbacks *,uint32_t *);
typedef int (*run_fn)(uint32_t,const m98_sp_io *,m98_sp_result *);
typedef int (*close_fn)(uint32_t *);
typedef uint32_t (*abi_fn)(void);
typedef double (*unary_fn)(double);
typedef double (*binary_fn)(double,double);
typedef double (*scale_fn)(double,int);
static open_fn sp_open;static run_fn sp_run;static close_fn sp_close;
static unary_fn unary[9];static binary_fn power;static scale_fn scale;
static HANDLE log_file=INVALID_HANDLE_VALUE,heap;
static unsigned checks,allocations,live_blocks,fail_next,reentry;
static uint32_t cookie_for_reentry;

static void text(const char *s){DWORD n=0,w=0;while(s[n])++n;
 if(log_file==INVALID_HANDLE_VALUE||!WriteFile(log_file,s,n,&w,NULL)||w!=n)ExitProcess(2);}
static void number(DWORD n){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);text(b+i);}
static void check(int ok,const char *name){++checks;text("CHECK:");text(name);text(ok?"=1\r\n":"=0\r\n");
 if(!ok){text("FAILURES=1\r\nSTATUS=FAIL\r\n");FlushFileBuffers(log_file);CloseHandle(log_file);ExitProcess(1);}}
#define C(x,n) check(!!(x),n)
static int same_path(const char *a,const char *b){unsigned i=0;char x,y;
 do{x=a[i];y=b[i];if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return 0;++i;}while(x);return 1;}
static void append(char *path,unsigned n,const char *tail){unsigned i=0;do{path[n+i]=tail[i];}while(tail[i++]);}
static HMODULE exact_load(const char *path,const char *label){char actual[MAX_PATH];DWORD n;HMODULE m=LoadLibraryA(path);
 C(m!=NULL,label);n=GetModuleFileNameA(m,actual,sizeof(actual));C(n&&n<sizeof(actual),"module_path_bounded");
 C(same_path(path,actual),"module_path_exact");text("MODULE_PATH=");text(actual);text("\r\n");return m;}
static void *allocate(void *u,size_t n){void *p;(void)u;++allocations;
 if(reentry){uint32_t saved=cookie_for_reentry;reentry=0;C(sp_close(&saved)==M98_SP_BUSY&&saved==cookie_for_reentry,"callback_reentry_busy");}
 if(fail_next){fail_next=0;return NULL;}p=HeapAlloc(heap,0,n);if(p)++live_blocks;return p;}
static void deallocate(void *u,void *p){(void)u;C(live_blocks&&HeapFree(heap,0,p),"native_heap_free");--live_blocks;}
static int provider(void *u,uint32_t op,double x,double y,double *out){(void)u;
 if(op==M98_SP_MATH_POW){*out=power(x,y);return 0;}
 if(op==M98_SP_MATH_LDEXP){*out=scale(x,(int)y);return 0;}
 if(op<1||op>8||!unary[op])return 1;
 *out=unary[op](x);return 0;}
static m98_sp_source source(unsigned file,unsigned index){m98_sp_source s={0};unsigned i;s.file=file;s.index=index;for(i=0;i<4;i++)s.swizzle[i]=i;return s;}
static m98_sp_instruction op(unsigned code,unsigned dst,unsigned index,unsigned n,m98_sp_source a,m98_sp_source b){m98_sp_instruction x={0};x.opcode=code;x.dst_file=dst;x.dst_index=index;x.source_count=n;if(n)x.source[0]=a;if(n>1)x.source[1]=b;return x;}
static m98_sp_program program(m98_sp_instruction *code,unsigned n,unsigned in,unsigned cn,unsigned temp,unsigned out){m98_sp_program p={0};p.abi=1;p.instruction_count=n;p.input_count=in;p.constant_count=cn;p.temp_count=temp;p.output_count=out;p.instructions=code;return p;}
static m98_sp_io io_value(void){m98_sp_io io={0};io.abi=1;io.live_mask=15;return io;}
static int near_values(float a,float b){float d=a-b;return d>=-0.000002f&&d<=0.000002f;}
typedef struct {unsigned char bytes[108];} fp_state;
static void fp_read(fp_state *s){__asm__ volatile("fnsave %0\n\tfwait\n\tfrstor %0":"=m"(s->bytes)::"memory");}
static void fp_begin(void){unsigned short cw=0x067f;__asm__ volatile("fninit\n\tfldcw %0\n\tfld1\n\tfldpi"::"m"(cw):"memory");}
static int saved_open(const m98_sp_program *p,const m98_sp_callbacks *cb,uint32_t *cookie){fp_state a,b;int rc;fp_read(&a);rc=sp_open(p,cb,cookie);fp_read(&b);C(!memcmp(&a,&b,sizeof(a)),"open_full_x87_state");return rc;}
static int saved_run(uint32_t cookie,const m98_sp_io *io,m98_sp_result *r){fp_state a,b;int rc;fp_read(&a);rc=sp_run(cookie,io,r);fp_read(&b);C(!memcmp(&a,&b,sizeof(a)),"run_full_x87_state");return rc;}
static int saved_close(uint32_t *cookie){fp_state a,b;int rc;fp_read(&a);rc=sp_close(cookie);fp_read(&b);C(!memcmp(&a,&b,sizeof(a)),"close_full_x87_state");return rc;}

static void branch(const m98_sp_callbacks *cb){
 m98_sp_instruction code[10];m98_sp_source z={0},in=source(M98_SP_INPUT,0),c0=source(M98_SP_CONSTANT,0),c1=source(M98_SP_CONSTANT,1),c2=source(M98_SP_CONSTANT,2),t0=source(M98_SP_TEMP,0),t1=source(M98_SP_TEMP,1),reverse=t1;
 m98_sp_program p;m98_sp_io io=io_value();m98_sp_result r;uint32_t cookie=0;unsigned ch,lane;
 static const float expected[4][4]={{36,20,36,20},{27,12,27,12},{18,6,18,6},{9,2,9,2}};
 static const float slopes[4]={-7,-12,-15,-16};
 code[0]=op(M98_SP_SLT,M98_SP_TEMP,0,2,in,c0);
 code[1]=op(M98_SP_IF,0,0,1,t0,z);
 code[2]=op(M98_SP_ADD,M98_SP_TEMP,1,2,in,c1);
 code[3]=op(M98_SP_ELSE,0,0,0,z,z);
 code[4]=op(M98_SP_MUL,M98_SP_TEMP,1,2,in,c2);
 code[5]=op(M98_SP_ENDIF,0,0,0,z,z);
 for(ch=0;ch<4;ch++)reverse.swizzle[ch]=3-ch;
 code[6]=op(M98_SP_MOV,M98_SP_OUTPUT,0,1,reverse,z);
 code[7]=op(M98_SP_DDX,M98_SP_OUTPUT,1,1,t1,z);
 code[8]=op(M98_SP_MOV,M98_SP_TEMP,0,1,c0,z);
 code[9]=op(M98_SP_END,0,0,0,z,z);
 p=program(code,10,1,3,2,2);
 for(ch=0;ch<4;ch++){io.input[0].a0[ch]=-(float)(ch+1);io.input[0].dx[ch]=2*(float)(ch+1);io.constant[0][ch]=0;io.constant[1][ch]=10*(float)(ch+1);io.constant[2][ch]=(float)(ch+2);}
 C(saved_open(&p,cb,&cookie)==M98_SP_OK&&cookie,"branch_open");cookie_for_reentry=cookie;reentry=1;
 C(saved_run(cookie,&io,&r)==M98_SP_OK&&r.live_mask==15&&r.output_count==2,"branch_actual_live_quad");
 for(ch=0;ch<4;ch++)for(lane=0;lane<4;lane++){C(r.output[0][ch][lane]==expected[ch][lane],"branch_swizzled_literal_oracle");C(r.output[1][ch][lane]==slopes[ch],"branch_fine_ddx_literal_oracle");}
 io.constant[1][3]=80;C(saved_run(cookie,&io,&r)==M98_SP_OK&&r.output[0][0][0]==76&&r.output[0][0][1]==20,"dynamic_uniform_changes_result");
 C(saved_close(&cookie)==M98_SP_OK&&!cookie&&!live_blocks,"branch_complete_teardown");
}

static void planes(const m98_sp_callbacks *cb){m98_sp_source z={0},in=source(M98_SP_INPUT,0);m98_sp_instruction code[3];m98_sp_program p;m98_sp_io io=io_value();m98_sp_result r;uint32_t cookie=0;unsigned ch,lane;
 code[0]=op(M98_SP_DDX,M98_SP_OUTPUT,0,1,in,z);code[1]=op(M98_SP_DDY,M98_SP_OUTPUT,1,1,in,z);code[2]=op(M98_SP_END,0,0,0,z,z);p=program(code,3,1,0,0,2);
 io.quad_x=19;io.quad_y=23;for(ch=0;ch<4;ch++){io.input[0].dx[ch]=(float)(2u<<ch);io.input[0].dy[ch]=(float)(3u<<ch);}
 C(saved_open(&p,cb,&cookie)==0,"planes_open");C(saved_run(cookie,&io,&r)==0&&r.live_mask==15,"planes_real_interpolation");
 for(ch=0;ch<4;ch++)for(lane=0;lane<4;lane++){C(r.output[0][ch][lane]==(float)(2u<<ch),"fine_ddx_literal_plane");C(r.output[1][ch][lane]==(float)(3u<<ch),"fine_ddy_literal_plane");}
 C(saved_close(&cookie)==0&&!live_blocks,"planes_teardown");
 code[0]=op(M98_SP_MOV,M98_SP_OUTPUT,0,1,in,z);code[1]=op(M98_SP_KILL_IF,0,0,1,in,z);p=program(code,3,1,0,0,1);io=io_value();
 for(ch=0;ch<4;ch++){io.input[0].a0[ch]=-1;io.input[0].dx[ch]=2;io.input[0].dy[ch]=2;}
 C(saved_open(&p,cb,&cookie)==0,"discard_open");C(saved_run(cookie,&io,&r)==0&&r.live_mask==14,"actual_discard_low_four_mask");
 io.live_mask=5;C(saved_run(cookie,&io,&r)==0&&r.live_mask==4,"discard_preserves_caller_live_mask");
 fail_next=1;memset(&r,0xa5,sizeof(r));{m98_sp_result poison=r;C(saved_run(cookie,&io,&r)==M98_SP_NOMEM&&!memcmp(&r,&poison,sizeof(r)),"native_allocation_failure_transactional");}
 C(saved_close(&cookie)==0&&!live_blocks,"discard_teardown");
 C(saved_run(cookie,&io,&r)==M98_SP_STALE,"zero_cookie_stale");
}

static void math_trial(const m98_sp_callbacks *cb){m98_sp_source z={0},c0=source(M98_SP_CONSTANT,0),c1=source(M98_SP_CONSTANT,1);m98_sp_instruction code[3];m98_sp_program p;m98_sp_io io=io_value();m98_sp_result r;uint32_t cookie=0;unsigned lane;
 code[0]=op(M98_SP_SIN,M98_SP_OUTPUT,0,1,c0,z);code[1]=op(M98_SP_ROUND_EVEN,M98_SP_OUTPUT,1,1,c1,z);code[2]=op(M98_SP_END,0,0,0,z,z);p=program(code,3,0,2,0,2);
 io.constant[0][0]=0;io.constant[0][1]=1.5707963267948966f;io.constant[0][2]=3.141592653589793f;io.constant[0][3]=-1.5707963267948966f;
 io.constant[1][0]=0.5f;io.constant[1][1]=1.5f;io.constant[1][2]=-2.5f;io.constant[1][3]=-0.5f;
 C(saved_open(&p,cb,&cookie)==0,"math_open");C(saved_run(cookie,&io,&r)==0&&r.live_mask==15,"math_actual_system_crt_provider");
 for(lane=0;lane<4;lane++){C(near_values(r.output[0][0][lane],0)&&near_values(r.output[0][1][lane],1)&&near_values(r.output[0][2][lane],0)&&near_values(r.output[0][3][lane],-1),"sin_independent_literal_tolerance");C(r.output[1][0][lane]==0&&r.output[1][1][lane]==2&&r.output[1][2][lane]==-2&&r.output[1][3][lane]==0,"nearest_even_literal_oracle");}
 C(saved_close(&cookie)==0&&!live_blocks,"math_teardown");code[0].opcode=M98_SP_FMA;cookie=0x12345678;C(saved_open(&p,cb,&cookie)==M98_SP_UNSUPPORTED&&cookie==0x12345678&&!live_blocks,"fused_opcode_explicit_unsupported");
}

void WINAPI m98_sp_probe(void){char base[MAX_PATH],path[MAX_PATH];DWORD n;HMODULE dll,crt;OSVERSIONINFOA os={sizeof(os),0,0,0,0,{0}};abi_fn abi;m98_sp_callbacks cb={0};
 n=GetModuleFileNameA(NULL,base,sizeof(base));if(!n||n>=sizeof(base))ExitProcess(3);while(n&&base[n-1]!='\\')--n;if(!n||n>MAX_PATH-16)ExitProcess(3);base[n]=0;
 memcpy(path,base,n+1);append(path,n,"SP13.LOG");log_file=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(4);
 text("M98_SOFTPIPE_PROBE=1\r\nNONCE=" M98_SP_NONCE "\r\n");
 C(GetVersionExA(&os),"actual_os_query");text("OS_PLATFORM=");number(os.dwPlatformId);text("\r\nOS_MAJOR=");number(os.dwMajorVersion);text("\r\nOS_MINOR=");number(os.dwMinorVersion);text("\r\nOS_BUILD_LOW=");number(os.dwBuildNumber&65535);text("\r\nACP=");number(GetACP());text("\r\n");
 C(os.dwPlatformId==1&&os.dwMajorVersion==4&&os.dwMinorVersion==10&&(os.dwBuildNumber&65535)==2222&&GetACP()==949,"real_win98_se_korean_identity");
 memcpy(path,base,n+1);append(path,n,"M98SHP.DLL");dll=exact_load(path,"load_adjacent_genuine_component");
 sp_open=(open_fn)(void *)GetProcAddress(dll,"m98_sp_open");sp_run=(run_fn)(void *)GetProcAddress(dll,"m98_sp_run");sp_close=(close_fn)(void *)GetProcAddress(dll,"m98_sp_close");abi=(abi_fn)(void *)GetProcAddress(dll,"m98_sp_abi");C(sp_open&&sp_run&&sp_close&&abi&&abi()==1,"exact_component_abi_exports");
 n=GetSystemDirectoryA(path,sizeof(path));C(n&&n<MAX_PATH-12,"actual_system_crt_path");append(path,n,"\\MSVCRT.DLL");crt=exact_load(path,"load_exact_original_system_crt");
 unary[M98_SP_MATH_COS]=(unary_fn)(void *)GetProcAddress(crt,"cos");unary[M98_SP_MATH_SIN]=(unary_fn)(void *)GetProcAddress(crt,"sin");unary[M98_SP_MATH_LOG]=(unary_fn)(void *)GetProcAddress(crt,"log");unary[M98_SP_MATH_SQRT]=(unary_fn)(void *)GetProcAddress(crt,"sqrt");unary[M98_SP_MATH_FLOOR]=(unary_fn)(void *)GetProcAddress(crt,"floor");unary[M98_SP_MATH_CEIL]=(unary_fn)(void *)GetProcAddress(crt,"ceil");power=(binary_fn)(void *)GetProcAddress(crt,"pow");scale=(scale_fn)(void *)GetProcAddress(crt,"ldexp");
 C(unary[1]&&unary[2]&&unary[3]&&unary[5]&&unary[6]&&unary[7]&&power&&scale,"genuine_crt_named_math_functions");heap=GetProcessHeap();C(heap!=NULL,"actual_process_heap");cb.abi=1;cb.allocate=allocate;cb.deallocate=deallocate;cb.math=provider;
 /* Set test state only after every module/CRT load, preserving two x87 values. */
 fp_begin();branch(&cb);planes(&cb);math_trial(&cb);__asm__ volatile("fninit":::"memory");
 C(!live_blocks,"all_context_heap_ownership_released");C(FreeLibrary(crt)&&FreeLibrary(dll),"owned_modules_released");
 text("REAL_TGSI_QUADS=1\r\nNATIVE_GLSL_GLES_WEBGL_WEBGPU_BROWSER=0\r\nALLOCATIONS=");number(allocations);text("\r\nCHECKS=");number(checks);text("\r\nFAILURES=0\r\nSTATUS=PASS\r\n");
 if(!FlushFileBuffers(log_file)||!CloseHandle(log_file))ExitProcess(5);
 ExitProcess(0);
}
