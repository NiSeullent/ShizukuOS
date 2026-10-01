/* SPDX-License-Identifier: GPL-2.0-only
 * Actual runtime-only GUI probe; no MSHTML/DOM/browser conformance claim. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "m98_trident_script.h"
#ifndef M98_SCRIPT_NONCE
#error Frozen nonce required
#endif
#ifndef M98_SCRIPT_SHA256
#error Frozen runtime identity required
#endif
#ifndef M98_SCRIPT_SELECTED_HEADER
#error Frozen selected semantic source required
#endif
#include M98_SCRIPT_SELECTED_HEADER
_Static_assert(sizeof(m98_script_value)==32,"native value ABI");
static HANDLE log_file=INVALID_HANDLE_VALUE;
static int log_good=1;
static unsigned checks;
static unsigned char original_x87[108] __attribute__((aligned(16)));
static int saved_x87;
static unsigned short control_word(void){unsigned short n;__asm__ volatile("fnstcw %0":"=m"(n));return n;}
static unsigned short status_word(void){unsigned short n;__asm__ volatile("fnstsw %0":"=am"(n));return n;}
static void zero(void *p,size_t n){unsigned char *b=p;while(n--)*b++=0;}
static uint32_t length(const char *p){uint32_t n=0;while(p[n])++n;return n;}
static void text(const char *p){DWORD n=length(p),done=0;if(!WriteFile(log_file,p,n,&done,NULL)||n!=done)log_good=0;}
static void number(uint32_t n){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+n%10);n/=10;}while(n);text(b+i);}
static int path(HMODULE module,const char *expected){char actual[MAX_PATH];DWORD n=GetModuleFileNameA(module,actual,sizeof(actual));return n&&n<sizeof(actual)&&!lstrcmpiA(actual,expected);}
/* An explicit internal observer root, not an invented document or DOM. */
static int32_t probe_get(void *user,uint32_t cookie,const uint16_t *name,uint32_t units,m98_script_value *v){
    (void)user;zero(v,sizeof(*v));v->size=sizeof(*v);
    const uint16_t expected[]={'c','o','n','t','r','o','l'};uint32_t i;
    if(cookie!=1||units!=7)return (int32_t)0x80070057u;
    for(i=0;i<7;++i)if(name[i]!=expected[i])return (int32_t)0x80020003u;
    v->type=M98_SCRIPT_INT32;v->integer=control_word();return 0;
}
static int32_t probe_set(void *u,uint32_t c,const uint16_t *n,uint32_t z,const m98_script_value *v){(void)u;(void)c;(void)n;(void)z;(void)v;return (int32_t)0x80004001u;}
static int32_t probe_call(void *u,uint32_t c,const uint16_t *n,uint32_t z,const m98_script_value *a,uint32_t count,m98_script_value *v){(void)u;(void)c;(void)n;(void)z;(void)a;(void)count;zero(v,sizeof(*v));v->size=sizeof(*v);return (int32_t)0x80004001u;}
static int32_t probe_retain(void *u,uint32_t c){(void)u;return c==1?0:(int32_t)0x80070057u;}
static void probe_release(void *u,uint32_t c){(void)u;(void)c;}
static void probe_cleanup(void *u,m98_script_value *v){(void)u;(void)v;}
static const m98_script_host probe_host={sizeof(m98_script_host),NULL,probe_get,probe_set,probe_call,probe_retain,probe_release,probe_cleanup};
#define CHECK(condition,label) do{++checks;text("check_");number(checks);text("="); \
    text(label);if(!(condition)){text(":FAIL\r\n");goto finish;}text(":PASS\r\n");}while(0)
#define BIND(field,name) do{FARPROC p=GetProcAddress(module,name);size_t i;CHECK(p&&sizeof(p)==sizeof(field),name); \
    for(i=0;i<sizeof(field);++i)((unsigned char *)&field)[i]=((unsigned char *)&p)[i];}while(0)
void mainCRTStartup(void){OSVERSIONINFOA version;HMODULE module=NULL;uint32_t context=0,old=0,jobs=0,fn=0;
    m98_script_options options; m98_script_result returned;m98_script_details detail;int passed=0;DWORD exit_code=2;
    int (*open_script)(const m98_script_options *,m98_script_context *)=NULL;
    int (*bind_script)(m98_script_context,const uint16_t *,uint32_t,uint32_t)=NULL;
    int (*eval_script)(m98_script_context,const char *,uint32_t,m98_script_result *)=NULL;
    int (*invoke_script)(m98_script_context,uint32_t,const m98_script_value *,uint32_t,m98_script_result *)=NULL;
    int (*invoke_this_script)(m98_script_context,uint32_t,const m98_script_value *,const m98_script_value *,uint32_t,m98_script_result *)=NULL;
    int (*jobs_script)(m98_script_context,uint32_t *)=NULL;
    int (*release_script)(m98_script_context,uint32_t)=NULL;
    int (*info_script)(m98_script_context,m98_script_details *)=NULL;
    int (*close_script)(m98_script_context)=NULL;
    log_file=CreateFileA("C:\\GOPLAB\\QJS13.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(2);
    text("M98QJS runtime-only native probe v1\r\nnonce=" M98_SCRIPT_NONCE "\r\nexpected_runtime_sha256=" M98_SCRIPT_SHA256 "\r\n");
    text("original_x87_control_word=");number(control_word());text("\r\n");
    zero(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    CHECK(GetVersionExA(&version)&&version.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS&&version.dwMajorVersion==4&&
          version.dwMinorVersion==10&&(version.dwBuildNumber&0xffff)==2222,"win98se_4_10_2222");
    CHECK(path(NULL,"C:\\GOPLAB\\QJS13PR.EXE"),"probe_exact_path");
    module=LoadLibraryA("C:\\GOPLAB\\M98QJS.DLL");CHECK(module&&path(module,"C:\\GOPLAB\\M98QJS.DLL"),"runtime_exact_path");
    BIND(open_script,"m98_script_open");BIND(bind_script,"m98_script_bind_root");BIND(eval_script,"m98_script_eval");BIND(invoke_script,"m98_script_invoke");BIND(invoke_this_script,"m98_script_invoke_this");
    BIND(jobs_script,"m98_script_jobs");BIND(release_script,"m98_script_release_result");BIND(info_script,"m98_script_info");BIND(close_script,"m98_script_close");
    /* Loading the original CRT may initialize its own x87 defaults. Apply
     * the caller test state after module loading, immediately before our API. */
    unsigned short altered=0x0a7f;
    __asm__ volatile("fnsave %0\n\tfldcw %1":"=m"(original_x87):"m"(altered):"memory");saved_x87=1;
    __asm__ volatile("fldz\n\tfldz\n\tfdivp\n\tfstp %%st(0)":::"memory");
    unsigned short caller_status=status_word();
    CHECK(control_word()==altered&&(caller_status&1),"caller_x87_test_environment");
    zero(&options,sizeof(options));options.size=sizeof(options);options.memory_bytes=8u<<20;options.stack_bytes=262144;options.interrupt_checks=20;options.job_limit=8;options.host=&probe_host;
    CHECK(open_script(&options,&context)==0&&context,"runtime_open");
    const uint16_t probe_name[]={'p','r','o','b','e'};
    CHECK(bind_script(context,probe_name,5,1)==0,"explicit_platform_observer_root");
#define EVAL(source) do{zero(&returned,sizeof(returned));returned.size=sizeof(returned); \
    CHECK(eval_script(context,source,sizeof(source)-1,&returned)==0&&returned.lease,"eval");}while(0)
#define DROP() do{CHECK(release_script(context,returned.lease)==0,"release_result");returned.lease=0;}while(0)
    EVAL("probe.control");CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==0x037f,"actual_internal_x87_pc64_nearest_masks");
    text("observed_internal_x87_control_word=");number(returned.value.integer);text("\r\n");DROP();
    CHECK(control_word()==altered&&status_word()==caller_status,"caller_full_x87_environment_restored");
    EVAL("typeof Atomics==='undefined'&&typeof SharedArrayBuffer==='undefined'");CHECK(returned.value.type==M98_SCRIPT_BOOL&&returned.value.integer,"single_thread_shared_memory_policy");DROP();
    EVAL("(()=>{class A{#x=7; f(){return this.#x}}; return new A().f()+({x:3})?.x+(null??2)})()");
    CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==12,"modern_syntax_private_optional_nullish");DROP();
    EVAL("Number((2n**64n)>>60n)+new Set([1,1,2]).size+new Uint8Array([3,4])[1]");
    CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==22,"bigint_set_typedarray");DROP();
    EVAL("Math.sumPrecise([1e20,1,-1e20])+Math.f16round(1.0001)");
    CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==2,"modern_math");DROP();
    EVAL(m98_selected_es2026);
    const char selected_expected[]="{\"scope\":\"selected ES2026 semantic checks\",\"checks\":34,\"full_conformance_verified\":false,\"browser_dom_verified\":false}";
    CHECK(returned.value.type==M98_SCRIPT_STRING&&returned.value.units==sizeof(selected_expected)-1,"selected_es2026_json");
    uint32_t si;for(si=0;si<sizeof(selected_expected)-1;++si)CHECK(returned.value.string[si]==(unsigned char)selected_expected[si],"selected_es2026_json_bytes");
    text("selected_es2026_checks=34\r\n");DROP();
    EVAL(m98_selected_numeric);
    const char numeric_expected[]="{\"scope\":\"selected numeric semantics\",\"checks\":24,\"full_conformance_verified\":false,\"native_math_verified\":false}";
    CHECK(returned.value.type==M98_SCRIPT_STRING&&returned.value.units==sizeof(numeric_expected)-1,"selected_numeric_json");
    for(si=0;si<sizeof(numeric_expected)-1;++si)CHECK(returned.value.string[si]==(unsigned char)numeric_expected[si],"selected_numeric_json_bytes");
    text("selected_numeric_checks=24\r\n");DROP();
    CHECK(control_word()==altered&&status_word()==caller_status,"caller_x87_restored_after_numeric_math");
    EVAL("Date.UTC(2026,0,1)===1767225600000 && Date.now()>1700000000000 && Number.isFinite(new Date().getTimezoneOffset())");
    CHECK(returned.value.type==M98_SCRIPT_BOOL&&returned.value.integer==1,"actual_utc_localtimezone");DROP();
    EVAL("'A\\u0000\\uD800\\uDC00\\uDFFF\\uD801'");
    const uint16_t expected[]={65,0,0xd800,0xdc00,0xdfff,0xd801};uint32_t i;
    CHECK(returned.value.type==M98_SCRIPT_STRING&&returned.value.units==6,"utf16_length");
    for(i=0;i<6;++i)CHECK(returned.value.string[i]==expected[i],"utf16_nul_surrogates");DROP();
    EVAL("globalThis.p=0; Promise.resolve(4).then(x=>p=x); p");
    CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==0,"promise_pending");DROP();
    CHECK(jobs_script(context,&jobs)==0&&jobs>0&&jobs<=8,"promise_jobs");EVAL("p");
    CHECK(returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==4,"promise_result");DROP();
    EVAL("globalThis.f=(x)=>x+3; f");CHECK(returned.value.type==M98_SCRIPT_FUNCTION&&returned.value.cookie,"function_cookie");fn=returned.value.cookie;DROP();
    m98_script_value arg;zero(&arg,sizeof(arg));arg.size=sizeof(arg);arg.type=M98_SCRIPT_INT32;arg.integer=8;
    zero(&returned,sizeof(returned));returned.size=sizeof(returned);
    CHECK(invoke_script(context,fn,&arg,1,&returned)==0&&returned.lease&&returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==11,"safe_function_invoke");DROP();
    EVAL("(function(x){return this.control+x})");fn=returned.value.cookie;CHECK(returned.value.type==M98_SCRIPT_FUNCTION&&fn,"explicit_receiver_function");DROP();
    m98_script_value receiver;zero(&receiver,sizeof(receiver));receiver.size=sizeof(receiver);receiver.type=M98_SCRIPT_OBJECT;receiver.cookie=1;
    zero(&returned,sizeof(returned));returned.size=sizeof(returned);
    CHECK(invoke_this_script(context,fn,&receiver,&arg,1,&returned)==0&&returned.lease&&returned.value.type==M98_SCRIPT_INT32&&returned.value.integer==0x037f+8,"native_explicit_this_receiver");DROP();
    zero(&returned,sizeof(returned));returned.size=sizeof(returned);
    CHECK(eval_script(context,"while(true){}",13,&returned)==M98_SCRIPT_LIMIT&&!returned.lease,"interpreter_interrupt");
    detail.size=sizeof(detail);CHECK(info_script(context,&detail)==0&&detail.interrupt_checks>0&&detail.interrupt_checks<=21,"interrupt_diagnostics");
    EVAL("typeof document==='undefined' && typeof std==='undefined' && typeof os==='undefined'");
    CHECK(returned.value.type==M98_SCRIPT_BOOL&&returned.value.integer,"runtime_isolation");DROP();
    old=context;CHECK(close_script(context)==0,"runtime_close");context=0;detail.size=sizeof(detail);
    CHECK(info_script(old,&detail)==M98_SCRIPT_STATE,"stale_context_rejected");
    CHECK(open_script(&options,&context)==0&&context&&context!=old,"new_context_generation");
    zero(&returned,sizeof(returned));returned.size=sizeof(returned);
    CHECK(invoke_script(context,fn,NULL,0,&returned)==M98_SCRIPT_STATE,"stale_function_rejected");
    passed=1;
finish:
    if(context&&(!close_script||close_script(context)!=0))passed=0;
    if(module&&!FreeLibrary(module))passed=0;
    if(saved_x87){__asm__ volatile("frstor %0"::"m"(original_x87):"memory");saved_x87=0;}
    text("checks=");number(checks);text(passed?"\r\ncomponent_result=PASS\r\n":"\r\ncomponent_result=FAIL\r\n");
    text("mshtml_automation_verified=0\r\nhtml5_verified=0\r\nwasm_verified=0\r\nes2026_conformance=0\r\napplications_verified=0\r\nactual_child_exit=externally_observed_only\r\n");
    if(passed&&log_good&&FlushFileBuffers(log_file))exit_code=0;if(!CloseHandle(log_file))exit_code=2;ExitProcess(exit_code);
}
