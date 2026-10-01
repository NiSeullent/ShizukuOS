/* SPDX-License-Identifier: GPL-2.0-only
 * Actual numeric engine oracles shared by host and Win98 DLL probe.
 * No browser, JS WebAssembly namespace, SIMD or full-Wasm claim. */
#ifndef M98_WASM_GUEST_HOST
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#define WINVER 0x0400
#endif
#include <stdint.h>
#include <string.h>
#include "m98_wasm.h"
#include "wasm_original_fixtures.h"
#ifdef M98_WASM_GUEST_HOST
#include <stdio.h>
#include <stdlib.h>
#else
#include <windows.h>
_Static_assert(sizeof(m98_wasm_value)==16, "Win32 numeric value ABI");
_Static_assert(sizeof(m98_wasm_options)==16 && sizeof(m98_wasm_info)==180, "Win32 options/info ABI");
_Static_assert(sizeof(m98_wasm_import)==20, "Win32 import ABI");
static HANDLE log_file=INVALID_HANDLE_VALUE;
#endif

#define API(name) static __typeof__(name) *p_##name
API(m98_wasm_open); API(m98_wasm_close); API(m98_wasm_load); API(m98_wasm_unload);
API(m98_wasm_instantiate); API(m98_wasm_instance_close); API(m98_wasm_call);
API(m98_wasm_memory_size); API(m98_wasm_memory_grow); API(m98_wasm_memory_read);
API(m98_wasm_memory_write); API(m98_wasm_inspect);
static uint32_t store,active_instance;
static unsigned checks,callbacks,fail_callback;

static void finish(unsigned status)
{
#ifdef M98_WASM_GUEST_HOST
    exit((int)status);
#else
    if(log_file!=INVALID_HANDLE_VALUE){
        if(!FlushFileBuffers(log_file))status=2;
        if(!CloseHandle(log_file))status=2;
        log_file=INVALID_HANDLE_VALUE;
    }
    ExitProcess(status);
#endif
}
static void text(const char *s)
{
#ifdef M98_WASM_GUEST_HOST
    if(fputs(s,stdout)==EOF)finish(2);
#else
    DWORD length=0,written;
    while(s[length])++length;
    while(length){
        if(!WriteFile(log_file,s,length,&written,NULL)||!written||written>length)finish(2);
        s+=written;length-=written;
    }
#endif
}
static void number(uint32_t value){char b[11];unsigned n=10;b[n]=0;do{b[--n]=(char)('0'+value%10);value/=10;}while(value);text(b+n);}
static void check(int ok,const char *name)
{
    ++checks;text("CHECK:");text(name);text(ok?"=1\r\n":"=0\r\n");
    if(!ok){text("FAILURES=1\r\nSTATUS=FAIL\r\n");finish(1);}
}
#define C(ok,name) check(!!(ok),name)
typedef struct { unsigned char bytes[108]; } fp_state;
static void save(fp_state *state){__asm__ volatile("fnsave %0\n\tfwait\n\tfrstor %0":"=m"(state->bytes)::"memory");}
/* Capture immediately around each real VM call, before logging or other APIs. */
#define VM(call) ({fp_state m98_guest_fp_before,m98_guest_fp_after;int m98_guest_call_status;save(&m98_guest_fp_before);m98_guest_call_status=(call);save(&m98_guest_fp_after);C(!memcmp(&m98_guest_fp_before,&m98_guest_fp_after,sizeof(m98_guest_fp_before)),"complete_x87_boundary");m98_guest_call_status;})
static m98_wasm_value value(uint32_t kind,uint64_t bits){m98_wasm_value v={kind,bits};return v;}
static uint32_t load(const void *bytes,uint32_t n){uint32_t m=0;C(VM(p_m98_wasm_load(store,bytes,n,&m))==0&&m,"real_module_load");return m;}
static uint32_t instantiate(uint32_t m){uint32_t i=0;C(VM(p_m98_wasm_instantiate(store,m,&i))==0&&i,"real_instance_create");return i;}
static void release(uint32_t m,uint32_t i){C(VM(p_m98_wasm_instance_close(store,i))==0,"instance_release");C(VM(p_m98_wasm_unload(store,m))==0,"module_release");}
static int imported_sum(void *user,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out)
{
    unsigned short current,changed=0x077f;m98_wasm_info info;(void)user;++callbacks;
    C(count==2&&args[0].kind==M98_WASM_I32&&args[1].kind==M98_WASM_I32,"actual_import_argument_types");
    __asm__ volatile("fnstcw %0":"=m"(current));C(current==0x0a7f,"import_restores_caller_control_word");
    C(VM(p_m98_wasm_inspect(store,&info))==M98_WASM_BUSY,"import_inspect_reentry_rejected");
    C(VM(p_m98_wasm_instance_close(store,active_instance))==M98_WASM_BUSY,"import_close_reentry_rejected");
    *out=value(M98_WASM_I32,(uint32_t)args[0].bits+(uint32_t)args[1].bits);
    __asm__ volatile("fninit\n\tfldcw %0\n\tfldpi"::"m"(changed):"memory");
    return fail_callback?1:0;
}

static void numeric(void)
{
    uint32_t m=load(wasm_arithmetic,sizeof(wasm_arithmetic)),i=instantiate(m),k;
    m98_wasm_value args[2],out[2],poison[2];
    for(k=0;k<32;k++){
        args[0]=value(M98_WASM_I32,UINT32_MAX-k);args[1]=value(M98_WASM_I32,k+2);
        C(VM(p_m98_wasm_call(store,i,"add",args,2,out,1))==0&&out[0].kind==M98_WASM_I32&&out[0].bits==1,"i32_real_modulo_add_literal");
    }
    args[0]=value(M98_WASM_I64,UINT64_C(0x123456789abcdef0));args[1]=value(M98_WASM_I64,UINT64_MAX);
    C(VM(p_m98_wasm_call(store,i,"wide",args,2,out,1))==0&&out[0].kind==M98_WASM_I64&&out[0].bits==UINT64_C(0x123456789abcdeef),"i64_exact_beyond_double_precision");
    args[0]=value(M98_WASM_I32,17);
    C(VM(p_m98_wasm_call(store,i,"pair",args,1,out,2))==0&&out[0].kind==M98_WASM_I32&&out[1].kind==M98_WASM_I32&&out[0].bits==17&&out[1].bits==17,"actual_multivalue_return");
    args[0]=value(M98_WASM_I32,8);args[1]=value(M98_WASM_I32,0);
    memset(out,0xa5,sizeof(out));memcpy(poison,out,sizeof(out));
    C(VM(p_m98_wasm_call(store,i,"div",args,2,out,1))==M98_WASM_TRAP&&!memcmp(out,poison,sizeof(out)),"division_trap_output_unchanged");
    args[1]=value(M98_WASM_I32,2);
    C(VM(p_m98_wasm_call(store,i,"div",args,2,out,1))==0&&out[0].kind==M98_WASM_I32&&out[0].bits==4,"instance_usable_after_trap");
    args[0]=value(M98_WASM_I64,8);memset(out,0xa5,sizeof(out));
    C(VM(p_m98_wasm_call(store,i,"add",args,2,out,1))==M98_WASM_TYPE&&!memcmp(out,poison,sizeof(out)),"wrong_numeric_type_transactional");
    C(VM(p_m98_wasm_unload(store,m))==M98_WASM_BUSY,"live_instance_owns_module");
    release(m,i);C(VM(p_m98_wasm_instance_close(store,i))==M98_WASM_STALE,"closed_instance_stale");
}
static void memories(void)
{
    uint32_t m=load(wasm_memory,sizeof(wasm_memory)),i=instantiate(m),pages=0,k;
    int32_t old;m98_wasm_value args[2],out;unsigned char bytes[40],actual[40],poison[40];
    C(VM(p_m98_wasm_memory_size(store,i,0,&pages))==0&&pages==1,"actual_initial_memory_page");
    C(VM(p_m98_wasm_memory_read(store,i,0,0,actual,6))==0&&!memcmp(actual,"Wasm98",6),"actual_data_segment_bytes");
    for(k=0;k<40;k++)bytes[k]=(unsigned char)(k+17);
    C(VM(p_m98_wasm_memory_write(store,i,0,65500,bytes,36))==0,"actual_memory_write_end_boundary");
    C(VM(p_m98_wasm_memory_read(store,i,0,65500,actual,36))==0&&!memcmp(bytes,actual,36),"actual_memory_readback_end_boundary");
    memset(actual,0xa5,sizeof(actual));memcpy(poison,actual,sizeof(actual));
    C(VM(p_m98_wasm_memory_read(store,i,0,65500,actual,37))==M98_WASM_RANGE&&!memcmp(actual,poison,40),"memory_overrun_output_unchanged");
    C(VM(p_m98_wasm_memory_read(store,i,0,UINT32_MAX,actual,2))==M98_WASM_RANGE,"memory_index_wrap_rejected");
    args[0]=value(M98_WASM_I32,100);args[1]=value(M98_WASM_I32,0x78563412);
    C(VM(p_m98_wasm_call(store,i,"store",args,2,NULL,0))==0,"real_wasm_store_instruction");
    C(VM(p_m98_wasm_call(store,i,"load",args,1,&out,1))==0&&out.kind==M98_WASM_I32&&out.bits==0x78563412,"real_wasm_load_instruction");
    C(VM(p_m98_wasm_memory_grow(store,i,0,1,&old))==0&&old==1,"actual_memory_grow_old_page");
    C(VM(p_m98_wasm_memory_size(store,i,0,&pages))==0&&pages==2,"actual_memory_grow_new_page");
    C(VM(p_m98_wasm_memory_read(store,i,0,65500,actual,36))==0&&!memcmp(bytes,actual,36),"growth_preserves_original_bytes");
    C(VM(p_m98_wasm_memory_read(store,i,0,65536,actual,40))==0,"growth_new_region_readable");
    for(k=0;k<40;k++)C(actual[k]==0,"growth_zero_initialization_literal");
    C(VM(p_m98_wasm_memory_grow(store,i,0,UINT32_MAX,&old))==0&&old==-1,"growth_limit_reports_minus_one");
    release(m,i);
}
static void floating(void)
{
    uint32_t m=load(wasm_float,sizeof(wasm_float)),i=instantiate(m);m98_wasm_value args[2],out;
    args[0]=value(M98_WASM_F64,UINT64_C(0x4004000000000000));
    C(VM(p_m98_wasm_call(store,i,"nearest",args,1,&out,1))==0&&out.kind==M98_WASM_F64&&out.bits==UINT64_C(0x4000000000000000),"f64_two_point_five_rounds_to_even_two");
    args[0]=value(M98_WASM_F32,UINT32_C(0x40600000));
    C(VM(p_m98_wasm_call(store,i,"fnearest",args,1,&out,1))==0&&out.kind==M98_WASM_F32&&out.bits==UINT32_C(0x40800000),"f32_three_point_five_rounds_to_even_four");
    args[0]=value(M98_WASM_F64,0);args[1]=value(M98_WASM_F64,UINT64_C(0x8000000000000000));
    C(VM(p_m98_wasm_call(store,i,"min",args,2,&out,1))==0&&out.kind==M98_WASM_F64&&out.bits==UINT64_C(0x8000000000000000),"f64_min_preserves_negative_zero_bits");
    C(VM(p_m98_wasm_call(store,i,"max",args,2,&out,1))==0&&out.kind==M98_WASM_F64&&out.bits==0,"f64_max_preserves_positive_zero_bits");
    args[0]=value(M98_WASM_F64,UINT64_C(0x4010000000000000));
    C(VM(p_m98_wasm_call(store,i,"sqrt",args,1,&out,1))==0&&out.kind==M98_WASM_F64&&out.bits==UINT64_C(0x4000000000000000),"f64_real_sqrt_four_literal_two");
    release(m,i);
}
static void imports_and_failures(void)
{
    uint32_t m=load(wasm_imports,sizeof(wasm_imports)),i=instantiate(m),bad=0x13579bdf;
    m98_wasm_value args[2],out;m98_wasm_info before,after;
    active_instance=i;args[0]=value(M98_WASM_I32,20);args[1]=value(M98_WASM_I32,22);
    C(VM(p_m98_wasm_call(store,i,"invoke",args,2,&out,1))==0&&out.kind==M98_WASM_I32&&out.bits==42&&callbacks==1,"actual_native_import_returns_42");
    fail_callback=1;C(VM(p_m98_wasm_call(store,i,"invoke",args,2,&out,1))==M98_WASM_TRAP,"actual_callback_error_becomes_trap");fail_callback=0;
    release(m,i);
    m=load(wasm_infinite,sizeof(wasm_infinite));i=instantiate(m);
    C(VM(p_m98_wasm_call(store,i,"loop",NULL,0,NULL,0))==M98_WASM_TRAP,"actual_infinite_dispatch_meter_stops");
    C(VM(p_m98_wasm_inspect(store,&after))==0&&strstr(after.diagnostic,"instruction limit exceeded"),"actual_instruction_budget_diagnostic");release(m,i);
    m=load(wasm_start_infinite,sizeof(wasm_start_infinite));
    C(VM(p_m98_wasm_instantiate(store,m,&bad))==M98_WASM_LINK&&bad==0x13579bdf,"start_loop_budget_and_transactional_instance");
    C(VM(p_m98_wasm_unload(store,m))==0,"start_failure_module_teardown");
    m=load(wasm_missing_import,sizeof(wasm_missing_import));
    C(VM(p_m98_wasm_instantiate(store,m,&bad))==M98_WASM_LINK,"missing_import_is_real_link_failure");
    C(VM(p_m98_wasm_unload(store,m))==0,"link_failure_module_teardown");
    C(VM(p_m98_wasm_inspect(store,&before))==0,"account_before_validation");
    C(VM(p_m98_wasm_load(store,wasm_bad_magic,sizeof(wasm_bad_magic),&bad))==M98_WASM_VALIDATE&&bad==0x13579bdf,"invalid_magic_no_module_publication");
    C(VM(p_m98_wasm_inspect(store,&after))==0&&after.used_bytes==before.used_bytes&&after.modules==0&&after.instances==0,"failure_and_instance_accounting_released");
}
static void suite(void)
{
    m98_wasm_options options={4194304,16384,2000,4};m98_wasm_import import={"host","sum","(ii)i",imported_sum,NULL};
    m98_wasm_info info;unsigned short upward=0x0a7f;uint32_t another=0;
    __asm__ volatile("fninit\n\tfldcw %0\n\tfldz\n\tfldz\n\tfdivp\n\tfld1"::"m"(upward):"memory");
    C(VM(p_m98_wasm_open(&options,&import,1,&store))==0&&store,"actual_store_creation");
    numeric();memories();floating();imports_and_failures();
    C(VM(p_m98_wasm_inspect(store,&info))==0&&!info.modules&&!info.instances&&info.peak_bytes<=options.memory_bytes,"complete_numeric_store_accounting");
    C(VM(p_m98_wasm_close(store))==0,"actual_store_teardown");
    C(VM(p_m98_wasm_inspect(store,&info))==M98_WASM_STALE,"closed_store_stale");
    C(VM(p_m98_wasm_open(&options,NULL,0,&another))==0&&another!=store,"fresh_store_generation");
    C(VM(p_m98_wasm_close(another))==0,"fresh_store_teardown");
    __asm__ volatile("fninit":::"memory");
}

#ifdef M98_WASM_GUEST_HOST
int main(void)
{
#define BIND(n) p_##n=n
    BIND(m98_wasm_open);BIND(m98_wasm_close);BIND(m98_wasm_load);BIND(m98_wasm_unload);
    BIND(m98_wasm_instantiate);BIND(m98_wasm_instance_close);BIND(m98_wasm_call);
    BIND(m98_wasm_memory_size);BIND(m98_wasm_memory_grow);BIND(m98_wasm_memory_read);
    BIND(m98_wasm_memory_write);BIND(m98_wasm_inspect);
    text("SCOPE=actual-host-engine-guest-oracles\r\nNATIVE_EXECUTION=0\r\n");suite();
    text("CHECKS=");number(checks);text("\r\nFAILURES=0\r\nSTATUS=PASS\r\n");return 0;
}
#else
void WINAPI m98_wasm_probe(void)
{
    HMODULE dll,crt;char actual[MAX_PATH],system[MAX_PATH];DWORD n;OSVERSIONINFOA os;
    log_file=CreateFileA("C:\\GOPLAB\\WA13.LOG",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(3);
    text("M98_WASM_PROBE=1\r\nNONCE=" M98_WASM_GUEST_NONCE "\r\n");
    memset(&os,0,sizeof(os));os.dwOSVersionInfoSize=sizeof(os);
    C(GetVersionExA(&os),"actual_os_query");
    text("OS_PLATFORM=");number(os.dwPlatformId);text("\r\nOS_MAJOR=");number(os.dwMajorVersion);
    text("\r\nOS_MINOR=");number(os.dwMinorVersion);text("\r\nOS_BUILD_LOW=");number(os.dwBuildNumber&65535);
    text("\r\nACP=");number(GetACP());text("\r\n");
    C(os.dwPlatformId==1&&os.dwMajorVersion==4&&os.dwMinorVersion==10&&(os.dwBuildNumber&65535)==2222&&GetACP()==949,"actual_win98_se_korean_identity");
    n=GetModuleFileNameA(NULL,actual,sizeof(actual));C(n&&n<sizeof(actual)&&!lstrcmpiA(actual,"C:\\GOPLAB\\WAS13PR.EXE"),"exact_native_probe_path");
    dll=LoadLibraryA("C:\\GOPLAB\\M98WASM.DLL");C(dll!=NULL,"load_exact_adjacent_runtime");
    n=GetModuleFileNameA(dll,actual,sizeof(actual));C(n&&n<sizeof(actual)&&!lstrcmpiA(actual,"C:\\GOPLAB\\M98WASM.DLL"),"actual_adjacent_runtime_path");
    text("MODULE_PATH=");text(actual);text("\r\n");
#define BIND(n) do{p_##n=(__typeof__(n) *)(void *)GetProcAddress(dll,#n);C(p_##n!=NULL,"resolve_" #n);}while(0)
    BIND(m98_wasm_open);BIND(m98_wasm_close);BIND(m98_wasm_load);BIND(m98_wasm_unload);
    BIND(m98_wasm_instantiate);BIND(m98_wasm_instance_close);BIND(m98_wasm_call);
    BIND(m98_wasm_memory_size);BIND(m98_wasm_memory_grow);BIND(m98_wasm_memory_read);
    BIND(m98_wasm_memory_write);BIND(m98_wasm_inspect);
    crt=GetModuleHandleA("MSVCRT.DLL");C(crt!=NULL,"runtime_original_crt_loaded");
    n=GetSystemDirectoryA(system,sizeof(system));C(n&&n<MAX_PATH-12,"actual_system_directory");memcpy(system+n,"\\MSVCRT.DLL",12);
    n=GetModuleFileNameA(crt,actual,sizeof(actual));C(n&&n<sizeof(actual)&&!lstrcmpiA(actual,system),"original_system_crt_exact_path");
    text("SYSTEM_CRT_PATH=");text(actual);text("\r\n");suite();
    C(FreeLibrary(dll),"owned_runtime_module_released");
    text("REAL_NUMERIC_WAMR=1\r\nFULL_BROWSER_WASM=0\r\nCHECKS=");number(checks);text("\r\nFAILURES=0\r\nSTATUS=PASS\r\n");finish(0);
}
#endif
