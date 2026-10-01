/* SPDX-License-Identifier: GPL-2.0-only
 * Ordinary Win98 native EXE: publish a new compiler TLS template to an
 * already-created admitted worker while preserving its original TLS plan.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "tls_remote.h"
extern unsigned ntw_tls_compiler_word,ntw_tls_compiler_read(void);
extern void ntw_tls_compiler_write(unsigned);
uint32_t _tls_index=0xdeadbeefu;
static uint32_t base_index=0xf00d1234u;
static unsigned base_template=0x10203040u;
static ntw_tls_plan base_plan,extension;
static ntw_tls_thread main_base,main_extension,worker_base,worker_extension;
static ntw_tls_native_target worker_target;
static CRITICAL_SECTION lock;
static HANDLE ready,go,done,finish,report=INVALID_HANDLE_VALUE;
static DWORD external_slot=TLS_OUT_OF_INDEXES,checks,failures;
static int io_failed;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static void text(const char *s){DWORD wrote,n=length(s);if(!WriteFile(report,s,n,&wrote,NULL)||wrote!=n)io_failed=1;}
static void number(DWORD value){char b[11];unsigned n=0;do{b[n++]=(char)('0'+value%10);value/=10;}while(value);while(n){char x[2]={b[--n],0};text(x);}}
static void check(const char *name,int condition)
{EnterCriticalSection(&lock);checks++;text(condition?"PASS=":"FAIL=");text(name);text("\r\n");if(!condition)failures++;LeaveCriticalSection(&lock);}
static int aligned_zero(const ntw_tls_thread *t)
{unsigned i;if(!t->data[0]||((UINT_PTR)t->data[0]&63u))return 0;for(i=4;i<32;i++)if(((BYTE *)t->data[0])[i])return 0;return 1;}
static void emergency(const char *reason)
{text("STATUS=");text(reason);text("\r\n");FlushFileBuffers(report);ExitProcess(44);}
static DWORD WINAPI worker(void *unused)
{
    const char *error=NULL;int admitted,attached,ok;(void)unused;
    EnterCriticalSection(&lock);
    admitted=ntw_tls_capture_current_target(&worker_target,&error);check("WORKER_CAPTURE_ACTUAL_TIB_VECTOR",admitted);
    attached=admitted&&ntw_tls_attach(&base_plan,&worker_base,&error);check("WORKER_ORIGINAL_PLAN_ATTACH",attached);
    if(!attached){LeaveCriticalSection(&lock);return 41;}
    *(unsigned *)worker_base.data[0]=0xb0b0b0b0u;
    check("WORKER_ORIGINAL_NATIVE_TLS_VALUE",TlsGetValue(base_index)==worker_base.data[0]);
    check("WORKER_UNRELATED_SLOT_SET",TlsSetValue(external_slot,(void *)(UINT_PTR)0x2468aceu));
    LeaveCriticalSection(&lock);SetEvent(ready);
    if(WaitForSingleObject(go,10000)!=WAIT_OBJECT_0)return 42;
    check("EXISTING_WORKER_COMPILER_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
    check("EXISTING_WORKER_NEW_TLS_ALIGNMENT_ZERO",aligned_zero(&worker_extension));
    ntw_tls_compiler_write(0xbadc0ffeu);check("EXISTING_WORKER_COMPILER_WRITE_READ",ntw_tls_compiler_read()==0xbadc0ffeu);
    check("EXISTING_WORKER_ORIGINAL_TLS_PRESERVED",TlsGetValue(base_index)==worker_base.data[0]&&*(unsigned *)worker_base.data[0]==0xb0b0b0b0u);
    check("EXISTING_WORKER_UNRELATED_TLS_PRESERVED",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x2468aceu);
    SetEvent(done);if(WaitForSingleObject(finish,10000)!=WAIT_OBJECT_0)return 43;
    EnterCriticalSection(&lock);
    check("WORKER_EXTENSION_SLOT_CLEARED_REMOTELY",!TlsGetValue(extension.module[0].slot));
    check("WORKER_ORIGINAL_TLS_STILL_ALIVE",TlsGetValue(base_index)==worker_base.data[0]&&*(unsigned *)worker_base.data[0]==0xb0b0b0b0u);
    ok=ntw_tls_detach(&worker_base,&error);check("WORKER_ORIGINAL_DETACH",ok);
    ntw_tls_retire_target(&worker_target);check("WORKER_TARGET_RETIRED_UNDER_LOCK",!worker_target.admitted);
    check("WORKER_UNRELATED_SLOT_AFTER_RETIRE",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x2468aceu);
    if(!TlsSetValue(external_slot,NULL))ok=0;
    LeaveCriticalSection(&lock);return ok?0:45;
}
void WINAPI entry(void)
{
    ntw_tls_ops ops={0};ntw_tls_remote_io remote={0};ntw_tls_spec spec;const char *error=NULL;
    OSVERSIONINFOA version={0};HANDLE thread=NULL;DWORD id=0,code=STILL_ACTIVE,result=30;
    report=CreateFileA("C:\\VXDLAB\\LATEPRB.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(report==INVALID_HANDLE_VALUE)ExitProcess(21);InitializeCriticalSection(&lock);
    text("PROBE=NTW_WIN98_EXISTING_WORKER_COMPILER_TLS_EXTENSION\r\n");
    version.dwOSVersionInfoSize=sizeof(version);
    if(GetVersionExA(&version)){text("OS_MAJOR=");number(version.dwMajorVersion);text("\r\nOS_MINOR=");number(version.dwMinorVersion);text("\r\nOS_BUILD=");number(version.dwBuildNumber&65535);text("\r\n");}
    if(!ntw_tls_native_ops(&ops)){text("STATUS=NATIVE_ABI_UNAVAILABLE\r\n");goto final;}
    check("NATIVE_WIN98_ABI",1);external_slot=TlsAlloc();check("UNRELATED_SLOT_ALLOC",external_slot!=TLS_OUT_OF_INDEXES);
    if(external_slot==TLS_OUT_OF_INDEXES)goto final;
    check("MAIN_UNRELATED_SLOT_SET",TlsSetValue(external_slot,(void *)(UINT_PTR)0x13579bdfu));
    ready=CreateEventA(NULL,TRUE,FALSE,NULL);go=CreateEventA(NULL,TRUE,FALSE,NULL);
    done=CreateEventA(NULL,TRUE,FALSE,NULL);finish=CreateEventA(NULL,TRUE,FALSE,NULL);
    if(!ready||!go||!done||!finish)emergency("EVENT_CREATE_FAILED");
    spec.initial=&base_template;spec.initialized_bytes=4;spec.zero_bytes=28;spec.alignment=64;spec.index_address=&base_index;
    if(!ntw_tls_prepare(&base_plan,&spec,1,&ops,&error)||!ntw_tls_attach(&base_plan,&main_base,&error))emergency("BASE_PREPARE_FAILED");
    *(unsigned *)main_base.data[0]=0xa0a0a0a0u;check("MAIN_ORIGINAL_PLAN_ATTACHED",1);
    thread=CreateThread(NULL,0,worker,NULL,0,&id);check("ACTUAL_ALREADY_CREATED_WORKER",thread!=NULL);
    if(!thread||WaitForSingleObject(ready,10000)!=WAIT_OBJECT_0)emergency("WORKER_NOT_READY");
    check("ADMITTED_RECORD_MATCHES_CREATED_THREAD",worker_target.owner==id&&worker_target.admitted);
    spec.initial=&ntw_tls_compiler_word;spec.index_address=&_tls_index;
    EnterCriticalSection(&lock);
    if(!ntw_tls_prepare(&extension,&spec,1,&ops,&error))emergency("EXTENSION_PREPARE_FAILED");
    check("NEW_PLAN_KEEPS_ORIGINAL_SLOT",_tls_index!=base_index&&_tls_index!=external_slot);
    if(!ntw_tls_attach(&extension,&main_extension,&error))emergency("MAIN_EXTENSION_FAILED");
    check("NATIVE_REMOTE_IO_VALIDATED",ntw_tls_native_remote_io(&worker_target,&remote,&error));
    if(!remote.read||!ntw_tls_remote_attach(&extension,&worker_extension,&remote,&error))emergency("REMOTE_EXTENSION_FAILED");
    check("REMOTE_THREAD_STATE_OWNS_REAL_PLAN",worker_extension.plan==&extension&&worker_extension.owner==id&&extension.live_threads==2);
    check("REMOTE_BLOCK_INDEPENDENT_OF_MAIN",worker_extension.data[0]!=main_extension.data[0]);
    check("ORIGINAL_PLAN_LIVE_COUNT_UNCHANGED",base_plan.live_threads==2);
    LeaveCriticalSection(&lock);
    check("MAIN_COMPILER_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
    ntw_tls_compiler_write(0xcafebabeu);check("MAIN_COMPILER_WRITE_READ",ntw_tls_compiler_read()==0xcafebabeu);
    SetEvent(go);if(WaitForSingleObject(done,10000)!=WAIT_OBJECT_0)emergency("WORKER_NEW_TLS_NOT_DONE");
    check("MAIN_COMPILER_THREAD_ISOLATION",ntw_tls_compiler_read()==0xcafebabeu);
    check("MAIN_ORIGINAL_NATIVE_TLS_PRESERVED",TlsGetValue(base_index)==main_base.data[0]&&*(unsigned *)main_base.data[0]==0xa0a0a0a0u);
    check("MAIN_UNRELATED_TLS_PRESERVED",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x13579bdfu);
    EnterCriticalSection(&lock);
    check("REMOTE_EXTENSION_DETACH",ntw_tls_remote_detach(&worker_extension,&remote,&error));
    check("REMOTE_SLOT_CLEAR_PRESERVES_ORIGINAL_PLAN",base_plan.live_threads==2&&extension.live_threads==1);
    LeaveCriticalSection(&lock);SetEvent(finish);
    if(WaitForSingleObject(thread,10000)!=WAIT_OBJECT_0)emergency("WORKER_NOT_JOINED");
    check("ACTUAL_WORKER_EXIT_QUERY",GetExitCodeThread(thread,&code));check("ACTUAL_WORKER_EXIT_ZERO",code==0);
    CloseHandle(thread);thread=NULL;
    check("RETIRED_TARGET_REFUSED",!ntw_tls_native_remote_io(&worker_target,&remote,&error));
    check("MAIN_EXTENSION_DETACH",ntw_tls_detach(&main_extension,&error));
    check("EXTENSION_DISPOSE_INDEX_RESTORE",ntw_tls_dispose(&extension,&error));
    check("COMPILER_INDEX_ORIGINAL_RESTORED",_tls_index==0xdeadbeefu);
    check("MAIN_BASE_DETACH",ntw_tls_detach(&main_base,&error));check("BASE_DISPOSE_INDEX_RESTORE",ntw_tls_dispose(&base_plan,&error));
    check("BASE_INDEX_ORIGINAL_RESTORED",base_index==0xf00d1234u);
    check("MAIN_UNRELATED_SLOT_AT_FINAL",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x13579bdfu);
    TlsSetValue(external_slot,NULL);check("UNRELATED_SLOT_FREE",TlsFree(external_slot));
    CloseHandle(ready);CloseHandle(go);CloseHandle(done);CloseHandle(finish);result=0;
final:
    text("CHECKS=");number(checks);text("\r\nFAILURES=");number(failures);text("\r\n");
    if(failures||io_failed)result=31;text(result?"STATUS=FAIL\r\n":"STATUS=PASS\r\n");
    if(!FlushFileBuffers(report)||io_failed)result=32;
    CloseHandle(report);DeleteCriticalSection(&lock);ExitProcess(result);
}
