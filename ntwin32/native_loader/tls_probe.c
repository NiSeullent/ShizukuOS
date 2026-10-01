/* SPDX-License-Identifier: GPL-2.0-only
 * Ordinary native PE with no automatic TLS directory. The MS-ABI compiler
 * fixture accesses only the explicit helper-published Win98 TLS slot.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "tls_runtime.h"
extern unsigned ntw_tls_compiler_word;
extern unsigned ntw_tls_compiler_read(void);
extern void ntw_tls_compiler_write(unsigned);
uint32_t _tls_index=0xdeadbeefu;
static ntw_tls_plan plan;
static ntw_tls_thread main_thread;
static CRITICAL_SECTION lock;
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD external_slot=TLS_OUT_OF_INDEXES,failures,checks;
static int io_failed;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static void text(const char *s){DWORD got,n=length(s);if(!WriteFile(report,s,n,&got,NULL)||got!=n)io_failed=1;}
static void number(DWORD value){char b[11];unsigned n=0;do{b[n++]=(char)('0'+value%10);value/=10;}while(value);while(n){char x[2];x[0]=b[--n];x[1]=0;text(x);}}
static void check(const char *name,int condition){EnterCriticalSection(&lock);checks++;text(condition?"PASS=":"FAIL=");text(name);text("\r\n");if(!condition)failures++;LeaveCriticalSection(&lock);}
static int aligned_zero(const ntw_tls_thread *t)
{
 unsigned n;if(((UINT_PTR)t->data[0]&63u)!=0)return 0;
 for(n=4;n<32;n++)if(((BYTE *)t->data[0])[n])return 0;return 1;
}
static DWORD WINAPI worker(void *ignored)
{
 ntw_tls_thread thread={0};const char *error=NULL;int attached,detached;DWORD result=0;(void)ignored;
 if(!TlsSetValue(external_slot,(void *)(UINT_PTR)0x2468aceu))return 40;
 EnterCriticalSection(&lock);attached=ntw_tls_attach(&plan,&thread,&error);check("WORKER_ATTACH",attached);LeaveCriticalSection(&lock);
 if(!attached)return 41;
 check("WORKER_COMPILER_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
 check("WORKER_ALIGNMENT64_ZERO_FILL",aligned_zero(&thread));
 ntw_tls_compiler_write(0xbadc0ffeu);check("WORKER_COMPILER_WRITE_READ",ntw_tls_compiler_read()==0xbadc0ffeu);
 check("WORKER_UNRELATED_NATIVE_SLOT",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x2468aceu);
 EnterCriticalSection(&lock);detached=ntw_tls_detach(&thread,&error);check("WORKER_DETACH",detached);LeaveCriticalSection(&lock);
 if(!detached)result=42;
 check("WORKER_UNRELATED_SLOT_AFTER_DETACH",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x2468aceu);
 if(!TlsSetValue(external_slot,NULL))result=43;return result;
}
void WINAPI entry(void)
{
 ntw_tls_ops ops={0};ntw_tls_spec spec;const char *error=NULL;OSVERSIONINFOA version={0};
 DWORD result=30,thread_id,wait,thread_exit=STILL_ACTIVE;HANDLE thread=NULL;int prepared=0,attached=0;
 report=CreateFileA("C:\\VXDLAB\\TLSPRB.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 InitializeCriticalSection(&lock);
 text("PROBE=NTW_WIN98_REAL_COMPILER_TLS\r\n");version.dwOSVersionInfoSize=sizeof(version);
 if(GetVersionExA(&version)){text("OS_MAJOR=");number(version.dwMajorVersion);text("\r\nOS_MINOR=");number(version.dwMinorVersion);text("\r\nOS_BUILD=");number(version.dwBuildNumber&65535);text("\r\n");}
 if(!ntw_tls_native_ops(&ops)){text("STATUS=NATIVE_ABI_UNAVAILABLE\r\n");goto finish;}
 check("NATIVE_WIN98_FS_SLOT_ABI",1);
 external_slot=TlsAlloc();check("UNRELATED_NATIVE_SLOT_ALLOC",external_slot!=TLS_OUT_OF_INDEXES);if(external_slot==TLS_OUT_OF_INDEXES)goto dispose_lock;
 check("UNRELATED_NATIVE_SLOT_SET",TlsSetValue(external_slot,(void *)(UINT_PTR)0x13579bdfu));
 spec.initial=&ntw_tls_compiler_word;spec.initialized_bytes=4;spec.zero_bytes=28;spec.alignment=64;spec.index_address=&_tls_index;
 EnterCriticalSection(&lock);prepared=ntw_tls_prepare(&plan,&spec,1,&ops,&error);check("PLAN_PREPARE",prepared);
 if(prepared){attached=ntw_tls_attach(&plan,&main_thread,&error);check("MAIN_ATTACH",attached);}LeaveCriticalSection(&lock);
 if(!prepared||!attached){if(error){text("TLS_ERROR=");text(error);text("\r\n");}goto cleanup;}
 check("MODULE_INDEX_IS_RESERVED_NATIVE_SLOT",_tls_index==plan.module[0].slot&&_tls_index<80&&_tls_index!=external_slot);
 check("MAIN_COMPILER_INITIAL_TEMPLATE",ntw_tls_compiler_read()==0x1234abcdu);
 check("MAIN_ALIGNMENT64_ZERO_FILL",aligned_zero(&main_thread));
 ntw_tls_compiler_write(0xcafebabeu);check("MAIN_COMPILER_WRITE_READ",ntw_tls_compiler_read()==0xcafebabeu);
 thread=CreateThread(NULL,0,worker,NULL,0,&thread_id);check("REAL_NATIVE_THREAD_CREATE",thread!=NULL);if(!thread)goto cleanup;
 wait=WaitForSingleObject(thread,10000);check("REAL_NATIVE_THREAD_WAIT",wait==WAIT_OBJECT_0);
 if(wait!=WAIT_OBJECT_0){text("STATUS=WORKER_NOT_JOINED\r\n");FlushFileBuffers(report);ExitProcess(44);}
 check("REAL_NATIVE_THREAD_EXIT_QUERY",GetExitCodeThread(thread,&thread_exit));check("REAL_NATIVE_THREAD_EXIT_ZERO",thread_exit==0);CloseHandle(thread);thread=NULL;
 check("MAIN_COMPILER_VALUE_THREAD_ISOLATED",ntw_tls_compiler_read()==0xcafebabeu);
 check("MAIN_UNRELATED_SLOT_UNCHANGED",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x13579bdfu);
 result=0;
cleanup:
 EnterCriticalSection(&lock);
 if(main_thread.active)check("MAIN_DETACH",ntw_tls_detach(&main_thread,&error));
 if(plan.ready||plan.count)check("PLAN_DISPOSE_INDEX_RESTORE",ntw_tls_dispose(&plan,&error));
 LeaveCriticalSection(&lock);
 check("COMPILER_INDEX_ORIGINAL_RESTORED",_tls_index==0xdeadbeefu);
 check("UNRELATED_SLOT_AFTER_PLAN_DISPOSE",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x13579bdfu);
 TlsSetValue(external_slot,NULL);check("UNRELATED_SLOT_FREE",TlsFree(external_slot));
dispose_lock:
finish:
 DeleteCriticalSection(&lock);
 text("CHECKS=");number(checks);text("\r\nFAILURES=");number(failures);text("\r\n");
 if(failures||io_failed)result=31;
 text(result?"STATUS=FAIL\r\n":"STATUS=PASS\r\n");if(io_failed)result=32;
 FlushFileBuffers(report);CloseHandle(report);ExitProcess(result);
}
