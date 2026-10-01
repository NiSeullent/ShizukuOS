/* SPDX-License-Identifier: GPL-2.0-only
 * Owned native Win98 process-exit observation, no application launch.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "exit_registry.h"
#include "original_kernel.h"
typedef BOOL (WINAPI *init_fn)(void);
typedef BOOL (WINAPI *register_fn)(px_callback,void *,DWORD,DWORD *);
typedef BOOL (WINAPI *unregister_fn)(DWORD);
typedef DWORD (WINAPI *count_fn)(void);
typedef BOOL (WINAPI *bind_fn)(volatile DWORD *,HANDLE);
typedef void (WINAPI *exit_fn)(UINT);
typedef BOOL (WINAPI *observe_fn)(DWORD *);
typedef struct static_context {DWORD id;} static_context;
static static_context first={1},second={2},removed={3};
static HANDLE report=INVALID_HANDLE_VALUE,victim,ready,go;
static DWORD main_id,caller_id,tls_slot=TLS_OUT_OF_INDEXES,expected_marker;
static volatile DWORD dep_a,dep_b;static unsigned callback_count,failures,checks;static int io_failed;
static CRITICAL_SECTION victim_lock;static exit_fn native_exit;static int use_native;
static volatile DWORD victim_tls_ok,caller_tls_ok;static DWORD dynamic_observation[3];
static DWORD len(const char *s){DWORD n=0;while(s[n])n++;return n;}
static void text(const char *s){DWORD n=len(s),written=0;if(!WriteFile(report,s,n,&written,NULL)||written!=n)io_failed=1;}
static void flush(void){if(!FlushFileBuffers(report)){io_failed=1;text("REPORT_FLUSH_FAILED=1\r\n");}}
static void value(const char *label,DWORD v){char b[9];unsigned i;for(i=0;i<8;i++)b[i]="0123456789ABCDEF"[(v>>(28-4*i))&15];b[8]=0;text(label);text(b);text("\r\n");}
static void check(const char *label,int okay){checks++;text(okay?"PASS ":"FAIL ");text(label);text("\r\n");if(!okay)failures++;}
static int equal(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static const char *mode(void){const char *p=GetCommandLineA(),*last=p;while(*p){if(*p==' ')last=p+1;p++;}return last;}
static void PX_CALL notify(void *context,uint32_t reason,uintptr_t reserved)
{
 static_context *c=context;DWORD code=STILL_ACTIVE,thread=GetCurrentThreadId(),marker=(DWORD)(UINT_PTR)TlsGetValue(tls_slot);
 callback_count++;text(c->id==2?"CALLBACK=B\r\n":c->id==1?"CALLBACK=A\r\n":"CALLBACK=REMOVED\r\n");
 check("callback rooted in native EXE static context",c==&first||c==&second);
 check("actual DLL process detach reason and nonNULL reserved",reason==DLL_PROCESS_DETACH&&reserved!=0);
 value("DETACH_THREAD_ID=",thread);value("DETACH_TLS_MARKER=",marker);value("INITIATING_CALLER_THREAD_ID=",caller_id);
 value("INITIATING_CALLER_TLS_MARKER=",expected_marker);value("DETACH_RUNS_ON_INITIATING_CALLER=",thread==caller_id);value("INITIATING_CALLER_TLS_SURVIVED=",thread==caller_id&&marker==expected_marker);
 value("NATIVE_DEP_A_ALREADY_DETACHED=",dep_a);value("NATIVE_DEP_B_ALREADY_DETACHED=",dep_b);
 check("other worker TLS marker was published",victim_tls_ok);check("caller worker TLS marker was published",expected_marker!=0x22222222||caller_tls_ok);
 check("other worker terminated before notification",GetExitCodeThread(victim,&code)&&code!=STILL_ACTIVE);value("OTHER_WORKER_EXIT_AT_DETACH=",code);
 check("callbacks reverse committed registration order",(callback_count==1&&c==&second)||(callback_count==2&&c==&first));
 if(c==&first){check("two notifications and removed callback absent",callback_count==2);value("CHECKS=",checks);value("FAILURES=",failures);
  flush();text(failures||io_failed?"STATUS=FAIL\r\n":"STATUS=SCOPED_NATIVE_EXIT_NOTIFICATION_PASS\r\n");}
 flush();
}
static DWORD WINAPI victim_thread(void *arg)
{(void)arg;victim_tls_ok=TlsSetValue(tls_slot,(void *)(UINT_PTR)0x33333333);EnterCriticalSection(&victim_lock);SetEvent(ready);Sleep(INFINITE);return 0;}
static DWORD WINAPI caller_thread(void *arg)
{(void)arg;caller_id=GetCurrentThreadId();caller_tls_ok=TlsSetValue(tls_slot,(void *)(UINT_PTR)0x22222222);SetEvent(ready);WaitForSingleObject(go,INFINITE);if(use_native)native_exit(73);else ExitProcess(73);return 90;}
static HMODULE observer(const char *path,volatile DWORD *state)
{HMODULE module=LoadLibraryA(path);bind_fn bind=module?(bind_fn)GetProcAddress(module,"PXObserverBind"):NULL;check("native dependency observer loaded and bound",bind&&bind(state,report));return module;}
void WINAPI entry(void)
{
 const char *selected=mode(),*path=NULL;int worker=0,unregistered=0,terminate=0,dynamic=0,resolver=0;HMODULE dll,dep;init_fn initialize;register_fn register_callback;unregister_fn unregister_callback;count_fn count;DWORD token_a=0,token_b=0,token_removed=0,victim_id=0,caller_created_id=0,create_error;HANDLE caller;
 if(equal(selected,"--main-import"))path="C:\\VXDLAB\\PXMI.LOG";
 else if(equal(selected,"--main-native")){path="C:\\VXDLAB\\PXMN.LOG";use_native=1;}
 else if(equal(selected,"--worker-import")){path="C:\\VXDLAB\\PXWI.LOG";worker=1;}
 else if(equal(selected,"--worker-native")){path="C:\\VXDLAB\\PXWN.LOG";worker=1;use_native=1;}
 else if(equal(selected,"--unregistered")){path="C:\\VXDLAB\\PXUN.LOG";unregistered=1;}
 else if(equal(selected,"--terminated")){path="C:\\VXDLAB\\PXTM.LOG";terminate=1;}
 else if(equal(selected,"--dynamic-unload")){path="C:\\VXDLAB\\PXDYN.LOG";dynamic=1;}
 else ExitProcess(20);
 report=CreateFileA(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 text("SCOPE=OWNED_NATIVE_EXIT_NOTIFICATION_NOT_APPLICATION_ACCEPTANCE\r\nAPPLICATION_EXECUTED=0\r\nMODE=");text(selected);text("\r\n");
 check("actual original native Win98 4.10.2222",px_original_win98());
 {union {FARPROC generic;exit_fn typed;} converted;converted.generic=px_original_kernel("ExitProcess",&resolver);native_exit=converted.typed;}
 check("actual original kernel ExitProcess export",native_exit!=NULL);
 value("KERNELEX_ORIGINAL_EXPORT_RESOLVER_USED=",resolver);
 value("IMPORTED_EXITPROCESS_ADDRESS=",(DWORD)(UINT_PTR)ExitProcess);value("KERNEL_EXPORT_EXITPROCESS_ADDRESS=",(DWORD)(UINT_PTR)native_exit);
 main_id=caller_id=GetCurrentThreadId();expected_marker=worker?0x22222222:0x11111111;
 tls_slot=TlsAlloc();check("real TLS observation slot",tls_slot!=TLS_OUT_OF_INDEXES&&TlsSetValue(tls_slot,(void *)(UINT_PTR)0x11111111));
 dep=observer("C:\\VXDLAB\\PXDEPA.DLL",&dep_a);(void)dep;
 dll=LoadLibraryA(dynamic?"C:\\VXDLAB\\PXUNLD.DLL":"C:\\VXDLAB\\M98EXIT.DLL");check("native OS managed notification DLL loaded",dll!=NULL);
 initialize=dll?(init_fn)GetProcAddress(dll,"M98ExitInitialize"):NULL;register_callback=dll?(register_fn)GetProcAddress(dll,"M98ExitRegister"):NULL;
 unregister_callback=dll?(unregister_fn)GetProcAddress(dll,"M98ExitUnregister"):NULL;count=dll?(count_fn)GetProcAddress(dll,"M98ExitCount"):NULL;
 check("four exact native manager exports",initialize&&register_callback&&unregister_callback&&count);if(failures)ExitProcess(22);
 check("registration before explicit initialize refused",!register_callback(notify,&first,sizeof(first),&token_a)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("native EXE validated and manager process lifetime pin acquired",initialize());check("repeated initialize retains same instance",initialize());
 check("stack context refused",!register_callback(notify,&token_a,sizeof(token_a),&token_removed)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("native DLL callback refused",!register_callback((px_callback)(UINT_PTR)native_exit,&first,sizeof(first),&token_removed)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("native EXE data address refused as callback",!register_callback((px_callback)(UINT_PTR)&first,&second,sizeof(second),&token_removed)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("native EXE code address refused as writable context",!register_callback(notify,(void *)(UINT_PTR)notify,1,&token_removed)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("static native EXE callback A published",register_callback(notify,&first,sizeof(first),&token_a));
 check("static native EXE callback B published",register_callback(notify,&second,sizeof(second),&token_b));
 check("rollback callback published",register_callback(notify,&removed,sizeof(removed),&token_removed));
 check("rollback callback unpublished",unregister_callback(token_removed)&&count()==2);
 check("stale rollback token refused",!unregister_callback(token_removed)&&GetLastError()==PX_NOT_FOUND);
 if(dynamic){observe_fn observe=(observe_fn)GetProcAddress(dll,"PXTestObserve");check("test variant native EXE observation published",observe&&observe(dynamic_observation));
  check("actual unpinned variant native DLL dynamic unload",FreeLibrary(dll));
  check("actual DLL_PROCESS_DETACH has NULL reserved",dynamic_observation[0]==DLL_PROCESS_DETACH&&dynamic_observation[1]==0&&dynamic_observation[2]==0x50584431u);
  check("dynamic unload invokes no registered process termination callbacks",callback_count==0);
  value("ACTUAL_DYNAMIC_DETACH_REASON=",dynamic_observation[0]);value("ACTUAL_DYNAMIC_DETACH_RESERVED_NONNULL=",dynamic_observation[1]);
  flush();text(failures||io_failed?"STATUS=FAIL\r\n":"STATUS=ACTUAL_DYNAMIC_UNLOAD_CONTROL_PASS\r\n");flush();ExitProcess(failures||io_failed?24:73);
 }
 dep=observer("C:\\VXDLAB\\PXDEPB.DLL",&dep_b);(void)dep;
 check("caller DLL reference released while manager pin retained",FreeLibrary(dll)&&count()==2);
 if(failures||io_failed){text("STATUS=FAIL_BEFORE_EXIT\r\n");flush();ExitProcess(23);}
 if(unregistered){check("all callbacks explicitly unregistered",unregister_callback(token_b)&&unregister_callback(token_a)&&!count());flush();text(failures||io_failed?"STATUS=FAIL_BEFORE_EXIT\r\n":"STATUS=UNREGISTERED_BEFORE_EXIT\r\n");flush();ExitProcess(failures||io_failed?24:73);}
 InitializeCriticalSection(&victim_lock);ready=CreateEventA(NULL,FALSE,FALSE,NULL);go=CreateEventA(NULL,TRUE,FALSE,NULL);check("owned native observation events",ready&&go);
 victim=CreateThread(NULL,0,victim_thread,NULL,0,&victim_id);create_error=victim?0:GetLastError();value("VICTIM_CREATE_HANDLE=",(DWORD)(UINT_PTR)victim);value("VICTIM_CREATE_THREAD_ID=",victim_id);value("VICTIM_CREATE_ERROR=",create_error);check("other worker alive with held private lock",victim&&WaitForSingleObject(ready,3000)==WAIT_OBJECT_0);value("OTHER_WORKER_HANDLE=",(DWORD)(UINT_PTR)victim);
 if(worker){caller=CreateThread(NULL,0,caller_thread,NULL,0,&caller_created_id);create_error=caller?0:GetLastError();value("CALLER_CREATE_HANDLE=",(DWORD)(UINT_PTR)caller);value("CALLER_CREATE_THREAD_ID=",caller_created_id);value("CALLER_CREATE_ERROR=",create_error);check("worker exit caller ready",caller&&WaitForSingleObject(ready,3000)==WAIT_OBJECT_0);}
 value("MAIN_THREAD_ID=",main_id);value("INITIATING_CALLER_THREAD_ID=",caller_id);
 if(failures||io_failed){text("STATUS=FAIL_BEFORE_EXIT\r\n");flush();ExitProcess(24);}
 if(terminate){text("READY_FOR_TERMINATE=1\r\n");flush();if(io_failed)ExitProcess(24);Sleep(INFINITE);ExitProcess(25);}
 text("READY_FOR_NATIVE_EXIT=1\r\n");flush();if(io_failed)ExitProcess(24);
 if(worker){SetEvent(go);Sleep(INFINITE);ExitProcess(26);}if(use_native)native_exit(73);else ExitProcess(73);
}
