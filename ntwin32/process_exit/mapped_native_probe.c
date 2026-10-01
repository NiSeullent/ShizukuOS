/* SPDX-License-Identifier: GPL-2.0-only
 * Own zero-import mapped TLS diagnostic. Never a production loader bridge.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "mapped_snapshot.h"
#include "mapped_fixture.h"
#include "original_kernel.h"
#include "../native_loader/pe.h"
#include "../native_loader/tls_runtime.h"
typedef void (WINAPI *tls_fn)(void *,DWORD,void *);
typedef BOOL (WINAPI *dll_fn)(HINSTANCE,DWORD,void *);
typedef void (WINAPI *bind_fn)(mx_fixture_observation *);
typedef DWORD (WINAPI *word_fn)(DWORD);
typedef void (WINAPI *exit_fn)(DWORD);
typedef void (WINAPI *notify_fn)(void *,uint32_t,uintptr_t);
typedef BOOL (WINAPI *register_fn)(notify_fn,void *,DWORD,DWORD *);
typedef BOOL (WINAPI *observer_fn)(volatile DWORD *,HANDLE);
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD io_failed;
static np_image image;static np_tls_info tls_info;static BYTE *file_bytes,*mapped;
static ntw_tls_plan plan;
static mx_snapshot snapshot;
static mx_fixture_observation observation;
static struct {ntw_tls_thread tls;HANDLE ready,gate,handle;DWORD id,marker,error;int caller;} owners[MX_OWNERS];
static volatile DWORD dep_a,dep_b;
static CRITICAL_SECTION victim_lock;
static word_fn own_word;
static exit_fn original_exit;
static int mode_worker,mode_missing,mode_dependency;
static void text(const char *s){DWORD n=0,w=0;while(s[n])n++;if(!WriteFile(report,s,n,&w,NULL)||w!=n)io_failed=1;}
static void number(const char *name,DWORD value){char h[9];unsigned i;for(i=0;i<8;i++)h[i]="0123456789ABCDEF"[(value>>(28-i*4))&15];h[8]=0;text(name);text("=");text(h);text("\r\n");}
static void flush(void){if(!FlushFileBuffers(report)){io_failed=1;text("REPORT_FLUSH_FAILED=1\r\n");}}
static void dispatch_finish(const char *status)
{text(io_failed?"STATUS=MAPPED_DIAGNOSTIC_FAIL\r\n":status);number("DISPATCH_IO_FAILED",io_failed);flush();}
static int equal(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int code_guard(void *opaque,uint32_t rva)
{
 unsigned n;(void)opaque;
 for(n=0;n<image.sections;n++){const np_section *s=&image.section[n];
  if(rva>=s->va&&rva-s->va<s->span)return (s->flags&0x60000000u)==0x60000000u&&!(s->flags&0x82000000u);
 }return 0;
}
static int relocate(void *opaque,uint32_t rva)
{DWORD v=np_u32(mapped+rva)+(DWORD)(UINT_PTR)mapped-image.base;unsigned i;(void)opaque;for(i=0;i<4;i++)mapped[rva+i]=(BYTE)(v>>(8*i));return 1;}
static FARPROC own_export(const char *name)
{
 uint32_t rva=0;const char *forward=NULL,*error=NULL;
 if(!np_export(&image,name,0,&rva,&forward,&error)||!rva||forward||!code_guard(NULL,rva))return NULL;
 return (FARPROC)(void *)(mapped+rva);
}
static void own_notify(DWORD reason,void *reserved)
{
 unsigned n;for(n=0;n<tls_info.count;n++)((tls_fn)(void *)(mapped+tls_info.callback[n]))(mapped,reason,NULL);
 ((dll_fn)(void *)(mapped+image.entry))((HINSTANCE)mapped,reason,reserved);
}
static int map_own_fixture(void)
{
 HANDLE h;DWORD high=0,bytes,got,old;unsigned n;const char *error=NULL;ntw_tls_spec spec;ntw_tls_ops ops;
 h=CreateFileA("C:\\VXDLAB\\MXFIX.DLL",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE)return 0;bytes=GetFileSize(h,&high);
 if(high||bytes<64||bytes>1024u*1024u){CloseHandle(h);return 0;}
 file_bytes=HeapAlloc(GetProcessHeap(),0,bytes);if(!file_bytes){CloseHandle(h);return 0;}
 if(!ReadFile(h,file_bytes,bytes,&got,NULL)||got!=bytes||!CloseHandle(h))return 0;
 if(!np_parse(&image,file_bytes,bytes,&error)||!np_runtime_profile(&image,&error)||!np_tls(&image,&tls_info,&error)||
    !(image.characteristics&0x2000)||image.size>1024u*1024u||image.directory[1][0]||image.directory[13][0]||
    !tls_info.present||tls_info.count!=1||tls_info.template_bytes!=4||tls_info.zero_bytes!=28||
    !code_guard(NULL,image.entry)||!code_guard(NULL,tls_info.callback[0]))return 0;
 mapped=VirtualAlloc(NULL,image.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);if(!mapped)return 0;
 for(n=0;n<image.headers;n++)mapped[n]=file_bytes[n];
 for(n=0;n<image.sections;n++){unsigned k;const np_section *s=&image.section[n];for(k=0;k<s->bytes;k++)mapped[s->va+k]=file_bytes[s->raw+k];}
 if(!np_relocations(&image,relocate,NULL,&error))return 0;
 for(n=0;n<image.sections;n++){const np_section *s=&image.section[n];DWORD protection;
  protection=s->flags&0x20000000u?(s->flags&0x80000000u?PAGE_EXECUTE_READWRITE:PAGE_EXECUTE_READ):(s->flags&0x80000000u?PAGE_READWRITE:PAGE_READONLY);
  if(!VirtualProtect(mapped+s->va,s->span,protection,&old))return 0;
 }
 if(!VirtualProtect(mapped,image.headers,PAGE_READONLY,&old)||!FlushInstructionCache(GetCurrentProcess(),mapped,image.size))return 0;
 spec.initial=mapped+tls_info.template_rva;spec.initialized_bytes=4;spec.zero_bytes=28;spec.alignment=tls_info.alignment;spec.index_address=(uint32_t *)(void *)(mapped+tls_info.index_rva);
 if(!ntw_tls_native_ops(&ops)||!ntw_tls_prepare(&plan,&spec,1,&ops,&error)||!ntw_tls_attach(&plan,&owners[0].tls,&error))return 0;
 own_notify(DLL_PROCESS_ATTACH,NULL);
 {bind_fn bind=(bind_fn)(void *)own_export("MxBind");own_word=(word_fn)(void *)own_export("MxWord");if(!bind||!own_word)return 0;bind(&observation);}
 if(observation.tls_process_attach!=1||observation.dll_process_attach!=1||own_word(0x11111111u)!=0x1234abcdu)return 0;
 owners[0].id=GetCurrentThreadId();owners[0].marker=0x11111111u;
 return owners[0].id!=0;
}
static DWORD WINAPI thread_start(void *arg)
{
 DWORD index=(DWORD)(UINT_PTR)arg;const char *error=NULL;
 owners[index].id=GetCurrentThreadId();
 if(!ntw_tls_attach(&plan,&owners[index].tls,&error)){owners[index].error=1;SetEvent(owners[index].ready);return 19;}
 own_notify(DLL_THREAD_ATTACH,NULL);
 if(own_word(owners[index].marker)!=0x1234abcdu){owners[index].error=2;SetEvent(owners[index].ready);return 20;}
 if(!owners[index].caller)EnterCriticalSection(&victim_lock);
 SetEvent(owners[index].ready);
 if(WaitForSingleObject(owners[index].gate,30000)!=WAIT_OBJECT_0)return 21;
 if(owners[index].caller)original_exit(73);
 /* No orderly thread detach/free occurs in this diagnostic. Only native
  * process termination owns shutdown; physical worker cessation is unproved. */
 return 22;
}
static int start_owner(unsigned index,int caller)
{
 DWORD id=0,error;owners[index].caller=caller;owners[index].marker=caller?0x22222222u:0x33333333u;
 owners[index].ready=CreateEventA(NULL,TRUE,FALSE,NULL);owners[index].gate=CreateEventA(NULL,TRUE,FALSE,NULL);
 if(!owners[index].ready||!owners[index].gate)return 0;
 owners[index].handle=CreateThread(NULL,0,thread_start,(void *)(UINT_PTR)index,0,&id);error=owners[index].handle?0:GetLastError();
 number(caller?"CALLER_CREATE_ID":"VICTIM_CREATE_ID",id);number(caller?"CALLER_CREATE_ERROR":"VICTIM_CREATE_ERROR",error);
 return owners[index].handle&&id&&WaitForSingleObject(owners[index].ready,10000)==WAIT_OBJECT_0&&!owners[index].error&&owners[index].id==id;
}
static void WINAPI dispatch(void *context,uint32_t reason,uintptr_t reserved)
{
 DWORD thread=GetCurrentThreadId(),expected=0,detached=dep_b?MX_OWN_OBSERVER:0;uintptr_t data;enum mx_error error;unsigned n;
 text("NOTIFICATION=ACTUAL_NATIVE_PROCESS_DETACH\r\n");number("DISPATCH_THREAD_ID",thread);number("DISPATCH_REASON",reason);number("DISPATCH_RESERVED_NONNULL",reserved!=0);
 number("DEPENDENCY_A_ALREADY_DETACHED",dep_a);number("DEPENDENCY_B_ALREADY_DETACHED",dep_b);
 if(context!=&snapshot||reason!=DLL_PROCESS_DETACH||!reserved||(dep_a&0x80000000u)||(dep_b&0x80000000u)){
  text("OWN_MAPPED_CODE_INVOKED=0\r\n");dispatch_finish("STATUS=MAPPED_DIAGNOSTIC_FAIL\r\n");return;
 }
 data=(uintptr_t)TlsGetValue(snapshot.spec.tls_slot);number("DISPATCH_EXISTING_TLS_DATA",(DWORD)data);
 error=mx_dispatch_guard(&snapshot,thread,data,detached);number("DISPATCH_GUARD",error);
 if(error!=MX_OK){
  text("OWN_MAPPED_CODE_INVOKED=0\r\n");
  if(error==MX_MISSING_TLS)text("REFUSAL=PREEXISTING_DISPATCHER_TLS_ABSENT\r\n");
  else if(error==MX_DETACHED_DEPENDENCY)text("REFUSAL=ACTUAL_NATIVE_DEPENDENCY_ALREADY_DETACHED\r\n");
  dispatch_finish("STATUS=MAPPED_DISPATCH_REFUSED\r\n");return;
 }
 for(n=0;n<snapshot.spec.owner_count;n++)if(snapshot.spec.owners[n].thread_id==thread)expected=snapshot.spec.owners[n].marker;
 ((tls_fn)(void *)(snapshot.spec.image_base+snapshot.spec.callbacks[0]))((void *)snapshot.spec.image_base,DLL_PROCESS_DETACH,NULL);
 ((dll_fn)(void *)(snapshot.spec.image_base+snapshot.spec.entry_rva))((HINSTANCE)snapshot.spec.image_base,DLL_PROCESS_DETACH,(void *)reserved);
 number("EXPECTED_DISPATCHER_TLS_WORD",expected);number("ACTUAL_MAPPED_TLS_CALLBACK_WORD",observation.tls_word);number("ACTUAL_MAPPED_DLLMAIN_WORD",observation.dll_word);
 number("ACTUAL_MAPPED_TLS_DETACH_COUNT",observation.tls_process_detach);number("ACTUAL_MAPPED_DLL_DETACH_COUNT",observation.dll_process_detach);
 number("ACTUAL_MAPPED_TLS_RESERVED_NONNULL",observation.tls_reserved_nonnull);number("ACTUAL_MAPPED_DLL_RESERVED_NONNULL",observation.dll_reserved_nonnull);
 number("ACTUAL_MAPPED_FAILURES",observation.failures);text("OWN_MAPPED_CODE_INVOKED=1\r\n");
 dispatch_finish(!io_failed&&!observation.failures&&observation.tls_word==expected&&observation.dll_word==expected&&observation.tls_process_detach==1&&observation.dll_process_detach==1?"STATUS=MAPPED_OWN_NOTIFICATION_PASS\r\n":"STATUS=MAPPED_DIAGNOSTIC_FAIL\r\n");
}
void WINAPI entry(void)
{
 const char *command=GetCommandLineA(),*mode=command;const char *path;DWORD token=0,n,used;mx_spec spec={0};HMODULE manager,a,b;
 BOOL (WINAPI *initialize)(void);register_fn publish;observer_fn bind;int resolver;
 for(n=0;command[n];n++)if(command[n]==' ')mode=command+n+1;
 mode_worker=equal(mode,"--worker");mode_missing=equal(mode,"--missing");mode_dependency=equal(mode,"--dependency");
 if(!mode_worker&&!mode_missing&&!mode_dependency&&!equal(mode,"--main"))ExitProcess(20);
 path=mode_worker?"C:\\VXDLAB\\MXWO.LOG":mode_missing?"C:\\VXDLAB\\MXNO.LOG":mode_dependency?"C:\\VXDLAB\\MXDP.LOG":"C:\\VXDLAB\\MXMA.LOG";
 report=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 text("SCOPE=OWN_ZERO_IMPORT_MAPPED_EXIT_DIAGNOSTIC\r\nAPPLICATION_SUCCESS=0\r\nPHYSICAL_WORKER_CESSATION_ESTABLISHED=0\r\n");text("MODE=");text(mode);text("\r\n");
 original_exit=(exit_fn)(void *)px_original_kernel("ExitProcess",&resolver);
 if(!original_exit||!px_original_win98()||!map_own_fixture())goto fail;
 a=LoadLibraryA("C:\\VXDLAB\\PXDEPA.DLL");if(!a)goto fail;bind=(observer_fn)(void *)GetProcAddress(a,"PXObserverBind");if(!bind||!bind(&dep_a,report))goto fail;
 manager=LoadLibraryA("C:\\VXDLAB\\M98EXIT.DLL");if(!manager)goto fail;
 initialize=(BOOL (WINAPI *)(void))(void *)GetProcAddress(manager,"M98ExitInitialize");publish=(register_fn)(void *)GetProcAddress(manager,"M98ExitRegister");if(!initialize||!publish||!initialize())goto fail;
 b=LoadLibraryA("C:\\VXDLAB\\PXDEPB.DLL");if(!b)goto fail;bind=(observer_fn)(void *)GetProcAddress(b,"PXObserverBind");if(!bind||!bind(&dep_b,report))goto fail;
 InitializeCriticalSection(&victim_lock);used=1;
 if(!mode_missing){if(!start_owner(1,0))goto fail;used=2;if(mode_worker){if(!start_owner(2,1))goto fail;used=3;}}
 spec.image_base=(uintptr_t)mapped;spec.image_bytes=image.size;spec.tls_slot=plan.module[0].slot;spec.dependencies=MX_KERNEL32|(mode_dependency?MX_OWN_OBSERVER:0);
 spec.entry_rva=image.entry;spec.callback_count=1;spec.callbacks[0]=tls_info.callback[0];spec.owner_count=used;
 for(n=0;n<used;n++){spec.owners[n].thread_id=owners[n].id;spec.owners[n].tls_data=(uintptr_t)owners[n].tls.data[0];spec.owners[n].tls_bytes=plan.module[0].bytes;spec.owners[n].marker=owners[n].marker;}
 if(observation.failures||mx_seal(&snapshot,&spec,code_guard,NULL)!=MX_OK||!publish(dispatch,&snapshot,sizeof(snapshot),&token))goto fail;
 text("SNAPSHOT=IMMUTABLE_NATIVE_EXE_BSS_AFTER_FULL_ATTACH\r\n");number("MAIN_THREAD_ID",owners[0].id);number("TLS_SLOT",snapshot.spec.tls_slot);number("ELIGIBLE_PREEXISTING_TLS_OWNERS",used);
 if(mode_missing&&!TlsSetValue(snapshot.spec.tls_slot,NULL))goto fail;
 text("READY_FOR_REAL_NATIVE_EXIT=1\r\n");flush();if(io_failed)goto fail;
 if(mode_worker){if(!SetEvent(owners[2].gate))goto fail;Sleep(30000);goto fail;}
 original_exit(73);
fail:
 text("STATUS=MAPPED_DIAGNOSTIC_PREPARATION_FAIL\r\n");flush();ExitProcess(23);
}
