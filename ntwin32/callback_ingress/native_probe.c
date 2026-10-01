/* SPDX-License-Identifier: GPL-2.0-only -- own mapped TLS/provider-worker probe */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "ingress.h"
#include "fixture.h"
#include "fixture_contract.h"
#include "../native_loader/pe.h"
typedef void (WINAPI *tls_fn)(void *,DWORD,void *);
typedef BOOL (WINAPI *dll_fn)(HINSTANCE,DWORD,void *);
typedef void (WINAPI *bind_fn)(ci_observation *);
typedef DWORD (WINAPI *word_fn)(DWORD);
static HANDLE report=INVALID_HANDLE_VALUE;
static DWORD checks,failures,io_failed,external_slot=TLS_OUT_OF_INDEXES;
static CRITICAL_SECTION lock;
static np_image image;
static np_tls_info tls_info;
static BYTE *original,*mapped;
static DWORD original_hash,code_hash;
static ntw_tls_plan plan;
static ntw_tls_thread main_tls;
static ni_manager manager;
static ci_observation observation;
static word_fn own_word;
static int process_attached;
static struct worker_record { HANDLE ready,gate,thread; DWORD id,base; ni_handle handle; } worker[2];
static void text(const char *s)
{ DWORD n=0,w=0; while(s[n]) n++; if(!WriteFile(report,s,n,&w,NULL) || w!=n) io_failed=1; }
static void number(const char *key,DWORD value)
{ char b[9]; unsigned n; for(n=0;n<8;n++) b[n]="0123456789ABCDEF"[(value>>(28-4*n))&15]; b[8]=0; text(key); text("="); text(b); text("\r\n"); }
static void check(const char *name,int condition)
{ EnterCriticalSection(&lock); checks++; text(condition?"PASS=":"FAIL="); text(name); text("\r\n"); if(!condition) failures++; LeaveCriticalSection(&lock); }
static DWORD hash(const BYTE *p,DWORD bytes)
{ DWORD h=2166136261u,i; for(i=0;i<bytes;i++) { h^=p[i]; h*=16777619u; } return h; }
static DWORD mapped_code_hash(void)
{ DWORD h=0,n; for(n=0;n<image.sections;n++) if(image.section[n].flags&0x20000000u) h^=hash(mapped+image.section[n].va,image.section[n].bytes); return h; }
static int relocate(void *context,uint32_t rva)
{ DWORD v=np_u32(mapped+rva)+(DWORD)(UINT_PTR)mapped-image.base; unsigned i; (void)context; for(i=0;i<4;i++) mapped[rva+i]=(BYTE)(v>>(8*i)); return 1; }
static int executable(uint32_t rva)
{ unsigned n; for(n=0;n<image.sections;n++) { const np_section *s=&image.section[n]; if(rva>=s->va && rva-s->va<s->span) return (s->flags&0xe2000000u)==0x60000000u; } return 0; }
static FARPROC own_export(const char *name)
{
    uint32_t rva=0; const char *forward=NULL,*error=NULL;
    if(!np_export(&image,name,0,&rva,&forward,&error) || !rva || forward || !executable(rva)) return NULL;
    return (FARPROC)(void *)(mapped+rva);
}
static int own_notify(DWORD reason)
{
    unsigned n;
    for(n=0;n<tls_info.count;n++) ((tls_fn)(void *)(mapped+tls_info.callback[n]))(mapped,reason,NULL);
    return ((dll_fn)(void *)(mapped+image.entry))((HINSTANCE)mapped,reason,NULL)!=FALSE;
}
static void thread_notice(void *context,uint32_t reason,const ntw_tls_thread *tls)
{
    (void)context;
    check("NOTIFICATION_CURRENT_NATIVE_TLS",tls->owner==GetCurrentThreadId() && tls->active && TlsGetValue(plan.module[0].slot)==tls->data[0]);
    check("NOTIFICATION_REENTRY_REFUSED",ni_begin_close(&manager)==NI_NOTIFICATION_ACTIVE);
    check("MAPPED_THREAD_NOTIFICATION",own_notify(reason));
}
static int map_fixture(void)
{
    HANDLE f; DWORD bytes,high=0,got,old,n; const char *error=NULL; const BYTE *d; ntw_tls_spec spec; ntw_tls_ops ops;
    f=CreateFileA("C:\\VXDLAB\\CIFIX.DLL",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(f==INVALID_HANDLE_VALUE) return 0;
    bytes=GetFileSize(f,&high); if(high || bytes<64 || bytes>1024u*1024u) { CloseHandle(f); return 0; }
    original=HeapAlloc(GetProcessHeap(),0,bytes); if(!original) { CloseHandle(f); return 0; }
    if(!ReadFile(f,original,bytes,&got,NULL) || got!=bytes) { CloseHandle(f); return 0; }
    if(!CloseHandle(f)) return 0;
    original_hash=hash(original,bytes); number("ORIGINAL_FIXTURE_FNV1A",original_hash); number("ORIGINAL_FIXTURE_BYTES",bytes);
    if(!np_parse(&image,original,bytes,&error) || !np_runtime_profile(&image,&error) || !np_tls(&image,&tls_info,&error) ||
       !(image.characteristics&0x2000) || image.size>1024u*1024u || !ci_fixture_zero_imports(&image) || image.directory[13][0] ||
       !tls_info.present || tls_info.count!=1 || tls_info.template_bytes!=4 || tls_info.zero_bytes!=28 ||
       !executable(image.entry) || !executable(tls_info.callback[0])) return 0;
    mapped=VirtualAlloc(NULL,image.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if(!mapped || (UINT_PTR)mapped>0xffffffffu-image.size) return 0;
    for(n=0;n<image.headers;n++) mapped[n]=original[n];
    for(n=0;n<image.sections;n++) {
        unsigned k; const np_section *s=&image.section[n];
        if((s->flags&0xa0000000u)==0xa0000000u) return 0;
        for(k=0;k<s->bytes;k++) mapped[s->va+k]=original[s->raw+k];
    }
    if(!np_relocations(&image,relocate,NULL,&error)) return 0;
    d=mapped+image.directory[9][0];
    if(np_u32(d)!=(DWORD)(UINT_PTR)mapped+tls_info.template_rva ||
       np_u32(d+4)!=(DWORD)(UINT_PTR)mapped+tls_info.template_rva+4 ||
       np_u32(d+8)!=(DWORD)(UINT_PTR)mapped+tls_info.index_rva ||
       np_u32(d+12)!=(DWORD)(UINT_PTR)mapped+tls_info.callbacks_rva ||
       np_u32(mapped+tls_info.callbacks_rva)!=(DWORD)(UINT_PTR)mapped+tls_info.callback[0] ||
       np_u32(mapped+tls_info.callbacks_rva+4)) return 0;
    for(n=0;n<image.sections;n++) {
        const np_section *s=&image.section[n]; DWORD protection;
        protection=s->flags&0x20000000u ? PAGE_EXECUTE_READ : (s->flags&0x80000000u ? PAGE_READWRITE : PAGE_READONLY);
        if(s->span && !VirtualProtect(mapped+s->va,s->span,protection,&old)) return 0;
    }
    if(!VirtualProtect(mapped,image.headers,PAGE_READONLY,&old) || !FlushInstructionCache(GetCurrentProcess(),mapped,image.size)) return 0;
    code_hash=mapped_code_hash();
    spec=(ntw_tls_spec){mapped+tls_info.template_rva,4,28,tls_info.alignment,(uint32_t *)(void *)(mapped+tls_info.index_rva)};
    if(!ntw_tls_native_ops(&ops) || !ntw_tls_prepare(&plan,&spec,1,&ops,&error) || !ntw_tls_attach(&plan,&main_tls,&error)) return 0;
    if(!own_notify(DLL_PROCESS_ATTACH)) return 0; process_attached=1;
    { bind_fn bind=(bind_fn)(void *)own_export("CiBind"); own_word=(word_fn)(void *)own_export("CiWord");
      if(!bind || !own_word) return 0; bind(&observation); }
    return observation.process_attach==1 && own_word(0xcafebabeu)==0x1234abcdu;
}
static DWORD WINAPI provider_worker(void *argument)
{
    struct worker_record *w=argument; ni_status status; ni_frame outer,nested; DWORD i,prior=0x1234abcdu; int valid=1;
    if(!TlsSetValue(external_slot,(void *)(UINT_PTR)w->base)) return 40;
    EnterCriticalSection(&lock); status=ni_worker_start(&manager,&w->handle); check("ACTUAL_PROVIDER_WORKER_ADMITTED",status==NI_OK);
    LeaveCriticalSection(&lock);
    if(status!=NI_OK) { SetEvent(w->ready); FlushFileBuffers(report); ExitProcess(41); }
    for(i=0;i<64;i++) {
        DWORD value=w->base+2*i;
        EnterCriticalSection(&lock);
        status=ni_callback_enter(&manager,&w->handle,&outer);
        if(status==NI_OK) status=ni_callback_enter(&manager,&w->handle,&nested);
        if(status!=NI_OK || ni_worker_stop(&manager,&w->handle)!=NI_BUSY || ni_callback_leave(&manager,&outer)!=NI_FRAME_ORDER) valid=0;
        LeaveCriticalSection(&lock);
        if(status!=NI_OK) { FlushFileBuffers(report); ExitProcess(42); }
        if(own_word(value)!=prior || own_word(value+1)!=value) valid=0; prior=value+1;
        EnterCriticalSection(&lock);
        if(ni_callback_leave(&manager,&nested)!=NI_OK || ni_callback_leave(&manager,&outer)!=NI_OK || ni_callback_leave(&manager,&outer)!=NI_FRAME_ORDER) valid=0;
        LeaveCriticalSection(&lock);
    }
    check("REUSED_MAPPED_COMPILER_TLS_128_CALLS",valid);
    check("PROVIDER_UNRELATED_NATIVE_TLS_PRESERVED",TlsGetValue(external_slot)==(void *)(UINT_PTR)w->base);
    if(!SetEvent(w->ready) || WaitForSingleObject(w->gate,15000)!=WAIT_OBJECT_0) { FlushFileBuffers(report); ExitProcess(43); }
    EnterCriticalSection(&lock);
    check("CLOSING_PREVENTS_NEW_CALLBACK",ni_callback_enter(&manager,&w->handle,&outer)==NI_CLOSING);
    status=ni_worker_stop(&manager,&w->handle); check("ACTUAL_PROVIDER_WORKER_RETIRED",status==NI_OK);
    check("RETIRED_HANDLE_REFUSED",ni_callback_leave(&manager,&nested)==NI_HANDLE);
    check("PROVIDER_OWNED_NATIVE_TLS_CLEARED",TlsGetValue(plan.module[0].slot)==NULL);
    LeaveCriticalSection(&lock);
    if(status!=NI_OK) { FlushFileBuffers(report); ExitProcess(44); }
    return TlsSetValue(external_slot,NULL) ? 0 : 45;
}
void WINAPI entry(void)
{
    DWORD result=30,n,started=0; const char *error=NULL; ni_frame frame;
    report=CreateFileA("C:\\VXDLAB\\CIWRK.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(report==INVALID_HANDLE_VALUE) ExitProcess(21);
    InitializeCriticalSection(&lock);
    text("SCOPE=OWN_MAPPED_TLS_PROVIDER_WORKER_INGRESS\r\nAPPLICATION_SUCCESS=0\r\nPRODUCTION_PROVIDER_INTEGRATED=0\r\n");
    if(!map_fixture()) { text("PREPARATION_FAILED=1\r\n"); goto finish; }
    check("ACTUAL_WIN98_TLS_BACKEND",main_tls.active && plan.ready);
    external_slot=TlsAlloc(); check("UNRELATED_NATIVE_SLOT_ALLOCATED",external_slot!=TLS_OUT_OF_INDEXES && external_slot!=plan.module[0].slot);
    if(external_slot==TLS_OUT_OF_INDEXES) goto finish;
    check("MAIN_NATIVE_EXTERNAL_SLOT_SET",TlsSetValue(external_slot,(void *)(UINT_PTR)0x13579bdfu));
    check("INGRESS_MANAGER_OPEN",ni_manager_init(&manager,&plan,thread_notice,NULL)==NI_OK);
    for(n=0;n<2;n++) {
        worker[n].base=n ? 0x22220000u : 0x11110000u;
        worker[n].ready=CreateEventA(NULL,TRUE,FALSE,NULL); worker[n].gate=CreateEventA(NULL,TRUE,FALSE,NULL);
        if(!worker[n].ready || !worker[n].gate) goto unsafe;
        worker[n].thread=CreateThread(NULL,0,provider_worker,&worker[n],0,&worker[n].id);
        check("REAL_NATIVE_PROVIDER_THREAD_CREATED",worker[n].thread!=NULL && worker[n].id!=0);
        if(!worker[n].thread) goto unsafe; started++;
    }
    for(n=0;n<2;n++) if(WaitForSingleObject(worker[n].ready,15000)!=WAIT_OBJECT_0) goto unsafe;
    EnterCriticalSection(&lock);
    check("PERSISTENT_WORKERS_REGISTERED_ONCE",manager.live_workers==2 && manager.live_calls==0 && observation.tls_attach==2 && observation.dll_attach==2);
    check("OTHER_THREAD_CANNOT_ENTER",ni_callback_enter(&manager,&worker[0].handle,&frame)==NI_WRONG_THREAD);
    check("OTHER_THREAD_CANNOT_RETIRE",ni_worker_stop(&manager,&worker[1].handle)==NI_WRONG_THREAD);
    check("LOGICAL_CLOSE_STARTED",ni_begin_close(&manager)==NI_OK);
    check("CLOSE_RETAINS_LIVE_WORKERS",ni_finish(&manager)==NI_BUSY);
    LeaveCriticalSection(&lock);
    for(n=0;n<2;n++) if(!SetEvent(worker[n].gate)) goto unsafe;
    for(n=0;n<2;n++) {
        DWORD code=STILL_ACTIVE;
        if(WaitForSingleObject(worker[n].thread,10000)!=WAIT_OBJECT_0) goto unsafe;
        check("ACTUAL_PROVIDER_THREAD_EXIT_QUERIED",GetExitCodeThread(worker[n].thread,&code)); check("ACTUAL_PROVIDER_THREAD_EXIT_ZERO",code==0);
        check("ACTUAL_PROVIDER_THREAD_HANDLE_CLOSED",CloseHandle(worker[n].thread)); worker[n].thread=NULL;
        check("PROVIDER_READY_EVENT_CLOSED",CloseHandle(worker[n].ready)); check("PROVIDER_GATE_EVENT_CLOSED",CloseHandle(worker[n].gate));
    }
    started=0;
    EnterCriticalSection(&lock);
    check("PROVIDER_LOGICAL_RETIREMENT_COMPLETE",ni_finish(&manager)==NI_OK && !manager.live_workers && !manager.live_calls);
    check("TLS_THREAD_NOTIFICATIONS_ONCE_EACH",observation.tls_attach==2 && observation.dll_attach==2 && observation.tls_detach==2 && observation.dll_detach==2);
    check("DETACH_READS_ACTUAL_WORKER_TLS",(observation.retired_word[0]==0x1111007fu && observation.retired_word[1]==0x2222007fu) || (observation.retired_word[1]==0x1111007fu && observation.retired_word[0]==0x2222007fu));
    check("MAPPED_NOTIFICATION_FAILURES_ZERO",!observation.failures);
    check("MAIN_COMPILER_TLS_STILL_ISOLATED",own_word(0xcafebabeu)==0xcafebabeu);
    check("MAIN_UNRELATED_NATIVE_TLS_PRESERVED",TlsGetValue(external_slot)==(void *)(UINT_PTR)0x13579bdfu);
    check("MAPPED_PROCESS_DETACH",own_notify(DLL_PROCESS_DETACH) && observation.process_detach==1); process_attached=0;
    check("MAIN_TLS_DETACHED",ntw_tls_detach(&main_tls,&error));
    check("PLAN_DISPOSED_AFTER_REAL_WORKER_JOIN",ntw_tls_dispose(&plan,&error));
    check("ORIGINAL_MAPPED_TLS_INDEX_RESTORED",np_u32(mapped+tls_info.index_rva)==0xdeadbeefu);
    check("ORIGINAL_FIXTURE_UNCHANGED",hash(original,image.bytes)==original_hash);
    check("MAPPED_CODE_UNCHANGED",mapped_code_hash()==code_hash);
    LeaveCriticalSection(&lock);
    check("UNRELATED_NATIVE_SLOT_CLEARED",TlsSetValue(external_slot,NULL)); check("UNRELATED_NATIVE_SLOT_FREED",TlsFree(external_slot)); external_slot=TLS_OUT_OF_INDEXES;
    if(plan.live_threads || main_tls.active || process_attached || plan.ready || plan.count) goto unsafe;
    check("MAPPED_IMAGE_RELEASED_AFTER_JOIN",VirtualFree(mapped,0,MEM_RELEASE)); mapped=NULL;
    check("ORIGINAL_FILE_STORAGE_RELEASED",HeapFree(GetProcessHeap(),0,original)); original=NULL;
    result=0;
    goto finish;
unsafe:
    text("REFUSAL=PROVIDER_LIFETIME_NOT_CLOSED\r\n"); number("STARTED_PROVIDER_THREADS",started);
    /* Keep every borrowed mapping/TLS/reference live until private process
     * termination. No unsafe unmap/free, timeout success or thread killing. */
finish:
    number("CHECKS",checks); number("FAILURES",failures);
    if(failures || io_failed) result=31;
    text(result?"STATUS=FAIL\r\n":"STATUS=PASS\r\n"); text("OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n");
    if(!FlushFileBuffers(report)) result=32;
    /* A failed/unjoined worker still borrows the report and lock. Let the OS
     * reclaim them on this failing private-process path; never destroy them
     * underneath a live provider or publish successful cleanup. */
    if(started || manager.live_workers) ExitProcess(result ? result : 33);
    if(!CloseHandle(report)) result=32;
    DeleteCriticalSection(&lock); ExitProcess(result);
}
