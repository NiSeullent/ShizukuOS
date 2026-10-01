/* SPDX-License-Identifier: GPL-2.0-only
 * Exact-production control/bounds tests with deliberately injected API
 * outcomes, not real NT waits or publisher execution. Guest owns that proof. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#define SHZ_COWAIT_HOST_TEST
#include "cowait_host_contract.h"
static DWORD wait_value,msg_value,error_value,wait_calls,msg_calls,dispatched,reposted,queue_flags;
static ULONGLONG ticks;
static int apartment_value,post_available,apc_value;
static unsigned snapshots,releases,pending,unregister_alive;
static MSG queued;
static IMessageFilter *registered_filter;
static unsigned checks;
#define VERIFY(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL:%d %s\n",__LINE__,#v);abort();}}while(0)
static HRESULT CoGetApartmentType(APTTYPE *a,APTTYPEQUALIFIER *q) {*a=apartment_value;*q=0;return S_OK;}
static DWORD WaitForMultipleObjectsEx(DWORD n,const HANDLE *h,BOOL all,DWORD ms,BOOL alert)
{
    (void)all;(void)ms;VERIFY(n>0&&n<=64&&h!=NULL);++wait_calls;
    if(alert&&apc_value){apc_value=0;return WAIT_IO_COMPLETION;}
    return wait_value;
}
static DWORD MsgWaitForMultipleObjectsEx(DWORD n,const HANDLE *h,DWORD ms,DWORD mask,DWORD flags)
{
    (void)h;(void)ms;(void)flags;++msg_calls;
    /* Actual gfx_msg.c reports pending posted/DDE/quit messages using
     * QS_POSTMESSAGE, not QS_ALLPOSTMESSAGE. Honor its genuine wait mask. */
    if(msg_value==99&&!(mask&QS_POSTMESSAGE))return WAIT_TIMEOUT;
    return msg_value==99?n:msg_value;
}
static BOOL PeekMessageW(MSG *out,HANDLE window,UINT min,UINT max,UINT flags)
{
    (void)window;queue_flags=flags;
    if(!post_available)return FALSE;
    /* Actual gfx_msg.c filter_ok also applies ranges to WM_QUIT. A separate
     * explicit quit peek is required until that general provider is changed. */
    if((min||max)&&(queued.message<min||queued.message>max))return FALSE;
    if(flags&(PM_QS_PAINT|PM_QS_SENDMESSAGE))return FALSE;
    *out=queued;post_available=0;return TRUE;
}
static BOOL TranslateMessage(const MSG *m){(void)m;return TRUE;}
static LRESULT DispatchMessageW(const MSG *m){(void)m;++dispatched;wait_value=0;return 42;}
static void PostQuitMessage(int code){VERIFY(code==73);++reposted;}
static DWORD GetLastError(void){return error_value;}
static ULONGLONG GetTickCount64(void){return ticks++;}
static void Sleep(DWORD ms){VERIFY(ms==1);ticks+=ms;}
static IMessageFilter *shz_message_filter_snapshot(void)
{if(!registered_filter)return NULL;++registered_filter->refs;++snapshots;return registered_filter;}
static DWORD host_pending(IMessageFilter *f,HANDLE task,DWORD elapsed,DWORD type)
{
    (void)elapsed;VERIFY(!task&&type==PENDINGTYPE_TOPLEVEL&&f->refs>=2);++pending;
    if(f->unregister){registered_filter=NULL;--f->refs;unregister_alive=f->refs>0;}
    return f->policy;
}
static ULONG host_release(IMessageFilter *f){VERIFY(f->refs>0);++releases;return --f->refs;}
#ifndef SHZ_COWAIT_SOURCE
#define SHZ_COWAIT_SOURCE "../dlls/ole32/co_wait.c"
#endif
#include SHZ_COWAIT_SOURCE
static void reset(void)
{
    wait_value=WAIT_TIMEOUT;msg_value=WAIT_TIMEOUT;error_value=6;wait_calls=msg_calls=dispatched=reposted=queue_flags=0;
    ticks=0;apartment_value=APTTYPE_MTA;post_available=apc_value=0;snapshots=releases=pending=unregister_alive=0;
    registered_filter=NULL;memset(&queued,0,sizeof queued);
}
int main(void)
{
    HANDLE handles[64];
    struct {DWORD before,index,after;} output={0x12345678,MAXDWORD,0x87654321};
    long page=sysconf(_SC_PAGESIZE);
    void *bad=mmap(NULL,(size_t)page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    unsigned i;
    VERIFY(bad!=MAP_FAILED);
    for(i=0;i<64;++i)handles[i]=(HANDLE)(uintptr_t)(i+1);
    reset();VERIFY(CoWaitForMultipleHandles(0,0,1,NULL,&output.index)==E_INVALIDARG&&output.index==0);
    VERIFY(CoWaitForMultipleHandles(0,0,1,handles,NULL)==E_INVALIDARG);
    VERIFY(CoWaitForMultipleHandles(0,0,0,handles,&output.index)==RPC_E_NO_SYNC);
    VERIFY(CoWaitForMultipleHandles(0x20,0,1,bad,&output.index)==E_INVALIDARG);
    VERIFY(CoWaitForMultipleHandles(0,0,65,bad,&output.index)==E_INVALIDARG);
    VERIFY(CoWaitForMultipleHandles(4,0,1,bad,&output.index)==E_NOTIMPL);
    VERIFY(!wait_calls&&!msg_calls);
    wait_value=1;VERIFY(CoWaitForMultipleHandles(8,1000,2,handles,&output.index)==S_OK&&output.index==1);
    wait_value=WAIT_ABANDONED_0+1;VERIFY(CoWaitForMultipleHandles(0,1000,2,handles,&output.index)==S_OK&&output.index==WAIT_ABANDONED_0+1);
    wait_value=WAIT_FAILED;VERIFY(CoWaitForMultipleHandles(0,0,1,handles,&output.index)==HRESULT_FROM_WIN32(6));
    error_value=0;VERIFY(CoWaitForMultipleHandles(0,0,1,handles,&output.index)==E_FAIL);
    wait_value=1000;VERIFY(CoWaitForMultipleHandles(0,0,1,handles,&output.index)==E_FAIL);
    wait_value=WAIT_IO_COMPLETION;VERIFY(CoWaitForMultipleHandles(0,0,1,handles,&output.index)==E_FAIL);
    VERIFY(CoWaitForMultipleHandles(2,0,1,handles,&output.index)==S_OK&&output.index==WAIT_IO_COMPLETION);
    wait_value=WAIT_TIMEOUT;VERIFY(CoWaitForMultipleHandles(0,0,1,handles,&output.index)==RPC_S_CALLPENDING);
    wait_value=0;VERIFY(CoWaitForMultipleHandles(1,1000,64,handles,&output.index)==S_OK&&output.index==0);
    reset();apartment_value=APTTYPE_STA;
    VERIFY(CoWaitForMultipleHandles(1,0,1,handles,&output.index)==E_NOTIMPL);
    VERIFY(CoWaitForMultipleHandles(0,0,64,handles,&output.index)==E_NOTIMPL);
    wait_value=1;VERIFY(CoWaitForMultipleHandles(8,0,2,handles,&output.index)==S_OK&&output.index==1&&!msg_calls);
    reset();apartment_value=APTTYPE_STA;apc_value=1;
    VERIFY(CoWaitForMultipleHandles(2,1000,1,handles,&output.index)==S_OK&&output.index==WAIT_IO_COMPLETION&&!msg_calls);
    reset();apartment_value=APTTYPE_STA;msg_value=99;post_available=1;queued.message=0x466;
    VERIFY(CoWaitForMultipleHandles(8,5,1,handles,&output.index)==RPC_S_CALLPENDING&&!dispatched&&post_available);
    reset();apartment_value=APTTYPE_STA;msg_value=99;post_available=1;queued.message=WM_DDE_FIRST;
    VERIFY(CoWaitForMultipleHandles(8,1000,1,handles,&output.index)==S_OK&&output.index==0&&dispatched==1&&!post_available);
    reset();apartment_value=APTTYPE_STA;msg_value=99;post_available=1;queued.message=0x466;
    VERIFY(CoWaitForMultipleHandles(16,1000,1,handles,&output.index)==S_OK&&output.index==0&&dispatched==1&&!post_available);
    {IMessageFilter f={1,PENDINGMSG_CANCELCALL,1};reset();apartment_value=APTTYPE_STA;msg_value=99;registered_filter=&f;
     VERIFY(CoWaitForMultipleHandles(16,1000,1,handles,&output.index)==RPC_E_CALL_CANCELED&&pending==1&&unregister_alive&&f.refs==0&&snapshots==releases);}
    {IMessageFilter f={1,PENDINGMSG_WAITNOPROCESS,0};reset();apartment_value=APTTYPE_STA;msg_value=99;registered_filter=&f;post_available=1;queued.message=0x466;
     VERIFY(CoWaitForMultipleHandles(16,5,1,handles,&output.index)==RPC_S_CALLPENDING&&pending>0&&f.refs==1&&!dispatched&&post_available&&snapshots==releases);}
    reset();apartment_value=APTTYPE_STA;msg_value=99;post_available=1;queued.message=WM_QUIT;queued.wParam=73;
    VERIFY(CoWaitForMultipleHandles(8,5,1,handles,&output.index)==RPC_S_CALLPENDING&&reposted==1&&!post_available);
    VERIFY(output.before==0x12345678&&output.after==0x87654321);
    VERIFY(!munmap(bad,(size_t)page));
    printf("CO-WAIT-HOST: %u checks PASS; exact body, typed guards, bounded array, unsupported flags, injected waits/filter reentry/quit; no NT/guest/app proof\n",checks);
    return 0;
}
