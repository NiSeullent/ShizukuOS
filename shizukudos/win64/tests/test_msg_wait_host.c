/* SPDX-License-Identifier: GPL-2.0-only
 * Compile the exact production MsgWait function extracted by the runner.
 * Injected queue/object results isolate polling order and zero-time behavior;
 * they do not constitute actual native waits or a publisher result. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { uint32_t op; uint64_t a,out0,out1; } shz_threadop_t;
#define DLLAPI
#define WINAPI
#define FALSE 0
#define TRUE 1
#define MAXIMUM_WAIT_OBJECTS 64
#define INFINITE UINT32_MAX
#define WAIT_FAILED UINT32_MAX
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 258
#define WAIT_IO_COMPLETION 192
#define ERROR_INVALID_PARAMETER 87
#define MWMO_WAITALL 1
#define MWMO_ALERTABLE 2
#define SHZ_TOP_QUEUEEVENT 1
#define SHZ_TOP_QUEUESTATUS 2
#define U32_NEED_GFX(result) do { if (!gfx_ready) return result; } while (0)
static unsigned checks,wait_calls,status_calls,sleep_calls;
static DWORD ticks,error_value,wait_value,queue_pending,timer_due;
static int gfx_ready,native_failure;
static DWORD got_count,got_timeout;
static BOOL got_all,got_alert;
static HANDLE got_handles[64];
#define VERIFY(v) do { ++checks; if(!(v)){fprintf(stderr,"FAIL:%d %s\n",__LINE__,#v);abort();} } while(0)
static DWORD GetTickCount(void) { return ticks; }
static void SetLastError(DWORD value) { error_value=value; }
static void u32_err(int32_t status) { error_value=(DWORD)-status; }
static int32_t NtUserThreadOp(shz_threadop_t *t)
{
    if(native_failure) return -6;
    if(t->op==SHZ_TOP_QUEUEEVENT)t->out0=0x999;
    else {VERIFY(t->op==SHZ_TOP_QUEUESTATUS);++status_calls;t->out0=queue_pending;t->out1=timer_due;}
    return 0;
}
static DWORD WaitForMultipleObjectsEx(DWORD n,const HANDLE *h,BOOL all,DWORD ms,BOOL alert)
{
    VERIFY(n>0&&n<=64&&h!=NULL);++wait_calls;
    got_count=n;got_timeout=ms;got_all=all;got_alert=alert;
    memcpy(got_handles,h,n*sizeof *h);
    return wait_value;
}
static void Sleep(DWORD ms){VERIFY(ms==1);++sleep_calls;ticks+=ms;}
#include "production_msg_wait.h"
static void reset(void)
{
    wait_calls=status_calls=sleep_calls=ticks=error_value=queue_pending=0;
    wait_value=WAIT_TIMEOUT;timer_due=UINT32_MAX;gfx_ready=1;native_failure=0;
    got_count=got_timeout=0;got_all=got_alert=FALSE;
    memset(got_handles,0,sizeof got_handles);
}
int main(void)
{
    HANDLE handles[64];unsigned i;
    for(i=0;i<64;++i)handles[i]=(HANDLE)(uintptr_t)(i+1);
    reset();VERIFY(MsgWaitForMultipleObjectsEx(64,handles,0,0,0)==WAIT_FAILED&&error_value==87&&!wait_calls);
    VERIFY(MsgWaitForMultipleObjectsEx(1,NULL,0,0,0)==WAIT_FAILED&&error_value==87&&!wait_calls);
    reset();gfx_ready=0;VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_FAILED&&!wait_calls);
    reset();native_failure=1;VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_FAILED&&error_value==6&&!wait_calls);
    reset();wait_value=0;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_OBJECT_0&&wait_calls==1&&got_timeout==0);
    VERIFY(got_count==2&&got_handles[0]==handles[0]&&got_handles[1]==(HANDLE)(uintptr_t)0x999);
    reset();VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_TIMEOUT&&wait_calls==1&&got_timeout==0);
    reset();queue_pending=1;wait_value=0;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_OBJECT_0&&wait_calls==1&&got_count==1&&got_timeout==0);
    reset();queue_pending=1;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_OBJECT_0+1&&wait_calls==1&&got_count==1);
    reset();queue_pending=1;wait_value=WAIT_IO_COMPLETION;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,MWMO_ALERTABLE)==WAIT_IO_COMPLETION&&got_alert);
    reset();queue_pending=1;wait_value=WAIT_FAILED;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_FAILED&&wait_calls==1);
    reset();queue_pending=1;
    VERIFY(MsgWaitForMultipleObjectsEx(0,NULL,0,0,0)==WAIT_OBJECT_0&&!wait_calls);
    reset();wait_value=1;
    VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,0)==WAIT_TIMEOUT&&wait_calls==1&&status_calls==2&&!sleep_calls);
    reset();VERIFY(MsgWaitForMultipleObjectsEx(1,handles,0,0,MWMO_WAITALL)==WAIT_TIMEOUT&&!wait_calls);
    reset();wait_value=62;
    VERIFY(MsgWaitForMultipleObjectsEx(63,handles,0,0,0)==62&&got_count==64&&got_handles[62]==handles[62]);
    VERIFY(got_handles[63]==(HANDLE)(uintptr_t)0x999);
    printf("MSG-WAIT-HOST: %u checks PASS; exact body zero-time polls/order/bounds/APC/failure; no native wait proof\n",checks);
    return 0;
}
