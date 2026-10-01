/* SPDX-License-Identifier: GPL-2.0-only
 * More than the old system-wide96 scheduler slots: real suspended creation,
 * unique native IDs, concurrent gated workers, genuine exits and slot reuse. */
#include "k32test.h"
#define WORKERS 160
struct context { HANDLE gate; volatile LONG ready; };
struct item { struct context *context; DWORD tid; volatile LONG entered; };
static DWORD WINAPI worker(void *opaque)
{
    struct item *item=opaque;
    item->tid=GetCurrentThreadId();
    InterlockedExchange(&item->entered,1);
    InterlockedIncrement(&item->context->ready);
    return WaitForSingleObject(item->context->gate,30000)==WAIT_OBJECT_0 ? 0 : 11;
}
static void cycle(void)
{
    struct context context={0};struct item items[WORKERS]={0};HANDLE handles[WORKERS]={0};
    DWORD ids[WORKERS]={0},created=0,i,j,code,start;BOOL unique=TRUE,resumed=TRUE,joined=TRUE,closed=TRUE;
    context.gate=CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(context.gate!=NULL,"real manual gate creates");if(!context.gate)return;
    for(i=0;i<WORKERS;++i){
        items[i].context=&context;
        handles[i]=CreateThread(NULL,65536,worker,&items[i],CREATE_SUSPENDED,&ids[i]);
        if(!handles[i])break;
        ++created;
    }
    CHECK(created==WORKERS,"160 actual simultaneous suspended threads exceed old96 global slots");
    CHECK(context.ready==0,"suspended workers have not executed before native resume");
    for(i=0;i<created;++i){
        if(!ids[i]||ids[i]==GetCurrentThreadId())unique=FALSE;
        for(j=0;j<i;++j)if(ids[i]==ids[j])unique=FALSE;
        if(ResumeThread(handles[i])!=1){
            resumed=FALSE;
            if(!TerminateThread(handles[i],12)||WaitForSingleObject(handles[i],10000)!=WAIT_OBJECT_0)ExitProcess(2);
        }
    }
    CHECK(unique,"all actual native worker thread IDs are nonzero and unique");
    CHECK(resumed,"every native suspended thread resumes from count1");
    start=GetTickCount();
    while(resumed&&(DWORD)context.ready<created&&GetTickCount()-start<20000)Sleep(1);
    CHECK((DWORD)context.ready==created,"all created workers genuinely run and publish before gate release");
    if((DWORD)context.ready!=created)unique=FALSE;
    else for(i=0;i<created;++i)if(items[i].entered!=1||items[i].tid!=ids[i])unique=FALSE;
    CHECK(unique,"executing TEB IDs match their own distinct creation IDs");
    CHECK(SetEvent(context.gate),"one actual manual event releases the waiting workers");
    for(i=0;i<created;++i){
        if(WaitForSingleObject(handles[i],10000)!=WAIT_OBJECT_0){
            joined=FALSE;
            /* Never return this cycle stack while a failed worker can still
             * read its context. Failed forced termination ends the process. */
            if(!TerminateThread(handles[i],12)||WaitForSingleObject(handles[i],10000)!=WAIT_OBJECT_0)ExitProcess(2);
        }
        code=MAXDWORD;if(!GetExitCodeThread(handles[i],&code)||code!=0)joined=FALSE;
        if(!CloseHandle(handles[i]))closed=FALSE;
    }
    CHECK(joined,"every real worker exits0 and signals its actual thread object");
    CHECK(closed,"every actual worker handle closes");
    CHECK(CloseHandle(context.gate),"actual gate handle closes after worker exit");
}
int main(int argc,char **argv)
{
    (void)argc;(void)argv;cycle();cycle();
    return k32t_finish("T_THREAD_CAPACITY");
}
