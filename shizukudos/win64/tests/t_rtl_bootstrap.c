/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine NT DLL/provider fixture: owned heap strings, raw export ordinals,
 * real performance syscall and eight actual threads. No browser proxy/mock. */
#include "k32test.h"
#include <winternl.h>
#define ST_SUCCESS ((NTSTATUS)0)
#define ST_INVALID ((NTSTATUS)0xc000000d)
#define ST_OVERFLOW ((NTSTATUS)0x80000005)
#define ST_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
__declspec(dllimport) NTSTATUS NTAPI RtlDuplicateUnicodeString(ULONG,const UNICODE_STRING *,UNICODE_STRING *);
__declspec(dllimport) LONG NTAPI RtlCompareUnicodeString(const UNICODE_STRING *,const UNICODE_STRING *,BOOLEAN);
__declspec(dllimport) BOOLEAN NTAPI RtlEqualUnicodeString(const UNICODE_STRING *,const UNICODE_STRING *,BOOLEAN);
__declspec(dllimport) BOOL NTAPI RtlQueryPerformanceCounter(PLARGE_INTEGER);
__declspec(dllimport) NTSTATUS NTAPI NtQueryPerformanceCounter(PLARGE_INTEGER,PLARGE_INTEGER);
__declspec(dllimport) VOID NTAPI RtlRunOnceInitialize(PRTL_RUN_ONCE);
__declspec(dllimport) NTSTATUS NTAPI RtlRunOnceExecuteOnce(PRTL_RUN_ONCE,PRTL_RUN_ONCE_INIT_FN,PVOID,PVOID *);

struct payload {LONG value,checksum;};
struct group {RTL_RUN_ONCE once;HANDLE start,release;volatile LONG entered,callbacks;struct payload payload;};
struct worker_context {struct group *group;PVOID result;NTSTATUS status;LONG value,checksum;};
static DWORD WINAPI initialize(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context)
{
    struct group *g=parameter;
    if(once!=&g->once)return FALSE;
    InterlockedIncrement(&g->callbacks);
    if(WaitForSingleObject(g->release,30000)!=WAIT_OBJECT_0)return FALSE;
    g->payload.value=0x1234;g->payload.checksum=0x1234^0x7fed;
    if(context)*context=&g->payload;
    return TRUE;
}
static DWORD WINAPI worker(void *argument)
{
    struct worker_context *context=argument;struct group *g=context->group;
    if(WaitForSingleObject(g->start,30000)!=WAIT_OBJECT_0)return 3;
    InterlockedIncrement(&g->entered);
    context->status=RtlRunOnceExecuteOnce(&g->once,initialize,g,&context->result);
    if(context->status==ST_SUCCESS) {
        struct payload *p=context->result;
        if(!p)return 4;
        context->value=p->value;context->checksum=p->checksum;
    }
    return context->status==ST_SUCCESS?0:5;
}
static DWORD WINAPI retry(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context)
{
    struct group *g=parameter;(void)once;
    if(InterlockedIncrement(&g->callbacks)==1)return FALSE;
    if(context)*context=&g->payload;
    return TRUE;
}
static DWORD WINAPI null_context(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context)
{
    (void)once;(void)parameter;return context==NULL;
}
int main(void)
{
    static const struct {const char *name;WORD ordinal;} names[]={
        {"RtlAnsiStringToUnicodeString",495},{"RtlCompareMemory",496},{"RtlCompareUnicodeString",497},
        {"RtlDuplicateUnicodeString",498},{"RtlEqualUnicodeString",499},{"RtlQueryPerformanceCounter",500},
        {"RtlRunOnceExecuteOnce",501},{"RtlRunOnceInitialize",502}};
    HMODULE module=GetModuleHandleW(L"ntdll.dll");BOOL bindings=module!=NULL;
    for(unsigned i=0;i<sizeof names/sizeof names[0];++i) {
        FARPROC p=module?GetProcAddress(module,names[i].name):NULL;
        bindings &= p && p==GetProcAddress(module,(LPCSTR)(ULONG_PTR)names[i].ordinal);
    }
    CHECK(bindings,"all eight new named exports match fresh pinned ordinals495..502");
    CHECK(module && GetProcAddress(module,(LPCSTR)(ULONG_PTR)127)==GetProcAddress(module,"NtShzBlkControl"),"old actual ordinal127 remains NtShzBlkControl");
    CHECK(module && GetProcAddress(module,"NtQueryPerformanceCounter")==GetProcAddress(module,"ZwQueryPerformanceCounter"),"old Nt/Zw same-address alias remains intact");
    unsigned char memory[]={1,2,0x80,4},different[]={1,2,0x81,4};
    CHECK(RtlCompareMemory(memory,different,sizeof memory)==2 && RtlCompareMemory(memory,memory,sizeof memory)==4,"memory comparison returns matching prefix count");
    CHECK(RtlCompareMemory(NULL,NULL,0)==0,"zero memory length does not dereference NULL");
    WCHAR lower[]={0xe9,0x3c9,0x44f,0,'z'},upper[]={0xc9,0x3a9,0x42f,0,'Z'};
    UNICODE_STRING a={sizeof lower,sizeof lower,lower},b={sizeof upper,sizeof upper,upper},out={0};
    CHECK(RtlEqualUnicodeString(&a,&b,TRUE) && RtlCompareUnicodeString(&a,&b,TRUE)==0,"case-insensitive ordinal comparison covers accented Latin Greek and Cyrillic code units");
    CHECK(!RtlEqualUnicodeString(&a,&b,FALSE) && RtlCompareUnicodeString(&a,&b,FALSE)==32,"case-sensitive comparison uses exact UTF16 unit difference");
    b.Length-=2;
    CHECK(!RtlEqualUnicodeString(&a,&b,TRUE) && RtlCompareUnicodeString(&a,&b,TRUE)==1,"embedded NUL does not truncate descriptor comparison and length difference counts code units");
    CHECK(RtlDuplicateUnicodeString(1,&a,&out)==ST_SUCCESS && out.Length==sizeof lower && out.MaximumLength==sizeof lower+2 && out.Buffer && !out.Buffer[5] && out.Buffer!=lower,"duplicate allocates actual process heap and appends requested terminator");
    if(out.Buffer) {
        CHECK(out.Buffer[0]==0xe9 && out.Buffer[4]=='z',"duplicate preserves full descriptor contents after embedded NUL");
        RtlFreeUnicodeString(&out);
        CHECK(!out.Buffer && !out.Length && !out.MaximumLength,"existing genuine Unicode free releases heap and clears descriptor");
    }
    UNICODE_STRING alias=a;
    CHECK(RtlDuplicateUnicodeString(1,&alias,&alias)==ST_SUCCESS && alias.Buffer!=lower && alias.Buffer[0]==0xe9,"self-alias descriptor snapshots genuine source before publishing allocation");
    if(alias.Buffer && alias.Buffer!=lower)RtlFreeUnicodeString(&alias);
    UNICODE_STRING empty={0};
    CHECK(RtlDuplicateUnicodeString(3,&empty,&out)==ST_SUCCESS && !out.Length && out.MaximumLength==2 && out.Buffer && !out.Buffer[0],"empty allocate-NUL option owns a real two-byte heap buffer");
    if(out.Buffer)RtlFreeUnicodeString(&out);
    out=a;
    CHECK(RtlDuplicateUnicodeString(2,&a,&out)==ST_INVALID && out.Buffer==a.Buffer,"unsupported duplicate flag leaves caller descriptor unchanged");
    UNICODE_STRING boundary={65534,65534,lower};
    CHECK(RtlDuplicateUnicodeString(1,&boundary,&out)==ST_INVALID && out.Buffer==lower,"terminator overflow is rejected before reading source or wrapping USHORT");
    char utf8[]={'A',(char)0xed,(char)0x95,(char)0x9c,(char)0xf0,(char)0x9f,(char)0x98,(char)0x80,0,'Z'};
    WCHAR expected[]={'A',0xd55c,0xd83d,0xde00,0,'Z',0},buffer[12];
    ANSI_STRING input={sizeof utf8,sizeof utf8,utf8};out=(UNICODE_STRING){0};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,TRUE)==ST_SUCCESS && out.Length==12 && out.MaximumLength==14 && out.Buffer && !out.Buffer[6],"actual fixed UTF8 ACP converts Korean supplementary pair and embedded NUL with real heap allocation");
    if(out.Buffer) {BOOL exact=TRUE;for(unsigned i=0;i<7;++i)exact &= out.Buffer[i]==expected[i];CHECK(exact,"UTF8 conversion agrees with independently specified UTF16 units");RtlFreeUnicodeString(&out);}
    buffer[0]=0x5678;out=(UNICODE_STRING){0,2,buffer};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==ST_OVERFLOW && out.Length==12 && buffer[0]==0x5678,"small caller buffer reports overflow with documented required descriptor length");
    out=(UNICODE_STRING){0,sizeof buffer,buffer};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==ST_SUCCESS && !buffer[6],"caller-owned Unicode conversion uses actual bounded buffer");
    LARGE_INTEGER before,now,after,frequency;
    CHECK(NtQueryPerformanceCounter(&before,&frequency)==ST_SUCCESS && frequency.QuadPart>0,"real kernel performance counter supplies genuine positive frequency");
    BOOL measured=RtlQueryPerformanceCounter(&now);
    CHECK(NtQueryPerformanceCounter(&after,NULL)==ST_SUCCESS && measured && now.QuadPart>=before.QuadPart && now.QuadPart<=after.QuadPart,"RTL counter lies between independent actual NT clock samples");
    CHECK(!RtlQueryPerformanceCounter(NULL),"invalid counter destination preserves real NT failure instead of unconditional success");
    struct group g={0};struct worker_context contexts[8];HANDLE threads[8]={0};unsigned created=0;DWORD code;
    g.start=CreateEventW(NULL,TRUE,FALSE,NULL);g.release=CreateEventW(NULL,TRUE,FALSE,NULL);
    CHECK(g.start && g.release,"actual shared start and initializer release events are created");
    if(!g.start || !g.release) {if(g.start)CloseHandle(g.start);if(g.release)CloseHandle(g.release);return k32t_finish("RTL_BOOTSTRAP");}
    RtlRunOnceInitialize(&g.once);
    for(unsigned i=0;i<8;++i) {
        contexts[i]=(struct worker_context){.group=&g};threads[i]=CreateThread(NULL,0,worker,&contexts[i],0,NULL);
        CHECK(threads[i]!=NULL,"real contender thread is created");if(!threads[i])break;++created;
    }
    CHECK(SetEvent(g.start),"start gate releases actual contender threads");
    DWORD start=GetTickCount();
    while((unsigned)InterlockedCompareExchange(&g.entered,0,0)<created && GetTickCount()-start<10000)Sleep(1);
    CHECK((unsigned)InterlockedCompareExchange(&g.entered,0,0)==created,"every created contender entered the genuine once call");
    CHECK(SetEvent(g.release),"initializer completion gate releases actual callback");
    for(unsigned i=0;i<created;++i) {
        DWORD waited=WaitForSingleObject(threads[i],30000);
        if(waited!=WAIT_OBJECT_0){CHECK(FALSE,"live worker join failed; end whole process before borrowed stack/event cleanup");ExitProcess(2);}
        CHECK(GetExitCodeThread(threads[i],&code) && code==0 && contexts[i].status==ST_SUCCESS && contexts[i].result==&g.payload && contexts[i].value==0x1234 && contexts[i].checksum==(0x1234^0x7fed),"each joined real thread sees exactly published initializer context and data");
        CHECK(CloseHandle(threads[i]),"joined worker handle closes after borrowed context lifetime is proved");
    }
    CHECK(created==8 && g.callbacks==1,"eight actual contender threads run successful callback exactly once");
    CHECK(CloseHandle(g.start),"start event cleanup follows all actual worker joins");
    CHECK(CloseHandle(g.release),"initializer release event cleanup follows all actual worker joins");
    PVOID context=NULL;
    CHECK(RtlRunOnceExecuteOnce(&g.once,NULL,NULL,&context)==ST_SUCCESS && context==&g.payload,"completed once returns saved context without invoking NULL callback");
    RtlRunOnceInitialize(&g.once);g.callbacks=0;
    CHECK(RtlRunOnceExecuteOnce(&g.once,retry,&g,&context)==ST_UNSUCCESSFUL && !g.once.Ptr,"failed genuine callback returns failure and resets initialization state");
    CHECK(RtlRunOnceExecuteOnce(&g.once,retry,&g,&context)==ST_SUCCESS && g.callbacks==2 && context==&g.payload,"second genuine callback attempt succeeds and publishes its context");
    RtlRunOnceInitialize(&g.once);
    CHECK(RtlRunOnceExecuteOnce(&g.once,null_context,NULL,NULL)==ST_SUCCESS && (ULONG_PTR)g.once.Ptr==2,"NULL output pointer reaches genuine callback unchanged and completes with NULL context");
    return k32t_finish("RTL_BOOTSTRAP");
}
