/* SPDX-License-Identifier: GPL-2.0-only
 * Python Unicode/UTF-8 expectations, independent prefix/descriptor oracles,
 * real pthread contention and bounded explicit kernel-provider adapters. */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sched.h>
#include "rtl_bootstrap_host_contract.h"
#include "rtl_bootstrap_vectors.inc"

static unsigned checks;
#define CHECK(x) do{__atomic_add_fetch(&checks,1,__ATOMIC_RELAXED);if(!(x)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#x);exit(2);}}while(0)
static pthread_mutex_t heap_lock=PTHREAD_MUTEX_INITIALIZER;
static unsigned heap_live,heap_calls,heap_fail;
struct allocation {uint64_t magic;SIZE_T size;};
PVOID ShzProcessHeap(void){return (PVOID)(uintptr_t)0x1234;}
PVOID RtlAllocateHeap(PVOID heap,ULONG flags,SIZE_T size)
{
    struct allocation *p;
    pthread_mutex_lock(&heap_lock);CHECK(heap==ShzProcessHeap() && !flags);++heap_calls;
    if(heap_fail && heap_fail==heap_calls){pthread_mutex_unlock(&heap_lock);return NULL;}
    p=malloc(sizeof *p+size+8);CHECK(p!=NULL);p->magic=UINT64_C(0x123456789abcdef0);p->size=size;
    memset(p+1,0xa5,size);memset((unsigned char *)(p+1)+size,0x5a,8);++heap_live;
    pthread_mutex_unlock(&heap_lock);return p+1;
}
BOOLEAN RtlFreeHeap(PVOID heap,ULONG flags,PVOID memory)
{
    struct allocation *p=(struct allocation *)memory-1;
    pthread_mutex_lock(&heap_lock);CHECK(heap==ShzProcessHeap() && !flags && heap_live && p->magic==UINT64_C(0x123456789abcdef0));
    for(unsigned i=0;i<8;++i)CHECK(*((unsigned char *)(p+1)+p->size+i)==0x5a);
    --heap_live;p->magic=0;free(p);pthread_mutex_unlock(&heap_lock);return TRUE;
}
static int performance_fail;
NTSTATUS NtQueryPerformanceCounter(PLARGE_INTEGER out,PLARGE_INTEGER frequency)
{
    struct timespec t;
    if(performance_fail || !out)return STATUS_ACCESS_DENIED;
    if(clock_gettime(CLOCK_MONOTONIC,&t))return STATUS_UNSUCCESSFUL;
    out->QuadPart=(int64_t)t.tv_sec*1000000000+t.tv_nsec;
    if(frequency)frequency->QuadPart=1000000000;
    return STATUS_SUCCESS;
}
NTSTATUS NtYieldExecution(void){sched_yield();return STATUS_SUCCESS;}
struct wait_node {struct wait_node *next;const void *key;int woken;pthread_cond_t condition;};
static pthread_mutex_t wait_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wait_change=PTHREAD_COND_INITIALIZER;
static struct wait_node *waiting;
static unsigned parked,peak_parked,wake_calls,wake_max;
static _Thread_local int wait_fail;
NTSTATUS RtlWaitOnAddress(volatile VOID *address,PVOID expected,SIZE_T size,PLARGE_INTEGER timeout)
{
    struct wait_node n;
    if(wait_fail)return STATUS_ACCESS_DENIED;
    CHECK(size==8 && !timeout);
    pthread_mutex_lock(&wait_lock);
    if((ULONG_PTR)__atomic_load_n((PVOID *)address,__ATOMIC_ACQUIRE)!=*(ULONG_PTR *)expected){pthread_mutex_unlock(&wait_lock);return STATUS_SUCCESS;}
    n.next=waiting;n.key=(const void *)address;n.woken=0;pthread_cond_init(&n.condition,NULL);waiting=&n;
    ++parked;if(parked>peak_parked)peak_parked=parked;pthread_cond_broadcast(&wait_change);
    while(!n.woken)pthread_cond_wait(&n.condition,&wait_lock);
    --parked;pthread_cond_destroy(&n.condition);pthread_mutex_unlock(&wait_lock);return STATUS_SUCCESS;
}
VOID RtlWakeAddressAll(PVOID key)
{
    struct wait_node **link;
    unsigned count=0;
    pthread_mutex_lock(&wait_lock);++wake_calls;
    for(link=&waiting;*link && count<64;) {
        struct wait_node *n=*link;
        if(n->key==key){*link=n->next;n->woken=1;++count;pthread_cond_signal(&n->condition);}else link=&n->next;
    }
    if(count>wake_max)wake_max=count;
    pthread_mutex_unlock(&wait_lock);
}
static void memory_and_strings(void)
{
    unsigned char a[130],b[130];WCHAR x[4],y[4];
    for(unsigned i=0;i<130;++i)a[i]=(unsigned char)(i*17);
    memcpy(b,a,sizeof a);CHECK(RtlCompareMemory(NULL,NULL,0)==0);
    for(unsigned i=0;i<130;++i){b[i]^=1;CHECK(RtlCompareMemory(a,b,130)==i);b[i]^=1;}
    CHECK(RtlCompareMemory(a,b,130)==130);
    for(unsigned cp=0;cp<65536;++cp) {
        x[0]=(WCHAR)cp;y[0]=uppercase_expected[cp];
        SHZ_UNICODE_STRING l={2,2,x},r={2,2,y};
        CHECK(RtlCompareUnicodeString(&l,&r,TRUE)==0);CHECK(RtlEqualUnicodeString(&l,&r,TRUE));
        CHECK(RtlCompareUnicodeString(&l,&r,FALSE)==(LONG)x[0]-(LONG)y[0]);
    }
    x[0]='A';x[1]=0;x[2]='z';y[0]='a';y[1]=0;y[2]='Y';
    SHZ_UNICODE_STRING l={6,8,x},r={6,8,y},empty={0,0,NULL};
    CHECK(RtlCompareUnicodeString(&l,&r,TRUE)==1 && !RtlEqualUnicodeString(&l,&r,TRUE));
    r.Length=4;CHECK(RtlCompareUnicodeString(&l,&r,TRUE)==1 && !RtlEqualUnicodeString(&l,&r,TRUE));
    CHECK(RtlCompareUnicodeString(&empty,&empty,FALSE)==0 && RtlEqualUnicodeString(&empty,&empty,TRUE));
}
static void ansi_and_duplicate(void)
{
    WCHAR destination[200],*big=malloc(65534);char *large=malloc(65535);
    SHZ_UNICODE_STRING out={0,0,NULL};
    CHECK(big && large);
    for(unsigned i=0;i<utf8_vector_count;++i) {
        const struct utf8_vector *v=&utf8_vectors[i];
        SHZ_BOOTSTRAP_ANSI_STRING input={(USHORT)v->bytes,(USHORT)v->bytes,(char *)utf8_bytes+v->byte_offset};
        CHECK(RtlAnsiStringToUnicodeString(&out,&input,TRUE)==STATUS_SUCCESS);
        CHECK(out.Length==v->units*2 && out.MaximumLength==v->units*2+2 && !out.Buffer[v->units]);
        for(unsigned j=0;j<v->units;++j)CHECK(out.Buffer[j]==utf16_words[v->word_offset+j]);
        RtlFreeHeap(ShzProcessHeap(),0,out.Buffer);
        out=(SHZ_UNICODE_STRING){0,sizeof destination,destination};
        CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_SUCCESS);
        CHECK(out.Length==v->units*2 && !destination[v->units]);
        for(unsigned j=0;j<v->units;++j)CHECK(destination[j]==utf16_words[v->word_offset+j]);
    }
    char sample[]={'x',(char)0xf0,(char)0x9f,(char)0x98,(char)0x80,0,'z'};
    SHZ_BOOTSTRAP_ANSI_STRING input={sizeof sample,sizeof sample,sample};
    destination[0]=0x4567;out=(SHZ_UNICODE_STRING){2,2,destination};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_BUFFER_OVERFLOW && out.Length==10 && destination[0]==0x4567);
    heap_fail=heap_calls+1;CHECK(RtlAnsiStringToUnicodeString(&out,&input,TRUE)==STATUS_NO_MEMORY && out.Length==10 && out.MaximumLength==12 && !out.Buffer);heap_fail=0;
    memset(large,'a',65535);input=(SHZ_BOOTSTRAP_ANSI_STRING){65535,65535,large};out=(SHZ_UNICODE_STRING){8,40,destination};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,TRUE)==STATUS_INVALID_PARAMETER_2 && out.Length==8 && out.Buffer==destination);
    input=(SHZ_BOOTSTRAP_ANSI_STRING){1,0,sample};CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_INVALID_PARAMETER_2);
    input=(SHZ_BOOTSTRAP_ANSI_STRING){1,1,NULL};CHECK(RtlAnsiStringToUnicodeString(&out,&input,TRUE)==STATUS_INVALID_PARAMETER_2);
    input=(SHZ_BOOTSTRAP_ANSI_STRING){0,0,NULL};out=(SHZ_UNICODE_STRING){0,sizeof destination,destination};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_SUCCESS && !out.Length && !destination[0]);
    union {WCHAR w[16];char b[32];} overlap;
    memcpy(overlap.b,"abcdef",6);input=(SHZ_BOOTSTRAP_ANSI_STRING){6,6,overlap.b};out=(SHZ_UNICODE_STRING){0,sizeof overlap,overlap.w};
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_SUCCESS && !out.Buffer[6]);
    for(unsigned i=0;i<6;++i)CHECK(out.Buffer[i]==(WCHAR)('a'+i));
    memcpy(overlap.b,"abcdef",6);heap_fail=heap_calls+1;
    CHECK(RtlAnsiStringToUnicodeString(&out,&input,FALSE)==STATUS_NO_MEMORY && !memcmp(overlap.b,"abcdef",6));heap_fail=0;
    for(unsigned flags=0;flags<4;++flags) {
        SHZ_UNICODE_STRING source={6,8,destination};destination[0]='q';destination[1]=0;destination[2]=0x20ac;
        out=(SHZ_UNICODE_STRING){8,12,destination};NTSTATUS status=RtlDuplicateUnicodeString(flags,&source,&out);
        if(flags==2){CHECK(status==STATUS_INVALID_PARAMETER && out.Buffer==destination);continue;}
        CHECK(status==STATUS_SUCCESS && out.Length==6 && out.MaximumLength==(flags?8:6));
        CHECK(out.Buffer[0]=='q' && out.Buffer[1]==0 && out.Buffer[2]==0x20ac && (!flags || !out.Buffer[3]));
        RtlFreeHeap(ShzProcessHeap(),0,out.Buffer);
    }
    SHZ_UNICODE_STRING empty={0,0,NULL};
    CHECK(RtlDuplicateUnicodeString(1,&empty,&out)==STATUS_SUCCESS && !out.Buffer && !out.Length && !out.MaximumLength);
    CHECK(RtlDuplicateUnicodeString(3,&empty,&out)==STATUS_SUCCESS && !out.Length && out.MaximumLength==2 && !out.Buffer[0]);RtlFreeHeap(ShzProcessHeap(),0,out.Buffer);
    SHZ_UNICODE_STRING alias={4,4,destination};destination[0]='u';destination[1]='v';
    CHECK(RtlDuplicateUnicodeString(1,&alias,&alias)==STATUS_SUCCESS && alias.Buffer!=destination && alias.Buffer[0]=='u' && alias.Buffer[1]=='v' && !alias.Buffer[2]);RtlFreeHeap(ShzProcessHeap(),0,alias.Buffer);
    SHZ_UNICODE_STRING source={65534,65534,big};out=(SHZ_UNICODE_STRING){8,12,destination};
    CHECK(RtlDuplicateUnicodeString(1,&source,&out)==STATUS_INVALID_PARAMETER && out.Buffer==destination);
    source=(SHZ_UNICODE_STRING){3,4,destination};CHECK(RtlDuplicateUnicodeString(1,&source,&out)==STATUS_INVALID_PARAMETER);
    source=(SHZ_UNICODE_STRING){2,2,NULL};CHECK(RtlDuplicateUnicodeString(0,&source,&out)==STATUS_INVALID_PARAMETER);
    source=(SHZ_UNICODE_STRING){2,2,destination};heap_fail=heap_calls+1;
    CHECK(RtlDuplicateUnicodeString(1,&source,&out)==STATUS_NO_MEMORY && !out.Buffer && out.Length==8 && out.MaximumLength==12);heap_fail=0;
    free(big);free(large);CHECK(!heap_live);
}
struct once_payload {unsigned value,checksum;};
static struct once_payload payload;
struct once_group {RTL_RUN_ONCE once;pthread_barrier_t start;unsigned threads,callbacks,fail_first;};
struct once_result {struct once_group *group;NTSTATUS status;PVOID context;unsigned value,checksum;};
static DWORD initialize(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context)
{
    struct once_group *group=parameter;struct timespec deadline;
    CHECK(once==&group->once);
    unsigned attempt=__atomic_add_fetch(&group->callbacks,1,__ATOMIC_RELAXED);
    if(group->threads>1 && attempt==1) {
        clock_gettime(CLOCK_REALTIME,&deadline);deadline.tv_sec+=10;
        pthread_mutex_lock(&wait_lock);
        while(parked<group->threads-1) {
            int e=pthread_cond_timedwait(&wait_change,&wait_lock,&deadline);
            if(e){fprintf(stderr,"not all contenders parked: %u/%u\n",parked,group->threads-1);exit(2);}
        }
        pthread_mutex_unlock(&wait_lock);
    }
    if(group->fail_first && attempt==1)return FALSE;
    payload.value=0x1234;payload.checksum=payload.value^0x7fed;
    if(context)*context=&payload;
    return TRUE;
}
static void *once_worker(void *argument)
{
    struct once_result *r=argument;pthread_barrier_wait(&r->group->start);
    r->status=RtlRunOnceExecuteOnce(&r->group->once,initialize,r->group,&r->context);
    if(NT_SUCCESS(r->status)){struct once_payload *p=r->context;r->value=p->value;r->checksum=p->checksum;}
    return NULL;
}
static DWORD simple_initialize(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context){(void)once;if(context)*context=parameter;return TRUE;}
static DWORD recursive_initialize(PRTL_RUN_ONCE once,PVOID parameter,PVOID *context)
{
    RTL_RUN_ONCE other={0};PVOID result=NULL;(void)once;
    CHECK(RtlRunOnceExecuteOnce(&other,simple_initialize,parameter,&result)==STATUS_SUCCESS && result==parameter);
    if(context)*context=result;
    return TRUE;
}
static void once_contract(unsigned threads,unsigned fail_first)
{
    pthread_t workers[96];struct once_result results[96];struct once_group group={0};unsigned failed=0;
    group.threads=threads;group.fail_first=fail_first;pthread_barrier_init(&group.start,NULL,threads);RtlRunOnceInitialize(&group.once);
    for(unsigned i=0;i<threads;++i){results[i]=(struct once_result){.group=&group};CHECK(!pthread_create(&workers[i],NULL,once_worker,&results[i]));}
    for(unsigned i=0;i<threads;++i){CHECK(!pthread_join(workers[i],NULL));if(results[i].status==STATUS_UNSUCCESSFUL)++failed;else CHECK(results[i].status==STATUS_SUCCESS && results[i].context==&payload && results[i].value==0x1234 && results[i].checksum==(0x1234^0x7fed));}
    CHECK(group.callbacks==(fail_first?2:1) && failed==(fail_first?1:0));pthread_barrier_destroy(&group.start);CHECK(!waiting && !parked);
    PVOID result=NULL;CHECK(RtlRunOnceExecuteOnce(&group.once,NULL,NULL,&result)==STATUS_SUCCESS && result==&payload);
}
int main(void)
{
    memory_and_strings();ansi_and_duplicate();
    LARGE_INTEGER first,last,saved;CHECK(RtlQueryPerformanceCounter(&first));for(unsigned i=0;i<1000;++i){CHECK(RtlQueryPerformanceCounter(&last) && last.QuadPart>=first.QuadPart);first=last;}
    saved.QuadPart=0x11223344;performance_fail=1;CHECK(!RtlQueryPerformanceCounter(&saved) && saved.QuadPart==0x11223344);performance_fail=0;CHECK(!RtlQueryPerformanceCounter(NULL));
    once_contract(96,0);CHECK(peak_parked>=95 && wake_max==64 && wake_calls>=2);once_contract(32,1);
    RTL_RUN_ONCE once={0};PVOID result=NULL;
    CHECK(RtlRunOnceExecuteOnce(&once,recursive_initialize,&payload,&result)==STATUS_SUCCESS && result==&payload);
    RtlRunOnceInitialize(&once);CHECK(RtlRunOnceExecuteOnce(&once,simple_initialize,NULL,NULL)==STATUS_SUCCESS && (ULONG_PTR)once.Ptr==2);
    RtlRunOnceInitialize(&once);CHECK(RtlRunOnceExecuteOnce(&once,NULL,NULL,NULL)==STATUS_INVALID_PARAMETER && !once.Ptr);
    CHECK(RtlRunOnceExecuteOnce(&once,simple_initialize,(void *)(uintptr_t)3,&result)==STATUS_INVALID_PARAMETER && (ULONG_PTR)once.Ptr==1);RtlRunOnceInitialize(&once);
    once.Ptr=(PVOID)(uintptr_t)3;CHECK(RtlRunOnceExecuteOnce(&once,simple_initialize,NULL,NULL)==STATUS_INVALID_PARAMETER);
    once.Ptr=(PVOID)(uintptr_t)1;wait_fail=1;CHECK(RtlRunOnceExecuteOnce(&once,simple_initialize,NULL,NULL)==STATUS_ACCESS_DENIED && (ULONG_PTR)once.Ptr==1);wait_fail=0;RtlRunOnceInitialize(&once);
    CHECK(!heap_live && !waiting && !parked);
    printf("PASS %u checks; Unicode case and Python UTF-8 oracles, descriptor bounds/alias/heap errors, real 96-way pthread contention and callback retry, genuine host monotonic clock\n",checks);return 0;
}
