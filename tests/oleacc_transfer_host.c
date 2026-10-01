/* SPDX-License-Identifier: GPL-2.0-only
 * Host adapters execute the actual patched Wine OLEACC transfer bodies. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdatomic.h>
#include <string.h>
#define WINAPI
typedef int32_t HRESULT, BOOL;
typedef uint32_t DWORD, ULONG;
typedef uint64_t ULONGLONG, WPARAM;
typedef int64_t LRESULT;
typedef void *HMODULE;
typedef const uint16_t *LPCWSTR;
typedef struct {uint32_t id;} IID;
typedef const IID *REFIID;
typedef pthread_mutex_t SRWLOCK;
#define SRWLOCK_INIT PTHREAD_MUTEX_INITIALIZER
#define TRUE 1
#define FALSE 0
#define S_OK ((HRESULT)0)
#define E_FAIL ((HRESULT)0x80004005u)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define E_OUTOFMEMORY ((HRESULT)0x8007000eu)
#define E_NOINTERFACE ((HRESULT)0x80004002u)
#define E_NOTIMPL ((HRESULT)0x80004001u)
#define E_UNEXPECTED ((HRESULT)0x8000ffffu)
#define SUCCEEDED(hr) ((HRESULT)(hr)>=0)
#define FAILED(hr) ((HRESULT)(hr)<0)
#define GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS 4u
#define GET_MODULE_HANDLE_EX_FLAG_PIN 1u
static atomic_uint checks, allocations;
#define CHECK(x) do {atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);}}while(0)
typedef struct IUnknown {atomic_int refs;} IUnknown;
typedef IUnknown *LPUNKNOWN;
static const IID good={1}, second={2}, wrong={3};
static IUnknown object={ATOMIC_VAR_INIT(1)};
static int heap_failure, pin_failure, invalid_qi, reenter;
static DWORD pid_value=0x12345678u;
static LRESULT reentrant_token;
static void *GetProcessHeap(void){return (void *)1;}
static DWORD GetCurrentProcessId(void){return pid_value;}
static BOOL GetModuleHandleExW(DWORD flags,LPCWSTR address,HMODULE *out){
    CHECK(flags==5 && address && out);
    if(pin_failure)return FALSE;
    *out=(void *)2;return TRUE;
}
static void *HeapAlloc(void *heap,DWORD flags,size_t n){
    CHECK(heap==(void *)1 && flags==0 && n>0);
    if(heap_failure)return NULL;
    void *p=malloc(n);if(p)atomic_fetch_add(&allocations,1);return p;
}
static BOOL HeapFree(void *heap,DWORD flags,void *p){
    CHECK(heap==(void *)1 && flags==0 && p);
    free(p);CHECK(atomic_fetch_sub(&allocations,1)>0);return TRUE;
}
static void AcquireSRWLockExclusive(SRWLOCK *p){CHECK(!pthread_mutex_lock(p));}
static void ReleaseSRWLockExclusive(SRWLOCK *p){CHECK(!pthread_mutex_unlock(p));}
static ULONG IUnknown_Release(IUnknown *p){int old=atomic_fetch_sub(&p->refs,1);CHECK(old>1);return (ULONG)(old-1);}
HRESULT WINAPI ObjectFromLresult(LRESULT,REFIID,WPARAM,void **);
static HRESULT IUnknown_QueryInterface(IUnknown *p,REFIID iid,void **out){
    CHECK(p==&object && iid && out);*out=NULL;
    if(reenter){
        void *nested=NULL;reenter=0;
        CHECK(ObjectFromLresult(reentrant_token,&good,0,&nested)==E_INVALIDARG && !nested);
        /* The callback can acquire the production lock without deadlocking. */
    }
    if(iid->id!=1 && iid->id!=2)return E_NOINTERFACE;
    if(invalid_qi)return S_OK;
    atomic_fetch_add(&p->refs,1);*out=p;return S_OK;
}

/* ACTUAL_PATCHED_WINE_TRANSFER_BODIES */

static void consume(LRESULT token){
    void *out=NULL;
    CHECK(ObjectFromLresult(token,&good,0,&out)==S_OK && out==&object);
    IUnknown_Release(out);
    out=(void *)3;
    CHECK(ObjectFromLresult(token,&good,0,&out)==E_INVALIDARG && !out);
}
static void *worker(void *unused){
    (void)unused;
    for(unsigned i=0;i<300;++i){
        LRESULT token=LresultFromObject(&good,0,&object);void *out=NULL;
        CHECK(token>0);
        CHECK(ObjectFromLresult(token,&wrong,0,&out)==E_NOINTERFACE && !out);
        consume(token);
    }
    return NULL;
}
int main(void){
    void *out=(void *)3;
    CHECK((HRESULT)LresultFromObject(NULL,0,&object)==E_INVALIDARG);
    CHECK((HRESULT)LresultFromObject(&good,0,NULL)==E_INVALIDARG);
    CHECK(ObjectFromLresult(0,&good,0,NULL)==E_INVALIDARG);
    CHECK(ObjectFromLresult(0,NULL,0,&out)==E_INVALIDARG && !out);
    CHECK(ObjectFromLresult(0,&good,0,&out)==E_INVALIDARG && !out);
    CHECK(ObjectFromLresult((LRESULT)E_FAIL,&good,0,&out)==E_FAIL && !out);
    CHECK((HRESULT)LresultFromObject(&wrong,0,&object)==E_NOINTERFACE);
    CHECK(atomic_load(&object.refs)==1 && !atomic_load(&allocations));
    const DWORD pids[]={0,127,128,255,0x80000000u,0xffffffffu};
    for(unsigned i=0;i<sizeof pids/sizeof *pids;++i){
        pid_value=pids[i];LRESULT boundary=LresultFromObject(&good,0,&object);
        CHECK(boundary>0 && SUCCEEDED((HRESULT)boundary));
        CHECK(ObjectFromLresult(boundary^((LRESULT)1<<24),&good,0,&out)==E_NOTIMPL && !out);
        consume(boundary);
    }
    pid_value=0x12345678u;
    pin_failure=1;CHECK((HRESULT)LresultFromObject(&good,0,&object)==E_FAIL);pin_failure=0;
    heap_failure=1;CHECK((HRESULT)LresultFromObject(&good,0,&object)==E_OUTOFMEMORY);heap_failure=0;
    invalid_qi=1;CHECK((HRESULT)LresultFromObject(&good,0,&object)==E_UNEXPECTED);invalid_qi=0;
    CHECK(atomic_load(&object.refs)==1 && !atomic_load(&allocations));
    LRESULT token=LresultFromObject(&good,(WPARAM)-1,&object);
    CHECK(token>0 && atomic_load(&object.refs)==2);
    CHECK(ObjectFromLresult(token^((LRESULT)1<<24),&good,0,&out)==E_NOTIMPL && !out);
    CHECK(ObjectFromLresult(token+10000,&good,0,&out)==E_INVALIDARG && !out);
    CHECK(ObjectFromLresult(token,&wrong,0,&out)==E_NOINTERFACE && !out && atomic_load(&object.refs)==2);
    reentrant_token=token;reenter=1;
    CHECK(ObjectFromLresult(token,&second,0,&out)==S_OK && out==&object && atomic_load(&object.refs)==2);
    IUnknown_Release(out);out=NULL;
    CHECK(ObjectFromLresult(token,&good,0,&out)==E_INVALIDARG && !out);
    token=LresultFromObject(&good,0,&object);
    invalid_qi=1;CHECK(ObjectFromLresult(token,&good,0,&out)==E_UNEXPECTED && !out);invalid_qi=0;
    consume(token);
    LRESULT tokens[256];
    for(unsigned i=0;i<256;++i){tokens[i]=LresultFromObject(&good,0,&object);CHECK(tokens[i]>0);if(i)CHECK(tokens[i]!=tokens[i-1]);}
    CHECK(atomic_load(&object.refs)==257 && atomic_load(&allocations)==256);
    CHECK((HRESULT)LresultFromObject(&good,0,&object)==E_OUTOFMEMORY);
    CHECK(atomic_load(&object.refs)==257 && atomic_load(&allocations)==256);
    ULONG previous=shz_lresult_sequence;shz_lresult_sequence=SHZ_LRESULT_SEQUENCE_MAX;
    consume(tokens[0]);CHECK((HRESULT)LresultFromObject(&good,0,&object)==E_OUTOFMEMORY);
    shz_lresult_sequence=previous;
    for(unsigned i=1;i<256;++i)consume(tokens[i]);
    CHECK(atomic_load(&object.refs)==1 && !atomic_load(&allocations) && !shz_lresult_list && !shz_lresult_count);
    pthread_t threads[8];
    for(unsigned i=0;i<8;++i)CHECK(!pthread_create(&threads[i],NULL,worker,NULL));
    for(unsigned i=0;i<8;++i)CHECK(!pthread_join(threads[i],NULL));
    CHECK(atomic_load(&object.refs)==1 && !atomic_load(&allocations) && !shz_lresult_list && !shz_lresult_count);
    printf("PASS %u actual OLEACC reference/token/reentry/concurrency checks; no VM\n",atomic_load(&checks));
    return 0;
}
