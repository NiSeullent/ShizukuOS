/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#define SHZ_HOST_TEST
#include "office_threadpool_host_api.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <assert.h>
static pthread_mutex_t hlock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t hchanged=PTHREAD_COND_INITIALIZER;
struct hobject { unsigned refs,kind; uint32_t access; int signaled,manual; LONG max; };
static struct hobject *handles[32768];
static unsigned next_handle=1,threads;
static _Thread_local DWORD last_error,thread_id;
static _Atomic unsigned next_thread_id=1,freed_modules,allocation_fail;
static struct hobject *lookup(HANDLE h) { uintptr_t n=(uintptr_t)h;return n<32768?handles[n]:NULL; }
static void deref(struct hobject *o){if(!--o->refs){if(o->kind==4)atomic_fetch_add(&freed_modules,1);free(o);}}
static HANDLE give(struct hobject *o){assert(next_handle<32768);handles[next_handle]=o;++o->refs;return (HANDLE)(uintptr_t)next_handle++;}
static HANDLE new_object(unsigned kind,int manual,int signal,LONG max){struct hobject *o=calloc(1,sizeof *o);HANDLE h;if(!o)return NULL;o->kind=kind;o->access=0x1f0003u;o->manual=manual;o->signaled=signal;o->max=max;pthread_mutex_lock(&hlock);h=give(o);pthread_mutex_unlock(&hlock);return h;}
void InitializeCriticalSection(CRITICAL_SECTION *m){pthread_mutexattr_t a;assert(!pthread_mutexattr_init(&a));assert(!pthread_mutexattr_settype(&a,PTHREAD_MUTEX_RECURSIVE));assert(!pthread_mutex_init(m,&a));pthread_mutexattr_destroy(&a);}
void DeleteCriticalSection(CRITICAL_SECTION *m){assert(!pthread_mutex_destroy(m));}
void EnterCriticalSection(CRITICAL_SECTION *m){assert(!pthread_mutex_lock(m));}
void LeaveCriticalSection(CRITICAL_SECTION *m){assert(!pthread_mutex_unlock(m));}
DWORD GetLastError(void){return last_error;}void SetLastError(DWORD e){last_error=e;}
DWORD GetCurrentThreadId(void){if(!thread_id)thread_id=atomic_fetch_add(&next_thread_id,1);return thread_id;}
void Sleep(DWORD ms){struct timespec t={ms/1000,(long)(ms%1000)*1000000};if(!ms)sched_yield();else while(nanosleep(&t,&t)&&errno==EINTR){}}
LONG NtQuerySystemTime(LARGE_INTEGER *time){struct timespec t;clock_gettime(CLOCK_REALTIME,&t);time->QuadPart=(t.tv_sec+11644473600ll)*10000000ll+t.tv_nsec/100;return 0;}
HANDLE GetCurrentProcess(void){return INVALID_HANDLE_VALUE;}void *GetProcessHeap(void){return (void *)1;}
void *HeapAlloc(void *heap,DWORD flags,size_t n){(void)heap;if(atomic_exchange(&allocation_fail,0)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}return flags&HEAP_ZERO_MEMORY?calloc(1,n):malloc(n);}
BOOL HeapFree(void *heap,DWORD flags,void *p){(void)heap;(void)flags;free(p);return TRUE;}
HANDLE CreateEventA(void *a,BOOL manual,BOOL initial,const char *name){(void)a;(void)name;return new_object(1,manual,initial,0);}
HANDLE CreateEventW(void *a,BOOL m,BOOL i,const void *name){(void)name;return CreateEventA(a,m,i,NULL);}
HANDLE CreateSemaphoreA(void *a,LONG initial,LONG max,const char *name){(void)a;(void)name;return new_object(2,0,initial,max);}
BOOL SetEvent(HANDLE h){struct hobject *o;pthread_mutex_lock(&hlock);o=lookup(h);if(o&&o->kind==1){o->signaled=1;pthread_cond_broadcast(&hchanged);}pthread_mutex_unlock(&hlock);if(!o)SetLastError(ERROR_INVALID_HANDLE);return o&&o->kind==1;}
BOOL ResetEvent(HANDLE h){struct hobject *o;pthread_mutex_lock(&hlock);o=lookup(h);if(o&&o->kind==1)o->signaled=0;pthread_mutex_unlock(&hlock);return o&&o->kind==1;}
BOOL ReleaseSemaphore(HANDLE h,LONG n,LONG *previous){struct hobject *o;BOOL ok;pthread_mutex_lock(&hlock);o=lookup(h);ok=o&&o->kind==2&&n>0&&n<=o->max-o->signaled;if(ok){if(previous)*previous=o->signaled;o->signaled+=n;pthread_cond_broadcast(&hchanged);}pthread_mutex_unlock(&hlock);return ok;}
BOOL ReleaseMutex(HANDLE h){(void)h;return FALSE;}
BOOL CloseHandle(HANDLE h){struct hobject *o;pthread_mutex_lock(&hlock);o=lookup(h);if(o){handles[(uintptr_t)h]=NULL;deref(o);}pthread_mutex_unlock(&hlock);if(!o)SetLastError(ERROR_INVALID_HANDLE);return o!=NULL;}
BOOL FreeLibrary(HMODULE h){return CloseHandle(h);}
BOOL DuplicateHandle(HANDLE a,HANDLE h,HANDLE b,HANDLE *out,DWORD access,BOOL inherit,DWORD options){struct hobject *o;(void)a;(void)b;(void)access;(void)inherit;(void)options;pthread_mutex_lock(&hlock);o=lookup(h);if(o)*out=give(o);pthread_mutex_unlock(&hlock);if(!o)SetLastError(ERROR_INVALID_HANDLE);return o!=NULL;}
DWORD WaitForMultipleObjects(DWORD n,const HANDLE *hs,BOOL all,DWORD ms){struct hobject *os[64];struct timespec until;unsigned i;DWORD result=WAIT_TIMEOUT;assert(n&&n<=64);clock_gettime(CLOCK_REALTIME,&until);until.tv_sec+=ms/1000;until.tv_nsec+=(long)(ms%1000)*1000000;if(until.tv_nsec>=1000000000){++until.tv_sec;until.tv_nsec-=1000000000;}pthread_mutex_lock(&hlock);for(i=0;i<n;++i){os[i]=lookup(hs[i]);if(!os[i])break;++os[i]->refs;}if(i<n){while(i)deref(os[--i]);pthread_mutex_unlock(&hlock);SetLastError(ERROR_INVALID_HANDLE);return WAIT_FAILED;}for(;;){unsigned ready=0;for(i=0;i<n;++i){if(os[i]->signaled){++ready;if(!all){result=i;break;}}}if((!all&&ready)||(all&&ready==n)){if(all){for(i=0;i<n;++i)if(!os[i]->manual)--os[i]->signaled;result=0;}else if(!os[result]->manual)--os[result]->signaled;break;}if(ms==0)break;if(ms==INFINITE)pthread_cond_wait(&hchanged,&hlock);else if(pthread_cond_timedwait(&hchanged,&hlock,&until)==ETIMEDOUT)break;}for(i=0;i<n;++i)deref(os[i]);pthread_mutex_unlock(&hlock);return result;}
DWORD WaitForSingleObject(HANDLE h,DWORD ms){return WaitForMultipleObjects(1,&h,FALSE,ms);}
struct thread_start { DWORD (*fn)(void *);void *arg;struct hobject *object; };
static void *thread_entry(void *p){struct thread_start s=*(struct thread_start *)p;free(p);s.fn(s.arg);pthread_mutex_lock(&hlock);s.object->signaled=1;--threads;pthread_cond_broadcast(&hchanged);deref(s.object);pthread_mutex_unlock(&hlock);return NULL;}
HANDLE CreateThread(void *a,size_t stack,DWORD (*fn)(void *),void *arg,DWORD flags,DWORD *id){pthread_t thread;struct thread_start *start;struct hobject *o;HANDLE h;(void)a;(void)stack;(void)flags;pthread_mutex_lock(&hlock);if(threads>=16){pthread_mutex_unlock(&hlock);SetLastError(ERROR_MAX_THRDS_REACHED);return NULL;}o=calloc(1,sizeof *o);start=malloc(sizeof *start);assert(o&&start);o->kind=3;o->manual=1;o->refs=1;++threads;h=give(o);start->fn=fn;start->arg=arg;start->object=o;assert(!pthread_create(&thread,NULL,thread_entry,start));pthread_detach(thread);pthread_mutex_unlock(&hlock);if(id)*id=1;return h;}
static _Atomic unsigned raised_mutant;
DWORD k32_nt_error(NTSTATUS s){SetLastError(s==(LONG)0xc0000008u?ERROR_INVALID_HANDLE:ERROR_GEN_FAILURE);return GetLastError();}
void RaiseException(DWORD code,DWORD flags,DWORD count,const ULONG_PTR *values){(void)flags;assert(code==(DWORD)STATUS_THREADPOOL_HANDLE_EXCEPTION && count==1 && values[0]==(ULONG_PTR)(ULONG)STATUS_INVALID_PARAMETER_3);atomic_fetch_add(&raised_mutant,1);}
LONG NtQueryObject(HANDLE h,ULONG cls,PVOID data,ULONG size,ULONG *length){struct hobject *o;SHZ_UNICODE_STRING *name=data;static const unsigned short event[]={'E','v','e','n','t'},mutant[]={'M','u','t','a','n','t'};unsigned i,n;(void)length;assert((cls==2 || cls==0) && size>=128);pthread_mutex_lock(&hlock);o=lookup(h);if(!o){pthread_mutex_unlock(&hlock);return (LONG)0xc0000008u;}if(cls==0){uint32_t granted=o->access;memset(data,0,56);memcpy((unsigned char *)data+4,&granted,4);pthread_mutex_unlock(&hlock);return 0;}n=o->kind==5?6:o->kind==6?3:5;name->Length=n*2;name->MaximumLength=n*2;name->Buffer=(unsigned short *)((unsigned char *)data+104);for(i=0;i<n;++i)name->Buffer[i]=o->kind==5?mutant[i]:o->kind==6?(unsigned short)"Key"[i]:event[i];pthread_mutex_unlock(&hlock);return 0;}
#include "../kernel32/k32_office_threadpool.c"
static _Atomic unsigned checks;
#define CHECK(c,m) do{atomic_fetch_add(&checks,1);if(!(c)){fprintf(stderr,"FAIL: %s at %d\n",m,__LINE__);exit(1);}}while(0)
struct context { _Atomic unsigned calls,last_status; HANDLE release,module; _Atomic unsigned wait_entered,wait_done; PVOID expected; };
static void cb_common(PTP_CALLBACK_INSTANCE instance,struct context *c,PVOID object,DWORD status){CHECK(object==c->expected,"callback receives actual owned object");atomic_store(&c->last_status,status);if(c->module)FreeLibraryWhenCallbackReturns(instance,c->module);atomic_fetch_add(&c->calls,1);if(c->release)CHECK(WaitForSingleObject(c->release,3000)==WAIT_OBJECT_0,"blocked callback released");}
static void work_cb(PTP_CALLBACK_INSTANCE i,PVOID c,PTP_WORK w){cb_common(i,c,w,0);}
static void timer_cb(PTP_CALLBACK_INSTANCE i,PVOID c,PTP_TIMER t){cb_common(i,c,t,0);}
static void wait_cb(PTP_CALLBACK_INSTANCE i,PVOID c,PTP_WAIT w,DWORD status){cb_common(i,c,w,status);}
static BOOL await(_Atomic unsigned *value,unsigned target){unsigned i;for(i=0;i<2500;++i){if(atomic_load(value)>=target)return TRUE;Sleep(1);}return FALSE;}
static FILETIME relative_ms(unsigned ms){ULONGLONG n=0-(ULONGLONG)ms*10000;FILETIME time={(DWORD)n,(DWORD)(n>>32)};return time;}
static DWORD cancel_work(PVOID p){struct context *c=p;atomic_store(&c->wait_entered,1);WaitForThreadpoolWorkCallbacks(c->expected,TRUE);atomic_store(&c->wait_done,1);return 0;}
int main(void){struct context work={0},timer={0},wait={0},blocked={0};PTP_WORK w;PTP_TIMER t;PTP_WAIT q;HANDLE event,a,b,thread;FILETIME due;DWORD id;unsigned before,i;
CHECK(!CreateThreadpoolWork(NULL,NULL,NULL)&&GetLastError()==ERROR_INVALID_PARAMETER,"null callback fails honestly");
atomic_store(&allocation_fail,1);CHECK(!CreateThreadpoolWork(work_cb,&work,NULL),"actual allocation failure propagated");
w=CreateThreadpoolWork(work_cb,&work,NULL);CHECK(w,"real workers created");work.expected=w;
for(i=0;i<60;++i)SubmitThreadpoolWork(w);WaitForThreadpoolWorkCallbacks(w,FALSE);CHECK(atomic_load(&work.calls)==60,"one asynchronous invocation per submission");CloseThreadpoolWork(w);
blocked.release=CreateEventW(NULL,TRUE,FALSE,NULL);w=CreateThreadpoolWork(work_cb,&blocked,NULL);blocked.expected=w;for(i=0;i<1000;++i)SubmitThreadpoolWork(w);CHECK(await(&blocked.calls,1),"blocked callbacks entered");thread=CreateThread(NULL,0,cancel_work,&blocked,0,&id);CHECK(thread,"actual cancellation waiter thread starts");CHECK(await(&blocked.wait_entered,1),"waiter entered");Sleep(30);CHECK(!atomic_load(&blocked.wait_done),"cancel still waits for running callbacks");before=atomic_load(&blocked.calls);CHECK(before<1000,"pending callbacks actually remain to cancel");SetEvent(blocked.release);CHECK(WaitForSingleObject(thread,3000)==WAIT_OBJECT_0,"cancel wait returns after active callbacks");CHECK(atomic_load(&blocked.calls)==before,"pending callbacks canceled without later execution");CloseHandle(thread);CloseThreadpoolWork(w);CloseHandle(blocked.release);
memset(&blocked,0,sizeof blocked);blocked.release=CreateEventW(NULL,TRUE,FALSE,NULL);blocked.module=new_object(4,0,0,0);w=CreateThreadpoolWork(work_cb,&blocked,NULL);blocked.expected=w;SubmitThreadpoolWork(w);CHECK(await(&blocked.calls,1),"deferred resource callback running");CloseThreadpoolWork(w);CHECK(atomic_load(&freed_modules)==0,"close keeps active callback and module alive");SetEvent(blocked.release);CHECK(await(&freed_modules,1),"module released after actual callback return");CloseHandle(blocked.release);
t=CreateThreadpoolTimer(timer_cb,&timer,NULL);CHECK(t,"real timer scheduler object");timer.expected=t;due=relative_ms(20);SetThreadpoolTimer(t,&due,0,0);Sleep(3);CHECK(!atomic_load(&timer.calls),"timer does not fire before relative due time");CHECK(await(&timer.calls,1),"relative timer fires through actual worker queue");WaitForThreadpoolTimerCallbacks(t,FALSE);due=relative_ms(2);SetThreadpoolTimer(t,&due,5,0);CHECK(await(&timer.calls,4),"periodic timer schedules actual callbacks");SetThreadpoolTimer(t,NULL,0,0);WaitForThreadpoolTimerCallbacks(t,TRUE);before=atomic_load(&timer.calls);Sleep(20);CHECK(atomic_load(&timer.calls)==before,"disarm prevents future timer submissions");CloseThreadpoolTimer(t);
event=CreateEventW(NULL,FALSE,FALSE,NULL);q=CreateThreadpoolWait(wait_cb,&wait,NULL);CHECK(q,"real wait bucket object");wait.expected=q;SetThreadpoolWait(q,event,NULL);SetEvent(event);CHECK(await(&wait.calls,1)&&atomic_load(&wait.last_status)==WAIT_OBJECT_0,"actual signal reaches wait callback");WaitForThreadpoolWaitCallbacks(q,FALSE);CHECK(WaitForSingleObject(event,0)==WAIT_TIMEOUT,"auto-reset signal actually consumed");SetEvent(event);Sleep(15);CHECK(atomic_load(&wait.calls)==1,"one shot wait does not resubmit until rearmed");CHECK(WaitForSingleObject(event,0)==WAIT_OBJECT_0,"disarmed one shot leaves new signal untouched");due=relative_ms(10);SetThreadpoolWait(q,event,&due);CHECK(await(&wait.calls,2)&&atomic_load(&wait.last_status)==WAIT_TIMEOUT,"actual timeout status reaches wait callback");SetThreadpoolWait(q,NULL,(FILETIME *)(uintptr_t)1);WaitForThreadpoolWaitCallbacks(q,FALSE);CHECK(TRUE,"NULL handle disarm ignores timeout pointer");
{HANDLE mutex=new_object(5,0,0,0);SetThreadpoolWait(q,mutex,NULL);CHECK(atomic_load(&raised_mutant)==1,"unsupported mutex reports documented exception without consuming ownership");CloseHandle(mutex);}
{HANDLE key=new_object(6,0,0,0);SetThreadpoolWait(q,key,NULL);CHECK(GetLastError()==ERROR_NOT_SUPPORTED,"nonwaitable native type fails before arming");CloseHandle(key);}
pthread_mutex_lock(&hlock);lookup(event)->access=0;pthread_mutex_unlock(&hlock);SetThreadpoolWait(q,event,NULL);CHECK(GetLastError()==ERROR_ACCESS_DENIED,"missing actual SYNCHRONIZE right fails before arming");SetEvent(event);Sleep(10);CHECK(atomic_load(&wait.calls)==2&&WaitForSingleObject(event,0)==WAIT_OBJECT_0,"failed arm neither queues callback nor consumes signal");pthread_mutex_lock(&hlock);lookup(event)->access=0x1f0003u;pthread_mutex_unlock(&hlock);
a=CreateEventW(NULL,FALSE,FALSE,NULL);b=CreateEventW(NULL,FALSE,FALSE,NULL);SetThreadpoolWait(q,a,NULL);Sleep(5);SetThreadpoolWait(q,b,NULL);SetEvent(a);Sleep(15);CHECK(atomic_load(&wait.calls)==2,"old arm snapshot cannot dispatch replacement generation");SetEvent(b);CHECK(await(&wait.calls,3),"new watched handle dispatches after replacement");SetThreadpoolWait(q,NULL,NULL);WaitForThreadpoolWaitCallbacks(q,TRUE);CloseThreadpoolWait(q);CloseHandle(a);CloseHandle(b);CloseHandle(event);
{struct context many[64]={0};PTP_WAIT waits[64];HANDLE events[64];for(i=0;i<64;++i){events[i]=CreateEventW(NULL,FALSE,FALSE,NULL);waits[i]=CreateThreadpoolWait(wait_cb,&many[i],NULL);CHECK(waits[i],"wait creation across bucket boundary");many[i].expected=waits[i];SetThreadpoolWait(waits[i],events[i],NULL);}for(i=0;i<64;++i)SetEvent(events[i]);for(i=0;i<64;++i){CHECK(await(&many[i].calls,1),"every actual handle dispatched across buckets");SetThreadpoolWait(waits[i],NULL,NULL);WaitForThreadpoolWaitCallbacks(waits[i],TRUE);CloseThreadpoolWait(waits[i]);CloseHandle(events[i]);}}
printf("OFFICE-THREADPOOL-HOST: %u checks passed; real pthread workers, timer/wait scheduling, cancellation, close, epochs, deferred resource and 64-handle bucket boundary\n",atomic_load(&checks));return 0;}
