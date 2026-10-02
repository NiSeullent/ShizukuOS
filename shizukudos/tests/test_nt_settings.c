/* SPDX-License-Identifier: GPL-2.0-only
 * Actual settings query/set/wrapper/ref/close/detach/final-process-free bodies.
 * Platform adapters: IRQ depth, caller-copy faults/departures, current TCB,
 * deterministic clock/TSC, selected pinned status rows, unused IPC hooks,
 * quarantined heap/static object publication, and bounded null-pseudo children.
 * Explicit departures run real detach/close/free before storage republication.
 * No synthetic query results; no native allocator, AP/SMP, real power/boost/
 * eviction, Windows 98 runtime, or whole-object-system proof is claimed.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "ntsys.h"
#include "thread-layout.inc"
#include "process-layout.inc"
#include "api-layout.inc"
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
typedef void *HANDLE, *PVOID, *LPVOID;
typedef int BOOL, *PBOOL;
typedef uint8_t BYTE;
typedef uint16_t WORD, USHORT;
typedef uint32_t DWORD, ULONG;
typedef uint64_t ULONG64, ULONG_PTR, KAFFINITY;
typedef size_t SIZE_T;
typedef int32_t NTSTATUS;
#define _WIN64 1
#include "sdk-layout.inc"
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define ERROR_INVALID_HANDLE 6u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOACCESS 998u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_BAD_LENGTH 24u
#define ERROR_NOT_SUPPORTED 50u
#define ORACLE_THREAD_SET_LIMITED 0x400u
#define ORACLE_STRICT_SETTINGS 19u
static unsigned checks, failures, irq_depth;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; if(failures<100) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
#define KASSERT(x) CHECK(x)
static process_t procs[MAX_PROCS+1];
static kobject_t objects[8], *named_head, *timers_head[16];
static unsigned timer_count, thread_hi=4;
static thread_t threads[4], *current;
static uint64_t jiffies=300, tsc=900;
static uint32_t ph, th, eh;
static unsigned read_calls, write_calls, read_bytes, cycle_calls, clock_calls;
static unsigned bad_publications, object_frees, process_frees, copy_events, held_at_copy;
static unsigned active_class, active_set, active_pseudo, entry_refs, departure_kind;
static uint64_t active_handle, active_buffer, reject_read, reject_write;
static unsigned process_constructor;
static DWORD last_error;
struct heap_record { void *p; int live; };
static struct heap_record heap[16];
static unsigned heap_count;
enum { PROCESS_INPUT=1, THREAD_INPUT=2, PROCESS_OUTPUT=3, THREAD_OUTPUT=4,
       KILL_INPUT=5, OWNER_INPUT=6, FREE_INPUT=7, RECIPROCAL_INPUT=8, TEARDOWN_INPUT=9 };
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void ipc_object_free(kobject_t *o);
void ipc_handle_closed(process_t *p,kobject_t *o);
void thread_object_detach(thread_t *t);
void vad_destroy(process_t *p);
int32_t handle_close(process_t *p,uint64_t h);
static void depart(unsigned mode);
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) { CHECK(irq_depth==f+1); irq_depth=(unsigned)f; }
static thread_t *thread_current(void) { return current; }
static uint64_t rdtsc(void) { return tsc; }
static int64_t filetime_now(void) { ++clock_calls; return INT64_C(10000000000); }
static void *kzalloc(size_t n) {
    CHECK(heap_count<16); if(heap_count>=16)return NULL;
    void *p=calloc(1,n); CHECK(p!=NULL); if(p)heap[heap_count++]=(struct heap_record){p,1}; return p;
}
static void kfree(void *p) {
    if(!p)return;
    if((uintptr_t)p>=(uintptr_t)objects && (uintptr_t)p<(uintptr_t)(objects+8)) {
        ++object_frees; if(((kobject_t*)p)->type==OB_PROCESS)++process_frees; return;
    }
    for(unsigned i=0;i<heap_count;++i)if(heap[i].p==p) { CHECK(heap[i].live);heap[i].live=0;return; }
    CHECK(0);
}
static void kprintf(const char *s,...) { (void)s; CHECK(0); }
void reg_key_object_free(kobject_t *o) { (void)o;CHECK(0); }
void token_object_free(kobject_t *o) { (void)o;CHECK(0); }
void file_object_closed(kobject_t *o) { (void)o;CHECK(0); }
void net_socket_handle_closing(kobject_t *o) { (void)o;CHECK(0); }
void ntdrv_device_handle_closing(kobject_t *o) { (void)o;CHECK(0); }
void net_socket_last_handle_closed(kobject_t *o) { (void)o;CHECK(0); }
static void notify_handle_closed(kobject_t *o) { (void)o;CHECK(0); }
static void npfs_handle_closed(kobject_t *o) { (void)o;CHECK(0); }
static void iocp_handle_closed(kobject_t *o) { (void)o;CHECK(0); }
static void job_handle_closed(kobject_t *o) { (void)o;CHECK(0); }
static void observe_ref_publication(kobject_t *o) {
    if(!active_pseudo)return;
    if(active_handle==CURRENT_PROCESS_HANDLE) {
        if(!procs[1].used || !o || o->type!=OB_PROCESS || procs[1].object!=o || o->u.proc.p!=&procs[1])++bad_publications;
    } else {
        if(!current || current->proc!=&procs[1] || current->state==TS_FREE || !o ||
           o->type!=OB_THREAD || current->object!=o || o->u.thr.t!=current ||
           o->u.thr.pid!=(uint64_t)procs[1].pid)++bad_publications;
    }
}
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; CHECK(!irq_depth); ++read_calls;read_bytes+=(unsigned)n;
    if(departure_kind && active_set) {
        unsigned mode=departure_kind;departure_kind=0;++copy_events;
        kobject_t *o=active_class==9||active_class==10?&objects[1]:&objects[3];
        held_at_copy+=o->refs>entry_refs;depart(mode);
    }
    if(!src || (reject_read>=src && reject_read-src<n))return -1;
    memcpy(dst,(void*)(uintptr_t)src,(size_t)n);return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    (void)p;CHECK(!irq_depth);++write_calls;
    if(departure_kind && !active_set && dst==active_buffer) {
        unsigned mode=departure_kind;departure_kind=0;++copy_events;depart(mode);
    }
    if(!dst || (reject_write>=dst && reject_write-dst<n))return -1;
    memcpy((void*)(uintptr_t)dst,src,(size_t)n);return 0;
}
static int32_t host_query(process_t*,uint64_t,uint64_t,uint64_t,uint64_t,uint64_t);
static int32_t host_set(process_t*,uint64_t,uint64_t,uint64_t,uint64_t);
static NTSTATUS NtShzQueryK32(ULONG cls,HANDLE h,void *b,ULONG n,ULONG *r) {
    active_class=cls;active_set=0;active_handle=(uintptr_t)h;active_buffer=(uintptr_t)b;
    active_pseudo=active_handle==CURRENT_PROCESS_HANDLE||active_handle==CURRENT_THREAD_HANDLE;
    NTSTATUS st=host_query(&procs[1],cls,active_handle,active_buffer,n,(uintptr_t)r);
    active_pseudo=active_class=0;CHECK(!irq_depth);return st;
}
static NTSTATUS NtShzSetK32(ULONG cls,HANDLE h,void *b,ULONG n) {
    active_class=cls;active_set=1;active_handle=(uintptr_t)h;active_buffer=(uintptr_t)b;
    active_pseudo=active_handle==CURRENT_PROCESS_HANDLE||active_handle==CURRENT_THREAD_HANDLE;
    entry_refs=(cls==9||cls==10?objects[1].refs:objects[3].refs);
    NTSTATUS st=host_set(&procs[1],cls,active_handle,active_buffer,n);
    active_pseudo=active_class=active_set=0;CHECK(!irq_depth);return st;
}
static void shz_set_last_error(DWORD e) { last_error=e; }
static DWORD RtlNtStatusToDosError(NTSTATUS s) {
    /* Adapter for selected rows of pinned actual ntdll status_map. */
    return s==STATUS_ACCESS_DENIED||s==STATUS_PROCESS_IS_TERMINATING||s==STATUS_THREAD_IS_TERMINATING?ERROR_ACCESS_DENIED:
           s==STATUS_INVALID_HANDLE||s==STATUS_OBJECT_TYPE_MISMATCH?ERROR_INVALID_HANDLE:
           s==STATUS_ACCESS_VIOLATION?ERROR_NOACCESS:s==STATUS_BUFFER_TOO_SMALL?ERROR_INSUFFICIENT_BUFFER:
           s==STATUS_INFO_LENGTH_MISMATCH?ERROR_BAD_LENGTH:s==STATUS_NOT_SUPPORTED?ERROR_NOT_SUPPORTED:ERROR_INVALID_PARAMETER;
}
#include "production.inc"
_Static_assert(sizeof(MEMORY_PRIORITY_INFORMATION)==4,"SDK memory priority");
_Static_assert(sizeof(PROCESS_POWER_THROTTLING_STATE)==12,"SDK process power");
_Static_assert(sizeof(THREAD_POWER_THROTTLING_STATE)==12,"SDK thread power");
_Static_assert(sizeof(SHZ_THREAD_POWER_THROTTLING_STATE)==12,"actual local thread power");
_Static_assert(sizeof(GROUP_AFFINITY)==16,"SDK x64 group affinity");
_Static_assert(sizeof(WOW64_CONTEXT)==716,"complete SDK Wow64 context");
static HANDLE H(uint64_t h) { return (HANDLE)(uintptr_t)h; }
static NTSTATUS q(unsigned cls,uint64_t h,void *b,unsigned n,ULONG *r) { return NtShzQueryK32(cls,H(h),b,n,r); }
static NTSTATUS s(unsigned cls,uint64_t h,void *b,unsigned n) { return NtShzSetK32(cls,H(h),b,n); }
static void dispose(void) {
    CHECK(!irq_depth);for(unsigned i=0;i<heap_count;++i)free(heap[i].p);heap_count=0;memset(heap,0,sizeof heap);
}
static void publish_process(process_t *p,kobject_t *o,int pid) {
    memset(p,0,sizeof *p);memset(o,0,sizeof *o);p->used=1;p->pid=pid;p->object=o;
    p->handles=kzalloc(32*sizeof *p->handles);p->handle_cap=32;p->pml4=0; /* metadata has no memory gate */
    o->type=OB_PROCESS;o->refs=1;o->u.proc.p=p;
}
static void publish_thread(thread_t *t,kobject_t *o,process_t *p,unsigned tid) {
    memset(t,0,sizeof *t);memset(o,0,sizeof *o);
    t->proc=p;t->state=TS_READY;t->object=o;t->tid=tid;t->mem_priority=5;
    t->create_tick=11;t->exit_tick=80;t->user_ticks=17;t->kernel_ticks=19;t->cycles=23;
    o->type=OB_THREAD;o->refs=1;o->u.thr.t=t;o->u.thr.pid=(uint64_t)p->pid;o->u.thr.tid=tid;ob_ref(p->object);
}
static void reset(void) {
    dispose();memset(procs,0,sizeof procs);memset(objects,0,sizeof objects);memset(threads,0,sizeof threads);
    named_head=NULL;timer_count=0;current=&threads[0];
    read_calls=write_calls=read_bytes=cycle_calls=clock_calls=0;
    bad_publications=object_frees=process_frees=copy_events=held_at_copy=0;
    active_class=active_set=active_pseudo=entry_refs=departure_kind=0;
    active_handle=active_buffer=reject_read=reject_write=0;last_error=0;process_constructor=1;
    publish_process(&procs[1],&objects[0],100);publish_process(&procs[2],&objects[1],101);
    publish_thread(&threads[0],&objects[2],&procs[1],1);threads[0].state=TS_RUNNING;
    publish_thread(&threads[1],&objects[3],&procs[2],2);
    objects[5].type=OB_EVENT;objects[5].refs=1;
    CHECK(!handle_insert(&procs[1],&objects[1],0x1fffff,&ph));
    CHECK(!handle_insert(&procs[1],&objects[3],0x1fffff,&th));
    CHECK(!handle_insert(&procs[1],&objects[5],0x1fffff,&eh));
}
static void access_of(uint32_t h,uint32_t access) { procs[1].handles[h/4-1].access=access; }
static void copies_reset(void) { read_calls=write_calls=read_bytes=0; }
static void detach_target(void) {
    threads[1].state=TS_ZOMBIE;threads[1].exit_code=7;
    thread_account_exit(&threads[1]);const uint64_t f=irq_save();thread_object_detach(&threads[1]);irq_restore(f);
    CHECK(!threads[1].object&&!objects[3].u.thr.t);
}
static void drop_process_constructor(void) { if(process_constructor) { process_constructor=0;ob_deref(&objects[1]); } }
static void depart(unsigned mode) {
    CHECK(!irq_depth);
    if(mode==KILL_INPUT) { threads[1].kill_pending=1;return; }
    if(mode==OWNER_INPUT) { procs[2].exit_owner=&threads[2];return; }
    if(mode==FREE_INPUT) { threads[1].state=TS_FREE;return; }
    if(mode==RECIPROCAL_INPUT) { threads[1].object=&objects[4];return; }
    if(mode==TEARDOWN_INPUT) { procs[2].teardown=1;return; }
    procs[2].terminated=1;procs[2].teardown=2;
    detach_target();drop_process_constructor();
    if(mode==PROCESS_INPUT||mode==PROCESS_OUTPUT||mode==THREAD_OUTPUT) CHECK(!handle_close(&procs[1],ph));
    if(mode==THREAD_INPUT||mode==THREAD_OUTPUT) CHECK(!handle_close(&procs[1],th));
    if(mode==PROCESS_INPUT||mode==PROCESS_OUTPUT) {
        if(!procs[2].used)publish_process(&procs[2],&objects[6],202);
        procs[2].mem_priority=4;procs[2].power_control=0xdddd;procs[2].power_state=0xeeee;
    }
    if(mode==THREAD_INPUT) {
        publish_thread(&threads[1],&objects[4],&procs[1],99);
        threads[1].mem_priority=4;threads[1].boost_disabled=0;threads[1].power_control=0xdddd;threads[1].power_state=0xeeee;
    } else if(mode==THREAD_OUTPUT) {
        CHECK(!objects[3].refs);memset(&objects[3],0,sizeof objects[3]);objects[3].type=OB_EVENT;objects[3].refs=1;
    }
}
struct guarded { uint32_t left, v[6], right; };
static void poison(struct guarded *g) { memset(g,0xa5,sizeof *g); }
static int all_poison(const void *p,size_t n) { const unsigned char *b=p;for(size_t i=0;i<n;++i)if(b[i]!=0xa5)return 0;return 1; }
static void metadata_literals(void) {
    procs[2].mem_priority=2;procs[2].power_control=0xf1234567;procs[2].power_state=0x89abcdef;
    threads[1].boost_disabled=1;threads[1].mem_priority=3;threads[1].power_control=0x76543210;threads[1].power_state=0xfedcba98;
}
static void query_row(unsigned cls,uint64_t h,int admitted,const uint32_t *expected,unsigned width) {
    struct guarded g;poison(&g);ULONG rl=0xdeadbeef;unsigned oi=h==CURRENT_PROCESS_HANDLE?0:h==CURRENT_THREAD_HANDLE?2:cls==13?1:3;
    unsigned refs=objects[oi].refs;
    copies_reset();NTSTATUS st=q(cls,h,g.v,sizeof g.v,&rl);
    CHECK(st==(admitted?STATUS_SUCCESS:STATUS_ACCESS_DENIED));
    if(admitted) { CHECK(!cycle_calls&&!clock_calls); CHECK(rl==width);CHECK(!memcmp(g.v,expected,width));CHECK(all_poison((char*)g.v+width,sizeof g.v-width)); }
    else { CHECK(rl==0xdeadbeef);CHECK(all_poison(g.v,sizeof g.v));CHECK(!read_calls&&!write_calls); }
    CHECK(g.left==0xa5a5a5a5&&g.right==0xa5a5a5a5);CHECK(objects[oi].refs==refs);
}
static void rights_queries(void) {
    const uint32_t prights[]={0,0x10,0x200,0x400,0x1000,0x1400,0x1fffff};
    const uint32_t trights[]={0,2,0x20,0x400,0x40,0x800,0x840,0x1fffff};
    for(unsigned i=0;i<sizeof prights/sizeof *prights;++i) {
        reset();metadata_literals();access_of(ph,prights[i]);uint32_t v[]={2,0xf1234567,0x89abcdef};
        for(unsigned tag=0;tag<4;++tag)query_row(13,ph|tag,!!(prights[i]&0x1400),v,12);
        MEMORY_PRIORITY_INFORMATION m={.MemoryPriority=0xa5a5a5a5};
        copies_reset();BOOL ok=GetProcessInformation(H(ph),ProcessMemoryPriority,&m,sizeof m);
        CHECK(ok==!!(prights[i]&0x1400));CHECK(m.MemoryPriority==(ok?2u:0xa5a5a5a5u));
    }
    for(unsigned i=0;i<sizeof trights/sizeof *trights;++i) {
        reset();metadata_literals();access_of(th,trights[i]);uint32_t v[]={1,3,0x76543210,0xfedcba98};
        for(unsigned tag=0;tag<4;++tag) {
            query_row(12,th|tag,!!(trights[i]&0x840),v,16);
            query_row(19,th|tag,!!(trights[i]&0x40),v,16);
        }
        BOOL boost=123;copies_reset();BOOL ok=GetThreadPriorityBoost(H(th),&boost);
        CHECK(ok==!!(trights[i]&0x840));CHECK(boost==(ok?TRUE:123));
        MEMORY_PRIORITY_INFORMATION m={.MemoryPriority=0xa5a5a5a5};
        ok=GetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)0,&m,sizeof m);
        CHECK(ok==!!(trights[i]&0x40));CHECK(m.MemoryPriority==(ok?3u:0xa5a5a5a5u));
        GROUP_AFFINITY ga;memset(&ga,0xa5,sizeof ga);ok=GetThreadGroupAffinity(H(th),&ga);
        CHECK(ok==!!(trights[i]&0x840));
        if(ok) { CHECK(ga.Mask==1&&ga.Group==0);CHECK(!ga.Reserved[0]&&!ga.Reserved[1]&&!ga.Reserved[2]); }
        else CHECK(all_poison(&ga,sizeof ga));
    }
}
static void buffers_and_faults(void) {
    const unsigned cls[]={12,13,19},width[]={16,12,16};
    for(unsigned i=0;i<3;++i) {
        reset();metadata_literals();
        for(unsigned n=0;n<width[i];++n) {
            struct guarded g;poison(&g);ULONG rl=99;copies_reset();
            CHECK(q(cls[i],i==1?ph:th,g.v,n,&rl)==STATUS_BUFFER_TOO_SMALL);
            CHECK(rl==width[i]&&all_poison(g.v,sizeof g.v)&&write_calls==1&&!read_calls);
        }
        struct guarded g;poison(&g);ULONG rl=99;reject_write=(uintptr_t)&rl;copies_reset();
        CHECK(q(cls[i],i==1?ph:th,g.v,0,&rl)==STATUS_ACCESS_VIOLATION);
        CHECK(rl==99&&all_poison(g.v,sizeof g.v));reject_write=0;
        reject_write=(uintptr_t)g.v;CHECK(q(cls[i],i==1?ph:th,g.v,sizeof g.v,&rl)==STATUS_ACCESS_VIOLATION);
        CHECK(rl==width[i]&&all_poison(g.v,sizeof g.v));reject_write=0;
        CHECK(q(cls[i],i==1?ph:th,0,width[i],NULL)==STATUS_ACCESS_VIOLATION);
        CHECK(q(cls[i],i==1?ph:th,g.v,sizeof g.v,NULL)==STATUS_SUCCESS);
        CHECK(g.left==0xa5a5a5a5&&g.right==0xa5a5a5a5);
    }
}
static void bad_handles(void) {
    const unsigned cls[]={12,13,19};
    for(unsigned c=0;c<3;++c)for(unsigned i=0;i<6;++i) {
        reset();uint64_t bad[]={0,0x100000000ull|th,0xdeadbeef,eh,c==1?th:ph,0};
        if(i==5) { uint32_t h;CHECK(!handle_insert(&procs[1],c==1?&objects[1]:&objects[3],0x1fffff,&h));CHECK(!handle_close(&procs[1],h));bad[i]=h; }
        struct guarded g;poison(&g);ULONG rl=0xdeadbeef;copies_reset();
        CHECK(q(cls[c],bad[i],g.v,sizeof g.v,&rl)==(i==3||i==4?STATUS_OBJECT_TYPE_MISMATCH:STATUS_INVALID_HANDLE));
        CHECK(!read_calls&&!write_calls&&rl==0xdeadbeef&&all_poison(g.v,sizeof g.v));
    }
    reset();struct guarded g;poison(&g);ULONG rl=99;
    CHECK(q(0xeeee,th,g.v,sizeof g.v,&rl)==STATUS_INVALID_INFO_CLASS);CHECK(rl==99&&all_poison(g.v,sizeof g.v));
}
static void setters_rights_and_widths(void) {
    const unsigned cls[]={2,3,8,9,10};const uint32_t rights[]={0,2,0x40,0x800,0x20,0x400,0x420,0x200,0x1fffff};
    for(unsigned c=0;c<5;++c)for(unsigned r=0;r<sizeof rights/sizeof *rights;++r)for(unsigned tag=0;tag<4;++tag) {
        reset();metadata_literals();int process=cls[c]>=9;uint32_t h=process?ph:th;access_of(h,rights[r]);
        uint32_t v[3]={cls[c]==2?0:2,0xf0f0f0f0,0xaaaaaaaa};
        int admit=process?!!(rights[r]&0x200):cls[c]==2?!!(rights[r]&0x420):!!(rights[r]&0x20);
        unsigned width=cls[c]==8||cls[c]==10?8:4,refs=objects[process?1:3].refs;
        copies_reset();NTSTATUS st=s(cls[c],h|tag,v,sizeof v);
        CHECK(st==(admit?STATUS_SUCCESS:STATUS_ACCESS_DENIED));
        CHECK(objects[process?1:3].refs==refs);
        if(admit) {
            CHECK(read_bytes==width&&!write_calls);
            if(process)CHECK(procs[2].mem_priority==2u&&procs[2].power_control==(cls[c]==10?v[0]:0xf1234567u)&&procs[2].power_state==(cls[c]==10?v[1]:0x89abcdefu));
            else CHECK(threads[1].mem_priority==(cls[c]==3?2u:3u)&&threads[1].boost_disabled==(cls[c]==2?0:1)&&threads[1].power_control==(cls[c]==8?v[0]:0x76543210u)&&threads[1].power_state==(cls[c]==8?v[1]:0xfedcba98u));
        } else {
            CHECK(!read_calls&&!write_calls);CHECK(procs[2].mem_priority==2&&procs[2].power_control==0xf1234567);
            CHECK(threads[1].mem_priority==3&&threads[1].boost_disabled==1&&threads[1].power_control==0x76543210);
        }
        access_of(h,0);reject_read=(uintptr_t)v;copies_reset();
        CHECK(s(cls[c],h,v,0)==STATUS_ACCESS_DENIED);CHECK(!read_calls&&!write_calls);
        CHECK(s(cls[c],h,v,sizeof v)==STATUS_ACCESS_DENIED);CHECK(!read_calls&&!write_calls);
    }
    for(unsigned c=0;c<5;++c) {
        reset();uint32_t v[3]={2,0xffffffff,0xaaaaaaaa};unsigned width=cls[c]==8||cls[c]==10?8:4;
        for(unsigned n=0;n<width;++n) { copies_reset();CHECK(s(cls[c],cls[c]>=9?ph:th,v,n)==STATUS_ACCESS_VIOLATION);CHECK(!write_calls); }
        reject_read=(uintptr_t)v;CHECK(s(cls[c],cls[c]>=9?ph:th,v,width)==STATUS_ACCESS_VIOLATION);reject_read=0;
        if(cls[c]==8) { reject_read=(uintptr_t)&v[1];CHECK(s(cls[c],th,v,8)==STATUS_ACCESS_VIOLATION);reject_read=0; }
        v[0]=0;if(cls[c]==3||cls[c]==9)CHECK(s(cls[c],cls[c]>=9?ph:th,v,width)==STATUS_INVALID_PARAMETER);
        v[0]=6;if(cls[c]==3||cls[c]==9)CHECK(s(cls[c],cls[c]>=9?ph:th,v,width)==STATUS_INVALID_PARAMETER);
        if(cls[c]==8||cls[c]==10) { v[0]=0xffffffff;v[1]=0x12345678;CHECK(!s(cls[c],cls[c]>=9?ph:th,v,sizeof v));
            CHECK(cls[c]==8?(threads[1].power_control==v[0]&&threads[1].power_state==v[1]):(procs[2].power_control==v[0]&&procs[2].power_state==v[1])); }
    }
}
static void setters_invalid_and_liveness(void) {
    const unsigned cls[]={2,3,8,9,10};
    for(unsigned c=0;c<5;++c)for(unsigned i=0;i<6;++i) {
        reset();uint32_t v[2]={2,1};uint64_t bad[]={0,0x100000000ull|th,0xdeadbeef,eh,cls[c]>=9?th:ph,0};
        if(i==5) { uint32_t h;CHECK(!handle_insert(&procs[1],cls[c]>=9?&objects[1]:&objects[3],0x1fffff,&h));CHECK(!handle_close(&procs[1],h));bad[i]=h; }
        copies_reset();CHECK(s(cls[c],bad[i],v,0)==(i==3||i==4?STATUS_OBJECT_TYPE_MISMATCH:STATUS_INVALID_HANDLE));
        CHECK(!read_calls&&!write_calls);
    }
    for(unsigned c=0;c<5;++c)for(unsigned mode=0;mode<7;++mode) {
        reset();metadata_literals();uint32_t v[2]={2,1};int process=cls[c]>=9;
        if(mode==0)procs[2].terminated=1;
        if(mode==1)procs[2].teardown=1;
        if(mode==2)procs[2].exit_owner=&threads[2];
        if(mode==3)threads[1].kill_pending=1;
        if(mode==4)threads[1].state=TS_ZOMBIE;
        if(mode==5)threads[1].state=TS_FREE;
        if(mode==6)threads[1].object=&objects[4];
        copies_reset();NTSTATUS st=s(cls[c],process?ph:th,v,cls[c]==8||cls[c]==10?8:4);
        NTSTATUS wanted=process?(mode<=2?STATUS_PROCESS_IS_TERMINATING:STATUS_SUCCESS):
                         mode==5||mode==6?STATUS_INVALID_HANDLE:STATUS_THREAD_IS_TERMINATING;
        CHECK(st==wanted);CHECK(!write_calls);
        if(wanted) { CHECK(threads[1].mem_priority==3&&threads[1].power_control==0x76543210&&threads[1].boost_disabled==1);
            CHECK(procs[2].mem_priority==2&&procs[2].power_control==0xf1234567); }
    }
    for(unsigned c=0;c<3;++c) { reset();threads[1].state=TS_NEW;uint32_t v[2]={2,1};CHECK(!s(cls[c],th,v,cls[c]==8?8:4)); }
}
static void detached_and_retained(void) {
    reset();metadata_literals();detach_target();
    publish_thread(&threads[1],&objects[4],&procs[1],99);
    threads[1].boost_disabled=0;threads[1].mem_priority=4;threads[1].power_control=2;threads[1].power_state=1;
    CHECK(procs[2].dead_user_ticks==17&&procs[2].dead_kernel_ticks==19&&procs[2].dead_cycles==23);
    uint32_t expected[]={1,3,0x76543210,0xfedcba98};query_row(12,th,1,expected,16);query_row(19,th,1,expected,16);
    procs[2].terminated=1;procs[2].teardown=2;drop_process_constructor();CHECK(!handle_close(&procs[1],ph));
    CHECK(!procs[2].used&&process_frees==1);
    publish_process(&procs[2],&objects[6],202);procs[2].mem_priority=4; /* old owner storage now belongs elsewhere */
    query_row(12,th,1,expected,16);query_row(19,th,1,expected,16);
    uint32_t v[2]={2,1};for(unsigned c=0;c<3;++c) {
        copies_reset();CHECK(s(c==0?2:c==1?3:8,th,v,c==2?8:4)==STATUS_THREAD_IS_TERMINATING);CHECK(!write_calls&&threads[1].mem_priority==4&&threads[1].power_control==2);
    }
    CHECK(!handle_close(&procs[1],th));CHECK(objects[3].refs==0&&object_frees>=2);
    reset();metadata_literals();threads[1].state=TS_ZOMBIE;query_row(12,th,1,expected,16);query_row(19,th,1,expected,16);
    reset();metadata_literals();procs[2].terminated=1;procs[2].teardown=2;procs[2].exit_owner=&threads[2];
    uint32_t pexpected[]={2,0xf1234567,0x89abcdef};query_row(13,ph,1,pexpected,12);
    reset();uint32_t cold;objects[7].type=OB_THREAD;objects[7].refs=1;objects[7].u.thr.pid=101;
    CHECK(!handle_insert(&procs[1],&objects[7],0x840,&cold));
    for(unsigned c=0;c<2;++c) {
        struct guarded g;poison(&g);ULONG rl=99;copies_reset();
        CHECK(q(c?19:12,cold,g.v,sizeof g.v,&rl)==STATUS_INVALID_HANDLE);
        CHECK(!read_calls&&!write_calls&&rl==99&&all_poison(g.v,sizeof g.v));
    }
}
static void caller_departures(void) {
    /* Provider self-controls first establish that these events perform real
     * last-ref process/thread frees, then explicitly overwrite reused storage. */
    reset();depart(PROCESS_INPUT);CHECK(copy_events==0&&process_frees==1&&procs[2].pid==202&&procs[2].used);
    reset();depart(THREAD_INPUT);CHECK(objects[3].refs==0&&!objects[3].u.thr.t&&threads[1].object==&objects[4]);
    const unsigned cls[]={2,3,8,9,10};
    for(unsigned c=0;c<5;++c) {
        reset();metadata_literals();uint32_t v[2]={2,1};departure_kind=cls[c]>=9?PROCESS_INPUT:THREAD_INPUT;
        CHECK(s(cls[c],cls[c]>=9?ph:th,v,cls[c]==8||cls[c]==10?8:4)==(cls[c]>=9?STATUS_PROCESS_IS_TERMINATING:STATUS_THREAD_IS_TERMINATING));
        CHECK(copy_events==1&&held_at_copy==1&&!write_calls);
        if(cls[c]>=9)CHECK(procs[2].mem_priority==4&&procs[2].power_control==0xdddd&&procs[2].power_state==0xeeee);
        else CHECK(threads[1].mem_priority==4&&threads[1].power_control==0xdddd&&threads[1].power_state==0xeeee&&threads[1].boost_disabled==0);
        CHECK(objects[cls[c]>=9?1:3].refs==0);
    }
    for(unsigned c=0;c<3;++c)for(unsigned mode=KILL_INPUT;mode<=TEARDOWN_INPUT;++mode) {
        reset();metadata_literals();uint32_t v[2]={2,1};departure_kind=mode;
        CHECK(s(c==0?2:c==1?3:8,th,v,c==2?8:4)==(mode==FREE_INPUT||mode==RECIPROCAL_INPUT?STATUS_INVALID_HANDLE:STATUS_THREAD_IS_TERMINATING));
        CHECK(copy_events==1&&held_at_copy==1&&threads[1].mem_priority==3&&threads[1].power_control==0x76543210&&threads[1].boost_disabled==1);
    }
    for(unsigned c=0;c<3;++c) {
        reset();metadata_literals();uint32_t expected[]={1,3,0x76543210,0xfedcba98};
        if(c==1) { expected[0]=2;expected[1]=0xf1234567;expected[2]=0x89abcdef; }
        struct guarded g;poison(&g);ULONG rl=99;departure_kind=c==1?PROCESS_OUTPUT:THREAD_OUTPUT;
        CHECK(!q(c==0?12:c==1?13:19,c==1?ph:th,g.v,sizeof g.v,&rl));
        CHECK(copy_events==1&&rl==(c==1?12u:16u)&&!memcmp(g.v,expected,c==1?12:16));
        CHECK(g.left==0xa5a5a5a5&&g.right==0xa5a5a5a5&&process_frees==1);
        CHECK(c==1?objects[1].refs==0:objects[3].type==OB_EVENT);
    }
    printf("SETTINGS_COPY_CONTROLS: events=%u process_frees=%u object_frees=%u\n",copy_events,process_frees,object_frees);
}
static int null_pseudo_child(int thread) {
    const unsigned before_failures=failures;
    reset();uint32_t v[4]={0};copies_reset();
    const uint32_t process_refs=objects[0].refs,thread_refs=objects[2].refs;
    if(thread)threads[0].object=NULL;else procs[1].object=NULL;
    NTSTATUS st=q(thread?12:13,thread?CURRENT_THREAD_HANDLE:CURRENT_PROCESS_HANDLE,v,sizeof v,NULL);
    return st==STATUS_INVALID_HANDLE&&!read_calls&&!write_calls&&!bad_publications&&
           failures==before_failures&&!irq_depth&&
           objects[0].refs==process_refs&&objects[2].refs==thread_refs;
}
static void null_pseudo_isolated(int thread) {
    fflush(NULL);pid_t child=fork();CHECK(child>=0);if(child<0)return;
    if(!child) {
        /* This child alone may expose a real baseline fault. Do not run that
         * control unless the child-local nondumpable setting succeeded. */
        if(prctl(PR_SET_DUMPABLE,0,0,0,0)) {
            fprintf(stderr,"SETTINGS_NULL_PSEUDO_CHILD: nondumpable setup failed errno=%d\n",errno);
            _exit(2);
        }
        _exit(null_pseudo_child(thread)?0:1);
    }
    int status=0,got=0;struct timespec pause={0,10000000};
    for(unsigned i=0;i<100;++i) {
        pid_t r=waitpid(child,&status,WNOHANG);
        if(r==child) { got=1;break; }
        if(r<0 && errno!=EINTR)break;
        nanosleep(&pause,NULL);
    }
    if(!got) { CHECK(!kill(child,SIGKILL)||errno==ESRCH);
        for(unsigned i=0;i<100;++i) { pid_t r=waitpid(child,&status,WNOHANG);if(r==child){got=1;break;}if(r<0&&errno!=EINTR)break;nanosleep(&pause,NULL); } }
    fprintf(stderr,"SETTINGS_NULL_PSEUDO_CHILD: thread=%d pid=%ld reaped=%d status=%d signal=%d\n",
            thread,(long)child,got,status,got&&WIFSIGNALED(status)?WTERMSIG(status):0);
    CHECK(got&&WIFEXITED(status)&&WEXITSTATUS(status)==0);
}
static void pseudo_identity(void) {
    reset();uint32_t pv[]={5,0,0},tv[]={0,5,0,0};
    query_row(13,CURRENT_PROCESS_HANDLE,1,pv,12);query_row(12,CURRENT_THREAD_HANDLE,1,tv,16);query_row(19,CURRENT_THREAD_HANDLE,1,tv,16);
    uint32_t v[2]={2,1};CHECK(!s(9,CURRENT_PROCESS_HANDLE,v,4));CHECK(!s(3,CURRENT_THREAD_HANDLE,v,4));
    for(unsigned mode=0;mode<7;++mode) {
        reset();struct guarded g;poison(&g);ULONG rl=99;copies_reset();
        if(mode==0)threads[0].proc=&procs[2];
        if(mode==1)objects[2].u.thr.t=&threads[1];
        if(mode==2)threads[0].state=TS_FREE;
        if(mode==3)objects[2].type=OB_EVENT;
        if(mode==4)objects[2].u.thr.pid=999;
        if(mode==5)objects[0].u.proc.p=&procs[2];
        if(mode==6)procs[1].used=0;
        NTSTATUS wanted=mode==3?STATUS_OBJECT_TYPE_MISMATCH:STATUS_INVALID_HANDLE;
        CHECK(q(mode>=5?13:12,mode>=5?CURRENT_PROCESS_HANDLE:CURRENT_THREAD_HANDLE,g.v,sizeof g.v,&rl)==wanted);
        CHECK(!bad_publications&&!read_calls&&!write_calls&&rl==99&&all_poison(g.v,sizeof g.v));
        CHECK(s(mode>=5?9:2,mode>=5?CURRENT_PROCESS_HANDLE:CURRENT_THREAD_HANDLE,v,0)==wanted);
        CHECK(!bad_publications&&!read_calls&&!write_calls);
    }
    null_pseudo_isolated(0);null_pseudo_isolated(1);
}
static void attached_identity(void) {
    for(unsigned cls=0;cls<3;++cls)for(unsigned mode=0;mode<5;++mode) {
        reset();struct guarded g;poison(&g);ULONG rl=99;unsigned refs=objects[cls==1?1:3].refs;
        if(cls==1) {
            if(mode==0)procs[2].used=0;
            if(mode==1)procs[2].object=&objects[6];
            if(mode==2)objects[1].u.proc.p=NULL;
            if(mode>=3)objects[1].u.proc.p=&procs[1];
        } else {
            if(mode==0)threads[1].state=TS_FREE;
            if(mode==1)threads[1].object=&objects[4];
            if(mode==2)threads[1].proc=NULL;
            if(mode==3)objects[3].u.thr.pid=202;
            if(mode==4)procs[2].used=0;
        }
        copies_reset();CHECK(q(cls==0?12:cls==1?13:19,cls==1?ph:th,g.v,sizeof g.v,&rl)==STATUS_INVALID_HANDLE);
        CHECK(!read_calls&&!write_calls&&rl==99&&all_poison(g.v,sizeof g.v));
        CHECK(objects[cls==1?1:3].refs==refs);
    }
}
static void memory_range_and_defaults(void) {
    reset();uint32_t pdefault[]={5,0,0},tdefault[]={0,5,0,0};
    query_row(13,ph,1,pdefault,12);query_row(12,th,1,tdefault,16);query_row(19,th,1,tdefault,16);
    for(uint32_t n=1;n<=5;++n) {
        CHECK(!s(9,ph,&n,4));CHECK(!s(3,th,&n,4));
        uint32_t p[]={n,0,0},t[]={0,n,0,0};query_row(13,ph,1,p,12);query_row(19,th,1,t,16);
    }
    const uint32_t boost[]={0,1,42,0xffffffff};
    for(unsigned i=0;i<4;++i) { CHECK(!s(2,th,(void*)&boost[i],4));CHECK(threads[1].boost_disabled==(boost[i]!=0)); }
}
static void wow64_consumer(void) {
    reset();WOW64_CONTEXT ctx;memset(&ctx,0xa5,sizeof ctx);
    copies_reset();CHECK(!Wow64GetThreadContext(H(th),NULL)&&last_error==ERROR_NOACCESS);CHECK(!read_calls&&!write_calls);
    const uint32_t rights[]={0,0x20,0x40,0x800,0x840};
    for(unsigned i=0;i<5;++i) {
        access_of(th,rights[i]);copies_reset();
        CHECK(!Wow64GetThreadContext(H(th),&ctx));
        CHECK(last_error==((rights[i]&0x840)?ERROR_INVALID_PARAMETER:ERROR_ACCESS_DENIED));
        CHECK(all_poison(&ctx,sizeof ctx));
    }
    CHECK(!Wow64GetThreadContext(H(eh),&ctx)&&last_error==ERROR_INVALID_HANDLE);
}

static void public_contracts(void) {
    reset();metadata_literals();MEMORY_PRIORITY_INFORMATION m={2};
    PROCESS_POWER_THROTTLING_STATE p={1,1,1};THREAD_POWER_THROTTLING_STATE t={1,1,1};BOOL boost=42;GROUP_AFFINITY ga;
    copies_reset();CHECK(!GetThreadPriorityBoost(H(th),NULL)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!GetThreadGroupAffinity(H(th),NULL)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!GetProcessInformation(H(ph),ProcessMemoryPriority,NULL,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetProcessInformation(H(ph),ProcessMemoryPriority,NULL,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!GetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)0,NULL,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)0,NULL,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!read_calls&&!write_calls);
    for(unsigned n=0;n<=16;++n)if(n!=4) {
        copies_reset();CHECK(!GetProcessInformation(H(0),ProcessMemoryPriority,&m,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!SetProcessInformation(H(0),ProcessMemoryPriority,&m,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!GetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)0,&m,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!SetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)0,&m,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!read_calls&&!write_calls);
    }
    for(unsigned n=0;n<=16;++n)if(n!=12) {
        copies_reset();CHECK(!GetProcessInformation(H(0),ProcessPowerThrottling,&p,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!SetProcessInformation(H(0),ProcessPowerThrottling,&p,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!GetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)3,&t,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!SetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)3,&t,n)&&last_error==ERROR_BAD_LENGTH);
        CHECK(!read_calls&&!write_calls);
    }
    p.Version=t.Version=0;copies_reset();
    CHECK(!GetProcessInformation(H(0),ProcessPowerThrottling,&p,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetProcessInformation(H(0),ProcessPowerThrottling,&p,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!GetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)3,&t,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetThreadInformation(H(0),(THREAD_INFORMATION_CLASS)3,&t,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!read_calls&&!write_calls);
    p.Version=t.Version=1;p.ControlMask=2;p.StateMask=0;t.ControlMask=2;t.StateMask=0;
    CHECK(!SetProcessInformation(H(ph),ProcessPowerThrottling,&p,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)3,&t,12)&&last_error==ERROR_INVALID_PARAMETER);
    p.ControlMask=t.ControlMask=0;p.StateMask=t.StateMask=1;
    CHECK(!SetProcessInformation(H(ph),ProcessPowerThrottling,&p,12)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)3,&t,12)&&last_error==ERROR_INVALID_PARAMETER);
    p.ControlMask=p.StateMask=5;t.ControlMask=t.StateMask=1;
    CHECK(SetProcessInformation(H(ph),ProcessPowerThrottling,&p,12));CHECK(procs[2].power_control==5&&procs[2].power_state==5);
    CHECK(SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)3,&t,12));CHECK(threads[1].power_control==1&&threads[1].power_state==1);
    CHECK(GetProcessInformation(H(ph),ProcessPowerThrottling,&p,12));CHECK(p.Version==1&&p.ControlMask==5&&p.StateMask==5);
    CHECK(GetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)3,&t,12));CHECK(t.Version==1&&t.ControlMask==1&&t.StateMask==1);
    CHECK(SetThreadPriorityBoost(H(th),42));CHECK(threads[1].boost_disabled==1);
    CHECK(GetThreadPriorityBoost(H(th),&boost)&&boost==TRUE);CHECK(GetThreadGroupAffinity(H(th),&ga)&&ga.Mask==1);
    copies_reset();CHECK(!SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)2,&m,4)&&last_error==ERROR_NOT_SUPPORTED);
    CHECK(!GetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)2,&m,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!SetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)1,&m,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!GetProcessInformation(H(ph),(PROCESS_INFORMATION_CLASS)0xeeee,&m,4)&&last_error==ERROR_INVALID_PARAMETER);
    CHECK(!read_calls&&!write_calls);
    procs[2].terminated=1;procs[2].teardown=2;threads[1].state=TS_ZOMBIE;
    CHECK(!SetThreadPriorityBoost(H(th),FALSE)&&last_error==ERROR_ACCESS_DENIED);
    CHECK(!SetProcessInformation(H(ph),ProcessMemoryPriority,&m,4)&&last_error==ERROR_ACCESS_DENIED);
    access_of(ph,0);access_of(th,0);memset(&p,0xa5,sizeof p);p.Version=1;memset(&t,0xa5,sizeof t);t.Version=1;
    CHECK(!GetProcessInformation(H(ph),ProcessPowerThrottling,&p,12)&&last_error==ERROR_ACCESS_DENIED);
    CHECK(p.Version==1&&p.ControlMask==0xa5a5a5a5&&p.StateMask==0xa5a5a5a5);
    CHECK(!GetThreadInformation(H(th),(THREAD_INFORMATION_CLASS)3,&t,12)&&last_error==ERROR_ACCESS_DENIED);
    CHECK(t.Version==1&&t.ControlMask==0xa5a5a5a5&&t.StateMask==0xa5a5a5a5);
}
int main(void) {
    /* Macro feature handling only keeps unchanged schema adapters compilable.
     * Behavioral cold/detached/rights/strict-selector expectations never skip. */
    CHECK(HOST_HAS_SET_LIMITED);
#if HOST_HAS_SET_LIMITED
    _Static_assert(THREAD_SET_LIMITED_INFORMATION==ORACLE_THREAD_SET_LIMITED,"actual named set-limited right");
#endif
    rights_queries();buffers_and_faults();bad_handles();attached_identity();memory_range_and_defaults();setters_rights_and_widths();
    setters_invalid_and_liveness();detached_and_retained();caller_departures();pseudo_identity();public_contracts();wow64_consumer();
    CHECK(!irq_depth);dispose();
    printf("NT_SETTINGS_HOST: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
