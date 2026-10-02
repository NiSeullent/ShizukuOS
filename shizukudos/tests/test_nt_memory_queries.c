/* SPDX-License-Identifier: GPL-2.0-only
 * Execute selected production query/wrapper, object/reference/final-free,
 * process_teardown, VAD and page-table bodies. Host boundaries are IRQ state,
 * caller copies, bounded physical-frame mapping/allocator, tracked quarantined
 * heap, CR3/invlpg and unselected IPC/loader teardown hooks. Actual close and
 * teardown precede explicit fixture storage republication. Released storage
 * remains allocated until fixture reset; this models stale ownership safely,
 * and is not native physical UAF, allocator, AP or SMP evidence.
 * Departures occur only at an outermost actual sample_peaks restore, actual
 * VAD lookup completion/page lookup entry, or selected caller-copy boundary.
 * No generic first-IRQ preemption hook and no synthetic memory-query result.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntsys.h"
#include "thread-layout.inc"
#include "process-layout.inc"
#include "api-layout.inc"
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
typedef void *HANDLE, *PVOID, *LPVOID;
typedef int BOOL;
typedef uint16_t USHORT;
typedef uint32_t DWORD, ULONG;
typedef uint64_t ULONG64, ULONG_PTR;
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
static unsigned checks, failures, irq_depth;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; if (failures < 100) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while (0)
#define KASSERT(x) CHECK(x)
static process_t procs[MAX_PROCS+1];
static kobject_t objects[8], *named_head, *timers_head[16];
static unsigned timer_count;
static thread_t threads[2];
static uint32_t ph, th;
static vlock_t *vlocks;
static uint64_t kpml4, g_peak_system_commit;
static unsigned inside_sample, walk_context, query_depth, active_class;
static unsigned query_start_refs;
static uint64_t active_buffer, active_retlen, reject_read, reject_write;
static unsigned read_calls, write_calls, sample_arm, vad_arm, lookup_arm, departing;
static unsigned sample_events, vad_events, lookup_events, copy_events;
static unsigned guarded_walks, held_walks, unguarded_walks, guarded_vads, held_vads;
static unsigned stale_frame_reads, frame_frees, array_frees, object_frees;
static unsigned ipc_teardowns, loader_teardowns, cr3_writes, tlb_events;
static unsigned departure_at_output, departure_after_entry, republish_output;
static uint64_t fake_cr3;
static DWORD last_error;
enum { DEPART_REUSE=1, DEPART_TEARDOWN=2 };
enum { FRAME_COUNT=128, HEAP_SLOTS=128 };
#define FRAME_BASE UINT64_C(0x100000)
static uint64_t frames[FRAME_COUNT][512], zero_table[512];
static unsigned char frame_used[FRAME_COUNT];
struct heap_record { void *p; size_t n; int live; };
static struct heap_record heap[HEAP_SLOTS];
static unsigned heap_count;
static void *poison_array;
static void sample_restore_departure(void);
static void depart_at_lookup(uint64_t root);
static void observe_walk(uint64_t root);
static void observe_vad(process_t *p);
static void depart_at_vad(process_t *p);
static void memory_departure(unsigned mode);
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void ipc_object_free(kobject_t *o);
void ipc_handle_closed(process_t *p,kobject_t *o);
void vad_destroy(process_t *p);
int32_t handle_close(process_t *p,uint64_t h);
void process_teardown(process_t *p);
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) {
    CHECK(irq_depth==f+1); irq_depth=(unsigned)f;
    if (!irq_depth && inside_sample && sample_arm && !departing) sample_restore_departure();
}
static uint64_t p2v(uint64_t pa) {
    if (!pa) return (uint64_t)(uintptr_t)zero_table; /* bounded invalid-root observation */
    CHECK(pa>=FRAME_BASE && pa-FRAME_BASE<sizeof frames);
    if (pa<FRAME_BASE || pa-FRAME_BASE>=sizeof frames) return (uint64_t)(uintptr_t)zero_table;
    unsigned i=(unsigned)((pa-FRAME_BASE)/PAGE_SIZE);
    if (walk_context && !frame_used[i]) ++stale_frame_reads;
    return (uint64_t)(uintptr_t)((unsigned char *)frames+(pa-FRAME_BASE));
}
static uint64_t pmm_alloc(void) {
    const uint64_t f=irq_save();
    for (unsigned i=0;i<FRAME_COUNT;++i) if (!frame_used[i]) {
        frame_used[i]=1; memset(frames[i],0,PAGE_SIZE); irq_restore(f);
        return FRAME_BASE+(uint64_t)i*PAGE_SIZE;
    }
    irq_restore(f); return 0;
}
static void pmm_free(uint64_t pa) {
    CHECK(pa>=FRAME_BASE && !(pa&(PAGE_SIZE-1)) && pa-FRAME_BASE<sizeof frames);
    if (pa<FRAME_BASE || pa-FRAME_BASE>=sizeof frames) return;
    unsigned i=(unsigned)((pa-FRAME_BASE)/PAGE_SIZE);
    const uint64_t f=irq_save(); CHECK(frame_used[i]); frame_used[i]=0; ++frame_frees; irq_restore(f);
    /* Released bytes remain quarantined. Actual free_level determines which
     * frames were released; subsequent actual walks expose stale ownership. */
}
static uint64_t pmm_free_count(void) { unsigned n=0; for(unsigned i=0;i<FRAME_COUNT;++i) n+=!frame_used[i]; return n; }
static uint64_t mem_ram_top(void) { return FRAME_COUNT*PAGE_SIZE; }
static size_t kheap_total(void) { return 1024*1024; }
static size_t kheap_used(void) { size_t n=0;for(unsigned i=0;i<heap_count;++i) if(heap[i].live)n+=heap[i].n;return n; }
static void invlpg(uint64_t a) { (void)a; ++tlb_events; }
static uint64_t read_cr3(void) { return fake_cr3; }
static void write_cr3(uint64_t r) { fake_cr3=r; ++cr3_writes; }
static void *kzalloc(size_t n) {
    CHECK(heap_count<HEAP_SLOTS); if(heap_count>=HEAP_SLOTS)return NULL;
    void *p=calloc(1,n); CHECK(p!=NULL); if(!p)return NULL;
    heap[heap_count++]=(struct heap_record){p,n,1}; return p;
}
static void kfree(void *p) {
    if(!p)return;
    if((uintptr_t)p>=(uintptr_t)objects && (uintptr_t)p<(uintptr_t)(objects+8)) { ++object_frees; return; }
    for(unsigned i=0;i<heap_count;++i) if(heap[i].p==p) {
        CHECK(heap[i].live); heap[i].live=0;
        if(p==poison_array) { ++array_frees; memset(p,0xdd,heap[i].n); }
        return;
    }
    CHECK(0); /* no undeclared provider release */
}
static void kprintf(const char *s,...) { (void)s; CHECK(0); }
void reg_key_object_free(kobject_t *o) { (void)o; CHECK(0); }
void token_object_free(kobject_t *o) { (void)o; CHECK(0); }
void file_object_closed(kobject_t *o) { (void)o; CHECK(0); }
void net_socket_handle_closing(kobject_t *o) { (void)o; CHECK(0); }
void ntdrv_device_handle_closing(kobject_t *o) { (void)o; CHECK(0); }
void net_socket_last_handle_closed(kobject_t *o) { (void)o; CHECK(0); }
static void notify_handle_closed(kobject_t *o) { (void)o; CHECK(0); }
static void npfs_handle_closed(kobject_t *o) { (void)o; CHECK(0); }
static void iocp_handle_closed(kobject_t *o) { (void)o; CHECK(0); }
static void job_handle_closed(kobject_t *o) { (void)o; CHECK(0); }
static void ipc_process_teardown(process_t *p) { CHECK(!p->ipc); ++ipc_teardowns; }
static void ldr_release_modules(process_t *p) { CHECK(!p->modules); ++loader_teardowns; }
static thread_t *thread_current(void) { return &threads[0]; }
static thread_t *thread_slot(unsigned i) { return i<2?&threads[i]:NULL; }
static uint64_t thread_cycles_now(thread_t *t) { (void)t; CHECK(0); return 0; }
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; CHECK(!irq_depth); ++read_calls;
    if(!src || src==reject_read)return -1;
    memcpy(dst,(void *)(uintptr_t)src,(size_t)n); return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    (void)p; CHECK(!irq_depth); ++write_calls;
    if(departure_at_output && (active_class==8||active_class==9) && dst==active_buffer) {
        unsigned mode=departure_at_output; departure_at_output=0; ++copy_events;
        memory_departure(mode);
    }
    if(!dst || dst==reject_write)return -1;
    memcpy((void *)(uintptr_t)dst,src,(size_t)n);
    if(departure_after_entry && active_class==9 && n==16 && dst==active_buffer) {
        unsigned mode=departure_after_entry; departure_after_entry=0; ++copy_events; memory_departure(mode);
    }
    return 0;
}
static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen);
static NTSTATUS NtShzQueryK32(ULONG cls,HANDLE h,void *b,ULONG n,ULONG *r) {
    ++query_depth; active_class=cls; active_buffer=(uintptr_t)b; active_retlen=(uintptr_t)r;
    query_start_refs=objects[1].refs;
    NTSTATUS st=host_query(&procs[1],cls,(uintptr_t)h,(uintptr_t)b,n,(uintptr_t)r);
    --query_depth; active_class=0; return st;
}
static void shz_set_last_error(DWORD e) { last_error=e; }
static DWORD RtlNtStatusToDosError(NTSTATUS s) {
    /* Status translation adapter: selected real table is pinned, not executed. */
    return s==STATUS_ACCESS_DENIED||s==STATUS_PROCESS_IS_TERMINATING?ERROR_ACCESS_DENIED:
           s==STATUS_INVALID_HANDLE||s==STATUS_OBJECT_TYPE_MISMATCH?ERROR_INVALID_HANDLE:
           s==STATUS_ACCESS_VIOLATION?ERROR_NOACCESS:s==STATUS_BUFFER_TOO_SMALL?ERROR_INSUFFICIENT_BUFFER:
           s==STATUS_INFO_LENGTH_MISMATCH?ERROR_BAD_LENGTH:ERROR_INVALID_PARAMETER;
}
#include "production.inc"
_Static_assert(sizeof(PROCESS_MEMORY_COUNTERS)==72,"actual x64 SDK PMC");
_Static_assert(sizeof(PROCESS_MEMORY_COUNTERS_EX)==80,"actual x64 SDK PMC EX");
_Static_assert(sizeof(PSAPI_WORKING_SET_EX_BLOCK)==8 && sizeof(PSAPI_WORKING_SET_EX_INFORMATION)==16,"actual x64 SDK working-set entry");
_Static_assert(sizeof(APP_MEMORY_INFORMATION)==32,"actual SDK app memory");
static HANDLE H(uint64_t h) { return (HANDLE)(uintptr_t)h; }
static NTSTATUS q(unsigned c,uint64_t h,void *b,unsigned n,ULONG *r) { return NtShzQueryK32(c,H(h),b,n,r); }
static void dispose(void) {
    CHECK(!irq_depth);
    for(unsigned i=0;i<heap_count;++i)free(heap[i].p);
    memset(heap,0,sizeof heap); heap_count=0;
}
static void publish_target(process_t *p,kobject_t *o,int pid,unsigned pages) {
    memset(p,0,sizeof *p);p->used=1;p->pid=pid;p->object=o;p->pml4=vm_new_space();
    CHECK(p->pml4);p->handles=kzalloc(16*sizeof *p->handles);p->handle_cap=16;
    memset(o,0,sizeof *o);o->type=OB_PROCESS;o->refs=1;o->u.proc.p=p;
    vad_init(p);kfree(p->vads.v);p->vads.cap=2;p->vads.v=kzalloc(2*sizeof(vad_t));p->vads.count=0;
    vad_t a={.start=0x400000,.end=0x400000+(uint64_t)pages*PAGE_SIZE,.state=VAD_COMMITTED,.prot=PAGE_READWRITE,.kind=VK_PRIVATE};
    vad_t b={.start=0x600000,.end=0x601000,.state=VAD_COMMITTED,.prot=PAGE_EXECUTE_READ,.kind=VK_IMAGE};
    CHECK(!vad_insert_at(p,0,&a));CHECK(!vad_insert_at(p,1,&b));
    for(unsigned i=0;i<pages;++i) { uint64_t pa=pmm_alloc();CHECK(pa);CHECK(!vm_map(p->pml4,0x400000+(uint64_t)i*PAGE_SIZE,pa,PT_U|PT_W)); }
    uint64_t pa=pmm_alloc();CHECK(pa);CHECK(!vm_map(p->pml4,0x600000,pa,PT_U));p->page_faults=pid==101?17:9999;
}
static void reset(void) {
    dispose();memset(procs,0,sizeof procs);memset(objects,0,sizeof objects);memset(threads,0,sizeof threads);
    memset(frames,0,sizeof frames);memset(frame_used,0,sizeof frame_used);memset(zero_table,0,sizeof zero_table);
    named_head=NULL;timer_count=inside_sample=walk_context=query_depth=active_class=0;g_peak_system_commit=0;
    read_calls=write_calls=sample_arm=vad_arm=lookup_arm=departing=0;
    sample_events=vad_events=lookup_events=copy_events=0;
    guarded_walks=held_walks=unguarded_walks=guarded_vads=held_vads=0;
    stale_frame_reads=frame_frees=array_frees=object_frees=0;ipc_teardowns=loader_teardowns=cr3_writes=tlb_events=0;
    departure_at_output=departure_after_entry=republish_output=0;
    active_buffer=active_retlen=reject_read=reject_write=0;poison_array=NULL;last_error=0;
    kpml4=pmm_alloc();CHECK(kpml4);publish_target(&procs[1],&objects[0],100,1);publish_target(&procs[2],&objects[1],101,2);
    fake_cr3=procs[1].pml4;
    threads[0].state=TS_RUNNING;threads[0].proc=&procs[1];threads[0].object=&objects[2];
    objects[2].type=OB_THREAD;objects[2].refs=1;objects[2].u.thr.t=&threads[0];
    CHECK(!handle_insert(&procs[1],&objects[1],0x1400,&ph));CHECK(!handle_insert(&procs[1],&objects[2],0x840,&th));
    vlocks=kzalloc(MAX_VLOCKS*sizeof *vlocks);
}
static void drop_constructor(void) { CHECK(objects[1].refs==2);ob_deref(&objects[1]);CHECK(objects[1].refs==1); }
static void memory_departure(unsigned mode) {
    CHECK(!irq_depth&&!departing);departing=1;
    process_t *p=&procs[2];p->terminated=1;process_teardown(p);
    CHECK(p->teardown==2&&p->pml4==kpml4&&frame_frees>0&&ipc_teardowns&&loader_teardowns);
    if(mode==DEPART_REUSE) {
        CHECK(!handle_close(&procs[1],ph));
        if(!objects[1].refs) {
            CHECK(!p->used&&!p->vads.v);publish_target(p,&objects[4],202,5);
        } else CHECK(p->used); /* held query/reference pins slot, not page tables */
    }
    departing=0;
}
static void sample_restore_departure(void) {
    unsigned mode=sample_arm;sample_arm=0;++sample_events;memory_departure(mode);
}
static void observe_walk(uint64_t root) {
    if(query_depth&&(active_class==8||active_class==9)&&root==procs[2].pml4) {
        if(irq_depth)++guarded_walks;else ++unguarded_walks;
        held_walks+=objects[1].refs>query_start_refs;
    }
}
static void observe_vad(process_t *p) {
    if(query_depth&&active_class==9&&p==&procs[2]) { guarded_vads+=irq_depth!=0;held_vads+=objects[1].refs>query_start_refs; }
}
static void depart_at_vad(process_t *p) {
    if(!vad_arm||irq_depth||p!=&procs[2])return;
    vad_arm=0;++vad_events;poison_array=p->vads.v;
    const uint64_t f=irq_save();
    vad_t n={.start=0x800000,.end=0x801000,.state=VAD_RESERVED,.prot=PAGE_NOACCESS,.kind=VK_PRIVATE};
    CHECK(p->vads.count==p->vads.cap);CHECK(!vad_insert_at(p,p->vads.count,&n));
    CHECK(p->vads.v!=poison_array&&array_frees==1);irq_restore(f);
}
static void depart_at_lookup(uint64_t root) {
    if(!lookup_arm||irq_depth||root!=procs[2].pml4)return;
    unsigned mode=lookup_arm;lookup_arm=0;++lookup_events;memory_departure(mode);
}
static int original_snapshot(const uint64_t *m) {
    return m[0]==17&&m[1]==3*PAGE_SIZE&&m[2]==3*PAGE_SIZE&&m[3]==2*PAGE_SIZE&&m[4]==2*PAGE_SIZE;
}
static PSAPI_WORKING_SET_EX_INFORMATION entry(uint64_t a) {
    PSAPI_WORKING_SET_EX_INFORMATION e;e.VirtualAddress=(void *)(uintptr_t)a;e.VirtualAttributes.Flags=UINT64_C(0x5a5a5a5a5a5a5a5a);return e;
}
static void rights(void) {
    const uint32_t masks[]={0x400,0x1000,0x1400,0x10,0x200,0,0x100000,0x410,0x1010,0x210};
    for(unsigned i=0;i<sizeof masks/sizeof *masks;++i) {
        reset();procs[1].handles[ph/4-1].access=masks[i];unsigned refs=objects[1].refs;
        const BOOL memory=(masks[i]&0x1400)!=0, working=(masks[i]&0x400)!=0;
        PROCESS_MEMORY_COUNTERS_EX pm;memset(&pm,0x5a,sizeof pm);last_error=0xbeef;
        CHECK(K32GetProcessMemoryInfo(H(ph),(PPROCESS_MEMORY_COUNTERS)&pm,sizeof pm)==memory);
        if(memory) CHECK(pm.cb==sizeof pm&&pm.PageFaultCount==17&&pm.WorkingSetSize==3*PAGE_SIZE&&pm.PeakWorkingSetSize==3*PAGE_SIZE&&pm.PrivateUsage==2*PAGE_SIZE);
        else CHECK(last_error==5&&pm.cb==0x5a5a5a5a&&pm.PrivateUsage==UINT64_C(0x5a5a5a5a5a5a5a5a));
        APP_MEMORY_INFORMATION app;memset(&app,0x5a,sizeof app);last_error=0xbeef;
        CHECK(GetProcessInformation(H(ph),ProcessAppMemoryInfo,&app,sizeof app)==memory);
        if(memory) CHECK(app.PrivateCommitUsage==2*PAGE_SIZE&&app.PeakPrivateCommitUsage==2*PAGE_SIZE&&app.TotalCommitUsage==2*PAGE_SIZE);
        else CHECK(last_error==5&&app.PrivateCommitUsage==UINT64_C(0x5a5a5a5a5a5a5a5a));
        PSAPI_WORKING_SET_EX_INFORMATION e=entry(0x400001);last_error=0xbeef;
        CHECK(K32QueryWorkingSetEx(H(ph),&e,sizeof e)==working);
        if(working)CHECK(e.VirtualAttributes.Flags==67&&e.VirtualAttributes.Valid&&e.VirtualAttributes.ShareCount==1&&e.VirtualAttributes.Win32Protection==PAGE_READWRITE);
        else CHECK(last_error==5&&e.VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a));
        uint64_t m[5];memset(m,0x5a,sizeof m);ULONG rl=77;
        CHECK(q(8,ph,m,sizeof m,&rl)==(memory?0:STATUS_ACCESS_DENIED));CHECK(rl==(memory?40:77));
        e=entry(0x400000);rl=77;CHECK(q(9,ph,&e,sizeof e,&rl)==(working?0:STATUS_ACCESS_DENIED));CHECK(rl==(working?16:77));
        if(!memory)CHECK(procs[2].peak_ws_pages==0&&procs[2].peak_commit==0);
        CHECK(objects[1].refs==refs&&!irq_depth);
    }
    reset();PROCESS_MEMORY_COUNTERS_EX pm;CHECK(K32GetProcessMemoryInfo(H(CURRENT_PROCESS_HANDLE),(PPROCESS_MEMORY_COUNTERS)&pm,sizeof pm));
    CHECK(pm.WorkingSetSize==2*PAGE_SIZE&&pm.PrivateUsage==PAGE_SIZE&&objects[0].refs==1&&!irq_depth);
    PSAPI_WORKING_SET_EX_INFORMATION e=entry(0x400000);CHECK(K32QueryWorkingSetEx(H(CURRENT_PROCESS_HANDLE),&e,sizeof e)&&e.VirtualAttributes.Flags==67);
}
static void buffers(void) {
    const unsigned lengths[]={0,1,7,39,40,41,56};
    for(unsigned i=0;i<sizeof lengths/sizeof *lengths;++i) {
        reset();uint64_t m[8];memset(m,0x5a,sizeof m);ULONG rl=77;
        CHECK(q(8,ph,m,lengths[i],&rl)==(lengths[i]<40?STATUS_BUFFER_TOO_SMALL:0));CHECK(rl==40);
        if(lengths[i]<40)CHECK(m[0]==UINT64_C(0x5a5a5a5a5a5a5a5a));else CHECK(original_snapshot(m));
        CHECK(m[5]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&m[7]==m[5]&&objects[1].refs==2&&!irq_depth);
    }
    for(unsigned n=0;n<=88;++n) {
        reset();struct { uint64_t before; PROCESS_MEMORY_COUNTERS_EX p; uint64_t after; } b;memset(&b,0x5a,sizeof b);
        BOOL allow=n>=sizeof(PROCESS_MEMORY_COUNTERS);CHECK(K32GetProcessMemoryInfo(H(ph),(PPROCESS_MEMORY_COUNTERS)&b.p,n)==allow);
        CHECK(b.before==UINT64_C(0x5a5a5a5a5a5a5a5a)&&b.after==b.before);
        if(allow) {
            CHECK(b.p.cb==(n>=sizeof b.p?sizeof b.p:sizeof(PROCESS_MEMORY_COUNTERS))&&b.p.PageFaultCount==17&&b.p.PagefileUsage==2*PAGE_SIZE);
            CHECK(b.p.QuotaPagedPoolUsage==0&&b.p.QuotaPeakPagedPoolUsage==0&&b.p.QuotaNonPagedPoolUsage==0&&b.p.QuotaPeakNonPagedPoolUsage==0);
            CHECK(b.p.PrivateUsage==(n>=sizeof b.p?2*PAGE_SIZE:UINT64_C(0x5a5a5a5a5a5a5a5a)));
        } else CHECK(last_error==122&&b.p.cb==0x5a5a5a5a&&!write_calls);
        CHECK(objects[1].refs==2&&!irq_depth);
    }
    reset();CHECK(!K32GetProcessMemoryInfo(H(ph),NULL,80)&&last_error==122);
    APP_MEMORY_INFORMATION app;memset(&app,0x5a,sizeof app);
    CHECK(!GetProcessInformation(H(ph),ProcessAppMemoryInfo,NULL,sizeof app)&&last_error==87);
    CHECK(!GetProcessInformation(H(ph),ProcessAppMemoryInfo,&app,sizeof app-1)&&last_error==24&&app.PrivateCommitUsage==UINT64_C(0x5a5a5a5a5a5a5a5a));
    const unsigned bad[]={0,1,15,17,31};
    for(unsigned i=0;i<sizeof bad/sizeof *bad;++i) {
        reset();PSAPI_WORKING_SET_EX_INFORMATION e[3]={entry(0x400000),entry(0x400000),entry(0x400000)};ULONG rl=77;
        CHECK(q(9,ph,e,bad[i],&rl)==STATUS_INFO_LENGTH_MISMATCH&&rl==77&&!read_calls);
        CHECK(!K32QueryWorkingSetEx(H(ph),e,bad[i])&&last_error==24&&e[0].VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a));
        CHECK(objects[1].refs==2&&!irq_depth);
    }
    reset();uint64_t m[5];memset(m,0x5a,sizeof m);ULONG rl=77;
    reject_write=(uintptr_t)&rl;CHECK(q(8,ph,m,0,&rl)==STATUS_ACCESS_VIOLATION&&rl==77&&m[0]==UINT64_C(0x5a5a5a5a5a5a5a5a));
    CHECK(q(8,ph,m,40,&rl)==STATUS_ACCESS_VIOLATION&&rl==77&&m[0]==UINT64_C(0x5a5a5a5a5a5a5a5a));
    reject_write=(uintptr_t)m;CHECK(q(8,ph,m,40,NULL)==STATUS_ACCESS_VIOLATION);reject_write=0;
    CHECK(q(8,ph,NULL,40,&rl)==STATUS_ACCESS_VIOLATION&&rl==40);
    PSAPI_WORKING_SET_EX_INFORMATION e=entry(0x400000);rl=77;reject_write=(uintptr_t)&rl;
    CHECK(q(9,ph,&e,16,&rl)==STATUS_ACCESS_VIOLATION&&rl==77&&e.VirtualAttributes.Flags==67);reject_write=0;
    reject_read=(uintptr_t)&e;e=entry(0x400000);CHECK(q(9,ph,&e,16,NULL)==STATUS_ACCESS_VIOLATION&&e.VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a));reject_read=0;
    reject_write=(uintptr_t)&e;CHECK(q(9,ph,&e,16,NULL)==STATUS_ACCESS_VIOLATION);reject_write=0;
    CHECK(q(9,ph,NULL,16,NULL)==STATUS_ACCESS_VIOLATION);
    CHECK(!K32QueryWorkingSetEx(H(ph),NULL,16)&&last_error==24);
    CHECK(q(999,ph,m,40,&rl)==STATUS_INVALID_INFO_CLASS&&objects[1].refs==2&&!irq_depth);
    reset();procs[1].handles[ph/4-1].access=0x200;e=entry(0x400000);rl=77;
    reject_read=(uintptr_t)&e;reject_write=(uintptr_t)&rl;
    CHECK(q(9,ph,&e,1,&rl)==STATUS_ACCESS_DENIED&&rl==77&&!read_calls&&!write_calls);
    CHECK(q(9,ph,&e,16,&rl)==STATUS_ACCESS_DENIED&&rl==77&&!read_calls&&!write_calls);
    CHECK(q(8,ph,m,0,&rl)==STATUS_ACCESS_DENIED&&rl==77&&!read_calls&&!write_calls);
    CHECK(objects[1].refs==2&&!irq_depth); /* selected access-first backend ordering */
}
static void handles_and_live_state(void) {
    const uint64_t invalid[]={0,64,68,UINT64_C(0x100000004),UINT64_C(0x100000000)};
    for(unsigned i=0;i<sizeof invalid/sizeof *invalid;++i)for(unsigned c=8;c<=9;++c) {
        reset();uint64_t b[6];memset(b,0x5a,sizeof b);ULONG rl=77;
        CHECK(q(c,invalid[i],b,c==8?40:16,&rl)==STATUS_INVALID_HANDLE);
        CHECK(rl==77&&b[1]==UINT64_C(0x5a5a5a5a5a5a5a5a)&&objects[1].refs==2&&!irq_depth);
    }
    for(unsigned c=8;c<=9;++c)for(unsigned tag=0;tag<4;++tag) {
        reset();uint64_t b[5]={0x400000};ULONG rl=77;
        CHECK(q(c,ph|tag,b,c==8?40:16,&rl)==0&&rl==(c==8?40:16));
        CHECK(objects[1].refs==2&&!irq_depth);
    }
    for(unsigned c=8;c<=9;++c) {
        reset();uint64_t b[5]={0x400000};ULONG rl=77;
        CHECK(q(c,th,b,c==8?40:16,&rl)==STATUS_OBJECT_TYPE_MISMATCH);
        CHECK(q(c,CURRENT_THREAD_HANDLE,b,c==8?40:16,&rl)==STATUS_OBJECT_TYPE_MISMATCH);
        CHECK(objects[2].refs==2&&objects[1].refs==2&&rl==77&&!irq_depth);
        CHECK(!handle_close(&procs[1],ph));CHECK(q(c,ph,b,c==8?40:16,&rl)==STATUS_INVALID_HANDLE);
    }
    for(unsigned mode=0;mode<5;++mode)for(unsigned c=8;c<=9;++c) {
        reset();uint64_t b[5]={0x400000};ULONG rl=77;
        if(mode==0)procs[2].used=0;else if(mode==1)procs[2].object=&objects[4];
        else if(mode==2)objects[1].u.proc.p=NULL;else if(mode==3)objects[1].u.proc.p=&procs[1];else procs[2].pml4=0;
        CHECK(q(c,ph,b,c==8?40:16,&rl)==STATUS_INVALID_HANDLE&&rl==77&&objects[1].refs==2&&!irq_depth&&!read_calls&&!write_calls);
    }
    for(unsigned mode=0;mode<3;++mode)for(unsigned c=8;c<=9;++c) {
        reset();uint64_t b[5]={0x400000};ULONG rl=77;
        if(!mode)procs[2].terminated=1;else procs[2].teardown=(int)mode;
        CHECK(q(c,ph,b,c==8?40:16,&rl)==STATUS_PROCESS_IS_TERMINATING&&rl==77&&objects[1].refs==2&&!irq_depth&&!read_calls&&!write_calls);
    }
    reset();drop_constructor();procs[2].terminated=1;process_teardown(&procs[2]);
    CHECK(procs[2].used&&objects[1].refs==1&&procs[2].teardown==2&&procs[2].pml4==kpml4&&frame_frees>0);
    uint64_t b[5]={0x400000};CHECK(q(8,ph,b,40,NULL)==STATUS_PROCESS_IS_TERMINATING);
    CHECK(q(9,ph,b,16,NULL)==STATUS_PROCESS_IS_TERMINATING);
    PROCESS_MEMORY_COUNTERS_EX pm;memset(&pm,0x5a,sizeof pm);
    CHECK(!K32GetProcessMemoryInfo(H(ph),(PPROCESS_MEMORY_COUNTERS)&pm,sizeof pm)&&last_error==5&&pm.cb==0x5a5a5a5a);
    PSAPI_WORKING_SET_EX_INFORMATION e=entry(0x400000);
    CHECK(!K32QueryWorkingSetEx(H(ph),&e,16)&&last_error==5&&e.VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a));
    CHECK(!handle_close(&procs[1],ph)&&!procs[2].used&&!procs[2].vads.v&&!objects[1].refs);
}
static void real_providers_and_attributes(void) {
    reset();uint64_t m[5];CHECK(!q(8,ph,m,40,NULL)&&original_snapshot(m));
    CHECK(guarded_walks>0&&held_walks>0&&!unguarded_walks&&!stale_frame_reads);
    PSAPI_WORKING_SET_EX_INFORMATION e[5]={entry(0x400000),entry(0x400fff),entry(0x600000),entry(0x800000),entry(UINT64_MAX)};
    ULONG rl=77;CHECK(!q(9,ph,e,sizeof e,&rl)&&rl==sizeof e);
    CHECK(e[0].VirtualAttributes.Flags==67&&e[1].VirtualAttributes.Flags==67&&e[2].VirtualAttributes.Valid&&e[2].VirtualAttributes.Win32Protection==PAGE_EXECUTE_READ);
    CHECK(!e[3].VirtualAttributes.Flags&&!e[4].VirtualAttributes.Flags&&guarded_vads>0&&held_vads>0&&!unguarded_walks);
    vlocks[0]=(vlock_t){&procs[2],procs[2].pid,0x400000};e[0]=entry(0x400000);
    CHECK(!q(9,ph,e,16,NULL)&&e[0].VirtualAttributes.Locked&&e[0].VirtualAttributes.Flags==UINT64_C(0x400043));
    vlocks[0].pid=999;e[0]=entry(0x400000);CHECK(!q(9,ph,e,16,NULL)&&!e[0].VirtualAttributes.Locked);
    CHECK(!vm_protect(procs[2].pml4,0x400000,PT_W));e[0]=entry(0x400000);CHECK(!q(9,ph,e,16,NULL)&&!e[0].VirtualAttributes.Flags);
    CHECK(!vm_protect(procs[2].pml4,0x400000,PT_U|PT_W));
    vlocks[0].pid=procs[2].pid;
    const uint64_t f=irq_save();k32_before_unmap(&procs[2],0x400000,0x402000,1);
    for(uint64_t a=0x400000;a<0x402000;a+=PAGE_SIZE) { uint64_t pa=0;int st=vm_unmap(procs[2].pml4,a,&pa);CHECK(!st);if(!st)pmm_free(pa); }
    vad_remove_at(&procs[2],0);irq_restore(f);
    CHECK(!q(8,ph,m,40,NULL)&&m[1]==PAGE_SIZE&&m[2]==3*PAGE_SIZE&&m[3]==0&&m[4]==2*PAGE_SIZE);
    e[0]=entry(0x400000);CHECK(!q(9,ph,e,16,NULL)&&!e[0].VirtualAttributes.Flags&&objects[1].refs==2&&!irq_depth);
    reset();procs[2].vads.v[0].kind=VK_VIEW;CHECK(!q(8,ph,m,40,NULL)&&m[3]==2*PAGE_SIZE); /* preserve existing provider policy */
    procs[2].page_faults=UINT64_C(0x100000017);PROCESS_MEMORY_COUNTERS_EX pm;
    CHECK(K32GetProcessMemoryInfo(H(ph),(PPROCESS_MEMORY_COUNTERS)&pm,sizeof pm)&&pm.PageFaultCount==23);
    reset();CHECK(!vad_split(&procs[2],0x401000)&&procs[2].vads.count==3);
    CHECK(vad_find(&procs[2],0x400000)->end==0x401000&&vad_find(&procs[2],0x401000)->start==0x401000);
    CHECK(!q(8,ph,m,40,NULL)&&original_snapshot(m));
}
static void lifetime_controls(void) {
    /* Control the exact Q8 seam before asking the query to exclude it. Actual
     * teardown/frame-free/handle-close/final process-free precede publication. */
    reset();drop_constructor();sample_arm=DEPART_REUSE;sample_peaks(&procs[2]);
    CHECK(sample_events==1&&frame_frees>0&&objects[1].refs==0&&procs[2].pid==202&&procs[2].object==&objects[4]);
    CHECK(object_frees==1&&ipc_teardowns==1&&loader_teardowns==1&&!irq_depth);
    reset();drop_constructor();sample_arm=DEPART_REUSE;uint64_t m[5];
    NTSTATUS s=q(8,ph,m,40,NULL);CHECK(s==0&&original_snapshot(m));
    CHECK(sample_events==0&&held_walks>0&&objects[1].refs==1&&procs[2].pid==101&&!irq_depth);
    printf("Q8_REUSE: status=%08x events=%u pid=%d held=%u frames_freed=%u\n",(unsigned)s,sample_events,procs[2].pid,held_walks,frame_frees);
    /* A real extra object reference prevents slot recycling, but cannot stop
     * the actual teardown provider from swapping/freeing its address space. */
    reset();drop_constructor();ob_ref(&objects[1]);fake_cr3=procs[2].pml4;sample_arm=DEPART_TEARDOWN;sample_peaks(&procs[2]);
    CHECK(sample_events==1&&objects[1].refs==2&&procs[2].used&&procs[2].teardown==2&&frame_frees>0&&fake_cr3==kpml4&&cr3_writes==1);
    CHECK(q(8,ph,m,40,NULL)==STATUS_PROCESS_IS_TERMINATING&&objects[1].refs==2);
    reset();drop_constructor();ob_ref(&objects[1]);sample_arm=DEPART_TEARDOWN;
    s=q(8,ph,m,40,NULL);CHECK(s==0&&original_snapshot(m));
    CHECK(sample_events==0&&objects[1].refs==2&&procs[2].used&&!procs[2].teardown&&held_walks>0&&!irq_depth);
    ob_deref(&objects[1]);CHECK(objects[1].refs==1);
    printf("Q8_RETAINED_TEARDOWN: status=%08x events=%u held=%u frames_freed=%u\n",(unsigned)s,sample_events,held_walks,frame_frees);
    /* Self-control proves the actual VAD lookup returns the old array pointer
     * before actual growth releases it. Quarantined bytes make this safe and
     * deterministic, rather than claiming native heap UAF execution. */
    reset();vad_arm=1;vad_t *old=vad_find(&procs[2],0x400000);
    CHECK(vad_events==1&&array_frees==1&&old&&old->prot!=PAGE_READWRITE&&procs[2].vads.v[0].prot==PAGE_READWRITE);
    reset();vad_arm=1;PSAPI_WORKING_SET_EX_INFORMATION e=entry(0x400000);
    s=q(9,ph,&e,16,NULL);CHECK(s==0&&e.VirtualAttributes.Flags==67);
    CHECK(!vad_events&&!array_frees&&guarded_vads>0&&held_vads>0&&!unguarded_walks&&objects[1].refs==2&&!irq_depth);
    printf("Q9_VAD_GROWTH: status=%08x events=%u released_arrays=%u flags=%llx guarded=%u held=%u\n",(unsigned)s,vad_events,array_frees,(unsigned long long)e.VirtualAttributes.Flags,guarded_vads,held_vads);
    /* The page-lookup control retains an extra real reference, tears down the
     * target and executes the unchanged walker on the released original root. */
    reset();ob_ref(&objects[1]);uint64_t root=procs[2].pml4,flags=0;lookup_arm=DEPART_TEARDOWN;
    CHECK(vm_lookup(root,0x400000,&flags)!=0&&lookup_events==1&&frame_frees>0&&stale_frame_reads>0&&objects[1].refs==3&&procs[2].used);
    reset();ob_ref(&objects[1]);lookup_arm=DEPART_TEARDOWN;e=entry(0x400000);
    s=q(9,ph,&e,16,NULL);CHECK(s==0&&e.VirtualAttributes.Flags==67);
    CHECK(!lookup_events&&!frame_frees&&!stale_frame_reads&&held_walks>0&&objects[1].refs==3&&!irq_depth);
    ob_deref(&objects[1]);CHECK(objects[1].refs==2);
    printf("Q9_ROOT_TEARDOWN: status=%08x events=%u stale_frame_reads=%u guarded=%u held=%u\n",(unsigned)s,lookup_events,stale_frame_reads,guarded_walks,held_walks);
    /* Local nonempty Q8 output survives live teardown/final free and explicit
     * overwrite of the original process slot after the snapshot/ref release. */
    reset();drop_constructor();departure_at_output=DEPART_REUSE;
    CHECK(!q(8,ph,m,40,NULL)&&original_snapshot(m));
    CHECK(copy_events==1&&object_frees==1&&!objects[1].refs&&procs[2].pid==202&&procs[2].object==&objects[4]&&!irq_depth);
    printf("Q8_LOCAL_OUTPUT: events=%u original_faults=%llu replacement_faults=%llu\n",copy_events,(unsigned long long)m[0],(unsigned long long)procs[2].page_faults);
    /* The batch keeps its held object through each output; close during the
     * sole local entry releases storage only after dispatch drops that ref. */
    reset();drop_constructor();departure_at_output=DEPART_REUSE;e=entry(0x400000);
    CHECK(!q(9,ph,&e,16,NULL)&&e.VirtualAttributes.Flags==67&&e.VirtualAddress==(void *)(uintptr_t)0x400000);
    CHECK(copy_events==1&&!objects[1].refs&&!procs[2].used&&!procs[2].vads.v&&object_frees==1&&!irq_depth);
    printf("Q9_LOCAL_OUTPUT: events=%u flags=%llx final_free=%u\n",copy_events,(unsigned long long)e.VirtualAttributes.Flags,object_frees);
}
static void batch_progress(void) {
    reset();PSAPI_WORKING_SET_EX_INFORMATION e[3]={entry(0x400000),entry(0x400000),entry(0x800000)};ULONG rl=77;
    departure_after_entry=DEPART_TEARDOWN;NTSTATUS s=q(9,ph,e,sizeof e,&rl);
    CHECK(s==STATUS_PROCESS_IS_TERMINATING&&rl==77&&copy_events==1&&e[0].VirtualAttributes.Flags==67);
    CHECK(e[1].VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a)&&e[2].VirtualAttributes.Flags==e[1].VirtualAttributes.Flags);
    CHECK(objects[1].refs==2&&procs[2].used&&procs[2].teardown==2&&!irq_depth);
    printf("Q9_PARTIAL_DEPARTURE: status=%08x events=%u first=%llx second=%llx reads=%u writes=%u\n",(unsigned)s,copy_events,(unsigned long long)e[0].VirtualAttributes.Flags,(unsigned long long)e[1].VirtualAttributes.Flags,read_calls,write_calls);
    for(unsigned write=0;write<2;++write) {
        reset();e[0]=entry(0x400000);e[1]=entry(0x400000);rl=77;
        if(write)reject_write=(uintptr_t)&e[1];else reject_read=(uintptr_t)&e[1];
        CHECK(q(9,ph,e,32,&rl)==STATUS_ACCESS_VIOLATION&&rl==77&&e[0].VirtualAttributes.Flags==67&&e[1].VirtualAttributes.Flags==UINT64_C(0x5a5a5a5a5a5a5a5a));
        CHECK(objects[1].refs==2&&!irq_depth);
    }
    reset();struct { uint64_t pre;PSAPI_WORKING_SET_EX_INFORMATION e[3];uint64_t post; } b;
    b.pre=b.post=UINT64_C(0x5a5a5a5a5a5a5a5a);for(unsigned i=0;i<3;++i)b.e[i]=entry(0x400000+i);
    rl=77;CHECK(!q(9,ph,b.e,sizeof b.e,&rl)&&rl==sizeof b.e);
    CHECK(b.pre==UINT64_C(0x5a5a5a5a5a5a5a5a)&&b.post==b.pre);
    for(unsigned i=0;i<3;++i)CHECK(b.e[i].VirtualAddress==(void *)(uintptr_t)(0x400000+i)&&b.e[i].VirtualAttributes.Flags==67);
    CHECK(objects[1].refs==2&&!irq_depth);
}
int main(void) {
    rights();buffers();handles_and_live_state();real_providers_and_attributes();lifetime_controls();batch_progress();dispose();
    CHECK(!irq_depth&&!heap_count);
    printf("NT_MEMORY_QUERIES_HOST: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
