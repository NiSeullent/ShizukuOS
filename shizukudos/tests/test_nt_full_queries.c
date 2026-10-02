/* SPDX-License-Identifier: GPL-2.0-only
 * Actual selected production bodies and complete process/object/TCB/module
 * schemas. Host boundaries: IRQ exclusion, user copies, static kernel memory,
 * heap allocation, current-thread/thread-slot and VirtualQuery platform calls.
 * Actual refs, handle close/final process-free, loader enumeration/release and
 * UTF/volume conversion execute. Module graph/image retirement providers below
 * are refusal/counter adapters; fixture publication explicitly writes static
 * module/process storage. This is UP host evidence, not native loader or SMP.
 * Departure occurs only at old unguarded PID lookup, list ReturnLength copy,
 * or path-copy entry. No generic IRQ-entry preemption hook exists. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntsys.h"
#include "thread-layout.inc"
#include "process-layout.inc"
#include "module-layout.inc"
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
#include "api-layout.inc"
typedef void *HANDLE, *PVOID, *LPVOID;
typedef int BOOL;
typedef uint8_t BOOLEAN;
typedef uint16_t WCHAR, *LPWSTR;
typedef uint32_t DWORD, ULONG;
typedef uint64_t ULONG64, ULONG_PTR;
typedef size_t SIZE_T;
typedef int32_t NTSTATUS;
#include "policy-layout.inc" /* actual pinned MinGW SDK enum and DEP layout */
typedef struct { LPVOID BaseAddress,AllocationBase; DWORD AllocationProtect; SIZE_T RegionSize; DWORD State,Protect,Type; } MEMORY_BASIC_INFORMATION;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define HEAP_ZERO_MEMORY 8u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOACCESS 998u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_BAD_LENGTH 24u
#define ERROR_UNEXP_NET_ERR 59u
#define ERROR_FILE_INVALID 1006u
static unsigned checks,failures,irq_depth;
#define CHECK(x) do { ++checks; if(!(x)) { ++failures; if(failures<70) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
#define KASSERT(x) CHECK(x)
static process_t procs[MAX_PROCS+1];
static handle_entry_t handle_tables[2][16];
static kobject_t objects[8],*named_head,*timers_head[16];
static unsigned timer_count,freed_heap,destroyed_vads,edge_frees;
static thread_t slots[3];
static module_t modules[3];
static uint32_t ph,th;
static DWORD last_error;
static uint64_t reject_read,reject_write;
static unsigned read_calls,last_read_size,write_calls;
static unsigned heap_allocs,heap_frees,heap_live,heap_fail;
static unsigned query_depth,active_class;
static uint64_t active_buffer,active_retlen;
static unsigned pid_depart,list_depart,path_depart,events,held_snapshots,guarded_snapshots,path_guarded,path_held;
static unsigned close_at_output,close_events,republish_at_output;
static uint64_t closing_handle;
static unsigned virtual_state=MEM_FREE;
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) { CHECK(irq_depth==f+1); irq_depth=(unsigned)f; }
static void kfree(void *p) { if(p) ++freed_heap; } /* static storage: observe real release without freeing C globals */
static void vad_destroy(process_t *p) { CHECK(p->teardown==2); ++destroyed_vads; }
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
static void image_owner_retire(image_map_t *im) { (void)im; CHECK(0); } /* these fixtures have no lazy image */
static void module_edges_free(module_t *m) { CHECK(!m->life.edges); ++edge_frees; }
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void ipc_object_free(kobject_t *o);
void ipc_handle_closed(process_t *p,kobject_t *o);
int32_t handle_close(process_t *p,uint64_t h);
void ldr_release_modules(process_t *p);
static thread_t *thread_current(void) { return &slots[0]; } /* current CPU platform binding */
static thread_t *thread_slot(unsigned i) { return i<3?&slots[i]:NULL; }
static uint64_t thread_cycles_now(thread_t *t) { (void)t; CHECK(0); return 0; } /* Q3 never requests accounting */
static void depart_at_pid_lookup(process_t *p);
static void depart_at_list_copy(void);
static void depart_at_path_copy(const char *src);
static void depart_at_output(process_t *p);
static void observe_path_copy(const char *src) {
    if(active_class==18 && src==modules[0].path) {
        path_guarded += irq_depth!=0; path_held += objects[1].refs>1;
    }
}
static void observe_module_snapshot(process_t *p) {
    if(query_depth && p==&procs[2]) {
        guarded_snapshots += irq_depth!=0;
        held_snapshots += objects[1].refs>1;
    }
}
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; CHECK(irq_depth==0); ++read_calls; last_read_size=(unsigned)n;
    if(!src||src==reject_read) return -1;
    memcpy(dst,(void *)(uintptr_t)src,(size_t)n); return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    CHECK(irq_depth==0); ++write_calls;
    if(active_class==5 && active_buffer && dst==active_retlen) depart_at_list_copy();
    if(close_at_output && active_class==18 && n==272 && dst==active_buffer) {
        close_at_output=0; ++close_events;
        depart_at_output(p);
    }
    if(!dst||dst==reject_write) return -1;
    memcpy((void *)(uintptr_t)dst,src,(size_t)n); return 0;
}
static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen);
static NTSTATUS NtShzQueryK32(ULONG cls,HANDLE h,void *b,ULONG n,ULONG *r) {
    ++query_depth; active_class=cls; active_buffer=(uintptr_t)b; active_retlen=(uintptr_t)r;
    NTSTATUS s=host_query(&procs[1],cls,(uintptr_t)h,(uintptr_t)b,n,(uintptr_t)r);
    --query_depth; active_class=0; return s;
}
static void shz_set_last_error(DWORD e) { last_error=e; }
static DWORD RtlNtStatusToDosError(NTSTATUS s) { /* transport status-map platform adapter, not selected feature */
    return s==STATUS_ACCESS_DENIED?5:s==STATUS_INVALID_HANDLE||s==STATUS_OBJECT_TYPE_MISMATCH?6:
      s==STATUS_ACCESS_VIOLATION?998:s==STATUS_BUFFER_TOO_SMALL?122:s==STATUS_INVALID_CID?87:87;
}
static DWORD GetCurrentProcessId(void) { return (DWORD)procs[1].pid; }
static HANDLE ShzProcessHeap(void) { return (HANDLE)(uintptr_t)1; }
static PVOID RtlAllocateHeap(HANDLE h,ULONG flags,SIZE_T n) {
    (void)h; ++heap_allocs; if(heap_fail) return NULL;
    unsigned char *b=malloc(n); if(!b) return NULL; ++heap_live;
    memset(b,flags&HEAP_ZERO_MEMORY?0:0xa5,n);
    /* Deliberate known heap poison: an uncopied module-list row looks like a
     * valid decoy, safely bounded. This is allocator reuse, not a fake list. */
    if(!(flags&HEAP_ZERO_MEMORY)) for(SIZE_T i=0;i+192<=n;i+=192) {
        uint64_t base=0x400000,size=0x2000;
        memcpy(b+i,&base,8); memcpy(b+i+8,&size,8);
        memset(b+i+16,0,176); memcpy(b+i+64,"\\DECOY.DLL",11);
    }
    return b;
}
static BOOL RtlFreeHeap(HANDLE h,ULONG f,PVOID b) { (void)h;(void)f; if(b) { ++heap_frees;CHECK(heap_live>0);--heap_live;free(b); } return TRUE; }
static SIZE_T VirtualQuery(LPVOID a,MEMORY_BASIC_INFORMATION *m,SIZE_T n) { (void)a;CHECK(n==sizeof *m);memset(m,0,sizeof *m);m->State=virtual_state;return sizeof *m; }
#include "production.inc"
typedef struct { uint64_t address; uint32_t pid,reserved; char path[256]; } expected_packet;
_Static_assert(sizeof(expected_packet)==272,"chosen private packet ABI");
_Static_assert(sizeof(SHZ_K32_MAPPED_FILE_PATH)==272,"actual frontend packet ABI");
_Static_assert(offsetof(SHZ_K32_MAPPED_FILE_PATH,address)==0&&offsetof(SHZ_K32_MAPPED_FILE_PATH,pid)==8&&offsetof(SHZ_K32_MAPPED_FILE_PATH,reserved)==12&&offsetof(SHZ_K32_MAPPED_FILE_PATH,path)==16,"actual frontend packet field offsets");
_Static_assert(sizeof(PROCESS_MITIGATION_DEP_POLICY)==8,"actual SDK DEP policy ABI");
_Static_assert(PATH_CAP==256,"actual loader path capacity");
static HANDLE H(uint64_t h) { return (HANDLE)(uintptr_t)h; }
static NTSTATUS q(unsigned c,uint64_t h,void *b,unsigned n,ULONG *r) { return NtShzQueryK32(c,H(h),b,n,r); }
static void publish_module(unsigned i,uint64_t base,const char *path) {
    module_t *m=&modules[i]; memset(m,0,sizeof *m);m->state=1;m->published=1;m->base=base;
    m->info.size_of_image=0x2000;strcpy(m->name,"fixture.dll");
    CHECK(strlen(path)<sizeof m->path);strcpy(m->path,path);
}
static void reset(void) {
    CHECK(!irq_depth&&!heap_live);memset(procs,0,sizeof procs);memset(handle_tables,0,sizeof handle_tables);
    memset(objects,0,sizeof objects);memset(slots,0,sizeof slots);memset(modules,0,sizeof modules);
    freed_heap=destroyed_vads=edge_frees=timer_count=0;named_head=NULL;
    read_calls=last_read_size=write_calls=heap_allocs=heap_frees=heap_fail=0;
    query_depth=active_class=pid_depart=list_depart=path_depart=events=held_snapshots=guarded_snapshots=path_guarded=path_held=0;
    active_buffer=active_retlen=reject_read=reject_write=close_at_output=close_events=republish_at_output=closing_handle=0;
    last_error=0;virtual_state=MEM_FREE;
    for(unsigned i=0;i<2;++i) {
        process_t *p=&procs[i+1];p->used=1;p->pid=100+(int)i;p->parent_pid=99;
        p->handles=handle_tables[i];p->handle_cap=16;p->object=&objects[i];
        objects[i].type=OB_PROCESS;objects[i].refs=1;objects[i].u.proc.p=p;
    }
    slots[0].state=TS_RUNNING;slots[0].proc=&procs[1];slots[0].object=&objects[2];
    objects[2].type=OB_THREAD;objects[2].refs=1;objects[2].u.thr.t=&slots[0];
    CHECK(handle_insert(&procs[1],&objects[1],0x1400,&ph)==0);
    CHECK(handle_insert(&procs[1],&objects[2],0x840,&th)==0);
    publish_module(0,0x400000,"\\ORIGINAL.EXE");publish_module(1,0x700000,"D:\\OTHER.DLL");
    modules[1].next=&modules[0];procs[2].modules=&modules[1];procs[2].image_base=0x400000;
}
static void drop_constructor(void) { CHECK(objects[1].refs==2);ob_deref(&objects[1]);CHECK(objects[1].refs==1); }
static void depart_at_pid_lookup(process_t *p) {
    if(!pid_depart||irq_depth||p!=&procs[2]) return;
    if(query_depth&&active_class==5&&!active_buffer) return; /* initial size pass cannot leak a copied row */
    pid_depart=0;++events;uint64_t f=irq_save();ldr_release_modules(p);p->terminated=1;p->teardown=2;irq_restore(f);
    CHECK(handle_close(&procs[1],ph)==0);CHECK(!p->used&&objects[1].refs==0&&destroyed_vads==1);
    /* Explicit fixture publication after actual last-ref process-free. */
    memset(p,0,sizeof *p);p->used=1;p->pid=202;p->handles=handle_tables[1];p->handle_cap=16;
    p->object=&objects[4];objects[4].type=OB_PROCESS;objects[4].refs=1;objects[4].u.proc.p=p;
    publish_module(0,0x400000,"\\REPLACEMENT.EXE");p->modules=&modules[0];p->image_base=0x400000;
}
static void depart_at_list_copy(void) {
    if(!list_depart||irq_depth) return;
    list_depart=0;++events;uint64_t f=irq_save();ldr_release_modules(&procs[2]);irq_restore(f);
}
static void depart_at_path_copy(const char *src) {
    if(!path_depart||irq_depth||src!=modules[0].path) return;
    path_depart=0;++events;uint64_t f=irq_save();ldr_release_modules(&procs[2]);
    publish_module(0,0x400000,"\\REPLACEMENT.EXE");procs[2].modules=&modules[0];irq_restore(f);
}
static void depart_at_output(process_t *cur) {
    process_t *p=&procs[2];uint64_t f=irq_save();
    ldr_release_modules(p);p->terminated=1;p->teardown=2;irq_restore(f);
    CHECK(handle_close(cur,closing_handle)==0);
    CHECK(!p->used&&!objects[1].refs&&destroyed_vads==1);
    if(republish_at_output) {
        republish_at_output=0;
        /* Actual final free precedes explicit fixture overwrite/publication.
         * The same module/process storage now belongs to another owner. */
        memset(p,0,sizeof *p);p->used=1;p->pid=202;p->object=&objects[4];
        p->handles=handle_tables[1];p->handle_cap=16;
        objects[4].type=OB_PROCESS;objects[4].refs=1;objects[4].u.proc.p=p;
        publish_module(0,0x400000,"\\REPLACEMENT.EXE");p->modules=&modules[0];
    }
}
static int eq_ascii(const WCHAR *w,const char *s) {
    unsigned i=0;for(;s[i];++i) if(w[i]!=(unsigned char)s[i]) return 0;return w[i]==0;
}
static void guard_w(WCHAR *w,unsigned n) { for(unsigned i=0;i<n;++i) w[i]=0x5a5a; }
static void rights(void) {
    static const uint32_t access[]={0x400,0x1400,0x1000,0x200,0x10,0,0x100000};
    for(unsigned i=0;i<7;++i) {
        reset();procs[1].handles[ph/4-1].access=access[i];BOOL allow=i<2;
        unsigned refs=objects[1].refs;PROCESS_MITIGATION_DEP_POLICY dep;memset(&dep,0x5a,sizeof dep);
        CHECK(GetProcessMitigationPolicy(H(ph),ProcessDEPPolicy,&dep,sizeof dep)==allow);
        if(allow) CHECK(dep.Enable&&dep.Permanent&&!dep.DisableAtlThunkEmulation);
        else CHECK(last_error==5&&dep.Flags==0x5a5a5a5a);
        WCHAR w[400];guard_w(w,400);DWORD n=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400001,w,400);
        CHECK((n!=0)==allow);
        if(allow) CHECK(eq_ascii(w,"\\Device\\HarddiskVolume1\\ORIGINAL.EXE"));
        else CHECK(last_error==5&&w[0]==0x5a5a);
        expected_packet p={0};p.address=0x400001;ULONG rl=77;
        CHECK(q(17,ph,NULL,0,&rl)==(allow?0:STATUS_ACCESS_DENIED));CHECK(rl==(allow?0:77));
        rl=77;CHECK(q(18,ph,&p,sizeof p,&rl)==(allow?0:STATUS_ACCESS_DENIED));
        if(allow) CHECK(rl==272&&p.pid==101&&!p.reserved&&!strcmp(p.path,"\\ORIGINAL.EXE"));
        else CHECK(rl==77&&p.pid==0);
        ULONG info[6]={0};CHECK(q(3,ph,info,sizeof info,NULL)==(i<3?0:STATUS_ACCESS_DENIED));
        CHECK(objects[1].refs==refs&&!irq_depth&&!heap_live);
    }
    reset();PROCESS_MITIGATION_DEP_POLICY dep={0};CHECK(GetProcessMitigationPolicy(H(CURRENT_PROCESS_HANDLE),ProcessDEPPolicy,&dep,sizeof dep));
    CHECK(q(17,CURRENT_PROCESS_HANDLE,NULL,0,NULL)==0);
}
static void policies(void) {
    reset();unsigned refs=objects[1].refs;
    for(int pol=0;pol<MaxProcessMitigationPolicy;++pol) {
        unsigned n=pol==ProcessDEPPolicy?8:pol==ProcessMitigationOptionsMask?16:4;
        uint8_t b[24];memset(b,0x5a,sizeof b);
        CHECK(GetProcessMitigationPolicy(H(ph),(PROCESS_MITIGATION_POLICY)pol,b,n));
        if(pol!=ProcessDEPPolicy) for(unsigned j=0;j<n;++j) CHECK(!b[j]);
        CHECK(b[n]==0x5a);
    }
    for(unsigned n=0;n<18;++n) {
        uint8_t b[24];memset(b,0x5a,sizeof b);BOOL allow=n==8||n==16;
        CHECK(GetProcessMitigationPolicy(H(ph),ProcessMitigationOptionsMask,b,n)==allow);
        if(!allow) CHECK(last_error==87&&b[0]==0x5a);
    }
    uint8_t b[16];memset(b,0x5a,sizeof b);
    CHECK(!GetProcessMitigationPolicy(H(ph),(PROCESS_MITIGATION_POLICY)-1,b,4)&&last_error==87);
    CHECK(!GetProcessMitigationPolicy(H(ph),MaxProcessMitigationPolicy,b,4)&&last_error==87);
    CHECK(!GetProcessMitigationPolicy(H(ph),ProcessDEPPolicy,NULL,8)&&last_error==87);
    CHECK(!GetProcessMitigationPolicy(H(ph),ProcessDEPPolicy,b,7)&&last_error==87&&b[0]==0x5a);
    CHECK(objects[1].refs==refs&&!irq_depth);
}
static void invalid_handles(void) {
    static const uint64_t bad[]={0,64,68,UINT64_C(0x100000004),UINT64_C(0x100000000)};
    for(unsigned i=0;i<5;++i) for(unsigned c=17;c<=18;++c) {
        reset();expected_packet p;memset(&p,0x5a,sizeof p);ULONG rl=77;unsigned refs=objects[1].refs;
        CHECK(q(c,bad[i],&p,c==17?0:sizeof p,&rl)==STATUS_INVALID_HANDLE);
        CHECK(p.path[0]==0x5a&&rl==77&&objects[1].refs==refs&&!irq_depth);
    }
    for(unsigned c=17;c<=18;++c) {
        reset();expected_packet p={0};p.address=0x400001;ULONG rl=77;
        CHECK(q(c,th,&p,c==17?0:sizeof p,&rl)==STATUS_OBJECT_TYPE_MISMATCH);
        CHECK(q(c,CURRENT_THREAD_HANDLE,&p,c==17?0:sizeof p,&rl)==STATUS_OBJECT_TYPE_MISMATCH);
        CHECK(objects[2].refs==2&&objects[1].refs==2);
        CHECK(handle_close(&procs[1],ph)==0);
        CHECK(q(c,ph,&p,c==17?0:sizeof p,&rl)==STATUS_INVALID_HANDLE);
    }
    for(unsigned tag=0;tag<4;++tag) {
        reset();expected_packet p={0};p.address=0x400001;ULONG rl=77;
        CHECK(q(17,ph|tag,NULL,0,&rl)==0&&rl==0);
        CHECK(q(18,ph|tag,&p,sizeof p,&rl)==0&&rl==272&&p.pid==101);
        CHECK(objects[1].refs==2&&!irq_depth);
    }
    for(unsigned mode=0;mode<4;++mode) for(unsigned c=17;c<=18;++c) {
        reset();expected_packet p={0};p.address=0x400001;ULONG rl=77;
        if(mode==0) procs[2].used=0;
        else if(mode==1) procs[2].object=&objects[4];
        else if(mode==2) objects[1].u.proc.p=NULL;
        else objects[1].u.proc.p=&procs[1];
        CHECK(q(c,ph,&p,c==17?0:sizeof p,&rl)==STATUS_INVALID_HANDLE);
        CHECK(rl==77&&p.pid==0&&objects[1].refs==2&&!irq_depth);
    }
}
static void buffers(void) {
    reset();ULONG rl=77;unsigned refs=objects[1].refs;
    CHECK(q(17,ph,(void *)(uintptr_t)1,0,&rl)==0&&rl==0&&!read_calls);
    rl=77;CHECK(q(17,ph,NULL,1,&rl)==STATUS_INFO_LENGTH_MISMATCH&&rl==77);
    reject_write=(uintptr_t)&rl;CHECK(q(17,ph,NULL,0,&rl)==STATUS_ACCESS_VIOLATION&&rl==77);reject_write=0;
    CHECK(objects[1].refs==refs&&!irq_depth);
    const unsigned sizes[]={0,7,8,271,272,273,320};
    for(unsigned i=0;i<7;++i) {
        reset();uint8_t b[336];memset(b,0x5a,sizeof b);uint64_t a=0x400001;memcpy(b,&a,8);rl=77;
        CHECK(q(18,ph,b,sizes[i],&rl)==(sizes[i]<272?STATUS_BUFFER_TOO_SMALL:0));
        CHECK(rl==272);
        if(sizes[i]<272) CHECK(!read_calls&&b[8]==0x5a);
        else { expected_packet p;memcpy(&p,b,sizeof p);CHECK(read_calls==1&&last_read_size==8&&p.address==a&&p.pid==101&&!p.reserved&&!strcmp(p.path,"\\ORIGINAL.EXE")); }
        CHECK(b[272]==0x5a&&objects[1].refs==2&&!irq_depth);
    }
    reset();expected_packet p={0};p.address=0x400001;rl=77;
    reject_read=(uintptr_t)&p;CHECK(q(18,ph,&p,sizeof p,&rl)==STATUS_ACCESS_VIOLATION&&rl==77);reject_read=0;
    reject_write=(uintptr_t)&p;CHECK(q(18,ph,&p,sizeof p,&rl)==STATUS_ACCESS_VIOLATION&&rl==272&&p.pid==0);reject_write=0;
    rl=77;reject_write=(uintptr_t)&rl;CHECK(q(18,ph,&p,0,&rl)==STATUS_ACCESS_VIOLATION&&rl==77);
    CHECK(q(18,ph,&p,sizeof p,&rl)==STATUS_ACCESS_VIOLATION&&rl==77&&p.pid==0);
    CHECK(!irq_depth&&objects[1].refs==2);
    reject_write=0;rl=77;CHECK(q(18,ph,NULL,272,&rl)==STATUS_ACCESS_VIOLATION&&rl==77);
    CHECK(q(18,ph,NULL,0,&rl)==STATUS_BUFFER_TOO_SMALL&&rl==272);
    CHECK(q(999,ph,&p,sizeof p,&rl)==STATUS_INVALID_INFO_CLASS);
}
static void path_sizes(void) {
    reset();char path[256];path[0]='\\';for(unsigned i=1;i<200;++i) path[i]=(char)('a'+i%26);path[200]=0;
    strcpy(modules[0].path,path);
    char expected[300];strcpy(expected,"\\Device\\HarddiskVolume1");strcat(expected,path);
    unsigned full=(unsigned)strlen(expected);
    const unsigned caps[]={1,2,16,222,223,224,400};
    for(unsigned i=0;i<7;++i) {
        WCHAR w[404];guard_w(w,404);last_error=0xbeef;
        DWORD got=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400000,w+1,caps[i]);
        unsigned copied=full<caps[i]?full:caps[i]-1;
        CHECK(got==(full>=caps[i]?caps[i]:full));
        CHECK(w[0]==0x5a5a&&w[caps[i]+1]==0x5a5a&&w[copied+1]==0);
        for(unsigned j=0;j<copied;++j) CHECK(w[j+1]==(unsigned char)expected[j]);
        if(full>=caps[i]) CHECK(last_error==122);else CHECK(last_error==0xbeef);
        CHECK(!heap_live&&objects[1].refs==2&&!irq_depth);
    }
    WCHAR w[400];guard_w(w,400);CHECK(!K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400000,w,0)&&last_error==87&&w[0]==0x5a5a);
    CHECK(!K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400000,NULL,10)&&last_error==87);
    reset();strcpy(modules[0].path,"D:\\caf\xc3\xa9-\xf0\x9f\x98\x80.dll");guard_w(w,400);
    DWORD n=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400000,w,400);
    const WCHAR suffix[]={'\\','c','a','f',0xe9,'-',0xd83d,0xde00,'.','d','l','l',0};
    CHECK(n==35);CHECK(!memcmp(w+23,suffix,sizeof suffix));CHECK(!heap_live);
}
static void addresses_and_exit(void) {
    const uint64_t addr[]={0x3fffff,0x400000,0x401fff,0x402000,0x700000,UINT64_MAX};
    for(unsigned i=0;i<6;++i) {
        reset();expected_packet p={0};p.address=addr[i];ULONG rl=77;
        CHECK(q(18,ph,&p,sizeof p,&rl)==0&&rl==272&&p.pid==101);
        CHECK((p.path[0]!=0)==(i==1||i==2||i==4));
    }
    reset();modules[0].base=UINT64_MAX-15;modules[0].info.size_of_image=32;procs[2].image_base=modules[0].base;
    expected_packet p={0};p.address=UINT64_MAX-1;CHECK(q(18,ph,&p,sizeof p,NULL)==0&&!strcmp(p.path,"\\ORIGINAL.EXE"));
    WCHAR w[400];guard_w(w,400);CHECK(K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)p.address,w,400)>0&&eq_ascii(w,"\\Device\\HarddiskVolume1\\ORIGINAL.EXE"));
    reset();modules[0].state=0;modules[1].state=2;p.address=0x400001;CHECK(q(18,ph,&p,sizeof p,NULL)==0&&!p.path[0]);
    for(unsigned mode=0;mode<3;++mode) {
        reset();if(mode==0) procs[2].terminated=1;else procs[2].teardown=(int)mode;
        p.address=0x400001;CHECK(q(17,ph,NULL,0,NULL)==0);
        CHECK(q(18,ph,&p,sizeof p,NULL)==0&&p.pid==101&&!p.path[0]);
        guard_w(w,400);CHECK(!K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400001,w,400)&&last_error==1006&&w[0]==0x5a5a);
    }
    reset();procs[1].modules=NULL;guard_w(w,400);
    CHECK(!K32GetMappedFileNameW(H(CURRENT_PROCESS_HANDLE),(void *)(uintptr_t)0x300000,w,400)&&last_error==59);
    virtual_state=0x1000;CHECK(!K32GetMappedFileNameW(H(CURRENT_PROCESS_HANDLE),(void *)(uintptr_t)0x300000,w,400)&&last_error==1006);
}
static void lifetime_and_races(void) {
    /* Self-control: exact old PID seam executes final free before modeled reuse. */
    reset();drop_constructor();pid_depart=1;CHECK(process_by_pid(101)==&procs[2]);
    CHECK(events==1&&destroyed_vads==1&&objects[1].refs==0&&procs[2].pid==202&&procs[2].object==&objects[4]);
    /* Actual mapped wrapper must not expose the replacement owner's path. A
     * legitimate concurrent target departure may refuse or return its snapshot. */
    reset();drop_constructor();pid_depart=1;WCHAR w[400];guard_w(w,400);
    DWORD n=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400001,w,400);
    CHECK(!n||eq_ascii(w,"\\Device\\HarddiskVolume1\\ORIGINAL.EXE"));
    CHECK(!n||!eq_ascii(w,"\\Device\\HarddiskVolume1\\REPLACEMENT.EXE"));
    CHECK(!heap_live&&!irq_depth);printf("PID_SEAM: events=%u returned=%u recycled=%u\n",events,n,destroyed_vads);
    /* Extra real reference alone cannot fix a stale count or module path. */
    reset();drop_constructor();ob_ref(&objects[1]);list_depart=1;guard_w(w,400);
    n=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400001,w,400);
    CHECK(!n||eq_ascii(w,"\\Device\\HarddiskVolume1\\ORIGINAL.EXE"));
    CHECK(!n||!eq_ascii(w,"\\Device\\HarddiskVolume1\\DECOY.DLL"));
    CHECK(objects[1].refs==2&&procs[2].used&&!destroyed_vads&&!heap_live&&!irq_depth);
    ob_deref(&objects[1]);printf("LIST_SEAM: events=%u returned=%u retained=%u\n",events,n,objects[1].refs);
    reset();drop_constructor();path_depart=1;guard_w(w,400);
    n=K32GetMappedFileNameW(H(ph),(void *)(uintptr_t)0x400001,w,400);
    CHECK(!n||eq_ascii(w,"\\Device\\HarddiskVolume1\\ORIGINAL.EXE"));
    CHECK(!n||!eq_ascii(w,"\\Device\\HarddiskVolume1\\REPLACEMENT.EXE"));
    CHECK(guarded_snapshots>0&&held_snapshots>0&&path_guarded>0&&path_held>0&&!irq_depth&&objects[1].refs==1);
    printf("PATH_SEAM: events=%u guarded=%u held=%u path_guarded=%u path_held=%u\n",events,guarded_snapshots,held_snapshots,path_guarded,path_held);
    /* Selected output is local and usable after its handle's actual final free. */
    reset();drop_constructor();procs[2].teardown=2;procs[2].terminated=1;
    close_at_output=1;closing_handle=ph;expected_packet p={0};p.address=0x400001;
    CHECK(q(18,ph,&p,sizeof p,NULL)==0&&p.pid==101&&!p.path[0]);
    CHECK(close_events==1&&!procs[2].used&&objects[1].refs==0&&destroyed_vads==1&&!irq_depth);
    CHECK(q(17,ph,NULL,0,NULL)==STATUS_INVALID_HANDLE);
    /* A LIVE nonempty snapshot must own its bytes across actual final free
     * and deliberate same-storage overwrite at the output-copy boundary. */
    reset();drop_constructor();close_at_output=republish_at_output=1;closing_handle=ph;
    memset(&p,0x5a,sizeof p);p.address=0x400001;
    CHECK(q(18,ph,&p,sizeof p,NULL)==0);
    CHECK(p.address==0x400001&&p.pid==101&&!p.reserved&&!strcmp(p.path,"\\ORIGINAL.EXE"));
    CHECK(close_events==1&&destroyed_vads==1&&!objects[1].refs&&procs[2].pid==202&&procs[2].object==&objects[4]);
    CHECK(!strcmp(modules[0].path,"\\REPLACEMENT.EXE")&&!irq_depth);
    CHECK(q(18,ph,&p,sizeof p,NULL)==STATUS_INVALID_HANDLE);
    /* Retained exit storage is freed only by real close/last dereference. */
    reset();drop_constructor();procs[2].terminated=1;procs[2].teardown=2;
    CHECK(q(17,ph,NULL,0,NULL)==0&&procs[2].used&&objects[1].refs==1);
    CHECK(handle_close(&procs[1],ph)==0&&objects[1].refs==0&&!procs[2].used&&destroyed_vads==1);
    /* Unchanged old Q5 remains PID based and emits the original 192-byte rows. */
    reset();uint8_t b[400];ULONG rl=77;memset(b,0x5a,sizeof b);
    CHECK(q(5,101,b,sizeof b,&rl)==0&&rl==384&&b[384]==0x5a);
    uint64_t base;memcpy(&base,b,8);CHECK(base==0x400000&&!strcmp((char *)b+64,"\\ORIGINAL.EXE"));
    CHECK(objects[1].refs==2&&!irq_depth);
}
int main(void) {
    rights();policies();invalid_handles();buffers();path_sizes();addresses_and_exit();lifetime_and_races();
    CHECK(!irq_depth&&!heap_live);
    printf("NT_FULL_QUERIES_HOST: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
