/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production schemas and bodies execute here. Host adapters provide IRQ,
 * user copy, WALLTIME, allocation and one CPU topology. Actual reference/handle,
 * detach/process-free, accounting, cycles and queue bodies remain unchanged.
 * A definition-only live_threads entry adapter models preemption only when
 * the caller has no outer IRQ guard. ZOMBIE publication is modeled; no native
 * context switch, AP, guest, Windows 98 VMM or physical clock runs. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include "ntsys.h"
#include "thread-layout.inc"
#include "process-layout.inc"
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
#include "api-layout.inc" /* actual access and private kernel class definitions */
#define TICK_100NS ((uint64_t)TICK_US * 10u)
typedef void *HANDLE;
typedef int BOOL;
typedef uint32_t DWORD, ULONG;
typedef int32_t NTSTATUS;
typedef uint64_t ULONG64, DWORD_PTR;
typedef DWORD *PDWORD;
typedef BOOL *PBOOL;
typedef ULONG64 *PULONG64;
typedef DWORD_PTR *PDWORD_PTR;
typedef struct { DWORD dwLowDateTime, dwHighDateTime; } FILETIME, *LPFILETIME;
#define WINAPI
#define K32API
#define TRUE 1
#define FALSE 0
#define ERROR_INVALID_HANDLE 6u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOACCESS 998u
static unsigned checks, failures, irq_depth;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; if(failures<45) fprintf(stderr,"line %d: %s\n",__LINE__,#x); } } while(0)
#define KASSERT(x) CHECK(x)
#include "sched_cpu.h"
#include "smp_acpi.h"
static process_t processes[2];
static handle_entry_t handle_tables[2][16];
static kobject_t objects[12], *named_head, *timers_head[16];
static unsigned timer_count, freed_heap, destroyed_vads;
static thread_t slots[8], *threads=slots, *current, *idle_thread;
static unsigned thread_hi=8;
static uint64_t jiffies, ready_order;
static k64_runqueues_t runqueues;
static shz_smp_topology_t topology;
static uint64_t reject_read, reject_write, clock_epoch=1000000000u;
static unsigned wall_calls, wall_inside, query_depth, snapshot_refs, departure_armed, departure_injected;
static unsigned close_at_copy;
static uint64_t closing_handle;
static DWORD last_error;
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) { CHECK(irq_depth==f+1); irq_depth=(unsigned)f; }
static int64_t filetime_now(void) { ++wall_calls; wall_inside += irq_depth!=0; return (int64_t)(clock_epoch+jiffies*10000u); }
static void kfree(void *p) { if(p) ++freed_heap; } /* static fixture allocations, counters prove actual free paths */
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
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void ipc_object_free(kobject_t *o);
void ipc_handle_closed(process_t *p,kobject_t *o);
thread_t *thread_current(void);
int32_t handle_close(process_t *p,uint64_t h);
static unsigned expected_refs;
static void observe_thread_snapshot(thread_t *t) { if(query_depth && t->object && t->object->refs>expected_refs) ++snapshot_refs; }
static void observe_process_snapshot(process_t *p) { if(query_depth && p->object && p->object->refs>expected_refs) ++snapshot_refs; }
static void depart_at_live_entry(process_t *p);
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; if(!src||src==reject_read) return -1; memcpy(dst,(void *)(uintptr_t)src,(size_t)n); return 0;
}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    CHECK(irq_depth==0); if(close_at_copy) { close_at_copy=0; CHECK(handle_close(p,closing_handle)==0); }
    if(!dst||dst==reject_write) return -1;
    memcpy((void *)(uintptr_t)dst,src,(size_t)n); return 0;
}
static int32_t host_query(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len,uint64_t retlen);
static int32_t host_set(process_t *cur,uint64_t cls,uint64_t h,uint64_t buf,uint64_t len);
static NTSTATUS NtShzQueryK32(ULONG cls,HANDLE h,void *b,ULONG n,ULONG *rl) {
    ++query_depth; int32_t s=host_query(&processes[0],cls,(uintptr_t)h,(uintptr_t)b,n,(uintptr_t)rl); --query_depth; return s;
}
static NTSTATUS NtShzSetK32(ULONG cls,HANDLE h,void *b,ULONG n) { return host_set(&processes[0],cls,(uintptr_t)h,(uintptr_t)b,n); }
static void shz_set_last_error(DWORD e) { last_error=e; }
static DWORD k32_nt_error(NTSTATUS s) {
    DWORD e=s==STATUS_ACCESS_DENIED||s==STATUS_PROCESS_IS_TERMINATING?ERROR_ACCESS_DENIED:
      s==STATUS_INVALID_HANDLE||s==STATUS_OBJECT_TYPE_MISMATCH?ERROR_INVALID_HANDLE:
      s==STATUS_ACCESS_VIOLATION?ERROR_NOACCESS:ERROR_INVALID_PARAMETER;
    shz_set_last_error(e); return e;
}
#include "production.inc"
static HANDLE H(uint64_t h) { return (HANDLE)(uintptr_t)h; }
static uint64_t ft(FILETIME t) { return ((uint64_t)t.dwHighDateTime<<32)|t.dwLowDateTime; }
static uint32_t ph,th;
static void reset(void) {
    CHECK(irq_depth==0); memset(processes,0,sizeof processes); memset(handle_tables,0,sizeof handle_tables);
    memset(objects,0,sizeof objects); memset(slots,0,sizeof slots); memset(&topology,0,sizeof topology);
    topology.count=1; topology.apic_id[0]=initial_apic_id(); k64_rq_init(&runqueues,slots,8,1);
    ready_order=0; jiffies=100; query_depth=0; snapshot_refs=0; departure_armed=departure_injected=0;
    close_at_copy=0; reject_read=reject_write=0; last_error=0; named_head=NULL; timer_count=0;
    freed_heap=destroyed_vads=0;
    for(unsigned i=0;i<8;++i) slots[i].ready_cpu=slots[i].on_cpu=K64_CPU_NONE;
    for(unsigned i=0;i<2;++i) {
        process_t *p=&processes[i]; p->used=1; p->pid=100+(int)i; p->parent_pid=99; p->create_tick=2;
        p->handles=handle_tables[i]; p->handle_cap=16; p->object=&objects[i];
        objects[i].type=OB_PROCESS; objects[i].refs=1; objects[i].u.proc.p=p;
    }
    current=&slots[0]; idle_thread=&slots[7]; current->state=TS_RUNNING; current->on_cpu=0;
    current->proc=&processes[0]; current->object=&objects[2]; objects[2].type=OB_THREAD; objects[2].refs=1;
    objects[2].u.thr.t=current; objects[2].u.thr.pid=100;
    runqueues.cpu[0].current=current; runqueues.cpu[0].idle=idle_thread;
    thread_t *t=&slots[1]; t->state=TS_READY; t->proc=&processes[1]; t->object=&objects[3];
    t->create_tick=3; t->user_ticks=3; t->kernel_ticks=5; t->cycles=7; t->sched_priority=8;
    t->quantum_ticks=t->quantum_left=6; t->cpu_mask=1; t->mem_priority=5;
    objects[3].type=OB_THREAD; objects[3].refs=1; objects[3].u.thr.t=t; objects[3].u.thr.pid=101;
    ob_ref(processes[1].object); /* actual constructor's thread-owned process ref */
    processes[1].dead_user_ticks=10; processes[1].dead_kernel_ticks=20; processes[1].dead_cycles=30;
    CHECK(handle_insert(&processes[0],processes[1].object,0x1400,&ph)==0);
    CHECK(handle_insert(&processes[0],t->object,0x840,&th)==0);
    uint64_t f=irq_save(); ready_enqueue(t); irq_restore(f);
    expected_refs=processes[1].object->refs;
}
static void depart_at_live_entry(process_t *p) {
    if(!departure_armed || irq_depth || p!=&processes[1]) return;
    departure_armed=0; ++departure_injected;
    const uint64_t f=irq_save(); thread_account_exit(&slots[1]); ready_remove(&slots[1]);
    slots[1].exit_tick=50; slots[1].state=TS_ZOMBIE; /* publication adapter; actual exit is noreturn */
    irq_restore(f);
}
static int32_t q(unsigned c,uint64_t h,void *b,unsigned n,ULONG *r) {
    return NtShzQueryK32(c,H(h),b,n,r);
}
static void rights(void) {
    static const uint32_t pa[]={0x400,0x1000,0x1400,0,0x200,0x100000};
    static const uint32_t ta[]={0x40,0x800,0x840,0,0x20,0x100000};
    for(unsigned i=0;i<6;++i) {
        reset(); processes[0].handles[ph/4-1].access=pa[i]; processes[0].handles[th/4-1].access=ta[i];
        FILETIME c={0},e={0},k={0},u={0}; ULONG64 cy=99; DWORD n=99; BOOL wow=TRUE;
        const BOOL allow=i<3; unsigned pr=objects[1].refs,tr=objects[3].refs;
        CHECK(GetProcessTimes(H(ph),&c,&e,&k,&u)==allow);
        if(allow) CHECK(ft(c)==1000020000u&&ft(k)==250000u&&ft(u)==130000u);
        else CHECK(last_error==ERROR_ACCESS_DENIED);
        CHECK(QueryProcessCycleTime(H(ph),&cy)==allow); if(allow) CHECK(cy==37); else CHECK(cy==99);
        CHECK(GetProcessHandleCount(H(ph),&n)==allow); if(allow) CHECK(n==0); else CHECK(n==99);
        CHECK(IsWow64Process(H(ph),&wow)==allow); if(allow) CHECK(wow==FALSE); else CHECK(wow==TRUE);
        expected_refs=tr;
        CHECK(GetThreadTimes(H(th),&c,&e,&k,&u)==allow);
        if(allow) CHECK(ft(c)==1000030000u&&ft(k)==50000u&&ft(u)==30000u);
        else CHECK(last_error==ERROR_ACCESS_DENIED);
        cy=99; CHECK(QueryThreadCycleTime(H(th),&cy)==allow); if(allow) CHECK(cy==7); else CHECK(cy==99);
        CHECK(objects[1].refs==pr&&objects[3].refs==tr&&irq_depth==0);
        ULONG s[4]={99,99,99,99}; const int32_t settings_st=q(12,th,s,sizeof s,NULL); CHECK(allow ? settings_st==STATUS_SUCCESS&&s[1]==5 : settings_st==STATUS_ACCESS_DENIED&&s[0]==99&&s[1]==99&&s[2]==99&&s[3]==99); /* chosen private Q12 query rights */
    }
    reset(); ULONG64 cy=99; DWORD n=99; BOOL wow=TRUE;
    CHECK(!QueryProcessCycleTime(H(ph),NULL)&&last_error==87);
    CHECK(!QueryThreadCycleTime(H(th),NULL)&&last_error==87);
    CHECK(!GetProcessHandleCount(H(ph),NULL)&&last_error==87);
    CHECK(!IsWow64Process(H(ph),NULL)&&last_error==87);
    CHECK(QueryProcessCycleTime(H(CURRENT_PROCESS_HANDLE),&cy));
    CHECK(QueryThreadCycleTime(H(CURRENT_THREAD_HANDLE),&cy));
    CHECK(GetProcessHandleCount(H(CURRENT_PROCESS_HANDLE),&n)&&n==2);
    CHECK(IsWow64Process(H(CURRENT_PROCESS_HANDLE),&wow)&&wow==FALSE);
}
static void handles_and_buffers(void) {
    static const uint64_t invalid[]={0,64,68,UINT64_C(0x100000004),UINT64_C(0x100000000)};
    static const unsigned cls[]={1,2,3};
    for(unsigned ci=0;ci<3;++ci) for(unsigned hi=0;hi<5;++hi) {
        reset(); uint8_t b[48]; memset(b,0x5a,sizeof b); ULONG rl=99;
        CHECK(q(cls[ci],invalid[hi],b,sizeof b,&rl)==STATUS_INVALID_HANDLE);
        CHECK(b[0]==0x5a&&rl==99&&irq_depth==0);
    }
    for(unsigned ci=0;ci<3;++ci) {
        reset(); unsigned c=cls[ci],need=c==3?24:40; uint64_t h=c==1?th:ph;
        uint8_t b[48]; memset(b,0x5a,sizeof b); ULONG rl=99;
        CHECK(q(c,h|3,b,need,&rl)==0&&rl==need);
        CHECK(q(c,c==1?ph:th,b,need,&rl)==STATUS_OBJECT_TYPE_MISMATCH);
        unsigned refs=objects[c==1?3:1].refs;
        memset(b,0x5a,sizeof b); rl=99;
        CHECK(q(c,h,b,need-1,&rl)==STATUS_BUFFER_TOO_SMALL&&rl==need&&b[0]==0x5a);
        CHECK(q(c,h,b,sizeof b,&rl)==0&&rl==need&&b[47]==0x5a);
        reject_write=(uintptr_t)b; CHECK(q(c,h,b,need,&rl)==STATUS_ACCESS_VIOLATION);
        reject_write=(uintptr_t)&rl; CHECK(q(c,h,b,need,&rl)==STATUS_ACCESS_VIOLATION);
        reject_write=0; CHECK(q(c,h,NULL,need,&rl)==STATUS_ACCESS_VIOLATION);
        CHECK(objects[c==1?3:1].refs==refs&&irq_depth==0);
    }
    reset(); uint8_t b[48]; CHECK(q(999,ph,b,sizeof b,NULL)==STATUS_INVALID_INFO_CLASS);
}
static void snapshots(void) {
    reset(); struct times t; expected_refs=objects[1].refs;
    departure_armed=1; CHECK(q(2,ph,&t,sizeof t,NULL)==0);
    CHECK(t.user_100ns==130000&&t.kernel_100ns==250000&&t.cycles==37);
    CHECK(snapshot_refs>0&&departure_injected==0); /* refs alone cannot block injected departure */
    CHECK(irq_depth==0&&runqueues.cpu[0].ready_count==1&&slots[1].ready_queued);
    departure_armed=0; uint64_t f=irq_save();
    if(slots[1].state!=TS_ZOMBIE) { thread_account_exit(&slots[1]); ready_remove(&slots[1]);
        slots[1].state=TS_ZOMBIE; slots[1].exit_tick=50; }
    irq_restore(f);
    CHECK(q(2,ph,&t,sizeof t,NULL)==0&&t.user_100ns==130000&&t.kernel_100ns==250000&&t.cycles==37);
    reset(); expected_refs=objects[3].refs; snapshot_refs=0;
    CHECK(q(1,th,&t,sizeof t,NULL)==0&&snapshot_refs>0);
    reset(); expected_refs=objects[1].refs; snapshot_refs=0; ULONG info[6];
    CHECK(q(3,ph,info,sizeof info,NULL)==0&&snapshot_refs>0);
    CHECK(info[0]==0&&info[1]==1&&info[2]==101&&info[3]==99&&info[4]==0x20&&info[5]==0);
    /* Same protected snapshot survives actual close at the first user copy. */
    reset(); closing_handle=ph; close_at_copy=1;
    CHECK(q(2,ph,&t,sizeof t,NULL)==0&&t.cycles==37);
    CHECK(handle_lookup(&processes[0],ph,OB_PROCESS)==NULL&&objects[1].refs==2);
    CHECK(q(2,ph,&t,sizeof t,NULL)==STATUS_INVALID_HANDLE);
    reset(); current->cycles=11; current->tsc_in=rdtsc(); ULONG64 cyc;
    CHECK(QueryThreadCycleTime(H(CURRENT_THREAD_HANDLE),&cyc)&&cyc>=11); /* actual rdtsc; no elapsed-time conversion */
    CHECK(wall_inside==0);
}
static void lifecycle(void) {
    reset(); struct times t; process_t *p=&processes[1]; thread_t *s=&slots[1];
    uint64_t f=irq_save(); thread_account_exit(s); ready_remove(s); s->state=TS_ZOMBIE; s->exit_tick=50;
    thread_object_detach(s); irq_restore(f);
    CHECK(objects[3].u.thr.t==NULL&&s->object==NULL&&objects[3].refs==1);
    memset(s,0,sizeof *s); s->state=TS_RUNNING; s->proc=&processes[0]; s->user_ticks=999; s->cycles=999;
    CHECK(q(1,th,&t,sizeof t,NULL)==0&&t.cycles==7&&t.user_100ns==30000&&t.exit_ft==1000500000u);
    ULONG settings[4]; CHECK(q(12,th,settings,sizeof settings,NULL)==0&&settings[1]==5);
    p->terminated=1; p->teardown=2; p->exit_tick=50;
    CHECK(q(2,ph,&t,sizeof t,NULL)==0&&t.cycles==37&&t.user_100ns==130000&&t.exit_ft==1000500000u);
    unsigned d=destroyed_vads;
    ob_deref(p->object); /* release production owner; retained process handle pins slot */
    CHECK(p->used&&objects[1].refs==1&&destroyed_vads==d);
    CHECK(handle_close(&processes[0],ph)==0);
    CHECK(!p->used&&p->handles==NULL&&destroyed_vads==d+1); /* actual OB_PROCESS final-ref free */
    p->used=1; p->pid=900; p->object=&objects[4]; objects[4].type=OB_PROCESS; objects[4].refs=1; objects[4].u.proc.p=p;
    p->handles=handle_tables[1]; p->handle_cap=16; p->dead_cycles=888;
    uint32_t reused; CHECK(handle_insert(&processes[0],p->object,0x400,&reused)==0&&reused==ph);
    CHECK(q(2,reused,&t,sizeof t,NULL)==0&&t.cycles==888);
    CHECK(q(1,th,&t,sizeof t,NULL)==0&&t.cycles==7); /* exact host process + native TCB slot reuse */
    CHECK(handle_close(&processes[0],th)==0&&objects[3].refs==0);
    CHECK(q(1,th,&t,sizeof t,NULL)==STATUS_INVALID_HANDLE);
    reset(); p=&processes[1]; p->object=&objects[4];
    CHECK(q(2,ph,&t,sizeof t,NULL)==STATUS_INVALID_HANDLE);
    reset(); processes[1].used=0;
    CHECK(q(3,ph,settings,sizeof settings,NULL)==STATUS_INVALID_HANDLE);
    reset(); slots[1].object=&objects[4]; unsigned tr=objects[3].refs;
    CHECK(q(1,th,&t,sizeof t,NULL)==STATUS_INVALID_HANDLE&&objects[3].refs==tr);
}
static void null_affinity_child(int which) {
    signal(SIGSEGV, SIG_DFL); DWORD_PTR a=99,b=99; last_error=0;
    BOOL ok=GetProcessAffinityMask(H(ph),which?&a:NULL,which?NULL:&b);
    _exit(!ok&&last_error==ERROR_INVALID_PARAMETER?0:2);
}
static void affinity(void) {
    static const uint32_t rights[]={0x200,0x400,0x1000,0x1400,0};
    for(unsigned i=0;i<5;++i) {
        reset(); processes[0].handles[ph/4-1].access=rights[i]; unsigned refs=objects[1].refs;
        CHECK(SetProcessAffinityMask(H(ph),1)==(i==0));
        if(i!=0) CHECK(last_error==ERROR_ACCESS_DENIED);
        DWORD_PTR a=99,b=99; CHECK(GetProcessAffinityMask(H(ph),&a,&b)==(i>0&&i<4));
        if(i>0&&i<4) CHECK(a==1&&b==1); else CHECK(a==99&&b==99&&last_error==ERROR_ACCESS_DENIED);
        CHECK(objects[1].refs==refs&&slots[1].cpu_mask==1&&slots[1].quantum_left==6&&slots[1].ready_queued);
    }
    reset(); processes[0].handles[ph/4-1].access=0x200; uint64_t mask=1;
    unsigned affinity_refs=objects[1].refs;
    CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,8)==0);
    CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,7)==STATUS_INFO_LENGTH_MISMATCH);
    CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,9)==STATUS_INFO_LENGTH_MISMATCH);
    reject_read=(uintptr_t)&mask; CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,8)==STATUS_ACCESS_VIOLATION); reject_read=0;
    CHECK(host_set(&processes[0],14,ph,0,8)==STATUS_ACCESS_VIOLATION);
    for(unsigned i=0;i<3;++i) { mask=i==0?0:i==1?2:UINT64_MAX; CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,8)==STATUS_INVALID_PARAMETER); }
    mask=1; CHECK(host_set(&processes[0],14,th,(uintptr_t)&mask,8)==STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(host_set(&processes[0],14,UINT64_C(0x100000004),(uintptr_t)&mask,8)==STATUS_INVALID_HANDLE);
    CHECK(host_set(&processes[0],14,ph|3,(uintptr_t)&mask,8)==0);
    processes[1].terminated=1; CHECK(!SetProcessAffinityMask(H(ph),1)&&last_error==ERROR_ACCESS_DENIED);
    processes[1].terminated=0; processes[1].teardown=1; CHECK(!SetProcessAffinityMask(H(ph),1)&&last_error==ERROR_ACCESS_DENIED);
    CHECK(objects[1].refs==affinity_refs&&irq_depth==0);
    processes[1].teardown=0; processes[1].exit_owner=current;
    CHECK(!SetProcessAffinityMask(H(ph),1)&&last_error==ERROR_ACCESS_DENIED);
    processes[1].exit_owner=NULL; processes[1].object=&objects[4];
    CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,8)==STATUS_INVALID_HANDLE);
    processes[1].object=&objects[1]; processes[1].used=0;
    CHECK(host_set(&processes[0],14,ph,(uintptr_t)&mask,8)==STATUS_INVALID_HANDLE);
    CHECK(objects[1].refs==affinity_refs&&irq_depth==0);
    reset(); DWORD_PTR a=99,b=99;
    CHECK(!GetProcessAffinityMask(H(64),&a,&b)&&last_error==ERROR_INVALID_HANDLE&&a==99&&b==99);
    CHECK(!GetProcessAffinityMask(H(th),&a,&b)&&last_error==ERROR_INVALID_HANDLE);
    for(int i=0;i<2;++i) {
        pid_t child=fork(); CHECK(child>=0);
        if(child==0) null_affinity_child(i);
        if(child>0) { int s; CHECK(waitpid(child,&s,0)==child); CHECK(WIFEXITED(s)&&WEXITSTATUS(s)==0); }
    }
    CHECK(irq_depth==0);
}
static void category(const char *name,void (*fn)(void)) {
    unsigned c=checks,f=failures; fn(); printf("%s: %u checks, %u failures\n",name,checks-c,failures-f);
}
int main(int argc,char **argv) {
    struct rlimit no_core={0,0}; CHECK(setrlimit(RLIMIT_CORE,&no_core)==0);
    cpu_set_t allowed,one; CHECK(sched_getaffinity(0,sizeof allowed,&allowed)==0);
    unsigned cpu; for(cpu=0;cpu<CPU_SETSIZE;++cpu) if(CPU_ISSET(cpu,&allowed)) break;
    CPU_ZERO(&one); CPU_SET(cpu,&one); CHECK(sched_setaffinity(0,sizeof one,&one)==0);
    printf("host CPU %u; physical CPUID maps to the UP fixture only\n",cpu);
    if(argc>1&&strcmp(argv[1],"normal")) {
        reset(); clock_epoch=!strcmp(argv[1],"clock-zero")?0:UINT64_MAX-499999;
        struct times t; unsigned before=wall_calls;
        CHECK(q(2,ph,&t,sizeof t,NULL)==0); uint64_t first=t.create_ft;
        CHECK(q(2,ph,&t,sizeof t,NULL)==0&&t.create_ft==first);
        CHECK(first==clock_epoch+20000u&&wall_calls==before+1&&wall_inside==0);
    } else { category("rights",rights); category("handles/buffers",handles_and_buffers);
        category("snapshots",snapshots); category("lifecycle",lifecycle); category("affinity",affinity); CHECK(wall_inside==0); }
    printf("NT_TIME_QUERIES_HOST: %u checks, %u failures\n",checks,failures);
    return failures?1:0;
}
