/* SPDX-License-Identifier: GPL-2.0-only
 * Host contracts execute extracted, unchanged production function bodies.
 * Fixtures adapt privileged IRQ, process/handle tables, allocation, user-copy,
 * resume, clock and blocking TLS boundaries. Real complete TCB/process/object
 * schemas, queue/policy, CPUID identity, object refs and reclaim bodies run here. The topology fixture maps one
 * permitted host CPU; no AP, hardware context switch or Windows 98 runs. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sched.h>
#include "ntsys.h"
#include "nt_sched_policy.h"
#if __has_include("nt_process_priority.h")
#include "nt_process_priority.h"
#else
/* The pre-implementation RED freezes the independently specified native ABI;
 * this declaration supplies no implementation or conversion algorithm. */
typedef struct { uint8_t Foreground, PriorityClass; } shz_nt_process_priority_t;
#define SHZ_NT_PROCESS_PRIORITY_INFO_CLASS 18u
#endif

#include "thread-layout.inc" /* complete actual production TCB schema */
#define CURRENT_THREAD_HANDLE UINT64_C(0xfffffffffffffffe)
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define THREAD_SET_INFORMATION 0x20u
#define THREAD_QUERY_INFORMATION 0x40u
#define PROCESS_SET_INFORMATION 0x200u
#define PROCESS_QUERY_INFORMATION 0x400u
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define K32S_PRIORITY_CLASS 1
#define K32Q_PROCESS_INFO 3
#include "process-layout.inc" /* actual complete process, VAD, handle and object declarations */
struct regs { uint64_t arg5; };
typedef void *HANDLE;
typedef int BOOL;
typedef int32_t LONG, NTSTATUS;
typedef int64_t LONG64;
typedef uint32_t ULONG, DWORD;
typedef uint64_t ULONG64, DWORD_PTR;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define THREAD_PRIORITY_IDLE (-15)
#define THREAD_PRIORITY_LOWEST (-2)
#define THREAD_PRIORITY_BELOW_NORMAL (-1)
#define THREAD_PRIORITY_NORMAL 0
#define THREAD_PRIORITY_ABOVE_NORMAL 1
#define THREAD_PRIORITY_HIGHEST 2
#define THREAD_PRIORITY_TIME_CRITICAL 15
#define THREAD_PRIORITY_ERROR_RETURN INT32_MAX
#define THREAD_MODE_BACKGROUND_BEGIN 0x10000
#define THREAD_MODE_BACKGROUND_END 0x20000
#define PROCESS_MODE_BACKGROUND_BEGIN 0x100000
#define PROCESS_MODE_BACKGROUND_END 0x200000
#define IDLE_PRIORITY_CLASS 0x40u
#define BELOW_NORMAL_PRIORITY_CLASS 0x4000u
#define NORMAL_PRIORITY_CLASS 0x20u
#define ABOVE_NORMAL_PRIORITY_CLASS 0x8000u
#define HIGH_PRIORITY_CLASS 0x80u
#define REALTIME_PRIORITY_CLASS 0x100u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_ACCESS_DENIED 5u
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_NOACCESS 998u
#define ERROR_PROCESS_MODE_ALREADY_BACKGROUND 402u
#define ERROR_PROCESS_MODE_NOT_BACKGROUND 403u

static process_t processes[2];
static thread_t slots[12], *current, *idle_thread;
static thread_t *threads = slots;
static unsigned thread_hi = 12;
static uint64_t jiffies, ready_order;
static kobject_t objects[20];
static struct { kobject_t *obj; uint32_t access; } handles[20];
static unsigned checks, failures, irq_depth, allocation;
static unsigned freed_vads;
static unsigned freed_stacks;
static unsigned char teb_storage[12][8192];
static uint64_t reject_read, reject_write;
static DWORD last_error;
static int tls_mode, fail_create_object;
static kobject_t *named_head, *timers_head[20];
static unsigned timer_count, destroyed_vads, freed_heap;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; if (failures < 30) \
    fprintf(stderr, "line %d: %s\n", __LINE__, #x); } } while (0)
#define KASSERT(x) CHECK(x)
#include "sched_cpu.h" /* unchanged native queue/policy and ticket primitives */
#include "smp_acpi.h"
static k64_runqueues_t runqueues;
static shz_smp_topology_t topology;
#define ready (runqueues.cpu[0].ready)
#define ready_mask (runqueues.cpu[0].ready_mask)
#define ready_count (runqueues.cpu[0].ready_count)
static uint64_t irq_save(void) { return irq_depth++; }
static void irq_restore(uint64_t f) { CHECK(irq_depth == f + 1); irq_depth = (unsigned)f; }
thread_t *thread_current(void);
static thread_t *thread_slot(unsigned i) { CHECK(irq_depth != 0); return i < 12 ? &slots[i] : NULL; }
static void ready_enqueue(thread_t *t);
void ob_ref(kobject_t *o);
void ob_deref(kobject_t *o);
void ipc_object_free(kobject_t *o);
static void kfree(void *p) { if (p) ++freed_heap; } /* static fixture storage */
static void vad_destroy(process_t *p) { (void)p; ++destroyed_vads; }
static void reg_key_object_free(kobject_t *o) { (void)o; CHECK(0); }
void token_object_free(kobject_t *o) { (void)o; CHECK(0); }
static void kprintf(const char *f, ...) { (void)f; CHECK(0); }
static int32_t handle_ref(process_t *p, uint64_t h, uint32_t type, kobject_t **out, uint32_t *access) {
    (void)p;
    if (!h || h % 4 || h / 4 >= 20 || !handles[h / 4].obj) return STATUS_INVALID_HANDLE;
    kobject_t *o = handles[h / 4].obj;
    if (type && o->type != type) return STATUS_OBJECT_TYPE_MISMATCH;
    ob_ref(o); *out = o; if (access) *access = handles[h / 4].access; return 0;
}
static kobject_t *handle_lookup(process_t *p, uint64_t h, uint32_t type) {
    kobject_t *o = NULL;
    if (!handle_ref(p, h, type, &o, NULL)) ob_deref(o);
    return o;
}
static int copy_from_user(process_t *p, void *dst, uint64_t src, uint64_t n) {
    (void)p; if (!src || src == reject_read) return -1; memcpy(dst, (void *)(uintptr_t)src, (size_t)n); return 0;
}
static int copy_to_user(process_t *p, uint64_t dst, const void *src, uint64_t n) {
    (void)p; if (!dst || dst == reject_write) return -1; memcpy((void *)(uintptr_t)dst, src, (size_t)n); return 0;
}
static int64_t stack_arg(process_t *p, struct regs *r, unsigned n) { (void)p; CHECK(n == 5); return (int64_t)r->arg5; }
static uint64_t ticks_now(void) { return jiffies; }
static int64_t shz_filetime_now_ipc(void) { return 100000000; }
static uint64_t thread_cycles_now(thread_t *t) { return t->cycles; } /* clock adapter */
static int vad_alloc(process_t *p, uint64_t *b, uint64_t *n, unsigned a, unsigned pr, unsigned k) {
    (void)p; (void)n; (void)a; (void)pr; (void)k; *b = 0x100000; return 0;
}
static int vad_free(process_t *p, uint64_t *b, uint64_t *n, unsigned a) {
    (void)p; (void)b; (void)n; CHECK(a == MEM_RELEASE); ++freed_vads; return 0;
}
static void user_thread_main(void *p) { (void)p; }
static thread_t *thread_create_suspended(const char *name, void (*fn)(void *), void *arg) {
    (void)name; (void)fn; (void)arg;
    thread_t *t = &slots[allocation++]; memset(t, 0, sizeof *t); t->state = TS_NEW;
    t->ready_cpu = t->on_cpu = K64_CPU_NONE;
    t->sched_priority = 16; t->quantum_ticks = 6; t->quantum_left = 6; t->cpu_mask = 1; return t;
}
static void thread_discard(thread_t *t) { CHECK(t->state == TS_NEW); t->state = TS_FREE; }
static uint64_t alloc_client_id(void) { return 400 + allocation * 4; }
static uint64_t proc_alloc_teb(process_t *p, uint64_t top, uint64_t base) {
    (void)p; (void)top; (void)base;
    memset(teb_storage[allocation], 0, sizeof teb_storage[allocation]);
    return (uintptr_t)teb_storage[allocation];
}
static kobject_t *ob_create(uint32_t type, const char *name) {
    (void)name; if (fail_create_object) return NULL;
    kobject_t *o = &objects[allocation + 5]; memset(o, 0, sizeof *o); o->type = type; o->refs = 1; return o;
}
static void thread_resume(thread_t *t) { CHECK(irq_depth != 0 && t->object); t->state = TS_READY; ready_enqueue(t); }
static void thread_user_tls_init(process_t *p, thread_t *t);
static int32_t dispatch(uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t ret);
static int32_t host_k32_set(process_t *cur, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len);
static int32_t host_k32_query(process_t *cur, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len, uint64_t retlen);
static HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)CURRENT_PROCESS_HANDLE; }
static DWORD GetCurrentProcessId(void) { return (DWORD)processes[0].pid; }
static LONG InterlockedCompareExchange(volatile LONG *p, LONG value, LONG expected) {
    __atomic_compare_exchange_n(p, &expected, value, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return expected;
}
static NTSTATUS NtShzSetK32(ULONG cls, HANDLE h, void *b, ULONG n) {
    return host_k32_set(&processes[0], cls, (uintptr_t)h, (uintptr_t)b, n);
}
static NTSTATUS NtShzQueryK32(ULONG cls, HANDLE h, void *b, ULONG n, ULONG *ret) {
    return host_k32_query(&processes[0], cls, (uintptr_t)h, (uintptr_t)b, n, (uintptr_t)ret);
}
static NTSTATUS NtQueryInformationProcess(HANDLE h, ULONG cls, void *b, ULONG n, ULONG *ret) {
    return dispatch(SYS_NtQueryInformationProcess, (uintptr_t)h, cls, (uintptr_t)b, n, (uintptr_t)ret);
}
static NTSTATUS NtSetInformationProcess(HANDLE h, ULONG cls, void *b, ULONG n) {
    return dispatch(SYS_NtSetInformationProcess, (uintptr_t)h, cls, (uintptr_t)b, n, 0);
}
static NTSTATUS NtQueryInformationThread(HANDLE h, ULONG cls, void *b, ULONG n, ULONG *ret) {
    return dispatch(SYS_NtQueryInformationThread, (uintptr_t)h, cls, (uintptr_t)b, n, (uintptr_t)ret);
}
static NTSTATUS NtSetInformationThread(HANDLE h, ULONG cls, void *b, ULONG n) {
    return dispatch(SYS_NtSetInformationThread, (uintptr_t)h, cls, (uintptr_t)b, n, 0);
}
static void shz_set_last_error(DWORD e) { last_error = e; }
static DWORD k32_nt_error(NTSTATUS st) {
    DWORD e = st == STATUS_INVALID_HANDLE ? ERROR_INVALID_HANDLE : st == STATUS_ACCESS_DENIED ||
        st == STATUS_THREAD_IS_TERMINATING || st == STATUS_PROCESS_IS_TERMINATING ? ERROR_ACCESS_DENIED : st == STATUS_NOT_SUPPORTED ? ERROR_NOT_SUPPORTED :
        st == STATUS_ACCESS_VIOLATION ? ERROR_NOACCESS : ERROR_INVALID_PARAMETER;
    shz_set_last_error(e); return e;
}
static int32_t unrelated_route(void) { CHECK(0); return STATUS_NOT_SUPPORTED; }
static void kstack_free(uint64_t base) { CHECK(base != 0 && irq_depth != 0); ++freed_stacks; }
#define sys_create_user_process(...) unrelated_route()
#define sys_open_process(...) unrelated_route()
#define sys_open_thread(...) unrelated_route()
#define sys_rw_vm(...) unrelated_route()
#define sys_create_thread(...) unrelated_route()
#define sys_suspend_resume(...) unrelated_route()
#define sys_terminate_thread(...) unrelated_route()
#define sys_duplicate(...) unrelated_route()
#define create_with_inherit(...) unrelated_route()
#define sys_create_job(...) unrelated_route()
#define ipc_open_named(...) unrelated_route()
#define sys_assign_job(...) unrelated_route()
#define sys_set_job(...) unrelated_route()
#define sys_query_job(...) unrelated_route()
#define sys_terminate_job(...) unrelated_route()
#define sys_is_in_job(...) unrelated_route()
#include "production.inc"

/* Only topology publication is a fixture. Both physical CPUID reading and the
 * production lookup run unchanged, on the single process-affinity CPU. */
static void owner_identity(unsigned cpu) {
    const uint32_t actual = initial_apic_id();
    memset(&topology, 0, sizeof topology);
    topology.count = cpu == 1 ? 2 : 1;
    topology.apic_id[0] = cpu == 0 ? actual : actual ^ 0xffu;
    if (cpu == 1) topology.apic_id[1] = actual;
}
static int32_t dispatch(uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, uint64_t ret) {
    struct regs r = {ret}; int handled = 0;
    int32_t st = ipc_proc_syscall(&processes[0], &r, num, a1, a2, a3, a4, &handled);
    return handled ? st : host_generic_syscall(&processes[0], &r, num, a1, a2, a3, a4);
}
static void thread_user_tls_init(process_t *p, thread_t *t) {
    CHECK(irq_depth == 0);
    CHECK(t->object && t->state == TS_NEW && t->object->u.thr.nt_base_increment == 0);
    uint32_t expected = p->priority_class == 0x40 ? 4 : p->priority_class == 0x4000 ? 6 :
        p->priority_class == 0x8000 ? 10 : p->priority_class == 0x80 ? 13 : 8;
    CHECK(t->sched_priority == expected && t->object->u.thr.last_sched_priority == expected);
    if (tls_mode) {
        uint32_t cls = 0x80;
        CHECK(host_k32_set(p, 1, CURRENT_PROCESS_HANDLE, (uintptr_t)&cls, 4) == 0);
        CHECK(t->sched_priority == 13);
        handles[8].obj = t->object; handles[8].access = 0x60;
        CHECK(SetThreadPriority((HANDLE)(uintptr_t)32, 2));
    }
}
static HANDLE H(uint64_t h) { return (HANDLE)(uintptr_t)h; }
static void reset(void) {
    memset(processes, 0, sizeof processes); memset(slots, 0, sizeof slots); memset(objects, 0, sizeof objects);
    memset(handles, 0, sizeof handles); k64_rq_init(&runqueues, slots, 12, 1);
    owner_identity(0);
    irq_depth = 0; ready_order = 0; jiffies = 100;
    reject_read = reject_write = 0; allocation = 3; tls_mode = fail_create_object = 0; last_error = 0;
    freed_vads = freed_stacks = destroyed_vads = freed_heap = timer_count = 0; named_head = NULL;
    for (unsigned i = 0; i < 12; ++i) slots[i].ready_cpu = slots[i].on_cpu = K64_CPU_NONE;
    for (unsigned i = 0; i < 2; ++i) {
        processes[i].used = 1; processes[i].pid = 100 + (int)i;
        processes[i].object = &objects[i]; objects[i].type = OB_PROCESS; objects[i].refs = 4; objects[i].u.proc.p = &processes[i];
    }
    current = &slots[0]; idle_thread = &slots[11];
    runqueues.cpu[0].current = current; runqueues.cpu[0].idle = idle_thread;
    current->on_cpu = 0;
    idle_thread->state = TS_READY; idle_thread->quantum_ticks = idle_thread->quantum_left = 6;
    idle_thread->cpu_mask = 1; /* a valid idle TCB: refusal must exercise the idle-owner rule */
    for (unsigned i = 0; i < 3; ++i) {
        thread_t *t = &slots[i]; kobject_t *o = &objects[i+2];
        t->state = i ? TS_READY : TS_RUNNING; t->id = (int)i; t->proc = &processes[i == 1]; t->object = o;
        t->sched_priority = 8; t->quantum_ticks = 6; t->quantum_left = 2; t->cpu_mask = 1;
        t->aging_service_left = i ? 0 : 3; /* READY owns no running service grant */
        t->stack_base = 0x100000 + i * 0x10000;
        t->teb = 0x10000 + i * 4096; t->tid = 204 + i*4;
        o->type = OB_THREAD; o->refs = 3; o->u.thr.t = t; o->u.thr.pid = (uint64_t)t->proc->pid;
        o->u.thr.tid = t->tid; o->u.thr.last_sched_priority = 8;
        handles[i+1].obj = o; handles[i+1].access = 0x60;
        if (i) { uint64_t f = irq_save(); ready_enqueue(t); irq_restore(f); }
    }
    handles[5].obj = processes[0].object; handles[5].access = PROCESS_SET_INFORMATION;
    handles[6].obj = processes[1].object; handles[6].access = PROCESS_SET_INFORMATION;
}
static int32_t set_raw(uint64_t h, int32_t inc) {
    return dispatch(SYS_NtSetInformationThread, h, 3, (uintptr_t)&inc, 4, 0);
}
static void check_queries(void) {
    struct thread_basic b; ULONG n = 0;
    CHECK(sizeof b == 48);
    CHECK(NtQueryInformationThread(H(8), 0, &b, sizeof b, &n) == 0);
    CHECK(n == 48 && b.pid == 101 && b.tid == 208 && b.prio == 8 && b.base == 0 && b.affinity == 1);
    n = 0; memset(&b, 0x5a, sizeof b);
    CHECK(NtQueryInformationThread(H(8), 0, &b, 47, &n) == STATUS_INFO_LENGTH_MISMATCH);
    CHECK(n == 48 && (unsigned char)b.exit_status == 0x5a);
    CHECK(NtQueryInformationThread(H(8), 0, &b, 49, &n) == 0);
    handles[2].access = THREAD_SET_INFORMATION;
    unsigned refs = objects[3].refs;
    CHECK(GetThreadPriority(H(8)) == THREAD_PRIORITY_ERROR_RETURN && last_error == ERROR_ACCESS_DENIED);
    CHECK(objects[3].refs == refs);
    handles[2].access = THREAD_QUERY_INFORMATION;
    CHECK(!SetThreadPriority(H(8), 1) && last_error == ERROR_ACCESS_DENIED);
    handles[2].access = 0x60;
    reject_write = (uintptr_t)&b;
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == STATUS_ACCESS_VIOLATION && objects[3].refs == refs);
    reject_write = (uintptr_t)&n;
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == STATUS_ACCESS_VIOLATION);
    reject_write = 0;
}
static void check_maps(void) {
    /* Primary table: learn.microsoft.com/windows/win32/procthread/scheduling-priorities.
     * Expected cells are independent of the production projection algorithm. */
    static const uint32_t classes[] = {0x40,0x4000,0x20,0x8000,0x80};
    static const int levels[] = {-15,-2,-1,0,1,2,15};
    static const uint32_t expected[5][7] = {{1,2,3,4,5,6,15},{1,4,5,6,7,8,15},
        {1,6,7,8,9,10,15},{1,8,9,10,11,12,15},{1,11,12,13,14,15,15}};
    for (unsigned c = 0; c < 5; ++c) for (unsigned k = 0; k < 7; ++k) {
        reset(); processes[1].priority_class = classes[c];
        CHECK(SetThreadPriority(H(9), levels[k])); /* tagged handle to another process's thread */
        CHECK(slots[1].sched_priority == expected[c][k]);
        CHECK(GetThreadPriority(H(8)) == levels[k]);
        CHECK(objects[3].u.thr.nt_base_increment == (levels[k] == -15 ? -16 : levels[k] == 15 ? 16 : levels[k]));
        CHECK(objects[3].u.thr.last_sched_priority == expected[c][k]);
        CHECK(slots[1].quantum_ticks == 6 && slots[1].cpu_mask == 1 && slots[1].aging_service_left == 0);
        CHECK(slots[1].ready_queued && ready_count == 2 &&
              (expected[c][k] == 8 ? ready[8].head == &slots[1] && ready[8].tail == &slots[2] :
                                    ready[expected[c][k]].tail == &slots[1]));
        CHECK(objects[3].refs == 3);
    }
    reset();
    CHECK(SetThreadPriority(H(4), 2));
    CHECK(slots[0].sched_priority == 10 && slots[0].quantum_left == 2 && slots[0].aging_service_left == 3);
    CHECK(SetThreadPriority(H(4), 1) && slots[0].quantum_left == 2);
    CHECK(SetThreadPriority((HANDLE)(uintptr_t)CURRENT_THREAD_HANDLE, 0));
    for (int i = -17; i <= 17; ++i) {
        if (i == -15 || i == -2 || i == -1 || i == 0 || i == 1 || i == 2 || i == 15) continue;
        CHECK(!SetThreadPriority(H(4), i) && last_error == ERROR_INVALID_PARAMETER);
    }
    CHECK(!SetThreadPriority(H(4), INT_MAX)); CHECK(!SetThreadPriority(H(4), INT_MIN));
    CHECK(!SetThreadPriority(H(4), 0x10000) && last_error == ERROR_NOT_SUPPORTED);
    CHECK(!SetThreadPriority(H(4), 0x20000) && last_error == ERROR_NOT_SUPPORTED);
    CHECK(set_raw(4, 16) == 0 && GetThreadPriority(H(4)) == 15);
    CHECK(set_raw(4, -16) == 0 && GetThreadPriority(H(4)) == -15);
    CHECK(set_raw(4, 15) == STATUS_INVALID_PARAMETER && set_raw(4, -15) == STATUS_INVALID_PARAMETER);
    CHECK(set_raw(4, INT_MAX) == STATUS_INVALID_PARAMETER && set_raw(4, INT_MIN) == STATUS_INVALID_PARAMETER);
    CHECK(!SetThreadPriority(H(999), 2) && last_error == ERROR_INVALID_HANDLE);
    CHECK(GetThreadPriority(H(999)) == THREAD_PRIORITY_ERROR_RETURN && last_error == ERROR_INVALID_HANDLE);
    CHECK(set_raw(UINT64_C(0x100000004), 0) == STATUS_INVALID_HANDLE);
    CHECK(set_raw(20, 0) == STATUS_OBJECT_TYPE_MISMATCH);
    int32_t inc = 1; unsigned refs = objects[2].refs;
    for (unsigned n = 0; n < 10; ++n) if (n != 4)
        CHECK(dispatch(SYS_NtSetInformationThread, 4, 3, (uintptr_t)&inc, n, 0) == STATUS_INFO_LENGTH_MISMATCH);
    reject_read = (uintptr_t)&inc;
    CHECK(dispatch(SYS_NtSetInformationThread, 4, 3, (uintptr_t)&inc, 4, 0) == STATUS_ACCESS_VIOLATION);
    reject_read = 0;
    CHECK(dispatch(SYS_NtSetInformationThread, 4, 3, 0, 4, 0) == STATUS_ACCESS_VIOLATION);
    CHECK(objects[2].refs == refs);
    CHECK(dispatch(SYS_NtSetInformationThread, 999, 999, 0, 0, 0) == STATUS_INVALID_INFO_CLASS);
    CHECK(dispatch(SYS_NtSetInformationThread, 4, 2, (uintptr_t)&inc, 4, 0) == STATUS_NOT_SUPPORTED);
    CHECK(dispatch(SYS_NtQueryInformationThread, 4, 999, 0, 0, 0) == STATUS_INVALID_INFO_CLASS);
}
static void check_affinity_and_lifetime(void) {
    reset(); CHECK(SetThreadAffinityMask(H(4), 1) == 1);
    CHECK(slots[0].quantum_left == 2 && slots[0].aging_service_left == 3);
    CHECK(SetThreadAffinityMask(H(999), 1) == 0 && last_error == ERROR_INVALID_HANDLE);
    uint64_t mask = 1;
    for (unsigned n = 0; n < 18; ++n) if (n != 8)
        CHECK(dispatch(SYS_NtSetInformationThread, 8, 4, (uintptr_t)&mask, n, 0) == STATUS_INFO_LENGTH_MISMATCH);
    for (unsigned i = 0; i < 4; ++i) {
        mask = (uint64_t[]){0,2,3,UINT64_MAX}[i];
        CHECK(dispatch(SYS_NtSetInformationThread, 8, 4, (uintptr_t)&mask, 8, 0) == STATUS_INVALID_PARAMETER);
    }
    mask = 1; reject_read = (uintptr_t)&mask;
    CHECK(dispatch(SYS_NtSetInformationThread, 8, 4, (uintptr_t)&mask, 8, 0) == STATUS_ACCESS_VIOLATION);
    reject_read = 0; handles[2].access = THREAD_QUERY_INFORMATION;
    CHECK(SetThreadAffinityMask(H(8), 1) == 0 && last_error == ERROR_ACCESS_DENIED);
    handles[2].access = THREAD_SET_INFORMATION;
    CHECK(SetThreadAffinityMask(H(8), 1) == 0 && last_error == ERROR_ACCESS_DENIED);
    handles[2].access = 0x60;
    CHECK(SetThreadPriority(H(8), 15));
    /* Another real native policy caller can change the absolute priority.
     * Reclamation must retain that value, rather than the API's last cache. */
    CHECK(thread_set_sched_policy(&slots[1], 19, 6, 1) == 0);
    slots[1].kill_pending = 1; CHECK(set_raw(8, 0) == STATUS_THREAD_IS_TERMINATING);
    slots[1].kill_pending = 0;
    { uint64_t f = irq_save(); ready_remove(&slots[1]); irq_restore(f); }
    slots[1].state = TS_ZOMBIE; slots[1].exit_code = 42;
    struct thread_basic b; ULONG n;
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == 0 && b.base == 16 && b.prio == 19 && b.exit_status == 42);
    CHECK(set_raw(8, 0) == STATUS_THREAD_IS_TERMINATING);
    uint64_t f = irq_save(); thread_object_detach(&slots[1]); irq_restore(f);
    CHECK(objects[3].u.thr.t == NULL && objects[3].u.thr.last_sched_priority == 19);
    slots[1].state = TS_FREE; slots[1].sched_priority = 31; slots[1].proc = NULL;
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == 0 && b.base == 16 && b.prio == 19 && b.teb == 0 && b.pid == 101);
    CHECK(GetThreadPriority(H(8)) == 15 && set_raw(8, 1) == STATUS_THREAD_IS_TERMINATING);
    CHECK(objects[3].refs == 2);
}
static void check_retarget_and_init(void) {
    reset(); thread_t *created = NULL;
    CHECK(start_thread_common(&processes[0], 0x1000, 0x40000, 0, 0, 65536, 1, &created) == 0);
    CHECK(created && created->state == TS_NEW && created->sched_priority == 8 && created->suspend_count == 1);
    CHECK(created->object->u.thr.nt_base_increment == 0 && created->quantum_ticks == 6);
    CHECK(SetThreadPriority(H(4), 2)); CHECK(SetThreadPriority(H(12), -15));
    slots[4].state = TS_READY; slots[4].sched_priority = 21; slots[4].quantum_ticks = 5; slots[4].cpu_mask = 1;
    { uint64_t f = irq_save(); ready_enqueue(&slots[4]); irq_restore(f); }
    uint32_t cls = 0x80;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == 0);
    CHECK(processes[0].priority_class == 0x80 && slots[0].sched_priority == 15 && slots[2].sched_priority == 1);
    CHECK(created->sched_priority == 13 && slots[1].sched_priority == 8 && slots[4].sched_priority == 21);
    CHECK(slots[0].quantum_left == 2 && slots[0].aging_service_left == 3 && slots[0].cpu_mask == 1);
    CHECK(objects[2].u.thr.nt_base_increment == 2 && objects[4].u.thr.nt_base_increment == -16);
    cls = 0x4000;
    CHECK(host_k32_set(&processes[0], 1, CURRENT_PROCESS_HANDLE, (uintptr_t)&cls, 4) == 0);
    CHECK(slots[0].sched_priority == 8 && created->sched_priority == 6 && slots[2].sched_priority == 1);
    cls = 0x100;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_NOT_SUPPORTED);
    CHECK(processes[0].priority_class == 0x4000 && slots[0].sched_priority == 8);
    cls = 0x80; handles[5].access = 0;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_ACCESS_DENIED);
    handles[5].access = PROCESS_SET_INFORMATION;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 5) == STATUS_INFO_LENGTH_MISMATCH);
    reject_read = (uintptr_t)&cls;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_ACCESS_VIOLATION); reject_read = 0;
    objects[4].u.thr.nt_base_increment = 7;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
    CHECK(slots[0].sched_priority == 8 && processes[0].priority_class == 0x4000);
    objects[4].u.thr.nt_base_increment = -16;
    processes[0].terminated = 1;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_PROCESS_IS_TERMINATING);
    reset(); tls_mode = 1;
    CHECK(start_thread_common(&processes[0], 0x1000, 0x40000, 0, 0, 65536, 1, &created) == 0);
    CHECK(created->sched_priority == 15 && created->object->u.thr.nt_base_increment == 2);
    reset(); processes[0].priority_class = 0x80;
    CHECK(start_thread_common(&processes[0], 0x1000, 0x40000, 0, 0, 65536, 0, &created) == 0);
    CHECK(created->state == TS_READY && created->sched_priority == 13);
}
static void check_retarget_table_and_refusals(void) {
    static const uint32_t classes[] = {0x40,0x4000,0x20,0x8000,0x80};
    static const int levels[] = {-15,-2,-1,0,1,2,15};
    static const uint32_t expected[5][7] = {{1,2,3,4,5,6,15},{1,4,5,6,7,8,15},
        {1,6,7,8,9,10,15},{1,8,9,10,11,12,15},{1,11,12,13,14,15,15}};
    for (unsigned c = 0; c < 5; ++c) for (unsigned k = 0; k < 7; ++k) {
        reset(); processes[1].priority_class = 0x80;
        CHECK(SetThreadPriority(H(8), levels[k]));
        uint32_t cls = classes[c];
        CHECK(host_k32_set(&processes[0], 1, 25, (uintptr_t)&cls, 4) == 0);
        CHECK(slots[1].sched_priority == expected[c][k] && objects[3].u.thr.last_sched_priority == expected[c][k]);
        CHECK(GetThreadPriority(H(8)) == levels[k]);
        CHECK(slots[0].sched_priority == 8 && slots[1].quantum_ticks == 6 && slots[1].aging_service_left == 0);
        CHECK(processes[1].priority_class == cls && objects[1].refs == 4 && objects[3].refs == 3);
    }
    reset(); uint32_t cls = 0x80;
    CHECK(host_k32_set(&processes[0], 1, 999, (uintptr_t)&cls, 4) == STATUS_INVALID_HANDLE);
    CHECK(host_k32_set(&processes[0], 1, 4, (uintptr_t)&cls, 4) == STATUS_OBJECT_TYPE_MISMATCH);
    for (unsigned i = 0; i < 3; ++i) {
        cls = (uint32_t[]){0,0x123,0x10000}[i];
        CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
        CHECK(processes[0].priority_class == 0 && slots[0].sched_priority == 8);
    }
    cls = 0x80; slots[2].cpu_mask = 2;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
    CHECK(slots[0].sched_priority == 8 && processes[0].priority_class == 0);
    slots[2].cpu_mask = 1; slots[2].quantum_ticks = 17;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
    CHECK(slots[0].sched_priority == 8 && processes[0].priority_class == 0);
    slots[2].quantum_ticks = 6; slots[2].sched_priority = 32;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
    CHECK(slots[0].sched_priority == 8 && processes[0].priority_class == 0);
    reset(); slots[2].kill_pending = 1;
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == 0);
    CHECK(slots[0].sched_priority == 13 && slots[2].sched_priority == 8);
    reset(); processes[0].teardown = 1;
    CHECK(set_raw(4, 2) == STATUS_THREAD_IS_TERMINATING);
    reset(); processes[0].exit_owner = &slots[2];
    CHECK(set_raw(4, 2) == STATUS_THREAD_IS_TERMINATING);
    CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_PROCESS_IS_TERMINATING);
    reset(); objects[2].u.thr.pid = 999;
    CHECK(set_raw(4, 2) == STATUS_THREAD_IS_TERMINATING);
    reset(); processes[0].priority_class = 0x100;
    CHECK(set_raw(4, 2) == STATUS_NOT_SUPPORTED);
    thread_t *created = NULL; unsigned refs = processes[0].object->refs;
    CHECK(start_thread_common(&processes[0], 0x1000, 0, 0, 0, 65536, 1, &created) == -1);
    CHECK(created == NULL && slots[3].state == TS_FREE && slots[3].object == NULL && processes[0].object->refs == refs);
    CHECK(freed_vads == 2 && slots[3].user_stack == 0 && objects[9].refs == 0);
}
static void check_native_requeue(void) {
    reset();
    CHECK(ready_count == 2 && ready_mask == (1u << 8) && ready[8].head == &slots[1] && ready[8].tail == &slots[2]);
    uint64_t arrival = slots[1].ready_order;
    jiffies += 7;
    CHECK(SetThreadPriority(H(8), 2));
    CHECK(ready[8].head == &slots[2] && ready[8].tail == &slots[2] && ready[10].head == &slots[1]);
    CHECK(ready_count == 2 && ready_mask == ((1u << 8) | (1u << 10)));
    CHECK(slots[1].ready_since == jiffies && slots[1].ready_order > arrival && slots[1].aging_service_left == 0);
    CHECK(SetThreadPriority(H(8), 0));
    CHECK(ready[8].head == &slots[2] && ready[8].tail == &slots[1] && slots[2].ready_next == &slots[1]);
    CHECK(ready_count == 2 && ready_mask == (1u << 8) && ready[10].head == NULL);
    arrival = slots[1].ready_order;
    uint64_t since = slots[1].ready_since;
    ++jiffies;
    CHECK(SetThreadPriority(H(8), 0));
    CHECK(slots[1].ready_order == arrival && slots[1].ready_since == since);
    CHECK(SetThreadPriority(H(4), 2));
    CHECK(slots[0].state == TS_RUNNING && slots[0].quantum_left == 2 && slots[0].aging_service_left == 3);
    CHECK(ready_count == 2 && ready_mask == (1u << 8));
}

static void check_ticket_and_owner_boundaries(void) {
    reset();
    const uint64_t outer = irq_save();
    uint32_t next = runqueues.lock.next;
    sched_policy_t p = {99, 88, 77};
    CHECK(thread_get_sched_policy(&slots[1], &p) == 0);
    CHECK(p.priority == 8 && p.quantum_ticks == 6 && p.cpu_mask == 1);
    CHECK(irq_depth == 1 && runqueues.lock.next == next + 1 &&
          runqueues.lock.owner == runqueues.lock.next && runqueues.lock.reservation == 0);
    const uint64_t arrival = slots[1].ready_order, since = slots[1].ready_since;
    next = runqueues.lock.next;
    CHECK(thread_set_sched_policy(&slots[1], 8, 6, 1) == 0);
    CHECK(irq_depth == 1 && runqueues.lock.next == next + 1 && runqueues.lock.owner == runqueues.lock.next);
    CHECK(slots[1].ready_cpu == 0 && slots[1].on_cpu == K64_CPU_NONE &&
          slots[1].ready_order == arrival && slots[1].ready_since == since && ready_count == 2);
    static const struct { unsigned priority, quantum; uint64_t mask; } bad[] = {
        {32, 6, 1}, {8, 0, 1}, {8, 17, 1}, {8, 6, 0}, {8, 6, 2}, {8, 6, UINT64_MAX}
    };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        next = runqueues.lock.next;
        CHECK(thread_set_sched_policy(&slots[1], bad[i].priority, bad[i].quantum, bad[i].mask) == -1);
        CHECK(irq_depth == 1 && runqueues.lock.next == next + 1 && runqueues.lock.owner == runqueues.lock.next);
        CHECK(slots[1].sched_priority == 8 && slots[1].quantum_ticks == 6 && slots[1].cpu_mask == 1 &&
              slots[1].ready_order == arrival && ready[8].head == &slots[1] && ready_count == 2);
    }
    thread_t foreign = {0};
    thread_t *invalid[] = {NULL, &foreign, (thread_t *)((uintptr_t)&slots[1] + 1), idle_thread, &slots[10]};
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        next = runqueues.lock.next;
        CHECK(thread_set_sched_policy(invalid[i], 8, 6, 1) == -1);
        CHECK(irq_depth == 1 && runqueues.lock.next == next + 1 && runqueues.lock.owner == runqueues.lock.next);
    }
    CHECK(thread_get_sched_policy(&slots[1], NULL) == -1 && irq_depth == 1);
    slots[10].state = TS_ZOMBIE;
    p = (sched_policy_t){99, 88, 77}; next = runqueues.lock.next;
    CHECK(thread_get_sched_policy(&slots[10], &p) == -1);
    CHECK(p.priority == 99 && p.quantum_ticks == 88 && p.cpu_mask == 77);
    CHECK(thread_set_sched_policy(&slots[10], 8, 6, 1) == -1);
    CHECK(irq_depth == 1 && runqueues.lock.next == next + 2 && runqueues.lock.owner == runqueues.lock.next);
    slots[10].state = TS_FREE;
    for (unsigned i = 0; i < 2; ++i) {
        owner_identity(i ? 32 : 1);
        CHECK(sched_cpu_identity() == (i ? K64_CPU_NONE : 1));
        CHECK(sched_cpu_register(1) == -2 && sched_cpu_register(32) == -1 && thread_current() == NULL);
        p = (sched_policy_t){99, 88, 77}; next = runqueues.lock.next;
        CHECK(thread_get_sched_policy(&slots[1], &p) == -1);
        CHECK(p.priority == 99 && p.quantum_ticks == 88 && p.cpu_mask == 77);
        CHECK(thread_set_sched_policy(&slots[1], 15, 6, 1) == -1);
        CHECK(irq_depth == 1 && runqueues.lock.next == next + 2 && runqueues.lock.owner == runqueues.lock.next);
        CHECK(set_raw(8, 2) == STATUS_THREAD_IS_TERMINATING && objects[3].refs == 3);
        uint32_t cls = 0x80;
        CHECK(host_k32_set(&processes[0], 1, 20, (uintptr_t)&cls, 4) == STATUS_INVALID_PARAMETER);
        CHECK(processes[0].priority_class == 0 && slots[0].sched_priority == 8 && slots[2].sched_priority == 8);
        CHECK(objects[0].refs == 4 && objects[2].u.thr.nt_base_increment == 0 &&
              slots[1].sched_priority == 8 && slots[1].ready_order == arrival && ready_count == 2);
        CHECK(irq_depth == 1 && runqueues.lock.owner == runqueues.lock.next && runqueues.lock.reservation == 0);
    }
    owner_identity(0);
    CHECK(sched_cpu_identity() == 0 && sched_cpu_register(0) == 0);
    queue_guard_t guard = queue_enter();
    CHECK(k64_rq_validate_locked(&runqueues) == 0);
    queue_leave(guard);
    irq_restore(outer);
    CHECK(irq_depth == 0 && runqueues.lock.owner == runqueues.lock.next);
}

static void check_actual_handoff_reclaim(void) {
    reset();
    CHECK(SetThreadPriority(H(8), 15));
    CHECK(thread_set_sched_policy(&slots[1], 19, 6, 1) == 0);
    const uint64_t outer = irq_save();
    ready_remove(&slots[1]);
    slots[1].state = TS_ZOMBIE; slots[1].exit_code = 42;
    slots[1].on_cpu = 0; runqueues.cpu[0].outgoing = &slots[1];
    thread_reap_exited();
    CHECK(slots[1].state == TS_ZOMBIE && slots[1].object == &objects[3] && freed_stacks == 0);
    CHECK(objects[3].u.thr.t == &slots[1] && objects[3].refs == 3 && irq_depth == 1);
    const uint32_t ticket = runqueues.lock.next;
    sched_switch_complete(); /* actual destination-stack completion body; no hardware switch */
    CHECK(slots[1].on_cpu == K64_CPU_NONE && runqueues.cpu[0].outgoing == NULL && !slots[1].ready_queued);
    CHECK(irq_depth == 1 && runqueues.lock.next == ticket + 1 && runqueues.lock.owner == runqueues.lock.next);
    CHECK(current == &slots[0] && current->on_cpu == 0 && current->quantum_left == 2 && current->aging_service_left == 3);
    thread_reap_exited();
    CHECK(slots[1].state == TS_FREE && slots[1].stack_base == 0 && slots[1].object == NULL && freed_stacks == 1);
    CHECK(objects[3].u.thr.t == NULL && objects[3].refs == 2 && objects[3].u.thr.last_sched_priority == 19);
    CHECK(objects[3].u.thr.nt_base_increment == 16 && objects[3].u.thr.exit_code == 42);
    irq_restore(outer);
    struct thread_basic b; ULONG n;
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == 0 && b.prio == 19 && b.base == 16 && b.tid == 208);
    /* Reuse this exact host TCB slot for a new identity, retaining the old
     * object handle. This proves the production cache seam, not guest reuse. */
    thread_t *t = &slots[1]; memset(t, 0, sizeof *t);
    t->state = TS_NEW; t->proc = &processes[0]; t->object = &objects[12]; t->tid = 900;
    t->sched_priority = 8; t->quantum_ticks = t->quantum_left = 6; t->cpu_mask = 1;
    t->ready_cpu = t->on_cpu = K64_CPU_NONE;
    objects[12].type = OB_THREAD; objects[12].refs = 3; objects[12].u.thr.t = t;
    objects[12].u.thr.pid = 100; objects[12].u.thr.tid = 900; objects[12].u.thr.last_sched_priority = 8;
    handles[9].obj = &objects[12]; handles[9].access = THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION;
    CHECK(set_raw(36, 1) == 0 && t->sched_priority == 9 && objects[12].u.thr.nt_base_increment == 1);
    CHECK(NtQueryInformationThread(H(8), 0, &b, 48, &n) == 0 && b.prio == 19 && b.base == 16 && b.pid == 101 && b.tid == 208);
    CHECK(GetThreadPriority(H(8)) == 15 && set_raw(8, 1) == STATUS_THREAD_IS_TERMINATING);
    CHECK(objects[3].refs == 2 && objects[12].refs == 3 && irq_depth == 0);
}
/* Independent native ordinals and process bases from ReactOS NDK/query and
 * Microsoft's scheduling table. No expected cell uses a production mapper. */
static const uint32_t process_classes[] = {0x40, 0x4000, 0x20, 0x8000, 0x80};
static const uint8_t native_classes[] = {1, 5, 2, 6, 3};
static const int process_bases[] = {4, 6, 8, 10, 13};
struct process_basic_test { int64_t exit_status; uint64_t peb, affinity; int64_t base_priority; uint64_t pid, ppid; };
static int32_t set_process_raw(uint64_t h, uint8_t cls, uint8_t foreground) {
    shz_nt_process_priority_t p = {foreground, cls};
    return NtSetInformationProcess((HANDLE)(uintptr_t)h, 18, &p, sizeof p);
}
static void check_process_default_and_table(void) {
    reset();
    shz_nt_process_priority_t out = {0x5a, 0x5a}; ULONG n = 0;
    CHECK(sizeof out == 2 && offsetof(shz_nt_process_priority_t, PriorityClass) == 1);
    NTSTATUS default_status = NtQueryInformationProcess(GetCurrentProcess(), 18, &out, sizeof out, &n);
    CHECK(default_status == 0);
    printf("NT_PROCESS_DEFAULT_OBSERVED: status=0x%08x length=%u foreground=%u ordinal=%u\n",
           (unsigned)default_status, n, out.Foreground, out.PriorityClass);
    CHECK(n == 2 && out.Foreground == 0 && out.PriorityClass == 2 && GetPriorityClass(GetCurrentProcess()) == 0x20);
    static const int levels[] = {-15, -2, -1, 0, 1, 2, 15};
    static const uint32_t expected[5][7] = {{1,2,3,4,5,6,15},{1,4,5,6,7,8,15},
        {1,6,7,8,9,10,15},{1,8,9,10,11,12,15},{1,11,12,13,14,15,15}};
    for (unsigned raw = 0; raw < 2; ++raw) for (unsigned c = 0; c < 5; ++c) for (unsigned k = 0; k < 7; ++k) {
        reset(); handles[6].access |= PROCESS_QUERY_INFORMATION;
        CHECK(SetThreadPriority(H(8), levels[k]));
        CHECK(raw ? set_process_raw(25, native_classes[c], 0) == 0 : SetPriorityClass(H(24), process_classes[c]));
        CHECK(processes[1].priority_class == process_classes[c] && GetPriorityClass(H(24)) == process_classes[c]);
        CHECK(NtQueryInformationProcess(H(25), 18, &out, 2, &n) == 0);
        CHECK(n == 2 && out.Foreground == 0 && out.PriorityClass == native_classes[c]);
        struct process_basic_test basic;
        CHECK(NtQueryInformationProcess(H(24), 0, &basic, sizeof basic, &n) == 0);
        if (c == 4 && k == 3) printf("NT_PROCESS_BASIC_HIGH_OBSERVED: raw=%u base=%lld stored_class=0x%x\n",
                                   raw, (long long)basic.base_priority, processes[1].priority_class);
        CHECK(n == 48 && basic.base_priority == process_bases[c] && basic.pid == 101 && basic.affinity == 1);
        CHECK(slots[1].sched_priority == expected[c][k] && objects[3].u.thr.last_sched_priority == expected[c][k]);
        CHECK(GetThreadPriority(H(8)) == levels[k] && objects[3].u.thr.nt_base_increment ==
              (levels[k] == -15 ? -16 : levels[k] == 15 ? 16 : levels[k]));
        CHECK(slots[1].quantum_ticks == 6 && slots[1].quantum_left == 6 && slots[1].cpu_mask == 1 &&
              slots[1].aging_service_left == 0 && slots[0].sched_priority == 8 && ready_count == 2);
        CHECK(objects[1].refs == 4 && irq_depth == 0 && runqueues.lock.next == runqueues.lock.owner);
    }
    for (unsigned c = 0; c < 5; ++c) {
        reset();
        CHECK(set_process_raw(CURRENT_PROCESS_HANDLE, native_classes[c], 0) == 0);
        thread_t *created = NULL;
        CHECK(start_thread_common(&processes[0], 0x1000, 0x40000, 0, 0, 65536, 1, &created) == 0);
        CHECK(created && created->state == TS_NEW && created->sched_priority == (uint32_t)process_bases[c] &&
              created->object->u.thr.nt_base_increment == 0 && created->object->u.thr.last_sched_priority == (uint32_t)process_bases[c]);
    }
}
static void check_process_rights_and_buffers(void) {
    reset(); shz_nt_process_priority_t p = {0, 3}; ULONG n = 0;
    struct { shz_nt_process_priority_t p; unsigned char tail[6]; } out;
    handles[6].access = PROCESS_SET_INFORMATION;
    CHECK(SetPriorityClass(H(24), 0x80));
    CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 2, &n) == STATUS_ACCESS_DENIED);
    const DWORD set_only_class = GetPriorityClass(H(24));
    CHECK(set_only_class == 0 && last_error == ERROR_ACCESS_DENIED && objects[1].refs == 4);
    printf("NT_PROCESS_SET_ONLY_GET_OBSERVED: class=0x%x error=%u\n", set_only_class, last_error);
    for (unsigned rights = 0; rights < 2; ++rights) {
        handles[6].access = rights ? PROCESS_QUERY_LIMITED_INFORMATION : PROCESS_QUERY_INFORMATION;
        CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 2, &n) == 0 && out.p.PriorityClass == 3 && n == 2);
        CHECK(GetPriorityClass(H(24)) == 0x80);
        CHECK(set_process_raw(24, 2, 0) == STATUS_ACCESS_DENIED);
        CHECK(!SetPriorityClass(H(24), 0x20) && last_error == ERROR_ACCESS_DENIED);
        CHECK(processes[1].priority_class == 0x80 && objects[1].refs == 4);
    }
    handles[6].access = PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION;
    for (unsigned size = 0; size < 7; ++size) if (size != 2) {
        memset(&out, 0x5a, sizeof out); n = 0;
        CHECK(NtQueryInformationProcess(H(24), 18, &out.p, size, &n) == STATUS_INFO_LENGTH_MISMATCH);
        CHECK(n == 2 && out.p.Foreground == 0x5a && out.tail[0] == 0x5a);
        CHECK(NtSetInformationProcess(H(24), 18, &p, size) == STATUS_INFO_LENGTH_MISMATCH);
        CHECK(processes[1].priority_class == 0x80 && slots[1].sched_priority == 13 && objects[1].refs == 4);
    }
    memset(&out, 0x5a, sizeof out);
    CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 2, &n) == 0 && n == 2 && out.p.PriorityClass == 3);
    for (unsigned i = 0; i < sizeof out.tail; ++i) CHECK(out.tail[i] == 0x5a);
    reject_write = (uintptr_t)&out;
    CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 2, &n) == STATUS_ACCESS_VIOLATION);
    reject_write = (uintptr_t)&n;
    CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 2, &n) == STATUS_ACCESS_VIOLATION);
    CHECK(NtQueryInformationProcess(H(24), 18, &out.p, 1, &n) == STATUS_ACCESS_VIOLATION);
    reject_write = 0; reject_read = (uintptr_t)&p;
    CHECK(NtSetInformationProcess(H(24), 18, &p, 2) == STATUS_ACCESS_VIOLATION);
    reject_read = 0;
    CHECK(NtSetInformationProcess(H(24), 18, NULL, 2) == STATUS_ACCESS_VIOLATION);
    CHECK(NtQueryInformationProcess(H(24), 18, NULL, 2, &n) == STATUS_ACCESS_VIOLATION);
    CHECK(objects[1].refs == 4 && processes[1].priority_class == 0x80 && slots[1].sched_priority == 13);
    static const uint64_t invalid[] = {0, 999, UINT64_C(0x100000018)};
    for (unsigned i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        CHECK(set_process_raw(invalid[i], 2, 0) == STATUS_INVALID_HANDLE);
        CHECK(NtQueryInformationProcess(H(invalid[i]), 18, &out.p, 2, NULL) == STATUS_INVALID_HANDLE);
        CHECK(GetPriorityClass(H(invalid[i])) == 0 && last_error == ERROR_INVALID_HANDLE);
    }
    CHECK(set_process_raw(8, 2, 0) == STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(NtQueryInformationProcess(H(8), 18, &out.p, 2, NULL) == STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(set_process_raw(CURRENT_THREAD_HANDLE, 2, 0) == STATUS_OBJECT_TYPE_MISMATCH);
    CHECK(NtQueryInformationProcess(H(24), 0x7fff, &out, sizeof out, &n) == STATUS_INVALID_INFO_CLASS);
    CHECK(NtSetInformationProcess(H(24), 0x7fff, &p, 2) == STATUS_INVALID_INFO_CLASS);
}
static void check_process_refusals_and_batch(void) {
    reset(); handles[5].access |= PROCESS_QUERY_INFORMATION;
    static const uint8_t invalid[] = {0, 7, 255};
    for (unsigned i = 0; i < sizeof invalid; ++i) CHECK(set_process_raw(20, invalid[i], 0) == STATUS_INVALID_PARAMETER);
    CHECK(set_process_raw(20, 4, 0) == STATUS_NOT_SUPPORTED);
    CHECK(set_process_raw(20, 2, 1) == STATUS_NOT_SUPPORTED);
    CHECK(set_process_raw(20, 2, 255) == STATUS_NOT_SUPPORTED);
    const BOOL bg_begin = SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_BEGIN);
    const DWORD bg_begin_error = last_error;
    CHECK(!bg_begin && bg_begin_error == ERROR_NOT_SUPPORTED);
    const BOOL bg_end = SetPriorityClass(GetCurrentProcess(), PROCESS_MODE_BACKGROUND_END);
    CHECK(!bg_end && last_error == ERROR_NOT_SUPPORTED);
    printf("NT_PROCESS_BACKGROUND_OBSERVED: begin=%d begin_error=%u end=%d end_error=%u\n",
           bg_begin, bg_begin_error, bg_end, last_error);
    CHECK(!SetPriorityClass(GetCurrentProcess(), 0) && last_error == ERROR_INVALID_PARAMETER);
    CHECK(!SetPriorityClass(GetCurrentProcess(), 0x123) && last_error == ERROR_INVALID_PARAMETER);
    CHECK(!SetPriorityClass(GetCurrentProcess(), 0x100) && last_error == ERROR_NOT_SUPPORTED);
    CHECK(GetPriorityClass(GetCurrentProcess()) == 0x20 && slots[0].sched_priority == 8 && objects[0].refs == 4);
    for (unsigned bad = 0; bad < 4; ++bad) {
        reset();
        if (!bad) objects[4].u.thr.nt_base_increment = 7;
        else if (bad == 1) slots[2].cpu_mask = 2;
        else if (bad == 2) slots[2].quantum_ticks = 0;
        else slots[2].sched_priority = 32;
        const uint64_t arrival = slots[2].ready_order, since = slots[2].ready_since;
        CHECK(set_process_raw(20, 3, 0) == STATUS_INVALID_PARAMETER);
        CHECK(processes[0].priority_class == 0 && slots[0].sched_priority == 8 && slots[2].sched_priority == (bad == 3 ? 32u : 8u));
        CHECK(objects[2].u.thr.last_sched_priority == 8 && objects[4].u.thr.last_sched_priority == 8 &&
              slots[0].quantum_left == 2 && slots[0].aging_service_left == 3 && objects[0].refs == 4);
        CHECK(slots[2].ready_order == arrival && slots[2].ready_since == since && ready_count == 2 &&
              ready[8].head == &slots[1] && ready[8].tail == &slots[2] && irq_depth == 0 && runqueues.lock.next == runqueues.lock.owner);
    }
    reset(); const uint64_t outer = irq_save(); owner_identity(1);
    CHECK(set_process_raw(20, 3, 0) == STATUS_INVALID_PARAMETER);
    CHECK(processes[0].priority_class == 0 && slots[0].sched_priority == 8 && slots[2].sched_priority == 8 && irq_depth == 1);
    owner_identity(0); irq_restore(outer);
    CHECK(set_process_raw(20, 3, 0) == 0 && slots[0].sched_priority == 13 && slots[2].sched_priority == 13);
    CHECK(slots[0].quantum_left == 2 && slots[0].aging_service_left == 3 && ready[13].head == &slots[2] &&
          slots[2].ready_cpu == 0 && slots[2].on_cpu == K64_CPU_NONE && ready_count == 2);
    queue_guard_t guard = queue_enter(); CHECK(k64_rq_validate_locked(&runqueues) == 0); queue_leave(guard);
}
static void check_process_retained_lifetime(void) {
    reset(); handles[6].access |= PROCESS_QUERY_INFORMATION;
    process_t *p = &processes[1]; kobject_t *o = &objects[1];
    p->priority_class = 0x80; p->terminated = 1; p->teardown = 2; p->exit_code = 42; o->signaled = 1;
    shz_nt_process_priority_t priority; struct process_basic_test basic; ULONG n;
    CHECK(NtQueryInformationProcess(H(24), 18, &priority, 2, &n) == 0 && priority.PriorityClass == 3 && priority.Foreground == 0);
    CHECK(GetPriorityClass(H(24)) == 0x80);
    CHECK(NtQueryInformationProcess(H(24), 0, &basic, sizeof basic, &n) == 0 && basic.base_priority == 13 && basic.exit_status == 42);
    CHECK(set_process_raw(24, 2, 0) == STATUS_PROCESS_IS_TERMINATING && p->priority_class == 0x80 && o->refs == 4);
    o->refs = 1; ob_ref(o); /* held object reference survives closing the last fixture handle */
    handles[6].obj = NULL; ob_deref(o);
    CHECK(o->refs == 1 && p->used == 1 && destroyed_vads == 0);
    CHECK(NtQueryInformationProcess(H(24), 18, &priority, 2, NULL) == STATUS_INVALID_HANDLE);
    handles[10].obj = o; handles[10].access = PROCESS_QUERY_INFORMATION;
    CHECK(NtQueryInformationProcess(H(40), 18, &priority, 2, NULL) == 0 && priority.PriorityClass == 3 && o->refs == 1);
    handles[10].obj = NULL; ob_deref(o); /* actual production ref/free bodies reclaim the exact process slot */
    CHECK(o->refs == 0 && p->used == 0 && destroyed_vads == 1);
    memset(p, 0, sizeof *p); p->used = 1; p->pid = 700; p->priority_class = 0x4000; p->object = &objects[14];
    objects[14].type = OB_PROCESS; objects[14].refs = 1; objects[14].u.proc.p = p;
    handles[6].obj = &objects[14]; handles[6].access = PROCESS_QUERY_INFORMATION;
    CHECK(NtQueryInformationProcess(H(24), 18, &priority, 2, &n) == 0 && priority.PriorityClass == 5 && n == 2);
    CHECK(NtQueryInformationProcess(H(24), 0, &basic, sizeof basic, &n) == 0 && basic.pid == 700 && basic.base_priority == 6);
    CHECK(objects[14].refs == 1 && o->refs == 0 && irq_depth == 0);
}
static void check_current_context_publication(void) {
    /* Keep reset and the compatibility mirror used by reclaim bodies intact.
     * Divergence is confined to these getter/NT-current-handle controls. */
    for (unsigned masked = 0; masked < 2; ++masked) {
        reset(); const uint64_t outer = masked ? irq_save() : 0;
        current = &slots[1];
        k64_runqueues_t before = runqueues;
        CHECK(thread_current() == &slots[0] && current == &slots[1]);
        CHECK(irq_depth == masked);
        CHECK(memcmp(&runqueues, &before, sizeof before) == 0);
        struct thread_basic basic; ULONG bytes = 0;
        CHECK(NtQueryInformationThread(H(CURRENT_THREAD_HANDLE), 0, &basic, sizeof basic, &bytes) == 0 &&
              bytes == 48 && basic.pid == 100 && basic.tid == 204);
        CHECK(irq_depth == masked);

        current = &slots[0]; runqueues.cpu[0].current = NULL;
        before = runqueues;
        CHECK(thread_current() == NULL && current == &slots[0]);
        CHECK(irq_depth == masked);
        CHECK(memcmp(&runqueues, &before, sizeof before) == 0);

        runqueues.cpu[0].current = &slots[0];
        runqueues.cpu[1].current = &slots[2]; owner_identity(1);
        before = runqueues;
        CHECK(sched_cpu_identity() == 1 && thread_current() == NULL && runqueues.online_mask == 1);
        CHECK(irq_depth == masked);
        CHECK(memcmp(&runqueues, &before, sizeof before) == 0);

        owner_identity(32); before = runqueues;
        CHECK(sched_cpu_identity() == K64_CPU_NONE && thread_current() == NULL && current == &slots[0]);
        CHECK(irq_depth == masked);
        CHECK(memcmp(&runqueues, &before, sizeof before) == 0);
        owner_identity(0); runqueues.cpu[1].current = NULL;
        if (masked) irq_restore(outer);
    }
}
int main(void) {
    cpu_set_t allowed, single;
    if (sched_getaffinity(0, sizeof allowed, &allowed)) return 2;
    unsigned cpu;
    for (cpu = 0; cpu < CPU_SETSIZE && !CPU_ISSET(cpu, &allowed); ++cpu) { }
    if (cpu == CPU_SETSIZE) return 2;
    CPU_ZERO(&single); CPU_SET(cpu, &single);
    if (sched_setaffinity(0, sizeof single, &single)) return 2;
    printf("NT_CPU_BOUNDARY: process_cpu_affinity=[%u], actual_APIC_id=%u\n", cpu, initial_apic_id());
    reset(); check_queries(); check_maps(); check_affinity_and_lifetime(); check_retarget_and_init();
    check_retarget_table_and_refusals();
    check_native_requeue();
    check_ticket_and_owner_boundaries(); check_actual_handoff_reclaim();
    const unsigned baseline_checks = checks, baseline_failures = failures;
    printf("NT_THREAD_PRIORITY_BASELINE: %u checks, %u failures\n", checks, failures);
#define PROCESS_CASE(fn) do { unsigned c = checks, f = failures; fn(); \
    printf("NT_PROCESS_PRIORITY_CASE: %s %u checks, %u failures\n", #fn, checks-c, failures-f); } while (0)
    PROCESS_CASE(check_process_default_and_table);
    PROCESS_CASE(check_process_rights_and_buffers);
    PROCESS_CASE(check_process_refusals_and_batch);
    PROCESS_CASE(check_process_retained_lifetime);
    printf("NT_PROCESS_PRIORITY_HOST: %u checks, %u failures\n", checks-baseline_checks, failures-baseline_failures);
    CHECK(irq_depth == 0);
    printf("NT_PRIORITY_EXISTING_CASES: %u checks, %u failures\n", checks, failures);
    const unsigned context_checks = checks, context_failures = failures;
    check_current_context_publication();
    printf("NT_DISPATCH_CURRENT_CONTEXT_HOST: %u checks, %u failures\n", checks-context_checks, failures-context_failures);
    printf("NT_THREAD_PRIORITY_HOST: %u checks, %u failures\n", checks, failures);
    return failures ? 1 : 0;
}
