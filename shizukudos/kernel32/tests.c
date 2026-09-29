/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 self-tests. Each check computes its result inside the guest from its own
 * CPU/kernel state and reports it through SHZ_HC_EVIDENCE for independent comparison
 * by the host harness. The kernel also prints PASS/FAIL, but the harness does not rely
 * on those strings.
 */
#include "k32.h"

extern void vm_set_demand_range(uint32_t lo, uint32_t hi);
extern uint32_t demand_faults;
extern uint64_t arch_timer_irqs(void);
extern uint32_t arch_exception_count(unsigned v);
extern uint32_t ipc_refused_buffers(void);
extern uint32_t ipc_stale(void);
extern uint32_t ipc_doorbells(void);
extern volatile uint32_t ipc_session_end;

static unsigned failures;
#define CHECK(name, cond) do { if (cond) kprintf("K32 test PASS: %s\n", name); \
    else { kprintf("K32 test FAIL: %s\n", name); ++failures; } } while (0)

/* ---- preemption ---- */
static volatile uint32_t spin_count[2];
static volatile int spin_stop;
static void spinner(void *arg)
{
    volatile uint32_t *c = &spin_count[(uintptr_t)arg];
    while (!spin_stop)
        ++*c;                                 /* never yields: only the timer can switch away */
}
static void test_preempt(void)
{
    thread_t *a = thread_create("spinA", spinner, (void *)0), *b = thread_create("spinB", spinner, (void *)1);
    const uint64_t before = sched_switch_count();
    KASSERT(a && b);
    thread_sleep_ms(40);
    spin_stop = 1;
    thread_join(a);
    thread_join(b);
    shz_evidence(2, sched_switch_count() - before);
    CHECK("timer preempts CPU-bound threads", spin_count[0] > 1000 && spin_count[1] > 1000 &&
                                             sched_switch_count() - before >= 10);
}

/* ---- mutex ---- */
static kmutex_t mtx;
static volatile uint32_t shared_counter;
static void mutex_worker(void *arg)
{
    unsigned i;
    (void)arg;
    for (i = 0; i < 5000; ++i) {
        uint32_t v;
        mutex_lock(&mtx);
        v = shared_counter;
        if ((i & 255) == 0)
            thread_yield();                   /* yield while holding the lock */
        shared_counter = v + 1;
        mutex_unlock(&mtx);
    }
}
static void test_mutex(void)
{
    thread_t *t[4];
    unsigned i;
    mutex_init(&mtx);
    for (i = 0; i < 4; ++i) t[i] = thread_create("mutexw", mutex_worker, 0);
    for (i = 0; i < 4; ++i) thread_join(t[i]);
    shz_evidence(3, shared_counter);
    CHECK("mutex serialises a read-modify-write (20000)", shared_counter == 20000);
}

/* ---- semaphores ---- */
static ksem_t items, slots;
static volatile uint32_t consumed_sum, produced;
static void producer(void *arg)
{
    unsigned i;
    (void)arg;
    for (i = 1; i <= 100; ++i) {
        sem_wait(&slots);
        produced = i;
        sem_post(&items);
    }
}
static void test_semaphore(void)
{
    thread_t *p;
    unsigned i;
    uint64_t t0, waited;
    ksem_t never;
    sem_init(&items, 0);
    sem_init(&slots, 1);
    p = thread_create("producer", producer, 0);
    for (i = 1; i <= 100; ++i) {
        sem_wait(&items);
        if (produced != i) { ++failures; kprintf("K32: producer order broken at %u\n", i); }
        consumed_sum += produced;
        sem_post(&slots);
    }
    thread_join(p);
    CHECK("semaphore producer/consumer ordering (5050)", consumed_sum == 5050);
    sem_init(&never, 0);
    t0 = shz_time_ns();
    CHECK("timed semaphore wait times out", sem_wait_timeout(&never, 30) == -1);
    waited = shz_time_ns() - t0;
    shz_evidence(13, waited / 1000);          /* microseconds by the Supervisor's clock */
}

static void test_sleep(void)
{
    const uint64_t t0 = shz_time_ns(), j0 = ticks_now();
    thread_sleep_ms(50);
    shz_evidence(14, (shz_time_ns() - t0) / 1000);
    shz_evidence(15, ticks_now() - j0);
    CHECK("sleep(50 ms) elapses on both clocks", (shz_time_ns() - t0) >= 45000000ull && ticks_now() - j0 >= 45);
}

/* ---- heap ---- */
static void test_heap(void)
{
    void *p[200];
    unsigned i, j, sum = 0;
    const size_t base = kheap_used();
    for (i = 0; i < 200; ++i) {
        const size_t n = 16 + (i * 37) % 900;
        p[i] = kmalloc(n);
        KASSERT(p[i]);
        memset(p[i], (int)i, n);
    }
    for (i = 0; i < 200; i += 2) kfree(p[i]);
    for (i = 1; i < 200; i += 2) {
        const size_t n = 16 + (i * 37) % 900;
        for (j = 0; j < n; ++j)
            if (((uint8_t *)p[i])[j] != (uint8_t)i) { ++failures; break; }
        sum += ((uint8_t *)p[i])[0];
    }
    for (i = 0; i < 100; ++i) { void *q = kmalloc(128); KASSERT(q); kfree(q); }
    for (i = 1; i < 200; i += 2) kfree(p[i]);
    shz_evidence(4, sum);
    CHECK("heap survives interleaved alloc/free without corruption", kheap_used() == base && sum != 0);
}

/* ---- demand paging ---- */
static void test_demand_paging(void)
{
    volatile uint32_t *base = (volatile uint32_t *)0x10000000u;
    unsigned i;
    const uint32_t before = pmm_free_count();
    vm_set_demand_range(0x10000000u, 0x10000000u + 16 * PAGE_SIZE);
    for (i = 0; i < 16; ++i)
        base[i * 1024] = 0xc0de0000u + i;
    for (i = 0; i < 16; ++i)
        if (base[i * 1024] != 0xc0de0000u + i) ++failures;
    vm_set_demand_range(0, 0);
    shz_evidence(5, demand_faults);
    CHECK("#PF handler demand-maps 16 kernel pages", demand_faults == 16 && before - pmm_free_count() >= 16);
}

/* ---- ring 3 ---- */
static void test_user(void)
{
    int pid_ok, pid_fault, pid_wild, code, faulted;
    const uint32_t free_before = pmm_free_count();
    const uint32_t gp_before = arch_exception_count(13), pf_before = arch_exception_count(14);
    KASSERT(proc_create("ok", user_ok_start, (uint32_t)(user_ok_end - user_ok_start), &pid_ok) == 0);
    KASSERT(proc_wait(pid_ok, &code, &faulted) == 0);
    shz_evidence(6, (uint32_t)code);
    CHECK("ring-3 process runs syscalls and exits 42", code == 42 && !faulted);
    KASSERT(proc_create("fault", user_fault_start, (uint32_t)(user_fault_end - user_fault_start), &pid_fault) == 0);
    KASSERT(proc_wait(pid_fault, &code, &faulted) == 0);
    shz_evidence(7, (uint32_t)code);
    CHECK("privileged instruction in ring 3 is contained (#GP)", faulted && code == (int)0x8000000d);
    KASSERT(proc_create("wild", user_wild_start, (uint32_t)(user_wild_end - user_wild_start), &pid_wild) == 0);
    KASSERT(proc_wait(pid_wild, &code, &faulted) == 0);
    shz_evidence(8, (uint32_t)code);
    CHECK("user write to kernel memory is contained (#PF)", faulted && code == (int)0x8000000e);
    shz_evidence(24, (arch_exception_count(13) - gp_before) | ((arch_exception_count(14) - pf_before) << 16));
    CHECK("no physical pages leaked by three processes", pmm_free_count() == free_before);
    shz_evidence(12, free_before - pmm_free_count());
}

void run_self_tests(const shz_bootinfo_t *bi)
{
    (void)bi;
    shz_evidence(0, read_cr0());
    shz_evidence(1, read_cr3());
    CHECK("paging enabled with write-protect", (read_cr0() & 0x80010001u) == 0x80010001u && (read_cr3() & 0xfff) == 0);
    test_preempt();
    test_mutex();
    test_semaphore();
    test_sleep();
    test_heap();
    test_demand_paging();
    test_user();
    shz_evidence(31, 0);
}

void report_final(void)
{
    shz_evidence(9, ipc_requests_served());
    shz_evidence(10, ipc_protocol_errors());
    shz_evidence(11, arch_timer_irqs());
    shz_evidence(25, ipc_refused_buffers());
    shz_evidence(26, ipc_stale());
    shz_evidence(27, ipc_doorbells());
    shz_evidence(28, failures);
    shz_evidence(29, 0x4b333221u);            /* "K32!" completion marker */
}
unsigned tests_failed(void) { return failures; }
