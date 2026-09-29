/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 self-tests. Results are computed inside the guest from its own CPU/kernel
 * state and published through SHZ_HC_EVIDENCE for independent verification by the host.
 */
#include "proc_internal.h"

extern void vm_set_demand_range(uint64_t lo, uint64_t hi);
extern uint64_t demand_faults;
extern uint64_t arch_timer_irqs(void);
extern uint32_t arch_exception_count(unsigned v);

static unsigned failures;
#define CHECK(name, cond) do { if (cond) kprintf("K64 test PASS: %s\n", name); \
    else { kprintf("K64 test FAIL: %s\n", name); ++failures; } } while (0)

static volatile uint64_t spin_count[2];
static volatile int spin_stop;
static void spinner(void *arg)
{
    volatile uint64_t *c = &spin_count[(uintptr_t)arg];
    while (!spin_stop)
        ++*c;
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
    CHECK("timer preempts CPU-bound kernel threads", spin_count[0] > 1000 && spin_count[1] > 1000 &&
                                                      sched_switch_count() - before >= 10);
}

static kmutex_t mtx;
static volatile uint64_t shared_counter;
static void mutex_worker(void *arg)
{
    unsigned i;
    (void)arg;
    for (i = 0; i < 5000; ++i) {
        uint64_t v;
        mutex_lock(&mtx);
        v = shared_counter;
        if ((i & 255) == 0)
            thread_yield();
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

static void test_heap_and_demand(void)
{
    void *p[200];
    unsigned i, j, sum = 0;
    const size_t base = kheap_used();
    volatile uint64_t *dp = (volatile uint64_t *)0xffffc00000000000ull;
    const uint64_t free_before = pmm_free_count();
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
    for (i = 1; i < 200; i += 2) kfree(p[i]);
    shz_evidence(4, sum);
    CHECK("kernel heap survives interleaved alloc/free", kheap_used() == base && sum != 0);
    vm_set_demand_range(0xffffc00000000000ull, 0xffffc00000000000ull + 16 * PAGE_SIZE);
    for (i = 0; i < 16; ++i) dp[i * 512] = 0xc0de0000ull + i;
    for (i = 0; i < 16; ++i) if (dp[i * 512] != 0xc0de0000ull + i) ++failures;
    vm_set_demand_range(0, 0);
    shz_evidence(5, demand_faults);
    CHECK("#PF handler demand-maps 16 kernel pages above the direct map", demand_faults == 16 &&
          free_before - pmm_free_count() >= 16);
}

static void test_user(void)
{
    int pid_a, pid_b, pid_fault, pid_wild, pid_high, faulted;
    int64_t code_a, code_b, code;
    const uint64_t free_before = pmm_free_count();
    const uint32_t gp_before = arch_exception_count(13), pf_before = arch_exception_count(14);

    /* Two SSE-using processes run concurrently: their xmm7 values must stay private. */
    KASSERT(proc_create_flat("okA", user_ok_start, user_ok_end - user_ok_start, &pid_a) == 0);
    KASSERT(proc_create_flat("okB", user_ok_start, user_ok_end - user_ok_start, &pid_b) == 0);
    KASSERT(proc_wait(pid_a, &code_a, &faulted) == 0 && !faulted);
    KASSERT(proc_wait(pid_b, &code_b, &faulted) == 0 && !faulted);
    shz_evidence(6, (uint64_t)code_a | ((uint64_t)code_b << 16));
    CHECK("two Long Mode processes keep SSE state across preemption (exit 42, 42)", code_a == 42 && code_b == 42);

    KASSERT(proc_create_flat("fault", user_fault_start, user_fault_end - user_fault_start, &pid_fault) == 0);
    KASSERT(proc_wait(pid_fault, &code, &faulted) == 0);
    shz_evidence(7, (uint64_t)code);
    CHECK("privileged instruction in ring 3 is contained", faulted && (uint32_t)code == (uint32_t)STATUS_PRIVILEGED_INSTRUCTION);

    KASSERT(proc_create_flat("wild", user_wild_start, user_wild_end - user_wild_start, &pid_wild) == 0);
    KASSERT(proc_wait(pid_wild, &code, &faulted) == 0);
    shz_evidence(8, (uint64_t)code);
    CHECK("user write to kernel memory is contained (#PF)", faulted && (uint32_t)code == (uint32_t)STATUS_ACCESS_VIOLATION);

    KASSERT(proc_create_flat("high", user_high_start, user_high_end - user_high_start, &pid_high) == 0);
    KASSERT(proc_wait(pid_high, &code, &faulted) == 0);
    shz_evidence(9, (uint64_t)code);
    CHECK("virtual memory above 4 GiB works and released memory faults", faulted && (uint32_t)code == (uint32_t)STATUS_ACCESS_VIOLATION);

    shz_evidence(24, (arch_exception_count(13) - gp_before) | ((uint64_t)(arch_exception_count(14) - pf_before) << 16));
    shz_evidence(12, free_before - pmm_free_count());
    CHECK("no physical pages leaked by five processes", pmm_free_count() == free_before);
}

void run_self_tests(const shz_bootinfo_t *bi)
{
    (void)bi;
    shz_evidence(0, read_cr0());
    shz_evidence(1, read_cr3());
    CHECK("running above 4 GiB virtual with paging", (read_cr0() & 0x80010001ull) == 0x80010001ull &&
          (uint64_t)&run_self_tests > 0xffffffff00000000ull);
    test_preempt();
    test_mutex();
    test_heap_and_demand();
    test_user();
}

unsigned tests_failed(void) { return failures; }

void report_final(void)
{
    shz_evidence(11, arch_timer_irqs());
    shz_evidence(28, failures);
    shz_evidence(29, 0x4b363421ull);          /* "K64!" completion marker */
}
