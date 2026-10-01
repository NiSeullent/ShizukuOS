/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 self-tests. Results are computed inside the guest from its own CPU/kernel
 * state and published through SHZ_HC_EVIDENCE for independent verification by the host.
 */
#include "proc_internal.h"
#include "fs.h"

extern void vm_set_demand_range(uint64_t lo, uint64_t hi);
extern uint64_t demand_faults;
extern uint64_t arch_timer_irqs(void);
extern uint32_t arch_exception_count(unsigned v);
extern int initrd_files;                                  /* main.c: files mounted from WIN64.IMG, -1 = none */
extern int32_t ldr_create_process(process_t *parent, const char *image_path, const char *cmdline, const char *cwd,
                                  process_t **out_proc, thread_t **out_thread);

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

/* The scheduler table holds far more than the old 96 threads and the kernel stacks are pages, not heap blocks (a
 * multi-process Chromium run creates a few hundred threads; run 20 stopped at "thread table full (96 slots)"). */
#define MANY_THREADS 400
static ksem_t many_gate;
static volatile int many_started, many_done;
static void many_worker(void *arg)
{
    (void)arg;
    ++many_started;
    sem_wait(&many_gate);
    ++many_done;
}
static void test_many_threads(void)
{
    static thread_t *t[MANY_THREADS];
    unsigned i, created = 0;
    uint64_t waited = 0;
    const uint64_t free_before = pmm_free_count();
    const size_t heap_before = kheap_used();
    uint64_t free_during, free_after;
    size_t heap_during;
    sem_init(&many_gate, 0);
    many_started = many_done = 0;
    for (i = 0; i < MANY_THREADS; ++i) {
        t[i] = thread_create("many", many_worker, 0);
        if (t[i]) ++created;
    }
    while (many_started < (int)created && waited < 2000) { thread_sleep_ms(5); waited += 5; }
    free_during = pmm_free_count();
    heap_during = kheap_used();
    for (i = 0; i < created; ++i) sem_post(&many_gate);
    for (i = 0; i < MANY_THREADS; ++i) if (t[i]) thread_join(t[i]);
    free_after = pmm_free_count();
    CHECK("400 kernel threads exist at once (table of 1024 slots)", created == MANY_THREADS && many_started == MANY_THREADS &&
                                                                     many_done == MANY_THREADS);
    CHECK("their 32 KiB kernel stacks come from the page allocator, not the 12 MiB heap",
          free_before - free_during >= MANY_THREADS * (KSTACK_BYTES / PAGE_SIZE) && heap_during - heap_before < 64 * 1024);
    CHECK("joining the threads returns every stack page", free_after + 16 >= free_before && kheap_used() <= heap_before + 4096);
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

/* Win64 end to end: initrd file system -> PE32+ loader -> user-mode ntdll/kernel32 -> console app -> exit code.
 * T_HELLO.EXE returns 7 and reports through evidence slots 19..21 (image base, PROCESSOR_ARCHITECTURE, argc).
 * The first run warms the kernel heap, so the page count of the second run must return to its starting value. */
#define WIN64_TEST_EXE "\\SHZ\\TESTS\\T_HELLO.EXE"
static int win64_run(int64_t *code, int *faulted)
{
    process_t *p = 0;
    thread_t *t = 0;
    int32_t st = ldr_create_process(0, WIN64_TEST_EXE, "T_HELLO.EXE first", "C:\\SHZ\\TESTS", &p, &t);
    if (st) {
        kprintf("K64 win64: ldr_create_process failed (%x)\n", (uint32_t)st);
        return -1;
    }
    return proc_wait(p->pid, code, faulted);
}

/* Ordinary T_*.EXE programs must exit 0 without a fault. T_HELLO and the deliberately nonzero observation diagnostic
 * have separate contracts. Programs print their own PASS/FAIL lines; a hung program has a bounded deadline. */
#define WIN64_APP_TIMEOUT_MS 60000u

/* t_ipc_exit.c has finite waits for readiness/termination (10s + 5s),
 * two lifecycle probes (2 * 10s), three exit races (3 * 10s), and ten
 * full T_NET_LOOP children (10 * 120s). Keep the standard 60s allowance
 * for loading/setup/cleanup in addition to those declared waits. The
 * host's whole-boot deadline still bounds a stalled QA run. */
#define WIN64_IPC_EXIT_CHILD_WAITS_MS (10000u + 5000u + 2u * 10000u + 3u * 10000u + 10u * 120000u)

static unsigned win64_app_timeout_ms(const char *name)
{
    return !strcmp(name, "T_IPC_EXIT.EXE")
        ? WIN64_APP_TIMEOUT_MS + WIN64_IPC_EXIT_CHILD_WAITS_MS
        : WIN64_APP_TIMEOUT_MS;
}
#define WIN64_MAX_APPS 256
#define WIN64_TESTS_PREFIX "\\SHZ\\TESTS\\"
#define WIN64_OBSERVATION_EXE "T_AUTORUN_OBSERVE.EXE"

static void win64_observation_diagnostic(void)
{
    process_t *p = 0;
    thread_t *t = 0;
    int pid = 0, faulted = 1, reaped = -1;
    int64_t code = -1;
    int32_t st = ldr_create_process(0, WIN64_TESTS_PREFIX WIN64_OBSERVATION_EXE,
                                  WIN64_OBSERVATION_EXE, "C:\\SHZ\\TESTS", &p, &t);
    if (!st) {
        const uint64_t started = ticks_now();
        pid = p->pid;
        while (!(p->terminated && p->threads_alive == 0) && ticks_now() - started < WIN64_APP_TIMEOUT_MS)
            thread_sleep_ms(1);
        if (!p->terminated) process_terminate(p, 0x102, 1);
        reaped = proc_wait(pid, &code, &faulted);
    }
    kprintf("K64 win64 diagnostic: " WIN64_OBSERVATION_EXE " pid=%d exit=%d faulted=%d reaped=%d\n",
            pid, (int)code, faulted, reaped);
    CHECK("Win64 observation diagnostic parent deliberately exits 7 without a fault",
          !st && !reaped && code == 7 && !faulted);
    /* The real child waits for its parent's process handle, then sleeps 10 seconds before printing its proof.
     * Keep the diagnostic observable even when an archive contains very few ordinary apps. The host requires
     * both real console identities, the native wait result and the ordered delayed child marker. */
    if (!st && !reaped && code == 7 && !faulted) thread_sleep_ms(11000);
}

static void win64_run_others(void)
{
    static char names[WIN64_MAX_APPS][32];
    unsigned n = 0, found = 0, i, j;
    fsnode_t *dir = fs_lookup("\\SHZ\\TESTS"), *c;
    if (!dir)
        return;
    if (k64_cmdline_has("shz.noapps")) {                        /* autorun.c: a run dedicated to one program */
        kprintf("K64 win64: shz.noapps: the self-checking apps are not run\n");
        return;
    }
    if (fs_lookup(WIN64_TESTS_PREFIX WIN64_OBSERVATION_EXE))
        win64_observation_diagnostic();
    for (c = dir->child; c; c = c->sibling) {
        const size_t len = strlen(c->name);
        if (c->is_dir || len < 7 || strncmp(c->name, "T_", 2) || strcmp(c->name + len - 4, ".EXE") ||
            !strcmp(c->name, "T_HELLO.EXE") || !strcmp(c->name, WIN64_OBSERVATION_EXE))
            continue;
        ++found;
        if (n < WIN64_MAX_APPS && len < sizeof names[0])
            memcpy(names[n++], c->name, len + 1);
    }
    CHECK("every self-checking T_*.EXE in \\SHZ\\TESTS fits the app list (none skipped)", n == found);
    for (i = 1; i < n; ++i) {                                   /* insertion sort: deterministic order */
        char tmp[32];
        memcpy(tmp, names[i], sizeof tmp);
        for (j = i; j > 0 && strcmp(names[j - 1], tmp) > 0; --j) memcpy(names[j], names[j - 1], sizeof tmp);
        memcpy(names[j], tmp, sizeof tmp);
    }
    kprintf("K64 win64: %u ordinary self-checking app(s), separate T_HELLO/observation contracts\n", n);
    for (i = 0; i < n; ++i) {
        char path[64], cmd[40], label[80];
        process_t *p = 0;
        thread_t *t = 0;
        int64_t code = -1;
        int faulted = 1, reaped = -1;
        int32_t st;
        const unsigned timeout_ms = win64_app_timeout_ms(names[i]);
        memcpy(path, WIN64_TESTS_PREFIX, sizeof WIN64_TESTS_PREFIX - 1);
        memcpy(path + sizeof WIN64_TESTS_PREFIX - 1, names[i], strlen(names[i]) + 1);
        memcpy(cmd, names[i], strlen(names[i]) + 1);
        if (timeout_ms != WIN64_APP_TIMEOUT_MS)
            kprintf("K64 win64: %s workload deadline %u ms (declared child waits %u ms + standard %u ms)\n",
                    names[i], timeout_ms, WIN64_IPC_EXIT_CHILD_WAITS_MS, WIN64_APP_TIMEOUT_MS);
        st = ldr_create_process(0, path, cmd, "C:\\SHZ\\TESTS", &p, &t);
        if (st == 0) {
            const uint64_t started = ticks_now();
            while (!(p->terminated && p->threads_alive == 0) && ticks_now() - started < timeout_ms)
                thread_sleep_ms(1);
            if (!p->terminated) {
                kprintf("K64 win64: %s timed out after %u ms, terminating\n", names[i], timeout_ms);
                process_terminate(p, 0x102, 1);
            }
            reaped = proc_wait(p->pid, &code, &faulted);
        } else {
            kprintf("K64 win64: %s failed to start (%x)\n", names[i], (uint32_t)st);
        }
        kprintf("K64 win64 app: %s exit=%d faulted=%d\n", names[i], (int)code, faulted);
        memcpy(label, "Win64 app ", 10);
        memcpy(label + 10, names[i], strlen(names[i]) + 1);
        memcpy(label + 10 + strlen(names[i]), " exits 0 without a fault", 25);
        CHECK(label, st == 0 && reaped == 0 && code == 0 && !faulted);
    }
}

static void test_win64(void)
{
    int64_t code1 = -1, code2 = -1;
    int f1 = 1, f2 = 1, ran1, ran2;
    uint64_t free_before;
    CHECK("initrd mounted with ntdll, kernel32 and the Win64 test app",
          initrd_files > 0 && fs_lookup("\\SHZ\\SYS64\\ntdll.dll") && fs_lookup("\\SHZ\\SYS64\\kernel32.dll") &&
          fs_lookup(WIN64_TEST_EXE));
    shz_evidence(23, initrd_files > 0 ? (uint64_t)initrd_files : 0);
    if (initrd_files <= 0 || !fs_lookup(WIN64_TEST_EXE))
        return;
    ran1 = win64_run(&code1, &f1);
    free_before = pmm_free_count();
    ran2 = win64_run(&code2, &f2);
    shz_evidence(22, free_before - pmm_free_count());
    shz_evidence(30, (uint64_t)(uint32_t)code2 | ((uint64_t)(f1 | f2) << 32) | ((uint64_t)(ran1 == 0 && ran2 == 0) << 33) |
                         ((uint64_t)((uint32_t)code1 == (uint32_t)code2) << 34));
    CHECK("Win64 console app runs to exit code 7 twice without a fault",
          ran1 == 0 && ran2 == 0 && code1 == 7 && code2 == 7 && !f1 && !f2);
    CHECK("second Win64 process returns every physical page", pmm_free_count() == free_before);
    win64_run_others();
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
    test_many_threads();
    test_heap_and_demand();
    test_user();
    test_win64();
}

unsigned tests_failed(void) { return failures; }

void report_final(void)
{
    shz_evidence(11, arch_timer_irqs());
    shz_evidence(28, failures);
    shz_evidence(29, 0x4b363421ull);          /* "K64!" completion marker */
}
