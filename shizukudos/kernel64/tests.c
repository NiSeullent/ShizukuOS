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

/* Every other T_*.EXE in \\SHZ\\TESTS is a self-checking Win64 program: it must exit 0 without a fault. It prints its own
 * PASS/FAIL lines through the console; a hung program is killed after WIN64_APP_TIMEOUT_MS. */
#define WIN64_APP_TIMEOUT_MS 60000u
#define WIN64_MAX_APPS 64
static void win64_run_others(void)
{
    static char names[WIN64_MAX_APPS][32];
    unsigned n = 0, i, j;
    fsnode_t *dir = fs_lookup("\\SHZ\\TESTS"), *c;
    if (!dir)
        return;
    for (c = dir->child; c && n < WIN64_MAX_APPS; c = c->sibling) {
        const size_t len = strlen(c->name);
        if (c->is_dir || len < 7 || len >= sizeof names[0] || strncmp(c->name, "T_", 2) || strcmp(c->name + len - 4, ".EXE") ||
            !strcmp(c->name, "T_HELLO.EXE"))
            continue;
        memcpy(names[n++], c->name, len + 1);
    }
    for (i = 1; i < n; ++i) {                                   /* insertion sort: deterministic order */
        char tmp[32];
        memcpy(tmp, names[i], sizeof tmp);
        for (j = i; j > 0 && strcmp(names[j - 1], tmp) > 0; --j) memcpy(names[j], names[j - 1], sizeof tmp);
        memcpy(names[j], tmp, sizeof tmp);
    }
    kprintf("K64 win64: %u self-checking app(s) besides T_HELLO.EXE\n", n);
    for (i = 0; i < n; ++i) {
        char path[64], cmd[40], label[80];
        process_t *p = 0;
        thread_t *t = 0;
        int64_t code = -1;
        int faulted = 1, reaped = -1;
        int32_t st;
        uint64_t waited = 0;
        memcpy(path, "\\SHZ\\TESTS\\", 12);
        memcpy(path + 12, names[i], strlen(names[i]) + 1);
        memcpy(cmd, names[i], strlen(names[i]) + 1);
        st = ldr_create_process(0, path, cmd, "C:\\SHZ\\TESTS", &p, &t);
        if (st == 0) {
            while (!(p->terminated && p->threads_alive == 0) && waited++ < WIN64_APP_TIMEOUT_MS)
                thread_sleep_ms(1);
            if (!p->terminated) {
                kprintf("K64 win64: %s timed out after %u ms, terminating\n", names[i], WIN64_APP_TIMEOUT_MS);
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
