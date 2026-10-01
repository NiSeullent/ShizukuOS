/* SPDX-License-Identifier: GPL-2.0-only
 * Executing-thread PMA acceptance checks, using the real scheduler and PIT/PV tick.
 * This component test does not establish integrated SMP or Windows VMM scheduling.
 */
#include "proc_internal.h"

/* Test-first declarations allow an old kernel to boot and report the missing
 * policy as a failed assertion, rather than failing to link. */
#ifndef SCHED_PRIORITY_LEVELS
#define SCHED_PRIORITY_LEVELS 32u
#define SCHED_DEFAULT_PRIORITY 16u
#define SCHED_MAX_QUANTUM_TICKS 16u
#define SCHED_STARVATION_TICKS 32u
typedef struct { uint32_t priority, quantum_ticks; uint64_t cpu_mask; } sched_policy_t;
typedef struct {
    uint64_t ticks, context_switches, preemptions, wakeups, timeouts;
    uint32_t ready_threads, live_threads, zombie_threads, cpu_count;
} sched_stats_t;
#endif
extern int thread_set_sched_policy(thread_t *, unsigned, unsigned, uint64_t) __attribute__((weak));
extern int thread_get_sched_policy(thread_t *, sched_policy_t *) __attribute__((weak));
extern void sched_get_stats(sched_stats_t *) __attribute__((weak));
extern int sched_validate(void) __attribute__((weak));

static unsigned pma_failures;
#define PMA_CHECK(name, condition) do { if (condition) kprintf("K64 PMA PASS: %s\n", name); \
    else { kprintf("K64 PMA FAIL: %s\n", name); ++pma_failures; } } while (0)

static volatile int long_wait_done;
static ksem_t long_wait_sem;
/* This value wraps ms*1000 to 384 on x86-64, turning an old deadline into one tick. */
#define LONG_WAIT_MS (UINT64_MAX / 1000u + 1u)
static void long_sleep_worker(void *arg)
{
    (void)arg;
    thread_sleep_ms(LONG_WAIT_MS);
    long_wait_done = 1;
}
static void long_sem_worker(void *arg)
{
    (void)arg;
    thread_exit(sem_wait_timeout(&long_wait_sem, LONG_WAIT_MS));
}
static void test_long_deadlines(void)
{
    thread_t *t;
    long_wait_done = 0;
    t = thread_create("pma-long-sleep", long_sleep_worker, 0);
    KASSERT(t);
    thread_sleep_ms(4);
    PMA_CHECK("overflowing millisecond sleep stays blocked until explicitly woken", !long_wait_done &&
              t->state == TS_BLOCKED);
    thread_wake(t);
    thread_join(t);
    sem_init(&long_wait_sem, 0);
    t = thread_create("pma-long-sem", long_sem_worker, 0);
    KASSERT(t);
    thread_sleep_ms(4);
    sem_post(&long_wait_sem);
    PMA_CHECK("overflowing timed semaphore wait consumes the posted token", thread_join(t) == 0 &&
              long_wait_sem.count == 0 && !long_wait_sem.waiters);
}

static void unused_worker(void *arg) { (void)arg; }

static void test_policy_validation(void)
{
    sched_policy_t before, after;
    thread_t *t = thread_create_suspended("pma-policy", unused_worker, 0);
    KASSERT(t);
    PMA_CHECK("new threads use the one-tick CPU0 default", !thread_get_sched_policy(t, &before) &&
              before.priority == 16 && before.quantum_ticks == 1 && before.cpu_mask == 1);
    PMA_CHECK("invalid priority and quantum are rejected", thread_set_sched_policy(t, 32, 1, 1) == -1 &&
              thread_set_sched_policy(t, 16, 0, 1) == -1 && thread_set_sched_policy(t, 16, 17, 1) == -1);
    PMA_CHECK("absent CPUs and empty affinity are rejected", thread_set_sched_policy(t, 16, 1, 0) == -1 &&
              thread_set_sched_policy(t, 16, 1, 2) == -1 && thread_set_sched_policy(t, 16, 1, 3) == -1);
    PMA_CHECK("rejected updates leave actual policy unchanged", !thread_get_sched_policy(t, &after) &&
              before.priority == after.priority && before.quantum_ticks == after.quantum_ticks &&
              before.cpu_mask == after.cpu_mask);
    PMA_CHECK("foreign and null TCBs are rejected", thread_set_sched_policy(0, 16, 1, 1) == -1 &&
              thread_set_sched_policy((thread_t *)(uintptr_t)1, 16, 1, 1) == -1 &&
              thread_get_sched_policy(t, 0) == -1);
    PMA_CHECK("valid policy changes are reported", !thread_set_sched_policy(t, 31, 16, 1) &&
              !thread_get_sched_policy(t, &after) && after.priority == 31 && after.quantum_ticks == 16 && after.cpu_mask == 1);
    thread_discard(t);
    PMA_CHECK("discarded TCBs reject policy updates", thread_set_sched_policy(t, 16, 1, 1) == -1);
}

static volatile unsigned fifo_done;
static unsigned fifo_order[3];
static void fifo_worker(void *arg)
{
    const unsigned index = __atomic_fetch_add(&fifo_done, 1, __ATOMIC_RELAXED);
    KASSERT(index < 3);
    fifo_order[index] = (unsigned)(uintptr_t)arg;
}

static void test_fifo(void)
{
    thread_t *t[3];
    unsigned i;
    uint64_t f;
    fifo_done = 0;
    for (i = 0; i < 3; ++i) {
        t[i] = thread_create_suspended("pma-fifo", fifo_worker, (void *)(uintptr_t)i);
        KASSERT(t[i]);
        KASSERT(!thread_set_sched_policy(t[i], 16, 16, 1));
    }
    f = irq_save();
    for (i = 0; i < 3; ++i) thread_resume(t[i]);
    irq_restore(f);
    for (i = 0; i < 3; ++i) thread_join(t[i]);
    PMA_CHECK("equal-priority ready threads execute in FIFO order", fifo_done == 3 &&
              fifo_order[0] == 0 && fifo_order[1] == 1 && fifo_order[2] == 2);
    PMA_CHECK("FIFO completion leaves no duplicate runnable entries", sched_validate());
}

typedef struct {
    volatile uint64_t loops;
    uint64_t last_tick, max_gap;
} pma_spinner_t;
static volatile int spinner_stop;
static pma_spinner_t spin_work[2];
static void pma_spinner(void *arg)
{
    pma_spinner_t *w = arg;
    while (!spinner_stop) {
        /* Sampling and the parent's phase reset share the same short UP IRQ
         * guard. Preemption between clock read and last_tick update can retain
         * a stale observation; a concurrent phase reset could even underflow. */
        const uint64_t f = irq_save();
        const uint64_t now = ticks_now();
        const uint64_t gap = now - w->last_tick;
        if (gap > w->max_gap) w->max_gap = gap;
        w->last_tick = now;
        irq_restore(f);
        ++w->loops; /* no yielding, blocking, or hypercall */
    }
}

static void start_spinners(thread_t **t, unsigned pa, unsigned qa, unsigned pb, unsigned qb)
{
    unsigned i;
    const uint64_t f = irq_save();
    spinner_stop = 0;
    memset(spin_work, 0, sizeof spin_work);
    for (i = 0; i < 2; ++i) {
        spin_work[i].last_tick = ticks_now();
        t[i] = thread_create_suspended("pma-cpu", pma_spinner, &spin_work[i]);
        KASSERT(t[i]);
    }
    KASSERT(!thread_set_sched_policy(t[0], pa, qa, 1));
    KASSERT(!thread_set_sched_policy(t[1], pb, qb, 1));
    for (i = 0; i < 2; ++i) thread_resume(t[i]);
    irq_restore(f);
}

static void stop_spinners(thread_t **t)
{
    spinner_stop = 1;
    thread_join(t[0]);
    thread_join(t[1]);
}

static uint64_t sample_first, sample_middle, sample_last, sample_raw_gap;
static volatile int sample_done;
static void interrupted_sampler(void *arg)
{
    (void)arg;
    /* Keep the captures atomic with the two intentional yields. Each other
     * context restores its own IF, so its timer still advances. Restoring IF
     * after each yield here could insert an extra dispatch interval before a
     * capture and confuse that observation with actual ready residence. */
    const uint64_t f = irq_save();
    sample_first = ticks_now();
    /* Force the two timer-switch opportunities in the old observation loop:
     * after reading the clock, and after writing that now-stale timestamp. */
    thread_yield();
    sample_middle = ticks_now();
    const uint64_t stale_last = sample_first;
    thread_yield();
    sample_last = ticks_now();
    sample_raw_gap = sample_last - stale_last;
    sample_done = 1;
    irq_restore(f);
}
static void sampler_competitor(void *arg)
{
    (void)arg;
    while (!sample_done) __asm__ volatile("" ::: "memory");
}
static void test_interrupted_observation(void)
{
    thread_t *low, *high;
    uint64_t wait;
    const uint64_t f = irq_save();
    sample_done = 0;
    low = thread_create_suspended("pma-sampler", interrupted_sampler, 0);
    high = thread_create_suspended("pma-sampler-cpu", sampler_competitor, 0);
    KASSERT(low && high);
    KASSERT(!thread_set_sched_policy(low, 0, 1, 1));
    KASSERT(!thread_set_sched_policy(high, 31, 1, 1));
    thread_resume(low); thread_resume(high);
    irq_restore(f);
    thread_join(low);
    wait = low->max_ready_wait_ticks;
    thread_join(high);
    PMA_CHECK("interrupted clock observations can span two serviced ready intervals", sample_raw_gap > 40 &&
              sample_middle - sample_first <= 40 && sample_last - sample_middle <= 40 && wait <= 40);
    kprintf("K64 PMA sampler: raw_gap=%llu service_gaps=%llu/%llu ready_wait=%llu ticks\n",
            sample_raw_gap, sample_middle - sample_first, sample_last - sample_middle, wait);
}

static void test_priority_and_quantum(void)
{
    thread_t *t[2];
    uint64_t a, b, a2, b2, first_gap, second_gap, first_wait, second_wait, f;
    uint64_t first_low_loops, second_low_start, second_low_loops;
    sched_stats_t before, after;
    start_spinners(t, 31, 1, 0, 1);
    thread_sleep_ms(128);
    f = irq_save();
    a = t[0]->run_ticks; b = t[1]->run_ticks;
    first_gap = spin_work[1].max_gap;
    first_wait = t[1]->max_ready_wait_ticks;
    first_low_loops = spin_work[1].loops;
    second_low_start = spin_work[0].loops;
    KASSERT(!thread_set_sched_policy(t[0], 0, 1, 1));
    KASSERT(!thread_set_sched_policy(t[1], 31, 1, 1));
    /* The second stable-policy window starts here. A pre-swap observation is
     * not a clock baseline for the newly low priority worker. */
    spin_work[0].last_tick = ticks_now();
    spin_work[0].max_gap = 0;
    t[0]->max_ready_wait_ticks = 0;
    irq_restore(f);
    thread_sleep_ms(128);
    f = irq_save();
    a2 = t[0]->run_ticks - a; b2 = t[1]->run_ticks - b;
    second_gap = spin_work[0].max_gap;
    second_wait = t[0]->max_ready_wait_ticks;
    second_low_loops = spin_work[0].loops - second_low_start;
    spinner_stop = 1;
    irq_restore(f);
    stop_spinners(t);
    PMA_CHECK("higher priority receives more CPU while low priority progresses", a > b * 2 && b >= 3 &&
              spin_work[0].loops > 1000 && spin_work[1].loops > 1000);
    PMA_CHECK("each low-priority policy phase executes useful CPU work", first_low_loops > 1000 && second_low_loops > 1000);
    PMA_CHECK("low-priority CPU-bound worker has bounded ready-to-dispatch residence", first_wait <= 40 && second_wait <= 40);
    PMA_CHECK("changing a ready/running priority changes actual CPU allocation", b2 > a2 * 2 && a2 >= 3);
    kprintf("K64 PMA policy: first=%llu/%llu changed=%llu/%llu low_wait=%llu observation_gap=%llu ticks\n",
            a, b, a2, b2, first_wait > second_wait ? first_wait : second_wait,
            first_gap > second_gap ? first_gap : second_gap);
    kprintf("K64 PMA progress: low_loops=%llu/%llu\n", first_low_loops, second_low_loops);
    sched_get_stats(&before);
    start_spinners(t, 16, 1, 16, 4);
    thread_sleep_ms(100);
    a = t[0]->run_ticks; b = t[1]->run_ticks;
    sched_get_stats(&after);
    PMA_CHECK("four-tick quantum changes CPU allocation between equal priorities", a > 5 && b >= a * 2 &&
              spin_work[0].loops > 1000 && spin_work[1].loops > 1000);
    PMA_CHECK("CPU-bound workers are preempted by the actual timer", after.preemptions - before.preemptions >= 20);
    kprintf("K64 PMA quantum: ticks=%llu/%llu preemptions=%llu\n", a, b, after.preemptions - before.preemptions);
    stop_spinners(t);
}

static uint64_t refresh_deadline, refresh_start, refresh_low_first, refresh_count, refresh_low_loops;
static void refresh_worker(void *arg)
{
    (void)arg;
    while (ticks_now() < refresh_deadline) {
        KASSERT(!thread_set_sched_policy(thread_current(), 31, 15 + (unsigned)(refresh_count & 1), 1));
        ++refresh_count; /* never yields; the test ends from the actual tick clock */
    }
}
static void refresh_low_worker(void *arg)
{
    (void)arg;
    refresh_low_first = ticks_now();
    while (ticks_now() < refresh_deadline) ++refresh_low_loops;
}
static void test_policy_refresh(void)
{
    thread_t *high, *low;
    const uint64_t f = irq_save();
    refresh_start = ticks_now();
    refresh_deadline = refresh_start + 80;
    refresh_low_first = refresh_count = refresh_low_loops = 0;
    high = thread_create_suspended("pma-refresh", refresh_worker, 0);
    low = thread_create_suspended("pma-refresh-low", refresh_low_worker, 0);
    KASSERT(high && low);
    KASSERT(!thread_set_sched_policy(high, 31, 16, 1));
    KASSERT(!thread_set_sched_policy(low, 0, 1, 1));
    thread_resume(high);
    thread_resume(low);
    irq_restore(f);
    thread_join(high);
    thread_join(low);
    PMA_CHECK("repeated quantum policy updates cannot postpone an aged ready worker", refresh_count > 1000 &&
              refresh_low_loops > 1000 && refresh_low_first - refresh_start <= 40);
    kprintf("K64 PMA refresh: updates=%llu low_first=%llu low_loops=%llu\n",
            refresh_count, refresh_low_first - refresh_start, refresh_low_loops);
}

static volatile int sleep_started, sleep_finished;
static void wake_worker(void *arg)
{
    (void)arg;
    sleep_started = 1;
    thread_sleep_ms(1000);
    ++sleep_finished;
}
static void test_duplicate_wake(void)
{
    thread_t *t;
    sched_stats_t before, after;
    uint64_t f;
    sleep_started = sleep_finished = 0;
    t = thread_create("pma-wake", wake_worker, 0);
    KASSERT(t);
    while (!sleep_started || t->state != TS_BLOCKED) thread_sleep_ms(1);
    f = irq_save();
    sched_get_stats(&before);
    thread_wake(t);
    thread_wake(t);
    sched_get_stats(&after);
    PMA_CHECK("duplicate wake enqueues and counts a sleeper exactly once", after.ready_threads == before.ready_threads + 1 &&
              after.wakeups == before.wakeups + 1 && sched_validate());
    irq_restore(f);
    thread_join(t);
    PMA_CHECK("woken thread exits once and leaves an intact queue", sleep_finished == 1 && sched_validate());
}

static ksem_t race_sem;
static uint64_t race_delay;
static void race_waiter(void *arg) { (void)arg; thread_exit(sem_wait_timeout(&race_sem, 1)); }
static void race_poster(void *arg)
{
    (void)arg;
    if (race_delay) thread_sleep_ms(race_delay);
    sem_post(&race_sem);
}
static void test_timed_semaphores(void)
{
    unsigned i, signaled = 0, timed_out = 0, correct = 0;
    sched_stats_t before, after;
    sched_get_stats(&before);
    for (i = 0; i < 48; ++i) {
        thread_t *waiter, *poster;
        int64_t result;
        sem_init(&race_sem, 0);
        race_delay = i % 3; /* signal before expiry, at the deadline, and after expiry */
        waiter = thread_create("pma-semwait", race_waiter, 0);
        poster = thread_create("pma-sempost", race_poster, 0);
        KASSERT(waiter && poster);
        result = thread_join(waiter);
        thread_join(poster);
        if (!result) ++signaled;
        if (result == -1) ++timed_out;
        if ((result == 0 || result == -1) && race_sem.waiters == 0 &&
            race_sem.count == (result == -1 ? 1 : 0) && sched_validate()) ++correct;
    }
    sched_get_stats(&after);
    PMA_CHECK("signal/timeout races conserve every semaphore token", correct == 48 && signaled && timed_out);
    PMA_CHECK("timed waits advance the scheduler timeout counter", after.timeouts > before.timeouts);
    kprintf("K64 PMA semaphore: signaled=%u timeout=%u conserved=%u/48\n", signaled, timed_out, correct);
}

static kobject_t *race_event;
static int64_t race_event_status;
static void event_waiter(void *arg)
{
    (void)arg;
    race_event_status = ob_wait(0, &race_event, 1, 0, -30000, 0);
}
static void test_events(void)
{
    unsigned i, correct = 0;
    race_event = ob_create(OB_EVENT, 0);
    KASSERT(race_event);
    race_event->u.event.manual = 1;
    for (i = 0; i < 24; ++i) {
        thread_t *t;
        ob_reset_event(race_event);
        race_event_status = -1;
        t = thread_create("pma-event", event_waiter, 0);
        KASSERT(t);
        thread_sleep_ms(i % 4);
        ob_signal_event(race_event);
        ob_signal_event(race_event);
        thread_join(t);
        if ((race_event_status == STATUS_SUCCESS || race_event_status == STATUS_TIMEOUT) &&
            !race_event->waiters && ob_wait(0, &race_event, 1, 0, 0, 0) == STATUS_SUCCESS && sched_validate()) ++correct;
    }
    PMA_CHECK("manual-event duplicate signals and timeout races keep waiters valid", correct == 24);
    ob_deref(race_event);
    race_event = 0;
}

static ksem_t many_gate;
static volatile unsigned many_started, many_done;
static thread_t *many_threads[1000];
static void many_worker(void *arg)
{
    (void)arg;
    __atomic_add_fetch(&many_started, 1, __ATOMIC_RELAXED);
    sem_wait(&many_gate);
    __atomic_add_fetch(&many_done, 1, __ATOMIC_RELAXED);
}
static void test_many(void)
{
    unsigned i, created = 0;
    const uint64_t free_before = pmm_free_count();
    const unsigned target = free_before >= 8128 ? 1000 : 100;
    sched_stats_t before, after;
    uint64_t deadline;
    sched_get_stats(&before);
    sem_init(&many_gate, 0);
    many_started = many_done = 0;
    memset(many_threads, 0, sizeof many_threads);
    for (i = 0; i < target; ++i) {
        many_threads[i] = thread_create("pma-many", many_worker, 0);
        if (many_threads[i]) ++created;
    }
    deadline = ticks_now() + 2000;
    while (many_started < created && ticks_now() < deadline) thread_sleep_ms(1);
    PMA_CHECK("large runnable cohort reaches its semaphore wait without losing a thread", created == target &&
              many_started == target && sched_validate());
    for (i = 0; i < created; ++i) sem_post(&many_gate);
    for (i = 0; i < target; ++i) if (many_threads[i]) thread_join(many_threads[i]);
    sched_get_stats(&after);
    PMA_CHECK("thread cohort returns all stacks and scheduler slots", many_done == created &&
              pmm_free_count() == free_before && before.live_threads == after.live_threads &&
              before.zombie_threads == after.zombie_threads && sched_validate());
    kprintf("K64 PMA cohort: target=%u created=%u started=%u done=%u free_before=%llu free_after=%llu\n",
            target, created, many_started, many_done, free_before, pmm_free_count());
}

unsigned run_pma_self_tests(void)
{
    sched_stats_t stats;
    pma_failures = 0;
    test_long_deadlines();
    PMA_CHECK("policy interfaces are available", thread_set_sched_policy && thread_get_sched_policy &&
              sched_get_stats && sched_validate);
    if (pma_failures) {
        if (k64_cmdline_has("shz.pma=test")) {
            kprintf("K64 PMA summary: failures=%u missing_interfaces=1\n", pma_failures);
            shz_evidence(18, 0x504d0000u | pma_failures);
            shz_exit(1);
        }
        return pma_failures;
    }
    test_policy_validation();
    test_fifo();
    test_interrupted_observation();
    test_priority_and_quantum();
    test_policy_refresh();
    test_duplicate_wake();
    test_timed_semaphores();
    test_events();
    test_many();
    sched_get_stats(&stats);
    PMA_CHECK("final scheduler snapshot reports UP and intact queues", stats.cpu_count == 1 && sched_validate());
    kprintf("K64 PMA summary: failures=%u ticks=%llu switches=%llu preemptions=%llu wakeups=%llu timeouts=%llu ready=%u live=%u cpus=%u\n",
            pma_failures, stats.ticks, stats.context_switches, stats.preemptions, stats.wakeups, stats.timeouts,
            stats.ready_threads, stats.live_threads, stats.cpu_count);
    if (k64_cmdline_has("shz.pma=test")) {
        shz_evidence(18, 0x504d0000u | pma_failures);
        shz_exit(pma_failures ? 1 : 0);
    }
    return pma_failures;
}
