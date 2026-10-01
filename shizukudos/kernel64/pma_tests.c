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
    /* Retain this context's IF guard across the two deliberate yields. Each
     * successor restores its own IF, so the timer still services it; an extra
     * interrupt cannot add an unintended third interval to our observations. */
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
extern volatile int pma_sched_trace_enabled;
#define PMA_TRACE_CAPACITY 64u
static struct pma_trace_event {
    uint64_t tick, run_ticks, waited, rip, flags;
    unsigned kind, state, quantum_left, quantum_ticks, aging_left;
} refresh_trace[PMA_TRACE_CAPACITY];
static thread_t *refresh_trace_low;
static unsigned refresh_trace_count, refresh_trace_overflow, refresh_trace_dispatches, refresh_trace_charges;
static uint64_t refresh_trace_entry, refresh_trace_irq_rip, refresh_trace_irq_flags;
static uint64_t refresh_trace_wrapper_entry;
static unsigned refresh_trace_injected_returns;
extern volatile int pma_sched_observe_enabled __attribute__((weak));
enum { OBS_NONE, OBS_ORDINARY, OBS_CREDIT, OBS_FIFO, OBS_GRANT };
static unsigned selection_phase, selection_armed, selection_observed;
static thread_t *selection_low, *selection_peer, *aged_fifo_threads[3];
static uint64_t selection_run_start;
static unsigned ordinary_selection_ok, credit_terminal_ok, credit_initial;
static unsigned aged_fifo_selected, aged_fifo_seen[3], aged_fifo_selection_order[3], aged_fifo_selection_grants[3];
static uint64_t aged_fifo_first_wait[3];
static void grant_observe_dispatch(thread_t *t, uint64_t waited);
static unsigned pma_aging_left(const thread_t *t)
{
#ifdef SCHED_AGED_SERVICE_TICKS
    return t->aging_service_left;
#else
    (void)t;
    return 0;                                  /* test-first old policy has no protected grant */
#endif
}

/* These hooks are passive: callers already have interrupts disabled. Only
 * this lifetime's low worker is observed; flushing happens after tracing ends. */
static void refresh_trace_record(unsigned kind, thread_t *t, uint64_t now, uint64_t waited,
                                 uint64_t rip, uint64_t flags)
{
    if (t != refresh_trace_low) return;
    if (refresh_trace_count == PMA_TRACE_CAPACITY) { ++refresh_trace_overflow; return; }
    struct pma_trace_event *e = &refresh_trace[refresh_trace_count++];
    e->kind = kind; e->tick = now - refresh_start; e->run_ticks = t->run_ticks;
    e->waited = waited; e->rip = rip; e->flags = flags;
    e->state = t->state; e->quantum_left = t->quantum_left; e->quantum_ticks = t->quantum_ticks;
    e->aging_left = t->aging_service_left;
}
void pma_sched_trace_dispatch(thread_t *t, uint64_t waited)
{
    /* The separate self-test flag collects only bounded selection counters.
     * IRQ/RIP ring recording remains exclusive to the explicit trace flag. */
    if (&pma_sched_observe_enabled && pma_sched_observe_enabled) {
        if (selection_phase == OBS_GRANT) grant_observe_dispatch(t, waited);
        if (selection_armed && !selection_observed && t == selection_peer && selection_low) {
            if (selection_phase == OBS_ORDINARY) {
                ordinary_selection_ok &= !pma_aging_left(t) && selection_low->state == TS_READY &&
                    !pma_aging_left(selection_low) && !selection_low->quantum_left &&
                    selection_low->run_ticks == selection_run_start + 1;
                selection_observed = 1;
            } else if (selection_phase == OBS_CREDIT) {
                credit_terminal_ok = selection_low->state == TS_READY && !pma_aging_left(selection_low) &&
                    !selection_low->quantum_left && selection_low->run_ticks == selection_run_start + credit_initial;
                selection_observed = 1;
            }
        }
        if (selection_phase == OBS_FIFO)
            for (unsigned i = 0; i < 3; ++i)
                if (t == aged_fifo_threads[i] && !aged_fifo_seen[i]) {
                    aged_fifo_seen[i] = 1;
                    aged_fifo_first_wait[i] = waited;
                    aged_fifo_selection_grants[i] = pma_aging_left(t);
                    if (aged_fifo_selected < 3) aged_fifo_selection_order[aged_fifo_selected++] = i;
                }
    }
    if (pma_sched_trace_enabled) {
        if (t == refresh_trace_low) ++refresh_trace_dispatches;
        refresh_trace_record(0, t, ticks_now(), waited, 0, 0);
    }
}
void pma_sched_trace_irq(uint64_t rip, uint64_t flags)
{
    thread_t *t = thread_current();
    if (t != refresh_trace_low) return;
    refresh_trace_irq_rip = rip; refresh_trace_irq_flags = flags;
    refresh_trace_record(1, t, ticks_now(), 0, rip, flags);
}
void pma_sched_trace_tick(thread_t *t, uint64_t now)
{
    if (t == refresh_trace_low) ++refresh_trace_charges;
    refresh_trace_record(2, t, now, 0, refresh_trace_irq_rip, refresh_trace_irq_flags);
}
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
    if (pma_sched_trace_enabled) {
        const uint64_t f = irq_save();
        refresh_trace_entry = ticks_now() - refresh_start;
        refresh_trace_record(3, thread_current(), ticks_now(), 0, 0, f);
        irq_restore(f);
    }
    refresh_low_first = ticks_now();
    while (ticks_now() < refresh_deadline) ++refresh_low_loops;
    if (pma_sched_trace_enabled) {
        const uint64_t f = irq_save();
        refresh_trace_record(4, thread_current(), ticks_now(), 0, 0, f);
        irq_restore(f);
    }
}
/* Explicit adversarial delivery control, not evidence of natural PIT bursts.
 * Two fixed software timer interrupts traverse the real ISR/context switch
 * path before the C body. Record wrapper entry and each resumed continuation
 * separately so wrapper instructions cannot be mistaken for absent execution. */
static void __attribute__((used, noinline)) refresh_injected_mark(unsigned phase)
{
    const uint64_t f = irq_save();
    if (!phase) refresh_trace_wrapper_entry = ticks_now() - refresh_start;
    else ++refresh_trace_injected_returns;
    if (pma_sched_trace_enabled)
        refresh_trace_record(phase ? 6 : 5, thread_current(), ticks_now(), phase, 0, f);
    irq_restore(f);
}
static void __attribute__((naked)) refresh_low_injected_entry(void *arg __attribute__((unused)))
{
    __asm__ volatile(
        "xor %edi, %edi\n\t"
        "sub $8, %rsp\n\t"
        "call refresh_injected_mark\n\t"
        "add $8, %rsp\n\t"
        "int $0x20\n\t"
        "mov $1, %edi\n\t"
        "sub $8, %rsp\n\t"
        "call refresh_injected_mark\n\t"
        "add $8, %rsp\n\t"
        "int $0x20\n\t"
        "mov $2, %edi\n\t"
        "sub $8, %rsp\n\t"
        "call refresh_injected_mark\n\t"
        "add $8, %rsp\n\t"
        "xor %edi, %edi\n\t"
        "jmp refresh_low_worker\n\t");
}
static void test_policy_refresh(void)
{
    thread_t *high, *low;
    const uint64_t f = irq_save();
    const int inject = k64_cmdline_has("shz.pma=inject");
    refresh_start = ticks_now();
    refresh_deadline = refresh_start + 80;
    refresh_low_first = refresh_count = refresh_low_loops = 0;
    high = thread_create_suspended("pma-refresh", refresh_worker, 0);
    low = thread_create_suspended("pma-refresh-low", inject ? refresh_low_injected_entry : refresh_low_worker, 0);
    KASSERT(high && low);
    KASSERT(!thread_set_sched_policy(high, 31, 16, 1));
    KASSERT(!thread_set_sched_policy(low, 0, 1, 1));
    const int trace = k64_cmdline_has("shz.pma=trace");
    refresh_trace_low = low;
    refresh_trace_count = refresh_trace_overflow = refresh_trace_dispatches = refresh_trace_charges = 0;
    refresh_trace_entry = refresh_trace_irq_rip = refresh_trace_irq_flags = 0;
    refresh_trace_wrapper_entry = refresh_trace_injected_returns = 0;
    pma_sched_trace_enabled = trace;
    thread_resume(high);
    thread_resume(low);
    irq_restore(f);
    thread_join(high);
    thread_join(low);
    const uint64_t end_flags = irq_save();
    pma_sched_trace_enabled = 0;
    const uint64_t own_wait = low->max_ready_wait_ticks, own_run = low->run_ticks;
    refresh_trace_low = 0;
    irq_restore(end_flags);
    PMA_CHECK("repeated quantum policy updates cannot postpone an aged ready worker", refresh_count > 1000 &&
              refresh_low_loops > 1000 && refresh_low_first - refresh_start <= 40);
    kprintf("K64 PMA refresh: updates=%llu low_first=%llu low_loops=%llu\n",
            refresh_count, refresh_low_first - refresh_start, refresh_low_loops);
    if (trace) {
        static const char *const kinds[] = {"dispatch", "irq", "charge", "entry", "end", "wrapper", "continuation"};
        kprintf("K64 PMA trace: worker=%u ready_wait=%llu run_ticks=%llu dispatches=%u charges=%u entry=%llu events=%u overflow=%u injected=%u\n",
                low->id, own_wait, own_run, refresh_trace_dispatches, refresh_trace_charges,
                refresh_trace_entry, refresh_trace_count, refresh_trace_overflow, refresh_trace_injected_returns);
        if (inject)
            kprintf("K64 PMA trace model: fixed_interrupts=2 wrapper_entry=%llu resumed_continuations=%u hardware_burst_claim=0\n",
                    refresh_trace_wrapper_entry, refresh_trace_injected_returns);
        for (unsigned i = 0; i < refresh_trace_count; ++i) {
            const struct pma_trace_event *e = &refresh_trace[i];
            kprintf("K64 PMA trace event: kind=%s tick=%llu run=%llu wait=%llu state=%u quantum=%u/%u aging_left=%u rip=%llx flags=%llx\n",
                    kinds[e->kind], e->tick, e->run_ticks, e->waited, e->state,
                    e->quantum_left, e->quantum_ticks, e->aging_left, e->rip, e->flags);
        }
    }
}

static volatile unsigned credit_control_done;
static unsigned credit_steps_ok, credit_setters_ok, credit_issued, credit_peer_observed;
static uint64_t credit_control_deadline;
static void ordinary_control_peer(void *arg) { (void)arg; }
static void ordinary_control_worker(void *arg)
{
    (void)arg;
    const uint64_t f = irq_save();
    selection_run_start = thread_current()->run_ticks;
    ordinary_selection_ok = !pma_aging_left(thread_current()) && thread_current()->quantum_left == 1;
    selection_armed = 1;
    thread_resume(selection_peer);
    __asm__ volatile("int $0x20" ::: "memory");  /* IF0: exact eligible accounting control */
    ordinary_selection_ok &= selection_observed;
    irq_restore(f);
}
static void credit_control_worker(void *arg)
{
    (void)arg;
    const uint64_t f = irq_save();
    thread_t *t = thread_current();
    credit_initial = pma_aging_left(t);          /* never manufacture or refill a grant */
    selection_run_start = t->run_ticks;
    credit_steps_ok = credit_setters_ok = credit_initial > 0 && credit_initial <= 4;
    if (credit_steps_ok) {
        for (unsigned left = credit_initial; left > 1; --left) {
            const uint64_t before_tick = ticks_now(), before_run = t->run_ticks;
            __asm__ volatile("int $0x20" ::: "memory");
            ++credit_issued;
            credit_steps_ok &= thread_current() == t && ticks_now() == before_tick + 1 &&
                t->run_ticks == before_run + 1 && pma_aging_left(t) == left - 1;
            const unsigned remaining = pma_aging_left(t);
            KASSERT(!thread_set_sched_policy(t, 0, 16, 1));
            KASSERT(!thread_set_sched_policy(t, 0, 1, 1));
            credit_setters_ok &= pma_aging_left(t) == remaining;
        }
        const unsigned terminal_remaining = pma_aging_left(t);
        KASSERT(!thread_set_sched_policy(t, 0, 16, 1));
        KASSERT(!thread_set_sched_policy(t, 0, 1, 1));
        credit_setters_ok &= terminal_remaining == 1 && pma_aging_left(t) == terminal_remaining;
        selection_armed = 1;
        ++credit_issued;
        __asm__ volatile("int $0x20" ::: "memory");
        credit_steps_ok &= selection_observed && credit_terminal_ok && credit_peer_observed;
    }
    credit_control_done = 1;
    irq_restore(f);
}
static void credit_control_peer(void *arg)
{
    (void)arg;
    /* Publish the target only after acquiring our own IF0 context. Keeping
     * this guard across sleeps lets other contexts receive real PIT ticks;
     * after the terminal INT we can observe READY/zero before its continuation
     * without another hardware IRQ interrupting this accounting observation. */
    const uint64_t f = irq_save();
    credit_control_deadline = ticks_now() + 256;
    thread_resume(selection_low);
    while (!credit_control_done && ticks_now() < credit_control_deadline) {
        if (selection_armed && !credit_peer_observed)
            credit_peer_observed = selection_low->state == TS_READY && !pma_aging_left(selection_low) &&
                selection_low->run_ticks == selection_run_start + credit_initial;
        thread_sleep_ms(1);
    }
    irq_restore(f);
}
static void test_eligible_credit_accounting(void)
{
    uint64_t f = irq_save();
    selection_phase = OBS_ORDINARY; selection_armed = selection_observed = ordinary_selection_ok = 0;
    selection_low = thread_create_suspended("pma-q1-control", ordinary_control_worker, 0);
    selection_peer = thread_create_suspended("pma-q1-peer", ordinary_control_peer, 0);
    KASSERT(selection_low && selection_peer);
    KASSERT(!thread_set_sched_policy(selection_low, 31, 1, 1));
    KASSERT(!thread_set_sched_policy(selection_peer, 31, 1, 1));
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 1;
    thread_resume(selection_low);
    irq_restore(f);
    thread_join(selection_low); thread_join(selection_peer);
    PMA_CHECK("ordinary one-tick dispatch yields to an equal priority peer after one eligible tick", ordinary_selection_ok);
    f = irq_save();
    selection_phase = OBS_CREDIT; selection_armed = selection_observed = credit_terminal_ok = 0;
    credit_initial = credit_steps_ok = credit_setters_ok = credit_issued = credit_control_done = credit_peer_observed = 0;
    credit_control_deadline = ticks_now() + 256;
    selection_low = thread_create_suspended("pma-credit-control", credit_control_worker, 0);
    selection_peer = thread_create_suspended("pma-credit-peer", credit_control_peer, 0);
    KASSERT(selection_low && selection_peer);
    KASSERT(!thread_set_sched_policy(selection_low, 0, 1, 1));
    KASSERT(!thread_set_sched_policy(selection_peer, 31, 1, 1));
    thread_resume(selection_peer);
    irq_restore(f);
    thread_join(selection_low); thread_join(selection_peer);
    f = irq_save();
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 0;
    selection_phase = OBS_NONE; selection_low = selection_peer = 0;
    irq_restore(f);
    PMA_CHECK("each controlled eligible tick spends real remaining credit without setter refill", credit_steps_ok &&
              credit_setters_ok && credit_issued == credit_initial && credit_terminal_ok && sched_validate());
    kprintf("K64 PMA credit control: initial=%u issued=%u steps=%u setters=%u terminal=%u peer_before_continuation=%u savedIF=0 software_only=1\n",
            credit_initial, credit_issued, credit_steps_ok, credit_setters_ok, credit_terminal_ok, credit_peer_observed);
}

/* Real scheduler lifecycle controls. Software timer deliveries at raised IRQL
 * are explicit accounting controls, not natural hardware delivery evidence. */
static thread_t *grant_low, *grant_high, *grant_arrival, *grant_coordinator;
static ksem_t grant_gate, grant_complete;
static volatile unsigned grant_stage, grant_done, grant_yield_clear, grant_wait_clear, grant_terminal;
static unsigned grant_seen, grant_setter_ok, grant_irql_ok, grant_arrival_ok;
static uint64_t grant_deadline, grant_run_start, grant_remaining_at_arrival, grant_arrival_wait, grant_loops;
static unsigned grant_first_seen, grant_first_ok, grant_coordinator_blocked, grant_completed;
static uint64_t grant_first_wait, grant_first_tick, grant_first_low_ticks, grant_body_tick;
static struct {
    uint64_t tick, waited, low_ticks;
    unsigned id, role, credit;
} grant_dispatches[16];
static unsigned grant_dispatch_count, grant_dispatch_overflow;
static void grant_observe_dispatch(thread_t *t, uint64_t waited)
{
    if (grant_stage != 3 || grant_done) return;
    if (grant_dispatch_count < 16) {
        const unsigned i = grant_dispatch_count++;
        grant_dispatches[i].tick = ticks_now(); grant_dispatches[i].waited = waited;
        grant_dispatches[i].low_ticks = grant_low->run_ticks - grant_run_start;
        grant_dispatches[i].id = t->id; grant_dispatches[i].credit = pma_aging_left(t);
        grant_dispatches[i].role = t == grant_coordinator ? 1 : t == grant_low ? 2 :
            t == grant_high ? 3 : t == grant_arrival ? 4 : 0;
    } else ++grant_dispatch_overflow;
    if (t == grant_arrival && !grant_first_seen) {
        grant_first_seen = 1; grant_first_wait = waited; grant_first_tick = ticks_now();
        grant_first_low_ticks = grant_low->run_ticks - grant_run_start;
        grant_coordinator_blocked = grant_coordinator->state == TS_BLOCKED &&
            grant_coordinator->wait_sem == &grant_complete;
        grant_first_ok = grant_coordinator_blocked && grant_low->state == TS_READY && !pma_aging_left(grant_low) &&
            grant_first_low_ticks <= grant_remaining_at_arrival && waited <= grant_remaining_at_arrival;
    }
}
static void grant_arrival_worker(void *arg)
{
    (void)arg;
    const uint64_t f = irq_save();
    grant_body_tick = ticks_now();
    grant_arrival_wait = thread_current()->max_ready_wait_ticks;
    grant_arrival_ok = grant_first_seen && grant_first_ok &&
        grant_low->state == TS_READY && !pma_aging_left(grant_low) &&
        grant_low->run_ticks - grant_run_start <= grant_remaining_at_arrival &&
        grant_arrival_wait <= grant_remaining_at_arrival;
    grant_terminal = 1;
    irq_restore(f);
}
static void grant_low_worker(void *arg)
{
    (void)arg;
    const uint64_t f = irq_save();
    sched_policy_t base;
    thread_t *t = thread_current();
    grant_seen = pma_aging_left(t);
    grant_setter_ok = grant_seen > 0 && grant_seen <= 4 &&
        !thread_get_sched_policy(t, &base) && base.priority == 0 && base.quantum_ticks == 1;
    for (unsigned i = 0; i < 32; ++i) {
        KASSERT(!thread_set_sched_policy(t, 0, i & 1 ? 1 : 16, 1));
        grant_setter_ok &= pma_aging_left(t) == grant_seen;
    }
#ifdef SHZ_STANDALONE
    uint64_t old_irql, before_ticks = ticks_now(), before_run = t->run_ticks;
    const unsigned before_quantum = t->quantum_left;
    __asm__ volatile("mov %%cr8, %0" : "=r"(old_irql));
    const uint64_t raised = 2;
    __asm__ volatile("mov %0, %%cr8" :: "r"(raised) : "memory");
    __asm__ volatile("int $0x20; int $0x20" ::: "memory");
    __asm__ volatile("mov %0, %%cr8" :: "r"(old_irql) : "memory");
    grant_irql_ok = grant_seen > 0 && thread_current() == t && ticks_now() == before_ticks + 2 &&
        t->run_ticks == before_run + 2 && t->quantum_left == before_quantum && pma_aging_left(t) == grant_seen;
#else
    grant_irql_ok = 1;                          /* Supervisor profile has no standalone CR8 policy */
#endif
    grant_stage = 1;
    thread_yield();                             /* successor observes READY with no carried grant */
    grant_stage = 2;
    sem_wait(&grant_gate);                      /* successor observes BLOCKED with no carried grant */
    grant_stage = 3;
    grant_run_start = t->run_ticks;
    grant_remaining_at_arrival = pma_aging_left(t);
    KASSERT(!thread_set_sched_policy(grant_high, 0, 1, 1));
    thread_resume(grant_arrival);                /* a genuinely new higher-priority READY arrival */
    const uint64_t end = ticks_now() + 12;
    irq_restore(f);
    while (!grant_terminal && ticks_now() < end) ++grant_loops;
    const uint64_t done_flags = irq_save();
    grant_done = 1;
    sem_post(&grant_complete);
    irq_restore(done_flags);
}
static void grant_high_worker(void *arg)
{
    (void)arg;
    unsigned posted = 0;
    while (!grant_done && ticks_now() < grant_deadline) {
        const uint64_t f = irq_save();
        if (grant_stage == 1 && grant_low->state == TS_READY)
            grant_yield_clear = !pma_aging_left(grant_low);
        if (grant_stage == 2 && grant_low->state == TS_BLOCKED && !posted) {
            grant_wait_clear = !pma_aging_left(grant_low);
            sem_post(&grant_gate);
            posted = 1;
        }
        irq_restore(f);
    }
    if (!posted) sem_post(&grant_gate);          /* failed policy cannot strand the bounded fixture */
}
static void test_aging_grant_lifecycle(void)
{
    const uint64_t f = irq_save();
    grant_stage = grant_done = grant_yield_clear = grant_wait_clear = grant_terminal = 0;
    grant_seen = grant_setter_ok = grant_irql_ok = grant_arrival_ok = 0;
    grant_run_start = grant_remaining_at_arrival = grant_arrival_wait = grant_loops = 0;
    grant_first_seen = grant_first_ok = grant_dispatch_count = grant_dispatch_overflow = 0;
    grant_first_wait = grant_first_tick = grant_first_low_ticks = grant_body_tick = 0;
    grant_coordinator_blocked = grant_completed = 0;
    grant_coordinator = thread_current();
    selection_phase = OBS_GRANT;
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 1;
    grant_deadline = ticks_now() + 256;
    sem_init(&grant_gate, 0);
    sem_init(&grant_complete, 0);
    grant_low = thread_create_suspended("pma-grant-low", grant_low_worker, 0);
    grant_high = thread_create_suspended("pma-grant-high", grant_high_worker, 0);
    grant_arrival = thread_create_suspended("pma-grant-new", grant_arrival_worker, 0);
    KASSERT(grant_low && grant_high && grant_arrival);
    KASSERT(!thread_set_sched_policy(grant_low, 0, 1, 1));
    KASSERT(!thread_set_sched_policy(grant_high, 31, 1, 1));
    KASSERT(!thread_set_sched_policy(grant_arrival, 31, 1, 1));
    thread_resume(grant_low); thread_resume(grant_high);
    /* Joining keeps the coordinator READY, so it can become another aged
     * contender and receive its own grant before the new arrival. Block it
     * throughout the isolated measurement; finite timeout still diagnoses a
     * stranded worker without silently claiming that isolation held. */
    grant_completed = sem_wait_timeout(&grant_complete, 512) == 0;
    irq_restore(f);
    thread_join(grant_low); thread_join(grant_high); thread_join(grant_arrival);
    const uint64_t observer_flags = irq_save();
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 0;
    selection_phase = OBS_NONE;
    irq_restore(observer_flags);
    PMA_CHECK("policy setters cannot renew an independent aged service grant", grant_setter_ok);
    PMA_CHECK("IRQL2 timer accounting preserves the dispatchable aged grant", grant_irql_ok);
    PMA_CHECK("yield semaphore wait and exit relinquish unused aged credit", grant_seen &&
              grant_yield_clear && grant_wait_clear && !pma_aging_left(grant_low) && sched_validate());
    PMA_CHECK("a new higher priority arrival waits only the remaining isolated aging grant", grant_seen &&
              grant_completed && grant_terminal && grant_arrival_ok &&
              grant_remaining_at_arrival > 0 && grant_remaining_at_arrival <= 4);
    kprintf("K64 PMA grant: initial=%u setters=%u irql2=%u yield_clear=%u wait_clear=%u arrival_wait=%llu remaining=%llu terminal=%u\n",
            grant_seen, grant_setter_ok, grant_irql_ok, grant_yield_clear, grant_wait_clear,
            grant_arrival_wait, grant_remaining_at_arrival, grant_arrival_ok);
    kprintf("K64 PMA grant selection: seen=%u first_wait=%llu low_eligible=%llu first_tick=%llu body_delay=%llu coordinator_blocked=%u completed=%u records=%u overflow=%u\n",
            grant_first_seen, grant_first_wait, grant_first_low_ticks, grant_first_tick,
            grant_first_seen ? grant_body_tick - grant_first_tick : 0, grant_coordinator_blocked, grant_completed,
            grant_dispatch_count, grant_dispatch_overflow);
    for (unsigned i = 0; i < grant_dispatch_count; ++i)
        kprintf("K64 PMA grant dispatch: role=%u id=%u tick=%llu wait=%llu grant=%u low_eligible=%llu\n",
                grant_dispatches[i].role, grant_dispatches[i].id, grant_dispatches[i].tick,
                grant_dispatches[i].waited, grant_dispatches[i].credit, grant_dispatches[i].low_ticks);
}

static volatile unsigned aged_fifo_done;
static unsigned aged_fifo_order[3], aged_fifo_grants[3];
static uint64_t aged_fifo_first[3], aged_fifo_loops[3], aged_fifo_start, aged_fifo_deadline;
static void aged_fifo_worker(void *arg)
{
    const unsigned index = (unsigned)(uintptr_t)arg;
    /* One declared delivery per worker stresses reclaim by OTHER aged heads. */
    __asm__ volatile("int $0x20" ::: "memory");
    const uint64_t f = irq_save();
    aged_fifo_first[index] = ticks_now() - aged_fifo_start;
    aged_fifo_grants[index] = pma_aging_left(thread_current());
    aged_fifo_order[aged_fifo_done++] = index;
    irq_restore(f);
    /* Fixed useful CPU work avoids a delivered pending tick ending a short
     * observation window before its first loop instruction. */
    while (aged_fifo_loops[index] < 2048) {
        ++aged_fifo_loops[index];
        __asm__ volatile("" ::: "memory");
    }
}
static void aged_fifo_high(void *arg)
{
    (void)arg;
    while (aged_fifo_done < 3 && ticks_now() < aged_fifo_deadline) __asm__ volatile("" ::: "memory");
}
static void test_multiple_aged_fifo(void)
{
    thread_t *low[3], *high;
    const uint64_t f = irq_save();
    aged_fifo_start = ticks_now(); aged_fifo_deadline = aged_fifo_start + 256;
    aged_fifo_done = 0;
    selection_phase = OBS_FIFO;
    aged_fifo_selected = 0;
    memset(aged_fifo_threads, 0, sizeof aged_fifo_threads);
    memset(aged_fifo_seen, 0, sizeof aged_fifo_seen);
    memset(aged_fifo_selection_order, 0xff, sizeof aged_fifo_selection_order);
    memset(aged_fifo_selection_grants, 0, sizeof aged_fifo_selection_grants);
    memset(aged_fifo_first_wait, 0, sizeof aged_fifo_first_wait);
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 1;
    memset(aged_fifo_order, 0xff, sizeof aged_fifo_order);
    memset(aged_fifo_grants, 0, sizeof aged_fifo_grants);
    memset(aged_fifo_first, 0, sizeof aged_fifo_first);
    memset(aged_fifo_loops, 0, sizeof aged_fifo_loops);
    high = thread_create_suspended("pma-aged-high", aged_fifo_high, 0);
    KASSERT(high && !thread_set_sched_policy(high, 31, 1, 1));
    thread_resume(high);
    for (unsigned i = 0; i < 3; ++i) {
        low[i] = thread_create_suspended("pma-aged-fifo", aged_fifo_worker, (void *)(uintptr_t)i);
        KASSERT(low[i] && !thread_set_sched_policy(low[i], 0, 1, 1));
        aged_fifo_threads[i] = low[i];
        thread_resume(low[i]);
    }
    irq_restore(f);
    for (unsigned i = 0; i < 3; ++i) thread_join(low[i]);
    thread_join(high);
    const uint64_t end_flags = irq_save();
    if (&pma_sched_observe_enabled) pma_sched_observe_enabled = 0;
    selection_phase = OBS_NONE;
    irq_restore(end_flags);
    unsigned ok = aged_fifo_done == 3 && aged_fifo_selected == 3;
    for (unsigned i = 0; i < 3; ++i)
        ok &= aged_fifo_selection_order[i] == i && aged_fifo_selection_grants[i] == 4 &&
            aged_fifo_first_wait[i] <= 32 + i * 4 && aged_fifo_loops[i] > 1000;
    PMA_CHECK("multiple aged FIFO heads receive bounded first selections and eventual useful work", ok && sched_validate());
    kprintf("K64 PMA aged selections: order=%u/%u/%u ready_wait=%llu/%llu/%llu grants=%u/%u/%u\n",
            aged_fifo_selection_order[0], aged_fifo_selection_order[1], aged_fifo_selection_order[2],
            aged_fifo_first_wait[0], aged_fifo_first_wait[1], aged_fifo_first_wait[2],
            aged_fifo_selection_grants[0], aged_fifo_selection_grants[1], aged_fifo_selection_grants[2]);
    kprintf("K64 PMA aged FIFO: order=%u/%u/%u first=%llu/%llu/%llu grants=%u/%u/%u loops=%llu/%llu/%llu injected=3\n",
            aged_fifo_order[0], aged_fifo_order[1], aged_fifo_order[2], aged_fifo_first[0], aged_fifo_first[1],
            aged_fifo_first[2], aged_fifo_grants[0], aged_fifo_grants[1], aged_fifo_grants[2],
            aged_fifo_loops[0], aged_fifo_loops[1], aged_fifo_loops[2]);
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
    test_eligible_credit_accounting();
    test_aging_grant_lifecycle();
    test_multiple_aged_fifo();
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
