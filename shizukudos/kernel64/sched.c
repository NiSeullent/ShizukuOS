/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 preemptive uniprocessor scheduler: priority FIFO ready queues,
 * bounded aging, configurable quantums, kernel/user threads, sleep and waits.
 * The tick is the Supervisor's paravirtual timer (vector 0x20), or standalone PIT.
 * Each thread owns an FXSAVE area so user-mode SSE state survives preemption.
 *
 * The UP IRQ guard protects queue and wait-list transitions together. No queue
 * lock is held across a context switch; restoring each saved context restores
 * its interrupt state. This is not an SMP lock or a replacement for Windows VMM.
 */
#include "k64.h"
extern int ntdrv_gs_all;                     /* ntdrv_ke.c: set once the driver host runs code that reads the KPCR through GS */

extern void switch_stacks(uint64_t *save_rsp, uint64_t new_rsp);
extern void thread_start(void);

#define MAX_THREADS 1024        /* a multi-process Chromium run holds a few hundred; the table is sized once, from the page allocator */

static void kstack_free(uint64_t base);
static thread_t *threads;       /* MAX_THREADS slots (sched_init); slots >= thread_hi have never been used */
static unsigned thread_hi;      /* high-water mark of the slot search: every loop over the table stops here, not at MAX_THREADS */
static thread_t *current;
static thread_t *idle_thread;
static uint32_t next_id = 1;
static volatile uint64_t jiffies;
static uint64_t switches;
static uint64_t preemptions, wakeups, timeouts, ready_order;
static struct { thread_t *head, *tail; } ready[SCHED_PRIORITY_LEVELS];
static uint32_t ready_mask, ready_count;
static uint64_t cpu_idle_ticks, cpu_kernel_ticks, cpu_user_ticks;
uint64_t g_kstack_top;
uint64_t g_user_rsp_scratch;

uint64_t ticks_now(void) { return jiffies; }
uint64_t sched_switch_count(void) { return switches; }
void sched_processor_times(uint64_t *idle, uint64_t *kernel, uint64_t *user)
{
    const uint64_t flags = irq_save();
    *idle = cpu_idle_ticks * (TICK_US * 10ull);
    *kernel = (cpu_idle_ticks + cpu_kernel_ticks) * (TICK_US * 10ull);
    *user = cpu_user_ticks * (TICK_US * 10ull);
    irq_restore(flags);
}
thread_t *thread_current(void) { return current; }
static int thread_pointer_valid(const thread_t *t);
static void ready_enqueue(thread_t *t);
static void ready_remove(thread_t *t);

int thread_set_sched_policy(thread_t *t, unsigned priority, unsigned quantum_ticks, uint64_t cpu_mask)
{
    uint64_t f;
    if (priority >= SCHED_PRIORITY_LEVELS || !quantum_ticks || quantum_ticks > SCHED_MAX_QUANTUM_TICKS || cpu_mask != 1)
        return -1;
    f = irq_save();
    if (!thread_pointer_valid(t) || t == idle_thread || t->state == TS_FREE || t->state == TS_ZOMBIE) {
        irq_restore(f);
        return -1;
    }
    const int move = t->ready_queued && priority != t->sched_priority;
    if (move) ready_remove(t);             /* remove under the old priority */
    t->sched_priority = priority;
    t->quantum_ticks = quantum_ticks;
    /* Updating policy cannot renew the slice currently being consumed. A
     * larger quantum takes effect on the next dispatch; a smaller one clamps
     * the remainder. Otherwise a CPU-bound caller could avoid expiry forever. */
    if (t->state != TS_RUNNING || t->quantum_left > quantum_ticks)
        t->quantum_left = quantum_ticks;
    t->cpu_mask = cpu_mask;
    if (move) ready_enqueue(t);            /* FIFO arrival in the new priority */
    irq_restore(f);
    return 0;
}

int thread_get_sched_policy(thread_t *t, sched_policy_t *out)
{
    const uint64_t f = irq_save();
    if (!out || !thread_pointer_valid(t) || t->state == TS_FREE || t->state == TS_ZOMBIE) {
        irq_restore(f);
        return -1;
    }
    out->priority = t->sched_priority;
    out->quantum_ticks = t->quantum_ticks;
    out->cpu_mask = t->cpu_mask;
    irq_restore(f);
    return 0;
}

void sched_get_stats(sched_stats_t *out)
{
    unsigned i;
    uint64_t f;
    if (!out) return;
    f = irq_save();
    memset(out, 0, sizeof *out);
    out->ticks = jiffies;
    out->context_switches = switches;
    out->preemptions = preemptions;
    out->wakeups = wakeups;
    out->timeouts = timeouts;
    out->ready_threads = ready_count;       /* idle is never in a runnable queue */
    out->cpu_count = 1;
    for (i = 0; i < thread_hi; ++i) {
        out->live_threads += threads[i].state != TS_FREE;
        out->zombie_threads += threads[i].state == TS_ZOMBIE;
    }
    irq_restore(f);
}

int sched_validate(void)
{
    uint8_t seen[MAX_THREADS] = {0};
    unsigned p, n = 0, i;
    uint32_t mask = 0;
    int ok = 1;
    const uint64_t f = irq_save();
    if (!thread_pointer_valid(current) || !thread_pointer_valid(idle_thread) || current->state != TS_RUNNING)
        ok = 0;
    for (p = 0; ok && p < SCHED_PRIORITY_LEVELS; ++p) {
        thread_t *t = ready[p].head, *prev = 0;
        if (t) mask |= 1u << p;
        while (t) {
            if (++n > MAX_THREADS || !thread_pointer_valid(t) || t == idle_thread ||
                t->state != TS_READY || !t->ready_queued || t->sched_priority != p || t->ready_prev != prev) {
                ok = 0;
                break;
            }
            i = (unsigned)(t - threads);
            if (seen[i]++) { ok = 0; break; }
            prev = t;
            t = t->ready_next;
        }
        if (prev != ready[p].tail) ok = 0;
    }
    if (mask != ready_mask || n != ready_count) ok = 0;
    for (i = 0; ok && i < thread_hi; ++i) {
        thread_t *t = &threads[i];
        const int queued = t->state == TS_READY && t != idle_thread;
        if (t->state > TS_NEW || !!t->ready_queued != queued || !!seen[i] != queued ||
            (!queued && (t->ready_prev || t->ready_next)) ||
            (t->state == TS_RUNNING && t != current) ||
            (t->state != TS_FREE && (t->sched_priority >= SCHED_PRIORITY_LEVELS || !t->quantum_ticks ||
             t->quantum_ticks > SCHED_MAX_QUANTUM_TICKS || t->cpu_mask != 1))) ok = 0;
    }
    irq_restore(f);
    return ok;
}

thread_t *thread_find_tid(void *process, uint64_t tid)
{
    unsigned i;
    for (i = 0; i < thread_hi; ++i)
        if (threads[i].state != TS_FREE && threads[i].state != TS_ZOMBIE && threads[i].proc == process && threads[i].tid == tid)
            return &threads[i];
    return 0;
}

/* IPC hook (kernel64/ipc_core.c): visits every allocated thread slot with interrupts off (kill wake-ups, reaping the
 * kernel stacks of exited user threads). */
void sched_for_each_thread(void (*fn)(thread_t *, void *), void *ctx)
{
    unsigned i;
    for (i = 0; i < thread_hi; ++i) {
        const uint64_t f = irq_save();
        if (threads[i].state != TS_FREE) fn(&threads[i], ctx);
        irq_restore(f);
    }
}

static int thread_pointer_valid(const thread_t *t)
{
    const uintptr_t base = (uintptr_t)threads, addr = (uintptr_t)t;
    return threads && addr >= base && addr - base < sizeof(*threads) * thread_hi &&
           (addr - base) % sizeof(*threads) == 0;
}

/* All runnable transitions are here; wait links are never used for run queues. */
static void ready_enqueue(thread_t *t)
{
    const unsigned p = t->sched_priority;
    KASSERT(t->state == TS_READY && !t->ready_queued && p < SCHED_PRIORITY_LEVELS);
    if (t == idle_thread) return;
    t->ready_prev = ready[p].tail;
    t->ready_next = 0;
    if (ready[p].tail) ready[p].tail->ready_next = t;
    else ready[p].head = t;
    ready[p].tail = t;
    t->ready_since = jiffies;
    t->ready_order = ++ready_order;
    t->ready_queued = 1;
    ready_mask |= 1u << p;
    ++ready_count;
}

static void ready_remove(thread_t *t)
{
    const unsigned p = t->sched_priority;
    KASSERT(t->ready_queued && ready_count && p < SCHED_PRIORITY_LEVELS);
    if (t->ready_prev) t->ready_prev->ready_next = t->ready_next;
    else ready[p].head = t->ready_next;
    if (t->ready_next) t->ready_next->ready_prev = t->ready_prev;
    else ready[p].tail = t->ready_prev;
    if (!ready[p].head) ready_mask &= ~(1u << p);
    t->ready_prev = t->ready_next = 0;
    t->ready_queued = 0;
    --ready_count;
}

static void make_ready(thread_t *t)
{
    if (t->state == TS_READY || t->state == TS_RUNNING) return;
    if (t->state == TS_BLOCKED) ++wakeups;
    t->state = TS_READY;
    ready_enqueue(t);
}

static thread_t *pick_aged(void)
{
    thread_t *oldest = 0;
    int p;
    /* Only FIFO heads can be selected. Once aged, the oldest arrival wins,
     * independent of priority; newer arrivals cannot jump in front of it. */
    for (p = (int)SCHED_PRIORITY_LEVELS - 1; p >= 0; --p) {
        thread_t *t = ready[p].head;
        if (t && jiffies - t->ready_since >= SCHED_STARVATION_TICKS &&
            (!oldest || t->ready_order < oldest->ready_order)) oldest = t;
    }
    return oldest;
}

static thread_t *pick_next(void)
{
    thread_t *oldest = pick_aged();
    int p;
    if (oldest) return oldest;
    for (p = (int)SCHED_PRIORITY_LEVELS - 1; p >= 0; --p)
        if (ready_mask & (1u << p)) return ready[p].head;
    return idle_thread;
}

static inline uint64_t rdtsc(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }

thread_t *thread_slot(unsigned i) { return i < thread_hi ? &threads[i] : 0; }

uint64_t thread_cycles_now(thread_t *t)
{
    const uint64_t f = irq_save();
    uint64_t c = t->cycles;
    if (t == current && t->tsc_in) c += rdtsc() - t->tsc_in;
    irq_restore(f);
    return c;
}

static inline void fx_save(thread_t *t) { __asm__ volatile("fxsave (%0)" :: "r"(t->fx) : "memory"); }
static inline void fx_restore(thread_t *t) { __asm__ volatile("fxrstor (%0)" :: "r"(t->fx) : "memory"); }

/* Interrupts must be disabled. */
static void schedule(int from_tick)
{
    thread_t *prev = current, *next;
    if (prev->state == TS_RUNNING) {
        prev->state = TS_READY;
        ready_enqueue(prev);
    }
    next = pick_next();
    if (next != idle_thread) {
        const uint64_t waited = jiffies - next->ready_since;
        if (waited > next->max_ready_wait_ticks) next->max_ready_wait_ticks = waited;
        ready_remove(next);
    }
    next->state = TS_RUNNING;
    next->quantum_left = next->quantum_ticks;
    if (next == prev) {
        return;
    }
    current = next;
    ++switches;
    if (from_tick) ++preemptions;
    tss_set_rsp0(next->stack_base + KSTACK_BYTES);
    g_kstack_top = next->stack_base + KSTACK_BYTES;
    {
        const uint64_t want = next->proc ? proc_pml4(next->proc) : kernel_pml4();
        if (read_cr3() != want)
            write_cr3(want);
    }
    if (prev->teb || next->teb || ntdrv_gs_all) {      /* ntdrv_gs_all: hosted drivers read a per-thread KPCR through GS (ntdrv_ke.c) */
        prev->user_gs_base = rdmsr(MSR_GS_BASE);
        wrmsr(MSR_GS_BASE, next->user_gs_base);
    }
    {
        const uint64_t now = rdtsc();                   /* cycle accounting: the slice prev just ran */
        if (prev->tsc_in) prev->cycles += now - prev->tsc_in;
        prev->tsc_in = 0;
        next->tsc_in = now;
    }
    fx_save(prev);
    fx_restore(next);
#ifdef SHZ_STANDALONE
    {   /* IRQL lives in CR8 there (a hosted NT driver writes it directly, kernel64/ntdrv_ke.c) and is per thread once a
         * thread can block at APC_LEVEL: a thread that leaves the CPU keeps its own value, the one that runs next gets its own */
        uint64_t v;
        __asm__ volatile("mov %%cr8, %0" : "=r"(v));
        prev->cr8 = v;
        v = next->cr8;
        __asm__ volatile("mov %0, %%cr8" : : "r"(v) : "memory");
    }
#endif
    switch_stacks(&prev->rsp, next->rsp);
}

void __attribute__((weak)) sched_check_timeouts(uint64_t now) { (void)now; }       /* objects.c overrides */
void __attribute__((weak)) thread_object_signal(thread_t *t) { (void)t; }          /* objects.c overrides */

static int tick_from_user;

void sched_tick_from(int user_mode)
{
    tick_from_user = user_mode;
    sched_tick();
}

void sched_tick(void)
{
    unsigned i;
    ++jiffies;
    if (current == idle_thread) ++cpu_idle_ticks;
    else if (tick_from_user) ++cpu_user_ticks;
    else ++cpu_kernel_ticks;
    current->run_ticks++;
    if (tick_from_user) current->user_ticks++; else current->kernel_ticks++;
#ifdef SHZ_STANDALONE
    if (tick_from_user) {   /* ring 3 always runs at PASSIVE_LEVEL: a raise that leaked out of a driver call must not stop preemption */
        uint64_t zero = 0;
        __asm__ volatile("mov %0, %%cr8" : : "r"(zero) : "memory");
    }
#endif
    tick_from_user = 0;
    for (i = 0; i < thread_hi; ++i)
        if (threads[i].state == TS_BLOCKED && threads[i].wake_tick && threads[i].wake_tick <= jiffies) {
            threads[i].wake_tick = 0;
            if (threads[i].wait_sem) {
                ksem_t *s = threads[i].wait_sem;
                thread_t **pp;
                for (pp = &s->waiters; *pp; pp = &(*pp)->next)
                    if (*pp == &threads[i]) { *pp = threads[i].next; break; }
                threads[i].wait_sem = 0;
                threads[i].next = 0;
                threads[i].wait_result = -1;
            }
            threads[i].wait_result = threads[i].wait_result ? threads[i].wait_result : 0x102;   /* STATUS_TIMEOUT marker */
            ++timeouts;
            make_ready(&threads[i]);
        }
    sched_check_timeouts(jiffies);
#ifdef SHZ_STANDALONE
    {   /* IRQL >= DISPATCH_LEVEL (CR8, written by a hosted NT driver through the DDK's inline KfRaiseIrql, or by the
         * driver host's own KeRaiseIrql) means "no dispatching": the tick still counts and wakes sleepers, but the
         * running thread is not preempted until it lowers IRQL (kernel64/ntdrv_ke.c). Not compiled for the Supervisor
         * build, whose scheduler is unchanged and where the guest's CR8 is not the driver host's business. */
        uint64_t cr8;
        __asm__ volatile("mov %%cr8, %0" : "=r"(cr8));
        if (cr8 >= 2) return;
    }
#endif
    if (current != idle_thread && current->quantum_left > 1) {
        --current->quantum_left;
        /* Higher priority arrivals and aged FIFO heads need not wait for the
         * old quantum. Aging must also override the highest running priority. */
        const int higher_ready = current->sched_priority < SCHED_PRIORITY_LEVELS - 1 &&
            (ready_mask & (~0u << (current->sched_priority + 1)));
        if (!higher_ready && !pick_aged()) return;
    }
    schedule(1);
}

void __attribute__((weak)) thread_object_detach(thread_t *t) { (void)t; }          /* objects.c overrides */

/* Interrupts must be disabled. A user thread that has exited (TS_ZOMBIE with an owning process) is never joined, so without
 * this its slot and its 32 KiB kernel stack would stay taken for the rest of the boot and the table would eventually fill
 * (CreateThread then fails). Once such a zombie is not `current`, nothing runs on its kernel stack any more (it left through
 * schedule() with interrupts off and is never picked again). Its waitable thread object keeps the exit status (objects.c).
 * `creator_hold` keeps a thread whose creator may still read t->object (start_thread_common until the creator released it,
 * see thread_creator_release). Kernel threads (proc == 0) stay zombies until thread_join(). `only` limits it to one process. */
static void reap_user_zombies(const void *only, int drop_holds)
{
    unsigned i;
    for (i = 0; i < thread_hi; ++i) {
        thread_t *t = &threads[i];
        if (t->state == TS_FREE || !t->proc || (only && t->proc != only)) continue;
        if (drop_holds) t->creator_hold = 0;    /* also a thread still inside thread_exit(): it is reaped at a later pass */
        if (t->state != TS_ZOMBIE || t == current || t->creator_hold) continue;
        thread_object_detach(t);
        kstack_free(t->stack_base);
        t->stack_base = 0;
        t->object = 0;
        t->state = TS_FREE;
    }
}

void thread_reap_process(const void *proc)
{
    const uint64_t f = irq_save();
    reap_user_zombies(proc, 1);
    irq_restore(f);
}

void thread_reap_exited(void)
{
    const uint64_t f = irq_save();
    reap_user_zombies(0, 0);
    irq_restore(f);
}

void thread_creator_release(thread_t *t)
{
    const uint64_t f = irq_save();
    t->creator_hold = 0;
    irq_restore(f);
}

/* Kernel stacks are runs of physical pages, not heap blocks: the 12 MiB kernel heap holds ~300 of them at 32 KiB, a multi-process
 * Chromium run needs that many threads alone. */
static uint64_t kstack_alloc(void)
{
    const uint64_t pa = pmm_alloc_contig(KSTACK_BYTES / PAGE_SIZE);
    return pa ? p2v(pa) : 0;
}

static void kstack_free(uint64_t base)
{
    if (base) pmm_free_contig(base - phys_base_va, KSTACK_BYTES / PAGE_SIZE);
}

static thread_t *thread_create_state(const char *name, void (*fn)(void *), void *arg, uint32_t state)
{
    uint64_t f = irq_save(), *sp;
    thread_t *t = 0;
    unsigned i, k;
    reap_user_zombies(0, 0);
    for (i = 0; i < thread_hi && threads[i].state != TS_FREE; ++i) { }
    if (i < MAX_THREADS) t = &threads[i];
    if (!t) {
        unsigned z = 0;
        for (i = 0; i < thread_hi; ++i) z += threads[i].state == TS_ZOMBIE;
        irq_restore(f);
        kprintf("K64: thread table full (%u slots, %u exited but not reclaimable)\n", MAX_THREADS, z);
        return 0;
    }
    memset(t, 0, sizeof *t);
    t->stack_base = kstack_alloc();
    if (!t->stack_base) { irq_restore(f); kprintf("K64: no kernel stack for a new thread\n"); return 0; }
    if ((unsigned)(t - threads) >= thread_hi) thread_hi = (unsigned)(t - threads) + 1;
    t->id = next_id++;
    t->create_tick = jiffies;
    t->mem_priority = 5;                            /* MEMORY_PRIORITY_NORMAL */
    t->sched_priority = SCHED_DEFAULT_PRIORITY;
    t->quantum_ticks = t->quantum_left = 1;
    t->cpu_mask = 1;
    for (k = 0; name[k] && k < sizeof t->name - 1; ++k) t->name[k] = name[k];
    t->fx[0] = 0x7f; t->fx[1] = 0x03;               /* FCW 0x037F */
    t->fx[24] = 0x80; t->fx[25] = 0x1f;             /* MXCSR 0x1F80 */
    sp = (uint64_t *)((t->stack_base + KSTACK_BYTES) & ~0xfull);
    *--sp = (uint64_t)thread_start;                 /* ret target */
    *--sp = 0x202;                                  /* rflags: IF */
    *--sp = 0;                                      /* rbp */
    *--sp = 0;                                      /* rbx */
    *--sp = (uint64_t)fn;                           /* r12 */
    *--sp = (uint64_t)arg;                          /* r13 */
    *--sp = 0;                                      /* r14 */
    *--sp = 0;                                      /* r15 */
    t->rsp = (uint64_t)sp;
    t->state = state;
    if (state == TS_READY) ready_enqueue(t);
    irq_restore(f);
    return t;
}

thread_t *thread_create(const char *name, void (*fn)(void *), void *arg) { return thread_create_state(name, fn, arg, TS_READY); }
thread_t *thread_create_suspended(const char *name, void (*fn)(void *), void *arg)
{
    /* Never picked by pick_next() (READY only) until thread_resume(). */
    return thread_create_state(name, fn, arg, TS_NEW);
}

void thread_resume(thread_t *t)
{
    const uint64_t f = irq_save();
    if (t->state == TS_NEW)
        make_ready(t);
    irq_restore(f);
}

void thread_discard(thread_t *t)
{
    const uint64_t f = irq_save();
    if (t->state == TS_NEW) {
        kstack_free(t->stack_base);
        t->state = TS_FREE;
    }
    irq_restore(f);
}

void thread_yield(void)
{
    uint64_t f = irq_save();
    schedule(0);
    irq_restore(f);
}

void __attribute__((weak)) thread_account_exit(thread_t *t) { (void)t; }        /* sysk32.c overrides: process totals */

void thread_exit(int64_t code)
{
    uint64_t f = irq_save();
    (void)f;
    current->exit_code = code;
    current->exit_tick = jiffies;
    if (current->tsc_in) {                          /* close the last slice now: the totals are final from here on */
        const uint64_t now = rdtsc();
        current->cycles += now - current->tsc_in;
        current->tsc_in = 0;
    }
    thread_account_exit(current);
    current->state = TS_ZOMBIE;
    thread_object_signal(current);
    for (;;) {
        schedule(0);
        cli();
    }
}

int64_t thread_join(thread_t *t)
{
    for (;;) {
        uint64_t f = irq_save();
        if (t->state == TS_ZOMBIE) {
            const int64_t code = t->exit_code;
            kstack_free(t->stack_base);
            t->state = TS_FREE;
            irq_restore(f);
            return code;
        }
        schedule(0);
        irq_restore(f);
    }
}

void thread_block_current(void)
{
    current->state = TS_BLOCKED;
    schedule(0);
}

void thread_wake(thread_t *t)
{
    const uint64_t f = irq_save();
    if (t->state == TS_BLOCKED) {
        t->wake_tick = 0;
        make_ready(t);
    }
    irq_restore(f);
}

/* Convert without ms*1000 overflow and keep finite saturation distinct from
 * zero (the infinite-wait sentinel). Even sleep(0) waits at least one tick. */
static uint64_t deadline_after_ms(uint64_t ms)
{
    const uint64_t whole = ms / TICK_US;
    const uint64_t fraction = ((ms % TICK_US) * 1000u + TICK_US - 1) / TICK_US;
    uint64_t ticks;
    if (whole > (UINT64_MAX - fraction) / 1000u) return UINT64_MAX;
    ticks = whole * 1000u + fraction;
    if (!ticks) ticks = 1;
    return ticks > UINT64_MAX - jiffies ? UINT64_MAX : jiffies + ticks;
}

void thread_sleep_ms(uint64_t ms)
{
    uint64_t f = irq_save();
    current->wake_tick = deadline_after_ms(ms);
    current->state = TS_BLOCKED;
    schedule(0);
    irq_restore(f);
}

/* ---------------------------------------------------------------- semaphores / mutexes */
void sem_init(ksem_t *s, int count) { s->count = count; s->waiters = 0; }

static int sem_wait_common(ksem_t *s, uint64_t ms)
{
    uint64_t f = irq_save();
    int rc = 0;
    if (s->count > 0) {
        --s->count;
        irq_restore(f);
        return 0;
    }
    current->next = 0;
    if (!s->waiters) s->waiters = current;
    else { thread_t *w = s->waiters; while (w->next) w = w->next; w->next = current; }
    current->wait_sem = s;
    current->wake_tick = ms ? deadline_after_ms(ms) : 0;
    current->wait_result = 0;
    current->state = TS_BLOCKED;
    schedule(0);
    if (ms && current->wait_result == -1)
        rc = -1;
    current->wait_result = 0;
    irq_restore(f);
    return rc;
}

void sem_wait(ksem_t *s) { sem_wait_common(s, 0); }
int sem_wait_timeout(ksem_t *s, uint64_t ms) { return sem_wait_common(s, ms ? ms : 1); }

void sem_post(ksem_t *s)
{
    uint64_t f = irq_save();
    thread_t *w = s->waiters;
    if (w) {
        s->waiters = w->next;
        w->next = 0;
        w->wait_sem = 0;
        w->wake_tick = 0;
        make_ready(w);
    } else {
        ++s->count;
    }
    irq_restore(f);
}

void mutex_init(kmutex_t *m) { m->locked = 0; m->owner = 0; m->waiters = 0; }

void mutex_lock(kmutex_t *m)
{
    for (;;) {
        uint64_t f = irq_save();
        if (!m->locked) {
            m->locked = 1;
            m->owner = current;
            irq_restore(f);
            return;
        }
        KASSERT(m->owner != current);
        current->next = 0;
        if (!m->waiters) m->waiters = current;
        else { thread_t *w = m->waiters; while (w->next) w = w->next; w->next = current; }
        current->state = TS_BLOCKED;
        schedule(0);
        irq_restore(f);
    }
}

void mutex_unlock(kmutex_t *m)
{
    uint64_t f = irq_save();
    thread_t *w;
    KASSERT(m->locked && m->owner == current);
    m->locked = 0;
    m->owner = 0;
    w = m->waiters;
    if (w) {
        m->waiters = w->next;
        w->next = 0;
        make_ready(w);
    }
    irq_restore(f);
}

static void idle_loop(void *arg)
{
    (void)arg;
    for (;;)
        __asm__ volatile("sti; hlt");
}

void sched_init(void)
{
    const uint64_t table = pmm_alloc_contig((unsigned)((sizeof(thread_t) * MAX_THREADS + PAGE_SIZE - 1) / PAGE_SIZE));
    KASSERT(table);
    threads = (thread_t *)p2v(table);                                       /* zeroed: every slot is TS_FREE */
    memset(ready, 0, sizeof ready);
    ready_mask = ready_count = 0;
    jiffies = switches = preemptions = wakeups = timeouts = ready_order = 0;
    idle_thread = 0;
    thread_hi = 1;
    current = &threads[0];
    current->id = next_id++;
    current->state = TS_RUNNING;
    current->sched_priority = SCHED_DEFAULT_PRIORITY;
    current->quantum_ticks = current->quantum_left = 1;
    current->cpu_mask = 1;
    current->name[0] = 'm'; current->name[1] = 'a'; current->name[2] = 'i'; current->name[3] = 'n';
    current->fx[0] = 0x7f; current->fx[1] = 0x03; current->fx[24] = 0x80; current->fx[25] = 0x1f;
    {
        extern uint8_t kstack_top[];
        current->stack_base = (uint64_t)kstack_top - KSTACK_BYTES;   /* the 32 KiB boot stack */
    }
    idle_thread = thread_create("idle", idle_loop, 0);
    KASSERT(idle_thread);
    ready_remove(idle_thread);                       /* it was created before the idle identity was known */
    idle_thread->sched_priority = 0;
    idle_thread->state = TS_READY;
}
