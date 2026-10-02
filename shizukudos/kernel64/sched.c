/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 preemptive uniprocessor scheduler: priority FIFO ready queues,
 * bounded aging, configurable quantums, kernel/user threads, sleep and waits.
 * The tick is the Supervisor's paravirtual timer (vector 0x20), or standalone PIT.
 * Each thread owns an FXSAVE area so user-mode SSE state survives preemption.
 *
 * PerCPU priority queues use short IRQ-off ticket admission. Native dispatch
 * remains BSP-only until AP shared-resource/entry/IRQ/ABI dependencies are ready.
 * No ticket is held across a context switch or external wait/object callback.
 * Windows VMM remains authoritative; this is a backend scheduler foundation.
 */
#include "k64.h"
#include "sched_cpu.h"
#include "smp_boot.h"
_Static_assert(K64_CPU_MAX == SHZ_SMP_MAX_CPUS, "CPU identity domain must match queue storage");
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
static k64_runqueues_t runqueues;
/* `current` and `idle_thread` are BSP compatibility mirrors for shared UP-only
 * wait/process paths. Dispatch and entry consume the actual owner's CPU record. */

typedef struct { uint64_t flags; uint32_t ticket; } queue_guard_t;
static queue_guard_t queue_enter(void)
{
    queue_guard_t g;
    g.flags = irq_save();
    g.ticket = k64_rq_lock(&runqueues);
    return g;
}
static void queue_leave(queue_guard_t g)
{
    k64_rq_unlock(&runqueues, g.ticket);
    irq_restore(g.flags);
}
uint32_t sched_cpu_identity(void)
{
    const unsigned cpu = shz_smp_this_cpu();
    return cpu < K64_CPU_MAX ? cpu : K64_CPU_NONE;
}
static int bsp_scheduler_owner(void) { return sched_cpu_identity() == 0; }
static k64_cpu_sched_t *sched_owner_context(void)
{
    const uint32_t cpu = sched_cpu_identity();
    return k64_rq_online(&runqueues, cpu) ? &runqueues.cpu[cpu] : 0;
}
uint64_t sched_cpu_online_mask(void)
{
    queue_guard_t g = queue_enter();
    const uint64_t mask = runqueues.online_mask;
    queue_leave(g);
    return mask;
}
int sched_cpu_register(uint32_t cpu)
{
    if (cpu >= K64_CPU_MAX) return -1;
    /* Architecture ONLINE is not scheduler ONLINE. Even an actual mapped AP
     * cannot run this BSP syscall/current compatibility path. */
    return cpu == 0 && bsp_scheduler_owner() && runqueues.online_mask == 1 ? 0 : -2;
}
uint64_t g_kstack_top;
uint64_t g_user_rsp_scratch;

/* Explicit PMA diagnostic mode only. Callbacks run with interrupts disabled;
 * they must not print, allocate, block, or change scheduling policy. */
volatile int pma_sched_trace_enabled;
volatile int pma_sched_observe_enabled;          /* bounded self-test selection counters; no IRQ trace */
void __attribute__((weak)) pma_sched_trace_dispatch(thread_t *t, uint64_t waited)
{ (void)t; (void)waited; }
void __attribute__((weak)) pma_sched_trace_tick(thread_t *t, uint64_t now)
{ (void)t; (void)now; }

uint64_t ticks_now(void) { return jiffies; }
uint64_t sched_switch_count(void) { return switches; }
void sched_processor_times(uint64_t *idle, uint64_t *kernel, uint64_t *user)
{
    const uint64_t flags = irq_save();
    const k64_cpu_sched_t *cpu = sched_owner_context();
    *idle = cpu ? cpu->idle_ticks * (TICK_US * 10ull) : 0;
    *kernel = cpu ? (cpu->idle_ticks + cpu->kernel_ticks) * (TICK_US * 10ull) : 0;
    *user = cpu ? cpu->user_ticks * (TICK_US * 10ull) : 0;
    irq_restore(flags);
}
thread_t *thread_current(void)
{
    const k64_cpu_sched_t *cpu = sched_owner_context();
    return cpu ? cpu->current : 0;
}
void sched_set_current_kstack(uint64_t top)
{
    const uint64_t flags = irq_save();
    k64_cpu_sched_t *cpu = sched_owner_context();
    const uint32_t id = sched_cpu_identity();
    KASSERT(cpu && cpu->current && cpu->current->on_cpu == id &&
            top == cpu->current->stack_base + KSTACK_BYTES);
    KASSERT(arch_sched_entry_set_stack(id, top) == 0);
    if (!id) g_kstack_top = top;              /* exported CPU0 compatibility mirror */
    irq_restore(flags);
}
static int thread_pointer_valid(const thread_t *t);
static void ready_enqueue(thread_t *t);
static void ready_remove(thread_t *t);

int thread_set_sched_policy(thread_t *t, unsigned priority, unsigned quantum_ticks, uint64_t cpu_mask)
{
    queue_guard_t g = queue_enter();
    int rc = -1;
    if (bsp_scheduler_owner() && thread_pointer_valid(t)) {
        const int move = t->ready_queued &&
            (priority != t->sched_priority || t->ready_cpu >= K64_CPU_MAX || !(cpu_mask & (1ull << t->ready_cpu)));
        rc = k64_rq_policy_locked(&runqueues, t, priority, quantum_ticks, cpu_mask, jiffies, ready_order + 1);
        if (!rc && move) ++ready_order;
    }
    queue_leave(g);
    return rc;
}

int thread_get_sched_policy(thread_t *t, sched_policy_t *out)
{
    queue_guard_t g = queue_enter();
    if (!bsp_scheduler_owner() || !out || !thread_pointer_valid(t) || t->state == TS_FREE || t->state == TS_ZOMBIE) {
        queue_leave(g);
        return -1;
    }
    out->priority = t->sched_priority;
    out->quantum_ticks = t->quantum_ticks;
    out->cpu_mask = t->cpu_mask;
    queue_leave(g);
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
    for (uint32_t c = 0; c < K64_CPU_MAX; ++c) if (k64_rq_online(&runqueues, c)) {
        out->ready_threads += runqueues.cpu[c].ready_count; /* excludes every idle */
        ++out->cpu_count;
    }
    for (i = 0; i < thread_hi; ++i) {
        out->live_threads += threads[i].state != TS_FREE;
        out->zombie_threads += threads[i].state == TS_ZOMBIE;
    }
    irq_restore(f);
}

int sched_validate(void)
{
    int ok = 1;
    queue_guard_t g = queue_enter();
    if (!sched_owner_context() || k64_rq_validate_locked(&runqueues)) ok = 0;
    for (uint32_t c = 0; ok && c < K64_CPU_MAX; ++c) if (k64_rq_online(&runqueues, c)) {
        k64_cpu_sched_t *cpu = &runqueues.cpu[c];
        if (!thread_pointer_valid(cpu->current) || !thread_pointer_valid(cpu->idle) ||
            cpu->current->state != TS_RUNNING || cpu->current->on_cpu != c ||
            (cpu->outgoing && (!thread_pointer_valid(cpu->outgoing) || cpu->outgoing->on_cpu != c))) ok = 0;
    }
    for (unsigned i = 0; ok && i < thread_hi; ++i) {
        thread_t *t = &threads[i];
        int is_idle = 0;
        for (uint32_t c = 0; c < K64_CPU_MAX; ++c) is_idle |= t == runqueues.cpu[c].idle;
        const int queued = t->state == TS_READY && !is_idle && t->on_cpu == K64_CPU_NONE;
        if (t->state > TS_NEW || !!t->ready_queued != queued ||
            (!queued && (t->ready_prev || t->ready_next)) ||
            (t->state == TS_RUNNING && (t->on_cpu >= K64_CPU_MAX || t != runqueues.cpu[t->on_cpu].current)) ||
            (t->on_cpu != K64_CPU_NONE && (!k64_rq_online(&runqueues, t->on_cpu) ||
             (t != runqueues.cpu[t->on_cpu].current && t != runqueues.cpu[t->on_cpu].outgoing))) ||
            t->aging_service_left > SCHED_AGED_SERVICE_TICKS ||
            (t->state != TS_RUNNING && t->aging_service_left) ||
            (t->state != TS_FREE && (t->sched_priority >= SCHED_PRIORITY_LEVELS || !t->quantum_ticks ||
             t->quantum_ticks > SCHED_MAX_QUANTUM_TICKS || !t->cpu_mask || (t->cpu_mask & ~runqueues.online_mask)))) ok = 0;
    }
    queue_leave(g);
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
    if (!bsp_scheduler_owner()) return;
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

/* All runnable queue transitions use the same ticket. Wait links stay separate. */
static void ready_enqueue_locked(thread_t *t)
{
    t->aging_service_left = 0;
    if (t == idle_thread) return;
    const uint32_t cpu = k64_rq_choose_locked(&runqueues, t->cpu_mask);
    KASSERT(k64_rq_enqueue_locked(&runqueues, t, cpu, jiffies, ++ready_order) == 0);
}
static void ready_enqueue(thread_t *t)
{
    queue_guard_t g = queue_enter();
    KASSERT(bsp_scheduler_owner());
    ready_enqueue_locked(t);
    queue_leave(g);
}
static void ready_remove(thread_t *t)
{
    queue_guard_t g = queue_enter();
    KASSERT(bsp_scheduler_owner() && k64_rq_remove_locked(&runqueues, t) == 0);
    queue_leave(g);
}
static void make_ready(thread_t *t)
{
    queue_guard_t g = queue_enter();
    KASSERT(bsp_scheduler_owner() && thread_pointer_valid(t));
    if (t->state != TS_READY && t->state != TS_RUNNING) {
        if (t->state == TS_BLOCKED) ++wakeups;
        t->state = TS_READY;
        t->aging_service_left = 0;
        t->ready_since = jiffies;
        t->ready_order = ++ready_order;
        /* A wake during handoff cannot publish a still-executing stack. */
        if (t->on_cpu == K64_CPU_NONE && t != idle_thread)
            KASSERT(k64_rq_enqueue_locked(&runqueues, t, k64_rq_choose_locked(&runqueues, t->cpu_mask),
                                         t->ready_since, t->ready_order) == 0);
    }
    queue_leave(g);
}
static thread_t *pick_next(uint32_t id, int *aged)
{
    thread_t *t = k64_rq_pick_locked(&runqueues, id, jiffies, aged);
    return t ? t : runqueues.cpu[id].idle;
}

static inline uint64_t rdtsc(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }

thread_t *thread_slot(unsigned i) { return i < thread_hi ? &threads[i] : 0; }

uint64_t thread_cycles_now(thread_t *t)
{
    const uint64_t f = irq_save();
    uint64_t c = t->cycles;
    if (t == thread_current() && t->tsc_in) c += rdtsc() - t->tsc_in;
    irq_restore(f);
    return c;
}

static inline void fx_save(thread_t *t) { __asm__ volatile("fxsave (%0)" :: "r"(t->fx) : "memory"); }
static inline void fx_restore(thread_t *t) { __asm__ volatile("fxrstor (%0)" :: "r"(t->fx) : "memory"); }

/* Interrupts must be disabled. */
static void schedule(int from_tick)
{
    const uint32_t id = sched_cpu_identity();
    KASSERT(k64_rq_online(&runqueues, id));
    const uint32_t ticket = k64_rq_lock(&runqueues);
    k64_cpu_sched_t *cpu = &runqueues.cpu[id];
    thread_t *prev = cpu->current, *next;
    int aged;
    KASSERT(prev && prev->on_cpu == id && !cpu->outgoing);
    /* A yield/wait/exit/preemption relinquishes any unused service allocation. */
    prev->aging_service_left = 0;
    if (prev->state == TS_RUNNING) {
        prev->state = TS_READY;
        prev->ready_since = jiffies;
        prev->ready_order = ++ready_order;
    }
    next = pick_next(id, &aged);
    /* Model the old enqueue-before-selection ordering without exposing the live
     * outgoing stack. Equal-priority FIFO heads precede this virtual arrival;
     * aged heads retain their independent priority override. */
    if (prev->state == TS_READY && prev != cpu->idle) {
        const int prev_aged = jiffies - prev->ready_since >= SCHED_STARVATION_TICKS;
        if ((prev_aged && (!aged || prev->ready_order < next->ready_order)) ||
            (!aged && !prev_aged && (next == cpu->idle || prev->sched_priority > next->sched_priority))) {
            next = prev;
            aged = prev_aged;
        }
    }
    const uint64_t waited = jiffies - next->ready_since;
    const int changed = k64_rq_dispatch_locked(&runqueues, id, next, aged, jiffies);
    KASSERT(changed >= 0);
    const int observe = next != cpu->idle && (pma_sched_trace_enabled || pma_sched_observe_enabled);
    if (changed) {
        if (!id) current = next;
        ++switches;
        if (from_tick) ++preemptions;
    }
    k64_rq_unlock(&runqueues, ticket);
    /* External observation never owns the queue ticket. IF remains clear;
     * next is current/on_cpu and any outgoing live stack remains withheld. */
    if (observe) pma_sched_trace_dispatch(next, waited);
    if (!changed) return;
    sched_set_current_kstack(next->stack_base + KSTACK_BYTES);
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

void sched_switch_complete(void)
{
    /* Destination stack is active, outgoing RSP saved; IF is still clear. */
    const uint32_t id = sched_cpu_identity();
    KASSERT(k64_rq_online(&runqueues, id));
    const uint32_t ticket = k64_rq_lock(&runqueues);
    KASSERT(k64_rq_complete_locked(&runqueues, id));
    k64_rq_unlock(&runqueues, ticket);
}

void __attribute__((weak)) sched_check_timeouts(uint64_t now) { (void)now; }       /* objects.c overrides */
void __attribute__((weak)) thread_object_signal(thread_t *t) { (void)t; }          /* objects.c overrides */

void sched_tick_from(int user_mode)
{
    k64_cpu_sched_t *cpu = sched_owner_context();
    if (!cpu) return;
    cpu->tick_from_user = user_mode;
    sched_tick();
}

void sched_tick(void)
{
    unsigned i;
    k64_cpu_sched_t *cpu = sched_owner_context();
    if (!cpu) return;
    const uint32_t id = sched_cpu_identity();
    thread_t *running = cpu->current;
    KASSERT(running && running->on_cpu == id && running->state == TS_RUNNING);
    if (pma_sched_trace_enabled) pma_sched_trace_tick(running, jiffies);
    /* Only BSP owns wall time and global UP timeout/object callbacks. Future
     * AP service interrupts charge their actual CPU/thread, never this clock. */
    queue_guard_t accounting = queue_enter();
    if (!id) ++jiffies;
    if (running == cpu->idle) ++cpu->idle_ticks;
    else if (cpu->tick_from_user) ++cpu->user_ticks;
    else ++cpu->kernel_ticks;
    running->run_ticks++;
    if (cpu->tick_from_user) running->user_ticks++; else running->kernel_ticks++;
    queue_leave(accounting);
#ifdef SHZ_STANDALONE
    if (cpu->tick_from_user) {   /* ring 3 always runs at PASSIVE_LEVEL: a raise that leaked out of a driver call must not stop preemption */
        uint64_t zero = 0;
        __asm__ volatile("mov %0, %%cr8" : : "r"(zero) : "memory");
    }
#endif
    cpu->tick_from_user = 0;
    for (i = 0; !id && i < thread_hi; ++i)
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
    if (!id) sched_check_timeouts(jiffies);
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
    queue_guard_t policy = queue_enter();
    if (running != cpu->idle) {
        if (running->quantum_left) --running->quantum_left;
        /* An aged selection is a finite service grant, not merely a dequeue.
         * Pending entry-boundary timer delivery must not immediately revoke
         * it for higher-ready or another aged head. Policy setters touch only
         * the base quantum and cannot refill this independent budget. */
        if (running->aging_service_left && --running->aging_service_left) {
            queue_leave(policy);
            return;
        }
    }
    if (running != cpu->idle && running->quantum_left) {
        /* After the finite grant, ordinary priority and aging rules apply. */
        const int higher_ready = running->sched_priority < SCHED_PRIORITY_LEVELS - 1 &&
            (cpu->ready_mask & (~0u << (running->sched_priority + 1)));
        if (!higher_ready && !k64_rq_aged_locked(&runqueues, id, jiffies)) {
            queue_leave(policy);
            return;
        }
    }
    queue_leave(policy);
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
        if (t->state != TS_ZOMBIE || t == current || t->creator_hold || t->on_cpu != K64_CPU_NONE) continue;
        thread_object_detach(t);
        kstack_free(t->stack_base);
        t->stack_base = 0;
        t->object = 0;
        t->state = TS_FREE;
    }
}

void thread_reap_process(const void *proc)
{
    if (!bsp_scheduler_owner()) return;
    const uint64_t f = irq_save();
    reap_user_zombies(proc, 1);
    irq_restore(f);
}

void thread_reap_exited(void)
{
    if (!bsp_scheduler_owner()) return;
    const uint64_t f = irq_save();
    reap_user_zombies(0, 0);
    irq_restore(f);
}

void thread_creator_release(thread_t *t)
{
    if (!bsp_scheduler_owner()) return;
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
    if (!bsp_scheduler_owner()) { irq_restore(f); return 0; }
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
    t->ready_cpu = t->on_cpu = K64_CPU_NONE;
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
    if (!bsp_scheduler_owner()) return;
    const uint64_t f = irq_save();
    if (t->state == TS_NEW)
        make_ready(t);
    irq_restore(f);
}

void thread_discard(thread_t *t)
{
    if (!bsp_scheduler_owner()) return;
    const uint64_t f = irq_save();
    if (t->state == TS_NEW) {
        kstack_free(t->stack_base);
        t->state = TS_FREE;
    }
    irq_restore(f);
}

void thread_yield(void)
{
    KASSERT(bsp_scheduler_owner());
    uint64_t f = irq_save();
    schedule(0);
    irq_restore(f);
}

void __attribute__((weak)) thread_account_exit(thread_t *t) { (void)t; }        /* sysk32.c overrides: process totals */

void thread_exit(int64_t code)
{
    KASSERT(bsp_scheduler_owner());
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
    if (!bsp_scheduler_owner()) return -1;
    for (;;) {
        uint64_t f = irq_save();
        if (t->state == TS_ZOMBIE && t->on_cpu == K64_CPU_NONE) {
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
    KASSERT(bsp_scheduler_owner());
    current->state = TS_BLOCKED;
    schedule(0);
}

void thread_wake(thread_t *t)
{
    if (!bsp_scheduler_owner()) return;
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
    KASSERT(bsp_scheduler_owner());
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
    KASSERT(bsp_scheduler_owner());
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
    KASSERT(bsp_scheduler_owner());
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
    KASSERT(bsp_scheduler_owner());
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
    KASSERT(bsp_scheduler_owner());
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
    KASSERT(bsp_scheduler_owner());
    const uint64_t table = pmm_alloc_contig((unsigned)((sizeof(thread_t) * MAX_THREADS + PAGE_SIZE - 1) / PAGE_SIZE));
    KASSERT(table);
    threads = (thread_t *)p2v(table);                                       /* zeroed: every slot is TS_FREE */
    k64_rq_init(&runqueues, threads, MAX_THREADS, 1);
    jiffies = switches = preemptions = wakeups = timeouts = ready_order = 0;
    idle_thread = 0;
    thread_hi = 1;
    current = &threads[0];
    current->id = next_id++;
    current->state = TS_RUNNING;
    current->ready_cpu = K64_CPU_NONE;
    current->on_cpu = 0;
    runqueues.cpu[0].current = current;
    current->sched_priority = SCHED_DEFAULT_PRIORITY;
    current->quantum_ticks = current->quantum_left = 1;
    current->cpu_mask = 1;
    current->name[0] = 'm'; current->name[1] = 'a'; current->name[2] = 'i'; current->name[3] = 'n';
    current->fx[0] = 0x7f; current->fx[1] = 0x03; current->fx[24] = 0x80; current->fx[25] = 0x1f;
    {
        extern uint8_t kstack_top[];
        current->stack_base = (uint64_t)kstack_top - KSTACK_BYTES;   /* the 32 KiB boot stack */
    }
    KASSERT(arch_sched_entry_bind(0, current->stack_base + KSTACK_BYTES) == 0);
    sched_set_current_kstack(current->stack_base + KSTACK_BYTES);
    idle_thread = thread_create("idle", idle_loop, 0);
    KASSERT(idle_thread);
    ready_remove(idle_thread);                       /* it was created before the idle identity was known */
    runqueues.cpu[0].idle = idle_thread;
    idle_thread->sched_priority = 0;
    idle_thread->state = TS_READY;
}
