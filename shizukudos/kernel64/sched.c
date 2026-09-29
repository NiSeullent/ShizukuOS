/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 preemptive round-robin scheduler (uniprocessor): kernel/user threads, sleep,
 * mutex and semaphore. The tick is the Supervisor's paravirtual timer (vector 0x20).
 * Each thread owns an FXSAVE area so user-mode SSE state survives preemption.
 */
#include "k64.h"

extern void switch_stacks(uint64_t *save_rsp, uint64_t new_rsp);
extern void thread_start(void);

#define MAX_THREADS 96

static thread_t threads[MAX_THREADS];
static thread_t *current;
static thread_t *idle_thread;
static uint32_t next_id = 1;
static volatile uint64_t jiffies;
static uint64_t switches;
uint64_t g_kstack_top;
uint64_t g_user_rsp_scratch;

uint64_t ticks_now(void) { return jiffies; }
uint64_t sched_switch_count(void) { return switches; }
thread_t *thread_current(void) { return current; }

thread_t *thread_find_tid(void *process, uint64_t tid)
{
    unsigned i;
    for (i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state != TS_FREE && threads[i].state != TS_ZOMBIE && threads[i].proc == process && threads[i].tid == tid)
            return &threads[i];
    return 0;
}

/* IPC hook (kernel64/ipc_core.c): visits every allocated thread slot with interrupts off (kill wake-ups, reaping the
 * kernel stacks of exited user threads). */
void sched_for_each_thread(void (*fn)(thread_t *, void *), void *ctx)
{
    unsigned i;
    for (i = 0; i < MAX_THREADS; ++i) {
        const uint64_t f = irq_save();
        if (threads[i].state != TS_FREE) fn(&threads[i], ctx);
        irq_restore(f);
    }
}

static thread_t *pick_next(void)
{
    unsigned i, start = current ? (unsigned)(current - threads) : 0;
    for (i = 1; i <= MAX_THREADS; ++i) {
        thread_t *t = &threads[(start + i) % MAX_THREADS];
        if (t->state == TS_READY && t != idle_thread)
            return t;
    }
    if (current && current->state == TS_RUNNING && current != idle_thread)
        return current;
    return idle_thread;
}

static inline uint64_t rdtsc(void) { uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); return ((uint64_t)hi << 32) | lo; }

thread_t *thread_slot(unsigned i) { return i < MAX_THREADS ? &threads[i] : 0; }

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
static void schedule(void)
{
    thread_t *prev = current, *next = pick_next();
    if (next == prev) {
        if (prev->state == TS_READY)
            prev->state = TS_RUNNING;
        return;
    }
    if (prev->state == TS_RUNNING)
        prev->state = TS_READY;
    next->state = TS_RUNNING;
    current = next;
    ++switches;
    tss_set_rsp0(next->stack_base + KSTACK_BYTES);
    g_kstack_top = next->stack_base + KSTACK_BYTES;
    {
        const uint64_t want = next->proc ? proc_pml4(next->proc) : kernel_pml4();
        if (read_cr3() != want)
            write_cr3(want);
    }
    if (prev->teb || next->teb) {
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
    current->run_ticks++;
    if (tick_from_user) current->user_ticks++; else current->kernel_ticks++;
    tick_from_user = 0;
    for (i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state == TS_BLOCKED && threads[i].wake_tick && threads[i].wake_tick <= jiffies) {
            threads[i].wake_tick = 0;
            threads[i].state = TS_READY;
            if (threads[i].wait_sem) {
                ksem_t *s = threads[i].wait_sem;
                thread_t **pp;
                for (pp = &s->waiters; *pp; pp = &(*pp)->next)
                    if (*pp == &threads[i]) { *pp = threads[i].next; break; }
                threads[i].wait_sem = 0;
                threads[i].wait_result = -1;
            }
            threads[i].wait_result = threads[i].wait_result ? threads[i].wait_result : 0x102;   /* STATUS_TIMEOUT marker */
        }
    sched_check_timeouts(jiffies);
    schedule();
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
    for (i = 0; i < MAX_THREADS; ++i) {
        thread_t *t = &threads[i];
        if (t->state != TS_ZOMBIE || !t->proc || t == current || (only && t->proc != only)) continue;
        if (drop_holds) t->creator_hold = 0;
        if (t->creator_hold) continue;
        thread_object_detach(t);
        kfree((void *)t->stack_base);
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

static thread_t *thread_create_state(const char *name, void (*fn)(void *), void *arg, uint32_t state)
{
    uint64_t f = irq_save(), *sp;
    thread_t *t = 0;
    unsigned i, k;
    reap_user_zombies(0, 0);
    for (i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state == TS_FREE) { t = &threads[i]; break; }
    if (!t) {
        unsigned z = 0;
        for (i = 0; i < MAX_THREADS; ++i) z += threads[i].state == TS_ZOMBIE;
        irq_restore(f);
        kprintf("K64: thread table full (%u slots, %u exited but not reclaimable)\n", MAX_THREADS, z);
        return 0;
    }
    memset(t, 0, sizeof *t);
    t->stack_base = (uint64_t)kmalloc(KSTACK_BYTES);
    if (!t->stack_base) { irq_restore(f); kprintf("K64: no kernel stack for a new thread\n"); return 0; }
    t->id = next_id++;
    t->create_tick = jiffies;
    t->mem_priority = 5;                            /* MEMORY_PRIORITY_NORMAL */
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
        t->state = TS_READY;
    irq_restore(f);
}

void thread_discard(thread_t *t)
{
    const uint64_t f = irq_save();
    if (t->state == TS_NEW) {
        kfree((void *)t->stack_base);
        t->state = TS_FREE;
    }
    irq_restore(f);
}

void thread_yield(void)
{
    uint64_t f = irq_save();
    schedule();
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
        schedule();
        cli();
    }
}

int64_t thread_join(thread_t *t)
{
    for (;;) {
        uint64_t f = irq_save();
        if (t->state == TS_ZOMBIE) {
            const int64_t code = t->exit_code;
            kfree((void *)t->stack_base);
            t->state = TS_FREE;
            irq_restore(f);
            return code;
        }
        schedule();
        irq_restore(f);
    }
}

void thread_block_current(void)
{
    current->state = TS_BLOCKED;
    schedule();
}

void thread_wake(thread_t *t)
{
    if (t->state == TS_BLOCKED) {
        t->wake_tick = 0;
        t->state = TS_READY;
    }
}

void thread_sleep_ms(uint64_t ms)
{
    uint64_t f = irq_save();
    current->wake_tick = jiffies + (ms * 1000u + TICK_US - 1) / TICK_US;
    if (current->wake_tick <= jiffies) current->wake_tick = jiffies + 1;
    current->state = TS_BLOCKED;
    schedule();
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
    current->wake_tick = ms ? jiffies + (ms * 1000u + TICK_US - 1) / TICK_US : 0;
    current->wait_result = 0;
    current->state = TS_BLOCKED;
    schedule();
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
        w->state = TS_READY;
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
        schedule();
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
        w->state = TS_READY;
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
    memset(threads, 0, sizeof threads);
    current = &threads[0];
    current->id = next_id++;
    current->state = TS_RUNNING;
    current->name[0] = 'm'; current->name[1] = 'a'; current->name[2] = 'i'; current->name[3] = 'n';
    current->fx[0] = 0x7f; current->fx[1] = 0x03; current->fx[24] = 0x80; current->fx[25] = 0x1f;
    {
        extern uint8_t kstack_top[];
        current->stack_base = (uint64_t)kstack_top - KSTACK_BYTES;   /* the 32 KiB boot stack */
    }
    idle_thread = thread_create("idle", idle_loop, 0);
    KASSERT(idle_thread);
    idle_thread->state = TS_READY;
}
