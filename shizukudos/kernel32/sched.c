/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 preemptive round-robin scheduler (uniprocessor), sleep, mutex, semaphore.
 * The tick is the Supervisor's paravirtual timer (SHZ_HC_TIMER_SET) delivered as
 * vector 0x20; kernel data is protected by disabling interrupts.
 */
#include "k32.h"

extern void switch_stacks(uint32_t *save_esp, uint32_t new_esp);
extern void vm_set_demand_range(uint32_t lo, uint32_t hi);

#define MAX_THREADS 48
#define STACK_BYTES 16384

enum { TS_FREE = 0, TS_READY = 1, TS_RUNNING = 2, TS_BLOCKED = 3, TS_ZOMBIE = 4 };

static thread_t threads[MAX_THREADS];
static thread_t *current;
static thread_t *idle_thread;
static uint32_t next_id = 1;
static volatile uint64_t jiffies;
static uint64_t switches;
extern uint32_t proc_page_directory(uint32_t proc_id);      /* user.c: 0 = kernel space */
extern uint32_t kernel_space(void);

uint64_t ticks_now(void) { return jiffies; }
uint64_t sched_switch_count(void) { return switches; }
thread_t *thread_current(void) { return current; }

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

/* Called with interrupts disabled. */
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
    tss_set_kernel_stack(next->stack_base + STACK_BYTES);
    {
        const uint32_t pd = proc_page_directory(next->proc);
        const uint32_t want = pd ? pd : kernel_space();
        if (read_cr3() != want)
            write_cr3(want);
    }
    switch_stacks(&prev->esp, next->esp);
}

void sched_tick(void)
{
    unsigned i;
    ++jiffies;
    current->run_ticks++;
    for (i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state == TS_BLOCKED && threads[i].wake_tick && threads[i].wake_tick <= jiffies) {
            threads[i].wake_tick = 0;
            threads[i].state = TS_READY;
            if (threads[i].wait_sem) {          /* timed semaphore wait expired */
                ksem_t *s = threads[i].wait_sem;
                thread_t **pp;
                for (pp = &s->waiters; *pp; pp = &(*pp)->next)
                    if (*pp == &threads[i]) { *pp = threads[i].next; break; }
                threads[i].wait_sem = 0;
                threads[i].exit_code = -1;      /* used as the timeout marker while blocked */
            }
        }
    schedule();
}

static void thread_trampoline(void (*fn)(void *), void *arg)
{
    sti();
    fn(arg);
    thread_exit(0);
}

thread_t *thread_create(const char *name, void (*fn)(void *), void *arg)
{
    uint32_t f = irq_save(), *sp;
    thread_t *t = 0;
    unsigned i, k;
    for (i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state == TS_FREE) { t = &threads[i]; break; }
    if (!t) { irq_restore(f); return 0; }
    memset(t, 0, sizeof *t);
    t->stack_base = (uint32_t)kmalloc(STACK_BYTES);
    if (!t->stack_base) { irq_restore(f); return 0; }
    t->id = next_id++;
    for (k = 0; name[k] && k < sizeof t->name - 1; ++k) t->name[k] = name[k];
    sp = (uint32_t *)(t->stack_base + STACK_BYTES);
    *--sp = (uint32_t)arg;
    *--sp = (uint32_t)fn;
    *--sp = 0;                                  /* fake return address for thread_trampoline */
    *--sp = (uint32_t)thread_trampoline;        /* popped by switch_stacks' ret */
    *--sp = 0x202;                              /* eflags: IF=1 */
    *--sp = 0;                                  /* ebp */
    *--sp = 0;                                  /* ebx */
    *--sp = 0;                                  /* esi */
    *--sp = 0;                                  /* edi */
    t->esp = (uint32_t)sp;
    t->state = TS_READY;
    irq_restore(f);
    return t;
}

void thread_yield(void)
{
    uint32_t f = irq_save();
    schedule();
    irq_restore(f);
}

void thread_exit(int code)
{
    uint32_t f = irq_save();
    (void)f;
    current->exit_code = code;
    current->state = TS_ZOMBIE;
    for (;;) {
        schedule();
        cli();
    }
}

int thread_join(thread_t *t)
{
    for (;;) {
        uint32_t f = irq_save();
        if (t->state == TS_ZOMBIE) {
            const int code = t->exit_code;
            kfree((void *)t->stack_base);
            t->state = TS_FREE;
            irq_restore(f);
            return code;
        }
        schedule();
        irq_restore(f);
    }
}

void thread_sleep_ms(uint32_t ms)
{
    uint32_t f = irq_save();
    current->wake_tick = jiffies + (ms * 1000u + TICK_US - 1) / TICK_US;
    if (current->wake_tick <= jiffies) current->wake_tick = jiffies + 1;
    current->state = TS_BLOCKED;
    schedule();
    irq_restore(f);
}

/* ---------------------------------------------------------------- semaphores / mutexes */
void sem_init(ksem_t *s, int count) { s->count = count; s->waiters = 0; }

static int sem_wait_common(ksem_t *s, uint32_t ms)
{
    uint32_t f = irq_save();
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
    current->exit_code = 0;
    current->state = TS_BLOCKED;
    schedule();
    if (ms && current->exit_code == -1)
        rc = -1;                                 /* timed out */
    current->exit_code = 0;
    irq_restore(f);
    return rc;
}

void sem_wait(ksem_t *s) { sem_wait_common(s, 0); }
int sem_wait_timeout(ksem_t *s, uint32_t ms) { return sem_wait_common(s, ms ? ms : 1); }

void sem_post(ksem_t *s)
{
    uint32_t f = irq_save();
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

void mutex_init(kmutex_t *m) { m->locked = 0; m->owner = 0; m->waiters = 0; m->depth = 0; }

void mutex_lock(kmutex_t *m)
{
    for (;;) {
        uint32_t f = irq_save();
        if (!m->locked) {
            m->locked = 1;
            m->owner = current;
            irq_restore(f);
            return;
        }
        KASSERT(m->owner != current);            /* non-recursive: recursion is a bug */
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
    uint32_t f = irq_save();
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

/* ---------------------------------------------------------------- init */
static void idle_loop(void *arg)
{
    (void)arg;
    for (;;)
        __asm__ volatile("sti; hlt");
}

void sched_init(void)
{
    /* The boot context becomes thread 1 ("main"). */
    memset(threads, 0, sizeof threads);
    current = &threads[0];
    current->id = next_id++;
    current->state = TS_RUNNING;
    current->name[0] = 'm'; current->name[1] = 'a'; current->name[2] = 'i'; current->name[3] = 'n';
    idle_thread = thread_create("idle", idle_loop, 0);
    KASSERT(idle_thread);
    idle_thread->state = TS_READY;               /* only picked when nothing else is runnable */
}

void sched_start_idle(void) { }
