/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the complete production Kernel32 scheduler C implementation.
 * Only CPU/IRQ/CR3/TSS/stack-switch boundaries are substituted. No deadline,
 * thread layout, queue, tick, semaphore, sleep, exit or join body is copied.
 * The host does not execute 32-bit context-switch assembly or guest stacks.
 */
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel32/k32.h"

static uint32_t host_irq_save(void);
static void host_irq_restore(uint32_t flags);
static uint32_t host_read_cr3(void);
static void host_write_cr3(uint32_t value);
static void host_sti(void);
static void host_cli(void);
static uint32_t host_flags(void);
static uint32_t host_stack_pointer(void);
void boundary_switch(uint32_t *save_esp, uint32_t new_esp);

/* Include the real header first; retain its types and ABI, and substitute only
 * privileged operations used by the production translation unit below. */
#define irq_save host_irq_save
#define irq_restore host_irq_restore
#define read_cr3 host_read_cr3
#define write_cr3 host_write_cr3
#define sti host_sti
#define cli host_cli
#define k32_flags host_flags
#define k32_stack_pointer host_stack_pointer
#define switch_stacks boundary_switch
#include "../kernel32/sched.c"
#undef irq_save
#undef irq_restore
#undef read_cr3
#undef write_cr3
#undef sti
#undef cli
#undef k32_flags
#undef k32_stack_pointer
#undef switch_stacks
#define current (runqueues.cpu[0].current)
#define idle_thread (runqueues.cpu[0].idle)
uint32_t arch_cpu_id(void) { return 0; }

static unsigned checks, failures;
static int host_if = 1, escape_armed, switch_depth, free_allowed;
static uint32_t host_cr3 = 0x1000;
static uint32_t *expected_save;
static unsigned free_calls;
static jmp_buf boundary_escape;
enum boundary_mode { ESCAPE, RESUME_SIGNAL, RESUME_TIMEOUT };
static enum boundary_mode mode;
static ksem_t *resume_sem;
static unsigned resume_ticks;
static thread_t *resume_thread;

static void fixture_error(const char *message)
{
    fprintf(stderr, "FIXTURE_ERROR: %s\n", message);
    exit(2);
}

static void check(int condition, const char *tag)
{
    ++checks;
    if (!condition) {
        ++failures;
        fprintf(stderr, "ASSERT: %s\n", tag);
    }
}

static void check_deadline(uint64_t got, uint64_t want, const char *tag)
{
    ++checks;
    if (got != want) {
        ++failures;
        fprintf(stderr, "ASSERT: %s got=%" PRIu64 " want=%" PRIu64 "\n", tag, got, want);
    }
}

static uint32_t host_irq_save(void)
{
    const uint32_t old = host_if ? 0x200u : 0;
    host_if = 0;
    return old;
}
static void host_irq_restore(uint32_t flags) { host_if = !!(flags & 0x200u); }
static uint32_t host_read_cr3(void) { return host_cr3; }
static void host_write_cr3(uint32_t value) { host_cr3 = value; }
static void host_sti(void) { host_if = 1; }
static void host_cli(void) { host_if = 0; }
/* Default-UP only: no real native destination stack exists in this fixture. */
static uint32_t host_flags(void) { return host_if ? 0x200u : 0; }
static uint32_t host_stack_pointer(void) { return 0; }
uint32_t kernel_space(void) { return 0x1000; }
uint32_t proc_page_directory(uint32_t pid)
{
    if (pid) fixture_error("unexpected process address-space request");
    return 0;
}
void tss_set_kernel_stack(uint32_t top)
{
    if (host_if || !top) fixture_error("invalid protected TSS transition");
}
void *kmalloc(size_t size)
{
    (void)size;
    fixture_error("host must not create/dereference a real 32-bit guest stack");
    return NULL;
}
void kfree(void *pointer)
{
    if (!free_allowed || (uintptr_t)pointer != 0x10000u)
        fixture_error("unexpected stack release");
    ++free_calls;
}
void kprintf(const char *format, ...) { (void)format; }
void kpanic(const char *format, ...)
{
    va_list args;
    fputs("FIXTURE_ERROR: production panic: ", stderr);
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    fputc('\n', stderr);
    exit(2);
}

void boundary_switch(uint32_t *save_esp, uint32_t new_esp)
{
    if (host_if || !new_esp) fixture_error("context switch outside IRQ-off boundary");
    sched_switch_complete(); /* actual destination-stack completion body */
    if (switch_depth) {
        if (current != resume_thread || save_esp != &idle_thread->esp)
            fixture_error("unexpected nested resume context");
        return;
    }
    if (save_esp != expected_save) fixture_error("context switch did not save the expected live TCB");
    if (mode == ESCAPE) {
        if (!escape_armed) fixture_error("unarmed context boundary");
        longjmp(boundary_escape, 1);
    }
    if (current != idle_thread || !resume_thread || !resume_sem)
        fixture_error("invalid synchronous hardware-boundary resume");
    ++switch_depth;
    if (mode == RESUME_SIGNAL) {
        sem_post(resume_sem);             /* production queue/wakeup operation */
        schedule();                      /* production selects the signaled TCB */
    } else {
        unsigned i;
        for (i = 0; i < resume_ticks; ++i) sched_tick();
    }
    --switch_depth;
    if (current != resume_thread)
        fixture_error("bounded resume did not return to its original TCB");
}

static void reset(uint64_t now)
{
    memset(threads, 0, sizeof threads);     /* production storage and real TCB type */
    k32_rq_init(&runqueues,threads,MAX_THREADS,1);
    for(unsigned i=0;i<MAX_THREADS;i++){threads[i].ready_cpu=threads[i].on_cpu=K32_CPU_NONE;threads[i].affinity_mask=1;}
    current = &threads[0];
    idle_thread = &threads[1];
    current->id = 1;
    current->state = TS_RUNNING;
    current->on_cpu = 0;
    current->esp = 0x101;
    current->stack_base = 0x10000;
    idle_thread->id = 2;
    idle_thread->state = TS_READY;
    idle_thread->esp = 0x201;
    idle_thread->stack_base = 0x20000;
    jiffies = now;
    switches = 0;
    host_if = 1;
    host_cr3 = 0x1000;
    escape_armed = switch_depth = free_allowed = 0;
    free_calls = 0;
    mode = ESCAPE;
    resume_sem = NULL;
    resume_thread = NULL;
}

static void park_sleep(uint32_t ms)
{
    expected_save = &current->esp;
    mode = ESCAPE;
    if (!setjmp(boundary_escape)) {
        escape_armed = 1;
        thread_sleep_ms(ms);
        fixture_error("sleep unexpectedly returned before switching");
    }
    escape_armed = 0;
    host_if = 1;                         /* next externally modeled ISR/worker epoch */
}

static void park_wait(ksem_t *sem, uint32_t ms, int infinite)
{
    expected_save = &current->esp;
    mode = ESCAPE;
    if (!setjmp(boundary_escape)) {
        escape_armed = 1;
        if (infinite) sem_wait(sem);
        else (void)sem_wait_timeout(sem, ms);
        fixture_error("empty semaphore unexpectedly returned before switching");
    }
    escape_armed = 0;
    host_if = 1;
}

static void tick_once(void)
{
    expected_save = &current->esp;
    mode = ESCAPE;
    host_if = 0;                         /* real ISR entry supplies IF=0 */
    if (!setjmp(boundary_escape)) {
        escape_armed = 1;
        sched_tick();                    /* actual timeout scan and ready selection */
    }
    escape_armed = 0;
    host_if = 1;
}

static void select_second(void)
{
    if (current != idle_thread) fixture_error("second worker selection requires parked first worker");
    idle_thread->state = TS_READY;
    idle_thread->on_cpu = K32_CPU_NONE;
    current = &threads[2];
    current->id = 3;
    current->state = TS_RUNNING;
    current->on_cpu = 0;
    current->esp = 0x301;
    current->stack_base = 0x30000;
}

static void test_interval_and_width(void)
{
    static const struct {
        uint64_t now;
        uint32_t ms;
        uint64_t want;
        const char *tag;
    } cases[] = {
        { 10, 4294968u, 4294978ull, "sleep multiplication boundary deadline" },
        { 10, UINT32_MAX, 4294967305ull, "sleep maximum milliseconds deadline" },
        { 4294967286ull, 20, 4294967306ull, "sleep deadline crosses 32-bit clock" },
        { 4294967296ull, 20, 4294967316ull, "sleep deadline above 32-bit clock" },
        { UINT32_MAX, 1, 4294967296ull, "sleep finite deadline cannot become infinite zero" },
        { 100, 0, 101, "sleep zero is one finite tick" },
        { UINT64_MAX - 2, 1, UINT64_MAX - 1, "sleep near terminal clock preserves representable deadline" },
        { UINT64_MAX - 2, 5, UINT64_MAX, "sleep finite overflow clamps without wrap" },
        { UINT64_MAX - 2, UINT32_MAX, UINT64_MAX, "sleep maximum interval clamps without zero sentinel" }
    };
    unsigned i;
    check(offsetof(thread_t, esp) == 0 && sizeof threads[0].esp == 4,
          "real TCB retains assembly ESP pointer at offset zero");
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        reset(cases[i].now);
        park_sleep(cases[i].ms);
        check_deadline(threads[0].wake_tick, cases[i].want, cases[i].tag);
        check(threads[0].state == TS_BLOCKED && current == idle_thread,
              "sleep uses actual blocked-to-idle scheduler transition");
    }
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        ksem_t sem;
        reset(cases[i].now);
        sem_init(&sem, 0);
        park_wait(&sem, cases[i].ms, 0);
        check_deadline(threads[0].wake_tick, cases[i].want,
                       "finite semaphore deadline preserves interval and 64-bit clock");
        check(sem.waiters == &threads[0] && !threads[0].next && threads[0].wait_sem == &sem && !sem.count,
              "finite semaphore publishes exactly one real blocked waiter");
    }
}

static void test_exact_expiry_and_infinite(void)
{
    ksem_t sem;
    reset(100);
    park_sleep(3);
    tick_once();
    tick_once();
    check(jiffies == 102 && threads[0].state == TS_BLOCKED,
          "sleep remains blocked immediately before deadline");
    tick_once();
    check(jiffies == 103 && threads[0].state == TS_RUNNING && !threads[0].wake_tick,
          "sleep wakes at exact deadline through production tick");

    reset(UINT32_MAX);
    sem_init(&sem, 0);
    park_wait(&sem, 1, 0);
    tick_once();
    check(jiffies == 4294967296ull && threads[0].state == TS_RUNNING && threads[0].exit_code == -1 &&
          !sem.waiters && !threads[0].wait_sem && !threads[0].wake_tick,
          "finite semaphore zero-collision expires and unlinks at exact deadline");

    reset(UINT32_MAX);
    park_sleep(1);
    tick_once();
    check(jiffies == 4294967296ull && threads[0].state == TS_RUNNING && !threads[0].wake_tick,
          "finite sleep zero-collision expires at exact deadline");

    reset(UINT32_MAX);
    sem_init(&sem, 0);
    park_wait(&sem, 0, 1);
    tick_once();
    tick_once();
    check(threads[0].state == TS_BLOCKED && !threads[0].wake_tick && sem.waiters == &threads[0] &&
          threads[0].wait_sem == &sem && threads[0].exit_code == 0,
          "indefinite semaphore retains intentional zero sentinel across 32-bit boundary");
    sem_post(&sem);
    check(threads[0].state == TS_READY && !sem.waiters && !threads[0].wait_sem && !sem.count,
          "indefinite waiter wakes once on a real post");
}

static void test_signal_and_timeout_order(void)
{
    ksem_t sem;
    reset(100);
    sem_init(&sem, 0);
    park_wait(&sem, 3, 0);
    tick_once();
    tick_once();
    check(threads[0].state == TS_BLOCKED && sem.waiters == &threads[0],
          "finite waiter remains linked before expiry");
    sem_post(&sem);
    check(!sem.waiters && !sem.count && !threads[0].wait_sem && !threads[0].wake_tick &&
          !threads[0].next && threads[0].exit_code == 0 && threads[0].state == TS_READY,
          "post before deadline consumes one token and removes live waiter");
    tick_once();
    check(threads[0].state == TS_RUNNING && threads[0].exit_code == 0 && !sem.count,
          "tick after prior post cannot convert success into timeout");

    reset(100);
    sem_init(&sem, 0);
    park_wait(&sem, 3, 0);
    tick_once();
    tick_once();
    tick_once();
    check(!sem.waiters && !threads[0].wait_sem && !threads[0].wake_tick &&
          threads[0].state == TS_RUNNING && threads[0].exit_code == -1,
          "timeout before post detaches real waiter with timeout marker");
    sem_post(&sem);
    check(sem.count == 1 && !sem.waiters && threads[0].exit_code == -1,
          "post after timeout leaves exactly one unconsumed token");
}

static void test_long_deadline_actual_expiry(void)
{
    static const struct { uint64_t now; uint32_t ms; uint64_t due; } cases[] = {
        { 10, 4294968u, 4294978ull },
        { 4294967296ull, 20, 4294967316ull }
    };
    unsigned i;
    for (i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        ksem_t sem;
        reset(cases[i].now);
        park_sleep(cases[i].ms);
        /* Advance only the externally supplied simulated clock. The two
         * comparisons/transitions below execute the unchanged real ISR body. */
        jiffies = cases[i].due - 2;
        tick_once();
        check(threads[0].state == TS_BLOCKED && threads[0].wake_tick != 0,
              "long finite sleep stays blocked before independently expected expiry");
        tick_once();
        check(jiffies == cases[i].due && threads[0].state == TS_RUNNING && !threads[0].wake_tick,
              "long finite sleep wakes through actual tick at expected expiry");
        reset(cases[i].now);
        sem_init(&sem, 0);
        park_wait(&sem, cases[i].ms, 0);
        jiffies = cases[i].due - 2;
        tick_once();
        check(threads[0].state == TS_BLOCKED && sem.waiters == &threads[0] &&
              threads[0].wait_sem == &sem && !threads[0].next && threads[0].exit_code == 0 && !sem.count,
              "long finite semaphore stays linked before independently expected expiry");
        tick_once();
        check(jiffies == cases[i].due && threads[0].state == TS_RUNNING && threads[0].exit_code == -1 &&
              !sem.waiters && !threads[0].wait_sem && !threads[0].wake_tick && !sem.count,
              "long finite semaphore expires through actual tick with exact unlink and marker");
        sem_post(&sem);
        check(sem.count == 1 && !sem.waiters && threads[0].exit_code == -1,
              "post after long finite timeout retains exactly one token");
    }
}

static void test_two_waiter_unlink_and_rewait(void)
{
    ksem_t sem;
    reset(100);
    sem_init(&sem, 0);
    park_wait(&sem, 3, 0);
    select_second();
    park_wait(&sem, 5, 0);
    check(sem.waiters == &threads[0] && threads[0].next == &threads[2] && !threads[2].next,
          "two real waits preserve FIFO live queue");
    tick_once(); tick_once(); tick_once();
    check(sem.waiters == &threads[2] && !threads[2].next && threads[0].exit_code == -1 &&
          threads[0].wait_sem == NULL && threads[2].wait_sem == &sem && threads[2].state == TS_BLOCKED,
          "head timeout preserves surviving waiter without duplicate reachability");
    /* The inactive old next pointer is not a live queue member. A new actual
     * wait must reinitialize it before appending; no pointer-hygiene-only fix. */
    park_wait(&sem, 0, 1);
    check(sem.waiters == &threads[2] && threads[2].next == &threads[0] && !threads[0].next &&
          threads[0].exit_code == 0 && threads[0].wait_sem == &sem,
          "actual rewait clears stale link and old timeout marker");
    sem_post(&sem);
    check(sem.waiters == &threads[0] && threads[2].state == TS_READY && !threads[2].wait_sem &&
          !threads[2].next && !sem.count,
          "post wakes surviving FIFO waiter exactly once");
    sem_post(&sem);
    check(!sem.waiters && threads[0].state == TS_READY && !threads[0].wait_sem &&
          !threads[0].next && !sem.count,
          "next post wakes requeued waiter without an extra token");
    sem_post(&sem);
    check(sem.count == 1, "post after both completed waits contributes one token");

    reset(100);
    sem_init(&sem, 0);
    park_wait(&sem, 5, 0);
    select_second();
    park_wait(&sem, 3, 0);
    tick_once(); tick_once(); tick_once();
    check(sem.waiters == &threads[0] && !threads[0].next && threads[0].state == TS_BLOCKED &&
          threads[2].exit_code == -1 && !threads[2].wait_sem,
          "interior timeout preserves live head and removes expired worker");
    sem_post(&sem);
    check(!sem.waiters && threads[0].state == TS_READY && !threads[0].wait_sem && !sem.count &&
          threads[2].exit_code == -1,
          "post after interior timeout wakes only surviving waiter");
    sem_post(&sem);
    check(sem.count == 1, "interior timeout and later posts preserve exact token count");
}

static int resumed_wait(ksem_t *sem, uint32_t ms, enum boundary_mode how, unsigned ticks)
{
    int rc;
    expected_save = &current->esp;
    resume_thread = current;
    resume_sem = sem;
    resume_ticks = ticks;
    mode = how;
    rc = sem_wait_timeout(sem, ms);
    mode = ESCAPE;
    check(host_if && current == resume_thread && current->state == TS_RUNNING,
          "finite wait resumes actual C call with caller IRQ state restored");
    return rc;
}

static void test_return_marker_and_exit(void)
{
    ksem_t sem;
    int rc;
    reset(100);
    sem_init(&sem, 0);
    rc = resumed_wait(&sem, 3, RESUME_SIGNAL, 0);
    check(rc == 0 && threads[0].exit_code == 0 && !sem.count && !sem.waiters,
          "resumed signaled finite wait returns success without timeout marker");
    reset(100);
    sem_init(&sem, 0);
    rc = resumed_wait(&sem, 3, RESUME_TIMEOUT, 3);
    check(rc == -1 && threads[0].exit_code == 0 && !sem.count && !sem.waiters,
          "resumed timed wait returns timeout and clears transient exit marker");
    expected_save = &current->esp;
    mode = ESCAPE;
    if (!setjmp(boundary_escape)) {
        escape_armed = 1;
        thread_exit(77);
    }
    escape_armed = 0;
    host_if = 1;
    check(threads[0].state == TS_ZOMBIE && threads[0].exit_code == 77,
          "real thread exit publishes its own code after timeout");
    free_allowed = 1;
    rc = thread_join(&threads[0]);
    free_allowed = 0;
    check(rc == 77 && threads[0].state == TS_FREE && free_calls == 1,
          "real join returns exit code and releases stack once");
    reset(100);
    sem_init(&sem, 0);
    rc = resumed_wait(&sem, 0, RESUME_TIMEOUT, 1);
    check(rc == -1 && jiffies == 101 && threads[0].exit_code == 0,
          "finite timeout zero remains one tick and returns timeout");
    reset(100);
    sem_init(&sem, 1);
    rc = sem_wait_timeout(&sem, UINT32_MAX);
    check(rc == 0 && sem.count == 0 && !sem.waiters && current->state == TS_RUNNING &&
          !current->wake_tick && host_if,
          "available token is consumed without blocking or inventing a deadline");
}

int main(void)
{
    test_interval_and_width();
    test_exact_expiry_and_infinite();
    test_signal_and_timeout_order();
    test_long_deadline_actual_expiry();
    test_two_waiter_unlink_and_rewait();
    test_return_marker_and_exit();
    if (failures) {
        printf("FAIL: %u of %u Kernel32 deadline checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %u Kernel32 deadline checks\n", checks);
    return 0;
}
