/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the Ke/Ex runtime a driver calls -- IRQL, spin locks, DPCs,
 * timers, dispatcher objects (events, semaphores, mutexes, timers), waits, delays, the stall
 * loop, the system clock and pools. Every exported entry is NTAPI (Microsoft x64) so an
 * unmodified .sys reaches it correctly. Semantics follow WDM; they are backed by the real
 * Kernel64 scheduler, heap and timebase -- no operation is a no-op stub.
 *
 * Uniprocessor model: raising IRQL to >= DISPATCH_LEVEL makes the current thread
 * non-preemptible (interrupts stay on, but the scheduler will not switch away); DPCs run in a
 * dedicated dispatch thread and are also flushed whenever IRQL drops below DISPATCH_LEVEL,
 * matching the point at which Windows drains the DPC queue.
 */
#include "ntdrv.h"

#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define HIGH_LEVEL 15

/* dispatcher header Type byte (ntddk KOBJECTS enum) */
#define EventNotificationObject 0
#define EventSynchronizationObject 1
#define MutantObject 2
#define SemaphoreObject 5
#define TimerNotificationObject 8
#define TimerSynchronizationObject 9

static volatile uint8_t g_irql;                 /* uniprocessor current IRQL */

uint8_t ntdrv_current_irql(void) { return g_irql; }

/* On this kernel the scheduler only preempts from the timer interrupt (or a voluntary
 * yield/sleep/block). Masking interrupts while IRQL >= DISPATCH_LEVEL therefore reproduces the
 * exact guarantee DISPATCH_LEVEL gives a driver: the scheduler cannot switch away, so a held
 * spin lock and a running DPC are never interrupted by other dispatch-level work. At
 * PASSIVE/APC the scheduler runs normally and waits may block. */
/* Drivers built with the WDK read the IRQL straight from CR8 on x64 (KeGetCurrentIrql, KeRaiseIrql and KeLowerIrql are inline
 * there), so CR8 mirrors g_irql. Interrupt delivery is unaffected: vectors are >= 0x20 (priority class 2 and up) and every
 * IRQL that could mask them (>= DISPATCH_LEVEL) also runs with interrupts disabled. */
static inline void write_cr8(uint64_t v) { __asm__ volatile("mov %0, %%cr8" : : "r"(v) : "memory"); }
static void set_irql(uint8_t v)
{
    g_irql = v;
    write_cr8(v);
    if (v >= DISPATCH_LEVEL) cli();
    else sti();
}


/* ---------------------------------------------------------------- KPCR emulation (GS base)
 * Drivers built with the WDK read the current thread, the PRCB and the processor block straight from the GS segment on x64
 * (KeGetCurrentThread/PsGetCurrentThread are gs:[0x188], KeGetPcr is gs:[0x18], KeGetCurrentPrcb gs:[0x20]). The kernel
 * itself never uses GS (there is no swapgs discipline: a user thread's GS base is its TEB, kernel threads run with 0), so
 * every thread that runs driver code gets a small KPCR of its own -- Self at 0x18, CurrentPrcb at 0x20, the embedded PRCB at
 * 0x180 with CurrentThread at +8 -- and GS points at it for as long as it is inside the host. The scheduler swaps GS at every
 * context switch once ntdrv_gs_all is set (sched.c), so the value follows the thread. Layout per the Windows x64 KPCR/KPRCB. */
int ntdrv_gs_all;
typedef struct kpcr_slot { struct kpcr_slot *next; void *thread; uint8_t blk[0x400] __attribute__((aligned(16))); } kpcr_slot_t;
static kpcr_slot_t *kpcr_hash[64];
static kpcr_slot_t isr_kpcr;

static void kpcr_fill(kpcr_slot_t *s, void *thread)
{
    uint64_t *q = (uint64_t *)s->blk;
    s->thread = thread;
    q[0x18 / 8] = (uint64_t)s->blk;                    /* KPCR.Self */
    q[0x20 / 8] = (uint64_t)(s->blk + 0x180);          /* KPCR.CurrentPrcb */
    q[0x188 / 8] = (uint64_t)thread;                   /* KPRCB.CurrentThread */
    q[0x198 / 8] = (uint64_t)thread;                   /* KPRCB.IdleThread: never idle here, but never NULL */
}
static uint64_t kpcr_for_current(void)
{
    thread_t *t = thread_current();
    unsigned h = (unsigned)(((uint64_t)t >> 6) & 63);
    kpcr_slot_t *s;
    uint64_t f = irq_save();
    for (s = kpcr_hash[h]; s; s = s->next) if (s->thread == t) { irq_restore(f); return (uint64_t)s->blk; }
    irq_restore(f);
    s = kzalloc(sizeof *s);
    if (!s) return (uint64_t)isr_kpcr.blk;
    kpcr_fill(s, t);
    f = irq_save();
    s->next = kpcr_hash[h]; kpcr_hash[h] = s;
    irq_restore(f);
    return (uint64_t)s->blk;
}
uint64_t ntdrv_gs_enter(void)                            /* returns the previous GS base for ntdrv_gs_leave */
{
    const uint64_t prev = rdmsr(MSR_GS_BASE);
    ntdrv_gs_all = 1;
    wrmsr(MSR_GS_BASE, kpcr_for_current());
    return prev;
}
uint64_t ntdrv_gs_enter_isr(void)                        /* interrupt context: no allocation, one shared block */
{
    const uint64_t prev = rdmsr(MSR_GS_BASE);
    kpcr_fill(&isr_kpcr, thread_current());
    wrmsr(MSR_GS_BASE, (uint64_t)isr_kpcr.blk);
    return prev;
}
void ntdrv_gs_leave(uint64_t prev) { wrmsr(MSR_GS_BASE, prev); }

/* ---------------------------------------------------------------- IRQL */
uint8_t NTAPI KeGetCurrentIrql(void) { return g_irql; }

void NTAPI KeRaiseIrql(uint8_t new_irql, uint8_t *old)
{
    if (new_irql < g_irql) kpanic("KeRaiseIrql lowers IRQL (%u < %u)", new_irql, g_irql);
    *old = g_irql;
    set_irql(new_irql);
}
uint8_t NTAPI KfRaiseIrql(uint8_t new_irql) { uint8_t o = g_irql; if (new_irql < g_irql) kpanic("KfRaiseIrql lowers IRQL"); set_irql(new_irql); return o; }
uint8_t NTAPI KeRaiseIrqlToDpcLevel(void) { uint8_t o = g_irql; if (o > DISPATCH_LEVEL) kpanic("raise to DPC from %u", o); set_irql(DISPATCH_LEVEL); return o; }
uint8_t NTAPI KeRaiseIrqlToSynchLevel(void) { uint8_t o = g_irql; set_irql(DISPATCH_LEVEL); return o; }

void ntdrv_dpc_queue_flush(void);
void NTAPI KeLowerIrql(uint8_t old)
{
    if (old > g_irql) kpanic("KeLowerIrql raises IRQL (%u > %u)", old, g_irql);
    set_irql(old);
    if (old < DISPATCH_LEVEL) ntdrv_dpc_queue_flush();
}
void NTAPI KfLowerIrql(uint8_t old) { KeLowerIrql(old); }

/* ---------------------------------------------------------------- spin locks (UP) */
void NTAPI KeInitializeSpinLock(KSPIN_LOCK *l) { *l = 0; }

/* On a uniprocessor a spin lock is IRQL elevation plus a debug-only owned flag. */
static void spin_acquire(KSPIN_LOCK *l)
{
    if (*l) kpanic("KeAcquireSpinLock: already held (deadlock on UP)");
    *l = 1;
}
static void spin_release(KSPIN_LOCK *l) { *l = 0; }

void NTAPI KeAcquireSpinLock(KSPIN_LOCK *l, uint8_t *old) { *old = g_irql; set_irql(DISPATCH_LEVEL); spin_acquire(l); }
void NTAPI KeReleaseSpinLock(KSPIN_LOCK *l, uint8_t old) { spin_release(l); set_irql(old); if (old < DISPATCH_LEVEL) ntdrv_dpc_queue_flush(); }
uint8_t NTAPI KfAcquireSpinLock(KSPIN_LOCK *l) { uint8_t o = g_irql; set_irql(DISPATCH_LEVEL); spin_acquire(l); return o; }
void NTAPI KfReleaseSpinLock(KSPIN_LOCK *l, uint8_t old) { spin_release(l); set_irql(old); if (old < DISPATCH_LEVEL) ntdrv_dpc_queue_flush(); }
void NTAPI KeAcquireSpinLockAtDpcLevel(KSPIN_LOCK *l) { if (g_irql < DISPATCH_LEVEL) kpanic("AcquireSpinLockAtDpcLevel below DISPATCH"); spin_acquire(l); }
void NTAPI KeReleaseSpinLockFromDpcLevel(KSPIN_LOCK *l) { spin_release(l); }
uint8_t NTAPI KeAcquireSpinLockRaiseToDpc(KSPIN_LOCK *l) { uint8_t o = g_irql; set_irql(DISPATCH_LEVEL); spin_acquire(l); return o; }

/* ---------------------------------------------------------------- DPCs */
static KDPC *dpc_head, *dpc_tail;
static ksem_t dpc_sem;
static int ke_ready;

void NTAPI KeInitializeDpc(KDPC *dpc, PKDEFERRED_ROUTINE routine, void *ctx)
{
    memset(dpc, 0, sizeof *dpc);
    dpc->Type = 0x13;                            /* DpcObject */
    dpc->Number = 0;
    dpc->DeferredRoutine = routine;
    dpc->DeferredContext = ctx;
}
void NTAPI KeInitializeThreadedDpc(KDPC *dpc, PKDEFERRED_ROUTINE routine, void *ctx) { KeInitializeDpc(dpc, routine, ctx); }

uint8_t NTAPI KeInsertQueueDpc(KDPC *dpc, void *sa1, void *sa2)
{
    uint64_t f = irq_save();
    if (dpc->DpcData) { irq_restore(f); return 0; }             /* already queued */
    dpc->SystemArgument1 = sa1; dpc->SystemArgument2 = sa2;
    dpc->DpcData = (void *)1;                                    /* queued marker */
    dpc->DpcListEntry.Flink = 0;
    if (dpc_tail) dpc_tail->DpcListEntry.Flink = (LIST_ENTRY *)dpc; else dpc_head = dpc;
    dpc_tail = dpc;
    irq_restore(f);
    if (ke_ready) sem_post(&dpc_sem);
    return 1;
}
uint8_t NTAPI KeRemoveQueueDpc(KDPC *dpc)
{
    uint64_t f = irq_save();
    KDPC **pp = &dpc_head, *prev = 0;
    while (*pp && *pp != dpc) { prev = *pp; pp = (KDPC **)&(*pp)->DpcListEntry.Flink; }
    if (!*pp) { irq_restore(f); return 0; }
    *pp = (KDPC *)dpc->DpcListEntry.Flink;
    if (dpc_tail == dpc) dpc_tail = prev;
    dpc->DpcData = 0;
    irq_restore(f);
    return 1;
}

/* Run one pass of the DPC queue at DISPATCH_LEVEL. */
void ntdrv_dpc_queue_flush(void)
{
    for (;;) {
        uint64_t f = irq_save();
        KDPC *dpc = dpc_head;
        void *sa1, *sa2;
        uint8_t saved;
        if (!dpc) { irq_restore(f); return; }
        dpc_head = (KDPC *)dpc->DpcListEntry.Flink;
        if (!dpc_head) dpc_tail = 0;
        dpc->DpcData = 0;
        sa1 = dpc->SystemArgument1; sa2 = dpc->SystemArgument2;
        irq_restore(f);
        saved = g_irql;
        if (g_irql < DISPATCH_LEVEL) set_irql(DISPATCH_LEVEL);
        dpc->DeferredRoutine(dpc, dpc->DeferredContext, sa1, sa2);
        if (saved < DISPATCH_LEVEL) set_irql(saved);
    }
}

static void dpc_worker(void *arg)
{
    (void)arg;
    ntdrv_gs_enter();
    for (;;) {
        sem_wait(&dpc_sem);
        set_irql(DISPATCH_LEVEL);
        ntdrv_dpc_queue_flush();
        set_irql(PASSIVE_LEVEL);
    }
}

/* ---------------------------------------------------------------- dispatcher objects */
static int hdr_signaled(DISPATCHER_HEADER *h)
{
    return h->SignalState > 0;
}
/* Apply acquire side effects of a satisfied wait. */
static void hdr_acquire(DISPATCHER_HEADER *h)
{
    switch (h->Type) {
    case EventSynchronizationObject: h->SignalState = 0; break;                 /* auto-reset */
    case SemaphoreObject: if (h->SignalState > 0) h->SignalState--; break;
    case TimerSynchronizationObject: h->SignalState = 0; break;
    case MutantObject: h->SignalState--; break;                                 /* recursive acquire */
    default: break;                                                             /* notification event/timer stay set */
    }
}

void NTAPI KeInitializeEvent(KEVENT *e, uint32_t type, uint8_t state)
{
    e->Header.Type = type ? EventSynchronizationObject : EventNotificationObject;   /* SynchronizationEvent=1 */
    e->Header.SignalState = state ? 1 : 0;
    e->Header.WaitListHead.Flink = e->Header.WaitListHead.Blink = &e->Header.WaitListHead;
}
void NTAPI KeClearEvent(KEVENT *e) { e->Header.SignalState = 0; }
LONG NTAPI KeResetEvent(KEVENT *e) { LONG p = e->Header.SignalState; e->Header.SignalState = 0; return p; }
LONG NTAPI KeReadStateEvent(KEVENT *e) { return e->Header.SignalState; }
LONG NTAPI KeSetEvent(KEVENT *e, LONG boost, uint8_t wait)
{
    LONG prev;
    uint64_t f = irq_save();
    (void)boost; (void)wait;
    prev = e->Header.SignalState;
    e->Header.SignalState = 1;
    irq_restore(f);
    return prev;
}

void NTAPI KeInitializeSemaphore(KSEMAPHORE *s, LONG count, LONG limit)
{
    s->Header.Type = SemaphoreObject;
    s->Header.SignalState = count;
    s->Limit = limit;
    s->Header.WaitListHead.Flink = s->Header.WaitListHead.Blink = &s->Header.WaitListHead;
}
LONG NTAPI KeReleaseSemaphore(KSEMAPHORE *s, LONG boost, LONG adjust, uint8_t wait)
{
    LONG prev;
    uint64_t f = irq_save();
    (void)boost; (void)wait;
    prev = s->Header.SignalState;
    if (prev + adjust > s->Limit) { irq_restore(f); kpanic("KeReleaseSemaphore over limit"); }
    s->Header.SignalState = prev + adjust;
    irq_restore(f);
    return prev;
}
LONG NTAPI KeReadStateSemaphore(KSEMAPHORE *s) { return s->Header.SignalState; }

void NTAPI KeInitializeMutex(KMUTANT *m, uint32_t level)
{
    (void)level;
    m->Header.Type = MutantObject;
    m->Header.SignalState = 1;                    /* 1 = free */
    m->OwnerThread = 0; m->Abandoned = 0;
    m->Header.WaitListHead.Flink = m->Header.WaitListHead.Blink = &m->Header.WaitListHead;
}
LONG NTAPI KeReleaseMutex(KMUTANT *m, uint8_t wait)
{
    (void)wait;
    m->Header.SignalState++;
    if (m->Header.SignalState == 1) m->OwnerThread = 0;
    return 0;
}

int64_t ntdrv_100ns_now(void);

/* Poll-based wait: correct on the UP scheduler and only ever called at PASSIVE/APC. */
static int32_t wait_one(DISPATCHER_HEADER *h, int64_t *deadline_tick, int alertable)
{
    (void)alertable;
    if (g_irql >= DISPATCH_LEVEL) kpanic("KeWaitForSingleObject at IRQL %u", g_irql);
    for (;;) {
        uint64_t f = irq_save();
        if (hdr_signaled(h)) { hdr_acquire(h); irq_restore(f); return STATUS_SUCCESS; }
        irq_restore(f);
        if (deadline_tick && *deadline_tick >= 0 && (int64_t)ticks_now() >= *deadline_tick)
            return STATUS_TIMEOUT;
        thread_sleep_ms(1);
    }
}

static int64_t deadline_from(int64_t *timeout_100ns, int64_t *store)
{
    if (!timeout_100ns) { *store = -1; return -1; }             /* infinite */
    if (*timeout_100ns == 0) { *store = 0; return 0; }
    if (*timeout_100ns < 0) {                                    /* relative */
        uint64_t ms = (uint64_t)(-*timeout_100ns) / 10000;
        *store = (int64_t)ticks_now() + (int64_t)(ms ? ms : 1);
    } else {
        *store = (int64_t)ticks_now();                           /* absolute times unsupported: fire soon */
    }
    return *store;
}

int32_t NTAPI KeWaitForSingleObject(void *obj, uint32_t reason, uint8_t mode, uint8_t alertable, int64_t *timeout)
{
    DISPATCHER_HEADER *h = obj;
    int64_t store;
    (void)reason; (void)mode;
    deadline_from(timeout, &store);
    if (timeout && *timeout == 0) {                             /* zero timeout: poll once */
        uint64_t f = irq_save();
        if (hdr_signaled(h)) { hdr_acquire(h); irq_restore(f); return STATUS_SUCCESS; }
        irq_restore(f);
        return STATUS_TIMEOUT;
    }
    return wait_one(h, timeout ? &store : 0, alertable);
}

int32_t NTAPI KeWaitForMultipleObjects(uint32_t count, void **objs, uint32_t wait_type, uint32_t reason,
                                       uint8_t mode, uint8_t alertable, int64_t *timeout, void *wait_blocks)
{
    int64_t store, *dl;
    uint32_t i;
    (void)reason; (void)mode; (void)alertable; (void)wait_blocks;
    if (g_irql >= DISPATCH_LEVEL) kpanic("KeWaitForMultipleObjects at IRQL %u", g_irql);
    deadline_from(timeout, &store);
    dl = timeout ? &store : 0;
    for (;;) {
        uint64_t f = irq_save();
        if (wait_type == 1) {                                   /* WaitAny */
            for (i = 0; i < count; ++i)
                if (hdr_signaled((DISPATCHER_HEADER *)objs[i])) { hdr_acquire((DISPATCHER_HEADER *)objs[i]); irq_restore(f); return STATUS_WAIT_0 + i; }
        } else {                                                /* WaitAll */
            int all = 1;
            for (i = 0; i < count; ++i) if (!hdr_signaled((DISPATCHER_HEADER *)objs[i])) { all = 0; break; }
            if (all) { for (i = 0; i < count; ++i) hdr_acquire((DISPATCHER_HEADER *)objs[i]); irq_restore(f); return STATUS_SUCCESS; }
        }
        irq_restore(f);
        if (dl && *dl >= 0 && (int64_t)ticks_now() >= *dl) return STATUS_TIMEOUT;
        if (dl && *dl == 0) return STATUS_TIMEOUT;
        thread_sleep_ms(1);
    }
}

/* ---------------------------------------------------------------- timers */
static KTIMER *timer_list[32];
static unsigned timer_count;

static void KeInitTimerCommon(KTIMER *t, int synch)
{
    memset(t, 0, sizeof *t);
    t->Header.Type = synch ? TimerSynchronizationObject : TimerNotificationObject;
    t->Header.SignalState = 0;
    t->Header.WaitListHead.Flink = t->Header.WaitListHead.Blink = &t->Header.WaitListHead;
}
void NTAPI KeInitializeTimer(KTIMER *t) { KeInitTimerCommon(t, 0); }
void NTAPI KeInitializeTimerEx(KTIMER *t, uint32_t type) { KeInitTimerCommon(t, type == 1); }

static void timer_arm(KTIMER *t)
{
    unsigned i;
    for (i = 0; i < timer_count; ++i) if (timer_list[i] == t) return;
    if (timer_count < 32) timer_list[timer_count++] = t;
}
static uint8_t timer_set(KTIMER *t, int64_t due_100ns, LONG period_ms, KDPC *dpc)
{
    uint64_t f = irq_save();
    uint8_t was = t->Header.SignalState != 0;
    uint64_t rel_ms = due_100ns < 0 ? (uint64_t)(-due_100ns) / 10000 : 1;   /* relative only; absolute -> soon */
    t->DueTime = ticks_now() + (rel_ms ? rel_ms : 1);
    t->Period = (uint32_t)(period_ms > 0 ? period_ms : 0);
    t->Dpc = dpc;
    t->Header.SignalState = 0;
    t->Header.Inserted = 1;
    timer_arm(t);
    irq_restore(f);
    return was;
}
uint8_t NTAPI KeSetTimer(KTIMER *t, LARGE_INTEGER due, KDPC *dpc) { return timer_set(t, due.QuadPart, 0, dpc); }
uint8_t NTAPI KeSetTimerEx(KTIMER *t, LARGE_INTEGER due, LONG period, KDPC *dpc) { return timer_set(t, due.QuadPart, period, dpc); }
uint8_t NTAPI KeCancelTimer(KTIMER *t)
{
    uint64_t f = irq_save();
    unsigned i;
    uint8_t was = t->Header.Inserted;
    t->Header.Inserted = 0;
    for (i = 0; i < timer_count; ++i) if (timer_list[i] == t) { timer_list[i] = timer_list[--timer_count]; break; }
    irq_restore(f);
    return was;
}
uint8_t NTAPI KeReadStateTimer(KTIMER *t) { return t->Header.SignalState != 0; }

static void timer_thread(void *arg)
{
    (void)arg;
    ntdrv_gs_enter();
    for (;;) {
        uint64_t now, f;
        unsigned i;
        thread_sleep_ms(1);
        now = ticks_now();
        f = irq_save();
        for (i = 0; i < timer_count; ++i) {
            KTIMER *t = timer_list[i];
            if (t->Header.Inserted && t->DueTime <= now) {
                KDPC *dpc = t->Dpc;
                t->Header.SignalState = 1;
                if (t->Period) t->DueTime = now + t->Period;
                else { t->Header.Inserted = 0; timer_list[i] = timer_list[--timer_count]; --i; }
                if (dpc) { irq_restore(f); KeInsertQueueDpc(dpc, 0, 0); f = irq_save(); }
            }
        }
        irq_restore(f);
    }
}

/* ---------------------------------------------------------------- time / delay / stall */
int64_t ntdrv_100ns_now(void)
{
    hcreg_t secs = 0;
    shz_hcall(SHZ_HC_WALLTIME, 0, 0, &secs);
    return (int64_t)(secs + 11644473600ull) * 10000000ll + (int64_t)((shz_time_ns() % 1000000000ull) / 100);
}
void NTAPI KeQuerySystemTime(LARGE_INTEGER *t) { t->QuadPart = ntdrv_100ns_now(); }
void NTAPI KeQuerySystemTimePrecise(LARGE_INTEGER *t) { t->QuadPart = ntdrv_100ns_now(); }
LARGE_INTEGER NTAPI KeQueryPerformanceCounter(LARGE_INTEGER *freq)
{
    LARGE_INTEGER v;
    if (freq) freq->QuadPart = 1000000000ll;                    /* ns ticks */
    v.QuadPart = (int64_t)shz_time_ns();
    return v;
}
uint32_t NTAPI KeQueryTimeIncrement(void) { return TICK_US * 10; }          /* 100 ns units per tick */
uint64_t NTAPI KeQueryInterruptTime(void) { return shz_time_ns() / 100; }

int32_t NTAPI KeDelayExecutionThread(uint8_t mode, uint8_t alertable, int64_t *interval)
{
    (void)mode; (void)alertable;
    if (g_irql >= DISPATCH_LEVEL) kpanic("KeDelayExecutionThread at IRQL %u", g_irql);
    if (interval && *interval < 0) {
        uint64_t ms = (uint64_t)(-*interval) / 10000;
        thread_sleep_ms(ms ? ms : 1);
    } else {
        thread_yield();
    }
    return STATUS_SUCCESS;
}
void NTAPI KeStallExecutionProcessor(uint32_t us)
{
    uint64_t end = shz_time_ns() + (uint64_t)us * 1000ull;
    while (shz_time_ns() < end) __asm__ volatile("pause");
}

/* ---------------------------------------------------------------- misc Ke */
uint32_t NTAPI KeGetCurrentProcessorNumber(void) { return 0; }
uint32_t NTAPI KeGetCurrentProcessorNumberEx(void *g) { (void)g; return 0; }
uint32_t NTAPI KeQueryActiveProcessorCount(void *g) { (void)g; return 1; }
uint32_t NTAPI KeQueryMaximumProcessorCount(void) { return 1; }
void *NTAPI KeGetCurrentThread(void) { return thread_current(); }
void NTAPI KeBugCheckEx(uint32_t code, uint64_t p1, uint64_t p2, uint64_t p3, uint64_t p4)
{
    kpanic("KeBugCheckEx 0x%x (%llx %llx %llx %llx) from driver", code, p1, p2, p3, p4);
}
void NTAPI KeBugCheck(uint32_t code) { kpanic("KeBugCheck 0x%x from driver", code); }

/* ---------------------------------------------------------------- interlocked */
LONG NTAPI InterlockedIncrement(LONG *p) { return __atomic_add_fetch(p, 1, __ATOMIC_SEQ_CST); }
LONG NTAPI InterlockedDecrement(LONG *p) { return __atomic_sub_fetch(p, 1, __ATOMIC_SEQ_CST); }
LONG NTAPI InterlockedExchange(LONG *p, LONG v) { return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST); }
LONG NTAPI InterlockedExchangeAdd(LONG *p, LONG v) { return __atomic_fetch_add(p, v, __ATOMIC_SEQ_CST); }
LONG NTAPI InterlockedCompareExchange(LONG *p, LONG ex, LONG comp) { __atomic_compare_exchange_n(p, &comp, ex, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return comp; }
int64_t NTAPI InterlockedCompareExchange64(int64_t *p, int64_t ex, int64_t comp) { __atomic_compare_exchange_n(p, &comp, ex, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return comp; }
void *NTAPI InterlockedExchangePointer(void **p, void *v) { return __atomic_exchange_n(p, v, __ATOMIC_SEQ_CST); }
void *NTAPI InterlockedCompareExchangePointer(void **p, void *ex, void *comp) { __atomic_compare_exchange_n(p, &comp, ex, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return comp; }

/* ---------------------------------------------------------------- Ex fast mutex / pools */
struct FAST_MUTEX { LONG Count; void *Owner; uint32_t Contention; uint8_t _pad[4]; void *Event[3]; };
void NTAPI ExInitializeFastMutex(struct FAST_MUTEX *m) { m->Count = 1; m->Owner = 0; m->Contention = 0; }
void NTAPI ExAcquireFastMutex(struct FAST_MUTEX *m)
{
    if (g_irql > APC_LEVEL) kpanic("ExAcquireFastMutex at IRQL %u", g_irql);
    while (__atomic_sub_fetch(&m->Count, 1, __ATOMIC_SEQ_CST) < 0) {
        __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST);
        m->Contention++;
        thread_yield();
    }
    m->Owner = thread_current();
}
void NTAPI ExReleaseFastMutex(struct FAST_MUTEX *m) { m->Owner = 0; __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST); }
uint8_t NTAPI ExTryToAcquireFastMutex(struct FAST_MUTEX *m)
{
    LONG one = 1;
    if (__atomic_compare_exchange_n(&m->Count, &one, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { m->Owner = thread_current(); return 1; }
    return 0;
}

#define POOL_TAGGED 0x40000000
void *NTAPI ExAllocatePool(uint32_t type, uint64_t n) { (void)type; return kmalloc(n ? n : 1); }
void *NTAPI ExAllocatePoolWithTag(uint32_t type, uint64_t n, uint32_t tag) { (void)type; (void)tag; return kmalloc(n ? n : 1); }
void *NTAPI ExAllocatePoolWithTagPriority(uint32_t type, uint64_t n, uint32_t tag, int pri) { (void)type; (void)tag; (void)pri; return kmalloc(n ? n : 1); }
void *NTAPI ExAllocatePoolUninitialized(uint32_t type, uint64_t n, uint32_t tag) { (void)type; (void)tag; return kmalloc(n ? n : 1); }
void *NTAPI ExAllocatePool2(uint64_t flags, uint64_t n, uint32_t tag)
{
    void *p = kmalloc(n ? n : 1);
    (void)tag;
    if (p && !(flags & 0x100 /* POOL_FLAG_UNINITIALIZED */)) memset(p, 0, n);
    return p;
}
void NTAPI ExFreePool(void *p) { kfree(p); }
void NTAPI ExFreePoolWithTag(void *p, uint32_t tag) { (void)tag; kfree(p); }

/* SLIST_HEADER initialization (the push/pop/flush/depth family lives in ntdrv_ex.c with the same encoding). */
void NTAPI ExInitializeSListHead(void *h) { memset(h, 0, 16); }

void ntdrv_ke_init(void)                        /* idempotent: the first driver load (kernel or NtLoadDriver) starts it */
{
    thread_t *w, *tt;
    if (ke_ready) return;
    sem_init(&dpc_sem, 0);
    g_irql = PASSIVE_LEVEL;
    write_cr8(PASSIVE_LEVEL);
    w = thread_create("ntdrv-dpc", dpc_worker, 0);
    tt = thread_create("ntdrv-timer", timer_thread, 0);
    KASSERT(w && tt);
    ke_ready = 1;
}
