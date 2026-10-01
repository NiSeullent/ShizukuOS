/* SPDX-License-Identifier: GPL-2.0-only
 * ntdll synchronisation: a parking lot on NtWaitForAlertByThreadId / NtAlertThreadByThreadId
 * (the primitives modern Windows uses), and on top of it WaitOnAddress, critical sections,
 * slim reader/writer locks and condition variables. Wake-ups cannot be lost: waiters validate
 * the protected word while holding the bucket lock, and wakers publish state before alerting.
 */
#include "nt.h"

#define BUCKETS 64

typedef struct wnode {
    struct wnode *next;
    const void *key;
    ULONG_PTR tid;
    volatile LONG woken;
} wnode_t;

static struct {
    volatile LONG lock;
    wnode_t *head, *tail;
} lot[BUCKETS];

static unsigned bucket_of(const void *key) { return (unsigned)((((uintptr_t)key >> 3) * 0x9e3779b1u) >> 8) % BUCKETS; }
static void b_lock(unsigned b) { while (__sync_lock_test_and_set(&lot[b].lock, 1)) NtYieldExecution(); }
static void b_unlock(unsigned b) { __sync_lock_release(&lot[b].lock); }

void ShzInitSync(void) { }

/* Returns 0 when woken, -1 on timeout, 1 when validate() said not to wait. */
static int park(const void *key, int (*validate)(const void *), const void *ctx, const LARGE_INTEGER *timeout)
{
    wnode_t n;
    const unsigned b = bucket_of(key);
    LARGE_INTEGER t;
    n.next = 0; n.key = key; n.tid = shz_tid(); n.woken = 0;
    b_lock(b);
    if (validate && !validate(ctx)) { b_unlock(b); return 1; }
    if (lot[b].tail) lot[b].tail->next = &n; else lot[b].head = &n;
    lot[b].tail = &n;
    b_unlock(b);
    for (;;) {
        NTSTATUS st;
        if (timeout) { t = *timeout; st = NtWaitForAlertByThreadId((PVOID)key, &t); }
        else st = NtWaitForAlertByThreadId((PVOID)key, 0);
        if (n.woken) return 0;
        if (st == STATUS_TIMEOUT) {
            wnode_t **pp;
            b_lock(b);
            if (n.woken) {                                   /* woken while timing out: its alert is (or will be) pending */
                LARGE_INTEGER zero = {0};
                b_unlock(b);
                NtWaitForAlertByThreadId((PVOID)key, &zero);
                return 0;
            }
            lot[b].tail = 0;
            for (pp = &lot[b].head; *pp; pp = &(*pp)->next) {
                if (*pp == &n) *pp = n.next;
                if (*pp) lot[b].tail = *pp;
                if (!*pp) break;
            }
            {
                wnode_t *w;                                  /* recompute tail after unlink */
                lot[b].tail = 0;
                for (w = lot[b].head; w; w = w->next) lot[b].tail = w;
            }
            b_unlock(b);
            return -1;
        }
        /* spurious alert: wait again with the same key */
    }
}

static void unpark(const void *key, int max)
{
    const unsigned b = bucket_of(key);
    ULONG_PTR tids[64];
    int n = 0, i;
    wnode_t **pp;
    b_lock(b);
    pp = &lot[b].head;
    while (*pp && n < max && n < 64) {
        wnode_t *w = *pp;
        if (w->key == key) {
            *pp = w->next;
            tids[n++] = w->tid;
            w->woken = 1;
        } else {
            pp = &w->next;
        }
    }
    {
        wnode_t *w;
        lot[b].tail = 0;
        for (w = lot[b].head; w; w = w->next) lot[b].tail = w;
    }
    b_unlock(b);
    for (i = 0; i < n; ++i)
        NtAlertThreadByThreadId(tids[i]);
}

/* ---------------------------------------------------------------- WaitOnAddress */
struct cmp { const volatile void *addr; const void *expect; SIZE_T size; };
static int validate_cmp(const void *c)
{
    const struct cmp *x = c;
    switch (x->size) {
    case 1: return *(const volatile uint8_t *)x->addr == *(const uint8_t *)x->expect;
    case 2: return *(const volatile uint16_t *)x->addr == *(const uint16_t *)x->expect;
    case 4: return *(const volatile uint32_t *)x->addr == *(const uint32_t *)x->expect;
    default: return *(const volatile uint64_t *)x->addr == *(const uint64_t *)x->expect;
    }
}

SHZ_EXPORT NTSTATUS NTAPI RtlWaitOnAddress(volatile VOID *addr, PVOID cmp, SIZE_T size, PLARGE_INTEGER timeout)
{
    struct cmp c = { addr, cmp, size };
    int r;
    if (size != 1 && size != 2 && size != 4 && size != 8) return STATUS_INVALID_PARAMETER;
    for (;;) {
        r = park((const void *)addr, validate_cmp, &c, timeout);
        if (r == 1) return STATUS_SUCCESS;                  /* value already differs */
        if (r == -1) return STATUS_TIMEOUT;
        return STATUS_SUCCESS;
    }
}
SHZ_EXPORT VOID NTAPI RtlWakeAddressSingle(PVOID addr) { unpark(addr, 1); }
SHZ_EXPORT VOID NTAPI RtlWakeAddressAll(PVOID addr) { unpark(addr, 64); }

/* ---------------------------------------------------------------- critical sections */
/* LockCount: -1 free, else (holders + waiters - 1). LockSemaphore holds a wake-token count. */
static LONG *tokens(RTL_CRITICAL_SECTION *cs) { return (LONG *)&cs->LockSemaphore; }
static int validate_zero(const void *p) { return *(const volatile LONG *)p == 0; }

SHZ_EXPORT NTSTATUS NTAPI RtlInitializeCriticalSectionEx(RTL_CRITICAL_SECTION *cs, ULONG spin, ULONG flags)
{
    (void)flags;
    cs->DebugInfo = 0;
    cs->LockCount = -1;
    cs->RecursionCount = 0;
    cs->OwningThread = 0;
    cs->LockSemaphore = 0;
    cs->SpinCount = spin;
    return STATUS_SUCCESS;
}
SHZ_EXPORT NTSTATUS NTAPI RtlInitializeCriticalSection(RTL_CRITICAL_SECTION *cs) { return RtlInitializeCriticalSectionEx(cs, 0, 0); }
SHZ_EXPORT NTSTATUS NTAPI RtlInitializeCriticalSectionAndSpinCount(RTL_CRITICAL_SECTION *cs, ULONG spin)
{
    return RtlInitializeCriticalSectionEx(cs, spin, 0);
}
SHZ_EXPORT NTSTATUS NTAPI RtlDeleteCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    cs->LockCount = -1; cs->RecursionCount = 0; cs->OwningThread = 0;
    return STATUS_SUCCESS;
}
SHZ_EXPORT BOOLEAN NTAPI RtlTryEnterCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    const HANDLE me = (HANDLE)(ULONG_PTR)shz_tid();
    if (__sync_val_compare_and_swap(&cs->LockCount, -1, 0) == -1) {
        cs->OwningThread = me;
        cs->RecursionCount = 1;
        return TRUE;
    }
    if (cs->OwningThread == me) {
        __sync_add_and_fetch(&cs->LockCount, 1);
        ++cs->RecursionCount;
        return TRUE;
    }
    return FALSE;
}
SHZ_EXPORT NTSTATUS NTAPI RtlEnterCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    const HANDLE me = (HANDLE)(ULONG_PTR)shz_tid();
    ULONG i;
    if (cs->OwningThread == me) {                             /* recursive entry by the owner */
        __sync_add_and_fetch(&cs->LockCount, 1);
        ++cs->RecursionCount;
        return STATUS_SUCCESS;
    }
    for (i = 0; i < cs->SpinCount; ++i)
        if (__sync_val_compare_and_swap(&cs->LockCount, -1, 0) == -1) goto acquired;
    if (__sync_add_and_fetch(&cs->LockCount, 1) != 0) {       /* contended: wait for a hand-off token */
        for (;;) {
            LONG t = *(volatile LONG *)tokens(cs);
            if (t > 0 && __sync_bool_compare_and_swap(tokens(cs), t, t - 1)) break;
            park(tokens(cs), validate_zero, tokens(cs), 0);
        }
    }
acquired:
    cs->OwningThread = me;
    cs->RecursionCount = 1;
    return STATUS_SUCCESS;
}
SHZ_EXPORT NTSTATUS NTAPI RtlLeaveCriticalSection(RTL_CRITICAL_SECTION *cs)
{
    if (--cs->RecursionCount) {                               /* still held recursively */
        __sync_sub_and_fetch(&cs->LockCount, 1);
        return STATUS_SUCCESS;
    }
    cs->OwningThread = 0;
    if (__sync_sub_and_fetch(&cs->LockCount, 1) >= 0) {       /* someone is waiting: hand the lock over */
        __sync_add_and_fetch(tokens(cs), 1);
        unpark(tokens(cs), 1);
    }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- SRW locks */
#define SRW_EXCL 1u
#define SRW_WAIT 2u
#define SRW_ONE 4u

/* park() invokes validation while holding the address's bucket lock. A
 * release/reacquire can happen after Acquire observed SRW_WAIT but before
 * park validates; that new owner has no WAIT bit. Publish WAIT for the
 * current owner under the bucket lock before linking the waiter, so its
 * release either wakes that queued waiter or validation sees a free word.
 * A CAS also closes release/reacquire during validation itself. */
static int validate_srw_wait(const void *p, ULONG_PTR busy_mask)
{
    volatile ULONG_PTR *word = (volatile ULONG_PTR *)p;
    for (;;) {
        const ULONG_PTR old = *word;
        if (!(old & busy_mask)) return 0;
        if (__sync_bool_compare_and_swap(word, old, old | SRW_WAIT)) return 1;
    }
}
static int validate_srw_excl(const void *p) { return validate_srw_wait(p, SRW_EXCL); }
static int validate_srw_busy(const void *p) { return validate_srw_wait(p, ~(ULONG_PTR)SRW_WAIT); }

SHZ_EXPORT VOID NTAPI RtlInitializeSRWLock(RTL_SRWLOCK *l) { l->Ptr = 0; }

SHZ_EXPORT VOID NTAPI RtlAcquireSRWLockExclusive(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    for (;;) {
        ULONG_PTR old = *w;
        if ((old & ~(ULONG_PTR)SRW_WAIT) == 0) {
            if (__sync_bool_compare_and_swap(w, old, old | SRW_EXCL)) return;
            continue;
        }
        if (!(old & SRW_WAIT)) { __sync_bool_compare_and_swap(w, old, old | SRW_WAIT); continue; }
        park((const void *)w, validate_srw_busy, (const void *)w, 0);
    }
}
SHZ_EXPORT BOOLEAN NTAPI RtlTryAcquireSRWLockExclusive(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    ULONG_PTR old = *w;
    return (old & ~(ULONG_PTR)SRW_WAIT) == 0 && __sync_bool_compare_and_swap(w, old, old | SRW_EXCL);
}
SHZ_EXPORT VOID NTAPI RtlReleaseSRWLockExclusive(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    ULONG_PTR old;
    do old = *w; while (!__sync_bool_compare_and_swap(w, old, old & ~(ULONG_PTR)(SRW_EXCL | SRW_WAIT)));
    if (old & SRW_WAIT) unpark((const void *)w, 64);
}
SHZ_EXPORT VOID NTAPI RtlAcquireSRWLockShared(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    for (;;) {
        ULONG_PTR old = *w;
        if (!(old & SRW_EXCL)) {
            if (__sync_bool_compare_and_swap(w, old, old + SRW_ONE)) return;
            continue;
        }
        if (!(old & SRW_WAIT)) { __sync_bool_compare_and_swap(w, old, old | SRW_WAIT); continue; }
        park((const void *)w, validate_srw_excl, (const void *)w, 0);
    }
}
SHZ_EXPORT BOOLEAN NTAPI RtlTryAcquireSRWLockShared(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    ULONG_PTR old = *w;
    return !(old & SRW_EXCL) && __sync_bool_compare_and_swap(w, old, old + SRW_ONE);
}
SHZ_EXPORT VOID NTAPI RtlReleaseSRWLockShared(RTL_SRWLOCK *l)
{
    volatile ULONG_PTR *w = (volatile ULONG_PTR *)&l->Ptr;
    ULONG_PTR old, nw;
    do { old = *w; nw = old - SRW_ONE; if (nw < SRW_ONE) nw &= ~(ULONG_PTR)SRW_WAIT; }
    while (!__sync_bool_compare_and_swap(w, old, nw));
    if ((old & SRW_WAIT) && nw < SRW_ONE) unpark((const void *)w, 64);
}

/* ---------------------------------------------------------------- condition variables */

SHZ_EXPORT VOID NTAPI RtlInitializeConditionVariable(RTL_CONDITION_VARIABLE *cv) { cv->Ptr = 0; }
SHZ_EXPORT VOID NTAPI RtlWakeConditionVariable(RTL_CONDITION_VARIABLE *cv)
{
    __sync_add_and_fetch((volatile LONG *)&cv->Ptr, 1);
    unpark(cv, 1);
}
SHZ_EXPORT VOID NTAPI RtlWakeAllConditionVariable(RTL_CONDITION_VARIABLE *cv)
{
    __sync_add_and_fetch((volatile LONG *)&cv->Ptr, 1);
    unpark(cv, 64);
}

struct cv_validate { volatile LONG *seq; LONG snap; };
static int validate_cv(const void *p) { const struct cv_validate *v = p; return *v->seq == v->snap; }

static NTSTATUS cv_wait(RTL_CONDITION_VARIABLE *cv, void (*unlock)(void *), void (*lock)(void *), void *lk,
                        PLARGE_INTEGER timeout)
{
    /* Snapshot the sequence, release the lock, park only if nobody signalled in between. */
    struct cv_validate v;
    int r;
    v.seq = (volatile LONG *)&cv->Ptr;
    v.snap = *v.seq;
    unlock(lk);
    r = park(cv, validate_cv, &v, timeout);
    lock(lk);
    return r == -1 ? STATUS_TIMEOUT : STATUS_SUCCESS;
}

static void srw_unlock_excl(void *l) { RtlReleaseSRWLockExclusive(l); }
static void srw_lock_excl(void *l) { RtlAcquireSRWLockExclusive(l); }
static void srw_unlock_shared(void *l) { RtlReleaseSRWLockShared(l); }
static void srw_lock_shared(void *l) { RtlAcquireSRWLockShared(l); }
static void cs_unlock(void *l) { RtlLeaveCriticalSection(l); }
static void cs_lock(void *l) { RtlEnterCriticalSection(l); }

SHZ_EXPORT NTSTATUS NTAPI RtlSleepConditionVariableSRW(RTL_CONDITION_VARIABLE *cv, RTL_SRWLOCK *l, PLARGE_INTEGER timeout,
                                                       ULONG flags)
{
    if (flags & CONDITION_VARIABLE_LOCKMODE_SHARED)
        return cv_wait(cv, srw_unlock_shared, srw_lock_shared, l, timeout);
    return cv_wait(cv, srw_unlock_excl, srw_lock_excl, l, timeout);
}
SHZ_EXPORT NTSTATUS NTAPI RtlSleepConditionVariableCS(RTL_CONDITION_VARIABLE *cv, RTL_CRITICAL_SECTION *cs, PLARGE_INTEGER timeout)
{
    /* A recursively held section is fully released and restored, as Windows requires exactly-once ownership. */
    LONG rec = cs->RecursionCount;
    NTSTATUS st;
    if (rec != 1) return STATUS_INVALID_PARAMETER;
    st = cv_wait(cv, cs_unlock, cs_lock, cs, timeout);
    return st;
}
