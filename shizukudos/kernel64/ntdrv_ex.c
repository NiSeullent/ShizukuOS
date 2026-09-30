/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the second Ex/Ke batch a real WDM driver needs beyond ntdrv_ke.c --
 * interlocked (spin-locked) doubly and singly linked lists, the x64 sequenced singly linked
 * list (SLIST_HEADER, the HeaderX64 encoding drivers' inline helpers rely on), lookaside lists,
 * executive resources (ERESOURCE), fast/guarded mutexes' remaining entries, callback objects
 * (ExCreateCallback/ExRegisterCallback/ExNotifyCallback), cache-aware rundown protection,
 * critical regions, in-stack queued spin locks, bug-check callbacks, the processor-feature and
 * accounting queries, and the kernel's exported data (KeNumberProcessors, KiBugCheckData,
 * InitSafeBootMode, KdDebugger*, NlsMbCodePageTag, the object-type pointers, the HAL dispatch
 * tables). Every entry is NTAPI and follows the documented WDM semantics on this uniprocessor
 * kernel; nothing here is a placeholder.
 */
#include "ntdrv.h"

#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2

/* ================================================================ interlocked LIST_ENTRY / SINGLE_LIST_ENTRY */
typedef struct _SINGLE_LIST_ENTRY { struct _SINGLE_LIST_ENTRY *Next; } SINGLE_LIST_ENTRY;

static inline void list_insert_tail(LIST_ENTRY *head, LIST_ENTRY *e)
{
    LIST_ENTRY *last = head->Blink;
    e->Flink = head; e->Blink = last; last->Flink = e; head->Blink = e;
}
static inline void list_insert_head(LIST_ENTRY *head, LIST_ENTRY *e)
{
    LIST_ENTRY *first = head->Flink;
    e->Flink = first; e->Blink = head; first->Blink = e; head->Flink = e;
}
static inline LIST_ENTRY *list_remove_head(LIST_ENTRY *head)
{
    LIST_ENTRY *e = head->Flink;
    if (e == head) return 0;
    head->Flink = e->Flink; e->Flink->Blink = head;
    return e;
}
static inline LIST_ENTRY *list_remove_tail(LIST_ENTRY *head)
{
    LIST_ENTRY *e = head->Blink;
    if (e == head) return 0;
    head->Blink = e->Blink; e->Blink->Flink = head;
    return e;
}

/* The lock is a real KSPIN_LOCK: taken through the IRQL machinery of ntdrv_ke.c so a DPC or ISR
 * cannot interleave with the list update on this UP kernel. The return value is the previous
 * head/tail (NULL for an empty list), as documented. */
LIST_ENTRY *NTAPI ExInterlockedInsertTailList(LIST_ENTRY *head, LIST_ENTRY *e, KSPIN_LOCK *lock)
{
    uint8_t irql; LIST_ENTRY *prev;
    KeAcquireSpinLock(lock, &irql);
    prev = head->Blink == head ? 0 : head->Blink;
    list_insert_tail(head, e);
    KeReleaseSpinLock(lock, irql);
    return prev;
}
LIST_ENTRY *NTAPI ExInterlockedInsertHeadList(LIST_ENTRY *head, LIST_ENTRY *e, KSPIN_LOCK *lock)
{
    uint8_t irql; LIST_ENTRY *prev;
    KeAcquireSpinLock(lock, &irql);
    prev = head->Flink == head ? 0 : head->Flink;
    list_insert_head(head, e);
    KeReleaseSpinLock(lock, irql);
    return prev;
}
LIST_ENTRY *NTAPI ExInterlockedRemoveHeadList(LIST_ENTRY *head, KSPIN_LOCK *lock)
{
    uint8_t irql; LIST_ENTRY *e;
    KeAcquireSpinLock(lock, &irql);
    e = list_remove_head(head);
    KeReleaseSpinLock(lock, irql);
    return e;
}
LIST_ENTRY *NTAPI ExInterlockedRemoveTailList(LIST_ENTRY *head, KSPIN_LOCK *lock)
{
    uint8_t irql; LIST_ENTRY *e;
    KeAcquireSpinLock(lock, &irql);
    e = list_remove_tail(head);
    KeReleaseSpinLock(lock, irql);
    return e;
}
SINGLE_LIST_ENTRY *NTAPI ExInterlockedPushEntryList(SINGLE_LIST_ENTRY *head, SINGLE_LIST_ENTRY *e, KSPIN_LOCK *lock)
{
    uint8_t irql; SINGLE_LIST_ENTRY *prev;
    KeAcquireSpinLock(lock, &irql);
    prev = head->Next;
    e->Next = prev; head->Next = e;
    KeReleaseSpinLock(lock, irql);
    return prev;
}
SINGLE_LIST_ENTRY *NTAPI ExInterlockedPopEntryList(SINGLE_LIST_ENTRY *head, KSPIN_LOCK *lock)
{
    uint8_t irql; SINGLE_LIST_ENTRY *e;
    KeAcquireSpinLock(lock, &irql);
    e = head->Next;
    if (e) head->Next = e->Next;
    KeReleaseSpinLock(lock, irql);
    return e;
}
uint32_t NTAPI ExInterlockedAddUlong(uint32_t *addend, uint32_t inc, KSPIN_LOCK *lock)
{
    uint8_t irql; uint32_t old;
    KeAcquireSpinLock(lock, &irql);
    old = *addend; *addend = old + inc;
    KeReleaseSpinLock(lock, irql);
    return old;
}
LARGE_INTEGER NTAPI ExInterlockedAddLargeInteger(LARGE_INTEGER *addend, LARGE_INTEGER inc, KSPIN_LOCK *lock)
{
    uint8_t irql; LARGE_INTEGER old;
    KeAcquireSpinLock(lock, &irql);
    old = *addend; addend->QuadPart += inc.QuadPart;
    KeReleaseSpinLock(lock, irql);
    return old;
}

/* ================================================================ SLIST_HEADER (x64 HeaderX64 encoding) */
/* Windows x64: bits 0..15 Depth, 16..63 Sequence in the first quadword; bits 4..63 of the second
 * quadword are the entry address >> 4 (entries are 16-byte aligned). A driver's inline
 * RtlFirstEntrySList / ExQueryDepthSList read exactly these fields, so the encoding is kept. */
typedef struct { uint64_t depth_seq, next; } slist_t;
#define SL_DEPTH(h) ((uint16_t)((h)->depth_seq & 0xffff))
#define SL_SEQ(h) ((h)->depth_seq >> 16)
#define SL_NEXT(h) ((SINGLE_LIST_ENTRY *)(((h)->next >> 4) << 4))
static void slist_set(slist_t *h, SINGLE_LIST_ENTRY *first, uint16_t depth, uint64_t seq)
{
    h->depth_seq = (seq << 16) | depth;
    h->next = ((uint64_t)first >> 4) << 4;
}
void NTAPI InitializeSListHead(void *head) { memset(head, 0, 16); }
uint16_t NTAPI ExQueryDepthSList(void *head) { return SL_DEPTH((slist_t *)head); }
SINGLE_LIST_ENTRY *NTAPI ExpInterlockedPushEntrySList(void *head, SINGLE_LIST_ENTRY *e)
{
    slist_t *h = head;
    uint64_t f = irq_save();
    SINGLE_LIST_ENTRY *first = SL_NEXT(h);
    if ((uint64_t)e & 0xf) { irq_restore(f); kpanic("ExpInterlockedPushEntrySList: entry %p not 16-byte aligned", e); }
    e->Next = first;
    slist_set(h, e, (uint16_t)(SL_DEPTH(h) + 1), SL_SEQ(h) + 1);
    irq_restore(f);
    return first;
}
SINGLE_LIST_ENTRY *NTAPI ExpInterlockedPopEntrySList(void *head)
{
    slist_t *h = head;
    uint64_t f = irq_save();
    SINGLE_LIST_ENTRY *first = SL_NEXT(h);
    if (first) slist_set(h, first->Next, (uint16_t)(SL_DEPTH(h) - 1), SL_SEQ(h) + 1);
    irq_restore(f);
    return first;
}
SINGLE_LIST_ENTRY *NTAPI ExpInterlockedFlushSList(void *head)
{
    slist_t *h = head;
    uint64_t f = irq_save();
    SINGLE_LIST_ENTRY *first = SL_NEXT(h);
    slist_set(h, 0, 0, SL_SEQ(h) + 1);
    irq_restore(f);
    return first;
}

/* ================================================================ lookaside lists */
/* GENERAL_LOOKASIDE (x64, 0x80 bytes): ListHead(0) Depth(0x10) MaximumDepth(0x12) TotalAllocates(0x14)
 * AllocateMisses(0x18) TotalFrees(0x1c) FreeMisses(0x20) Type(0x24) Tag(0x28) Size(0x2c) Allocate(0x30)
 * Free(0x38) ListEntry(0x40) LastTotalAllocates(0x50) LastAllocateMisses(0x54) Future[2](0x58). */
typedef struct {
    slist_t ListHead;
    uint16_t Depth, MaximumDepth;
    uint32_t TotalAllocates, AllocateMisses, TotalFrees, FreeMisses;
    uint32_t Type, Tag, Size;
    void *(NTAPI *Allocate)(uint32_t type, uint64_t n, uint32_t tag);
    void (NTAPI *Free)(void *p);
    LIST_ENTRY ListEntry;
    uint32_t LastTotalAllocates, LastAllocateMisses, Future[2];
    uint8_t CacheLinePad[0x20];         /* DECLSPEC_CACHEALIGN: the record is 0x80 bytes */
} GENERAL_LOOKASIDE;
_Static_assert(sizeof(GENERAL_LOOKASIDE) == 0x80 && __builtin_offsetof(GENERAL_LOOKASIDE, Allocate) == 0x30 &&
               __builtin_offsetof(GENERAL_LOOKASIDE, Depth) == 0x10 && __builtin_offsetof(GENERAL_LOOKASIDE, Tag) == 0x28 &&
               __builtin_offsetof(GENERAL_LOOKASIDE, Size) == 0x2c, "GENERAL_LOOKASIDE");
extern void *NTAPI ExAllocatePoolWithTag(uint32_t, uint64_t, uint32_t);
extern void NTAPI ExFreePool(void *);
static LIST_ENTRY lookaside_list = { &lookaside_list, &lookaside_list };

static void lookaside_init(GENERAL_LOOKASIDE *l, void *alloc, void *free, uint32_t type, uint64_t size, uint32_t tag, uint16_t depth)
{
    memset(l, 0, sizeof *l);
    l->Depth = depth ? depth : 4;                            /* Windows starts at 4 and tunes towards MaximumDepth */
    l->MaximumDepth = 256;
    l->Type = type;
    l->Tag = tag;
    l->Size = (uint32_t)size;
    l->Allocate = alloc ? alloc : (void *)ExAllocatePoolWithTag;
    l->Free = free ? free : (void *)ExFreePool;
    { uint64_t f = irq_save(); list_insert_tail(&lookaside_list, &l->ListEntry); irq_restore(f); }
}
static void lookaside_delete(GENERAL_LOOKASIDE *l)
{
    SINGLE_LIST_ENTRY *e;
    uint64_t f = irq_save();
    LIST_ENTRY *p = &l->ListEntry;
    p->Blink->Flink = p->Flink; p->Flink->Blink = p->Blink;
    irq_restore(f);
    while ((e = ExpInterlockedPopEntrySList(&l->ListHead)) != 0) l->Free(e);
}
void NTAPI ExInitializeNPagedLookasideList(void *l, void *alloc, void *free, uint32_t flags, uint64_t size, uint32_t tag, uint16_t depth)
{ (void)flags; lookaside_init(l, alloc, free, 0 /* NonPagedPool */, size, tag, depth); }
void NTAPI ExInitializePagedLookasideList(void *l, void *alloc, void *free, uint32_t flags, uint64_t size, uint32_t tag, uint16_t depth)
{ (void)flags; lookaside_init(l, alloc, free, 1 /* PagedPool */, size, tag, depth); }
void NTAPI ExDeleteNPagedLookasideList(void *l) { lookaside_delete(l); }
void NTAPI ExDeletePagedLookasideList(void *l) { lookaside_delete(l); }

/* ExAllocatePoolWithQuota raises STATUS_INSUFFICIENT_RESOURCES on failure unless the caller passed
 * POOL_QUOTA_FAIL_INSTEAD_OF_RAISE (8); charging is against the calling process's quota, which
 * for a system thread is the system process (unlimited here). */
void *NTAPI ExAllocatePoolWithQuotaTag(uint32_t type, uint64_t n, uint32_t tag)
{
    void *p = ExAllocatePoolWithTag(type & ~8u, n, tag);
    if (!p && !(type & 8)) kpanic("ExAllocatePoolWithQuotaTag: %llu bytes unavailable (would raise STATUS_INSUFFICIENT_RESOURCES)", n);
    return p;
}

/* ================================================================ critical regions (per-thread APC disable count) */
/* A kernel thread here has no APC machinery; the count still has to be exact because
 * ERESOURCE acquisition asserts it and drivers pair Enter/Leave across calls. */
#define CR_MAX 128
static struct { thread_t *t; int count; } cr_tab[CR_MAX];
static int *cr_slot(thread_t *t)
{
    unsigned i, free = CR_MAX;
    for (i = 0; i < CR_MAX; ++i) {
        if (cr_tab[i].t == t) return &cr_tab[i].count;
        if (!cr_tab[i].t && free == CR_MAX) free = i;
    }
    if (free == CR_MAX) kpanic("KeEnterCriticalRegion: too many threads");
    cr_tab[free].t = t; cr_tab[free].count = 0;
    return &cr_tab[free].count;
}
void NTAPI KeEnterCriticalRegion(void) { uint64_t f = irq_save(); (*cr_slot(thread_current()))++; irq_restore(f); }
void NTAPI KeLeaveCriticalRegion(void)
{
    uint64_t f = irq_save();
    int *c = cr_slot(thread_current());
    if (*c <= 0) { irq_restore(f); kpanic("KeLeaveCriticalRegion without KeEnterCriticalRegion"); }
    (*c)--;
    irq_restore(f);
}
uint8_t NTAPI KeAreApcsDisabled(void) { uint64_t f = irq_save(); int c = *cr_slot(thread_current()); irq_restore(f); return c != 0; }
uint8_t NTAPI KeAreAllApcsDisabled(void) { return KeAreApcsDisabled() || ntdrv_current_irql() >= APC_LEVEL; }
void NTAPI KeEnterGuardedRegion(void) { KeEnterCriticalRegion(); }
void NTAPI KeLeaveGuardedRegion(void) { KeLeaveCriticalRegion(); }

/* ================================================================ ERESOURCE */
/* 0x68 bytes on x64; the layout is private to the executive, so the host's own record fits in it.
 * Semantics: one exclusive owner (recursively), or any number of shared owners; a shared owner may
 * not recursively acquire exclusive (deadlock on Windows: bug-checked here); Wait=FALSE returns
 * FALSE instead of blocking; callers must be inside a critical region or at APC_LEVEL. */
typedef struct {
    LIST_ENTRY SystemResourcesList;
    thread_t *owner;                    /* exclusive owner */
    int32_t excl_count;                 /* recursion depth of the exclusive owner */
    int32_t shared_count;
    thread_t *shared[4];                /* shared owners (recursion counted in shared_rec) */
    int32_t shared_rec[4];
    uint32_t waiters;
} eresource_t;
_Static_assert(sizeof(eresource_t) <= 0x68, "eresource fits");
static LIST_ENTRY resource_list = { &resource_list, &resource_list };

NTSTATUS NTAPI ExInitializeResourceLite(eresource_t *r)
{
    uint64_t f;
    memset(r, 0, 0x68);
    f = irq_save(); list_insert_tail(&resource_list, &r->SystemResourcesList); irq_restore(f);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ExReinitializeResourceLite(eresource_t *r)
{
    uint64_t f = irq_save();
    r->owner = 0; r->excl_count = r->shared_count = 0; r->waiters = 0;
    memset(r->shared, 0, sizeof r->shared); memset(r->shared_rec, 0, sizeof r->shared_rec);
    irq_restore(f);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI ExDeleteResourceLite(eresource_t *r)
{
    uint64_t f = irq_save();
    LIST_ENTRY *p = &r->SystemResourcesList;
    if (r->owner || r->shared_count) { irq_restore(f); kpanic("ExDeleteResourceLite: resource %p still owned", r); }
    p->Blink->Flink = p->Flink; p->Flink->Blink = p->Blink;
    irq_restore(f);
    return STATUS_SUCCESS;
}
static int shared_index(eresource_t *r, thread_t *t) { int i; for (i = 0; i < 4; ++i) if (r->shared[i] == t) return i; return -1; }
static void resource_check_caller(const char *who)
{
    if (ntdrv_current_irql() > APC_LEVEL) kpanic("%s at IRQL %u", who, ntdrv_current_irql());
    if (!KeAreApcsDisabled() && ntdrv_current_irql() < APC_LEVEL) kpanic("%s outside a critical region", who);
}
uint8_t NTAPI ExAcquireResourceExclusiveLite(eresource_t *r, uint8_t wait)
{
    thread_t *me = thread_current();
    resource_check_caller("ExAcquireResourceExclusiveLite");
    for (;;) {
        uint64_t f = irq_save();
        if (r->owner == me) { r->excl_count++; irq_restore(f); return 1; }
        if (!r->owner && !r->shared_count) { r->owner = me; r->excl_count = 1; irq_restore(f); return 1; }
        if (shared_index(r, me) >= 0) { irq_restore(f); kpanic("ExAcquireResourceExclusiveLite: shared owner re-acquiring exclusive (deadlock)"); }
        if (!wait) { irq_restore(f); return 0; }
        r->waiters++;
        irq_restore(f);
        thread_sleep_ms(1);
        f = irq_save(); r->waiters--; irq_restore(f);
    }
}
uint8_t NTAPI ExAcquireResourceSharedLite(eresource_t *r, uint8_t wait)
{
    thread_t *me = thread_current();
    resource_check_caller("ExAcquireResourceSharedLite");
    for (;;) {
        uint64_t f = irq_save();
        int i = shared_index(r, me);
        if (r->owner == me) { r->excl_count++; irq_restore(f); return 1; }      /* exclusive owner: counted as another exclusive level */
        if (i >= 0) { r->shared_rec[i]++; irq_restore(f); return 1; }
        if (!r->owner && !(r->waiters && wait)) {                                  /* a waiting exclusive acquirer has priority */
            for (i = 0; i < 4; ++i) if (!r->shared[i]) { r->shared[i] = me; r->shared_rec[i] = 1; r->shared_count++; irq_restore(f); return 1; }
            irq_restore(f); kpanic("ExAcquireResourceSharedLite: more than 4 shared owners");
        }
        if (!wait) { irq_restore(f); return 0; }
        irq_restore(f);
        thread_sleep_ms(1);
    }
}
uint8_t NTAPI ExAcquireSharedStarveExclusive(eresource_t *r, uint8_t wait) { return ExAcquireResourceSharedLite(r, wait); }
uint8_t NTAPI ExAcquireSharedWaitForExclusive(eresource_t *r, uint8_t wait) { return ExAcquireResourceSharedLite(r, wait); }
void NTAPI ExReleaseResourceForThreadLite(eresource_t *r, uint64_t thread_id)
{
    thread_t *me = (thread_t *)thread_id;
    uint64_t f = irq_save();
    int i;
    if (r->owner == me) {
        if (--r->excl_count == 0) r->owner = 0;
    } else if ((i = shared_index(r, me)) >= 0) {
        if (--r->shared_rec[i] == 0) { r->shared[i] = 0; r->shared_count--; }
    } else { irq_restore(f); kpanic("ExReleaseResourceLite: %p not owned by the caller", r); }
    irq_restore(f);
}
void NTAPI ExReleaseResourceLite(eresource_t *r) { ExReleaseResourceForThreadLite(r, (uint64_t)thread_current()); }
uint8_t NTAPI ExIsResourceAcquiredExclusiveLite(eresource_t *r) { return r->owner == thread_current(); }
uint32_t NTAPI ExIsResourceAcquiredSharedLite(eresource_t *r)
{
    int i = shared_index(r, thread_current());
    if (r->owner == thread_current()) return (uint32_t)r->excl_count;
    return i >= 0 ? (uint32_t)r->shared_rec[i] : 0;
}
uint32_t NTAPI ExGetExclusiveWaiterCount(eresource_t *r) { return r->waiters; }
uint32_t NTAPI ExGetSharedWaiterCount(eresource_t *r) { (void)r; return 0; }
void NTAPI ExConvertExclusiveToSharedLite(eresource_t *r)
{
    uint64_t f = irq_save();
    if (r->owner == thread_current() && r->excl_count == 1) {
        int i; for (i = 0; i < 4; ++i) if (!r->shared[i]) { r->shared[i] = r->owner; r->shared_rec[i] = 1; r->shared_count++; break; }
        r->owner = 0; r->excl_count = 0;
    }
    irq_restore(f);
}
/* ExEnterCriticalRegionAndAcquireResourceExclusive & co. are exported by Vista+ kernels as convenience wrappers. */
void *NTAPI ExEnterCriticalRegionAndAcquireResourceExclusive(eresource_t *r) { KeEnterCriticalRegion(); ExAcquireResourceExclusiveLite(r, 1); return 0; }
void *NTAPI ExEnterCriticalRegionAndAcquireResourceShared(eresource_t *r) { KeEnterCriticalRegion(); ExAcquireResourceSharedLite(r, 1); return 0; }
void NTAPI ExReleaseResourceAndLeaveCriticalRegion(eresource_t *r) { ExReleaseResourceLite(r); KeLeaveCriticalRegion(); }

/* ================================================================ fast mutex (unsafe variants) / guarded mutex */
struct FAST_MUTEX { LONG Count; void *Owner; uint32_t Contention; uint8_t _pad[4]; void *Event[3]; };
extern void NTAPI ExAcquireFastMutex(struct FAST_MUTEX *);
extern void NTAPI ExReleaseFastMutex(struct FAST_MUTEX *);
extern uint8_t NTAPI ExTryToAcquireFastMutex(struct FAST_MUTEX *);
/* The Unsafe variants require the caller to be at APC_LEVEL or in a critical region already; they do not raise. */
void NTAPI ExAcquireFastMutexUnsafe(struct FAST_MUTEX *m)
{
    if (!KeAreAllApcsDisabled()) kpanic("ExAcquireFastMutexUnsafe outside APC_LEVEL/critical region");
    while (__atomic_sub_fetch(&m->Count, 1, __ATOMIC_SEQ_CST) < 0) { __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST); m->Contention++; thread_yield(); }
    m->Owner = thread_current();
}
void NTAPI ExReleaseFastMutexUnsafe(struct FAST_MUTEX *m) { m->Owner = 0; __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST); }
/* KGUARDED_MUTEX has FAST_MUTEX's layout; acquisition enters a guarded region instead of raising to APC_LEVEL. */
void NTAPI KeInitializeGuardedMutex(struct FAST_MUTEX *m) { m->Count = 1; m->Owner = 0; m->Contention = 0; }
void NTAPI KeAcquireGuardedMutex(struct FAST_MUTEX *m)
{
    if (ntdrv_current_irql() > APC_LEVEL) kpanic("KeAcquireGuardedMutex at IRQL %u", ntdrv_current_irql());
    KeEnterGuardedRegion();
    while (__atomic_sub_fetch(&m->Count, 1, __ATOMIC_SEQ_CST) < 0) { __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST); m->Contention++; thread_yield(); }
    m->Owner = thread_current();
}
void NTAPI KeReleaseGuardedMutex(struct FAST_MUTEX *m)
{
    if (m->Owner != thread_current()) kpanic("KeReleaseGuardedMutex: not the owner");
    m->Owner = 0; __atomic_add_fetch(&m->Count, 1, __ATOMIC_SEQ_CST);
    KeLeaveGuardedRegion();
}
uint8_t NTAPI KeTryToAcquireGuardedMutex(struct FAST_MUTEX *m)
{
    LONG one = 1;
    KeEnterGuardedRegion();
    if (__atomic_compare_exchange_n(&m->Count, &one, 0, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) { m->Owner = thread_current(); return 1; }
    KeLeaveGuardedRegion();
    return 0;
}
void NTAPI KeAcquireGuardedMutexUnsafe(struct FAST_MUTEX *m) { ExAcquireFastMutexUnsafe(m); }
void NTAPI KeReleaseGuardedMutexUnsafe(struct FAST_MUTEX *m) { ExReleaseFastMutexUnsafe(m); }

/* ================================================================ in-stack queued spin locks */
typedef struct { struct { void *Next; KSPIN_LOCK *Lock; } LockQueue; uint8_t OldIrql; uint8_t _pad[7]; } KLOCK_QUEUE_HANDLE;
extern uint8_t NTAPI KfAcquireSpinLock(KSPIN_LOCK *);
extern void NTAPI KfReleaseSpinLock(KSPIN_LOCK *, uint8_t);
extern void NTAPI KeAcquireSpinLockAtDpcLevel(KSPIN_LOCK *);
extern void NTAPI KeReleaseSpinLockFromDpcLevel(KSPIN_LOCK *);
void NTAPI KeAcquireInStackQueuedSpinLock(KSPIN_LOCK *lock, KLOCK_QUEUE_HANDLE *h)
{ h->LockQueue.Next = 0; h->LockQueue.Lock = lock; h->OldIrql = KfAcquireSpinLock(lock); }
void NTAPI KeReleaseInStackQueuedSpinLock(KLOCK_QUEUE_HANDLE *h) { KfReleaseSpinLock(h->LockQueue.Lock, h->OldIrql); }
void NTAPI KeAcquireInStackQueuedSpinLockAtDpcLevel(KSPIN_LOCK *lock, KLOCK_QUEUE_HANDLE *h)
{ h->LockQueue.Next = 0; h->LockQueue.Lock = lock; h->OldIrql = DISPATCH_LEVEL; KeAcquireSpinLockAtDpcLevel(lock); }
void NTAPI KeReleaseInStackQueuedSpinLockFromDpcLevel(KLOCK_QUEUE_HANDLE *h) { KeReleaseSpinLockFromDpcLevel(h->LockQueue.Lock); }
uint8_t NTAPI KeTryToAcquireSpinLockAtDpcLevel(KSPIN_LOCK *l)
{
    if (ntdrv_current_irql() < DISPATCH_LEVEL) kpanic("KeTryToAcquireSpinLockAtDpcLevel below DISPATCH_LEVEL");
    if (*l) return 0;
    *l = 1;
    return 1;
}
uint8_t NTAPI KeTestSpinLock(KSPIN_LOCK *l) { return *l == 0; }

/* ================================================================ DPC / processor queries */
extern void ntdrv_dpc_queue_flush(void);
void NTAPI KeFlushQueuedDpcs(void)
{
    if (ntdrv_current_irql() >= DISPATCH_LEVEL) kpanic("KeFlushQueuedDpcs at IRQL %u", ntdrv_current_irql());
    ntdrv_dpc_queue_flush();                     /* every DPC queued before this call has now run on this (only) processor */
}
uint64_t NTAPI KeQueryActiveProcessors(void) { return 1; }
uint64_t NTAPI KeQueryActiveProcessorCountEx(uint16_t group) { return group == 0 || group == 0xffff ? 1 : 0; }
uint16_t NTAPI KeQueryActiveGroupCount(void) { return 1; }
uint16_t NTAPI KeQueryMaximumGroupCount(void) { return 1; }
uint32_t NTAPI KeQueryMaximumProcessorCountEx(uint16_t group) { return group == 0 || group == 0xffff ? 1 : 0; }
uint32_t NTAPI KeGetRecommendedSharedDataAlignment(void) { return 64; }         /* the cache line size of every supported x64 part */
uint64_t NTAPI KeIpiGenericCall(uint64_t (NTAPI *fn)(uint64_t), uint64_t ctx)
{
    /* On the single processor the broadcast is the local call, with every other interrupt
     * excluded for its duration -- the guarantee the caller relies on. */
    uint64_t f = irq_save(), r = fn(ctx);
    irq_restore(f);
    return r;
}
int8_t KeNumberProcessors = 1;                                                    /* data export (CCHAR) */
uint64_t KiBugCheckData[5];                                                       /* data export */
uint32_t InitSafeBootMode;                                                        /* data export: 0 = normal boot */
uint8_t KdDebuggerEnabled;                                                        /* data export */
uint8_t KdDebuggerNotPresent = 1;                                                 /* data export */
uint8_t NlsMbCodePageTag;                                                         /* data export: ANSI code page is single-byte */
uint8_t NlsMbOemCodePageTag;
uint8_t NTAPI KdRefreshDebuggerNotPresent(void) { return KdDebuggerNotPresent; }
#define STATUS_DEBUGGER_INACTIVE ((int32_t)0xC0000354)
NTSTATUS NTAPI KdEnableDebugger(void) { return STATUS_DEBUGGER_INACTIVE; }        /* no debugger transport is configured */
NTSTATUS NTAPI KdDisableDebugger(void) { return STATUS_DEBUGGER_INACTIVE; }
NTSTATUS NTAPI KdSystemDebugControl(uint32_t cmd, void *in, uint32_t inlen, void *out, uint32_t outlen, uint32_t *retlen, uint8_t mode)
{ (void)cmd; (void)in; (void)inlen; (void)out; (void)outlen; (void)mode; if (retlen) *retlen = 0; return STATUS_DEBUGGER_INACTIVE; }
void NTAPI DbgBreakPointWithStatus(uint32_t status) { kprintf("[drv] DbgBreakPointWithStatus(%x)\n", status); }

/* Bug-check callbacks: KBUGCHECK_CALLBACK_RECORD (x64): Entry(0) CallbackRoutine(0x10) Buffer(0x18) Length(0x20)
 * Component(0x28) Checksum(0x30) State(0x38). kpanic() runs them (ntdrv_run_bugcheck_callbacks) so a driver's
 * crash-time bookkeeping happens on a real kernel panic, as on Windows. */
typedef struct { LIST_ENTRY Entry; void (NTAPI *CallbackRoutine)(void *, uint32_t); void *Buffer; uint32_t Length; uint32_t _p;
                 const uint8_t *Component; uint64_t Checksum; uint8_t State; uint8_t _p2[7]; } KBUGCHECK_CALLBACK_RECORD;
static LIST_ENTRY bugcheck_list = { &bugcheck_list, &bugcheck_list };
uint8_t NTAPI KeRegisterBugCheckCallback(KBUGCHECK_CALLBACK_RECORD *r, void *routine, void *buffer, uint32_t len, const uint8_t *component)
{
    uint64_t f = irq_save();
    if (r->State == 1) { irq_restore(f); return 0; }                              /* BufferInserted: already registered */
    r->CallbackRoutine = routine; r->Buffer = buffer; r->Length = len; r->Component = component;
    r->Checksum = (uint64_t)routine ^ (uint64_t)buffer ^ len; r->State = 1;
    list_insert_tail(&bugcheck_list, &r->Entry);
    irq_restore(f);
    return 1;
}
uint8_t NTAPI KeDeregisterBugCheckCallback(KBUGCHECK_CALLBACK_RECORD *r)
{
    uint64_t f = irq_save();
    if (r->State != 1) { irq_restore(f); return 0; }
    r->Entry.Blink->Flink = r->Entry.Flink; r->Entry.Flink->Blink = r->Entry.Blink;
    r->State = 0;
    irq_restore(f);
    return 1;
}
void ntdrv_run_bugcheck_callbacks(void)
{
    LIST_ENTRY *e;
    for (e = bugcheck_list.Flink; e != &bugcheck_list; e = e->Flink) {
        KBUGCHECK_CALLBACK_RECORD *r = (KBUGCHECK_CALLBACK_RECORD *)e;
        if (r->State == 1) r->CallbackRoutine(r->Buffer, r->Length);
    }
}
/* Reason callbacks (KbCallbackDumpIo etc.): registered and unregistered exactly like the above; the dump they
 * feed does not exist here, so they are never invoked. */
typedef struct { LIST_ENTRY Entry; void *CallbackRoutine; const uint8_t *Component; uint64_t Checksum; uint32_t Reason; uint8_t State; uint8_t _p[3]; } KBUGCHECK_REASON_CALLBACK_RECORD;
static LIST_ENTRY bugcheck_reason_list = { &bugcheck_reason_list, &bugcheck_reason_list };
uint8_t NTAPI KeRegisterBugCheckReasonCallback(KBUGCHECK_REASON_CALLBACK_RECORD *r, void *routine, uint32_t reason, const uint8_t *component)
{
    uint64_t f = irq_save();
    if (r->State == 1) { irq_restore(f); return 0; }
    r->CallbackRoutine = routine; r->Reason = reason; r->Component = component; r->State = 1;
    list_insert_tail(&bugcheck_reason_list, &r->Entry);
    irq_restore(f);
    return 1;
}
uint8_t NTAPI KeDeregisterBugCheckReasonCallback(KBUGCHECK_REASON_CALLBACK_RECORD *r)
{
    uint64_t f = irq_save();
    if (r->State != 1) { irq_restore(f); return 0; }
    r->Entry.Blink->Flink = r->Entry.Flink; r->Entry.Flink->Blink = r->Entry.Blink;
    r->State = 0;
    irq_restore(f);
    return 1;
}

/* ================================================================ callback objects (\Callback\...) */
typedef struct callback_reg { struct callback_reg *next; struct callback_obj *obj; void (NTAPI *fn)(void *, void *, void *); void *ctx; int busy; } callback_reg_t;
typedef struct callback_obj { struct callback_obj *next; char name[64]; int allow_multiple; callback_reg_t *regs; int refs; } callback_obj_t;
static callback_obj_t *callbacks;
static kmutex_t cb_lock;
static int cb_lock_ready;
static void cb_ensure(void) { if (!cb_lock_ready) { mutex_init(&cb_lock); cb_lock_ready = 1; } }
struct objattr { uint32_t Length, pad; uint64_t RootDirectory; UNICODE_STRING *ObjectName; uint32_t Attributes, pad2; void *sd, *sqos; };
#define OBJ_OPENIF 0x80u
#define STATUS_OBJECT_NAME_COLLISION ((int32_t)0xC0000035)

NTSTATUS NTAPI ExCreateCallback(callback_obj_t **out, struct objattr *oa, uint8_t create, uint8_t allow_multiple)
{
    char name[64] = "";
    callback_obj_t *o;
    cb_ensure();
    if (oa && oa->ObjectName) ntdrv_wide_to_ascii(oa->ObjectName->Buffer, oa->ObjectName->Length / 2, name, sizeof name);
    mutex_lock(&cb_lock);
    for (o = callbacks; o; o = o->next)
        if (name[0] && !strcmp(o->name, name)) {
            if (create && !(oa->Attributes & OBJ_OPENIF)) { mutex_unlock(&cb_lock); return STATUS_OBJECT_NAME_COLLISION; }
            o->refs++; mutex_unlock(&cb_lock); *out = o; return STATUS_SUCCESS;
        }
    if (!create) { mutex_unlock(&cb_lock); return STATUS_OBJECT_NAME_NOT_FOUND; }
    o = kzalloc(sizeof *o);
    if (!o) { mutex_unlock(&cb_lock); return STATUS_INSUFFICIENT_RESOURCES; }
    memcpy(o->name, name, sizeof name);
    o->allow_multiple = allow_multiple; o->refs = 1;
    o->next = callbacks; callbacks = o;
    mutex_unlock(&cb_lock);
    *out = o;
    return STATUS_SUCCESS;
}
void *NTAPI ExRegisterCallback(callback_obj_t *o, void *fn, void *ctx)
{
    callback_reg_t *r;
    cb_ensure();
    mutex_lock(&cb_lock);
    if (!o->allow_multiple && o->regs) { mutex_unlock(&cb_lock); return 0; }
    r = kzalloc(sizeof *r);
    if (r) { r->obj = o; r->fn = fn; r->ctx = ctx; r->next = o->regs; o->regs = r; o->refs++; }
    mutex_unlock(&cb_lock);
    return r;
}
void NTAPI ExUnregisterCallback(callback_reg_t *r)
{
    callback_reg_t **pp;
    cb_ensure();
    mutex_lock(&cb_lock);
    while (r->busy) { mutex_unlock(&cb_lock); thread_sleep_ms(1); mutex_lock(&cb_lock); }   /* wait for a running notification */
    for (pp = &r->obj->regs; *pp; pp = &(*pp)->next) if (*pp == r) { *pp = r->next; break; }
    r->obj->refs--;
    mutex_unlock(&cb_lock);
    kfree(r);
}
void NTAPI ExNotifyCallback(callback_obj_t *o, void *arg1, void *arg2)
{
    callback_reg_t *r;
    cb_ensure();
    mutex_lock(&cb_lock);
    for (r = o->regs; r; r = r->next) {
        r->busy = 1;
        mutex_unlock(&cb_lock);
        r->fn(r->ctx, arg1, arg2);
        mutex_lock(&cb_lock);
        r->busy = 0;
    }
    mutex_unlock(&cb_lock);
}

/* ================================================================ rundown protection (cache-aware) */
/* EX_RUNDOWN_REF: Count/Ptr in one ULONG_PTR; bit 0 set = rundown active, else count << 1. The
 * cache-aware variant is an opaque block the caller sizes with ExSizeOfRundownProtectionCacheAware. */
typedef struct { volatile int64_t count; volatile int rundown; int _p; } rundown_t;
uint64_t NTAPI ExSizeOfRundownProtectionCacheAware(void) { return sizeof(rundown_t); }
void NTAPI ExInitializeRundownProtectionCacheAware(rundown_t *r, uint64_t size) { if (size < sizeof *r) kpanic("ExInitializeRundownProtectionCacheAware: %llu bytes", size); r->count = 0; r->rundown = 0; }
void NTAPI ExReInitializeRundownProtectionCacheAware(rundown_t *r) { r->count = 0; r->rundown = 0; }
uint8_t NTAPI ExAcquireRundownProtectionCacheAware(rundown_t *r)
{
    uint64_t f = irq_save();
    if (r->rundown) { irq_restore(f); return 0; }
    r->count++;
    irq_restore(f);
    return 1;
}
uint8_t NTAPI ExAcquireRundownProtectionCacheAwareEx(rundown_t *r, uint32_t n)
{
    uint64_t f = irq_save();
    if (r->rundown) { irq_restore(f); return 0; }
    r->count += n;
    irq_restore(f);
    return 1;
}
void NTAPI ExReleaseRundownProtectionCacheAware(rundown_t *r) { uint64_t f = irq_save(); if (r->count <= 0) { irq_restore(f); kpanic("ExReleaseRundownProtectionCacheAware underflow"); } r->count--; irq_restore(f); }
void NTAPI ExReleaseRundownProtectionCacheAwareEx(rundown_t *r, uint32_t n) { uint64_t f = irq_save(); r->count -= n; irq_restore(f); }
void NTAPI ExWaitForRundownProtectionReleaseCacheAware(rundown_t *r)
{
    r->rundown = 1;
    while (r->count > 0) thread_sleep_ms(1);
}
void NTAPI ExRundownCompletedCacheAware(rundown_t *r) { r->rundown = 1; r->count = 0; }
/* The plain EX_RUNDOWN_REF is one ULONG_PTR the driver's inline helpers touch on Windows through these exports. */
void NTAPI ExfInitializeRundownProtection(volatile uint64_t *r) { *r = 0; }
uint8_t NTAPI ExfAcquireRundownProtection(volatile uint64_t *r) { uint64_t f = irq_save(); if (*r & 1) { irq_restore(f); return 0; } *r += 2; irq_restore(f); return 1; }
void NTAPI ExfReleaseRundownProtection(volatile uint64_t *r) { uint64_t f = irq_save(); *r -= 2; irq_restore(f); }
void NTAPI ExfWaitForRundownProtectionRelease(volatile uint64_t *r) { uint64_t f = irq_save(); uint64_t c = *r; *r = 1; irq_restore(f); (void)c; }
void NTAPI ExfReInitializeRundownProtection(volatile uint64_t *r) { *r = 0; }
void NTAPI ExfRundownCompleted(volatile uint64_t *r) { *r = 1; }

/* ================================================================ processor features / accounting */
uint8_t NTAPI ExIsProcessorFeaturePresent(uint32_t feature)
{
    uint32_t a, b, c, d;
    __asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(1), "c"(0));
    switch (feature) {
    case 6:  return (d >> 25) & 1;              /* PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE) */
    case 8:  return (d >> 4) & 1;               /* PF_RDTSC_INSTRUCTION_AVAILABLE */
    case 10: return (d >> 26) & 1;              /* PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2) */
    case 13: return (c >> 0) & 1;               /* PF_SSE3_INSTRUCTIONS_AVAILABLE */
    case 14: return (c >> 13) & 1;              /* PF_COMPARE_EXCHANGE128 */
    case 12: { uint32_t ea, eb, ec, ed; __asm__ volatile("cpuid" : "=a"(ea), "=b"(eb), "=c"(ec), "=d"(ed) : "a"(0x80000001), "c"(0)); return (ed >> 20) & 1; }  /* PF_NX_ENABLED */
    case 17: return (c >> 27) & 1;              /* PF_XSAVE_ENABLED */
    case 36: return (c >> 9) & 1;               /* PF_SSSE3_INSTRUCTIONS_AVAILABLE */
    case 37: return (c >> 19) & 1;              /* PF_SSE4_1 */
    case 38: return (c >> 20) & 1;              /* PF_SSE4_2 */
    case 39: return (c >> 28) & 1;              /* PF_AVX */
    case 2: case 3: case 4: case 5: case 7: case 9: case 11: case 15: case 16: return 0;  /* MMX/3DNow/PAE/etc: not claimed */
    default: return 0;
    }
}
struct cpu_acc { uint64_t idle, busy; };
static void acc_cb(thread_t *t, void *ctx)
{
    struct cpu_acc *a = ctx;
    if (!strcmp(t->name, "idle")) a->idle += t->run_ticks; else a->busy += t->run_ticks;
}
void NTAPI ExGetCurrentProcessorCounts(uint32_t *idle, uint32_t *kernel_user, uint32_t *index)
{
    struct cpu_acc a = { 0, 0 };
    sched_for_each_thread(acc_cb, &a);
    if (idle) *idle = (uint32_t)a.idle;
    if (kernel_user) *kernel_user = (uint32_t)(a.idle + a.busy);
    if (index) *index = 0;
}
void NTAPI ExGetCurrentProcessorCpuUsage(uint32_t *usage)
{
    struct cpu_acc a = { 0, 0 };
    sched_for_each_thread(acc_cb, &a);
    *usage = a.idle + a.busy ? (uint32_t)(a.busy * 100 / (a.idle + a.busy)) : 0;
}

/* ================================================================ ExQueueWorkItem (legacy WORK_QUEUE_ITEM) */
typedef struct { LIST_ENTRY List; void (NTAPI *WorkerRoutine)(void *); void *Parameter; } WORK_QUEUE_ITEM;
extern void ntdrv_queue_system_work(void (NTAPI *fn)(void *), void *ctx, void *tag);       /* ntdrv_io.c worker thread */
void NTAPI ExQueueWorkItem(WORK_QUEUE_ITEM *w, uint32_t queue_type)
{
    (void)queue_type;
    ntdrv_queue_system_work(w->WorkerRoutine, w->Parameter, w);
}

/* ================================================================ object types (data exports) */
/* OBJECT_TYPE is opaque to drivers: they pass *IoFileObjectType etc. to ObReferenceObjectByHandle. Each descriptor
 * carries the kernel handle kind it validates against (ntdrv_zw.c). */
typedef struct { uint32_t kind; const char *name; } ntdrv_object_type_t;
static ntdrv_object_type_t type_file = { KH_FILE, "File" }, type_device = { KH_DEVICE, "Device" }, type_driver = { KH_DRIVER, "Driver" },
                           type_thread = { KH_THREAD, "Thread" }, type_process = { KH_PROCESS, "Process" }, type_event = { KH_EVENT, "Event" },
                           type_semaphore = { KH_SEMAPHORE, "Semaphore" }, type_key = { KH_KEY, "Key" }, type_dir = { KH_DIR, "Directory" };
void *IoFileObjectType = &type_file, *IoDeviceObjectType = &type_device, *IoDriverObjectType = &type_driver;
void *PsThreadType = &type_thread, *PsProcessType = &type_process, *ExEventObjectType = &type_event, *ExSemaphoreObjectType = &type_semaphore;
void *CmKeyObjectType = &type_key, *ObDirectoryObjectType = &type_dir;
int ntdrv_object_type_kind(const void *type) { return type ? (int)((const ntdrv_object_type_t *)type)->kind : KH_NONE; }

/* ================================================================ HAL dispatch tables (data exports) */
/* HAL_DISPATCH version 4 (Windows 10 x64): Version + 22 entry points. The entries that have a meaning on this
 * host are real; the others answer STATUS_NOT_IMPLEMENTED, the documented "not provided" result. */
#define STATUS_INVALID_LEVEL ((int32_t)0xC0000148)
static NTSTATUS NTAPI hal_query_system_information(uint32_t cls, uint32_t len, void *buf, uint32_t *retlen)
{ (void)cls; (void)len; (void)buf; if (retlen) *retlen = 0; return STATUS_INVALID_LEVEL; }
static NTSTATUS NTAPI hal_set_system_information(uint32_t cls, uint32_t len, void *buf) { (void)cls; (void)len; (void)buf; return STATUS_INVALID_LEVEL; }
static NTSTATUS NTAPI hal_not_implemented(void) { return STATUS_NOT_IMPLEMENTED; }
extern NTSTATUS NTAPI HalExamineMBR(DEVICE_OBJECT *, uint32_t, uint32_t, void **);
extern void *NTAPI HalGetAdapter(void *, uint32_t *);
extern void ntdrv_hal_examine_mbr_entry(void);
void *HalDispatchTable[24] = {
    (void *)4,                                   /* Version */
    (void *)hal_query_system_information,        /* HalQuerySystemInformation */
    (void *)hal_set_system_information,          /* HalSetSystemInformation */
    (void *)hal_not_implemented,                 /* HalQueryBusSlots */
    (void *)0,                                   /* Spare1 */
    (void *)HalExamineMBR,                       /* HalExamineMBR */
    (void *)hal_not_implemented,                 /* HalIoReadPartitionTable */
    (void *)hal_not_implemented,                 /* HalIoSetPartitionInformation */
    (void *)hal_not_implemented,                 /* HalIoWritePartitionTable */
    (void *)hal_not_implemented,                 /* HalReferenceHandlerForBus */
    (void *)hal_not_implemented,                 /* HalReferenceBusHandler */
    (void *)hal_not_implemented,                 /* HalDereferenceBusHandler */
    (void *)hal_not_implemented,                 /* HalInitPnpDriver */
    (void *)hal_not_implemented,                 /* HalInitPowerManagement */
    (void *)HalGetAdapter,                       /* HalGetDmaAdapter */
    (void *)hal_not_implemented,                 /* HalGetInterruptTranslator */
    (void *)hal_not_implemented,                 /* HalStartMirroring */
    (void *)hal_not_implemented,                 /* HalEndMirroring */
    (void *)hal_not_implemented,                 /* HalMirrorPhysicalMemory */
    (void *)hal_not_implemented,                 /* HalEndOfBoot */
    (void *)hal_not_implemented,                 /* HalMirrorVerify */
    (void *)hal_not_implemented,                 /* HalGetAcpiTable */
    (void *)hal_not_implemented,                 /* HalSetPciErrorHandlerCallback */
    (void *)hal_not_implemented,                 /* HalGetPrmCache */
};
#define NI (void *)hal_not_implemented
void *HalPrivateDispatchTable[32] = { (void *)8 /* Version */, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI,
                                      NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI, NI };
#undef NI
