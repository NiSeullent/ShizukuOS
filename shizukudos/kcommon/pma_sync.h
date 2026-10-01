/* SPDX-License-Identifier: GPL-2.0-only
 * Shared native-backend spin primitives, independent of Windows/VMM scheduling.
 *
 * Ticket admission is FIFO; unsigned 32-bit counters wrap naturally. Fewer than
 * 2^32 outstanding tickets are required, and an issued ticket cannot be canceled.
 * The returned ticket is the release token: invalid or repeated release fails.
 * A trylock never joins or bypasses the ticket queue and leaves *ticket unchanged
 * on failure. Initialization requires exclusive access to an unused lock.
 *
 * CALLER CONTRACT: prevent same-CPU preemption or interrupt reentry by another
 * user of this lock before acquisition. Never sleep, block, call DOS/VMM, or take
 * a blocking lock while held. Restore the caller's IRQ/preemption state only
 * after release. These helpers themselves do not change IRQs, IRQL or affinity.
 * Use the existing domain/kernel scheduler rules; this header does not enable SMP.
 *
 * Native ticket locks are not KSPIN_LOCK ABI storage. The binary word helpers
 * preserve that pointer-sized 0/1 contract, with acquire/release publication.
 * They validate held state, not a CPU/thread identity. The current UP NT host
 * rejects contention instead of spinning behind a same-CPU nonpreemptible owner.
 */
#ifndef SHZ_PMA_SYNC_H
#define SHZ_PMA_SYNC_H
#include <stdint.h>

typedef struct { uint32_t next, owner; } pma_ticketlock_t;

/* These targets must emit CPU atomics, never an out-of-line libatomic call. */
_Static_assert(__atomic_always_lock_free(sizeof(uint32_t), 0), "PMA needs lock-free 32-bit atomics");
_Static_assert(__atomic_always_lock_free(sizeof(uintptr_t), 0), "PMA needs lock-free native-word atomics");

static inline void pma_spin_pause(void)
{
    /* REP NOP is safe on the i486 baseline and PAUSE on newer x86 CPUs. */
    __asm__ volatile("rep; nop" ::: "memory");
}

static inline void pma_ticket_init(pma_ticketlock_t *lock)
{
    __atomic_store_n(&lock->next, 0, __ATOMIC_RELAXED);
    __atomic_store_n(&lock->owner, 0, __ATOMIC_RELAXED);
}

static inline uint32_t pma_ticket_lock(pma_ticketlock_t *lock)
{
    const uint32_t ticket = __atomic_fetch_add(&lock->next, 1, __ATOMIC_RELAXED);
    while (__atomic_load_n(&lock->owner, __ATOMIC_ACQUIRE) != ticket)
        pma_spin_pause();
    return ticket;
}

static inline int pma_ticket_trylock(pma_ticketlock_t *lock, uint32_t *ticket)
{
    uint32_t owner = __atomic_load_n(&lock->owner, __ATOMIC_ACQUIRE);
    uint32_t expected = owner;
    if (!__atomic_compare_exchange_n(&lock->next, &expected, owner + 1u, 0,
                                     __ATOMIC_RELAXED, __ATOMIC_RELAXED))
        return 0;
    *ticket = owner;
    return 1;
}

static inline int pma_ticket_unlock(pma_ticketlock_t *lock, uint32_t ticket)
{
    /* owner == next means no acquisition was issued, including at wraparound.
     * Reject that token before advancing owner and stranding the next caller. */
    if (__atomic_load_n(&lock->next, __ATOMIC_RELAXED) == ticket)
        return 0;
    return __atomic_compare_exchange_n(&lock->owner, &ticket, ticket + 1u, 0,
                                        __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}

static inline void pma_word_init(uintptr_t *word)
{
    __atomic_store_n(word, 0, __ATOMIC_RELAXED);
}

static inline int pma_word_try_lock(uintptr_t *word)
{
    uintptr_t expected = 0;
    return __atomic_compare_exchange_n(word, &expected, 1, 0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
}

static inline int pma_word_unlock(uintptr_t *word)
{
    uintptr_t expected = 1;
    return __atomic_compare_exchange_n(word, &expected, 0, 0, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
#endif
