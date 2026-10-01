/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_MEM_LOCK_H
#define SHZ_K64_MEM_LOCK_H
#include "k64.h"
#include "smp_boot.h"
#include "../kcommon/pma_sync.h"
/* Internal normal-context memory locks. IRQs are disabled before ticket issue,
 * preventing local interrupt/preemption reentry. No NMI use, recursion, waits,
 * callbacks, allocation delegation or context switch while held. PMM and heap
 * locks are never nested. Zero initialization is the unused-lock state. */
typedef struct __attribute__((aligned(64))) {
    pma_ticketlock_t ticket;
    uint32_t cpu_owner,held;
} shz_mem_lock_t;
typedef struct { uint64_t flags;uint32_t cpu,ticket;int valid; } shz_mem_guard_t;
static inline shz_mem_guard_t shz_mem_lock_enter(shz_mem_lock_t *lock)
{
    shz_mem_guard_t guard={0};
    guard.flags=irq_save(); /* Identity must be sampled after IRQ/preemption exclusion. */
    guard.cpu=shz_smp_this_cpu();
    if(guard.cpu>=SHZ_SMP_MAX_CPUS) { irq_restore(guard.flags);return guard; }
    KASSERT(!(__atomic_load_n(&lock->held,__ATOMIC_ACQUIRE) &&
              __atomic_load_n(&lock->cpu_owner,__ATOMIC_RELAXED)==guard.cpu));
    guard.ticket=pma_ticket_lock(&lock->ticket);
    __atomic_store_n(&lock->cpu_owner,guard.cpu,__ATOMIC_RELAXED);
    __atomic_store_n(&lock->held,1,__ATOMIC_RELEASE);guard.valid=1;
    return guard;
}
static inline void shz_mem_lock_leave(shz_mem_lock_t *lock,shz_mem_guard_t guard)
{
    KASSERT(guard.valid && shz_smp_this_cpu()==guard.cpu &&
            __atomic_load_n(&lock->held,__ATOMIC_ACQUIRE) &&
            __atomic_load_n(&lock->cpu_owner,__ATOMIC_RELAXED)==guard.cpu);
    __atomic_store_n(&lock->held,0,__ATOMIC_RELEASE);
    KASSERT(pma_ticket_unlock(&lock->ticket,guard.ticket));
    irq_restore(guard.flags);
}
#endif
