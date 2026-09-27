/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the independent NTWrapper9x object/event core at actual CPL 0.
 * This single-CPU harness supplies local IRQ exclusion, not an SMP lock.
 */
#include "../../ntwrapper/include/ntwrapper.h"

static uintptr_t irq_enter(void *opaque)
{
    uintptr_t flags;
    (void)opaque;
    __asm__ volatile("pushfq; popq %0; cli" : "=r"(flags) :: "memory");
    return flags;
}

static void irq_leave(void *opaque, uintptr_t flags)
{
    (void)opaque;
    __asm__ volatile("pushq %0; popfq" :: "r"(flags) : "memory", "cc");
}

int sd_kernel_probe(void)
{
    uint16_t cs;
    struct ntw_context context;
    struct ntw_lock_ops locks = {irq_enter, irq_leave, 0};
    struct ntw_lease lease = {0};
    ntw_handle event = 0;
    int previous = -1;
    __asm__ volatile("mov %%cs, %0" : "=r"(cs));
    if ((cs & 3) != 0) return 0;
    if (ntw_initialize(&context, &locks) != NTW_OK) return 0;
    if (ntw_event_create(&context, 0, 0, NTW_EVENT_ALL, &event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_event_set(&context, event, &previous) != NTW_OK || previous != 0) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_reference(&context, event, NTW_EVENT_QUERY, &lease) != NTW_OK) return 0;
    if (ntw_close(&context, event) != NTW_OK) return 0;
    if (ntw_event_query(&context, event, &previous) != NTW_BAD_HANDLE) return 0;
    if (ntw_shutdown(&context) != NTW_BUSY) return 0;
    if (ntw_dereference(&lease) != NTW_OK) return 0;
    if (ntw_event_create(&context, 1, 1, NTW_EVENT_ALL, &event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_OK) return 0;
    if (ntw_event_reset(&context, event, &previous) != NTW_OK || previous != 1) return 0;
    if (ntw_event_try_wait(&context, event) != NTW_PENDING) return 0;
    if (ntw_close(&context, event) != NTW_OK) return 0;
    return ntw_shutdown(&context) == NTW_OK;
}
