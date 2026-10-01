/* SPDX-License-Identifier: GPL-2.0-only
 * Exact driver-host spin/IRQL bodies, with privileged CPU operations modeled.
 * Removing atomic exclusion or accepting an unmatched unlock must fail.
 */
#include <assert.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../ntddk.h"
#if __has_include("../../kcommon/pma_sync.h")
#include "../../kcommon/pma_sync.h"
#endif

#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define HIGH_LEVEL 15
#define NTDRV_DIRQL 13
static uint8_t modeled_irql;
static unsigned irq_off, cli_count, sti_count, flush_count, panics;
static jmp_buf panic_target;
static int expect_panic;
static inline uint8_t cur_irql(void) { return modeled_irql; }
static inline void write_irql(uint8_t value) { modeled_irql = value; }
#define g_irql (cur_irql())
static void cli(void) { irq_off = 1; ++cli_count; }
static void sti(void) { irq_off = 0; ++sti_count; }
static void ntdrv_dpc_queue_flush(void) { ++flush_count; }
static void kpanic(const char *format, ...) __attribute__((noreturn));
static void kpanic(const char *format, ...)
{
    (void)format;
    ++panics;
    if (expect_panic) longjmp(panic_target, 1);
    abort();
}
#include "ntdrv_spin_production.inc"

static void reset(void)
{
    modeled_irql = PASSIVE_LEVEL;
    irq_off = cli_count = sti_count = flush_count = 0;
}

static void test_basic(void)
{
    KSPIN_LOCK lock;
    uint8_t old = 99;
    reset();
    KeInitializeSpinLock(&lock);
    assert(sizeof lock == 8 && lock == 0);
    KeAcquireSpinLock(&lock, &old);
    assert(old == PASSIVE_LEVEL && modeled_irql == DISPATCH_LEVEL && lock == 1);
    assert(irq_off && cli_count == 1 && sti_count == 0 && flush_count == 0);
    KeReleaseSpinLock(&lock, old);
    assert(lock == 0 && modeled_irql == PASSIVE_LEVEL && !irq_off);
    assert(cli_count == 1 && sti_count == 1 && flush_count == 1);
}

static void test_inline_irql_and_isr(void)
{
    KSPIN_LOCK lock;
    uint8_t old;
    reset();
    KeInitializeSpinLock(&lock);
    modeled_irql = DISPATCH_LEVEL;  /* a hosted driver's inline CR8 raise */
    old = KfAcquireSpinLock(&lock);
    KfReleaseSpinLock(&lock, old);
    assert(!irq_off && !cli_count && !sti_count && !flush_count);
    irq_off = 1;
    old = ntdrv_isr_enter();
    KeAcquireSpinLockAtDpcLevel(&lock);
    KeReleaseSpinLockFromDpcLevel(&lock);
    ntdrv_isr_leave(old);
    assert(irq_off && modeled_irql == DISPATCH_LEVEL && !sti_count && !flush_count);
    reset();
    old = KeAcquireSpinLockRaiseToDpc(&lock);
    KeReleaseSpinLock(&lock, old);
    assert(!irq_off && modeled_irql == PASSIVE_LEVEL && flush_count == 1);
}

static void test_double_acquire(void)
{
    KSPIN_LOCK lock;
    reset();
    KeInitializeSpinLock(&lock);
    modeled_irql = DISPATCH_LEVEL;
    KeAcquireSpinLockAtDpcLevel(&lock);
    expect_panic = 1;
    if (!setjmp(panic_target)) {
        KeAcquireSpinLockAtDpcLevel(&lock);
        assert(!"recursive/contended UP acquisition must fail, not overwrite its owner");
    }
    expect_panic = 0;
    assert(lock == 1);
    KeReleaseSpinLockFromDpcLevel(&lock);
}

static void test_unmatched_unlock(void)
{
    KSPIN_LOCK lock;
    reset();
    KeInitializeSpinLock(&lock);
    expect_panic = 1;
    if (!setjmp(panic_target)) {
        KeReleaseSpinLockFromDpcLevel(&lock);
        assert(!"unlocking a free NT spinlock must be rejected");
    }
    expect_panic = 0;
    assert(lock == 0);
}

int main(void)
{
    test_basic();
    test_inline_irql_and_isr();
    test_double_acquire();
    test_unmatched_unlock();
    assert(panics == 2);
    puts("PASS actual NT spinlock ABI/IRQL/ISR and unmatched-ownership checks");
    return 0;
}
