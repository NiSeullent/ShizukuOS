/* SPDX-License-Identifier: GPL-2.0-only
 * Native exclusion/publication, FIFO admission, wrap and invalid-release tests.
 * Removing acquire/release ordering, making trylock barge or dropping atomic
 * RMW exclusion breaks these checks. No guest/SMP scheduler is modeled here.
 */
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "../kcommon/pma_sync.h"

#define WORKERS 8
#ifdef PMA_SYNC_TSAN_SMALL
#define STRESS_WORKERS 2
#define ITERATIONS 500
#define EXPECTED_PUBLICATIONS 1000
#else
#define STRESS_WORKERS 4
#define ITERATIONS 5000
#define EXPECTED_PUBLICATIONS 20000
#endif
static pma_ticketlock_t fair;
static uintptr_t binary;
static uint64_t counter, payload, published;
static unsigned order[WORKERS], used;
static uint32_t initial_ticket;

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void *fifo_worker(void *arg)
{
    uint32_t ticket = pma_ticket_lock(&fair);
    assert(used < WORKERS);
    order[used++] = (unsigned)(uintptr_t)arg;
    assert(pma_ticket_unlock(&fair, ticket));
    return NULL;
}

static void test_fifo(uint32_t start)
{
    pthread_t workers[WORKERS];
    unsigned i;
    uint32_t ticket, sentinel = 0x12345678;
    pma_ticket_init(&fair);
    /* A cold lock near rollover: no live reader is present during setup. */
    fair.next = fair.owner = start;
    assert(!pma_ticket_unlock(&fair, start));
    assert(fair.next == start && fair.owner == start);
    initial_ticket = pma_ticket_lock(&fair);
    assert(initial_ticket == start);
    used = 0;
    assert(!pma_ticket_trylock(&fair, &sentinel) && sentinel == 0x12345678);
    assert(!pma_ticket_unlock(&fair, initial_ticket + 1));
    for (i = 0; i < WORKERS; ++i) {
        uint64_t deadline = monotonic_ms() + 10000;
        assert(pthread_create(&workers[i], NULL, fifo_worker, (void *)(uintptr_t)i) == 0);
        while (__atomic_load_n(&fair.next, __ATOMIC_RELAXED) != (uint32_t)(start + i + 2)) {
            assert(monotonic_ms() < deadline);
            sched_yield();
        }
        assert(!pma_ticket_trylock(&fair, &sentinel));
    }
    assert(pma_ticket_unlock(&fair, initial_ticket));
    for (i = 0; i < WORKERS; ++i) assert(pthread_join(workers[i], NULL) == 0);
    assert(used == WORKERS);
    for (i = 0; i < WORKERS; ++i) assert(order[i] == i);
    assert(pma_ticket_trylock(&fair, &ticket));
    assert(ticket == (uint32_t)(start + WORKERS + 1));
    assert(pma_ticket_unlock(&fair, ticket));
    assert(!pma_ticket_unlock(&fair, ticket));
}

static void *stress_worker(void *arg)
{
    unsigned i;
    int use_binary = (int)(uintptr_t)arg;
    for (i = 0; i < ITERATIONS; ++i) {
        uint32_t ticket = 0;
        if (use_binary) {
            while (!pma_word_try_lock(&binary)) sched_yield();
        } else {
            ticket = pma_ticket_lock(&fair);
        }
        /* These shared values are deliberately non-atomic. The lock must
         * publish each predecessor's writes and exclude every other worker. */
        assert(payload == (published ^ UINT64_C(0xfedcba9876543210)));
        ++counter;
        ++published;
        payload = published ^ UINT64_C(0xfedcba9876543210);
        if (use_binary) assert(pma_word_unlock(&binary));
        else assert(pma_ticket_unlock(&fair, ticket));
        /* Perturb admission after release; yielding while held violates the
         * spinlock contract and creates artificial same-CPU owner starvation. */
        if ((i & 127) == 0) sched_yield();
    }
    return NULL;
}

static void test_stress(int use_binary)
{
    pthread_t workers[STRESS_WORKERS];
    unsigned i;
    pma_ticket_init(&fair);
    pma_word_init(&binary);
    counter = published = 0;
    payload = UINT64_C(0xfedcba9876543210);
    for (i = 0; i < STRESS_WORKERS; ++i)
        assert(pthread_create(&workers[i], NULL, stress_worker, (void *)(uintptr_t)use_binary) == 0);
    for (i = 0; i < STRESS_WORKERS; ++i) assert(pthread_join(workers[i], NULL) == 0);
    assert(counter == EXPECTED_PUBLICATIONS && published == EXPECTED_PUBLICATIONS);
    assert(payload == ((uint64_t)EXPECTED_PUBLICATIONS ^ UINT64_C(0xfedcba9876543210)));
}

static void test_word(void)
{
    pma_word_init(&binary);
    assert(!pma_word_unlock(&binary));
    assert(pma_word_try_lock(&binary));
    assert(!pma_word_try_lock(&binary));
    assert(binary == 1 && pma_word_unlock(&binary));
    assert(!pma_word_unlock(&binary));
    binary = 2;  /* a corrupt state must not be silently cleared */
    assert(!pma_word_try_lock(&binary) && !pma_word_unlock(&binary) && binary == 2);
}

int main(void)
{
    test_word();
    test_fifo(0);
    test_fifo(UINT32_MAX - 2);
    test_stress(0);
    test_stress(1);
    printf("PASS PMA FIFO/wraparound/non-barging/invalid-release and %u synchronized publications\n",
           2 * EXPECTED_PUBLICATIONS);
    return 0;
}
