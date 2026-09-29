/* SPDX-License-Identifier: GPL-2.0-only
 * Original host tests. These exercise actual pthread contention and publication,
 * not Windows loader/SEH behavior or guest execution.
 */
#define _POSIX_C_SOURCE 200809L
#include "../initonce.h"
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

_Static_assert(sizeof(ntw_once) == sizeof(void *), "INIT_ONCE pointer-size ABI");
_Static_assert(_Alignof(ntw_once) == _Alignof(void *), "INIT_ONCE alignment ABI");

static unsigned long checks;
static unsigned long yield_count;
#define CHECK(expression) do { \
    (void)__atomic_add_fetch(&checks, 1ul, __ATOMIC_RELAXED); \
    if (!(expression)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #expression); \
        exit(1); \
    } \
} while (0)

static void host_yield(void)
{
    (void)__atomic_add_fetch(&yield_count, 1ul, __ATOMIC_RELAXED);
    (void)sched_yield();
}

static void barrier(pthread_barrier_t *b)
{
    int result = pthread_barrier_wait(b);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void check_only(ntw_once *once, int expected, void *expected_context)
{
    void *context = (void *)(uintptr_t)0x1000;
    int pending = 73;
    CHECK(ntw_once_begin(once, NTW_ONCE_CHECK_ONLY, &pending, &context, NULL) == expected);
    if (expected == NTW_ONCE_OK) {
        CHECK(pending == 0 && context == expected_context);
    } else {
        CHECK(pending == 73 && context == (void *)(uintptr_t)0x1000);
    }
}

static void basic_contracts(void)
{
    ntw_once once = NTW_ONCE_STATIC_INIT;
    _Alignas(4) uint32_t payload[2] = { 123, 456 };
    void *context = (void *)(uintptr_t)0x1000;
    int pending = 73;
    CHECK(once.state == 0);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    CHECK(ntw_once_complete(&once, 0, payload) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_begin(&once, 0, &pending, &context, NULL) == NTW_ONCE_OK);
    CHECK(pending == 1 && context == (void *)(uintptr_t)0x1000);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    CHECK(ntw_once_complete(&once, NTW_ONCE_ASYNC, payload) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_complete(&once, 0, payload) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_OK, payload);
    CHECK(ntw_once_begin(&once, 0, &pending, &context, NULL) == NTW_ONCE_OK);
    CHECK(pending == 0 && context == payload);
    CHECK(ntw_once_complete(&once, 0, payload) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_complete(&once, NTW_ONCE_INIT_FAILED, NULL) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    CHECK(once.state == 0);
    CHECK(ntw_once_begin(&once, 0, &pending, NULL, NULL) == NTW_ONCE_OK && pending == 1);
    CHECK(ntw_once_complete(&once, NTW_ONCE_INIT_FAILED, NULL) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    CHECK(ntw_once_begin(&once, 0, &pending, NULL, NULL) == NTW_ONCE_OK && pending == 1);
    CHECK(ntw_once_complete(&once, 0, NULL) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_OK, NULL);
    CHECK(ntw_once_begin(&once, 0, &pending, NULL, NULL) == NTW_ONCE_OK && pending == 0);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    CHECK(ntw_once_begin(&once, NTW_ONCE_ASYNC, &pending, NULL, NULL) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    CHECK(ntw_once_begin(&once, 0, &pending, &context, host_yield) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_complete(&once, 0, payload) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_complete(&once, NTW_ONCE_INIT_FAILED, NULL) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_begin(&once, NTW_ONCE_ASYNC, &pending, NULL, NULL) == NTW_ONCE_OK);
    CHECK(pending == 1);
    CHECK(ntw_once_complete(&once, NTW_ONCE_ASYNC, payload) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_OK, payload);
    CHECK(ntw_once_begin(&once, NTW_ONCE_ASYNC, &pending, &context, NULL) == NTW_ONCE_OK);
    CHECK(pending == 0 && context == payload);
    CHECK(ntw_once_begin(&once, 0, &pending, &context, NULL) == NTW_ONCE_OK);
    CHECK(pending == 0 && context == payload);
    CHECK(ntw_once_complete(&once, NTW_ONCE_ASYNC, payload) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    CHECK(ntw_once_begin(&once, 0, &pending, NULL, NULL) == NTW_ONCE_OK);
    context = (void *)(UINTPTR_MAX & ~(uintptr_t)3);
    CHECK(ntw_once_complete(&once, 0, context) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_OK, context); /* No truncation on 64-bit host. */
}

static int should_not_run(ntw_once *once, void *parameter, void **context)
{
    (void)once; (void)parameter; (void)context;
    CHECK(0);
    return 0;
}

static void invalid_inputs(void)
{
    static const uint32_t bad_begin[] = { 3, 4, 5, 6, 7, 8, UINT32_MAX };
    static const uint32_t bad_complete[] = { 1, 3, 5, 6, 7, 8, UINT32_MAX };
    ntw_once once = NTW_ONCE_STATIC_INIT;
    _Alignas(ntw_once) unsigned char unaligned[sizeof(ntw_once) + 1];
    ntw_once *bad = (ntw_once *)(void *)(unaligned + 1);
    int pending = 73;
    void *context = (void *)(uintptr_t)0x1000;
    size_t i;
    CHECK(ntw_once_init(NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_init(bad) == NTW_ONCE_INVALID);
    CHECK(ntw_once_begin(NULL, 0, &pending, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_begin(bad, 0, &pending, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_begin(&once, 0, NULL, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_complete(NULL, 0, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_complete(bad, 0, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_execute(&once, NULL, NULL, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(ntw_once_execute(NULL, should_not_run, NULL, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(pending == 73 && context == (void *)(uintptr_t)0x1000 && once.state == 0);
    for (i = 0; i < sizeof(bad_begin) / sizeof(bad_begin[0]); ++i) {
        CHECK(ntw_once_begin(&once, bad_begin[i], &pending, &context, NULL) == NTW_ONCE_INVALID);
        CHECK(pending == 73 && context == (void *)(uintptr_t)0x1000 && once.state == 0);
    }
    CHECK(ntw_once_begin(&once, 0, &pending, &context, NULL) == NTW_ONCE_OK);
    for (i = 0; i < sizeof(bad_complete) / sizeof(bad_complete[0]); ++i) {
        CHECK(ntw_once_complete(&once, bad_complete[i], NULL) == NTW_ONCE_INVALID);
        check_only(&once, NTW_ONCE_NOT_READY, NULL);
    }
    for (i = 1; i < 4; ++i)
        CHECK(ntw_once_complete(&once, 0, (void *)((uintptr_t)0x1000 + i)) == NTW_ONCE_INVALID);
    CHECK(ntw_once_complete(&once, NTW_ONCE_INIT_FAILED, (void *)(uintptr_t)0x1000) == NTW_ONCE_INVALID);
    pending = 73;
    CHECK(ntw_once_begin(&once, NTW_ONCE_ASYNC, &pending, &context, NULL) == NTW_ONCE_CONFLICT);
    CHECK(ntw_once_begin(&once, 0, &pending, &context, NULL) == NTW_ONCE_INVALID);
    CHECK(pending == 73 && context == (void *)(uintptr_t)0x1000);
    CHECK(ntw_once_complete(&once, NTW_ONCE_INIT_FAILED, NULL) == NTW_ONCE_OK);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
}

typedef struct callback_data {
    ntw_once *expected_once;
    void **expected_context_argument;
    void *publish;
    unsigned calls;
    int result;
} callback_data;

static int callback_contract(ntw_once *once, void *parameter, void **context)
{
    callback_data *data = (callback_data *)parameter;
    CHECK(once == data->expected_once && context == data->expected_context_argument);
    check_only(once, NTW_ONCE_NOT_READY, NULL); /* Safe query from initializer. */
    ++data->calls;
    if (context != NULL) *context = data->publish;
    return data->result;
}

static void execute_contracts(void)
{
    ntw_once once = NTW_ONCE_STATIC_INIT;
    void *context = NULL;
    callback_data data = { &once, &context, (void *)(uintptr_t)0x1000, 0, 0 };
    CHECK(ntw_once_execute(&once, callback_contract, &data, &context, host_yield) == NTW_ONCE_CALLBACK_FAILED);
    CHECK(data.calls == 1 && context == data.publish);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    data.result = 1;
    CHECK(ntw_once_execute(&once, callback_contract, &data, &context, host_yield) == NTW_ONCE_OK);
    CHECK(data.calls == 2 && context == data.publish);
    context = NULL;
    CHECK(ntw_once_execute(&once, should_not_run, NULL, &context, NULL) == NTW_ONCE_OK);
    CHECK(context == data.publish);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    data.expected_context_argument = NULL;
    CHECK(ntw_once_execute(&once, callback_contract, &data, NULL, NULL) == NTW_ONCE_OK);
    CHECK(data.calls == 3);
    check_only(&once, NTW_ONCE_OK, NULL);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    data.expected_context_argument = &context;
    data.publish = (void *)(uintptr_t)0x1001;
    CHECK(ntw_once_execute(&once, callback_contract, &data, &context, NULL) == NTW_ONCE_INVALID);
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    data.publish = (void *)(uintptr_t)0x1000;
    CHECK(ntw_once_execute(&once, callback_contract, &data, &context, NULL) == NTW_ONCE_OK);
    CHECK(data.calls == 5);
    CHECK(ntw_once_init(&once) == NTW_ONCE_OK);
    {
        int pending;
        CHECK(ntw_once_begin(&once, NTW_ONCE_ASYNC, &pending, NULL, NULL) == NTW_ONCE_OK);
        CHECK(ntw_once_execute(&once, should_not_run, NULL, &context, NULL) == NTW_ONCE_CONFLICT);
        CHECK(ntw_once_complete(&once, NTW_ONCE_ASYNC, NULL) == NTW_ONCE_OK);
    }
}

#define THREADS 8u
typedef struct concurrent {
    ntw_once once;
    pthread_barrier_t start;
    unsigned calls;
    unsigned active;
    unsigned failures_before_success;
    _Alignas(4) uint32_t payload[16];
} concurrent;

typedef struct execute_argument {
    concurrent *shared;
    int status;
} execute_argument;

static int concurrent_callback(ntw_once *once, void *parameter, void **context)
{
    concurrent *shared = (concurrent *)parameter;
    unsigned call = __atomic_add_fetch(&shared->calls, 1u, __ATOMIC_RELAXED);
    unsigned i;
    CHECK(once == &shared->once);
    CHECK(__atomic_add_fetch(&shared->active, 1u, __ATOMIC_RELAXED) == 1);
    for (i = 0; i < 128; ++i) host_yield();
    if (call <= shared->failures_before_success) {
        CHECK(__atomic_sub_fetch(&shared->active, 1u, __ATOMIC_RELAXED) == 0);
        return 0;
    }
    for (i = 0; i < 16; ++i) shared->payload[i] = UINT32_C(0xbeef0000) + i;
    *context = shared->payload;
    CHECK(__atomic_sub_fetch(&shared->active, 1u, __ATOMIC_RELAXED) == 0);
    return 1;
}

static void *execute_thread(void *parameter)
{
    execute_argument *argument = (execute_argument *)parameter;
    concurrent *shared = argument->shared;
    void *context = NULL;
    unsigned i;
    barrier(&shared->start);
    argument->status = ntw_once_execute(&shared->once, concurrent_callback, shared,
                                        &context, host_yield);
    if (argument->status == NTW_ONCE_OK) {
        CHECK(context == shared->payload);
        /* Plain reads intentionally depend on the once acquire/release pair. */
        for (i = 0; i < 16; ++i) CHECK(shared->payload[i] == UINT32_C(0xbeef0000) + i);
    } else CHECK(argument->status == NTW_ONCE_CALLBACK_FAILED);
    return NULL;
}

static void concurrent_execute(unsigned failures)
{
    concurrent shared = { .once = NTW_ONCE_STATIC_INIT, .failures_before_success = failures };
    pthread_t threads[THREADS];
    execute_argument arguments[THREADS];
    unsigned i, failed = 0;
    CHECK(pthread_barrier_init(&shared.start, NULL, THREADS + 1) == 0);
    for (i = 0; i < THREADS; ++i) {
        arguments[i].shared = &shared;
        arguments[i].status = 99;
        CHECK(pthread_create(&threads[i], NULL, execute_thread, &arguments[i]) == 0);
    }
    barrier(&shared.start);
    for (i = 0; i < THREADS; ++i) {
        CHECK(pthread_join(threads[i], NULL) == 0);
        if (arguments[i].status == NTW_ONCE_CALLBACK_FAILED) ++failed;
    }
    CHECK(failed == failures && shared.calls == failures + 1 && shared.active == 0);
    check_only(&shared.once, NTW_ONCE_OK, shared.payload);
    CHECK(pthread_barrier_destroy(&shared.start) == 0);
}

typedef struct waiter_argument {
    ntw_once *once;
    int pending;
    void *context;
} waiter_argument;

static void *waiter_thread(void *parameter)
{
    waiter_argument *argument = (waiter_argument *)parameter;
    CHECK(ntw_once_begin(argument->once, 0, &argument->pending,
                         &argument->context, host_yield) == NTW_ONCE_OK);
    if (argument->pending) {
        argument->context = (void *)(uintptr_t)0x2000;
        CHECK(ntw_once_complete(argument->once, 0, argument->context) == NTW_ONCE_OK);
    }
    return NULL;
}

static void synchronous_wait(int fail_first)
{
    ntw_once once = NTW_ONCE_STATIC_INIT;
    waiter_argument argument = { &once, 73, NULL };
    pthread_t thread;
    int pending;
    unsigned long before = __atomic_load_n(&yield_count, __ATOMIC_RELAXED);
    CHECK(ntw_once_begin(&once, 0, &pending, NULL, NULL) == NTW_ONCE_OK && pending == 1);
    CHECK(pthread_create(&thread, NULL, waiter_thread, &argument) == 0);
    while (__atomic_load_n(&yield_count, __ATOMIC_RELAXED) < before + 16) (void)sched_yield();
    check_only(&once, NTW_ONCE_NOT_READY, NULL);
    CHECK(ntw_once_complete(&once, fail_first ? NTW_ONCE_INIT_FAILED : 0,
                            fail_first ? NULL : (void *)(uintptr_t)0x1000) == NTW_ONCE_OK);
    CHECK(pthread_join(thread, NULL) == 0);
    CHECK(argument.pending == fail_first);
    CHECK(argument.context == (void *)(uintptr_t)(fail_first ? 0x2000 : 0x1000));
    check_only(&once, NTW_ONCE_OK, argument.context);
}

typedef struct async_shared {
    ntw_once once;
    pthread_barrier_t ready;
} async_shared;

typedef struct async_argument {
    async_shared *shared;
    _Alignas(4) uint32_t payload[16];
    unsigned number;
    int won;
    void *winner;
} async_argument;

static void *async_thread(void *parameter)
{
    async_argument *argument = (async_argument *)parameter;
    unsigned i;
    int pending = 73, status;
    CHECK(ntw_once_begin(&argument->shared->once, NTW_ONCE_ASYNC,
                         &pending, NULL, NULL) == NTW_ONCE_OK && pending == 1);
    for (i = 0; i < 16; ++i) argument->payload[i] = argument->number * 100 + i;
    barrier(&argument->shared->ready); /* Every attempt starts before any finishes. */
    status = ntw_once_complete(&argument->shared->once, NTW_ONCE_ASYNC, argument->payload);
    CHECK(status == NTW_ONCE_OK || status == NTW_ONCE_CONFLICT);
    argument->won = status == NTW_ONCE_OK;
    CHECK(ntw_once_begin(&argument->shared->once, NTW_ONCE_CHECK_ONLY,
                         &pending, &argument->winner, NULL) == NTW_ONCE_OK && pending == 0);
    return NULL;
}

static void asynchronous_competition(void)
{
    async_shared shared = { .once = NTW_ONCE_STATIC_INIT };
    async_argument arguments[THREADS];
    pthread_t threads[THREADS];
    unsigned i, j, winners = 0;
    void *winner = NULL;
    CHECK(pthread_barrier_init(&shared.ready, NULL, THREADS) == 0);
    for (i = 0; i < THREADS; ++i) {
        arguments[i].shared = &shared;
        arguments[i].number = i + 1;
        CHECK(pthread_create(&threads[i], NULL, async_thread, &arguments[i]) == 0);
    }
    for (i = 0; i < THREADS; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    for (i = 0; i < THREADS; ++i) {
        if (arguments[i].won) {
            ++winners;
            winner = arguments[i].payload;
        }
    }
    CHECK(winners == 1 && winner != NULL);
    for (i = 0; i < THREADS; ++i) {
        uint32_t *published = (uint32_t *)arguments[i].winner;
        CHECK(arguments[i].winner == winner);
        for (j = 1; j < 16; ++j) CHECK(published[j] == published[0] + j);
        if (!arguments[i].won) {
            /* The loser owns its candidate and may discard it after failure. */
            for (j = 0; j < 16; ++j) arguments[i].payload[j] = 0;
        }
    }
    check_only(&shared.once, NTW_ONCE_OK, winner);
    CHECK(pthread_barrier_destroy(&shared.ready) == 0);
}

static jmp_buf reentry_escape;
static ntw_once reentry_once = NTW_ONCE_STATIC_INIT;
static unsigned reentry_yields;

static void bounded_reentry_yield(void)
{
    ++reentry_yields;
    if (reentry_yields == 8) longjmp(reentry_escape, 1);
}

static void reentry_is_not_success(void)
{
    int pending = 73;
    CHECK(ntw_once_begin(&reentry_once, 0, &pending, NULL, NULL) == NTW_ONCE_OK);
    if (setjmp(reentry_escape) == 0) {
        (void)ntw_once_begin(&reentry_once, 0, &pending, NULL, bounded_reentry_yield);
        CHECK(0); /* A same-thread synchronous begin must not falsely succeed. */
    }
    CHECK(reentry_yields == 8);
    CHECK(ntw_once_complete(&reentry_once, 0, NULL) == NTW_ONCE_OK);
    check_only(&reentry_once, NTW_ONCE_OK, NULL);
}

int main(void)
{
    unsigned iteration;
    (void)alarm(45); /* Broken waits fail the process instead of hanging CI. */
    basic_contracts();
    invalid_inputs();
    execute_contracts();
    synchronous_wait(0);
    synchronous_wait(1);
    reentry_is_not_success();
    for (iteration = 0; iteration < 24; ++iteration) {
        concurrent_execute(0);
        concurrent_execute(3);
        asynchronous_competition();
    }
    (void)alarm(0);
    printf("InitOnce: %lu checks passed; 72 eight-thread contention rounds; host only.\n",
            __atomic_load_n(&checks, __ATOMIC_RELAXED));
    return 0;
}
