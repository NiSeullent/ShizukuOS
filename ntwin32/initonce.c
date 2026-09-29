/* SPDX-License-Identifier: GPL-2.0-only
 * Original atomic state machine; no external implementation was copied.
 */
#include "initonce.h"
#include <stddef.h>

/* Low bits are project-private states; complete stores the aligned context.
 * The pending states contain no allocated waiter pointers or global registry. */
#define ONCE_EMPTY ((uintptr_t)0)
#define ONCE_SYNC ((uintptr_t)1)
#define ONCE_DONE ((uintptr_t)2)
#define ONCE_ASYNC ((uintptr_t)3)
#define ONCE_MASK ((uintptr_t)3)

static int valid_once(const ntw_once *once)
{
    return once != NULL && (uintptr_t)once % _Alignof(ntw_once) == 0;
}

int ntw_once_init(ntw_once *once)
{
    if (!valid_once(once)) return NTW_ONCE_INVALID;
    __atomic_store_n(&once->state, ONCE_EMPTY, __ATOMIC_RELAXED);
    return NTW_ONCE_OK;
}

int ntw_once_begin(ntw_once *once, uint32_t flags, int *pending, void **context,
                   ntw_once_yield_fn yield)
{
    uintptr_t state;
    if (!valid_once(once) || pending == NULL ||
        (flags & ~(NTW_ONCE_CHECK_ONLY | NTW_ONCE_ASYNC)) != 0 ||
        flags == (NTW_ONCE_CHECK_ONLY | NTW_ONCE_ASYNC))
        return NTW_ONCE_INVALID;
    for (;;) {
        state = __atomic_load_n(&once->state, __ATOMIC_ACQUIRE);
        if ((state & ONCE_MASK) == ONCE_DONE) {
            if (context != NULL) *context = (void *)(state & ~ONCE_MASK);
            *pending = 0;
            return NTW_ONCE_OK;
        }
        if ((flags & NTW_ONCE_CHECK_ONLY) != 0) return NTW_ONCE_NOT_READY;
        if (state == ONCE_EMPTY) {
            uintptr_t desired = (flags & NTW_ONCE_ASYNC) != 0 ? ONCE_ASYNC : ONCE_SYNC;
            if (__atomic_compare_exchange_n(&once->state, &state, desired, 0,
                                             __ATOMIC_ACQUIRE, __ATOMIC_RELAXED)) {
                *pending = 1;
                return NTW_ONCE_OK;
            }
        } else if (state == ONCE_ASYNC) {
            if ((flags & NTW_ONCE_ASYNC) == 0) return NTW_ONCE_CONFLICT;
            *pending = 1;
            return NTW_ONCE_OK;
        } else if (state == ONCE_SYNC) {
            if ((flags & NTW_ONCE_ASYNC) != 0) return NTW_ONCE_CONFLICT;
            if (yield == NULL) return NTW_ONCE_INVALID;
            yield();
        } else {
            /* Only possible after direct corruption of opaque storage. */
            return NTW_ONCE_INVALID;
        }
    }
}

int ntw_once_complete(ntw_once *once, uint32_t flags, void *context)
{
    uintptr_t expected, desired;
    if (!valid_once(once) || (flags & ~(NTW_ONCE_ASYNC | NTW_ONCE_INIT_FAILED)) != 0 ||
        flags == (NTW_ONCE_ASYNC | NTW_ONCE_INIT_FAILED) ||
        ((uintptr_t)context & ONCE_MASK) != 0 ||
        ((flags & NTW_ONCE_INIT_FAILED) != 0 && context != NULL))
        return NTW_ONCE_INVALID;
    expected = (flags & NTW_ONCE_ASYNC) != 0 ? ONCE_ASYNC : ONCE_SYNC;
    desired = (flags & NTW_ONCE_INIT_FAILED) != 0 ? ONCE_EMPTY :
               ((uintptr_t)context | ONCE_DONE);
    if (!__atomic_compare_exchange_n(&once->state, &expected, desired, 0,
                                      __ATOMIC_RELEASE, __ATOMIC_RELAXED))
        return NTW_ONCE_CONFLICT;
    return NTW_ONCE_OK;
}

int ntw_once_execute(ntw_once *once, ntw_once_callback callback, void *parameter,
                     void **context, ntw_once_yield_fn yield)
{
    int pending, status;
    void *published;
    if (callback == NULL) return NTW_ONCE_INVALID;
    status = ntw_once_begin(once, 0, &pending, context, yield);
    if (status != NTW_ONCE_OK || pending == 0) return status;
    if (!callback(once, parameter, context)) {
        status = ntw_once_complete(once, NTW_ONCE_INIT_FAILED, NULL);
        return status == NTW_ONCE_OK ? NTW_ONCE_CALLBACK_FAILED : status;
    }
    published = context != NULL ? *context : NULL;
    status = ntw_once_complete(once, 0, published);
    if (status == NTW_ONCE_INVALID) {
        /* Misaligned callback context is invalid use; still unblock waiters. */
        (void)ntw_once_complete(once, NTW_ONCE_INIT_FAILED, NULL);
    }
    return status;
}
