/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWin32Wrapper9x one-time initialization; see INITONCE.md.
 */
#ifndef NTW_INITONCE_H
#define NTW_INITONCE_H
#include <stdint.h>

/* Pointer-sized and pointer-aligned, initially all zero. Opaque to callers. */
typedef struct { volatile uintptr_t state; } ntw_once;
#define NTW_ONCE_STATIC_INIT { 0 }
#define NTW_ONCE_CHECK_ONLY UINT32_C(1)
#define NTW_ONCE_ASYNC UINT32_C(2)
#define NTW_ONCE_INIT_FAILED UINT32_C(4)
#define NTW_ONCE_CONTEXT_RESERVED_BITS 2u

enum ntw_once_status {
    NTW_ONCE_OK = 0,
    NTW_ONCE_NOT_READY = -1,
    NTW_ONCE_INVALID = -2,
    NTW_ONCE_CONFLICT = -3,
    NTW_ONCE_CALLBACK_FAILED = -4
};

typedef void (*ntw_once_yield_fn)(void);
/* Native C calling convention. A Win32 WINAPI callback needs an adapter. */
typedef int (*ntw_once_callback)(ntw_once *, void *, void **);

/* Initialize only exclusively owned storage; never reset a live operation. */
int ntw_once_init(ntw_once *once);
/* OK + pending=1 owns/joins initialization; OK + pending=0 retrieves context.
 * CHECK_ONLY never waits or starts initialization. On failure, both outputs
 * are untouched. On OK + pending=1, context is untouched. Yield is required
 * only when synchronous contention actually needs to wait. */
int ntw_once_begin(ntw_once *once, uint32_t flags, int *pending, void **context,
                   ntw_once_yield_fn yield);
/* Context must have its low two bits clear. INIT_FAILED requires NULL context.
 * Async losers get CONFLICT and must release their own losing context. */
int ntw_once_complete(ntw_once *once, uint32_t flags, void *context);
/* Callback receives exactly the context argument, including NULL. A callback
 * failure resets the attempt and returns CALLBACK_FAILED, allowing the Win32
 * adapter to preserve callback-supplied LastError. Invalid callback contexts
 * are rejected and the attempt reset; no SEH exception is raised here. */
int ntw_once_execute(ntw_once *once, ntw_once_callback callback, void *parameter,
                     void **context, ntw_once_yield_fn yield);

#endif
