/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_CALLBACK_INGRESS_H
#define NTW_CALLBACK_INGRESS_H
#include "../native_loader/tls_runtime.h"

#define NI_WORKERS 64u
#define NI_DEPTH 32u
#define NI_THREAD_ATTACH 2u
#define NI_THREAD_DETACH 3u

typedef enum ni_status {
    NI_OK, NI_ARGUMENT, NI_NOT_OPEN, NI_NOTIFICATION_ACTIVE, NI_CLOSING,
    NI_LIMIT, NI_DUPLICATE_THREAD, NI_HANDLE, NI_WRONG_THREAD, NI_BUSY,
    NI_FRAME_ORDER, NI_TLS_ATTACH, NI_TLS_RETAINED, NI_TLS_IDENTITY,
    NI_TLS_DETACH, NI_OUTPUT_ALIAS
} ni_status;
typedef struct ni_handle {
    uint32_t slot, generation;
    const struct ni_manager *manager;
} ni_handle;
typedef struct ni_frame { ni_handle worker; uint32_t depth, serial; } ni_frame;
typedef void (*ni_notify)(void *context, uint32_t reason,
                          const ntw_tls_thread *published_tls);
typedef struct ni_worker {
    ntw_tls_thread tls;
    uint32_t generation, owner, depth, serial, stack[NI_DEPTH];
    uint32_t state, notified;
} ni_worker;
typedef struct ni_manager {
    const struct ni_manager *self;
    ntw_tls_plan *plan;
    ni_notify notify;
    void *context;
    const char *last_tls_error;
    uint32_t state, closing, notification_active, live_workers, live_calls;
    ni_worker worker[NI_WORKERS];
} ni_manager;

/* Integrator contract, not a thread-creation API:
 * - Zero-initialize stable manager storage ONCE. Own one process-wide logical
 *   loader lock; hold it for ALL calls, plan operations and notification hooks.
 * - plan is already prepared, stable and borrowed. Its module set/ops do not
 *   change while this manager is open. An admitted worker is a real OS thread,
 *   not a fiber; its TLS vector/slots must not be replaced behind this owner.
 * - notify runs after all templates are published and before target callbacks;
 *   for detach it runs while that same thread's TLS is still live. The adapter
 *   performs graph-ordered TLS callbacks/DllMain with real mapped bases. It
 *   returns normally and does not reenter these lifecycle APIs or wait for a
 *   different thread. This module does not catch target exceptions or SEH.
 * - Call worker_start on the ACTUAL provider worker, once before it enters
 *   target code; worker_stop on that same worker after its final callback.
 *   Keep TLS and notifications across idle/reused callbacks. Never approximate
 *   worker exit with per-callback DLL_THREAD_DETACH/ATTACH.
 * - Handles/frames bind their exact manager identity. They are values: copying
 *   a frame does not create another right.
 *   Frames close strictly LIFO, on their actual owner thread, exactly once.
 * - Callback code runs OUTSIDE the lock, between enter and leave. No callback
 *   begins if enter fails. Abrupt thread termination, ExitThread bypassing
 *   worker_stop, longjmp/exception bypassing leave, and fiber switching need
 *   separate ingress/abandonment implementations; retain storage on these paths.
 * - finish proves logical retirement only. Join every real provider thread and
 *   unregister every ingress facility before unmapping target code, disposing
 *   plan or closing provider DLL references. Never wait for joins in DllMain.
 * - All pointer arguments are live, naturally aligned C objects. Outputs are
 *   writable and disjoint from inputs, manager, plan and their owned storage.
 *   Detected manager/plan/output-input aliases are rejected without writing.
 *   No generic invalid-address probing or sandbox boundary is implemented.
 */
ni_status ni_manager_init(ni_manager *, ntw_tls_plan *, ni_notify, void *context);
/* Normal failure leaves out unchanged. NI_TLS_RETAINED / NI_TLS_IDENTITY
 * after an attach notification return a valid recovery handle in out, keep
 * live_workers/TLS ownership, and prohibit callback entry. Stop must succeed
 * on the same real thread before reuse/finish. last_tls_error records an
 * existing TLS backend's static diagnostic, if that backend was called.
 */
ni_status ni_worker_start(ni_manager *, ni_handle *out);
ni_status ni_callback_enter(ni_manager *, const ni_handle *, ni_frame *out);
ni_status ni_callback_leave(ni_manager *, const ni_frame *);
ni_status ni_worker_stop(ni_manager *, const ni_handle *);
/* Closing is irreversible, including while workers remain busy. Leaves/stops
 * remain allowed; new admissions/callbacks fail. finish may be retried after
 * workers retire, but the same manager cannot be reinitialized or copied.
 */
ni_status ni_begin_close(ni_manager *);
ni_status ni_finish(ni_manager *);
const char *ni_status_name(ni_status);
#endif
