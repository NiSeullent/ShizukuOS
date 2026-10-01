/* SPDX-License-Identifier: GPL-2.0-only
 * Original explicit Automation adapter. No registry or scripting substitution. */
#ifndef M98_TRIDENT_AUTOMATION_H
#define M98_TRIDENT_AUTOMATION_H
#include "m98_trident_script.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef uint32_t m98_automation_context;
/* Negative HRESULTs, distinct from the script runtime's status codes. */
#define M98_AUTO_STATE ((int32_t)0x8004a001u)
#define M98_AUTO_THREAD ((int32_t)0x8004a002u)
#define M98_AUTO_BUSY ((int32_t)0x8004a003u)
#define M98_AUTO_LIMIT ((int32_t)0x8004a004u)
#define M98_AUTO_TYPE ((int32_t)0x8004a005u)
typedef struct m98_automation_options {
    uint32_t size;
    void *user;
    /* Called by pump only, on the UI thread, outside every COM/host callback.
     * FUNCTION cookies belong to one script context until that runtime closes.
     * Implement this hook using invoke, release_result, then explicit jobs.
     * No synchronous event return value/cancellation is supplied. */
    int32_t (*dispatch)(void *,uint32_t,const m98_script_value *receiver,
                        const m98_script_value *,uint32_t);
} m98_automation_options;
typedef struct m98_automation_error {
    uint32_t size;
    int32_t hresult,exception_scode;
    uint32_t argument; /* logical source-order index, UINT32_MAX if unavailable */
    uint32_t description_units;
    uint16_t description[256]; /* bounded diagnostic, explicit units */
} m98_automation_error;
/* Four contexts on one established UI thread. COM must already be initialized
 * as STA by the caller. Objects:128/context; wrappers:64; queued calls:32;
 * arguments:32; owned strings:128/context, 65536 units each; member identifier:
 * 1..256 units, no embedded NUL. Close also frees unreleased output strings.
 * All context/object cookies are process-unique, never recycled or wrapped.
 * No ambient document, window, filesystem or service is installed. */
int32_t m98_automation_open(const m98_automation_options *,m98_automation_context *);
/* unknown is an actual native IUnknown*. Its own canonical identity is queried;
 * caller keeps its original reference. Returned cookie owns one adapter ref. */
int32_t m98_automation_attach(m98_automation_context,void *unknown,uint32_t *cookie);
int32_t m98_automation_retain(m98_automation_context,uint32_t);
int32_t m98_automation_release(m98_automation_context,uint32_t);
int32_t m98_automation_get(m98_automation_context,uint32_t,const uint16_t *,uint32_t,m98_script_value *);
int32_t m98_automation_set(m98_automation_context,uint32_t,const uint16_t *,uint32_t,const m98_script_value *);
int32_t m98_automation_call(m98_automation_context,uint32_t,const uint16_t *,uint32_t,const m98_script_value *,uint32_t,m98_script_value *);
/* Output get/call values own their strings/object reference until this call.
 * Do not clear a borrowed input or copy an owned result to duplicate ownership. */
int32_t m98_automation_release_result(m98_automation_context,m98_script_value *);
/* Complete host table uses a context cookie encoded as user, never a COM ptr.
 * The table is suitable for m98_script_options.host. */
int32_t m98_automation_host(m98_automation_context,m98_script_host *);
int32_t m98_automation_error_info(m98_automation_context,m98_automation_error *);
/* Pump max 1..32 callbacks; recursively pumping/closing is rejected. A failing
 * dispatch is consumed exactly once and its HRESULT returned. New callbacks
 * remain queued. Arguments are borrowed only during dispatch. */
int32_t m98_automation_pump(m98_automation_context,uint32_t maximum,uint32_t *completed);
/* Detach/unadvise document event bindings, then close adapter BEFORE runtime.
 * Close discards queued work and invalidates every object/context generation.
 * Native wrappers may survive document refs but reject all later invocations.
 * Caller-sent UI actions or compiled fixture text are never native proof. */
int32_t m98_automation_close(m98_automation_context);
#ifdef __cplusplus
}
#endif
#endif
