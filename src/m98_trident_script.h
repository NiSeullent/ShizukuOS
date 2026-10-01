/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit portable script/Automation seam. No COM or engine pointers in ABI. */
#ifndef M98_TRIDENT_SCRIPT_H
#define M98_TRIDENT_SCRIPT_H
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef uint32_t m98_script_context;
enum m98_script_status {
    M98_SCRIPT_OK=0, M98_SCRIPT_INVALID=-201, M98_SCRIPT_BUSY=-202,
    M98_SCRIPT_STATE=-203, M98_SCRIPT_THREAD=-204, M98_SCRIPT_LIMIT=-205,
    M98_SCRIPT_EXCEPTION=-206, M98_SCRIPT_MEMORY=-207, M98_SCRIPT_HOST=-208
};
enum m98_script_type {
    M98_SCRIPT_UNDEFINED=0, M98_SCRIPT_NULL=1, M98_SCRIPT_BOOL=2,
    M98_SCRIPT_INT32=3, M98_SCRIPT_NUMBER=4, M98_SCRIPT_STRING=5,
    M98_SCRIPT_OBJECT=6, M98_SCRIPT_FUNCTION=7, M98_SCRIPT_METHOD=8
};
/* Canonical strings are explicit UTF-16 code units, preserving embedded NUL
 * and lone surrogates. No implicit terminator or code-page conversion.
 * BOOL is integer 0/1; INT32 uses integer; NUMBER uses number; OBJECT and
 * FUNCTION use nonzero opaque cookies. METHOD is host-output-only: cookie is
 * the genuine target object and string/units is the actual method name.
 * All unused fields must be zero. There are no raw IUnknown/JSValue pointers.
 */
typedef struct m98_script_value {
    uint32_t size,type;
    int32_t integer;
    uint32_t cookie;
    double number;
    const uint16_t *string;
    uint32_t units;
} m98_script_value;
/* Host callbacks are synchronous, on the owning UI thread, under a reentry
 * guard. No script API may be called from any host callback or finalizer.
 * Input values/strings are borrowed for the callback duration. FUNCTION
 * cookies are canonical, engine-owned and valid until context close; a host
 * event wrapper may store (context,cookie) and invoke it later outside the
 * callback. At most 256 distinct function identities are retained per context.
 *
 * get/call output strings and object cookies remain valid until release_result.
 * release_result is mandatory and called exactly once on both HRESULT success
 * and failure, including partially populated outputs. The engine copies a
 * string before cleanup and retains a new canonical object proxy before result
 * cleanup. retain/release balance exactly once per retained object identity;
 * proxies stay canonical/alive until context close (maximum 128 identities).
 * Every nonnegative HRESULT must accompany a valid typed value. Negative
 * HRESULT becomes a script exception and is preserved in diagnostics. No
 * missing member, unsupported Automation variant or host failure is faked.
 */
typedef struct m98_script_host {
    uint32_t size;
    void *user;
    int32_t (*get)(void *,uint32_t,const uint16_t *,uint32_t,m98_script_value *);
    int32_t (*set)(void *,uint32_t,const uint16_t *,uint32_t,const m98_script_value *);
    int32_t (*call)(void *,uint32_t,const uint16_t *,uint32_t,const m98_script_value *,uint32_t,m98_script_value *);
    int32_t (*retain)(void *,uint32_t);
    void (*release)(void *,uint32_t);
    void (*release_result)(void *,m98_script_value *);
} m98_script_host;
/* Four contexts maximum, all on one explicitly established UI thread. Options
 * and host table are copied; user stays valid through context close/finalizers.
 * Runtime memory 256KiB..32MiB, native stack 16KiB..256KiB; finite interrupt
 * checks 1..100000 and pending jobs 1..10000 per execution. Interrupt checks
 * occur at the interpreter's checkpoints, not exactly once per instruction.
 * No worker/std/os/filesystem modules, ambient document/window, COM global
 * registration or mandatory WebKit dependency is supplied by this runtime.
 */
typedef struct m98_script_options {
    uint32_t size,memory_bytes,stack_bytes,interrupt_checks,job_limit;
    const m98_script_host *host; /* NULL permits a runtime-only context */
} m98_script_options;
/* Returned strings are copied into a bounded engine-owned result lease. The
 * caller releases each lease; maximum 16 outstanding results per context.
 * Close invalidates all context/function/result generations and frees leases.
 * Scalar results also use a lease. Copying a struct does not duplicate a lease.
 */
typedef struct m98_script_result {
    uint32_t size,lease;
    m98_script_value value;
} m98_script_result;
typedef struct m98_script_details {
    uint32_t size;
    int32_t result,host_hresult;
    uint32_t interrupt_checks,jobs,exception_utf8_bytes;
    char exception_utf8[256]; /* bounded diagnostic, not a lossless BSTR */
} m98_script_details;
int m98_script_open(const m98_script_options *,m98_script_context *);
/* Root/name limits 1..256 UTF-16 units, no embedded NUL for member identifiers.
 * Source is explicit strict UTF-8, 1..1MiB, and evaluated as a global script.
 * The source length must not include a terminal NUL. No module loader/bytecode.
 */
int m98_script_bind_root(m98_script_context,const uint16_t *,uint32_t,uint32_t);
int m98_script_eval(m98_script_context,const char *,uint32_t,m98_script_result *);
int m98_script_invoke(m98_script_context,uint32_t,const m98_script_value *,uint32_t,m98_script_result *);
/* Explicit receiver preserves genuine Automation DISPID_THIS/event semantics.
 * NULL selects undefined; no receiver or argument ownership is transferred. */
int m98_script_invoke_this(m98_script_context,uint32_t,const m98_script_value *,const m98_script_value *,uint32_t,m98_script_result *);
/* Explicitly run pending Promise jobs, bounded by the same finite options.
 * eval/invoke do not implicitly drain jobs. Arguments: maximum 32 values;
 * Automation strings/results: maximum 65536 UTF-16 units each.
 */
int m98_script_jobs(m98_script_context,uint32_t *);
int m98_script_release_result(m98_script_context,uint32_t);
int m98_script_info(m98_script_context,m98_script_details *);
int m98_script_close(m98_script_context);
#ifdef __cplusplus
}
#endif
#endif
