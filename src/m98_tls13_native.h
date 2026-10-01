/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_TLS13_NATIVE_H
#define M98_TLS13_NATIVE_H
#include <stdint.h>
#include <stddef.h>
#include "m98_tls13.h"

/* Opt-in blocking facade over a nonblocking TCP BIO. No DNS lookup, ambient
 * trust, installation or standard OS API replacement. C calling convention.
 * One live handle per process. Calls are serialized; concurrent/reentrant
 * calls fail BUSY. Hostname and CA need remain valid only until open returns.
 * Native loading requires M98TLS13.DLL beside M98NET.DLL; networking/crypto
 * modules must be the original installed system modules.
 */
typedef uint32_t m98_net_handle;
enum m98_net_result {
    M98_NET_OK=0, M98_NET_EOF=3,
    M98_NET_INVALID=-101, M98_NET_BUSY=-102, M98_NET_IO=-103,
    M98_NET_TIMEOUT=-104, M98_NET_LOAD=-105, M98_NET_CLEANUP=-106,
    M98_NET_STATE=-107, M98_NET_LIMIT=-108
};
/* Backend certificate/entropy/clock/protocol failures retain M98_TLS_* codes.
 * Deadlines 1..300000 ms bound connect, handshake and each I/O/shutdown call.
 * Checks occur before/after native calls and inside BIO callbacks. OS loader,
 * CSP and individual TLS CPU calls are synchronous and cannot be preempted.
 * A finite controller-step cap also stops a perpetually ready provider.
 */
typedef struct m98_net_options {
    uint32_t size;
    uint8_t ipv4[4];               /* wire order; explicit unicast/loopback */
    uint16_t port, reserved;
    const char *hostname;          /* separate ASCII DNS identity/SNI */
    const unsigned char *ca_pem;   /* explicit PEM bundle, terminal NUL */
    uint32_t ca_bytes;
    uint32_t connect_ms, handshake_ms, io_ms;
} m98_net_options;
typedef struct m98_net_details {
    uint32_t size, phase;
    int32_t result, backend_error;
    uint32_t verify_flags, os_error, established, cleanup_pending, cleanup_error;
} m98_net_details;
enum { M98_NET_CONNECT=1, M98_NET_HANDSHAKE=2, M98_NET_READY=3,
       M98_NET_IO_PHASE=4, M98_NET_SHUTDOWN=5, M98_NET_DEAD=6 };

/* Normal failure cleans owned resources and returns handle 0. If cleanup
 * itself fails, return CLEANUP with a nonzero quarantined handle: query its
 * original failure with info and retry close. No new open is then allowed.
 */
int m98_net_open(const m98_net_options *, m98_net_handle *);
/* Write all requested bytes, <=1 MiB. On failure written counts only completed
 * plaintext writes; already transmitted partial ciphertext is not replayable.
 * Read returns the first authenticated partial payload, <=1 MiB. Timeout,
 * transport EOF without close_notify and fatal errors close the connection.
 * On any read error/EOF the count is zero and buffer contents are unspecified.
 * Error/EOF retains the handle for diagnostics until explicit close.
 */
int m98_net_write(m98_net_handle,const void *,size_t,size_t *);
int m98_net_read(m98_net_handle,void *,size_t,size_t *);
/* Sends authenticated close_notify, half-closes TCP output, drains encrypted
 * input until TCP EOF within the same deadline, then frees owned resources.
 * Drained bytes are never interpreted as authenticated peer close_notify.
 * close is immediate owned-resource cleanup, without a wire shutdown wait.
 * Both reject stale handles; close may be retried after cleanup failure.
 */
int m98_net_shutdown(m98_net_handle);
int m98_net_close(m98_net_handle);
int m98_net_info(m98_net_handle,m98_net_details *);

#ifdef M98_NET_IMPLEMENTATION
/* Internal platform seam. Host models/Unix loopback do not prove Win98 APIs. */
typedef struct m98_net_backend {
    int (*create)(const m98_tls_options *,m98_tls_client **);
    int (*handshake)(m98_tls_client *);
    int (*write)(m98_tls_client *,const void *,size_t,size_t *);
    int (*read)(m98_tls_client *,void *,size_t,size_t *);
    int (*shutdown)(m98_tls_client *);
    int (*backend_error)(const m98_tls_client *);
    uint32_t (*verify_flags)(const m98_tls_client *);
    int (*is_established)(const m98_tls_client *);
    void (*free)(m98_tls_client *);
} m98_net_backend;
typedef struct m98_net_platform_ops {
    int (*start)(m98_net_backend *);
    int (*connect)(const uint8_t *,uint16_t); /* 0 connected, 2 pending */
    int (*wait)(int,uint32_t,int);           /* requested TLS WANT; connect flag */
    int (*finish_connect)(void);
    int (*half_close)(void);
    int (*send)(void *,const unsigned char *,size_t);
    int (*recv)(void *,unsigned char *,size_t);
    int (*random)(void *,unsigned char *,size_t); /* exactly 1, or failure */
    int64_t (*utc)(void *);
    uint32_t (*ticks)(void);
    uint32_t (*error)(void);
    int (*stop)(void); /* 0 complete; otherwise retain owned handles for retry */
} m98_net_platform_ops;
extern const m98_net_platform_ops m98_net_platform;
#endif
#endif
