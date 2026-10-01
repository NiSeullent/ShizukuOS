/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTW_TLS_RUNTIME_H
#define NTW_TLS_RUNTIME_H
#include <stdint.h>
#include <stddef.h>
#define NTW_TLS_MODULES 32u
#define NTW_TLS_BYTES (1024u*1024u)
#define NTW_TLS_NO_SLOT UINT32_MAX

/* Loader lock serializes every plan operation. All target threads must have
 * detached before disposal. Inputs and index pointers have already passed
 * the loader's mapped PE bounds and writable-section checks. This helper
 * never executes callbacks: the loader does so after a complete attach.
 */
typedef struct ntw_tls_ops {
    void *context;
    uint32_t (*reserve)(void *);
    int (*release)(void *,uint32_t);
    void *(*allocate)(void *,uint32_t);
    void (*deallocate)(void *,void *);
    uint32_t (*thread_id)(void *);
    int (*read)(void *,uint32_t,void **);
    int (*publish)(void *,uint32_t,void *);
} ntw_tls_ops;
typedef struct ntw_tls_spec {
    const void *initial;
    uint32_t initialized_bytes,zero_bytes,alignment;
    uint32_t *index_address;
} ntw_tls_spec;
typedef struct ntw_tls_module {
    unsigned char *initial;
    uint32_t bytes,zero,alignment,slot,old_index;
    uint32_t *index_address;
} ntw_tls_module;
typedef struct ntw_tls_plan {
    ntw_tls_ops ops;
    ntw_tls_module module[NTW_TLS_MODULES];
    uint32_t count,live_threads;
    int ready;
} ntw_tls_plan;
typedef struct ntw_tls_thread {
    ntw_tls_plan *plan;
    void *allocation[NTW_TLS_MODULES],*data[NTW_TLS_MODULES];
    uint32_t owner,count,published;
    int active;
} ntw_tls_thread;

/* Zero-initialize caller-owned plan/thread storage before the first call.
 * Failed attach rolls back all publications; a rollback publication failure
 * retains active storage so the caller can retry detach without dangling TLS.
 */
int ntw_tls_prepare(ntw_tls_plan *,const ntw_tls_spec *,uint32_t,const ntw_tls_ops *,const char **);
int ntw_tls_attach(ntw_tls_plan *,ntw_tls_thread *,const char **);
int ntw_tls_detach(ntw_tls_thread *,const char **);
int ntw_tls_dispose(ntw_tls_plan *,const char **);
#ifdef _WIN32
/* Actual Win98-only backend; FS:0x2c must match the original TDB vector.
 * No FS pointer is replaced. No NT ABI or KernelEx identity is inferred.
 */
int ntw_tls_native_ops(ntw_tls_ops *);
#endif
#endif
