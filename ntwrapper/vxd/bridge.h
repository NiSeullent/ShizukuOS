/* SPDX-License-Identifier: GPL-2.0-only -- original implementation. */
#ifndef NTWV_BRIDGE_H
#define NTWV_BRIDGE_H
#include <stdint.h>
#include "../include/ntwrapper.h"

#define NTWV_IOCTL_QUERY 0x4e540001u
#define NTWV_QUERY_MAGIC 0x3957544eu
#define NTWV_MAP_GLOBAL 0x40000000u
#define NTWV_ERROR_INVALID_PARAMETER 87u
#define NTWV_ERROR_NOT_SUPPORTED 50u
#define NTWV_ERROR_INSUFFICIENT_BUFFER 122u
#define NTWV_ERROR_NOACCESS 998u
#define NTWV_ERROR_NOT_READY 21u

/* VWIN32-owned structure. Buffer fields remain untrusted 32-bit addresses. */
struct ntwv_dioc {
    uint32_t internal1, vm, internal2, code, input, input_bytes;
    uint32_t output, output_bytes, returned, overlapped, device, process;
};
struct ntwv_query {
    uint32_t magic, size, abi, core_abi, max_objects, features, initialized, selftest;
};
struct ntwv_pages {
    uint32_t (*check)(uint32_t page, uint32_t count, uint32_t flags);
    uint32_t (*lock)(uint32_t page, uint32_t count, uint32_t flags);
    uint32_t (*unlock)(uint32_t page, uint32_t count, uint32_t flags);
    uint32_t (*ptes)(uint32_t page, uint32_t count, uint32_t *output, uint32_t flags);
    uintptr_t (*enter)(void *opaque);
    void (*leave)(void *opaque, uintptr_t saved);
    /* The native implementation copies to a validated pinned kernel alias.
     * Host tests supply a bounded mock alias resolver instead. */
    void (*write)(uint32_t alias, const void *source, uint32_t bytes);
};

int ntwv_initialize(const struct ntw_lock_ops *ops);
int ntwv_shutdown(void);
uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *pages);
int ntwv_native_init(void);
int ntwv_native_exit(void);
uint32_t ntwv_native_dioc(const struct ntwv_dioc *request);
#endif
