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

/* WIN64 subsystem bridge (ShizukuDOS ABI 1.1, shizukudos/abi/shz_ipc.h). The VxD is the Win98 domain's
 * endpoint of the Kernel64 <-> Win98 channel: it maps the channel window the Supervisor exposes at a
 * guest-physical address, pushes frames NTW32.DLL hands it, pops frames for it, and rings the doorbell
 * with VMCALL. NTW32.DLL never sees a channel address; the VxD owns src/dst/generation of every frame. */
#define NTWV_IOCTL_W64_OPEN 0x4e540010u     /* no input; output struct ntwv_w64_open */
#define NTWV_IOCTL_W64_SEND 0x4e540011u     /* input: 64-byte header + inline payload [+ pool data]; output int32 status */
#define NTWV_IOCTL_W64_RECV 0x4e540012u     /* no input; output: one 256-byte slot (header + payload) */
#define NTWV_IOCTL_W64_WAIT 0x4e540013u     /* input uint32 timeout_ms (advisory); output uint32 doorbell mask */
#define NTWV_W64_MAGIC 0x3436574eu          /* "NW64" */
#define NTWV_W64_SEND_MAX 4096u             /* header + inline payload + pool data per SEND (two pinned pages) */
#define NTWV_W64_PENDING_POOL 4u            /* pool blocks outstanding (freed when the matching reply is received) */
#define NTWV_ERROR_NOT_ENOUGH_MEMORY 8u
#define NTWV_ERROR_GEN_FAILURE 31u
#define NTWV_ERROR_DEV_NOT_EXIST 55u
#define NTWV_ERROR_BUSY 170u
#define NTWV_ERROR_NO_MORE_ITEMS 259u
#define NTWV_ERROR_REVISION_MISMATCH 1306u
#define NTWV_ERROR_ACCESS_DENIED 5u

struct ntwv_w64_open {                      /* 64 bytes */
    uint32_t magic, size;                   /* NTWV_W64_MAGIC, 64 */
    uint32_t abi_major, abi_minor;          /* as reported by the Supervisor (SHZ_HC_ABI_VERSION) */
    uint32_t channel_id, self_domain, peer_domain, generation;
    uint32_t slot_count, pool_bytes;        /* ring depth and shared pool size of the mapped channel */
    uint32_t sent, received;                /* frames pushed / popped by this VxD instance */
    uint32_t proto_errors, notify_errors;   /* malformed slots dropped; NOTIFY hypercalls that failed */
    uint32_t pending_pool, owner_id;        /* pool blocks awaiting their reply; caller's VxD-derived endpoint
                                             * owner (shz_w64_owner.h), informational only, never a credential */
};

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
    /* Copies from a validated pinned alias into kernel memory (WIN64 bridge input). */
    void (*read)(void *destination, uint32_t alias, uint32_t bytes);
};
/* Hypervisor and physical-mapping services: native.c binds VMCALL/CPUID/_MapPhysToLinear, host tests a model. */
struct ntwv_hv {
    int (*hypervisor_present)(void);        /* CPUID.1:ECX[31] and the Shizuku Supervisor signature at 0x40000000 */
    /* VMCALL with the ABI register convention: EAX = op, EBX/ECX = arguments; returns EAX status, EBX/ECX results. */
    int32_t (*hcall)(uint32_t op, uint32_t a, uint32_t b, uint32_t *ebx_out, uint32_t *ecx_out);
    void *(*map_phys)(uint32_t phys, uint32_t bytes);   /* system linear alias of a guest-physical window, NULL on failure */
};

int ntwv_initialize(const struct ntw_lock_ops *ops);
int ntwv_shutdown(void);
uint32_t ntwv_dioc(const struct ntwv_dioc *request, const struct ntwv_pages *pages);
uint32_t ntwv_dioc_ex(const struct ntwv_dioc *request, const struct ntwv_pages *pages, const struct ntwv_hv *hv);
/* Forget the mapped channel only when no W64 request is admitted; otherwise
 * leave it intact. Pending buffers remain peer-visible until a terminal reply
 * or Supervisor-owned channel teardown: reset is not cancellation/rundown. */
void ntwv_w64_reset(void);
/* Native endpoint owner departure (shz_w64_owner.h). Marks every LIVE owner whose VWIN32 context matches the
 * nonzero selectors; the REVOKING transition and the OWNER_CONTROL(REVOKE) push run now when the W64 gate is
 * free, otherwise on the next admitted W64 DIOC. hv may be NULL (push deferred). */
void ntwv_w64_owner_departed(const struct ntwv_hv *hv, uint32_t vm, uint32_t device, uint32_t process, uint32_t reason);
int ntwv_native_init(void);
int ntwv_native_exit(void);
uint32_t ntwv_native_dioc(const struct ntwv_dioc *request);
#endif
