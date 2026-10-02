/* SPDX-License-Identifier: GPL-2.0-only -- original native Windows PMA endpoint. */
#ifndef NTWV_PMA_ENDPOINT_H
#define NTWV_PMA_ENDPOINT_H
#include "bridge.h"
#include "../../shizukudos/abi/shz_vmm_pma.h"

/* Local DIOC interface; the channel and PMA wire ABI are unchanged. This first
 * endpoint owns channel2 exclusively until its real PROCESS_EXIT reply. */
#define NTWV_IOCTL_PMA_REGISTER 0x4e540020u
#define NTWV_IOCTL_PMA_QUERY 0x4e540021u
#define NTWV_IOCTL_PMA_TAKE 0x4e540022u
#define NTWV_IOCTL_PMA_CLOSE 0x4e540023u
#define NTWV_PMA_ENDPOINT_MAGIC 0x45504d50u
#define NTWV_PMA_POLL_MS 20u
#define NTWV_PMA_TIMEOUT_MAX_MS 60000u
#define NTWV_PMA_RESULT_QUERY 1u
#define NTWV_PMA_RESULT_ERROR 2u
#define NTWV_ERROR_TIMEOUT 1460u
#define NTWV_ERROR_ACCESS_DENIED 5u

struct ntwv_pma_registration {
    uint32_t size, event_handle, timeout_ms, reserved;
};
struct ntwv_pma_owner {
    uint32_t magic, size, domain, pid, tid;
    uint32_t owner_generation, thread_generation, channel_generation;
};
struct ntwv_pma_ticket { uint64_t request_id; uint32_t generation, reserved; };
struct ntwv_pma_result {
    uint32_t magic, size, kind, error;
    uint64_t request_id;
    uint32_t generation, reserved;
    shz_pma_info_t info;
};
_Static_assert(sizeof(struct ntwv_pma_registration) == 16, "PMA registration DIOC");
_Static_assert(sizeof(struct ntwv_pma_owner) == 32, "PMA owner DIOC");
_Static_assert(sizeof(struct ntwv_pma_ticket) == 16, "PMA ticket DIOC");
_Static_assert(sizeof(struct ntwv_pma_result) == 96, "PMA result DIOC");

/* Every operation below binds to an original Win98 service. Host tests replace
 * these privileged boundaries; the production broker and rings are unchanged. */
struct ntwv_pma_services {
    uint32_t (*system_vm)(void);
    uint32_t (*current_vm)(void);
    uint32_t (*current_thread)(void);
    uint32_t (*now_ms)(void);
    uint32_t (*open_event)(uint32_t handle);
    int (*set_event)(uint32_t handle);
    int (*close_event)(uint32_t handle);
    uint32_t (*schedule_event)(uint32_t ref);
    void (*cancel_event)(uint32_t handle);
    uint32_t (*schedule_timeout)(uint32_t ms, uint32_t ref);
    void (*cancel_timeout)(uint32_t handle);
    uintptr_t (*enter)(void *opaque);
    void (*leave)(void *opaque, uintptr_t saved);
};
int ntwv_pma_initialize(const struct ntwv_pma_services *services, const struct ntwv_hv *hv);
int ntwv_pma_shutdown(void);
int ntwv_pma_unload_safe(void);
void ntwv_pma_resume(void);
uint32_t ntwv_pma_dispatch(const struct ntwv_dioc *request, const void *input,
                           void *output, uint32_t *bytes);
uint32_t ntwv_pma_take_ack(const struct ntwv_dioc *request, uint64_t request_id);
uint32_t ntwv_pma_close_ack(const struct ntwv_dioc *request);
void ntwv_pma_event(uint32_t vm, uint32_t thread, uint32_t ref);
void ntwv_pma_timeout(uint32_t ref);
void ntwv_pma_owner_departed(uint32_t vm, uint32_t thread, uint32_t device, uint32_t process);

/* Trusted kernel callers only. These take the existing nonblocking SPSC
 * admission token; no user pointer or VMM service executes while it is held. */
uint32_t ntwv_endpoint_acquire(const struct ntwv_hv *hv, struct ntwv_w64_open *info);
uint32_t ntwv_endpoint_send(const struct ntwv_hv *hv, const shz_msg_hdr_t *header, const void *payload);
uint32_t ntwv_endpoint_recv(void *slot);
uint32_t ntwv_endpoint_release(void);
void ntwv_endpoint_abort_registration(void);
#endif
