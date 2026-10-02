/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_NATIVE_SESSIONS_H
#define SHZ_NATIVE_SESSIONS_H
#include "device.h"
#include "../ahci_native/ahci.h"
#include "../xhci_native/xhci.h"
struct shz_core_owner {
    void *context;
    int (*validate)(void *,uint64_t owner,uint64_t generation);
};
struct shz_ahci_session {
    struct shz_device lifecycle;struct shz_core_owner owner;
    struct ahci_device core;struct ahci_ops platform;struct ahci_config config;
};
struct shz_xhci_session {
    struct shz_device lifecycle;struct shz_core_owner owner;
    struct xhci_device core;struct xhci_ops platform;struct xhci_config config;
};
/* All native MMIO/sync/admission operations validate the same real resource
 * owner's lease. These adapters add no DMA translation or NT/Win98 binding.
 * Bind leaves the controller stopped; start uses the existing actual core. */
int shz_ahci_bind(struct shz_ahci_session *,const struct shz_core_owner *,
                    const struct ahci_ops *,const struct ahci_config *,uint64_t owner,uint64_t generation);
int shz_ahci_read(struct shz_ahci_session *,uint64_t lba,unsigned count,void *,size_t);
int shz_ahci_write(struct shz_ahci_session *,uint64_t lba,unsigned count,const void *,size_t);
int shz_ahci_flush(struct shz_ahci_session *);
int shz_xhci_bind(struct shz_xhci_session *,const struct shz_core_owner *,
                    const struct xhci_ops *,const struct xhci_config *,uint64_t owner,uint64_t generation);
int shz_xhci_noop(struct shz_xhci_session *);
#endif
