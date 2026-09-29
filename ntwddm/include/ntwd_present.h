/* SPDX-License-Identifier: GPL-2.0-only
 * Software device/context/present wrapper around the NTWDDM framebuffer.
 * Shaped after the public WDDM D3DKMT device, context, and blit-present
 * sequence. It does not call Dxgkrnl and does not succeed at GPU work.
 * See ../PROVENANCE.md.
 */
#ifndef NTWD_PRESENT_H
#define NTWD_PRESENT_H

#include "ntwddm.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define NTWD_ABI_VERSION NTWG_ABI_VERSION
#define NTWD_NODE_SOFTWARE 0u
#define NTWD_NODE_GPU 1u
#define NTWD_CREATE_GPU 1u

typedef struct ntwd_device ntwd_device;
typedef struct ntwd_context ntwd_context;

typedef struct ntwd_device_desc {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t create_flags;
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *allocator_user;
    ntwg_framebuffer_desc framebuffer;
} ntwd_device_desc;

ntwg_status ntwd_device_create(const ntwd_device_desc *desc, ntwd_device **out);
ntwg_status ntwd_device_destroy(ntwd_device *device);
ntwg_status ntwd_context_create(ntwd_device *device, uint32_t node,
                                ntwd_context **out);
ntwg_status ntwd_context_destroy(ntwd_context *context);
/* Copies the device primary through ntwg_present. source NULL, an unbound
 * device, or a GPU context is a failure. A bounds failure writes nothing. */
ntwg_status ntwd_present(ntwd_context *context, const ntwg_rect *source,
                         uint32_t dst_x, uint32_t dst_y, ntwg_fence *fence);
ntwg_status ntwd_primary_surface(const ntwd_device *device, ntwg_surface *out);
ntwg_status ntwd_software_context(const ntwd_device *device, ntwg_context **out);

#ifdef __cplusplus
}
#endif
#endif
