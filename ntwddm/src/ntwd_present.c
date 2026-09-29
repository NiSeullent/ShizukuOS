/* SPDX-License-Identifier: GPL-2.0-only
 * Original software present path. The public WDDM sequence is
 * device -> context -> present; GPU nodes stay unsupported.
 */
#include "ntwd_present.h"

struct ntwd_device {
    ntwg_allocate_fn allocate;
    ntwg_deallocate_fn deallocate;
    void *user;
    ntwg_context *core;
    ntwg_surface primary;
    uint32_t live_contexts;
};

struct ntwd_context {
    ntwd_device *device;
    uint32_t node;
    uint32_t live;
};

static void fail_rollback(ntwd_device *device)
{
    ntwg_deallocate_fn deallocate = device->deallocate;
    void *user = device->user;
    if (device->core != NULL) {
        if (device->primary != 0)
            (void)ntwg_surface_release(device->core, device->primary);
        (void)ntwg_destroy(device->core);
    }
    deallocate(user, device, sizeof(*device));
}

ntwg_status ntwd_device_create(const ntwd_device_desc *desc, ntwd_device **out)
{
    ntwd_device *device;
    ntwg_create_desc create;
    ntwg_surface_desc surface;
    ntwg_status status;
    if (out == NULL) return NTWG_E_INVALID;
    *out = NULL;
    if (desc == NULL || desc->struct_size < sizeof(*desc)) return NTWG_E_INVALID;
    if (desc->abi_version != NTWD_ABI_VERSION) return NTWG_E_VERSION;
    if (desc->allocate == NULL || desc->deallocate == NULL) return NTWG_E_INVALID;
    if ((desc->create_flags & ~NTWD_CREATE_GPU) != 0) return NTWG_E_INVALID;
    if ((desc->create_flags & NTWD_CREATE_GPU) != 0) return NTWG_E_UNSUPPORTED;
    if (desc->framebuffer.struct_size < sizeof(desc->framebuffer) ||
        desc->framebuffer.abi_version != NTWG_ABI_VERSION)
        return NTWG_E_INVALID;
    device = (ntwd_device *)desc->allocate(desc->allocator_user, sizeof(*device));
    if (device == NULL) return NTWG_E_NOMEM;
    device->allocate = desc->allocate;
    device->deallocate = desc->deallocate;
    device->user = desc->allocator_user;
    device->core = NULL;
    device->primary = 0;
    device->live_contexts = 0;
    create.struct_size = sizeof(create);
    create.abi_version = NTWG_ABI_VERSION;
    create.allocate = desc->allocate;
    create.deallocate = desc->deallocate;
    create.allocator_user = desc->allocator_user;
    status = ntwg_create(&create, &device->core);
    if (status != NTWG_OK) {
        desc->deallocate(desc->allocator_user, device, sizeof(*device));
        return status;
    }
    status = ntwg_bind_framebuffer(device->core, &desc->framebuffer);
    if (status != NTWG_OK) {
        fail_rollback(device);
        return status;
    }
    surface.struct_size = sizeof(surface);
    surface.abi_version = NTWG_ABI_VERSION;
    surface.width = desc->framebuffer.width;
    surface.height = desc->framebuffer.height;
    surface.pitch_bytes = 0;
    surface.format = desc->framebuffer.format;
    status = ntwg_surface_create(device->core, &surface, &device->primary);
    if (status != NTWG_OK) {
        fail_rollback(device);
        return status;
    }
    *out = device;
    return NTWG_OK;
}

ntwg_status ntwd_device_destroy(ntwd_device *device)
{
    ntwg_status status;
    if (device == NULL) return NTWG_E_INVALID;
    if (device->live_contexts != 0) return NTWG_E_BUSY;
    status = ntwg_surface_release(device->core, device->primary);
    if (status != NTWG_OK) return status;
    device->primary = 0;
    status = ntwg_destroy(device->core);
    if (status != NTWG_OK) return status;
    device->core = NULL;
    device->deallocate(device->user, device, sizeof(*device));
    return NTWG_OK;
}

ntwg_status ntwd_context_create(ntwd_device *device, uint32_t node,
                                ntwd_context **out)
{
    ntwd_context *context;
    if (out == NULL) return NTWG_E_INVALID;
    *out = NULL;
    if (device == NULL) return NTWG_E_INVALID;
    if (node != NTWD_NODE_SOFTWARE) return NTWG_E_UNSUPPORTED;
    if (device->live_contexts == UINT32_MAX) return NTWG_E_EXHAUSTED;
    context = (ntwd_context *)device->allocate(device->user, sizeof(*context));
    if (context == NULL) return NTWG_E_NOMEM;
    context->device = device;
    context->node = node;
    context->live = 1;
    device->live_contexts++;
    *out = context;
    return NTWG_OK;
}

ntwg_status ntwd_context_destroy(ntwd_context *context)
{
    ntwd_device *device;
    if (context == NULL || context->live == 0 || context->device == NULL)
        return NTWG_E_INVALID;
    device = context->device;
    if (device->live_contexts == 0) return NTWG_E_INVALID;
    context->live = 0;
    device->live_contexts--;
    device->deallocate(device->user, context, sizeof(*context));
    return NTWG_OK;
}

ntwg_status ntwd_present(ntwd_context *context, const ntwg_rect *source,
                         uint32_t dst_x, uint32_t dst_y, ntwg_fence *fence)
{
    if (context == NULL || context->live == 0 || context->device == NULL)
        return NTWG_E_INVALID;
    if (context->node != NTWD_NODE_SOFTWARE) return NTWG_E_UNSUPPORTED;
    return ntwg_present(context->device->core, context->device->primary,
                        source, dst_x, dst_y, fence);
}

ntwg_status ntwd_primary_surface(const ntwd_device *device, ntwg_surface *out)
{
    if (out == NULL) return NTWG_E_INVALID;
    *out = 0;
    if (device == NULL || device->primary == 0) return NTWG_E_INVALID;
    *out = device->primary;
    return NTWG_OK;
}

ntwg_status ntwd_software_context(const ntwd_device *device, ntwg_context **out)
{
    if (out == NULL) return NTWG_E_INVALID;
    *out = NULL;
    if (device == NULL || device->core == NULL) return NTWG_E_INVALID;
    *out = device->core;
    return NTWG_OK;
}
