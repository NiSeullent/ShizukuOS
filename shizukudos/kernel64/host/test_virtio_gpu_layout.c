/* SPDX-License-Identifier: GPL-2.0-only
 * kernel64/virtio_gpu.h (written from the Virtio 1.2 specification) against the host's <linux/virtio_gpu.h>: every
 * command/response code, feature bit and format value, and the size and field offsets of every wire structure the
 * driver sends or receives. A mismatch means the guest driver would put a field where the device does not read it.
 */
#include <stddef.h>
#include <stdio.h>
#include <linux/virtio_gpu.h>
#include "virtio_gpu.h"

static unsigned checks, failures;
#define SAME(a, b) do { ++checks; if ((unsigned long long)(a) != (unsigned long long)(b)) { ++failures; \
    printf("FAIL: %s = %llu, %s = %llu\n", #a, (unsigned long long)(a), #b, (unsigned long long)(b)); } } while (0)
#define SIZE(mine, theirs) SAME(sizeof(mine), sizeof(struct theirs))
#define OFF(mine, mf, theirs, tf) SAME(offsetof(mine, mf), offsetof(struct theirs, tf))

int main(void)
{
    SAME(VGPU_F_VIRGL, VIRTIO_GPU_F_VIRGL); SAME(VGPU_F_EDID, VIRTIO_GPU_F_EDID);
    SAME(VGPU_F_RESOURCE_BLOB, VIRTIO_GPU_F_RESOURCE_BLOB); SAME(VGPU_F_CONTEXT_INIT, VIRTIO_GPU_F_CONTEXT_INIT);
    SAME(VGPU_CMD_GET_DISPLAY_INFO, VIRTIO_GPU_CMD_GET_DISPLAY_INFO);
    SAME(VGPU_CMD_RESOURCE_CREATE_2D, VIRTIO_GPU_CMD_RESOURCE_CREATE_2D);
    SAME(VGPU_CMD_RESOURCE_UNREF, VIRTIO_GPU_CMD_RESOURCE_UNREF);
    SAME(VGPU_CMD_SET_SCANOUT, VIRTIO_GPU_CMD_SET_SCANOUT);
    SAME(VGPU_CMD_RESOURCE_FLUSH, VIRTIO_GPU_CMD_RESOURCE_FLUSH);
    SAME(VGPU_CMD_TRANSFER_TO_HOST_2D, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D);
    SAME(VGPU_CMD_RESOURCE_ATTACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING);
    SAME(VGPU_CMD_RESOURCE_DETACH_BACKING, VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING);
    SAME(VGPU_CMD_GET_CAPSET_INFO, VIRTIO_GPU_CMD_GET_CAPSET_INFO);
    SAME(VGPU_CMD_GET_CAPSET, VIRTIO_GPU_CMD_GET_CAPSET);
    SAME(VGPU_CMD_GET_EDID, VIRTIO_GPU_CMD_GET_EDID);
    SAME(VGPU_CMD_CTX_CREATE, VIRTIO_GPU_CMD_CTX_CREATE);
    SAME(VGPU_CMD_CTX_DESTROY, VIRTIO_GPU_CMD_CTX_DESTROY);
    SAME(VGPU_CMD_CTX_ATTACH_RESOURCE, VIRTIO_GPU_CMD_CTX_ATTACH_RESOURCE);
    SAME(VGPU_CMD_CTX_DETACH_RESOURCE, VIRTIO_GPU_CMD_CTX_DETACH_RESOURCE);
    SAME(VGPU_CMD_RESOURCE_CREATE_3D, VIRTIO_GPU_CMD_RESOURCE_CREATE_3D);
    SAME(VGPU_CMD_TRANSFER_TO_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_TO_HOST_3D);
    SAME(VGPU_CMD_TRANSFER_FROM_HOST_3D, VIRTIO_GPU_CMD_TRANSFER_FROM_HOST_3D);
    SAME(VGPU_CMD_SUBMIT_3D, VIRTIO_GPU_CMD_SUBMIT_3D);
    SAME(VGPU_CMD_UPDATE_CURSOR, VIRTIO_GPU_CMD_UPDATE_CURSOR);
    SAME(VGPU_CMD_MOVE_CURSOR, VIRTIO_GPU_CMD_MOVE_CURSOR);
    SAME(VGPU_RESP_OK_NODATA, VIRTIO_GPU_RESP_OK_NODATA);
    SAME(VGPU_RESP_OK_DISPLAY_INFO, VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
    SAME(VGPU_RESP_OK_CAPSET_INFO, VIRTIO_GPU_RESP_OK_CAPSET_INFO);
    SAME(VGPU_RESP_OK_CAPSET, VIRTIO_GPU_RESP_OK_CAPSET);
    SAME(VGPU_RESP_OK_EDID, VIRTIO_GPU_RESP_OK_EDID);
    SAME(VGPU_RESP_ERR_UNSPEC, VIRTIO_GPU_RESP_ERR_UNSPEC);
    SAME(VGPU_RESP_ERR_INVALID_PARAMETER, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER);
    SAME(VGPU_FLAG_FENCE, VIRTIO_GPU_FLAG_FENCE);
    SAME(VGPU_FORMAT_B8G8R8A8_UNORM, VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM);
    SAME(VGPU_FORMAT_B8G8R8X8_UNORM, VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM);
    SAME(VGPU_FORMAT_R8G8B8X8_UNORM, VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM);
    SAME(VGPU_CAPSET_VIRGL, VIRTIO_GPU_CAPSET_VIRGL); SAME(VGPU_CAPSET_VIRGL2, VIRTIO_GPU_CAPSET_VIRGL2);
    SAME(VGPU_MAX_SCANOUTS, VIRTIO_GPU_MAX_SCANOUTS);
    SAME(VGPU_EVENT_DISPLAY, VIRTIO_GPU_EVENT_DISPLAY);
    SAME(VGPU_CFG_EVENTS_READ, offsetof(struct virtio_gpu_config, events_read));
    SAME(VGPU_CFG_EVENTS_CLEAR, offsetof(struct virtio_gpu_config, events_clear));
    SAME(VGPU_CFG_NUM_SCANOUTS, offsetof(struct virtio_gpu_config, num_scanouts));
    SAME(VGPU_CFG_NUM_CAPSETS, offsetof(struct virtio_gpu_config, num_capsets));

    SIZE(vgpu_hdr_t, virtio_gpu_ctrl_hdr);
    OFF(vgpu_hdr_t, flags, virtio_gpu_ctrl_hdr, flags); OFF(vgpu_hdr_t, fence_id, virtio_gpu_ctrl_hdr, fence_id);
    OFF(vgpu_hdr_t, ctx_id, virtio_gpu_ctrl_hdr, ctx_id); OFF(vgpu_hdr_t, ring_idx, virtio_gpu_ctrl_hdr, ring_idx);
    SIZE(vgpu_rect_t, virtio_gpu_rect);
    SIZE(vgpu_resp_display_info_t, virtio_gpu_resp_display_info);
    OFF(vgpu_resp_display_info_t, pmodes[1].enabled, virtio_gpu_resp_display_info, pmodes[1].enabled);
    SIZE(vgpu_resource_create_2d_t, virtio_gpu_resource_create_2d);
    OFF(vgpu_resource_create_2d_t, format, virtio_gpu_resource_create_2d, format);
    OFF(vgpu_resource_create_2d_t, height, virtio_gpu_resource_create_2d, height);
    SIZE(vgpu_resource_unref_t, virtio_gpu_resource_unref);
    SIZE(vgpu_set_scanout_t, virtio_gpu_set_scanout);
    OFF(vgpu_set_scanout_t, scanout_id, virtio_gpu_set_scanout, scanout_id);
    OFF(vgpu_set_scanout_t, resource_id, virtio_gpu_set_scanout, resource_id);
    SIZE(vgpu_resource_flush_t, virtio_gpu_resource_flush);
    OFF(vgpu_resource_flush_t, resource_id, virtio_gpu_resource_flush, resource_id);
    SIZE(vgpu_transfer_to_host_2d_t, virtio_gpu_transfer_to_host_2d);
    OFF(vgpu_transfer_to_host_2d_t, offset, virtio_gpu_transfer_to_host_2d, offset);
    OFF(vgpu_transfer_to_host_2d_t, resource_id, virtio_gpu_transfer_to_host_2d, resource_id);
    SIZE(vgpu_mem_entry_t, virtio_gpu_mem_entry);
    SIZE(vgpu_resource_attach_backing_t, virtio_gpu_resource_attach_backing);
    OFF(vgpu_resource_attach_backing_t, nr_entries, virtio_gpu_resource_attach_backing, nr_entries);
    SIZE(vgpu_resource_detach_backing_t, virtio_gpu_resource_detach_backing);
    SIZE(vgpu_get_edid_t, virtio_gpu_cmd_get_edid);
    SIZE(vgpu_resp_edid_t, virtio_gpu_resp_edid);
    OFF(vgpu_resp_edid_t, edid, virtio_gpu_resp_edid, edid);
    SIZE(vgpu_get_capset_info_t, virtio_gpu_get_capset_info);
    SIZE(vgpu_resp_capset_info_t, virtio_gpu_resp_capset_info);
    OFF(vgpu_resp_capset_info_t, capset_max_size, virtio_gpu_resp_capset_info, capset_max_size);
    SIZE(vgpu_get_capset_t, virtio_gpu_get_capset);
    SIZE(vgpu_box_t, virtio_gpu_box);
    SIZE(vgpu_transfer_host_3d_t, virtio_gpu_transfer_host_3d);
    OFF(vgpu_transfer_host_3d_t, offset, virtio_gpu_transfer_host_3d, offset);
    OFF(vgpu_transfer_host_3d_t, layer_stride, virtio_gpu_transfer_host_3d, layer_stride);
    SIZE(vgpu_resource_create_3d_t, virtio_gpu_resource_create_3d);
    OFF(vgpu_resource_create_3d_t, bind, virtio_gpu_resource_create_3d, bind);
    OFF(vgpu_resource_create_3d_t, flags, virtio_gpu_resource_create_3d, flags);
    SIZE(vgpu_ctx_create_t, virtio_gpu_ctx_create);
    OFF(vgpu_ctx_create_t, debug_name, virtio_gpu_ctx_create, debug_name);
    SIZE(vgpu_ctx_destroy_t, virtio_gpu_ctx_destroy);
    SIZE(vgpu_ctx_resource_t, virtio_gpu_ctx_resource);
    SIZE(vgpu_cmd_submit_t, virtio_gpu_cmd_submit);
    SIZE(vgpu_cursor_pos_t, virtio_gpu_cursor_pos);
    SIZE(vgpu_update_cursor_t, virtio_gpu_update_cursor);
    OFF(vgpu_update_cursor_t, resource_id, virtio_gpu_update_cursor, resource_id);
    OFF(vgpu_update_cursor_t, hot_y, virtio_gpu_update_cursor, hot_y);
    printf("virtio-gpu layout: %u checks, %u failed\n", checks, failures);
    return failures ? 1 : 0;
}
