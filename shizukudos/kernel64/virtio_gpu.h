/* SPDX-License-Identifier: GPL-2.0-only
 * virtio-gpu device protocol (Virtio 1.2, OASIS, section 5.7 "GPU Device"), written from the specification. All fields are
 * little-endian; every structure is naturally aligned and has no implicit padding. kernel64/host/test_virtio_gpu_layout.c
 * checks sizes and offsets against the host's <linux/virtio_gpu.h>.
 *
 * Used by gfx_virtio.c. Control queue = virtqueue 0, cursor queue = virtqueue 1. Every control request starts with a
 * vgpu_hdr_t and is answered with at least a vgpu_hdr_t whose type is VGPU_RESP_OK_* or VGPU_RESP_ERR_*.
 */
#ifndef K64_VIRTIO_GPU_H
#define K64_VIRTIO_GPU_H
#include <stdint.h>

/* feature bits */
#define VGPU_F_VIRGL 0                      /* 3D mode: virgl command streams (SUBMIT_3D), capsets */
#define VGPU_F_EDID 1
#define VGPU_F_RESOURCE_UUID 2
#define VGPU_F_RESOURCE_BLOB 3
#define VGPU_F_CONTEXT_INIT 4

enum {
    VGPU_CMD_GET_DISPLAY_INFO = 0x0100, VGPU_CMD_RESOURCE_CREATE_2D, VGPU_CMD_RESOURCE_UNREF, VGPU_CMD_SET_SCANOUT,
    VGPU_CMD_RESOURCE_FLUSH, VGPU_CMD_TRANSFER_TO_HOST_2D, VGPU_CMD_RESOURCE_ATTACH_BACKING, VGPU_CMD_RESOURCE_DETACH_BACKING,
    VGPU_CMD_GET_CAPSET_INFO, VGPU_CMD_GET_CAPSET, VGPU_CMD_GET_EDID,
    VGPU_CMD_CTX_CREATE = 0x0200, VGPU_CMD_CTX_DESTROY, VGPU_CMD_CTX_ATTACH_RESOURCE, VGPU_CMD_CTX_DETACH_RESOURCE,
    VGPU_CMD_RESOURCE_CREATE_3D, VGPU_CMD_TRANSFER_TO_HOST_3D, VGPU_CMD_TRANSFER_FROM_HOST_3D, VGPU_CMD_SUBMIT_3D,
    VGPU_CMD_UPDATE_CURSOR = 0x0300, VGPU_CMD_MOVE_CURSOR,
    VGPU_RESP_OK_NODATA = 0x1100, VGPU_RESP_OK_DISPLAY_INFO, VGPU_RESP_OK_CAPSET_INFO, VGPU_RESP_OK_CAPSET, VGPU_RESP_OK_EDID,
    VGPU_RESP_ERR_UNSPEC = 0x1200, VGPU_RESP_ERR_OUT_OF_MEMORY, VGPU_RESP_ERR_INVALID_SCANOUT_ID,
    VGPU_RESP_ERR_INVALID_RESOURCE_ID, VGPU_RESP_ERR_INVALID_CONTEXT_ID, VGPU_RESP_ERR_INVALID_PARAMETER,
};

#define VGPU_FLAG_FENCE 1u                  /* the device answers only once the command's work has completed */

typedef struct { uint32_t type, flags; uint64_t fence_id; uint32_t ctx_id; uint8_t ring_idx, pad[3]; } vgpu_hdr_t;   /* 24 */
typedef struct { uint32_t x, y, width, height; } vgpu_rect_t;

#define VGPU_MAX_SCANOUTS 16
typedef struct { vgpu_rect_t r; uint32_t enabled, flags; } vgpu_display_one_t;
typedef struct { vgpu_hdr_t hdr; vgpu_display_one_t pmodes[VGPU_MAX_SCANOUTS]; } vgpu_resp_display_info_t;

enum { VGPU_FORMAT_B8G8R8A8_UNORM = 1, VGPU_FORMAT_B8G8R8X8_UNORM = 2, VGPU_FORMAT_A8R8G8B8_UNORM = 3,
       VGPU_FORMAT_X8R8G8B8_UNORM = 4, VGPU_FORMAT_R8G8B8A8_UNORM = 67, VGPU_FORMAT_X8B8G8R8_UNORM = 68,
       VGPU_FORMAT_A8B8G8R8_UNORM = 121, VGPU_FORMAT_R8G8B8X8_UNORM = 134 };

typedef struct { vgpu_hdr_t hdr; uint32_t resource_id, format, width, height; } vgpu_resource_create_2d_t;
typedef struct { vgpu_hdr_t hdr; uint32_t resource_id, pad; } vgpu_resource_unref_t;
typedef struct { vgpu_hdr_t hdr; vgpu_rect_t r; uint32_t scanout_id, resource_id; } vgpu_set_scanout_t;
typedef struct { vgpu_hdr_t hdr; vgpu_rect_t r; uint32_t resource_id, pad; } vgpu_resource_flush_t;
typedef struct { vgpu_hdr_t hdr; vgpu_rect_t r; uint64_t offset; uint32_t resource_id, pad; } vgpu_transfer_to_host_2d_t;
typedef struct { uint64_t addr; uint32_t length, pad; } vgpu_mem_entry_t;
/* followed by nr_entries vgpu_mem_entry_t in the same (device-readable) part of the chain */
typedef struct { vgpu_hdr_t hdr; uint32_t resource_id, nr_entries; } vgpu_resource_attach_backing_t;
typedef struct { vgpu_hdr_t hdr; uint32_t resource_id, pad; } vgpu_resource_detach_backing_t;

typedef struct { vgpu_hdr_t hdr; uint32_t scanout, pad; } vgpu_get_edid_t;
typedef struct { vgpu_hdr_t hdr; uint32_t size, pad; uint8_t edid[1024]; } vgpu_resp_edid_t;

#define VGPU_CAPSET_VIRGL 1u
#define VGPU_CAPSET_VIRGL2 2u
typedef struct { vgpu_hdr_t hdr; uint32_t capset_index, pad; } vgpu_get_capset_info_t;
typedef struct { vgpu_hdr_t hdr; uint32_t capset_id, capset_max_version, capset_max_size, pad; } vgpu_resp_capset_info_t;
typedef struct { vgpu_hdr_t hdr; uint32_t capset_id, capset_version; } vgpu_get_capset_t;
/* response: vgpu_hdr_t followed by capset_max_size bytes */

/* 3D (only with VGPU_F_VIRGL) */
typedef struct { uint32_t x, y, z, w, h, d; } vgpu_box_t;
typedef struct { vgpu_hdr_t hdr; vgpu_box_t box; uint64_t offset; uint32_t resource_id, level, stride, layer_stride; } vgpu_transfer_host_3d_t;
typedef struct {
    vgpu_hdr_t hdr;
    uint32_t resource_id, target, format, bind, width, height, depth, array_size, last_level, nr_samples, flags, pad;
} vgpu_resource_create_3d_t;
typedef struct { vgpu_hdr_t hdr; uint32_t nlen, context_init; char debug_name[64]; } vgpu_ctx_create_t;
typedef struct { vgpu_hdr_t hdr; } vgpu_ctx_destroy_t;
typedef struct { vgpu_hdr_t hdr; uint32_t resource_id, pad; } vgpu_ctx_resource_t;
/* followed by `size` bytes of virgl command stream */
typedef struct { vgpu_hdr_t hdr; uint32_t size, pad; } vgpu_cmd_submit_t;

/* cursor queue (no response is written) */
typedef struct { uint32_t scanout_id, x, y, pad; } vgpu_cursor_pos_t;
typedef struct { vgpu_hdr_t hdr; vgpu_cursor_pos_t pos; uint32_t resource_id, hot_x, hot_y, pad; } vgpu_update_cursor_t;

/* device configuration space */
#define VGPU_CFG_EVENTS_READ 0
#define VGPU_CFG_EVENTS_CLEAR 4
#define VGPU_CFG_NUM_SCANOUTS 8
#define VGPU_CFG_NUM_CAPSETS 12
#define VGPU_EVENT_DISPLAY 1u
#endif
