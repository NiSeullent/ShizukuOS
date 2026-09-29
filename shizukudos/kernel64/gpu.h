/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 GPU internals shared by the virtio-gpu driver (gfx_virtio.c) and the GPU system calls (gpu_sys.c).
 * Every vg_* call below takes the driver lock itself; none may be called from interrupt context. They return an NTSTATUS
 * (STATUS_NO_SUCH_DEVICE when no virtio-gpu drives the display, STATUS_NOT_SUPPORTED when the feature was not negotiated,
 * STATUS_UNSUCCESSFUL when the device answered a command with an error, STATUS_IO_TIMEOUT when it did not answer).
 */
#ifndef K64_GPU_H
#define K64_GPU_H
#include "gfx.h"

#define STATUS_IO_TIMEOUT ((int32_t)0xC00000B5)

typedef struct { uint32_t x, y, z, w, h, d; } vg_box_t;

int vg_active(void);                                /* virtio-gpu is the display backend and has not failed */
int vg_has_virgl(void);
void vg_fill_info(shz_gpu_info_t *info);            /* device part of NtShzGpuQuery (lock taken inside) */
int32_t vg_get_edid(uint8_t *out, uint32_t cap, uint32_t *len);
/* argb = 64*64 kernel copy of the image for SHZ_GPU_CURSOR_SHAPE, NULL otherwise */
int32_t vg_cursor(uint32_t op, const uint32_t *argb, uint32_t hot_x, uint32_t hot_y, int32_t x, int32_t y);
int32_t vg_capset(uint32_t id, uint32_t version, void *out, uint32_t cap, uint32_t *len);
int32_t vg_ctx_create(uint32_t ctx, const char *name, uint32_t name_len);
int32_t vg_ctx_destroy(uint32_t ctx);
/* backing: gfx_pages_alloc() memory of `bytes`, owned by the caller; the resource is attached to `ctx` */
int32_t vg_res3d_create(uint32_t ctx, uint32_t res, const shz_gpu_res_t *a, void *backing, uint64_t bytes);
int32_t vg_res3d_destroy(uint32_t ctx, uint32_t res);
int32_t vg_submit3d(uint32_t ctx, const void *stream, uint32_t bytes);     /* stream: gfx_pages_alloc() memory */
int32_t vg_transfer3d(uint32_t ctx, uint32_t res, int to_host, const vg_box_t *box, uint32_t level, uint32_t stride,
                      uint32_t layer_stride);
#endif
