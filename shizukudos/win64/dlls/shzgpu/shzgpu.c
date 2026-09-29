/* SPDX-License-Identifier: GPL-2.0-only
 * shzgpu.dll - the Shizuku-specific user-mode GPU API (declared and documented in win64/include/shzgpu.h).
 *
 * This is a thin layer over the GPU system calls 0xd0-0xdf (NtShzGpu*, kernel64/gpu_sys.c): it validates arguments,
 * fills the request structures and returns the kernel's NTSTATUS unchanged. It is NOT a Windows graphics API (no D3D,
 * DXGI, OpenGL ICD, Vulkan ICD); programs that want 3D build a virgl command stream with win64/include/shzvirgl.h and
 * submit it with ShzGpuSubmit, which is the interface a future OpenGL/D3D user-mode driver would sit on
 * (docs/shizukudos10/GPU.md). What a call can do depends on the backend the kernel chose:
 *   virtio-gpu        query, EDID, hardware cursor; with VIRGL also capsets, contexts, resources, submit, transfers
 *   Bochs VBE         query only (cursor and 3D calls fail with STATUS_NOT_SUPPORTED)
 *   no display        every call fails with STATUS_NO_SUCH_DEVICE
 */
#include "nt.h"
#include "shzgpu.h"

DLLAPI int32_t __stdcall ShzGpuQuery(shz_gpu_info_t *info)
{
    unsigned i;
    if (!info) return STATUS_INVALID_PARAMETER;
    for (i = 0; i < sizeof *info; ++i) ((volatile uint8_t *)info)[i] = 0;
    info->size = sizeof *info;
    return NtShzGpuQuery(info);
}

DLLAPI int32_t __stdcall ShzGpuGetEdid(uint8_t *buf, uint32_t len, uint32_t *out_len)
{
    if (!buf && len) return STATUS_INVALID_PARAMETER;
    return NtShzGpuEdid(buf, len, out_len);
}

DLLAPI int32_t __stdcall ShzGpuSetCursor(const uint32_t *argb64x64, uint32_t hot_x, uint32_t hot_y, int32_t x, int32_t y)
{
    shz_gpu_cursor_t c;
    if (!argb64x64 || hot_x >= SHZ_GPU_CURSOR_W || hot_y >= SHZ_GPU_CURSOR_H) return STATUS_INVALID_PARAMETER;
    c.op = SHZ_GPU_CURSOR_SHAPE;
    c.x = x;
    c.y = y;
    c.hot_x = hot_x;
    c.hot_y = hot_y;
    c.pad = 0;
    c.pixels = (uint64_t)(uintptr_t)argb64x64;
    return NtShzGpuCursor(&c);
}

DLLAPI int32_t __stdcall ShzGpuMoveCursor(int32_t x, int32_t y)
{
    shz_gpu_cursor_t c = { SHZ_GPU_CURSOR_MOVE, x, y, 0, 0, 0, 0 };
    return NtShzGpuCursor(&c);
}

DLLAPI int32_t __stdcall ShzGpuHideCursor(void)
{
    shz_gpu_cursor_t c = { SHZ_GPU_CURSOR_HIDE, 0, 0, 0, 0, 0, 0 };
    return NtShzGpuCursor(&c);
}

DLLAPI int32_t __stdcall ShzGpuGetCapset(uint32_t id, uint32_t version, void *buf, uint32_t len, uint32_t *out_len)
{
    shz_gpu_capset_t c;
    int32_t st;
    if (!buf && len) return STATUS_INVALID_PARAMETER;
    c.id = id;
    c.version = version;
    c.buf = (uint64_t)(uintptr_t)buf;
    c.buf_len = len;
    c.out_len = 0;
    st = NtShzGpuCapset(&c);
    if (out_len) *out_len = c.out_len;
    return st;
}

DLLAPI int32_t __stdcall ShzGpuCreateContext(const char *debug_name, uint32_t *ctx)
{
    if (!ctx) return STATUS_INVALID_PARAMETER;
    return NtShzGpuCtxCreate(debug_name, ctx);
}

DLLAPI int32_t __stdcall ShzGpuDestroyContext(uint32_t ctx) { return NtShzGpuCtxDestroy(ctx); }

DLLAPI int32_t __stdcall ShzGpuCreateResource(shz_gpu_res_t *r)
{
    if (!r) return STATUS_INVALID_PARAMETER;
    return NtShzGpuResourceCreate(r);
}

DLLAPI int32_t __stdcall ShzGpuDestroyResource(uint32_t res) { return NtShzGpuResourceDestroy(res); }

DLLAPI int32_t __stdcall ShzGpuSubmit(uint32_t ctx, const uint32_t *stream, uint32_t dwords)
{
    if (!stream || !dwords) return STATUS_INVALID_PARAMETER;
    return NtShzGpuSubmit(ctx, stream, (uint64_t)dwords * 4u);
}

/* Reads a w x h region at (0,0) of a 2D resource into `pixels` (rows `stride` bytes apart) with TRANSFER_FROM_HOST_3D. */
DLLAPI int32_t __stdcall ShzGpuReadback(uint32_t ctx, uint32_t res, uint32_t w, uint32_t h, void *pixels, uint32_t stride)
{
    shz_gpu_xfer_t x;
    if (!pixels || !w || !h || stride < w * 4u) return STATUS_INVALID_PARAMETER;
    x.ctx = ctx; x.res = res; x.direction = SHZ_GPU_FROM_HOST; x.level = 0;
    x.x = 0; x.y = 0; x.z = 0; x.w = w; x.h = h; x.d = 1;
    x.stride = stride; x.layer_stride = 0;
    x.data = (uint64_t)(uintptr_t)pixels;
    x.data_len = (uint64_t)stride * h;
    return NtShzGpuTransfer(&x);
}

/* Writes `w` bytes of `data` to a buffer resource at byte offset `x` with TRANSFER_TO_HOST_3D. */
DLLAPI int32_t __stdcall ShzGpuUpload(uint32_t ctx, uint32_t res, uint32_t x, uint32_t w, const void *data)
{
    shz_gpu_xfer_t t;
    if (!data || !w) return STATUS_INVALID_PARAMETER;
    t.ctx = ctx; t.res = res; t.direction = SHZ_GPU_TO_HOST; t.level = 0;
    t.x = x; t.y = 0; t.z = 0; t.w = w; t.h = 1; t.d = 1;
    t.stride = 0; t.layer_stride = 0;
    t.data = (uint64_t)(uintptr_t)data;
    t.data_len = w;
    return NtShzGpuTransfer(&t);
}
