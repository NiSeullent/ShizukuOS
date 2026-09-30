/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku GPU interface: the Kernel64 <-> user-mode ABI of the display/GPU system calls 0xd0-0xdf (kernel64/gpu_sys.c,
 * ntsys.h SYSCALL_LIST_GPU) and the API of shzgpu.dll (win64/dlls/shzgpu), a Shizuku-specific library. It is NOT a
 * Windows API: there is no D3D, DXGI, OpenGL ICD or Vulkan ICD in this system (see docs/shizukudos10/GPU.md).
 *
 * Backends (chosen once at boot by kernel64/gfx_fb.c: the first one whose device is present):
 *   SHZ_GPU_BACKEND_VIRTIO  paravirtual virtio-gpu (QEMU -device virtio-vga / virtio-gpu-pci). The desktop is a host-side
 *                           2D resource; the kernel sends TRANSFER_TO_HOST_2D + RESOURCE_FLUSH for each damaged
 *                           rectangle only. Hardware cursor plane, EDID. With the VIRGL feature (QEMU virtio-vga-gl on a
 *                           host with a GL-capable display) also 3D contexts that execute virgl command streams on the
 *                           host GPU: that is the accelerated path.
 *   SHZ_GPU_BACKEND_BGA     Bochs VBE linear framebuffer (QEMU -vga std): the CPU copies damaged rectangles; no cursor, no 3D.
 *   SHZ_GPU_BACKEND_GOP     after a UEFI direct boot: the firmware's GOP linear framebuffer in the firmware's mode (any
 *                           PCI display or a RAM framebuffer; BGRX or RGBX): the CPU copies damaged rectangles; no cursor,
 *                           no 3D, no mode setting.
 * Everything here is fixed-width so the freestanding kernel and mingw-w64 user code share it. Pointers are user virtual
 * addresses carried in uint64_t. Status values are NTSTATUS: STATUS_NO_SUCH_DEVICE (0xC000000E) without any display,
 * STATUS_NOT_SUPPORTED (0xC00000BB) when the backend lacks the feature (cursor on BGA, 3D without VIRGL).
 */
#ifndef SHZ_GPU_ABI_H
#define SHZ_GPU_ABI_H
#include <stdint.h>

#define SHZ_GPU_BACKEND_NONE 0u
#define SHZ_GPU_BACKEND_BGA 1u
#define SHZ_GPU_BACKEND_VIRTIO 2u
#define SHZ_GPU_BACKEND_GOP 3u              /* the UEFI GOP framebuffer the boot manager handed over (kernel64/gfx_gop.c) */

#define SHZ_GPU_FEAT_2D 0x01u               /* host-side scanout resource updated by transfer + flush of dirty rectangles */
#define SHZ_GPU_FEAT_CURSOR 0x02u           /* hardware cursor plane (64x64 ARGB) */
#define SHZ_GPU_FEAT_EDID 0x04u             /* EDID of scanout 0 available through ShzGpuGetEdid */
#define SHZ_GPU_FEAT_VIRGL 0x08u            /* VIRTIO_GPU_F_VIRGL negotiated: 3D contexts, SUBMIT_3D, capsets */
#define SHZ_GPU_FEAT_IRQ 0x10u              /* command completion is signalled by interrupt (otherwise polled) */

/* Counters since boot. `presents` counts every rectangle the compositor pushed to the display (both backends); the
 * others are virtio-gpu commands. A small invalidation must cost one small transfer, never a full frame. */
typedef struct {
    uint64_t presents, present_pixels;
    uint64_t transfers_2d, transfer_bytes, flushes;
    uint64_t ctrl_cmds, cursor_cmds, notifies, irqs, errors;
    uint64_t submits_3d, submit_bytes, transfers_3d;
} shz_gpu_stats_t;

typedef struct {
    uint32_t size;                          /* sizeof(shz_gpu_info_t), set by the caller */
    uint32_t backend;                       /* SHZ_GPU_BACKEND_* */
    uint32_t features;                      /* SHZ_GPU_FEAT_* */
    uint32_t width, height, pitch;          /* desktop mode (32 bpp 0x00RRGGBB) */
    uint32_t host_width, host_height;       /* scanout 0 mode the device reports (GET_DISPLAY_INFO), 0 if none */
    uint32_t num_scanouts, num_capsets;
    uint32_t edid_size;                     /* bytes of EDID held by the kernel (0 = none) */
    uint32_t edid_pref_width, edid_pref_height;     /* first detailed timing descriptor */
    char edid_vendor[4];                    /* PNP manufacturer id, e.g. "RHT" */
    uint32_t capset_id[4], capset_max_version[4], capset_max_size[4];
    uint16_t pci_vendor, pci_device;
    uint32_t pad;
    uint64_t device_features, driver_features;      /* virtio feature bits offered / accepted */
    shz_gpu_stats_t stats;
} shz_gpu_info_t;

/* NtShzGpuCursor */
#define SHZ_GPU_CURSOR_W 64u
#define SHZ_GPU_CURSOR_H 64u
enum { SHZ_GPU_CURSOR_SHAPE = 1, SHZ_GPU_CURSOR_MOVE = 2, SHZ_GPU_CURSOR_HIDE = 3 };
typedef struct {
    uint32_t op;                            /* SHZ_GPU_CURSOR_* */
    int32_t x, y;                           /* screen position of the hot spot (SHAPE, MOVE) */
    uint32_t hot_x, hot_y;                  /* SHAPE */
    uint32_t pad;
    uint64_t pixels;                        /* SHAPE: 64*64 uint32 0xAARRGGBB, rows top to bottom */
} shz_gpu_cursor_t;

/* NtShzGpuCapset: copies the host's capability set (virgl: struct virgl_caps_v1/v2 of virgl_hw.h). */
typedef struct { uint32_t id, version; uint64_t buf; uint32_t buf_len, out_len; } shz_gpu_capset_t;
#define SHZ_GPU_CAPSET_VIRGL 1u
#define SHZ_GPU_CAPSET_VIRGL2 2u

/* NtShzGpuResourceCreate: a virgl resource (virtio-gpu RESOURCE_CREATE_3D) with kernel-owned guest backing, attached to
 * the context. Values are Gallium/virgl ones (SHZ_PIPE_*, SHZ_VIRGL_FORMAT_*, SHZ_VIRGL_BIND_* in shzvirgl.h). The
 * backing holds width*height*depth*array_size*4 bytes for textures (32-bit formats only) or width bytes for buffers. */
typedef struct {
    uint32_t ctx, target, format, bind, width, height, depth, array_size;
    uint32_t res;                           /* out */
    uint32_t pad;
    uint64_t backing_bytes;                 /* out */
} shz_gpu_res_t;

/* NtShzGpuTransfer: TRANSFER_TO_HOST_3D copies `data` into the backing first; TRANSFER_FROM_HOST_3D copies the backing to
 * `data` afterwards. The box is written to / read from backing offset 0 with the given row stride. */
enum { SHZ_GPU_TO_HOST = 1, SHZ_GPU_FROM_HOST = 2 };
typedef struct {
    uint32_t ctx, res, direction, level;
    uint32_t x, y, z, w, h, d;
    uint32_t stride, layer_stride;
    uint64_t data;                          /* user buffer */
    uint64_t data_len;
} shz_gpu_xfer_t;

#define SHZ_GPU_MAX_CONTEXTS 8u
#define SHZ_GPU_MAX_RESOURCES 32u
#define SHZ_GPU_MAX_SUBMIT (256u << 10)     /* bytes per NtShzGpuSubmit */
#define SHZ_GPU_MAX_BACKING (16u << 20)     /* bytes per 3D resource */

#ifdef _WIN32
/* ---- system calls (ntdll stubs generated from SYSCALL_LIST_GPU) */
#define SHZ_GPU_NT __stdcall
int32_t SHZ_GPU_NT NtShzGpuQuery(shz_gpu_info_t *info);
int32_t SHZ_GPU_NT NtShzGpuEdid(void *buf, uint64_t len, uint32_t *out_len);
int32_t SHZ_GPU_NT NtShzGpuCursor(const shz_gpu_cursor_t *c);
int32_t SHZ_GPU_NT NtShzGpuCapset(shz_gpu_capset_t *c);
int32_t SHZ_GPU_NT NtShzGpuCtxCreate(const char *debug_name, uint32_t *ctx_out);
int32_t SHZ_GPU_NT NtShzGpuCtxDestroy(uint64_t ctx);
int32_t SHZ_GPU_NT NtShzGpuResourceCreate(shz_gpu_res_t *r);
int32_t SHZ_GPU_NT NtShzGpuResourceDestroy(uint64_t res);
int32_t SHZ_GPU_NT NtShzGpuSubmit(uint64_t ctx, const void *stream, uint64_t bytes);
int32_t SHZ_GPU_NT NtShzGpuTransfer(shz_gpu_xfer_t *x);

/* ---- shzgpu.dll: thin, documented wrappers. Every function returns an NTSTATUS (>= 0 success). */
#ifdef BUILDING_SHZGPU
#define SHZGPU_API __declspec(dllexport)
#else
#define SHZGPU_API __declspec(dllimport)
#endif
/* Fills *info (info->size is set by the function). */
SHZGPU_API int32_t __stdcall ShzGpuQuery(shz_gpu_info_t *info);
/* Copies up to `len` bytes of the EDID of scanout 0; *out_len = bytes available. */
SHZGPU_API int32_t __stdcall ShzGpuGetEdid(uint8_t *buf, uint32_t len, uint32_t *out_len);
/* Hardware cursor: 64x64 0xAARRGGBB image with its hot spot, shown with the hot spot at (x, y). */
SHZGPU_API int32_t __stdcall ShzGpuSetCursor(const uint32_t *argb64x64, uint32_t hot_x, uint32_t hot_y, int32_t x, int32_t y);
SHZGPU_API int32_t __stdcall ShzGpuMoveCursor(int32_t x, int32_t y);
SHZGPU_API int32_t __stdcall ShzGpuHideCursor(void);
/* Host capability set `id` (SHZ_GPU_CAPSET_*) at `version` into buf; *out_len = bytes the host has. */
SHZGPU_API int32_t __stdcall ShzGpuGetCapset(uint32_t id, uint32_t version, void *buf, uint32_t len, uint32_t *out_len);
/* 3D (virgl): contexts, resources, command submission, transfers. The stream format is shzvirgl.h's. */
SHZGPU_API int32_t __stdcall ShzGpuCreateContext(const char *debug_name, uint32_t *ctx);
SHZGPU_API int32_t __stdcall ShzGpuDestroyContext(uint32_t ctx);
SHZGPU_API int32_t __stdcall ShzGpuCreateResource(shz_gpu_res_t *r);
SHZGPU_API int32_t __stdcall ShzGpuDestroyResource(uint32_t res);
SHZGPU_API int32_t __stdcall ShzGpuSubmit(uint32_t ctx, const uint32_t *stream, uint32_t dwords);
SHZGPU_API int32_t __stdcall ShzGpuReadback(uint32_t ctx, uint32_t res, uint32_t w, uint32_t h, void *pixels, uint32_t stride);
SHZGPU_API int32_t __stdcall ShzGpuUpload(uint32_t ctx, uint32_t res, uint32_t x, uint32_t w, const void *data);
#endif
#endif
