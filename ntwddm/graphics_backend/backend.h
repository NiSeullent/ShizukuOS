/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef NTG_BACKEND_H
#define NTG_BACKEND_H
#include "m98_softpipe_raster.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Private software resource ABI, never a D3D/DXGI feature-level declaration.
 * Calls are serialized globally; callback reentry returns BUSY. Callback
 * storage remains alive until destroy. Allocations must be disjoint, aligned,
 * live and exclusively owned until deallocate. Borrowed pointers must be valid.
 * Cookies are monotonic and not transferable to another device. Every failed
 * call preserves outputs/resources, except a caller explicitly mapped memory.
 * Mapped pointers cease to be valid at unmap. No asynchronous GPU work exists.
 */
enum { NTG_OK=0, NTG_INVALID=1, NTG_LIMIT=2, NTG_NOMEM=3,
       NTG_UNSUPPORTED=4, NTG_STALE=5, NTG_BUSY=6, NTG_BACKEND=7 };
enum { NTG_RGBA8=1, NTG_D32=2, NTG_SHADER=3 };
enum { NTG_MAX_DEVICES=4, NTG_MAX_RESOURCES=16, NTG_MAX_SIZE=64,
       NTG_TEXTURE_MEMORY_LIMIT=2097152 };
typedef uint64_t ntg_resource;
typedef struct {
 uint32_t abi,width,height,format,pitch,mip_levels,array_size,samples,flags;
} ntg_texture_desc;
typedef struct {
 void *pixels; size_t bytes; uint32_t width,height,pitch,format;
} ntg_mapping;
typedef struct {
 uint32_t abi,varying_count,quad_budget,depth_test,depth_write,blend,reserved[2];
 m98_r_vertex vertex[3]; float constant[M98_SP_MAX_CONSTANTS][4];
} ntg_draw_desc;
/* Own renderable RGBA8/D32 attachments, shader object and target binding.
 * One mip/layer/sample is supported; other requests fail before allocation.
 * Texture maps are exclusive. Bound targets cannot be mapped; copied textures
 * may be mapped after unbinding. Bind retains each object until replacement.
 * Release drops a caller reference, never the separate binding reference.
 * Destroy refuses outstanding maps and releases all remaining owned objects.
 * The 2 MiB/device cap covers owned texture bytes only. Mesa separately caps
 * each shader context at 4 MiB, with at most 16 globally live contexts; raster
 * scratch is at most 32 KiB per synchronous draw. These are separate budgets,
 * not a 2 MiB total device-memory claim. All API results use NTG status codes.
 * Every allocate/free/math callback runs in its own nearest/masked x87/MXCSR
 * scope. Changed callback FP state cannot affect later Mesa arithmetic; the
 * public call restores the external caller state. Callback math must still
 * return a real computed result/error for the requested operation.
 */
uint32_t ntg_abi(void);
int ntg_create(const m98_sp_callbacks *,uint32_t *device);
int ntg_destroy(uint32_t *device);
int ntg_texture_create(uint32_t,const ntg_texture_desc *,ntg_resource *);
int ntg_shader_create(uint32_t,const m98_sp_program *,ntg_resource *);
int ntg_retain(uint32_t,ntg_resource);
int ntg_release(uint32_t,ntg_resource *);
int ntg_map(uint32_t,ntg_resource,ntg_mapping *);
int ntg_unmap(uint32_t,ntg_resource);
int ntg_clear_color(uint32_t,ntg_resource,const uint8_t rgba[4]);
int ntg_clear_depth(uint32_t,ntg_resource,float depth);
int ntg_copy(uint32_t,ntg_resource source,ntg_resource target);
int ntg_bind(uint32_t,ntg_resource color,ntg_resource depth,ntg_resource shader);
int ntg_draw(uint32_t,const ntg_draw_desc *,m98_r_stats *);
#ifdef __cplusplus
}
#endif
#endif
