/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_SOFTPIPE_RASTER_H
#define M98_SOFTPIPE_RASTER_H
#include "m98_softpipe_shader.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Private single-triangle software raster slice, not a GL/browser API.
 * Top-left y-down target; exact 1/16-pixel vertices and center samples.
 * Strides/capacities describe live, exclusive caller buffers. RGBA is straight
 * UNORM8; depth is float32 in [0,1]. Both attachments are mandatory; their
 * full declared capacity spans and the stats object must be mutually disjoint.
 * Shader cookie/table/user and target buffers remain valid and unmodified
 * throughout draw; returned allocator blocks are exclusively component-owned
 * until deallocate. Descriptor/vertices/constants are copied before callbacks.
 * Failure preserves attachment pixels, padding and stats. Calls are serialized;
 * callback reentry/concurrent calls return BUSY before shared state is read.
 * Each m98_r_ops callback starts with nearest-even masked arithmetic, and its
 * changed environment cannot affect subsequent raster operations. Nested
 * trusted Mesa shader heap/math providers must preserve their internal FP
 * environment; the frozen shader does not scope those providers individually.
 * Empty/degenerate draws dispatch no shader and do not validate a stale cookie.
 */
enum { M98_R_OK=0,M98_R_INVALID=1,M98_R_LIMIT=2,M98_R_NOMEM=3,
 M98_R_UNSUPPORTED=4,M98_R_BUSY=5,M98_R_BAD_OUTPUT=6,
 M98_R_SHADER_ERROR_BASE=100 };
enum { M98_R_DEPTH_OFF=0,M98_R_DEPTH_LESS=1,M98_R_DEPTH_LEQUAL=2,
 M98_R_DEPTH_ALWAYS=3 };
enum { M98_R_REPLACE=0,M98_R_SOURCE_OVER=1 };
enum { M98_R_MAX_WIDTH=64,M98_R_MAX_HEIGHT=64,M98_R_MAX_QUADS=1024,
 M98_R_MAX_COORD16=4096,M98_R_MAX_COLOR_STRIDE=4096,
 M98_R_MAX_DEPTH_STRIDE=1024 };
typedef struct {
 int32_t x16,y16;float z;float varying[M98_SP_MAX_INPUTS][4];
} m98_r_vertex;
typedef struct {
 uint32_t width,height,color_stride,color_capacity,depth_stride,depth_capacity;
 uint8_t *color;float *depth;
} m98_r_surface;
typedef struct {
 uint32_t abi,shader_cookie,varying_count,quad_budget,depth_test,depth_write,blend,reserved;
 m98_r_surface surface;m98_r_vertex vertex[3];
 float constant[M98_SP_MAX_CONSTANTS][4];
} m98_r_draw;
typedef struct {
 uint32_t abi,reserved;void *user;
 void *(*allocate)(void *,size_t);void (*deallocate)(void *,void *);
 int (*run_shader)(uint32_t,const m98_sp_io *,m98_sp_result *);
} m98_r_ops;
typedef struct {
 uint32_t covered_samples,shader_quads,depth_rejected_samples,
 discarded_samples,written_samples,scratch_bytes;
} m98_r_stats;
/* quad_budget reserves covered geometry quads before allocation. Depth may
 * reject samples before shading; shaders cannot write depth in this profile.
 * Exactly one RGBA output is required. Helper quad lanes preserve derivatives;
 * only returned live covered/depth-passing lanes modify attachments.
 * Source-over is a defined byte-domain straight-alpha composition, not an
 * arbitrary OpenGL blend equation or sRGB operation. Perspective/MSAA/stencil/
 * textures/GLSL/GLES/WebGL2/WebGPU/browser/native integration remain absent.
 */
int m98_raster_draw(const m98_r_draw *,const m98_r_ops *,m98_r_stats *);
uint32_t m98_raster_abi(void);
#ifdef __cplusplus
}
#endif
#endif
