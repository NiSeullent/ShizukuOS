/* SPDX-License-Identifier: GPL-2.0-only
 * shzvirgl.h - header-only encoder for the virgl 3D command stream, i.e. the payload of the virtio-gpu command
 * VIRTIO_GPU_CMD_SUBMIT_3D that the host's virglrenderer decodes (src/vrend_decode.c) and executes with the host GPU
 * driver (OpenGL). It is used by shzgpu.dll (user mode) and by the host tests (kernel64/host/test_virgl_enc.c decodes
 * what it writes with the pinned upstream protocol header; kernel64/host/test_virgl_exec.c feeds the same stream to the
 * host's libvirglrenderer and reads the rendered pixels back).
 *
 * Written from the protocol description, not copied: every value below is re-declared here under a SHZ_VIRGL_ name and
 * the unit test compares each one with virglrenderer 1.0.0's virgl_protocol.h / virgl_hw.h (third_party/virglrenderer-1.0.0,
 * MIT). Gallium enum values (PIPE_*) are those of Mesa's p_defines.h, which virgl carries unchanged.
 *
 * Stream format: a sequence of packets, each one header dword  cmd | object_type << 8 | payload_dwords << 16  followed by
 * payload_dwords dwords. Offsets named in the comments ("[1] handle") are payload positions counted from the header (the
 * header itself is [0]), which is how virgl_protocol.h numbers them.
 *
 * Only what a minimal draw needs is here: surfaces, framebuffer, blend/DSA/rasterizer state, TGSI shaders (sent as TGSI
 * TEXT, which is what virgl transports; the host translates TGSI to GLSL), vertex elements and buffers, inline buffer
 * writes, viewport, clear and non-indexed draws. No textures/samplers, queries, streamout, compute or indexed draws.
 * Freestanding: no libc, no allocation; the caller provides the dword buffer.
 */
#ifndef SHZ_VIRGL_H
#define SHZ_VIRGL_H
#include <stdint.h>

/* ---- virgl_context_cmd (virgl_protocol.h) */
#define SHZ_VIRGL_CCMD_NOP 0u
#define SHZ_VIRGL_CCMD_CREATE_OBJECT 1u
#define SHZ_VIRGL_CCMD_BIND_OBJECT 2u
#define SHZ_VIRGL_CCMD_DESTROY_OBJECT 3u
#define SHZ_VIRGL_CCMD_SET_VIEWPORT_STATE 4u
#define SHZ_VIRGL_CCMD_SET_FRAMEBUFFER_STATE 5u
#define SHZ_VIRGL_CCMD_SET_VERTEX_BUFFERS 6u
#define SHZ_VIRGL_CCMD_CLEAR 7u
#define SHZ_VIRGL_CCMD_DRAW_VBO 8u
#define SHZ_VIRGL_CCMD_RESOURCE_INLINE_WRITE 9u
#define SHZ_VIRGL_CCMD_SET_SUB_CTX 28u
#define SHZ_VIRGL_CCMD_CREATE_SUB_CTX 29u
#define SHZ_VIRGL_CCMD_DESTROY_SUB_CTX 30u
#define SHZ_VIRGL_CCMD_BIND_SHADER 31u

/* ---- virgl_object_type */
#define SHZ_VIRGL_OBJECT_BLEND 1u
#define SHZ_VIRGL_OBJECT_RASTERIZER 2u
#define SHZ_VIRGL_OBJECT_DSA 3u
#define SHZ_VIRGL_OBJECT_SHADER 4u
#define SHZ_VIRGL_OBJECT_VERTEX_ELEMENTS 5u
#define SHZ_VIRGL_OBJECT_SURFACE 8u

/* ---- payload sizes in dwords (header excluded) */
#define SHZ_VIRGL_BLEND_SIZE 11u                    /* handle, S0, S1, S2[8] */
#define SHZ_VIRGL_DSA_SIZE 5u                       /* handle, S0, S1, S2, alpha_ref */
#define SHZ_VIRGL_RS_SIZE 9u                        /* handle, S0, point_size, sprite_coord_enable, S3, line_width, offset x3 */
#define SHZ_VIRGL_SURFACE_SIZE 5u                   /* handle, res, format, level|first_elem, layers|last_elem */
#define SHZ_VIRGL_SHADER_HDR_SIZE 5u                /* handle, type, offset/len, num_tokens, num_so_outputs (=0) */
#define SHZ_VIRGL_CLEAR_SIZE 8u                     /* buffers, color f32 x4, depth f64 (2 dwords), stencil */
#define SHZ_VIRGL_VIEWPORT_SIZE(n) (1u + 6u * (n))  /* start_slot, then scale[3] translate[3] per viewport */
#define SHZ_VIRGL_FRAMEBUFFER_SIZE(n) (2u + (n))    /* nr_cbufs, zsurf, cbufs[n] */
#define SHZ_VIRGL_VE_SIZE(n) (1u + 4u * (n))        /* handle, then src_offset, instance_divisor, vb_index, format */
#define SHZ_VIRGL_VB_SIZE(n) (3u * (n))             /* stride, offset, res per buffer */
#define SHZ_VIRGL_DRAW_VBO_SIZE 12u
#define SHZ_VIRGL_INLINE_WRITE_HDR 11u              /* res, level, usage, stride, layer_stride, x, y, z, w, h, d */
#define SHZ_VIRGL_BIND_SHADER_SIZE 2u               /* handle, type */
#define SHZ_VIRGL_SHADER_OFFSET_CONT 0x80000000u

/* ---- virgl_formats / VIRGL_BIND_* (virgl_hw.h) */
#define SHZ_VIRGL_FORMAT_B8G8R8A8_UNORM 1u
#define SHZ_VIRGL_FORMAT_B8G8R8X8_UNORM 2u
#define SHZ_VIRGL_FORMAT_R32G32_FLOAT 29u
#define SHZ_VIRGL_FORMAT_R32G32B32A32_FLOAT 31u
#define SHZ_VIRGL_FORMAT_R8_UNORM 64u
#define SHZ_VIRGL_BIND_RENDER_TARGET (1u << 1)
#define SHZ_VIRGL_BIND_SAMPLER_VIEW (1u << 3)
#define SHZ_VIRGL_BIND_VERTEX_BUFFER (1u << 4)
#define SHZ_VIRGL_BIND_CONSTANT_BUFFER (1u << 6)
#define SHZ_VIRGL_BIND_DISPLAY_TARGET (1u << 7)

/* ---- Gallium enums used in the stream (Mesa p_defines.h) */
#define SHZ_PIPE_BUFFER 0u
#define SHZ_PIPE_TEXTURE_2D 2u
#define SHZ_PIPE_SHADER_VERTEX 0u
#define SHZ_PIPE_SHADER_FRAGMENT 1u
#define SHZ_PIPE_PRIM_TRIANGLES 4u
#define SHZ_PIPE_CLEAR_DEPTH (1u << 0)
#define SHZ_PIPE_CLEAR_STENCIL (1u << 1)
#define SHZ_PIPE_CLEAR_COLOR0 (1u << 2)
#define SHZ_PIPE_MASK_RGBA 0xfu

/* Encoder state. `len` counts dwords written; once a packet does not fit, `overflow` is set, nothing more is written and
 * the stream must not be submitted. */
typedef struct {
    uint32_t *buf;
    uint32_t cap, len;
    int overflow;
} shz_virgl_cs_t;

static inline void shz_virgl_init(shz_virgl_cs_t *cs, uint32_t *buf, uint32_t cap_dwords)
{
    cs->buf = buf;
    cs->cap = cap_dwords;
    cs->len = 0;
    cs->overflow = 0;
}

static inline uint32_t shz_virgl_hdr(uint32_t cmd, uint32_t obj, uint32_t len) { return cmd | (obj << 8) | (len << 16); }
static inline uint32_t shz_virgl_f32(float f) { union { float f; uint32_t u; } v; v.f = f; return v.u; }

/* Reserves one packet (header + `len` payload dwords, len < 65536) and returns a pointer to payload [1] (the header is
 * already written at [0]); NULL on overflow. */
static inline uint32_t *shz_virgl_packet(shz_virgl_cs_t *cs, uint32_t cmd, uint32_t obj, uint32_t len)
{
    uint32_t *p;
    if (cs->overflow || len > 0xffffu || len + 1u > cs->cap - cs->len) {
        cs->overflow = 1;
        return 0;
    }
    p = cs->buf + cs->len;
    p[0] = shz_virgl_hdr(cmd, obj, len);
    cs->len += len + 1u;
    return p + 1;
}

/* ---- objects */
/* Render-target view of a texture: [1] handle [2] res [3] format [4] level [5] first_layer | last_layer << 16. */
static inline void shz_virgl_create_surface(shz_virgl_cs_t *cs, uint32_t handle, uint32_t res, uint32_t format, uint32_t level)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_SURFACE, SHZ_VIRGL_SURFACE_SIZE);
    if (!p) return;
    p[0] = handle; p[1] = res; p[2] = format; p[3] = level; p[4] = 0;
}

/* Blending off, colour write mask on all eight render targets. S2 per target: blend_enable bit 0, rgb_func 1-3,
 * rgb_src 4-8, rgb_dst 9-13, alpha_func 14-16, alpha_src 17-21, alpha_dst 22-26, colormask 27-30. */
static inline void shz_virgl_create_blend_opaque(shz_virgl_cs_t *cs, uint32_t handle, uint32_t colormask)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_BLEND, SHZ_VIRGL_BLEND_SIZE);
    unsigned i;
    if (!p) return;
    p[0] = handle;
    p[1] = 0;                                       /* S0: independent blend, logicop, dither, alpha-to-coverage/one off */
    p[2] = 0;                                       /* S1: logicop func */
    for (i = 0; i < 8; ++i) p[3 + i] = (colormask & 0xfu) << 27;
}

/* Depth, stencil and alpha test all disabled. */
static inline void shz_virgl_create_dsa_off(shz_virgl_cs_t *cs, uint32_t handle)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_DSA, SHZ_VIRGL_DSA_SIZE);
    if (!p) return;
    p[0] = handle; p[1] = 0; p[2] = 0; p[3] = 0; p[4] = 0;
}

#define SHZ_VIRGL_RS_DEPTH_CLIP (1u << 1)
#define SHZ_VIRGL_RS_FRONT_CCW (1u << 15)
#define SHZ_VIRGL_RS_HALF_PIXEL_CENTER (1u << 29)
/* Filled polygons, no culling, no offsets, point size and line width 1. `s0` adds SHZ_VIRGL_RS_* bits. */
static inline void shz_virgl_create_rasterizer(shz_virgl_cs_t *cs, uint32_t handle, uint32_t s0)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_RASTERIZER, SHZ_VIRGL_RS_SIZE);
    if (!p) return;
    p[0] = handle;
    p[1] = s0;                                      /* cull_face 8-9 = 0 (none), fill_front 10-11 = fill_back 12-13 = 0 (fill) */
    p[2] = shz_virgl_f32(1.0f);                     /* point_size */
    p[3] = 0;                                       /* sprite_coord_enable */
    p[4] = 0;                                       /* S3: line stipple, clip plane enable */
    p[5] = shz_virgl_f32(1.0f);                     /* line_width */
    p[6] = p[7] = p[8] = 0;                         /* polygon offset units, scale, clamp */
}

static inline void shz_virgl_bind_object(shz_virgl_cs_t *cs, uint32_t type, uint32_t handle)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_BIND_OBJECT, type, 1);
    if (p) p[0] = handle;
}

static inline uint32_t shz_virgl_strlen(const char *s) { uint32_t n = 0; while (s[n]) ++n; return n; }

/* A shader given as TGSI text, sent in one packet: [1] handle [2] type [3] text length incl. NUL (a first packet; the
 * CONT bit would mark a continuation) [4] num_tokens [5] number of stream-output outputs (0), then the text padded with
 * zero bytes to a dword boundary. num_tokens is the size of the binary TGSI the host allocates for the translation; the
 * text is not tokenised here, so a generous bound derived from the line count is sent (the host adds 10 more). */
static inline void shz_virgl_create_shader_tgsi(shz_virgl_cs_t *cs, uint32_t handle, uint32_t type, const char *text)
{
    const uint32_t bytes = shz_virgl_strlen(text) + 1u, dws = (bytes + 3u) / 4u;
    uint32_t lines = 1, i, *p;
    uint8_t *d;
    for (i = 0; i < bytes; ++i) lines += text[i] == '\n';
    p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_SHADER, SHZ_VIRGL_SHADER_HDR_SIZE + dws);
    if (!p) return;
    p[0] = handle;
    p[1] = type;
    p[2] = bytes;
    p[3] = 32u * (lines + 1u);
    p[4] = 0;
    d = (uint8_t *)(p + 5);
    for (i = 0; i < dws * 4u; ++i) d[i] = i < bytes ? (uint8_t)text[i] : 0;
}

static inline void shz_virgl_bind_shader(shz_virgl_cs_t *cs, uint32_t handle, uint32_t type)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_BIND_SHADER, 0, SHZ_VIRGL_BIND_SHADER_SIZE);
    if (!p) return;
    p[0] = handle; p[1] = type;
}

typedef struct { uint32_t src_offset, instance_divisor, vertex_buffer_index, src_format; } shz_virgl_ve_t;
static inline void shz_virgl_create_vertex_elements(shz_virgl_cs_t *cs, uint32_t handle, uint32_t n, const shz_virgl_ve_t *ve)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CREATE_OBJECT, SHZ_VIRGL_OBJECT_VERTEX_ELEMENTS, SHZ_VIRGL_VE_SIZE(n));
    uint32_t i;
    if (!p) return;
    p[0] = handle;
    for (i = 0; i < n; ++i) {
        p[1 + 4 * i] = ve[i].src_offset;
        p[2 + 4 * i] = ve[i].instance_divisor;
        p[3 + 4 * i] = ve[i].vertex_buffer_index;
        p[4 + 4 * i] = ve[i].src_format;
    }
}

/* ---- state */
static inline void shz_virgl_set_framebuffer(shz_virgl_cs_t *cs, uint32_t nr_cbufs, const uint32_t *cbufs, uint32_t zsurf)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_SET_FRAMEBUFFER_STATE, 0, SHZ_VIRGL_FRAMEBUFFER_SIZE(nr_cbufs));
    uint32_t i;
    if (!p) return;
    p[0] = nr_cbufs;
    p[1] = zsurf;
    for (i = 0; i < nr_cbufs; ++i) p[2 + i] = cbufs[i];
}

/* One viewport covering a w x h target with the Gallium convention (framebuffer row 0 is the top row): window x =
 * ndc_x * w/2 + w/2, window y = ndc_y * h/2 + h/2, depth z * 0.5 + 0.5. */
static inline void shz_virgl_set_viewport(shz_virgl_cs_t *cs, uint32_t w, uint32_t h)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_SET_VIEWPORT_STATE, 0, SHZ_VIRGL_VIEWPORT_SIZE(1));
    if (!p) return;
    p[0] = 0;                                       /* start slot */
    p[1] = shz_virgl_f32((float)w * 0.5f);
    p[2] = shz_virgl_f32((float)h * 0.5f);
    p[3] = shz_virgl_f32(0.5f);
    p[4] = shz_virgl_f32((float)w * 0.5f);
    p[5] = shz_virgl_f32((float)h * 0.5f);
    p[6] = shz_virgl_f32(0.5f);
}

typedef struct { uint32_t stride, offset, res; } shz_virgl_vb_t;
static inline void shz_virgl_set_vertex_buffers(shz_virgl_cs_t *cs, uint32_t n, const shz_virgl_vb_t *vb)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_SET_VERTEX_BUFFERS, 0, SHZ_VIRGL_VB_SIZE(n));
    uint32_t i;
    if (!p) return;
    for (i = 0; i < n; ++i) {
        p[3 * i] = vb[i].stride;
        p[3 * i + 1] = vb[i].offset;
        p[3 * i + 2] = vb[i].res;
    }
}

/* Writes `bytes` (a multiple of 4) of `data` into buffer resource `res` at byte offset `x`, inside the command stream. */
static inline void shz_virgl_inline_write_buffer(shz_virgl_cs_t *cs, uint32_t res, uint32_t x, const void *data, uint32_t bytes)
{
    const uint32_t dws = (bytes + 3u) / 4u;
    const uint8_t *s = (const uint8_t *)data;
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_RESOURCE_INLINE_WRITE, 0, SHZ_VIRGL_INLINE_WRITE_HDR + dws), i;
    uint8_t *d;
    if (!p) return;
    p[0] = res;
    p[1] = 0;                                       /* level */
    p[2] = 0;                                       /* usage (unused by the host) */
    p[3] = 0;                                       /* stride */
    p[4] = 0;                                       /* layer stride */
    p[5] = x; p[6] = 0; p[7] = 0;                   /* box x, y, z */
    p[8] = bytes; p[9] = 1; p[10] = 1;              /* box w, h, d */
    d = (uint8_t *)(p + 11);
    for (i = 0; i < dws * 4u; ++i) d[i] = i < bytes ? s[i] : 0;
}

static inline void shz_virgl_clear(shz_virgl_cs_t *cs, uint32_t buffers, const float rgba[4], double depth, uint32_t stencil)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_CLEAR, 0, SHZ_VIRGL_CLEAR_SIZE);
    union { double d; uint32_t u[2]; } dv;
    if (!p) return;
    dv.d = depth;
    p[0] = buffers;
    p[1] = shz_virgl_f32(rgba[0]); p[2] = shz_virgl_f32(rgba[1]); p[3] = shz_virgl_f32(rgba[2]); p[4] = shz_virgl_f32(rgba[3]);
    p[5] = dv.u[0]; p[6] = dv.u[1];                 /* little-endian double, low dword first */
    p[7] = stencil;
}

/* Non-indexed, non-instanced draw: [1] start [2] count [3] mode [4] indexed [5] instance_count [6] index_bias
 * [7] start_instance [8] primitive_restart [9] restart_index [10] min_index [11] max_index [12] count_from_so. */
static inline void shz_virgl_draw_arrays(shz_virgl_cs_t *cs, uint32_t mode, uint32_t start, uint32_t count)
{
    uint32_t *p = shz_virgl_packet(cs, SHZ_VIRGL_CCMD_DRAW_VBO, 0, SHZ_VIRGL_DRAW_VBO_SIZE);
    if (!p) return;
    p[0] = start; p[1] = count; p[2] = mode; p[3] = 0; p[4] = 1; p[5] = 0; p[6] = 0; p[7] = 0; p[8] = 0;
    p[9] = start; p[10] = start + count - 1u; p[11] = 0;
}

/* ---- the reference scene used by T_GPU_3D.EXE and the host tests
 * One draw into a w x h B8G8R8A8 render target `rt_res`: clear to `clear_rgba`, then a triangle with per-vertex colours
 * through a TGSI vertex shader (position and colour passed through) and a TGSI fragment shader (interpolated colour out).
 * The vertex data (3 x {x, y, z, w, r, g, b, a} floats, 96 bytes) is written inline into buffer resource `vb_res`
 * (>= 96 bytes, VIRGL_BIND_VERTEX_BUFFER). Object handles 1..8 of the context are used. */
#define SHZ_VIRGL_DEMO_VS \
    "VERT\n" \
    "DCL IN[0]\n" \
    "DCL IN[1]\n" \
    "DCL OUT[0], POSITION\n" \
    "DCL OUT[1], GENERIC[0]\n" \
    "  0: MOV OUT[0], IN[0]\n" \
    "  1: MOV OUT[1], IN[1]\n" \
    "  2: END\n"
#define SHZ_VIRGL_DEMO_FS \
    "FRAG\n" \
    "PROPERTY FS_COLOR0_WRITES_ALL_CBUFS 1\n" \
    "DCL IN[0], GENERIC[0], PERSPECTIVE\n" \
    "DCL OUT[0], COLOR\n" \
    "  0: MOV OUT[0], IN[0]\n" \
    "  1: END\n"

enum { SHZ_VIRGL_H_SURF = 1, SHZ_VIRGL_H_BLEND, SHZ_VIRGL_H_DSA, SHZ_VIRGL_H_RS, SHZ_VIRGL_H_VS, SHZ_VIRGL_H_FS, SHZ_VIRGL_H_VE };

static inline void shz_virgl_encode_triangle(shz_virgl_cs_t *cs, uint32_t rt_res, uint32_t vb_res, uint32_t w, uint32_t h,
                                             const float clear_rgba[4], const float vertices[24])
{
    const uint32_t cbuf = SHZ_VIRGL_H_SURF;
    const shz_virgl_ve_t ve[2] = { { 0, 0, 0, SHZ_VIRGL_FORMAT_R32G32B32A32_FLOAT },
                                   { 16, 0, 0, SHZ_VIRGL_FORMAT_R32G32B32A32_FLOAT } };
    const shz_virgl_vb_t vb = { 32, 0, vb_res };
    shz_virgl_create_surface(cs, SHZ_VIRGL_H_SURF, rt_res, SHZ_VIRGL_FORMAT_B8G8R8A8_UNORM, 0);
    shz_virgl_set_framebuffer(cs, 1, &cbuf, 0);
    shz_virgl_create_blend_opaque(cs, SHZ_VIRGL_H_BLEND, SHZ_PIPE_MASK_RGBA);
    shz_virgl_bind_object(cs, SHZ_VIRGL_OBJECT_BLEND, SHZ_VIRGL_H_BLEND);
    shz_virgl_create_dsa_off(cs, SHZ_VIRGL_H_DSA);
    shz_virgl_bind_object(cs, SHZ_VIRGL_OBJECT_DSA, SHZ_VIRGL_H_DSA);
    shz_virgl_create_rasterizer(cs, SHZ_VIRGL_H_RS, SHZ_VIRGL_RS_DEPTH_CLIP | SHZ_VIRGL_RS_HALF_PIXEL_CENTER);
    shz_virgl_bind_object(cs, SHZ_VIRGL_OBJECT_RASTERIZER, SHZ_VIRGL_H_RS);
    shz_virgl_create_shader_tgsi(cs, SHZ_VIRGL_H_VS, SHZ_PIPE_SHADER_VERTEX, SHZ_VIRGL_DEMO_VS);
    shz_virgl_bind_shader(cs, SHZ_VIRGL_H_VS, SHZ_PIPE_SHADER_VERTEX);
    shz_virgl_create_shader_tgsi(cs, SHZ_VIRGL_H_FS, SHZ_PIPE_SHADER_FRAGMENT, SHZ_VIRGL_DEMO_FS);
    shz_virgl_bind_shader(cs, SHZ_VIRGL_H_FS, SHZ_PIPE_SHADER_FRAGMENT);
    shz_virgl_create_vertex_elements(cs, SHZ_VIRGL_H_VE, 2, ve);
    shz_virgl_bind_object(cs, SHZ_VIRGL_OBJECT_VERTEX_ELEMENTS, SHZ_VIRGL_H_VE);
    shz_virgl_inline_write_buffer(cs, vb_res, 0, vertices, 24u * 4u);
    shz_virgl_set_vertex_buffers(cs, 1, &vb);
    shz_virgl_set_viewport(cs, w, h);
    shz_virgl_clear(cs, SHZ_PIPE_CLEAR_COLOR0, clear_rgba, 1.0, 0);
    shz_virgl_draw_arrays(cs, SHZ_PIPE_PRIM_TRIANGLES, 0, 3);
}

/* Checks a read-back image of the reference scene against the geometry, computed independently of any renderer:
 * pixels are w*h dwords 0xAARRGGBB (B8G8R8A8 bytes), row 0 = top (Gallium). Window position of a vertex is
 * ((x+1)*w/2, (y+1)*h/2) (the viewport above); a pixel is covered when its centre (i+.5, j+.5) is strictly inside the
 * triangle. Pixels whose centre is within 1/64 pixel of an edge are counted in `edge` and not compared (the rasteriser's
 * sub-pixel snapping decides those). Covered pixels must carry the barycentric blend of the vertex colours (+-2/255,
 * alpha 255); the others the clear colour exactly. */
typedef struct { int covered, inside_ok, outside, outside_ok, edge; } shz_virgl_tri_check_t;

static inline double shz_virgl_edge(const double *a, const double *b, double px, double py)
{
    return (b[0] - a[0]) * (py - a[1]) - (b[1] - a[1]) * (px - a[0]);
}

static inline uint32_t shz_virgl_unorm8(float c) { return c <= 0.0f ? 0u : c >= 1.0f ? 255u : (uint32_t)(c * 255.0f + 0.5f); }

static inline void shz_virgl_check_triangle(const uint32_t *pix, uint32_t w, uint32_t h, const float clear[4],
                                            const float verts[24], shz_virgl_tri_check_t *r)
{
    const uint32_t want_clear = shz_virgl_unorm8(clear[3]) << 24 | shz_virgl_unorm8(clear[0]) << 16 |
                                shz_virgl_unorm8(clear[1]) << 8 | shz_virgl_unorm8(clear[2]);
    double v[3][2], area, len2[3];
    uint32_t x, y;
    int k;
    r->covered = r->inside_ok = r->outside = r->outside_ok = r->edge = 0;
    for (k = 0; k < 3; ++k) {
        v[k][0] = ((double)verts[k * 8] + 1.0) * w / 2;
        v[k][1] = ((double)verts[k * 8 + 1] + 1.0) * h / 2;
    }
    area = shz_virgl_edge(v[0], v[1], v[2][0], v[2][1]);
    for (k = 0; k < 3; ++k) {
        const double *a = v[(k + 1) % 3], *b = v[(k + 2) % 3];
        len2[k] = (b[0] - a[0]) * (b[0] - a[0]) + (b[1] - a[1]) * (b[1] - a[1]);
    }
    for (y = 0; y < h; ++y)
        for (x = 0; x < w; ++x) {
            const double px = x + 0.5, py = y + 0.5;
            const uint32_t got = pix[y * w + x];
            double e[3];
            int on_edge = 0;
            e[0] = shz_virgl_edge(v[1], v[2], px, py) / area;      /* barycentric weight of vertex 0 */
            e[1] = shz_virgl_edge(v[2], v[0], px, py) / area;
            e[2] = shz_virgl_edge(v[0], v[1], px, py) / area;
            for (k = 0; k < 3; ++k)                                /* distance e*|area|/len < 1/64, squared */
                if (e[k] * e[k] * area * area * 4096.0 < len2[k]) on_edge = 1;
            if (on_edge) { ++r->edge; continue; }
            if (e[0] > 0 && e[1] > 0 && e[2] > 0) {
                double want[3], d;
                int c, ok = (got >> 24) == 0xff;
                ++r->covered;
                for (c = 0; c < 3; ++c)                            /* r, g, b of the vertex colours at [4..6] */
                    want[c] = 255.0 * (e[0] * verts[4 + c] + e[1] * verts[12 + c] + e[2] * verts[20 + c]);
                d = (double)((got >> 16) & 0xff) - want[0]; if (d > 2.0 || d < -2.0) ok = 0;
                d = (double)((got >> 8) & 0xff) - want[1]; if (d > 2.0 || d < -2.0) ok = 0;
                d = (double)(got & 0xff) - want[2]; if (d > 2.0 || d < -2.0) ok = 0;
                r->inside_ok += ok;
            } else {
                ++r->outside;
                r->outside_ok += got == want_clear;
            }
        }
}
#endif
