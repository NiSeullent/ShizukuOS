/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test of the virgl command-stream encoder (win64/include/shzvirgl.h) against the upstream protocol layout.
 *
 * The encoder declares its own constants; this test compares each of them with virglrenderer 1.0.0's virgl_protocol.h and
 * virgl_hw.h (pinned under third_party/virglrenderer-1.0.0, MIT) and then decodes what the encoder wrote the way
 * src/vrend_decode.c does: walk packets by the 16-bit length in the header, reject unknown commands, check each packet's
 * length against the size the decoder demands and read every field back at the offset virgl_protocol.h names.
 * Runtime acceptance of the same stream by the real decoder is test_virgl_exec.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "virgl_protocol.h"
#include "virgl_hw.h"
#include "shzvirgl.h"

static unsigned checks, failures;
#define CHECK(c, ...) do { ++checks; if (!(c)) { ++failures; printf("FAIL %s:%d: ", __FILE__, __LINE__); printf(__VA_ARGS__); printf("\n"); } } while (0)
#define SAME(a, b) CHECK((uint64_t)(a) == (uint64_t)(b), "%s = %llu but %s = %llu", #a, (unsigned long long)(a), #b, (unsigned long long)(b))

static float f32(uint32_t u) { union { uint32_t u; float f; } v; v.u = u; return v.f; }

static void constants(void)
{
    SAME(SHZ_VIRGL_CCMD_NOP, VIRGL_CCMD_NOP);
    SAME(SHZ_VIRGL_CCMD_CREATE_OBJECT, VIRGL_CCMD_CREATE_OBJECT);
    SAME(SHZ_VIRGL_CCMD_BIND_OBJECT, VIRGL_CCMD_BIND_OBJECT);
    SAME(SHZ_VIRGL_CCMD_DESTROY_OBJECT, VIRGL_CCMD_DESTROY_OBJECT);
    SAME(SHZ_VIRGL_CCMD_SET_VIEWPORT_STATE, VIRGL_CCMD_SET_VIEWPORT_STATE);
    SAME(SHZ_VIRGL_CCMD_SET_FRAMEBUFFER_STATE, VIRGL_CCMD_SET_FRAMEBUFFER_STATE);
    SAME(SHZ_VIRGL_CCMD_SET_VERTEX_BUFFERS, VIRGL_CCMD_SET_VERTEX_BUFFERS);
    SAME(SHZ_VIRGL_CCMD_CLEAR, VIRGL_CCMD_CLEAR);
    SAME(SHZ_VIRGL_CCMD_DRAW_VBO, VIRGL_CCMD_DRAW_VBO);
    SAME(SHZ_VIRGL_CCMD_RESOURCE_INLINE_WRITE, VIRGL_CCMD_RESOURCE_INLINE_WRITE);
    SAME(SHZ_VIRGL_CCMD_SET_SUB_CTX, VIRGL_CCMD_SET_SUB_CTX);
    SAME(SHZ_VIRGL_CCMD_CREATE_SUB_CTX, VIRGL_CCMD_CREATE_SUB_CTX);
    SAME(SHZ_VIRGL_CCMD_DESTROY_SUB_CTX, VIRGL_CCMD_DESTROY_SUB_CTX);
    SAME(SHZ_VIRGL_CCMD_BIND_SHADER, VIRGL_CCMD_BIND_SHADER);
    SAME(SHZ_VIRGL_OBJECT_BLEND, VIRGL_OBJECT_BLEND);
    SAME(SHZ_VIRGL_OBJECT_RASTERIZER, VIRGL_OBJECT_RASTERIZER);
    SAME(SHZ_VIRGL_OBJECT_DSA, VIRGL_OBJECT_DSA);
    SAME(SHZ_VIRGL_OBJECT_SHADER, VIRGL_OBJECT_SHADER);
    SAME(SHZ_VIRGL_OBJECT_VERTEX_ELEMENTS, VIRGL_OBJECT_VERTEX_ELEMENTS);
    SAME(SHZ_VIRGL_OBJECT_SURFACE, VIRGL_OBJECT_SURFACE);
    SAME(SHZ_VIRGL_BLEND_SIZE, VIRGL_OBJ_BLEND_SIZE);
    SAME(SHZ_VIRGL_DSA_SIZE, VIRGL_OBJ_DSA_SIZE);
    SAME(SHZ_VIRGL_RS_SIZE, VIRGL_OBJ_RS_SIZE);
    SAME(SHZ_VIRGL_SURFACE_SIZE, VIRGL_OBJ_SURFACE_SIZE);
    SAME(SHZ_VIRGL_SHADER_HDR_SIZE, VIRGL_OBJ_SHADER_HDR_SIZE(0));
    SAME(SHZ_VIRGL_CLEAR_SIZE, VIRGL_OBJ_CLEAR_SIZE);
    SAME(SHZ_VIRGL_VIEWPORT_SIZE(1), VIRGL_SET_VIEWPORT_STATE_SIZE(1));
    SAME(SHZ_VIRGL_VIEWPORT_SIZE(3), VIRGL_SET_VIEWPORT_STATE_SIZE(3));
    SAME(SHZ_VIRGL_FRAMEBUFFER_SIZE(1), VIRGL_SET_FRAMEBUFFER_STATE_SIZE(1));
    SAME(SHZ_VIRGL_FRAMEBUFFER_SIZE(8), VIRGL_SET_FRAMEBUFFER_STATE_SIZE(8));
    SAME(SHZ_VIRGL_VE_SIZE(2), VIRGL_OBJ_VERTEX_ELEMENTS_SIZE(2));
    SAME(SHZ_VIRGL_VB_SIZE(2), VIRGL_SET_VERTEX_BUFFERS_SIZE(2));
    SAME(SHZ_VIRGL_DRAW_VBO_SIZE, VIRGL_DRAW_VBO_SIZE);
    SAME(SHZ_VIRGL_INLINE_WRITE_HDR, VIRGL_RESOURCE_IW_DATA_START - 1);
    SAME(SHZ_VIRGL_BIND_SHADER_SIZE, VIRGL_BIND_SHADER_SIZE);
    SAME(SHZ_VIRGL_SHADER_OFFSET_CONT, VIRGL_OBJ_SHADER_OFFSET_CONT);
    SAME(shz_virgl_hdr(7, 5, 300), VIRGL_CMD0(7, 5, 300));
    SAME(SHZ_VIRGL_FORMAT_B8G8R8A8_UNORM, VIRGL_FORMAT_B8G8R8A8_UNORM);
    SAME(SHZ_VIRGL_FORMAT_B8G8R8X8_UNORM, VIRGL_FORMAT_B8G8R8X8_UNORM);
    SAME(SHZ_VIRGL_FORMAT_R32G32_FLOAT, VIRGL_FORMAT_R32G32_FLOAT);
    SAME(SHZ_VIRGL_FORMAT_R32G32B32A32_FLOAT, VIRGL_FORMAT_R32G32B32A32_FLOAT);
    SAME(SHZ_VIRGL_FORMAT_R8_UNORM, VIRGL_FORMAT_R8_UNORM);
    SAME(SHZ_VIRGL_BIND_RENDER_TARGET, VIRGL_BIND_RENDER_TARGET);
    SAME(SHZ_VIRGL_BIND_SAMPLER_VIEW, VIRGL_BIND_SAMPLER_VIEW);
    SAME(SHZ_VIRGL_BIND_VERTEX_BUFFER, VIRGL_BIND_VERTEX_BUFFER);
    SAME(SHZ_VIRGL_BIND_CONSTANT_BUFFER, VIRGL_BIND_CONSTANT_BUFFER);
    SAME(SHZ_VIRGL_BIND_DISPLAY_TARGET, VIRGL_BIND_DISPLAY_TARGET);
    SAME(SHZ_VIRGL_RS_DEPTH_CLIP, VIRGL_OBJ_RS_S0_DEPTH_CLIP(1));
    SAME(SHZ_VIRGL_RS_FRONT_CCW, VIRGL_OBJ_RS_S0_FRONT_CCW(1));
    SAME(SHZ_VIRGL_RS_HALF_PIXEL_CENTER, VIRGL_OBJ_RS_S0_HALF_PIXEL_CENTER(1));
}

/* A decoded packet: pointer to its header ([0]) and payload length, as vrend_decode_ctx_submit_cmd sees it. */
typedef struct { const uint32_t *p; uint32_t cmd, obj, len; } pkt_t;

static unsigned split(const uint32_t *buf, uint32_t ndw, pkt_t *out, unsigned max)
{
    uint32_t off = 0;
    unsigned n = 0;
    while (off < ndw) {
        const uint32_t hdr = buf[off], len = hdr >> 16;
        CHECK((hdr & 0xff) < VIRGL_MAX_COMMANDS, "packet %u: command %u out of range", n, hdr & 0xff);
        CHECK(off + len + 1 <= ndw, "packet %u overruns the stream (off %u len %u total %u)", n, off, len, ndw);
        if (off + len + 1 > ndw || n == max) break;
        out[n].p = buf + off;
        out[n].cmd = hdr & 0xff;
        out[n].obj = (hdr >> 8) & 0xff;
        out[n].len = len;
        ++n;
        off += len + 1;
    }
    CHECK(off == ndw, "stream does not end on a packet boundary (%u of %u)", off, ndw);
    return n;
}

static void check_shader(const pkt_t *k, uint32_t handle, uint32_t type, const char *text)
{
    const uint32_t bytes = (uint32_t)strlen(text) + 1, pkt_length = k->len - 5;      /* vrend: length - shader_offset + 1 */
    const uint32_t offlen = k->p[VIRGL_OBJ_SHADER_OFFSET];
    CHECK(k->cmd == VIRGL_CCMD_CREATE_OBJECT && k->obj == VIRGL_OBJECT_SHADER, "shader packet type %u/%u", k->cmd, k->obj);
    CHECK(k->len >= VIRGL_OBJ_SHADER_HDR_SIZE(0), "shader packet too short");
    SAME(k->p[VIRGL_OBJ_SHADER_HANDLE], handle);
    SAME(k->p[VIRGL_OBJ_SHADER_TYPE], type);
    CHECK(!(offlen & VIRGL_OBJ_SHADER_OFFSET_CONT), "first shader packet flagged as continuation");
    SAME(offlen, bytes);
    CHECK((offlen + 3) / 4 >= pkt_length && (offlen + 3) / 4 == pkt_length, "text dwords %u vs length %u", pkt_length, offlen);
    SAME(k->p[VIRGL_OBJ_SHADER_SO_NUM_OUTPUTS], 0);
    CHECK(k->p[VIRGL_OBJ_SHADER_NUM_TOKENS] >= 16 && k->p[VIRGL_OBJ_SHADER_NUM_TOKENS] < 8000, "num_tokens %u",
          k->p[VIRGL_OBJ_SHADER_NUM_TOKENS]);
    CHECK(!memcmp((const char *)(k->p + 6), text, bytes), "shader text differs");
    CHECK(memchr((const char *)(k->p + 6) + pkt_length * 4 - 4, 0, 4) != NULL, "no NUL in the last dword (vrend requires it)");
}

static void scene(void)
{
    static const float clear[4] = { 0.2f, 0.4f, 0.6f, 1.0f };
    static float verts[24];
    uint32_t buf[1024];
    pkt_t k[64];
    shz_virgl_cs_t cs;
    unsigned n, i;
    union { uint32_t u[2]; double d; } depth;
    for (i = 0; i < 24; ++i) verts[i] = (float)i * 0.125f - 1.0f;
    shz_virgl_init(&cs, buf, 1024);
    shz_virgl_encode_triangle(&cs, 11, 12, 64, 48, clear, verts);
    CHECK(!cs.overflow, "overflow");
    n = split(buf, cs.len, k, 64);
    SAME(n, 19);
    if (n != 19) return;
    /* 0 surface */
    SAME(k[0].cmd, VIRGL_CCMD_CREATE_OBJECT); SAME(k[0].obj, VIRGL_OBJECT_SURFACE); SAME(k[0].len, VIRGL_OBJ_SURFACE_SIZE);
    SAME(k[0].p[VIRGL_OBJ_SURFACE_HANDLE], SHZ_VIRGL_H_SURF);
    SAME(k[0].p[VIRGL_OBJ_SURFACE_RES_HANDLE], 11);
    SAME(k[0].p[VIRGL_OBJ_SURFACE_FORMAT], VIRGL_FORMAT_B8G8R8A8_UNORM);
    SAME(k[0].p[VIRGL_OBJ_SURFACE_TEXTURE_LEVEL], 0);
    SAME(k[0].p[VIRGL_OBJ_SURFACE_TEXTURE_LAYERS], 0);
    /* 1 framebuffer */
    SAME(k[1].cmd, VIRGL_CCMD_SET_FRAMEBUFFER_STATE); SAME(k[1].len, VIRGL_SET_FRAMEBUFFER_STATE_SIZE(1));
    SAME(k[1].p[VIRGL_SET_FRAMEBUFFER_STATE_NR_CBUFS], 1);
    SAME(k[1].p[VIRGL_SET_FRAMEBUFFER_STATE_NR_ZSURF_HANDLE], 0);
    SAME(k[1].p[VIRGL_SET_FRAMEBUFFER_STATE_CBUF_HANDLE(0)], SHZ_VIRGL_H_SURF);
    /* 2,3 blend */
    SAME(k[2].obj, VIRGL_OBJECT_BLEND); SAME(k[2].len, VIRGL_OBJ_BLEND_SIZE);
    SAME(k[2].p[VIRGL_OBJ_BLEND_HANDLE], SHZ_VIRGL_H_BLEND);
    SAME(k[2].p[VIRGL_OBJ_BLEND_S0], 0);
    for (i = 0; i < VIRGL_MAX_COLOR_BUFS; ++i)
        SAME(k[2].p[VIRGL_OBJ_BLEND_S2(i)], VIRGL_OBJ_BLEND_S2_RT_COLORMASK(0xf) | VIRGL_OBJ_BLEND_S2_RT_BLEND_ENABLE(0));
    SAME(k[3].cmd, VIRGL_CCMD_BIND_OBJECT); SAME(k[3].obj, VIRGL_OBJECT_BLEND); SAME(k[3].len, 1);
    SAME(k[3].p[VIRGL_OBJ_BIND_HANDLE], SHZ_VIRGL_H_BLEND);
    /* 4,5 dsa */
    SAME(k[4].obj, VIRGL_OBJECT_DSA); SAME(k[4].len, VIRGL_OBJ_DSA_SIZE);
    SAME(k[4].p[VIRGL_OBJ_DSA_HANDLE], SHZ_VIRGL_H_DSA);
    SAME(k[4].p[VIRGL_OBJ_DSA_S0] & VIRGL_OBJ_DSA_S0_DEPTH_ENABLE(1), 0);
    SAME(k[5].obj, VIRGL_OBJECT_DSA); SAME(k[5].p[VIRGL_OBJ_BIND_HANDLE], SHZ_VIRGL_H_DSA);
    /* 6,7 rasterizer */
    SAME(k[6].obj, VIRGL_OBJECT_RASTERIZER); SAME(k[6].len, VIRGL_OBJ_RS_SIZE);
    SAME(k[6].p[VIRGL_OBJ_RS_HANDLE], SHZ_VIRGL_H_RS);
    SAME(k[6].p[VIRGL_OBJ_RS_S0], VIRGL_OBJ_RS_S0_DEPTH_CLIP(1) | VIRGL_OBJ_RS_S0_HALF_PIXEL_CENTER(1) |
                                   VIRGL_OBJ_RS_S0_CULL_FACE(0) | VIRGL_OBJ_RS_S0_FILL_FRONT(0) | VIRGL_OBJ_RS_S0_FILL_BACK(0));
    CHECK(f32(k[6].p[VIRGL_OBJ_RS_POINT_SIZE]) == 1.0f && f32(k[6].p[VIRGL_OBJ_RS_LINE_WIDTH]) == 1.0f, "point/line size");
    SAME(k[7].obj, VIRGL_OBJECT_RASTERIZER);
    /* 8..11 shaders */
    check_shader(&k[8], SHZ_VIRGL_H_VS, 0 /* PIPE_SHADER_VERTEX */, SHZ_VIRGL_DEMO_VS);
    SAME(k[9].cmd, VIRGL_CCMD_BIND_SHADER); SAME(k[9].len, VIRGL_BIND_SHADER_SIZE);
    SAME(k[9].p[VIRGL_BIND_SHADER_HANDLE], SHZ_VIRGL_H_VS); SAME(k[9].p[VIRGL_BIND_SHADER_TYPE], 0);
    check_shader(&k[10], SHZ_VIRGL_H_FS, 1 /* PIPE_SHADER_FRAGMENT */, SHZ_VIRGL_DEMO_FS);
    SAME(k[11].cmd, VIRGL_CCMD_BIND_SHADER);
    SAME(k[11].p[VIRGL_BIND_SHADER_HANDLE], SHZ_VIRGL_H_FS); SAME(k[11].p[VIRGL_BIND_SHADER_TYPE], 1);
    /* 12,13 vertex elements */
    SAME(k[12].obj, VIRGL_OBJECT_VERTEX_ELEMENTS); SAME(k[12].len, VIRGL_OBJ_VERTEX_ELEMENTS_SIZE(2));
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_HANDLE], SHZ_VIRGL_H_VE);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_SRC_OFFSET(0)], 0);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_SRC_OFFSET(1)], 16);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_INSTANCE_DIVISOR(1)], 0);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_VERTEX_BUFFER_INDEX(1)], 0);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_SRC_FORMAT(0)], VIRGL_FORMAT_R32G32B32A32_FLOAT);
    SAME(k[12].p[VIRGL_OBJ_VERTEX_ELEMENTS_V0_SRC_FORMAT(1)], VIRGL_FORMAT_R32G32B32A32_FLOAT);
    SAME(k[13].obj, VIRGL_OBJECT_VERTEX_ELEMENTS);
    /* 14 inline write of the 96 vertex bytes */
    SAME(k[14].cmd, VIRGL_CCMD_RESOURCE_INLINE_WRITE); SAME(k[14].len, 11 + 24);
    SAME(k[14].p[VIRGL_RESOURCE_IW_RES_HANDLE], 12);
    SAME(k[14].p[VIRGL_RESOURCE_IW_LEVEL], 0);
    SAME(k[14].p[VIRGL_RESOURCE_IW_X], 0); SAME(k[14].p[VIRGL_RESOURCE_IW_W], 96);
    SAME(k[14].p[VIRGL_RESOURCE_IW_H], 1); SAME(k[14].p[VIRGL_RESOURCE_IW_D], 1);
    SAME((k[14].len - 11) * 4, 96);                                          /* data_len as vrend computes it */
    CHECK(!memcmp(k[14].p + VIRGL_RESOURCE_IW_DATA_START, verts, 96), "vertex data");
    /* 15 vertex buffers */
    SAME(k[15].cmd, VIRGL_CCMD_SET_VERTEX_BUFFERS); SAME(k[15].len, VIRGL_SET_VERTEX_BUFFERS_SIZE(1));
    SAME(k[15].p[VIRGL_SET_VERTEX_BUFFER_STRIDE(0)], 32);
    SAME(k[15].p[VIRGL_SET_VERTEX_BUFFER_OFFSET(0)], 0);
    SAME(k[15].p[VIRGL_SET_VERTEX_BUFFER_HANDLE(0)], 12);
    /* 16 viewport */
    SAME(k[16].cmd, VIRGL_CCMD_SET_VIEWPORT_STATE); SAME(k[16].len, VIRGL_SET_VIEWPORT_STATE_SIZE(1));
    SAME(k[16].p[VIRGL_SET_VIEWPORT_START_SLOT], 0);
    CHECK(f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_SCALE_0(0)]) == 32.0f && f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_SCALE_1(0)]) == 24.0f &&
          f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_SCALE_2(0)]) == 0.5f && f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_TRANSLATE_0(0)]) == 32.0f &&
          f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_TRANSLATE_1(0)]) == 24.0f && f32(k[16].p[VIRGL_SET_VIEWPORT_STATE_TRANSLATE_2(0)]) == 0.5f,
          "viewport scale/translate");
    /* 17 clear */
    SAME(k[17].cmd, VIRGL_CCMD_CLEAR); SAME(k[17].len, VIRGL_OBJ_CLEAR_SIZE);
    SAME(k[17].p[VIRGL_OBJ_CLEAR_BUFFERS], 1u << 2);                          /* PIPE_CLEAR_COLOR0 */
    CHECK(f32(k[17].p[VIRGL_OBJ_CLEAR_COLOR_0]) == 0.2f && f32(k[17].p[VIRGL_OBJ_CLEAR_COLOR_1]) == 0.4f &&
          f32(k[17].p[VIRGL_OBJ_CLEAR_COLOR_2]) == 0.6f && f32(k[17].p[VIRGL_OBJ_CLEAR_COLOR_3]) == 1.0f, "clear colour");
    memcpy(&depth, k[17].p + VIRGL_OBJ_CLEAR_DEPTH_0, 8);                     /* vrend memcpy()s the double from here */
    CHECK(depth.d == 1.0, "clear depth %f", depth.d);
    SAME(k[17].p[VIRGL_OBJ_CLEAR_STENCIL], 0);
    /* 18 draw */
    SAME(k[18].cmd, VIRGL_CCMD_DRAW_VBO); SAME(k[18].len, VIRGL_DRAW_VBO_SIZE);
    SAME(k[18].p[VIRGL_DRAW_VBO_START], 0); SAME(k[18].p[VIRGL_DRAW_VBO_COUNT], 3);
    SAME(k[18].p[VIRGL_DRAW_VBO_MODE], 4);                                   /* PIPE_PRIM_TRIANGLES */
    SAME(k[18].p[VIRGL_DRAW_VBO_INDEXED], 0); SAME(k[18].p[VIRGL_DRAW_VBO_INSTANCE_COUNT], 1);
    SAME(k[18].p[VIRGL_DRAW_VBO_MIN_INDEX], 0); SAME(k[18].p[VIRGL_DRAW_VBO_MAX_INDEX], 2);
    SAME(k[18].p[VIRGL_DRAW_VBO_COUNT_FROM_SO], 0);
}

static void overflow(void)
{
    uint32_t buf[64];
    shz_virgl_cs_t cs;
    static const float c[4] = { 0, 0, 0, 0 };
    static const float v[24] = { 0 };
    unsigned cap;
    for (cap = 0; cap < 64; ++cap) {
        memset(buf, 0xa5, sizeof buf);
        shz_virgl_init(&cs, buf, cap);
        shz_virgl_encode_triangle(&cs, 1, 2, 8, 8, c, v);
        CHECK(cs.overflow && cs.len <= cap, "cap %u: overflow %d len %u", cap, cs.overflow, cs.len);
        CHECK(buf[cap] == 0xa5a5a5a5u, "cap %u: wrote past the capacity", cap);
    }
}

int main(void)
{
    constants();
    scene();
    overflow();
    printf("virgl encoder: %u checks, %u failed\n", checks, failures);
    return failures ? 1 : 0;
}
