/* SPDX-License-Identifier: GPL-2.0-only
 * Executes the virgl command stream written by win64/include/shzvirgl.h on the HOST's virglrenderer - the library QEMU's
 * virtio-gpu-gl device hands SUBMIT_3D payloads to - and checks the pixels it renders.
 *
 * What this proves and what it does not:
 *  - It runs the exact stream T_GPU_3D.EXE submits (shz_virgl_encode_triangle) through virglrenderer's decoder, its
 *    TGSI->GLSL translator and a real OpenGL driver (here Mesa llvmpipe through EGL_MESA_platform_surfaceless: this
 *    machine has no GPU and no /dev/dri), with the same resource creation / attach / transfer_read calls QEMU makes for
 *    RESOURCE_CREATE_3D, RESOURCE_ATTACH_BACKING, CTX_ATTACH_RESOURCE, SUBMIT_3D and TRANSFER_FROM_HOST_3D.
 *  - It does NOT go through the guest kernel, the virtqueue or QEMU: that end-to-end path needs QEMU with a GL display
 *    (`-device virtio-vga-gl -display egl-headless`), which requires a DRM render node (see docs/shizukudos10/GPU.md).
 * The library is loaded with dlopen so the build needs no -dev package; if it is missing the test exits 77 (not run).
 *
 * Expected image: shz_virgl_check_triangle() computes it from the geometry with the documented Gallium semantics (row 0
 * of the render target is the top row, viewport (x+1)*W/2, (y+1)*H/2, pixel-centre coverage), never from a renderer:
 * clear colour outside, barycentric blend of the vertex colours (+-2/255) inside, pixels within 1/64 px of an edge not
 * compared. T_GPU_3D.EXE uses the same checker on what it reads back through the guest.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "virglrenderer.h"
#include "virgl_hw.h"
#include "shzvirgl.h"

#define W 64
#define H 64

static struct {
    int (*init)(void *, int, struct virgl_renderer_callbacks *);
    int (*context_create)(uint32_t, uint32_t, const char *);
    void (*context_destroy)(uint32_t);
    int (*resource_create)(struct virgl_renderer_resource_create_args *, struct iovec *, uint32_t);
    int (*attach_iov)(int, struct iovec *, int);
    void (*ctx_attach_resource)(int, int);
    int (*submit_cmd)(void *, int, int);
    int (*transfer_read_iov)(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, struct virgl_box *, uint64_t, struct iovec *, int);
    void (*get_cap_set)(uint32_t, uint32_t *, uint32_t *);
    void (*fill_caps)(uint32_t, uint32_t, void *);
    void (*resource_unref)(uint32_t);
    void (*cleanup)(void *);
    void (*set_log_callback)(virgl_log_callback_type, void *, virgl_free_data_callback_type);
} vr;

static unsigned checks, failures;
#define CHECK(c, ...) do { ++checks; if (!(c)) { ++failures; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

static void log_cb(enum virgl_log_level_flags level, const char *msg, void *user)
{
    (void)user;
    if (level >= VIRGL_LOG_LEVEL_WARNING) printf("  virglrenderer: %s", msg);
}
static void write_fence(void *cookie, uint32_t fence) { (void)cookie; (void)fence; }

int main(void)
{
    static const float clear[4] = { 0.2f, 0.4f, 0.6f, 1.0f };
    /* x, y, z, w, r, g, b, a per vertex: red, green, blue corners (NDC chosen so no pixel centre lies on an edge) */
    static const float verts[24] = { -0.8f, -0.7f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f,
                                     0.9f, -0.55f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f,
                                     -0.1f, 0.85f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f };
    static uint32_t cmd[4096];
    struct virgl_renderer_callbacks cbs;
    struct virgl_renderer_resource_create_args rt, vb;
    struct iovec rt_iov, vb_iov;
    struct virgl_box box = { 0, 0, 0, W, H, 1 };
    uint32_t max_ver = 0, max_size = 0, *pix, i;
    struct virgl_caps_v2 *caps;
    shz_virgl_cs_t cs;
    void *lib = dlopen("libvirglrenderer.so.1", RTLD_NOW);
    int r;
    if (!lib) {
        printf("NOT RUN: libvirglrenderer.so.1 is not installed (%s)\n", dlerror());
        return 77;
    }
#define SYM(field, name) do { *(void **)&vr.field = dlsym(lib, name); if (!vr.field) { printf("FAIL: %s missing\n", name); return 1; } } while (0)
    SYM(init, "virgl_renderer_init");
    SYM(context_create, "virgl_renderer_context_create");
    SYM(context_destroy, "virgl_renderer_context_destroy");
    SYM(resource_create, "virgl_renderer_resource_create");
    SYM(attach_iov, "virgl_renderer_resource_attach_iov");
    SYM(ctx_attach_resource, "virgl_renderer_ctx_attach_resource");
    SYM(submit_cmd, "virgl_renderer_submit_cmd");
    SYM(transfer_read_iov, "virgl_renderer_transfer_read_iov");
    SYM(get_cap_set, "virgl_renderer_get_cap_set");
    SYM(fill_caps, "virgl_renderer_fill_caps");
    SYM(resource_unref, "virgl_renderer_resource_unref");
    SYM(cleanup, "virgl_renderer_cleanup");
    SYM(set_log_callback, "virgl_set_log_callback");
    vr.set_log_callback(log_cb, NULL, NULL);
    memset(&cbs, 0, sizeof cbs);
    cbs.version = 1;
    cbs.write_fence = write_fence;
    r = vr.init(&cbs, VIRGL_RENDERER_USE_EGL | VIRGL_RENDERER_USE_SURFACELESS, &cbs);
    if (r) {
        printf("NOT RUN: virgl_renderer_init(EGL surfaceless) failed (%d): no usable OpenGL driver on this host\n", r);
        return 77;
    }
    /* capset 2 (VIRGL2) is what a guest reads with GET_CAPSET */
    vr.get_cap_set(2, &max_ver, &max_size);
    CHECK(max_ver >= 1 && max_size >= sizeof(struct virgl_caps_v1), "capset VIRGL2 version %u size %u", max_ver, max_size);
    caps = calloc(1, max_size > sizeof *caps ? max_size : sizeof *caps);
    vr.fill_caps(2, max_ver, caps);
    printf("  host virgl caps: glsl_level %u, max_render_targets %u, max_texture_2d_size %u, capability_bits %#x\n",
           caps->v1.glsl_level, caps->v1.max_render_targets, caps->max_texture_2d_size, caps->capability_bits);
    CHECK(caps->v1.render.bitmask[VIRGL_FORMAT_B8G8R8A8_UNORM / 32] >> (VIRGL_FORMAT_B8G8R8A8_UNORM % 32) & 1,
          "B8G8R8A8_UNORM not renderable on the host");
    /* (the vertexbuffer mask only lists formats beyond the GL 3.x core set, so R32G32B32A32_FLOAT is not looked up there) */
    free(caps);

    CHECK(vr.context_create(1, 6, "shzgpu") == 0, "context_create");
    memset(&rt, 0, sizeof rt);
    rt.handle = 1; rt.target = SHZ_PIPE_TEXTURE_2D; rt.format = SHZ_VIRGL_FORMAT_B8G8R8A8_UNORM;
    rt.bind = SHZ_VIRGL_BIND_RENDER_TARGET | SHZ_VIRGL_BIND_SAMPLER_VIEW; rt.width = W; rt.height = H; rt.depth = 1; rt.array_size = 1;
    memset(&vb, 0, sizeof vb);
    vb.handle = 2; vb.target = SHZ_PIPE_BUFFER; vb.format = SHZ_VIRGL_FORMAT_R8_UNORM; vb.bind = SHZ_VIRGL_BIND_VERTEX_BUFFER;
    vb.width = 4096; vb.height = 1; vb.depth = 1; vb.array_size = 1;
    pix = calloc(W * H, 4);
    rt_iov.iov_base = pix; rt_iov.iov_len = W * H * 4;
    vb_iov.iov_base = calloc(1, 4096); vb_iov.iov_len = 4096;
    CHECK(vr.resource_create(&rt, NULL, 0) == 0, "resource_create render target");
    CHECK(vr.resource_create(&vb, NULL, 0) == 0, "resource_create vertex buffer");
    CHECK(vr.attach_iov(1, &rt_iov, 1) == 0, "attach_iov render target");
    CHECK(vr.attach_iov(2, &vb_iov, 1) == 0, "attach_iov vertex buffer");
    vr.ctx_attach_resource(1, 1);
    vr.ctx_attach_resource(1, 2);

    shz_virgl_init(&cs, cmd, sizeof cmd / 4);
    shz_virgl_encode_triangle(&cs, 1, 2, W, H, clear, verts);
    CHECK(!cs.overflow, "encoder overflow");
    printf("  stream: %u dwords\n", cs.len);
    r = vr.submit_cmd(cmd, 1, (int)cs.len);
    CHECK(r == 0, "submit_cmd -> %d (the host rejected a packet)", r);
    for (i = 0; i < (uint32_t)W * H; ++i) pix[i] = 0xdeadbeef;
    r = vr.transfer_read_iov(1, 1, 0, W * 4, 0, &box, 0, NULL, 0);
    CHECK(r == 0, "transfer_read_iov -> %d", r);

    {
        shz_virgl_tri_check_t t;
        shz_virgl_check_triangle(pix, W, H, clear, verts, &t);
        printf("  %d covered pixels (%d with the interpolated colour), %d outside (%d with the clear colour), %d on an edge "
               "(not compared)\n", t.covered, t.inside_ok, t.outside, t.outside_ok, t.edge);
        CHECK(t.covered > 500 && t.inside_ok == t.covered, "triangle interior: %d of %d pixels right", t.inside_ok, t.covered);
        CHECK(t.outside > 500 && t.outside_ok == t.outside, "clear colour outside the triangle: %d of %d", t.outside_ok, t.outside);
        CHECK(t.edge < 64, "%d pixel centres within 1/64 px of an edge", t.edge);
        /* the checker itself must notice damage: one wrong pixel inside and one outside */
        for (i = 0; i < (uint32_t)W * H; ++i) {
            shz_virgl_tri_check_t u;
            if (pix[i] == 0xff336699u) continue;
            pix[i] ^= 0x00404040u;
            shz_virgl_check_triangle(pix, W, H, clear, verts, &u);
            pix[i] ^= 0x00404040u;
            CHECK(u.inside_ok == t.inside_ok - 1 || u.edge != t.edge, "checker missed a corrupted covered pixel");
            break;
        }
        pix[0] ^= 1;
        {
            shz_virgl_tri_check_t u;
            shz_virgl_check_triangle(pix, W, H, clear, verts, &u);
            CHECK(u.outside_ok == t.outside_ok - 1, "checker missed a corrupted clear pixel");
        }
        pix[0] ^= 1;
    }
    /* a corrupted packet must be refused by the decoder (and not crash it) */
    {
        uint32_t bad[3] = { shz_virgl_hdr(SHZ_VIRGL_CCMD_DRAW_VBO, 0, 2), 0, 3 };   /* DRAW_VBO with 2 instead of 12 dwords */
        printf("  submitting a deliberately malformed DRAW_VBO (2 dwords); virglrenderer must refuse it:\n");
        CHECK(vr.submit_cmd(bad, 1, 3) != 0, "a DRAW_VBO with a wrong length was accepted");
    }
    vr.context_destroy(1);
    vr.resource_unref(1);
    vr.resource_unref(2);
    vr.cleanup(&cbs);
    printf("virgl exec: %u checks, %u failed\n", checks, failures);
    return failures ? 1 : 0;
}
