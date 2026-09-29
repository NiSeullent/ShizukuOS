/* SPDX-License-Identifier: GPL-2.0-only
 * GPU 3D path from user mode: a virgl context on virtio-gpu, executed by the HOST's GPU driver.
 *
 * With VIRTIO_GPU_F_VIRGL negotiated (QEMU -device virtio-vga-gl on a host with a GL display):
 *   capset VIRGL2 (host GL capabilities), a context, a 64x64 B8G8R8A8 render target and a vertex buffer
 *   (RESOURCE_CREATE_3D + guest backing + CTX_ATTACH_RESOURCE), the reference stream of shzvirgl.h (clear, TGSI vertex and
 *   fragment shaders, one triangle with per-vertex colours; SUBMIT_3D, fenced), TRANSFER_FROM_HOST_3D of the render
 *   target and a pixel check against the triangle computed from its geometry (shz_virgl_check_triangle). Then the
 *   objects are destroyed. (Rejection of malformed streams is checked on the host, kernel64/host/test_virgl_exec.c:
 *   whether QEMU reports a decode error back to the guest depends on its version.)
 * Without VIRGL (Bochs VBE, or virtio-gpu in 2D mode) it verifies that every 3D call is refused with
 * STATUS_NOT_SUPPORTED and prints "GPU-3D: unavailable ..."; that is the expected outcome there, not a pass of the 3D path.
 * Without any display it reports SKIP.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
#include "shzgpu.h"
#include "shzvirgl.h"

static int bad;
#define CHECK(cond, name) do { if (cond) printf("PASS: %s\n", name); else { printf("FAIL: %s (line %d)\n", name, __LINE__); ++bad; } } while (0)
#define NT_NOT_SUPPORTED ((int32_t)0xC00000BB)
#define NT_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#define W 64
#define H 64

static const float clear[4] = { 0.2f, 0.4f, 0.6f, 1.0f };
static const float verts[24] = { -0.8f, -0.7f, 0.0f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f,
                                 0.9f, -0.55f, 0.0f, 1.0f, 0.0f, 1.0f, 0.0f, 1.0f,
                                 -0.1f, 0.85f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f };

static int unavailable(const shz_gpu_info_t *info)
{
    uint32_t ctx = 0, n = 0, caps[4];
    shz_gpu_res_t r;
    uint32_t dw[2] = { 0, 0 };
    memset(&r, 0, sizeof r);
    CHECK(!(info->features & SHZ_GPU_FEAT_VIRGL), "the device did not negotiate VIRGL");
    CHECK(ShzGpuCreateContext("t_gpu_3d", &ctx) == NT_NOT_SUPPORTED, "ShzGpuCreateContext -> STATUS_NOT_SUPPORTED");
    CHECK(ShzGpuGetCapset(SHZ_GPU_CAPSET_VIRGL2, 1, caps, sizeof caps, &n) == NT_NOT_SUPPORTED, "ShzGpuGetCapset -> STATUS_NOT_SUPPORTED");
    CHECK(ShzGpuCreateResource(&r) == NT_NOT_SUPPORTED, "ShzGpuCreateResource -> STATUS_NOT_SUPPORTED");
    CHECK(ShzGpuSubmit(1, dw, 2) == NT_NOT_SUPPORTED, "ShzGpuSubmit -> STATUS_NOT_SUPPORTED");
    printf("GPU-3D: unavailable (backend %u, VIRGL not negotiated): every 3D call refused with STATUS_NOT_SUPPORTED\n", info->backend);
    printf("%s: GPU 3D test (negative path only)\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}

int main(void)
{
    static uint32_t caps[1024], cmd[4096], pix[W * H];
    shz_gpu_info_t info;
    shz_gpu_res_t rt, vb;
    shz_virgl_cs_t cs;
    shz_virgl_tri_check_t t;
    uint32_t ctx = 0, n = 0;
    int32_t st;
    st = ShzGpuQuery(&info);
    if (st == NT_NO_SUCH_DEVICE) { printf("SKIP: no display device (%08x)\n", (unsigned)st); return 0; }
    CHECK(st >= 0, "ShzGpuQuery");
    if (st < 0) return 1;
    if (!(info.features & SHZ_GPU_FEAT_VIRGL)) return unavailable(&info);

    st = ShzGpuGetCapset(SHZ_GPU_CAPSET_VIRGL2, 1, caps, sizeof caps, &n);
    CHECK(st >= 0 && n >= 308, "capset VIRGL2 read from the host");
    /* struct virgl_caps_v1: max_version, 4 x 16-dword format masks, bool set, glsl_level at dword 1+64+1 */
    printf("GPU-3D: host caps %u bytes, glsl_level %u, max_render_targets %u\n", n, caps[66], caps[70]);
    st = ShzGpuCreateContext("t_gpu_3d", &ctx);
    CHECK(st >= 0 && ctx, "virgl context created");
    if (st < 0) return 1;
    memset(&rt, 0, sizeof rt);
    rt.ctx = ctx; rt.target = SHZ_PIPE_TEXTURE_2D; rt.format = SHZ_VIRGL_FORMAT_B8G8R8A8_UNORM;
    rt.bind = SHZ_VIRGL_BIND_RENDER_TARGET | SHZ_VIRGL_BIND_SAMPLER_VIEW;
    rt.width = W; rt.height = H; rt.depth = 1; rt.array_size = 1;
    CHECK(ShzGpuCreateResource(&rt) >= 0 && rt.res >= 16 && rt.backing_bytes >= W * H * 4, "64x64 render target (RESOURCE_CREATE_3D)");
    memset(&vb, 0, sizeof vb);
    vb.ctx = ctx; vb.target = SHZ_PIPE_BUFFER; vb.format = SHZ_VIRGL_FORMAT_R8_UNORM; vb.bind = SHZ_VIRGL_BIND_VERTEX_BUFFER;
    vb.width = 4096; vb.height = 1; vb.depth = 1; vb.array_size = 1;
    CHECK(ShzGpuCreateResource(&vb) >= 0 && vb.res > rt.res, "vertex buffer");
    shz_virgl_init(&cs, cmd, sizeof cmd / 4);
    shz_virgl_encode_triangle(&cs, rt.res, vb.res, W, H, clear, verts);
    CHECK(!cs.overflow, "stream encoded");
    st = ShzGpuSubmit(ctx, cmd, cs.len);
    CHECK(st >= 0, "SUBMIT_3D (clear, TGSI VS/FS, triangle) completed by the host");
    memset(pix, 0xab, sizeof pix);
    st = ShzGpuReadback(ctx, rt.res, W, H, pix, W * 4);
    CHECK(st >= 0, "TRANSFER_FROM_HOST_3D of the render target");
    shz_virgl_check_triangle(pix, W, H, clear, verts, &t);
    printf("GPU-3D: %d covered pixels (%d right), %d clear (%d right), %d on edges\n", t.covered, t.inside_ok, t.outside,
           t.outside_ok, t.edge);
    CHECK(t.covered > 500 && t.inside_ok == t.covered && t.outside > 500 && t.outside_ok == t.outside && t.edge < 64,
          "rendered triangle matches the geometry (interpolated colours inside, clear colour outside)");
    CHECK(ShzGpuDestroyResource(vb.res) >= 0 && ShzGpuDestroyResource(rt.res) >= 0, "resources destroyed");
    CHECK(ShzGpuDestroyResource(rt.res) < 0, "a destroyed resource id is invalid");
    CHECK(ShzGpuDestroyContext(ctx) >= 0, "context destroyed");
    if (!bad) printf("GPU-3D: triangle verified\n");
    printf("%s: GPU 3D test\n", bad ? "FAIL" : "PASS");
    return bad ? 1 : 0;
}
