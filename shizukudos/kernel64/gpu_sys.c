/* SPDX-License-Identifier: GPL-2.0-only
 * GPU system calls 0xd0-0xdf (sys_ext_gpu, routed by sysext.c; ABI in win64/include/shzgpu.h, user library shzgpu.dll).
 *
 * This file owns validation, copying between user and kernel memory and object ownership; the device work is done by
 * gfx_virtio.c (gpu.h). 3D contexts and resources belong to the process that created them: only it can use or destroy
 * them, and the ones of processes that no longer exist are released at the next GPU system call (no process-exit hook is
 * needed). Resource ids 1 and 2 are the kernel's own (desktop scanout, cursor); user resources start at 16 and are never
 * reused. Every buffer handed to the device is kernel memory (gfx_pages_alloc): user pages are never given to the device.
 */
#include "gpu.h"

typedef struct { int used; uint32_t id; int pid; } gctx_t;
typedef struct { int used; uint32_t id, ctx; int pid; void *backing; uint64_t bytes; } gres_t;

static gctx_t g_ctx[SHZ_GPU_MAX_CONTEXTS];
static gres_t g_res[SHZ_GPU_MAX_RESOURCES];
static uint32_t g_next_res = 16;
static kmutex_t gpu_lock;                           /* the two tables; held across device calls (they never re-enter) */

static int pid_alive(int pid)
{
    process_t *p = process_by_pid(pid);
    return p && !p->terminated;
}

/* gpu_lock held */
static void res_release(gres_t *r)
{
    vg_res3d_destroy(r->ctx, r->id);
    gfx_pages_free(r->backing, r->bytes);
    memset(r, 0, sizeof *r);
}

/* gpu_lock held: drop everything owned by processes that are gone */
static void reap(void)
{
    unsigned i;
    for (i = 0; i < SHZ_GPU_MAX_RESOURCES; ++i)
        if (g_res[i].used && !pid_alive(g_res[i].pid)) res_release(&g_res[i]);
    for (i = 0; i < SHZ_GPU_MAX_CONTEXTS; ++i)
        if (g_ctx[i].used && !pid_alive(g_ctx[i].pid)) {
            vg_ctx_destroy(g_ctx[i].id);
            g_ctx[i].used = 0;
        }
}

static gctx_t *ctx_of(process_t *cur, uint64_t id)
{
    if (!id || id > SHZ_GPU_MAX_CONTEXTS || !g_ctx[id - 1].used || g_ctx[id - 1].pid != cur->pid) return 0;
    return &g_ctx[id - 1];
}

static gres_t *res_of(process_t *cur, uint64_t id)
{
    unsigned i;
    for (i = 0; i < SHZ_GPU_MAX_RESOURCES; ++i)
        if (g_res[i].used && g_res[i].id == id && g_res[i].pid == cur->pid) return &g_res[i];
    return 0;
}

static int32_t sys_query(process_t *cur, uint64_t uinfo)
{
    shz_gpu_info_t info;
    uint32_t size = 0;
    if (copy_from_user(cur, &size, uinfo, sizeof size)) return STATUS_ACCESS_VIOLATION;
    if (size != sizeof info) return STATUS_INFO_LENGTH_MISMATCH;
    memset(&info, 0, sizeof info);
    info.size = sizeof info;
    info.backend = g_fb.backend->id;
    info.width = g_fb.width;
    info.height = g_fb.height;
    info.pitch = g_fb.pitch;
    info.stats.presents = g_fb.stat_presents;
    info.stats.present_pixels = g_fb.stat_present_pixels;
    if (info.backend == SHZ_GPU_BACKEND_VIRTIO) vg_fill_info(&info);
    return copy_to_user(cur, uinfo, &info, sizeof info) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

static int32_t sys_edid(process_t *cur, uint64_t ubuf, uint64_t len, uint64_t uout)
{
    static uint8_t e[1024];
    uint32_t n = 0;
    int32_t st;
    if (!vg_active()) return STATUS_NOT_SUPPORTED;
    mutex_lock(&gpu_lock);
    st = vg_get_edid(e, sizeof e, &n);
    if (!st && ubuf && copy_to_user(cur, ubuf, e, len < n ? len : n)) st = STATUS_ACCESS_VIOLATION;
    mutex_unlock(&gpu_lock);
    if (!st && uout && copy_to_user(cur, uout, &n, sizeof n)) st = STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_cursor(process_t *cur, uint64_t uc)
{
    const uint64_t bytes = SHZ_GPU_CURSOR_W * SHZ_GPU_CURSOR_H * 4u;
    shz_gpu_cursor_t c;
    uint32_t *img = 0;
    int32_t st;
    if (copy_from_user(cur, &c, uc, sizeof c)) return STATUS_ACCESS_VIOLATION;
    if (c.op < SHZ_GPU_CURSOR_SHAPE || c.op > SHZ_GPU_CURSOR_HIDE) return STATUS_INVALID_PARAMETER;
    if (!vg_active()) return STATUS_NOT_SUPPORTED;                          /* the BGA has no cursor plane */
    if (c.op == SHZ_GPU_CURSOR_SHAPE) {
        img = gfx_pages_alloc(bytes);
        if (!img) return STATUS_NO_MEMORY;
        if (copy_from_user(cur, img, c.pixels, bytes)) {
            gfx_pages_free(img, bytes);
            return STATUS_ACCESS_VIOLATION;
        }
    }
    st = vg_cursor(c.op, img, c.hot_x, c.hot_y, c.x, c.y);
    if (img) gfx_pages_free(img, bytes);
    return st;
}

static int32_t sys_capset(process_t *cur, uint64_t uc)
{
    shz_gpu_capset_t c;
    uint8_t *buf;
    uint32_t n = 0;
    int32_t st;
    if (copy_from_user(cur, &c, uc, sizeof c)) return STATUS_ACCESS_VIOLATION;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    if (c.buf_len > (64u << 10)) c.buf_len = 64u << 10;
    buf = gfx_pages_alloc(c.buf_len ? c.buf_len : 1);
    if (!buf) return STATUS_NO_MEMORY;
    st = vg_capset(c.id, c.version, buf, c.buf_len, &n);
    if (!st && c.buf_len && copy_to_user(cur, c.buf, buf, c.buf_len < n ? c.buf_len : n)) st = STATUS_ACCESS_VIOLATION;
    gfx_pages_free(buf, c.buf_len ? c.buf_len : 1);
    c.out_len = n;
    if (!st && copy_to_user(cur, uc, &c, sizeof c)) st = STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_ctx_create(process_t *cur, uint64_t uname, uint64_t uout)
{
    char name[64];
    uint64_t len = 0;
    unsigned i;
    uint32_t id = 0;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    if (uname) {
        if (user_string_len(cur, uname, sizeof name - 1, &len) || copy_from_user(cur, name, uname, len)) return STATUS_ACCESS_VIOLATION;
    }
    name[len] = 0;
    mutex_lock(&gpu_lock);
    reap();
    for (i = 0; i < SHZ_GPU_MAX_CONTEXTS && g_ctx[i].used; ++i)
        ;
    if (i == SHZ_GPU_MAX_CONTEXTS) st = STATUS_INSUFFICIENT_RESOURCES;
    else {
        id = i + 1;
        st = vg_ctx_create(id, name, (uint32_t)len);
        if (!st) {
            g_ctx[i].used = 1;
            g_ctx[i].id = id;
            g_ctx[i].pid = cur->pid;
        }
    }
    mutex_unlock(&gpu_lock);
    if (!st && copy_to_user(cur, uout, &id, sizeof id)) st = STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_ctx_destroy(process_t *cur, uint64_t id)
{
    gctx_t *c;
    unsigned i;
    int32_t st = STATUS_INVALID_HANDLE;
    mutex_lock(&gpu_lock);
    c = ctx_of(cur, id);
    if (c) {
        for (i = 0; i < SHZ_GPU_MAX_RESOURCES; ++i)
            if (g_res[i].used && g_res[i].ctx == c->id) res_release(&g_res[i]);
        st = vg_ctx_destroy(c->id);
        c->used = 0;
    }
    mutex_unlock(&gpu_lock);
    return st;
}

static int32_t sys_res_create(process_t *cur, uint64_t ur)
{
    shz_gpu_res_t a;
    gres_t *slot = 0;
    uint64_t bytes;
    unsigned i;
    int32_t st;
    if (copy_from_user(cur, &a, ur, sizeof a)) return STATUS_ACCESS_VIOLATION;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    if (a.target == 0 /* PIPE_BUFFER */) {
        if (!a.width || a.height != 1 || a.depth != 1 || a.array_size != 1) return STATUS_INVALID_PARAMETER;
        bytes = a.width;
    } else if (a.target == 2 /* PIPE_TEXTURE_2D */) {
        if (!a.width || !a.height || a.width > 4096 || a.height > 4096 || a.depth != 1 || a.array_size != 1)
            return STATUS_INVALID_PARAMETER;
        bytes = (uint64_t)a.width * a.height * 4u;                         /* 32-bit formats only */
    } else {
        return STATUS_NOT_SUPPORTED;
    }
    if (bytes > SHZ_GPU_MAX_BACKING) return STATUS_INVALID_PARAMETER;
    bytes = (bytes + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    mutex_lock(&gpu_lock);
    reap();
    if (!ctx_of(cur, a.ctx)) {
        mutex_unlock(&gpu_lock);
        return STATUS_INVALID_HANDLE;
    }
    for (i = 0; i < SHZ_GPU_MAX_RESOURCES && !slot; ++i)
        if (!g_res[i].used) slot = &g_res[i];
    if (!slot) st = STATUS_INSUFFICIENT_RESOURCES;
    else if (!(slot->backing = gfx_pages_alloc(bytes))) st = STATUS_NO_MEMORY;
    else {
        slot->id = g_next_res++;
        st = vg_res3d_create(a.ctx, slot->id, &a, slot->backing, bytes);
        if (st) {
            gfx_pages_free(slot->backing, bytes);
            slot->backing = 0;
        } else {
            slot->used = 1;
            slot->ctx = a.ctx;
            slot->pid = cur->pid;
            slot->bytes = bytes;
            a.res = slot->id;
            a.backing_bytes = bytes;
        }
    }
    mutex_unlock(&gpu_lock);
    if (!st && copy_to_user(cur, ur, &a, sizeof a)) st = STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t sys_res_destroy(process_t *cur, uint64_t id)
{
    gres_t *r;
    int32_t st = STATUS_INVALID_HANDLE;
    mutex_lock(&gpu_lock);
    r = res_of(cur, id);
    if (r) {
        res_release(r);
        st = STATUS_SUCCESS;
    }
    mutex_unlock(&gpu_lock);
    return st;
}

static int32_t sys_submit(process_t *cur, uint64_t ctx, uint64_t ustream, uint64_t bytes)
{
    void *buf;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    if (!bytes || bytes % 4 || bytes > SHZ_GPU_MAX_SUBMIT) return STATUS_INVALID_PARAMETER;
    buf = gfx_pages_alloc(bytes);
    if (!buf) return STATUS_NO_MEMORY;
    if (copy_from_user(cur, buf, ustream, bytes)) {
        gfx_pages_free(buf, bytes);
        return STATUS_ACCESS_VIOLATION;
    }
    mutex_lock(&gpu_lock);
    st = ctx_of(cur, ctx) ? vg_submit3d((uint32_t)ctx, buf, (uint32_t)bytes) : STATUS_INVALID_HANDLE;
    mutex_unlock(&gpu_lock);
    gfx_pages_free(buf, bytes);
    return st;
}

static int32_t sys_transfer(process_t *cur, uint64_t ux)
{
    shz_gpu_xfer_t x;
    gres_t *r;
    vg_box_t box;
    int32_t st;
    if (copy_from_user(cur, &x, ux, sizeof x)) return STATUS_ACCESS_VIOLATION;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    if (x.direction != SHZ_GPU_TO_HOST && x.direction != SHZ_GPU_FROM_HOST) return STATUS_INVALID_PARAMETER;
    mutex_lock(&gpu_lock);
    r = res_of(cur, x.res);
    if (!r || r->ctx != x.ctx || !ctx_of(cur, x.ctx)) st = STATUS_INVALID_HANDLE;
    else if (x.data_len > r->bytes) st = STATUS_INVALID_PARAMETER;
    else if (x.direction == SHZ_GPU_TO_HOST && x.data_len && copy_from_user(cur, r->backing, x.data, x.data_len))
        st = STATUS_ACCESS_VIOLATION;
    else {
        box.x = x.x; box.y = x.y; box.z = x.z; box.w = x.w; box.h = x.h; box.d = x.d;
        st = vg_transfer3d(x.ctx, x.res, x.direction == SHZ_GPU_TO_HOST, &box, x.level, x.stride, x.layer_stride);
        if (!st && x.direction == SHZ_GPU_FROM_HOST && x.data_len && copy_to_user(cur, x.data, r->backing, x.data_len))
            st = STATUS_ACCESS_VIOLATION;
    }
    mutex_unlock(&gpu_lock);
    return st;
}

int32_t sys_ext_gpu(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    int32_t st;
    (void)r;
    (void)a4;
    if (num < SYS_NtShzGpuQuery || num > SYS_NtShzGpuTransfer) return STATUS_INVALID_SYSTEM_SERVICE;
    st = gfx_fb_init();                                 /* lazily brings the display up (STATUS_NO_SUCH_DEVICE without one) */
    if (st) return st;
    switch (num) {
    case SYS_NtShzGpuQuery: return sys_query(cur, a1);
    case SYS_NtShzGpuEdid: return sys_edid(cur, a1, a2, a3);
    case SYS_NtShzGpuCursor: return sys_cursor(cur, a1);
    case SYS_NtShzGpuCapset: return sys_capset(cur, a1);
    case SYS_NtShzGpuCtxCreate: return sys_ctx_create(cur, a1, a2);
    case SYS_NtShzGpuCtxDestroy: return sys_ctx_destroy(cur, a1);
    case SYS_NtShzGpuResourceCreate: return sys_res_create(cur, a1);
    case SYS_NtShzGpuResourceDestroy: return sys_res_destroy(cur, a1);
    case SYS_NtShzGpuSubmit: return sys_submit(cur, a1, a2, a3);
    case SYS_NtShzGpuTransfer: return sys_transfer(cur, a1);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
