/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 virtio-gpu driver (Virtio 1.2, OASIS, section 5.7), on the virtio-pci transport of virtio_pci.c.
 *
 * Role 1, display backend of gfx_fb.c (gfx_backend_virtio): the desktop is ONE host-side 2D resource (B8G8R8X8, the
 * mode of the GUI) whose guest backing IS the compositor's back buffer, bound to scanout 0. gfx_fb_present(rect) sends
 * TRANSFER_TO_HOST_2D for exactly that rectangle (offset = y * pitch + x * 4, so the host copies only those rows and
 * columns) and RESOURCE_FLUSH for the same rectangle, as one batch with one doorbell, and waits for both answers, so the
 * rectangle is on the host's display when present returns. There is no full-frame copy after start-up.
 * Role 2, device side of the GPU system calls (gpu_sys.c): EDID, hardware cursor (a 64x64 B8G8R8A8 resource shown on
 * the cursor queue), capability sets, and with VIRTIO_GPU_F_VIRGL the 3D commands (CTX_CREATE, RESOURCE_CREATE_3D,
 * CTX_ATTACH_RESOURCE, SUBMIT_3D, TRANSFER_TO/FROM_HOST_3D) that make the HOST execute virgl command streams with its
 * GPU driver: the accelerated path. Fenced 3D commands are answered by the device only once the host has finished them.
 *
 * Command engine: requests and small responses bounce through VG_SLOTS DMA pages; large payloads (backing-entry lists,
 * 3D command streams, capsets) are passed as extra descriptors pointing at their pages. All device access is serialised
 * by vg.lock and every call waits for its answers before returning, so the ring never holds stale chains. Completions
 * are signalled by INTx (virtio_pci_irq_enable) when the line is free, otherwise the used ring is polled; the wait never
 * sleeps with interrupts disabled. A command that is not answered within VG_TIMEOUT_MS disables the device (the chains
 * still point at the slots) and the display stops updating instead of corrupting memory.
 *
 * Profiles: in the Supervisor profile virtio_pci_find() always fails, so this driver never probes successfully.
 * Not implemented: multiple scanouts, display hot-plug/resize (config-change events are only counted), blob resources,
 * context types other than virgl (CONTEXT_INIT), VIRTIO_F_RING_EVENT_IDX / indirect descriptors.
 */
#include "gfx.h"
#include "gpu.h"
#include "virtio_pci.h"
#include "virtio_gpu.h"

#define VG_SLOTS 4u                         /* commands per batch */
#define VG_REQ_MAX 2048u                    /* request bytes in a slot page; the response area follows */
#define VG_RESP_MAX 2048u
#define VG_ENT_PAGES 4u                     /* attach-backing entry pages: 1024 physically contiguous runs */
#define VG_MAX_SG 80u                       /* descriptors of one chain besides the slot */
#define VG_TIMEOUT_MS 5000u
#define VG_FB_RES 1u
#define VG_CURSOR_RES 2u

typedef struct {
    const void *req;
    uint32_t req_len;
    const virtq_sg_t *out_x;                /* extra device-readable buffers after the request */
    unsigned n_out_x;
    void *resp;                             /* response copied back here (<= VG_RESP_MAX) */
    uint32_t resp_len;
    const virtq_sg_t *in_x;                 /* or: device-writable buffers the caller reads itself */
    unsigned n_in_x;
    uint32_t resp_type;                     /* out: type of the response header (0 when there is none) */
} vg_cmd_t;

static struct {
    int ok;
    virtio_dev_t dev;
    virtq_t *ctrlq, *cursorq;
    int irq;
    ksem_t kick;
    volatile int kick_pending;
    kmutex_t lock;
    uint64_t slot_pa[VG_SLOTS];
    uint64_t ent_pa[VG_ENT_PAGES];
    uint32_t width, height, pitch;
    uint32_t host_w, host_h, num_scanouts, num_capsets, config_events;
    uint8_t edid[1024];
    uint32_t edid_len, edid_w, edid_h;
    char edid_vendor[4];
    uint32_t capset_id[4], capset_ver[4], capset_size[4], ncapsets;
    uint64_t fence;
    uint32_t *cursor_img;
    int cursor_ready;
    shz_gpu_stats_t st;
} vg;

static inline int irqs_enabled(void) { uint64_t f; __asm__ volatile("pushfq; popq %0" : "=r"(f)); return (f >> 9) & 1; }

static void vg_irq(void *arg, uint8_t isr)
{
    (void)arg;
    if (isr & 2) ++vg.config_events;
    if (!(isr & 1)) return;
    ++vg.st.irqs;
    if (!vg.kick_pending) {
        vg.kick_pending = 1;
        sem_post(&vg.kick);
    }
}

/* Lock held. Queues n commands on q with one doorbell and waits until the device has returned every one of them. */
static int32_t vg_run(virtq_t *q, vg_cmd_t *c, unsigned n)
{
    virtq_sg_t out[1 + VG_MAX_SG], in[1 + VG_MAX_SG];
    unsigned i, j, pending = 0;
    uint64_t t0;
    if (!vg.ok) return STATUS_NO_SUCH_DEVICE;
    KASSERT(n && n <= VG_SLOTS);
    for (i = 0; i < n; ++i) {
        uint8_t *slot = (uint8_t *)p2v(vg.slot_pa[i]);
        unsigned no = 0, ni = 0;
        KASSERT(c[i].req_len <= VG_REQ_MAX && c[i].resp_len <= VG_RESP_MAX && c[i].n_out_x <= VG_MAX_SG && c[i].n_in_x <= VG_MAX_SG);
        memcpy(slot, c[i].req, c[i].req_len);
        out[no].pa = vg.slot_pa[i];
        out[no++].len = c[i].req_len;
        for (j = 0; j < c[i].n_out_x; ++j) out[no++] = c[i].out_x[j];
        if (c[i].resp_len) {
            memset(slot + VG_REQ_MAX, 0, c[i].resp_len);
            in[ni].pa = vg.slot_pa[i] + VG_REQ_MAX;
            in[ni++].len = c[i].resp_len;
        }
        for (j = 0; j < c[i].n_in_x; ++j) in[ni++] = c[i].in_x[j];
        c[i].resp_type = 0;
        if (virtq_add(q, out, no, in, ni, (void *)(uintptr_t)(i + 1)) < 0) {
            kprintf("K64 virtio-gpu: queue %u has no room for a %u-descriptor chain\n", q->index, no + ni);
            vg.ok = 0;                                          /* chains queued before this one are still outstanding */
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        pending |= 1u << i;
    }
    if (virtq_kick_prepare(q)) {
        virtio_pci_notify(&vg.dev, q);
        ++vg.st.notifies;
    }
    t0 = ticks_now();
    for (;;) {
        void *ck;
        uint32_t written;
        vg.kick_pending = 0;
        __asm__ volatile("" ::: "memory");
        while ((ck = virtq_get_used(q, &written)) != 0) {
            const unsigned k = (unsigned)(uintptr_t)ck - 1;
            if (k < n) pending &= ~(1u << k);
        }
        if (!pending) break;
        if (ticks_now() - t0 > VG_TIMEOUT_MS) {
            kprintf("K64 virtio-gpu: no answer from the device within %u ms (pending mask %x); display disabled\n",
                    VG_TIMEOUT_MS, pending);
            vg.ok = 0;
            return STATUS_IO_TIMEOUT;
        }
        if (vg.irq && irqs_enabled()) sem_wait_timeout(&vg.kick, 10);
        else if (irqs_enabled()) thread_yield();
        else __asm__ volatile("pause");
    }
    for (i = 0; i < n; ++i) {
        if (c[i].resp_len) {
            memcpy(c[i].resp, (uint8_t *)p2v(vg.slot_pa[i]) + VG_REQ_MAX, c[i].resp_len);
            c[i].resp_type = ((const vgpu_hdr_t *)c[i].resp)->type;
            if (c[i].resp_type >= VGPU_RESP_ERR_UNSPEC) ++vg.st.errors;
        }
        if (q == vg.ctrlq) ++vg.st.ctrl_cmds;
        else ++vg.st.cursor_cmds;
    }
    return STATUS_SUCCESS;
}

/* Lock held: one control command with a header-only answer. */
static int32_t vg_simple(const void *req, uint32_t len, const virtq_sg_t *x, unsigned nx)
{
    vgpu_hdr_t resp;
    vg_cmd_t c;
    int32_t st;
    memset(&c, 0, sizeof c);
    c.req = req;
    c.req_len = len;
    c.out_x = x;
    c.n_out_x = nx;
    c.resp = &resp;
    c.resp_len = sizeof resp;
    st = vg_run(vg.ctrlq, &c, 1);
    if (st) return st;
    if (c.resp_type != VGPU_RESP_OK_NODATA) {
        kprintf("K64 virtio-gpu: command %x answered %x\n", ((const vgpu_hdr_t *)req)->type, c.resp_type);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

static void hdr(vgpu_hdr_t *h, uint32_t type, uint32_t ctx, int fence)
{
    memset(h, 0, sizeof *h);
    h->type = type;
    h->ctx_id = ctx;
    if (fence) {
        h->flags = VGPU_FLAG_FENCE;
        h->fence_id = ++vg.fence;
    }
}

/* Physically contiguous runs of a page-aligned kernel buffer (direct map or gfx_pages arena), at most `max`. */
static unsigned vg_runs(const void *va, uint64_t bytes, virtq_sg_t *sg, unsigned max)
{
    uint64_t off;
    unsigned n = 0;
    for (off = 0; off < bytes; off += PAGE_SIZE) {
        const uint64_t pa = vm_lookup(kernel_pml4(), (uint64_t)va + off, 0) & ~0xfffull;
        const uint32_t len = (uint32_t)(bytes - off < PAGE_SIZE ? bytes - off : PAGE_SIZE);
        if (!pa) return 0;
        if (n && sg[n - 1].pa + sg[n - 1].len == pa && sg[n - 1].len < (1u << 30)) sg[n - 1].len += len;
        else if (n == max) return 0;
        else { sg[n].pa = pa; sg[n].len = len; ++n; }
    }
    return n;
}

/* Lock held: RESOURCE_ATTACH_BACKING with the entry list built in the entry pages. */
static int32_t vg_attach(uint32_t res, const void *va, uint64_t bytes)
{
    static virtq_sg_t runs[VG_ENT_PAGES * (PAGE_SIZE / sizeof(vgpu_mem_entry_t))];
    virtq_sg_t x[VG_ENT_PAGES];
    vgpu_resource_attach_backing_t ab;
    const unsigned per_page = PAGE_SIZE / sizeof(vgpu_mem_entry_t);
    unsigned n = vg_runs(va, bytes, runs, sizeof runs / sizeof runs[0]), i, pages;
    if (!n) return STATUS_INSUFFICIENT_RESOURCES;
    for (i = 0; i < n; ++i) {
        vgpu_mem_entry_t *e = (vgpu_mem_entry_t *)p2v(vg.ent_pa[i / per_page]) + i % per_page;
        e->addr = runs[i].pa;
        e->length = runs[i].len;
        e->pad = 0;
    }
    pages = (n + per_page - 1) / per_page;
    for (i = 0; i < pages; ++i) {
        x[i].pa = vg.ent_pa[i];
        x[i].len = (uint32_t)((i + 1 < pages ? per_page : n - i * per_page) * sizeof(vgpu_mem_entry_t));
    }
    hdr(&ab.hdr, VGPU_CMD_RESOURCE_ATTACH_BACKING, 0, 0);
    ab.resource_id = res;
    ab.nr_entries = n;
    return vg_simple(&ab, sizeof ab, x, pages);
}

/* Lock held: TRANSFER_TO_HOST_2D of one rectangle of a 2D resource with the given pitch. */
static void vg_xfer2d_req(vgpu_transfer_to_host_2d_t *t, uint32_t res, uint32_t pitch, int x, int y, int w, int h)
{
    hdr(&t->hdr, VGPU_CMD_TRANSFER_TO_HOST_2D, 0, 0);
    t->r.x = (uint32_t)x; t->r.y = (uint32_t)y; t->r.width = (uint32_t)w; t->r.height = (uint32_t)h;
    t->offset = (uint64_t)y * pitch + (uint64_t)x * 4u;
    t->resource_id = res;
    t->pad = 0;
}

static void vg_parse_edid(void)
{
    static const uint8_t magic[8] = { 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0 };
    uint8_t sum = 0;
    unsigned i;
    const uint8_t *e = vg.edid;
    if (vg.edid_len < 128 || memcmp(e, magic, 8)) {
        kprintf("K64 virtio-gpu: EDID of %u bytes has no valid header; ignored\n", vg.edid_len);
        vg.edid_len = 0;
        return;
    }
    for (i = 0; i < 128; ++i) sum = (uint8_t)(sum + e[i]);
    if (sum) {
        kprintf("K64 virtio-gpu: EDID checksum wrong (%x); ignored\n", sum);
        vg.edid_len = 0;
        return;
    }
    vg.edid_vendor[0] = (char)('@' + ((e[8] >> 2) & 0x1f));
    vg.edid_vendor[1] = (char)('@' + (((e[8] & 3) << 3) | (e[9] >> 5)));
    vg.edid_vendor[2] = (char)('@' + (e[9] & 0x1f));
    vg.edid_vendor[3] = 0;
    if (e[54] | e[55]) {                                        /* first descriptor is a detailed timing: preferred mode */
        vg.edid_w = e[56] | ((uint32_t)(e[58] & 0xf0) << 4);
        vg.edid_h = e[59] | ((uint32_t)(e[61] & 0xf0) << 4);
    }
}

static int vg_probe(gfx_fb_t *fb)
{
    vgpu_hdr_t q;
    vgpu_resp_display_info_t di;
    vgpu_resource_create_2d_t rc;
    vgpu_set_scanout_t so;
    vg_cmd_t c;
    unsigned i;
    int32_t st;
    if (virtio_pci_find(VIRTIO_ID_GPU, &vg.dev)) return -1;
    kprintf("K64 virtio-gpu: PCI %x:%x.%x id %x:%x irq %u\n", vg.dev.pci.bus, vg.dev.pci.dev, vg.dev.pci.fn, vg.dev.pci.vendor,
            vg.dev.pci.device, vg.dev.irq_line);
    if (virtio_pci_negotiate(&vg.dev, (1ull << VGPU_F_VIRGL) | (1ull << VGPU_F_EDID))) return -1;
    vg.ctrlq = virtio_pci_queue_setup(&vg.dev, 0, 256);
    vg.cursorq = virtio_pci_queue_setup(&vg.dev, 1, 16);
    for (i = 0; i < VG_SLOTS; ++i) vg.slot_pa[i] = pmm_alloc();
    for (i = 0; i < VG_ENT_PAGES; ++i) vg.ent_pa[i] = pmm_alloc();
    for (i = 0; i < VG_SLOTS; ++i) if (!vg.slot_pa[i]) goto fail;
    for (i = 0; i < VG_ENT_PAGES; ++i) if (!vg.ent_pa[i]) goto fail;
    if (!vg.ctrlq || !vg.cursorq) goto fail;
    sem_init(&vg.kick, 0);
    vg.irq = virtio_pci_irq_enable(&vg.dev, vg_irq, 0) == 0;
    virtio_pci_driver_ok(&vg.dev);
    if (virtio_pci_status(&vg.dev) & VIRTIO_STATUS_DEVICE_NEEDS_RESET) goto fail;
    vg.num_scanouts = virtio_pci_cfg_read32(&vg.dev, VGPU_CFG_NUM_SCANOUTS);
    vg.num_capsets = virtio_pci_cfg_read32(&vg.dev, VGPU_CFG_NUM_CAPSETS);
    if (virtio_pci_cfg_read32(&vg.dev, VGPU_CFG_EVENTS_READ))
        virtio_pci_cfg_write32(&vg.dev, VGPU_CFG_EVENTS_CLEAR, virtio_pci_cfg_read32(&vg.dev, VGPU_CFG_EVENTS_READ));
    vg.ok = 1;
    vg.width = fb->width;
    vg.height = fb->height;
    vg.pitch = fb->pitch;
    mutex_lock(&vg.lock);
    /* display info: the mode the host would like on scanout 0 (only reported; the GUI keeps its own mode) */
    memset(&c, 0, sizeof c);
    hdr(&q, VGPU_CMD_GET_DISPLAY_INFO, 0, 0);
    c.req = &q; c.req_len = sizeof q; c.resp = &di; c.resp_len = sizeof di;
    st = vg_run(vg.ctrlq, &c, 1);
    if (st || c.resp_type != VGPU_RESP_OK_DISPLAY_INFO) goto fail_locked;
    if (di.pmodes[0].enabled) {
        vg.host_w = di.pmodes[0].r.width;
        vg.host_h = di.pmodes[0].r.height;
    }
    if (vg.dev.driver_features & (1ull << VGPU_F_EDID)) {
        static vgpu_resp_edid_t er;
        vgpu_get_edid_t ge;
        hdr(&ge.hdr, VGPU_CMD_GET_EDID, 0, 0);
        ge.scanout = 0;
        ge.pad = 0;
        memset(&c, 0, sizeof c);
        c.req = &ge; c.req_len = sizeof ge; c.resp = &er; c.resp_len = sizeof er;
        st = vg_run(vg.ctrlq, &c, 1);
        if (st) goto fail_locked;
        if (c.resp_type == VGPU_RESP_OK_EDID && er.size <= sizeof vg.edid) {
            memcpy(vg.edid, er.edid, er.size);
            vg.edid_len = er.size;
            vg_parse_edid();
        }
    }
    if (vg.dev.driver_features & (1ull << VGPU_F_VIRGL))
        for (i = 0; i < vg.num_capsets && i < 4; ++i) {
            vgpu_get_capset_info_t gi;
            vgpu_resp_capset_info_t ri;
            hdr(&gi.hdr, VGPU_CMD_GET_CAPSET_INFO, 0, 0);
            gi.capset_index = i;
            gi.pad = 0;
            memset(&c, 0, sizeof c);
            c.req = &gi; c.req_len = sizeof gi; c.resp = &ri; c.resp_len = sizeof ri;
            if (vg_run(vg.ctrlq, &c, 1) || c.resp_type != VGPU_RESP_OK_CAPSET_INFO) break;
            vg.capset_id[vg.ncapsets] = ri.capset_id;
            vg.capset_ver[vg.ncapsets] = ri.capset_max_version;
            vg.capset_size[vg.ncapsets] = ri.capset_max_size;
            ++vg.ncapsets;
        }
    /* the desktop resource, backed by the compositor's back buffer, on scanout 0 */
    hdr(&rc.hdr, VGPU_CMD_RESOURCE_CREATE_2D, 0, 0);
    rc.resource_id = VG_FB_RES;
    rc.format = VGPU_FORMAT_B8G8R8X8_UNORM;
    rc.width = fb->width;
    rc.height = fb->height;
    if (vg_simple(&rc, sizeof rc, 0, 0)) goto fail_locked;
    if (vg_attach(VG_FB_RES, fb->back, (uint64_t)fb->pitch * fb->height)) goto fail_locked;
    hdr(&so.hdr, VGPU_CMD_SET_SCANOUT, 0, 0);
    so.r.x = 0; so.r.y = 0; so.r.width = fb->width; so.r.height = fb->height;
    so.scanout_id = 0;
    so.resource_id = VG_FB_RES;
    if (vg_simple(&so, sizeof so, 0, 0)) goto fail_locked;
    mutex_unlock(&vg.lock);
    fb->lfb = 0;
    fb->lfb_pa = 0;
    fb->bga_version = 0;
    kprintf("K64 virtio-gpu: features offered %llx accepted %llx (virgl %d edid %d), %s, %u scanout(s), host mode %ux%u, "
            "EDID %u bytes (%s %ux%u), %u capset(s)\n", vg.dev.device_features, vg.dev.driver_features,
            (int)(vg.dev.driver_features >> VGPU_F_VIRGL & 1), (int)(vg.dev.driver_features >> VGPU_F_EDID & 1),
            vg.irq ? "INTx" : "polled", vg.num_scanouts, vg.host_w, vg.host_h, vg.edid_len, vg.edid_len ? vg.edid_vendor : "-",
            vg.edid_w, vg.edid_h, vg.ncapsets);
    for (i = 0; i < vg.ncapsets; ++i)
        kprintf("K64 virtio-gpu: capset %u: id %u max version %u size %u\n", i, vg.capset_id[i], vg.capset_ver[i], vg.capset_size[i]);
    return 0;
fail_locked:
    mutex_unlock(&vg.lock);
fail:
    kprintf("K64 virtio-gpu: initialisation failed; falling back to the next display backend\n");
    vg.ok = 0;
    virtio_pci_reset(&vg.dev);                                  /* the device forgets the rings: no DMA into freed pages */
    for (i = 0; i < VG_SLOTS; ++i) if (vg.slot_pa[i]) { pmm_free(vg.slot_pa[i]); vg.slot_pa[i] = 0; }
    for (i = 0; i < VG_ENT_PAGES; ++i) if (vg.ent_pa[i]) { pmm_free(vg.ent_pa[i]); vg.ent_pa[i] = 0; }
    return -1;
}

static void vg_present(int x, int y, int w, int h)
{
    vgpu_transfer_to_host_2d_t t;
    vgpu_resource_flush_t f;
    vgpu_hdr_t r1, r2;
    vg_cmd_t c[2];
    int32_t st;
    if (!vg.ok) return;
    vg_xfer2d_req(&t, VG_FB_RES, vg.pitch, x, y, w, h);
    hdr(&f.hdr, VGPU_CMD_RESOURCE_FLUSH, 0, 0);
    f.r = t.r;
    f.resource_id = VG_FB_RES;
    f.pad = 0;
    memset(c, 0, sizeof c);
    c[0].req = &t; c[0].req_len = sizeof t; c[0].resp = &r1; c[0].resp_len = sizeof r1;
    c[1].req = &f; c[1].req_len = sizeof f; c[1].resp = &r2; c[1].resp_len = sizeof r2;
    mutex_lock(&vg.lock);
    st = vg_run(vg.ctrlq, c, 2);
    if (!st) {
        ++vg.st.transfers_2d;
        ++vg.st.flushes;
        vg.st.transfer_bytes += (uint64_t)w * (uint64_t)h * 4u;
    }
    mutex_unlock(&vg.lock);
    if (!st && (c[0].resp_type != VGPU_RESP_OK_NODATA || c[1].resp_type != VGPU_RESP_OK_NODATA))
        kprintf("K64 virtio-gpu: present %d,%d %dx%d answered %x/%x\n", x, y, w, h, c[0].resp_type, c[1].resp_type);
}

const gfx_backend_t gfx_backend_virtio = { "virtio-gpu", SHZ_GPU_BACKEND_VIRTIO, vg_probe, vg_present };

/* ---------------------------------------------------------------- services for gpu_sys.c */
int vg_active(void) { return vg.ok && g_fb.ready && g_fb.backend == &gfx_backend_virtio; }
int vg_has_virgl(void) { return vg_active() && (vg.dev.driver_features >> VGPU_F_VIRGL & 1); }

void vg_fill_info(shz_gpu_info_t *info)
{
    unsigned i;
    if (!vg_active()) return;
    mutex_lock(&vg.lock);
    info->features = SHZ_GPU_FEAT_2D | SHZ_GPU_FEAT_CURSOR | (vg.edid_len ? SHZ_GPU_FEAT_EDID : 0) |
                     (vg.dev.driver_features >> VGPU_F_VIRGL & 1 ? SHZ_GPU_FEAT_VIRGL : 0) | (vg.irq ? SHZ_GPU_FEAT_IRQ : 0);
    info->host_width = vg.host_w;
    info->host_height = vg.host_h;
    info->num_scanouts = vg.num_scanouts;
    info->num_capsets = vg.ncapsets;
    info->edid_size = vg.edid_len;
    info->edid_pref_width = vg.edid_w;
    info->edid_pref_height = vg.edid_h;
    memcpy(info->edid_vendor, vg.edid_vendor, 4);
    for (i = 0; i < vg.ncapsets && i < 4; ++i) {
        info->capset_id[i] = vg.capset_id[i];
        info->capset_max_version[i] = vg.capset_ver[i];
        info->capset_max_size[i] = vg.capset_size[i];
    }
    info->pci_vendor = vg.dev.pci.vendor;
    info->pci_device = vg.dev.pci.device;
    info->device_features = vg.dev.device_features;
    info->driver_features = vg.dev.driver_features;
    {
        shz_gpu_stats_t s = vg.st;
        s.presents = info->stats.presents;              /* the compositor-side counters are kept by gfx_fb.c */
        s.present_pixels = info->stats.present_pixels;
        info->stats = s;
    }
    mutex_unlock(&vg.lock);
}

int32_t vg_get_edid(uint8_t *out, uint32_t cap, uint32_t *len)
{
    if (!vg_active()) return STATUS_NO_SUCH_DEVICE;
    if (!vg.edid_len) return STATUS_NOT_SUPPORTED;
    mutex_lock(&vg.lock);
    memcpy(out, vg.edid, cap < vg.edid_len ? cap : vg.edid_len);
    *len = vg.edid_len;
    mutex_unlock(&vg.lock);
    return STATUS_SUCCESS;
}

int32_t vg_cursor(uint32_t op, const uint32_t *argb, uint32_t hot_x, uint32_t hot_y, int32_t x, int32_t y)
{
    vgpu_update_cursor_t u;
    vg_cmd_t c;
    int32_t st = STATUS_SUCCESS;
    if (!vg_active()) return STATUS_NO_SUCH_DEVICE;
    if (op == SHZ_GPU_CURSOR_SHAPE && (!argb || hot_x >= SHZ_GPU_CURSOR_W || hot_y >= SHZ_GPU_CURSOR_H)) return STATUS_INVALID_PARAMETER;
    mutex_lock(&vg.lock);
    if (op == SHZ_GPU_CURSOR_SHAPE) {
        vgpu_transfer_to_host_2d_t t;
        if (!vg.cursor_ready) {
            vgpu_resource_create_2d_t rc;
            if (!vg.cursor_img) vg.cursor_img = gfx_pages_alloc(SHZ_GPU_CURSOR_W * SHZ_GPU_CURSOR_H * 4u);
            if (!vg.cursor_img) { st = STATUS_NO_MEMORY; goto out; }
            hdr(&rc.hdr, VGPU_CMD_RESOURCE_CREATE_2D, 0, 0);
            rc.resource_id = VG_CURSOR_RES;
            rc.format = VGPU_FORMAT_B8G8R8A8_UNORM;
            rc.width = SHZ_GPU_CURSOR_W;
            rc.height = SHZ_GPU_CURSOR_H;
            if ((st = vg_simple(&rc, sizeof rc, 0, 0)) != 0) goto out;
            if ((st = vg_attach(VG_CURSOR_RES, vg.cursor_img, SHZ_GPU_CURSOR_W * SHZ_GPU_CURSOR_H * 4u)) != 0) goto out;
            vg.cursor_ready = 1;
        }
        memcpy(vg.cursor_img, argb, SHZ_GPU_CURSOR_W * SHZ_GPU_CURSOR_H * 4u);  /* 0xAARRGGBB dwords = B8G8R8A8 bytes */
        vg_xfer2d_req(&t, VG_CURSOR_RES, SHZ_GPU_CURSOR_W * 4u, 0, 0, SHZ_GPU_CURSOR_W, SHZ_GPU_CURSOR_H);
        if ((st = vg_simple(&t, sizeof t, 0, 0)) != 0) goto out;
    }
    memset(&u, 0, sizeof u);
    hdr(&u.hdr, op == SHZ_GPU_CURSOR_MOVE ? VGPU_CMD_MOVE_CURSOR : VGPU_CMD_UPDATE_CURSOR, 0, 0);
    u.pos.scanout_id = 0;
    u.pos.x = (uint32_t)(x < 0 ? 0 : x);
    u.pos.y = (uint32_t)(y < 0 ? 0 : y);
    u.resource_id = op == SHZ_GPU_CURSOR_SHAPE ? VG_CURSOR_RES : 0;         /* 0 on UPDATE hides the cursor */
    u.hot_x = hot_x;
    u.hot_y = hot_y;
    memset(&c, 0, sizeof c);
    c.req = &u;
    c.req_len = sizeof u;                                                  /* the cursor queue writes no response */
    st = vg_run(vg.cursorq, &c, 1);
out:
    mutex_unlock(&vg.lock);
    return st;
}

int32_t vg_capset(uint32_t id, uint32_t version, void *out, uint32_t cap, uint32_t *len)
{
    virtq_sg_t in[VG_MAX_SG];
    vgpu_get_capset_t g;
    vg_cmd_t c;
    uint32_t size = 0;
    uint8_t *buf;
    unsigned i, n;
    int32_t st;
    if (!vg_active()) return STATUS_NO_SUCH_DEVICE;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    for (i = 0; i < vg.ncapsets; ++i)
        if (vg.capset_id[i] == id && version <= vg.capset_ver[i]) size = vg.capset_size[i];
    if (!size || size > (64u << 10)) return STATUS_INVALID_PARAMETER;
    buf = gfx_pages_alloc(sizeof(vgpu_hdr_t) + size);
    if (!buf) return STATUS_NO_MEMORY;
    n = vg_runs(buf, sizeof(vgpu_hdr_t) + size, in, VG_MAX_SG);
    hdr(&g.hdr, VGPU_CMD_GET_CAPSET, 0, 0);
    g.capset_id = id;
    g.capset_version = version;
    memset(&c, 0, sizeof c);
    c.req = &g; c.req_len = sizeof g; c.in_x = in; c.n_in_x = n;
    mutex_lock(&vg.lock);
    st = n ? vg_run(vg.ctrlq, &c, 1) : STATUS_INSUFFICIENT_RESOURCES;
    mutex_unlock(&vg.lock);
    if (!st && ((const vgpu_hdr_t *)buf)->type != VGPU_RESP_OK_CAPSET) st = STATUS_UNSUCCESSFUL;
    if (!st) {
        memcpy(out, buf + sizeof(vgpu_hdr_t), cap < size ? cap : size);
        *len = size;
    }
    gfx_pages_free(buf, sizeof(vgpu_hdr_t) + size);
    return st;
}

static int32_t vg_locked_simple(const void *req, uint32_t len)
{
    int32_t st;
    mutex_lock(&vg.lock);
    st = vg_simple(req, len, 0, 0);
    mutex_unlock(&vg.lock);
    return st;
}

int32_t vg_ctx_create(uint32_t ctx, const char *name, uint32_t name_len)
{
    vgpu_ctx_create_t cc;
    if (!vg_has_virgl()) return vg_active() ? STATUS_NOT_SUPPORTED : STATUS_NO_SUCH_DEVICE;
    memset(&cc, 0, sizeof cc);
    hdr(&cc.hdr, VGPU_CMD_CTX_CREATE, ctx, 0);
    if (name_len > sizeof cc.debug_name - 1) name_len = sizeof cc.debug_name - 1;
    memcpy(cc.debug_name, name, name_len);
    cc.nlen = name_len;
    cc.context_init = 0;                                                   /* the default (virgl) context type */
    return vg_locked_simple(&cc, sizeof cc);
}

int32_t vg_ctx_destroy(uint32_t ctx)
{
    vgpu_ctx_destroy_t cd;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    hdr(&cd.hdr, VGPU_CMD_CTX_DESTROY, ctx, 0);
    return vg_locked_simple(&cd, sizeof cd);
}

int32_t vg_res3d_create(uint32_t ctx, uint32_t res, const shz_gpu_res_t *a, void *backing, uint64_t bytes)
{
    vgpu_resource_create_3d_t rc;
    vgpu_ctx_resource_t at;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    memset(&rc, 0, sizeof rc);
    hdr(&rc.hdr, VGPU_CMD_RESOURCE_CREATE_3D, ctx, 0);
    rc.resource_id = res;
    rc.target = a->target;
    rc.format = a->format;
    rc.bind = a->bind;
    rc.width = a->width;
    rc.height = a->height;
    rc.depth = a->depth;
    rc.array_size = a->array_size;
    rc.last_level = 0;
    rc.nr_samples = 0;
    rc.flags = 0;
    mutex_lock(&vg.lock);
    st = vg_simple(&rc, sizeof rc, 0, 0);
    if (!st) st = vg_attach(res, backing, bytes);
    if (!st) {
        hdr(&at.hdr, VGPU_CMD_CTX_ATTACH_RESOURCE, ctx, 0);
        at.resource_id = res;
        at.pad = 0;
        st = vg_simple(&at, sizeof at, 0, 0);
    }
    mutex_unlock(&vg.lock);
    return st;
}

int32_t vg_res3d_destroy(uint32_t ctx, uint32_t res)
{
    vgpu_ctx_resource_t dt;
    vgpu_resource_unref_t un;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    hdr(&dt.hdr, VGPU_CMD_CTX_DETACH_RESOURCE, ctx, 0);
    dt.resource_id = res;
    dt.pad = 0;
    hdr(&un.hdr, VGPU_CMD_RESOURCE_UNREF, 0, 0);                          /* also drops the guest backing */
    un.resource_id = res;
    un.pad = 0;
    mutex_lock(&vg.lock);
    st = vg_simple(&dt, sizeof dt, 0, 0);
    if (!st) st = vg_simple(&un, sizeof un, 0, 0);
    mutex_unlock(&vg.lock);
    return st;
}

int32_t vg_submit3d(uint32_t ctx, const void *stream, uint32_t bytes)
{
    virtq_sg_t x[VG_MAX_SG];
    vgpu_cmd_submit_t s;
    unsigned n;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    n = vg_runs(stream, bytes, x, VG_MAX_SG);
    if (!n) return STATUS_INSUFFICIENT_RESOURCES;
    hdr(&s.hdr, VGPU_CMD_SUBMIT_3D, ctx, 1);                               /* fenced: answered when the host GPU is done */
    s.size = bytes;
    s.pad = 0;
    mutex_lock(&vg.lock);
    st = vg_simple(&s, sizeof s, x, n);
    if (!st) {
        ++vg.st.submits_3d;
        vg.st.submit_bytes += bytes;
    }
    mutex_unlock(&vg.lock);
    return st;
}

int32_t vg_transfer3d(uint32_t ctx, uint32_t res, int to_host, const vg_box_t *box, uint32_t level, uint32_t stride,
                      uint32_t layer_stride)
{
    vgpu_transfer_host_3d_t t;
    int32_t st;
    if (!vg_has_virgl()) return STATUS_NOT_SUPPORTED;
    hdr(&t.hdr, to_host ? VGPU_CMD_TRANSFER_TO_HOST_3D : VGPU_CMD_TRANSFER_FROM_HOST_3D, ctx, 1);
    t.box.x = box->x; t.box.y = box->y; t.box.z = box->z;
    t.box.w = box->w; t.box.h = box->h; t.box.d = box->d;
    t.offset = 0;
    t.resource_id = res;
    t.level = level;
    t.stride = stride;
    t.layer_stride = layer_stride;
    mutex_lock(&vg.lock);
    st = vg_simple(&t, sizeof t, 0, 0);
    if (!st) ++vg.st.transfers_3d;
    mutex_unlock(&vg.lock);
    return st;
}
