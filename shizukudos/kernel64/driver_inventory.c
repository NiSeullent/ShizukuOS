/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 device -> driver inventory (see driver_inventory.h for the contract).
 *
 * Ownership rules preserved:
 *  - native backends own their functions through pci_claim(); this file only reads pci_claimed_by() and never claims;
 *  - hosted NT drivers keep ntdrv_io.c's own_function() + ntdrv_bind_enum() -> ntdrv_pnp_add() path: ntdrv_pnp_add()
 *    makes its caller the PDO's function driver and ntdrv_pnp_start_pending() then sends AddDevice/START to it, so it
 *    is NEVER called here for a natively owned function (that would hand a native device to an NT FDO). Native
 *    functions are published only through ntdrv_pnp_publish_native(), a devnode WITHOUT a function driver, which
 *    ntdrv_pnp.c does not provide yet: the reference is weak and DRVINV_PNP_UNAVAILABLE is reported until
 *    core-integration applies .codex/handoff/driver-bindings-to-core-integration.patch.
 *
 * init_status meaning (no backend records its own init return code; the observable facts are used):
 *  - display rows: the gfx_fb_init() NTSTATUS when DRVINV_RUN_START_DISPLAY ran it, else STATUS_SUCCESS only when the
 *    claiming backend is the active display backend;
 *  - other bound rows: STATUS_SUCCESS (every backend calls pci_claim() only after its bring-up reached ownership);
 *  - unowned rows: STATUS_NO_SUCH_DEVICE (catalogue match, no backend) or STATUS_NOT_SUPPORTED (no catalogue driver).
 */
#include "driver_inventory.h"

#ifndef DRVINV_HOST
#include "k64.h"
#include "ntsys.h"
#include "pci.h"
#include "gfx.h"
#include "blk.h"
#include "net.h"
#include "ntdrv.h"
#include "proc_internal.h"
#endif

#ifndef STATUS_NO_SUCH_DEVICE
#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#endif
#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((int32_t)0xC00000A3)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((int32_t)0xC00000BB)
#endif
#ifndef STATUS_IO_DEVICE_ERROR
#define STATUS_IO_DEVICE_ERROR ((int32_t)0xC0000185)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND ((int32_t)0xC0000225)
#endif

/* ------------------------------------------------------------------------------------------------ pure helpers */
static int str_eq(const char *a, const char *b)
{
    if (!a || !b) return 0;
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static __attribute__((unused)) void str_copy(char *dst, unsigned cap, const char *src)
{
    unsigned i = 0;
    if (!cap) return;
    while (src && src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}
static __attribute__((unused)) int str_prefix(const char *s, const char *p)
{
    if (!s || !p) return 0;
    while (*p) if (*s++ != *p++) return 0;
    return 1;
}

enum drvinv_status drvinv_fold(enum shz_drvcat_binding bind, int op_attempted, int32_t op_status)
{
    if (bind == SHZ_BIND_NO_DRIVER) return DRVINV_UNSUPPORTED;
    if (bind == SHZ_BIND_MATCHED_NOT_STARTED) return DRVINV_NOT_ATTACHED;   /* a catalogue name is not a driver */
    if (bind != SHZ_BIND_BOUND && bind != SHZ_BIND_BOUND_HOSTED && bind != SHZ_BIND_BOUND_UNLISTED)
        return DRVINV_UNSUPPORTED;                                           /* unknown state: never upgraded */
    if (!op_attempted || op_status == DRVINV_OP_NOT_RUN) return DRVINV_BOUND_UNVERIFIED;
    return op_status == 0 ? DRVINV_WORKING : DRVINV_FAILED;
}

enum drvinv_op drvinv_op_for_service(const char *service)
{
    if (str_eq(service, "ahci_blk") || str_eq(service, "nvme") || str_eq(service, "sdhci")) return DRVINV_OP_STORAGE_READ0;
    if (str_eq(service, "gfx_virtio") || str_eq(service, "gfx_bga") || str_eq(service, "shzgop")) return DRVINV_OP_DISPLAY_MODE;
    if (str_eq(service, "net_rtl8139")) return DRVINV_OP_NIC_LINK;
    return DRVINV_OP_NONE;
}

uint64_t drvinv_query_size(uint32_t rows)
{
    if (rows > DRVINV_MAX_ROWS) return 0;
    return (uint64_t)sizeof(drvinv_header_t) + (uint64_t)rows * sizeof(drvinv_row_t);
}

const char *drvinv_status_name(enum drvinv_status s)
{
    switch (s) {
    case DRVINV_UNSUPPORTED: return "unsupported (no driver)";
    case DRVINV_NOT_ATTACHED: return "driver matched, backend not attached";
    case DRVINV_BOUND_UNVERIFIED: return "bound, operation not verified";
    case DRVINV_WORKING: return "bound, operation verified";
    case DRVINV_FAILED: return "bound, operation FAILED";
    }
    return "invalid";
}

#ifndef DRVINV_HOST
/* ------------------------------------------------------------------------------------------------ kernel part */
/* Native devnode publication and hosted-PDO lookup live in ntdrv_pnp.c (core-integration). Weak until wired. */
extern int ntdrv_pnp_publish_native(const pci_dev_t *dev, const char *service, const char *description,
                                    const char *hwid) __attribute__((weak));
extern int ntdrv_pnp_function_state(const pci_dev_t *dev) __attribute__((weak));   /* -1 none, 0 recorded, 1 started */

typedef struct {                                 /* last storage read, keyed by function (kept across queries) */
    uint8_t bus, dev, fn, valid;
    int32_t status;
    uint32_t value[4];
    char detail[32];
} storage_probe_t;

static storage_probe_t g_storage[DRVINV_MAX_ROWS];
static unsigned g_nstorage;
static uint8_t g_published[DRVINV_MAX_ROWS][3];
static unsigned g_npublished;
static uint32_t g_runs;
static uint8_t g_sector[4096] __attribute__((aligned(4096)));   /* kernel-image buffer: valid for every blk driver */

static const storage_probe_t *storage_find(uint8_t bus, uint8_t dev, uint8_t fn)
{
    unsigned i;
    for (i = 0; i < g_nstorage; ++i)
        if (g_storage[i].bus == bus && g_storage[i].dev == dev && g_storage[i].fn == fn) return &g_storage[i];
    return 0;
}

/* The whole block device whose kernel-observed locator names this PCI function (AHCI and NVMe fill it). */
static blk_dev_t *blk_for_function(const pci_dev_t *d)
{
    blk_dev_t *b;
    unsigned i;
    for (i = 0; (b = blk_get(i)) != 0; ++i)
        if (!b->parent && b->storage.transport && b->storage.bus == d->bus && b->storage.device == d->dev &&
            b->storage.function == d->fn)
            return b;
    return 0;
}

static void storage_probe(const pci_dev_t *d)
{
    storage_probe_t *s = 0;
    blk_dev_t *b;
    unsigned i;
    for (i = 0; i < g_nstorage; ++i)
        if (g_storage[i].bus == d->bus && g_storage[i].dev == d->dev && g_storage[i].fn == d->fn) s = &g_storage[i];
    if (!s) {
        if (g_nstorage >= DRVINV_MAX_ROWS) return;
        s = &g_storage[g_nstorage++];
    }
    memset(s, 0, sizeof *s);
    s->bus = d->bus; s->dev = d->dev; s->fn = d->fn; s->valid = 1;
    b = blk_for_function(d);
    if (!b) {                                    /* claimed, but no registered block device carries this locator */
        s->status = DRVINV_OP_NOT_RUN;          /* cannot verify (e.g. sdhci fills no locator): unverified, not failed */
        str_copy(s->detail, sizeof s->detail, "no block device locator");
        return;
    }
    str_copy(s->detail, sizeof s->detail, b->name);
    s->value[0] = b->sector_size;
    s->value[2] = (uint32_t)b->sectors; s->value[3] = (uint32_t)(b->sectors >> 32);
    if (!b->sector_size || b->sector_size > sizeof g_sector || !b->sectors) { s->status = STATUS_NOT_SUPPORTED; return; }
    memset(g_sector, 0, b->sector_size);
    if (blk_read(b, 0, 1, g_sector)) { s->status = STATUS_IO_DEVICE_ERROR; return; }
    s->status = 0;
    s->value[1] = g_sector[510] == 0x55 && g_sector[511] == 0xaa;
}

static int published(const pci_dev_t *d)
{
    unsigned i;
    for (i = 0; i < g_npublished; ++i)
        if (g_published[i][0] == d->bus && g_published[i][1] == d->dev && g_published[i][2] == d->fn) return 1;
    return 0;
}

static const gfx_backend_t *backend_for_service(const char *service)
{
    if (str_eq(service, "gfx_virtio")) return &gfx_backend_virtio;
    if (str_eq(service, "shzgop")) return &gfx_backend_gop;
    return 0;                                    /* gfx_bga: backend object is static in gfx_fb.c, matched by name */
}

/* Fills one row from a live enumeration entry. Storage results come from the cache only. */
static void fill_row(drvinv_row_t *r, const pci_dev_t *d, int fb_valid)
{
    shz_pci_ident_t id;
    shz_drvcat_result_t res;
    shz_pci_ids_t ids;
    const char *owner = pci_claimed_by(d);
    const shz_drvcat_entry_t *e = 0;
    const uint32_t rev = pci_cfg_read32(d, 0x08), hdr = pci_cfg_read32(d, 0x0c) >> 16 & 0x7f;
    int attempted = 0;
    memset(r, 0, sizeof *r);
    memset(&id, 0, sizeof id);
    r->bus = d->bus; r->dev = d->dev; r->fn = d->fn;
    id.vendor = d->vendor; id.device = d->device;
    id.class_code = d->class_code; id.subclass = d->subclass; id.prog_if = d->prog_if; id.revision = (uint8_t)rev;
    if (hdr == 0) {
        const uint32_t ss = pci_cfg_read32(d, 0x2c);
        id.subsys_vendor = (uint16_t)ss; id.subsys_device = (uint16_t)(ss >> 16); id.has_subsys = 1;
    }
    r->vendor = id.vendor; r->device = id.device; r->subsys_vendor = id.subsys_vendor; r->subsys_device = id.subsys_device;
    r->class_code = id.class_code; r->subclass = id.subclass; r->prog_if = id.prog_if; r->revision = id.revision;
    r->catalog_index = 0xff;
    r->op_status = DRVINV_OP_NOT_RUN;
    str_copy(r->owner, sizeof r->owner, owner);
    if (!shz_pci_ids_build(&id, &ids) && ids.n_hw) str_copy(r->hwid, sizeof r->hwid, ids.hw[0]);
    if (shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &id, owner, fb_valid, &res)) {
        r->bind_state = SHZ_BIND_NO_DRIVER;
        r->status = DRVINV_UNSUPPORTED;
        r->init_status = STATUS_NOT_SUPPORTED;
        return;
    }
    r->bind_state = (uint8_t)res.state;
    if (res.bound >= 0) { e = &shz_k64_catalog[res.bound]; r->catalog_index = (uint8_t)res.bound; }
    else if (res.best >= 0) { e = &shz_k64_catalog[res.best]; r->catalog_index = (uint8_t)res.best; }
    /* service names the actual owner: a hosted NT driver's service, or the catalogue backend; for an owner absent
     * from the catalogue (BOUND_UNLISTED) the best catalogue match is NOT the driver, so service stays empty */
    if (res.state == SHZ_BIND_BOUND_HOSTED) {
        if (str_prefix(owner, "ntdrv:")) str_copy(r->service, sizeof r->service, owner + 6);
    } else if (e && res.state != SHZ_BIND_BOUND_UNLISTED) str_copy(r->service, sizeof r->service, e->service);
    if (res.state == SHZ_BIND_BOUND_HOSTED || res.state == SHZ_BIND_BOUND_UNLISTED) {
        e = 0;                                   /* no native catalogue operation applies to a foreign owner */
        r->catalog_index = 0xff;
    }

    if (res.state == SHZ_BIND_NO_DRIVER) { r->init_status = STATUS_NOT_SUPPORTED; r->status = DRVINV_UNSUPPORTED; return; }
    if (res.state == SHZ_BIND_MATCHED_NOT_STARTED) { r->init_status = STATUS_NO_SUCH_DEVICE; r->status = DRVINV_NOT_ATTACHED; return; }

    r->init_status = 0;
    if (res.state == SHZ_BIND_BOUND_HOSTED) {
        r->op_kind = DRVINV_OP_HOSTED_PNP;
        if (ntdrv_pnp_function_state) {
            const int st = ntdrv_pnp_function_state(d);
            r->pnp_state = st > 0 ? DRVINV_PNP_HOSTED_STARTED : st == 0 ? DRVINV_PNP_HOSTED_RECORDED : DRVINV_PNP_NONE;
            r->op_value[0] = r->pnp_state;
            r->op_status = st > 0 ? 0 : STATUS_DEVICE_NOT_READY;    /* START_DEVICE not (yet) successful */
            attempted = 1;
        } else r->pnp_state = DRVINV_PNP_UNAVAILABLE;
    } else if (res.state == SHZ_BIND_BOUND && e) {
        r->op_kind = (uint8_t)drvinv_op_for_service(e->service);
        r->pnp_state = published(d) ? DRVINV_PNP_NATIVE_PUBLISHED : ntdrv_pnp_publish_native ? DRVINV_PNP_NONE
                                                                                                : DRVINV_PNP_UNAVAILABLE;
        if (r->op_kind == DRVINV_OP_STORAGE_READ0) {
            const storage_probe_t *s = storage_find(d->bus, d->dev, d->fn);
            if (s && s->valid) {
                r->op_status = s->status; attempted = 1;
                memcpy(r->op_value, s->value, sizeof r->op_value);
                str_copy(r->detail, sizeof r->detail, s->detail);
            }
        } else if (r->op_kind == DRVINV_OP_DISPLAY_MODE) {
            const gfx_backend_t *be = g_fb.backend, *want = backend_for_service(e->service);
            const int ready = g_fb.ready;
            attempted = 1;
            if (ready && be && (be == want || (!want && str_eq(be->name, "Bochs VBE")))) {
                r->op_status = 0;
                r->op_value[0] = g_fb.width; r->op_value[1] = g_fb.height;
                r->op_value[2] = g_fb.pitch; r->op_value[3] = g_fb.bpp;
                str_copy(r->detail, sizeof r->detail, be->name);
            } else {                             /* claimed, but this backend does not drive the screen now */
                r->op_status = STATUS_DEVICE_NOT_READY;
                r->init_status = STATUS_DEVICE_NOT_READY;
                if (ready && be) str_copy(r->detail, sizeof r->detail, be->name);
            }
        } else if (r->op_kind == DRVINV_OP_NIC_LINK) {
            attempted = 1;
            r->op_value[0] = (uint32_t)nic_link_up();
            r->op_value[1] = nic_stat(0); r->op_value[2] = nic_stat(1); r->op_value[3] = nic_stat(5);
            r->op_status = r->op_value[0] ? 0 : STATUS_DEVICE_NOT_READY;   /* PHY reports no link */
            str_copy(r->detail, sizeof r->detail, r->op_value[0] ? "link up" : "no link");
        }
    }
    r->status = (uint8_t)drvinv_fold(res.state, attempted, r->op_status);
}

static unsigned build_rows(drvinv_header_t *h, drvinv_row_t *rows, unsigned max, pci_dev_t *all, unsigned *n_all)
{
    shz_gop_status_t gop;
    unsigned i, n = 0, written = 0;
    ntdrv_gop_status(&gop);
    memset(h, 0, sizeof *h);
    h->version = DRVINV_VERSION; h->row_size = sizeof(drvinv_row_t);
    h->gop_state = gop.state; h->gop_check = gop.check;
    h->gop_width = gop.mode.width; h->gop_height = gop.mode.height; h->gop_pitch = gop.mode.pitch;
    h->gop_format = gop.mode.format; h->gop_base = gop.mode.base; h->gop_size = gop.mode.size;
    h->runs = g_runs;
    str_copy(h->active_backend, sizeof h->active_backend, gop.active_backend);
#ifdef SHZ_STANDALONE                                   /* Supervisor profile: config ports trap, nothing passed through */
    n = pci_enumerate(all, DRVINV_MAX_ROWS);
#endif
    for (i = 0; i < n && written < max; ++i) {
        fill_row(&rows[written], &all[i], gop.check == SHZ_GOP_OK);
        if (rows[written].op_kind == DRVINV_OP_STORAGE_READ0 && rows[written].op_status != DRVINV_OP_NOT_RUN)
            ++h->storage_probed;
        ++written;
    }
    h->count = written; h->total_enumerated = n;
    if (n_all) *n_all = n;
    return written;
}

static drvinv_row_t g_rows[DRVINV_MAX_ROWS];            /* driver_inventory_run() scratch; boot/thread context */

unsigned driver_inventory_run(uint32_t flags)
{
    pci_dev_t all[DRVINV_MAX_ROWS];
    drvinv_header_t h;
    unsigned n, i, total = 0;
    int32_t display_init = DRVINV_OP_NOT_RUN;
    if (flags & DRVINV_RUN_START_DISPLAY) display_init = gfx_fb_init();   /* production initialiser, idempotent */
    n = build_rows(&h, g_rows, DRVINV_MAX_ROWS, all, &total);
    if (flags & DRVINV_RUN_STORAGE_READ) {
        for (i = 0; i < n; ++i)
            if (g_rows[i].status >= DRVINV_BOUND_UNVERIFIED && g_rows[i].bind_state == SHZ_BIND_BOUND &&
                g_rows[i].op_kind == DRVINV_OP_STORAGE_READ0)
                storage_probe(&all[i]);
        n = build_rows(&h, g_rows, DRVINV_MAX_ROWS, all, &total);   /* fold the fresh reads into the rows */
    }
    if (flags & DRVINV_RUN_PUBLISH_PNP) {
        for (i = 0; i < n; ++i) {
            drvinv_row_t *r = &g_rows[i];
            if (r->bind_state != SHZ_BIND_BOUND || r->catalog_index == 0xff || published(&all[i])) continue;
            if (!ntdrv_pnp_publish_native) { r->pnp_state = DRVINV_PNP_UNAVAILABLE; continue; }
            if (ntdrv_pnp_publish_native(&all[i], r->service, shz_k64_catalog[r->catalog_index].description, r->hwid)) {
                kprintf("K64 drvinv: %x:%x.%x %s: PnP devnode publication refused\n", r->bus, r->dev, r->fn, r->service);
                continue;
            }
            if (g_npublished < DRVINV_MAX_ROWS) {
                g_published[g_npublished][0] = r->bus; g_published[g_npublished][1] = r->dev;
                g_published[g_npublished][2] = r->fn; ++g_npublished;
            }
            r->pnp_state = DRVINV_PNP_NATIVE_PUBLISHED;
        }
    }
    ++g_runs;
    if (flags & DRVINV_RUN_REPORT) {
#ifndef SHZ_STANDALONE
        kprintf("K64 drvinv: Supervisor profile: no PCI function is passed through to Kernel64; nothing enumerated\n");
#endif
        if (display_init != DRVINV_OP_NOT_RUN)
            kprintf("K64 drvinv: gfx_fb_init() = %x (%s)\n", (uint32_t)display_init,
                    h.active_backend[0] ? h.active_backend : "no display backend");
        for (i = 0; i < n; ++i) {
            const drvinv_row_t *r = &g_rows[i];
            kprintf("K64 drvinv: %x:%x.%x %04x:%04x %s svc=%s owner=%s init=%x op=%u/%x [%x %x %x %x] %s pnp=%u -> %s\n",
                    r->bus, r->dev, r->fn, r->vendor, r->device, r->hwid, r->service[0] ? r->service : "-",
                    r->owner[0] ? r->owner : "-", (uint32_t)r->init_status, r->op_kind, (uint32_t)r->op_status,
                    r->op_value[0], r->op_value[1], r->op_value[2], r->op_value[3], r->detail[0] ? r->detail : "-",
                    r->pnp_state, drvinv_status_name((enum drvinv_status)r->status));
        }
        if (total > n) kprintf("K64 drvinv: %u more PCI function(s) not inventoried\n", total - n);
        kprintf("K64 drvinv: run %u: %u function(s), %u storage read(s); gop state %u check %u %ux%u\n", g_runs, total,
                h.storage_probed, h.gop_state, h.gop_check, h.gop_width, h.gop_height);
    }
    return n;
}

int driver_inventory_query(drvinv_header_t *hdr, drvinv_row_t *rows, unsigned max)
{
    pci_dev_t all[DRVINV_MAX_ROWS];
    drvinv_row_t tmp[1];
    if (!hdr || (max && !rows)) return -1;
    if (!max) {                                          /* header + counts only */
        unsigned total = 0;
        build_rows(hdr, tmp, 0, all, &total);
        hdr->count = total < DRVINV_MAX_ROWS ? total : DRVINV_MAX_ROWS;
        return 0;
    }
    build_rows(hdr, rows, max > DRVINV_MAX_ROWS ? DRVINV_MAX_ROWS : max, all, 0);
    return 0;
}

int32_t driver_inventory_query_user(struct process *p, uint64_t out, uint64_t length, uint64_t return_length)
{
    drvinv_header_t h;
    drvinv_row_t *rows;
    uint64_t need;
    uint32_t need32;
    int32_t st = STATUS_SUCCESS;
    rows = kzalloc(sizeof(drvinv_row_t) * DRVINV_MAX_ROWS);
    if (!rows) return STATUS_NO_MEMORY;
    driver_inventory_query(&h, rows, DRVINV_MAX_ROWS);
    need = drvinv_query_size(h.count);
    need32 = (uint32_t)need;
    if (return_length && copy_to_user(p, return_length, &need32, sizeof need32)) { st = STATUS_ACCESS_VIOLATION; goto out; }
    if (length < need) { st = STATUS_INFO_LENGTH_MISMATCH; goto out; }
    if (copy_to_user(p, out, &h, sizeof h) ||
        (h.count && copy_to_user(p, out + sizeof h, rows, (uint64_t)h.count * sizeof(drvinv_row_t))))
        st = STATUS_ACCESS_VIOLATION;
out:
    kfree(rows);
    return st;
}
#endif
