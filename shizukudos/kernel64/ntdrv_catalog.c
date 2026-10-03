/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 driver catalogue and SetupAPI-style matcher (see ntdrv_catalog.h). Freestanding: links into Kernel64 and the
 * host test unchanged. Original implementation of Microsoft's documented PCI identifier and driver-rank contracts.
 */
#include "ntdrv_catalog.h"

/* One entry per in-kernel backend that really calls pci_claim(); `claim` strings are copied verbatim from those calls
 * (gfx_virtio.c, gfx_fb.c, gfx_gop.c, ahci_blk.c, nvme.c, sdhci.c, net_rtl8139.c). Device classes without an entry
 * (USB host controllers, audio, bridges, ...) have no attached Kernel64 backend and are reported as NO_DRIVER. */
const shz_drvcat_entry_t shz_k64_catalog[] = {
    { "gfx_virtio", "Shizuku virtio-gpu display", "gfx_virtio (virtio-gpu)",
      { "PCI\\VEN_1AF4&DEV_1050", 0 }, { 0 }, 0 },
    { "gfx_bga", "Shizuku Bochs VBE display", "gfx_fb (Bochs VBE)",
      { "PCI\\VEN_1234&DEV_1111", 0 }, { 0 }, 0 },
    { "shzgop", "Shizuku basic display (UEFI GOP framebuffer)", "gfx_fb (UEFI GOP)",
      { "PCI\\CC_0300", "PCI\\CC_0380", 0 }, { 0 }, SHZ_DRVCAT_NEEDS_BOOT_FB | SHZ_DRVCAT_BASIC_DISPLAY },
    { "ahci_blk", "Shizuku AHCI SATA controller", "ahci_blk (AHCI SATA)",
      { "PCI\\CC_010601", 0 }, { 0 }, 0 },
    { "nvme", "Shizuku NVM Express controller", "nvme (NVMe)",
      { "PCI\\CC_010802", 0 }, { 0 }, 0 },
    { "sdhci", "Shizuku SD host controller", "sdhci (SD/eMMC)",
      { "PCI\\CC_0805", 0 }, { 0 }, 0 },
    { "net_rtl8139", "Shizuku Realtek RTL8139 network adapter", "net_rtl8139",
      { "PCI\\VEN_10EC&DEV_8139", 0 }, { 0 }, 0 },
};
const unsigned shz_k64_catalog_count = sizeof shz_k64_catalog / sizeof shz_k64_catalog[0];

typedef struct { char *p; unsigned n, cap; int overflow; } sbuf_t;

static void put_s(sbuf_t *b, const char *s)
{
    while (*s) {
        if (b->n + 1 >= b->cap) { b->overflow = 1; break; }
        b->p[b->n++] = *s++;
    }
    b->p[b->n] = 0;
}
static void put_hex(sbuf_t *b, uint32_t v, unsigned digits)
{
    static const char hx[] = "0123456789ABCDEF";
    char t[9];
    unsigned i;
    for (i = 0; i < digits; ++i) t[i] = hx[(v >> (4 * (digits - 1 - i))) & 15];
    t[digits] = 0;
    put_s(b, t);
}

enum { P_DEV = 1, P_SUBSYS = 2, P_REV = 4, P_CC3 = 8, P_CC2 = 16, P_VEN = 32 };
static int emit(char *dst, const shz_pci_ident_t *id, unsigned parts)
{
    sbuf_t b = { dst, 0, SHZ_DRVCAT_ID_CHARS, 0 };
    dst[0] = 0;
    put_s(&b, "PCI\\");
    if (parts & P_VEN) { put_s(&b, "VEN_"); put_hex(&b, id->vendor, 4); }
    if (parts & P_DEV) { put_s(&b, "&DEV_"); put_hex(&b, id->device, 4); }
    if (parts & P_SUBSYS) {
        put_s(&b, "&SUBSYS_");
        put_hex(&b, ((uint32_t)id->subsys_device << 16) | id->subsys_vendor, 8);
    }
    if (parts & P_REV) { put_s(&b, "&REV_"); put_hex(&b, id->revision, 2); }
    if (parts & (P_CC3 | P_CC2)) {
        put_s(&b, (parts & P_VEN) ? "&CC_" : "CC_");
        put_hex(&b, id->class_code, 2);
        put_hex(&b, id->subclass, 2);
        if (parts & P_CC3) put_hex(&b, id->prog_if, 2);
    }
    return b.overflow ? -1 : 0;
}

int shz_pci_ids_build(const shz_pci_ident_t *id, shz_pci_ids_t *out)
{
    static const unsigned hw[] = { P_VEN | P_DEV | P_SUBSYS | P_REV, P_VEN | P_DEV | P_SUBSYS,
                                   P_VEN | P_DEV | P_CC3, P_VEN | P_DEV | P_CC2 };
    static const unsigned compat[] = { P_VEN | P_DEV | P_REV, P_VEN | P_DEV, P_VEN | P_CC3, P_VEN | P_CC2, P_VEN,
                                       P_CC3, P_CC2 };
    unsigned i;
    if (!id || !out) return -1;
    out->n_hw = out->n_compat = 0;
    for (i = 0; i < sizeof hw / sizeof hw[0]; ++i)
        if (emit(out->hw[out->n_hw], id, hw[i]) == 0) ++out->n_hw;
    for (i = 0; i < sizeof compat / sizeof compat[0]; ++i)
        if (emit(out->compat[out->n_compat], id, compat[i]) == 0) ++out->n_compat;
    return 0;
}

static int id_equal(const char *a, const char *b)
{
    for (;; ++a, ++b) {
        char x = *a, y = *b;
        if (x >= 'a' && x <= 'z') x = (char)(x - 'a' + 'A');
        if (y >= 'a' && y <= 'z') y = (char)(y - 'a' + 'A');
        if (x != y) return 0;
        if (!x) return 1;
    }
}

uint32_t shz_drvcat_rank(const shz_drvcat_entry_t *e, const shz_pci_ids_t *ids, const char **matched)
{
    uint32_t best = SHZ_DRVCAT_NO_RANK;
    unsigned band, d, k;
    if (!e || !ids) return best;
    for (band = 0; band < 4; ++band) {
        const int device_compat = band >= 2, entry_compat = band & 1;
        const unsigned nd = device_compat ? ids->n_compat : ids->n_hw;
        const char *const *list = entry_compat ? e->compat : e->hw;
        for (d = 0; d < nd; ++d) {
            const char *did = device_compat ? ids->compat[d] : ids->hw[d];
            for (k = 0; k < SHZ_DRVCAT_MAX_ENTRY_IDS && list[k]; ++k) {
                const uint32_t r = (uint32_t)band << 12 | (uint32_t)d << 8 | k;
                if (r < best && id_equal(list[k], did)) {
                    best = r;
                    if (matched) *matched = did;
                }
            }
        }
        if (best != SHZ_DRVCAT_NO_RANK) break;          /* a lower band always wins */
    }
    return best;
}

static void copy_id(char *dst, const char *src)
{
    unsigned i = 0;
    while (src && src[i] && i + 1 < SHZ_DRVCAT_ID_CHARS) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}

static int same_claim(const char *a, const char *b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

int shz_drvcat_match(const shz_drvcat_entry_t *cat, unsigned n, const shz_pci_ident_t *id, const char *claim,
                     int boot_fb_valid, shz_drvcat_result_t *out)
{
    shz_pci_ids_t ids;
    unsigned i;
    if (!out) return -1;
    out->best = out->bound = -1;
    out->best_rank = out->bound_rank = SHZ_DRVCAT_NO_RANK;
    out->state = SHZ_BIND_NO_DRIVER;
    out->matched_id[0] = 0;
    if ((!cat && n) || !id || shz_pci_ids_build(id, &ids)) return -1;
    for (i = 0; i < n; ++i) {
        const char *m = 0;
        const uint32_t r = shz_drvcat_rank(&cat[i], &ids, &m);
        if (r == SHZ_DRVCAT_NO_RANK) continue;
        /* The owner is classified against every matching entry, gated or not: an actual claim is a fact. */
        if (claim && cat[i].claim && same_claim(cat[i].claim, claim) && r < out->bound_rank) {
            out->bound = (int)i;
            out->bound_rank = r;
        }
        if ((cat[i].flags & SHZ_DRVCAT_NEEDS_BOOT_FB) && !boot_fb_valid) continue;
        if (r < out->best_rank) {                       /* ties keep catalogue order */
            out->best = (int)i;
            out->best_rank = r;
            copy_id(out->matched_id, m);
        }
    }
    if (claim) {
        static const char hosted[] = "ntdrv:";
        unsigned k = 0;
        while (hosted[k] && claim[k] == hosted[k]) ++k;
        if (out->bound >= 0) out->state = SHZ_BIND_BOUND;
        else out->state = hosted[k] ? SHZ_BIND_BOUND_UNLISTED : SHZ_BIND_BOUND_HOSTED;
    } else {
        out->state = out->best >= 0 ? SHZ_BIND_MATCHED_NOT_STARTED : SHZ_BIND_NO_DRIVER;
    }
    return 0;
}

const char *shz_drvcat_binding_name(enum shz_drvcat_binding b)
{
    switch (b) {
    case SHZ_BIND_NO_DRIVER: return "unsupported (no catalogue driver)";
    case SHZ_BIND_MATCHED_NOT_STARTED: return "matched, backend not attached (unsupported this boot)";
    case SHZ_BIND_BOUND: return "bound";
    case SHZ_BIND_BOUND_HOSTED: return "bound (hosted NT driver)";
    case SHZ_BIND_BOUND_UNLISTED: return "bound (backend not in catalogue)";
    }
    return "invalid";
}

enum shz_gop_check shz_gop_mode_check(const shz_gop_mode_t *m, uint64_t limit)
{
    uint64_t bytes;
    if (!m || (!m->base && !m->size && !m->bpp)) return SHZ_GOP_ABSENT;
    if (!m->base || (m->base & 3)) return SHZ_GOP_BAD_BASE;
    if (m->bpp != 32) return SHZ_GOP_BAD_BPP;
    if (m->format != SHZ_GOP_FMT_RGBX8888 && m->format != SHZ_GOP_FMT_BGRX8888) return SHZ_GOP_BAD_FORMAT;
    if (!m->width || !m->height) return SHZ_GOP_BAD_GEOMETRY;
    if ((m->pitch & 3) || m->pitch / 4 < m->width) return SHZ_GOP_BAD_PITCH;
    bytes = (uint64_t)m->pitch * m->height;             /* both < 2^32: cannot overflow 64 bits */
    if (bytes > m->size) return SHZ_GOP_EXCEEDS_SIZE;
    if (m->base > UINT64_MAX - m->size) return SHZ_GOP_WRAPS;
    if (m->width > SHZ_GOP_MAX_DIM || m->height > SHZ_GOP_MAX_DIM) return SHZ_GOP_TOO_LARGE;
    if (limit && m->base + m->size > limit) return SHZ_GOP_ABOVE_LIMIT;
    return SHZ_GOP_OK;
}

const char *shz_gop_check_name(enum shz_gop_check c)
{
    static const char *const names[] = { "valid", "absent", "bad base", "unsupported pixel format", "unsupported bpp",
                                         "zero geometry", "bad pitch", "pitch*height exceeds size", "range wraps",
                                         "mode larger than 8192", "above the graphics arena limit" };
    return (unsigned)c < sizeof names / sizeof names[0] ? names[c] : "invalid";
}
