/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 driver catalogue: SetupAPI-style PCI hardware/compatible ID generation, catalogue matching with the
 * documented Windows rank bands, and binding outcomes against the actual PCI ownership record (pci_claim()).
 *
 * Pure and freestanding (no kernel headers, no allocation) so the same translation unit links into Kernel64 and into
 * the host unit test. Matching only SELECTS a candidate; it never starts hardware. A function is reported BOUND only
 * when a real kernel backend has recorded ownership with pci_claim(); a catalogue match without that record is
 * MATCHED_NOT_STARTED, i.e. the hardware stays unsupported on this boot.
 *
 * ID formats follow Microsoft's "Identifiers for PCI devices" and the rank bands follow "How Windows ranks drivers":
 *   0x0000-0x0FFF  catalogue hardware ID  == device hardware ID
 *   0x1000-0x1FFF  catalogue compatible ID == device hardware ID
 *   0x2000-0x2FFF  catalogue hardware ID  == device compatible ID
 *   0x3000-0x3FFF  catalogue compatible ID == device compatible ID
 * Within a band the device list position (more specific first) dominates, then the catalogue list position.
 * No upstream implementation is copied.
 */
#ifndef K64_NTDRV_CATALOG_H
#define K64_NTDRV_CATALOG_H
#include <stdint.h>

#define SHZ_DRVCAT_ID_CHARS 64u                 /* longest: PCI\VEN_xxxx&DEV_xxxx&SUBSYS_xxxxxxxx&REV_xx (47) + NUL */
#define SHZ_DRVCAT_MAX_HWIDS 4u
#define SHZ_DRVCAT_MAX_COMPAT 8u
#define SHZ_DRVCAT_MAX_ENTRY_IDS 4u
#define SHZ_DRVCAT_NO_RANK 0xffffffffu

/* One PCI function as read from configuration space (read-only fields; no BAR sizing). */
typedef struct {
    uint16_t vendor, device, subsys_vendor, subsys_device;
    uint8_t class_code, subclass, prog_if, revision;
    uint8_t has_subsys;                         /* type-0 header: subsystem IDs are meaningful */
} shz_pci_ident_t;

typedef struct {
    char hw[SHZ_DRVCAT_MAX_HWIDS][SHZ_DRVCAT_ID_CHARS];
    char compat[SHZ_DRVCAT_MAX_COMPAT][SHZ_DRVCAT_ID_CHARS];
    unsigned n_hw, n_compat;
} shz_pci_ids_t;

/* Catalogue entry (an INF [Models] line plus the service it installs). `claim` is the exact string the backend passes
 * to pci_claim() once it really owns the function. */
#define SHZ_DRVCAT_NEEDS_BOOT_FB 1u             /* only meaningful when a validated firmware framebuffer was handed over */
#define SHZ_DRVCAT_BASIC_DISPLAY 2u
typedef struct {
    const char *service;
    const char *description;
    const char *claim;
    const char *hw[SHZ_DRVCAT_MAX_ENTRY_IDS];   /* NULL-terminated within the array */
    const char *compat[SHZ_DRVCAT_MAX_ENTRY_IDS];
    uint32_t flags;
} shz_drvcat_entry_t;

enum shz_drvcat_binding {
    SHZ_BIND_NO_DRIVER = 0,                     /* nothing in the catalogue matches: unsupported hardware */
    SHZ_BIND_MATCHED_NOT_STARTED = 1,           /* a catalogue driver matches, but no backend owns the function */
    SHZ_BIND_BOUND = 2,                         /* the owner recorded by pci_claim() is a matching catalogue driver */
    SHZ_BIND_BOUND_HOSTED = 3,                  /* owned by a hosted NT driver ("ntdrv:<service>") via Enum\PCI */
    SHZ_BIND_BOUND_UNLISTED = 4                 /* owned by a kernel backend absent from this catalogue (reported, not hidden) */
};

typedef struct {
    int best;                                   /* catalogue index of the best-ranked candidate, -1 when none */
    uint32_t best_rank;
    int bound;                                  /* catalogue index of the owning entry when BOUND, else -1 */
    uint32_t bound_rank;
    enum shz_drvcat_binding state;
    char matched_id[SHZ_DRVCAT_ID_CHARS];       /* device ID that produced best_rank */
} shz_drvcat_result_t;

/* Windows-format IDs, most specific first. Returns 0, or -1 for a NULL argument. */
int shz_pci_ids_build(const shz_pci_ident_t *id, shz_pci_ids_t *out);
/* Rank of one entry against one device ID set, SHZ_DRVCAT_NO_RANK when it does not match. Case-insensitive. */
uint32_t shz_drvcat_rank(const shz_drvcat_entry_t *e, const shz_pci_ids_t *ids, const char **matched);
/* Selects the best candidate and classifies the actual owner `claim` (NULL: no pci_claim() record).
 * `boot_fb_valid` gates SHZ_DRVCAT_NEEDS_BOOT_FB entries. Returns 0, or -1 for invalid arguments. */
int shz_drvcat_match(const shz_drvcat_entry_t *cat, unsigned n, const shz_pci_ident_t *id, const char *claim,
                     int boot_fb_valid, shz_drvcat_result_t *out);
const char *shz_drvcat_binding_name(enum shz_drvcat_binding b);

/* The Kernel64 catalogue: one entry per real in-kernel backend that calls pci_claim(). */
extern const shz_drvcat_entry_t shz_k64_catalog[];
extern const unsigned shz_k64_catalog_count;

/* ---- GOP basic display mode validation (boot handoff, shz_bootinfo_t fb_* fields) ---- */
#define SHZ_GOP_FMT_RGBX8888 0u                 /* values of enum shz_fb_format (abi/shz_abi.h) */
#define SHZ_GOP_FMT_BGRX8888 1u
#define SHZ_GOP_MAX_DIM 8192u                   /* the GUI's back-buffer limit (gfx_gop.c) */
enum shz_gop_check {
    SHZ_GOP_OK = 0, SHZ_GOP_ABSENT, SHZ_GOP_BAD_BASE, SHZ_GOP_BAD_FORMAT, SHZ_GOP_BAD_BPP, SHZ_GOP_BAD_GEOMETRY,
    SHZ_GOP_BAD_PITCH, SHZ_GOP_EXCEEDS_SIZE, SHZ_GOP_WRAPS, SHZ_GOP_TOO_LARGE, SHZ_GOP_ABOVE_LIMIT
};
typedef struct {
    uint64_t base, size;
    uint32_t width, height, pitch, bpp, format; /* pitch in bytes */
} shz_gop_mode_t;
/* `limit` is the first physical address the mapping may not reach (K64_GFX_ARENA_OFFSET in the kernel); 0 = none. */
enum shz_gop_check shz_gop_mode_check(const shz_gop_mode_t *m, uint64_t limit);
const char *shz_gop_check_name(enum shz_gop_check c);

/* ---- ntdrv_bind.c (Kernel64 only): boot binding snapshot over the actual PCI enumeration and pci_claim() record ---- */
#define SHZ_DRVBIND_MAX 32u
typedef struct {
    uint8_t bus, dev, fn, reserved;
    shz_pci_ident_t ident;
    shz_drvcat_result_t result;
    char owner[48];                             /* pci_claimed_by() copy, "" when unowned */
} shz_drvbind_t;
enum shz_gop_display {
    SHZ_GOPDISP_NO_HANDOFF = 0,                 /* no validated firmware framebuffer in this boot's bootinfo */
    SHZ_GOPDISP_REJECTED,                       /* handed over, but refused by the GOP mode check */
    SHZ_GOPDISP_AVAILABLE,                      /* valid; the display stack has not been initialised yet */
    SHZ_GOPDISP_ACTIVE,                         /* gfx_gop.c is the active display backend */
    SHZ_GOPDISP_SUPERSEDED,                     /* valid, but another backend (virtio-gpu) drives the screen */
    SHZ_GOPDISP_SUPERVISED                      /* Supervisor profile: the console owns GOP; not delegated to Kernel64 */
};
typedef struct {
    enum shz_gop_display state;
    enum shz_gop_check check;
    shz_gop_mode_t mode;
    const char *active_backend;                 /* g_fb.backend->name when the display is up, else NULL */
} shz_gop_status_t;
/* Entries written (<= max); *total receives the number of enumerated functions. Read-only config access. */
unsigned ntdrv_binding_snapshot(shz_drvbind_t *out, unsigned max, unsigned *total);
void ntdrv_gop_status(shz_gop_status_t *out);
/* Boot report: one "K64 drvbind:" line per enumerated PCI function plus the GOP basic display status. */
void ntdrv_binding_report(void);
#endif
