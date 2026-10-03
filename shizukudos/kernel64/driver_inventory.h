/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 device -> driver inventory (lane driver-bindings, batch 2).
 *
 * One row per PCI function from the REAL enumeration (pci_enumerate) classified against the Kernel64 catalogue
 * (ntdrv_catalog.c) and the REAL ownership record written by native backends with pci_claim() (gfx_gop.c,
 * gfx_virtio.c, gfx_fb.c, ahci_blk.c, nvme.c, sdhci.c, net_rtl8139.c) or by hosted NT drivers ("ntdrv:<service>",
 * ntdrv_io.c). Each bound row carries an OPERATION RESULT obtained through the owning backend's existing API:
 *   storage  - blk_read() of LBA 0 on the whole block device whose storage locator names this bus/device/function;
 *   display  - the current mode of g_fb when the claiming backend is the active display backend;
 *   network  - the RTL8139 PHY link bit through nic_link_up() plus the driver's frame counters;
 *   hosted   - the PnP devnode state of the hosted NT function driver (ntdrv_pnp.c).
 * A catalogue match alone is never reported as installed or working: status stays NOT_ATTACHED until a backend owns
 * the function, and BOUND_UNVERIFIED until its operation succeeded. No device is reset, programmed or BAR-sized here.
 *
 * The row/header layout below is the user-visible ABI of the proposed private NtQuerySystemInformation class
 * DRVINV_QUERY_CLASS (wired by core-integration; see .codex/handoff/driver-bindings-to-core-integration.patch).
 */
#ifndef K64_DRIVER_INVENTORY_H
#define K64_DRIVER_INVENTORY_H
#include <stdint.h>
#include "ntdrv_catalog.h"

#define DRVINV_VERSION 1u
#define DRVINV_MAX_ROWS 32u
#define DRVINV_QUERY_CLASS 0x105u               /* proposed private NtQuerySystemInformation class (0x104: GOP handoff) */

/* driver_inventory_run() flags */
#define DRVINV_RUN_STORAGE_READ 1u              /* read LBA 0 through each bound storage backend (may block; thread ctx) */
#define DRVINV_RUN_START_DISPLAY 2u             /* call the production gfx_fb_init() (idempotent) and record its NTSTATUS */
#define DRVINV_RUN_PUBLISH_PNP 4u               /* publish bound native functions as PnP devnodes when ntdrv_pnp provides it */
#define DRVINV_RUN_REPORT 8u                    /* "K64 drvinv:" boot report lines */

enum drvinv_status {                            /* folded per-row state; only WORKING means a verified operation */
    DRVINV_UNSUPPORTED = 0,                     /* no catalogue driver and no owner: unsupported hardware */
    DRVINV_NOT_ATTACHED = 1,                    /* a catalogue driver matches, but no backend owns the function */
    DRVINV_BOUND_UNVERIFIED = 2,                /* owned by a backend; its operation was not run or is unavailable */
    DRVINV_WORKING = 3,                         /* owned and the operation through the owning backend succeeded */
    DRVINV_FAILED = 4                           /* owned, but the operation through the owning backend failed */
};
enum drvinv_op {
    DRVINV_OP_NONE = 0,
    DRVINV_OP_STORAGE_READ0 = 1,                /* op_value: sector size, 0x55AA signature flag, sectors lo, sectors hi */
    DRVINV_OP_DISPLAY_MODE = 2,                 /* op_value: width, height, pitch, bpp */
    DRVINV_OP_NIC_LINK = 3,                     /* op_value: link up, rx frames, tx frames, irqs */
    DRVINV_OP_HOSTED_PNP = 4                    /* op_value: pnp state, 0, 0, 0 */
};
enum drvinv_pnp {
    DRVINV_PNP_NONE = 0,                        /* no devnode for this function */
    DRVINV_PNP_HOSTED_RECORDED = 1,             /* hosted NT driver PDO recorded, not started */
    DRVINV_PNP_HOSTED_STARTED = 2,              /* hosted NT driver PDO started (IRP_MN_START_DEVICE succeeded) */
    DRVINV_PNP_NATIVE_PUBLISHED = 3,            /* native backend devnode published into the PnP graph */
    DRVINV_PNP_UNAVAILABLE = 4                  /* ntdrv_pnp has no query/publish entry in this build (handoff pending) */
};

#define DRVINV_OP_NOT_RUN ((int32_t)0x7fffffff) /* op_status sentinel: no operation was attempted */

typedef struct {
    uint8_t bus, dev, fn, bind_state;           /* bind_state: enum shz_drvcat_binding */
    uint16_t vendor, device, subsys_vendor, subsys_device;
    uint8_t class_code, subclass, prog_if, revision;
    uint8_t status, op_kind, pnp_state, catalog_index;   /* catalog_index 0xff: none */
    int32_t init_status;                        /* NTSTATUS of the backend bring-up as observed (see driver_inventory.c) */
    int32_t op_status;                          /* NTSTATUS of the operation, DRVINV_OP_NOT_RUN when not attempted */
    uint32_t op_value[4];
    char service[32];                           /* catalogue service of the owner (or best match), "" when none */
    char owner[48];                             /* pci_claimed_by() string, "" when unowned */
    char hwid[64];                              /* most specific Windows hardware ID */
    char detail[32];                            /* block device / display backend name used for the operation */
} drvinv_row_t;

typedef struct {
    uint32_t version, row_size, count, total_enumerated;
    uint32_t gop_state, gop_check;              /* enum shz_gop_display / enum shz_gop_check */
    uint32_t gop_width, gop_height, gop_pitch, gop_format;
    uint64_t gop_base, gop_size;
    uint32_t runs, storage_probed;              /* completed driver_inventory_run() calls; rows with a storage read */
    char active_backend[32];                    /* g_fb.backend->name, "" when no display is up */
} drvinv_header_t;

_Static_assert(sizeof(drvinv_row_t) == 220, "drvinv_row_t ABI");
_Static_assert(sizeof(drvinv_header_t) == 96, "drvinv_header_t ABI");

/* ---- pure helpers (host-testable) ---- */
enum drvinv_status drvinv_fold(enum shz_drvcat_binding bind, int op_attempted, int32_t op_status);
enum drvinv_op drvinv_op_for_service(const char *service);
/* Bytes needed for `rows` rows, 0 when rows exceeds DRVINV_MAX_ROWS. */
uint64_t drvinv_query_size(uint32_t rows);
const char *drvinv_status_name(enum drvinv_status s);

/* ---- Kernel64 entry points ---- */
#ifndef DRVINV_HOST
/* Builds the inventory; returns the number of rows (functions enumerated may exceed it). Thread context. */
unsigned driver_inventory_run(uint32_t flags);
/* Snapshot for setupapi/status: re-classifies live claims and display/NIC state, keeps the last storage reads.
 * Returns 0 or -1 (NULL header). rows may be NULL when max is 0. */
int driver_inventory_query(drvinv_header_t *hdr, drvinv_row_t *rows, unsigned max);
struct process;
/* NtQuerySystemInformation(DRVINV_QUERY_CLASS) body: header + rows to user memory, NTSTATUS. */
int32_t driver_inventory_query_user(struct process *p, uint64_t out, uint64_t length, uint64_t return_length);
#endif
#endif
