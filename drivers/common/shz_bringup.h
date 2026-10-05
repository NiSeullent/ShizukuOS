/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuCore Kernel64 driver bring-up: one boot-time entry for the Core64 boot path.
 *
 * Enumeration (existing Kernel64 PCI scan) -> match against the native driver table and the installed driver catalog
 * (HKLM\SYSTEM\CurrentControlSet\Enum\PCI devnodes written by shzpnp add-driver --install, the same records that
 * shz_query_pnp_catalog publishes) -> probe/resources/init through the existing owners (disk_init()'s ahci/nvme/sdhci
 * cores, the gfx owners, NtLoadDriver's kernel core: DriverEntry, devnode binding, AddDevice, IRP_MN_START_DEVICE with
 * the function's own BARs/INTx) -> power (IRP_MJ_SHUTDOWN notifications, native cache flush) and removal (the existing
 * NtUnloadDriver QUERY_REMOVE/REMOVE path) -> a per-function result table copied from what those owners actually did.
 *
 * Bring-up claims nothing itself: no physical range, IRQ, DMA or I/O port is granted here. Only functions whose devnode
 * names an installed kernel service are handed to that service, and never a function a native driver already claimed.
 * Rows are fixed width and carry no kernel pointers. Implemented in shizukudos/kernel64/ntdrv_pnp.c.
 */
#ifndef SHZ_COMMON_BRINGUP_H
#define SHZ_COMMON_BRINGUP_H
#include <stdint.h>

#define SHZ_BRINGUP_VERSION 2u              /* 2: catalog/profile tail appended after row[] */
#define SHZ_BRINGUP_ROWS 32u               /* = the Kernel64 pci_enumerate() capacity */
#define SHZ_BRINGUP_SERVICES 16u

/* phase argument */
#define SHZ_BRINGUP_PHASE_EARLY 1u         /* BSP, after mem_init(), before sched_init(): firmware discovery only */
#define SHZ_BRINGUP_PHASE_DEVICES 2u       /* after disk_init(), sched_init() and sti(): services, binding, report */

/* flags argument */
#define SHZ_BRINGUP_F_LAPTOP_FIRMWARE 0x1u /* EARLY: run the retained-firmware ACPI discovery (k64_laptop_firmware_init) */
#define SHZ_BRINGUP_F_LOAD_SERVICES 0x2u   /* DEVICES: load installed kernel services named by present, unclaimed devnodes */
#define SHZ_BRINGUP_F_QUIET 0x4u           /* DEVICES: summary line only, no per-function log lines */
#define SHZ_BRINGUP_F_FOUNDATION 0x8u      /* DEVICES: native Win98 foundation profile: no catalog import, no services */

/* profile_flags (same values as shz_abi.h SHZ_DRVREP_PASSTHROUGH / SHZ_DRVREP_FOUNDATION) */
#define SHZ_BRINGUP_PROFILE_DEVICES_ELSEWHERE 0x1u  /* Supervisor guest: Kernel64 owns no PCI function */
#define SHZ_BRINGUP_PROFILE_FOUNDATION 0x2u         /* foundation profile: only native in-kernel drivers */

enum shz_bringup_driver {
    SHZ_BRINGUP_DRV_NONE = 0,
    SHZ_BRINGUP_DRV_AHCI = 1,              /* class 01.06.01 -> ahci_blk.c over drivers/ahci_native */
    SHZ_BRINGUP_DRV_NVME = 2,              /* class 01.08.02 -> nvme.c */
    SHZ_BRINGUP_DRV_SDHCI = 3,             /* class 08.05.xx -> sdhci.c */
    SHZ_BRINGUP_DRV_GFX_BOCHS = 4,         /* 1234:1111 -> gfx_fb.c (Bochs VBE) */
    SHZ_BRINGUP_DRV_GFX_VIRTIO = 5,        /* 1af4:1050 -> gfx_virtio.c */
    SHZ_BRINGUP_DRV_GFX_GOP = 6,           /* other class 03: gfx_gop.c owns it only when the GOP framebuffer is in its BAR */
    SHZ_BRINGUP_DRV_NET_RTL8139 = 7,       /* 10ec:8139 -> net_rtl8139.c */
    SHZ_BRINGUP_DRV_HOSTED = 8,            /* installed Windows x64 .sys through the NT driver host */
    SHZ_BRINGUP_DRV_XHCI_UNLINKED = 9,     /* class 0c.03.30: drivers/xhci_native core exists, not linked into Kernel64 */
    SHZ_BRINGUP_DRV_PLATFORM = 10          /* host/ISA/PCI bridges: chipset, no function driver needed */
};
enum shz_bringup_state {
    SHZ_BRINGUP_UNSUPPORTED = 0,           /* no native driver and no installed service: left unclaimed */
    SHZ_BRINGUP_RUNNING = 1,               /* owner claimed it and published its function (blk device, PDO started) */
    SHZ_BRINGUP_CLAIMED = 2,               /* owner claimed it; no published function observed (non-PnP hosted, gfx) */
    SHZ_BRINGUP_NOT_STARTED = 3,           /* a native driver matches; its owner has not claimed it (failed or deferred) */
    SHZ_BRINGUP_INIT_FAILED = 4,           /* installed service load / AddDevice / START_DEVICE failed: init_status */
    SHZ_BRINGUP_BOUND_NO_START = 5,        /* hosted driver bound but has no AddDevice (legacy driver) */
    SHZ_BRINGUP_INFRASTRUCTURE = 6,        /* platform function (bridge) */
    SHZ_BRINGUP_LINKED_ELSEWHERE = 7       /* source driver exists in drivers/, Kernel64 has no production binding */
};

typedef struct {
    uint8_t bus, dev, fn, class_code, subclass, prog_if, irq_line, reserved0;
    uint16_t vendor, device;
    uint16_t driver, state;                /* shz_bringup_driver, shz_bringup_state */
    int32_t init_status;                   /* NTSTATUS for hosted rows; blk devices published for storage; 0 otherwise */
    uint32_t published;                    /* blk whole devices / started PDOs observed for this function */
    char owner[48];                        /* pci_claimed_by() text, truncated */
    char service[32];                      /* devnode Service value, if the installed catalog names one */
} shz_bringup_row_t;

typedef struct {
    uint32_t version, row_size, profile_passthrough, rows;
    uint32_t running, claimed, not_started, failed, unsupported, infrastructure, linked_elsewhere;
    uint32_t services_considered, services_loaded, services_failed;
    int32_t laptop_firmware;               /* k64_laptop_firmware_init result; 1 = not attempted */
    uint32_t laptop_has_ecdt;              /* ECDT parsed; EC I/O is NOT granted or started */
    shz_bringup_row_t row[SHZ_BRINGUP_ROWS];
    /* version 2 tail (ntdrv_catalog.c, \SHZ\DRIVERS\CATALOG.INI v2) */
    uint32_t catalog_entries;              /* [Driver.n] sections of a file that validated as a whole */
    uint32_t catalog_matched;              /* builtin rows matched to a linked Kernel64 driver + service rows verified */
    uint32_t catalog_rejected;             /* rows rejected (malformed, image hash mismatch, builtin without linked driver) */
    uint32_t catalog_registered;           /* Enum\PCI devnodes written for validated service rows */
    int32_t catalog_status;                /* 0 imported, 1 absent / not attempted, < 0 whole file rejected (SHZ_CAT_E_*) */
    uint32_t profile_flags;                /* SHZ_BRINGUP_PROFILE_* */
    uint32_t reserved1;
    uint64_t install_generation;           /* k64_install_generation() at report time, 0 unattested */
} shz_bringup_report_t;

/* The single boot entry. `bootinfo` is the kernel's copy (const shz_bootinfo_t *; needed for EARLY only, may be NULL for
 * DEVICES). Returns 0, or a negative count of rows in INIT_FAILED (DEVICES), or the laptop result (EARLY, < 0 on error).
 * DEVICES runs once; later calls only refresh the report. Not reentrant: call from the boot thread. */
int shz_driver_bringup_init(const void *bootinfo, unsigned phase, unsigned flags);
/* Recomputes the rows from the owners' current claims (a gfx owner claims lazily) and returns the kernel copy. */
const shz_bringup_report_t *shz_driver_bringup_report(void);
/* Power transition before reset/power-off: IRP_MJ_SHUTDOWN to registered hosted devices, then flush every whole blk
 * device. Returns the number of flushes that failed. */
int shz_driver_bringup_quiesce(void);  /* runs once; later calls return the first result */
#endif
