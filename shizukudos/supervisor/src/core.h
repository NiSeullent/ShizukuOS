/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuCore owns admission and launch of the existing Supervisor domains.
 * This private host context does not extend either shared boot ABI.
 */
#ifndef SHZ_CORE_H
#define SHZ_CORE_H
#include "domain.h"
#include "boot_manifest.h"

#define SHZ_CORE_NAME "ShizukuCore Kernel"
#define SHZ_CORE_CHILD_COUNT 4u

typedef struct {
    const char *name;
    const char *mode;
    const char *parent;
    uint32_t domain_id;
    dom_kind_t kind;
} shz_core_child_t;

enum shz_core_phase {
    SHZ_CORE_NEW = 0,
    SHZ_CORE_CREATING,
    SHZ_CORE_READY,
    SHZ_CORE_RUNNING,
    SHZ_CORE_FINISHED,
    SHZ_CORE_FAILED
};

typedef struct { uint64_t base, size; } shz_core_range_t;
typedef struct {
    shz_core_range_t guest, kernel32, kernel64, host, ipc, disk, memmap;
    shz_blob_t blobs[SHZ_MAX_BLOBS];
    uint64_t tsc_hz;
    uint32_t loader_flags;
} shz_core_resources_t;

/* Initialize to {0}. Members is an admission mask indexed by descriptor,
 * not a second lifecycle table. Runtime state remains exclusively in g_dom.
 * No retry is allowed after this context leaves NEW; allocations are retained
 * on failure because the existing Supervisor pool has no release operation.
 */
typedef struct {
    shz_info_t *owner;
    uint64_t boot_epoch, domain_epoch;
    uint32_t phase, members;
    uint32_t generation[SHZ_CORE_CHILD_COUNT];
    shz_core_resources_t resources;
    /* Installed-target admission. manifest_state is SHZ_CORE_MANIFEST_*;
     * attempted marks constructors invoked so rollback quarantines exactly
     * the slots this root wrote. */
    uint32_t manifest_state, attempted, driver_state;
    uint32_t manifest_child[SHZ_CORE_CHILD_COUNT]; /* entry index + 1, 0 when unlisted */
    shz_bman_t manifest;
    /* Kernel64 SHZ_HC_DRIVER_REPORT, copied into Supervisor memory and
     * validated; driver_report is SHZ_CORE_DRV_REPORTED_* or 0. One report
     * per admitted Kernel64 domain generation (report_generation). */
    uint32_t driver_report, driver_report_generation;
    shz_drvrep_t driver_report_copy;
} shz_core_t;

enum shz_core_manifest_state {
    SHZ_CORE_MANIFEST_NONE = 0,     /* not evaluated */
    SHZ_CORE_MANIFEST_ABSENT = 1,   /* historical unmanifested route: no installed-target attestation */
    SHZ_CORE_MANIFEST_ADMITTED = 2, /* every blob/child bound to a stamped SHZBOOT.MAN: attested */
    SHZ_CORE_MANIFEST_TEMPLATE = 3  /* unstamped installer template: blobs/children/dependencies bound
                                     * exactly as ADMITTED, installed-target identity NOT attested */
};

/* Driver initialization hook. Called once, after every child and IPC
 * channel is admitted and before the root becomes READY; the scheduler has
 * not run any child yet. The driver-bringup worker provides the strong
 * definition; the weak default in core.c returns SHZ_CORE_DRIVERS_ABSENT.
 * Return 0 = bound, SHZ_CORE_DRIVERS_ABSENT = no provider linked,
 * negative = refuse (ShizukuCore rolls the whole creation back). The hook
 * must not change root resources, domains or channels; Core re-validates. */
#define SHZ_CORE_DRIVERS_ABSENT 1
enum shz_core_driver_state {
    SHZ_CORE_DRV_NONE = 0, SHZ_CORE_DRV_ABSENT = 1, SHZ_CORE_DRV_BOUND = 2,
    /* driver_report values: Kernel64's own post-bring-up report (never BOUND) */
    SHZ_CORE_DRV_REPORTED_OK = 3,       /* failed == 0 && services_failed == 0 */
    SHZ_CORE_DRV_REPORTED_FAILED = 4
};
typedef struct {
    uint64_t boot_epoch, domain_epoch;
    uint64_t install_generation;    /* 0 when manifest absent */
    uint32_t members;               /* bit index = shz_core_child() index */
    uint32_t loader_flags, cap_bits, manifest_state;
    const shz_bman_t *manifest;     /* NULL when absent; read-only */
    const shz_core_resources_t *resources;
} shz_core_driver_view_t;
int shz_core_driver_init(const shz_core_driver_view_t *view, shz_info_t *info);

const shz_core_child_t *shz_core_child(unsigned index);
const shz_core_child_t *shz_core_find(uint32_t domain_id);
int shz_core_create(shz_core_t *core, shz_info_t *info, const shz_caps_t *caps,
                    const uint8_t *vbios, unsigned vbios_len);
int shz_core_run(shz_core_t *core, shz_info_t *info);

/* Bootinfo install tail for a kernel child being constructed by the
 * creating root. Fills SHZ_INSTID_SUPERVISOR identity and returns 1 only
 * when that root admitted a stamped manifest; otherwise zeroes *out (the
 * historical unattested route) and returns 0. */
int shz_core_install_identity(shz_install_identity_t *out);
/* Pure report validation (magic/version/size/flags/reserved, counter sum ==
 * rows <= SHZ_DRVREP_MAX_ROWS, install_generation == expected). Returns
 * SHZ_OK or a negative shz_status; *why gets a static reason. */
int shz_core_drvrep_validate(const shz_drvrep_t *r, uint64_t expected_generation, const char **why);
/* SHZ_HC_DRIVER_REPORT backend. `copy` is already in Supervisor memory.
 * Accepts only the running root's admitted Kernel64 at its admitted
 * generation, once. Returns SHZ_OK or a negative shz_status. */
int shz_core_driver_report(uint32_t domain_id, uint32_t domain_generation, const shz_drvrep_t *copy);
#endif
