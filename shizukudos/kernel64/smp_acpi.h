/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_SMP_ACPI_H
#define SHZ_K64_SMP_ACPI_H
#include <stdint.h>
#include <stddef.h>

#define SHZ_SMP_MAX_CPUS 32u
#define SHZ_SMP_ACPI_MAX_TABLE (1024u * 1024u)

enum shz_smp_acpi_status {
    SHZ_SMP_ACPI_OK = 0,
    SHZ_SMP_ACPI_NOT_FOUND = -1,
    SHZ_SMP_ACPI_INVALID = -2,
    SHZ_SMP_ACPI_UNSUPPORTED = -3,
    SHZ_SMP_ACPI_LIMIT = -4
};
/* The reader must reject unavailable physical ranges rather than faulting.
 * No parser pointer aliases firmware; all fields are copied and LE-decoded. */
typedef int (*shz_smp_phys_read_fn)(void *ctx, uint64_t pa, void *dst, size_t len);
typedef struct shz_smp_topology {
    uint64_t rsdp_pa, madt_pa, lapic_pa;
    uint32_t count, bsp_index, pcat_compat;
    uint32_t apic_id[SHZ_SMP_MAX_CPUS];
    uint32_t acpi_uid[SHZ_SMP_MAX_CPUS];
} shz_smp_topology_t;

/* RSDP supplied by firmware, or found by the BIOS-only scanner. This first
 * xAPIC backend rejects enabled x2APIC CPUs explicitly; no partial topology. */
int shz_smp_acpi_probe(shz_smp_phys_read_fn read, void *ctx, uint64_t rsdp_pa,
                       uint32_t bsp_apic_id, shz_smp_topology_t *out);
int shz_smp_acpi_find_bios(shz_smp_phys_read_fn read, void *ctx, uint64_t *rsdp_pa);
#endif
