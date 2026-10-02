/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SUPERVISOR_AP_BOOT_H
#define SHZ_SUPERVISOR_AP_BOOT_H
#include <stdint.h>
#include <stddef.h>
#include "../../kernel64/smp_acpi.h"
#define SHZ_AP_MAGIC UINT64_C(0x31504150555a4853)
#define SHZ_AP_CFG_MAGIC UINT32_C(0x31435041)
#define SHZ_AP_VERSION 1u
#define SHZ_AP_PAGE 4096u
#define SHZ_AP_PARAMS 0x800u
#define SHZ_AP_STACK_BYTES 65536u
#define SHZ_AP_WORK_BYTES 4096u
#define SHZ_AP_WORK_ROUNDS 512u
#define SHZ_AP_FAIL_CAP 1u
#define SHZ_AP_FAIL_START 2u
#define SHZ_AP_FAIL_WORK 3u
enum shz_ap_state { SHZ_AP_NEW, SHZ_AP_STARTING, SHZ_AP_ENTERED, SHZ_AP_VMX,
                    SHZ_AP_WORKING, SHZ_AP_DONE, SHZ_AP_FAILED, SHZ_AP_FAILING };
typedef struct { uint32_t magic, version, count, flags; } shz_ap_config_t;
typedef struct {
    uint32_t state, error, apic_id, reserved;
    uint64_t cr3, stack, gdt, idt, tss, cr0, cr4, efer, hash, work;
} shz_ap_record_t;
typedef struct {
    uint64_t magic;
    uint32_t version, bytes, requested, flags;
    uint64_t low_base, low_pages;
    shz_smp_topology_t topology;
    uint32_t sealed, release;
    uint64_t bsp_hash;
    shz_ap_record_t cpu[SHZ_SMP_MAX_CPUS];
} shz_ap_boot_t;
typedef struct {
    uint32_t cr3, cpu, apic_id, claim;
    uint64_t stack, entry;
} shz_ap_params_t;
_Static_assert(sizeof(shz_ap_params_t) == 32, "startup assembly ABI");
_Static_assert(sizeof(shz_ap_boot_t) <= SHZ_AP_PAGE, "one retained resource page");
int shz_ap_config_valid(const shz_ap_config_t *, size_t);
/* Whole physical range, firmware stride, overflow/type/cache checks. type=0
 * allows firmware RAM for the ACPI reader; type=2 requires owned LoaderData. */
int shz_ap_map_covers(const void *, size_t, size_t, uint64_t, uint64_t, unsigned);
int shz_ap_boot_valid(const shz_ap_boot_t *, uint64_t, uint64_t,
                      const void *, size_t, size_t, uint64_t, uint64_t);
int shz_ap_advance(shz_ap_record_t *, unsigned, unsigned);
void shz_ap_fail(shz_ap_record_t *, unsigned);
uint64_t shz_ap_hash(const uint8_t *, size_t, unsigned);
int shz_ap_lapic_pte_ok(uint64_t, uint64_t);
int shz_ap_lapic_base_ok(uint64_t, uint64_t);
#endif
