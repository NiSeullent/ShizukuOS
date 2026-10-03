/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_LAPTOP_FIRMWARE_H
#define SHZ_LAPTOP_FIRMWARE_H
#include "laptop.h"

#define SHZ_FIRMWARE_ROOT_ENTRIES 128u
#define SHZ_FIRMWARE_RSDP_MAX 4096u
#define SHZ_FIRMWARE_OTHER_TABLE_MAX 1048576u
#define SHZ_FIRMWARE_READ_BUDGET 4194304u

/* Trusted native firmware owner only. Each synchronous, bounded read validates
 * its real mapping/owner generation before and after copying, preserves a
 * stable firmware snapshot for the complete probe, and leaves no detached I/O
 * targeting destination. Zero means exact-length success; negative SHZ_*
 * errors are preserved. Application pointers/claimed ownership are not grants.
 */
typedef int (*shz_firmware_read_fn)(void *context,uint64_t physical_address,
                                  void *destination,size_t bytes);
struct shz_laptop_firmware {
    uint64_t rsdp_pa,root_pa,fadt_pa,ecdt_pa;
    uint32_t entry_count;
    uint8_t rsdp_revision,uses_xsdt,has_ecdt;
    struct shz_fixed fixed;
    struct shz_ec_table ec;
};

/* RSDP revision0 uses RSDT; revision1 is unsupported; >=2 prefers its nonzero
 * XSDT. A malformed/unreadable nonzero XSDT never falls back to RSDT. FADT is
 * required, ECDT optional. All directory members are checksummed, without AML
 * execution or register access. Every requested callback byte, including
 * snapshot-header rereads and failed reads, consumes the aggregate read budget.
 * Over-budget reads are refused before invoking the provider. Output remains
 * byte-for-byte unchanged on every error, including absent FADT.
 */
int shz_laptop_firmware_probe(shz_firmware_read_fn read,void *context,
                             uint64_t rsdp_pa,struct shz_laptop_firmware *out);
#endif
