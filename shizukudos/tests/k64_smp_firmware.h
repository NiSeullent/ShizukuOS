/* SPDX-License-Identifier: GPL-2.0-only
 * Isolated test-stub handoff of actual Multiboot firmware memory-map records.
 * This is not a production bootinfo extension or a synthetic ACPI topology.
 */
#ifndef SHZ_SMP_TEST_FIRMWARE_H
#define SHZ_SMP_TEST_FIRMWARE_H
#include <stdint.h>
#define SHZ_SMP_TEST_FIRMWARE_PA 0x8000u
#define SHZ_SMP_TEST_FIRMWARE_MAGIC 0x4d50534du
/* The isolated runner pins QEMU pc RAM to256MiB. This validates only that
 * fixture's reserved RAM tail, not arbitrary E820 reserved/MMIO memory. */
#define SHZ_SMP_TEST_RAM_TOP (256ull<<20)
struct shz_smp_test_firmware {
    uint32_t magic,count;
    struct { uint64_t base,size; uint32_t type,reserved; } range[32];
};
#endif
