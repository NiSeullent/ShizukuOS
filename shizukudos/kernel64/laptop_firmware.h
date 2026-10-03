/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_LAPTOP_FIRMWARE_H
#define SHZ_K64_LAPTOP_FIRMWARE_H
#include "k64.h"
#include "../../drivers/shz_laptop/firmware.h"

/* BSP boot-time discovery only, after mem_init and before sched_init. Uses
 * retained firmware authority; does not claim EC/I2C, route SCI, enable ACPI,
 * modify register state, or manufacture a UEFI firmware memory grant. */
int k64_laptop_firmware_init(const shz_bootinfo_t *);
/* Kernel-only immutable copy. NULL after absent/rejected/unsupported firmware.
 * A caller cannot treat register addresses in this snapshot as an I/O grant. */
const struct shz_laptop_firmware *k64_laptop_firmware_snapshot(void);
#endif
