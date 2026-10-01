/* SPDX-License-Identifier: GPL-2.0-only
 * INT 12h conventional memory in KiB.
 * ShizukuDOS refuses to boot below 448. The DOS16 BIOS contract accepts
 * 480..640. With no map installed, the platform reports 639: 640 KiB
 * minus the 1 KiB EBDA, the same value stored at BDA 0040:0013.
 * A supplied E820 map reports the usable range that starts at physical 0,
 * clipped below 0xA0000, including values below 448.
 */
#ifndef CSMWRAP_INT12_H
#define CSMWRAP_INT12_H
#include "e820.h"
#include <stddef.h>
#include <stdint.h>
#define CSM_CONVENTIONAL_KB_MIN 448u
#define CSM_CONVENTIONAL_KB 639u
uint16_t csm_int12(const csm_e820_entry *map, size_t count);
#endif
