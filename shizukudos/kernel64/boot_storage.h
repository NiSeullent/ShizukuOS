/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_BOOT_STORAGE_H
#define SHZ_K64_BOOT_STORAGE_H
#include "blk.h"
/* Entry owner calls only after actual archive parser and storage enumeration.
 * The archive_loaded argument is its actual parser result, never userspace. */
int k64_boot_storage_bind(const shz_bootinfo_t *,int archive_loaded);
#endif
