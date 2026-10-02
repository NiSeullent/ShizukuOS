/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_AP_PREPARE_H
#define SHZ_AP_PREPARE_H
#include "efi_ext.h"
#include "../include/ap_boot.h"
EFI_STATUS shz_ap_prepare(EFI_BOOT_SERVICES *, uint64_t, const shz_ap_config_t *,
                           uint64_t *, uint64_t *);
#endif
