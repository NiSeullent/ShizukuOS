/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHIZUKUDOS_UEFI32_PAGING_H
#define SHIZUKUDOS_UEFI32_PAGING_H
#include <stdint.h>
/* Caller supplies safe reads of firmware-owned identity-mapped page tables. */
typedef int (*sd32_read_pte)(void *, uint64_t physical, uint64_t *entry);
int sd32_identity_page(uint64_t cr3, uint64_t address, int levels, int writable,
                       int executable, sd32_read_pte read, void *context);
#endif
