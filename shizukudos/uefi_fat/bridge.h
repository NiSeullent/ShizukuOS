/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SDFAT_BRIDGE_H
#define SDFAT_BRIDGE_H
#include "budget.h"
#include "layout.h"
#include "../../drivers/ahci_native/ahci.h"
struct sdfat_binding {
    struct ahci_device *disk;
    SDFAT_PROOF *proof;
    struct sdfat_clock clock;
    uint64_t (*ticks)(void *);
    void *ticks_user;
};
int sdfat_fat_now(void *, uint64_t *);
uint64_t sdfat_ahci_now(void *);
int sdfat_read_sector(void *, uint64_t, uint8_t[512], uint32_t);
#endif
