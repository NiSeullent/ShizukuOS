/* SPDX-License-Identifier: GPL-2.0-only
 * Host build of kernel64/sdhci.c (-DSDHCI_HOST_TEST, tests/run_sdhci_host.py): the real kernel headers for the types,
 * a register-level SDHCI + SD/eMMC card model (tests/test_sdhci.c) behind the register accessors, and host versions
 * of the few kernel services the driver uses (kprintf, pmm_alloc/p2v, blk_kva_to_pa, mutexes). */
#ifndef SDHCI_HOST_SHIM_H
#define SDHCI_HOST_SHIM_H
#include "blk.h"
#include "pci.h"

uint32_t mock_read(volatile uint8_t *regs, unsigned off, unsigned size);
void mock_write(volatile uint8_t *regs, unsigned off, uint32_t v, unsigned size);
uint64_t mock_now_us(void);
void mock_relax(void);
int sdhci_host_test_probe(void *regs, blk_dev_t **out);
#endif
