/* SPDX-License-Identifier: GPL-2.0-only
 * ACPI MCFG (revision 1) parse and ECAM physical address calculation.
 * Bases are bus-zero relative. Nothing is mapped or port-probed here.
 */
#ifndef CSMWRAP_MCFG_H
#define CSMWRAP_MCFG_H
#include <stddef.h>
#include <stdint.h>

typedef struct csm_mcfg_window {
    uint64_t base;
    uint16_t segment;
    uint8_t first_bus;
    uint8_t last_bus;
} csm_mcfg_window;

/* On failure *count is 0 and windows is left unchanged.
 * windows == NULL && capacity == 0 queries the entry count. */
int csm_mcfg_parse(const void *table, size_t bytes, csm_mcfg_window *windows,
                   size_t capacity, size_t *count);

/* Writes *physical only on success. width is 1, 2 or 4 and must be
 * naturally aligned inside the 4096-byte function space. */
int csm_ecam_address(const csm_mcfg_window *window, uint16_t segment, uint8_t bus,
                     uint8_t dev, uint8_t fn, uint16_t offset, uint8_t width,
                     uint64_t *physical);
#endif
