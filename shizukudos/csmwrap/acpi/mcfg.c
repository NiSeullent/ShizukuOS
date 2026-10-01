/* SPDX-License-Identifier: GPL-2.0-only */
#include "mcfg.h"
#include "regs.h"

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int window_from(const uint8_t *entry, csm_mcfg_window *window)
{
    uint64_t span;
    window->base = rd64(entry);
    window->segment = rd16(entry + 8);
    window->first_bus = entry[10];
    window->last_bus = entry[11];
    if (rd32(entry + 12) != 0 || window->first_bus > window->last_bus)
        return CSM_ERR_MALFORMED;
    if ((window->base & 0xfffffull) != 0)
        return CSM_ERR_MALFORMED;
    span = ((uint64_t)window->last_bus + 1ull) << 20;
    if (span == 0 || window->base > UINT64_MAX - (span - 1ull))
        return CSM_ERR_MALFORMED;
    return CSM_OK;
}

static int windows_overlap(const csm_mcfg_window *a, const csm_mcfg_window *b)
{
    uint64_t a_first, a_last, b_first, b_last;
    a_first = a->base + ((uint64_t)a->first_bus << 20);
    a_last = a->base + (((uint64_t)a->last_bus + 1ull) << 20) - 1ull;
    b_first = b->base + ((uint64_t)b->first_bus << 20);
    b_last = b->base + (((uint64_t)b->last_bus + 1ull) << 20) - 1ull;
    if (a->segment == b->segment && a->first_bus <= b->last_bus && b->first_bus <= a->last_bus)
        return 1;
    return a_first <= b_last && b_first <= a_last;
}

int csm_mcfg_parse(const void *table, size_t bytes, csm_mcfg_window *windows,
                   size_t capacity, size_t *count)
{
    const uint8_t *p = (const uint8_t *)table;
    uint32_t length;
    size_t entries, i, j;
    uint8_t sum = 0;
    csm_mcfg_window parsed[64];
    if (!count)
        return CSM_ERR_ARG;
    *count = 0;
    if (!p || (windows == 0 && capacity != 0))
        return CSM_ERR_ARG;
    if (bytes < 44 || p[0] != 'M' || p[1] != 'C' || p[2] != 'F' || p[3] != 'G')
        return CSM_ERR_MALFORMED;
    length = rd32(p + 4);
    if (length < 44 || length > bytes || ((length - 44u) % 16u) != 0)
        return CSM_ERR_MALFORMED;
    if (p[8] != 1)
        return CSM_ERR_ARG;
    for (i = 0; i < length; ++i)
        sum = (uint8_t)(sum + p[i]);
    if (sum != 0)
        return CSM_ERR_MALFORMED;
    for (i = 36; i < 44; ++i)
        if (p[i] != 0)
            return CSM_ERR_MALFORMED;
    entries = (length - 44u) / 16u;
    if (entries > 64)
        return CSM_ERR_NOSPACE;
    for (i = 0; i < entries; ++i) {
        if (window_from(p + 44 + i * 16, &parsed[i]))
            return CSM_ERR_MALFORMED;
        for (j = 0; j < i; ++j)
            if (windows_overlap(&parsed[i], &parsed[j]))
                return CSM_ERR_MALFORMED;
    }
    if (!windows) {
        if (capacity != 0)
            return CSM_ERR_ARG;
        *count = entries;
        return CSM_OK;
    }
    if (capacity < entries)
        return CSM_ERR_NOSPACE;
    for (i = 0; i < entries; ++i)
        windows[i] = parsed[i];
    *count = entries;
    return CSM_OK;
}

int csm_ecam_address(const csm_mcfg_window *window, uint16_t segment, uint8_t bus,
                     uint8_t dev, uint8_t fn, uint16_t offset, uint8_t width, uint64_t *physical)
{
    uint64_t addr;
    if (!window || !physical)
        return CSM_ERR_ARG;
    if (dev > 31 || fn > 7 || (width != 1 && width != 2 && width != 4))
        return CSM_ERR_ARG;
    if ((offset % width) != 0 || offset > 4096u - width)
        return CSM_ERR_ARG;
    if (segment != window->segment || bus < window->first_bus || bus > window->last_bus)
        return CSM_ERR_RANGE;
    if ((window->base & 0xfffffull) != 0 || window->first_bus > window->last_bus)
        return CSM_ERR_MALFORMED;
    addr = window->base + ((uint64_t)bus << 20) + ((uint64_t)dev << 15) +
           ((uint64_t)fn << 12) + offset;
    *physical = addr;
    return CSM_OK;
}
