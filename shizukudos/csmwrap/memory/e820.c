/* SPDX-License-Identifier: GPL-2.0-only */
#include "e820.h"
#include "regs.h"
#include <string.h>

_Static_assert(sizeof(csm_uefi_memory) == 40, "UEFI descriptor prefix");
_Static_assert(sizeof(csm_e820_entry) == 24, "E820 entry layout");

#define CSM_E820_LIMIT 128

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int classify(uint32_t efi_type, uint32_t *e820_type)
{
    switch (efi_type) {
    case CSM_EFI_LOADER_CODE:
    case CSM_EFI_LOADER_DATA:
    case CSM_EFI_BOOT_CODE:
    case CSM_EFI_BOOT_DATA:
    case CSM_EFI_CONVENTIONAL:
        *e820_type = CSM_E820_USABLE;
        return 1;
    case CSM_EFI_ACPI_RECLAIM:
        *e820_type = CSM_E820_ACPI;
        return 1;
    case CSM_EFI_ACPI_NVS:
        *e820_type = CSM_E820_NVS;
        return 1;
    case CSM_EFI_UNUSABLE:
        *e820_type = CSM_E820_UNUSABLE;
        return 1;
    case CSM_EFI_MMIO:
    case CSM_EFI_MMIO_PORT:
        return 0;
    default:
        *e820_type = CSM_E820_RESERVED;
        return 1;
    }
}

static int push_piece(csm_e820_entry *scratch, unsigned *n, uint64_t base, uint64_t length,
                      uint32_t type)
{
    if (!length)
        return CSM_OK;
    if (*n >= CSM_E820_LIMIT * 2)
        return CSM_ERR_NOSPACE;
    scratch[*n].base = base;
    scratch[*n].length = length;
    scratch[*n].type = type;
    scratch[*n].attributes = 1;
    *n += 1;
    return CSM_OK;
}

static int carve(csm_e820_entry *scratch, unsigned *n, uint64_t base, uint64_t length,
                 uint32_t type, const csm_range *cut)
{
    uint64_t end, cut_end;
    if (!cut || !cut->size)
        return push_piece(scratch, n, base, length, type);
    if (cut->size > UINT64_MAX - cut->base)
        return CSM_ERR_MALFORMED;
    end = base + length;
    cut_end = cut->base + cut->size;
    if (end <= cut->base || cut_end <= base)
        return push_piece(scratch, n, base, length, type);
    if (base < cut->base) {
        int st = push_piece(scratch, n, base, cut->base - base, type);
        if (st)
            return st;
    }
    if (cut_end < end)
        return push_piece(scratch, n, cut_end, end - cut_end, type);
    return CSM_OK;
}

static void sort_entries(csm_e820_entry *scratch, unsigned n)
{
    unsigned i;
    for (i = 1; i < n; ++i) {
        csm_e820_entry key = scratch[i];
        unsigned j = i;
        while (j > 0 && (scratch[j - 1].base > key.base ||
                         (scratch[j - 1].base == key.base && scratch[j - 1].type > key.type))) {
            scratch[j] = scratch[j - 1];
            --j;
        }
        scratch[j] = key;
    }
}

int csm_uefi_to_e820(const void *descriptors, size_t count, size_t descriptor_size,
                     const csm_range *framebuffer, csm_e820_entry *out, size_t capacity,
                     size_t *written)
{
    const uint8_t *base = (const uint8_t *)descriptors;
    csm_e820_entry scratch[CSM_E820_LIMIT * 2];
    csm_e820_entry merged[CSM_E820_LIMIT * 2];
    unsigned n = 0, w = 0, i;
    size_t d;
    if (!written)
        return CSM_ERR_ARG;
    *written = 0;
    if (count && !descriptors)
        return CSM_ERR_ARG;
    if (descriptor_size < sizeof(csm_uefi_memory) || (descriptor_size & 7) || count > CSM_E820_LIMIT)
        return CSM_ERR_ARG;
    if (count && descriptor_size > (SIZE_MAX / count))
        return CSM_ERR_MALFORMED;
    for (d = 0; d < count; ++d) {
        const uint8_t *p = base + d * descriptor_size;
        uint32_t efi_type = rd32(p);
        uint32_t e820_type = 0;
        uint64_t phys = rd64(p + 8);
        uint64_t pages = rd64(p + 24);
        uint64_t bytes;
        int st;
        if ((phys & 4095ull) || !pages)
            return CSM_ERR_MALFORMED;
        if (pages > (UINT64_MAX - phys) / 4096ull)
            return CSM_ERR_MALFORMED;
        bytes = pages * 4096ull;
        if (!classify(efi_type, &e820_type))
            continue;
        st = carve(scratch, &n, phys, bytes, e820_type, framebuffer);
        if (st)
            return st;
    }
    sort_entries(scratch, n);
    for (i = 0; i < n;) {
        uint64_t start = scratch[i].base;
        uint64_t end = start + scratch[i].length;
        uint32_t type = scratch[i].type;
        unsigned j = i + 1;
        while (j < n) {
            uint64_t jend;
            if (scratch[j].type == type && scratch[j].base <= end) {
                jend = scratch[j].base + scratch[j].length;
                if (jend > end)
                    end = jend;
                ++j;
                continue;
            }
            if (scratch[j].type != type && scratch[j].base < end)
                return CSM_ERR_MALFORMED;
            break;
        }
        if (w >= (unsigned)(sizeof merged / sizeof merged[0]))
            return CSM_ERR_NOSPACE;
        merged[w].base = start;
        merged[w].length = end - start;
        merged[w].type = type;
        merged[w].attributes = 1;
        ++w;
        i = j;
    }
    *written = w;
    if (w > capacity || (!out && w))
        return CSM_ERR_NOSPACE;
    if (w && out)
        memcpy(out, merged, (size_t)w * sizeof merged[0]);
    return CSM_OK;
}

uint16_t csm_e820_conventional_kb(const csm_e820_entry *map, size_t count, int *found)
{
    size_t i;
    if (found)
        *found = 0;
    if (!map || !count)
        return 639;
    for (i = 0; i < count; ++i) {
        uint64_t end;
        if (map[i].type != CSM_E820_USABLE || map[i].base != 0 || !map[i].length)
            continue;
        end = map[i].length;
        if (end > 0xA0000ull)
            end = 0xA0000ull;
        if (found)
            *found = 1;
        return (uint16_t)(end >> 10);
    }
    return 0;
}

uint16_t csm_e820_extended_kb(const csm_e820_entry *map, size_t count, int *present)
{
    size_t i;
    if (present)
        *present = 0;
    if (!map)
        return 0;
    for (i = 0; i < count; ++i) {
        uint64_t kb;
        if (map[i].base != 0x100000ull || map[i].type != CSM_E820_USABLE || !map[i].length)
            continue;
        if (present)
            *present = 1;
        kb = map[i].length >> 10;
        if (kb > 0xFC00ull)
            kb = 0xFC00ull;
        return (uint16_t)kb;
    }
    return 0;
}
