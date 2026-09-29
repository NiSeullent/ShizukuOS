/* SPDX-License-Identifier: GPL-2.0-only
 * Place a PE32 into a caller buffer without rewriting its subsystem version.
 * HIGHLOW relocations are applied only when the actual base differs from the
 * preferred base and a relocation directory exists.
 */
#ifndef NTW_MAP_H
#define NTW_MAP_H
#include <stddef.h>
#include <stdint.h>
enum ntw_map_status { NTW_MAP_OK = 0, NTW_MAP_INVALID = -1, NTW_MAP_LIMIT = -2,
    NTW_MAP_RELOC = -3 };
typedef struct ntw_tls_view {
    int present;
    const uint8_t *raw;
    uint32_t raw_bytes, zero_fill, characteristics, alignment;
    uint32_t *index_slot;
    uint32_t callback_vas[32];
    uint32_t callback_count;
} ntw_tls_view;
typedef struct ntw_placed {
    uint32_t preferred_base, actual_base, size_of_image, entry_rva;
    uint16_t subsystem_major, subsystem_minor;
    int relocations_applied;
    ntw_tls_view tls;
} ntw_placed;
int ntw_place_pe32(const uint8_t *file, uint32_t file_len, uint8_t *image,
                   uint32_t image_cap, uint32_t actual_base, ntw_placed *out);
int ntw_rva_span(const uint8_t *file, uint32_t file_len, uint32_t rva, uint32_t length, uint32_t *offset);
#endif
