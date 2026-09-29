/* SPDX-License-Identifier: GPL-2.0-only
 * Original PE32 placement. Subsystem version bytes are copied, never rewritten.
 * Relocation behavior follows the PE/COFF HIGHLOW contract used by the pinned
 * ReactOS loader (LdrRelocateImage) and was checked against chrome.exe, which
 * contains only ABSOLUTE and HIGHLOW entries. No upstream body is copied.
 */
#include "map.h"
static uint16_t ru16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t ru32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void wu32(uint8_t *p, uint32_t value) {
    p[0] = (uint8_t)value; p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16); p[3] = (uint8_t)(value >> 24);
}
static int in_file(uint32_t off, uint32_t len, uint32_t file_len) {
    return len <= file_len && off <= file_len - len;
}
static uint32_t alignment_of(uint32_t characteristics) {
    uint32_t nibble = (characteristics >> 20) & 0xFu;
    if (characteristics & ~0x00F00000u) return 0;
    if (!nibble) return 1;
    if (nibble > 13) return 0;
    return 1u << (nibble - 1);
}
int ntw_place_pe32(const uint8_t *file, uint32_t file_len, uint8_t *image,
                   uint32_t image_cap, uint32_t actual_base, ntw_placed *out) {
    uint32_t pe, opt, image_size, headers, sections, i, preferred, delta, decode;
    uint16_t major, minor;
    if (!file || !image || !out || file_len < 0x40 || file[0] != 'M' || file[1] != 'Z')
        return NTW_MAP_INVALID;
    pe = ru32(file + 0x3c);
    if (!in_file(pe, 24, file_len) || ru32(file + pe) != 0x00004550u) return NTW_MAP_INVALID;
    if (ru16(file + pe + 4) != 0x14c) return NTW_MAP_INVALID;
    opt = pe + 24;
    if (ru16(file + pe + 20) < 96 || !in_file(opt, ru16(file + pe + 20), file_len))
        return NTW_MAP_INVALID;
    if (ru16(file + opt) != 0x10b) return NTW_MAP_INVALID;
    image_size = ru32(file + opt + 56);
    headers = ru32(file + opt + 60);
    if (!image_size || image_size > image_cap || headers > file_len || headers > image_size)
        return NTW_MAP_LIMIT;
    for (i = 0; i < image_size; ++i) image[i] = 0;
    for (i = 0; i < headers; ++i) image[i] = file[i];
    sections = ru16(file + pe + 6);
    if (sections > 96) return NTW_MAP_INVALID;
    if (!in_file(opt + ru16(file + pe + 20), sections * 40, file_len)) return NTW_MAP_INVALID;
    for (i = 0; i < sections; ++i) {
        const uint8_t *section = file + opt + ru16(file + pe + 20) + i * 40;
        uint32_t virtual = ru32(section + 12), raw_size = ru32(section + 16);
        uint32_t raw = ru32(section + 20), span = ru32(section + 8), copy, n;
        if (raw_size > span) raw_size = span;
        if (!raw_size) continue;
        if (virtual > image_size || raw_size > image_size - virtual) return NTW_MAP_INVALID;
        if (!in_file(raw, raw_size, file_len)) return NTW_MAP_INVALID;
        copy = raw_size;
        for (n = 0; n < copy; ++n) image[virtual + n] = file[raw + n];
    }
    preferred = ru32(file + opt + 28);
    major = ru16(file + opt + 48);
    minor = ru16(file + opt + 50);
    if (ru16(image + opt + 48) != major || ru16(image + opt + 50) != minor)
        return NTW_MAP_INVALID;
    delta = 0;
    out->relocations_applied = 0;
    if (actual_base && actual_base != preferred) {
        uint32_t rva = ru32(image + opt + 96 + 5 * 8);
        uint32_t size = ru32(image + opt + 96 + 5 * 8 + 4);
        uint32_t cursor;
        if (rva && size) {
        if (rva > image_size || size > image_size - rva) return NTW_MAP_INVALID;
        delta = actual_base - preferred;
        cursor = rva;
        while (cursor + 8 <= rva + size) {
            uint32_t page = ru32(image + cursor), block = ru32(image + cursor + 4), slot;
            if (block < 8 || cursor + block > rva + size) return NTW_MAP_INVALID;
            for (slot = cursor + 8; slot + 2 <= cursor + block; slot += 2) {
                uint16_t entry = ru16(image + slot);
                uint32_t kind = entry >> 12, target = page + (entry & 0xfff);
                if (kind == 0) continue;
                if (kind != 3) return NTW_MAP_RELOC;
                if (target + 4 > image_size) return NTW_MAP_INVALID;
                wu32(image + target, ru32(image + target) + delta);
            }
            cursor += block;
        }
        out->relocations_applied = 1;
        }
    }
    decode = out->relocations_applied ? actual_base : preferred;
    out->preferred_base = preferred;
    out->actual_base = decode;
    out->size_of_image = image_size;
    out->entry_rva = ru32(image + opt + 16);
    out->subsystem_major = ru16(image + opt + 48);
    out->subsystem_minor = ru16(image + opt + 50);
    out->tls.present = 0;
    out->tls.callback_count = 0;
    {
        uint32_t rva = ru32(image + opt + 96 + 9 * 8);
        uint32_t size = ru32(image + opt + 96 + 9 * 8 + 4);
        uint32_t start, end, index, callbacks, n;
        if (rva || size) {
            if (size < 24 || rva > image_size || size > image_size - rva) return NTW_MAP_INVALID;
            start = ru32(image + rva);
            end = ru32(image + rva + 4);
            index = ru32(image + rva + 8);
            callbacks = ru32(image + rva + 12);
            out->tls.zero_fill = ru32(image + rva + 16);
            out->tls.characteristics = ru32(image + rva + 20);
            out->tls.alignment = alignment_of(out->tls.characteristics);
            if (!out->tls.alignment || end < start) return NTW_MAP_INVALID;
            out->tls.raw_bytes = end - start;
            if (out->tls.raw_bytes) {
                if (start < decode || start - decode > image_size ||
                    out->tls.raw_bytes > image_size - (start - decode))
                    return NTW_MAP_INVALID;
                out->tls.raw = image + (start - decode);
            } else out->tls.raw = 0;
            if (index < decode || index - decode + 4 > image_size) return NTW_MAP_INVALID;
            out->tls.index_slot = (uint32_t *)(void *)(image + (index - decode));
            if (callbacks) {
                uint32_t slot = callbacks;
                for (n = 0; n < 32; ++n) {
                    uint32_t fn;
                    if (slot < decode || slot - decode + 4 > image_size) return NTW_MAP_INVALID;
                    fn = ru32(image + (slot - decode));
                    if (!fn) break;
                    out->tls.callback_vas[n] = fn;
                    slot += 4;
                }
                if (n == 32 && ru32(image + (slot - decode))) return NTW_MAP_LIMIT;
                out->tls.callback_count = n;
            }
            out->tls.present = 1;
        }
    }
    return NTW_MAP_OK;
}
int ntw_rva_span(const uint8_t *file, uint32_t file_len, uint32_t rva, uint32_t length, uint32_t *offset) {
    uint32_t pe, opt, sections, headers, i;
    if (!file || !offset || !in_file(0x3c, 4, file_len)) return NTW_MAP_INVALID;
    pe = ru32(file + 0x3c);
    if (!in_file(pe, 24, file_len)) return NTW_MAP_INVALID;
    opt = pe + 24;
    headers = ru32(file + opt + 60);
    sections = ru16(file + pe + 6);
    if (rva < headers && length <= headers - rva) { *offset = rva; return NTW_MAP_OK; }
    for (i = 0; i < sections; ++i) {
        const uint8_t *section = file + opt + ru16(file + pe + 20) + i * 40;
        uint32_t virtual = ru32(section + 12), raw_size = ru32(section + 16), raw = ru32(section + 20);
        if (!in_file((uint32_t)(section - file), 40, file_len)) return NTW_MAP_INVALID;
        if (raw_size && virtual <= rva && rva + length <= virtual + raw_size && in_file(raw + (rva - virtual), length, file_len)) {
            *offset = raw + (rva - virtual);
            return NTW_MAP_OK;
        }
    }
    return NTW_MAP_INVALID;
}
