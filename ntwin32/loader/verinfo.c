/* SPDX-License-Identifier: GPL-2.0-only */
#include "verinfo.h"
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint32_t align4(uint32_t n) { return (n + 3u) & ~3u; }
static int rva_off(const uint8_t *image, uint32_t length, uint32_t rva, uint32_t *offset) {
    uint32_t pe, opt, nsec, i, table;
    if (length < 0x40) return 0;
    pe = rd32(image + 0x3c);
    if (pe + 24 + 4 > length) return 0;
    opt = pe + 24;
    nsec = rd16(image + pe + 6);
    table = opt + rd16(image + pe + 20);
    for (i = 0; i < nsec; ++i) {
        uint32_t ent = table + i * 40u;
        uint32_t virt, raw, span, ptr;
        if (ent + 40 > length) return 0;
        virt = rd32(image + ent + 12);
        span = rd32(image + ent + 8);
        raw = rd32(image + ent + 16);
        ptr = rd32(image + ent + 20);
        if (raw > span) span = raw;
        if (rva >= virt && rva - virt < span) {
            uint32_t file = ptr + (rva - virt);
            if (file >= length) return 0;
            *offset = file;
            return 1;
        }
    }
    return 0;
}
static int find_version(const uint8_t *image, uint32_t length, uint32_t dir_rva, uint32_t *data_rva, uint32_t *data_size) {
    uint32_t root, named, ids, i, type_off = 0, name_off = 0, lang_off = 0;
    if (!rva_off(image, length, dir_rva, &root) || root + 16 > length) return 0;
    named = rd16(image + root + 12);
    ids = rd16(image + root + 14);
    for (i = 0; i < named + ids; ++i) {
        uint32_t ent = root + 16 + i * 8u, name, offset;
        if (ent + 8 > length) return 0;
        name = rd32(image + ent);
        offset = rd32(image + ent + 4);
        if (i >= named && name == 16u && (offset & 0x80000000u)) { type_off = offset & 0x7fffffffu; break; }
    }
    if (!type_off) return 0;
    if (!rva_off(image, length, dir_rva + type_off, &root) || root + 16 > length) return 0;
    named = rd16(image + root + 12);
    ids = rd16(image + root + 14);
    if (!ids && !named) return 0;
    {
        uint32_t ent = root + 16, offset = rd32(image + ent + 4);
        if (!(offset & 0x80000000u)) return 0;
        name_off = offset & 0x7fffffffu;
    }
    if (!rva_off(image, length, dir_rva + name_off, &root) || root + 16 > length) return 0;
    if (!rd16(image + root + 12) && !rd16(image + root + 14)) return 0;
    {
        uint32_t ent = root + 16, offset = rd32(image + ent + 4);
        if (offset & 0x80000000u) return 0;
        lang_off = offset;
    }
    if (!rva_off(image, length, dir_rva + lang_off, &root) || root + 16 > length) return 0;
    *data_rva = rd32(image + root);
    *data_size = rd32(image + root + 4);
    return *data_size >= 6;
}
int ntw_ver_find(const uint8_t *image, uint32_t length, uint32_t *offset, uint32_t *size, uint32_t *error) {
    uint32_t pe, opt, magic, dir, dir_size, data_rva = 0, data_size = 0, file;
    if (error) *error = 0;
    if (!image || !offset || !size || length < 0x40 || image[0] != 'M' || image[1] != 'Z') {
        if (error) *error = NTW_VER_NOT_FOUND;
        return 0;
    }
    pe = rd32(image + 0x3c);
    if (pe + 248 > length) { if (error) *error = NTW_VER_NOT_FOUND; return 0; }
    opt = pe + 24;
    magic = rd16(image + opt);
    if (magic != 0x10bu) { if (error) *error = NTW_VER_NOT_FOUND; return 0; }
    dir = rd32(image + opt + 96 + 16);
    dir_size = rd32(image + opt + 96 + 20);
    if (!dir || !dir_size || !find_version(image, length, dir, &data_rva, &data_size)) {
        if (error) *error = NTW_VER_NOT_FOUND;
        return 0;
    }
    if (!rva_off(image, length, data_rva, &file) || file + data_size > length) {
        if (error) *error = NTW_VER_NOT_FOUND;
        return 0;
    }
    if (rd16(image + file) < 6 || rd16(image + file) > data_size) {
        if (error) *error = NTW_VER_NOT_FOUND;
        return 0;
    }
    *offset = file;
    *size = rd16(image + file);
    return 1;
}
static int key_match(const uint8_t *block, uint32_t at, uint32_t end, const uint16_t *want, uint32_t *after) {
    uint32_t i = 0;
    while (want[i]) {
        if (at + 2 > end || rd16(block + at) != want[i]) return 0;
        at += 2;
        i++;
    }
    if (at + 2 > end || rd16(block + at) != 0) return 0;
    *after = at + 2;
    return 1;
}
static int node_bounds(const uint8_t *block, uint32_t block_size, uint32_t at,
                       uint32_t *length, uint32_t *value, uint32_t *value_bytes, uint32_t *child) {
    uint16_t words, type;
    uint32_t key_end;
    if (at + 6 > block_size) return 0;
    *length = rd16(block + at);
    words = rd16(block + at + 2);
    type = rd16(block + at + 4);
    if (*length < 6 || at + *length > block_size) return 0;
    key_end = at + 6;
    while (key_end + 2 <= at + *length && rd16(block + key_end) != 0) key_end += 2;
    if (key_end + 2 > at + *length) return 0;
    key_end += 2;
    *value = align4(key_end);
    *value_bytes = type ? (uint32_t)words * 2u : words;
    if (*value > at + *length || *value_bytes > at + *length - *value) return 0;
    *child = align4(*value + *value_bytes);
    if (*child > at + *length) *child = at + *length;
    return 1;
}
static const uint16_t *component(const uint16_t *path, uint16_t *out, uint32_t cap, const uint16_t **next) {
    uint32_t n = 0;
    while (*path == '\\') path++;
    if (!*path) { *next = path; out[0] = 0; return 0; }
    while (*path && *path != '\\' && n + 1 < cap) out[n++] = *path++;
    out[n] = 0;
    *next = path;
    return out;
}
int ntw_ver_query(const uint8_t *block, uint32_t block_size, const uint16_t *path,
                  const void **data, uint32_t *data_bytes, uint32_t *error) {
    uint32_t at = 0, length = 0, value = 0, value_bytes = 0, child = 0;
    if (error) *error = 0;
    if (!block || !path || !data || !data_bytes ||
        !node_bounds(block, block_size, 0, &length, &value, &value_bytes, &child)) {
        if (error) *error = NTW_VER_NOT_FOUND;
        return 0;
    }
    while (*path == '\\') path++;
    while (*path) {
        uint16_t part[64];
        const uint16_t *rest = path;
        uint32_t scan, parent_end, found = 0, ignored = 0;
        if (!component(path, part, 64, &rest) || !part[0]) break;
        path = rest;
        parent_end = at + length;
        scan = child;
        while (scan + 6 <= parent_end) {
            uint32_t clen, cval, cvbytes, cchild, match_end;
            if (!node_bounds(block, parent_end, scan, &clen, &cval, &cvbytes, &cchild)) break;
            if (key_match(block, scan + 6, scan + clen, part, &match_end)) {
                at = scan;
                length = clen;
                value = cval;
                value_bytes = cvbytes;
                child = cchild;
                found = 1;
                break;
            }
            if (!clen) break;
            scan += clen;
        }
        (void)ignored;
        if (!found) { if (error) *error = NTW_VER_NOT_FOUND; return 0; }
        while (*path == '\\') path++;
    }
    if (!value_bytes) { if (error) *error = NTW_VER_NOT_FOUND; return 0; }
    *data = block + value;
    *data_bytes = value_bytes;
    return 1;
}
