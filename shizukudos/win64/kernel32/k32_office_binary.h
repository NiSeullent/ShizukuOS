/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded on-disk executable classification. Does not establish loadability.
 */
#ifndef SHZ_K32_OFFICE_BINARY_H
#define SHZ_K32_OFFICE_BINARY_H
#include <stddef.h>
#include <stdint.h>
typedef unsigned (*shz_binary_read_fn)(void *, uint64_t, void *, size_t);
struct shz_binary_reader { shz_binary_read_fn read; void *context; uint64_t length; };
struct shz_binary_result { unsigned type; int mz; };
static unsigned shz_binary_u16(const unsigned char *p) { return p[0] | ((unsigned)p[1] << 8); }
static uint32_t shz_binary_u32(const unsigned char *p)
{ return p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static unsigned shz_binary_read(const struct shz_binary_reader *r, uint64_t off, void *out, size_t n)
{
    if (off > r->length || n > r->length - off) return 193; /* ERROR_BAD_EXE_FORMAT */
    return r->read(r->context, off, out, n);
}
static unsigned shz_binary_classify(const struct shz_binary_reader *r, struct shz_binary_result *result)
{
    unsigned char dos[64], header[96], section[40];
    unsigned error, machine, characteristics, magic, optional, sections, i;
    uint64_t ext, table, header_end;
    uint32_t image_size, header_size;
    result->mz = 0;
    if (r->length < 2) return 193;
    error = shz_binary_read(r, 0, dos, r->length < sizeof dos ? (size_t)r->length : sizeof dos);
    if (error) return error;
    if (dos[0] != 'M' || dos[1] != 'Z') return 193;
    result->mz = 1;
    if (r->length < 28 || shz_binary_u16(dos + 8) < 2 ||
        (uint64_t)shz_binary_u16(dos + 8) * 16 > r->length) return 193;
    /* Old DOS headers lack an extended-header field. Invalid/out-of-file
     * extension offsets retain DOS classification, as the source references. */
    if (r->length < 64) { result->type = 1; return 0; }
    ext = shz_binary_u32(dos + 60);
    if (ext < 64 || ext > r->length || r->length - ext < 4) { result->type = 1; return 0; }
    error = shz_binary_read(r, ext, header, 4);
    if (error) return error;
    if (header[0] == 'N' && header[1] == 'E') {
        error = shz_binary_read(r, ext, header, 64);
        if (error) return error;
        if (shz_binary_u16(header + 12) & 0x8000) return 193; /* library, not application */
        switch (header[54]) {
        case 1: result->type = 5; return 0; /* explicit OS/2 16 */
        case 2: result->type = 2; return 0; /* explicit Windows 16 */
        case 5: result->type = 1; return 0; /* DOS extender */
        default: return 50; /* ambiguous old NE target requires module-table analysis */
        }
    }
    if (header[0] == 'L' && (header[1] == 'E' || header[1] == 'X')) return 50;
    if (header[0] != 'P' || header[1] != 'E' || header[2] || header[3]) { result->type = 1; return 0; }
    error = shz_binary_read(r, ext, header, 26);
    if (error) return error;
    machine = shz_binary_u16(header + 4); sections = shz_binary_u16(header + 6);
    optional = shz_binary_u16(header + 20); characteristics = shz_binary_u16(header + 22);
    magic = shz_binary_u16(header + 24);
    if (!(characteristics & 2) || (characteristics & 0x2000) || !sections) return 193;
    if ((magic == 0x10b && (machine == 0x14c || machine == 0x1c4) && optional >= 224) ||
        (magic == 0x20b && (machine == 0x8664 || machine == 0xaa64) && optional >= 240)) {
        error = shz_binary_read(r, ext + 24, header, 64);
        if (error) return error;
        image_size = shz_binary_u32(header + 56); header_size = shz_binary_u32(header + 60);
        table = ext + 24 + optional; header_end = table + (uint64_t)sections * 40;
        if (!image_size || header_size < header_end || header_size > r->length || header_size > image_size) return 193;
        for (i = 0; i < sections; ++i) {
            uint32_t raw_size, raw_offset, virtual_size, address;
            uint64_t extent;
            error = shz_binary_read(r, table + (uint64_t)i * 40, section, sizeof section);
            if (error) return error;
            virtual_size = shz_binary_u32(section + 8); address = shz_binary_u32(section + 12);
            raw_size = shz_binary_u32(section + 16); raw_offset = shz_binary_u32(section + 20);
            if (raw_size && (raw_offset > r->length || raw_size > r->length - raw_offset)) return 193;
            extent = virtual_size > raw_size ? virtual_size : raw_size;
            if (address > image_size || extent > image_size - address) return 193;
        }
        result->type = magic == 0x10b ? 0 : 6;
        return 0;
    }
    return 193;
}
#endif
