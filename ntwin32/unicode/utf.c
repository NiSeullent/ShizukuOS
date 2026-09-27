/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded UTF decoders/encoders. See README.md for provenance.
 */
#include "utf.h"

typedef struct decoded {
    uint32_t scalar;
    size_t consumed;
    int valid;
} decoded;

static int extent(const void *pointer, size_t units, size_t unit_bytes,
                   size_t alignment, size_t *bytes)
{
    if (units > SIZE_MAX / unit_bytes) return NTWU_OVERFLOW;
    *bytes = units * unit_bytes;
    if (units == 0) return NTWU_OK;
    if (pointer == NULL || (uintptr_t)pointer % alignment != 0) return NTWU_INVALID;
    if (*bytes > UINTPTR_MAX - (uintptr_t)pointer) return NTWU_OVERFLOW;
    return NTWU_OK;
}

static int overlaps(const void *a, size_t a_bytes, const void *b, size_t b_bytes)
{
    if (a_bytes == 0 || b_bytes == 0) return 0;
    return (uintptr_t)a < (uintptr_t)b + b_bytes &&
           (uintptr_t)b < (uintptr_t)a + a_bytes;
}

static int arguments(const void *source, size_t source_units, size_t source_unit_bytes,
                      const void *destination, size_t destination_units,
                      size_t destination_unit_bytes, uint32_t flags, size_t *required)
{
    size_t source_bytes, destination_bytes, metadata_bytes;
    int status;
    if ((flags & ~NTWU_STRICT) != 0) return NTWU_INVALID_FLAGS;
    status = extent(required, 1, sizeof(*required), _Alignof(size_t), &metadata_bytes);
    if (status != NTWU_OK) return status;
    status = extent(source, source_units, source_unit_bytes, source_unit_bytes, &source_bytes);
    if (status != NTWU_OK) return status;
    status = extent(destination, destination_units, destination_unit_bytes,
                     destination_unit_bytes, &destination_bytes);
    if (status != NTWU_OK) return status;
    if (overlaps(source, source_bytes, destination, destination_bytes) ||
        overlaps(required, metadata_bytes, source, source_bytes) ||
        overlaps(required, metadata_bytes, destination, destination_bytes))
        return NTWU_OVERLAP;
    return NTWU_OK;
}

static decoded decode_utf8(const uint8_t *source, size_t remaining)
{
    decoded result = { UINT32_C(0xfffd), 1, 0 };
    uint32_t scalar, lead = source[0];
    size_t needed, i;
    uint8_t second_min = 0x80, second_max = 0xbf;
    if (lead < 0x80) {
        result.scalar = lead;
        result.valid = 1;
        return result;
    }
    if (lead >= 0xc2 && lead <= 0xdf) {
        needed = 2;
        scalar = lead & 0x1f;
    } else if (lead >= 0xe0 && lead <= 0xef) {
        needed = 3;
        scalar = lead & 0x0f;
        if (lead == 0xe0) second_min = 0xa0;
        if (lead == 0xed) second_max = 0x9f;
    } else if (lead >= 0xf0 && lead <= 0xf4) {
        needed = 4;
        scalar = lead & 0x07;
        if (lead == 0xf0) second_min = 0x90;
        if (lead == 0xf4) second_max = 0x8f;
    } else return result;
    for (i = 1; i < needed; ++i) {
        uint8_t byte, minimum = i == 1 ? second_min : 0x80;
        uint8_t maximum = i == 1 ? second_max : 0xbf;
        if (i == remaining) return result;
        byte = source[i];
        if (byte < minimum || byte > maximum) return result;
        scalar = (scalar << 6) | (uint32_t)(byte & 0x3f);
        ++result.consumed;
    }
    result.scalar = scalar;
    result.valid = 1;
    return result;
}

static decoded decode_utf16(const uint16_t *source, size_t remaining)
{
    decoded result = { source[0], 1, 1 };
    uint32_t first = source[0];
    if (first >= 0xd800 && first <= 0xdfff) {
        if (first <= 0xdbff && remaining > 1 && source[1] >= 0xdc00 && source[1] <= 0xdfff) {
            result.scalar = UINT32_C(0x10000) + ((first - 0xd800) << 10) +
                             ((uint32_t)source[1] - 0xdc00);
            result.consumed = 2;
        } else {
            result.scalar = UINT32_C(0xfffd);
            result.valid = 0;
        }
    }
    return result;
}

static size_t utf8_width(uint32_t scalar)
{
    if (scalar <= 0x7f) return 1;
    if (scalar <= 0x7ff) return 2;
    if (scalar <= 0xffff) return 3;
    return 4;
}

static void encode_utf8(uint8_t *destination, uint32_t scalar, size_t width)
{
    if (width == 1) destination[0] = (uint8_t)scalar;
    else if (width == 2) {
        destination[0] = (uint8_t)(0xc0 | (scalar >> 6));
        destination[1] = (uint8_t)(0x80 | (scalar & 0x3f));
    } else if (width == 3) {
        destination[0] = (uint8_t)(0xe0 | (scalar >> 12));
        destination[1] = (uint8_t)(0x80 | ((scalar >> 6) & 0x3f));
        destination[2] = (uint8_t)(0x80 | (scalar & 0x3f));
    } else {
        destination[0] = (uint8_t)(0xf0 | (scalar >> 18));
        destination[1] = (uint8_t)(0x80 | ((scalar >> 12) & 0x3f));
        destination[2] = (uint8_t)(0x80 | ((scalar >> 6) & 0x3f));
        destination[3] = (uint8_t)(0x80 | (scalar & 0x3f));
    }
}

int ntwu_utf8_to_utf16(const uint8_t *source, size_t source_bytes,
                       uint16_t *destination, size_t destination_units,
                       uint32_t flags, size_t *required)
{
    size_t read = 0, count = 0;
    int status = arguments(source, source_bytes, 1, destination, destination_units,
                           sizeof(*destination), flags, required);
    if (status != NTWU_OK) return status;
    while (read < source_bytes) {
        decoded item = decode_utf8(source + read, source_bytes - read);
        size_t width = item.scalar > 0xffff ? 2u : 1u;
        if (!item.valid && (flags & NTWU_STRICT) != 0) return NTWU_MALFORMED;
        if (count > SIZE_MAX - width) return NTWU_OVERFLOW;
        count += width;
        if (count > SIZE_MAX / sizeof(*destination)) return NTWU_OVERFLOW;
        read += item.consumed;
    }
    if (destination_units == 0 || count > destination_units) {
        *required = count;
        return destination_units == 0 ? NTWU_OK : NTWU_INSUFFICIENT;
    }
    read = 0;
    count = 0;
    while (read < source_bytes) {
        decoded item = decode_utf8(source + read, source_bytes - read);
        if (item.scalar <= 0xffff) destination[count++] = (uint16_t)item.scalar;
        else {
            uint32_t offset = item.scalar - 0x10000;
            destination[count++] = (uint16_t)(0xd800 + (offset >> 10));
            destination[count++] = (uint16_t)(0xdc00 + (offset & 0x3ff));
        }
        read += item.consumed;
    }
    *required = count;
    return NTWU_OK;
}

int ntwu_utf16_to_utf8(const uint16_t *source, size_t source_units,
                       uint8_t *destination, size_t destination_bytes,
                       uint32_t flags, size_t *required)
{
    size_t read = 0, count = 0;
    int status = arguments(source, source_units, sizeof(*source), destination,
                           destination_bytes, 1, flags, required);
    if (status != NTWU_OK) return status;
    while (read < source_units) {
        decoded item = decode_utf16(source + read, source_units - read);
        size_t width = utf8_width(item.scalar);
        if (!item.valid && (flags & NTWU_STRICT) != 0) return NTWU_MALFORMED;
        if (count > SIZE_MAX - width) return NTWU_OVERFLOW;
        count += width;
        read += item.consumed;
    }
    if (destination_bytes == 0 || count > destination_bytes) {
        *required = count;
        return destination_bytes == 0 ? NTWU_OK : NTWU_INSUFFICIENT;
    }
    read = 0;
    count = 0;
    while (read < source_units) {
        decoded item = decode_utf16(source + read, source_units - read);
        size_t width = utf8_width(item.scalar);
        encode_utf8(destination + count, item.scalar, width);
        count += width;
        read += item.consumed;
    }
    *required = count;
    return NTWU_OK;
}
