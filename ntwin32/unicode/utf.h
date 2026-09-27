/* SPDX-License-Identifier: GPL-2.0-only
 * Original NTWin32Wrapper9x UTF conversion core; Win32 adapter in ../runtime.c.
 */
#ifndef NTWU_UTF_H
#define NTWU_UTF_H
#include <stddef.h>
#include <stdint.h>

#define NTWU_STRICT UINT32_C(1)
enum ntwu_status {
    NTWU_OK = 0,
    NTWU_INVALID = -1,
    NTWU_INVALID_FLAGS = -2,
    NTWU_MALFORMED = -3,
    NTWU_INSUFFICIENT = -4,
    NTWU_OVERLAP = -5,
    NTWU_OVERFLOW = -6
};

/* Explicit lengths count source/destination code units: bytes for UTF-8,
 * uint16_t elements for UTF-16. Embedded NUL is data; no terminator is added.
 * UTF-16 is in native-endian uint16_t values, not a serialized byte stream.
 *
 * flags=0 substitutes U+FFFD per maximal ill-formed subpart; NTWU_STRICT rejects
 * malformed input. Other flags are invalid. Capacity zero queries the size and
 * ignores destination. Empty input is valid, and may have a NULL source.
 *
 * required is mandatory and must not overlap source or active destination.
 * It receives the complete required length on OK or INSUFFICIENT; all other
 * errors leave it unchanged. The destination is unchanged on every failure.
 * Source, output, and metadata storage must remain stable for both passes;
 * no concurrent mutation or overlapping source/output storage is allowed.
 * All declared nonempty address ranges must designate valid accessible memory.
 */
int ntwu_utf8_to_utf16(const uint8_t *source, size_t source_bytes,
                       uint16_t *destination, size_t destination_units,
                       uint32_t flags, size_t *required);
int ntwu_utf16_to_utf8(const uint16_t *source, size_t source_units,
                       uint8_t *destination, size_t destination_bytes,
                       uint32_t flags, size_t *required);

#endif
