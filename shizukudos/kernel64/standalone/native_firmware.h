/* SPDX-License-Identifier: GPL-2.0-only
 * Private native Multiboot firmware ownership record. It supplements memholes;
 * it is not a Supervisor ABI and never grants page allocator eligibility.
 */
#ifndef SHZ_NATIVE_FIRMWARE_H
#define SHZ_NATIVE_FIRMWARE_H
#include <stdint.h>
#include "memholes.h"

#define SHZ_NATIVE_FIRMWARE_GPA 0x6800u
#define SHZ_NATIVE_FIRMWARE_MAGIC 0x46564e53u /* SNVF */
#define SHZ_NATIVE_FIRMWARE_VERSION 1u
#define SHZ_NATIVE_FIRMWARE_MULTIBOOT 1u
#define SHZ_NATIVE_FIRMWARE_RANGES 64u

typedef struct {
    uint64_t base, length;
    uint32_t type, reserved;
} shz_native_firmware_range_t;
typedef struct {
    uint32_t magic, version, bytes, count;
    uint32_t profile, check, reserved, reserved2;
    shz_native_firmware_range_t range[SHZ_NATIVE_FIRMWARE_RANGES];
} shz_native_firmware_t;
typedef int (*shz_native_firmware_read_fn)(void *, uint64_t, void *, uint32_t);

_Static_assert(sizeof(shz_native_firmware_range_t) == 24, "fixed firmware row layout");
_Static_assert(sizeof(shz_native_firmware_t) <= 0x800, "firmware record must end before bootinfo 0x7000");
_Static_assert(SHZ_MEMHOLES_GPA + sizeof(shz_memholes_t) <= SHZ_NATIVE_FIRMWARE_GPA,
               "firmware record must not overlap memholes");

static inline void shz_native_firmware_clear(shz_native_firmware_t *h)
{
    uint8_t *p = (uint8_t *)h;
    uint32_t i;
    for (i = 0; i < sizeof(*h); ++i) p[i] = 0;
}
static inline uint32_t shz_native_firmware_sum(const shz_native_firmware_t *h)
{
    uint32_t i, sum = h->magic + h->version + h->bytes + h->count + h->profile + h->reserved + h->reserved2;
    for (i = 0; i < h->count && i < SHZ_NATIVE_FIRMWARE_RANGES; ++i) {
        const shz_native_firmware_range_t *r = &h->range[i];
        sum += (uint32_t)r->base + (uint32_t)(r->base >> 32) + (uint32_t)r->length +
               (uint32_t)(r->length >> 32) + r->type + r->reserved;
    }
    return ~sum;
}
static inline int shz_native_firmware_valid(const shz_native_firmware_t *h, int native_multiboot)
{
    uint32_t i;
    if (!h || !native_multiboot || h->magic != SHZ_NATIVE_FIRMWARE_MAGIC ||
        h->version != SHZ_NATIVE_FIRMWARE_VERSION || h->bytes != sizeof(*h) ||
        h->profile != SHZ_NATIVE_FIRMWARE_MULTIBOOT || !h->count ||
        h->count > SHZ_NATIVE_FIRMWARE_RANGES || h->reserved || h->reserved2 ||
        h->check != shz_native_firmware_sum(h)) return 0;
    for (i = 0; i < h->count; ++i)
        if (h->range[i].reserved || h->range[i].length > UINT64_MAX - h->range[i].base) return 0;
    return 1;
}

/* Return 1 for a complete captured map, 0 for explicitly absent, -1 malformed.
 * The whole variable-length source is validated before any consumer can use it.
 * Count overflow clears every row; a hidden 65th reservation cannot authorize RAM.
 * source_limit bounds loader metadata reads, independently of the row addresses.
 */
static inline int shz_native_firmware_capture(shz_native_firmware_t *h, int present, uint64_t pa,
        uint32_t bytes, uint64_t source_limit, shz_native_firmware_read_fn read, void *ctx)
{
    uint32_t off = 0, count = 0;
    if (!h) return -1;
    shz_native_firmware_clear(h);
    if (!present) return 0;
    if (!read || !bytes || pa >= UINT64_C(0x100000000) ||
        bytes > UINT64_C(0xffffffff) - pa || pa >= source_limit || bytes > source_limit - pa) return -1;
    while (off < bytes) {
        uint32_t size;
        uint8_t payload[20];
        uint32_t i;
        shz_native_firmware_range_t *r;
        if (bytes - off < 4 || !read(ctx, pa + off, &size, 4) || size < 20 ||
            size > bytes - off - 4 || count == SHZ_NATIVE_FIRMWARE_RANGES ||
            !read(ctx, pa + off + 4, payload, sizeof(payload))) goto malformed;
        r = &h->range[count];
        /* Byte copies avoid alignment and strict-aliasing assumptions of packed E820 records. */
        for (i = 0; i < 8; ++i) ((uint8_t *)&r->base)[i] = payload[i];
        for (i = 0; i < 8; ++i) ((uint8_t *)&r->length)[i] = payload[8 + i];
        for (i = 0; i < 4; ++i) ((uint8_t *)&r->type)[i] = payload[16 + i];
        if (r->length > UINT64_MAX - r->base) goto malformed;
        ++count;
        off += size + 4; /* bounded by bytes - off above, so addition cannot wrap */
    }
    h->magic = SHZ_NATIVE_FIRMWARE_MAGIC;
    h->version = SHZ_NATIVE_FIRMWARE_VERSION;
    h->bytes = sizeof(*h);
    h->count = count;
    h->profile = SHZ_NATIVE_FIRMWARE_MULTIBOOT;
    h->check = shz_native_firmware_sum(h);
    return 1;
malformed:
    shz_native_firmware_clear(h);
    return -1;
}

static inline int shz_native_firmware_readable_type(uint32_t type)
{
    return type == 1 || type == 3 || type == 4;
}
/* Exact cover of the complete read, including unsorted adjacent/overlapping RAM.
 * Any overlapping denied firmware row wins, irrespective of source row order.
 */
static inline int shz_native_firmware_covers_types(const shz_native_firmware_t *h, uint64_t pa,
        uint32_t bytes, uint32_t type_mask)
{
    uint64_t end, cursor;
    uint32_t i;
    if (!bytes || bytes > UINT64_MAX - pa || !shz_native_firmware_valid(h, 1)) return 0;
    end = pa + bytes;
    for (i = 0; i < h->count; ++i) {
        const shz_native_firmware_range_t *r = &h->range[i];
        if (r->length && !(r->type < 32 && (type_mask & (1u << r->type))) && r->base < end &&
            pa < r->base + r->length) return 0;
    }
    cursor = pa;
    while (cursor < end) {
        uint64_t next = cursor;
        for (i = 0; i < h->count; ++i) {
            const shz_native_firmware_range_t *r = &h->range[i];
            if (r->type < 32 && (type_mask & (1u << r->type)) && r->base <= cursor &&
                r->base + r->length > next) next = r->base + r->length;
        }
        if (next == cursor) return 0;
        cursor = next;
    }
    return 1;
}
static inline int shz_native_firmware_covers(const shz_native_firmware_t *h, uint64_t pa, uint32_t bytes)
{ return shz_native_firmware_covers_types(h, pa, bytes, (1u << 1) | (1u << 3) | (1u << 4)); }
static inline int shz_native_firmware_ram_covers(const shz_native_firmware_t *h, uint64_t pa, uint32_t bytes)
{ return shz_native_firmware_covers_types(h, pa, bytes, 1u << 1); }
#endif
