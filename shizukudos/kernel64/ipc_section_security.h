/* SPDX-License-Identifier: GPL-2.0-only
 * Section security descriptor capture and the supported DACL access checks.
 * Original implementation from Microsoft's SECURITY_DESCRIPTOR / ACL contracts.
 * Duplication control flow was checked against Wine db11d0fe server/handle.c
 * (duplicate_handle) and ReactOS f06eace8 ntoskrnl/ob/obhandle.c (ObDuplicateObject):
 * existing granted rights need no fresh DACL check; gaining rights does.
 * Chromium base/memory/platform_shared_memory_region_win.cc relies on exactly
 * that distinction when taking a read-only section protected by an empty DACL.
 * No upstream source code is copied here. Nonempty ACL/token evaluation and
 * implicit owner rights remain unsupported, rather than granted speculatively.
 */
#ifndef SHZ_IPC_SECTION_SECURITY_H
#define SHZ_IPC_SECTION_SECURITY_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define SHZ_SEC_MAX 65536u
#define SHZ_SEC_AV ((int32_t)0xc0000005)
#define SHZ_SEC_DENIED ((int32_t)0xc0000022)
#define SHZ_SEC_BAD_ACL ((int32_t)0xc0000077)
#define SHZ_SEC_BAD_SD ((int32_t)0xc0000079)
#define SHZ_SEC_UNSUPPORTED ((int32_t)0xc00000bb)
#define SHZ_SEC_DACL_PRESENT 0x0004u
#define SHZ_SEC_SACL_PRESENT 0x0010u
#define SHZ_SEC_RELATIVE 0x8000u

typedef int (*shz_sec_read)(void *, uint64_t, void *, size_t);

static uint16_t shz_sec_u16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t shz_sec_u32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t shz_sec_u64(const uint8_t *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void shz_sec_put32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }

static int shz_sec_acl_valid(const uint8_t *acl, uint32_t len)
{
    uint32_t pos = 8, i;
    if (len < 8 || (acl[0] != 2 && acl[0] != 4) || shz_sec_u16(acl + 2) != len) return 0;
    for (i = 0; i < shz_sec_u16(acl + 4); ++i) {
        uint32_t n;
        if (pos > len || len - pos < 4) return 0;
        n = shz_sec_u16(acl + pos + 2);
        if (n < 4 || (n & 3) || n > len - pos) return 0;
        pos += n;
    }
    return 1;
}

/* Capture once into owned self-relative storage. Every address is read through
 * the caller's checked reader; no direct user pointer dereference is involved.
 * Owner, group, SACL and DACL are all copied, preserving security queries.
 * out has SHZ_SEC_MAX bytes; *length is meaningful only on success. */
static int32_t shz_sec_capture(void *ctx, shz_sec_read read, uint64_t address,
                              uint8_t *out, uint32_t *length)
{
    uint8_t head[40], part[8];
    uint16_t control;
    uint32_t used = 20, i;
    if (!address) { *length = 0; return 0; }
    if (read(ctx, address, head, 4)) return SHZ_SEC_AV;
    if (head[0] != 1) return SHZ_SEC_BAD_SD;
    control = shz_sec_u16(head + 2);
    if (read(ctx, address, head, (control & SHZ_SEC_RELATIVE) ? 20 : 40)) return SHZ_SEC_AV;
    /* A concurrent mutation must not change the representation after sizing. */
    if (head[0] != 1 || shz_sec_u16(head + 2) != control) return SHZ_SEC_BAD_SD;
    memset(out, 0, 20);
    memcpy(out, head, 4);
    control |= SHZ_SEC_RELATIVE;
    memcpy(out + 2, &control, 2);
    for (i = 0; i < 4; ++i) {
        uint64_t ptr;
        uint32_t size;
        if (i == 2 && !(control & SHZ_SEC_SACL_PRESENT)) continue;
        if (i == 3 && !(control & SHZ_SEC_DACL_PRESENT)) continue;
        if (shz_sec_u16(head + 2) & SHZ_SEC_RELATIVE) {
            const uint32_t off = shz_sec_u32(head + 4 + 4 * i);
            if (!off) continue;
            if (off < 20 || (off & 3) || address > UINT64_MAX - off) return SHZ_SEC_BAD_SD;
            ptr = address + off;
        } else {
            ptr = shz_sec_u64(head + 8 + 8 * i);
            if (!ptr) continue;
        }
        if (ptr > UINT64_MAX - 8 || read(ctx, ptr, part, 8)) return SHZ_SEC_AV;
        if (i < 2) {
            if (part[0] != 1 || part[1] > 15) return SHZ_SEC_BAD_SD;
            size = 8u + 4u * part[1];
        } else {
            size = shz_sec_u16(part + 2);
            if (size < 8 || (size & 3) || (part[0] != 2 && part[0] != 4)) return SHZ_SEC_BAD_ACL;
        }
        if (size > SHZ_SEC_MAX - used || ptr > UINT64_MAX - size) return SHZ_SEC_BAD_SD;
        if (read(ctx, ptr, out + used, size)) return SHZ_SEC_AV;
        if (i < 2) {
            if (out[used] != 1 || out[used + 1] != part[1]) return SHZ_SEC_BAD_SD;
        } else if (!shz_sec_acl_valid(out + used, size)) return SHZ_SEC_BAD_ACL;
        shz_sec_put32(out + 4 + 4 * i, used);
        used += size;
    }
    *length = used;
    return 0;
}

/* Generic section access mapping (SECTION_* plus standard rights). */
static uint32_t shz_sec_section_access(uint32_t a)
{
    uint32_t m = a & 0x0fffffffu;
    if (a & 0x80000000u) m |= 0x00020005u; /* READ_CONTROL | QUERY | MAP_READ */
    if (a & 0x40000000u) m |= 0x00020012u; /* READ_CONTROL | MAP_WRITE | EXTEND_SIZE */
    if (a & 0x20000000u) m |= 0x00020008u; /* READ_CONTROL | MAP_EXECUTE */
    if (a & 0x10000000u) m |= 0x000f001fu; /* SECTION_ALL_ACCESS */
    return m;
}

/* No/NULL DACL permits access. An empty DACL denies new section-specific
 * rights. A nonempty ACL needs a token-aware evaluator, which is not here yet.
 * Returning unsupported for that case avoids inventing permissions. The
 * caller holds its object-security lock while consulting sd. */
static int32_t shz_sec_section_check(const uint8_t *sd, uint32_t len,
                                    uint32_t granted, uint32_t desired)
{
    uint32_t off, n, extra = desired & ~granted;
    if (!extra) return 0;
    if (!sd) return len ? SHZ_SEC_BAD_SD : 0;
    if (len < 20 || sd[0] != 1 || !(shz_sec_u16(sd + 2) & SHZ_SEC_RELATIVE)) return SHZ_SEC_BAD_SD;
    /* A mandatory label in the SACL can deny access even with a NULL DACL.
     * Token/integrity evaluation is absent, so do not grant that expansion. */
    if (shz_sec_u16(sd + 2) & SHZ_SEC_SACL_PRESENT) {
        off = shz_sec_u32(sd + 12);
        if (off) {
            if (off < 20 || (off & 3) || off > len || len - off < 8) return SHZ_SEC_BAD_SD;
            n = shz_sec_u16(sd + off + 2);
            if (n > len - off || !shz_sec_acl_valid(sd + off, n)) return SHZ_SEC_BAD_ACL;
            if (shz_sec_u16(sd + off + 4)) return SHZ_SEC_UNSUPPORTED;
        }
    }
    if (!(shz_sec_u16(sd + 2) & SHZ_SEC_DACL_PRESENT)) return 0;
    off = shz_sec_u32(sd + 16);
    if (!off) return 0;
    if (off < 20 || (off & 3) || off > len || len - off < 8) return SHZ_SEC_BAD_SD;
    n = shz_sec_u16(sd + off + 2);
    if (n > len - off || !shz_sec_acl_valid(sd + off, n)) return SHZ_SEC_BAD_ACL;
    if (shz_sec_u16(sd + off + 4)) return SHZ_SEC_UNSUPPORTED;
    if (extra & 0x1fu) return SHZ_SEC_DENIED;
    /* Owner/privilege-based standard rights need the token-aware evaluator. */
    return SHZ_SEC_UNSUPPORTED;
}
#endif
