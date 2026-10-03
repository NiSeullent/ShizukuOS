/* Win98 providers for the ntdll calls libuv 1.52.1 resolves at startup.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * The NTSTATUS -> Win32 pairs are the documented public mappings (MS-ERREF /
 * winerror.h; cross-checked against the behavior ReactOS and Wine implement
 * for RtlNtStatusToDosError). No Microsoft source is used. Order matters: the
 * first entry for a Win32 value is the one lc_nt_status_from_win32 reports.
 */
#include "lc_ntdll.h"

typedef struct pair { uint32_t nt, win; } pair;
static const pair table[] = {
    { 0x00000103u, 997 }, { 0x00000102u, 258 }, { 0x00000080u, 735 }, { 0x000000C0u, 192 },
    { 0x40000000u, 183 }, { 0x80000005u, 234 }, { 0x80000006u, 18 }, { 0x8000001Au, 259 },
    { 0xC0000001u, 31 }, { 0xC0000010u, 1 }, { 0xC00000AFu, 1 }, { 0xC0000002u, 1 },
    { 0xC0000003u, 87 }, { 0xC0000004u, 24 }, { 0xC0000005u, 998 }, { 0xC0000008u, 6 },
    { 0xC0000024u, 6 }, { 0xC0000128u, 6 }, { 0xC000000Du, 87 }, { 0xC000000Eu, 2 },
    { 0xC000000Fu, 2 }, { 0xC0000034u, 2 }, { 0xC0000011u, 38 }, { 0xC0000017u, 8 },
    { 0xC0000018u, 487 }, { 0xC0000141u, 487 }, { 0xC0000022u, 5 }, { 0xC0000056u, 5 },
    { 0xC00000BAu, 5 }, { 0xC0000121u, 5 }, { 0xC00000CAu, 5 }, { 0xC0000023u, 122 },
    { 0xC0000033u, 123 }, { 0xC0000035u, 183 }, { 0xC000003Au, 3 }, { 0xC000003Bu, 161 },
    { 0xC0000043u, 32 }, { 0xC0000054u, 33 }, { 0xC0000055u, 33 }, { 0xC000002Au, 158 },
    { 0xC000007Fu, 112 }, { 0xC000009Au, 1450 }, { 0xC00000BBu, 50 }, { 0xC0000103u, 267 },
    { 0xC0000101u, 145 }, { 0xC000014Bu, 109 }, { 0xC00000B0u, 233 }, { 0xC00000AEu, 231 },
    { 0xC00000ACu, 231 }, { 0xC00000ABu, 231 }, { 0xC00000ADu, 230 }, { 0xC00000B1u, 232 },
    { 0xC0000120u, 995 }, { 0xC00000B5u, 121 }, { 0xC0000236u, 1225 }, { 0xC000020Du, 64 },
    { 0xC000020Cu, 64 }, { 0xC0000241u, 1236 }, { 0xC0000225u, 1168 }, { 0xC00000D4u, 17 },
    { 0xC00000E8u, 1784 }, { 0xC00000A2u, 19 }, { 0xC0000013u, 21 }, { 0xC00000A3u, 21 },
    { 0xC0000014u, 1785 }, { 0xC000011Fu, 4 }, { 0xC0000106u, 206 }, { 0xC0000095u, 534 },
    { 0xC0000061u, 1314 }, { 0xC00000C4u, 59 }, { 0xC000023Fu, 1234 }, { 0xC000023Du, 1232 },
    { 0xC000023Cu, 1231 }, { 0xC000020Au, 1227 }, { 0xC00000D0u, 71 }, { 0xC000007Bu, 193 },
    { 0xC000007Au, 127 }, { 0xC0000135u, 126 }, { 0xC00000BEu, 53 }, { 0xC00000CCu, 67 },
    { 0xC0000275u, 4390 }, { 0xC0000098u, 1006 }, { 0xC0000185u, 1117 }, { 0xC0000032u, 1393 },
    { 0xC0000102u, 1392 }, { 0xC0000012u, 34 }, { 0xC00000CBu, 66 }
};
#define TABLE_N (sizeof(table) / sizeof(table[0]))

uint32_t lc_nt_status_to_dos(uint32_t status)
{
    size_t i;
    if (status == 0) return 0;
    if ((status & 0xFFFF0000u) == 0xC0070000u || (status & 0xFFFF0000u) == 0x80070000u)
        return status & 0xFFFFu;
    for (i = 0; i < TABLE_N; i++)
        if (table[i].nt == status) return table[i].win;
    return LC_ERROR_MR_MID_NOT_FOUND;
}

uint32_t lc_nt_status_from_win32(uint32_t error)
{
    size_t i;
    if (error == 0) return LC_STATUS_SUCCESS;
    for (i = 0; i < TABLE_N; i++)
        if (table[i].win == error) return table[i].nt;
    return 0xC0070000u | (error & 0xFFFFu);
}

static void put32(unsigned char *b, size_t o, uint32_t v)
{
    b[o] = (unsigned char)v; b[o + 1] = (unsigned char)(v >> 8);
    b[o + 2] = (unsigned char)(v >> 16); b[o + 3] = (unsigned char)(v >> 24);
}
static void put64(unsigned char *b, size_t o, uint64_t v) { put32(b, o, (uint32_t)v); put32(b, o + 4, (uint32_t)(v >> 32)); }
static uint32_t get32(const unsigned char *b, size_t o)
{
    return (uint32_t)b[o] | (uint32_t)b[o + 1] << 8 | (uint32_t)b[o + 2] << 16 | (uint32_t)b[o + 3] << 24;
}
static uint64_t get64(const unsigned char *b, size_t o) { return get32(b, o) | (uint64_t)get32(b, o + 4) << 32; }

static uint32_t backend_status(const lc_nt_ops *ops)
{
    uint32_t e = ops->error(ops->opaque);
    return lc_nt_status_from_win32(e ? e : 31 /* ERROR_GEN_FAILURE */);
}

static int valid_ops(const lc_nt_ops *o)
{
    return o && o->file_info && o->seek && o->set_eof && o->set_times && o->process_ids && o->error;
}

/* Sector-granular estimate: Win98 has no handle-based allocation query. */
static uint64_t alloc_size(uint64_t size) { return (size + 511u) & ~(uint64_t)511u; }

static void fill_basic(unsigned char *b, const lc_nt_file_info *f)
{
    put64(b, 0, f->creation); put64(b, 8, f->access); put64(b, 16, f->write);
    put64(b, 24, f->write); /* no ChangeTime on FAT: last write */
    put32(b, 32, f->attributes); put32(b, 36, 0);
}
static void fill_standard(unsigned char *b, const lc_nt_file_info *f)
{
    put64(b, 0, alloc_size(f->size)); put64(b, 8, f->size); put32(b, 16, f->links);
    b[20] = 0; /* DeletePending: Win98 delete is immediate-on-close, never pending */
    b[21] = (f->attributes & 0x10u) ? 1 : 0; b[22] = b[23] = 0;
}

uint32_t lc_nt_query_information_file(const lc_nt_ops *ops, uintptr_t handle, void *buffer, uint32_t length,
                                      uint32_t cls, uint32_t *information)
{
    unsigned char *b = buffer;
    lc_nt_file_info f;
    uint64_t pos;
    uint32_t need, i;
    if (information) *information = 0;
    if (!valid_ops(ops) || !buffer || !information) return LC_STATUS_INVALID_PARAMETER;
    if (!handle || handle == (uintptr_t)-1) return LC_STATUS_INVALID_HANDLE;
    switch (cls) {
    case LC_FileBasicInformation: need = 40; break;
    case LC_FileStandardInformation: need = 24; break;
    case LC_FilePositionInformation: need = 8; break;
    case LC_FileAllInformation: need = 100; break; /* through NameLength */
    default: return LC_STATUS_NOT_IMPLEMENTED; /* Mode/Access/Name/... have no Win98 source */
    }
    if (length < need) return LC_STATUS_INFO_LENGTH_MISMATCH;
    if (cls == LC_FilePositionInformation) {
        if (!ops->seek(ops->opaque, handle, 0, LC_SEEK_CUR, &pos)) return backend_status(ops);
        put64(b, 0, pos);
        *information = 8;
        return LC_STATUS_SUCCESS;
    }
    if (!ops->file_info(ops->opaque, handle, &f)) return backend_status(ops);
    if (cls == LC_FileBasicInformation) fill_basic(b, &f);
    else if (cls == LC_FileStandardInformation) fill_standard(b, &f);
    else {
        if (!ops->seek(ops->opaque, handle, 0, LC_SEEK_CUR, &pos)) return backend_status(ops);
        for (i = 0; i < 100; i++) b[i] = 0;
        fill_basic(b, &f);
        fill_standard(b + 40, &f);
        put64(b, 64, f.index);
        /* EaInformation, AccessInformation, ModeInformation, AlignmentInformation
         * and the name are not obtainable from a Win98 handle: zero / empty name. */
        put64(b, 80, pos);
        put32(b, 96, 0);
    }
    *information = need;
    return LC_STATUS_SUCCESS;
}

static uint32_t restore_position(const lc_nt_ops *ops, uintptr_t handle, uint64_t pos)
{
    uint64_t now;
    return ops->seek(ops->opaque, handle, (int64_t)pos, LC_SEEK_SET, &now) ? LC_STATUS_SUCCESS : backend_status(ops);
}

uint32_t lc_nt_set_information_file(const lc_nt_ops *ops, uintptr_t handle, const void *buffer, uint32_t length,
                                    uint32_t cls, uint32_t *information)
{
    const unsigned char *b = buffer;
    lc_nt_file_info f;
    uint64_t pos, now, t[3];
    uint32_t attrs, st;
    if (information) *information = 0;
    if (!valid_ops(ops) || !buffer || !information) return LC_STATUS_INVALID_PARAMETER;
    if (!handle || handle == (uintptr_t)-1) return LC_STATUS_INVALID_HANDLE;
    switch (cls) {
    case LC_FileBasicInformation:
        if (length < 40) return LC_STATUS_INFO_LENGTH_MISMATCH;
        attrs = get32(b, 32);
        t[0] = get64(b, 0); t[1] = get64(b, 8); t[2] = get64(b, 16); /* 0 = leave unchanged */
        if (attrs) {
            /* Attributes cannot be set through a Win98 handle. Accept only a
             * request that changes nothing; refuse before touching the times. */
            if (!ops->file_info(ops->opaque, handle, &f)) return backend_status(ops);
            if ((attrs & 0x27u) != (f.attributes & 0x27u)) return LC_STATUS_NOT_IMPLEMENTED;
        }
        if (t[0] || t[1] || t[2]) {
            if (!ops->set_times(ops->opaque, handle, t[0] ? &t[0] : 0, t[1] ? &t[1] : 0, t[2] ? &t[2] : 0))
                return backend_status(ops);
        }
        *information = 0;
        return LC_STATUS_SUCCESS;
    case LC_FileEndOfFileInformation:
        if (length < 8) return LC_STATUS_INFO_LENGTH_MISMATCH;
        if (!ops->seek(ops->opaque, handle, 0, LC_SEEK_CUR, &pos)) return backend_status(ops);
        if (get64(b, 0) > 0x7FFFFFFFFFFFFFFFull) return LC_STATUS_INVALID_PARAMETER;
        if (!ops->seek(ops->opaque, handle, (int64_t)get64(b, 0), LC_SEEK_SET, &now)) {
            st = backend_status(ops);
            restore_position(ops, handle, pos);
            return st;
        }
        if (!ops->set_eof(ops->opaque, handle)) {
            st = backend_status(ops);
            restore_position(ops, handle, pos);
            return st;
        }
        return restore_position(ops, handle, pos); /* NT leaves the file pointer unchanged */
    case LC_FilePositionInformation:
        if (length < 8) return LC_STATUS_INFO_LENGTH_MISMATCH;
        if (get64(b, 0) > 0x7FFFFFFFFFFFFFFFull) return LC_STATUS_INVALID_PARAMETER;
        return ops->seek(ops->opaque, handle, (int64_t)get64(b, 0), LC_SEEK_SET, &now)
                   ? LC_STATUS_SUCCESS : backend_status(ops);
    default:
        /* Rename/Link/Disposition need path or delete-on-close handle semantics
         * that Win98 does not offer through a handle. */
        return LC_STATUS_NOT_IMPLEMENTED;
    }
}

uint32_t lc_nt_query_volume_information_file(const lc_nt_ops *ops, uintptr_t handle, void *buffer, uint32_t length,
                                             uint32_t cls, uint32_t *information)
{
    unsigned char *b = buffer;
    lc_nt_file_info f;
    uint32_t i;
    if (information) *information = 0;
    if (!valid_ops(ops) || !buffer || !information) return LC_STATUS_INVALID_PARAMETER;
    if (!handle || handle == (uintptr_t)-1) return LC_STATUS_INVALID_HANDLE;
    if (cls != LC_FileFsVolumeInformation) return LC_STATUS_NOT_IMPLEMENTED;
    if (length < 18) return LC_STATUS_INFO_LENGTH_MISMATCH;
    if (!ops->file_info(ops->opaque, handle, &f)) return backend_status(ops);
    for (i = 0; i < 18; i++) b[i] = 0;
    /* Serial comes from the handle (dwVolumeSerialNumber). Creation time and
     * label are not available by handle: reported as 0 / empty label. */
    put32(b, 8, f.volume_serial);
    *information = 18;
    return LC_STATUS_SUCCESS;
}

uint32_t lc_nt_query_information_process(const lc_nt_ops *ops, uintptr_t handle, void *buffer, uint32_t length,
                                         uint32_t cls, uint32_t *return_length)
{
    unsigned char *b = buffer;
    uint32_t pid = 0, parent = 0, i;
    if (return_length) *return_length = 0;
    if (!valid_ops(ops) || !buffer) return LC_STATUS_INVALID_PARAMETER;
    if (cls != LC_ProcessBasicInformation) return LC_STATUS_NOT_IMPLEMENTED;
    if (length < 24) return LC_STATUS_INFO_LENGTH_MISMATCH;
    if (!handle) return LC_STATUS_INVALID_HANDLE;
    if (!ops->process_ids(ops->opaque, handle, &pid, &parent)) return backend_status(ops);
    for (i = 0; i < 24; i++) b[i] = 0;
    put32(b, 0, 259); /* ExitStatus = STILL_ACTIVE: the process was just queried alive */
    put32(b, 16, pid);
    put32(b, 20, parent);
    /* PebBaseAddress, AffinityMask, BasePriority are not provided (0). */
    if (return_length) *return_length = 24;
    return LC_STATUS_SUCCESS;
}
