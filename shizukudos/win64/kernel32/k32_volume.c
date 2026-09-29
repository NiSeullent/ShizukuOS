/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: drives and volumes, path names of files (long/short/final/temporary) and the temporary directory.
 *
 * There is exactly one volume, C:, the RAM file system. Its NT device name is \Device\HarddiskVolume1 (what QueryDosDevice("C:") returns and
 * what NtCreateFile accepts as a path prefix), its volume GUID path is the constant below, and its properties (label, serial number, file
 * system name, sizes, device type) come from NtQueryVolumeInformationFile, i.e. from the kernel. Another drive letter names no device.
 * The file system keeps no 8.3 aliases, so the short form of a path is its long form (as on an NTFS volume with 8.3 creation disabled);
 * GetLongPathName and GetShortPathName both verify that every component exists (see canonical_path).
 */
#include "k32.h"

static const WCHAR NT_DEVICE[] = { '\\','D','e','v','i','c','e','\\','H','a','r','d','d','i','s','k','V','o','l','u','m','e','1',0 };
/* \\?\Volume{GUID}\ : 49 characters */
static const WCHAR VOLUME_GUID_PATH[] = { '\\','\\','?','\\','V','o','l','u','m','e','{','5','3','4','8','5','a','3','1','-','0','0','0','0','-',
                                          '4','0','0','0','-','8','0','0','0','-','0','0','0','0','0','0','0','0','0','0','0','1','}','\\',0 };
#define VOLUME_GUID_LEN 49

static WCHAR up(WCHAR c) { return c >= 'a' && c <= 'z' ? (WCHAR)(c - 32) : c; }

/* ---------------------------------------------------------------- drive letters */
/* The drive a root/path argument names: NULL means the current drive. Returns 0 for anything without a drive letter (UNC, garbage). */
static int drive_of(LPCWSTR p, WCHAR *letter)
{
    WCHAR cwd[MAX_PATH];
    if (!p) {
        if (!k32_current_directory(cwd, MAX_PATH) || cwd[1] != ':') return 0;
        *letter = up(cwd[0]);
        return 1;
    }
    if (p[0] == '\\' && p[1] == '\\' && p[2] == '?' && p[3] == '\\') p += 4;
    if (!((p[0] >= 'A' && p[0] <= 'Z') || (p[0] >= 'a' && p[0] <= 'z')) || p[1] != ':') return 0;
    *letter = up(p[0]);
    return 1;
}

/* Opens the root directory of the volume behind a drive letter; fails for a drive that does not exist. */
static NTSTATUS open_root(WCHAR letter, HANDLE *h)
{
    WCHAR root[4] = { letter, ':', '\\', 0 };
    return k32_open_path(root, FILE_READ_ATTRIBUTES, FILE_OPEN_D, OPT_DIRECTORY, h, 0);
}

static int drive_exists(WCHAR letter)
{
    HANDLE h;
    if (open_root(letter, &h)) return 0;
    NtClose(h);
    return 1;
}

K32API UINT WINAPI GetDriveTypeW(LPCWSTR root)
{
    WCHAR l;
    HANDLE h;
    SHZ_IO_STATUS_BLOCK io;
    ULONG info[2];
    NTSTATUS st;
    UINT type;
    if (root && !root[0]) return DRIVE_NO_ROOT_DIR;
    if (!drive_of(root, &l)) return DRIVE_NO_ROOT_DIR;
    if (open_root(l, &h)) return DRIVE_NO_ROOT_DIR;
    st = NtQueryVolumeInformationFile(h, &io, info, sizeof info, 4);                 /* FileFsDeviceInformation: {DeviceType, Characteristics} */
    NtClose(h);
    if (!NT_SUCCESS(st)) return DRIVE_UNKNOWN;
    if (info[1] & 0x10) return DRIVE_REMOTE;                                         /* FILE_REMOTE_DEVICE */
    switch (info[0]) {
    case 2: case 3: type = DRIVE_CDROM; break;                                       /* FILE_DEVICE_CD_ROM, FILE_DEVICE_CD_ROM_FILE_SYSTEM */
    case 7: case 8: type = (info[1] & 1) ? DRIVE_REMOVABLE : DRIVE_FIXED; break;     /* FILE_DEVICE_DISK(_FILE_SYSTEM), FILE_REMOVABLE_MEDIA */
    case 0x14: type = DRIVE_REMOTE; break;                                           /* FILE_DEVICE_NETWORK_FILE_SYSTEM */
    case 0x24: type = DRIVE_RAMDISK; break;                                          /* FILE_DEVICE_VIRTUAL_DISK */
    default: type = DRIVE_UNKNOWN;
    }
    return type;
}
K32API UINT WINAPI GetDriveTypeA(LPCSTR root)
{
    WCHAR w[MAX_PATH];
    if (!root) return GetDriveTypeW(0);
    if (k32_utf8_to_wide(root, -1, w, MAX_PATH) <= 0) return DRIVE_NO_ROOT_DIR;
    return GetDriveTypeW(w);
}

K32API DWORD WINAPI GetLogicalDrives(void)
{
    DWORD mask = 0;
    WCHAR l;
    for (l = 'A'; l <= 'Z'; ++l)
        if (drive_exists(l)) mask |= 1u << (l - 'A');
    return mask;
}

K32API DWORD WINAPI GetLogicalDriveStringsW(DWORD cap, LPWSTR buf)
{
    WCHAR l;
    DWORD n = 0;
    for (l = 'A'; l <= 'Z'; ++l) {
        if (!drive_exists(l)) continue;
        if (n + 4 < cap && buf) { buf[n] = l; buf[n + 1] = ':'; buf[n + 2] = '\\'; buf[n + 3] = 0; }
        n += 4;
    }
    if (n + 1 > cap || !buf) return n + 1;                                           /* required size including the final NUL */
    buf[n] = 0;
    return n;
}
K32API DWORD WINAPI GetLogicalDriveStringsA(DWORD cap, LPSTR buf)
{
    WCHAR l;
    DWORD n = 0;
    for (l = 'A'; l <= 'Z'; ++l) {
        if (!drive_exists(l)) continue;
        if (n + 4 < cap && buf) { buf[n] = (char)l; buf[n + 1] = ':'; buf[n + 2] = '\\'; buf[n + 3] = 0; }
        n += 4;
    }
    if (n + 1 > cap || !buf) return n + 1;
    buf[n] = 0;
    return n;
}

/* ---------------------------------------------------------------- volume properties */
K32API BOOL WINAPI GetVolumeInformationW(LPCWSTR root, LPWSTR label, DWORD label_cap, LPDWORD serial, LPDWORD maxcomp, LPDWORD flags,
                                         LPWSTR fsname, DWORD fs_cap)
{
    WCHAR l;
    HANDLE h;
    SHZ_IO_STATUS_BLOCK io;
    BYTE buf[256];
    NTSTATUS st;
    if (root && !root[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (!drive_of(root, &l)) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (root && root[1] == ':' && root[2] && !(root[2] == '\\' && !root[3])) { shz_set_last_error(ERROR_DIR_NOT_ROOT); return FALSE; }
    st = open_root(l, &h);
    if (st) { k32_nt_error(st == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_OBJECT_PATH_NOT_FOUND : st); return FALSE; }
    if (label || serial) {
        st = NtQueryVolumeInformationFile(h, &io, buf, sizeof buf, 1);                /* FileFsVolumeInformation */
        if (NT_SUCCESS(st)) {
            const DWORD nbytes = *(const DWORD *)(buf + 12);
            if (serial) *serial = *(const DWORD *)(buf + 8);
            if (label) {
                if (nbytes / 2 + 1 > label_cap) { NtClose(h); shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
                memcpy(label, buf + 18, nbytes);
                label[nbytes / 2] = 0;
            }
        }
        if (!NT_SUCCESS(st)) { NtClose(h); k32_nt_error(st); return FALSE; }
    }
    if (maxcomp || flags || fsname) {
        st = NtQueryVolumeInformationFile(h, &io, buf, sizeof buf, 5);                /* FileFsAttributeInformation */
        if (NT_SUCCESS(st)) {
            const DWORD nbytes = *(const DWORD *)(buf + 8);
            if (flags) *flags = *(const DWORD *)buf;
            if (maxcomp) *maxcomp = *(const DWORD *)(buf + 4);
            if (fsname) {
                if (nbytes / 2 + 1 > fs_cap) { NtClose(h); shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
                memcpy(fsname, buf + 12, nbytes);
                fsname[nbytes / 2] = 0;
            }
        }
        if (!NT_SUCCESS(st)) { NtClose(h); k32_nt_error(st); return FALSE; }
    }
    NtClose(h);
    return TRUE;
}
K32API BOOL WINAPI GetVolumeInformationA(LPCSTR root, LPSTR label, DWORD label_cap, LPDWORD serial, LPDWORD maxcomp, LPDWORD flags,
                                         LPSTR fsname, DWORD fs_cap)
{
    WCHAR wroot[MAX_PATH], wl[MAX_PATH], wf[MAX_PATH];
    if (root && k32_utf8_to_wide(root, -1, wroot, MAX_PATH) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (!GetVolumeInformationW(root ? wroot : 0, label ? wl : 0, MAX_PATH, serial, maxcomp, flags, fsname ? wf : 0, MAX_PATH)) return FALSE;
    if (label && k32_wide_to_utf8(wl, -1, label, (int)label_cap) <= 0) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
    if (fsname && k32_wide_to_utf8(wf, -1, fsname, (int)fs_cap) <= 0) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
    return TRUE;
}

/* Free and total space of the volume holding `dir`, in bytes, from FileFsFullSizeInformation. */
static BOOL disk_space(LPCWSTR dir, ULONGLONG *avail, ULONGLONG *total, ULONGLONG *totfree, DWORD *spc, DWORD *bps)
{
    WCHAR l;
    HANDLE h;
    SHZ_IO_STATUS_BLOCK io;
    struct { LONGLONG total, caller, actual; ULONG spau, bps; } f;
    NTSTATUS st;
    if (dir && !dir[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (!drive_of(dir, &l)) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    st = open_root(l, &h);
    if (st) { k32_nt_error(st == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_OBJECT_PATH_NOT_FOUND : st); return FALSE; }
    st = NtQueryVolumeInformationFile(h, &io, &f, sizeof f, 7);
    NtClose(h);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    {
        const ULONGLONG unit = (ULONGLONG)f.spau * f.bps;
        if (avail) *avail = (ULONGLONG)f.caller * unit;
        if (total) *total = (ULONGLONG)f.total * unit;
        if (totfree) *totfree = (ULONGLONG)f.actual * unit;
        if (spc) *spc = f.spau;
        if (bps) *bps = f.bps;
    }
    return TRUE;
}

K32API BOOL WINAPI GetDiskFreeSpaceExW(LPCWSTR dir, PULARGE_INTEGER avail, PULARGE_INTEGER total, PULARGE_INTEGER totfree)
{
    ULONGLONG a, t, f;
    if (!disk_space(dir, &a, &t, &f, 0, 0)) return FALSE;
    if (avail) avail->QuadPart = a;
    if (total) total->QuadPart = t;
    if (totfree) totfree->QuadPart = f;
    return TRUE;
}
K32API BOOL WINAPI GetDiskFreeSpaceExA(LPCSTR dir, PULARGE_INTEGER avail, PULARGE_INTEGER total, PULARGE_INTEGER totfree)
{
    WCHAR w[MAX_PATH];
    if (dir && k32_utf8_to_wide(dir, -1, w, MAX_PATH) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return GetDiskFreeSpaceExW(dir ? w : 0, avail, total, totfree);
}

/* GetDiskFreeSpace wants a root path; cluster counts saturate at 32 bits. */
K32API BOOL WINAPI GetDiskFreeSpaceW(LPCWSTR root, LPDWORD spc, LPDWORD bps, LPDWORD nfree, LPDWORD ntotal)
{
    ULONGLONG a, t, f;
    DWORD s, b;
    if (root && root[0] && !(root[1] == ':' && root[2] == '\\' && !root[3])) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (!disk_space(root, &a, &t, &f, &s, &b)) return FALSE;
    if (spc) *spc = s;
    if (bps) *bps = b;
    if (nfree) *nfree = (DWORD)(a / ((ULONGLONG)s * b) > 0xffffffffu ? 0xffffffffu : a / ((ULONGLONG)s * b));
    if (ntotal) *ntotal = (DWORD)(t / ((ULONGLONG)s * b) > 0xffffffffu ? 0xffffffffu : t / ((ULONGLONG)s * b));
    return TRUE;
}
K32API BOOL WINAPI GetDiskFreeSpaceA(LPCSTR root, LPDWORD spc, LPDWORD bps, LPDWORD nfree, LPDWORD ntotal)
{
    WCHAR w[MAX_PATH];
    if (root && k32_utf8_to_wide(root, -1, w, MAX_PATH) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return GetDiskFreeSpaceW(root ? w : 0, spc, bps, nfree, ntotal);
}

/* ---------------------------------------------------------------- volume names and mount points */
K32API BOOL WINAPI GetVolumePathNameW(LPCWSTR path, LPWSTR out, DWORD cap)
{
    WCHAR full[320];
    WCHAR l;
    if (!path || !out || !cap) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!path[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (!GetFullPathNameW(path, 320, full, 0)) return FALSE;
    if (!drive_of(full, &l)) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (cap < 4) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    out[0] = up(full[0]); out[1] = ':'; out[2] = '\\'; out[3] = 0;
    return TRUE;
}
K32API BOOL WINAPI GetVolumePathNameA(LPCSTR path, LPSTR out, DWORD cap)
{
    WCHAR w[MAX_PATH], o[8];
    if (!path || !out || !cap) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (k32_utf8_to_wide(path, -1, w, MAX_PATH) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (!GetVolumePathNameW(w, o, 8)) return FALSE;
    if (cap < 4) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    out[0] = (char)o[0]; out[1] = ':'; out[2] = '\\'; out[3] = 0;
    return TRUE;
}

K32API BOOL WINAPI GetVolumeNameForVolumeMountPointW(LPCWSTR mp, LPWSTR out, DWORD cap)
{
    WCHAR l;
    if (!mp || !out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!drive_of(mp, &l) || mp[1] != ':' || mp[2] != '\\' || mp[3]) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (!drive_exists(l)) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    if (cap < VOLUME_GUID_LEN + 1) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return FALSE; }
    memcpy(out, VOLUME_GUID_PATH, (VOLUME_GUID_LEN + 1) * sizeof(WCHAR));
    return TRUE;
}

static int is_volume_guid_path(LPCWSTR s)
{
    size_t i;
    for (i = 0; i < VOLUME_GUID_LEN; ++i)
        if (up(s[i]) != up(VOLUME_GUID_PATH[i])) return 0;
    return s[i] == 0;
}

K32API BOOL WINAPI GetVolumePathNamesForVolumeNameW(LPCWSTR volume, LPWSTR names, DWORD cap, PDWORD retlen)
{
    if (!volume) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!is_volume_guid_path(volume)) { shz_set_last_error(ERROR_FILE_NOT_FOUND); return FALSE; }
    if (retlen) *retlen = 5;                                                         /* "C:\" NUL NUL */
    if (cap < 5 || !names) { shz_set_last_error(ERROR_MORE_DATA); return FALSE; }
    names[0] = 'C'; names[1] = ':'; names[2] = '\\'; names[3] = 0; names[4] = 0;
    return TRUE;
}

/* The volumes of this machine: just the one. */
#define VOLFIND_MAGIC 0x564c4f46u
typedef struct { ULONG magic; int done; } volfind_t;
static volfind_t *volfind_of(HANDLE h)
{
    volfind_t *v = h;
    if (!h || h == INVALID_HANDLE_VALUE || ((uintptr_t)h & 15) || !RtlValidateHeap(ShzProcessHeap(), 0, h) || v->magic != VOLFIND_MAGIC) return 0;
    return v;
}

K32API HANDLE WINAPI FindFirstVolumeW(LPWSTR out, DWORD cap)
{
    volfind_t *v;
    if (!out || cap < VOLUME_GUID_LEN + 1) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return INVALID_HANDLE_VALUE; }
    v = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *v);
    if (!v) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    v->magic = VOLFIND_MAGIC;
    memcpy(out, VOLUME_GUID_PATH, (VOLUME_GUID_LEN + 1) * sizeof(WCHAR));           /* \\?\Volume{GUID}\ with its trailing backslash */
    return v;
}
K32API BOOL WINAPI FindNextVolumeW(HANDLE h, LPWSTR out, DWORD cap)
{
    volfind_t *v = volfind_of(h);
    (void)out; (void)cap;
    if (!v) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    v->done = 1;
    shz_set_last_error(ERROR_NO_MORE_FILES);
    return FALSE;
}
K32API BOOL WINAPI FindVolumeClose(HANDLE h)
{
    volfind_t *v = volfind_of(h);
    if (!v) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    v->magic = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, v);
    return TRUE;
}

/* DOS device names: the drive letter of the volume maps to its NT device. Returns the characters stored, including the terminating NULs. */
K32API DWORD WINAPI QueryDosDeviceW(LPCWSTR name, LPWSTR target, DWORD cap)
{
    WCHAR l;
    const size_t dev = k32_wlen(NT_DEVICE);
    if (!name) {                                                                     /* every DOS device name: "C:" */
        if (cap < 4) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
        target[0] = 'C'; target[1] = ':'; target[2] = 0; target[3] = 0;
        return 4;
    }
    if (!((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) || name[1] != ':' || name[2]) {
        shz_set_last_error(ERROR_FILE_NOT_FOUND);
        return 0;
    }
    l = up(name[0]);
    if (!drive_exists(l)) { shz_set_last_error(ERROR_FILE_NOT_FOUND); return 0; }
    if (cap < dev + 2) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    memcpy(target, NT_DEVICE, (dev + 1) * sizeof(WCHAR));
    target[dev + 1] = 0;
    return (DWORD)dev + 2;
}

/* ---------------------------------------------------------------- final path name of an open file */
K32API DWORD WINAPI GetFinalPathNameByHandleW(HANDLE h, LPWSTR out, DWORD cap, DWORD flags)
{
    BYTE raw[4 + 2 * 520];
    SHZ_IO_STATUS_BLOCK io;
    WCHAR full[600];
    NTSTATUS st;
    size_t n = 0, nlen, i;
    const WCHAR *name;
    const DWORD vol = flags & 0x7, kind = flags & 0x8;
    if ((flags & ~0xfu) || (vol != 0 && vol != 1 && vol != 2 && vol != 4) || (kind != 0 && kind != 8)) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return 0;
    }
    st = NtQueryInformationFile(h, &io, raw, sizeof raw, 9);                          /* volume-relative name: "\dir\file" */
    if (!NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW) { k32_nt_error(st == STATUS_BUFFER_OVERFLOW ? STATUS_NAME_TOO_LONG : st); return 0; }
    nlen = *(const ULONG *)raw / 2;
    name = (const WCHAR *)(raw + 4);
    switch (vol) {
    case 0:                                                                          /* VOLUME_NAME_DOS: \\?\C:\dir\file */
        full[n++] = '\\'; full[n++] = '\\'; full[n++] = '?'; full[n++] = '\\'; full[n++] = 'C'; full[n++] = ':';
        break;
    case 1:                                                                          /* VOLUME_NAME_GUID: \\?\Volume{GUID}\dir\file */
        memcpy(full, VOLUME_GUID_PATH, (VOLUME_GUID_LEN - 1) * sizeof(WCHAR));
        n = VOLUME_GUID_LEN - 1;
        break;
    case 2:                                                                          /* VOLUME_NAME_NT: \Device\HarddiskVolume1\dir\file */
        n = k32_wlen(NT_DEVICE);
        memcpy(full, NT_DEVICE, n * sizeof(WCHAR));
        break;
    default: break;                                                                  /* VOLUME_NAME_NONE: \dir\file */
    }
    for (i = 0; i < nlen && n < 599; ++i) full[n++] = name[i];
    full[n] = 0;
    if (cap <= n) return (DWORD)n + 1;                                               /* required size including the NUL */
    memcpy(out, full, (n + 1) * sizeof(WCHAR));
    return (DWORD)n;
}
K32API DWORD WINAPI GetFinalPathNameByHandleA(HANDLE h, LPSTR out, DWORD cap, DWORD flags)
{
    WCHAR w[700];
    char a[2100];
    DWORD n = GetFinalPathNameByHandleW(h, w, 700, flags);
    int len;
    if (!n || n >= 700) return n;
    len = k32_wide_to_utf8(w, -1, a, sizeof a);
    if (len <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    if ((DWORD)len > cap) return (DWORD)len;                                         /* len counts the NUL */
    memcpy(out, a, (size_t)len);
    return (DWORD)len - 1;
}

/* ---------------------------------------------------------------- long and short path names */
/* Whether a path component could be a DOS 8.3 short name: at most one dot, a base of 1-8 characters and an extension of at most 3. */
static int is_83_shape(const WCHAR *c, size_t len)
{
    size_t dot = len, i, dots = 0;
    for (i = 0; i < len; ++i) if (c[i] == '.') { if (!dots) dot = i; ++dots; }
    if (dots > 1 || dot == 0 || len == 0) return 0;
    if (dot > 8) return 0;
    return dot == len || len - dot - 1 <= 3;
}

/* GetLongPathName: every component must exist (ERROR_FILE_NOT_FOUND otherwise). A component that could be a short name is replaced by the
 * name the file system stores for it (this file system has no 8.3 aliases, so that only corrects its case); any other component, and "."
 * and "..", are copied as given. The root, separators and a trailing separator are kept. */
static DWORD canonical_path(LPCWSTR in, LPWSTR out)
{
    WCHAR w[300];
    size_t n, pos, o = 0, i;
    WIN32_FIND_DATAW fd;
    if (!in) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!in[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return 0; }
    n = k32_wlen(in);
    if (n >= 299) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    if (in[0] == '\\' && in[1] == '\\' && in[2] != '?') { shz_set_last_error(ERROR_BAD_NETPATH); return 0; }        /* UNC: there are no network shares */
    memcpy(w, in, (n + 1) * sizeof(WCHAR));
    pos = 0;                                                                         /* skip the root: "\\?\", "X:", "\" */
    if (w[0] == '\\' && w[1] == '\\' && w[2] == '?' && w[3] == '\\') pos = 4;
    if (w[pos] && w[pos + 1] == ':') pos += 2;
    if (w[pos] == '\\' || w[pos] == '/') ++pos;
    for (i = 0; i < pos; ++i) out[o++] = w[i];
    while (pos < n) {
        size_t s = pos, len, k;
        WCHAR spec[300];
        HANDLE h;
        while (pos < n && w[pos] != '\\' && w[pos] != '/') ++pos;
        len = pos - s;
        if (len == 0) { ++pos; if (o + 1 < 299) out[o++] = w[pos - 1]; continue; }    /* doubled separator */
        if ((len == 1 && w[s] == '.') || (len == 2 && w[s] == '.' && w[s + 1] == '.')) {
            for (i = 0; i < len; ++i) out[o++] = w[s + i];
        } else {
            for (k = 0; k < len; ++k)
                if (w[s + k] == '*' || w[s + k] == '?') { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
            if (o + len >= 299) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
            memcpy(spec, out, o * sizeof(WCHAR));
            memcpy(spec + o, w + s, len * sizeof(WCHAR));
            spec[o + len] = 0;
            h = FindFirstFileW(spec, &fd);
            if (h == INVALID_HANDLE_VALUE) {
                if (shz_last_error() == ERROR_PATH_NOT_FOUND) shz_set_last_error(ERROR_FILE_NOT_FOUND);
                return 0;
            }
            FindClose(h);
            if (is_83_shape(w + s, len)) {
                const size_t fl = k32_wlen(fd.cFileName);
                if (o + fl >= 299) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
                for (k = 0; k < fl; ++k) out[o++] = fd.cFileName[k];
            } else {
                for (k = 0; k < len; ++k) out[o++] = w[s + k];
            }
        }
        if (pos < n) { out[o++] = w[pos]; ++pos; }                                   /* separator (a trailing one is kept) */
    }
    out[o] = 0;
    return (DWORD)o;
}

static DWORD path_name(LPCWSTR in, LPWSTR out, DWORD cap)
{
    WCHAR tmp[300];
    DWORD n = canonical_path(in, tmp);
    if (!n) return 0;
    if (cap <= n || !out) return n + 1;
    memcpy(out, tmp, (n + 1) * sizeof(WCHAR));
    shz_set_last_error(0);
    return n;
}
K32API DWORD WINAPI GetLongPathNameW(LPCWSTR in, LPWSTR out, DWORD cap) { return path_name(in, out, cap); }
K32API DWORD WINAPI GetShortPathNameW(LPCWSTR in, LPWSTR out, DWORD cap) { return path_name(in, out, cap); }

static DWORD path_name_a(LPCSTR in, LPSTR out, DWORD cap, DWORD (WINAPI *fn)(LPCWSTR, LPWSTR, DWORD))
{
    WCHAR w[300], o[300];
    char a[900];
    DWORD n;
    int len;
    if (!in) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (k32_utf8_to_wide(in, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    n = fn(w, o, 300);
    if (!n || n >= 300) return n;
    len = k32_wide_to_utf8(o, -1, a, sizeof a);
    if (len <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    if ((DWORD)len > cap || !out) return (DWORD)len;
    memcpy(out, a, (size_t)len);
    return (DWORD)len - 1;
}
K32API DWORD WINAPI GetLongPathNameA(LPCSTR in, LPSTR out, DWORD cap) { return path_name_a(in, out, cap, GetLongPathNameW); }
K32API DWORD WINAPI GetShortPathNameA(LPCSTR in, LPSTR out, DWORD cap) { return path_name_a(in, out, cap, GetShortPathNameW); }

/* ---------------------------------------------------------------- temporary directory and files */
/* TMP, TEMP, USERPROFILE, then the Windows directory; the result is a full path ending in a backslash. */
K32API DWORD WINAPI GetTempPathW(DWORD cap, LPWSTR buf)
{
    static const WCHAR vars[3][12] = { { 'T','M','P',0 }, { 'T','E','M','P',0 }, { 'U','S','E','R','P','R','O','F','I','L','E',0 } };
    WCHAR raw[MAX_PATH], full[MAX_PATH + 2];
    DWORD n = 0, i;
    for (i = 0; i < 3 && !n; ++i) {
        n = GetEnvironmentVariableW(vars[i], raw, MAX_PATH);
        if (n >= MAX_PATH) n = 0;
    }
    if (!n) n = GetWindowsDirectoryW(raw, MAX_PATH);
    if (!n || n >= MAX_PATH) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    n = GetFullPathNameW(raw, MAX_PATH, full, 0);
    if (!n || n >= MAX_PATH) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    if (full[n - 1] != '\\') { full[n++] = '\\'; full[n] = 0; }
    if (cap <= n || !buf) return n + 1;
    memcpy(buf, full, (n + 1) * sizeof(WCHAR));
    return n;
}
K32API DWORD WINAPI GetTempPathA(DWORD cap, LPSTR buf)
{
    WCHAR w[MAX_PATH + 2];
    char a[3 * (MAX_PATH + 2)];
    DWORD n = GetTempPathW(MAX_PATH + 2, w);
    int len;
    if (!n || n >= MAX_PATH + 2) return n;
    len = k32_wide_to_utf8(w, -1, a, sizeof a);
    if (len <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    if ((DWORD)len > cap || !buf) return (DWORD)len;
    memcpy(buf, a, (size_t)len);
    return (DWORD)len - 1;
}

static const char hexd[] = "0123456789abcdef";

/* <path>\<up to 3 chars of prefix><hex unique>.tmp; with unique == 0 a name is chosen and its (empty) file created. */
K32API UINT WINAPI GetTempFileNameW(LPCWSTR path, LPCWSTR prefix, UINT unique, LPWSTR out)
{
    WCHAR name[MAX_PATH + 16];
    size_t n, i, base;
    UINT u = unique, tries;
    if (!path || !prefix || !out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    n = k32_wlen(path);
    if (n > MAX_PATH - 14) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    memcpy(name, path, n * sizeof(WCHAR));
    if (n && name[n - 1] != '\\') name[n++] = '\\';
    for (i = 0; i < 3 && prefix[i]; ++i) name[n++] = prefix[i];
    base = n;
    if (!u) {                                                                        /* pick a number no existing file uses, and claim it */
        LARGE_INTEGER t;
        NtQuerySystemTime(&t);
        u = (UINT)((t.QuadPart / 10000) ^ ((ULONGLONG)shz_pid() << 8) ^ shz_tid()) & 0xffff;
        if (!u) u = 1;
    }
    for (tries = 0; tries < 0x10000; ++tries) {
        int digits = 4, shift;
        n = base;
        while (digits < 8 && (u >> (4 * digits))) ++digits;                          /* "%.4x": at least four hex digits */
        for (shift = 4 * (digits - 1); shift >= 0; shift -= 4) name[n++] = (WCHAR)hexd[(u >> shift) & 15];
        name[n++] = '.'; name[n++] = 't'; name[n++] = 'm'; name[n++] = 'p'; name[n] = 0;
        if (unique) break;                                                           /* the caller fixed the number: no file is created */
        {
            HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, 0, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
            if (h != INVALID_HANDLE_VALUE) { NtClose(h); break; }
            if (shz_last_error() == ERROR_PATH_NOT_FOUND) { shz_set_last_error(ERROR_DIRECTORY); return 0; }     /* the directory does not exist */
            if (shz_last_error() != ERROR_FILE_EXISTS && shz_last_error() != ERROR_ALREADY_EXISTS) return 0;
        }
        u = (u + 1) & 0xffff;
        if (!u) u = 1;
    }
    if (tries == 0x10000) { shz_set_last_error(ERROR_FILE_EXISTS); return 0; }
    memcpy(out, name, (n + 1) * sizeof(WCHAR));
    return u;
}
K32API UINT WINAPI GetTempFileNameA(LPCSTR path, LPCSTR prefix, UINT unique, LPSTR out)
{
    WCHAR wp[MAX_PATH], wx[8], wo[MAX_PATH + 16];
    UINT u;
    if (!path || !prefix || !out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (k32_utf8_to_wide(path, -1, wp, MAX_PATH) <= 0) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    if (k32_utf8_to_wide(prefix, -1, wx, 8) <= 0) {                                  /* only the first three characters count */
        int i;
        for (i = 0; i < 3 && prefix[i]; ++i) wx[i] = (unsigned char)prefix[i];
        wx[i] = 0;
    }
    u = GetTempFileNameW(wp, wx, unique, wo);
    if (!u) return 0;
    if (k32_wide_to_utf8(wo, -1, out, MAX_PATH) <= 0) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return 0; }
    return u;
}
