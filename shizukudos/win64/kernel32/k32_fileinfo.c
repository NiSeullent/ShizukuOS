/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: file information by handle and by name (attributes, times, size, identity, name), SetFileInformationByHandle,
 * ReplaceFile, byte-range locks, and the overlapped-result / cancel functions.
 *
 * The information comes from NtQueryInformationFile / NtSetInformationFile (FileBasicInformation 4, FileStandardInformation 5,
 * FileInternalInformation 6, FileNameInformation 9, FileEndOfFileInformation 20, ...) and NtQueryVolumeInformationFile.
 * File requests complete before the call returns; requests on pipes (kernel64/npfs.c) may be pending: GetOverlappedResult waits
 * for them, CancelIo / CancelIoEx cancel them (ERROR_OPERATION_ABORTED), SetFileCompletionNotificationModes sets the NT modes.
 */
#include "k32.h"

typedef struct { LONGLONG create, access, write, change; ULONG attrs, pad; } basic_t;                 /* FILE_BASIC_INFORMATION, 40 bytes */
typedef struct { LONGLONG alloc, eof; ULONG links; BYTE del, dir; WORD pad; } std_t;                   /* FILE_STANDARD_INFORMATION, 24 bytes */

#define ATTR_SETTABLE (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | \
                       FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)

static void ft_put(FILETIME *ft, LONGLONG v) { ft->dwLowDateTime = (DWORD)v; ft->dwHighDateTime = (DWORD)((ULONGLONG)v >> 32); }
static LONGLONG ft_get(const FILETIME *ft) { return (LONGLONG)(((ULONGLONG)ft->dwHighDateTime << 32) | ft->dwLowDateTime); }

static NTSTATUS q_basic(HANDLE h, basic_t *b) { SHZ_IO_STATUS_BLOCK io; return NtQueryInformationFile(h, &io, b, sizeof *b, 4); }
static NTSTATUS q_std(HANDLE h, std_t *s) { SHZ_IO_STATUS_BLOCK io; return NtQueryInformationFile(h, &io, s, sizeof *s, 5); }

/* Serial number of the volume the handle lives on (FileFsVolumeInformation: serial at offset 8). */
static NTSTATUS q_serial(HANDLE h, DWORD *serial)
{
    SHZ_IO_STATUS_BLOCK io;
    BYTE buf[128];
    NTSTATUS st = NtQueryVolumeInformationFile(h, &io, buf, sizeof buf, 1);
    if (NT_SUCCESS(st)) *serial = *(const DWORD *)(buf + 8);
    return st;
}

/* ---------------------------------------------------------------- by handle */
K32API BOOL WINAPI GetFileInformationByHandle(HANDLE h, LPBY_HANDLE_FILE_INFORMATION out)
{
    basic_t b;
    std_t s;
    LONGLONG idx = 0;
    DWORD serial = 0;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if (!out) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = q_serial(h, &serial);                                                    /* fails for devices such as the console */
    if (NT_SUCCESS(st)) st = q_basic(h, &b);
    if (NT_SUCCESS(st)) st = q_std(h, &s);
    if (NT_SUCCESS(st)) st = NtQueryInformationFile(h, &io, &idx, 8, 6);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    memset(out, 0, sizeof *out);
    out->dwFileAttributes = b.attrs;
    ft_put(&out->ftCreationTime, b.create);
    ft_put(&out->ftLastAccessTime, b.access);
    ft_put(&out->ftLastWriteTime, b.write);
    out->dwVolumeSerialNumber = serial;
    out->nFileSizeHigh = (DWORD)((ULONGLONG)s.eof >> 32);
    out->nFileSizeLow = (DWORD)s.eof;
    out->nNumberOfLinks = s.links;
    out->nFileIndexHigh = (DWORD)((ULONGLONG)idx >> 32);
    out->nFileIndexLow = (DWORD)idx;
    return TRUE;
}

/* Windows' FILE_INFO_BY_HANDLE_CLASS numbering. */
enum { CL_BASIC = 0, CL_STANDARD = 1, CL_NAME = 2, CL_RENAME = 3, CL_DISPOSITION = 4, CL_ALLOCATION = 5, CL_EOF = 6, CL_STREAM = 7,
       CL_COMPRESSION = 8, CL_ATTRTAG = 9, CL_IDBOTH = 10, CL_IDBOTH_RESTART = 11, CL_IOPRIO = 12, CL_REMOTE = 13, CL_FULLDIR = 14,
       CL_FULLDIR_RESTART = 15, CL_STORAGE = 16, CL_ALIGNMENT = 17, CL_ID = 18, CL_IDEXT = 19, CL_IDEXT_RESTART = 20,
       CL_DISPOSITION_EX = 21, CL_RENAME_EX = 22, CL_CASE_SENSITIVE = 23, CL_NORMALIZED_NAME = 24, CL_MAX = 25 };

K32API BOOL WINAPI GetFileInformationByHandleEx(HANDLE h, FILE_INFO_BY_HANDLE_CLASS cls, LPVOID buf, DWORD size)
{
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if ((unsigned)cls >= CL_MAX) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!buf) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    switch ((int)cls) {
    case CL_BASIC: {                                                              /* FILE_BASIC_INFO == FILE_BASIC_INFORMATION */
        if (size < sizeof(basic_t)) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_basic(h, (basic_t *)buf);
        break;
    }
    case CL_STANDARD: {                                                           /* FILE_STANDARD_INFO == FILE_STANDARD_INFORMATION */
        if (size < sizeof(std_t)) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_std(h, (std_t *)buf);
        break;
    }
    case CL_NAME: case CL_NORMALIZED_NAME: {                                      /* FILE_NAME_INFO: {DWORD FileNameLength; WCHAR FileName[]} */
        if (size < 4) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = NtQueryInformationFile(h, &io, buf, size, 9);
        break;
    }
    case CL_ATTRTAG: {                                                            /* FILE_ATTRIBUTE_TAG_INFO: {attributes, reparse tag} */
        basic_t b;
        if (size < 8) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_basic(h, &b);
        if (NT_SUCCESS(st)) { ((DWORD *)buf)[0] = b.attrs; ((DWORD *)buf)[1] = 0; }        /* no reparse points */
        break;
    }
    case CL_COMPRESSION: {                                                        /* FILE_COMPRESSION_INFO: nothing is compressed */
        std_t s;
        BYTE *o = buf;
        if (size < 16) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_std(h, &s);
        if (NT_SUCCESS(st)) { memset(o, 0, 16); *(LONGLONG *)o = s.eof; }         /* CompressedFileSize == EndOfFile, format COMPRESSION_FORMAT_NONE */
        break;
    }
    case CL_ALIGNMENT: {                                                          /* FILE_ALIGNMENT_INFO: FILE_BYTE_ALIGNMENT */
        basic_t b;
        if (size < 4) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_basic(h, &b);
        if (NT_SUCCESS(st)) *(DWORD *)buf = 0;
        break;
    }
    case CL_ID: {                                                                 /* FILE_ID_INFO: {ULONGLONG VolumeSerialNumber; BYTE FileId[16]} */
        DWORD serial;
        LONGLONG idx = 0;
        BYTE *o = buf;
        if (size < 24) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        st = q_serial(h, &serial);
        if (NT_SUCCESS(st)) st = NtQueryInformationFile(h, &io, &idx, 8, 6);
        if (NT_SUCCESS(st)) { memset(o, 0, 24); *(ULONGLONG *)o = serial; *(LONGLONG *)(o + 8) = idx; }
        break;
    }
    default:
        shz_set_last_error(ERROR_NOT_SUPPORTED);                                  /* directory and stream enumeration classes */
        return FALSE;
    }
    if (!NT_SUCCESS(st)) { k32_nt_error(st == STATUS_BUFFER_TOO_SMALL ? STATUS_INFO_LENGTH_MISMATCH : st); return FALSE; }
    if (st == STATUS_BUFFER_OVERFLOW) { shz_set_last_error(ERROR_MORE_DATA); return FALSE; }      /* the name is longer than the buffer */
    return TRUE;
}

static BOOL rename_by_handle(HANDLE h, const FILE_RENAME_INFO *ri, DWORD size, BOOL replace)
{
    WCHAR dos[300], nt[320];
    struct { BYTE replace, pad[7]; HANDLE root; ULONG len; WCHAR name[320]; } r;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    size_t n;
    if (size < offsetof(FILE_RENAME_INFO, FileName) || ri->FileNameLength % 2 || ri->FileNameLength / 2 >= 300 ||
        size < offsetof(FILE_RENAME_INFO, FileName) + ri->FileNameLength) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
    if (ri->RootDirectory) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }        /* relative-to-handle names are not supported */
    memcpy(dos, ri->FileName, ri->FileNameLength);
    dos[ri->FileNameLength / 2] = 0;
    st = k32_dos_to_nt(dos, nt, 320);
    if (st) { k32_nt_error(st); return FALSE; }
    n = k32_wlen(nt);
    memset(&r, 0, sizeof r);
    r.replace = replace != 0;
    r.len = (ULONG)(n * 2);
    memcpy(r.name, nt, n * sizeof(WCHAR));
    st = NtSetInformationFile(h, &io, &r, (ULONG)(20 + n * 2), 10);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI SetFileInformationByHandle(HANDLE h, FILE_INFO_BY_HANDLE_CLASS cls, LPVOID buf, DWORD size)
{
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if ((unsigned)cls >= CL_MAX || !buf) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    switch ((int)cls) {
    case CL_BASIC: {                                                              /* zero times and zero attributes mean "unchanged" */
        basic_t b;
        if (size < sizeof b) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        memcpy(&b, buf, sizeof b);
        if (b.attrs) { b.attrs &= ATTR_SETTABLE; if (!b.attrs) b.attrs = FILE_ATTRIBUTE_NORMAL; }
        st = NtSetInformationFile(h, &io, &b, sizeof b, 4);
        break;
    }
    case CL_DISPOSITION: {                                                        /* FILE_DISPOSITION_INFO: {BOOLEAN DeleteFile} */
        BYTE del;
        if (size < 1) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        del = *(const BYTE *)buf != 0;
        st = NtSetInformationFile(h, &io, &del, 1, 13);
        break;
    }
    case CL_DISPOSITION_EX: {                                                     /* FILE_DISPOSITION_INFO_EX: {DWORD Flags} */
        DWORD flags;
        BYTE del;
        if (size < 4) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        flags = *(const DWORD *)buf;
        if (flags & ~(DWORD)(FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_ON_CLOSE)) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
        del = (flags & FILE_DISPOSITION_FLAG_DELETE) != 0;                        /* deletion always happens when the last handle closes */
        st = NtSetInformationFile(h, &io, &del, 1, 13);
        break;
    }
    case CL_EOF: {                                                                /* FILE_END_OF_FILE_INFO: {LARGE_INTEGER EndOfFile} */
        LONGLONG eof;
        if (size < 8) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        eof = *(const LONGLONG *)buf;
        st = NtSetInformationFile(h, &io, &eof, 8, 20);
        break;
    }
    case CL_ALLOCATION: {                                                         /* FILE_ALLOCATION_INFO: space is allocated on demand, so only a shrink is visible */
        LONGLONG alloc, eof;
        std_t s;
        if (size < 8) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        alloc = *(const LONGLONG *)buf;
        if (alloc < 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        st = q_std(h, &s);
        if (NT_SUCCESS(st) && alloc < s.eof) { eof = alloc; st = NtSetInformationFile(h, &io, &eof, 8, 20); }
        break;
    }
    case CL_IOPRIO: {                                                             /* FILE_IO_PRIORITY_HINT_INFO: a hint; only its range is validated */
        if (size < 4) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
        if (*(const DWORD *)buf >= 3) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        st = q_std(h, &(std_t){0});                                               /* validates the handle */
        break;
    }
    case CL_RENAME: return rename_by_handle(h, buf, size, ((const FILE_RENAME_INFO *)buf)->ReplaceIfExists);
    case CL_RENAME_EX: {                                                          /* FILE_RENAME_FLAG_REPLACE_IF_EXISTS only */
        const DWORD flags = ((const FILE_RENAME_INFO *)buf)->Flags;
        if (flags & ~1u) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
        return rename_by_handle(h, buf, size, (flags & 1) != 0);
    }
    default:
        shz_set_last_error(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- times */
K32API BOOL WINAPI GetFileTime(HANDLE h, LPFILETIME c, LPFILETIME a, LPFILETIME w)
{
    basic_t b;
    NTSTATUS st = q_basic(h, &b);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    if (c) ft_put(c, b.create);
    if (a) ft_put(a, b.access);
    if (w) ft_put(w, b.write);
    return TRUE;
}

K32API BOOL WINAPI SetFileTime(HANDLE h, const FILETIME *c, const FILETIME *a, const FILETIME *w)
{
    basic_t b;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    memset(&b, 0, sizeof b);                                                      /* a zero time is left unchanged */
    if (c) b.create = ft_get(c);
    if (a) b.access = ft_get(a);
    if (w) b.write = ft_get(w);
    st = NtSetInformationFile(h, &io, &b, sizeof b, 4);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* ---------------------------------------------------------------- by name */
static BOOL name_ok(LPCWSTR name)
{
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!name[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetFileAttributesExW(LPCWSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data)
{
    HANDLE h;
    basic_t b;
    std_t s;
    WIN32_FILE_ATTRIBUTE_DATA *d = data;
    NTSTATUS st;
    if (level != GetFileExInfoStandard || !data) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!name_ok(name)) return FALSE;
    st = k32_open_path(name, FILE_READ_ATTRIBUTES, FILE_OPEN_D, 0, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    st = q_basic(h, &b);
    if (NT_SUCCESS(st)) st = q_std(h, &s);
    NtClose(h);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    d->dwFileAttributes = b.attrs;
    ft_put(&d->ftCreationTime, b.create);
    ft_put(&d->ftLastAccessTime, b.access);
    ft_put(&d->ftLastWriteTime, b.write);
    d->nFileSizeHigh = (DWORD)((ULONGLONG)s.eof >> 32);
    d->nFileSizeLow = (DWORD)s.eof;
    return TRUE;
}
K32API BOOL WINAPI GetFileAttributesExA(LPCSTR name, GET_FILEEX_INFO_LEVELS level, LPVOID data)
{
    WCHAR w[300];
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return GetFileAttributesExW(w, level, data);
}

K32API BOOL WINAPI SetFileAttributesW(LPCWSTR name, DWORD attrs)
{
    HANDLE h;
    basic_t b;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    if (!name_ok(name)) return FALSE;
    st = k32_open_path(name, FILE_WRITE_ATTRIBUTES, FILE_OPEN_D, 0, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    memset(&b, 0, sizeof b);
    b.attrs = attrs & ATTR_SETTABLE;                                              /* other bits (directory, compressed, ...) cannot be set */
    if (!b.attrs) b.attrs = FILE_ATTRIBUTE_NORMAL;                                /* clears the settable attributes */
    st = NtSetInformationFile(h, &io, &b, sizeof b, 4);
    NtClose(h);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI SetFileAttributesA(LPCSTR name, DWORD attrs)
{
    WCHAR w[300];
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (k32_utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return SetFileAttributesW(w, attrs);
}

/* ---------------------------------------------------------------- ReplaceFile */
static BOOL exists(LPCWSTR path) { return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES; }

K32API BOOL WINAPI ReplaceFileW(LPCWSTR replaced, LPCWSTR replacement, LPCWSTR backup, DWORD flags, LPVOID excl, LPVOID reserved)
{
    DWORD a;
    if (!replaced || !replacement || excl || reserved || (flags & ~(DWORD)(REPLACEFILE_WRITE_THROUGH | REPLACEFILE_IGNORE_MERGE_ERRORS |
                                                                          REPLACEFILE_IGNORE_ACL_ERRORS))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    a = GetFileAttributesW(replaced);                                             /* the replaced file must exist (error 2 or 3 otherwise) */
    if (a == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (a & FILE_ATTRIBUTE_DIRECTORY) { shz_set_last_error(ERROR_UNABLE_TO_REMOVE_REPLACED); return FALSE; }
    a = GetFileAttributesW(replacement);
    if (a == INVALID_FILE_ATTRIBUTES) return FALSE;
    if (a & FILE_ATTRIBUTE_DIRECTORY) { shz_set_last_error(ERROR_UNABLE_TO_MOVE_REPLACEMENT); return FALSE; }
    if (backup) {                                                                 /* replaced -> backup (an existing backup file is overwritten) */
        if (exists(backup) && !DeleteFileW(backup)) { shz_set_last_error(ERROR_UNABLE_TO_REMOVE_REPLACED); return FALSE; }
        if (!MoveFileExW(replaced, backup, 0)) { shz_set_last_error(ERROR_UNABLE_TO_REMOVE_REPLACED); return FALSE; }
    } else if (!DeleteFileW(replaced)) {
        shz_set_last_error(ERROR_UNABLE_TO_REMOVE_REPLACED);
        return FALSE;
    }
    if (!MoveFileExW(replacement, replaced, 0)) {                                 /* replacement -> replaced; put the original back if possible */
        if (backup && MoveFileExW(backup, replaced, 0)) shz_set_last_error(ERROR_UNABLE_TO_MOVE_REPLACEMENT_2);
        else shz_set_last_error(ERROR_UNABLE_TO_MOVE_REPLACEMENT);
        return FALSE;
    }
    return TRUE;
}

/* ---------------------------------------------------------------- byte-range locks */
static BOOL lock_range(HANDLE h, DWORD lo, DWORD hi, DWORD nlo, DWORD nhi, BOOL excl, BOOL fail_now)
{
    LARGE_INTEGER off, len;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    off.QuadPart = ((LONGLONG)hi << 32) | lo;
    len.QuadPart = ((LONGLONG)nhi << 32) | nlo;
    for (;;) {
        st = NtLockFile(h, 0, 0, 0, &io, &off, &len, 0, TRUE, excl != 0);
        if (st != (NTSTATUS)0xC0000055 || fail_now) break;                        /* STATUS_LOCK_NOT_GRANTED: poll until the holder lets go */
        {
            LARGE_INTEGER pause;
            pause.QuadPart = -100000;                                             /* 10 ms */
            NtDelayExecution(FALSE, &pause);
        }
    }
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI LockFile(HANDLE h, DWORD lo, DWORD hi, DWORD nlo, DWORD nhi) { return lock_range(h, lo, hi, nlo, nhi, TRUE, TRUE); }

K32API BOOL WINAPI LockFileEx(HANDLE h, DWORD flags, DWORD reserved, DWORD nlo, DWORD nhi, LPOVERLAPPED ov)
{
    BOOL ok;
    if (reserved || (flags & ~(DWORD)(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)) || !ov) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    ok = lock_range(h, ov->Offset, ov->OffsetHigh, nlo, nhi, (flags & LOCKFILE_EXCLUSIVE_LOCK) != 0, (flags & LOCKFILE_FAIL_IMMEDIATELY) != 0);
    ov->Internal = ok ? 0 : (ULONG_PTR)STATUS_LOCK_NOT_GRANTED;
    ov->InternalHigh = 0;
    if (ok && ov->hEvent) NtSetEvent(ov->hEvent, 0);                              /* the request completed synchronously */
    return ok;
}

static BOOL unlock_range(HANDLE h, DWORD lo, DWORD hi, DWORD nlo, DWORD nhi)
{
    LARGE_INTEGER off, len;
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st;
    off.QuadPart = ((LONGLONG)hi << 32) | lo;
    len.QuadPart = ((LONGLONG)nhi << 32) | nlo;
    st = NtUnlockFile(h, &io, &off, &len, 0);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI UnlockFile(HANDLE h, DWORD lo, DWORD hi, DWORD nlo, DWORD nhi) { return unlock_range(h, lo, hi, nlo, nhi); }
K32API BOOL WINAPI UnlockFileEx(HANDLE h, DWORD reserved, DWORD nlo, DWORD nhi, LPOVERLAPPED ov)
{
    if (reserved || !ov) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!unlock_range(h, ov->Offset, ov->OffsetHigh, nlo, nhi)) return FALSE;
    ov->Internal = 0;
    ov->InternalHigh = 0;
    if (ov->hEvent) NtSetEvent(ov->hEvent, 0);
    return TRUE;
}

/* ---------------------------------------------------------------- overlapped results and cancellation */
K32API BOOL WINAPI GetOverlappedResultEx(HANDLE h, LPOVERLAPPED ov, LPDWORD n, DWORD ms, BOOL alertable)
{
    NTSTATUS st;
    if (!ov) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = (NTSTATUS)ov->Internal;
    if (st == STATUS_PENDING) {                                                   /* only possible for requests that complete later */
        LARGE_INTEGER to;
        HANDLE ev = (HANDLE)((ULONG_PTR)ov->hEvent & ~(ULONG_PTR)1);
        HANDLE w = ev ? ev : h;
        NTSTATUS ws;
        if (!ms) { shz_set_last_error(ERROR_IO_INCOMPLETE); return FALSE; }
        to.QuadPart = -(LONGLONG)ms * 10000;
        ws = NtWaitForSingleObject(w, alertable != 0, ms == INFINITE ? 0 : &to);
        if (ws == STATUS_TIMEOUT) { shz_set_last_error(ERROR_IO_INCOMPLETE); return FALSE; }
        if (ws != STATUS_SUCCESS) { k32_nt_error(ws); return FALSE; }
        st = (NTSTATUS)ov->Internal;
    }
    if (n) *n = (DWORD)ov->InternalHigh;
    if (st == STATUS_PENDING) { shz_set_last_error(ERROR_IO_INCOMPLETE); return FALSE; }
    if (st < 0 && st != STATUS_END_OF_FILE) { k32_nt_error(st); return FALSE; }
    if (st == STATUS_END_OF_FILE) { shz_set_last_error(ERROR_HANDLE_EOF); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI GetOverlappedResult(HANDLE h, LPOVERLAPPED ov, LPDWORD n, BOOL wait)
{
    return GetOverlappedResultEx(h, ov, n, wait ? INFINITE : 0, FALSE);
}

K32API BOOL WINAPI CancelIo(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st = NtCancelIoFile(h, &io);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

/* CancelIoEx: the pending requests of the handle (from any thread), or the one issued with `ov`; ERROR_NOT_FOUND when there is
 * none. Cancelled requests complete with STATUS_CANCELLED (ERROR_OPERATION_ABORTED) through their event / completion port. */
K32API BOOL WINAPI CancelIoEx(HANDLE h, LPOVERLAPPED ov)
{
    SHZ_IO_STATUS_BLOCK io;
    NTSTATUS st = NtCancelIoFileEx(h, (SHZ_IO_STATUS_BLOCK *)ov, &io);
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI SetFileCompletionNotificationModes(HANDLE h, UCHAR flags)
{
    SHZ_IO_STATUS_BLOCK io;
    ULONG v = flags;
    NTSTATUS st;
    if (flags & ~(UCHAR)(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS | FILE_SKIP_SET_EVENT_ON_HANDLE)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtSetInformationFile(h, &io, &v, sizeof v, 41);                          /* FileIoCompletionNotificationInformation */
    if (!NT_SUCCESS(st)) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI AreFileApisANSI(void) { return TRUE; }                         /* the *A file functions take the ANSI (UTF-8) code page */
