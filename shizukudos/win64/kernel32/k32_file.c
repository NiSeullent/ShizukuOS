/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: files, directories, console handles and paths on top of the NT file API.
 * Paths are converted to NT form (\??\C:\...) in user mode, as on Windows; the kernel file
 * system is case-insensitive (ASCII folding) and UTF-8 internally. Overlapped I/O completes
 * synchronously (the OVERLAPPED offset is honoured, the event is signalled); true asynchronous
 * completion is not implemented and no function claims it.
 */
#include "k32.h"

#define FILE_OPEN_D 1
#define FILE_CREATE_D 2
#define FILE_OPEN_IF_D 3
#define FILE_OVERWRITE_D 4
#define FILE_OVERWRITE_IF_D 5
#define OPT_DIRECTORY 1
#define OPT_NON_DIRECTORY 0x40
#define OPT_DELETE_ON_CLOSE 0x1000
#define ATTR_DEVICE 0x40

size_t k32_wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

/* ---------------------------------------------------------------- current directory */
static WCHAR g_cwd[260];
static int g_cwd_init;

static void cwd_init(void)
{
    if (g_cwd_init) return;
    {
        const uint8_t *params = PEB_PARAMS(shz_peb());
        const USHORT len = *(const USHORT *)(params + 0x38) / 2;
        const WCHAR *buf = *(WCHAR *const *)(params + 0x40);
        size_t i;
        for (i = 0; i < len && i < 258; ++i) g_cwd[i] = buf[i];
        g_cwd[i] = 0;
        if (i && g_cwd[i - 1] != '\\') { g_cwd[i++] = '\\'; g_cwd[i] = 0; }
    }
    g_cwd_init = 1;
}

DWORD k32_current_directory(WCHAR *buf, DWORD cap)
{
    size_t n;
    cwd_init();
    n = k32_wlen(g_cwd);
    if (n > 3 && g_cwd[n - 1] == '\\') --n;                    /* GetCurrentDirectory omits a trailing separator (except "C:\") */
    if (cap <= n) return (DWORD)n + 1;
    memcpy(buf, g_cwd, n * sizeof(WCHAR));
    buf[n] = 0;
    return (DWORD)n;
}

K32API DWORD WINAPI GetCurrentDirectoryW(DWORD cap, LPWSTR buf) { return k32_current_directory(buf, cap); }
K32API DWORD WINAPI GetCurrentDirectoryA(DWORD cap, LPSTR buf)
{
    WCHAR w[260];
    DWORD n = k32_current_directory(w, 260), i;
    if (cap <= n) return n + 1;
    for (i = 0; i <= n; ++i) buf[i] = (char)w[i];
    return n;
}

/* ---------------------------------------------------------------- path conversion */
NTSTATUS k32_dos_to_nt(LPCWSTR dos, WCHAR *nt, size_t cap)
{
    size_t n = 0, i;
    static const WCHAR prefix[] = { '\\', '?', '?', '\\', 0 };
    WCHAR tmp[300];
    size_t t = 0;
    cwd_init();
    if (dos[0] == '\\' && dos[1] == '\\' && dos[2] == '?' && dos[3] == '\\') {       /* \\?\ verbatim */
        for (i = 4; dos[i] && t < 298; ++i) tmp[t++] = dos[i];
    } else if (dos[0] && dos[1] == ':') {
        for (i = 0; dos[i] && t < 298; ++i) tmp[t++] = dos[i];
    } else if (dos[0] == '\\' || dos[0] == '/') {                                    /* rooted on the current drive */
        tmp[t++] = 'C'; tmp[t++] = ':';
        for (i = 0; dos[i] && t < 298; ++i) tmp[t++] = dos[i];
    } else {
        for (i = 0; g_cwd[i] && t < 298; ++i) tmp[t++] = g_cwd[i];
        for (i = 0; dos[i] && t < 298; ++i) tmp[t++] = dos[i];
    }
    tmp[t] = 0;
    if (t >= 298) return STATUS_OBJECT_NAME_INVALID;
    for (i = 0; prefix[i]; ++i) nt[n++] = prefix[i];
    for (i = 0; tmp[i] && n + 1 < cap; ++i) nt[n++] = tmp[i] == '/' ? '\\' : tmp[i];
    nt[n] = 0;
    return STATUS_SUCCESS;
}

static NTSTATUS open_path(LPCWSTR dos, ACCESS_MASK access, ULONG disposition, ULONG options, HANDLE *h, ULONG_PTR *info)
{
    WCHAR nt[320];
    SHZ_UNICODE_STRING us;
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = k32_dos_to_nt(dos, nt, 320);
    if (st) return st;
    us.Buffer = nt;
    us.Length = (USHORT)(k32_wlen(nt) * 2);
    us.MaximumLength = us.Length + 2;
    memset(&oa, 0, sizeof oa);
    oa.Length = sizeof oa;
    oa.ObjectName = &us;
    memset(&iosb, 0, sizeof iosb);
    st = NtCreateFile(h, access, &oa, &iosb, 0, FILE_ATTRIBUTE_NORMAL, 3, disposition, options, 0, 0);
    if (info) *info = iosb.Information;
    return st;
}

static WCHAR *widen_str(const char *s, WCHAR *buf, size_t cap);
static int utf8_to_wide(const char *s, int n, WCHAR *w, int cap);
static int wide_to_utf8(const WCHAR *w, int n, char *s, int cap);

/* ---------------------------------------------------------------- CreateFile and friends */
K32API HANDLE WINAPI CreateFileW(LPCWSTR name, DWORD access, DWORD share, LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags,
                                 HANDLE tmpl)
{
    HANDLE h = INVALID_HANDLE_VALUE;
    ULONG d, opts = 0;
    ULONG_PTR info = 0;
    NTSTATUS st;
    static const WCHAR conout[] = { 'C','O','N','O','U','T','$',0 }, conin[] = { 'C','O','N','I','N','$',0 };
    (void)share; (void)sa; (void)tmpl;
    if (!name || !name[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    switch (disp) {
    case CREATE_NEW: d = FILE_CREATE_D; break;
    case CREATE_ALWAYS: d = FILE_OVERWRITE_IF_D; break;
    case OPEN_EXISTING: d = FILE_OPEN_D; break;
    case OPEN_ALWAYS: d = FILE_OPEN_IF_D; break;
    case TRUNCATE_EXISTING: d = FILE_OVERWRITE_D; break;
    default: shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE;
    }
    {
        const WCHAR *a = name, *b = conout, *c = conin;
        int is_out = 1, is_in = 1;
        while (*b) { if ((*a | 32) != (*b | 32)) is_out = 0; ++a; ++b; }
        a = name;
        while (*c) { if ((*a | 32) != (*c | 32)) is_in = 0; ++a; ++c; }
        if (is_out && !name[7]) name = L"\\??\\CONOUT$";
        else if (is_in && !name[6]) name = L"\\??\\CONIN$";
    }
    if (flags & FILE_FLAG_DELETE_ON_CLOSE) opts |= OPT_DELETE_ON_CLOSE;
    if (!(flags & FILE_FLAG_BACKUP_SEMANTICS)) opts |= OPT_NON_DIRECTORY;
    if (name[0] == '\\' && name[1] == '?' && name[2] == '?' && name[3] == '\\') {
        WCHAR nt[64];
        SHZ_UNICODE_STRING us;
        SHZ_OBJECT_ATTRIBUTES oa;
        SHZ_IO_STATUS_BLOCK iosb;
        size_t n = k32_wlen(name);
        memcpy(nt, name, (n + 1) * sizeof(WCHAR));
        us.Buffer = nt; us.Length = (USHORT)(n * 2); us.MaximumLength = us.Length + 2;
        memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us;
        st = NtCreateFile(&h, access, &oa, &iosb, 0, 0, 3, FILE_OPEN_D, 0, 0, 0);
    } else {
        st = open_path(name, access ? access : 0, d, opts, &h, &info);
    }
    if (st) { k32_nt_error(st); return INVALID_HANDLE_VALUE; }
    shz_set_last_error((info == 1 && (disp == CREATE_ALWAYS || disp == OPEN_ALWAYS)) || info == 3 ? ERROR_ALREADY_EXISTS : 0);
    return h;
}
K32API HANDLE WINAPI CreateFileA(LPCSTR name, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t)
{
    WCHAR w[300];
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    return CreateFileW(w, a, s, sa, d, f, t);
}

static NTSTATUS rw_file(HANDLE h, void *buf, DWORD len, DWORD *done, LPOVERLAPPED ov, int write)
{
    SHZ_IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;
    NTSTATUS st;
    memset(&iosb, 0, sizeof iosb);
    if (ov) {
        off.QuadPart = ((LONGLONG)ov->OffsetHigh << 32) | ov->Offset;
        st = write ? NtWriteFile(h, 0, 0, 0, &iosb, buf, len, &off, 0) : NtReadFile(h, 0, 0, 0, &iosb, buf, len, &off, 0);
        ov->Internal = (ULONG_PTR)st;
        ov->InternalHigh = iosb.Information;
        if (ov->hEvent) NtSetEvent(ov->hEvent, 0);
    } else {
        st = write ? NtWriteFile(h, 0, 0, 0, &iosb, buf, len, 0, 0) : NtReadFile(h, 0, 0, 0, &iosb, buf, len, 0, 0);
    }
    if (done) *done = (DWORD)iosb.Information;
    return st;
}

K32API BOOL WINAPI ReadFile(HANDLE h, LPVOID buf, DWORD len, LPDWORD done, LPOVERLAPPED ov)
{
    NTSTATUS st = rw_file(h, buf, len, done, ov, 0);
    if (st == STATUS_END_OF_FILE) { if (done) *done = 0; shz_set_last_error(0); return TRUE; }   /* EOF is success with 0 bytes */
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI WriteFile(HANDLE h, LPCVOID buf, DWORD len, LPDWORD done, LPOVERLAPPED ov)
{
    NTSTATUS st = rw_file(h, (void *)buf, len, done, ov, 1);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetFileSizeEx(HANDLE h, PLARGE_INTEGER size)
{
    struct { LONGLONG alloc, eof; ULONG links; BYTE del, dir; WORD pad; } s;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = NtQueryInformationFile(h, &iosb, &s, sizeof s, 5);
    if (st) { k32_nt_error(st); return FALSE; }
    size->QuadPart = s.eof;
    return TRUE;
}
K32API DWORD WINAPI GetFileSize(HANDLE h, LPDWORD high)
{
    LARGE_INTEGER li;
    if (!GetFileSizeEx(h, &li)) return INVALID_FILE_SIZE;
    if (high) *high = (DWORD)(li.QuadPart >> 32);
    shz_set_last_error(0);
    return (DWORD)li.QuadPart;
}

K32API BOOL WINAPI SetFilePointerEx(HANDLE h, LARGE_INTEGER dist, PLARGE_INTEGER newpos, DWORD method)
{
    SHZ_IO_STATUS_BLOCK iosb;
    LONGLONG base = 0, pos;
    NTSTATUS st;
    if (method == FILE_CURRENT) {
        st = NtQueryInformationFile(h, &iosb, &base, 8, 14);
        if (st) { k32_nt_error(st); return FALSE; }
    } else if (method == FILE_END) {
        LARGE_INTEGER sz;
        if (!GetFileSizeEx(h, &sz)) return FALSE;
        base = sz.QuadPart;
    } else if (method != FILE_BEGIN) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pos = base + dist.QuadPart;
    if (pos < 0) { shz_set_last_error(ERROR_NEGATIVE_SEEK); return FALSE; }
    st = NtSetInformationFile(h, &iosb, &pos, 8, 14);
    if (st) { k32_nt_error(st); return FALSE; }
    if (newpos) newpos->QuadPart = pos;
    return TRUE;
}
K32API DWORD WINAPI SetFilePointer(HANDLE h, LONG lo, PLONG hi, DWORD method)
{
    LARGE_INTEGER d, np;
    d.QuadPart = ((LONGLONG)(hi ? *hi : (lo < 0 ? -1 : 0)) << 32) | (DWORD)lo;
    if (!SetFilePointerEx(h, d, &np, method)) return INVALID_SET_FILE_POINTER;
    if (hi) *hi = (LONG)(np.QuadPart >> 32);
    shz_set_last_error(0);
    return (DWORD)np.QuadPart;
}
K32API BOOL WINAPI SetEndOfFile(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    LONGLONG pos;
    NTSTATUS st = NtQueryInformationFile(h, &iosb, &pos, 8, 14);
    if (!st) st = NtSetInformationFile(h, &iosb, &pos, 8, 20);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI FlushFileBuffers(HANDLE h)
{
    SHZ_IO_STATUS_BLOCK iosb;
    LONGLONG dummy;
    NTSTATUS st = NtQueryInformationFile(h, &iosb, &dummy, 8, 14);      /* validates the handle; the RAM file system has no cache */
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}

K32API DWORD WINAPI GetFileType(HANDLE h)
{
    struct { ULONGLONG c, a, w, ch; ULONG attrs, pad; } b;
    SHZ_IO_STATUS_BLOCK iosb;
    if (NtQueryInformationFile(h, &iosb, &b, sizeof b, 4)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FILE_TYPE_UNKNOWN; }
    shz_set_last_error(0);
    return (b.attrs & ATTR_DEVICE) ? FILE_TYPE_CHAR : FILE_TYPE_DISK;
}

/* ---------------------------------------------------------------- attributes, delete, rename, directories */
K32API DWORD WINAPI GetFileAttributesW(LPCWSTR name)
{
    HANDLE h;
    struct { ULONGLONG c, a, w, ch; ULONG attrs, pad; } b;
    SHZ_IO_STATUS_BLOCK iosb;
    NTSTATUS st = open_path(name, FILE_READ_ATTRIBUTES, FILE_OPEN_D, 0, &h, 0);
    if (st) { k32_nt_error(st); return INVALID_FILE_ATTRIBUTES; }
    st = NtQueryInformationFile(h, &iosb, &b, sizeof b, 4);
    NtClose(h);
    if (st) { k32_nt_error(st); return INVALID_FILE_ATTRIBUTES; }
    return b.attrs;
}
K32API DWORD WINAPI GetFileAttributesA(LPCSTR name)
{
    WCHAR w[300];
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_FILE_ATTRIBUTES; }
    return GetFileAttributesW(w);
}

K32API BOOL WINAPI DeleteFileW(LPCWSTR name)
{
    HANDLE h;
    SHZ_IO_STATUS_BLOCK iosb;
    BYTE del = 1;
    NTSTATUS st = open_path(name, DELETE, FILE_OPEN_D, OPT_NON_DIRECTORY, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    st = NtSetInformationFile(h, &iosb, &del, 1, 13);
    NtClose(h);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI DeleteFileA(LPCSTR name)
{
    WCHAR w[300];
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return DeleteFileW(w);
}

K32API BOOL WINAPI MoveFileExW(LPCWSTR from, LPCWSTR to, DWORD flags)
{
    HANDLE h;
    SHZ_IO_STATUS_BLOCK iosb;
    WCHAR nt[320];
    struct { BYTE replace, pad[7]; HANDLE root; ULONG len; WCHAR name[300]; } ri;
    NTSTATUS st;
    size_t n;
    st = open_path(from, DELETE, FILE_OPEN_D, 0, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    st = k32_dos_to_nt(to, nt, 320);
    if (st) { NtClose(h); k32_nt_error(st); return FALSE; }
    n = k32_wlen(nt);
    memset(&ri, 0, sizeof ri);
    ri.replace = (flags & MOVEFILE_REPLACE_EXISTING) != 0;
    ri.len = (ULONG)(n * 2);
    memcpy(ri.name, nt, n * sizeof(WCHAR));
    st = NtSetInformationFile(h, &iosb, &ri, (ULONG)(20 + n * 2), 10);
    NtClose(h);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI MoveFileW(LPCWSTR a, LPCWSTR b) { return MoveFileExW(a, b, 0); }
K32API BOOL WINAPI MoveFileA(LPCSTR a, LPCSTR b)
{
    WCHAR wa[300], wb[300];
    if (utf8_to_wide(a, -1, wa, 300) <= 0 || utf8_to_wide(b, -1, wb, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return MoveFileW(wa, wb);
}

K32API BOOL WINAPI CreateDirectoryW(LPCWSTR name, LPSECURITY_ATTRIBUTES sa)
{
    HANDLE h;
    NTSTATUS st = open_path(name, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_CREATE_D, OPT_DIRECTORY, &h, 0);
    (void)sa;
    if (st) { k32_nt_error(st); return FALSE; }
    NtClose(h);
    return TRUE;
}
K32API BOOL WINAPI CreateDirectoryA(LPCSTR name, LPSECURITY_ATTRIBUTES sa)
{
    WCHAR w[300];
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return CreateDirectoryW(w, sa);
}
K32API BOOL WINAPI RemoveDirectoryW(LPCWSTR name)
{
    HANDLE h;
    SHZ_IO_STATUS_BLOCK iosb;
    BYTE del = 1;
    NTSTATUS st = open_path(name, DELETE, FILE_OPEN_D, OPT_DIRECTORY, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    st = NtSetInformationFile(h, &iosb, &del, 1, 13);
    NtClose(h);
    if (st) { k32_nt_error(st); return FALSE; }
    return TRUE;
}
K32API BOOL WINAPI RemoveDirectoryA(LPCSTR name)
{
    WCHAR w[300];
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return RemoveDirectoryW(w);
}

K32API BOOL WINAPI SetCurrentDirectoryW(LPCWSTR dir)
{
    WCHAR nt[320];
    HANDLE h;
    size_t n, i, o = 0;
    NTSTATUS st = open_path(dir, FILE_LIST_DIRECTORY, FILE_OPEN_D, OPT_DIRECTORY, &h, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    NtClose(h);
    st = k32_dos_to_nt(dir, nt, 320);
    if (st) { k32_nt_error(st); return FALSE; }
    n = k32_wlen(nt);
    cwd_init();
    for (i = 4; i < n && o < 257; ++i) g_cwd[o++] = nt[i];
    if (o && g_cwd[o - 1] != '\\') g_cwd[o++] = '\\';
    g_cwd[o] = 0;
    return TRUE;
}

/* ---------------------------------------------------------------- FindFirstFile */
typedef struct {
    HANDLE dir;
    WCHAR pattern[260];
    BYTE buf[4096];
    ULONG used, avail;
    int done;
} find_t;

static int wild_match(const WCHAR *p, const WCHAR *s)
{
    for (;;) {
        WCHAR pc = *p, sc = *s;
        if (pc == '*') { while (*p == '*') ++p; if (!*p) return 1; for (; *s; ++s) if (wild_match(p, s)) return 1; return wild_match(p, s); }
        if (!pc) return !sc;
        if (!sc) return 0;
        if (pc != '?' && (pc | 32) != (sc | 32)) return 0;
        ++p; ++s;
    }
}

static BOOL fill_find(find_t *f, LPWIN32_FIND_DATAW out)
{
    for (;;) {
        SHZ_IO_STATUS_BLOCK iosb;
        NTSTATUS st;
        if (f->used >= f->avail) {
            if (f->done) return FALSE;
            memset(&iosb, 0, sizeof iosb);
            st = NtQueryDirectoryFile(f->dir, 0, 0, 0, &iosb, f->buf, sizeof f->buf, 3, 0, 0, 0);
            if (st) { f->done = 1; shz_set_last_error(st == STATUS_NO_MORE_FILES || st == STATUS_NO_SUCH_FILE ? ERROR_NO_MORE_FILES : RtlNtStatusToDosError(st)); return FALSE; }
            f->used = 0;
            f->avail = (ULONG)iosb.Information;
        }
        {
            const BYTE *e = f->buf + f->used;
            const ULONG next = *(const ULONG *)e;
            const ULONGLONG create = *(const ULONGLONG *)(e + 8), wr = *(const ULONGLONG *)(e + 24), eof = *(const ULONGLONG *)(e + 40);
            const ULONG attrs = *(const ULONG *)(e + 56), nlen = *(const ULONG *)(e + 60);
            const WCHAR *name = (const WCHAR *)(e + 92);
            WCHAR tmp[260];
            ULONG i, n = nlen / 2;
            if (n > 259) n = 259;
            for (i = 0; i < n; ++i) tmp[i] = name[i];
            tmp[n] = 0;
            f->used = next ? f->used + next : f->avail;
            if (!wild_match(f->pattern, tmp)) continue;
            memset(out, 0, sizeof *out);
            out->dwFileAttributes = attrs;
            out->ftCreationTime.dwLowDateTime = (DWORD)create; out->ftCreationTime.dwHighDateTime = (DWORD)(create >> 32);
            out->ftLastWriteTime.dwLowDateTime = (DWORD)wr; out->ftLastWriteTime.dwHighDateTime = (DWORD)(wr >> 32);
            out->ftLastAccessTime = out->ftLastWriteTime;
            out->nFileSizeLow = (DWORD)eof; out->nFileSizeHigh = (DWORD)(eof >> 32);
            memcpy(out->cFileName, tmp, (n + 1) * sizeof(WCHAR));
            return TRUE;
        }
    }
}

K32API HANDLE WINAPI FindFirstFileW(LPCWSTR spec, LPWIN32_FIND_DATAW out)
{
    WCHAR dirpart[300];
    size_t n = k32_wlen(spec), cut = n, i;
    find_t *f;
    NTSTATUS st;
    if (n >= 300) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return INVALID_HANDLE_VALUE; }
    while (cut && spec[cut - 1] != '\\' && spec[cut - 1] != '/' && spec[cut - 1] != ':') --cut;
    memcpy(dirpart, spec, cut * sizeof(WCHAR));
    if (!cut) { dirpart[0] = '.'; dirpart[1] = 0; } else dirpart[cut] = 0;
    f = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *f);
    if (!f) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    for (i = 0; cut + i <= n && i < 259; ++i) f->pattern[i] = spec[cut + i];
    st = open_path(dirpart, FILE_LIST_DIRECTORY | SYNCHRONIZE, FILE_OPEN_D, OPT_DIRECTORY, &f->dir, 0);
    if (st) { RtlFreeHeap(ShzProcessHeap(), 0, f); k32_nt_error(st == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_OBJECT_PATH_NOT_FOUND : st); return INVALID_HANDLE_VALUE; }
    if (!fill_find(f, out)) {
        DWORD e = shz_last_error();
        NtClose(f->dir); RtlFreeHeap(ShzProcessHeap(), 0, f);
        shz_set_last_error(e == ERROR_NO_MORE_FILES ? ERROR_FILE_NOT_FOUND : e);
        return INVALID_HANDLE_VALUE;
    }
    return f;
}
K32API BOOL WINAPI FindNextFileW(HANDLE h, LPWIN32_FIND_DATAW out) { return fill_find((find_t *)h, out); }
K32API BOOL WINAPI FindClose(HANDLE h)
{
    find_t *f = (find_t *)h;
    if (!f || f == INVALID_HANDLE_VALUE) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    NtClose(f->dir);
    RtlFreeHeap(ShzProcessHeap(), 0, f);
    return TRUE;
}
K32API HANDLE WINAPI FindFirstFileA(LPCSTR spec, LPWIN32_FIND_DATAA out)
{
    WCHAR w[300];
    WIN32_FIND_DATAW fw;
    HANDLE h;
    if (utf8_to_wide(spec, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    h = FindFirstFileW(w, &fw);
    if (h == INVALID_HANDLE_VALUE) return h;
    memcpy(out, &fw, offsetof(WIN32_FIND_DATAW, cFileName));
    wide_to_utf8(fw.cFileName, -1, out->cFileName, MAX_PATH);
    out->cAlternateFileName[0] = 0;
    return h;
}
K32API BOOL WINAPI FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA out)
{
    WIN32_FIND_DATAW fw;
    if (!FindNextFileW(h, &fw)) return FALSE;
    memcpy(out, &fw, offsetof(WIN32_FIND_DATAW, cFileName));
    wide_to_utf8(fw.cFileName, -1, out->cFileName, MAX_PATH);
    out->cAlternateFileName[0] = 0;
    return TRUE;
}

/* ---------------------------------------------------------------- paths */
K32API DWORD WINAPI GetFullPathNameW(LPCWSTR name, DWORD cap, LPWSTR buf, LPWSTR *part)
{
    WCHAR tmp[320], out[320];
    size_t n = 0, i, o = 0;
    cwd_init();
    if (name[0] && name[1] == ':') { for (i = 0; name[i] && n < 318; ++i) tmp[n++] = name[i] == '/' ? '\\' : name[i]; }
    else if (name[0] == '\\' || name[0] == '/') { tmp[n++] = 'C'; tmp[n++] = ':'; for (i = 0; name[i] && n < 318; ++i) tmp[n++] = name[i] == '/' ? '\\' : name[i]; }
    else { for (i = 0; g_cwd[i] && n < 300; ++i) tmp[n++] = g_cwd[i]; for (i = 0; name[i] && n < 318; ++i) tmp[n++] = name[i] == '/' ? '\\' : name[i]; }
    tmp[n] = 0;
    /* normalise "." and ".." components after the drive root */
    out[o++] = tmp[0]; out[o++] = tmp[1]; out[o++] = '\\';
    i = 3;
    while (i < n) {
        size_t s = i, len;
        while (i < n && tmp[i] != '\\') ++i;
        len = i - s;
        if (i < n) ++i;
        if (len == 0 || (len == 1 && tmp[s] == '.')) continue;
        if (len == 2 && tmp[s] == '.' && tmp[s + 1] == '.') { if (o > 3) { --o; while (o > 3 && out[o - 1] != '\\') --o; } continue; }
        memcpy(out + o, tmp + s, len * sizeof(WCHAR));
        o += len;
        if (i <= n && (i < n || tmp[n - 1] == '\\')) out[o++] = '\\';
    }
    if (o > 3 && out[o - 1] == '\\' && !(n && tmp[n - 1] == '\\')) --o;
    out[o] = 0;
    if (cap <= o) return (DWORD)o + 1;
    memcpy(buf, out, (o + 1) * sizeof(WCHAR));
    if (part) { size_t k = o; while (k && buf[k - 1] != '\\') --k; *part = (o && buf[o - 1] != '\\') ? buf + k : 0; }
    return (DWORD)o;
}
K32API DWORD WINAPI GetFullPathNameA(LPCSTR name, DWORD cap, LPSTR buf, LPSTR *part)
{
    WCHAR w[300], o[320];
    DWORD n;
    if (utf8_to_wide(name, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    n = GetFullPathNameW(w, 320, o, 0);
    if (!n || n >= 320) return n;
    if (cap <= n) return n + 1;
    wide_to_utf8(o, -1, buf, (int)cap);
    if (part) { DWORD k = n; while (k && buf[k - 1] != '\\') --k; *part = buf[n - 1] != '\\' ? buf + k : 0; }
    return n;
}
K32API DWORD WINAPI GetTempPathW(DWORD cap, LPWSTR buf)
{
    static const WCHAR t[] = { 'C', ':', '\\', 'T', 'E', 'M', 'P', '\\', 0 };
    if (cap <= 8) return 9;
    memcpy(buf, t, sizeof t);
    return 8;
}
K32API DWORD WINAPI GetTempPathA(DWORD cap, LPSTR buf)
{
    static const char t[] = "C:\\TEMP\\";
    if (cap <= 8) return 9;
    memcpy(buf, t, sizeof t);
    return 8;
}
K32API UINT WINAPI GetWindowsDirectoryA(LPSTR buf, UINT cap) { static const char t[] = "C:\\SHZ"; if (cap < sizeof t) return sizeof t; memcpy(buf, t, sizeof t); return sizeof t - 1; }
K32API UINT WINAPI GetSystemDirectoryA(LPSTR buf, UINT cap) { static const char t[] = "C:\\SHZ\\SYS64"; if (cap < sizeof t) return sizeof t; memcpy(buf, t, sizeof t); return sizeof t - 1; }
K32API UINT WINAPI GetWindowsDirectoryW(LPWSTR buf, UINT cap) { char a[16]; UINT n = GetWindowsDirectoryA(a, sizeof a); DWORD i; if (cap <= n) return n + 1; for (i = 0; i <= n; ++i) buf[i] = a[i]; return n; }
K32API UINT WINAPI GetSystemDirectoryW(LPWSTR buf, UINT cap) { char a[32]; UINT n = GetSystemDirectoryA(a, sizeof a); DWORD i; if (cap <= n) return n + 1; for (i = 0; i <= n; ++i) buf[i] = a[i]; return n; }

K32API BOOL WINAPI CopyFileW(LPCWSTR from, LPCWSTR to, BOOL fail_if_exists)
{
    HANDLE in, out;
    BYTE *buf;
    DWORD got, put;
    BOOL ok = TRUE;
    in = CreateFileW(from, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
    if (in == INVALID_HANDLE_VALUE) return FALSE;
    out = CreateFileW(to, GENERIC_WRITE, 0, 0, fail_if_exists ? CREATE_NEW : CREATE_ALWAYS, 0, 0);
    if (out == INVALID_HANDLE_VALUE) { NtClose(in); return FALSE; }
    buf = RtlAllocateHeap(ShzProcessHeap(), 0, 65536);
    if (!buf) { NtClose(in); NtClose(out); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    for (;;) {
        if (!ReadFile(in, buf, 65536, &got, 0)) { ok = FALSE; break; }
        if (!got) break;
        if (!WriteFile(out, buf, got, &put, 0) || put != got) { ok = FALSE; break; }
    }
    RtlFreeHeap(ShzProcessHeap(), 0, buf);
    NtClose(in);
    NtClose(out);
    return ok;
}

/* ---------------------------------------------------------------- standard handles and console */
static ULONG_PTR console_mode[3] = { 0x1f7, 3, 3 };
static int std_index(HANDLE h)
{
    const uint8_t *params = PEB_PARAMS(shz_peb());
    int i;
    for (i = 0; i < 3; ++i)
        if (h == *(HANDLE *)(params + 0x20 + i * 8)) return i;
    return -1;
}
K32API HANDLE WINAPI GetStdHandle(DWORD which)
{
    const uint8_t *params = PEB_PARAMS(shz_peb());
    HANDLE h;
    switch (which) {
    case STD_INPUT_HANDLE: h = *(HANDLE *)(params + 0x20); break;
    case STD_OUTPUT_HANDLE: h = *(HANDLE *)(params + 0x28); break;
    case STD_ERROR_HANDLE: h = *(HANDLE *)(params + 0x30); break;
    default: shz_set_last_error(ERROR_INVALID_HANDLE); return INVALID_HANDLE_VALUE;
    }
    return h ? h : INVALID_HANDLE_VALUE;
}
K32API BOOL WINAPI SetStdHandle(DWORD which, HANDLE h)
{
    uint8_t *params = PEB_PARAMS(shz_peb());
    switch (which) {
    case STD_INPUT_HANDLE: *(HANDLE *)(params + 0x20) = h; return TRUE;
    case STD_OUTPUT_HANDLE: *(HANDLE *)(params + 0x28) = h; return TRUE;
    case STD_ERROR_HANDLE: *(HANDLE *)(params + 0x30) = h; return TRUE;
    default: shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE;
    }
}
static int is_console(HANDLE h)
{
    struct { ULONGLONG c, a, w, ch; ULONG attrs, pad; } b;
    SHZ_IO_STATUS_BLOCK iosb;
    return NtQueryInformationFile(h, &iosb, &b, sizeof b, 4) == 0 && (b.attrs & ATTR_DEVICE);
}
K32API BOOL WINAPI GetConsoleMode(HANDLE h, LPDWORD mode)
{
    int i = std_index(h);
    if (!is_console(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    *mode = (DWORD)console_mode[i < 0 ? 1 : i];
    return TRUE;
}
K32API BOOL WINAPI SetConsoleMode(HANDLE h, DWORD mode)
{
    int i = std_index(h);
    if (!is_console(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    console_mode[i < 0 ? 1 : i] = mode;
    return TRUE;
}
K32API BOOL WINAPI WriteConsoleA(HANDLE h, const VOID *buf, DWORD n, LPDWORD written, LPVOID reserved)
{
    (void)reserved;
    if (!is_console(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    return WriteFile(h, buf, n, written, 0);
}
K32API BOOL WINAPI WriteConsoleW(HANDLE h, const VOID *buf, DWORD n, LPDWORD written, LPVOID reserved)
{
    char tmp[1024];
    const WCHAR *w = buf;
    DWORD done = 0, off = 0;
    (void)reserved;
    if (!is_console(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    while (off < n) {
        DWORD chunk = n - off > 250 ? 250 : n - off, put;
        int len = wide_to_utf8(w + off, (int)chunk, tmp, sizeof tmp);
        if (len <= 0) break;
        if (!WriteFile(h, tmp, (DWORD)len - 1, &put, 0)) return FALSE;
        off += chunk;
        done += chunk;
    }
    if (written) *written = done;
    return TRUE;
}
K32API BOOL WINAPI ReadConsoleA(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPVOID ctl)
{
    (void)ctl;
    if (!is_console(h)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    return ReadFile(h, buf, n, got, 0);
}
K32API UINT WINAPI GetConsoleCP(void) { return 65001; }
K32API UINT WINAPI GetConsoleOutputCP(void) { return 65001; }
K32API BOOL WINAPI SetConsoleOutputCP(UINT cp) { if (cp != 65001 && cp != 437) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; } return cp == 65001; }
K32API BOOL WINAPI SetConsoleCP(UINT cp) { return cp == 65001; }

/* ---------------------------------------------------------------- UTF-8 <-> UTF-16 helpers used above */
static int utf8_to_wide(const char *s, int n, WCHAR *w, int cap)
{
    int o = 0, i = 0;
    if (n < 0) { n = 0; while (s[n]) ++n; ++n; }
    while (i < n) {
        unsigned c = (unsigned char)s[i++];
        unsigned cp;
        if (c < 0x80) cp = c;
        else if ((c & 0xe0) == 0xc0 && i < n) { cp = ((c & 0x1f) << 6) | (s[i++] & 0x3f); }
        else if ((c & 0xf0) == 0xe0 && i + 1 < n) { cp = ((c & 0x0f) << 12) | ((s[i] & 0x3f) << 6) | (s[i + 1] & 0x3f); i += 2; }
        else if ((c & 0xf8) == 0xf0 && i + 2 < n) { cp = ((c & 7) << 18) | ((s[i] & 0x3f) << 12) | ((s[i + 1] & 0x3f) << 6) | (s[i + 2] & 0x3f); i += 3; }
        else cp = 0xfffd;
        if (cp >= 0x10000) {
            if (o + 2 > cap) return 0;
            cp -= 0x10000;
            w[o++] = (WCHAR)(0xd800 + (cp >> 10));
            w[o++] = (WCHAR)(0xdc00 + (cp & 0x3ff));
        } else {
            if (o + 1 > cap) return 0;
            w[o++] = (WCHAR)cp;
        }
    }
    return o;
}
static int wide_to_utf8(const WCHAR *w, int n, char *s, int cap)
{
    int o = 0, i = 0;
    if (n < 0) { n = 0; while (w[n]) ++n; ++n; }
    while (i < n) {
        unsigned cp = w[i++];
        if (cp >= 0xd800 && cp < 0xdc00 && i < n && w[i] >= 0xdc00 && w[i] < 0xe000) cp = 0x10000 + ((cp - 0xd800) << 10) + (w[i++] - 0xdc00);
        if (cp < 0x80) { if (o + 1 > cap) return 0; s[o++] = (char)cp; }
        else if (cp < 0x800) { if (o + 2 > cap) return 0; s[o++] = (char)(0xc0 | (cp >> 6)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
        else if (cp < 0x10000) { if (o + 3 > cap) return 0; s[o++] = (char)(0xe0 | (cp >> 12)); s[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
        else { if (o + 4 > cap) return 0; s[o++] = (char)(0xf0 | (cp >> 18)); s[o++] = (char)(0x80 | ((cp >> 12) & 0x3f)); s[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
    }
    return o;
}
static WCHAR *widen_str(const char *s, WCHAR *buf, size_t cap) { int n = utf8_to_wide(s, -1, buf, (int)cap); if (n <= 0) buf[0] = 0; return buf; }

/* exported through k32_misc.c */
int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap) { return utf8_to_wide(s, n, w, cap); }
int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap) { return wide_to_utf8(w, n, s, cap); }
