/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: directory enumeration (FindFirstFile/FindNextFile/FindClose and the Ex and ANSI forms).
 *
 * The kernel lists a directory with NtQueryDirectoryFile(FileBothDirectoryInformation); the pattern is applied here. Wildcards are
 * the Win32 ones: '*' any run, '?' exactly one character, "*.*" matches every name, a trailing ".*" also matches a name without
 * extension and a trailing "." matches only names without one (DOS rules). Matching folds case (Unicode simple case mapping)
 * unless FIND_FIRST_EX_CASE_SENSITIVE is given. Directories other than the volume root start with the entries "." and ".."
 * (synthesised here, with the directory's own times); "." and ".." reported by the file system are ignored so they never appear twice.
 * FindExSearchLimitToDirectories filters the entries (it is advisory on Windows); FindExSearchLimitToDevices is not supported.
 */
#include "k32.h"
#include "nls_core.h"

#define FIND_MAGIC 0x444e4946u                               /* "FIND" */

typedef struct {
    ULONG magic;
    HANDLE dir;
    WCHAR pattern[260];
    int case_sensitive, dirs_only, basic, want_dots, dot_state;      /* dot_state: 0 nothing emitted, 1 "." emitted, 2 ".." emitted */
    struct { ULONGLONG create, access, write, change; ULONG attrs, pad; } dir_info;
    BYTE buf[4096];
    ULONG used, avail;
    int done;
} find_t;

/* A search handle is a live process-heap block carrying FIND_MAGIC; the heap is asked first, so a closed or foreign handle is never read. */
static find_t *find_of(HANDLE h)
{
    find_t *f = (find_t *)h;
    if (!h || h == INVALID_HANDLE_VALUE || ((uintptr_t)h & 15) || !RtlValidateHeap(ShzProcessHeap(), 0, h) || f->magic != FIND_MAGIC) return 0;
    return f;
}

/* ---------------------------------------------------------------- wildcard matching */
static uint32_t fold(WCHAR c, int cs) { return cs ? c : nls_upper(c); }

static int match_nt(const WCHAR *p, const WCHAR *s, int cs)
{
    const WCHAR *star = 0, *ss = 0;
    while (*s) {
        if (*p == '*') { star = p++; ss = s; continue; }
        if (*p == '?' || (*p && fold(*p, cs) == fold(*s, cs))) { ++p; ++s; continue; }
        if (star) { p = star + 1; s = ++ss; continue; }
        return 0;
    }
    while (*p == '*') ++p;
    return !*p;
}

static unsigned count_dots(const WCHAR *s, size_t n) { unsigned d = 0; size_t i; for (i = 0; i < n; ++i) if (s[i] == '.') ++d; return d; }

/* DOS rule: `pat[0..plen)` is the pattern without its trailing "." or ".*"; the name must not have more dots than that pattern. */
static int match_head(const WCHAR *pat, size_t plen, const WCHAR *name, int cs)
{
    WCHAR tmp[262];
    if (plen >= 260) return 0;
    memcpy(tmp, pat, plen * sizeof(WCHAR));
    tmp[plen] = 0;
    return count_dots(name, k32_wlen(name)) <= count_dots(tmp, plen) && match_nt(tmp, name, cs);
}

static int wild_match(const WCHAR *pat, const WCHAR *name, int cs)
{
    const size_t pl = k32_wlen(pat);
    if (!pl) return 0;
    if ((pl == 1 && pat[0] == '*') || (pl == 3 && pat[0] == '*' && pat[1] == '.' && pat[2] == '*')) return 1;
    if (match_nt(pat, name, cs)) return 1;
    if (pl >= 2 && pat[pl - 2] == '.' && pat[pl - 1] == '*') return match_head(pat, pl - 2, name, cs);
    if (pat[pl - 1] == '.') return match_head(pat, pl - 1, name, cs);
    return 0;
}

/* ---------------------------------------------------------------- enumeration */
static void fill_entry(const find_t *f, LPWIN32_FIND_DATAW out, ULONGLONG create, ULONGLONG access, ULONGLONG write, ULONGLONG size,
                       ULONG attrs, const WCHAR *name, ULONG nchars)
{
    memset(out, 0, sizeof *out);
    out->dwFileAttributes = attrs;
    out->ftCreationTime.dwLowDateTime = (DWORD)create; out->ftCreationTime.dwHighDateTime = (DWORD)(create >> 32);
    out->ftLastAccessTime.dwLowDateTime = (DWORD)access; out->ftLastAccessTime.dwHighDateTime = (DWORD)(access >> 32);
    out->ftLastWriteTime.dwLowDateTime = (DWORD)write; out->ftLastWriteTime.dwHighDateTime = (DWORD)(write >> 32);
    out->nFileSizeLow = (DWORD)size; out->nFileSizeHigh = (DWORD)(size >> 32);
    if (nchars > 259) nchars = 259;
    memcpy(out->cFileName, name, nchars * sizeof(WCHAR));
    out->cFileName[nchars] = 0;
    (void)f;                                                  /* cAlternateFileName stays empty: this file system has no 8.3 names */
}

static BOOL next_entry(find_t *f, LPWIN32_FIND_DATAW out)
{
    static const WCHAR dot[] = { '.', 0 }, dotdot[] = { '.', '.', 0 };
    while (f->want_dots && f->dot_state < 2) {
        const WCHAR *nm = f->dot_state == 0 ? dot : dotdot;
        ++f->dot_state;
        if (wild_match(f->pattern, nm, f->case_sensitive)) {
            fill_entry(f, out, f->dir_info.create, f->dir_info.access, f->dir_info.write, 0, FILE_ATTRIBUTE_DIRECTORY, nm, (ULONG)k32_wlen(nm));
            return TRUE;
        }
    }
    for (;;) {
        SHZ_IO_STATUS_BLOCK iosb;
        NTSTATUS st;
        const BYTE *e;
        ULONG next, attrs, nlen, n, i;
        WCHAR name[260];
        ULONGLONG create, access, write, eof;
        if (f->used >= f->avail) {
            if (f->done) { shz_set_last_error(ERROR_NO_MORE_FILES); return FALSE; }
            memset(&iosb, 0, sizeof iosb);
            st = NtQueryDirectoryFile(f->dir, 0, 0, 0, &iosb, f->buf, sizeof f->buf, 3, 0, 0, 0);
            if (st) {
                f->done = 1;
                shz_set_last_error(st == STATUS_NO_MORE_FILES || st == STATUS_NO_SUCH_FILE ? ERROR_NO_MORE_FILES : RtlNtStatusToDosError(st));
                return FALSE;
            }
            f->used = 0;
            f->avail = (ULONG)iosb.Information;
        }
        e = f->buf + f->used;
        next = *(const ULONG *)e;
        create = *(const ULONGLONG *)(e + 8);
        access = *(const ULONGLONG *)(e + 16);
        write = *(const ULONGLONG *)(e + 24);
        eof = *(const ULONGLONG *)(e + 40);
        attrs = *(const ULONG *)(e + 56);
        nlen = *(const ULONG *)(e + 60);
        n = nlen / 2;
        if (n > 259) n = 259;
        for (i = 0; i < n; ++i) name[i] = ((const WCHAR *)(e + 94))[i];         /* FILE_BOTH_DIR_INFORMATION.FileName */
        name[n] = 0;
        f->used = next ? f->used + next : f->avail;
        if ((n == 1 && name[0] == '.') || (n == 2 && name[0] == '.' && name[1] == '.')) continue;          /* synthesised above */
        if (f->dirs_only && !(attrs & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!wild_match(f->pattern, name, f->case_sensitive)) continue;
        fill_entry(f, out, create, access, write, eof, attrs, name, n);
        return TRUE;
    }
}

static int is_root_nt(const WCHAR *nt)                          /* "\??\C:" or "\??\C:\" */
{
    size_t n = k32_wlen(nt);
    if (n < 6) return 0;
    return n == 6 || (n == 7 && nt[6] == '\\');
}

K32API HANDLE WINAPI FindFirstFileExW(LPCWSTR spec, FINDEX_INFO_LEVELS level, LPVOID data, FINDEX_SEARCH_OPS op, LPVOID filter, DWORD flags)
{
    WCHAR dirpart[300], nt[320];
    size_t n, cut, i;
    find_t *f;
    NTSTATUS st;
    if (!spec || !data) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (!spec[0]) { shz_set_last_error(ERROR_PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if ((int)level != FindExInfoStandard && (int)level != FindExInfoBasic) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if ((int)op == FindExSearchLimitToDevices) { shz_set_last_error(ERROR_NOT_SUPPORTED); return INVALID_HANDLE_VALUE; }
    if ((int)op != FindExSearchNameMatch && (int)op != FindExSearchLimitToDirectories) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (filter || (flags & ~7u)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    n = k32_wlen(spec);
    if (n >= 300) { shz_set_last_error(ERROR_FILENAME_EXCED_RANGE); return INVALID_HANDLE_VALUE; }
    cut = n;
    while (cut && spec[cut - 1] != '\\' && spec[cut - 1] != '/' && spec[cut - 1] != ':') --cut;
    memcpy(dirpart, spec, cut * sizeof(WCHAR));
    if (!cut) { dirpart[0] = '.'; dirpart[1] = 0; } else dirpart[cut] = 0;
    f = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *f);
    if (!f) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    f->magic = FIND_MAGIC;
    f->case_sensitive = (flags & FIND_FIRST_EX_CASE_SENSITIVE) != 0;
    f->dirs_only = (int)op == FindExSearchLimitToDirectories;
    f->basic = (int)level == FindExInfoBasic;
    for (i = 0; cut + i <= n && i < 259; ++i) f->pattern[i] = spec[cut + i];
    st = k32_open_path(dirpart, FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_READ_ATTRIBUTES, FILE_OPEN_D, OPT_DIRECTORY, &f->dir, 0);
    if (st) {
        f->magic = 0;
        RtlFreeHeap(ShzProcessHeap(), 0, f);
        k32_nt_error(st == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_OBJECT_PATH_NOT_FOUND : st);
        return INVALID_HANDLE_VALUE;
    }
    {
        SHZ_IO_STATUS_BLOCK iosb;
        memset(&f->dir_info, 0, sizeof f->dir_info);
        f->dir_info.attrs = FILE_ATTRIBUTE_DIRECTORY;
        NtQueryInformationFile(f->dir, &iosb, &f->dir_info, sizeof f->dir_info, 4);           /* the directory's own times, for "." and ".." */
    }
    f->want_dots = k32_dos_to_nt(dirpart, nt, 320) == 0 && !is_root_nt(nt);
    if (!next_entry(f, (LPWIN32_FIND_DATAW)data)) {
        const DWORD e = shz_last_error();
        NtClose(f->dir);
        f->magic = 0;
        RtlFreeHeap(ShzProcessHeap(), 0, f);
        shz_set_last_error(e == ERROR_NO_MORE_FILES ? ERROR_FILE_NOT_FOUND : e);
        return INVALID_HANDLE_VALUE;
    }
    shz_set_last_error(0);
    return f;
}

K32API HANDLE WINAPI FindFirstFileW(LPCWSTR spec, LPWIN32_FIND_DATAW out)
{
    return FindFirstFileExW(spec, FindExInfoStandard, out, FindExSearchNameMatch, 0, 0);
}

K32API BOOL WINAPI FindNextFileW(HANDLE h, LPWIN32_FIND_DATAW out)
{
    find_t *f = find_of(h);
    if (!f) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    return next_entry(f, out);
}

K32API BOOL WINAPI FindClose(HANDLE h)
{
    find_t *f = find_of(h);
    if (!f) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    NtClose(f->dir);
    f->magic = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, f);
    return TRUE;
}

static void to_ansi(const WIN32_FIND_DATAW *w, LPWIN32_FIND_DATAA a)
{
    memcpy(a, w, offsetof(WIN32_FIND_DATAW, cFileName));
    if (k32_wide_to_utf8(w->cFileName, -1, a->cFileName, MAX_PATH) <= 0) a->cFileName[0] = 0;
    a->cAlternateFileName[0] = 0;
}

K32API HANDLE WINAPI FindFirstFileExA(LPCSTR spec, FINDEX_INFO_LEVELS level, LPVOID data, FINDEX_SEARCH_OPS op, LPVOID filter, DWORD flags)
{
    WCHAR w[300];
    WIN32_FIND_DATAW fw;
    HANDLE h;
    if (!spec || !data) { shz_set_last_error(ERROR_INVALID_PARAMETER); return INVALID_HANDLE_VALUE; }
    if (k32_utf8_to_wide(spec, -1, w, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return INVALID_HANDLE_VALUE; }
    h = FindFirstFileExW(w, level, &fw, op, filter, flags);
    if (h != INVALID_HANDLE_VALUE) to_ansi(&fw, (LPWIN32_FIND_DATAA)data);
    return h;
}
K32API HANDLE WINAPI FindFirstFileA(LPCSTR spec, LPWIN32_FIND_DATAA out) { return FindFirstFileExA(spec, FindExInfoStandard, out, FindExSearchNameMatch, 0, 0); }
K32API BOOL WINAPI FindNextFileA(HANDLE h, LPWIN32_FIND_DATAA out)
{
    WIN32_FIND_DATAW fw;
    if (!FindNextFileW(h, &fw)) return FALSE;
    to_ansi(&fw, out);
    return TRUE;
}
