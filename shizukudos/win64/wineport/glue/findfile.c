/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: FindFirstFileW / FindNextFileW / FindClose for the Wine modules.
 *
 * Why: the Shizuku kernel writes FILE_BOTH_DIR_INFORMATION with FileName at offset 96 (sizeof of its padded struct)
 * and the Shizuku kernel32 reads it at offset 92; Windows puts it at 94. The two disagree, so kernel32's FindFirstFileW
 * returns every entry with an empty cFileName (and patterns other than "*" never match). Until that is fixed there,
 * the Wine modules (DirectWrite enumerates %WINDIR%\Fonts) use this enumeration, which reads the documented offset 94
 * and falls back to 96 only when the documented position holds the padding of the current kernel (a file name never
 * starts with U+0000), so it keeps working once the kernel follows the Windows layout.
 * Matching: '*' and '?' wildcards, case-insensitive (ASCII folding); "*.*" matches every name.
 */
#include <stdarg.h>
#include <string.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"

#define FIND_MAGIC 0x444e4946u                       /* "FIND" */

struct find
{
    DWORD magic;
    HANDLE dir;
    ULONG used, avail;
    BOOL done;
    WCHAR pattern[MAX_PATH];
    BYTE buf[8192];
};

static WCHAR fold(WCHAR c) { return c >= 'a' && c <= 'z' ? (WCHAR)(c - 32) : c; }

static BOOL match(const WCHAR *p, const WCHAR *s)
{
    if (!wcscmp(p, L"*.*") || !wcscmp(p, L"*")) return TRUE;
    while (*p)
    {
        if (*p == '*')
        {
            while (*p == '*') p++;
            if (!*p) return TRUE;
            for (; *s; s++) if (match(p, s)) return TRUE;
            return FALSE;
        }
        if (!*s || (*p != '?' && fold(*p) != fold(*s))) return FALSE;
        p++;
        s++;
    }
    return !*s;
}

static BOOL next_entry(struct find *f, WIN32_FIND_DATAW *out)
{
    for (;;)
    {
        IO_STATUS_BLOCK iosb;
        const BYTE *e;
        ULONG next, len, n;
        const WCHAR *name;
        WCHAR tmp[MAX_PATH];
        NTSTATUS st;

        if (f->used >= f->avail)
        {
            if (f->done) { SetLastError(ERROR_NO_MORE_FILES); return FALSE; }
            memset(&iosb, 0, sizeof(iosb));
            st = NtQueryDirectoryFile(f->dir, NULL, NULL, NULL, &iosb, f->buf, sizeof(f->buf), FileBothDirectoryInformation,
                                      FALSE, NULL, FALSE);
            if (st)
            {
                f->done = TRUE;
                SetLastError(st == STATUS_NO_MORE_FILES || st == STATUS_NO_SUCH_FILE ? ERROR_NO_MORE_FILES
                                                                                     : RtlNtStatusToDosError(st));
                return FALSE;
            }
            f->used = 0;
            f->avail = (ULONG)iosb.Information;
        }
        e = f->buf + f->used;
        next = *(const ULONG *)e;
        len = *(const ULONG *)(e + 60) / sizeof(WCHAR);
        name = (const WCHAR *)(e + 94);                         /* FILE_BOTH_DIR_INFORMATION.FileName (Windows) */
        if (len && !name[0] && ((const WCHAR *)(e + 96))[0]) name = (const WCHAR *)(e + 96);  /* current Shizuku kernel */
        n = len < MAX_PATH - 1 ? len : MAX_PATH - 1;
        memcpy(tmp, name, n * sizeof(WCHAR));
        tmp[n] = 0;
        f->used = next ? f->used + next : f->avail;
        if (!match(f->pattern, tmp)) continue;
        memset(out, 0, sizeof(*out));
        out->dwFileAttributes = *(const ULONG *)(e + 56);
        memcpy(&out->ftCreationTime, e + 8, sizeof(FILETIME));
        memcpy(&out->ftLastAccessTime, e + 16, sizeof(FILETIME));
        memcpy(&out->ftLastWriteTime, e + 24, sizeof(FILETIME));
        out->nFileSizeLow = *(const DWORD *)(e + 40);
        out->nFileSizeHigh = *(const DWORD *)(e + 44);
        memcpy(out->cFileName, tmp, (n + 1) * sizeof(WCHAR));
        return TRUE;
    }
}

HANDLE WINAPI FindFirstFileExW(LPCWSTR spec, FINDEX_INFO_LEVELS level, void *data, FINDEX_SEARCH_OPS op, void *filter,
                               DWORD flags)
{
    WCHAR full[MAX_PATH], nt[MAX_PATH + 8], *slash;
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    struct find *f;
    NTSTATUS st;
    DWORD n;

    if (!spec || !data || (level != FindExInfoStandard && level != FindExInfoBasic))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return INVALID_HANDLE_VALUE;
    }
    n = GetFullPathNameW(spec, MAX_PATH, full, NULL);
    if (!n || n >= MAX_PATH) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return INVALID_HANDLE_VALUE; }
    if (!(slash = wcsrchr(full, '\\'))) { SetLastError(ERROR_PATH_NOT_FOUND); return INVALID_HANDLE_VALUE; }
    if (!(f = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*f)))) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return INVALID_HANDLE_VALUE; }
    wcscpy(f->pattern, slash + 1);
    if (!f->pattern[0]) wcscpy(f->pattern, L"*");
    if (slash == full + 2 && full[1] == ':') slash++;           /* keep "C:\" for the root */
    *slash = 0;
    wcscpy(nt, L"\\??\\");
    wcscat(nt, full);
    RtlInitUnicodeString(&us, nt);
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    st = NtCreateFile(&f->dir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                      FILE_OPEN, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (st)
    {
        HeapFree(GetProcessHeap(), 0, f);
        SetLastError(st == STATUS_OBJECT_NAME_NOT_FOUND ? ERROR_PATH_NOT_FOUND : RtlNtStatusToDosError(st));
        return INVALID_HANDLE_VALUE;
    }
    f->magic = FIND_MAGIC;
    if (!next_entry(f, data))
    {
        DWORD err = GetLastError();
        NtClose(f->dir);
        HeapFree(GetProcessHeap(), 0, f);
        SetLastError(err == ERROR_NO_MORE_FILES ? ERROR_FILE_NOT_FOUND : err);
        return INVALID_HANDLE_VALUE;
    }
    return f;
}

HANDLE WINAPI FindFirstFileW(LPCWSTR spec, WIN32_FIND_DATAW *data)
{
    return FindFirstFileExW(spec, FindExInfoStandard, data, FindExSearchNameMatch, NULL, 0);
}

BOOL WINAPI FindNextFileW(HANDLE h, WIN32_FIND_DATAW *data)
{
    struct find *f = h;
    if (!f || f == INVALID_HANDLE_VALUE || f->magic != FIND_MAGIC) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    return next_entry(f, data);
}

BOOL WINAPI FindClose(HANDLE h)
{
    struct find *f = h;
    if (!f || f == INVALID_HANDLE_VALUE || f->magic != FIND_MAGIC) { SetLastError(ERROR_INVALID_HANDLE); return FALSE; }
    f->magic = 0;
    NtClose(f->dir);
    HeapFree(GetProcessHeap(), 0, f);
    return TRUE;
}

void *__imp_FindFirstFileExW = (void *)FindFirstFileExW;
void *__imp_FindFirstFileW = (void *)FindFirstFileW;
void *__imp_FindNextFileW = (void *)FindNextFileW;
void *__imp_FindClose = (void *)FindClose;
