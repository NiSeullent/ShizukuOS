/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: current directory, file status and the command processor.
 *  _getcwd/_wgetcwd       GetCurrentDirectory; a NULL buffer is allocated (at least `size` units), as MSDN documents
 *  _stat64i32/_wstat64i32 GetFileAttributesExW: mode (_S_IFDIR or _S_IFREG, read permission, write permission unless
 *                         read-only, execute for .exe/.com/.bat/.cmd and directories), size (truncated to _off_t),
 *                         times in seconds since 1970, st_nlink 1, st_dev/st_rdev the drive number (A: = 0)
 *  system/_wsystem        there is no command processor: system(NULL) returns 0 ("none available"), a command
 *                         fails with -1 and errno ENOENT
 * Narrow names are widened byte for byte, like the other file functions of this runtime (wcrt_stdio.c).
 * Written from MSDN.
 */
#include "shzwcrt.h"
#include <errno.h>
#include <direct.h>
#include <process.h>
#include <sys/stat.h>

static wchar_t *widen_path(const char *s)
{
    size_t n = strlen(s), i;
    wchar_t *w = malloc((n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    for (i = 0; i <= n; ++i) w[i] = (unsigned char)s[i];
    return w;
}

/* ---------------------------------------------------------------- current directory */
char *__cdecl _getcwd(char *buf, int size)
{
    DWORD need = GetCurrentDirectoryA(0, NULL);          /* length including the terminator */
    if (!need) { shzw_set_errno(ENOENT); return NULL; }
    if (!buf) {
        if (size < (int)need) size = (int)need;
        if (!(buf = malloc(size))) { shzw_set_errno(ENOMEM); return NULL; }
    } else if (size < (int)need) {
        shzw_set_errno(ERANGE);
        return NULL;
    }
    GetCurrentDirectoryA(size, buf);
    return buf;
}

wchar_t *__cdecl _wgetcwd(wchar_t *buf, int size)
{
    DWORD need = GetCurrentDirectoryW(0, NULL);
    if (!need) { shzw_set_errno(ENOENT); return NULL; }
    if (!buf) {
        if (size < (int)need) size = (int)need;
        if (!(buf = malloc(size * sizeof(wchar_t)))) { shzw_set_errno(ENOMEM); return NULL; }
    } else if (size < (int)need) {
        shzw_set_errno(ERANGE);
        return NULL;
    }
    GetCurrentDirectoryW(size, buf);
    return buf;
}

/* ---------------------------------------------------------------- file status */
static __time64_t unix_time(const FILETIME *ft)
{
    __int64 v = ((__int64)ft->dwHighDateTime << 32) | ft->dwLowDateTime;
    return (v - 116444736000000000ll) / 10000000;
}

static int stat_w(const wchar_t *path, struct _stat64i32 *st)
{
    WIN32_FILE_ATTRIBUTE_DATA data;
    size_t n;
    unsigned short mode;
    int drive = -1;
    if (!path || !st) { shzw_set_errno(EINVAL); return -1; }
    n = wcslen(path);
    /* like the UCRT: a trailing separator is accepted only for directories; wildcards never match */
    if (!n || wcspbrk(path, L"*?")) { shzw_set_errno(ENOENT); return -1; }
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &data)) {
        DWORD e = GetLastError();
        shzw_set_errno(e == ERROR_ACCESS_DENIED ? EACCES : ENOENT);
        return -1;
    }
    if ((path[n - 1] == '\\' || path[n - 1] == '/') && !(data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        !(n == 3 && path[1] == ':')) {
        shzw_set_errno(ENOENT);
        return -1;
    }
    memset(st, 0, sizeof(*st));
    if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        mode = _S_IFDIR | _S_IEXEC;
    } else {
        const wchar_t *ext = wcsrchr(path, '.');
        mode = _S_IFREG;
        if (ext && (!_wcsicmp(ext, L".exe") || !_wcsicmp(ext, L".com") || !_wcsicmp(ext, L".bat") ||
                    !_wcsicmp(ext, L".cmd")))
            mode |= _S_IEXEC;
    }
    mode |= _S_IREAD;
    if (!(data.dwFileAttributes & FILE_ATTRIBUTE_READONLY)) mode |= _S_IWRITE;
    mode |= (mode & 0700) >> 3 | (mode & 0700) >> 6;    /* group and other get the owner's bits */
    if (n >= 2 && path[1] == ':') {
        wchar_t c = path[0] | 0x20;
        if (c >= 'a' && c <= 'z') drive = c - 'a';
    }
    if (drive < 0) {
        wchar_t cwd[4];
        if (GetCurrentDirectoryW(4, cwd) >= 2 && cwd[1] == ':') drive = (cwd[0] | 0x20) - 'a';
    }
    st->st_mode = mode;
    st->st_nlink = 1;
    st->st_dev = st->st_rdev = drive < 0 ? 0 : drive;
    st->st_size = (_off_t)data.nFileSizeLow;
    st->st_atime = unix_time(&data.ftLastAccessTime);
    st->st_mtime = unix_time(&data.ftLastWriteTime);
    st->st_ctime = unix_time(&data.ftCreationTime);
    return 0;
}

int __cdecl _wstat64i32(const wchar_t *path, struct _stat64i32 *st)
{
    return stat_w(path, st);
}

int __cdecl _stat64i32(const char *path, struct _stat64i32 *st)
{
    wchar_t *w;
    int r;
    if (!path) { shzw_set_errno(EINVAL); return -1; }
    if (!(w = widen_path(path))) { shzw_set_errno(ENOMEM); return -1; }
    r = stat_w(w, st);
    free(w);
    return r;
}

/* ---------------------------------------------------------------- command processor */
int __cdecl system(const char *command)
{
    if (!command) return 0;                              /* no command processor */
    shzw_set_errno(ENOENT);
    return -1;
}

int __cdecl _wsystem(const wchar_t *command)
{
    if (!command) return 0;
    shzw_set_errno(ENOENT);
    return -1;
}
