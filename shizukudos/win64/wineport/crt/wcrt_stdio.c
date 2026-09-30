/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: streams (FILE), low-level descriptors and the console/file plumbing under them.
 *
 * Streams are unbuffered: every fwrite is one WriteFile, reads go through a one-character push-back slot. Text mode
 * translation is limited to what the programs here need: "\n" is written as-is (the Shizuku console accepts bare LF)
 * and reads do not strip CR. Descriptors 0..2 are the standard handles of the process.
 */
#include "shzwcrt.h"
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>

#define MAX_FD 64
#define SF_READ   1
#define SF_WRITE  2
#define SF_EOF    4
#define SF_ERR    8
#define SF_APPEND 16

typedef struct shzw_file {
    int fd;
    int flags;
    int ungot;                         /* -1: none */
    int used;
} shzw_file;

static shzw_file files[MAX_FD] = {
    { 0, SF_READ, -1, 1 }, { 1, SF_WRITE, -1, 1 }, { 2, SF_WRITE, -1, 1 },
};
static struct { HANDLE h; int used; int append; } fds[MAX_FD];
static CRITICAL_SECTION io_cs;
static LONG io_init;

static void io_lock(void)
{
    if (InterlockedCompareExchange(&io_init, 1, 0) == 0) { InitializeCriticalSection(&io_cs); io_init = 2; }
    while (io_init != 2) Sleep(0);
    EnterCriticalSection(&io_cs);
}
static void io_unlock(void) { LeaveCriticalSection(&io_cs); }

static HANDLE std_handle(int fd)
{
    return GetStdHandle(fd == 0 ? STD_INPUT_HANDLE : fd == 1 ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
}

HANDLE shzw_fd_handle(int fd)
{
    if (fd < 0 || fd >= MAX_FD) return INVALID_HANDLE_VALUE;
    if (fd <= 2 && !fds[fd].used) return std_handle(fd);
    return fds[fd].used ? fds[fd].h : INVALID_HANDLE_VALUE;
}

static int fd_alloc(HANDLE h, int append)
{
    int i;
    io_lock();
    for (i = 3; i < MAX_FD; ++i)
        if (!fds[i].used) { fds[i].used = 1; fds[i].h = h; fds[i].append = append; io_unlock(); return i; }
    io_unlock();
    shzw_set_errno(EMFILE);
    return -1;
}

FILE *__cdecl __acrt_iob_func(unsigned index) { return index < 3 ? (FILE *)&files[index] : NULL; }
FILE *__cdecl __iob_func(void) { return (FILE *)files; }

static int fd_write(int fd, const void *data, size_t len)
{
    HANDLE h = shzw_fd_handle(fd);
    DWORD done = 0;
    if (h == INVALID_HANDLE_VALUE || !h) { shzw_set_errno(EBADF); return -1; }
    if (fd >= 3 && fds[fd].append) SetFilePointer(h, 0, NULL, FILE_END);
    while (len) {
        DWORD chunk = len > 0x10000000 ? 0x10000000 : (DWORD)len;
        if (!WriteFile(h, data, chunk, &done, NULL)) { shzw_set_errno(EIO); return -1; }
        data = (const char *)data + done;
        len -= done;
        if (!done) break;
    }
    return 0;
}

int shzw_file_write(FILE *fp, const void *data, size_t bytes)
{
    shzw_file *f = (shzw_file *)fp;
    if (!f || !f->used) return -1;
    if (fd_write(f->fd, data, bytes) < 0) { f->flags |= SF_ERR; return -1; }
    return (int)bytes;
}

/* ---------------------------------------------------------------- descriptors */
int __cdecl _write(int fd, const void *buf, unsigned int n) { return fd_write(fd, buf, n) < 0 ? -1 : (int)n; }
int __cdecl _read(int fd, void *buf, unsigned int n)
{
    HANDLE h = shzw_fd_handle(fd);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE) { shzw_set_errno(EBADF); return -1; }
    if (!ReadFile(h, buf, n, &got, NULL)) {
        if (GetLastError() == ERROR_BROKEN_PIPE || GetLastError() == ERROR_HANDLE_EOF) return 0;
        shzw_set_errno(EIO);
        return -1;
    }
    return (int)got;
}
int __cdecl _close(int fd)
{
    if (fd < 3 || fd >= MAX_FD || !fds[fd].used) { shzw_set_errno(EBADF); return -1; }
    CloseHandle(fds[fd].h);
    fds[fd].used = 0;
    return 0;
}
intptr_t __cdecl _get_osfhandle(int fd)
{
    HANDLE h = shzw_fd_handle(fd);
    if (h == INVALID_HANDLE_VALUE) shzw_set_errno(EBADF);
    return (intptr_t)h;
}
int __cdecl _open_osfhandle(intptr_t h, int flags) { return fd_alloc((HANDLE)h, !!(flags & _O_APPEND)); }
int __cdecl _isatty(int fd)
{
    HANDLE h = shzw_fd_handle(fd);
    return h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_CHAR;
}
__int64 __cdecl _lseeki64(int fd, __int64 off, int whence)
{
    HANDLE h = shzw_fd_handle(fd);
    LARGE_INTEGER d, r;
    d.QuadPart = off;
    if (h == INVALID_HANDLE_VALUE) { shzw_set_errno(EBADF); return -1; }
    if (!SetFilePointerEx(h, d, &r, whence == SEEK_CUR ? FILE_CURRENT : whence == SEEK_END ? FILE_END : FILE_BEGIN)) {
        shzw_set_errno(EINVAL);
        return -1;
    }
    return r.QuadPart;
}
long __cdecl _lseek(int fd, long off, int whence) { return (long)_lseeki64(fd, off, whence); }

static int open_w(const wchar_t *path, int oflag, int pmode)
{
    DWORD access = 0, disp, share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    HANDLE h;
    (void)pmode;
    switch (oflag & (_O_RDONLY | _O_WRONLY | _O_RDWR)) {
    case _O_WRONLY: access = GENERIC_WRITE; break;
    case _O_RDWR: access = GENERIC_READ | GENERIC_WRITE; break;
    default: access = GENERIC_READ; break;
    }
    if ((oflag & (_O_CREAT | _O_EXCL)) == (_O_CREAT | _O_EXCL)) disp = CREATE_NEW;
    else if ((oflag & (_O_CREAT | _O_TRUNC)) == (_O_CREAT | _O_TRUNC)) disp = CREATE_ALWAYS;
    else if (oflag & _O_CREAT) disp = OPEN_ALWAYS;
    else if (oflag & _O_TRUNC) disp = TRUNCATE_EXISTING;
    else disp = OPEN_EXISTING;
    h = CreateFileW(path, access, share, NULL, disp, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD e = GetLastError();
        shzw_set_errno(e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND ? ENOENT :
                       e == ERROR_FILE_EXISTS || e == ERROR_ALREADY_EXISTS ? EEXIST : EACCES);
        return -1;
    }
    return fd_alloc(h, !!(oflag & _O_APPEND));
}
static wchar_t *widen(const char *s)
{
    size_t n = strlen(s), i;
    wchar_t *w = malloc((n + 1) * sizeof(wchar_t));
    if (!w) return NULL;
    for (i = 0; i <= n; ++i) w[i] = (unsigned char)s[i];
    return w;
}
int __cdecl _wopen(const wchar_t *path, int oflag, ...)
{
    va_list ap;
    int pmode = 0;
    if (oflag & _O_CREAT) { va_start(ap, oflag); pmode = va_arg(ap, int); va_end(ap); }
    return open_w(path, oflag, pmode);
}
int __cdecl _open(const char *path, int oflag, ...)
{
    va_list ap;
    int pmode = 0, r;
    wchar_t *w = widen(path);
    if (oflag & _O_CREAT) { va_start(ap, oflag); pmode = va_arg(ap, int); va_end(ap); }
    if (!w) return -1;
    r = open_w(w, oflag, pmode);
    free(w);
    return r;
}

/* ---------------------------------------------------------------- streams */
static FILE *stream_open(int fd, int flags)
{
    int i;
    io_lock();
    for (i = 3; i < MAX_FD; ++i)
        if (!files[i].used) { files[i].used = 1; files[i].fd = fd; files[i].flags = flags; files[i].ungot = -1; io_unlock(); return (FILE *)&files[i]; }
    io_unlock();
    _close(fd);
    shzw_set_errno(EMFILE);
    return NULL;
}

static int mode_flags(const wchar_t *mode, int *oflag)
{
    int f = 0, o = 0, plus = !!wcschr(mode, '+');
    switch (mode[0]) {
    case 'r': o = plus ? _O_RDWR : _O_RDONLY; f = SF_READ | (plus ? SF_WRITE : 0); break;
    case 'w': o = (plus ? _O_RDWR : _O_WRONLY) | _O_CREAT | _O_TRUNC; f = SF_WRITE | (plus ? SF_READ : 0); break;
    case 'a': o = (plus ? _O_RDWR : _O_WRONLY) | _O_CREAT | _O_APPEND; f = SF_WRITE | SF_APPEND | (plus ? SF_READ : 0); break;
    default: return -1;
    }
    if (wcschr(mode, 'x')) o |= _O_EXCL;
    *oflag = o;
    return f;
}

FILE *__cdecl _wfopen(const wchar_t *path, const wchar_t *mode)
{
    int oflag, flags, fd;
    if (!path || !mode || (flags = mode_flags(mode, &oflag)) < 0) { shzw_set_errno(EINVAL); return NULL; }
    if ((fd = open_w(path, oflag, _S_IREAD | _S_IWRITE)) < 0) return NULL;
    return stream_open(fd, flags);
}
FILE *__cdecl fopen(const char *path, const char *mode)
{
    wchar_t *wp, *wm;
    FILE *f = NULL;
    if (!path || !mode) { shzw_set_errno(EINVAL); return NULL; }
    wp = widen(path);
    wm = widen(mode);
    if (wp && wm) f = _wfopen(wp, wm);
    free(wp);
    free(wm);
    return f;
}
errno_t __cdecl fopen_s(FILE **out, const char *path, const char *mode)
{
    if (!out) return EINVAL;
    *out = fopen(path, mode);
    return *out ? 0 : *_errno();
}
errno_t __cdecl _wfopen_s(FILE **out, const wchar_t *path, const wchar_t *mode)
{
    if (!out) return EINVAL;
    *out = _wfopen(path, mode);
    return *out ? 0 : *_errno();
}
FILE *__cdecl _fdopen(int fd, const char *mode)
{
    wchar_t m[8];
    int oflag, flags, i;
    for (i = 0; i < 7 && mode[i]; ++i) m[i] = (unsigned char)mode[i];
    m[i] = 0;
    if ((flags = mode_flags(m, &oflag)) < 0) return NULL;
    return stream_open(fd, flags);
}
int __cdecl fclose(FILE *fp)
{
    shzw_file *f = (shzw_file *)fp;
    if (!f || !f->used) return EOF;
    if (f - files < 3) return 0;
    _close(f->fd);
    f->used = 0;
    return 0;
}
int __cdecl _fileno(FILE *fp) { return fp ? ((shzw_file *)fp)->fd : -1; }
int __cdecl fflush(FILE *fp) { (void)fp; return 0; }
int __cdecl _flushall(void) { return 0; }
int __cdecl setvbuf(FILE *fp, char *buf, int mode, size_t size) { (void)fp; (void)buf; (void)mode; (void)size; return 0; }
void __cdecl setbuf(FILE *fp, char *buf) { (void)fp; (void)buf; }
int __cdecl feof(FILE *fp) { return !!(((shzw_file *)fp)->flags & SF_EOF); }
int __cdecl ferror(FILE *fp) { return !!(((shzw_file *)fp)->flags & SF_ERR); }
void __cdecl clearerr(FILE *fp) { ((shzw_file *)fp)->flags &= ~(SF_EOF | SF_ERR); }
void __cdecl _lock_file(FILE *fp) { (void)fp; }
void __cdecl _unlock_file(FILE *fp) { (void)fp; }

size_t __cdecl fwrite(const void *p, size_t size, size_t n, FILE *fp)
{
    size_t bytes = size * n;
    if (!fp || !bytes) return 0;
    return shzw_file_write(fp, p, bytes) < 0 ? 0 : n;
}
size_t __cdecl _fwrite_nolock(const void *p, size_t size, size_t n, FILE *fp) { return fwrite(p, size, n, fp); }
int __cdecl fputs(const char *s, FILE *fp) { size_t n = strlen(s); return !n || fwrite(s, 1, n, fp) == n ? 0 : EOF; }
int __cdecl fputc(int c, FILE *fp) { char ch = (char)c; return fwrite(&ch, 1, 1, fp) == 1 ? (unsigned char)c : EOF; }
int __cdecl putc(int c, FILE *fp) { return fputc(c, fp); }
int __cdecl _fputc_nolock(int c, FILE *fp) { return fputc(c, fp); }
int __cdecl putchar(int c) { return fputc(c, stdout); }
int __cdecl _putchar_nolock(int c) { return fputc(c, stdout); }
int __cdecl puts(const char *s) { return fputs(s, stdout) == EOF || fputc('\n', stdout) == EOF ? EOF : 0; }
int __cdecl fputws(const wchar_t *s, FILE *fp)
{
    for (; *s; ++s) if (fputc((unsigned short)*s < 256 ? (char)*s : '?', fp) == EOF) return EOF;
    return 0;
}
wint_t __cdecl fputwc(wchar_t c, FILE *fp) { return fputc((unsigned short)c < 256 ? (char)c : '?', fp) == EOF ? WEOF : c; }
wint_t __cdecl putwc(wchar_t c, FILE *fp) { return fputwc(c, fp); }
int __cdecl _putws(const wchar_t *s) { return fputws(s, stdout) == EOF || fputc('\n', stdout) == EOF ? EOF : 0; }

size_t __cdecl fread(void *p, size_t size, size_t n, FILE *fp)
{
    shzw_file *f = (shzw_file *)fp;
    size_t want = size * n, got = 0;
    if (!f || !want) return 0;
    if (f->ungot >= 0) { ((unsigned char *)p)[got++] = (unsigned char)f->ungot; f->ungot = -1; }
    while (got < want) {
        int r = _read(f->fd, (char *)p + got, (unsigned int)(want - got > 0x10000000 ? 0x10000000 : want - got));
        if (r < 0) { f->flags |= SF_ERR; break; }
        if (!r) { f->flags |= SF_EOF; break; }
        got += (size_t)r;
    }
    return size ? got / size : 0;
}
int __cdecl fgetc(FILE *fp)
{
    unsigned char c;
    return fread(&c, 1, 1, fp) == 1 ? c : EOF;
}
int __cdecl getc(FILE *fp) { return fgetc(fp); }
int __cdecl _fgetc_nolock(FILE *fp) { return fgetc(fp); }
int __cdecl getchar(void) { return fgetc(stdin); }
int __cdecl ungetc(int c, FILE *fp)
{
    shzw_file *f = (shzw_file *)fp;
    if (c == EOF || !f || f->ungot >= 0) return EOF;
    f->ungot = (unsigned char)c;
    f->flags &= ~SF_EOF;
    return c;
}
char *__cdecl fgets(char *s, int n, FILE *fp)
{
    int i = 0, c;
    if (n <= 0) return NULL;
    while (i < n - 1 && (c = fgetc(fp)) != EOF) { s[i++] = (char)c; if (c == '\n') break; }
    if (!i) return NULL;
    s[i] = 0;
    return s;
}
wint_t __cdecl fgetwc(FILE *fp) { int c = fgetc(fp); return c == EOF ? WEOF : (wint_t)c; }
wchar_t *__cdecl fgetws(wchar_t *s, int n, FILE *fp)
{
    int i = 0, c;
    if (n <= 0) return NULL;
    while (i < n - 1 && (c = fgetc(fp)) != EOF) { s[i++] = (wchar_t)c; if (c == '\n') break; }
    if (!i) return NULL;
    s[i] = 0;
    return s;
}

int __cdecl _fseeki64(FILE *fp, __int64 off, int whence)
{
    shzw_file *f = (shzw_file *)fp;
    if (whence == SEEK_CUR && f->ungot >= 0) off -= 1;
    f->ungot = -1;
    f->flags &= ~SF_EOF;
    return _lseeki64(f->fd, off, whence) < 0 ? -1 : 0;
}
int __cdecl fseek(FILE *fp, long off, int whence) { return _fseeki64(fp, off, whence); }
__int64 __cdecl _ftelli64(FILE *fp)
{
    shzw_file *f = (shzw_file *)fp;
    __int64 p = _lseeki64(f->fd, 0, SEEK_CUR);
    return p < 0 ? -1 : p - (f->ungot >= 0);
}
long __cdecl ftell(FILE *fp) { return (long)_ftelli64(fp); }
void __cdecl rewind(FILE *fp) { _fseeki64(fp, 0, SEEK_SET); clearerr(fp); }
int __cdecl fgetpos(FILE *fp, fpos_t *pos) { *pos = _ftelli64(fp); return *pos < 0 ? -1 : 0; }
int __cdecl fsetpos(FILE *fp, fpos_t *pos) { return _fseeki64(fp, *pos, SEEK_SET); }

/* ---------------------------------------------------------------- file system helpers */
int __cdecl remove(const char *path) { return DeleteFileA(path) ? 0 : (shzw_set_errno(ENOENT), -1); }
int __cdecl _wremove(const wchar_t *path) { return DeleteFileW(path) ? 0 : (shzw_set_errno(ENOENT), -1); }
int __cdecl _unlink(const char *path) { return remove(path); }
int __cdecl _wunlink(const wchar_t *path) { return _wremove(path); }
int __cdecl rename(const char *a, const char *b) { return MoveFileA(a, b) ? 0 : (shzw_set_errno(EACCES), -1); }
int __cdecl _wrename(const wchar_t *a, const wchar_t *b) { return MoveFileW(a, b) ? 0 : (shzw_set_errno(EACCES), -1); }
int __cdecl _mkdir(const char *path) { return CreateDirectoryA(path, NULL) ? 0 : (shzw_set_errno(EEXIST), -1); }
int __cdecl _wmkdir(const wchar_t *path) { return CreateDirectoryW(path, NULL) ? 0 : (shzw_set_errno(EEXIST), -1); }
int __cdecl _rmdir(const char *path) { return RemoveDirectoryA(path) ? 0 : (shzw_set_errno(ENOENT), -1); }
int __cdecl _wrmdir(const wchar_t *path) { return RemoveDirectoryW(path) ? 0 : (shzw_set_errno(ENOENT), -1); }
int __cdecl _access(const char *path, int mode)
{
    DWORD a = GetFileAttributesA(path);
    if (a == INVALID_FILE_ATTRIBUTES) { shzw_set_errno(ENOENT); return -1; }
    if ((mode & 2) && (a & FILE_ATTRIBUTE_READONLY)) { shzw_set_errno(EACCES); return -1; }
    return 0;
}
int __cdecl _waccess(const wchar_t *path, int mode)
{
    DWORD a = GetFileAttributesW(path);
    if (a == INVALID_FILE_ATTRIBUTES) { shzw_set_errno(ENOENT); return -1; }
    if ((mode & 2) && (a & FILE_ATTRIBUTE_READONLY)) { shzw_set_errno(EACCES); return -1; }
    return 0;
}
FILE *__cdecl _wfsopen(const wchar_t *path, const wchar_t *mode, int share) { (void)share; return _wfopen(path, mode); }
FILE *__cdecl _fsopen(const char *path, const char *mode, int share) { (void)share; return fopen(path, mode); }
