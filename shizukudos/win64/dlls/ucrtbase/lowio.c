/* SPDX-License-Identifier: GPL-2.0-only
 * Low-level I/O of the Shizuku UCRT: the file-descriptor table over Win32 handles (_open / _wsopen_dispatch /
 * _open_osfhandle / _get_osfhandle / _read / _write / _lseek / _close / _dup / _chsize / _setmode ...) and the file
 * system helpers built directly on kernel32 (_access, remove, rename, _mkdir, _getcwd, _fullpath, _stat, _findfirst).
 *
 * Text mode follows Microsoft's documented rules: _write turns LF into CR LF; _read turns CR LF into LF, and a CTRL+Z
 * byte ends a text-mode disk file. _O_U16TEXT / _O_WTEXT / _O_U8TEXT descriptors take UTF-16 buffers in _write
 * (UTF-8 is written for _O_U8TEXT; console handles receive WriteConsoleW). Descriptors 0, 1 and 2 are bound lazily to
 * the process's standard handles, in text mode.
 */
#include "crtint.h"
#include "crtos.h"

#define O_RDONLY_ 0x0000
#define O_WRONLY_ 0x0001
#define O_RDWR_ 0x0002
#define O_APPEND_ 0x0008
#define O_RANDOM_ 0x0010
#define O_SEQUENTIAL_ 0x0020
#define O_TEMPORARY_ 0x0040
#define O_NOINHERIT_ 0x0080
#define O_CREAT_ 0x0100
#define O_TRUNC_ 0x0200
#define O_EXCL_ 0x0400
#define O_SHORT_LIVED_ 0x1000
#define O_OBTAIN_DIR_ 0x2000
#define O_TEXT_ 0x4000
#define O_BINARY_ 0x8000
#define O_WTEXT_ 0x10000
#define O_U16TEXT_ 0x20000
#define O_U8TEXT_ 0x40000

/* per-descriptor flags */
#define F_OPEN 0x01
#define F_EOF 0x02
#define F_STDCLOSED 0x04                       /* a standard descriptor closed by _close: not rebound */
#define F_PIPE 0x08
#define F_NOINHERIT 0x10
#define F_APPEND 0x20
#define F_DEV 0x40
#define F_TEXT 0x80
enum { TM_ANSI = 0, TM_UTF8 = 1, TM_UTF16 = 2 };

typedef struct {
    os_handle h;
    unsigned char flags;
    unsigned char textmode;                 /* TM_* for text-mode descriptors */
    int pipech;                             /* one byte of look-ahead for pipes/devices, -1 when empty */
    os_critsec lock;
    int lock_ready;
} fdinfo;

#define FD_BLOCK 64
#define FD_MAX 8192
static fdinfo *g_fdblocks[FD_MAX / FD_BLOCK];
int crt_default_fmode(void);

static fdinfo *fd_entry(int fd)
{
    if (fd < 0 || fd >= FD_MAX || !g_fdblocks[fd / FD_BLOCK]) return 0;
    return &g_fdblocks[fd / FD_BLOCK][fd % FD_BLOCK];
}
static fdinfo *fd_alloc_block(int b)
{
    fdinfo *blk = g_fdblocks[b];
    int i;
    if (blk) return blk;
    blk = crt_calloc(FD_BLOCK, sizeof *blk);
    if (!blk) return 0;
    for (i = 0; i < FD_BLOCK; ++i) { blk[i].h = OS_INVALID_HANDLE; blk[i].pipech = -1; }
    g_fdblocks[b] = blk;
    return blk;
}
static void fd_lock_init(fdinfo *e)
{
    if (!e->lock_ready) { InitializeCriticalSection(&e->lock); e->lock_ready = 1; }
}

/* Standard descriptors: bound on first use to GetStdHandle, text mode, device/pipe flags from GetFileType. */
static void fd_bind_std(int fd)
{
    fdinfo *e;
    os_handle h;
    if (fd > 2) return;
    crt_lock(CRT_LOCK_FDS);
    if (!fd_alloc_block(0)) { crt_unlock(CRT_LOCK_FDS); return; }
    e = &g_fdblocks[0][fd];
    if (!(e->flags & (F_OPEN | F_STDCLOSED))) {
        h = GetStdHandle(fd == 0 ? OS_STD_INPUT : fd == 1 ? OS_STD_OUTPUT : OS_STD_ERROR);
        if (h && h != OS_INVALID_HANDLE) {
            const os_dword t = GetFileType(h);
            e->h = h;
            e->flags = F_OPEN | F_TEXT;
            if (t == OS_FILE_TYPE_CHAR) e->flags |= F_DEV;
            else if (t == OS_FILE_TYPE_PIPE) e->flags |= F_PIPE;
            e->textmode = TM_ANSI;
            fd_lock_init(e);
        }
    }
    crt_unlock(CRT_LOCK_FDS);
}

static fdinfo *fd_get(int fd)
{
    fdinfo *e;
    if (fd >= 0 && fd <= 2) fd_bind_std(fd);
    e = fd_entry(fd);
    return (e && (e->flags & F_OPEN)) ? e : 0;
}
#define FD_CHECK(fd, e, ret)                                                                                           \
    do {                                                                                                               \
        e = fd_get(fd);                                                                                                \
        if (!e) { *crt_doserrno_ptr() = 0; crt_set_errno(CRT_EBADF); crt_invalid_parameter(); return (ret); }          \
    } while (0)

static os_handle find_first_full(const wchar16 *spec, os_find_dataw *d);
static int fd_new(os_handle h, int flags, int textmode)
{
    int b, i;
    fd_bind_std(0);                                       /* the standard descriptors keep 0..2 when they exist */
    fd_bind_std(1);
    fd_bind_std(2);
    crt_lock(CRT_LOCK_FDS);
    for (b = 0; b < FD_MAX / FD_BLOCK; ++b) {
        fdinfo *blk = fd_alloc_block(b);
        if (!blk) break;
        for (i = 0; i < FD_BLOCK; ++i) {
            const int fd = b * FD_BLOCK + i;
            if (!(blk[i].flags & F_OPEN)) {
                blk[i].h = h;
                blk[i].flags = (unsigned char)(flags | F_OPEN);
                blk[i].textmode = (unsigned char)textmode;
                blk[i].pipech = -1;
                fd_lock_init(&blk[i]);
                crt_unlock(CRT_LOCK_FDS);
                return fd;
            }
        }
    }
    crt_unlock(CRT_LOCK_FDS);
    crt_set_errno(CRT_EMFILE);
    *crt_doserrno_ptr() = 0;
    return -1;
}

static int mode_flags(int oflag, int *textmode)
{
    int f = 0, m = oflag & (O_TEXT_ | O_BINARY_ | O_WTEXT_ | O_U16TEXT_ | O_U8TEXT_);
    if (!m) m = crt_default_fmode();
    *textmode = TM_ANSI;
    if (m & O_BINARY_) return 0;
    f |= F_TEXT;
    if (m & (O_WTEXT_ | O_U16TEXT_)) *textmode = TM_UTF16;
    else if (m & O_U8TEXT_) *textmode = TM_UTF8;
    return f;
}

/* ---------------------------------------------------------------- open / close */
static crt_errno_t sopen_core(const wchar16 *path, int oflag, int shflag, int pmode, int *pfh)
{
    os_dword access, share, disp, attrs = OS_FILE_ATTRIBUTE_NORMAL;
    os_handle h;
    int flags, textmode, fd;
    *pfh = -1;
    switch (oflag & (O_RDONLY_ | O_WRONLY_ | O_RDWR_)) {
    case O_RDONLY_: access = OS_GENERIC_READ; break;
    case O_WRONLY_: access = (oflag & O_APPEND_) ? OS_GENERIC_READ | OS_GENERIC_WRITE : OS_GENERIC_WRITE; break;
    case O_RDWR_: access = OS_GENERIC_READ | OS_GENERIC_WRITE; break;
    default: crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return CRT_EINVAL;
    }
    switch (shflag) {
    case 0x10: share = 0; break;                                     /* _SH_DENYRW */
    case 0x20: share = OS_FILE_SHARE_READ; break;                    /* _SH_DENYWR */
    case 0x30: share = OS_FILE_SHARE_WRITE; break;                   /* _SH_DENYRD */
    case 0x40: share = OS_FILE_SHARE_READ | OS_FILE_SHARE_WRITE; break; /* _SH_DENYNO */
    case 0x50: share = OS_FILE_SHARE_READ | OS_FILE_SHARE_WRITE | OS_FILE_SHARE_DELETE; break; /* _SH_SECURE */
    default: crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return CRT_EINVAL;
    }
    switch (oflag & (O_CREAT_ | O_EXCL_ | O_TRUNC_)) {
    case 0: case O_EXCL_: disp = OS_OPEN_EXISTING; break;
    case O_CREAT_: disp = OS_OPEN_ALWAYS; break;
    case O_CREAT_ | O_EXCL_: case O_CREAT_ | O_TRUNC_ | O_EXCL_: disp = OS_CREATE_NEW; break;
    case O_TRUNC_: case O_TRUNC_ | O_EXCL_: disp = OS_TRUNCATE_EXISTING; break;
    default: disp = OS_CREATE_ALWAYS; break;                         /* O_CREAT | O_TRUNC */
    }
    if ((oflag & O_CREAT_) && !(pmode & 0x80 /* _S_IWRITE */)) attrs = OS_FILE_ATTRIBUTE_READONLY;
    if (oflag & O_TEMPORARY_) { attrs |= OS_FILE_FLAG_DELETE_ON_CLOSE; access |= 0x10000 /* DELETE */; share |= OS_FILE_SHARE_DELETE; }
    if (oflag & O_SHORT_LIVED_) attrs |= OS_FILE_ATTRIBUTE_TEMPORARY;
    if (oflag & O_SEQUENTIAL_) attrs |= OS_FILE_FLAG_SEQUENTIAL_SCAN;
    else if (oflag & O_RANDOM_) attrs |= OS_FILE_FLAG_RANDOM_ACCESS;
    if (oflag & O_OBTAIN_DIR_) attrs |= OS_FILE_FLAG_BACKUP_SEMANTICS;
    h = CreateFileW(path, access, share, 0, disp, attrs, 0);
    if (h == OS_INVALID_HANDLE && (access & OS_GENERIC_READ) && (oflag & (O_RDONLY_ | O_WRONLY_ | O_RDWR_)) == O_WRONLY_) {
        access &= ~OS_GENERIC_READ;                                 /* append-only file without read access */
        h = CreateFileW(path, access, share, 0, disp, attrs, 0);
    }
    if (h == OS_INVALID_HANDLE) {
        crt_dosmaperr(GetLastError());
        return crt_get_errno();
    }
    flags = mode_flags(oflag, &textmode);
    {
        const os_dword t = GetFileType(h);
        if (t == OS_FILE_TYPE_CHAR) flags |= F_DEV;
        else if (t == OS_FILE_TYPE_PIPE) flags |= F_PIPE;
    }
    if (oflag & O_APPEND_) flags |= F_APPEND;
    if (oflag & O_NOINHERIT_) flags |= F_NOINHERIT;
    fd = fd_new(h, flags, textmode);
    if (fd < 0) { CloseHandle(h); return CRT_EMFILE; }
    *pfh = fd;
    return 0;
}

static wchar16 *path_to_wide(const char *p)
{
    int n = MultiByteToWideChar(OS_CP_ACP, 0, p, -1, 0, 0);
    wchar16 *w = n > 0 ? crt_malloc((size_t)n * sizeof(wchar16)) : 0;
    if (w) MultiByteToWideChar(OS_CP_ACP, 0, p, -1, w, n);
    else crt_set_errno(CRT_ENOMEM);
    return w;
}

DLLAPI crt_errno_t CRTAPI _wsopen_dispatch(const wchar16 *path, int oflag, int shflag, int pmode, int *pfh, int secure)
{
    (void)secure;
    CRT_VALIDATE(pfh != 0, CRT_EINVAL, CRT_EINVAL);
    *pfh = -1;
    CRT_VALIDATE(path != 0, CRT_EINVAL, CRT_EINVAL);
    return sopen_core(path, oflag, shflag, pmode, pfh);
}
DLLAPI crt_errno_t CRTAPI _sopen_dispatch(const char *path, int oflag, int shflag, int pmode, int *pfh, int secure)
{
    wchar16 *w;
    crt_errno_t r;
    CRT_VALIDATE(pfh != 0, CRT_EINVAL, CRT_EINVAL);
    *pfh = -1;
    CRT_VALIDATE(path != 0, CRT_EINVAL, CRT_EINVAL);
    w = path_to_wide(path);
    if (!w) return CRT_ENOMEM;
    r = _wsopen_dispatch(w, oflag, shflag, pmode, pfh, secure);
    crt_free(w);
    return r;
}
DLLAPI crt_errno_t CRTAPI _sopen_s(int *pfh, const char *path, int oflag, int shflag, int pmode) { return _sopen_dispatch(path, oflag, shflag, pmode, pfh, 1); }
DLLAPI crt_errno_t CRTAPI _wsopen_s(int *pfh, const wchar16 *path, int oflag, int shflag, int pmode) { return _wsopen_dispatch(path, oflag, shflag, pmode, pfh, 1); }
DLLAPI int CRTAPI _open(const char *path, int oflag, ...)
{
    int fh = -1, pmode = 0;
    va_list ap;
    va_start(ap, oflag);
    if (oflag & O_CREAT_) pmode = va_arg(ap, int);
    va_end(ap);
    return _sopen_dispatch(path, oflag, 0x40, pmode, &fh, 0) ? -1 : fh;
}
DLLAPI int CRTAPI _wopen(const wchar16 *path, int oflag, ...)
{
    int fh = -1, pmode = 0;
    va_list ap;
    va_start(ap, oflag);
    if (oflag & O_CREAT_) pmode = va_arg(ap, int);
    va_end(ap);
    return _wsopen_dispatch(path, oflag, 0x40, pmode, &fh, 0) ? -1 : fh;
}
DLLAPI int CRTAPI _sopen(const char *path, int oflag, int shflag, ...)
{
    int fh = -1, pmode = 0;
    va_list ap;
    va_start(ap, shflag);
    if (oflag & O_CREAT_) pmode = va_arg(ap, int);
    va_end(ap);
    return _sopen_dispatch(path, oflag, shflag, pmode, &fh, 0) ? -1 : fh;
}
DLLAPI int CRTAPI _wsopen(const wchar16 *path, int oflag, int shflag, ...)
{
    int fh = -1, pmode = 0;
    va_list ap;
    va_start(ap, shflag);
    if (oflag & O_CREAT_) pmode = va_arg(ap, int);
    va_end(ap);
    return _wsopen_dispatch(path, oflag, shflag, pmode, &fh, 0) ? -1 : fh;
}
DLLAPI int CRTAPI _creat(const char *path, int pmode) { return _open(path, O_CREAT_ | O_TRUNC_ | O_RDWR_, pmode); }
DLLAPI int CRTAPI _wcreat(const wchar16 *path, int pmode) { return _wopen(path, O_CREAT_ | O_TRUNC_ | O_RDWR_, pmode); }

DLLAPI int CRTAPI _open_osfhandle(intptr_t h, int oflag)
{
    int flags, textmode;
    os_dword t;
    if (!h || h == -1) { crt_set_errno(CRT_EBADF); return -1; }
    t = GetFileType((os_handle)h);
    flags = mode_flags(oflag, &textmode);
    if (t == OS_FILE_TYPE_CHAR) flags |= F_DEV;
    else if (t == OS_FILE_TYPE_PIPE) flags |= F_PIPE;
    if (oflag & O_APPEND_) flags |= F_APPEND;
    if (oflag & O_NOINHERIT_) flags |= F_NOINHERIT;
    return fd_new((os_handle)h, flags, textmode);
}
DLLAPI intptr_t CRTAPI _get_osfhandle(int fd)
{
    fdinfo *e;
    FD_CHECK(fd, e, -1);
    return (intptr_t)e->h;
}
DLLAPI int CRTAPI _close(int fd)
{
    fdinfo *e;
    int r = 0;
    FD_CHECK(fd, e, -1);
    EnterCriticalSection(&e->lock);
    if (e->flags & F_OPEN) {
        /* the standard handles are closed only when the descriptor was bound to them by this CRT */
        if (!CloseHandle(e->h)) { crt_dosmaperr(GetLastError()); r = -1; }
        e->flags = fd <= 2 ? F_STDCLOSED : 0;
        e->h = OS_INVALID_HANDLE;
        e->pipech = -1;
    }
    LeaveCriticalSection(&e->lock);
    return r;
}

DLLAPI int CRTAPI _dup(int fd)
{
    fdinfo *e;
    os_handle h;
    int nfd;
    FD_CHECK(fd, e, -1);
    if (!DuplicateHandle(GetCurrentProcess(), e->h, GetCurrentProcess(), &h, 0, 1, OS_DUPLICATE_SAME_ACCESS)) {
        crt_dosmaperr(GetLastError());
        return -1;
    }
    nfd = fd_new(h, e->flags & ~(F_OPEN | F_NOINHERIT | F_EOF), e->textmode);
    if (nfd < 0) CloseHandle(h);
    return nfd;
}
DLLAPI int CRTAPI _dup2(int fd, int fd2)
{
    fdinfo *e, *t;
    os_handle h;
    FD_CHECK(fd, e, -1);
    if (fd2 < 0 || fd2 >= FD_MAX) { crt_set_errno(CRT_EBADF); crt_invalid_parameter(); return -1; }
    if (fd == fd2) return 0;
    crt_lock(CRT_LOCK_FDS);
    if (!fd_alloc_block(fd2 / FD_BLOCK)) { crt_unlock(CRT_LOCK_FDS); crt_set_errno(CRT_EMFILE); return -1; }
    crt_unlock(CRT_LOCK_FDS);
    if (fd_get(fd2)) _close(fd2);
    if (!DuplicateHandle(GetCurrentProcess(), e->h, GetCurrentProcess(), &h, 0, 1, OS_DUPLICATE_SAME_ACCESS)) {
        crt_dosmaperr(GetLastError());
        return -1;
    }
    t = fd_entry(fd2);
    crt_lock(CRT_LOCK_FDS);
    t->h = h;
    t->flags = (unsigned char)((e->flags & ~(F_NOINHERIT | F_EOF)) | F_OPEN);
    t->textmode = e->textmode;
    t->pipech = -1;
    fd_lock_init(t);
    crt_unlock(CRT_LOCK_FDS);
    if (fd2 <= 2) SetStdHandle(fd2 == 0 ? OS_STD_INPUT : fd2 == 1 ? OS_STD_OUTPUT : OS_STD_ERROR, h);
    return 0;
}

DLLAPI int CRTAPI _setmode(int fd, int mode)
{
    fdinfo *e;
    int old, tm;
    FD_CHECK(fd, e, -1);
    CRT_VALIDATE(mode == O_TEXT_ || mode == O_BINARY_ || mode == O_WTEXT_ || mode == O_U16TEXT_ || mode == O_U8TEXT_, CRT_EINVAL, -1);
    old = !(e->flags & F_TEXT) ? O_BINARY_ : e->textmode == TM_UTF16 ? O_U16TEXT_ : e->textmode == TM_UTF8 ? O_U8TEXT_ : O_TEXT_;
    if (mode == O_BINARY_) e->flags &= (unsigned char)~F_TEXT;
    else {
        mode_flags(mode, &tm);
        e->flags |= F_TEXT;
        e->textmode = (unsigned char)tm;
    }
    return old;
}
int crt_fd_textmode(int fd)                               /* -1 bad fd, 0 binary, 1 ANSI text, 2 UTF-8, 3 UTF-16 */
{
    fdinfo *e = fd_get(fd);
    if (!e) return -1;
    if (!(e->flags & F_TEXT)) return 0;
    return 1 + e->textmode;
}
int crt_fd_is_device(int fd)
{
    fdinfo *e = fd_get(fd);
    return e && (e->flags & F_DEV);
}
DLLAPI int CRTAPI _isatty(int fd)
{
    fdinfo *e = fd_get(fd);
    if (!e) { crt_set_errno(CRT_EBADF); return 0; }
    return (e->flags & F_DEV) ? 0x40 : 0;
}

/* ---------------------------------------------------------------- seek */
static int64_t seek_locked(fdinfo *e, int64_t off, int whence)
{
    int64_t pos = 0;
    if (whence < 0 || whence > 2) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return -1; }
    if (e->flags & (F_PIPE | F_DEV)) { crt_set_errno(CRT_ESPIPE); *crt_doserrno_ptr() = 0; return -1; }
    if (!SetFilePointerEx(e->h, off, &pos, (os_dword)whence)) { crt_dosmaperr(GetLastError()); return -1; }
    e->flags &= (unsigned char)~F_EOF;
    return pos;
}
DLLAPI long long CRTAPI _lseeki64(int fd, long long off, int whence)
{
    fdinfo *e;
    int64_t r;
    FD_CHECK(fd, e, -1);
    EnterCriticalSection(&e->lock);
    r = seek_locked(e, off, whence);
    LeaveCriticalSection(&e->lock);
    return r;
}
DLLAPI crt_long CRTAPI _lseek(int fd, crt_long off, int whence)
{
    fdinfo *e;
    int64_t cur, r;
    FD_CHECK(fd, e, -1);
    EnterCriticalSection(&e->lock);
    cur = seek_locked(e, 0, 1);
    r = cur < 0 ? -1 : seek_locked(e, off, whence);
    if (r > CRT_LONG_MAX) {                                  /* not representable: restore and fail */
        seek_locked(e, cur, 0);
        crt_set_errno(CRT_EINVAL);
        r = -1;
    }
    LeaveCriticalSection(&e->lock);
    return (crt_long)r;
}
DLLAPI long long CRTAPI _telli64(int fd) { return _lseeki64(fd, 0, 1); }
DLLAPI crt_long CRTAPI _tell(int fd) { return _lseek(fd, 0, 1); }
DLLAPI long long CRTAPI _filelengthi64(int fd)
{
    fdinfo *e;
    int64_t size = 0;
    FD_CHECK(fd, e, -1);
    if (!GetFileSizeEx(e->h, &size)) { crt_dosmaperr(GetLastError()); return -1; }
    return size;
}
DLLAPI crt_long CRTAPI _filelength(int fd)
{
    long long n = _filelengthi64(fd);
    if (n > CRT_LONG_MAX) { crt_set_errno(CRT_EFBIG); return -1; }
    return (crt_long)n;
}
DLLAPI int CRTAPI _eof(int fd)
{
    long long cur, len;
    fdinfo *e;
    FD_CHECK(fd, e, -1);
    cur = _lseeki64(fd, 0, 1);
    len = _filelengthi64(fd);
    if (cur < 0 || len < 0) return -1;
    return cur >= len;
}
DLLAPI int CRTAPI _commit(int fd)
{
    fdinfo *e;
    FD_CHECK(fd, e, -1);
    if (!FlushFileBuffers(e->h)) {
        if (e->flags & (F_DEV | F_PIPE)) return 0;
        crt_dosmaperr(GetLastError());
        return -1;
    }
    return 0;
}

/* ---------------------------------------------------------------- read */
static int raw_read(fdinfo *e, void *buf, unsigned n, os_dword *got)
{
    *got = 0;
    if (!ReadFile(e->h, buf, n, got, 0)) {
        const os_dword err = GetLastError();
        if (err == 109 /* ERROR_BROKEN_PIPE */) { *got = 0; return 0; }
        crt_dosmaperr(err);
        return -1;
    }
    return 0;
}

/* reads one more byte after a CR at the end of a text buffer */
static int peek_byte(fdinfo *e)
{
    unsigned char b;
    os_dword got;
    if (e->pipech >= 0) { int c = e->pipech; e->pipech = -1; return c; }
    if (raw_read(e, &b, 1, &got) < 0 || !got) return -1;
    return b;
}
static void unread_byte(fdinfo *e, int b)
{
    if (e->flags & (F_PIPE | F_DEV)) e->pipech = b;
    else { int64_t pos; SetFilePointerEx(e->h, -1, &pos, 1); }
}

static int read_locked(fdinfo *e, void *vbuf, unsigned n)
{
    unsigned char *buf = vbuf, *in, *out, *end;
    os_dword got = 0;
    unsigned have = 0;
    if (!n || (e->flags & F_EOF)) return 0;
    if (e->pipech >= 0 && (e->flags & (F_PIPE | F_DEV))) { buf[have++] = (unsigned char)e->pipech; e->pipech = -1; }
    if (have < n) {
        if (raw_read(e, buf + have, n - have, &got) < 0) return -1;
        have += got;
    }
    if (!(e->flags & F_TEXT)) return (int)have;
    if (e->textmode != TM_ANSI) {
        /* UTF-16 / UTF-8 text: CR LF -> LF on 16-bit units (UTF-8 input is returned as bytes, translated) */
        if (e->textmode == TM_UTF16) {
            unsigned short *w = (unsigned short *)buf, *o = w;
            unsigned cnt = have / 2, i;
            for (i = 0; i < cnt; ++i) {
                if (w[i] == '\r' && i + 1 < cnt && w[i + 1] == '\n') continue;
                *o++ = w[i];
            }
            return (int)((unsigned char *)o - buf);
        }
    }
    /* ANSI text: CR LF -> LF; CTRL+Z ends a disk file */
    in = out = buf;
    end = buf + have;
    while (in < end) {
        if (*in == 0x1a && !(e->flags & (F_DEV | F_PIPE))) {
            e->flags |= F_EOF;
            {   /* leave the file position at the CTRL+Z, as the UCRT does */
                int64_t pos;
                SetFilePointerEx(e->h, -(int64_t)(end - in), &pos, 1);
            }
            break;
        }
        if (*in != '\r') { *out++ = *in++; continue; }
        if (in + 1 < end) {
            if (in[1] == '\n') { *out++ = '\n'; in += 2; }
            else *out++ = *in++;
            continue;
        }
        /* CR is the last byte read: look at the next one */
        {
            int c = peek_byte(e);
            ++in;
            if (c == '\n') *out++ = '\n';
            else {
                *out++ = '\r';
                if (c >= 0) unread_byte(e, c);
            }
        }
    }
    return (int)(out - buf);
}
DLLAPI int CRTAPI _read(int fd, void *buf, unsigned n)
{
    fdinfo *e;
    int r;
    FD_CHECK(fd, e, -1);
    CRT_VALIDATE(buf != 0 || n == 0, CRT_EINVAL, -1);
    CRT_VALIDATE(n <= 0x7fffffffu, CRT_EINVAL, -1);
    EnterCriticalSection(&e->lock);
    r = read_locked(e, buf, n);
    LeaveCriticalSection(&e->lock);
    return r;
}

/* ---------------------------------------------------------------- write */
static int raw_write(fdinfo *e, const void *buf, unsigned n)
{
    os_dword put = 0;
    if (!n) return 0;
    if (!WriteFile(e->h, buf, n, &put, 0)) { crt_dosmaperr(GetLastError()); return -1; }
    if (put < n) { crt_set_errno(CRT_ENOSPC); *crt_doserrno_ptr() = 0; return -1; }
    return 0;
}
static int write_locked(fdinfo *e, const void *vbuf, unsigned n)
{
    const unsigned char *buf = vbuf;
    unsigned char tmp[1026];
    unsigned i, k;
    if (e->flags & F_APPEND) { int64_t pos; SetFilePointerEx(e->h, 0, &pos, 2); }
    if (!(e->flags & F_TEXT)) return raw_write(e, buf, n) < 0 ? -1 : (int)n;
    if (e->textmode == TM_ANSI) {
        for (i = 0; i < n;) {
            k = 0;
            while (i < n && k < 1024) {
                if (buf[i] == '\n') tmp[k++] = '\r';
                tmp[k++] = buf[i++];
            }
            if (raw_write(e, tmp, k) < 0) return -1;
        }
        return (int)n;
    }
    /* Unicode text modes: the buffer holds UTF-16 code units */
    CRT_VALIDATE(!(n & 1), CRT_EINVAL, -1);
    {
        const unsigned short *w = (const unsigned short *)buf;
        const unsigned cnt = n / 2;
        if (e->flags & F_DEV) {                              /* console: WriteConsoleW, LF -> CR LF */
            unsigned short wt[513];
            for (i = 0; i < cnt;) {
                os_dword put;
                k = 0;
                while (i < cnt && k < 511) {
                    if (w[i] == '\n') wt[k++] = '\r';
                    wt[k++] = w[i++];
                }
                if (!WriteConsoleW(e->h, wt, k, &put, 0) && raw_write(e, wt, k * 2) < 0) return -1;
            }
            return (int)n;
        }
        if (e->textmode == TM_UTF16) {
            unsigned short wt[513];
            for (i = 0; i < cnt;) {
                k = 0;
                while (i < cnt && k < 511) {
                    if (w[i] == '\n') wt[k++] = '\r';
                    wt[k++] = w[i++];
                }
                if (raw_write(e, wt, k * 2) < 0) return -1;
            }
            return (int)n;
        }
        for (i = 0; i < cnt;) {                              /* UTF-8 */
            k = 0;
            while (i < cnt && k < 1016) {
                uint32_t cp = w[i++];
                if (cp >= 0xd800 && cp <= 0xdbff && i < cnt && w[i] >= 0xdc00 && w[i] <= 0xdfff)
                    cp = 0x10000 + ((cp - 0xd800) << 10) + (w[i++] - 0xdc00u);
                else if (cp >= 0xd800 && cp <= 0xdfff) cp = 0xfffd;
                if (cp == '\n') tmp[k++] = '\r';
                if (cp < 0x80) tmp[k++] = (unsigned char)cp;
                else if (cp < 0x800) { tmp[k++] = (unsigned char)(0xc0 | (cp >> 6)); tmp[k++] = (unsigned char)(0x80 | (cp & 0x3f)); }
                else if (cp < 0x10000) {
                    tmp[k++] = (unsigned char)(0xe0 | (cp >> 12)); tmp[k++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f));
                    tmp[k++] = (unsigned char)(0x80 | (cp & 0x3f));
                } else {
                    tmp[k++] = (unsigned char)(0xf0 | (cp >> 18)); tmp[k++] = (unsigned char)(0x80 | ((cp >> 12) & 0x3f));
                    tmp[k++] = (unsigned char)(0x80 | ((cp >> 6) & 0x3f)); tmp[k++] = (unsigned char)(0x80 | (cp & 0x3f));
                }
            }
            if (raw_write(e, tmp, k) < 0) return -1;
        }
        return (int)n;
    }
}
DLLAPI int CRTAPI _write(int fd, const void *buf, unsigned n)
{
    fdinfo *e;
    int r;
    FD_CHECK(fd, e, -1);
    CRT_VALIDATE(buf != 0 || n == 0, CRT_EINVAL, -1);
    EnterCriticalSection(&e->lock);
    r = write_locked(e, buf, n);
    LeaveCriticalSection(&e->lock);
    return r;
}

/* ---------------------------------------------------------------- size */
DLLAPI crt_errno_t CRTAPI _chsize_s(int fd, long long size)
{
    fdinfo *e;
    int64_t cur = 0, len = 0, tmp;
    crt_errno_t r = 0;
    e = fd_get(fd);
    if (!e) { crt_set_errno(CRT_EBADF); crt_invalid_parameter(); return CRT_EBADF; }
    CRT_VALIDATE(size >= 0, CRT_EINVAL, CRT_EINVAL);
    EnterCriticalSection(&e->lock);
    if (!SetFilePointerEx(e->h, 0, &cur, 1) || !GetFileSizeEx(e->h, &len)) { crt_dosmaperr(GetLastError()); r = crt_get_errno(); goto out; }
    if (size > len) {                                         /* extend with zero bytes */
        static const unsigned char zeros[512];
        int64_t left = size - len;
        SetFilePointerEx(e->h, 0, &tmp, 2);
        while (left > 0) {
            const unsigned k = left > 512 ? 512 : (unsigned)left;
            if (raw_write(e, zeros, k) < 0) { r = crt_get_errno(); goto restore; }
            left -= k;
        }
    } else {
        if (!SetFilePointerEx(e->h, size, &tmp, 0) || !SetEndOfFile(e->h)) { crt_dosmaperr(GetLastError()); r = crt_get_errno(); }
    }
restore:
    SetFilePointerEx(e->h, cur, &tmp, 0);
out:
    LeaveCriticalSection(&e->lock);
    return r;
}
DLLAPI int CRTAPI _chsize(int fd, crt_long size) { return _chsize_s(fd, size) ? -1 : 0; }

/* ---------------------------------------------------------------- file system */
DLLAPI crt_errno_t CRTAPI _waccess_s(const wchar16 *path, int mode)
{
    os_dword a;
    CRT_VALIDATE(path != 0 && !(mode & ~6), CRT_EINVAL, CRT_EINVAL);
    a = GetFileAttributesW(path);
    if (a == OS_INVALID_FILE_ATTRIBUTES) { crt_dosmaperr(GetLastError()); return crt_get_errno(); }
    if (!(a & OS_FILE_ATTRIBUTE_DIRECTORY) && (a & OS_FILE_ATTRIBUTE_READONLY) && (mode & 2)) {
        *crt_doserrno_ptr() = 5;
        crt_set_errno(CRT_EACCES);
        return CRT_EACCES;
    }
    return 0;
}
DLLAPI crt_errno_t CRTAPI _access_s(const char *path, int mode)
{
    wchar16 *w;
    crt_errno_t r;
    CRT_VALIDATE(path != 0, CRT_EINVAL, CRT_EINVAL);
    w = path_to_wide(path);
    if (!w) return CRT_ENOMEM;
    r = _waccess_s(w, mode);
    crt_free(w);
    return r;
}
DLLAPI int CRTAPI _waccess(const wchar16 *path, int mode) { return _waccess_s(path, mode) ? -1 : 0; }
DLLAPI int CRTAPI _access(const char *path, int mode) { return _access_s(path, mode) ? -1 : 0; }

static int wide_wrap1(const char *p, int (CRTAPI *fn)(const wchar16 *))
{
    wchar16 *w;
    int r;
    CRT_VALIDATE(p != 0, CRT_EINVAL, -1);
    w = path_to_wide(p);
    if (!w) return -1;
    r = fn(w);
    crt_free(w);
    return r;
}
DLLAPI int CRTAPI _wunlink(const wchar16 *p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, -1);
    if (!DeleteFileW(p)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
DLLAPI int CRTAPI _wremove(const wchar16 *p) { return _wunlink(p); }
DLLAPI int CRTAPI _wmkdir(const wchar16 *p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, -1);
    if (!CreateDirectoryW(p, 0)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
DLLAPI int CRTAPI _wrmdir(const wchar16 *p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, -1);
    if (!RemoveDirectoryW(p)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
DLLAPI int CRTAPI _wchdir(const wchar16 *p)
{
    CRT_VALIDATE(p != 0, CRT_EINVAL, -1);
    if (!SetCurrentDirectoryW(p)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
DLLAPI int CRTAPI _unlink(const char *p) { return wide_wrap1(p, _wunlink); }
DLLAPI int CRTAPI remove(const char *p) { return wide_wrap1(p, _wremove); }
DLLAPI int CRTAPI _mkdir(const char *p) { return wide_wrap1(p, _wmkdir); }
DLLAPI int CRTAPI _rmdir(const char *p) { return wide_wrap1(p, _wrmdir); }
DLLAPI int CRTAPI _chdir(const char *p) { return wide_wrap1(p, _wchdir); }
DLLAPI int CRTAPI _wrename(const wchar16 *a, const wchar16 *b)
{
    CRT_VALIDATE(a != 0 && b != 0, CRT_EINVAL, -1);
    if (!MoveFileExW(a, b, OS_MOVEFILE_COPY_ALLOWED)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
DLLAPI int CRTAPI rename(const char *a, const char *b)
{
    wchar16 *wa, *wb;
    int r = -1;
    CRT_VALIDATE(a != 0 && b != 0, CRT_EINVAL, -1);
    wa = path_to_wide(a);
    wb = wa ? path_to_wide(b) : 0;
    if (wa && wb) r = _wrename(wa, wb);
    crt_free(wa);
    crt_free(wb);
    return r;
}

DLLAPI wchar16 *CRTAPI _wgetcwd(wchar16 *buf, int n)
{
    os_dword len = GetCurrentDirectoryW(0, 0);
    wchar16 *out = buf;
    if (!len) { crt_dosmaperr(GetLastError()); return 0; }
    if (!buf) {
        const size_t cap = (size_t)(n > (int)len ? n : (int)len);
        out = crt_malloc(cap * sizeof(wchar16));
        if (!out) return 0;
        n = (int)cap;
    } else CRT_VALIDATE(n > 0, CRT_EINVAL, 0);
    if ((os_dword)n < len) { crt_set_errno(CRT_ERANGE); return 0; }
    GetCurrentDirectoryW((os_dword)n, out);
    return out;
}
DLLAPI char *CRTAPI _getcwd(char *buf, int n)
{
    wchar16 *w = _wgetcwd(0, 0);
    int need;
    char *out = buf;
    if (!w) return 0;
    need = WideCharToMultiByte(OS_CP_ACP, 0, w, -1, 0, 0, 0, 0);
    if (!buf) {
        const int cap = n > need ? n : need;
        out = crt_malloc((size_t)cap);
        if (!out) { crt_free(w); return 0; }
        n = cap;
    } else if (n <= 0) { crt_free(w); crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    if (n < need) { crt_free(w); crt_set_errno(CRT_ERANGE); return 0; }
    WideCharToMultiByte(OS_CP_ACP, 0, w, -1, out, n, 0, 0);
    crt_free(w);
    return out;
}
DLLAPI wchar16 *CRTAPI _wfullpath(wchar16 *buf, const wchar16 *path, size_t n)
{
    os_dword len;
    wchar16 *out = buf;
    if (!path || !*path) return _wgetcwd(buf, (int)n);
    len = GetFullPathNameW(path, 0, 0, 0);
    if (!len) { crt_dosmaperr(GetLastError()); return 0; }
    if (!buf) {
        out = crt_malloc((size_t)len * sizeof(wchar16));
        if (!out) return 0;
        n = len;
    }
    if (n < len) { crt_set_errno(CRT_ERANGE); return 0; }
    GetFullPathNameW(path, (os_dword)n, out, 0);
    return out;
}
DLLAPI char *CRTAPI _fullpath(char *buf, const char *path, size_t n)
{
    wchar16 *wp = path && *path ? path_to_wide(path) : 0, *w;
    int need;
    char *out = buf;
    if (path && *path && !wp) return 0;
    w = _wfullpath(0, wp, 0);
    crt_free(wp);
    if (!w) return 0;
    need = WideCharToMultiByte(OS_CP_ACP, 0, w, -1, 0, 0, 0, 0);
    if (!buf) {
        out = crt_malloc((size_t)need);
        if (!out) { crt_free(w); return 0; }
        n = (size_t)need;
    }
    if (n < (size_t)need) { crt_free(w); crt_set_errno(CRT_ERANGE); return 0; }
    WideCharToMultiByte(OS_CP_ACP, 0, w, -1, out, (int)n, 0, 0);
    crt_free(w);
    return out;
}

/* ---------------------------------------------------------------- _stat / _fstat (times from FindFirstFileW) */
struct crt_stat64 {                                         /* struct _stat64 */
    unsigned st_dev;
    unsigned short st_ino, st_mode;
    short st_nlink, st_uid, st_gid;
    unsigned st_rdev;
    long long st_size;
    long long st_atime, st_mtime, st_ctime;
};
struct crt_stat64i32 {                                      /* struct _stat64i32 */
    unsigned st_dev;
    unsigned short st_ino, st_mode;
    short st_nlink, st_uid, st_gid;
    unsigned st_rdev;
    int32_t st_size;
    long long st_atime, st_mtime, st_ctime;
};
#define S_IFDIR_ 0x4000
#define S_IFCHR_ 0x2000
#define S_IFIFO_ 0x1000
#define S_IFREG_ 0x8000
#define S_IREAD_ 0x0100
#define S_IWRITE_ 0x0080
#define S_IEXEC_ 0x0040

static long long ft_to_time(const os_filetime *ft)
{
    const uint64_t t = ((uint64_t)ft->hi << 32) | ft->lo;
    if (!t) return 0;
    return (long long)(t / 10000000ull) - 11644473600ll;
}
static int ends_with_exe(const wchar16 *p)
{
    size_t n = crt_wcslen(p);
    static const char *const exts[] = { ".exe", ".cmd", ".bat", ".com" };
    unsigned i, j;
    if (n < 4) return 0;
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 4; ++j)
            if (crt_towlower_c(p[n - 4 + j]) != (unsigned)exts[i][j]) break;
        if (j == 4) return 1;
    }
    return 0;
}
static int is_root_like(const wchar16 *p)
{
    /* "X:\", "X:" , "\" and "/" have no directory entry of their own */
    size_t n = crt_wcslen(p);
    if (n == 1 && (p[0] == '\\' || p[0] == '/')) return 1;
    if ((n == 2 || n == 3) && p[1] == ':' && (n == 2 || p[2] == '\\' || p[2] == '/')) return 1;
    return 0;
}
static int wstat_core(const wchar16 *path, struct crt_stat64 *st)
{
    os_find_dataw fd;
    os_handle h;
    os_dword attrs;
    size_t n;
    CRT_VALIDATE(path != 0 && st != 0, CRT_EINVAL, -1);
    crt_memset(st, 0, sizeof *st);
    n = crt_wcslen(path);
    if (!n) { crt_set_errno(CRT_ENOENT); *crt_doserrno_ptr() = 2; return -1; }
    attrs = GetFileAttributesW(path);
    if (attrs == OS_INVALID_FILE_ATTRIBUTES) { crt_dosmaperr(GetLastError()); if (crt_get_errno() == CRT_EINVAL) crt_set_errno(CRT_ENOENT); return -1; }
    if (!is_root_like(path) && (h = find_first_full(path, &fd)) != OS_INVALID_HANDLE) {
        FindClose(h);
        st->st_size = (long long)(((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow);
        st->st_atime = ft_to_time(&fd.ftLastAccessTime);
        st->st_mtime = ft_to_time(&fd.ftLastWriteTime);
        st->st_ctime = ft_to_time(&fd.ftCreationTime);
        if (!st->st_atime) st->st_atime = st->st_mtime;
        if (!st->st_ctime) st->st_ctime = st->st_mtime;
    }
    st->st_mode = (attrs & OS_FILE_ATTRIBUTE_DIRECTORY) ? (S_IFDIR_ | S_IEXEC_) : S_IFREG_;
    st->st_mode |= (attrs & OS_FILE_ATTRIBUTE_READONLY) ? S_IREAD_ : (S_IREAD_ | S_IWRITE_);
    if (!(attrs & OS_FILE_ATTRIBUTE_DIRECTORY) && ends_with_exe(path)) st->st_mode |= S_IEXEC_;
    st->st_mode |= (unsigned short)((st->st_mode & 0x1c0) >> 3 | (st->st_mode & 0x1c0) >> 6);
    st->st_nlink = 1;
    {
        wchar16 full[260];
        const wchar16 *p = path;
        if (GetFullPathNameW(path, 260, full, 0)) p = full;
        st->st_dev = st->st_rdev = (p[0] && p[1] == ':') ? (unsigned)(crt_towupper_c(p[0]) - 'A') : 0;
    }
    return 0;
}
DLLAPI int CRTAPI _wstat64(const wchar16 *path, struct crt_stat64 *st) { return wstat_core(path, st); }
DLLAPI int CRTAPI _stat64(const char *path, struct crt_stat64 *st)
{
    wchar16 *w;
    int r;
    CRT_VALIDATE(path != 0 && st != 0, CRT_EINVAL, -1);
    w = path_to_wide(path);
    if (!w) return -1;
    r = wstat_core(w, st);
    crt_free(w);
    return r;
}
static int narrow_size(struct crt_stat64i32 *o, const struct crt_stat64 *s)
{
    o->st_dev = s->st_dev; o->st_ino = s->st_ino; o->st_mode = s->st_mode; o->st_nlink = s->st_nlink;
    o->st_uid = s->st_uid; o->st_gid = s->st_gid; o->st_rdev = s->st_rdev;
    o->st_atime = s->st_atime; o->st_mtime = s->st_mtime; o->st_ctime = s->st_ctime;
    if (s->st_size > 0x7fffffffll) { crt_set_errno(CRT_EOVERFLOW); return -1; }
    o->st_size = (int32_t)s->st_size;
    return 0;
}
DLLAPI int CRTAPI _stat64i32(const char *path, struct crt_stat64i32 *st)
{
    struct crt_stat64 t;
    if (_stat64(path, &t)) return -1;
    return narrow_size(st, &t);
}
DLLAPI int CRTAPI _wstat64i32(const wchar16 *path, struct crt_stat64i32 *st)
{
    struct crt_stat64 t;
    if (_wstat64(path, &t)) return -1;
    return narrow_size(st, &t);
}
DLLAPI int CRTAPI _fstat64(int fd, struct crt_stat64 *st)
{
    fdinfo *e;
    int64_t size = 0;
    CRT_VALIDATE(st != 0, CRT_EINVAL, -1);
    FD_CHECK(fd, e, -1);
    crt_memset(st, 0, sizeof *st);
    if (e->flags & F_DEV) { st->st_mode = S_IFCHR_ | S_IREAD_ | S_IWRITE_; st->st_dev = st->st_rdev = (unsigned)fd; }
    else if (e->flags & F_PIPE) { st->st_mode = S_IFIFO_ | S_IREAD_ | S_IWRITE_; st->st_dev = st->st_rdev = (unsigned)fd; }
    else {
        os_filetime now;
        st->st_mode = S_IFREG_ | S_IREAD_ | S_IWRITE_;
        st->st_mode |= (unsigned short)((st->st_mode & 0x1c0) >> 3 | (st->st_mode & 0x1c0) >> 6);
        if (GetFileSizeEx(e->h, &size)) st->st_size = size;
        GetSystemTimeAsFileTime(&now);                        /* no per-handle times on this system: see CRT.md */
        st->st_atime = st->st_mtime = st->st_ctime = ft_to_time(&now);
    }
    st->st_nlink = 1;
    return 0;
}
DLLAPI int CRTAPI _fstat64i32(int fd, struct crt_stat64i32 *st)
{
    struct crt_stat64 t;
    if (_fstat64(fd, &t)) return -1;
    return narrow_size(st, &t);
}

/* ---------------------------------------------------------------- _findfirst / _findnext (64-bit time, 64-bit size) */
struct crt_finddata64 { unsigned attrib; long long time_create, time_access, time_write, size; char name[260]; };
struct crt_wfinddata64 { unsigned attrib; long long time_create, time_access, time_write, size; wchar16 name[260]; };
/* FindFirstFileW with the path made absolute first (this system's kernel32 resolves relative patterns less generally
 * than Windows does) */
static os_handle find_first_full(const wchar16 *spec, os_find_dataw *d)
{
    wchar16 full[300];
    const os_dword n = GetFullPathNameW(spec, 300, full, 0);
    return FindFirstFileW(n && n < 300 ? full : spec, d);
}
static void fill_wfind(struct crt_wfinddata64 *o, const os_find_dataw *d)
{
    o->attrib = d->dwFileAttributes == OS_FILE_ATTRIBUTE_NORMAL ? 0 : d->dwFileAttributes;
    o->time_create = ft_to_time(&d->ftCreationTime);
    o->time_access = ft_to_time(&d->ftLastAccessTime);
    o->time_write = ft_to_time(&d->ftLastWriteTime);
    o->size = (long long)(((uint64_t)d->nFileSizeHigh << 32) | d->nFileSizeLow);
    crt_memcpy(o->name, d->cFileName, sizeof o->name);
}
static void w2n_find(struct crt_finddata64 *o, const struct crt_wfinddata64 *w)
{
    o->attrib = w->attrib; o->time_create = w->time_create; o->time_access = w->time_access;
    o->time_write = w->time_write; o->size = w->size;
    WideCharToMultiByte(OS_CP_ACP, 0, w->name, -1, o->name, 260, 0, 0);
}
DLLAPI intptr_t CRTAPI _wfindfirst64(const wchar16 *spec, struct crt_wfinddata64 *out)
{
    os_find_dataw d;
    os_handle h;
    CRT_VALIDATE(spec != 0 && out != 0, CRT_EINVAL, -1);
    h = find_first_full(spec, &d);
    if (h == OS_INVALID_HANDLE) {
        const os_dword e = GetLastError();
        crt_dosmaperr(e);
        if (e == 2 || e == 3 || e == 18) crt_set_errno(CRT_ENOENT);
        return -1;
    }
    fill_wfind(out, &d);
    return (intptr_t)h;
}
DLLAPI int CRTAPI _wfindnext64(intptr_t h, struct crt_wfinddata64 *out)
{
    os_find_dataw d;
    CRT_VALIDATE(h != -1 && out != 0, CRT_EINVAL, -1);
    if (!FindNextFileW((os_handle)h, &d)) {
        const os_dword e = GetLastError();
        crt_dosmaperr(e);
        if (e == 18) crt_set_errno(CRT_ENOENT);
        return -1;
    }
    fill_wfind(out, &d);
    return 0;
}
DLLAPI intptr_t CRTAPI _findfirst64(const char *spec, struct crt_finddata64 *out)
{
    struct crt_wfinddata64 w;
    wchar16 *ws;
    intptr_t h;
    CRT_VALIDATE(spec != 0 && out != 0, CRT_EINVAL, -1);
    ws = path_to_wide(spec);
    if (!ws) return -1;
    h = _wfindfirst64(ws, &w);
    crt_free(ws);
    if (h != -1) w2n_find(out, &w);
    return h;
}
DLLAPI int CRTAPI _findnext64(intptr_t h, struct crt_finddata64 *out)
{
    struct crt_wfinddata64 w;
    CRT_VALIDATE(out != 0, CRT_EINVAL, -1);
    if (_wfindnext64(h, &w)) return -1;
    w2n_find(out, &w);
    return 0;
}
DLLAPI int CRTAPI _findclose(intptr_t h)
{
    if (!FindClose((os_handle)h)) { crt_dosmaperr(GetLastError()); return -1; }
    return 0;
}
