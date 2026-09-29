/* SPDX-License-Identifier: GPL-2.0-only
 * Buffered streams (FILE) of the Shizuku UCRT over the descriptor layer of lowio.c: fopen family, fread / fwrite,
 * character and line I/O (narrow and wide), seeking, buffering control, the stream table behind __acrt_iob_func,
 * and the stream entry points of the printf / scanf engines (__stdio_common_vf[w]printf[_s|_p], __stdio_common_vf[w]scanf).
 *
 * FILE is opaque in the UCRT headers (struct _iobuf { void *_Placeholder; }); _get_stream_buffer_pointers exposes the
 * buffer fields. Buffering follows the documented UCRT behaviour: disk files and pipes are fully buffered (4096
 * bytes), stderr is unbuffered, and output to a character device (the console) is buffered only for the duration of
 * one call and then flushed. Streams are locked with a recursive lock (_lock_file may be nested with any stream call).
 */
#include "crtint.h"
#include "crtos.h"

#define S_READ 0x0001
#define S_WRITE 0x0002
#define S_UPDATE 0x0004
#define S_EOF 0x0008
#define S_ERROR 0x0010
#define S_BUF_CRT 0x0040
#define S_BUF_USER 0x0080
#define S_BUF_NONE 0x0400
#define S_STRING 0x1000
#define S_INUSE 0x2000
#define S_READING 0x4000
#define S_WRITING 0x8000
#define S_DEVFLUSH 0x10000                     /* flush at the end of every output call (console) */
#define S_WIDE_TEXT 0x20000                    /* descriptor in a Unicode text mode: wide I/O writes UTF-16 units */
#define S_CHECKED 0x40000                      /* buffering mode decided (device check done or setvbuf called) */
#define BUFSZ 4096

typedef struct crt_file {
    char *ptr;
    char *base;
    int cnt;
    long flags;
    long fd;
    int charbuf;
    int bufsiz;
    char *tmpfname;
    os_critsec lock;
} crt_file;

#define MAX_STREAMS 512
static crt_file g_std[3];
static crt_file *g_streams[MAX_STREAMS];
static int g_max_streams = MAX_STREAMS;
static int g_stdio_ready;
int crt_fd_textmode(int fd);
int crt_fd_is_device(int fd);
int CRTAPI _close(int);
int CRTAPI _read(int, void *, unsigned);
int CRTAPI _write(int, const void *, unsigned);
long long CRTAPI _lseeki64(int, long long, int);
crt_errno_t CRTAPI _wsopen_dispatch(const wchar16 *, int, int, int, int *, int);
int CRTAPI _wunlink(const wchar16 *);

void crt_stdio_init(void)
{
    int i;
    for (i = 0; i < 3; ++i) {
        crt_file *f = &g_std[i];
        f->fd = i;
        f->flags = S_INUSE | (i == 0 ? S_READ : S_WRITE);
        if (i == 2) f->flags |= S_BUF_NONE;
        f->charbuf = 0;
        InitializeCriticalSection(&f->lock);
        g_streams[i] = f;
    }
    g_stdio_ready = 1;
}

DLLAPI crt_file *CRTAPI __acrt_iob_func(unsigned i) { return i < 3 ? &g_std[i] : 0; }
DLLAPI void CRTAPI _lock_file(crt_file *f) { EnterCriticalSection(&f->lock); }
DLLAPI void CRTAPI _unlock_file(crt_file *f) { LeaveCriticalSection(&f->lock); }
DLLAPI crt_errno_t CRTAPI _get_stream_buffer_pointers(crt_file *f, char ***base, char ***ptr, int **cnt)
{
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EINVAL);
    if (base) *base = &f->base;
    if (ptr) *ptr = &f->ptr;
    if (cnt) *cnt = &f->cnt;
    return 0;
}
DLLAPI int CRTAPI _fileno(crt_file *f) { CRT_VALIDATE(f != 0, CRT_EINVAL, -1); return (int)f->fd; }
DLLAPI int CRTAPI _getmaxstdio(void) { return g_max_streams; }
DLLAPI int CRTAPI _setmaxstdio(int n)
{
    CRT_VALIDATE(n >= 3 && n <= MAX_STREAMS, CRT_EINVAL, -1);   /* this CRT's table has a fixed 512 slots */
    g_max_streams = n;
    return n;
}

/* ---------------------------------------------------------------- stream table */
static crt_file *stream_alloc(void)
{
    int i;
    crt_lock(CRT_LOCK_STREAMS);
    for (i = 3; i < g_max_streams; ++i) {
        crt_file *f = g_streams[i];
        if (!f) {
            f = crt_calloc(1, sizeof *f);
            if (!f) break;
            InitializeCriticalSection(&f->lock);
            g_streams[i] = f;
        }
        if (!(f->flags & S_INUSE)) {
            f->flags = S_INUSE;
            f->ptr = f->base = 0;
            f->cnt = 0;
            f->fd = -1;
            f->bufsiz = 0;
            f->tmpfname = 0;
            crt_unlock(CRT_LOCK_STREAMS);
            return f;
        }
    }
    crt_unlock(CRT_LOCK_STREAMS);
    crt_set_errno(CRT_EMFILE);
    return 0;
}

/* ---------------------------------------------------------------- buffer management */
static void get_buffer(crt_file *f)
{
    if (f->base || (f->flags & S_BUF_NONE)) return;
    f->base = crt_malloc(BUFSZ);
    if (f->base) { f->bufsiz = BUFSZ; f->flags |= S_BUF_CRT; }
    else { f->flags |= S_BUF_NONE; }
    f->ptr = f->base;
    f->cnt = 0;
}
static void setup_new_stream(crt_file *f)
{
    const int tm = crt_fd_textmode((int)f->fd);
    if (tm >= 2) f->flags |= S_WIDE_TEXT;
    if (crt_fd_is_device((int)f->fd) && !(f->flags & S_BUF_USER)) f->flags |= S_DEVFLUSH;
}

/* writes out pending output; 0 or EOF */
static int flush_locked(crt_file *f)
{
    int r = 0;
    if ((f->flags & S_WRITING) && f->base && f->ptr > f->base) {
        const unsigned n = (unsigned)(f->ptr - f->base);
        if (_write((int)f->fd, f->base, n) != (int)n) { f->flags |= S_ERROR; r = CRT_EOF; }
    }
    if (f->flags & S_WRITING) {
        f->ptr = f->base;
        f->cnt = 0;
        if (f->flags & S_UPDATE) f->flags &= ~S_WRITING;
    }
    return r;
}

static int std_ready(crt_file *f)
{
    if (f >= g_std && f < g_std + 3 && !(f->flags & S_CHECKED)) {
        setup_new_stream(f);
        f->flags |= S_CHECKED;
    }
    return 1;
}

/* switch to writing; returns 0 or -1 (stream not writable / in read mode) */
static int begin_write(crt_file *f)
{
    std_ready(f);
    if (f->flags & S_STRING) return 0;
    if (!(f->flags & (S_WRITE | S_UPDATE))) { f->flags |= S_ERROR; crt_set_errno(CRT_EBADF); return -1; }
    if (f->flags & S_READING) {
        if (!(f->flags & S_EOF) && f->cnt > 0) { f->flags |= S_ERROR; return -1; }
        f->flags &= ~(S_READING | S_EOF);
        f->ptr = f->base;
        f->cnt = 0;
    }
    if (!(f->flags & S_WRITING)) {
        f->flags |= S_WRITING;
        f->flags &= ~S_EOF;
        get_buffer(f);
        f->ptr = f->base;
        f->cnt = f->base ? f->bufsiz : 0;
    }
    return 0;
}

static int put_bytes(crt_file *f, const char *p, size_t n)
{
    if (begin_write(f) < 0) return -1;
    if (f->flags & S_STRING) return -1;
    if (!f->base) {                                            /* unbuffered */
        while (n) {
            const unsigned k = n > 0x40000000u ? 0x40000000u : (unsigned)n;
            if (_write((int)f->fd, p, k) != (int)k) { f->flags |= S_ERROR; return -1; }
            p += k;
            n -= k;
        }
        return 0;
    }
    while (n) {
        size_t room = (size_t)f->cnt, k;
        if (!room) {
            if (flush_locked(f) < 0) return -1;
            f->flags |= S_WRITING;
            f->ptr = f->base;
            f->cnt = f->bufsiz;
            room = (size_t)f->cnt;
            if (n >= room) {                                   /* large write: bypass the buffer */
                const unsigned w = (unsigned)(n > 0x40000000u ? 0x40000000u : n - n % (size_t)f->bufsiz);
                if (w) {
                    if (_write((int)f->fd, p, w) != (int)w) { f->flags |= S_ERROR; return -1; }
                    p += w;
                    n -= w;
                    continue;
                }
            }
        }
        k = n < room ? n : room;
        crt_memcpy(f->ptr, p, k);
        f->ptr += k;
        f->cnt -= (int)k;
        p += k;
        n -= k;
    }
    return 0;
}
static void end_output_call(crt_file *f)
{
    if (f->flags & (S_DEVFLUSH | S_BUF_NONE)) flush_locked(f);
}

/* refills the read buffer; returns the next byte or EOF */
static int fill_locked(crt_file *f)
{
    int n;
    std_ready(f);
    if (f->flags & S_STRING) { f->flags |= S_EOF; return CRT_EOF; }
    if (!(f->flags & (S_READ | S_UPDATE))) { f->flags |= S_ERROR; crt_set_errno(CRT_EBADF); return CRT_EOF; }
    if (f->flags & S_WRITING) {
        if (!(f->flags & S_UPDATE)) { f->flags |= S_ERROR; return CRT_EOF; }
        if (flush_locked(f) < 0) return CRT_EOF;
        f->flags &= ~S_WRITING;
    }
    f->flags |= S_READING;
    /* reading from stdin flushes a console stdout first, as interactive programs expect */
    if (f == &g_std[0] && (g_std[1].flags & S_WRITING)) { EnterCriticalSection(&g_std[1].lock); flush_locked(&g_std[1]); LeaveCriticalSection(&g_std[1].lock); }
    get_buffer(f);
    if (f->base) n = _read((int)f->fd, f->base, (unsigned)f->bufsiz);
    else n = _read((int)f->fd, &f->charbuf, 1);
    if (n <= 0) {
        f->flags |= n == 0 ? S_EOF : S_ERROR;
        f->cnt = 0;
        return CRT_EOF;
    }
    if (!f->base) return (unsigned char)f->charbuf;
    f->ptr = f->base + 1;
    f->cnt = n - 1;
    return (unsigned char)f->base[0];
}
static int getc_locked(crt_file *f)
{
    if ((f->flags & S_READING) && f->cnt > 0) {
        --f->cnt;
        return (unsigned char)*f->ptr++;
    }
    return fill_locked(f);
}

/* ---------------------------------------------------------------- open / close */
typedef struct { int oflag, sflags; } open_mode;
static int parse_mode(const wchar16 *m, open_mode *om)
{
    int plus = 0, got_tb = 0;
    om->oflag = 0;
    om->sflags = 0;
    while (*m == ' ') ++m;
    switch (*m++) {
    case 'r': om->oflag = 0x0000; om->sflags = S_READ; break;
    case 'w': om->oflag = 0x0001 | 0x0100 | 0x0200; om->sflags = S_WRITE; break;
    case 'a': om->oflag = 0x0001 | 0x0100 | 0x0008; om->sflags = S_WRITE; break;
    default: return -1;
    }
    for (; *m; ++m) {
        switch (*m) {
        case '+':
            if (plus) return -1;
            plus = 1;
            om->oflag = (om->oflag & ~3) | 0x0002;
            om->sflags = S_UPDATE;
            break;
        case 'b': if (got_tb) return -1; got_tb = 1; om->oflag |= 0x8000; break;
        case 't': if (got_tb) return -1; got_tb = 1; om->oflag |= 0x4000; break;
        case 'x': om->oflag |= 0x0400; break;
        case 'c': case 'n': break;                                  /* commit flags: no disk cache here */
        case 'N': om->oflag |= 0x0080; break;
        case 'S': om->oflag |= 0x0020; break;
        case 'R': om->oflag |= 0x0010; break;
        case 'T': om->oflag |= 0x1000; break;
        case 'D': om->oflag |= 0x0040; break;
        case ' ': break;
        case ',': {
            /* ccs=UTF-8 | UTF-16LE | UNICODE */
            const wchar16 *p = m + 1;
            static const char *const names[] = { "ccs=UTF-8", "ccs=UTF-16LE", "ccs=UNICODE" };
            static const int modes[] = { 0x40000, 0x20000, 0x10000 };
            unsigned i, j;
            while (*p == ' ') ++p;
            for (i = 0; i < 3; ++i) {
                for (j = 0; names[i][j] && crt_towupper_c(p[j]) == (unsigned)crt_toupper_c(names[i][j]); ++j) {}
                if (!names[i][j]) {
                    om->oflag = (om->oflag & ~(0x4000 | 0x8000)) | modes[i];
                    m = p + j - 1;
                    break;
                }
            }
            if (i == 3) return -1;
            break;
        }
        default: return -1;
        }
    }
    return 0;
}

static crt_file *open_common(const wchar16 *name, const wchar16 *mode, int shflag, crt_file *reuse)
{
    open_mode om;
    int fd;
    crt_file *f;
    crt_errno_t e;
    if (parse_mode(mode, &om) < 0) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    e = _wsopen_dispatch(name, om.oflag, shflag, 0x180, &fd, 0);
    if (e) return 0;
    f = reuse ? reuse : stream_alloc();
    if (!f) { _close(fd); return 0; }
    f->flags = S_INUSE | om.sflags;
    f->fd = fd;
    f->ptr = f->base = 0;
    f->cnt = 0;
    f->bufsiz = 0;
    setup_new_stream(f);
    return f;
}
static wchar16 *to_wide(const char *s)
{
    int n = MultiByteToWideChar(OS_CP_ACP, 0, s, -1, 0, 0);
    wchar16 *w = n > 0 ? crt_malloc((size_t)n * sizeof(wchar16)) : 0;
    if (w) MultiByteToWideChar(OS_CP_ACP, 0, s, -1, w, n);
    return w;
}
DLLAPI crt_file *CRTAPI _wfsopen(const wchar16 *name, const wchar16 *mode, int sh)
{
    CRT_VALIDATE(name != 0 && mode != 0 && *mode, CRT_EINVAL, 0);
    CRT_VALIDATE(*name, CRT_EINVAL, 0);
    return open_common(name, mode, sh, 0);
}
DLLAPI crt_file *CRTAPI _fsopen(const char *name, const char *mode, int sh)
{
    wchar16 *wn, *wm;
    crt_file *f = 0;
    CRT_VALIDATE(name != 0 && mode != 0 && *mode, CRT_EINVAL, 0);
    CRT_VALIDATE(*name, CRT_EINVAL, 0);
    wn = to_wide(name);
    wm = to_wide(mode);
    if (wn && wm) f = open_common(wn, wm, sh, 0);
    else crt_set_errno(CRT_ENOMEM);
    crt_free(wn);
    crt_free(wm);
    return f;
}
DLLAPI crt_file *CRTAPI fopen(const char *name, const char *mode) { return _fsopen(name, mode, 0x40); }
DLLAPI crt_file *CRTAPI _wfopen(const wchar16 *name, const wchar16 *mode) { return _wfsopen(name, mode, 0x40); }
DLLAPI crt_errno_t CRTAPI fopen_s(crt_file **out, const char *name, const char *mode)
{
    CRT_VALIDATE(out != 0, CRT_EINVAL, CRT_EINVAL);
    *out = _fsopen(name, mode, 0x10);                               /* the secure form denies sharing */
    return *out ? 0 : crt_get_errno();
}
DLLAPI crt_errno_t CRTAPI _wfopen_s(crt_file **out, const wchar16 *name, const wchar16 *mode)
{
    CRT_VALIDATE(out != 0, CRT_EINVAL, CRT_EINVAL);
    *out = _wfsopen(name, mode, 0x10);
    return *out ? 0 : crt_get_errno();
}

static int close_locked(crt_file *f)
{
    int r = 0;
    if (!(f->flags & S_INUSE)) { crt_set_errno(CRT_EINVAL); return CRT_EOF; }
    if (f->flags & S_STRING) { f->flags = 0; return 0; }
    if (flush_locked(f) < 0) r = CRT_EOF;
    if (f->flags & S_BUF_CRT) crt_free(f->base);
    f->base = f->ptr = 0;
    f->cnt = 0;
    if (f->fd >= 0 && _close((int)f->fd) < 0) r = CRT_EOF;
    if (f->tmpfname) {
        wchar16 *w = to_wide(f->tmpfname);
        if (w) { _wunlink(w); crt_free(w); }
        crt_free(f->tmpfname);
        f->tmpfname = 0;
    }
    f->flags = 0;
    f->fd = -1;
    return r;
}
DLLAPI int CRTAPI fclose(crt_file *f)
{
    int r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = close_locked(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI _fclose_nolock(crt_file *f) { CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EOF); return close_locked(f); }
DLLAPI int CRTAPI _fcloseall(void)
{
    int i, n = 0;
    for (i = 3; i < MAX_STREAMS; ++i) {
        crt_file *f = g_streams[i];
        if (f && (f->flags & S_INUSE) && fclose(f) == 0) ++n;
    }
    return n;
}

static crt_file *reopen_common(const wchar16 *name, const wchar16 *mode, crt_file *f)
{
    crt_file *r;
    EnterCriticalSection(&f->lock);
    if (f->flags & S_INUSE) close_locked(f);
    r = open_common(name, mode, 0x40, f);
    if (!r) f->flags = 0;
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI crt_file *CRTAPI _wfreopen(const wchar16 *name, const wchar16 *mode, crt_file *f)
{
    CRT_VALIDATE(name != 0 && mode != 0 && f != 0, CRT_EINVAL, 0);
    return reopen_common(name, mode, f);
}
DLLAPI crt_file *CRTAPI freopen(const char *name, const char *mode, crt_file *f)
{
    wchar16 *wn, *wm;
    crt_file *r = 0;
    CRT_VALIDATE(name != 0 && mode != 0 && f != 0, CRT_EINVAL, 0);
    wn = to_wide(name);
    wm = to_wide(mode);
    if (wn && wm) r = reopen_common(wn, wm, f);
    crt_free(wn);
    crt_free(wm);
    return r;
}
DLLAPI crt_errno_t CRTAPI freopen_s(crt_file **out, const char *name, const char *mode, crt_file *f)
{
    CRT_VALIDATE(out != 0, CRT_EINVAL, CRT_EINVAL);
    *out = freopen(name, mode, f);
    return *out ? 0 : crt_get_errno();
}
DLLAPI crt_errno_t CRTAPI _wfreopen_s(crt_file **out, const wchar16 *name, const wchar16 *mode, crt_file *f)
{
    CRT_VALIDATE(out != 0, CRT_EINVAL, CRT_EINVAL);
    *out = _wfreopen(name, mode, f);
    return *out ? 0 : crt_get_errno();
}
static crt_file *fdopen_common(int fd, const wchar16 *mode)
{
    open_mode om;
    crt_file *f;
    CRT_VALIDATE(mode != 0, CRT_EINVAL, 0);
    if (parse_mode(mode, &om) < 0 || crt_fd_textmode(fd) < 0) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return 0; }
    f = stream_alloc();
    if (!f) return 0;
    f->flags = S_INUSE | om.sflags;
    f->fd = fd;
    setup_new_stream(f);
    return f;
}
DLLAPI crt_file *CRTAPI _wfdopen(int fd, const wchar16 *mode) { return fdopen_common(fd, mode); }
DLLAPI crt_file *CRTAPI _fdopen(int fd, const char *mode)
{
    wchar16 wm[32];
    size_t i;
    CRT_VALIDATE(mode != 0, CRT_EINVAL, 0);
    for (i = 0; mode[i] && i < 31; ++i) wm[i] = (unsigned char)mode[i];
    wm[i] = 0;
    return fdopen_common(fd, wm);
}

/* ---------------------------------------------------------------- flushing */
DLLAPI int CRTAPI _fflush_nolock(crt_file *f)
{
    if (!f) return 0;
    return flush_locked(f);
}
static int flush_all(int count_only_ok)
{
    int i, n = 0, err = 0;
    for (i = 0; i < MAX_STREAMS; ++i) {
        crt_file *f = g_streams[i];
        if (!f || !(f->flags & S_INUSE)) continue;
        EnterCriticalSection(&f->lock);
        if (flush_locked(f) < 0) err = 1;
        else ++n;
        LeaveCriticalSection(&f->lock);
    }
    return count_only_ok ? n : (err ? CRT_EOF : 0);
}
DLLAPI int CRTAPI fflush(crt_file *f)
{
    int r;
    if (!f) return flush_all(0);
    EnterCriticalSection(&f->lock);
    r = flush_locked(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI _flushall(void) { return flush_all(1); }
void crt_flushall_close(int close)
{
    int i;
    if (!g_stdio_ready) return;
    flush_all(0);
    if (!close) return;
    for (i = 3; i < MAX_STREAMS; ++i) {                           /* temporary files are removed at exit */
        crt_file *f = g_streams[i];
        if (f && (f->flags & S_INUSE) && f->tmpfname) fclose(f);
    }
}

/* ---------------------------------------------------------------- character I/O */
DLLAPI int CRTAPI _fputc_nolock(int c, crt_file *f)
{
    const char ch = (char)c;
    if (put_bytes(f, &ch, 1) < 0) return CRT_EOF;
    return (unsigned char)ch;
}
DLLAPI int CRTAPI fputc(int c, crt_file *f)
{
    int r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = _fputc_nolock(c, f);
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI putc(int c, crt_file *f) { return fputc(c, f); }
DLLAPI int CRTAPI _putc_nolock(int c, crt_file *f) { return _fputc_nolock(c, f); }
DLLAPI int CRTAPI putchar(int c) { return fputc(c, &g_std[1]); }
DLLAPI int CRTAPI _fputchar(int c) { return fputc(c, &g_std[1]); }
DLLAPI int CRTAPI _fgetc_nolock(crt_file *f) { return getc_locked(f); }
DLLAPI int CRTAPI fgetc(crt_file *f)
{
    int r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = getc_locked(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI getc(crt_file *f) { return fgetc(f); }
DLLAPI int CRTAPI _getc_nolock(crt_file *f) { return getc_locked(f); }
DLLAPI int CRTAPI getchar(void) { return fgetc(&g_std[0]); }
DLLAPI int CRTAPI _fgetchar(void) { return fgetc(&g_std[0]); }

static int ungetc_locked(int c, crt_file *f)
{
    if (c == CRT_EOF) return CRT_EOF;
    if (f->flags & S_WRITING) {
        if (!(f->flags & S_UPDATE)) return CRT_EOF;
        if (flush_locked(f) < 0) return CRT_EOF;
        f->flags &= ~S_WRITING;
    }
    if (!(f->flags & (S_READ | S_UPDATE | S_STRING))) return CRT_EOF;
    f->flags |= S_READING;
    if (!f->base) {
        get_buffer(f);
        if (!f->base) {                                             /* unbuffered: one character in charbuf */
            if (f->cnt) return CRT_EOF;
            f->charbuf = c;
            f->ptr = (char *)&f->charbuf;
            f->cnt = 1;
            f->flags &= ~S_EOF;
            return c & 0xff;
        }
        f->ptr = f->base + f->bufsiz;
        f->cnt = 0;
    }
    if (f->ptr == f->base) {
        if (f->cnt) return CRT_EOF;                                 /* no room in front of unread data */
        ++f->ptr;
    }
    if (f->flags & S_STRING) {
        if (*(f->ptr - 1) != (char)c) return CRT_EOF;               /* a string source is not modified */
        --f->ptr;
    } else *--f->ptr = (char)c;
    ++f->cnt;
    f->flags &= ~S_EOF;
    return c & 0xff;
}
DLLAPI int CRTAPI _ungetc_nolock(int c, crt_file *f) { return ungetc_locked(c, f); }
DLLAPI int CRTAPI ungetc(int c, crt_file *f)
{
    int r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = ungetc_locked(c, f);
    LeaveCriticalSection(&f->lock);
    return r;
}

/* ---------------------------------------------------------------- block I/O */
DLLAPI size_t CRTAPI _fwrite_nolock(const void *buf, size_t size, size_t count, crt_file *f)
{
    size_t total, done = 0;
    if (!size || !count) return 0;
    CRT_VALIDATE(f != 0 && buf != 0, CRT_EINVAL, 0);
    CRT_VALIDATE(count <= (size_t)-1 / size, CRT_EINVAL, 0);
    total = size * count;
    if (put_bytes(f, buf, total) < 0) {
        /* how much reached the buffer or the file is not tracked byte-exactly after an error */
        return done / size;
    }
    return count;
}
DLLAPI size_t CRTAPI fwrite(const void *buf, size_t size, size_t count, crt_file *f)
{
    size_t r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, 0);
    EnterCriticalSection(&f->lock);
    r = _fwrite_nolock(buf, size, count, f);
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI size_t CRTAPI _fread_nolock_s(void *buf, size_t bufsize, size_t size, size_t count, crt_file *f)
{
    char *p = buf;
    size_t total, got = 0;
    if (!size || !count) return 0;
    CRT_VALIDATE(f != 0 && buf != 0, CRT_EINVAL, 0);
    CRT_VALIDATE(count <= (size_t)-1 / size, CRT_EINVAL, 0);
    total = size * count;
    if (total > bufsize) { crt_memset(buf, 0, bufsize); CRT_VALIDATE(0, CRT_ERANGE, 0); }
    while (got < total) {
        if ((f->flags & S_READING) && f->cnt > 0) {
            size_t k = (size_t)f->cnt < total - got ? (size_t)f->cnt : total - got;
            crt_memcpy(p + got, f->ptr, k);
            f->ptr += k;
            f->cnt -= (int)k;
            got += k;
            continue;
        }
        if (f->base && total - got >= (size_t)f->bufsiz && (f->flags & S_READING) && !(f->flags & S_STRING)) {
            /* large read straight into the caller's buffer */
            const unsigned want = (unsigned)((total - got) > 0x40000000u ? 0x40000000u : total - got - (total - got) % (size_t)f->bufsiz);
            int n = _read((int)f->fd, p + got, want);
            if (n <= 0) { f->flags |= n == 0 ? S_EOF : S_ERROR; break; }
            got += (size_t)n;
            continue;
        }
        {
            int c = fill_locked(f);
            if (c == CRT_EOF) break;
            p[got++] = (char)c;
        }
    }
    return got / size;
}
DLLAPI size_t CRTAPI _fread_nolock(void *buf, size_t size, size_t count, crt_file *f)
{
    return _fread_nolock_s(buf, (size_t)-1, size, count, f);
}
DLLAPI size_t CRTAPI fread_s(void *buf, size_t bufsize, size_t size, size_t count, crt_file *f)
{
    size_t r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, 0);
    EnterCriticalSection(&f->lock);
    r = _fread_nolock_s(buf, bufsize, size, count, f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI size_t CRTAPI fread(void *buf, size_t size, size_t count, crt_file *f) { return fread_s(buf, (size_t)-1, size, count, f); }

/* ---------------------------------------------------------------- lines */
DLLAPI char *CRTAPI fgets(char *buf, int n, crt_file *f)
{
    int i = 0, c = 0;
    CRT_VALIDATE(buf != 0 && n > 0 && f != 0, CRT_EINVAL, 0);
    EnterCriticalSection(&f->lock);
    while (i < n - 1) {
        c = getc_locked(f);
        if (c == CRT_EOF) break;
        buf[i++] = (char)c;
        if (c == '\n') break;
    }
    LeaveCriticalSection(&f->lock);
    if (i == 0 && n > 1) return 0;
    if (c == CRT_EOF && (f->flags & S_ERROR)) return 0;
    buf[i] = 0;
    return buf;
}
DLLAPI int CRTAPI fputs(const char *s, crt_file *f)
{
    int r;
    CRT_VALIDATE(s != 0 && f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = put_bytes(f, s, crt_strlen(s)) < 0 ? CRT_EOF : 0;
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI puts(const char *s)
{
    crt_file *f = &g_std[1];
    int r;
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = (put_bytes(f, s, crt_strlen(s)) < 0 || put_bytes(f, "\n", 1) < 0) ? CRT_EOF : 0;
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI char *CRTAPI gets_s(char *buf, size_t n)
{
    crt_file *f = &g_std[0];
    size_t i = 0;
    int c;
    CRT_VALIDATE(buf != 0 && n > 0, CRT_EINVAL, 0);
    EnterCriticalSection(&f->lock);
    for (;;) {
        c = getc_locked(f);
        if (c == CRT_EOF || c == '\n') break;
        if (i + 1 >= n) {                                            /* line too long: discard the rest */
            while (c != CRT_EOF && c != '\n') c = getc_locked(f);
            LeaveCriticalSection(&f->lock);
            buf[0] = 0;
            CRT_VALIDATE(0, CRT_ERANGE, 0);
        }
        buf[i++] = (char)c;
    }
    LeaveCriticalSection(&f->lock);
    if (c == CRT_EOF && i == 0) return 0;
    buf[i] = 0;
    return buf;
}

/* ---------------------------------------------------------------- wide character I/O */
static int wide_units_mode(crt_file *f) { std_ready(f); return (f->flags & S_WIDE_TEXT) || crt_fd_textmode((int)f->fd) == 0; }
DLLAPI crt_wint CRTAPI _fputwc_nolock(wchar16 c, crt_file *f)
{
    if (wide_units_mode(f) || (f->flags & S_STRING)) {
        if (put_bytes(f, (const char *)&c, 2) < 0) return CRT_WEOF;
        return c;
    } else {
        char ch;
        if (crt_wctomb_c(&ch, c) < 0) { crt_set_errno(CRT_EILSEQ); f->flags |= S_ERROR; return CRT_WEOF; }
        if (put_bytes(f, &ch, 1) < 0) return CRT_WEOF;
        return c;
    }
}
DLLAPI crt_wint CRTAPI fputwc(wchar16 c, crt_file *f)
{
    crt_wint r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_WEOF);
    EnterCriticalSection(&f->lock);
    r = _fputwc_nolock(c, f);
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI crt_wint CRTAPI putwc(wchar16 c, crt_file *f) { return fputwc(c, f); }
DLLAPI crt_wint CRTAPI putwchar(wchar16 c) { return fputwc(c, &g_std[1]); }
DLLAPI crt_wint CRTAPI _fputwchar(wchar16 c) { return fputwc(c, &g_std[1]); }
DLLAPI crt_wint CRTAPI _putwc_nolock(wchar16 c, crt_file *f) { return _fputwc_nolock(c, f); }
DLLAPI crt_wint CRTAPI _fgetwc_nolock(crt_file *f)
{
    if (wide_units_mode(f)) {
        const int a = getc_locked(f), b = a == CRT_EOF ? CRT_EOF : getc_locked(f);
        if (a == CRT_EOF || b == CRT_EOF) return CRT_WEOF;
        return (crt_wint)(a | (b << 8));
    } else {
        const int c = getc_locked(f);
        return c == CRT_EOF ? CRT_WEOF : (crt_wint)c;                  /* C locale: bytes are U+0000..U+00FF */
    }
}
DLLAPI crt_wint CRTAPI fgetwc(crt_file *f)
{
    crt_wint r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_WEOF);
    EnterCriticalSection(&f->lock);
    r = _fgetwc_nolock(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI crt_wint CRTAPI getwc(crt_file *f) { return fgetwc(f); }
DLLAPI crt_wint CRTAPI getwchar(void) { return fgetwc(&g_std[0]); }
DLLAPI crt_wint CRTAPI _fgetwchar(void) { return fgetwc(&g_std[0]); }
DLLAPI crt_wint CRTAPI _getwc_nolock(crt_file *f) { return _fgetwc_nolock(f); }
DLLAPI crt_wint CRTAPI ungetwc(crt_wint c, crt_file *f)
{
    crt_wint r = c;
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_WEOF);
    if (c == CRT_WEOF) return CRT_WEOF;
    EnterCriticalSection(&f->lock);
    if (wide_units_mode(f)) {
        if (ungetc_locked(c >> 8, f) == CRT_EOF || ungetc_locked(c & 0xff, f) == CRT_EOF) r = CRT_WEOF;
    } else if (c > 0xff || ungetc_locked(c, f) == CRT_EOF) r = CRT_WEOF;
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI crt_wint CRTAPI _ungetwc_nolock(crt_wint c, crt_file *f) { return ungetwc(c, f); }
DLLAPI wchar16 *CRTAPI fgetws(wchar16 *buf, int n, crt_file *f)
{
    int i = 0;
    crt_wint c = 0;
    CRT_VALIDATE(buf != 0 && n > 0 && f != 0, CRT_EINVAL, 0);
    EnterCriticalSection(&f->lock);
    while (i < n - 1) {
        c = _fgetwc_nolock(f);
        if (c == CRT_WEOF) break;
        buf[i++] = c;
        if (c == '\n') break;
    }
    LeaveCriticalSection(&f->lock);
    if (i == 0 && n > 1) return 0;
    buf[i] = 0;
    return buf;
}
DLLAPI int CRTAPI fputws(const wchar16 *s, crt_file *f)
{
    int r = 0;
    CRT_VALIDATE(s != 0 && f != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    for (; *s; ++s)
        if (_fputwc_nolock(*s, f) == CRT_WEOF) { r = CRT_EOF; break; }
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI _putws(const wchar16 *s)
{
    int r;
    crt_file *f = &g_std[1];
    CRT_VALIDATE(s != 0, CRT_EINVAL, CRT_EOF);
    EnterCriticalSection(&f->lock);
    r = fputws(s, f);
    if (r == 0 && _fputwc_nolock('\n', f) == CRT_WEOF) r = CRT_EOF;
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}

/* ---------------------------------------------------------------- positioning */
static long long tell_locked(crt_file *f)
{
    long long pos;
    if (f->fd < 0) { crt_set_errno(CRT_EINVAL); return -1; }
    pos = _lseeki64((int)f->fd, 0, 1);
    if (pos < 0) return -1;
    if (f->flags & S_WRITING) {
        if (f->base) pos += f->ptr - f->base;
    } else if ((f->flags & S_READING) && f->cnt > 0) {
        long long unread = f->cnt;
        if (crt_fd_textmode((int)f->fd) == 1) {                     /* each LF in the buffer came from CR LF */
            int i;
            for (i = 0; i < f->cnt; ++i) if (f->ptr[i] == '\n') ++unread;
        }
        pos -= unread;
    }
    return pos;
}
DLLAPI long long CRTAPI _ftelli64_nolock(crt_file *f) { return tell_locked(f); }
DLLAPI long long CRTAPI _ftelli64(crt_file *f)
{
    long long r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, -1);
    EnterCriticalSection(&f->lock);
    r = tell_locked(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI crt_long CRTAPI ftell(crt_file *f)
{
    long long r = _ftelli64(f);
    if (r > CRT_LONG_MAX) { crt_set_errno(CRT_EINVAL); return -1; }
    return (crt_long)r;
}
DLLAPI crt_long CRTAPI _ftell_nolock(crt_file *f) { return (crt_long)tell_locked(f); }
static int seek_locked(crt_file *f, long long off, int whence)
{
    if (whence < 0 || whence > 2) { crt_set_errno(CRT_EINVAL); crt_invalid_parameter(); return -1; }
    if (whence == 1) {                                            /* relative to the logical position */
        long long cur = tell_locked(f);
        if (cur < 0) return -1;
        off += cur;
        whence = 0;
    }
    if (flush_locked(f) < 0) return -1;
    f->flags &= ~(S_EOF | S_READING);
    if (f->flags & S_UPDATE) f->flags &= ~S_WRITING;
    f->ptr = f->base;
    f->cnt = 0;
    if (f->fd < 0 || _lseeki64((int)f->fd, off, whence) < 0) return -1;
    return 0;
}
DLLAPI int CRTAPI _fseeki64_nolock(crt_file *f, long long off, int whence) { return seek_locked(f, off, whence); }
DLLAPI int CRTAPI _fseeki64(crt_file *f, long long off, int whence)
{
    int r;
    CRT_VALIDATE(f != 0, CRT_EINVAL, -1);
    EnterCriticalSection(&f->lock);
    r = seek_locked(f, off, whence);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI fseek(crt_file *f, crt_long off, int whence) { return _fseeki64(f, off, whence); }
DLLAPI int CRTAPI _fseek_nolock(crt_file *f, crt_long off, int whence) { return seek_locked(f, off, whence); }
DLLAPI void CRTAPI rewind(crt_file *f)
{
    CRT_VALIDATE_NORET(f != 0, CRT_EINVAL);
    EnterCriticalSection(&f->lock);
    seek_locked(f, 0, 0);
    f->flags &= ~S_ERROR;
    LeaveCriticalSection(&f->lock);
}
DLLAPI int CRTAPI fgetpos(crt_file *f, long long *pos)
{
    CRT_VALIDATE(f != 0 && pos != 0, CRT_EINVAL, -1);
    *pos = _ftelli64(f);
    return *pos < 0 ? -1 : 0;
}
DLLAPI int CRTAPI fsetpos(crt_file *f, const long long *pos)
{
    CRT_VALIDATE(f != 0 && pos != 0, CRT_EINVAL, -1);
    return _fseeki64(f, *pos, 0);
}
DLLAPI int CRTAPI feof(crt_file *f) { CRT_VALIDATE(f != 0, CRT_EINVAL, 0); return (f->flags & S_EOF) ? 0x10 : 0; }
DLLAPI int CRTAPI ferror(crt_file *f) { CRT_VALIDATE(f != 0, CRT_EINVAL, 0); return (f->flags & S_ERROR) ? 0x20 : 0; }
DLLAPI void CRTAPI clearerr(crt_file *f)
{
    CRT_VALIDATE_NORET(f != 0, CRT_EINVAL);
    EnterCriticalSection(&f->lock);
    f->flags &= ~(S_EOF | S_ERROR);
    LeaveCriticalSection(&f->lock);
}
DLLAPI crt_errno_t CRTAPI clearerr_s(crt_file *f)
{
    CRT_VALIDATE(f != 0, CRT_EINVAL, CRT_EINVAL);
    clearerr(f);
    return 0;
}

/* ---------------------------------------------------------------- buffering control */
DLLAPI int CRTAPI setvbuf(crt_file *f, char *buf, int mode, size_t size)
{
    CRT_VALIDATE(f != 0, CRT_EINVAL, -1);
    CRT_VALIDATE(mode == 0 /* _IOFBF */ || mode == 0x40 /* _IOLBF */ || mode == 4 /* _IONBF */, CRT_EINVAL, -1);
    if (mode != 4) CRT_VALIDATE(size >= 2 && size <= 0x7fffffff, CRT_EINVAL, -1);
    EnterCriticalSection(&f->lock);
    flush_locked(f);
    if (f->flags & S_BUF_CRT) crt_free(f->base);
    f->flags &= ~(S_BUF_CRT | S_BUF_USER | S_BUF_NONE | S_DEVFLUSH | S_READING | S_WRITING);
    f->base = f->ptr = 0;
    f->cnt = 0;
    f->bufsiz = 0;
    if (mode == 4) f->flags |= S_BUF_NONE;
    else {
        size &= ~(size_t)1;                                          /* the UCRT rounds the size down to even */
        if (buf) { f->base = buf; f->flags |= S_BUF_USER; }
        else {
            f->base = crt_malloc(size);
            if (!f->base) { LeaveCriticalSection(&f->lock); return -1; }
            f->flags |= S_BUF_CRT;
        }
        f->bufsiz = (int)size;
        f->ptr = f->base;
        /* _IOLBF is full buffering in the UCRT */
    }
    f->flags |= S_CHECKED;                                           /* explicit choice: no automatic device flush */
    LeaveCriticalSection(&f->lock);
    return 0;
}
DLLAPI void CRTAPI setbuf(crt_file *f, char *buf) { setvbuf(f, buf, buf ? 0 : 4, 512); }

/* ---------------------------------------------------------------- temporary files */
static unsigned g_tmp_counter;
static void make_tmp_name(char *out, size_t cap, unsigned n)
{
    /* "<TEMP>s<pid>.<n>" */
    wchar16 tp[260];
    char tmp[320];
    size_t k, i;
    os_dword len = GetTempPathW(260, tp);
    unsigned long long v;
    char digits[24];
    int nd;
    if (!len || len >= 260) { tp[0] = '.'; tp[1] = '\\'; tp[2] = 0; len = 2; }
    k = (size_t)WideCharToMultiByte(OS_CP_ACP, 0, tp, (int)len, tmp, 260, 0, 0);
    tmp[k++] = 's';
    v = GetCurrentProcessId();
    nd = 0; do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) tmp[k++] = digits[--nd];
    tmp[k++] = '.';
    v = n;
    nd = 0; do { digits[nd++] = (char)('0' + v % 10); v /= 10; } while (v);
    while (nd) tmp[k++] = digits[--nd];
    tmp[k] = 0;
    for (i = 0; i <= k && i < cap; ++i) out[i] = tmp[i];
    out[cap - 1] = 0;
}
DLLAPI crt_errno_t CRTAPI tmpfile_s(crt_file **out)
{
    char name[300];
    wchar16 *w;
    unsigned tries;
    CRT_VALIDATE(out != 0, CRT_EINVAL, CRT_EINVAL);
    *out = 0;
    for (tries = 0; tries < 1000; ++tries) {
        static const wchar16 mode[] = { 'w', '+', 'b', 'x', 'D', 0 };
        crt_file *f;
        make_tmp_name(name, sizeof name, ++g_tmp_counter);
        w = to_wide(name);
        if (!w) return CRT_ENOMEM;
        f = open_common(w, mode, 0x10, 0);
        crt_free(w);
        if (f) {
            f->tmpfname = crt_malloc(crt_strlen(name) + 1);
            if (f->tmpfname) crt_memcpy(f->tmpfname, name, crt_strlen(name) + 1);
            *out = f;
            return 0;
        }
        if (crt_get_errno() != CRT_EEXIST) return crt_get_errno();
    }
    return CRT_EEXIST;
}
DLLAPI crt_file *CRTAPI tmpfile(void)
{
    crt_file *f = 0;
    tmpfile_s(&f);
    return f;
}
DLLAPI crt_errno_t CRTAPI tmpnam_s(char *buf, size_t n)
{
    char name[300];
    size_t len;
    CRT_VALIDATE(buf != 0 && n > 0, CRT_EINVAL, CRT_EINVAL);
    make_tmp_name(name, sizeof name, ++g_tmp_counter);
    len = crt_strlen(name);
    if (len >= n) { buf[0] = 0; CRT_VALIDATE(0, CRT_ERANGE, CRT_ERANGE); }
    crt_memcpy(buf, name, len + 1);
    return 0;
}
DLLAPI char *CRTAPI tmpnam(char *buf)
{
    static char sbuf[300];
    if (!buf) buf = sbuf;
    return tmpnam_s(buf, 260) ? 0 : buf;
}
DLLAPI int CRTAPI _rmtmp(void)
{
    int i, n = 0;
    for (i = 3; i < MAX_STREAMS; ++i) {
        crt_file *f = g_streams[i];
        if (f && (f->flags & S_INUSE) && f->tmpfname && fclose(f) == 0) ++n;
    }
    return n;
}

/* ---------------------------------------------------------------- printf / scanf on streams */
static int stream_put(crt_out *o, const void *units, size_t n)
{
    crt_file *f = o->ctx;
    if (!o->wide) return put_bytes(f, units, n) < 0 ? -1 : 0;
    {
        const wchar16 *w = units;
        size_t i;
        for (i = 0; i < n; ++i)
            if (_fputwc_nolock(w[i], f) == CRT_WEOF) return -1;
        return 0;
    }
}
static int vfprintf_common(uint64_t options, crt_file *f, const void *fmt, int wide, va_list ap, int positional, int secure)
{
    crt_out o;
    va_list aq;
    int r;
    CRT_VALIDATE(f != 0 && fmt != 0, CRT_EINVAL, -1);
    (void)secure;
    o.wide = wide;
    o.put = stream_put;
    o.count = 0;
    o.stopped = 0;
    o.ctx = f;
    EnterCriticalSection(&f->lock);
    va_copy(aq, ap);
    r = positional ? crt_format_p(&o, options, fmt, wide, &aq) : crt_format(&o, options, fmt, wide, &aq);
    va_end(aq);
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI __stdio_common_vfprintf(uint64_t opt, crt_file *f, const char *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 0, ap, 0, 0);
}
DLLAPI int CRTAPI __stdio_common_vfprintf_s(uint64_t opt, crt_file *f, const char *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 0, ap, 0, 1);
}
DLLAPI int CRTAPI __stdio_common_vfprintf_p(uint64_t opt, crt_file *f, const char *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 0, ap, 1, 1);
}
DLLAPI int CRTAPI __stdio_common_vfwprintf(uint64_t opt, crt_file *f, const wchar16 *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 1, ap, 0, 0);
}
DLLAPI int CRTAPI __stdio_common_vfwprintf_s(uint64_t opt, crt_file *f, const wchar16 *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 1, ap, 0, 1);
}
DLLAPI int CRTAPI __stdio_common_vfwprintf_p(uint64_t opt, crt_file *f, const wchar16 *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfprintf_common(opt, f, fmt, 1, ap, 1, 1);
}

typedef struct { crt_in in; crt_file *f; int wide; } stream_in;
static int stream_get(crt_in *in)
{
    stream_in *s = (stream_in *)in;
    if (s->wide) {
        const crt_wint c = _fgetwc_nolock(s->f);
        return c == CRT_WEOF ? -1 : (int)c;
    }
    return getc_locked(s->f);
}
static void stream_unget(crt_in *in, int c)
{
    stream_in *s = (stream_in *)in;
    if (c < 0) return;
    if (s->wide) {
        if (wide_units_mode(s->f)) { ungetc_locked(c >> 8, s->f); ungetc_locked(c & 0xff, s->f); }
        else ungetc_locked(c, s->f);
    } else ungetc_locked(c, s->f);
}
static int vfscanf_common(uint64_t options, crt_file *f, const void *fmt, int wide, va_list ap)
{
    stream_in s;
    va_list aq;
    int r;
    CRT_VALIDATE(f != 0 && fmt != 0, CRT_EINVAL, CRT_EOF);
    crt_memset(&s, 0, sizeof s);
    s.in.get = stream_get;
    s.in.unget = stream_unget;
    s.f = f;
    s.wide = wide;
    EnterCriticalSection(&f->lock);
    va_copy(aq, ap);
    r = crt_scan(&s.in, options, fmt, wide, &aq);
    va_end(aq);
    LeaveCriticalSection(&f->lock);
    return r;
}
DLLAPI int CRTAPI __stdio_common_vfscanf(uint64_t opt, crt_file *f, const char *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfscanf_common(opt, f, fmt, 0, ap);
}
DLLAPI int CRTAPI __stdio_common_vfwscanf(uint64_t opt, crt_file *f, const wchar16 *fmt, void *loc, va_list ap)
{
    (void)loc;
    return vfscanf_common(opt, f, fmt, 1, ap);
}

/* ---------------------------------------------------------------- perror */
DLLAPI void CRTAPI perror(const char *prefix)
{
    char *CRTAPI _strerror(const char *);
    crt_file *f = &g_std[2];
    const char *m = _strerror(prefix);
    EnterCriticalSection(&f->lock);
    put_bytes(f, m, crt_strlen(m));
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
}
DLLAPI void CRTAPI _wperror(const wchar16 *prefix)
{
    wchar16 *CRTAPI __wcserror(const wchar16 *);
    const wchar16 *m = __wcserror(prefix);
    crt_file *f = &g_std[2];
    EnterCriticalSection(&f->lock);
    for (; *m; ++m) {
        char ch;
        if (crt_wctomb_c(&ch, *m) < 0) ch = '?';
        put_bytes(f, &ch, 1);
    }
    end_output_call(f);
    LeaveCriticalSection(&f->lock);
}
