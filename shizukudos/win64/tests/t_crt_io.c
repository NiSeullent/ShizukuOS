/* SPDX-License-Identifier: GPL-2.0-only
 * ucrtbase.dll streams and low-level I/O on the Shizuku Win64 runtime (through the import table, crt_imp.h):
 * text-mode CR LF translation in both directions (checked against the raw bytes with kernel32), fopen modes, buffered
 * fwrite/fread, fprintf/fscanf, fgets/ungetc/feof, fseek/ftell, the descriptor layer (_wsopen_dispatch as dxil.dll
 * calls it, _read/_write/_lseek/_chsize/_setmode/_dup/_get_osfhandle/_open_osfhandle/_fdopen), rename/remove/_access/
 * _stat64/_findfirst64, tmpfile, and stdout/stderr through __acrt_iob_func. Expected values follow the C standard and
 * Microsoft's documentation of text and binary mode.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"
#include "crt_imp.h"

#define O_RDONLY_ 0
#define O_WRONLY_ 1
#define O_RDWR_ 2
#define O_CREAT_ 0x100
#define O_TRUNC_ 0x200
#define O_TEXT_ 0x4000
#define O_BINARY_ 0x8000

static int inv_calls;
static void inv_handler(const unsigned short *e, const unsigned short *f, const unsigned short *file, unsigned line, uintptr_t r)
{
    (void)e; (void)f; (void)file; (void)line; (void)r;
    ++inv_calls;                                               /* return: the function fails with its documented errno */
}
static int raw_bytes(const WCHAR *name, char *buf, int cap)
{
    HANDLE h = CreateFileW(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    DWORD got = 0;
    if (h == INVALID_HANDLE_VALUE) return -1;
    ReadFile(h, buf, (DWORD)cap, &got, 0);
    CloseHandle(h);
    return (int)got;
}

int main(void)
{
    char buf[256];
    void *f;
    int n;

    U_CHECK("ucrtbase.dll is mapped and its string functions resolve", crt_imp_init());
    crt__set_invalid_parameter_handler(inv_handler);           /* the default handler would end the process */
    CreateDirectoryW(L"C:\\TEMP", 0);                          /* GetTempPath's directory, for tmpfile() */

    /* ---- text mode: LF -> CR LF on write, CR LF -> LF on read */
    f = crt_fopen("CRTIO1.TXT", "w");
    U_CHECK("fopen(\"w\") creates a file", f != 0);
    if (!f) return u_finish("t_crt_io");
    U_CHECK("fputs + fprintf", crt_fputs("line1\n", f) >= 0 && crt_fprintf(f, "%d|%s|%.3f\n", 42, "two", 2.5) == 13);
    U_CHECK("fclose flushes", crt_fclose(f) == 0);
    n = raw_bytes(L"CRTIO1.TXT", buf, sizeof buf);
    U_CHECK("the file holds CR LF line ends", n == 21 && !memcmp(buf, "line1\r\n42|two|2.500\r\n", 21));
    f = crt_fopen("CRTIO1.TXT", "r");
    {
        char l1[32] = "", l2[32] = "";
        int k = 0;
        char s[8] = "";
        double d = 0;
        U_CHECK("fgets reads LF-terminated lines in text mode", f && crt_fgets(l1, 32, f) && !crt_strcmp(l1, "line1\n"));
        U_CHECK("fscanf", crt_fscanf(f, "%d|%3s|%lf", &k, s, &d) == 3 && k == 42 && !crt_strcmp(s, "two") && d == 2.5);
        U_CHECK("fgetc sees the translated newline, then EOF", crt_fgetc(f) == '\n' && crt_fgetc(f) == -1 && crt_feof(f));
        (void)l2;
        crt_fclose(f);
    }
    /* ---- binary mode, seeking, ungetc */
    f = crt_fopen("CRTIO1.TXT", "rb");
    {
        char b[32];
        U_CHECK("fread in binary mode keeps CR LF", f && crt_fread(b, 1, 7, f) == 7 && !memcmp(b, "line1\r\n", 7));
        U_CHECK("ftell after 7 bytes", crt_ftell(f) == 7);
        U_CHECK("fseek to 2", crt_fseek(f, 2, 0) == 0 && crt_fgetc(f) == 'n');
        U_CHECK("ungetc pushes back", crt_ungetc('X', f) == 'X' && crt_fgetc(f) == 'X' && crt_fgetc(f) == 'e');
        U_CHECK("fseek from the end", crt_fseek(f, -2, 2) == 0 && crt_fgetc(f) == '\r' && crt_fgetc(f) == '\n' && crt_fgetc(f) == -1);
        crt_fclose(f);
    }
    /* ---- append and update modes */
    f = crt_fopen("CRTIO1.TXT", "ab");
    U_CHECK("append mode writes at the end", f && crt_fwrite("tail", 1, 4, f) == 4 && crt_fclose(f) == 0);
    n = raw_bytes(L"CRTIO1.TXT", buf, sizeof buf);
    U_CHECK("appended bytes", n == 25 && !memcmp(buf + 21, "tail", 4));
    f = crt_fopen("CRTIO1.TXT", "r+b");
    if (f) {
        crt_fseek(f, 0, 0);
        crt_fwrite("LINE", 1, 4, f);
        crt_fseek(f, 0, 1);                                   /* switching from writing to reading needs a seek */
        U_CHECK("update mode: read after write", crt_fgetc(f) == '1');
        crt_fclose(f);
    }
    n = raw_bytes(L"CRTIO1.TXT", buf, sizeof buf);
    U_CHECK("r+ overwrote in place", n == 25 && !memcmp(buf, "LINE1\r\n", 7));
    inv_calls = 0;
    f = crt_fopen("CRTIO1.TXT", "rq");
    U_CHECK("an invalid mode character is an invalid parameter (EINVAL)", f == 0 && inv_calls == 1 && *crt__errno() == 22);

    /* ---- descriptors (the functions dxil.dll imports) */
    {
        static const WCHAR name[] = L"CRTIO2.BIN";
        int fd = -1, fd2, oldmode;
        char b[16];
        U_CHECK("_wsopen_dispatch creates a file", crt__wsopen_dispatch(name, O_RDWR_ | O_CREAT_ | O_TRUNC_ | O_BINARY_, 0x40, 0x180, &fd, 0) == 0 && fd >= 3);
        U_CHECK("_write", crt__write(fd, "0123456789", 10) == 10);
        U_CHECK("_lseek returns the new position", crt__lseek(fd, 3, 0) == 3);
        U_CHECK("_read", crt__read(fd, b, 4) == 4 && !memcmp(b, "3456", 4));
        U_CHECK("_chsize truncates", crt__chsize(fd, 5) == 0 && crt__lseek(fd, 0, 2) == 5);
        U_CHECK("_chsize extends with zeros", crt__chsize(fd, 8) == 0 && crt__lseek(fd, 5, 0) == 5 && crt__read(fd, b, 8) == 3 && b[0] == 0 && b[2] == 0);
        U_CHECK("_get_osfhandle returns the Win32 handle", crt__get_osfhandle(fd) != -1 && GetFileType((HANDLE)crt__get_osfhandle(fd)) == FILE_TYPE_DISK);
        fd2 = crt__dup(fd);
        U_CHECK("_dup shares the file position", fd2 >= 0 && fd2 != fd && crt__lseek(fd2, 0, 1) == 8);
        oldmode = crt__setmode(fd2, O_TEXT_);
        U_CHECK("_setmode returns the previous mode", oldmode == O_BINARY_);
        crt__lseek(fd2, 0, 0);
        U_CHECK("text-mode _write translates", crt__write(fd2, "a\nb", 3) == 3 && crt__lseek(fd2, 0, 1) == 4);
        U_CHECK("_close", crt__close(fd2) == 0 && crt__close(fd) == 0);
        inv_calls = 0;
        U_CHECK("a closed descriptor is rejected (EBADF, invalid parameter)", crt__close(fd) == -1 && *crt__errno() == 9 && inv_calls == 1);
        n = raw_bytes(name, buf, sizeof buf);
        U_CHECK("file bytes after the descriptor tests", n == 8 && !memcmp(buf, "a\r\nb4", 5));
    }
    {
        HANDLE h = CreateFileW(L"CRTIO2.BIN", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        int fd = crt__open_osfhandle((intptr_t)h, O_RDONLY_ | O_BINARY_);
        void *g = fd >= 0 ? crt__fdopen(fd, "rb") : 0;
        U_CHECK("_open_osfhandle + _fdopen wrap an existing handle", g && crt_fgetc(g) == 'a' && crt_fgetc(g) == '\r');
        if (g) crt_fclose(g);                                  /* closes the descriptor and the handle */
    }
    /* ---- file system helpers */
    {
        crt_stat64 st;
        crt_finddata64 fd;
        intptr_t fh;
        U_CHECK("_access sees an existing file", crt__access("CRTIO2.BIN", 0) == 0);
        U_CHECK("rename", crt_rename("CRTIO2.BIN", "CRTIO3.BIN") == 0 && crt__access("CRTIO2.BIN", 0) == -1 && *crt__errno() == 2);
        {
            const int r = crt__stat64("CRTIO3.BIN", &st);
            U_CHECKF("_stat64 size and mode", r == 0 && st.st_size == 8 && (st.st_mode & 0xf000) == 0x8000, "r=%d errno=%d size=%d mode=%x",
                     r, *crt__errno(), (int)st.st_size, st.st_mode);
        }
        fh = crt__findfirst64("CRTIO3.*", &fd);
        U_CHECKF("_findfirst64", fh != -1 && fd.size == 8 && !crt_strcmp(fd.name, "CRTIO3.BIN"), "h=%d errno=%d size=%d name=%s", (int)fh,
                 *crt__errno(), (int)fd.size, fh != -1 ? fd.name : "-");
        if (fh != -1) crt__findclose(fh);
        U_CHECK("remove", crt_remove("CRTIO3.BIN") == 0 && crt_remove("CRTIO1.TXT") == 0 && crt__access("CRTIO1.TXT", 0) == -1);
        U_CHECK("_getcwd", crt__getcwd(buf, sizeof buf) && buf[1] == ':');
    }
    /* ---- tmpfile */
    f = crt_tmpfile();
    U_CHECK("tmpfile opens a read/write stream", f != 0);
    if (f) {
        char b[8] = "";
        crt_fputs("tmp", f);
        crt_fseek(f, 0, 0);
        U_CHECK("tmpfile round trip", crt_fread(b, 1, 3, f) == 3 && !memcmp(b, "tmp", 3));
        crt_fclose(f);
    }
    /* ---- standard streams */
    {
        void *out = crt___acrt_iob_func(1), *err = crt___acrt_iob_func(2);
        U_CHECK("stdout / stderr descriptors are 1 / 2", crt__fileno(out) == 1 && crt__fileno(err) == 2);
        U_CHECK("fprintf(stdout) through the UCRT", crt_fprintf(out, "t_crt_io: hello from ucrtbase printf %s %d\n", "ok", 7) ==
                (int)sizeof "t_crt_io: hello from ucrtbase printf ok 7\n" - 1);
        U_CHECK("fwrite to stdout", crt_fwrite("t_crt_io: fwrite line\n", 1, 22, out) == 22 && crt_fflush(out) == 0);
        U_CHECK("fputwc of a Latin-1 character in text mode", crt_fputwc(0xe9, out) == 0xe9 && crt_fputwc('\n', out) == '\n');
    }
    return u_finish("t_crt_io");
}
