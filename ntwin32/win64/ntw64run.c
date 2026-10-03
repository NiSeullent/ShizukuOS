/* SPDX-License-Identifier: GPL-2.0-only
 * NTW64RUN.EXE: Windows 98 console front end for the ShizukuDOS WIN64 subsystem (NTW32.DLL, ntw64.h).
 * Original i486 PE32 console program, subsystem 4.10, no CRT.
 *
 *   NTW64RUN [/i] [/d:<dir>] <image> [arguments...]    run a Win64 program in the Kernel64 domain
 *   NTW64RUN /q                                        report the WIN64 subsystem
 *
 *   <image>    a path in the Kernel64 file system, e.g. \SHZ\TESTS\T_HELLO.EXE
 *   /i         forward this program's standard input (until end of file) to the Win64 process; without it the
 *              process sees end of file at once. Input is forwarded before output is shown.
 *   /d:<dir>   working directory for the process (Kernel64 path)
 *
 * The Win64 command line is the text from <image> to the end of this program's command line. stdout and
 * stderr of the Win64 process arrive merged on this program's stdout. The exit code is the Win64 process's
 * exit code; 252..255 mean NTW64RUN itself failed and a message on stderr names the Win32 error when that
 * stream is writable: 254 bridge unavailable (no VxD Supervisor/channel, ABI mismatch), 253 access denied
 * (foreign/unauthorized owner), 252 handle/channel revoked, 255 any other frontend failure. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "ntw64.h"

#define RUN_FAILED 255u
/* Distinct frontend failure classes (a remote exit code can still equal them; stderr names the cause). */
#define RUN_BRIDGE_UNAVAILABLE 254u   /* VxD/Supervisor/Kernel64 channel absent or ABI mismatch */
#define RUN_ACCESS_DENIED 253u        /* owner/capability refused: foreign or unauthorized caller */
#define RUN_CHANNEL_REVOKED 252u      /* process/channel handle no longer valid (revoked or generation retired) */
#define CMD_CHARS 2048
#define PATH_CAP 261

static HANDLE out_h, err_h;
static int io_failed;
static DWORD first_code;
static DWORD io_error;
static WCHAR wpath[PATH_CAP], wcmd[CMD_CHARS + 1], wdir[PATH_CAP];
static char io[4096];

static DWORD slen(const char *s) { DWORD n = 0; while (s[n]) ++n; return n; }
/* A successful short write consumes only its reported prefix. Never replay a
 * failed write, and refuse zero progress or an impossible reported length. */
static BOOL put(HANDLE h, const char *s, DWORD n)
{
    while (n) {
        DWORD w = 0;
        if (!WriteFile(h, s, n, &w, NULL)) {
            if (!io_failed) io_error = GetLastError();
            io_failed = 1;
            return FALSE;
        }
        if (!w || w > n) {
            SetLastError(ERROR_WRITE_FAULT);
            if (!io_failed) io_error = ERROR_WRITE_FAULT;
            io_failed = 1;
            return FALSE;
        }
        s += w;
        n -= w;
    }
    return TRUE;
}
static void puts_to(HANDLE h, const char *s) { put(h, s, slen(s)); }
static void put_num(HANDLE h, DWORD v, int hex)
{
    char digits[12];
    int n = 0;
    const DWORD base = hex ? 16u : 10u;
    if (hex) puts_to(h, "0x");
    do { digits[n++] = "0123456789abcdef"[v % base]; v /= base; } while (v);
    while (n) put(h, &digits[--n], 1);
}

static DWORD classify(DWORD error)
{
    switch (error) {
    case 50: case 55: case 1306: return RUN_BRIDGE_UNAVAILABLE;
    case 5: case 288: case 1314: return RUN_ACCESS_DENIED;
    case 6: return RUN_CHANNEL_REVOKED;
    default: return RUN_FAILED;
    }
}

static DWORD failed(const char *what)
{
    const DWORD error = GetLastError();
    DWORD code;
    puts_to(err_h, "NTW64RUN: ");
    puts_to(err_h, what);
    puts_to(err_h, " failed, Win32 error ");
    put_num(err_h, error, 0);
    switch (error) {
    case 2: puts_to(err_h, " (not found: NTWRAP9X.VXD or the Kernel64 image)"); break;
    case 50: puts_to(err_h, " (no ShizukuDOS Supervisor: not running as a Win98 domain)"); break;
    case 55: puts_to(err_h, " (the Supervisor announces no Kernel64 channel)"); break;
    case 1306: puts_to(err_h, " (inter-kernel ABI major version mismatch)"); break;
    case 5: case 288: case 1314: puts_to(err_h, " (access denied: the caller does not own this channel or process)"); break;
    case 6: puts_to(err_h, " (handle or channel revoked)"); break;
    default: break;
    }
    puts_to(err_h, "\r\n");
    code = classify(error);
    if (!first_code) first_code = code;
    return code;
}

static DWORD usage(void)
{
    puts_to(err_h, "usage: NTW64RUN [/i] [/d:<dir>] <image> [arguments...]\r\n"
                   "       NTW64RUN /q\r\n"
                   "  runs a Win64 (PE32+) program in the ShizukuDOS Kernel64 domain\r\n"
                   "  <image>  Kernel64 path, e.g. \\SHZ\\TESTS\\T_HELLO.EXE\r\n"
                   "  /i       forward standard input (until end of file)\r\n"
                   "  /q       report the WIN64 subsystem and exit\r\n");
    return RUN_FAILED;
}

static const char *skip_blank(const char *s) { while (*s == ' ' || *s == '\t') ++s; return s; }

/* End of the token at s (quotes group, as in the Windows command-line convention for argv[0]). */
static const char *token_end(const char *s)
{
    int quoted = 0;
    while (*s && (quoted || (*s != ' ' && *s != '\t'))) {
        if (*s == '"') quoted = !quoted;
        ++s;
    }
    return s;
}

/* ANSI -> UTF-16 with the native converter; the quotes of a token are dropped when `unquote`. Returns the
 * number of UTF-16 units, or 0 when the text is empty, too long for `cap` or not convertible. */
static int widen(const char *s, const char *end, WCHAR *out, int cap, int unquote)
{
    static char tmp[CMD_CHARS + 1];
    int n = 0, w;
    for (; s < end; ++s) {
        if (unquote && *s == '"') continue;
        if (n >= CMD_CHARS) return 0;
        tmp[n++] = *s;
    }
    if (n == 0) return 0;
    w = MultiByteToWideChar(CP_ACP, 0, tmp, n, out, cap - 1);
    if (w <= 0) return 0;
    out[w] = 0;
    return w;
}

static DWORD query(void)
{
    ntw64_info_t info;
    if (!NtwQuerySubsystem64(&info)) return failed("NtwQuerySubsystem64");
    puts_to(out_h, "WIN64 subsystem: ABI "); put_num(out_h, info.abi_major, 0); puts_to(out_h, ".");
    put_num(out_h, info.abi_minor, 0); puts_to(out_h, ", subsystem "); put_num(out_h, info.subsystem_version >> 16, 0);
    puts_to(out_h, "."); put_num(out_h, info.subsystem_version & 0xffffu, 0); puts_to(out_h, ", capabilities ");
    put_num(out_h, info.capabilities, 1); puts_to(out_h, "\r\nprocesses: ");
    put_num(out_h, info.active_processes, 0); puts_to(out_h, " of "); put_num(out_h, info.max_processes, 0);
    puts_to(out_h, " active; console window "); put_num(out_h, info.console_window, 0); puts_to(out_h, " x ");
    put_num(out_h, info.console_chunk, 0); puts_to(out_h, " bytes\r\nchannel "); put_num(out_h, info.channel_id, 0);
    puts_to(out_h, " generation "); put_num(out_h, info.generation, 0); puts_to(out_h, " (VxD: ");
    put_num(out_h, info.vxd_sent, 0); puts_to(out_h, " sent, "); put_num(out_h, info.vxd_received, 0);
    puts_to(out_h, " received, "); put_num(out_h, info.vxd_proto_errors, 0); puts_to(out_h, " malformed)\r\n");
    if (io_failed) { SetLastError(io_error); return failed("WriteFile"); }
    return 0;
}

static DWORD run(void)
{
    const char *s = skip_blank(token_end(skip_blank(GetCommandLineA())));      /* skip argv[0] */
    const char *dir = NULL, *dir_end = NULL, *image_end;
    int forward_input = 0;
    int frontend_failed = 0, terminate = 0;
    HANDLE process = NULL;
    DWORD got = 0, code = 0;
    io_failed = 0;
    io_error = 0;
    first_code = 0;
    out_h = GetStdHandle(STD_OUTPUT_HANDLE);
    err_h = GetStdHandle(STD_ERROR_HANDLE);
    while (*s == '/' || *s == '-') {
        const char *end = token_end(s);
        const char opt = (char)(s[1] | 0x20);
        if (opt == 'q' && end == s + 2) return query();
        if (opt == 'i' && end == s + 2) forward_input = 1;
        else if (opt == 'd' && s[2] == ':' && end > s + 3) { dir = s + 3; dir_end = end; }
        else return usage();
        s = skip_blank(end);
    }
    if (!*s) return usage();
    image_end = token_end(s);
    {   /* trailing blanks are not part of the Win64 command line */
        const char *e = s + slen(s);
        while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) --e;
        if (widen(s, image_end, wpath, sizeof wpath / sizeof wpath[0], 1) <= 0 ||
            widen(s, e, wcmd, CMD_CHARS + 1, 0) <= 0 ||
            (dir && widen(dir, dir_end, wdir, sizeof wdir / sizeof wdir[0], 1) <= 0)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return failed("argument conversion");
        }
    }
    if (!NtwCreateProcess64W(wpath, wcmd, dir ? wdir : NULL, &process))
        return failed("NtwCreateProcess64W");
    if (forward_input) {
        const HANDLE in_h = GetStdHandle(STD_INPUT_HANDLE);
        DWORD n = 0, written = 0;
        for (;;) {
            if (!ReadFile(in_h, io, sizeof io, &n, NULL)) {
                /* A pipe whose writer closed supplies EOF on classic Win32. */
                if (GetLastError() != ERROR_BROKEN_PIPE) {
                    frontend_failed = 1;
                    (void)failed("ReadFile");
                }
                break;
            }
            if (!n) break;
            if (n > sizeof io) {
                SetLastError(ERROR_INVALID_DATA);
                frontend_failed = 1;
                (void)failed("ReadFile length");
                break;
            }
            if (!NtwWriteConsole64(process, io, n, &written)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) break;        /* the process ended first */
                frontend_failed = 1;
                (void)failed("NtwWriteConsole64");
                break;
            }
            if (written != n) {
                SetLastError(ERROR_WRITE_FAULT);
                frontend_failed = 1;
                (void)failed("NtwWriteConsole64 length");
                break;
            }
        }
    }
    if (!NtwCloseConsole64(process) && GetLastError() != ERROR_BROKEN_PIPE) {
        frontend_failed = 1;
        (void)failed("NtwCloseConsole64");
    }
    for (;;) {
        if (!NtwReadConsole64(process, io, sizeof io, &got)) {
            if (GetLastError() != NTW64_ERROR_HANDLE_EOF) {
                frontend_failed = 1;
                terminate = 1;
                (void)failed("NtwReadConsole64");
            }
            break;
        }
        if (!got || got > sizeof io) {
            SetLastError(ERROR_INVALID_DATA);
            frontend_failed = 1;
            terminate = 1;
            (void)failed("NtwReadConsole64 length");
            break;
        }
        if (!put(out_h, io, got)) {
            SetLastError(io_error);
            frontend_failed = 1;
            terminate = 1;
            (void)failed("WriteFile");
            break;
        }
    }
    if (terminate && !NtwKillProcess64(process, RUN_FAILED)) {
        frontend_failed = 1;
        (void)failed("NtwKillProcess64");
    }
    if (!NtwWaitProcess64(process, INFINITE, &code)) {
        frontend_failed = 1;
        (void)failed("NtwWaitProcess64");
    }
    if (!NtwCloseProcess64(process)) {
        frontend_failed = 1;
        (void)failed("NtwCloseProcess64");
    }
    /* A real remote exit never clears an earlier frontend failure. */
    return frontend_failed || io_failed ? (first_code ? first_code : RUN_FAILED) : code;
}

void mainCRTStartup(void)
{
    ExitProcess(run());
}
