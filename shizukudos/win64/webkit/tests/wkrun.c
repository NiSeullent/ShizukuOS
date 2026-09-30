/* SPDX-License-Identifier: GPL-2.0-only
 * WKRUN.EXE: the autorun driver of the W3 WebKit guest runs (shizukudos/win64/webkit/tests/wkguest.py).
 *
 * Reads WKRUN.TXT from the current directory. Each non-empty line is `<name>|<timeout seconds>|<command line>`; the
 * program is started with CreateProcessA in the current directory, waited for, and reported as
 *   WKRUN-RESULT <name> exit=<code> ms=<elapsed>
 * (exit=-1: could not be started, exit=-2: timed out and terminated). The last line is
 *   WKRUN-DONE pass=<n> fail=<n>
 * and the exit code is the number of failures (programs with a non-zero exit). Only kernel32 is used, so a toolchain
 * or C runtime problem of the programs under test cannot hide the report. */
#include <windows.h>

static HANDLE out;

static void put(const char *s)
{
    DWORD n = 0, len = 0;
    while (s[len]) len++;
    WriteFile(out, s, len, &n, 0);
}

static void put_u(unsigned long v)
{
    char b[24];
    int i = 23;
    b[i] = 0;
    do { b[--i] = (char)('0' + v % 10); v /= 10; } while (v);
    put(b + i);
}

static void put_i(long v)
{
    if (v < 0) { put("-"); put_u((unsigned long)-v); } else put_u((unsigned long)v);
}

int main(void)
{
    static char buf[65536];
    HANDLE f;
    DWORD got = 0;
    unsigned pass = 0, fail = 0;
    char *p;
    out = GetStdHandle(STD_OUTPUT_HANDLE);
    f = CreateFileA("WKRUN.TXT", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    if (f == INVALID_HANDLE_VALUE) { put("WKRUN: cannot open WKRUN.TXT\r\n"); return 255; }
    ReadFile(f, buf, sizeof buf - 1, &got, 0);
    CloseHandle(f);
    buf[got] = 0;
    for (p = buf; *p;) {
        char *line = p, *name, *tmo, *cmd;
        unsigned long timeout = 0;
        while (*p && *p != '\n') p++;
        if (*p) *p++ = 0;
        { char *e = line; while (*e) e++; while (e > line && (e[-1] == '\r' || e[-1] == ' ')) *--e = 0; }
        if (!*line || *line == '#') continue;
        name = line;
        for (tmo = name; *tmo && *tmo != '|'; tmo++) {}
        if (!*tmo) continue;
        *tmo++ = 0;
        for (cmd = tmo; *cmd && *cmd != '|'; cmd++) timeout = timeout * 10 + (unsigned long)(*cmd - '0');
        if (!*cmd) continue;
        cmd++;
        {
            STARTUPINFOA si;
            PROCESS_INFORMATION pi;
            DWORD t0 = GetTickCount(), code = 0, w;
            long rc;
            ZeroMemory(&si, sizeof si);
            si.cb = sizeof si;
            put("WKRUN-START "); put(name); put("\r\n");
            if (!CreateProcessA(0, cmd, 0, 0, TRUE, 0, 0, 0, &si, &pi)) {
                rc = -1;
                put("WKRUN: CreateProcess failed, error "); put_u(GetLastError()); put("\r\n");
            } else {
                w = WaitForSingleObject(pi.hProcess, timeout ? timeout * 1000 : INFINITE);
                if (w == WAIT_TIMEOUT) {
                    TerminateProcess(pi.hProcess, 0xdead);
                    WaitForSingleObject(pi.hProcess, 10000);
                    rc = -2;
                } else {
                    GetExitCodeProcess(pi.hProcess, &code);
                    rc = (long)code;
                }
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
            }
            if (rc == 0) pass++; else fail++;
            put("WKRUN-RESULT "); put(name); put(" exit="); put_i(rc); put(" ms="); put_u(GetTickCount() - t0);
            put("\r\n");
        }
    }
    put("WKRUN-DONE pass="); put_u(pass); put(" fail="); put_u(fail); put("\r\n");
    return (int)fail;
}
