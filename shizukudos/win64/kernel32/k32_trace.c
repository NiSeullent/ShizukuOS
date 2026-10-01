/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll diagnostics for bring-up runs (tests/run_k64_chromium.py): when the environment has SHZ_K32TRACE=1 (the
 * Kernel64 loader adds it for every process when the kernel command line carries `shz.k32trace`), kernel32 writes one
 * line per explicit failure of a feature it does not implement ("K32 unsupported: ...") and per failed GetProcAddress
 * ("K32 trace: GetProcAddress ...") to the debug console (NtShzDebugPrint -> serial log). Without the variable nothing
 * is printed and nothing else changes: the functions fail the same way either way.
 */
#include "k32.h"

static int trace_state;                                  /* 0 unknown, 1 off, 2 on */

int k32_trace_on(void)
{
    if (!trace_state) {
        static const WCHAR name[] = { 'S','H','Z','_','K','3','2','T','R','A','C','E', 0 };
        const DWORD error = GetLastError();
        WCHAR v[8];
        const DWORD n = GetEnvironmentVariableW(name, v, 8);
        trace_state = n == 1 && v[0] == '1' ? 2 : 1;
        /* An absent diagnostic setting must not replace the API's real error
         * with ERROR_ENVVAR_NOT_FOUND on this process's first traced failure. */
        SetLastError(error);
    }
    return trace_state == 2;
}

static unsigned put(char *b, unsigned at, unsigned cap, const char *s)
{
    while (s && *s && at + 1 < cap) b[at++] = *s++;
    return at;
}

static unsigned put_hex(char *b, unsigned at, unsigned cap, ULONG_PTR v)
{
    char t[20];
    int n = 0;
    do { t[n++] = "0123456789abcdef"[v & 15]; v >>= 4; } while (v && n < 16);
    while (n && at + 1 < cap) b[at++] = t[--n];
    return at;
}

void k32_trace3(const char *a, const char *b, const char *c)
{
    char line[240];
    unsigned n = 0;
    if (!k32_trace_on()) return;
    n = put(line, n, sizeof line, "K32 trace: ");
    n = put(line, n, sizeof line, a);
    n = put(line, n, sizeof line, b);
    n = put(line, n, sizeof line, c);
    line[n++] = '\n';
    NtShzDebugPrint(line, n);
}

/* An explicit failure: sets the last error and, when tracing, reports it. Returns FALSE for convenience. */
BOOL k32_unsupported(const char *fn, const char *what, DWORD err)
{
    shz_set_last_error(err);
    if (k32_trace_on()) {
        char line[240];
        unsigned n = 0;
        n = put(line, n, sizeof line, "K32 unsupported: ");
        n = put(line, n, sizeof line, fn);
        n = put(line, n, sizeof line, " (");
        n = put(line, n, sizeof line, what);
        n = put(line, n, sizeof line, ") -> error 0x");
        n = put_hex(line, n, sizeof line, err);
        line[n++] = '\n';
        NtShzDebugPrint(line, n);
        shz_set_last_error(err);
    }
    return FALSE;
}

void k32_trace_hex(const char *a, const char *b, ULONG_PTR v)
{
    char line[240];
    unsigned n = 0;
    if (!k32_trace_on()) return;
    n = put(line, n, sizeof line, "K32 trace: ");
    n = put(line, n, sizeof line, a);
    n = put(line, n, sizeof line, b);
    n = put(line, n, sizeof line, "0x");
    n = put_hex(line, n, sizeof line, v);
    line[n++] = '\n';
    NtShzDebugPrint(line, n);
}
