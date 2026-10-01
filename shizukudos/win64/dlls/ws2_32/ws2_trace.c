/* SPDX-License-Identifier: GPL-2.0-only
 * Bring-up diagnostics, enabled by the existing SHZ_K32TRACE=1 profile.
 * Records scalar operation/error codes only; never changes Winsock results.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "ws2_trace.h"
LONG __stdcall NtShzDebugPrint(const char *, ULONG);

static unsigned append(char *out, unsigned pos, const char *value)
{
    while (*value && pos < 160) out[pos++] = *value++;
    return pos;
}
static unsigned hex(char *out, unsigned pos, unsigned value)
{
    char digits[8]; unsigned n = 0;
    do { digits[n++] = "0123456789abcdef"[value & 15]; value >>= 4; } while (value);
    while (n && pos < 160) out[pos++] = digits[--n];
    return pos;
}
static void emit(const char *function, unsigned value, unsigned ov, unsigned cb, int request)
{
    DWORD saved = GetLastError(); WCHAR enabled[2]; char line[192]; unsigned n = 0;
    if (GetEnvironmentVariableW(L"SHZ_K32TRACE", enabled, 2) == 1 && enabled[0] == '1') {
        n = append(line, n, "WS2 trace: "); n = append(line, n, function);
        n = append(line, n, request ? " request=0x" : " error=0x"); n = hex(line, n, value);
        if (request) {
            n = append(line, n, " overlapped="); n = hex(line, n, ov);
            n = append(line, n, " callback="); n = hex(line, n, cb);
        }
        line[n++] = '\n'; NtShzDebugPrint(line, n);
    }
    SetLastError(saved);
}
void ws2_trace_failure(const char *function, unsigned error) { emit(function, error, 0, 0, 0); }
void ws2_trace_request(const char *function, unsigned request, unsigned overlapped, unsigned callback)
{ emit(function, request, overlapped, callback, 1); }
void ws2_trace_guid(const void *guid)
{
    const unsigned char *bytes = guid; DWORD saved = GetLastError(); WCHAR enabled[2];
    char line[80]; unsigned n = 0, i;
    if (GetEnvironmentVariableW(L"SHZ_K32TRACE", enabled, 2) == 1 && enabled[0] == '1') {
        n = append(line, n, "WS2 trace: extension GUID bytes=");
        for (i = 0; i < 16; ++i) {
            line[n++] = "0123456789abcdef"[bytes[i] >> 4];
            line[n++] = "0123456789abcdef"[bytes[i] & 15];
        }
        line[n++] = '\n'; NtShzDebugPrint(line, n);
    }
    SetLastError(saved);
}
