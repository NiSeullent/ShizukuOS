/* Conversion algorithm controls against an explicitly synthetic ACP model.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * The exact production header is compiled; no OS/file/engine claim is made.
 */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/core_FileSystemWin9x.h"

static DWORD lastError;
void SetLastError(DWORD value) { lastError = value; }
DWORD GetLastError(void) { return lastError; }

int WideCharToMultiByte(unsigned page, DWORD flags, const WCHAR* source, int count,
    char* output, int capacity, const char* defaultCharacter, BOOL* substituted)
{
    int i, used = 0;
    assert(page == CP_ACP && flags == 0 && !defaultCharacter && substituted);
    *substituted = FALSE;
    for (i = 0; i < count; ++i) {
        unsigned value = source[i];
        int bytes = value == 0xac00 ? 2 : 1;
        if (used + bytes > capacity) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        if (value == 0xac00) { output[used++] = (char)0x81; output[used++] = 0x41; }
        else if (value == 0xff21) output[used++] = 'A'; /* Best fit without a default substitution. */
        else if (value > 127) { output[used++] = '?'; *substituted = 1; }
        else output[used++] = (char)value;
    }
    return used;
}

int MultiByteToWideChar(unsigned page, DWORD flags, const char* source, int count,
    WCHAR* output, int capacity)
{
    int i, used = 0;
    assert(page == CP_ACP && flags == 0);
    for (i = 0; i < count; ++i) {
        unsigned value = (unsigned char)source[i];
        if (used == capacity) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        if (value == 0x81 && i + 1 < count && source[i + 1] == 0x41) {
            output[used++] = 0xac00;
            ++i;
        } else output[used++] = value < 128 ? (WCHAR)value : (WCHAR)0xfffd;
    }
    return used;
}

int main(void)
{
    const WCHAR ascii[] = { 'C', ':', '\\', 'x' };
    const WCHAR dbcs[] = { 'C', ':', '\\', 0xac00 };
    const WCHAR substitute[] = { 0xd83d, 0xde80 };
    const WCHAR bestFit[] = { 0xff21 };
    const WCHAR nul[] = { 'x', 0, 'y' };
    WCHAR roundTrip[MAX_PATH], tooLong[MAX_PATH];
    char result[MAX_PATH];
    unsigned i;
    assert(iewkWin9xPathFromWide(ascii, 4, result, sizeof(result)) && !strcmp(result, "C:\\x"));
    assert(iewkWin9xPathFromWide(dbcs, 4, result, sizeof(result)) && strlen(result) == 5);
    assert(iewkWin9xPathToWide(result, 5, roundTrip, MAX_PATH)
        && !memcmp(roundTrip, dbcs, sizeof(dbcs)) && !roundTrip[4]);
    assert(!iewkWin9xPathFromWide(substitute, 2, result, sizeof(result))
        && GetLastError() == ERROR_NO_UNICODE_TRANSLATION && !result[0]);
    assert(!iewkWin9xPathFromWide(bestFit, 1, result, sizeof(result))
        && GetLastError() == ERROR_NO_UNICODE_TRANSLATION && !result[0]);
    assert(!iewkWin9xPathFromWide(nul, 3, result, sizeof(result))
        && GetLastError() == ERROR_INVALID_NAME && !result[0]);
    assert(!iewkWin9xPathFromWide(ascii, 4, result, 4)
        && GetLastError() == ERROR_INSUFFICIENT_BUFFER && !result[0]);
    for (i = 0; i < MAX_PATH; ++i) tooLong[i] = 'x';
    assert(!iewkWin9xPathFromWide(tooLong, MAX_PATH, result, sizeof(result))
        && GetLastError() == ERROR_FILENAME_EXCED_RANGE && !result[0]);
    assert(!iewkWin9xPathToWide("\x81", 1, roundTrip, MAX_PATH)
        && GetLastError() == ERROR_NO_UNICODE_TRANSLATION && !roundTrip[0]);
    assert(!iewkWin9xPathFromWide(NULL, 1, result, sizeof(result))
        && GetLastError() == ERROR_INVALID_PARAMETER && !result[0]);
    puts("host.conversion.controls=9\nhost.conversion.result=PASS\nwindows.api.verified=0\nengine.executed=0");
    return 0;
}
