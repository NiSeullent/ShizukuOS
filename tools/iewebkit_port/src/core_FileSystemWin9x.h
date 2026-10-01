/* Lossless Win9x filesystem path conversion for the genuine WTF/JSC port.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * The caller still uses the real OS file APIs. Unicode file contents are
 * independent of the active-code-page filename limit. No name is substituted.
 */
#ifndef IEWK_CORE_FILESYSTEM_WIN9X_H
#define IEWK_CORE_FILESYSTEM_WIN9X_H

#include <windows.h>
#include <stddef.h>
#include <string.h>

static int iewkWin9xPathFromWide(const WCHAR* source, size_t count,
    char* destination, size_t capacity)
{
    char encoded[MAX_PATH];
    WCHAR restored[MAX_PATH];
    BOOL substituted = FALSE;
    int bytes, characters;
    size_t i;
    if (destination && capacity)
        destination[0] = 0;
    if (!source || !destination || !capacity || !count) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (count >= MAX_PATH) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (!source[i]) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
    }
    /* WC_NO_BEST_FIT_CHARS is not a Win9x prerequisite. A full round trip
     * rejects both default substitutions and best-fit aliases with flags 0.
     */
    bytes = WideCharToMultiByte(CP_ACP, 0, source, (int)count, encoded,
        MAX_PATH - 1, NULL, &substituted);
    if (bytes <= 0)
        return 0;
    if (substituted) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    characters = MultiByteToWideChar(CP_ACP, 0, encoded, bytes,
        restored, MAX_PATH - 1);
    if (characters <= 0)
        return 0;
    if ((size_t)characters != count
        || memcmp(source, restored, count * sizeof(WCHAR))) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if ((size_t)bytes >= capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    encoded[bytes] = 0;
    memcpy(destination, encoded, (size_t)bytes + 1);
    return 1;
}

static int iewkWin9xPathToWide(const char* source, size_t count,
    WCHAR* destination, size_t capacity)
{
    WCHAR decoded[MAX_PATH];
    char restored[MAX_PATH];
    int characters;
    size_t i;
    if (destination && capacity)
        destination[0] = 0;
    if (!source || !destination || !capacity || !count) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    if (count >= MAX_PATH) {
        SetLastError(ERROR_FILENAME_EXCED_RANGE);
        return 0;
    }
    for (i = 0; i < count; ++i) {
        if (!source[i]) {
            SetLastError(ERROR_INVALID_NAME);
            return 0;
        }
    }
    characters = MultiByteToWideChar(CP_ACP, 0, source, (int)count,
        decoded, MAX_PATH - 1);
    if (characters <= 0)
        return 0;
    if (!iewkWin9xPathFromWide(decoded, (size_t)characters,
            restored, sizeof(restored)))
        return 0;
    if (strlen(restored) != count || memcmp(source, restored, count)) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return 0;
    }
    if ((size_t)characters >= capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    decoded[characters] = 0;
    memcpy(destination, decoded, ((size_t)characters + 1) * sizeof(WCHAR));
    return 1;
}
#endif
