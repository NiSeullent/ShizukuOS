/* SPDX-License-Identifier: GPL-2.0-only
 * Tiny check helper for the W3 dependency guest checks: one PASS/FAIL line per check, exit code = failures. */
#ifndef DEPTEST_H
#define DEPTEST_H
#include <stdio.h>
static int dt_failures;
#define CHECK(cond) do { if (cond) printf("PASS %s\n", #cond); \
    else { printf("FAIL %s (%s:%d)\n", #cond, __FILE__, __LINE__); ++dt_failures; } fflush(stdout); } while (0)
#define DONE(name) (printf("%s: %d failure(s)\n", name, dt_failures), dt_failures ? 1 : 0)

#ifdef _WIN32
#include <string.h>
#include <windows.h>
/* Path of a font shipped in WIN64.IMG (\SHZ\FONTS, the Windows fonts directory of the Shizuku runtime). */
static inline const char *dt_font_path(const char *file)
{
    static char path[MAX_PATH];
    UINT n = GetWindowsDirectoryA(path, MAX_PATH - 32);
    if (!n || n > MAX_PATH - 32) return file;
    strcat(path, "\\fonts\\");
    strcat(path, file);
    return path;
}
#endif
#endif
