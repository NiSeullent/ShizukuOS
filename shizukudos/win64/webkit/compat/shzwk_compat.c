/* SPDX-License-Identifier: GPL-2.0-only
 * Link-time glue between mingw-w64's UCRT import library and the Shizuku Win64 runtime, for the WebKit build
 * (docs/shizukudos10/WEBKIT.md "Toolchain"). mingw-w64 expects two functions from ucrtbase.dll that the Shizuku
 * ucrtbase does not export (asked from K5 in docs/shizukudos10/reports/W1.md):
 *   rand_s                  libstdc++'s std::random_device; implemented here over ProcessPrng (bcryptprimitives.dll),
 *                           which is what the Windows UCRT uses;
 *   __C_specific_handler    referenced by crt2.o's unwind data; the Shizuku ntdll exports it, and build.py links the
 *                           Shizuku libntdll.a ahead of the UCRT import library so the reference binds there.
 * Nothing here replaces a function the Shizuku runtime provides. */
#include <stddef.h>

typedef int BOOL;
__declspec(dllimport) BOOL __stdcall ProcessPrng(unsigned char *data, size_t len);

int rand_s(unsigned int *value)
{
    if (!value) return 22;                          /* EINVAL, as the UCRT */
    if (!ProcessPrng((unsigned char *)value, sizeof *value)) { *value = 0; return 22; }
    return 0;
}

/* libstdc++ (built with dllimport declarations) calls through the import slot. */
int (*__imp_rand_s)(unsigned int *) = rand_s;
