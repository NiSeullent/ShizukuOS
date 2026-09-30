/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - what the platform layer provides to the portable core.
 *
 * Implementations: win/platform_win.c inside shzlite.dll (HeapAlloc on the process heap, CreateFileW, GetTickCount64)
 * and tests/platform_host.c for the Linux host tests (malloc, stdio).
 */
#ifndef SHZ_PLATFORM_H
#define SHZ_PLATFORM_H

#include "base.h"

/* shz_alloc / shz_realloc / shz_free are declared in base.h and implemented by the platform. */

/* Milliseconds since some fixed point (event timeStamp). */
uint64_t shz_platform_time_ms(void);

/* Read a whole local file. path is a file: URL path as shz_url_file_path returns it ("C:/SHZ/TESTS/A.PNG" or
 * "/tmp/x.png"); the platform converts separators. *data is shz_alloc'ed (the caller frees it). SHZ_OK or a failure. */
shz_res shz_platform_read_file(const shz_char *path, uint8_t **data, size_t *len);

/* Debug trace (OutputDebugStringA in the DLL when SHZ_TRIDENT_TRACE is set; stderr on the host when SHZ_TRACE=1). */
void shz_platform_trace(const char *msg);

#endif /* SHZ_PLATFORM_H */
