/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - platform.h for the Linux host tests (libc malloc, stdio, clock_gettime).
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../core/platform.h"

void *shz_alloc(size_t n)
{
    return calloc(1, n ? n : 1);
}

void *shz_realloc(void *p, size_t n)
{
    return realloc(p, n ? n : 1);
}

void shz_free(void *p)
{
    free(p);
}

uint64_t shz_platform_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

shz_res shz_platform_read_file(const shz_char *path, uint8_t **data, size_t *len)
{
    char buf[4096];
    size_t i;
    FILE *f;
    long size;
    *data = NULL;
    *len = 0;
    for (i = 0; path[i] && i + 1 < sizeof(buf); ++i) buf[i] = path[i] < 0x80 ? (char)path[i] : '?';
    buf[i] = 0;
    f = fopen(buf, "rb");
    if (!f) return (shz_res)0x80070002;               /* HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) */
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    *data = shz_alloc(size > 0 ? (size_t)size : 1);
    if (!*data) { fclose(f); return SHZ_E_OUTOFMEMORY; }
    *len = fread(*data, 1, size > 0 ? (size_t)size : 0, f);
    fclose(f);
    return SHZ_OK;
}

void shz_platform_trace(const char *msg)
{
    if (getenv("SHZ_TRACE")) fprintf(stderr, "shz: %s\n", msg);
}
