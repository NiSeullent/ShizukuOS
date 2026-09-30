/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - platform.h for Windows / Shizuku (kernel32 only): the process heap, file reading and time.
 * Owner: core.
 */
#include "winglue.h"
#include "../core/platform.h"

void *shz_alloc(size_t n)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n ? n : 1);
}

void *shz_realloc(void *p, size_t n)
{
    if (!p) return HeapAlloc(GetProcessHeap(), 0, n ? n : 1);
    return HeapReAlloc(GetProcessHeap(), 0, p, n ? n : 1);
}

void shz_free(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}

uint64_t shz_platform_time_ms(void)
{
    return GetTickCount64();
}

shz_res shz_platform_read_file(const shz_char *path, uint8_t **data, size_t *len)
{
    shz_char *p = shz_strdup(path);
    HANDLE file;
    LARGE_INTEGER size;
    DWORD got = 0;
    size_t i;
    *data = NULL;
    *len = 0;
    if (!p) return E_OUTOFMEMORY;
    for (i = 0; p[i]; ++i)
        if (p[i] == '/') p[i] = '\\';
    file = CreateFileW(shz_to_wc(p), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    shz_free(p);
    if (file == INVALID_HANDLE_VALUE) return HRESULT_FROM_WIN32(GetLastError());
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 0x40000000) {
        CloseHandle(file);
        return E_FAIL;
    }
    *data = shz_alloc((size_t)size.QuadPart);
    if (!*data) {
        CloseHandle(file);
        return E_OUTOFMEMORY;
    }
    if (size.QuadPart && !ReadFile(file, *data, (DWORD)size.QuadPart, &got, NULL)) {
        HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
        CloseHandle(file);
        shz_free(*data);
        *data = NULL;
        return hr;
    }
    CloseHandle(file);
    *len = got;
    return S_OK;
}

void shz_platform_trace(const char *msg)
{
    static int enabled = -1;
    if (enabled < 0) {
        char buf[8];
        enabled = GetEnvironmentVariableA("SHZ_TRIDENT_TRACE", buf, sizeof(buf)) > 0;
    }
    if (!enabled) return;
    OutputDebugStringA("shzlite: ");
    OutputDebugStringA(msg);
    OutputDebugStringA("\n");
}
