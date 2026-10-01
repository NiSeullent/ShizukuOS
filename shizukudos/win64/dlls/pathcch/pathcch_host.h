/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only allocator/API boundary for testing the unchanged UTF-16 algorithm.
 * Compile with -fshort-wchar; no host libc wchar routine is called.
 */
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>
#include <stdlib.h>
typedef wchar_t WCHAR;
typedef uint32_t DWORD;
typedef int32_t HRESULT;
typedef int BOOL;
typedef int INT;
typedef size_t SIZE_T;
#define DLLAPI
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAX_PATH 260
#define S_OK ((HRESULT)0)
#define S_FALSE ((HRESULT)1)
#define E_INVALIDARG ((HRESULT)0x80070057)
#define E_OUTOFMEMORY ((HRESULT)0x8007000e)
#define ERROR_FILENAME_EXCED_RANGE 206
#define HRESULT_FROM_WIN32(x) ((HRESULT)((x) ? (0x80070000u | ((x) & 0xffffu)) : 0))
#define SUCCEEDED(x) ((HRESULT)(x) >= 0)
#define FAILED(x) ((HRESULT)(x) < 0)
#define LMEM_ZEROINIT 0x40
static int path_host_allocations;
static int path_host_fail_allocation;
static int lstrlenW(const WCHAR *p) { int n = 0; while (p[n]) ++n; return n; }
static WCHAR *lstrcpyW(WCHAR *d, const WCHAR *s) { WCHAR *r = d; while ((*d++ = *s++)) { } return r; }
static WCHAR *lstrcatW(WCHAR *d, const WCHAR *s) { lstrcpyW(d + lstrlenW(d), s); return d; }
static void *LocalAlloc(unsigned flags, size_t size)
{
    void *p;
    if (path_host_fail_allocation) { path_host_fail_allocation = 0; return NULL; }
    p = flags & LMEM_ZEROINIT ? calloc(1, size) : malloc(size);
    if (p) ++path_host_allocations;
    return p;
}
static void *LocalFree(void *p) { if (p) --path_host_allocations; free(p); return NULL; }
static void *GetProcessHeap(void) { return (void *)1; }
static void *HeapAlloc(void *heap, unsigned flags, size_t size) { (void)heap; (void)flags; return LocalAlloc(0, size); }
static BOOL HeapFree(void *heap, unsigned flags, void *p) { (void)heap; (void)flags; LocalFree(p); return TRUE; }
