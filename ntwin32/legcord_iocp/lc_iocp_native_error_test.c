/* Negative-boundary regression for the exported ABI wrappers: the exact
 * underlying error must reach GetLastError (previously report(call(&error),
 * error) could read error before the call wrote it, giving ERROR_GEN_FAILURE).
 * Builds the real lc_iocp_native.c with host_shim/windows.h. Host only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "lc_iocp.h"

BOOL WINAPI dll_entry(HINSTANCE, DWORD, LPVOID);
HANDLE WINAPI ShizukuLc_CreateIoCompletionPort(HANDLE, HANDLE, ULONG_PTR, DWORD);
BOOL WINAPI ShizukuLc_PostQueuedCompletionStatus(HANDLE, DWORD, ULONG_PTR, LPOVERLAPPED);
BOOL WINAPI ShizukuLc_CloseIoCompletionPort(HANDLE);

static DWORD last_error;
static int sem_open_count;
void SetLastError(DWORD e) { last_error = e; }
DWORD GetLastError(void) { return last_error; }
void InitializeCriticalSection(CRITICAL_SECTION *c) { c->depth = 0; }
void DeleteCriticalSection(CRITICAL_SECTION *c) { (void)c; }
void EnterCriticalSection(CRITICAL_SECTION *c) { ++c->depth; }
void LeaveCriticalSection(CRITICAL_SECTION *c) { --c->depth; }
HANDLE CreateSemaphoreA(void *a, LONG i, LONG m, const char *n) { (void)a; (void)i; (void)m; (void)n; ++sem_open_count; return (HANDLE)(uintptr_t)0x1000; }
BOOL ReleaseSemaphore(HANDLE h, LONG c, LONG *p) { (void)h; (void)c; (void)p; return TRUE; }
DWORD WaitForSingleObject(HANDLE h, DWORD t) { (void)h; (void)t; return WAIT_OBJECT_0; }
BOOL CloseHandle(HANDLE h) { (void)h; --sem_open_count; return TRUE; }

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #x); exit(1); } } while (0)

int main(void)
{
    OVERLAPPED ov;
    HANDLE port;
    memset(&ov, 0, sizeof ov);
    CHECK(dll_entry(NULL, DLL_PROCESS_ATTACH, NULL));
    /* Unknown port handles: exact ERROR_INVALID_HANDLE (6), never 31. */
    last_error = 0;
    CHECK(!ShizukuLc_PostQueuedCompletionStatus((HANDLE)(uintptr_t)0x777, 1, 2, &ov));
    CHECK(GetLastError() == 6);
    last_error = 0;
    CHECK(!ShizukuLc_CloseIoCompletionPort((HANDLE)(uintptr_t)0x777));
    CHECK(GetLastError() == 6);
    last_error = 0;
    CHECK(!ShizukuLc_PostQueuedCompletionStatus(NULL, 1, 2, &ov));
    CHECK(GetLastError() == 6);
    /* Positive path and double-close stale handle keep the exact code. */
    port = ShizukuLc_CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    CHECK(port != NULL);
    CHECK(ShizukuLc_PostQueuedCompletionStatus(port, 3, 4, &ov));
    CHECK(ShizukuLc_CloseIoCompletionPort(port));
    last_error = 0;
    CHECK(!ShizukuLc_PostQueuedCompletionStatus(port, 3, 4, &ov));
    CHECK(GetLastError() == 6);
    last_error = 0;
    CHECK(!ShizukuLc_CloseIoCompletionPort(port));
    CHECK(GetLastError() == 6);
    puts("lc_iocp_native_error_test: PASS");
    return 0;
}
