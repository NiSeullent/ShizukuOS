/* Win98 KERNEL32 backend and Win32-ABI exports for the completion port core.
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Uses only Windows 95/98 KERNEL32 primitives (critical section, counting
 * semaphore, WaitForSingleObject). Exports use the documented Win32 argument
 * and failure contracts of the corresponding NT functions under ShizukuLc_*
 * names. Handles are provider-private: they must be closed with
 * ShizukuLc_CloseIoCompletionPort, never with KERNEL32 CloseHandle.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600 /* OVERLAPPED_ENTRY type only; no Vista import is used */
#include <windows.h>
#include <stddef.h>
#include "lc_iocp.h"

#ifndef LC_NATIVE_HOST_TEST
int lc_sock_native_attach(HINSTANCE);
void lc_sock_native_detach(void);
DWORD lc_sock_native_associate(HANDLE, uint32_t, ULONG_PTR);
#endif

#ifndef LC_NATIVE_HOST_TEST /* host error-ordering test builds this TU with a LP64 header shim */
_Static_assert(sizeof(void *) == 4, "PE32 Win98 provider");
#endif
_Static_assert(sizeof(lc_entry) == sizeof(OVERLAPPED_ENTRY), "OVERLAPPED_ENTRY size");
_Static_assert(offsetof(lc_entry, key) == offsetof(OVERLAPPED_ENTRY, lpCompletionKey), "key");
_Static_assert(offsetof(lc_entry, overlapped) == offsetof(OVERLAPPED_ENTRY, lpOverlapped), "ov");
_Static_assert(offsetof(lc_entry, internal) == offsetof(OVERLAPPED_ENTRY, Internal), "internal");
_Static_assert(offsetof(lc_entry, bytes) == offsetof(OVERLAPPED_ENTRY, dwNumberOfBytesTransferred), "bytes");

static CRITICAL_SECTION lock;
static lc_iocp_context context;
static LONG ready;

static void op_enter(void *o) { (void)o; EnterCriticalSection(&lock); }
static void op_leave(void *o) { (void)o; LeaveCriticalSection(&lock); }
static uintptr_t op_sem_create(void *o, uint32_t maximum)
{
    (void)o;
    return (uintptr_t)CreateSemaphoreA(NULL, 0, (LONG)maximum, NULL);
}
static int op_sem_release(void *o, uintptr_t s, uint32_t count)
{
    (void)o;
    return ReleaseSemaphore((HANDLE)s, (LONG)count, NULL) != 0;
}
static uint32_t op_sem_wait(void *o, uintptr_t s, uint32_t timeout)
{
    DWORD r;
    (void)o;
    r = WaitForSingleObject((HANDLE)s, timeout);
    if (r == WAIT_OBJECT_0) return 0;
    if (r == WAIT_TIMEOUT) return LC_WAIT_TIMEOUT;
    return LC_WAIT_FAILED;
}
static int op_sem_close(void *o, uintptr_t s) { (void)o; return CloseHandle((HANDLE)s) != 0; }
static uint32_t op_error(void *o) { (void)o; return GetLastError(); }

static BOOL report(int ok, uint32_t error)
{
    if (!ok) SetLastError(error ? error : LC_BAD_BACKEND);
    return ok ? TRUE : FALSE;
}

static int usable(void)
{
    if (ready == 1) return 1;
    SetLastError(ERROR_DLL_INIT_FAILED);
    return 0;
}

static uint32_t to_port(HANDLE handle)
{
    uintptr_t v = (uintptr_t)handle;
    return v > 0xffffffffu ? 0 : (uint32_t)v;
}

HANDLE WINAPI ShizukuLc_CreateIoCompletionPort(HANDLE file, HANDLE existing, ULONG_PTR key, DWORD concurrency)
{
    uint32_t error = 0, handle = 0;
    if (!usable()) return NULL;
    if (file == INVALID_HANDLE_VALUE) {
        if (existing) { /* NT also rejects this combination */
            SetLastError(ERROR_INVALID_PARAMETER);
            return NULL;
        }
        if (!lc_iocp_create(&context, concurrency, &handle, &error)) {
            SetLastError(error);
            return NULL;
        }
        return (HANDLE)(uintptr_t)handle;
    }
    if (!existing) {
        /* Create-and-associate in one call would need a completion source. */
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    /* Sockets: Winsock overlapped events bridged by lc_sock_native.c. Other
     * handles: Win98 has no completion source, lc_iocp_associate reports it. */
    if (!lc_iocp_validate(&context, to_port(existing), &error)) {
        SetLastError(error);
        return NULL;
    }
#ifndef LC_NATIVE_HOST_TEST
    error = lc_sock_native_associate(file, to_port(existing), key);
    if (!error) return existing;
    if (error != ERROR_NOT_SUPPORTED) {
        SetLastError(error);
        return NULL;
    }
#endif
    lc_iocp_associate(&context, to_port(existing), (uintptr_t)file, key, &error);
    SetLastError(error);
    return NULL;
}

BOOL WINAPI ShizukuLc_PostQueuedCompletionStatus(HANDLE port, DWORD bytes, ULONG_PTR key, LPOVERLAPPED overlapped)
{
    uint32_t error = 0;
    int ok;
    if (!usable()) return FALSE;
    ok = lc_iocp_post(&context, to_port(port), bytes, key, overlapped, &error);
    return report(ok, error);   /* call sequenced before error is read */
}

BOOL WINAPI ShizukuLc_GetQueuedCompletionStatus(HANDLE port, LPDWORD bytes, PULONG_PTR key,
                                                LPOVERLAPPED *overlapped, DWORD timeout)
{
    lc_entry entry;
    uint32_t error = 0, removed = 0;
    if (!usable()) return FALSE;
    if (!bytes || !key || !overlapped) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    *overlapped = NULL;
    if (!lc_iocp_get(&context, to_port(port), &entry, 1, &removed, timeout, &error))
        return report(0, error);
    *bytes = entry.bytes;
    *key = entry.key;
    *overlapped = (LPOVERLAPPED)entry.overlapped;
    return TRUE;
}

BOOL WINAPI ShizukuLc_GetQueuedCompletionStatusEx(HANDLE port, LPOVERLAPPED_ENTRY entries, ULONG count,
                                                  PULONG removed, DWORD timeout, BOOL alertable)
{
    uint32_t error = 0, n = 0;
    if (!usable()) return FALSE;
    if (removed) *removed = 0;
    if (alertable) {
        /* Win98 has no APC delivery to wire into this wait. */
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    if (!removed) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (!lc_iocp_get(&context, to_port(port), (lc_entry *)entries, count, &n, timeout, &error))
        return report(0, error);
    *removed = n;
    return TRUE;
}

BOOL WINAPI ShizukuLc_CloseIoCompletionPort(HANDLE port)
{
    uint32_t error = 0;
    int ok;
    if (!usable()) return FALSE;
    ok = lc_iocp_close(&context, to_port(port), &error);
    return report(ok, error);   /* call sequenced before error is read */
}

BOOL WINAPI dll_entry(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    static const lc_iocp_ops ops = { NULL, op_enter, op_leave, op_sem_create, op_sem_release,
                                     op_sem_wait, op_sem_close, op_error };
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InitializeCriticalSection(&lock);
        if (!lc_iocp_init(&context, &ops)) return FALSE;
#ifndef LC_NATIVE_HOST_TEST
        if (!lc_sock_native_attach(instance)) return FALSE;
#endif
        ready = 1;
    } else if (reason == DLL_PROCESS_DETACH && !reserved) {
        /* FreeLibrary: callers must have closed their ports. Process exit
         * (reserved != NULL) leaves kernel cleanup to the OS. */
        ready = 0;
#ifndef LC_NATIVE_HOST_TEST
        lc_sock_native_detach();
#endif
        /* open_ports falls at the START of a close; busy also covers closing
         * ports and threads still inside. If busy, leak the lock rather than
         * delete it under a live getter (the contract in README forbids this). */
        if (!lc_iocp_busy(&context)) DeleteCriticalSection(&lock);
    }
    return TRUE;
}
