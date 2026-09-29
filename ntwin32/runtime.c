/* SPDX-License-Identifier: GPL-2.0-only
 * Original app-local PE32 provider. Only stock Win98 imports, no CRT. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <limits.h>
#include "sync.h"
#include "resolve.h"
#include "initonce.h"
#include "unicode/utf.h"
#include "exception/k32veh.h"
typedef char pointer_width_must_be_32[(sizeof(void *) == 4) ? 1 : -1];
typedef char once_matches_win32[(sizeof(ntw_once) == sizeof(INIT_ONCE)) ? 1 : -1];
typedef char wchar_matches_utf16[(sizeof(WCHAR) == sizeof(uint16_t)) ? 1 : -1];
static ntw_srw tick_lock;
static struct ntw_tick_clock tick_clock;
static HMODULE native_kernel32;
/* A zero-delay yield leaves this waiter runnable. Use a finite blocking wait
 * so lock/initialization owners can progress at a lower scheduling priority.
 * Resolution and fairness remain properties of the native scheduler. */
static void yield_thread(void) { Sleep(1); }
void WINAPI NtwInitializeSRWLock(void *lock) { ntw_srw_init((ntw_srw *)lock); }
void WINAPI NtwAcquireSRWLockExclusive(void *lock) { ntw_srw_acquire_exclusive(lock, yield_thread); }
void WINAPI NtwAcquireSRWLockShared(void *lock) { ntw_srw_acquire_shared(lock, yield_thread); }
void WINAPI NtwReleaseSRWLockExclusive(void *lock) { ntw_srw_release_exclusive(lock); }
void WINAPI NtwReleaseSRWLockShared(void *lock) { ntw_srw_release_shared(lock); }
BOOLEAN WINAPI NtwTryAcquireSRWLockExclusive(void *lock) { return (BOOLEAN)ntw_srw_try_exclusive(lock); }
BOOLEAN WINAPI NtwTryAcquireSRWLockShared(void *lock) { return (BOOLEAN)ntw_srw_try_shared(lock); }
ULONGLONG WINAPI NtwGetTickCount64(void) {
    ULONGLONG result;
    ntw_srw_acquire_exclusive(&tick_lock, yield_thread);
    result = ntw_tick_sample(&tick_clock, GetTickCount());
    ntw_srw_release_exclusive(&tick_lock);
    return result;
}
static BOOL once_result(int status) {
    if (status == NTW_ONCE_OK) return TRUE;
    /* A callback may set its own error before returning FALSE. */
    if (status != NTW_ONCE_CALLBACK_FAILED)
        SetLastError(status == NTW_ONCE_INVALID ? ERROR_INVALID_PARAMETER : ERROR_GEN_FAILURE);
    return FALSE;
}
void WINAPI NtwInitOnceInitialize(PINIT_ONCE once) {
    (void)ntw_once_init((ntw_once *)once);
}
BOOL WINAPI NtwInitOnceBeginInitialize(PINIT_ONCE once, DWORD flags,
                                      PBOOL pending, LPVOID *context) {
    return once_result(ntw_once_begin((ntw_once *)once, flags, pending,
                                      context, yield_thread));
}
BOOL WINAPI NtwInitOnceComplete(PINIT_ONCE once, DWORD flags, LPVOID context) {
    return once_result(ntw_once_complete((ntw_once *)once, flags, context));
}
struct once_callback_args { PINIT_ONCE_FN callback; PVOID parameter; };
static int once_callback(ntw_once *once, void *parameter, void **context) {
    struct once_callback_args *args = parameter;
    /* Real WINAPI invocation: never cast a stdcall callback to cdecl. */
    return args->callback((PINIT_ONCE)once, args->parameter, context);
}
BOOL WINAPI NtwInitOnceExecuteOnce(PINIT_ONCE once, PINIT_ONCE_FN callback,
                                  PVOID parameter, LPVOID *context) {
    struct once_callback_args args = { callback, parameter };
    return once_result(ntw_once_execute((ntw_once *)once,
        callback ? once_callback : NULL, &args, context, yield_thread));
}

static int utf_error(DWORD error) { SetLastError(error); return 0; }
static int utf_result(int status, size_t required) {
    if (status == NTWU_OK || status == NTWU_INSUFFICIENT) {
        /* Never truncate a size_t count into the signed Win32 result. */
        if (required > INT_MAX) return utf_error(ERROR_INVALID_PARAMETER);
        if (status == NTWU_OK) return (int)required;
    }
    if (status == NTWU_INSUFFICIENT) return utf_error(ERROR_INSUFFICIENT_BUFFER);
    if (status == NTWU_MALFORMED) return utf_error(ERROR_NO_UNICODE_TRANSLATION);
    if (status == NTWU_INVALID_FLAGS) return utf_error(ERROR_INVALID_FLAGS);
    return utf_error(ERROR_INVALID_PARAMETER);
}

/* The caller supplies accessible, stable source storage. Like Win32, these
 * scans cannot validate mappings or recover from an invalid pointer. The
 * only bound is representable address extent, not an arbitrary string cap. */
static int utf8_length(LPCCH source, int supplied, size_t *length) {
    size_t count = 0, limit;
    if (!source || supplied == 0 || supplied < -1) return 0;
    if (supplied > 0) { *length = (size_t)supplied; return 1; }
    limit = UINTPTR_MAX - (uintptr_t)source;
    while (count < limit) {
        if (source[count++] == 0) { *length = count; return 1; }
    }
    return 0;
}
static int utf16_length(LPCWCH source, int supplied, size_t *length) {
    size_t count = 0, limit;
    if (!source || (uintptr_t)source % sizeof(*source) != 0 ||
        supplied == 0 || supplied < -1) return 0;
    if (supplied > 0) { *length = (size_t)supplied; return 1; }
    limit = (UINTPTR_MAX - (uintptr_t)source) / sizeof(*source);
    while (count < limit) {
        if (source[count++] == 0) { *length = count; return 1; }
    }
    return 0;
}
int WINAPI NtwMultiByteToWideChar(UINT page, DWORD flags, LPCCH source,
                                int source_bytes, LPWSTR destination, int capacity) {
    size_t length, required = 0;
    int status;
    if (page != CP_UTF8)
        return MultiByteToWideChar(page, flags, source, source_bytes, destination, capacity);
    if (flags & ~((DWORD)MB_ERR_INVALID_CHARS)) return utf_error(ERROR_INVALID_FLAGS);
    if (capacity < 0 || (const void *)source == (const void *)destination ||
        !source || source_bytes == 0 || source_bytes < -1)
        return utf_error(ERROR_INVALID_PARAMETER);
    if (capacity > 0 && !destination) return utf_error(ERROR_INSUFFICIENT_BUFFER);
    if (!utf8_length(source, source_bytes, &length)) return utf_error(ERROR_INVALID_PARAMETER);
    status = ntwu_utf8_to_utf16((const uint8_t *)source, length,
        (uint16_t *)destination, (size_t)capacity,
        flags ? NTWU_STRICT : 0, &required);
    return utf_result(status, required);
}
int WINAPI NtwWideCharToMultiByte(UINT page, DWORD flags, LPCWCH source,
                                int source_units, LPSTR destination, int capacity,
                                LPCCH default_char, LPBOOL used_default) {
    size_t length, required = 0;
    int status;
    if (page != CP_UTF8)
        return WideCharToMultiByte(page, flags, source, source_units,
                                  destination, capacity, default_char, used_default);
    if (flags & ~((DWORD)WC_ERR_INVALID_CHARS)) return utf_error(ERROR_INVALID_FLAGS);
    if (default_char || used_default || capacity < 0 ||
        (const void *)source == (const void *)destination ||
        !source || source_units == 0 || source_units < -1)
        return utf_error(ERROR_INVALID_PARAMETER);
    if (capacity > 0 && !destination) return utf_error(ERROR_INSUFFICIENT_BUFFER);
    if (!utf16_length(source, source_units, &length)) return utf_error(ERROR_INVALID_PARAMETER);
    status = ntwu_utf16_to_utf8((const uint16_t *)source, length,
        (uint8_t *)destination, (size_t)capacity,
        flags ? NTWU_STRICT : 0, &required);
    return utf_result(status, required);
}
FARPROC WINAPI NtwGetProcAddress(HMODULE module, LPCSTR name);
PVOID WINAPI NtwAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
ULONG WINAPI NtwRemoveVectoredExceptionHandler(PVOID handle);
static ntw_proc lookup_owned(void *context, const char *name) {
    (void)context;
#define NTW_ROUTE(exported, implementation) \
    if (ntw_export_name_equal(name, exported)) return (ntw_proc)implementation;
#include "routes.inc"
#undef NTW_ROUTE
    return (ntw_proc)0;
}
static ntw_proc lookup_native(void *context, uintptr_t module, const char *name) {
    (void)context;
    return (ntw_proc)GetProcAddress((HMODULE)module, name);
}
FARPROC WINAPI NtwGetProcAddress(HMODULE module, LPCSTR name) {
    const struct ntw_resolver resolver = {
        (uintptr_t)native_kernel32, lookup_owned, lookup_native, NULL
    };
    return (FARPROC)ntw_resolve(&resolver, (uintptr_t)module, name);
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        native_kernel32 = GetModuleHandleA("KERNEL32.DLL");
        if (!native_kernel32) return FALSE;
        if (ntw_k32_init() != NTWE_OK) return FALSE;
    }
    return TRUE;
}
PVOID WINAPI NtwAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
    void *registered = NULL;
    int status = ntw_k32_add(first, (ntw_vectored_handler)handler, &registered);
    if (status != NTWE_OK) {
        SetLastError(status == NTWE_NO_MEMORY || status == NTWE_LIMIT
                     ? ERROR_NOT_ENOUGH_MEMORY : ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return registered;
}
ULONG WINAPI NtwRemoveVectoredExceptionHandler(PVOID handle) {
    int status = ntw_k32_remove(handle);
    if (status == NTWE_OK || status == NTWE_PENDING) return 1;
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
}
