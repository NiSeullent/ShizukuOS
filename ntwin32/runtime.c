/* SPDX-License-Identifier: GPL-2.0-only
 * Original app-local PE32 provider. Only stock Win98 imports, no CRT. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include "sync.h"
#include "resolve.h"
#include "initonce.h"
typedef char pointer_width_must_be_32[(sizeof(void *) == 4) ? 1 : -1];
typedef char once_matches_win32[(sizeof(ntw_once) == sizeof(INIT_ONCE)) ? 1 : -1];
static ntw_srw tick_lock;
static struct ntw_tick_clock tick_clock;
static HMODULE native_kernel32;
static void yield_thread(void) { Sleep(0); }
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
FARPROC WINAPI NtwGetProcAddress(HMODULE module, LPCSTR name);
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
    }
    return TRUE;
}
