/* SPDX-License-Identifier: GPL-2.0-only
 * Original app-local PE32 provider. Only stock Win98 imports, no CRT. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>
#include <limits.h>
#include "sync.h"
#include "resolve.h"
#include "routing.h"
#include "initonce.h"
#include "unicode/utf.h"
#include "exception/k32veh.h"
typedef char pointer_width_must_be_32[(sizeof(void *) == 4) ? 1 : -1];
typedef char once_matches_win32[(sizeof(ntw_once) == sizeof(INIT_ONCE)) ? 1 : -1];
typedef char wchar_matches_utf16[(sizeof(WCHAR) == sizeof(uint16_t)) ? 1 : -1];
static ntw_srw tick_lock;
static struct ntw_tick_clock tick_clock;
static HMODULE native_kernel32;

/* The seventeen exports, declared here so the generated table can name them. */
void WINAPI NtwInitializeSRWLock(void *lock);
void WINAPI NtwAcquireSRWLockExclusive(void *lock);
void WINAPI NtwAcquireSRWLockShared(void *lock);
void WINAPI NtwReleaseSRWLockExclusive(void *lock);
void WINAPI NtwReleaseSRWLockShared(void *lock);
BOOLEAN WINAPI NtwTryAcquireSRWLockExclusive(void *lock);
BOOLEAN WINAPI NtwTryAcquireSRWLockShared(void *lock);
ULONGLONG WINAPI NtwGetTickCount64(void);
FARPROC WINAPI NtwGetProcAddress(HMODULE module, LPCSTR name);
void WINAPI NtwInitOnceInitialize(PINIT_ONCE once);
BOOL WINAPI NtwInitOnceBeginInitialize(PINIT_ONCE once, DWORD flags, PBOOL pending, LPVOID *context);
BOOL WINAPI NtwInitOnceComplete(PINIT_ONCE once, DWORD flags, LPVOID context);
BOOL WINAPI NtwInitOnceExecuteOnce(PINIT_ONCE once, PINIT_ONCE_FN callback, PVOID parameter, LPVOID *context);
int WINAPI NtwMultiByteToWideChar(UINT page, DWORD flags, LPCCH source, int source_bytes,
                                  LPWSTR destination, int capacity);
int WINAPI NtwWideCharToMultiByte(UINT page, DWORD flags, LPCWCH source, int source_units,
                                  LPSTR destination, int capacity, LPCCH default_char, LPBOOL used_default);
PVOID WINAPI NtwAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler);
ULONG WINAPI NtwRemoveVectoredExceptionHandler(PVOID handle);

/* Routing table generated from routes.json (build/platform/routes.inc). */
enum {
#define NTW_ROUTE(exported, implementation, order) NTW_INDEX_##implementation,
#define NTW_STUB(module, name, provider)
#include "routes.inc"
#undef NTW_ROUTE
#undef NTW_STUB
    NTW_ROUTE_COUNT
};
static const struct ntw_route_entry route_entries[] = {
#define NTW_ROUTE(exported, implementation, order) { exported, order },
#define NTW_STUB(module, name, provider)
#include "routes.inc"
#undef NTW_ROUTE
#undef NTW_STUB
};
static const struct ntw_stub_entry stub_entries[] = {
#define NTW_ROUTE(exported, implementation, order)
#define NTW_STUB(module, name, provider) { module, name, provider },
#include "routes.inc"
#undef NTW_ROUTE
#undef NTW_STUB
    { 0, 0, 0 }  /* sentinel so the array is never empty */
};
static const struct ntw_route_table route_table = {
    route_entries, NTW_ROUTE_COUNT,
    stub_entries, (unsigned)(sizeof stub_entries / sizeof stub_entries[0]) - 1u,
    NTW_DEFAULT_ORDER
};
typedef char route_count_matches[(sizeof route_entries / sizeof route_entries[0] == NTW_ROUTE_COUNT) ? 1 : -1];

/* Per-process routing state, written under the loader lock at attach and
 * read-only afterwards. Static storage is zero without a runtime memset. */
static struct ntw_route_policy policy;
static struct ntw_resolver resolver;
static ntw_proc forward[NTW_ROUTE_COUNT];   /* non-own provider chosen for a static export */
static struct { uintptr_t base, end; } kernelex_images[2];
static unsigned kernelex_image_count;
static uintptr_t own_base, own_end;   /* this DLL's image, for the self-forward guard */
static unsigned kernelex_state;
static char config_text[NTW_ROUTE_TEXT_MAX + 1];
static char config_path[MAX_PATH + 16];

static void route_log(void *context, const char *message) {
    (void)context;
    OutputDebugStringA(message);
}
static ntw_proc lookup_owned(void *context, const char *name) {
    (void)context;
#define NTW_ROUTE(exported, implementation, order) \
    if (ntw_export_name_equal(name, exported)) return (ntw_proc)implementation;
#define NTW_STUB(module, name, provider)
#include "routes.inc"
#undef NTW_ROUTE
#undef NTW_STUB
    return (ntw_proc)0;
}
static ntw_proc lookup_native(void *context, uintptr_t module, const char *name) {
    (void)context;
    return (ntw_proc)GetProcAddress((HMODULE)module, name);
}
static int kernelex_owns(void *context, ntw_proc address) {
    unsigned i;
    (void)context;
    for (i = 0; i < kernelex_image_count; ++i)
        if ((uintptr_t)address >= kernelex_images[i].base && (uintptr_t)address < kernelex_images[i].end)
            return 1;
    return 0;
}

static void say3(const char *a, const char *b, const char *c) {
    char buffer[NTW_ROUTE_MESSAGE_MAX];
    struct ntw_text text;
    ntw_text_start(&text, buffer, sizeof buffer);
    ntw_text_add(&text, a);
    if (b) ntw_text_add_bounded(&text, b, 80);
    if (c) ntw_text_add(&text, c);
    OutputDebugStringA(buffer);
}

/* KernelEx presence: the core and its API libraries are looked up by file
 * name with GetModuleHandleA only (nothing is loaded). An API library counts
 * when the resolver's native lookup finds its get_api_table export. Its
 * mapped image range, read from its own PE headers, is what attributes a
 * native-loader result to KernelEx. Requires resolver.native to be set. */
static void detect_kernelex(void) {
    static const char *const libraries[2] = { "KEXBASES.DLL", "KEXBASEN.DLL" };
    HMODULE core = GetModuleHandleA("KERNELEX.DLL");
    unsigned i;
    kernelex_image_count = 0;
    for (i = 0; i < 2; ++i) {
        HMODULE library = GetModuleHandleA(libraries[i]);
        uint32_t size;
        if (!library) continue;
        if (!resolver.native(resolver.context, (uintptr_t)library, "get_api_table")) {
            say3("NTW32: ", libraries[i], " is mapped without get_api_table; ignored");
            continue;
        }
        if (((uintptr_t)library & 0xfff) ||
            !ntw_route_image_size((const unsigned char *)library, 0x1000, &size) ||
            (uintptr_t)library + size < (uintptr_t)library) {
            say3("NTW32: ", libraries[i], " has unreadable PE headers; not attributed");
            continue;
        }
        kernelex_images[kernelex_image_count].base = (uintptr_t)library;
        kernelex_images[kernelex_image_count].end = (uintptr_t)library + size;
        ++kernelex_image_count;
    }
    kernelex_state = kernelex_image_count ? NTW_KERNELEX_ACTIVE :
                     core ? NTW_KERNELEX_CORE_ONLY : NTW_KERNELEX_NOT_DETECTED;
    if (!core && kernelex_image_count)
        say3("NTW32: KernelEx API library mapped without KERNELEX.DLL core", 0, 0);
}

static void load_configuration(HINSTANCE instance) {
    DWORD length, got;
    HANDLE file;
    unsigned i, directory = 0;
    ntw_route_policy_init(&policy);
    length = GetEnvironmentVariableA("NTW32_ROUTING", config_text, sizeof config_text);
    if (length) {
        if (length >= sizeof config_text) {
            ++policy.warnings;
            say3("NTW32: NTW32_ROUTING longer than 4096 bytes; ignored", 0, 0);
            return;
        }
        policy.source = NTW_ROUTE_SOURCE_ENV;
        (void)ntw_route_parse(&policy, config_text, length, '|', route_log, 0);
        return;
    }
    length = GetModuleFileNameA(instance, config_path, MAX_PATH);
    if (!length || length >= MAX_PATH) {
        ++policy.warnings;
        say3("NTW32: cannot determine the provider path; NTW32.INI not read", 0, 0);
        return;
    }
    for (i = 0; i < length; ++i)
        if (config_path[i] == '\\' || config_path[i] == '/') directory = i + 1;
    if (!directory || directory + sizeof "NTW32.INI" > MAX_PATH) {
        ++policy.warnings;
        say3("NTW32: provider path has no directory; NTW32.INI not read", 0, 0);
        return;
    }
    {
        static const char ini[] = "NTW32.INI";
        for (i = 0; i < sizeof ini; ++i) config_path[directory + i] = ini[i];
    }
    file = CreateFileA(config_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return;   /* absent or unreadable: defaults */
    got = 0;
    if (!ReadFile(file, config_text, sizeof config_text, &got, NULL)) {
        ++policy.warnings;
        say3("NTW32: NTW32.INI could not be read; defaults retained", 0, 0);
    } else if (got >= sizeof config_text) {
        ++policy.warnings;
        say3("NTW32: NTW32.INI longer than 4096 bytes; ignored", 0, 0);
    } else {
        policy.source = NTW_ROUTE_SOURCE_INI;
        (void)ntw_route_parse(&policy, config_text, got, '\n', route_log, 0);
    }
    (void)CloseHandle(file);
}

static void summarize(void) {
    char buffer[NTW_ROUTE_MESSAGE_MAX];
    struct ntw_text text;
    ntw_text_start(&text, buffer, sizeof buffer);
    ntw_text_add(&text, "NTW32: routing mode=");
    ntw_text_add(&text, ntw_route_mode_name(policy.mode));
    ntw_text_add(&text, " source=");
    ntw_text_add(&text, policy.source == NTW_ROUTE_SOURCE_ENV ? "NTW32_ROUTING" :
                 policy.source == NTW_ROUTE_SOURCE_INI ? "NTW32.INI" : "default");
    ntw_text_add(&text, " overrides=");
    ntw_text_add_uint(&text, policy.override_count);
    ntw_text_add(&text, " warnings=");
    ntw_text_add_uint(&text, policy.warnings);
    ntw_text_add(&text, " kernelex=");
    ntw_text_add(&text, ntw_route_kernelex_name(kernelex_state));
    ntw_text_add(&text, " order=");
    if (policy.order) ntw_text_add_order(&text, policy.order);
    else ntw_text_add(&text, "routes.json");
    OutputDebugStringA(buffer);
}

/* Static exports are already bound to this DLL by the prepared import table.
 * When the policy selects another provider for a name, the export forwards
 * to it; otherwise the own implementation stays bound. */
static void bind_forwards(void) {
    unsigned i;
    for (i = 0; i < NTW_ROUTE_COUNT; ++i) {
        unsigned provider = NTW_PROVIDER_NONE;
        ntw_proc target;
        /* The dynamic router applies the policy inside itself and is never
         * forwarded; a mode Native lookup is still a pure passthrough there. */
        if (i == NTW_INDEX_NtwGetProcAddress) { forward[i] = (ntw_proc)0; continue; }
        target = ntw_resolve_named(&resolver, route_entries[i].name, &provider);
        /* A loader answer inside this DLL would make the export call itself
         * forever; such an answer is this implementation, so keep it bound. */
        if (target && provider != NTW_PROVIDER_OWN &&
            (uintptr_t)target >= own_base && (uintptr_t)target < own_end) {
            say3("NTW32: static export ", route_entries[i].name,
                 " resolved into NTW32.DLL itself; own implementation kept");
            target = (ntw_proc)0;
        }
        forward[i] = (target && provider != NTW_PROVIDER_OWN) ? target : (ntw_proc)0;
        /* Outside mode Native the resolver has just reported the name as
         * unresolved; say what the already-bound export does instead. */
        if (!target && (policy.log ||
                        ntw_route_effective_mode(&policy, "KERNEL32.DLL", route_entries[i].name) != NTW_MODE_NATIVE))
            say3("NTW32: static export ", route_entries[i].name, " keeps the own implementation");
    }
}

static void configure(HINSTANCE instance) {
    unsigned i;
    uint32_t size;
    for (i = 0; i < NTW_ROUTE_COUNT; ++i) forward[i] = (ntw_proc)0;
    own_base = (uintptr_t)instance;
    own_end = own_base;
    /* Headers of the loaded image are mapped; without a readable size the
     * guard still covers the first page, where no forward target can lie. */
    if (!(own_base & 0xfff) && ntw_route_image_size((const unsigned char *)instance, 0x1000, &size) &&
        own_base + size > own_base)
        own_end = own_base + size;
    else
        own_end = own_base + 0x1000;
    load_configuration(instance);
    (void)ntw_route_check(&policy, "KERNEL32.DLL", route_log, 0);
    resolver.kernel32_module = (uintptr_t)native_kernel32;
    resolver.owned = lookup_owned;
    resolver.native = lookup_native;
    resolver.context = NULL;
    resolver.table = &route_table;
    resolver.policy = &policy;
    resolver.kernelex_owns = kernelex_owns;
    resolver.log = route_log;
    detect_kernelex();
    resolver.kernelex_state = kernelex_state;
    if (policy.log) summarize();
    bind_forwards();
}

/* Forward to the provider the policy selected, when it is not this DLL. */
#define NTW_FORWARD(implementation, type, ...) do { \
    ntw_proc target_ = forward[NTW_INDEX_##implementation]; \
    if (target_) return ((type)target_)(__VA_ARGS__); } while (0)
#define NTW_FORWARD_VOID(implementation, type, ...) do { \
    ntw_proc target_ = forward[NTW_INDEX_##implementation]; \
    if (target_) { ((type)target_)(__VA_ARGS__); return; } } while (0)
typedef void (WINAPI *lock_void_fn)(void *);
typedef BOOLEAN (WINAPI *lock_bool_fn)(void *);

/* A zero-delay yield leaves this waiter runnable. Use a finite blocking wait
 * so lock/initialization owners can progress at a lower scheduling priority.
 * Resolution and fairness remain properties of the native scheduler. */
static void yield_thread(void) { Sleep(1); }
void WINAPI NtwInitializeSRWLock(void *lock) {
    NTW_FORWARD_VOID(NtwInitializeSRWLock, lock_void_fn, lock);
    ntw_srw_init((ntw_srw *)lock);
}
void WINAPI NtwAcquireSRWLockExclusive(void *lock) {
    NTW_FORWARD_VOID(NtwAcquireSRWLockExclusive, lock_void_fn, lock);
    ntw_srw_acquire_exclusive(lock, yield_thread);
}
void WINAPI NtwAcquireSRWLockShared(void *lock) {
    NTW_FORWARD_VOID(NtwAcquireSRWLockShared, lock_void_fn, lock);
    ntw_srw_acquire_shared(lock, yield_thread);
}
void WINAPI NtwReleaseSRWLockExclusive(void *lock) {
    NTW_FORWARD_VOID(NtwReleaseSRWLockExclusive, lock_void_fn, lock);
    ntw_srw_release_exclusive(lock);
}
void WINAPI NtwReleaseSRWLockShared(void *lock) {
    NTW_FORWARD_VOID(NtwReleaseSRWLockShared, lock_void_fn, lock);
    ntw_srw_release_shared(lock);
}
BOOLEAN WINAPI NtwTryAcquireSRWLockExclusive(void *lock) {
    NTW_FORWARD(NtwTryAcquireSRWLockExclusive, lock_bool_fn, lock);
    return (BOOLEAN)ntw_srw_try_exclusive(lock);
}
BOOLEAN WINAPI NtwTryAcquireSRWLockShared(void *lock) {
    NTW_FORWARD(NtwTryAcquireSRWLockShared, lock_bool_fn, lock);
    return (BOOLEAN)ntw_srw_try_shared(lock);
}
ULONGLONG WINAPI NtwGetTickCount64(void) {
    ULONGLONG result;
    ntw_proc target = forward[NTW_INDEX_NtwGetTickCount64];
    if (target) return ((ULONGLONG (WINAPI *)(void))target)();
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
    NTW_FORWARD_VOID(NtwInitOnceInitialize, void (WINAPI *)(PINIT_ONCE), once);
    (void)ntw_once_init((ntw_once *)once);
}
BOOL WINAPI NtwInitOnceBeginInitialize(PINIT_ONCE once, DWORD flags,
                                      PBOOL pending, LPVOID *context) {
    NTW_FORWARD(NtwInitOnceBeginInitialize, BOOL (WINAPI *)(PINIT_ONCE, DWORD, PBOOL, LPVOID *),
                once, flags, pending, context);
    return once_result(ntw_once_begin((ntw_once *)once, flags, pending,
                                      context, yield_thread));
}
BOOL WINAPI NtwInitOnceComplete(PINIT_ONCE once, DWORD flags, LPVOID context) {
    NTW_FORWARD(NtwInitOnceComplete, BOOL (WINAPI *)(PINIT_ONCE, DWORD, LPVOID), once, flags, context);
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
    NTW_FORWARD(NtwInitOnceExecuteOnce, BOOL (WINAPI *)(PINIT_ONCE, PINIT_ONCE_FN, PVOID, LPVOID *),
                once, callback, parameter, context);
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
typedef int (WINAPI *mb_fn)(UINT, DWORD, LPCCH, int, LPWSTR, int);
typedef int (WINAPI *wc_fn)(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
int WINAPI NtwMultiByteToWideChar(UINT page, DWORD flags, LPCCH source,
                                int source_bytes, LPWSTR destination, int capacity) {
    size_t length, required = 0;
    int status;
    NTW_FORWARD(NtwMultiByteToWideChar, mb_fn, page, flags, source, source_bytes, destination, capacity);
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
    NTW_FORWARD(NtwWideCharToMultiByte, wc_fn, page, flags, source, source_units,
                destination, capacity, default_char, used_default);
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
FARPROC WINAPI NtwGetProcAddress(HMODULE module, LPCSTR name) {
    DWORD saved = GetLastError();
    FARPROC found = (FARPROC)ntw_resolve(&resolver, (uintptr_t)module, name);
    /* A native probe that failed before another provider answered must not
     * leak ERROR_PROC_NOT_FOUND into a successful lookup. An unresolved routed
     * name reports that documented loader error, so a caller probing for the
     * symbol sees a failure rather than a stale value. */
    if (found) SetLastError(saved);
    else if (module == native_kernel32 && (uintptr_t)name > UINT16_MAX &&
             ntw_route_effective_mode(&policy, "KERNEL32.DLL", name) != NTW_MODE_NATIVE)
        SetLastError(ERROR_PROC_NOT_FOUND);
    return found;
}
BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        native_kernel32 = GetModuleHandleA("KERNEL32.DLL");
        if (!native_kernel32) return FALSE;
        if (ntw_k32_init() != NTWE_OK) return FALSE;
        configure(instance);
    }
    return TRUE;
}
PVOID WINAPI NtwAddVectoredExceptionHandler(ULONG first, PVECTORED_EXCEPTION_HANDLER handler) {
    void *registered = NULL;
    int status;
    NTW_FORWARD(NtwAddVectoredExceptionHandler, PVOID (WINAPI *)(ULONG, PVECTORED_EXCEPTION_HANDLER),
                first, handler);
    status = ntw_k32_add(first, (ntw_vectored_handler)handler, &registered);
    if (status != NTWE_OK) {
        SetLastError(status == NTWE_NO_MEMORY || status == NTWE_LIMIT
                     ? ERROR_NOT_ENOUGH_MEMORY : ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return registered;
}
ULONG WINAPI NtwRemoveVectoredExceptionHandler(PVOID handle) {
    int status;
    NTW_FORWARD(NtwRemoveVectoredExceptionHandler, ULONG (WINAPI *)(PVOID), handle);
    status = ntw_k32_remove(handle);
    if (status == NTWE_OK || status == NTWE_PENDING) return 1;
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
}
