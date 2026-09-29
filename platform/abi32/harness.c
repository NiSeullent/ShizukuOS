/* SPDX-License-Identifier: GPL-2.0-only
 * Original Linux ELF32 test harness for actual MinGW-produced PE32 code.
 * Mocked OS services are deliberately limited and not a Windows emulator.
 */
#include <stdint.h>
#include <stddef.h>
#include "pe_config.h"

#define STDCALL __attribute__((stdcall))
#define KERNEL_HANDLE UINT32_C(0x12340000)
#define OTHER_HANDLE UINT32_C(0x56780000)

_Static_assert(sizeof(void *) == 4, "Must execute genuine 32-bit code");

struct call_result { uint32_t low, high, stack_ok; };
extern void abi_call(uintptr_t target, const uint32_t *arguments, uint32_t count,
                      struct call_result *result);
static uint32_t checks, export_calls;

static void write_bytes(const char *text, uint32_t bytes)
{
    int result;
    __asm__ volatile("int $0x80" : "=a"(result) : "a"(4), "b"(1), "c"(text), "d"(bytes) : "memory");
    (void)result;
}

static void write_string(const char *text)
{
    uint32_t bytes = 0;
    while (text[bytes]) ++bytes;
    write_bytes(text, bytes);
}

static void write_number(uint32_t value)
{
    char digits[10];
    uint32_t length = 0;
    do {
        digits[length++] = (char)('0' + value % 10);
        value /= 10;
    } while (value != 0);
    while (length != 0) write_bytes(&digits[--length], 1);
}

__attribute__((noreturn)) static void fail(const char *expression, uint32_t line)
{
    write_string("FAIL ABI32 line "); write_number(line); write_string(": ");
    write_string(expression); write_string("\n");
    __asm__ volatile("int $0x80" : : "a"(1), "b"(1) : "memory");
    for (;;) { }
}

#define CHECK(expression) do { ++checks; if (!(expression)) fail(#expression, __LINE__); } while (0)

static int equal(const char *left, const char *right)
{
    while (*left && *left == *right) { ++left; ++right; }
    return *left == *right;
}

static uint32_t last_error;
static uint32_t module_available = 1;
static uint32_t module_calls, native_calls, sleep_calls, tick_calls;
static uint32_t zero_delay_yields;
static uintptr_t native_last_module;
static const char *native_last_name;
static void (*sleep_completion)(void);

/* Routing-policy scenario state. The fake KernelEx API library is a data
 * buffer with valid PE32 headers; addresses inside it are compared, never
 * called. KERNELEX.DLL's handle is an opaque value that is never read. */
#define KEX_CORE_HANDLE UINT32_C(0x5a000000)
#define INI_HANDLE UINT32_C(0x77770004)
__attribute__((aligned(4096))) static unsigned char kex_image[8192];
static uint32_t kex_probe_calls, kex_core_present, kex_bases_present;
static uint32_t kex_hook_initonce, kex_hook_sleep, native_self_alias;
static const char *ini_text;
static uint32_t ini_length, ini_opened, ini_closed, ini_reads;
static const char *env_text;
static char debug_log[16384];
static uint32_t debug_length, debug_messages, reattaches;

static void STDCALL mock_SetLastError(uint32_t error) { last_error = error; }
static uint32_t STDCALL mock_GetLastError(void) { return last_error; }
static void STDCALL mock_Sleep(uint32_t milliseconds)
{
    void (*complete)(void) = sleep_completion;
    ++sleep_calls;
    CHECK(complete != NULL);
    /* Deterministic priority model: the waiter is runnable at higher priority
     * than the owner. A zero-delay yield does not make that owner eligible.
     * Fail promptly if the real DLL keeps polling without ever blocking. */
    if (milliseconds == 0) {
        ++zero_delay_yields;
        CHECK(zero_delay_yields < 8);
        return;
    }
    CHECK(milliseconds != UINT32_MAX);
    sleep_completion = NULL;
    complete();
}
static uint32_t STDCALL mock_GetTickCount(void)
{
    static const uint32_t samples[] = { UINT32_C(0xfffffff0), UINT32_C(0xfffffff5), 3, 19, 35 };
    CHECK(tick_calls < sizeof(samples) / sizeof(samples[0]));
    return samples[tick_calls++];
}
static uintptr_t STDCALL mock_GetModuleHandleA(const char *name)
{
    if (equal(name, "KERNEL32.DLL")) {
        ++module_calls;
        return module_available ? KERNEL_HANDLE : 0;
    }
    /* KernelEx presence is probed by name only; nothing is ever loaded. */
    ++kex_probe_calls;
    if (equal(name, "KERNELEX.DLL")) return kex_core_present ? KEX_CORE_HANDLE : 0;
    if (equal(name, "KEXBASES.DLL")) return kex_bases_present ? (uintptr_t)kex_image : 0;
    CHECK(equal(name, "KEXBASEN.DLL"));
    return 0;
}
static uint32_t STDCALL native_function(void) { return UINT32_C(0xcafe1234); }

static uint32_t native_mb_calls, native_wc_calls, native_mb_args[6], native_wc_args[8];
static int native_conversion_result;
static uint32_t native_conversion_error;
static int STDCALL mock_MultiByteToWideChar(uint32_t page, uint32_t flags,
    const char *source, int length, uint16_t *destination, int capacity)
{
    ++native_mb_calls;
    native_mb_args[0] = page; native_mb_args[1] = flags;
    native_mb_args[2] = (uintptr_t)source; native_mb_args[3] = (uint32_t)length;
    native_mb_args[4] = (uintptr_t)destination; native_mb_args[5] = (uint32_t)capacity;
    if (!native_conversion_result) last_error = native_conversion_error;
    return native_conversion_result;
}
static int STDCALL mock_WideCharToMultiByte(uint32_t page, uint32_t flags,
    const uint16_t *source, int length, char *destination, int capacity,
    const char *default_char, int *used_default)
{
    ++native_wc_calls;
    native_wc_args[0] = page; native_wc_args[1] = flags;
    native_wc_args[2] = (uintptr_t)source; native_wc_args[3] = (uint32_t)length;
    native_wc_args[4] = (uintptr_t)destination; native_wc_args[5] = (uint32_t)capacity;
    native_wc_args[6] = (uintptr_t)default_char; native_wc_args[7] = (uintptr_t)used_default;
    if (!native_conversion_result) last_error = native_conversion_error;
    return native_conversion_result;
}

/* The native KERNEL32 export inventory this mock models: the DLL's own
 * imports (all present in the Windows 98 SE OEM manifest) plus CompareStringW,
 * a natively exported name that routes.json lists as a known native stub.
 * Every other KERNEL32 name is absent, as the SRW/InitOnce/tick/VEH names are
 * on Windows 98. Other module handles export everything (foreign DLL model). */
static uintptr_t STDCALL mock_GetProcAddress(uintptr_t module, const char *name)
{
    static const char *const inventory[] = {
        "Sleep", "GetTickCount", "GetModuleHandleA", "SetLastError", "GetLastError",
        "GetModuleFileNameA", "CreateFileA", "ReadFile", "CloseHandle",
        "GetEnvironmentVariableA", "OutputDebugStringA", "CompareStringW" };
    uint32_t i;
    ++native_calls;
    native_last_module = module;
    native_last_name = name;
    if ((uintptr_t)name <= UINT32_C(0xffff)) return (uintptr_t)&native_function;
    if (module == (uintptr_t)kex_image) {
        /* Like the documented KernelEx API libraries, only get_api_table is exported. */
        return equal(name, "get_api_table") ? (uintptr_t)kex_image + UINT32_C(0x800) : 0;
    }
    if (module != KERNEL_HANDLE) return (uintptr_t)&native_function;
    /* Hostile loader model: answer with the provider's own export. */
    if (native_self_alias && equal(name, "InitializeSRWLock")) return PE_BASE + RVA_InitializeSRWLock;
    /* A KernelEx-hooked loader answers with code inside its API library. */
    if ((kex_hook_initonce && equal(name, "InitOnceExecuteOnce")) ||
        (kex_hook_sleep && equal(name, "Sleep")))
        return (uintptr_t)kex_image + UINT32_C(0x1000);
    if (equal(name, "GetProcAddress")) return (uintptr_t)&mock_GetProcAddress;
    if (equal(name, "MultiByteToWideChar")) return (uintptr_t)&mock_MultiByteToWideChar;
    if (equal(name, "WideCharToMultiByte")) return (uintptr_t)&mock_WideCharToMultiByte;
    for (i = 0; i < sizeof inventory / sizeof inventory[0]; ++i)
        if (equal(name, inventory[i])) return (uintptr_t)&native_function;
    mock_SetLastError(127);
    return 0;
}

static uint32_t STDCALL mock_GetModuleFileNameA(uintptr_t module, char *buffer, uint32_t size)
{
    static const char path[] = "C:\\APP\\NTW32.DLL";
    uint32_t i;
    CHECK(module == PE_BASE && size >= sizeof path);
    for (i = 0; i < sizeof path; ++i) buffer[i] = path[i];
    return sizeof path - 1;
}
static uintptr_t STDCALL mock_CreateFileA(const char *path, uint32_t access, uint32_t share,
    void *security, uint32_t disposition, uint32_t flags, uintptr_t template_file)
{
    CHECK(equal(path, "C:\\APP\\NTW32.INI"));
    CHECK(access == UINT32_C(0x80000000) && share == 1 && security == NULL);
    CHECK(disposition == 3 && flags == UINT32_C(0x80) && template_file == 0);
    if (!ini_text) { mock_SetLastError(2); return UINT32_MAX; }
    ++ini_opened;
    ini_reads = 0;
    return INI_HANDLE;
}
static int STDCALL mock_ReadFile(uintptr_t handle, void *buffer, uint32_t bytes,
    uint32_t *read, void *overlapped)
{
    uint32_t i, count = ini_length < bytes ? ini_length : bytes;
    CHECK(handle == INI_HANDLE && overlapped == NULL && read != NULL);
    CHECK(ini_reads++ == 0);
    for (i = 0; i < count; ++i) ((char *)buffer)[i] = ini_text[i];
    *read = count;
    return 1;
}
static int STDCALL mock_CloseHandle(uintptr_t handle)
{
    CHECK(handle == INI_HANDLE);
    ++ini_closed;
    return 1;
}
static uint32_t STDCALL mock_GetEnvironmentVariableA(const char *name, char *buffer, uint32_t size)
{
    uint32_t length = 0, i;
    CHECK(equal(name, "NTW32_ROUTING"));
    if (!env_text) { mock_SetLastError(203); return 0; }
    while (env_text[length]) ++length;
    if (length >= size) return length + 1;   /* documented: required size including NUL */
    for (i = 0; i <= length; ++i) buffer[i] = env_text[i];
    return length;
}
static void STDCALL mock_OutputDebugStringA(const char *text)
{
    uint32_t i, length = 0;
    ++debug_messages;
    while (text[length]) ++length;
    CHECK(length < 200 && debug_length + length + 2 < sizeof debug_log);
    for (i = 0; i < length; ++i) debug_log[debug_length++] = text[i];
    debug_log[debug_length++] = '\n';
    debug_log[debug_length] = 0;
}
static int log_contains(const char *needle)
{
    uint32_t start, i;
    for (start = 0; start < debug_length; ++start) {
        for (i = 0; needle[i] && start + i < debug_length && debug_log[start + i] == needle[i]; ++i) { }
        if (!needle[i]) return 1;
    }
    return 0;
}
static void clear_log(void)
{
    debug_length = 0;
    debug_messages = 0;
    debug_log[0] = 0;
}
static void put16(unsigned char *at, uint32_t value)
{
    at[0] = (unsigned char)(value & 0xffu);
    at[1] = (unsigned char)((value >> 8) & 0xffu);
}
static void put32(unsigned char *at, uint32_t value)
{
    put16(at, value & 0xffffu);
    put16(at + 2, value >> 16);
}
static void build_kex_image(void)
{
    uint32_t i;
    for (i = 0; i < sizeof kex_image; ++i) kex_image[i] = 0;
    kex_image[0] = 'M'; kex_image[1] = 'Z';
    put32(kex_image + 60, 0x80);                    /* e_lfanew */
    put32(kex_image + 0x80, UINT32_C(0x00004550));  /* PE\0\0 */
    put16(kex_image + 0x84, 0x14c);                 /* i386 */
    put16(kex_image + 0x80 + 24, 0x10b);            /* PE32 */
    put32(kex_image + 0x80 + 24 + 56, 0x2000);      /* SizeOfImage: whole buffer */
}

static void patch_imports(void)
{
#include "pe_imports.inc"
}

static struct call_result invoke(uint32_t rva, uint32_t count, const uint32_t *arguments)
{
    struct call_result result;
    abi_call(PE_BASE + rva, arguments, count, &result);
    ++export_calls;
    CHECK(result.stack_ok == 1);
    return result;
}
static struct call_result call0(uint32_t rva) { return invoke(rva, 0, NULL); }
static struct call_result call1(uint32_t rva, uintptr_t a)
{
    uint32_t args[] = { a };
    return invoke(rva, 1, args);
}
static struct call_result call2(uint32_t rva, uintptr_t a, uintptr_t b)
{
    uint32_t args[] = { a, b };
    return invoke(rva, 2, args);
}
static struct call_result call3(uint32_t rva, uintptr_t a, uintptr_t b, uintptr_t c)
{
    uint32_t args[] = { a, b, c };
    return invoke(rva, 3, args);
}
static struct call_result call4(uint32_t rva, uintptr_t a, uintptr_t b, uintptr_t c, uintptr_t d)
{
    uint32_t args[] = { a, b, c, d };
    return invoke(rva, 4, args);
}
static uint32_t convert_mb(uint32_t page, uint32_t flags, const void *source,
    int length, void *destination, int capacity)
{
    uint32_t args[] = { page, flags, (uintptr_t)source, (uint32_t)length,
                        (uintptr_t)destination, (uint32_t)capacity };
    return invoke(RVA_MultiByteToWideChar, 6, args).low;
}
static uint32_t convert_wc(uint32_t page, uint32_t flags, const void *source,
    int length, void *destination, int capacity, const void *default_char, void *used_default)
{
    uint32_t args[] = { page, flags, (uintptr_t)source, (uint32_t)length,
        (uintptr_t)destination, (uint32_t)capacity, (uintptr_t)default_char, (uintptr_t)used_default };
    return invoke(RVA_WideCharToMultiByte, 8, args).low;
}

static void srw_and_ticks(void)
{
    uintptr_t lock = UINT32_MAX;
    struct call_result result;
    (void)call1(RVA_InitializeSRWLock, (uintptr_t)&lock);
    CHECK(lock == 0);
    (void)call1(RVA_AcquireSRWLockExclusive, (uintptr_t)&lock);
    CHECK((call1(RVA_TryAcquireSRWLockExclusive, (uintptr_t)&lock).low & 255u) == 0);
    CHECK((call1(RVA_TryAcquireSRWLockShared, (uintptr_t)&lock).low & 255u) == 0);
    (void)call1(RVA_ReleaseSRWLockExclusive, (uintptr_t)&lock);
    (void)call1(RVA_AcquireSRWLockShared, (uintptr_t)&lock);
    CHECK((call1(RVA_TryAcquireSRWLockShared, (uintptr_t)&lock).low & 255u) == 1);
    CHECK((call1(RVA_TryAcquireSRWLockExclusive, (uintptr_t)&lock).low & 255u) == 0);
    (void)call1(RVA_ReleaseSRWLockShared, (uintptr_t)&lock);
    CHECK((call1(RVA_TryAcquireSRWLockExclusive, (uintptr_t)&lock).low & 255u) == 0);
    (void)call1(RVA_ReleaseSRWLockShared, (uintptr_t)&lock);
    CHECK((call1(RVA_TryAcquireSRWLockExclusive, (uintptr_t)&lock).low & 255u) == 1);
    (void)call1(RVA_ReleaseSRWLockExclusive, (uintptr_t)&lock);
    CHECK(sleep_calls == 0); /* No host scheduler is masquerading as Win32. */
    result = call0(RVA_GetTickCount64);
    CHECK(result.low == UINT32_C(0xfffffff0) && result.high == 0);
    result = call0(RVA_GetTickCount64);
    CHECK(result.low == UINT32_C(0xfffffff5) && result.high == 0);
    result = call0(RVA_GetTickCount64);
    CHECK(result.low == 3 && result.high == 1);
    result = call0(RVA_GetTickCount64);
    CHECK(result.low == 19 && result.high == 1 && tick_calls == 4);
}

static uintptr_t *blocked_lock;
static uint32_t blocked_shared_owner;
static void release_owner_from_mock_sleep(void)
{
    (void)call1(blocked_shared_owner ? RVA_ReleaseSRWLockShared :
                RVA_ReleaseSRWLockExclusive, (uintptr_t)blocked_lock);
}
static void srw_waits(void)
{
    uintptr_t lock = 0;
    uint32_t owner_shared, waiter_shared;
    for (owner_shared = 0; owner_shared < 2; ++owner_shared) {
        for (waiter_shared = 0; waiter_shared < 2; ++waiter_shared) {
            uint32_t before = sleep_calls;
            if (owner_shared && waiter_shared) continue; /* No contention. */
            (void)call1(owner_shared ? RVA_AcquireSRWLockShared :
                        RVA_AcquireSRWLockExclusive, (uintptr_t)&lock);
            blocked_lock = &lock;
            blocked_shared_owner = owner_shared;
            sleep_completion = release_owner_from_mock_sleep;
            (void)call1(waiter_shared ? RVA_AcquireSRWLockShared :
                        RVA_AcquireSRWLockExclusive, (uintptr_t)&lock);
            CHECK(sleep_calls == before + 1 && sleep_completion == NULL);
            CHECK(lock == (waiter_shared ? 2u : 1u));
            (void)call1(waiter_shared ? RVA_ReleaseSRWLockShared :
                        RVA_ReleaseSRWLockExclusive, (uintptr_t)&lock);
            CHECK(lock == 0);
        }
    }
}

static void dynamic_routing(void)
{
    struct call_result result;
    static const char tick_name[] = "GetTickCount64";
    static const char native_name[] = "Sleep";
    static const char bad_case[] = "gettickcount64";
    static const char missing[] = "NoSuchSymbol";
    uint32_t calls = native_calls;
    clear_log();
    last_error = UINT32_C(0xabcd);
    /* Default mode Auto: a name Windows 98 lacks is probed natively first,
     * then answered by the own implementation; the failed probe's last error
     * does not leak into the successful lookup. */
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == ++calls);
    CHECK(native_last_module == KERNEL_HANDLE && native_last_name == tick_name);
    CHECK(last_error == UINT32_C(0xabcd));
    result = call0(result.low - PE_BASE);
    CHECK(result.low == 35 && result.high == 1);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"InitOnceExecuteOnce");
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce && native_calls == ++calls);
    /* Own-first entries in routes.json never touch the native loader. */
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"GetProcAddress");
    CHECK(result.low == PE_BASE + RVA_GetProcAddress && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"MultiByteToWideChar");
    CHECK(result.low == PE_BASE + RVA_MultiByteToWideChar && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"WideCharToMultiByte");
    CHECK(result.low == PE_BASE + RVA_WideCharToMultiByte && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)native_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK(native_last_module == KERNEL_HANDLE && native_last_name == native_name);
    CHECK(debug_messages == 0);   /* log=0: successful routes are silent */
    /* A case-different name is unknown everywhere: unresolved, with a
     * diagnostic naming module and function, and the loader's error code. */
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)bad_case);
    CHECK(result.low == 0 && native_calls == ++calls && last_error == 127);
    CHECK(log_contains("NTW32: KERNEL32.DLL!gettickcount64 unresolved (mode auto; native absent; own absent; kernelex not-detected)"));
    result = call2(RVA_GetProcAddress, OTHER_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK(native_last_module == OTHER_HANDLE && native_last_name == tick_name);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, 42);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK((uintptr_t)native_last_name == 42);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)missing);
    CHECK(result.low == 0 && native_calls == ++calls && last_error == 127);
    CHECK(log_contains("KERNEL32.DLL!NoSuchSymbol unresolved"));
}

static void reattach(void)
{
    clear_log();
    ++reattaches;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0).low == 1);
}
static void expect_own_srw(void)
{
    uintptr_t lock = UINT32_MAX;
    (void)call1(RVA_InitializeSRWLock, (uintptr_t)&lock);
    CHECK(lock == 0);
    CHECK((call1(RVA_TryAcquireSRWLockExclusive, (uintptr_t)&lock).low & 255u) == 1);
    (void)call1(RVA_ReleaseSRWLockExclusive, (uintptr_t)&lock);
    CHECK(lock == 0);
}

/* Every routing mode, exercised by re-attaching the actual DLL with mocked
 * NTW32.INI / NTW32_ROUTING contents and mocked KernelEx presence. */
static void routing_policy(void)
{
    static const char tick_name[] = "GetTickCount64";
    static const char once_name[] = "InitOnceExecuteOnce";
    static const char compare_name[] = "CompareStringW";
    static const char sleep_name[] = "Sleep";
    static char big_text[4098];   /* 4097 configuration bytes plus a terminator */
    static const uint8_t sample[] = { 'A', 0, 0xed, 0x95, 0x9c };
    struct call_result result;
    uint32_t calls, mb_before, i;
    uint16_t wide[8];
    for (i = 0; i + 1 < sizeof big_text; ++i) big_text[i] = (i % 64 == 63) ? '\n' : ';';
    big_text[sizeof big_text - 1] = 0;

    /* 1. Defaults: no file, no variable, no KernelEx. Nothing is logged, and
     *    a natively exported known stub is still used when nothing else can. */
    env_text = NULL; ini_text = NULL;
    reattach();
    CHECK(ini_opened == 0 && debug_messages == 0 && kex_probe_calls == 3 * (1 + reattaches));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)compare_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == calls + 1);
    CHECK(log_contains("NTW32: KERNEL32.DLL!CompareStringW -> known-stub provider used as last resort: native (mode auto)"));

    /* 2. The variable replaces the file: mode Own with tracing. */
    env_text = "[routing]|mode=own|log=1";
    reattach();
    CHECK(ini_opened == 0);
    CHECK(log_contains("NTW32: routing mode=own source=NTW32_ROUTING overrides=0 warnings=0 kernelex=not-detected"));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == calls);
    CHECK(log_contains("NTW32: KERNEL32.DLL!GetTickCount64 -> own (mode own)"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)sleep_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == calls + 1);
    CHECK(log_contains("NTW32: KERNEL32.DLL!Sleep -> native (mode own)"));

    /* 3. Own never accepts an answer attributed to a KernelEx API library. */
    kex_core_present = 1; kex_bases_present = 1; kex_hook_initonce = 1; kex_hook_sleep = 1;
    reattach();
    CHECK(log_contains("kernelex=active"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce);
    last_error = 0;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)sleep_name);
    CHECK(result.low == 0 && last_error == 127);
    CHECK(log_contains("NTW32: KERNEL32.DLL!Sleep unresolved (mode own; native result attributed to KernelEx and rejected; own absent; kernelex active)"));

    /* 4. Auto with KernelEx active: own beats a KernelEx-attributed pointer;
     *    KernelEx is the last resort for a name nobody else provides. */
    env_text = "[routing]|mode=auto|log=1";
    reattach();
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce);
    CHECK(log_contains("NTW32: KERNEL32.DLL!InitOnceExecuteOnce -> own (mode auto)"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)sleep_name);
    CHECK(result.low == (uintptr_t)kex_image + UINT32_C(0x1000));
    CHECK(log_contains("NTW32: KERNEL32.DLL!Sleep -> kernelex (mode auto)"));

    /* 5. KernelEx mode takes the KernelEx answer even for an owned name and
     *    forwards the already-bound static export to it (not called: the
     *    fake library is data). Names KernelEx lacks fall to native, then own. */
    env_text = "[routing]|mode=kernelex|log=1";
    reattach();
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == (uintptr_t)kex_image + UINT32_C(0x1000));
    CHECK(log_contains("NTW32: KERNEL32.DLL!InitOnceExecuteOnce -> kernelex (mode kernelex)"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64);
    CHECK(log_contains("NTW32: KERNEL32.DLL!GetTickCount64 -> own (mode kernelex)"));
    expect_own_srw();

    /* 6. KernelEx mode without KernelEx degrades to native, then own. */
    kex_core_present = 0; kex_bases_present = 0; kex_hook_initonce = 0; kex_hook_sleep = 0;
    reattach();
    CHECK(log_contains("kernelex=not-detected"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce);
    kex_core_present = 1;
    reattach();
    CHECK(log_contains("kernelex=core-only"));
    kex_core_present = 0;

    /* 7. Native mode: dynamic lookups pass through silently; a static export
     *    forwards to native when native has the name, and otherwise keeps
     *    the own implementation. */
    env_text = "[routing]|mode=native|log=1";
    reattach();
    CHECK(log_contains("NTW32: static export GetTickCount64 keeps the own implementation"));
    calls = native_calls;
    last_error = UINT32_C(0x5151);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == 0 && native_calls == calls + 1 && last_error == 127);
    CHECK(!log_contains("unresolved"));
    mb_before = native_mb_calls;
    native_conversion_result = 555;
    CHECK(convert_mb(65001, 0, sample, 5, wide, 8) == 555 && native_mb_calls == mb_before + 1);
    CHECK(native_mb_args[0] == 65001 && native_mb_args[2] == (uintptr_t)sample && native_mb_args[5] == 8);
    expect_own_srw();

    /* 8. NTW32.INI beside the DLL: process mode plus module and function
     *    overrides; a function override wins over a module override. */
    env_text = NULL;
    ini_text = "[routing]\r\nmode=own\r\nlog=1\r\n\r\n; overrides\r\n[modules]\r\n"
               "kernel32.dll = auto\r\n[functions]\r\nGetTickCount64=native\r\nSleep=own\r\n";
    for (ini_length = 0; ini_text[ini_length]; ++ini_length) { }
    reattach();
    CHECK(ini_opened == 1 && ini_closed == 1);
    CHECK(log_contains("NTW32: routing mode=own source=NTW32.INI overrides=3 warnings=0 kernelex=not-detected"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == 0 && !log_contains("GetTickCount64 unresolved"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)sleep_name);
    CHECK(result.low == (uintptr_t)&native_function);
    CHECK(log_contains("NTW32: KERNEL32.DLL!Sleep -> native (mode own)"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce);
    CHECK(log_contains("NTW32: KERNEL32.DLL!InitOnceExecuteOnce -> own (mode auto)"));

    /* 9. Malformed lines are reported one by one; Auto and defaults remain. */
    ini_text = "[routing]\r\nmode=turbo\r\nlog=1\r\nlog=yes\r\nbogus\r\n[weird]\r\nx=1\r\n"
               "[functions]\r\n9bad=own\r\nGetTickCount64=maybe\r\nGetTickCount64=own\r\n"
               "GetTickCount64=native\r\n[modules]\r\nKERNEL32.DLL=own\r\nkernel32.dll=native\r\n";
    for (ini_length = 0; ini_text[ini_length]; ++ini_length) { }
    reattach();
    CHECK(log_contains("NTW32: routing config line 2: unknown mode; Auto retained 'turbo'"));
    CHECK(log_contains("NTW32: routing config line 4: duplicate log ignored 'yes'"));
    CHECK(log_contains("NTW32: routing config line 5: expected key=value 'bogus'"));
    CHECK(log_contains("NTW32: routing config line 6: unknown section 'weird'"));
    CHECK(log_contains("NTW32: routing config line 7: key under unknown section ignored 'x'"));
    CHECK(log_contains("NTW32: routing config line 9: invalid function name '9bad'"));
    CHECK(log_contains("NTW32: routing config line 10: unknown mode 'maybe'"));
    CHECK(log_contains("NTW32: routing config line 12: duplicate override ignored 'GetTickCount64'"));
    CHECK(log_contains("NTW32: routing config line 15: duplicate override ignored 'kernel32.dll'"));
    CHECK(log_contains("NTW32: routing mode=auto source=NTW32.INI overrides=2 warnings=9 kernelex=not-detected"));

    /* 10. Oversized or non-ASCII configuration is ignored as a whole. */
    ini_text = big_text; ini_length = sizeof big_text - 1;
    reattach();
    CHECK(log_contains("NTW32: NTW32.INI longer than 4096 bytes; ignored"));
    ini_text = "[routing]\r\nmode=own\r\n\x80";
    for (ini_length = 0; ini_text[ini_length]; ++ini_length) { }
    reattach();
    CHECK(log_contains("NTW32: routing config: control or non-ASCII byte; configuration ignored"));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == calls + 1);
    ini_text = NULL;
    env_text = big_text;
    reattach();
    CHECK(log_contains("NTW32: NTW32_ROUTING longer than 4096 bytes; ignored"));

    /* 11. A loader answer inside NTW32.DLL itself never becomes a forward
     *     target; without this guard the export would recurse until the
     *     stack overflowed. */
    env_text = NULL; ini_text = NULL;
    native_self_alias = 1;
    reattach();
    CHECK(log_contains("NTW32: static export InitializeSRWLock resolved into NTW32.DLL itself; own implementation kept"));
    expect_own_srw();
    native_self_alias = 0;

    /* 12. A configured Auto order: [routing] order= for every name, an
     *     [order] entry for one name. KernelEx first, then own, then native. */
    kex_core_present = 1; kex_bases_present = 1; kex_hook_initonce = 1; kex_hook_sleep = 1;
    env_text = "[routing]|order=kernelex,own,native|log=1|[order]|InitOnceExecuteOnce=own,native";
    reattach();
    CHECK(log_contains("NTW32: routing mode=auto source=NTW32_ROUTING overrides=1 warnings=0 kernelex=active order=kernelex,own,native"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)sleep_name);
    CHECK(result.low == (uintptr_t)kex_image + UINT32_C(0x1000));
    CHECK(log_contains("NTW32: KERNEL32.DLL!Sleep -> kernelex (mode auto)"));
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)once_name);
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce);
    CHECK(log_contains("NTW32: KERNEL32.DLL!InitOnceExecuteOnce -> own (mode auto)"));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == calls + 1);
    CHECK(log_contains("NTW32: KERNEL32.DLL!GetTickCount64 -> own (mode auto)"));
    /* The configured order also replaces the own-first routes.json entry of
     * MultiByteToWideChar: KernelEx does not have it, own does. */
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"MultiByteToWideChar");
    CHECK(result.low == PE_BASE + RVA_MultiByteToWideChar);
    expect_own_srw();
    /* An order that leaves out own: a name only own provides is unresolved. */
    env_text = "[routing]|order=native,kernelex";
    reattach();
    CHECK(log_contains("NTW32: KERNEL32.DLL!InitializeSRWLock unresolved (mode auto; native absent; own not consulted; kernelex active)"));
    CHECK(log_contains("NTW32: static export InitializeSRWLock keeps the own implementation"));
    clear_log();
    last_error = 0;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == 0 && last_error == 127);
    CHECK(log_contains("NTW32: KERNEL32.DLL!GetTickCount64 unresolved (mode auto; native absent; own not consulted; kernelex active)"));
    expect_own_srw();   /* static exports keep the own implementation */
    kex_core_present = 0; kex_bases_present = 0; kex_hook_initonce = 0; kex_hook_sleep = 0;

    /* 13. Malformed orders and entries that cannot take effect are reported;
     *     the defaults for those items remain. */
    env_text = "[routing]|mode=own|order=native|log=1|[modules]|USER32.DLL=native|"
               "[order]|Bogus-Name=own|Sleep=auto|Sleep=own,own";
    reattach();
    CHECK(log_contains("NTW32: routing config line 8: invalid function name 'Bogus-Name'"));
    CHECK(log_contains("NTW32: routing config line 9: invalid provider order 'auto'"));
    CHECK(log_contains("NTW32: routing config line 10: invalid provider order 'own,own'"));
    CHECK(log_contains("NTW32: routing config: [modules] USER32.DLL is not routed by this provider; entry has no effect"));
    CHECK(log_contains("NTW32: routing config: [routing] order has no effect: no name is routed in mode auto; the mode is own"));
    CHECK(log_contains("NTW32: routing mode=own source=NTW32_ROUTING overrides=1 warnings=5 kernelex=not-detected order=native"));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == calls);
    env_text = "[routing]|order=turbo";
    reattach();
    CHECK(log_contains("NTW32: routing config line 2: invalid provider order; routes.json order retained 'turbo'"));
    calls = native_calls;
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"MultiByteToWideChar");
    CHECK(result.low == PE_BASE + RVA_MultiByteToWideChar && native_calls == calls);   /* routes.json: own first */

    /* Back to the defaults for the remaining checks. */
    env_text = NULL;
    reattach();
    CHECK(debug_messages == 0);
}

static uint32_t payload[4] = { 10, 20, 30, 40 };
struct callback_plan {
    uintptr_t *expected_once;
    void **expected_context;
    void *publish;
    uint32_t calls;
    int success;
};

static int STDCALL init_callback(uintptr_t *once, void *parameter, void **context)
{
    struct callback_plan *plan = (struct callback_plan *)parameter;
    CHECK(once == plan->expected_once && context == plan->expected_context);
    ++plan->calls;
    if (context != NULL) *context = plan->publish;
    if (!plan->success) mock_SetLastError(UINT32_C(0x10293847));
    return plan->success;
}

static void once_callbacks(void)
{
    uintptr_t once = UINT32_MAX;
    void *context = NULL;
    struct callback_plan plan = { &once, &context, payload, 0, 0 };
    struct call_result result;
    (void)call1(RVA_InitOnceInitialize, (uintptr_t)&once);
    CHECK(once == 0);
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, (uintptr_t)&context);
    CHECK(result.low == 0 && plan.calls == 1 && last_error == UINT32_C(0x10293847));
    CHECK(context == payload && once == 0);
    plan.success = 1;
    last_error = UINT32_C(0xabcd);
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, (uintptr_t)&context);
    CHECK(result.low == 1 && plan.calls == 2 && context == payload);
    CHECK(last_error == UINT32_C(0xabcd));
    context = NULL;
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, (uintptr_t)&context);
    CHECK(result.low == 1 && plan.calls == 2 && context == payload);
    (void)call1(RVA_InitOnceInitialize, (uintptr_t)&once);
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, 0, 0, (uintptr_t)&context);
    CHECK(result.low == 0 && last_error == 87 && once == 0);
    plan.publish = (void *)((uintptr_t)payload + 1);
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, (uintptr_t)&context);
    CHECK(result.low == 0 && last_error == 87 && once == 0 && plan.calls == 3);
    plan.publish = payload;
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, (uintptr_t)&context);
    CHECK(result.low == 1 && context == payload && plan.calls == 4);
    (void)call1(RVA_InitOnceInitialize, (uintptr_t)&once);
    plan.expected_context = NULL;
    result = call4(RVA_InitOnceExecuteOnce, (uintptr_t)&once, (uintptr_t)&init_callback,
                    (uintptr_t)&plan, 0);
    CHECK(result.low == 1 && plan.calls == 5);
    context = (void *)(uintptr_t)0x1000;
    {
        int pending = 73;
        result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 1,
                        (uintptr_t)&pending, (uintptr_t)&context);
        CHECK(result.low == 1 && pending == 0 && context == NULL);
    }
}

static uintptr_t *yielded_once;
static void complete_from_mock_sleep(void)
{
    CHECK(call3(RVA_InitOnceComplete, (uintptr_t)yielded_once, 0,
                 (uintptr_t)payload).low == 1);
}

static void once_explicit(void)
{
    uintptr_t once = 0;
    int pending = 73;
    void *context = (void *)(uintptr_t)0x1000;
    struct call_result result;
    uint32_t before_sleep = sleep_calls;
    last_error = 0;
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 1,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 0 && pending == 73 && context == (void *)(uintptr_t)0x1000);
    CHECK(last_error == 31 && once == 0);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 8,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 0 && last_error == 87 && pending == 73 && once == 0);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 0,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 1 && context == (void *)(uintptr_t)0x1000);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 0, (uintptr_t)payload + 1);
    CHECK(result.low == 0 && last_error == 87);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 4, 0);
    CHECK(result.low == 1 && once == 0);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 0,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 1);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 0, (uintptr_t)payload);
    CHECK(result.low == 1);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 0,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 0 && context == payload);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 0, (uintptr_t)payload);
    CHECK(result.low == 0 && last_error == 31);
    (void)call1(RVA_InitOnceInitialize, (uintptr_t)&once);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 2,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 1);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 2,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 1);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 6, 0);
    CHECK(result.low == 0 && last_error == 87);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 2, (uintptr_t)payload);
    CHECK(result.low == 1);
    result = call3(RVA_InitOnceComplete, (uintptr_t)&once, 2, (uintptr_t)(payload + 1));
    CHECK(result.low == 0 && last_error == 31);
    context = NULL;
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 1,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 0 && context == payload);
    (void)call1(RVA_InitOnceInitialize, (uintptr_t)&once);
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 0,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 1);
    /* A deterministic service mock completes the existing attempt while the
     * second begin yields. This checks Sleep's imported stdcall path, not
     * real Windows scheduling or thread concurrency. */
    yielded_once = &once;
    sleep_completion = complete_from_mock_sleep;
    result = call4(RVA_InitOnceBeginInitialize, (uintptr_t)&once, 0,
                    (uintptr_t)&pending, (uintptr_t)&context);
    CHECK(result.low == 1 && pending == 0 && context == payload);
    CHECK(sleep_calls == before_sleep + 1 && sleep_completion == NULL);
}

static int same_bytes(const void *left, const void *right, uint32_t size)
{
    const uint8_t *a = left, *b = right;
    uint32_t i;
    for (i = 0; i < size; ++i) if (a[i] != b[i]) return 0;
    return 1;
}
static void fill_bytes(void *buffer, uint32_t size)
{
    uint8_t *bytes = buffer;
    uint32_t i;
    for (i = 0; i < size; ++i) bytes[i] = 0xa5;
}
static int untouched(const void *buffer, uint32_t size)
{
    const uint8_t *bytes = buffer;
    uint32_t i;
    for (i = 0; i < size; ++i) if (bytes[i] != 0xa5) return 0;
    return 1;
}

static void utf_conversion(void)
{
    static const uint8_t utf8[] = { 'A', 0, 0xed, 0x95, 0x9c, 0xf0, 0x9f, 0x98, 0x80 };
    static const uint16_t utf16[] = { 'A', 0, 0xd55c, 0xd83d, 0xde00 };
    static const uint8_t terminated[] = { 0xed, 0x95, 0x9c, 0xf0, 0x9f, 0x98, 0x80, 0 };
    static const uint16_t terminated_wide[] = { 0xd55c, 0xd83d, 0xde00, 0 };
    static const uint8_t malformed[] = { 0xe1, 0x80, 'A' };
    static const uint8_t surrogate_utf8[] = { 0xed, 0xa0, 0x80 };
    static const uint16_t malformed_wide[] = { 0xd800, 'A' };
    static const uint8_t replacement[] = { 0xef, 0xbf, 0xbd, 'A' };
    static const uint16_t empty[] = { 0 };
    uint16_t wide[16];
    uint8_t bytes[32];
    uint32_t used = 0x1234;
    fill_bytes(wide, sizeof(wide)); fill_bytes(bytes, sizeof(bytes));
    last_error = 0x1357;
    CHECK(convert_mb(65001, 8, utf8, 9, NULL, 0) == 5 && last_error == 0x1357);
    CHECK(convert_wc(65001, 128, utf16, 5, NULL, 0, NULL, NULL) == 9 && last_error == 0x1357);
    /* A zero output capacity ignores unrelated destination pointer values. */
    CHECK(convert_mb(65001, 0, utf8, 9, (void *)(uintptr_t)1, 0) == 5);
    CHECK(convert_wc(65001, 0, utf16, 5, (void *)(uintptr_t)1, 0, NULL, NULL) == 9);
    CHECK(convert_mb(65001, 8, utf8, 9, wide, 5) == 5);
    CHECK(same_bytes(wide, utf16, sizeof(utf16)) && wide[5] == 0xa5a5);
    CHECK(convert_wc(65001, 128, wide, 5, bytes, 9, NULL, NULL) == 9);
    CHECK(same_bytes(bytes, utf8, sizeof(utf8)) && bytes[9] == 0xa5);
    CHECK(last_error == 0x1357);
    CHECK(convert_mb(65001, 0, terminated, -1, NULL, 0) == 4);
    CHECK(convert_mb(65001, 0, terminated, -1, wide, 16) == 4);
    CHECK(same_bytes(wide, terminated_wide, sizeof(terminated_wide)));
    CHECK(convert_wc(65001, 0, terminated_wide, -1, NULL, 0, NULL, NULL) == 8);
    CHECK(convert_wc(65001, 0, terminated_wide, -1, bytes, 32, NULL, NULL) == 8);
    CHECK(same_bytes(bytes, terminated, sizeof(terminated)));
    CHECK(convert_mb(65001, 0, "", -1, wide, 16) == 1 && wide[0] == 0);
    CHECK(convert_wc(65001, 0, empty, -1, bytes, 32, NULL, NULL) == 1 && bytes[0] == 0);
    fill_bytes(wide, sizeof(wide)); fill_bytes(bytes, sizeof(bytes));
    CHECK(convert_mb(65001, 8, malformed, 3, wide, 16) == 0 && last_error == 1113);
    CHECK(untouched(wide, sizeof(wide)));
    CHECK(convert_mb(65001, 8, malformed, 3, NULL, 0) == 0 && last_error == 1113);
    CHECK(convert_wc(65001, 128, malformed_wide, 2, bytes, 32, NULL, NULL) == 0 && last_error == 1113);
    CHECK(untouched(bytes, sizeof(bytes)));
    CHECK(convert_wc(65001, 128, malformed_wide, 2, NULL, 0, NULL, NULL) == 0 && last_error == 1113);
    CHECK(convert_mb(65001, 0, malformed, 3, wide, 16) == 2);
    CHECK(wide[0] == 0xfffd && wide[1] == 'A' && wide[2] == 0xa5a5);
    CHECK(convert_mb(65001, 0, surrogate_utf8, 3, wide, 16) == 3);
    CHECK(wide[0] == 0xfffd && wide[1] == 0xfffd && wide[2] == 0xfffd);
    CHECK(convert_wc(65001, 0, malformed_wide, 2, bytes, 32, NULL, NULL) == 4);
    CHECK(same_bytes(bytes, replacement, 4) && bytes[4] == 0xa5);
    fill_bytes(wide, sizeof(wide)); fill_bytes(bytes, sizeof(bytes));
    CHECK(convert_mb(65001, 0, utf8, 9, wide, 4) == 0 && last_error == 122);
    CHECK(untouched(wide, sizeof(wide)));
    CHECK(convert_wc(65001, 0, utf16, 5, bytes, 8, NULL, NULL) == 0 && last_error == 122);
    CHECK(untouched(bytes, sizeof(bytes)));
    CHECK(convert_mb(65001, 1, utf8, 9, wide, 16) == 0 && last_error == 1004);
    CHECK(convert_mb(65001, 128, utf8, 9, wide, 16) == 0 && last_error == 1004);
    CHECK(convert_wc(65001, 8, utf16, 5, bytes, 32, NULL, NULL) == 0 && last_error == 1004);
    CHECK(convert_wc(65001, 129, utf16, 5, bytes, 32, NULL, NULL) == 0 && last_error == 1004);
    CHECK(convert_wc(65001, 0, utf16, 5, bytes, 32, "?", NULL) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, utf16, 5, bytes, 32, NULL, &used) == 0 && last_error == 87);
    CHECK(used == 0x1234 && untouched(bytes, sizeof(bytes)) && untouched(wide, sizeof(wide)));
    CHECK(convert_mb(65001, 0, NULL, 1, wide, 16) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, NULL, 1, bytes, 32, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, 0, wide, 16) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, -2, wide, 16) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, utf16, 0, bytes, 32, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, utf16, -2, bytes, 32, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, 9, wide, -1) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, utf16, 5, bytes, -1, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, 9, NULL, 1) == 0 && last_error == 122);
    CHECK(convert_wc(65001, 0, utf16, 5, NULL, 1, NULL, NULL) == 0 && last_error == 122);
    CHECK(convert_mb(65001, 0, wide, 1, wide, 0) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, wide, 1, wide, 0, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, wide, 4, wide + 1, 2) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, wide, 4, wide + 1, 2, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, 9, (uint8_t *)wide + 1, 5) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, (const uint8_t *)utf16 + 1, 1, bytes, 32, NULL, NULL) == 0 && last_error == 87);
    CHECK(untouched(wide, sizeof(wide)) && untouched(bytes, sizeof(bytes)));
    /* Wrapping extents are rejected before these deliberately unmapped values
     * could be read. Actual accessible-memory validation is caller-owned. */
    CHECK(convert_mb(65001, 0, (const void *)(uintptr_t)UINT32_MAX, 2, NULL, 0) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, (const void *)(uintptr_t)0xfffffffe, 2, NULL, 0, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, (const void *)(uintptr_t)UINT32_MAX, -1, NULL, 0) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, (const void *)(uintptr_t)0xfffffffe, -1, NULL, 0, NULL, NULL) == 0 && last_error == 87);
    CHECK(convert_mb(65001, 0, utf8, 9, (void *)(uintptr_t)0xfffffffe, 2) == 0 && last_error == 87);
    CHECK(convert_wc(65001, 0, utf16, 5, (void *)(uintptr_t)UINT32_MAX, 1, NULL, NULL) == 0 && last_error == 87);
    CHECK(native_mb_calls == 0 && native_wc_calls == 0);
}

static void utf_long_and_native(void)
{
    static uint8_t bytes[131073];
    static uint16_t wide[131073];
    static const uint32_t pages[] = { 0, 1, 1252, 65000, 999999 };
    uint32_t i, j;
    for (i = 0; i < sizeof(bytes) - 1; ++i) bytes[i] = 'a';
    CHECK(convert_mb(65001, 8, bytes, -1, NULL, 0) == sizeof(bytes));
    CHECK(convert_mb(65001, 8, bytes, -1, wide, 131073) == sizeof(bytes));
    CHECK(wide[0] == 'a' && wide[131071] == 'a' && wide[131072] == 0);
    CHECK(convert_wc(65001, 128, wide, -1, NULL, 0, NULL, NULL) == sizeof(bytes));
    fill_bytes(bytes, sizeof(bytes));
    CHECK(convert_wc(65001, 128, wide, -1, bytes, 131073, NULL, NULL) == sizeof(bytes));
    CHECK(bytes[0] == 'a' && bytes[131071] == 'a' && bytes[131072] == 0);
    CHECK(native_mb_calls == 0 && native_wc_calls == 0);
    for (i = 0; i < sizeof(pages) / sizeof(pages[0]); ++i) {
        uint32_t expected_mb[] = { pages[i], UINT32_MAX, 0, (uint32_t)-2, 0, (uint32_t)-7 };
        uint32_t expected_wc[] = { pages[i], UINT32_MAX, 0, (uint32_t)-2, 0, (uint32_t)-7, 1, 2 };
        native_conversion_result = 713;
        last_error = 0x4242;
        CHECK(convert_mb(pages[i], UINT32_MAX, NULL, -2, NULL, -7) == 713 && last_error == 0x4242);
        CHECK(convert_wc(pages[i], UINT32_MAX, NULL, -2, NULL, -7,
                           (const void *)(uintptr_t)1, (void *)(uintptr_t)2) == 713 && last_error == 0x4242);
        for (j = 0; j < 6; ++j) CHECK(native_mb_args[j] == expected_mb[j]);
        for (j = 0; j < 8; ++j) CHECK(native_wc_args[j] == expected_wc[j]);
        CHECK(native_mb_calls == i * 2 + 1 && native_wc_calls == i * 2 + 1);
        native_conversion_result = 0; native_conversion_error = 0x7878;
        CHECK(convert_mb(pages[i], 0, bytes, 1, wide, 1) == 0 && last_error == 0x7878);
        CHECK(convert_wc(pages[i], 0, wide, 1, bytes, 1, NULL, NULL) == 0 && last_error == 0x7878);
    }
}

int harness_main(void)
{
    patch_imports();
    build_kex_image();
    module_available = 0;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0).low == 0);
    CHECK(module_calls == 1 && kex_probe_calls == 0);
    module_available = 1;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0).low == 1);
    CHECK(module_calls == 2 && kex_probe_calls == 3 && ini_opened == 0 && debug_messages == 0);
    srw_and_ticks();
    srw_waits();
    dynamic_routing();
    once_callbacks();
    once_explicit();
    utf_conversion();
    utf_long_and_native();
    routing_policy();
    CHECK(call3(PE_ENTRY, PE_BASE, 0, 0).low == 1);
    CHECK(module_calls == 2 + reattaches);
    write_string("PASS NTW32 actual PE32 ABI: ");
    write_number(checks); write_string(" checks; "); write_number(export_calls);
    write_string(" PE calls with verified ESP; Windows services mocked.\n");
    return 0;
}
