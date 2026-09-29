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

static void STDCALL mock_SetLastError(uint32_t error) { last_error = error; }
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
    CHECK(equal(name, "KERNEL32.DLL"));
    ++module_calls;
    return module_available ? KERNEL_HANDLE : 0;
}
static uint32_t STDCALL native_function(void) { return UINT32_C(0xcafe1234); }
static uintptr_t STDCALL mock_GetProcAddress(uintptr_t module, const char *name)
{
    ++native_calls;
    native_last_module = module;
    native_last_name = name;
    if ((uintptr_t)name > UINT32_C(0xffff) && equal(name, "NoSuchSymbol")) {
        mock_SetLastError(127);
        return 0;
    }
    return (uintptr_t)&native_function;
}

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

/* The WIN64 subsystem client's transport imports. This harness never calls those exports (w64_harness.c
 * does, against the VxD bridge and the Kernel64 model); reaching one of these mocks here is a failure. */
static uintptr_t STDCALL mock_CreateFileA(const char *name, uint32_t access, uint32_t share, void *security,
    uint32_t disposition, uint32_t flags, uintptr_t template_file)
{
    (void)name; (void)access; (void)share; (void)security; (void)disposition; (void)flags; (void)template_file;
    fail("unexpected CreateFileA", __LINE__);
}
static uint32_t STDCALL mock_DeviceIoControl(uintptr_t device, uint32_t code, void *input, uint32_t input_bytes,
    void *output, uint32_t output_bytes, uint32_t *returned, void *overlapped)
{
    (void)device; (void)code; (void)input; (void)input_bytes; (void)output; (void)output_bytes;
    (void)returned; (void)overlapped;
    fail("unexpected DeviceIoControl", __LINE__);
}
static uint32_t STDCALL mock_GetLastError(void) { fail("unexpected GetLastError", __LINE__); }

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
    last_error = UINT32_C(0xabcd);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == PE_BASE + RVA_GetTickCount64 && native_calls == calls);
    CHECK(last_error == UINT32_C(0xabcd));
    result = call0(result.low - PE_BASE);
    CHECK(result.low == 35 && result.high == 1);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"InitOnceExecuteOnce");
    CHECK(result.low == PE_BASE + RVA_InitOnceExecuteOnce && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"GetProcAddress");
    CHECK(result.low == PE_BASE + RVA_GetProcAddress);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"MultiByteToWideChar");
    CHECK(result.low == PE_BASE + RVA_MultiByteToWideChar && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)"WideCharToMultiByte");
    CHECK(result.low == PE_BASE + RVA_WideCharToMultiByte && native_calls == calls);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)native_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK(native_last_module == KERNEL_HANDLE && native_last_name == native_name);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)bad_case);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    result = call2(RVA_GetProcAddress, OTHER_HANDLE, (uintptr_t)tick_name);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK(native_last_module == OTHER_HANDLE && native_last_name == tick_name);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, 42);
    CHECK(result.low == (uintptr_t)&native_function && native_calls == ++calls);
    CHECK((uintptr_t)native_last_name == 42);
    result = call2(RVA_GetProcAddress, KERNEL_HANDLE, (uintptr_t)missing);
    CHECK(result.low == 0 && native_calls == ++calls && last_error == 127);
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
    module_available = 0;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0).low == 0);
    CHECK(module_calls == 1);
    module_available = 1;
    CHECK(call3(PE_ENTRY, PE_BASE, 1, 0).low == 1);
    CHECK(module_calls == 2);
    srw_and_ticks();
    srw_waits();
    dynamic_routing();
    once_callbacks();
    once_explicit();
    utf_conversion();
    utf_long_and_native();
    CHECK(call3(PE_ENTRY, PE_BASE, 0, 0).low == 1);
    CHECK(module_calls == 2);
    write_string("PASS NTW32 actual PE32 ABI: ");
    write_number(checks); write_string(" checks; "); write_number(export_calls);
    write_string(" PE calls with verified ESP; Windows services mocked.\n");
    return 0;
}
