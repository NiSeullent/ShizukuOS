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
static uintptr_t native_last_module;
static const char *native_last_name;
static void (*sleep_completion)(void);

static void STDCALL mock_SetLastError(uint32_t error) { last_error = error; }
static void STDCALL mock_Sleep(uint32_t milliseconds)
{
    void (*complete)(void) = sleep_completion;
    CHECK(milliseconds == 0);
    ++sleep_calls;
    CHECK(complete != NULL);
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
    CHECK(sleep_calls == 1 && sleep_completion == NULL);
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
    dynamic_routing();
    once_callbacks();
    once_explicit();
    CHECK(call3(PE_ENTRY, PE_BASE, 0, 0).low == 1);
    CHECK(module_calls == 2);
    write_string("PASS NTW32 actual PE32 ABI: ");
    write_number(checks); write_string(" checks; "); write_number(export_calls);
    write_string(" PE calls with verified ESP; Windows services mocked.\n");
    return 0;
}
