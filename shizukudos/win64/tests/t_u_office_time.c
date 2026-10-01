/* SPDX-License-Identifier: GPL-2.0-only
 * Real UCRT time API-set, allocation ownership and snapshot-aware formatting.
 */
#include "k32test.h"
#define OFFICE_CALL __cdecl
#define OFFICE_CHECK(c, label) CHECK(c, label)
#include "office_time_contract.h"
typedef crt_inv_handler (__cdecl *set_invalid_fn)(crt_inv_handler);
static unsigned invalid_calls;
static void __cdecl invalid_parameter(const wchar16 *a, const wchar16 *b, const wchar16 *c, unsigned d, uintptr_t e)
{ (void)a; (void)b; (void)c; (void)d; (void)e; ++invalid_calls; }

int main(void)
{
    HMODULE module = LoadLibraryW(L"api-ms-win-crt-time-l1-1-0.dll");
    struct office_time_api api;
    set_invalid_fn set_handler;
    crt_inv_handler previous;
    CHECK(module != 0, "load actual UCRT time API-set");
    if (!module) return 1;
    api.days = (void *)GetProcAddress(module, "_Getdays");
    api.months = (void *)GetProcAddress(module, "_Getmonths");
    api.wdays = (void *)GetProcAddress(module, "_W_Getdays");
    api.wmonths = (void *)GetProcAddress(module, "_W_Getmonths");
    api.names = (void *)GetProcAddress(module, "_Gettnames");
    api.wnames = (void *)GetProcAddress(module, "_W_Gettnames");
    api.format = (void *)GetProcAddress(module, "_Strftime");
    api.wformat = (void *)GetProcAddress(module, "_Wcsftime");
    api.release = (void *)GetProcAddress(module, "free");
    api.error = (void *)GetProcAddress(module, "_errno");
    set_handler = (set_invalid_fn)GetProcAddress(module, "_set_invalid_parameter_handler");
    CHECK(api.days && api.months && api.wdays && api.wmonths && api.names && api.wnames && api.format && api.wformat,
          "all eight actual publisher time imports resolve");
    CHECK(api.release && api.error && set_handler, "actual CRT ownership and error APIs resolve");
    if (!api.days || !api.months || !api.wdays || !api.wmonths || !api.names || !api.wnames || !api.format || !api.wformat ||
        !api.release || !api.error || !set_handler) { FreeLibrary(module); return 1; }
    previous = set_handler(invalid_parameter);
    office_time_contract(&api);
    CHECK(invalid_calls == 2, "each invalid weekday/directive reaches the actual CRT callback exactly once");
    set_handler(previous);
    CHECK(FreeLibrary(module), "release actual time API-set reference");
    return k32t_finish("T_U_OFFICE_TIME");
}
