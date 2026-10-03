/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine Windows 98 backend and stdcall Vista locale-name entry points.
 * Imports only Windows 98 SE KERNEL32 exports (gated by build.py against
 * benchmarks/win98se-ko-oem-native-exports-v1.json). Results come from the
 * running system's installed NLS data; failures set the Win32 last error.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "office_nls.h"

/* EnumSystemLocalesA has no context argument: one bounded collection runs at
 * a time under an InterlockedExchange spin lock owned by this module. */
static volatile LONG enum_lock;
static uint32_t *enum_out;
static uint32_t enum_max, enum_count;
static int enum_overflow;

static uint32_t parse_hex_lcid(const char *s, uint32_t *v)
{
    uint32_t value = 0, n = 0;
    for (; *s; ++s, ++n) {
        char c = *s;
        uint32_t d;
        if (c >= '0' && c <= '9') d = (uint32_t)(c - '0');
        else if (c >= 'a' && c <= 'f') d = (uint32_t)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') d = (uint32_t)(c - 'A' + 10);
        else return 0;
        if (n >= 8) return 0;
        value = (value << 4) | d;
    }
    *v = value;
    return n != 0;
}

static BOOL CALLBACK collect_locale(LPSTR text)
{
    uint32_t lcid;
    if (!text || !parse_hex_lcid(text, &lcid)) return TRUE;   /* not an LCID: skip */
    if (enum_count >= enum_max) { enum_overflow = 1; return FALSE; }
    enum_out[enum_count++] = lcid;
    return TRUE;
}

static uint32_t w98_enumerate(void *ctx, uint32_t *lcids, uint32_t max)
{
    uint32_t count;
    BOOL ok;
    (void)ctx;
    while (InterlockedExchange((LONG *)&enum_lock, 1)) Sleep(0);
    enum_out = lcids; enum_max = max; enum_count = 0; enum_overflow = 0;
    ok = EnumSystemLocalesA(collect_locale, LCID_INSTALLED);
    count = (!ok || enum_overflow) ? (uint32_t)-1 : enum_count;
    enum_out = 0;
    InterlockedExchange((LONG *)&enum_lock, 0);
    return count;
}

static int w98_query(void *ctx, uint32_t lcid, uint32_t lctype, char *out, int cch)
{
    int r;
    (void)ctx;
    r = GetLocaleInfoA((LCID)lcid, (LCTYPE)lctype, out, cch);
    if (r > 0) return r;
    r = (int)GetLastError();
    return r > 0 ? -r : 0;
}

static uint32_t w98_user(void *ctx) { (void)ctx; return (uint32_t)GetUserDefaultLCID(); }
static uint32_t w98_system(void *ctx) { (void)ctx; return (uint32_t)GetSystemDefaultLCID(); }

static int w98_wide(void *ctx, uint32_t codepage, const char *in, int bytes, uint16_t *out, int cch)
{
    int r;
    (void)ctx;
    r = MultiByteToWideChar((UINT)codepage, 0, in, bytes, (LPWSTR)out, cch);
    if (r > 0) return r;
    r = (int)GetLastError();
    return r > 0 ? -r : 0;
}

static const struct ofn_backend win98_backend = {
    0, w98_query, w98_enumerate, w98_user, w98_system, w98_wide
};

static int finish(uint32_t err, uint32_t result)
{
    if (err) { SetLastError(err); return 0; }
    return (int)result;
}

int WINAPI OfnGetUserDefaultLocaleName(LPWSTR out, int cch)
{
    uint32_t result = 0;
    if (cch < 0) return finish(OFN_ERROR_INVALID_PARAMETER, 0);
    return finish(ofn_user_default_locale_name(&win98_backend, (uint16_t *)out, (uint32_t)cch, &result), result);
}

int WINAPI OfnGetLocaleInfoEx(LPCWSTR name, LCTYPE type, LPWSTR out, int cch)
{
    uint32_t result = 0;
    if (cch < 0) return finish(OFN_ERROR_INVALID_PARAMETER, 0);
    return finish(ofn_get_locale_info_ex(&win98_backend, (const uint16_t *)name, (uint32_t)type,
                                         (uint16_t *)out, (uint32_t)cch, &result), result);
}

int WINAPI OfnResolveLocaleName(LPCWSTR name, LPWSTR out, int cch)
{
    uint32_t result = 0;
    if (cch < 0) return finish(OFN_ERROR_INVALID_PARAMETER, 0);
    return finish(ofn_resolve_locale_name(&win98_backend, (const uint16_t *)name, (uint16_t *)out, (uint32_t)cch, &result), result);
}

LCID WINAPI OfnLocaleNameToLCID(LPCWSTR name, DWORD flags)
{
    uint32_t lcid = 0, err;
    if (flags & ~(DWORD)0x08000000u) { SetLastError(OFN_ERROR_INVALID_FLAGS); return 0; }  /* LOCALE_ALLOW_NEUTRAL_NAMES */
    err = ofn_name_to_lcid(&win98_backend, (const uint16_t *)name, &lcid);
    if (err) { SetLastError(err); return 0; }
    return (LCID)lcid;
}

int WINAPI OfnLCIDToLocaleName(LCID lcid, LPWSTR out, int cch, DWORD flags)
{
    uint32_t result = 0;
    if (cch < 0 || (flags & ~(DWORD)0x08000000u)) return finish(cch < 0 ? OFN_ERROR_INVALID_PARAMETER : OFN_ERROR_INVALID_FLAGS, 0);
    if (lcid == LOCALE_USER_DEFAULT || lcid == 0) lcid = GetUserDefaultLCID();
    else if (lcid == LOCALE_SYSTEM_DEFAULT) lcid = GetSystemDefaultLCID();
    return finish(ofn_lcid_to_name(&win98_backend, (uint32_t)lcid, (uint16_t *)out, (uint32_t)cch, &result), result);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
