/* SPDX-License-Identifier: GPL-2.0-only
 * Original, private ANSI-to-Unicode transport for the shared Win98 adapter.
 * No USER32 export is supplied; no character-dependent message forwarding.
 * The consumer's actual W API performs properties, messages, text and metrics.
 */
#ifdef M98_THEME_TRANSPORT_HOST_TEST
#include "transport_host_types.h"
#else
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#endif
#define M98_THEME_TRANSPORT_IMPLEMENTATION
#include "transport.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

_Static_assert(sizeof(WCHAR) == 2, "Windows UTF-16 code units required");
_Static_assert(sizeof(LOGFONTA) == 60 && sizeof(LOGFONTW) == 92, "Windows font ABI required");
_Static_assert(offsetof(LOGFONTA, lfFaceName) == offsetof(LOGFONTW, lfFaceName), "font numeric prefix mismatch");
_Static_assert(sizeof(NONCLIENTMETRICSA) == 344 && sizeof(NONCLIENTMETRICSW) == 504, "Vista metrics ABI required");

static BOOL private_key(LPCSTR key, WCHAR wide[64])
{
    unsigned i;
    if (!key || (uintptr_t)key < 0x10000u) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    for (i = 0; i < 64; ++i) {
        unsigned char c = (unsigned char)key[i];
        if (c > 127u) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
        wide[i] = c;
        if (!c) {
            if (i) return TRUE;
            SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
        }
    }
    SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
}

HANDLE WINAPI m98w_GetPropA(HWND window, LPCSTR key)
{ WCHAR wide[64]; return private_key(key, wide) ? GetPropW(window, wide) : NULL; }
BOOL WINAPI m98w_SetPropA(HWND window, LPCSTR key, HANDLE value)
{ WCHAR wide[64]; return private_key(key, wide) ? SetPropW(window, wide, value) : FALSE; }
HANDLE WINAPI m98w_RemovePropA(HWND window, LPCSTR key)
{ WCHAR wide[64]; return private_key(key, wide) ? RemovePropW(window, wide) : NULL; }

LRESULT WINAPI m98w_SendMessageA(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    /* The shared adapter sends only this numeric, payload-free message. */
    if (message != WM_THEMECHANGED || wparam || lparam) {
        SetLastError(ERROR_NOT_SUPPORTED); return 0;
    }
    return SendMessageW(window, message, wparam, lparam);
}

static BOOL font_to_ansi(const LOGFONTW *wide, LOGFONTA *out)
{
    LOGFONTA ansi;
    WCHAR roundtrip[LF_FACESIZE];
    BOOL substituted = FALSE;
    unsigned count;
    int bytes, chars;
    for (count = 0; count < LF_FACESIZE && wide->lfFaceName[count]; ++count) { }
    if (count == LF_FACESIZE) { SetLastError(ERROR_INVALID_DATA); return FALSE; }
    memset(&ansi, 0, sizeof(ansi));
    memcpy(&ansi, wide, offsetof(LOGFONTA, lfFaceName));
    bytes = WideCharToMultiByte(CP_ACP, 0, wide->lfFaceName, (int)count + 1,
                               ansi.lfFaceName, LF_FACESIZE, NULL, &substituted);
    if (!bytes) return FALSE;
    if (substituted) { SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE; }
    chars = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, ansi.lfFaceName, bytes,
                                roundtrip, LF_FACESIZE);
    if (!chars) return FALSE;
    if ((unsigned)chars != count + 1u || memcmp(roundtrip, wide->lfFaceName, (count + 1u) * sizeof(WCHAR))) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION); return FALSE;
    }
    *out = ansi;
    return TRUE;
}

BOOL WINAPI m98w_SystemParametersInfoA(UINT action, UINT parameter, PVOID storage, UINT flags)
{
    if (!storage || flags) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (action == SPI_GETNONCLIENTMETRICS) {
        NONCLIENTMETRICSW wide;
        NONCLIENTMETRICSA ansi;
        UINT requested = ((NONCLIENTMETRICSA *)storage)->cbSize;
        const UINT legacy = (UINT)offsetof(NONCLIENTMETRICSA, iPaddedBorderWidth);
        if ((requested != legacy && requested != sizeof(ansi)) || parameter != requested) {
            SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
        }
        memset(&wide, 0, sizeof(wide)); wide.cbSize = sizeof(wide);
        if (!SystemParametersInfoW(action, sizeof(wide), &wide, 0)) return FALSE;
        memset(&ansi, 0, sizeof(ansi)); ansi.cbSize = requested;
        ansi.iBorderWidth = wide.iBorderWidth;
        ansi.iScrollWidth = wide.iScrollWidth; ansi.iScrollHeight = wide.iScrollHeight;
        ansi.iCaptionWidth = wide.iCaptionWidth; ansi.iCaptionHeight = wide.iCaptionHeight;
        ansi.iSmCaptionWidth = wide.iSmCaptionWidth; ansi.iSmCaptionHeight = wide.iSmCaptionHeight;
        ansi.iMenuWidth = wide.iMenuWidth; ansi.iMenuHeight = wide.iMenuHeight;
        ansi.iPaddedBorderWidth = wide.iPaddedBorderWidth;
        if (!font_to_ansi(&wide.lfCaptionFont, &ansi.lfCaptionFont) ||
            !font_to_ansi(&wide.lfSmCaptionFont, &ansi.lfSmCaptionFont) ||
            !font_to_ansi(&wide.lfMenuFont, &ansi.lfMenuFont) ||
            !font_to_ansi(&wide.lfStatusFont, &ansi.lfStatusFont) ||
            !font_to_ansi(&wide.lfMessageFont, &ansi.lfMessageFont)) return FALSE;
        /* A pre-Vista caller allocated exactly 340 bytes: never write padding. */
        memcpy(storage, &ansi, requested);
        return TRUE;
    }
    if (action == SPI_GETICONTITLELOGFONT) {
        LOGFONTW wide;
        LOGFONTA ansi;
        if (parameter != sizeof(ansi)) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
        memset(&wide, 0, sizeof(wide));
        if (!SystemParametersInfoW(action, sizeof(wide), &wide, 0)) return FALSE;
        if (!font_to_ansi(&wide, &ansi)) return FALSE;
        memcpy(storage, &ansi, sizeof(ansi));
        return TRUE;
    }
    SetLastError(ERROR_NOT_SUPPORTED); return FALSE;
}

int WINAPI m98w_DrawTextA(HDC dc, LPCSTR text, int length, LPRECT bounds, UINT flags)
{
    const UINT supported = DT_CENTER | DT_RIGHT | DT_VCENTER | DT_BOTTOM | DT_WORDBREAK |
                           DT_SINGLELINE | DT_NOCLIP | DT_CALCRECT | DT_NOPREFIX | DT_END_ELLIPSIS;
    const unsigned limit = 1048576u;
    WCHAR *wide = NULL;
    char *roundtrip = NULL;
    HANDLE heap;
    RECT area;
    BOOL substituted = FALSE;
    int count, chars, bytes, drawn = 0;
    DWORD error;
    if (!dc || !text || !bounds || length < -1) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & ~supported) { SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    count = length;
    if (count == -1) {
        unsigned i;
        for (i = 0; i <= limit && text[i]; ++i) { }
        if (i > limit) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
        count = (int)i;
    }
    if ((unsigned)count > limit) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    chars = count ? MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text, count, NULL, 0) : 0;
    if (count && !chars) return 0;
    if (chars < 0 || (unsigned)chars > limit) { SetLastError(ERROR_INVALID_DATA); return 0; }
    heap = GetProcessHeap();
    wide = HeapAlloc(heap, HEAP_ZERO_MEMORY, ((size_t)chars + 1u) * sizeof(WCHAR));
    if (!wide) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    if (count) {
        if (MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, text, count, wide, chars) != chars) goto done;
        /* Detect invalid sequences, default characters and silent best-fit
         * conversion. DrawTextW must receive exactly the caller's string. */
        roundtrip = HeapAlloc(heap, 0, (size_t)count + 1u);
        if (!roundtrip) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); goto done; }
        bytes = WideCharToMultiByte(CP_ACP, 0, wide, chars, roundtrip, count, NULL, &substituted);
        if (!bytes) goto done;
        if (substituted || bytes != count || memcmp(roundtrip, text, (size_t)count)) {
            SetLastError(ERROR_NO_UNICODE_TRANSLATION); goto done;
        }
    }
    area = *bounds;
    drawn = DrawTextW(dc, wide, chars, &area, flags);
done:
    error = GetLastError();
    if (roundtrip && !HeapFree(heap, 0, roundtrip)) { drawn = 0; error = ERROR_GEN_FAILURE; }
    if (!HeapFree(heap, 0, wide)) { drawn = 0; error = ERROR_GEN_FAILURE; }
    SetLastError(error);
    if (drawn) *bounds = area;
    return drawn;
}
