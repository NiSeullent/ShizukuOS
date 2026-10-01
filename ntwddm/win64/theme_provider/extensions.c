/* SPDX-License-Identifier: GPL-2.0-only
 * Original extensions to the shared application-owned theme provider.
 * Microsoft uxtheme.h documentation and Wine uxtheme.spec/draw.c at
 * df15af3652511150490934682202d45af892f887 were consulted for ABI/semantics.
 * No Wine implementation was copied. No new painter or system theme hook.
 */
#ifdef M98_THEME_EXTENSION_HOST_TEST
#include "host_types.h"
#else
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#endif

HRESULT WINAPI m98e_GetThemeEnumValue(HTHEME, int, int, int, int *);
HRESULT WINAPI m98e_GetThemeInt(HTHEME, int, int, int, int *);
HRESULT WINAPI m98e_DrawThemeBackground(HTHEME, HDC, int, int, const RECT *, const RECT *);

HRESULT WINAPI m98w_GetThemePartSize(HTHEME theme, HDC dc, int part, int state,
                                    const RECT *bounds, THEMESIZE kind, SIZE *out)
{
    int background, border;
    SIZE value;
    HRESULT hr;
    (void)dc; /* The built-in borderfill parts have no font/image dimensions. */
    if (!out) return E_POINTER;
    if (kind != TS_MIN && kind != TS_TRUE && kind != TS_DRAW) return E_INVALIDARG;
    if (bounds && (bounds->right < bounds->left || bounds->bottom < bounds->top))
        return E_INVALIDARG;
    hr = m98e_GetThemeEnumValue(theme, part, state, TMT_BGTYPE, &background);
    if (FAILED(hr)) return hr;
    /* A raster image's intrinsic size cannot be inferred from border geometry.
     * Support only the actual shared engine's built-in borderfill backgrounds. */
    if (background != BT_BORDERFILL) return E_NOTIMPL;
    hr = m98e_GetThemeInt(theme, part, state, TMT_BORDERSIZE, &border);
    if (FAILED(hr)) return hr;
    if (border < 0 || (unsigned)border > (0x7fffffffu - 1u) / 2u) return E_INVALIDARG;
    value.cx = value.cy = (LONG)((unsigned)border * 2u + (kind == TS_MIN ? 0u : 1u));
    *out = value;
    return S_OK;
}

HRESULT WINAPI m98w_DrawThemeBackgroundEx(HTHEME theme, HDC dc, int part, int state,
                                         const RECT *bounds, const DTBGOPTS *options)
{
    const RECT *clip = NULL;
    if (options) {
        if (options->dwSize != sizeof(*options)) return E_INVALIDARG;
        /* Only options rendered by the shared GDI adapter are accepted. Omit,
         * mirror and region flags must never be silently claimed as applied. */
        if (options->dwFlags & ~DTBG_CLIPRECT) return E_NOTIMPL;
        if (options->dwFlags & DTBG_CLIPRECT) clip = &options->rcClip;
    }
    return m98e_DrawThemeBackground(theme, dc, part, state, bounds, clip);
}
