/* SPDX-License-Identifier: GPL-2.0-only
 * Opt-in application-owned visual styles. No system/KnownDLL registration,
 * service, subclass hook, GPU, msstyles, or non-client interception is implied.
 * Windows 98 native ANSI GDI renders exactly representable Unicode strings.
 * Reviewed Wine dlls/uxtheme/{system,draw}.c at
 * df15af3652511150490934682202d45af892f887 and ReactOS
 * dll/win32/uxtheme/{system,draw}.c at
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8. No implementation was copied.
 * Win98 adaptation: explicit private style selection, no theme service or
 * hooks, UTF-16-to-ACP conversion rejecting substitution, native ANSI metrics.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#include "uxtheme_engine_core.h"

static CRITICAL_SECTION lock;
static volatile LONG initialized;
static m98_theme_engine *engine;
static HWND associated_windows[M98_THEME_CAPACITY];
static m98_theme_handle associated_handles[M98_THEME_CAPACITY];
static const char theme_property[] = "M98ThemeEngine.Handle";
static const char override_property[] = "M98ThemeEngine.Override";
HRESULT WINAPI m98_GetThemeSysFont(HTHEME, int, LOGFONTW *);

static void *allocate(void *user, size_t bytes)
{ (void)user; return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes); }
static void deallocate(void *user, void *memory, size_t bytes)
{ (void)user; (void)bytes; HeapFree(GetProcessHeap(), 0, memory); }
static HRESULT result(ntth_status status)
{
    switch (status) {
    case NTTH_OK: return S_OK;
    case NTTH_E_HANDLE: return E_HANDLE;
    case NTTH_E_NOMEM: case NTTH_E_EXHAUSTED: return E_OUTOFMEMORY;
    case NTTH_E_UNSUPPORTED: return E_NOTIMPL;
    case NTTH_E_NO_THEME: return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
    default: return E_INVALIDARG;
    }
}
static HRESULT enter(void)
{
    if (InterlockedCompareExchange(&initialized, 1, 0) == 0) {
        InitializeCriticalSection(&lock);
        InterlockedExchange(&initialized, 2);
    } else while (InterlockedCompareExchange(&initialized, 2, 2) != 2) Sleep(0);
    EnterCriticalSection(&lock);
    if (!engine) {
        ntth_create_desc desc;
        ntth_status status;
        desc.struct_size = sizeof(desc); desc.allocate = allocate;
        desc.deallocate = deallocate; desc.allocator_user = NULL;
        status = m98_theme_engine_create(&desc, &engine);
        if (status != NTTH_OK) { LeaveCriticalSection(&lock); return result(status); }
    }
    return S_OK;
}
static m98_theme_handle cookie(HTHEME theme) { return (m98_theme_handle)(ULONG_PTR)theme; }
static COLORREF rgb(uint32_t color)
{ return RGB((color >> 16) & 255u, (color >> 8) & 255u, color & 255u); }
static BOOL window_owned(HWND window)
{
    DWORD process = 0;
    return IsWindow(window) && GetWindowThreadProcessId(window, &process) &&
           process == GetCurrentProcessId();
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)module;
    /* Lazy allocation avoids loader-lock initialization. No callbacks or
     * thread creation during detach. Callers must finish calls before unload. */
    if (reason == DLL_PROCESS_DETACH && !reserved && initialized == 2) {
        unsigned i;
        for (i = 0; i < M98_THEME_CAPACITY; ++i)
            if (window_owned(associated_windows[i]) &&
                (m98_theme_handle)(ULONG_PTR)GetPropA(associated_windows[i], theme_property) == associated_handles[i])
                RemovePropA(associated_windows[i], theme_property);
        m98_theme_engine_dispose(engine); engine = NULL;
        DeleteCriticalSection(&lock); initialized = 0;
    }
    return TRUE;
}

HRESULT WINAPI m98e_M98SetThemeStyle(DWORD style)
{
    HRESULT hr = enter();
    if (FAILED(hr)) return hr;
    hr = result(m98_theme_engine_style(engine, style));
    LeaveCriticalSection(&lock);
    /* Caller sends WM_THEMECHANGED after selecting a style. Never broadcast
     * from this process-local provider or modify other applications. */
    return hr;
}
DWORD WINAPI m98e_M98GetThemeStyle(void)
{
    DWORD style = 0;
    if (SUCCEEDED(enter())) { style = m98_theme_engine_get_style(engine); LeaveCriticalSection(&lock); }
    return style;
}
BOOL WINAPI m98e_IsThemeActive(void)
{
    BOOL active = FALSE;
    if (SUCCEEDED(enter())) { active = m98_theme_engine_active(engine); LeaveCriticalSection(&lock); }
    return active;
}
BOOL WINAPI m98e_IsAppThemed(void)
{
    BOOL active = FALSE;
    if (SUCCEEDED(enter())) { active = m98_theme_engine_app_themed(engine); LeaveCriticalSection(&lock); }
    return active;
}
DWORD WINAPI m98e_GetThemeAppProperties(void)
{
    DWORD flags = 0;
    if (SUCCEEDED(enter())) { flags = m98_theme_engine_get_flags(engine); LeaveCriticalSection(&lock); }
    return flags;
}
void WINAPI m98e_SetThemeAppProperties(DWORD flags)
{
    if (SUCCEEDED(enter())) { m98_theme_engine_set_flags(engine, flags); LeaveCriticalSection(&lock); }
}

/* Match a semicolon list, preserving requested order and ignoring ASCII case. */
static unsigned match_class(LPCWSTR text)
{
    if (!text) return 0;
    while (*text) {
        char name[16]; unsigned n = 0; int supported = 1;
        while (*text && *text != ';') {
            WCHAR c = *text++;
            if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
            if (n < 15 && c < 128) name[n++] = (char)c;
            else supported = 0;
        }
        name[n] = 0;
        if (supported && n == 6 && name[0]=='B' && name[1]=='U' && name[2]=='T' &&
            name[3]=='T' && name[4]=='O' && name[5]=='N') return 1;
        if (supported && n == 6 && name[0]=='W' && name[1]=='I' && name[2]=='N' &&
            name[3]=='D' && name[4]=='O' && name[5]=='W') return 2;
        if (*text == ';') ++text;
    }
    return 0;
}
HTHEME WINAPI m98e_OpenThemeData(HWND window, LPCWSTR classes)
{
    unsigned selected, override;
    m98_theme_handle handle = 0;
    HRESULT hr;
    if (!classes || (window && !window_owned(window))) { SetLastError(ERROR_INVALID_PARAMETER); return NULL; }
    override = window ? (unsigned)(ULONG_PTR)GetPropA(window, override_property) : 0;
    selected = override == 3 ? 0 : override ? override : match_class(classes);
    if (!selected) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
    hr = enter();
    if (FAILED(hr)) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }
    hr = result(m98_theme_engine_open(engine, selected == 1 ? "BUTTON" : "WINDOW", &handle));
    if (SUCCEEDED(hr) && window && !SetPropA(window, theme_property, (HANDLE)(ULONG_PTR)handle)) {
        m98_theme_engine_close(engine, handle); handle = 0; hr = E_OUTOFMEMORY;
    }
    if (SUCCEEDED(hr)) {
        unsigned index = (handle & 255u) - 1u;
        associated_windows[index] = window; associated_handles[index] = handle;
    }
    LeaveCriticalSection(&lock);
    if (FAILED(hr)) SetLastError(hr == E_OUTOFMEMORY ? ERROR_NOT_ENOUGH_MEMORY : ERROR_NOT_SUPPORTED);
    return (HTHEME)(ULONG_PTR)handle;
}
HRESULT WINAPI m98e_CloseThemeData(HTHEME theme)
{
    HRESULT hr = enter();
    if (FAILED(hr)) return hr;
    hr = result(m98_theme_engine_close(engine, cookie(theme)));
    if (SUCCEEDED(hr)) {
        unsigned index = (cookie(theme) & 255u) - 1u;
        HWND window = associated_windows[index];
        if (window_owned(window) && (HTHEME)GetPropA(window, theme_property) == theme)
            RemovePropA(window, theme_property);
        associated_windows[index] = NULL; associated_handles[index] = 0;
    }
    LeaveCriticalSection(&lock);
    return hr;
}
HTHEME WINAPI m98e_GetWindowTheme(HWND window)
{
    HTHEME theme;
    ntth_part_properties properties;
    HRESULT hr;
    if (!window_owned(window)) return NULL;
    theme = (HTHEME)GetPropA(window, theme_property);
    hr = enter();
    if (FAILED(hr)) return NULL;
    if (!(cookie(theme) & 255u) || (cookie(theme) & 255u) > M98_THEME_CAPACITY ||
        associated_windows[(cookie(theme) & 255u) - 1u] != window ||
        associated_handles[(cookie(theme) & 255u) - 1u] != cookie(theme)) hr = E_HANDLE;
    else hr = result(m98_theme_engine_query(engine, cookie(theme), 1, 1, &properties));
    LeaveCriticalSection(&lock);
    return SUCCEEDED(hr) ? theme : NULL;
}
HRESULT WINAPI m98e_SetWindowTheme(HWND window, LPCWSTR app, LPCWSTR classes)
{
    unsigned value;
    if (!window_owned(window)) return E_HANDLE;
    if (app && *app) return E_NOTIMPL; /* No application-specific namespaces. */
    if (!app && !classes) RemovePropA(window, override_property);
    else {
        value = (app && !*app) || (classes && !*classes) ? 3 : match_class(classes);
        if (!value) return E_NOTIMPL;
        if (!SetPropA(window, override_property, (HANDLE)(ULONG_PTR)value)) return E_OUTOFMEMORY;
    }
    RemovePropA(window, theme_property);
    /* Send after all state changes, outside the engine lock, permitting the
     * window procedure to close/reopen handles without a deadlock. */
    SendMessageA(window, WM_THEMECHANGED, 0, 0);
    return S_OK;
}

static HRESULT query(HTHEME theme, int part, int state, ntth_part_properties *out)
{
    HRESULT hr = enter();
    if (FAILED(hr)) return hr;
    hr = result(m98_theme_engine_query(engine, cookie(theme), part, state, out));
    LeaveCriticalSection(&lock);
    return hr;
}
BOOL WINAPI m98e_IsThemePartDefined(HTHEME theme, int part, int state)
{ ntth_part_properties p; return SUCCEEDED(query(theme, part, state ? state : 1, &p)); }
BOOL WINAPI m98e_IsThemeBackgroundPartiallyTransparent(HTHEME theme, int part, int state)
{ ntth_part_properties p; (void)query(theme, part, state, &p); return FALSE; }
HRESULT WINAPI m98e_GetThemeColor(HTHEME theme, int part, int state, int property, COLORREF *out)
{
    ntth_part_properties p; COLORREF value; HRESULT hr;
    if (!out) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    switch (property) {
    case TMT_BORDERCOLOR: value = rgb(p.bordercolor); break;
    case TMT_FILLCOLOR: value = rgb(p.fillcolor); break;
    case TMT_TEXTCOLOR: value = rgb(p.textcolor); break;
    case TMT_GRADIENTCOLOR1: case TMT_GRADIENTCOLOR2:
        if (p.filltype != NTTH_FT_HORZGRADIENT && p.filltype != NTTH_FT_VERTGRADIENT) return E_NOTIMPL;
        value = rgb(property == TMT_GRADIENTCOLOR1 ? p.gradient1 : p.gradient2); break;
    default: return E_NOTIMPL;
    }
    *out = value; return S_OK;
}
HRESULT WINAPI m98e_GetThemeInt(HTHEME theme, int part, int state, int property, int *out)
{
    ntth_part_properties p; HRESULT hr;
    if (!out) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    if (property != TMT_BORDERSIZE) return E_NOTIMPL;
    *out = (int)p.bordersize; return S_OK;
}
HRESULT WINAPI m98e_GetThemeEnumValue(HTHEME theme, int part, int state, int property, int *out)
{
    ntth_part_properties p; HRESULT hr; int value;
    if (!out) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    if (property == TMT_BGTYPE) value = (int)p.bgtype;
    else if (property == TMT_FILLTYPE) value = (int)p.filltype;
    else return E_NOTIMPL;
    *out = value; return S_OK;
}
HRESULT WINAPI m98e_GetThemeMargins(HTHEME theme, HDC dc, int part, int state,
                                    int property, RECT *bounds, MARGINS *out)
{
    ntth_part_properties p; MARGINS value; HRESULT hr;
    (void)dc; (void)bounds;
    if (!out) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    if (property != TMT_CONTENTMARGINS && property != TMT_SIZINGMARGINS) return E_NOTIMPL;
    value.cxLeftWidth = value.cxRightWidth = value.cyTopHeight = value.cyBottomHeight = (int)p.bordersize;
    *out = value; return S_OK;
}
HRESULT WINAPI m98e_GetThemeBackgroundContentRect(HTHEME theme, HDC dc, int part,
                                                  int state, const RECT *bounds, RECT *out)
{
    MARGINS margin; RECT value; HRESULT hr;
    if (!bounds || !out) return E_POINTER;
    if (bounds->right < bounds->left || bounds->bottom < bounds->top) return E_INVALIDARG;
    hr = m98e_GetThemeMargins(theme, dc, part, state, TMT_CONTENTMARGINS, NULL, &margin);
    if (FAILED(hr)) return hr;
    value = *bounds;
    /* Clamp the inset for tiny parts, avoiding inverted content rectangles. */
    if ((LONGLONG)value.right - value.left < 2 * margin.cxLeftWidth)
        value.left = value.right = (LONG)(((LONGLONG)value.left + value.right) / 2);
    else { value.left += margin.cxLeftWidth; value.right -= margin.cxRightWidth; }
    if ((LONGLONG)value.bottom - value.top < 2 * margin.cyTopHeight)
        value.top = value.bottom = (LONG)(((LONGLONG)value.top + value.bottom) / 2);
    else { value.top += margin.cyTopHeight; value.bottom -= margin.cyBottomHeight; }
    *out = value; return S_OK;
}
HRESULT WINAPI m98e_GetThemeSysFont(HTHEME theme, int id, LOGFONTW *font)
{
    ntth_part_properties p; HRESULT hr;
    if (theme) { hr = query(theme, 1, 1, &p); if (FAILED(hr)) return hr; }
    return m98_GetThemeSysFont(NULL, id, font);
}
HRESULT WINAPI m98e_GetThemeFont(HTHEME theme, HDC dc, int part, int state,
                                 int property, LOGFONTW *font)
{
    ntth_part_properties p; HRESULT hr; (void)dc;
    if (!font) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    if (property != TMT_FONT) return E_NOTIMPL;
    return m98_GetThemeSysFont(NULL, TMT_MSGBOXFONT, font);
}

HRESULT WINAPI m98e_DrawThemeBackground(HTHEME theme, HDC dc, int part, int state,
                                        const RECT *bounds, const RECT *clip)
{
    BITMAPINFO info; HDC memory = NULL; HBITMAP bitmap = NULL, old = NULL;
    void *pixels = NULL; ntwg_rect rect; HRESULT hr; int saved = 0;
    LONGLONG width, height; ntth_part_properties p;
    if (!dc || !bounds) return E_POINTER;
    hr = query(theme, part, state, &p); if (FAILED(hr)) return hr;
    width = (LONGLONG)bounds->right - bounds->left;
    height = (LONGLONG)bounds->bottom - bounds->top;
    if (width < 0 || height < 0) return E_INVALIDARG;
    if (!width || !height) return S_OK;
    if (width > 16384 || height > 16384 || width * height > 33554432) return E_OUTOFMEMORY;
    if (GetMapMode(dc) != MM_TEXT) return E_NOTIMPL;
    if (clip && (clip->right < clip->left || clip->bottom < clip->top)) return E_INVALIDARG;
    ZeroMemory(&info, sizeof(info)); info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth = (LONG)width; info.bmiHeader.biHeight = -(LONG)height;
    info.bmiHeader.biPlanes = 1; info.bmiHeader.biBitCount = 32; info.bmiHeader.biCompression = BI_RGB;
    memory = CreateCompatibleDC(dc);
    if (!memory) return E_OUTOFMEMORY;
    bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &pixels, NULL, 0);
    if (!bitmap || !pixels) { hr = E_OUTOFMEMORY; goto done; }
    old = (HBITMAP)SelectObject(memory, bitmap);
    if (!old || old == (HBITMAP)HGDI_ERROR || !GdiFlush()) { hr = E_FAIL; goto done; }
    rect.x = rect.y = 0; rect.width = (uint32_t)width; rect.height = (uint32_t)height;
    hr = enter(); if (FAILED(hr)) goto done;
    hr = result(m98_theme_engine_draw(engine, cookie(theme), part, state, pixels,
                 (uint32_t)width, (uint32_t)height, (uint32_t)width * 4u, &rect, NULL));
    LeaveCriticalSection(&lock);
    if (FAILED(hr)) goto done;
    saved = SaveDC(dc); if (!saved) { hr = E_FAIL; goto done; }
    if (clip && IntersectClipRect(dc, clip->left, clip->top, clip->right, clip->bottom) == ERROR) {
        hr = E_FAIL; goto done;
    }
    if (!BitBlt(dc, bounds->left, bounds->top, (int)width, (int)height, memory, 0, 0, SRCCOPY) || !GdiFlush()) hr = E_FAIL;
done:
    if (saved && !RestoreDC(dc, saved)) hr = E_FAIL;
    if (old && old != (HBITMAP)HGDI_ERROR) SelectObject(memory, old);
    if (bitmap) DeleteObject(bitmap);
    if (memory) DeleteDC(memory);
    return hr;
}

HRESULT WINAPI m98e_DrawThemeTextEx(HTHEME theme, HDC dc, int part, int state,
                                    LPCWSTR text, int length, DWORD flags,
                                    RECT *bounds, const DTTOPTS *options)
{
    ntth_part_properties p; HRESULT hr; char *ansi = NULL; int bytes, count, saved;
    NONCLIENTMETRICSA metrics; HFONT font = NULL; HGDIOBJ selected;
    BOOL substituted = FALSE; RECT area; COLORREF color;
    WCHAR *roundtrip = NULL; int wide_count, source_count, i;
    if (!dc || !bounds || !text) return E_POINTER;
    if (length < -1) return E_INVALIDARG;
    hr = query(theme, part ? part : 1, part ? state : 1, &p); if (FAILED(hr)) return hr;
    if (options && (options->dwSize != sizeof(*options) || (options->dwFlags & ~DTT_TEXTCOLOR))) return E_NOTIMPL;
    /* Preserve DrawText semantics, including punctuation, accelerator prefixes,
     * alignment, wrapping, explicit UTF-16 length and DT_CALCRECT. No '?' loss. */
    bytes = WideCharToMultiByte(CP_ACP, 0, text, length, NULL, 0, NULL, &substituted);
    if (!bytes && length != 0) return HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION);
    if (substituted) return HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION);
    /* DT_MODIFYSTRING may append four ANSI characters in our private copy. */
    ansi = allocate(NULL, (size_t)bytes + 5u); if (!ansi) return E_OUTOFMEMORY;
    if (bytes && !WideCharToMultiByte(CP_ACP, 0, text, length, ansi, bytes, NULL, &substituted)) {
        hr = HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION); goto done;
    }
    if (substituted) { hr = HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION); goto done; }
    /* Win98's flags=0 conversion can silently choose best-fit characters
     * without setting usedDefaultChar. Verify every original UTF-16 code unit
     * by converting back; never paint a changed string as successful Unicode. */
    wide_count = bytes ? MultiByteToWideChar(CP_ACP, 0, ansi, bytes, NULL, 0) : 0;
    source_count = length;
    if (length == -1) { source_count = 0; do { ++source_count; } while (text[source_count - 1]); }
    if (wide_count != source_count) { hr = HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION); goto done; }
    if (wide_count) {
        roundtrip = allocate(NULL, (size_t)wide_count * sizeof(WCHAR));
        if (!roundtrip) { hr = E_OUTOFMEMORY; goto done; }
        if (MultiByteToWideChar(CP_ACP, 0, ansi, bytes, roundtrip, wide_count) != wide_count) {
            hr = HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION); goto done;
        }
        for (i = 0; i < wide_count; ++i)
            if (roundtrip[i] != text[i]) { hr = HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION); goto done; }
    }
    saved = SaveDC(dc); if (!saved) { hr = E_FAIL; goto done; }
    if (part) {
        ZeroMemory(&metrics, sizeof(metrics));
        /* Vista declarations append iPaddedBorderWidth. Win98 accepts only
         * the pre-Vista structure size, including for the ANSI entrypoint. */
        metrics.cbSize = sizeof(metrics) - sizeof(metrics.iPaddedBorderWidth);
        if (!SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, metrics.cbSize, &metrics, 0) ||
            !(font = CreateFontIndirectA(&metrics.lfMessageFont))) {
            hr = E_FAIL; RestoreDC(dc, saved); goto done;
        }
        selected = SelectObject(dc, font);
        if (!selected || selected == HGDI_ERROR) { hr = E_FAIL; RestoreDC(dc, saved); goto done; }
    }
    color = options && (options->dwFlags & DTT_TEXTCOLOR) ? options->crText : rgb(p.textcolor);
    if (SetTextColor(dc, color) == CLR_INVALID || !SetBkMode(dc, TRANSPARENT)) hr = E_FAIL;
    else {
        area = *bounds; count = length == -1 && bytes ? bytes - 1 : bytes;
        if (count && !DrawTextA(dc, ansi, count, &area, flags)) hr = E_FAIL;
        else { hr = S_OK; if (flags & DT_CALCRECT) *bounds = area; }
    }
    if (!RestoreDC(dc, saved)) hr = E_FAIL;
done:
    if (font) DeleteObject(font);
    if (roundtrip) deallocate(NULL, roundtrip, (size_t)wide_count * sizeof(WCHAR));
    deallocate(NULL, ansi, (size_t)bytes + 5u);
    return hr;
}
HRESULT WINAPI m98e_DrawThemeText(HTHEME theme, HDC dc, int part, int state,
                                  LPCWSTR text, int length, DWORD flags,
                                  DWORD flags2, const RECT *bounds)
{
    RECT area; DTTOPTS options;
    if (!bounds) return E_POINTER;
    if (flags2 & ~DTT_GRAYED) return E_NOTIMPL;
    ZeroMemory(&options, sizeof(options)); options.dwSize = sizeof(options);
    if (flags2 & DTT_GRAYED) { options.dwFlags = DTT_TEXTCOLOR; options.crText = GetSysColor(COLOR_GRAYTEXT); }
    area = *bounds;
    return m98e_DrawThemeTextEx(theme, dc, part, state, text, length, flags, &area, &options);
}
