/* SPDX-License-Identifier: GPL-2.0-only
 * Real shared-engine geometry/lifecycle + mocked GDI dispatch tests.
 * Does not execute an AMD64 Windows DLL or prove a guest HDC can render.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define M98_THEME_EXTENSION_HOST_TEST
#include "extensions.c"
#include "uxtheme_engine_core.h"
#include "cookie.h"

static unsigned checks;
static m98_theme_engine *engine;
static int override_properties, background_override, border_override;
static HRESULT enum_failure, int_failure, draw_result;
static unsigned draw_calls;
static HTHEME drawn_theme;
static HDC drawn_dc;
static int drawn_part, drawn_state;
static RECT drawn_bounds, drawn_clip;
static int had_bounds, had_clip;

#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expression); exit(1); } } while (0)

static void *allocate(void *user, size_t bytes) { (void)user; return calloc(1, bytes); }
static void deallocate(void *user, void *memory, size_t bytes)
{ (void)user; (void)bytes; free(memory); }
static HRESULT status_result(ntth_status status)
{
    switch (status) {
    case NTTH_OK: return S_OK;
    case NTTH_E_HANDLE: return E_HANDLE;
    case NTTH_E_UNSUPPORTED: return E_NOTIMPL;
    default: return E_INVALIDARG;
    }
}
HRESULT m98e_GetThemeEnumValue(HTHEME theme, int part, int state, int property, int *out)
{
    ntth_part_properties p;
    HRESULT hr;
    CHECK(property == TMT_BGTYPE);
    if (enum_failure) return enum_failure;
    if (override_properties) { *out = background_override; return S_OK; }
    hr = status_result(m98_theme_engine_query(engine, (uint32_t)(uintptr_t)theme, part, state, &p));
    if (!FAILED(hr)) *out = (int)p.bgtype;
    return hr;
}
HRESULT m98e_GetThemeInt(HTHEME theme, int part, int state, int property, int *out)
{
    ntth_part_properties p;
    HRESULT hr;
    CHECK(property == TMT_BORDERSIZE);
    if (int_failure) return int_failure;
    if (override_properties) { *out = border_override; return S_OK; }
    hr = status_result(m98_theme_engine_query(engine, (uint32_t)(uintptr_t)theme, part, state, &p));
    if (!FAILED(hr)) *out = (int)p.bordersize;
    return hr;
}
HRESULT m98e_DrawThemeBackground(HTHEME theme, HDC dc, int part, int state,
                                const RECT *bounds, const RECT *clip)
{
    ++draw_calls; drawn_theme = theme; drawn_dc = dc; drawn_part = part; drawn_state = state;
    had_bounds = bounds != NULL; had_clip = clip != NULL;
    if (bounds) drawn_bounds = *bounds;
    if (clip) drawn_clip = *clip;
    return draw_result;
}

int main(void)
{
    ntth_create_desc allocator = {sizeof(allocator), allocate, deallocate, NULL};
    uint32_t style, handle, state;
    HTHEME theme;
    SIZE size;
    RECT bounds = {-100, -200, 100, 200}, invalid = {10, 0, 9, 1};
    DTBGOPTS options = {sizeof(options), 0, {1, 2, 3, 4}};
    unsigned before;
    HDC dc = (HDC)(uintptr_t)17;
    CHECK(sizeof(RECT) == 16 && sizeof(SIZE) == 8 && sizeof(DTBGOPTS) == 24);
    CHECK(sizeof(uintptr_t) == 8);
    CHECK(m98w_cookie_value(0) == 0);
    CHECK(m98w_cookie_value(257) == 257);
    CHECK(m98w_cookie_value(UINT32_MAX) == UINT32_MAX);
    CHECK(m98w_cookie_value((uintptr_t)UINT32_MAX + 1u) == 0);
    CHECK(m98w_cookie_value(UINT64_C(0x100000101)) == 0);
    CHECK(m98w_cookie_value(UINTPTR_MAX) == 0);
    CHECK(m98_theme_engine_create(&allocator, &engine) == NTTH_OK);
    for (style = M98_THEME_CLASSIC; style <= M98_THEME_MODERN; ++style) {
        CHECK(m98_theme_engine_style(engine, style) == NTTH_OK);
        CHECK(m98_theme_engine_open(engine, "BUTTON", &handle) == NTTH_OK);
        theme = (HTHEME)(uintptr_t)handle;
        for (state = 1; state <= 4; ++state) {
            for (int kind = TS_MIN; kind <= TS_DRAW; ++kind) {
                size.cx = size.cy = -77;
                CHECK(m98w_GetThemePartSize(theme, NULL, 1, (int)state, &bounds, (THEMESIZE)kind, &size) == S_OK);
                CHECK(size.cx == (kind == TS_MIN ? 2 : 3) && size.cy == size.cx);
            }
        }
        CHECK(m98w_GetThemePartSize(theme, dc, 1, 1, NULL, TS_TRUE, &size) == S_OK);
        CHECK(size.cx == 3 && size.cy == 3);
        size.cx = 55; size.cy = 66;
        CHECK(m98w_GetThemePartSize(theme, dc, 99, 1, NULL, TS_MIN, &size) == E_NOTIMPL);
        CHECK(size.cx == 55 && size.cy == 66);
        CHECK(m98w_GetThemePartSize(theme, dc, 1, 1, &invalid, TS_MIN, &size) == E_INVALIDARG);
        CHECK(size.cx == 55 && size.cy == 66);
        CHECK(m98w_GetThemePartSize(theme, dc, 1, 1, NULL, (THEMESIZE)3, &size) == E_INVALIDARG);
        CHECK(m98w_GetThemePartSize(theme, dc, 1, 1, NULL, TS_MIN, NULL) == E_POINTER);
        CHECK(m98_theme_engine_style(engine, M98_THEME_OFF) == NTTH_OK);
        CHECK(FAILED(m98w_GetThemePartSize(theme, dc, 1, 1, NULL, TS_MIN, &size)));
        CHECK(size.cx == 55 && size.cy == 66);
        CHECK(m98_theme_engine_close(engine, handle) == NTTH_OK);
        CHECK(m98w_GetThemePartSize(theme, dc, 1, 1, NULL, TS_MIN, &size) == E_HANDLE);
        CHECK(size.cx == 55 && size.cy == 66);
    }
    override_properties = 1; background_override = BT_BORDERFILL;
    theme = (HTHEME)(uintptr_t)257;
    for (int border = 0; border <= 32; ++border) {
        border_override = border;
        CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == S_OK);
        CHECK(size.cx == border * 2 && size.cy == size.cx);
        CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_DRAW, &size) == S_OK);
        CHECK(size.cx == border * 2 + 1 && size.cy == size.cx);
    }
    border_override = 0x3fffffff;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_TRUE, &size) == S_OK);
    CHECK(size.cx == 0x7fffffff && size.cy == size.cx);
    size.cx = 55; size.cy = 66;
    border_override = 0x40000000;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == E_INVALIDARG);
    CHECK(size.cx == 55 && size.cy == 66);
    border_override = -1;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == E_INVALIDARG);
    CHECK(size.cx == 55 && size.cy == 66);
    background_override = 0;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == E_NOTIMPL);
    CHECK(size.cx == 55 && size.cy == 66);
    background_override = BT_BORDERFILL; enum_failure = E_HANDLE;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == E_HANDLE);
    CHECK(size.cx == 55 && size.cy == 66);
    enum_failure = 0; int_failure = E_FAIL;
    CHECK(m98w_GetThemePartSize(theme, NULL, 1, 1, NULL, TS_MIN, &size) == E_FAIL);
    CHECK(size.cx == 55 && size.cy == 66);

    draw_result = S_OK;
    CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 1, 2, &bounds, NULL) == S_OK);
    CHECK(draw_calls == 1 && drawn_theme == theme && drawn_dc == dc && drawn_part == 1 && drawn_state == 2);
    CHECK(had_bounds && !had_clip && !memcmp(&drawn_bounds, &bounds, sizeof(bounds)));
    CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 3, 4, &bounds, &options) == S_OK);
    CHECK(draw_calls == 2 && drawn_part == 3 && drawn_state == 4 && !had_clip);
    options.dwFlags = DTBG_CLIPRECT;
    CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 1, 1, &bounds, &options) == S_OK);
    CHECK(draw_calls == 3 && had_clip && !memcmp(&drawn_clip, &options.rcClip, sizeof(RECT)));
    draw_result = E_FAIL;
    CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 1, 1, &bounds, &options) == E_FAIL);
    CHECK(draw_calls == 4);
    for (DWORD flag = 2; flag != 0; flag <<= 1) {
        before = draw_calls; options.dwFlags = flag;
        CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 1, 1, &bounds, &options) == E_NOTIMPL);
        CHECK(draw_calls == before);
    }
    before = draw_calls; options.dwFlags = 0; --options.dwSize;
    CHECK(m98w_DrawThemeBackgroundEx(theme, dc, 1, 1, &bounds, &options) == E_INVALIDARG);
    CHECK(draw_calls == before);
    CHECK(m98_theme_engine_destroy(engine) == NTTH_OK);
    printf("PASS: %u shared-engine part-size and extension dispatch assertions\n", checks);
    return 0;
}
