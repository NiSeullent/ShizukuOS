/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS userland appearance settings, using the real theme/GDI provider.
 * The selected Classic/ShizukuOS profile is shared with participating userland.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0600
#include <windows.h>
#include <uxtheme.h>

#define STYLE_CLASSIC 1u
#define STYLE_SHIZUKUOS 3u
#define ID_CLASSIC 101
#define ID_SHIZUKUOS 102
#define ID_APPLY 103
#define ID_CLOSE 104

typedef HRESULT (WINAPI *set_style_fn)(DWORD);
typedef DWORD (WINAPI *get_style_fn)(void);
typedef HRESULT (WINAPI *load_profile_fn)(void);
typedef HRESULT (WINAPI *save_profile_fn)(DWORD);
typedef HTHEME (WINAPI *open_theme_fn)(HWND,LPCWSTR);
typedef HRESULT (WINAPI *close_theme_fn)(HTHEME);
typedef HRESULT (WINAPI *draw_background_fn)(HTHEME,HDC,int,int,const RECT *,const RECT *);
typedef HRESULT (WINAPI *draw_text_fn)(HTHEME,HDC,int,int,LPCWSTR,int,DWORD,DWORD,const RECT *);
/* Bind dynamic calls to the SDK ABI, including DrawThemeText's flags2 slot. */
_Static_assert(__builtin_types_compatible_p(open_theme_fn, __typeof__(&OpenThemeData)), "OpenThemeData ABI");
_Static_assert(__builtin_types_compatible_p(close_theme_fn, __typeof__(&CloseThemeData)), "CloseThemeData ABI");
_Static_assert(__builtin_types_compatible_p(draw_background_fn, __typeof__(&DrawThemeBackground)), "DrawThemeBackground ABI");
_Static_assert(__builtin_types_compatible_p(draw_text_fn, __typeof__(&DrawThemeText)), "DrawThemeText ABI");

static set_style_fn set_style;
static get_style_fn get_style;
static load_profile_fn load_profile;
static save_profile_fn save_profile;
static open_theme_fn open_theme;
static close_theme_fn close_theme;
static draw_background_fn draw_background;
static draw_text_fn draw_text;
static HMODULE provider;
static HWND classic_choice, shizukuos_choice, apply_button, close_button;
static DWORD selected;
static const char *status_text = "Choose a theme, then select Apply.";

static void redraw(HWND window)
{
    InvalidateRect(window, NULL, TRUE);
    InvalidateRect(apply_button, NULL, TRUE);
    InvalidateRect(close_button, NULL, TRUE);
}

static int paint_part(HDC dc, LPCWSTR name, int part, int state,
                      const RECT *rect, LPCWSTR label)
{
    HTHEME theme = open_theme(NULL, name);
    HRESULT hr;
    if (!theme) return 0;
    hr = draw_background(theme, dc, part, state, rect, NULL);
    if (SUCCEEDED(hr) && label)
        hr = draw_text(theme, dc, part, state, label, -1,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE, 0, rect);
    if (FAILED(close_theme(theme))) return 0;
    return SUCCEEDED(hr);
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_CREATE) {
        HINSTANCE instance = GetModuleHandleA(NULL);
        classic_choice = CreateWindowExA(0, "BUTTON", "Classic", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 24, 66, 144, 28,
            window, (HMENU)(ULONG_PTR)ID_CLASSIC, instance, NULL);
        shizukuos_choice = CreateWindowExA(0, "BUTTON", "ShizukuOS", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | BS_AUTORADIOBUTTON, 180, 66, 144, 28,
            window, (HMENU)(ULONG_PTR)ID_SHIZUKUOS, instance, NULL);
        apply_button = CreateWindowExA(0, "BUTTON", "Apply", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | WS_GROUP | BS_OWNERDRAW, 166, 170, 88, 30,
            window, (HMENU)(ULONG_PTR)ID_APPLY, instance, NULL);
        close_button = CreateWindowExA(0, "BUTTON", "Close", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | BS_OWNERDRAW, 268, 170, 88, 30,
            window, (HMENU)(ULONG_PTR)ID_CLOSE, instance, NULL);
        if (!classic_choice || !shizukuos_choice || !apply_button || !close_button) return -1;
        CheckRadioButton(window, ID_CLASSIC, ID_SHIZUKUOS,
                         selected == STYLE_CLASSIC ? ID_CLASSIC : ID_SHIZUKUOS);
        return 0;
    }
    if (message == WM_COMMAND) {
        unsigned id = LOWORD(wp);
        if (id == IDOK) id = GetFocus() == close_button ? ID_CLOSE : ID_APPLY;
        if (id == IDCANCEL) id = ID_CLOSE;
        if ((id == ID_CLASSIC || id == ID_SHIZUKUOS) && HIWORD(wp) == BN_CLICKED) {
            DWORD choice = id == ID_CLASSIC ? STYLE_CLASSIC : STYLE_SHIZUKUOS;
            if (SUCCEEDED(set_style(choice))) {
                selected = choice;
                status_text = "Select Apply to save this theme.";
                SendMessageA(window, WM_THEMECHANGED, 0, 0);
            } else {
                status_text = "This theme could not be opened.";
                CheckRadioButton(window, ID_CLASSIC, ID_SHIZUKUOS,
                                 selected == STYLE_CLASSIC ? ID_CLASSIC : ID_SHIZUKUOS);
            }
            redraw(window);
            return 0;
        }
        if (id == ID_APPLY && HIWORD(wp) == BN_CLICKED) {
            status_text = SUCCEEDED(save_profile(selected)) ?
                "Theme saved." : "The theme setting could not be saved.";
            redraw(window);
            return 0;
        }
        if (id == ID_CLOSE) { DestroyWindow(window); return 0; }
    }
    if (message == WM_DRAWITEM) {
        const DRAWITEMSTRUCT *item = (const DRAWITEMSTRUCT *)lp;
        int state;
        if (!item || item->CtlType != ODT_BUTTON ||
            (item->CtlID != ID_APPLY && item->CtlID != ID_CLOSE))
            return DefWindowProcA(window, message, wp, lp);
        state = item->itemState & ODS_DISABLED ? 4 : item->itemState & ODS_SELECTED ? 3 : 1;
        if (!paint_part(item->hDC, L"BUTTON", 1, state, &item->rcItem,
                        item->CtlID == ID_APPLY ? L"Apply" : L"Close"))
            return FALSE;
        if (item->itemState & ODS_FOCUS) {
            RECT focus = item->rcItem;
            InflateRect(&focus, -3, -3);
            DrawFocusRect(item->hDC, &focus);
        }
        return TRUE;
    }
    if (message == WM_PAINT) {
        PAINTSTRUCT paint;
        HDC dc = BeginPaint(window, &paint);
        RECT header = {16, 14, 356, 48}, hint = {24, 112, 352, 154};
        int old_mode = SetBkMode(dc, TRANSPARENT);
        COLORREF old_color = SetTextColor(dc, RGB(18, 40, 59));
        if (!paint_part(dc, L"WINDOW", 1, 1, &header, L"ShizukuOS Appearance"))
            DrawTextA(dc, "ShizukuOS Appearance", -1, &header, DT_SINGLELINE);
        DrawTextA(dc, status_text, -1, &hint, DT_WORDBREAK);
        SetBkMode(dc, old_mode);
        SetTextColor(dc, old_color);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(window, message, wp, lp);
}

static int load_provider(void)
{
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, path, sizeof(path)), i;
    const char name[] = "M98THEME.DLL";
    if (!length || length >= sizeof(path)) return 0;
    i = length;
    while (i && path[i-1] != '\\' && path[i-1] != '/') --i;
    if (!i || i + sizeof(name) > sizeof(path)) return 0;
    for (length = 0; length < sizeof(name); ++length) path[i+length] = name[length];
    provider = LoadLibraryA(path);
    if (!provider) return 0;
#define RESOLVE(v,n,t) do { v = (t)(void *)GetProcAddress(provider,n); if (!v) return 0; } while (0)
    RESOLVE(set_style, "M98SetThemeStyle", set_style_fn);
    RESOLVE(get_style, "M98GetThemeStyle", get_style_fn);
    RESOLVE(load_profile, "ShizukuOSLoadUserTheme", load_profile_fn);
    RESOLVE(save_profile, "ShizukuOSSaveUserTheme", save_profile_fn);
    RESOLVE(open_theme, "OpenThemeData", open_theme_fn);
    RESOLVE(close_theme, "CloseThemeData", close_theme_fn);
    RESOLVE(draw_background, "DrawThemeBackground", draw_background_fn);
    RESOLVE(draw_text, "DrawThemeText", draw_text_fn);
#undef RESOLVE
    return 1;
}

void mainCRTStartup(void)
{
    WNDCLASSA klass = {0};
    HWND window;
    MSG message;
    int next, code = 0;
    if (!load_provider()) {
        MessageBoxA(NULL, "Place SHZAPPEAR.EXE and M98THEME.DLL in the same folder.",
                    "ShizukuOS Appearance", MB_OK | MB_ICONERROR);
        if (provider) FreeLibrary(provider);
        ExitProcess(1);
    }
    if (FAILED(load_profile())) {
        status_text = "The saved theme could not be read. Select Apply to replace it.";
        if (FAILED(set_style(STYLE_SHIZUKUOS))) { FreeLibrary(provider); ExitProcess(2); }
    }
    selected = get_style();
    klass.lpfnWndProc = window_proc;
    klass.hInstance = GetModuleHandleA(NULL);
    klass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    klass.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    klass.lpszClassName = "ShizukuOS.Appearance";
    if (!RegisterClassA(&klass)) { FreeLibrary(provider); ExitProcess(3); }
    window = CreateWindowExA(0, klass.lpszClassName, "ShizukuOS Appearance",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 392, 252, NULL, NULL, klass.hInstance, NULL);
    if (!window) { UnregisterClassA(klass.lpszClassName, klass.hInstance); FreeLibrary(provider); ExitProcess(4); }
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    SetFocus(selected == STYLE_CLASSIC ? classic_choice : shizukuos_choice);
    while ((next = GetMessageA(&message, NULL, 0, 0)) > 0)
        if (!IsDialogMessageA(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageA(&message);
        }
    if (next < 0) { DestroyWindow(window); code = 5; }
    UnregisterClassA(klass.lpszClassName, klass.hInstance);
    FreeLibrary(provider);
    ExitProcess((UINT)code);
}
