/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS appearance settings: a native Windows98 USER/GDI dialog-style app.
 * Classic is the native Windows98 baseline and needs no theme provider. The
 * ShizukuOS profile is offered only when the real M98THEME.DLL provider loads
 * and resolves every export; otherwise the exact failure is shown. Explorer
 * (taskbar/desktop) remains the shell either way; this app never replaces it,
 * and the provider style is process-local plus a per-user registry profile for
 * participating applications. Nothing here proves a Win98 guest execution.
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
#define ID_OK 105
#define ID_GROUP 106
#define ID_GLOBAL 107

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
static int provider_ok;
static HWND global_button, classic_choice, shizukuos_choice, ok_button, apply_button, close_button;
static DWORD selected, saved; /* saved 0: no trustworthy persisted profile */
static char provider_error[128] = "Theme provider not loaded.";
static char status_buffer[160] = "Choose a scheme, then select Apply.";
static const char *status_text = status_buffer;

static void set_status(const char *text)
{
    int i = 0;
    while (text[i] && i < (int)sizeof(status_buffer) - 1) { status_buffer[i] = text[i]; ++i; }
    status_buffer[i] = 0;
}

static void redraw(HWND window)
{
    InvalidateRect(window, NULL, TRUE);
    InvalidateRect(ok_button, NULL, TRUE);
    InvalidateRect(apply_button, NULL, TRUE);
    InvalidateRect(close_button, NULL, TRUE);
}

static int paint_part(HDC dc, LPCWSTR name, int part, int state,
                      const RECT *rect, LPCWSTR label)
{
    HTHEME theme;
    HRESULT hr;
    if (!provider_ok) return 0;
    theme = open_theme(NULL, name);
    if (!theme) return 0;
    hr = draw_background(theme, dc, part, state, rect, NULL);
    if (SUCCEEDED(hr) && label)
        hr = draw_text(theme, dc, part, state, label, -1,
                       DT_CENTER | DT_VCENTER | DT_SINGLELINE, 0, rect);
    if (FAILED(close_theme(theme))) return 0;
    return SUCCEEDED(hr);
}

/* Native Windows98 push button, used for Classic and when the provider is absent. */
static void paint_native_button(const DRAWITEMSTRUCT *item, const char *label)
{
    RECT rect = item->rcItem;
    UINT flags = DFCS_BUTTONPUSH;
    int old_mode;
    COLORREF old_color;
    if (item->itemState & ODS_DISABLED) flags |= DFCS_INACTIVE;
    if (item->itemState & ODS_SELECTED) flags |= DFCS_PUSHED;
    DrawFrameControl(item->hDC, &rect, DFC_BUTTON, flags);
    if (item->itemState & ODS_SELECTED) OffsetRect(&rect, 1, 1);
    old_mode = SetBkMode(item->hDC, TRANSPARENT);
    old_color = SetTextColor(item->hDC, GetSysColor(item->itemState & ODS_DISABLED ?
                                                    COLOR_GRAYTEXT : COLOR_BTNTEXT));
    DrawTextA(item->hDC, label, -1, &rect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SetTextColor(item->hDC, old_color);
    SetBkMode(item->hDC, old_mode);
}

/* Explicit user action only: open the adjacent native global-palette selector
 * (SHZTHEME.EXE). It owns its own window, registry profile and result reporting;
 * this app never auto-runs it, never writes its profile, and does not wait for it. */
static void launch_global_selector(void)
{
    char path[MAX_PATH], command[MAX_PATH + 3];
    const char name[] = "SHZTHEME.EXE";
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD length = GetModuleFileNameA(NULL, path, sizeof(path)), i, k, attr;
    char text[160];
    if (!length || length >= sizeof(path)) {
        set_status("Global palette selector: this program's folder could not be determined.");
        return;
    }
    i = length;
    while (i && path[i-1] != '\\' && path[i-1] != '/') --i;
    if (!i || i + sizeof(name) > sizeof(path)) {
        set_status("Global palette selector: path is invalid or too long.");
        return;
    }
    for (k = 0; k < sizeof(name); ++k) path[i+k] = name[k];
    attr = GetFileAttributesA(path);
    if (attr == 0xFFFFFFFFu || (attr & FILE_ATTRIBUTE_DIRECTORY)) {
        set_status("SHZTHEME.EXE was not found next to this program; global palette unchanged.");
        return;
    }
    length = i + (DWORD)sizeof(name) - 1;
    command[0] = '"';
    for (k = 0; k < length; ++k) command[k+1] = path[k];
    command[length+1] = '"';
    command[length+2] = 0;
    for (k = 0; k < sizeof(startup); ++k) ((char *)&startup)[k] = 0;
    startup.cb = sizeof(startup);
    if (!CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
        wsprintfA(text, "SHZTHEME.EXE could not be started (error %lu); global palette unchanged.",
                  (unsigned long)GetLastError());
        set_status(text);
        return;
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);
    set_status("Global palette selector opened. It reports its own result; nothing is changed here.");
}

static void sync_choice(HWND window)
{
    CheckRadioButton(window, ID_CLASSIC, ID_SHIZUKUOS,
                     selected == STYLE_SHIZUKUOS ? ID_SHIZUKUOS : ID_CLASSIC);
}

/* Returns 1 when the choice is persisted or there is truthfully nothing to persist. */
static int apply_selection(void)
{
    if (!provider_ok) {
        if (selected == STYLE_CLASSIC) {
            set_status("Classic is the native Windows98 appearance; nothing to save.");
            return 1;
        }
        set_status(provider_error);
        return 0;
    }
    if (FAILED(save_profile(selected))) {
        set_status("The theme setting could not be saved.");
        return 0;
    }
    saved = selected;
    set_status("Theme saved. Explorer remains your shell.");
    return 1;
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wp, LPARAM lp)
{
    if (message == WM_CREATE) {
        HINSTANCE instance = GetModuleHandleA(NULL);
        HWND group = CreateWindowExA(0, "BUTTON", "Appearance scheme", WS_CHILD | WS_VISIBLE |
            BS_GROUPBOX, 16, 12, 344, 74, window, (HMENU)(ULONG_PTR)ID_GROUP, instance, NULL);
        classic_choice = CreateWindowExA(0, "BUTTON", "Windows Classic", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON, 28, 34, 150, 24,
            window, (HMENU)(ULONG_PTR)ID_CLASSIC, instance, NULL);
        shizukuos_choice = CreateWindowExA(0, "BUTTON", "ShizukuOS", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | BS_AUTORADIOBUTTON | (provider_ok ? 0 : WS_DISABLED), 190, 34, 150, 24,
            window, (HMENU)(ULONG_PTR)ID_SHIZUKUOS, instance, NULL);
        global_button = CreateWindowExA(0, "BUTTON", "Global palette settings...", WS_CHILD |
            WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_PUSHBUTTON, 16, 144, 344, 26,
            window, (HMENU)(ULONG_PTR)ID_GLOBAL, instance, NULL);
        ok_button = CreateWindowExA(0, "BUTTON", "OK", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | WS_GROUP | BS_OWNERDRAW, 100, 216, 80, 26,
            window, (HMENU)(ULONG_PTR)ID_OK, instance, NULL);
        close_button = CreateWindowExA(0, "BUTTON", "Cancel", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | BS_OWNERDRAW, 188, 216, 80, 26,
            window, (HMENU)(ULONG_PTR)ID_CLOSE, instance, NULL);
        apply_button = CreateWindowExA(0, "BUTTON", "Apply", WS_CHILD | WS_VISIBLE |
            WS_TABSTOP | BS_OWNERDRAW, 276, 216, 80, 26,
            window, (HMENU)(ULONG_PTR)ID_APPLY, instance, NULL);
        if (!group || !classic_choice || !shizukuos_choice || !global_button || !ok_button ||
            !apply_button || !close_button) return -1;
        sync_choice(window);
        return 0;
    }
    if (message == WM_COMMAND) {
        unsigned id = LOWORD(wp);
        if (id == IDOK) {
            HWND focus = GetFocus();
            id = focus == close_button ? ID_CLOSE : focus == apply_button ? ID_APPLY : ID_OK;
        }
        if (id == IDCANCEL) id = ID_CLOSE;
        if ((id == ID_CLASSIC || id == ID_SHIZUKUOS) && HIWORD(wp) == BN_CLICKED) {
            DWORD choice = id == ID_CLASSIC ? STYLE_CLASSIC : STYLE_SHIZUKUOS;
            if (!provider_ok) {
                /* Classic is native; ShizukuOS radio is disabled in this state. */
                selected = STYLE_CLASSIC;
                set_status(choice == STYLE_CLASSIC ? "Native Classic selected." : provider_error);
            } else if (SUCCEEDED(set_style(choice))) {
                selected = choice;
                set_status("Previewing in this window. Select Apply to save.");
                SendMessageA(window, WM_THEMECHANGED, 0, 0);
            } else {
                set_status("This theme could not be opened.");
            }
            sync_choice(window);
            redraw(window);
            return 0;
        }
        if (id == ID_GLOBAL && HIWORD(wp) == BN_CLICKED) {
            launch_global_selector();
            redraw(window);
            return 0;
        }
        if (id == ID_APPLY && HIWORD(wp) == BN_CLICKED) {
            apply_selection();
            redraw(window);
            return 0;
        }
        if (id == ID_OK && HIWORD(wp) == BN_CLICKED) {
            if (apply_selection()) DestroyWindow(window);
            else redraw(window);
            return 0;
        }
        if (id == ID_CLOSE) {
            /* Cancel discards an unsaved process-local preview. */
            if (provider_ok && saved && selected != saved) set_style(saved);
            DestroyWindow(window);
            return 0;
        }
    }
    if (message == WM_CLOSE) {
        SendMessageA(window, WM_COMMAND, ID_CLOSE, 0);
        return 0;
    }
    if (message == WM_DRAWITEM) {
        const DRAWITEMSTRUCT *item = (const DRAWITEMSTRUCT *)lp;
        int state;
        const char *label;
        LPCWSTR wide;
        if (!item || item->CtlType != ODT_BUTTON ||
            (item->CtlID != ID_APPLY && item->CtlID != ID_CLOSE && item->CtlID != ID_OK))
            return DefWindowProcA(window, message, wp, lp);
        label = item->CtlID == ID_APPLY ? "Apply" : item->CtlID == ID_OK ? "OK" : "Cancel";
        wide = item->CtlID == ID_APPLY ? L"Apply" : item->CtlID == ID_OK ? L"OK" : L"Cancel";
        state = item->itemState & ODS_DISABLED ? 4 : item->itemState & ODS_SELECTED ? 3 : 1;
        if (!(provider_ok && selected == STYLE_SHIZUKUOS &&
              paint_part(item->hDC, L"BUTTON", 1, state, &item->rcItem, wide)))
            paint_native_button(item, label);
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
        RECT note = {16, 96, 360, 140}, hint = {16, 176, 360, 212};
        int old_mode = SetBkMode(dc, TRANSPARENT);
        COLORREF old_color = SetTextColor(dc, GetSysColor(COLOR_BTNTEXT));
        DrawTextA(dc, provider_ok ?
            "Explorer keeps the taskbar and desktop in both schemes. These choices affect only applications that use the theme provider, not the whole desktop; use Global palette settings for system colors." :
            "Explorer keeps the taskbar and desktop. Windows Classic is native; the ShizukuOS provider scheme is unavailable (see below). Global palette settings are separate.",
            -1, &note, DT_WORDBREAK);
        DrawTextA(dc, status_text, -1, &hint, DT_WORDBREAK);
        SetBkMode(dc, old_mode);
        SetTextColor(dc, old_color);
        EndPaint(window, &paint);
        return 0;
    }
    if (message == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcA(window, message, wp, lp);
}

static void provider_fail(const char *what, DWORD code)
{
    wsprintfA(provider_error, "ShizukuOS theme provider unavailable: %s (error %lu).",
              what, (unsigned long)code);
}

static int load_provider(void)
{
    char path[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, path, sizeof(path)), i;
    const char name[] = "M98THEME.DLL";
    if (!length || length >= sizeof(path)) { provider_fail("module path", GetLastError()); return 0; }
    i = length;
    while (i && path[i-1] != '\\' && path[i-1] != '/') --i;
    if (!i || i + sizeof(name) > sizeof(path)) { provider_fail("module path", ERROR_BAD_PATHNAME); return 0; }
    for (length = 0; length < sizeof(name); ++length) path[i+length] = name[length];
    provider = LoadLibraryA(path);
    if (!provider) { provider_fail("M98THEME.DLL not loadable", GetLastError()); return 0; }
#define RESOLVE(v,n,t) do { v = (t)(void *)GetProcAddress(provider,n); \
    if (!v) { provider_fail("missing export " n, GetLastError()); return 0; } } while (0)
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
    selected = STYLE_CLASSIC;
    provider_ok = load_provider();
    if (!provider_ok && provider) { FreeLibrary(provider); provider = NULL; }
    if (provider_ok) {
        if (FAILED(load_profile())) {
            set_status("The saved theme could not be read. Select Apply to replace it.");
            if (FAILED(set_style(STYLE_SHIZUKUOS))) {
                provider_fail("provider refused the ShizukuOS style", ERROR_GEN_FAILURE);
                provider_ok = 0;
                FreeLibrary(provider); provider = NULL;
            } else selected = STYLE_SHIZUKUOS;
        } else {
            selected = get_style();
            saved = selected;
            if (selected != STYLE_SHIZUKUOS) selected = STYLE_CLASSIC;
        }
    } else {
        set_status(provider_error);
    }
    klass.lpfnWndProc = window_proc;
    klass.hInstance = GetModuleHandleA(NULL);
    klass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    klass.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    klass.lpszClassName = "ShizukuOS.Appearance";
    if (!RegisterClassA(&klass)) { if (provider) FreeLibrary(provider); ExitProcess(3); }
    window = CreateWindowExA(0, klass.lpszClassName, "ShizukuOS Appearance",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 384, 292, NULL, NULL, klass.hInstance, NULL);
    if (!window) { UnregisterClassA(klass.lpszClassName, klass.hInstance); if (provider) FreeLibrary(provider); ExitProcess(4); }
    ShowWindow(window, SW_SHOWNORMAL);
    UpdateWindow(window);
    SetFocus(selected == STYLE_SHIZUKUOS ? shizukuos_choice : classic_choice);
    while ((next = GetMessageA(&message, NULL, 0, 0)) > 0)
        if (!IsDialogMessageA(window, &message)) {
            TranslateMessage(&message);
            DispatchMessageA(&message);
        }
    if (next < 0) { DestroyWindow(window); code = 5; }
    UnregisterClassA(klass.lpszClassName, klass.hInstance);
    if (provider) FreeLibrary(provider);
    ExitProcess((UINT)code);
}
