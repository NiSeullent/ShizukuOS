/* SPDX-License-Identifier: GPL-2.0-only
 * Interactive acceptance probe for an explicitly loaded, app-local provider.
 * A build or a log alone is not evidence of visible Windows 98 scanout.
 * Run with a fresh runner-generated --nonce=<32 lowercase hex characters>.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>

#define CLIENT_WIDTH 456
#define CLIENT_HEIGHT 264
#define RUN_MILLISECONDS 30000u
#ifndef WM_THEMECHANGED
#define WM_THEMECHANGED 0x031Au
#endif

typedef HANDLE theme_handle;
typedef HRESULT (WINAPI *style_function)(DWORD);
typedef theme_handle (WINAPI *open_function)(HWND, LPCWSTR);
typedef HRESULT (WINAPI *close_function)(theme_handle);
typedef HRESULT (WINAPI *background_function)(theme_handle, HDC, int, int,
                                             const RECT *, const RECT *);
typedef HRESULT (WINAPI *text_function)(theme_handle, HDC, int, int, LPCWSTR,
                                       int, DWORD, DWORD, const RECT *);

static style_function set_style;
static open_function open_theme;
static close_function close_theme;
static background_function draw_background;
static text_function draw_text;
static theme_handle button_theme, window_theme;
static HANDLE logfile = INVALID_HANDLE_VALUE;
static HWND main_window;
static DWORD selected_style, switches, paints[3];
static int failed, io_failed, cleanup_failed, closing, paint_event_sent;
static char run_nonce[33], provider_path[MAX_PATH];
static const char window_class_name[] = "M98ThemeInteractiveProbe";
static const RECT classic_control = {12, 136, 216, 184};
static const RECT modern_control = {228, 136, 432, 184};

static void log_text(const char *text)
{
    DWORD length = 0, written = 0;
    while (text[length]) ++length;
    if (logfile == INVALID_HANDLE_VALUE ||
        !WriteFile(logfile, text, length, &written, NULL) || written != length)
        io_failed = 1;
}

static void log_number(const char *name, DWORD value)
{
    char digits[11];
    unsigned count = 0, i;
    log_text(name);
    do { digits[count++] = (char)('0' + value % 10u); value /= 10u; } while (value);
    for (i = 0; i < count / 2u; ++i) {
        char digit = digits[i];
        digits[i] = digits[count - i - 1u]; digits[count - i - 1u] = digit;
    }
    digits[count] = 0; log_text(digits); log_text("\r\n");
}

static void record_failure(const char *stage, HRESULT result)
{
    static const char hex[] = "0123456789abcdef";
    char code[9];
    DWORD value = (DWORD)result;
    unsigned i;
    failed = 1;
    log_text("FAIL_STAGE="); log_text(stage); log_text("\r\nHRESULT=0x");
    for (i = 0; i < 8u; ++i) code[i] = hex[(value >> (28u - 4u * i)) & 15u];
    code[8] = 0; log_text(code); log_text("\r\n");
}

static void record_native_failure(const char *stage)
{
    DWORD error = GetLastError();
    record_failure(stage, HRESULT_FROM_WIN32(error ? error : ERROR_INVALID_HANDLE));
}

static void record_cleanup_failure(const char *stage, HRESULT result)
{
    cleanup_failed = 1; record_failure(stage, result);
}

static int read_nonce(void)
{
    static const char option[] = "--nonce=";
    const char *cursor = GetCommandLineA();
    unsigned i;
    if (!cursor || !*cursor) return 0;
    if (*cursor == '"') {
        ++cursor;
        while (*cursor && *cursor != '"') ++cursor;
        if (!*cursor) return 0;
        ++cursor;
    } else {
        while (*cursor && *cursor != ' ' && *cursor != '\t') ++cursor;
    }
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    for (i = 0; option[i]; ++i) {
        if (*cursor != option[i]) return 0;
        ++cursor;
    }
    for (i = 0; i < 32u; ++i) {
        char character = *cursor++;
        if (!((character >= '0' && character <= '9') ||
              (character >= 'a' && character <= 'f'))) return 0;
        run_nonce[i] = character;
    }
    run_nonce[32] = 0;
    while (*cursor == ' ' || *cursor == '\t') ++cursor;
    return *cursor == 0;
}

static int local_path(const char *executable, const char *name, char *output)
{
    unsigned length = 0, directory = 0, i;
    while (executable[length]) {
        if (executable[length] == '\\' || executable[length] == '/') directory = length + 1u;
        ++length;
    }
    if (!directory) return 0;
    for (i = 0; i < directory; ++i) output[i] = executable[i];
    for (i = 0; name[i]; ++i) {
        if (directory + i >= MAX_PATH - 1u) return 0;
        output[directory + i] = name[i];
    }
    output[directory + i] = 0; return 1;
}

static int same_path(const char *first, const char *second)
{
    while (*first || *second) {
        char a = *first++, b = *second++;
        if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
        if (a == '/') a = '\\';
        if (b == '/') b = '\\';
        if (a != b) return 0;
    }
    return 1;
}

static int close_handles(int cleanup)
{
    HRESULT result;
    int success = 1;
    if (button_theme) {
        result = close_theme(button_theme);
        if (result == S_OK) button_theme = NULL;
        else {
            if (cleanup) record_cleanup_failure("CloseThemeData(BUTTON)", result);
            else record_failure("CloseThemeData(BUTTON)", result);
            success = 0;
        }
    }
    if (window_theme) {
        result = close_theme(window_theme);
        if (result == S_OK) window_theme = NULL;
        else {
            if (cleanup) record_cleanup_failure("CloseThemeData(WINDOW)", result);
            else record_failure("CloseThemeData(WINDOW)", result);
            success = 0;
        }
    }
    return success;
}

static int select_style(DWORD requested)
{
    HRESULT result;
    if (failed || io_failed) return 0;
    if (requested == selected_style) return 1;
    result = set_style(requested);
    if (result != S_OK) { record_failure("M98SetThemeStyle", result); return 0; }
    /* Older handles are invalid for drawing but must still be explicitly closed. */
    selected_style = requested;
    if (!close_handles(0)) return 0;
    window_theme = open_theme(NULL, L"WINDOW");
    if (!window_theme) { record_native_failure("OpenThemeData(WINDOW)"); return 0; }
    button_theme = open_theme(NULL, L"BUTTON");
    if (!button_theme) { record_native_failure("OpenThemeData(BUTTON)"); return 0; }
    ++switches; paint_event_sent = 0;
    log_text(requested == 1u ? "SELECTED_STYLE=CLASSIC\r\n" : "SELECTED_STYLE=MODERN\r\n");
    log_number("SELECT_SWITCH=", switches);
    SendMessageA(main_window, WM_THEMECHANGED, 0, 0);
    if (!InvalidateRect(main_window, NULL, FALSE)) {
        record_native_failure("InvalidateRect(style)"); return 0;
    }
    return !io_failed;
}

static int paint_part(HDC dc, theme_handle theme, int part, int state,
                      const RECT *rectangle, LPCWSTR label, DWORD flags)
{
    HRESULT result = draw_background(theme, dc, part, state, rectangle, NULL);
    if (result != S_OK) { record_failure("DrawThemeBackground", result); return 0; }
    result = draw_text(theme, dc, part, state, label, -1, flags, 0, rectangle);
    if (result != S_OK) { record_failure("DrawThemeText", result); return 0; }
    return 1;
}

static int paint_scene(HDC dc)
{
    static const WCHAR *labels[4] = {L"Normal", L"Hot", L"Pressed", L"Disabled"};
    const DWORD centered = DT_CENTER | DT_VCENTER | DT_SINGLELINE;
    RECT client, caption = {12, 12, 444, 48}, footer = {12, 200, 444, 252};
    unsigned i;
    HRESULT result;
    if (!button_theme || !window_theme || (selected_style != 1u && selected_style != 2u)) {
        record_failure("theme-handles-not-ready", E_HANDLE); return 0;
    }
    if (!GetClientRect(main_window, &client) ||
        !FillRect(dc, &client, (HBRUSH)(COLOR_BTNFACE + 1))) {
        record_native_failure("GetClientRect/FillRect"); return 0;
    }
    if (!paint_part(dc, window_theme, 1, 1, &caption,
                    selected_style == 1u ? L"Classic theme" : L"Modern theme", centered)) return 0;
    for (i = 0; i < 4u; ++i) {
        RECT button = {12 + (LONG)i * 108, 64, 108 + (LONG)i * 108, 116};
        if (!paint_part(dc, button_theme, 1, (int)i + 1, &button, labels[i], centered)) return 0;
    }
    if (!paint_part(dc, button_theme, 1, selected_style == 1u ? 3 : 1,
                    &classic_control, L"Classic (C)", centered) ||
        !paint_part(dc, button_theme, 1, selected_style == 2u ? 3 : 1,
                    &modern_control, L"Modern (M)", centered)) return 0;
    result = draw_text(button_theme, dc, 1, 1,
        L"Click a style, or press C / M. Esc closes.\nAutomatic switches at 10 and 20 seconds; closes at 30 seconds.",
        -1, DT_CENTER | DT_WORDBREAK, 0, &footer);
    if (result != S_OK) { record_failure("DrawThemeText(instructions)", result); return 0; }
    if (!GdiFlush()) { record_native_failure("GdiFlush(paint)"); return 0; }
    return 1;
}

static int inside(const RECT *rectangle, int x, int y)
{
    return x >= rectangle->left && x < rectangle->right &&
           y >= rectangle->top && y < rectangle->bottom;
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT painting;
        HDC dc = BeginPaint(window, &painting);
        int success = 0;
        if (!dc) record_native_failure("BeginPaint");
        else {
            if (!failed && !io_failed) success = paint_scene(dc);
            if (!EndPaint(window, &painting)) {
                record_native_failure("EndPaint"); success = 0;
            }
        }
        if (success) {
            ++paints[selected_style];
            if (!paint_event_sent) {
                log_text(selected_style == 1u ? "PAINT_EVENT=CLASSIC\r\n" : "PAINT_EVENT=MODERN\r\n");
                log_number("EVENT_SWITCH=", switches);
                paint_event_sent = 1;
            }
        }
        return 0;
    }
    case WM_ERASEBKGND: return 1;
    case WM_THEMECHANGED: return 0;
    case WM_KEYDOWN:
        if (wparam == 'C') select_style(1);
        else if (wparam == 'M') select_style(2);
        else if (wparam == VK_ESCAPE) closing = 1;
        return 0;
    case WM_LBUTTONUP: {
        int x = (int)(short)LOWORD(lparam), y = (int)(short)HIWORD(lparam);
        if (inside(&classic_control, x, y)) select_style(1);
        else if (inside(&modern_control, x, y)) select_style(2);
        return 0;
    }
    case WM_CLOSE: case WM_DESTROY: closing = 1; return 0;
    default: return DefWindowProcA(window, message, wparam, lparam);
    }
}

void mainCRTStartup(void)
{
    char executable[MAX_PATH], expected_provider[MAX_PATH], log_path[MAX_PATH];
    DWORD length, start = 0, last_repaint = 0;
    HMODULE provider = NULL;
    HINSTANCE instance = GetModuleHandleA(NULL);
    OSVERSIONINFOA version = {0};
    WNDCLASSA window_class = {0};
    RECT rectangle = {0, 0, CLIENT_WIDTH, CLIENT_HEIGHT};
    const DWORD window_style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    ATOM registered = 0;
    int identified = 0, provider_local = 0, auto_modern = 0, auto_classic = 0;
    HRESULT result;
    if (!read_nonce()) ExitProcess(2);
    length = GetModuleFileNameA(NULL, executable, MAX_PATH);
    if (!length || length >= MAX_PATH ||
        !local_path(executable, "M98THEME.DLL", expected_provider) ||
        !local_path(executable, "THEME.LOG", log_path)) ExitProcess(2);
    logfile = CreateFileA(log_path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (logfile == INVALID_HANDLE_VALUE) ExitProcess(2);
    log_text("NTTHGUI_LOG_VERSION=1\r\nBEGIN_NONCE="); log_text(run_nonce);
    log_text("\r\nSCOPE=app-local native GDI theme; separate visible capture required\r\n");
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) { record_native_failure("GetVersionExA"); goto cleanup; }
    log_number("OS_PLATFORM=", version.dwPlatformId);
    log_number("OS_MAJOR=", version.dwMajorVersion);
    log_number("OS_MINOR=", version.dwMinorVersion);
    identified = version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
                 version.dwMajorVersion == 4u && version.dwMinorVersion == 10u;
    if (!identified) { record_failure("native-Windows-98-required", E_FAIL); goto cleanup; }
    provider = LoadLibraryA(expected_provider);
    if (!provider) { record_native_failure("LoadLibraryA(app-local-provider)"); goto cleanup; }
    length = GetModuleFileNameA(provider, provider_path, MAX_PATH);
    if (!length || length >= MAX_PATH) {
        provider_path[0] = 0; record_native_failure("GetModuleFileNameA(provider)"); goto cleanup;
    }
    if (!same_path(expected_provider, provider_path)) {
        record_failure("provider-path-mismatch", E_FAIL); goto cleanup;
    }
    provider_local = 1;
#define RESOLVE(variable, type, name) do { \
    variable = (type)(void *)GetProcAddress(provider, name); \
    if (!variable) { record_native_failure("GetProcAddress(" name ")"); goto cleanup; } \
} while (0)
    RESOLVE(set_style, style_function, "M98SetThemeStyle");
    RESOLVE(open_theme, open_function, "OpenThemeData");
    RESOLVE(close_theme, close_function, "CloseThemeData");
    RESOLVE(draw_background, background_function, "DrawThemeBackground");
    RESOLVE(draw_text, text_function, "DrawThemeText");
#undef RESOLVE
    window_class.lpfnWndProc = window_proc; window_class.hInstance = instance;
    window_class.hCursor = LoadCursorA(NULL, IDC_ARROW);
    if (!window_class.hCursor) { record_native_failure("LoadCursorA"); goto cleanup; }
    window_class.lpszClassName = window_class_name;
    registered = RegisterClassA(&window_class);
    if (!registered) { record_native_failure("RegisterClassA"); goto cleanup; }
    if (!AdjustWindowRect(&rectangle, window_style, FALSE)) {
        record_native_failure("AdjustWindowRect"); goto cleanup;
    }
    main_window = CreateWindowExA(0, window_class_name, "Win98 app-local theme probe",
        window_style, 24, 24, rectangle.right - rectangle.left, rectangle.bottom - rectangle.top,
        NULL, NULL, instance, NULL);
    if (!main_window) { record_native_failure("CreateWindowExA"); goto cleanup; }
    if (!select_style(1)) goto cleanup;
    ShowWindow(main_window, SW_SHOWNORMAL);
    if (!UpdateWindow(main_window)) { record_native_failure("UpdateWindow"); goto cleanup; }
    start = GetTickCount(); last_repaint = start;
    /* Bounded wall clock and message batches; a hung native call still needs
     * the external guest supervisor's deadline. GetTickCount wrap is safe. */
    while (!closing && !failed && !io_failed &&
           (DWORD)(GetTickCount() - start) < RUN_MILLISECONDS) {
        MSG message;
        DWORD now = GetTickCount(), elapsed = now - start;
        unsigned batch = 0;
        if (!auto_modern && elapsed >= 10000u) {
            auto_modern = 1; if (!select_style(2)) break;
        }
        if (!auto_classic && elapsed >= 20000u) {
            auto_classic = 1; if (!select_style(1)) break;
        }
        while (batch++ < 32u && PeekMessageA(&message, NULL, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) { closing = 1; break; }
            TranslateMessage(&message); DispatchMessageA(&message);
            if (closing || failed || io_failed) break;
        }
        if (!closing && !failed && !io_failed && (DWORD)(now - last_repaint) >= 250u) {
            last_repaint = now;
            if (!InvalidateRect(main_window, NULL, FALSE)) record_native_failure("InvalidateRect(refresh)");
        }
        Sleep(10);
    }
    if (!failed && (!paints[1] || !paints[2] || switches < 2u))
        record_failure("both-styles-not-painted", E_FAIL);
cleanup:
    if (close_theme) close_handles(1);
    if (set_style) {
        result = set_style(0);
        if (result != S_OK) record_cleanup_failure("M98SetThemeStyle(disable)", result);
    }
    if (main_window && !DestroyWindow(main_window)) {
        cleanup_failed = 1; record_native_failure("DestroyWindow");
    }
    main_window = NULL;
    if (registered && !UnregisterClassA(window_class_name, instance)) {
        cleanup_failed = 1; record_native_failure("UnregisterClassA");
    }
    if (provider && !FreeLibrary(provider)) {
        cleanup_failed = 1; record_native_failure("FreeLibrary");
    }
    /* These final fields occur exactly once; RESULT is the final log line.
     * External exit status is required because closing the log can still fail. */
    log_text("RUN_NONCE="); log_text(run_nonce); log_text("\r\nPROVIDER_PATH=");
    log_text(provider_path); log_text("\r\n");
    log_number("DLL_LOCAL=", (DWORD)provider_local);
    log_number("WIN98_IDENTIFIED=", (DWORD)identified);
    log_number("CLASSIC_PAINTS=", paints[1]); log_number("MODERN_PAINTS=", paints[2]);
    log_number("SWITCHES=", switches);
    log_text(cleanup_failed ? "CLEANUP=FAIL\r\n" : "CLEANUP=PASS\r\n");
    log_text(failed || io_failed ? "RESULT=FAIL\r\n" : "RESULT=PASS\r\n");
    if (!FlushFileBuffers(logfile)) io_failed = 1;
    if (!CloseHandle(logfile)) io_failed = 1;
    ExitProcess(io_failed ? 2u : failed ? 1u : 0u);
}
