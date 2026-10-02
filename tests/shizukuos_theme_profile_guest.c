/* SPDX-License-Identifier: GPL-2.0-only
 * Native profile/DIB probe. A build is not evidence of guest execution.
 */
#ifndef M98_PROFILE_HELPERS_ONLY
/* MinGW's stddef.h loads _mingw.h, so select SDK declarations before it.
 * This header target does not change the exact native Win98 runtime guard.
 */
#define WIN32_LEAN_AND_MEAN
#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
#define _WIN32_WINNT 0x0600
#endif
#include <stddef.h>
#include <stdint.h>

#define M98P_COMMAND_CAPACITY 512u
enum m98p_mode { M98P_INVALID, M98P_DEFAULT, M98P_SAVE_CLASSIC,
                M98P_CHECK_CLASSIC, M98P_SAVE_SHIZUKUOS, M98P_CHECK_SHIZUKUOS };

static enum m98p_mode m98p_parse_mode(const char *command)
{
    static const char *names[] = { "default-shizukuos", "save-classic", "check-classic",
                                  "save-shizukuos", "check-shizukuos" };
    size_t length = 0, p = 0, start, end, i, j;
    if (!command) return M98P_INVALID;
    while (length < M98P_COMMAND_CAPACITY && command[length]) {
        unsigned char c = (unsigned char)command[length];
        if (c < 32 && c != '\t') return M98P_INVALID;
        ++length;
    }
    if (!length || length == M98P_COMMAND_CAPACITY) return M98P_INVALID;
    while (p < length && (command[p] == ' ' || command[p] == '\t')) ++p;
    start = p;
    if (p < length && command[p] == '"') {
        start = ++p;
        while (p < length && command[p] != '"') ++p;
        if (p == start || p == length) return M98P_INVALID;
        ++p;
        if (p == length || (command[p] != ' ' && command[p] != '\t')) return M98P_INVALID;
    } else {
        while (p < length && command[p] != ' ' && command[p] != '\t') {
            if (command[p] == '"') return M98P_INVALID;
            ++p;
        }
        if (p == start) return M98P_INVALID;
    }
    while (p < length && (command[p] == ' ' || command[p] == '\t')) ++p;
    start = p;
    while (p < length && command[p] != ' ' && command[p] != '\t') ++p;
    end = p;
    while (p < length && (command[p] == ' ' || command[p] == '\t')) ++p;
    if (p != length || end == start) return M98P_INVALID;
    for (i = 0; i < 5; ++i) {
        for (j = 0; start + j < end && names[i][j] && command[start + j] == names[i][j]; ++j) {}
        if (start + j == end && !names[i][j]) return (enum m98p_mode)(i + 1);
    }
    return M98P_INVALID;
}
static int m98p_win98(uint32_t platform, uint32_t major, uint32_t minor)
{ return platform == 1u && major == 4u && minor == 10u; }
static int m98p_save_allowed(enum m98p_mode mode, uint32_t platform,
                             uint32_t major, uint32_t minor)
{ return (mode == M98P_SAVE_CLASSIC || mode == M98P_SAVE_SHIZUKUOS) && m98p_win98(platform, major, minor); }
static int m98p_adjacent(const char *executable, char *destination, size_t capacity)
{
    static const char dll[] = "M98THEME.DLL";
    size_t length = 0, separator = 2, part = 3, i;
    if (!executable || !destination) return 0;
    while (length < 260u && executable[length]) ++length;
    if (length < 4u || length == 260u || executable[1] != ':' || executable[2] != '\\' ||
        !((executable[0] >= 'A' && executable[0] <= 'Z') || (executable[0] >= 'a' && executable[0] <= 'z'))) return 0;
    for (i = 3; i <= length; ++i) {
        unsigned char c = (unsigned char)executable[i];
        if (c && (c < 32 || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')) return 0;
        if (!c || c == '\\') {
            size_t n = i - part;
            if (!n || (n == 1 && executable[part] == '.') ||
                (n == 2 && executable[part] == '.' && executable[part + 1] == '.')) return 0;
            if (c) { separator = i; part = i + 1; }
        }
    }
    if (separator + 1u + sizeof(dll) > capacity) return 0;
    for (i = 0; i <= separator; ++i) destination[i] = executable[i];
    for (i = 0; i < sizeof(dll); ++i) destination[separator + 1u + i] = dll[i];
    return 1;
}
static int m98p_same_path(const char *a, const char *b)
{
    size_t i;
    if (!a || !b) return 0;
    for (i = 0; i < 260u; ++i) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'a' && x <= 'z') x -= 'a' - 'A';
        if (y >= 'a' && y <= 'z') y -= 'a' - 'A';
        if (x == '/') x = '\\';
        if (y == '/') y = '\\';
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 0;
}

#ifndef M98_PROFILE_HELPERS_ONLY
#include <windows.h>
#include <uxtheme.h>
#include <vssym32.h>
#ifndef M98_PROFILE_NONCE
#error Build with a frozen M98_PROFILE_NONCE
#endif

typedef HRESULT (WINAPI *load_fn)(void);
typedef HRESULT (WINAPI *save_fn)(DWORD);
typedef DWORD (WINAPI *get_fn)(void);
typedef HTHEME (WINAPI *open_fn)(HWND, LPCWSTR);
typedef HRESULT (WINAPI *close_fn)(HTHEME);
typedef HRESULT (WINAPI *draw_fn)(HTHEME, HDC, int, int, const RECT *, const RECT *);
typedef HRESULT (WINAPI *color_fn)(HTHEME, int, int, int, COLORREF *);
_Static_assert(__builtin_types_compatible_p(open_fn, __typeof__(&OpenThemeData)), "OpenThemeData ABI");
_Static_assert(__builtin_types_compatible_p(close_fn, __typeof__(&CloseThemeData)), "CloseThemeData ABI");
_Static_assert(__builtin_types_compatible_p(draw_fn, __typeof__(&DrawThemeBackground)), "DrawThemeBackground ABI");
_Static_assert(__builtin_types_compatible_p(color_fn, __typeof__(&GetThemeColor)), "GetThemeColor ABI");

static HANDLE output;
static int log_ok = 1, failed;
static unsigned checks;
static HMODULE provider;
static HKEY registry_key;
static HDC screen, memory;
static HBITMAP bitmap;
static HGDIOBJ previous;
static int selected_bitmap;
static HTHEME button, window_theme;
static open_fn open_theme;
static close_fn close_theme;
static draw_fn draw;
static color_fn color;
static const char key_name[] = "Software\\ShizukuOS\\Appearance";

static void say(const char *text)
{
    DWORD length = 0, written;
    while (text[length]) ++length;
    while (log_ok && length) {
        if (!WriteFile(output, text, length, &written, NULL) || !written || written > length) { log_ok = 0; return; }
        text += written; length -= written;
    }
}
static void number(const char *name, DWORD value)
{
    char text[11]; unsigned p = 10;
    text[p] = 0;
    do { text[--p] = (char)('0' + value % 10u); value /= 10u; } while (value);
    say(name); say(text + p); say("\r\n");
}
static int check(int condition, const char *name)
{
    if (!condition) { failed = 1; say("FAIL_STAGE="); say(name); say("\r\n"); return 0; }
    ++checks; say("CHECK="); say(name); say("\r\n");
    return log_ok;
}
#define NEED(c, label) do { if (!check(!!(c), (label))) goto cleanup; } while (0)

/* Independent typed readback: never creates/writes/deletes a registry value. */
static int profile(DWORD expected, int require_absent, int after_paint)
{
    HKEY acquired = NULL;
    DWORD type = 0, bytes = sizeof(DWORD), value = 0;
    LONG error = RegOpenKeyExA(HKEY_CURRENT_USER, key_name, 0, KEY_QUERY_VALUE, &acquired);
    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) {
        if (require_absent) number(after_paint ? "PROFILE_AFTER_ABSENT=" : "PROFILE_BEFORE_ABSENT=", 1);
        return check(require_absent, "typed-profile-key-absent");
    }
    if (!check(error == ERROR_SUCCESS, "typed-profile-open")) return 0;
    registry_key = acquired;
    if (!check(registry_key != NULL, "typed-profile-owned-key")) return 0;
    error = RegQueryValueExA(registry_key, "ThemeStyle", NULL, &type, (BYTE *)&value, &bytes);
    if (!check(RegCloseKey(registry_key) == ERROR_SUCCESS, "typed-profile-close")) return 0;
    registry_key = NULL;
    if (require_absent) {
        if (error == ERROR_FILE_NOT_FOUND) number(after_paint ? "PROFILE_AFTER_ABSENT=" : "PROFILE_BEFORE_ABSENT=", 1);
        return check(error == ERROR_FILE_NOT_FOUND, "typed-profile-value-absent");
    }
    number(after_paint ? "PROFILE_AFTER_TYPE=" : "PROFILE_BEFORE_TYPE=", type);
    number(after_paint ? "PROFILE_AFTER_BYTES=" : "PROFILE_BEFORE_BYTES=", bytes);
    number(after_paint ? "PROFILE_AFTER_VALUE=" : "PROFILE_BEFORE_VALUE=", value);
    return check(error == ERROR_SUCCESS && type == REG_DWORD && bytes == sizeof(DWORD) && value == expected,
                 "typed-profile-exact-DWORD");
}
static COLORREF rgb_value(uint32_t value)
{ return RGB((value >> 16) & 255u, (value >> 8) & 255u, value & 255u); }

static int pixels(const RECT *r, COLORREF border, COLORREF fill, const RECT *clip,
                  const uint32_t *gradient)
{
    int x, y;
    for (y = 0; y < 32; ++y) for (x = 0; x < 32; ++x) {
        COLORREF expected = RGB(0, 0, 0);
        int inside = x >= r->left && x < r->right && y >= r->top && y < r->bottom;
        if (clip && (x < clip->left || x >= clip->right || y < clip->top || y >= clip->bottom)) inside = 0;
        if (inside) {
            if (x == r->left || x == r->right - 1 || y == r->top || y == r->bottom - 1) expected = border;
            else expected = gradient ? rgb_value(gradient[x - r->left - 1]) : fill;
        }
        if (GetPixel(memory, x, y) != expected) return 0;
    }
    return 1;
}
static int painter(DWORD style)
{
    static const uint32_t cb[] = {0x808080u,0x000080u,0x000000u,0x808080u};
    static const uint32_t cf[] = {0xc0c0c0u,0xd4d0c8u,0xa0a0a0u,0xc0c0c0u};
    static const uint32_t sb[] = {0x3d7890u,0x40a5c5u,0x0e6680u,0xa6b6c3u};
    static const uint32_t sf[] = {0xedf5f9u,0xdceff7u,0xbedfeau,0xe8eef2u};
    static const uint32_t gradient[] = {0x102a43u,0x113a54u,0x124a66u,0x135b78u,0x146b8au,0x167c9cu};
    static const char *state_labels[] = {"button-state1-pixels","button-state2-pixels","button-state3-pixels","button-state4-pixels"};
    const uint32_t *b = style == 1 ? cb : sb, *f = style == 1 ? cf : sf;
    RECT rectangle = {2,2,10,10}, clip = {4,4,6,6}, caption = {2,2,10,6};
    COLORREF value; int state;
    for (state = 1; state <= 4; ++state) {
        if (!check(color(button,1,state,TMT_BORDERCOLOR,&value) == S_OK && value == rgb_value(b[state-1]), "literal-button-border") ||
            !check(color(button,1,state,TMT_FILLCOLOR,&value) == S_OK && value == rgb_value(f[state-1]), "literal-button-fill") ||
            !check(PatBlt(memory,0,0,32,32,BLACKNESS) && GdiFlush(), "clear-DIB") ||
            !check(draw(button,memory,1,state,&rectangle,NULL) == S_OK && GdiFlush(), "real-button-GDI-painter") ||
            !check(pixels(&rectangle,rgb_value(b[state-1]),rgb_value(f[state-1]),NULL,NULL),state_labels[state-1])) return 0;
    }
    if (!check(PatBlt(memory,0,0,32,32,BLACKNESS) && GdiFlush(), "clear-clipped-DIB") ||
        !check(draw(button,memory,1,1,&rectangle,&clip) == S_OK && GdiFlush(), "real-clipped-GDI-painter") ||
        !check(pixels(&rectangle,rgb_value(b[0]),rgb_value(f[0]),&clip,NULL), "clip-and-untouched-outside")) return 0;
    if (!check(color(window_theme,1,1,TMT_BORDERCOLOR,&value) == S_OK && value == rgb_value(style == 1 ? 0x000040u : 0x102a43u), "literal-caption-border") ||
        !check(PatBlt(memory,0,0,32,32,BLACKNESS) && GdiFlush(), "clear-caption-DIB") ||
        !check(draw(window_theme,memory,1,1,&caption,NULL) == S_OK && GdiFlush(), "real-caption-GDI-painter") ||
        !check(pixels(&caption,rgb_value(style == 1 ? 0x000040u : 0x102a43u),rgb_value(0x000080u),NULL,
                      style == 3 ? gradient : NULL), "literal-caption-gradient-or-Classic")) return 0;
    return 1;
}

void mainCRTStartup(void)
{
    static const char *names[] = {"invalid","default-shizukuos","save-classic","check-classic","save-shizukuos","check-shizukuos"};
    enum m98p_mode mode;
    OSVERSIONINFOA version = {0}; BITMAPINFO info = {0};
    char executable[MAX_PATH], adjacent[MAX_PATH], actual[MAX_PATH];
    DWORD length, wanted; void *bits = NULL; int cleanup_ok = 1;
    load_fn load_profile; save_fn save_profile; get_fn get_style;
    output = GetStdHandle(STD_OUTPUT_HANDLE);
    /* Refuse CON/pipe/bad file before any mode can persist a user setting. */
    if (!output || output == INVALID_HANDLE_VALUE ||
        GetFileType(output) != FILE_TYPE_DISK || !FlushFileBuffers(output)) ExitProcess(2);
    say("SHZTPRO_LOG_VERSION=1\r\nNONCE=" M98_PROFILE_NONCE "\r\nSCOPE=win98-only-profile-typed-HKCU-and-DIB\r\n");
    mode = m98p_parse_mode(GetCommandLineA());
    NEED(mode != M98P_INVALID, "one-exact-mode-required");
    say("MODE="); say(names[mode]); say("\r\n");
    wanted = mode == M98P_SAVE_CLASSIC || mode == M98P_CHECK_CLASSIC ? 1u : 3u;
    version.dwOSVersionInfoSize = sizeof(version);
    NEED(GetVersionExA(&version), "read-native-OS-identity");
    number("OS_PLATFORM=",version.dwPlatformId); number("OS_MAJOR=",version.dwMajorVersion);
    number("OS_MINOR=",version.dwMinorVersion); number("OS_BUILD_LOW=",LOWORD(version.dwBuildNumber));
    NEED(m98p_win98(version.dwPlatformId,version.dwMajorVersion,version.dwMinorVersion), "Windows98-required-before-registry-or-save");
    say("WIN98_IDENTIFIED=1\r\n");
    length = GetModuleFileNameA(NULL,executable,sizeof(executable));
    NEED(length && length < sizeof(executable) && m98p_adjacent(executable,adjacent,sizeof(adjacent)), "absolute-adjacent-provider-path");
    provider = LoadLibraryA(adjacent); NEED(provider, "load-real-adjacent-provider");
    length = GetModuleFileNameA(provider,actual,sizeof(actual));
    NEED(length && length < sizeof(actual) && m98p_same_path(adjacent,actual), "actual-loaded-provider-is-adjacent");
    say("PROVIDER_PATH="); say(actual); say("\r\nDLL_LOCAL=1\r\n");
#define RESOLVE(v,type,name) do { v=(type)(void *)GetProcAddress(provider,name); NEED(v != NULL,name); } while (0)
    RESOLVE(load_profile,load_fn,"ShizukuOSLoadUserTheme");
    RESOLVE(save_profile,save_fn,"ShizukuOSSaveUserTheme");
    RESOLVE(get_style,get_fn,"M98GetThemeStyle");
    RESOLVE(open_theme,open_fn,"OpenThemeData"); RESOLVE(close_theme,close_fn,"CloseThemeData");
    RESOLVE(draw,draw_fn,"DrawThemeBackground"); RESOLVE(color,color_fn,"GetThemeColor");
    NEED(get_style() == 0, "fresh-process-provider-begins-OFF");
    if (mode == M98P_SAVE_CLASSIC || mode == M98P_SAVE_SHIZUKUOS) {
        NEED(m98p_save_allowed(mode,version.dwPlatformId,version.dwMajorVersion,version.dwMinorVersion), "Win98-save-predicate");
        NEED(save_profile(wanted) == S_OK, "actual-explicit-profile-save");
        say("SAVE_CALLED=1\r\n");
        NEED(get_style() == 0, "Save-persists-only-does-not-apply");
    } else say("SAVE_CALLED=0\r\n");
    NEED(profile(wanted,mode == M98P_DEFAULT,0), "independent-profile-before-Load");
    NEED(load_profile() == S_OK && get_style() == wanted, "actual-Load-applies-exact-style");
    number("STYLE=",wanted);
    button = open_theme(NULL,L"BUTTON"); NEED(button, "open-real-button-theme");
    window_theme = open_theme(NULL,L"WINDOW"); NEED(window_theme, "open-real-window-theme");
    screen = GetDC(NULL); NEED(screen, "get-screen-DC");
    memory = CreateCompatibleDC(screen); NEED(memory, "create-memory-DC");
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth=32; info.bmiHeader.biHeight=-32;
    info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32; info.bmiHeader.biCompression=BI_RGB;
    bitmap = CreateDIBSection(screen,&info,DIB_RGB_COLORS,&bits,NULL,0);
    NEED(bitmap && bits, "create-native-32-bit-top-down-DIB");
    previous = SelectObject(memory,bitmap);
    selected_bitmap = previous != NULL && previous != HGDI_ERROR;
    NEED(selected_bitmap && GdiFlush(), "select-and-synchronize-native-DIB");
    NEED(painter(wanted), "all-literal-native-palette-and-DIB-oracles");
    NEED(profile(wanted,mode == M98P_DEFAULT,1), "independent-profile-after-paint");
cleanup:
    if (registry_key) { if (RegCloseKey(registry_key) != ERROR_SUCCESS) cleanup_ok=0; registry_key=NULL; }
    if (button) { if (!close_theme || close_theme(button) != S_OK) cleanup_ok=0; button=NULL; }
    if (window_theme) { if (!close_theme || close_theme(window_theme) != S_OK) cleanup_ok=0; window_theme=NULL; }
    if (selected_bitmap) { if (SelectObject(memory,previous) != bitmap) cleanup_ok=0; selected_bitmap=0; }
    if (bitmap) { if (!DeleteObject(bitmap)) cleanup_ok=0; bitmap=NULL; }
    if (memory) { if (!DeleteDC(memory)) cleanup_ok=0; memory=NULL; }
    if (screen) { if (!ReleaseDC(NULL,screen)) cleanup_ok=0; screen=NULL; }
    if (provider) { if (!FreeLibrary(provider)) cleanup_ok=0; provider=NULL; }
    number("CHECK_COUNT=",checks); say(cleanup_ok ? "CLEANUP=PASS\r\n" : "CLEANUP=FAIL\r\n");
    if (!cleanup_ok || !log_ok || !FlushFileBuffers(output)) failed=1;
    say(failed ? "RESULT=FAIL\r\n" : "RESULT=PASS\r\n");
    if (!log_ok || !FlushFileBuffers(output)) failed=1;
    ExitProcess(failed ? 1u : 0u);
}
#endif
