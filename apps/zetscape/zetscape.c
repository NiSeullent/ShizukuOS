/* Lightweight native x86 Win98 SE browser host for the genuine shared engine.
 * SPDX-License-Identifier: GPL-2.0-only
 * This file implements no replacement HTML/JavaScript renderer. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "zetscape_extensions.h"

#ifdef _WIN64
#error Zetscape requires a native x86 program
#endif

#define ID_ADDRESS 100
#define ID_GO 101
#define ID_BACK 102
#define ID_FORWARD 103
#define ID_RELOAD 104
#define ID_STOP 105
#define WM_LOAD_ENGINE (WM_APP + 1)
#define WM_ENGINE_NAVIGATION (WM_APP + 2)
#define CMD_REFRESH 22u
#define CMD_STOP 23u
#define ZET_PROVIDER "ZETWEB.DLL"

typedef struct PendingNavigation {
    struct PendingNavigation *next;
    size_t url_length, method_length, body_length, allocated_bytes;
    unsigned kind;
    int history_delta;
    char data[1];
} PendingNavigation;

typedef struct {
    HWND window, address, status, viewport, buttons[5];
    WNDPROC original_edit;
    HMODULE module;
    const IEWKEngineV1 *engine;
    const ZetscapeExtensionsV1 *extension;
    IEWKView *view;
    IEWKHostV1 callbacks;
    DWORD owner_thread;
    uint32_t navigation, completed_navigation;
    PendingNavigation *pending_head, *pending_tail;
    size_t pending_bytes;
    unsigned pending_count;
    BOOL closing, unloading, unload_pending, load_pending, layout_pending,
         focus_pending, navigation_posted, require_hardware;
} Browser;

static Browser *browser(HWND window)
{
    return (Browser *)(LONG_PTR)GetWindowLongA(window, GWL_USERDATA);
}

static void status(Browser *b, const char *text)
{
    if (!b->closing)
        SetWindowTextA(b->status, text);
}

static BOOL owner(Browser *b)
{
    return b && !b->closing && !b->unloading && !b->unload_pending &&
        b->owner_thread == GetCurrentThreadId();
}

static BOOL hash_text(const char *text)
{
    unsigned i;
    BOOL nonzero = FALSE;
    for (i = 0; i < 64; ++i) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return FALSE;
        if (c != '0') nonzero = TRUE;
    }
    return text[64] == 0 && nonzero;
}

static BOOL hardware_admitted(Browser *b)
{
    ZetscapeGraphicsV1 observed;
    ZeroMemory(&observed, sizeof(observed));
    observed.size = sizeof(observed);
    observed.abi = ZETSCAPE_EXTENSION_ABI;
    return b->extension && b->extension->graphics &&
        b->extension->graphics(b->view, &observed) == IEWK_OK &&
        observed.size >= sizeof(observed) && observed.abi == ZETSCAPE_EXTENSION_ABI &&
        (observed.flags & ZET_REQUIRED_HARDWARE) == ZET_REQUIRED_HARDWARE &&
        !(observed.flags & ZET_SOFTWARE_RENDERER) && observed.pci_vendor &&
        observed.pci_device && hash_text(observed.driver_sha256) &&
        observed.renderer_name[0] && observed.renderer_name[63] == 0;
}

static void layout(Browser *b)
{
    RECT r;
    unsigned i;
    int width, height, address_width;
    GetClientRect(b->window, &r);
    width = r.right; height = r.bottom;
    address_width = width > 400 ? width - 344 : 56;
    for (i = 0; i < 5; ++i)
        MoveWindow(b->buttons[i], 4 + (int)i * 54, 4, 50, 24, TRUE);
    MoveWindow(b->address, 278, 4, address_width, 24, TRUE);
    MoveWindow(GetDlgItem(b->window, ID_GO), 282 + address_width, 4, 54, 24, TRUE);
    MoveWindow(b->status, 4, height > 24 ? height - 22 : 0,
               width > 8 ? width - 8 : 0, 20, TRUE);
    MoveWindow(b->viewport, 0, 32, width, height > 56 ? height - 56 : 0, TRUE);
    if (owner(b) && b->view)
        b->engine->resize(b->view, 0, 0, width, height > 56 ? height - 56 : 0);
}

static void clear_pending(Browser *b)
{
    while (b->pending_head) {
        PendingNavigation *item = b->pending_head;
        b->pending_head = item->next;
        HeapFree(GetProcessHeap(), 0, item);
    }
    b->pending_tail = NULL;
    b->pending_count = 0;
    b->pending_bytes = 0;
    b->navigation_posted = FALSE;
}

static void unload(Browser *b)
{
    /* Provider calls and its child-window callbacks may pump nested messages.
     * Only the outer application loop may destroy the view or release its DLL. */
    b->unload_pending = TRUE;
    clear_pending(b);
}

static void unload_now(Browser *b)
{
    IEWKView *view = b->view;
    b->unloading = TRUE;
    b->view = NULL;
    clear_pending(b);
    if (view)
        b->engine->destroy(view); /* Quiesces all callbacks before DLL release. */
    b->engine = NULL; b->extension = NULL;
    if (b->module) FreeLibrary(b->module);
    b->module = NULL;
    b->unloading = FALSE;
    b->unload_pending = FALSE;
}

static void request(Browser *b, const char *url, size_t length,
                    const char *method, size_t method_length,
                    const void *body, size_t body_length)
{
    uint32_t id;
    int result;
    if (!owner(b) || !b->view || !url || !length || length > IEWK_URL_LIMIT ||
        !method || !method_length || (body_length && !body))
        return;
    if (b->navigation == 0xffffffffu) {
        status(b, "Restart Zetscape before further navigation.");
        return;
    }
    id = ++b->navigation;
    status(b, "Loading...");
    /* Parsing, canonicalization, origins, TLS and subresources belong to the
     * actual engine. Address-bar text never establishes an origin or lock. */
    result = b->engine->navigate(b->view, id, url, length,
                                method, method_length, body, body_length);
    if (result != IEWK_OK && owner(b) && id == b->navigation &&
        b->completed_navigation != id)
        status(b, "The page could not be opened.");
}

static void IEWK_CALL committed(void *context, uint32_t id, const char *url,
                                size_t length, const char *origin,
                                size_t origin_length, uint32_t security)
{
    Browser *b = (Browser *)context;
    WCHAR wide[IEWK_URL_LIMIT + 1];
    char ansi[IEWK_URL_LIMIT + 1];
    int count;
    (void)origin; (void)origin_length; (void)security;
    if (!owner(b) || id != b->navigation || !url || !length || length > IEWK_URL_LIMIT)
        return;
    b->completed_navigation = id;
    count = MultiByteToWideChar(CP_UTF8, 0, url, (int)length, wide, IEWK_URL_LIMIT);
    if (count > 0) {
        count = WideCharToMultiByte(CP_ACP, 0, wide, count, ansi, IEWK_URL_LIMIT, NULL, NULL);
        if (count > 0) { ansi[count] = 0; SetWindowTextA(b->address, ansi); }
    }
    status(b, "Ready");
}

static void IEWK_CALL title(void *context, const char *text, size_t length)
{
    Browser *b = (Browser *)context;
    WCHAR wide[256];
    char ansi[256];
    int count;
    if (!owner(b) || !text || !length || length > 255)
        return;
    count = MultiByteToWideChar(CP_UTF8, 0, text, (int)length, wide, 255);
    if (count > 0) {
        count = WideCharToMultiByte(CP_ACP, 0, wide, count, ansi, 255, NULL, NULL);
        if (count > 0) { ansi[count] = 0; SetWindowTextA(b->window, ansi); }
    }
}

static void IEWK_CALL failed(void *context, uint32_t id, int code,
                             const char *text, size_t length)
{
    Browser *b = (Browser *)context;
    (void)code; (void)text; (void)length;
    if (owner(b) && id == b->navigation) {
        b->completed_navigation = id;
        status(b, "The page could not be loaded.");
    }
}

static void IEWK_CALL navigation_requested(void *context, const char *url,
                                           size_t length, const char *method,
                                           size_t method_length,
                                           const void *body, size_t body_length)
{
    Browser *b = (Browser *)context;
    PendingNavigation *item;
    size_t bytes;
    if (!owner(b) || !url || !length || length > IEWK_URL_LIMIT ||
        !method || !method_length || method_length > 32 ||
        (body_length && !body) || b->pending_count >= 16 ||
        body_length > 16u * 1024u * 1024u ||
        body_length > (size_t)-1 - sizeof(*item) - length - method_length)
        return;
    bytes = sizeof(*item) + length + method_length + body_length;
    if (b->pending_bytes > 32u * 1024u * 1024u ||
        bytes > 32u * 1024u * 1024u - b->pending_bytes) {
        status(b, "The queued page data exceeds the available memory budget."); return;
    }
    item = (PendingNavigation *)HeapAlloc(GetProcessHeap(), 0, bytes);
    if (!item) { status(b, "There is not enough memory to open the page."); return; }
    item->next = NULL; item->kind = 0; item->allocated_bytes = bytes;
    item->url_length = length;
    item->method_length = method_length; item->body_length = body_length;
    CopyMemory(item->data, url, length);
    CopyMemory(item->data + length, method, method_length);
    if (body_length) CopyMemory(item->data + length + method_length, body, body_length);
    if (b->pending_tail) b->pending_tail->next = item;
    else b->pending_head = item;
    b->pending_tail = item; ++b->pending_count; b->pending_bytes += bytes;
    /* Borrowed engine callback data must be copied. Dispatch after return to
     * avoid recursively entering the provider's navigation implementation. */
    if (!b->navigation_posted) {
        b->navigation_posted = PostMessageA(b->window, WM_ENGINE_NAVIGATION, 0, 0);
        if (!b->navigation_posted) {
            clear_pending(b); status(b, "The page request could not be queued.");
        }
    }
}

static void address_go(Browser *b)
{
    char input[IEWK_URL_LIMIT + 1], utf8[IEWK_URL_LIMIT + 1];
    WCHAR wide[IEWK_URL_LIMIT + 1];
    int length, count;
    length = GetWindowTextA(b->address, input, sizeof(input));
    if (!length) return;
    count = MultiByteToWideChar(CP_ACP, 0, input, length, wide, IEWK_URL_LIMIT);
    if (count <= 0) { status(b, "The address could not be read."); return; }
    count = WideCharToMultiByte(CP_UTF8, 0, wide, count, utf8, IEWK_URL_LIMIT, NULL, NULL);
    if (count <= 0) { status(b, "The address is too long or invalid."); return; }
    navigation_requested(b, utf8, (size_t)count, "GET", 3, NULL, 0);
}

static void queue_command(Browser *b, unsigned kind, int delta)
{
    PendingNavigation *item;
    if (!owner(b) || !b->view || b->pending_count >= 16 ||
        b->pending_bytes > 32u * 1024u * 1024u - sizeof(*item)) return;
    item = (PendingNavigation *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*item));
    if (!item) { status(b, "There is not enough memory for the page request."); return; }
    item->kind = kind; item->history_delta = delta; item->allocated_bytes = sizeof(*item);
    if (b->pending_tail) b->pending_tail->next = item;
    else b->pending_head = item;
    b->pending_tail = item; ++b->pending_count; b->pending_bytes += sizeof(*item);
    if (!b->navigation_posted) {
        b->navigation_posted = PostMessageA(b->window, WM_ENGINE_NAVIGATION, 0, 0);
        if (!b->navigation_posted) clear_pending(b);
    }
}

static BOOL provider_path(char path[MAX_PATH])
{
    DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
    DWORD i;
    if (!length || length >= MAX_PATH) return FALSE;
    for (i = length; i && path[i - 1] != '\\'; --i) {}
    if (!i || i + sizeof(ZET_PROVIDER) > MAX_PATH) return FALSE;
    lstrcpyA(path + i, ZET_PROVIDER);
    return TRUE;
}

static void load(Browser *b)
{
    char path[MAX_PATH];
    union { FARPROC raw; IEWKGetEngineV1 typed; } get;
    union { FARPROC raw; ZetscapeGetExtensionsV1 typed; } get_extension;
    unsigned i;
    if (!owner(b) || b->module) return;
    if (!provider_path(path)) { status(b, "The installation path is invalid."); return; }
    b->module = LoadLibraryA(path);
    if (!owner(b)) return;
    if (!b->module) { status(b, "Zetscape's web engine could not be loaded. Check the installation."); return; }
    get.raw = GetProcAddress(b->module, "IEWebKitGetEngineV1");
    if (!get.raw || get.typed(IEWK_ABI_V1, &b->engine) != IEWK_OK ||
        iewk_engine_validate(b->engine) != IEWK_OK) {
        unload(b); status(b, "Zetscape's web engine is unavailable."); return;
    }
    if (!owner(b)) return;
    get_extension.raw = GetProcAddress(b->module, "ZetscapeGetExtensionsV1");
    if (get_extension.raw) {
        if (get_extension.typed(ZETSCAPE_EXTENSION_ABI, &b->extension) != IEWK_OK ||
            !b->extension || b->extension->abi != ZETSCAPE_EXTENSION_ABI ||
            b->extension->size < sizeof(*b->extension))
            b->extension = NULL;
    }
    if (!owner(b)) return;
    b->callbacks.size = sizeof(b->callbacks); b->callbacks.abi = IEWK_ABI_V1;
    b->callbacks.context = b; b->callbacks.committed = committed;
    b->callbacks.title = title; b->callbacks.failed = failed;
    b->callbacks.navigate_requested = navigation_requested;
    if (b->engine->create(&b->callbacks, b->viewport, &b->view) != IEWK_OK || !b->view) {
        unload(b); status(b, "Zetscape's web engine could not start."); return;
    }
    if (!owner(b)) return;
    layout(b);
    if (!owner(b)) return;
    if (b->require_hardware && !hardware_admitted(b)) {
        unload(b); status(b, "Graphics acceleration is required but unavailable."); return;
    }
    if (!owner(b)) return;
    EnableWindow(b->address, TRUE); EnableWindow(GetDlgItem(b->window, ID_GO), TRUE);
    for (i = 2; i < 5; ++i) EnableWindow(b->buttons[i], TRUE);
    if (b->extension && b->extension->history) {
        EnableWindow(b->buttons[0], TRUE); EnableWindow(b->buttons[1], TRUE);
    }
    status(b, "Ready");
}

static void service(Browser *b)
{
    PendingNavigation *item;
    /* Called only after outer DispatchMessage returns. No host window procedure
     * invokes the engine, including nested messages pumped by that engine. */
    if (!owner(b)) return;
    if (b->load_pending) { b->load_pending = FALSE; load(b); }
    if (!owner(b)) return;
    if (b->layout_pending) { b->layout_pending = FALSE; layout(b); }
    if (!owner(b)) return;
    if (b->focus_pending) {
        b->focus_pending = FALSE;
        if (b->view) b->engine->focus(b->view, 1);
    }
    if (!owner(b)) return;
    item = b->pending_head;
    if (!item) return;
    b->pending_head = item->next; --b->pending_count;
    b->pending_bytes -= item->allocated_bytes;
    if (!b->pending_head) b->pending_tail = NULL;
    if (item->kind == 0)
        request(b, item->data, item->url_length, item->data + item->url_length,
                item->method_length, item->data + item->url_length + item->method_length,
                item->body_length);
    else if (b->view && item->kind == 1) b->engine->command(b->view, CMD_REFRESH);
    else if (b->view && item->kind == 2) b->engine->command(b->view, CMD_STOP);
    else if (b->view && item->kind == 3 && b->extension && b->extension->history) {
        if (b->navigation == 0xffffffffu)
            status(b, "Restart Zetscape before further navigation.");
        else {
            uint32_t id = ++b->navigation;
            int result;
            status(b, "Loading...");
            result = b->extension->history(b->view, id, item->history_delta);
            if (result != IEWK_OK && owner(b) && id == b->navigation && b->completed_navigation != id)
                status(b, "The history entry could not be opened.");
        }
    }
    HeapFree(GetProcessHeap(), 0, item);
    if (owner(b) && b->pending_head && !b->navigation_posted) {
        b->navigation_posted = PostMessageA(b->window, WM_ENGINE_NAVIGATION, 0, 0);
        if (!b->navigation_posted) clear_pending(b);
    }
}

static LRESULT CALLBACK edit_proc(HWND edit, UINT message, WPARAM wparam, LPARAM lparam)
{
    Browser *b = browser(GetParent(edit));
    if (!b || !b->original_edit) return DefWindowProcA(edit, message, wparam, lparam);
    if (message == WM_KEYDOWN && wparam == VK_RETURN && owner(b)) { address_go(b); return 0; }
    return CallWindowProcA(b->original_edit, edit, message, wparam, lparam);
}

static HWND control(Browser *b, const char *kind, const char *text, DWORD style, int id)
{
    HWND result = CreateWindowExA(0, kind, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 0, 0, b->window, (HMENU)(INT_PTR)id, GetModuleHandleA(NULL), NULL);
    if (result) SendMessageA(result, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), FALSE);
    return result;
}

static LRESULT CALLBACK window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
    Browser *b = browser(window);
    if (message == WM_CREATE) {
        CREATESTRUCTA *created = (CREATESTRUCTA *)lparam;
        b = (Browser *)created->lpCreateParams; b->window = window;
        SetWindowLongA(window, GWL_USERDATA, (LONG)(LONG_PTR)b);
        b->buttons[0] = control(b, "BUTTON", "Back", BS_PUSHBUTTON, ID_BACK);
        b->buttons[1] = control(b, "BUTTON", "Next", BS_PUSHBUTTON, ID_FORWARD);
        b->buttons[2] = control(b, "BUTTON", "Reload", BS_PUSHBUTTON, ID_RELOAD);
        b->buttons[3] = control(b, "BUTTON", "Stop", BS_PUSHBUTTON, ID_STOP);
        b->buttons[4] = control(b, "BUTTON", "Home", BS_PUSHBUTTON, 106);
        b->address = control(b, "EDIT", "", ES_AUTOHSCROLL | WS_BORDER, ID_ADDRESS);
        b->status = control(b, "STATIC", "Starting Zetscape...", SS_LEFT, 107);
        b->viewport = control(b, "STATIC", "", SS_LEFT, 108);
        if (!b->address || !b->status || !b->viewport ||
            !control(b, "BUTTON", "Go", BS_PUSHBUTTON, ID_GO)) return -1;
        { unsigned i; for (i = 0; i < 5; ++i) {
            if (!b->buttons[i]) return -1;
            EnableWindow(b->buttons[i], FALSE);
        } }
        EnableWindow(b->address, FALSE); EnableWindow(GetDlgItem(window, ID_GO), FALSE);
        SendMessageA(b->address, EM_LIMITTEXT, IEWK_URL_LIMIT, 0);
        b->original_edit = (WNDPROC)(LONG_PTR)SetWindowLongA(b->address, GWL_WNDPROC, (LONG)(LONG_PTR)edit_proc);
        if (!b->original_edit || !PostMessageA(window, WM_LOAD_ENGINE, 0, 0)) return -1;
        return 0;
    }
    if (!b) return DefWindowProcA(window, message, wparam, lparam);
    switch (message) {
    case WM_LOAD_ENGINE: b->load_pending = TRUE; return 0;
    case WM_ENGINE_NAVIGATION:
        b->navigation_posted = FALSE;
        return 0;
    case WM_GETMINMAXINFO:
        ((MINMAXINFO *)lparam)->ptMinTrackSize.x = 480;
        ((MINMAXINFO *)lparam)->ptMinTrackSize.y = 160;
        return 0;
    case WM_SIZE: b->layout_pending = TRUE; return 0;
    case WM_SETFOCUS: b->focus_pending = TRUE; return 0;
    case WM_COMMAND:
        if (LOWORD(wparam) == ID_GO) address_go(b);
        else if (LOWORD(wparam) == ID_RELOAD) queue_command(b, 1, 0);
        else if (LOWORD(wparam) == ID_STOP) queue_command(b, 2, 0);
        else if (b->view && LOWORD(wparam) == 106) navigation_requested(b, "https://example.org/", 20, "GET", 3, NULL, 0);
        else if (b->view && b->extension && b->extension->history &&
                 (LOWORD(wparam) == ID_BACK || LOWORD(wparam) == ID_FORWARD))
            queue_command(b, 3, LOWORD(wparam) == ID_BACK ? -1 : 1);
        return 0;
    case WM_DESTROY:
        if (b->original_edit && IsWindow(b->address))
            SetWindowLongA(b->address, GWL_WNDPROC, (LONG)(LONG_PTR)b->original_edit);
        b->closing = TRUE; unload(b); PostQuitMessage(0); return 0;
    case WM_NCDESTROY:
        SetWindowLongA(window, GWL_USERDATA, 0); return DefWindowProcA(window, message, wparam, lparam);
    default: return DefWindowProcA(window, message, wparam, lparam);
    }
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR arguments, int show)
{
    OSVERSIONINFOA os;
    WNDCLASSA klass;
    Browser *b;
    HWND window;
    MSG message;
    BOOL hardware;
    int got;
    (void)previous;
    hardware = lstrcmpA(arguments, "--shizuku") == 0;
    if (arguments[0] && !hardware) return 10;
    ZeroMemory(&os, sizeof(os)); os.dwOSVersionInfoSize = sizeof(os);
    if (sizeof(void *) != 4 || !GetVersionExA(&os) || os.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        os.dwMajorVersion != 4 || os.dwMinorVersion != 10 || LOWORD(os.dwBuildNumber) != 2222) {
        MessageBoxA(NULL, "Zetscape requires Windows 98 SE.", "Zetscape", MB_OK | MB_ICONERROR);
        return 3;
    }
    b = (Browser *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*b));
    if (!b) return 2;
    b->owner_thread = GetCurrentThreadId(); b->require_hardware = hardware;
    ZeroMemory(&klass, sizeof(klass)); klass.lpfnWndProc = window_proc;
    klass.hInstance = instance; klass.hCursor = LoadCursorA(NULL, IDC_ARROW);
    klass.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); klass.lpszClassName = "Zetscape98";
    if (!RegisterClassA(&klass)) { HeapFree(GetProcessHeap(), 0, b); return 2; }
    window = CreateWindowExA(0, klass.lpszClassName, "Zetscape", WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 960, 640, NULL, NULL, instance, b);
    if (!window) { HeapFree(GetProcessHeap(), 0, b); return 2; }
    ShowWindow(window, show); UpdateWindow(window);
    while ((got = GetMessageA(&message, NULL, 0, 0)) > 0) {
        TranslateMessage(&message); DispatchMessageA(&message);
        service(b);
        if (b->unload_pending) unload_now(b);
    }
    b->closing = TRUE;
    if (IsWindow(window)) DestroyWindow(window);
    unload_now(b);
    HeapFree(GetProcessHeap(), 0, b);
    return got < 0 ? 2 : (int)message.wParam;
}
