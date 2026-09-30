/* SPDX-License-Identifier: GPL-2.0-only
 * user32: keyboard and mouse input. The kernel (kernel64/gfx_input.c) owns the devices (PS/2 keyboard and mouse), the
 * system key state, the pointer and the routing of every event to ONE thread's queue; this file is the user-mode half:
 *
 *  - the per-thread key state (GetKeyState/GetKeyboardState) and the asynchronous one (GetAsyncKeyState), the pointer
 *    (GetCursorPos, SetCursorPos, ClipCursor), SendInput / keybd_event / mouse_event, hot keys, TrackMouseEvent,
 *    GetLastInputInfo: thin wrappers over NtUserInput;
 *  - the keyboard layout (US 00000409, win64/include/shzkbd.h shared with the kernel): MapVirtualKey, ToUnicode, VkKeyScan,
 *    GetKeyNameText and TranslateMessage (WM_CHAR / WM_SYSCHAR from the thread's key state, VK_PACKET for injected
 *    Unicode characters);
 *  - the mouse-message translation done when a message is retrieved (u32_mouse_translate, called from GetMessage and
 *    PeekMessage): the kernel delivers mouse messages with SCREEN coordinates; user32 asks the window for its hit-test
 *    code (WM_NCHITTEST, following HTTRANSPARENT to the parent), activates the top-level window on a click
 *    (WM_MOUSEACTIVATE), lets the window pick the pointer image (WM_SETCURSOR, whose DefWindowProc handling lives here as
 *    well) and turns the message into its client form (client coordinates) or non-client form (WM_NC*, hit-test code in
 *    wParam), detecting double clicks (CS_DBLCLKS, GetDoubleClickTime, SM_CXDOUBLECLK);
 *  - the pointer image: SetCursor/ShowCursor hand the thread's cursor (at most 32x32, scaled) to the kernel, which draws
 *    it while the pointer is over a window of this thread;
 *  - DefWindowProc's mouse/keyboard behaviour: WM_SETCURSOR, WM_MOUSEACTIVATE and the wheel go to the parent first,
 *    WM_CONTEXTMENU from a right click, Alt+F4, and the modal move/size loop started from the caption or a sizing border.
 *
 * Gaps (not hidden behaviour): one keyboard layout, no dead keys or IME; mouse messages removed through a filter that only
 * matched their other form are consumed; low-level hooks and raw input do not exist.
 */
#include "user32_int.h"
#include "shzkbd.h"

static int32_t input_op(shz_input_t *in)
{
    const int32_t st = NtUserInput(in);
    if (st < 0) u32_err(st);
    return st;
}

static int32_t input_simple(uint32_t op, int64_t a, int64_t b, int64_t c, int64_t d, shz_input_t *out)
{
    memset(out, 0, sizeof *out);
    out->op = op;
    out->a = a; out->b = b; out->c = c; out->d = d;
    return input_op(out);
}

uint32_t u32_input_info(void)
{
    static volatile LONG cached = -1;
    shz_input_t in;
    if (cached >= 0) return (uint32_t)cached;
    if (!u32_display(0)) return 0;
    if (input_simple(SHZ_IN_INFO, 0, 0, 0, 0, &in) < 0) return 0;
    cached = (LONG)(uint32_t)in.out0;
    return (uint32_t)in.out0;
}

/* ---------------------------------------------------------------- key state */
DLLAPI SHORT WINAPI GetKeyState(int vk)
{
    shz_input_t in;
    uint8_t s;
    if (!u32_display(0) || input_simple(SHZ_IN_GETKEYSTATE, vk & 0xff, 0, 0, 0, &in) < 0) return 0;
    s = (uint8_t)in.out0;
    return (SHORT)(((s & 0x80) ? 0xff80 : 0) | (s & 1));          /* down: negative, as on Windows (0xFF80 | toggle) */
}

DLLAPI BOOL WINAPI GetKeyboardState(PBYTE state)
{
    shz_input_t in;
    if (!state) { SetLastError(ERROR_NOACCESS); return FALSE; }
    if (!u32_display(0)) { memset(state, 0, 256); return TRUE; }  /* no input devices: nothing is down */
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_GETKEYBOARDSTATE;
    in.buf = (uint64_t)(uintptr_t)state;
    in.buf_len = 256;
    return input_op(&in) >= 0;
}

DLLAPI BOOL WINAPI SetKeyboardState(LPBYTE state)
{
    shz_input_t in;
    if (!state) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_SETKEYBOARDSTATE;
    in.buf = (uint64_t)(uintptr_t)state;
    in.buf_len = 256;
    return input_op(&in) >= 0;
}

DLLAPI SHORT WINAPI GetAsyncKeyState(int vk)
{
    shz_input_t in;
    if (!u32_display(0) || input_simple(SHZ_IN_GETASYNCKEYSTATE, vk & 0xff, 0, 0, 0, &in) < 0) return 0;
    return (SHORT)(uint16_t)in.out0;
}

/* ---------------------------------------------------------------- pointer position */
DLLAPI BOOL WINAPI GetCursorPos(LPPOINT pt)
{
    shz_input_t in;
    if (!pt) { SetLastError(ERROR_NOACCESS); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (input_simple(SHZ_IN_GETCURSORPOS, 0, 0, 0, 0, &in) < 0) return FALSE;
    pt->x = (LONG)(int64_t)in.out0;
    pt->y = (LONG)(int64_t)in.out1;
    return TRUE;
}

DLLAPI BOOL WINAPI GetPhysicalCursorPos(LPPOINT pt) { return GetCursorPos(pt); }     /* 96 DPI everywhere: logical == physical */

DLLAPI BOOL WINAPI SetCursorPos(int x, int y)
{
    shz_input_t in;
    U32_NEED_GFX(FALSE);
    return input_simple(SHZ_IN_SETCURSORPOS, x, y, 0, 0, &in) >= 0;
}

DLLAPI BOOL WINAPI SetPhysicalCursorPos(int x, int y) { return SetCursorPos(x, y); }

DLLAPI BOOL WINAPI ClipCursor(const RECT *rc)
{
    shz_input_t in;
    U32_NEED_GFX(FALSE);
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_CLIPCURSOR;
    in.a = rc != 0;
    if (rc) { in.rect.left = rc->left; in.rect.top = rc->top; in.rect.right = rc->right; in.rect.bottom = rc->bottom; }
    return input_op(&in) >= 0;
}

DLLAPI BOOL WINAPI GetClipCursor(LPRECT rc)
{
    shz_input_t in;
    if (!rc) { SetLastError(ERROR_NOACCESS); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (input_simple(SHZ_IN_GETCLIPCURSOR, 0, 0, 0, 0, &in) < 0) return FALSE;
    rc->left = in.rect.left; rc->top = in.rect.top; rc->right = in.rect.right; rc->bottom = in.rect.bottom;
    return TRUE;
}

DLLAPI BOOL WINAPI GetLastInputInfo(PLASTINPUTINFO lii)
{
    shz_input_t in;
    if (!lii || lii->cbSize != sizeof *lii) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!u32_display(0)) { lii->dwTime = 0; return TRUE; }        /* no input device ever produced input */
    if (input_simple(SHZ_IN_INFO, 0, 0, 0, 0, &in) < 0) return FALSE;
    lii->dwTime = (DWORD)in.out1;
    return TRUE;
}

/* ---------------------------------------------------------------- synthesized input */
DLLAPI UINT WINAPI SendInput(UINT n, LPINPUT inputs, int cb)
{
    shz_inrec_t recs[64];
    UINT done = 0;
    if (cb != (int)sizeof(INPUT) || (n && !inputs)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    U32_NEED_GFX(0);
    while (done < n) {
        UINT k = 0, i;
        shz_input_t in;
        for (i = done; i < n && k < 64; ++i) {
            const INPUT *s = &inputs[i];
            shz_inrec_t *r = &recs[k];
            memset(r, 0, sizeof *r);
            if (s->type == INPUT_MOUSE) {
                r->type = 0;
                r->flags = s->mi.dwFlags;
                r->dx = s->mi.dx;
                r->dy = s->mi.dy;
                r->data = (int32_t)s->mi.mouseData;
                r->extra = (uint64_t)s->mi.dwExtraInfo;
            } else if (s->type == INPUT_KEYBOARD) {
                r->type = 1;
                r->flags = s->ki.dwFlags;
                r->vk = s->ki.wVk;
                r->scan = s->ki.wScan;
                r->extra = (uint64_t)s->ki.dwExtraInfo;
            } else {
                SetLastError(ERROR_NOT_SUPPORTED);                     /* INPUT_HARDWARE: no such devices */
                n = i;
                break;
            }
            ++k;
        }
        if (!k) break;
        memset(&in, 0, sizeof in);
        in.op = SHZ_IN_SENDINPUT;
        in.a = k;
        in.buf = (uint64_t)(uintptr_t)recs;
        in.buf_len = k * (uint32_t)sizeof recs[0];
        if (input_op(&in) < 0) break;
        done += (UINT)in.out0;
    }
    return done;
}

DLLAPI VOID WINAPI keybd_event(BYTE vk, BYTE scan, DWORD flags, ULONG_PTR extra)
{
    INPUT i;
    memset(&i, 0, sizeof i);
    i.type = INPUT_KEYBOARD;
    i.ki.wVk = vk;
    i.ki.wScan = scan;
    i.ki.dwFlags = flags;
    i.ki.dwExtraInfo = extra;
    SendInput(1, &i, sizeof i);
}

DLLAPI VOID WINAPI mouse_event(DWORD flags, DWORD dx, DWORD dy, DWORD data, ULONG_PTR extra)
{
    INPUT i;
    memset(&i, 0, sizeof i);
    i.type = INPUT_MOUSE;
    i.mi.dx = (LONG)dx;
    i.mi.dy = (LONG)dy;
    i.mi.mouseData = data;
    i.mi.dwFlags = flags;
    i.mi.dwExtraInfo = extra;
    SendInput(1, &i, sizeof i);
}

/* There is no audio device in this system: the beep is silent, but the call succeeds as it does on a machine without a
 * sound card. */
DLLAPI BOOL WINAPI MessageBeep(UINT type) { (void)type; return TRUE; }

DLLAPI BOOL WINAPI BlockInput(BOOL block)
{
    (void)block;
    SetLastError(ERROR_ACCESS_DENIED);                                 /* no process holds the rights to block input */
    return FALSE;
}

/* ---------------------------------------------------------------- hot keys, mouse tracking */
DLLAPI BOOL WINAPI RegisterHotKey(HWND hwnd, int id, UINT mods, UINT vk)
{
    shz_input_t in;
    int32_t st;
    U32_NEED_GFX(FALSE);
    if (vk == 0 || vk > 0xff || (mods & ~(MOD_ALT | MOD_CONTROL | MOD_SHIFT | MOD_WIN | MOD_NOREPEAT))) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_HOTKEY;
    in.a = (int64_t)(uintptr_t)hwnd;
    in.b = id;
    in.c = (int64_t)(mods | (vk << 16));
    in.d = 1;
    st = NtUserInput(&in);
    if (st < 0) {
        if ((uint32_t)st == 0xC0000235u) SetLastError(ERROR_HOTKEY_ALREADY_REGISTERED);
        else u32_err(st);
        return FALSE;
    }
    return TRUE;
}

DLLAPI BOOL WINAPI UnregisterHotKey(HWND hwnd, int id)
{
    shz_input_t in;
    int32_t st;
    U32_NEED_GFX(FALSE);
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_HOTKEY;
    in.a = (int64_t)(uintptr_t)hwnd;
    in.b = id;
    st = NtUserInput(&in);
    if (st < 0) {
        if ((uint32_t)st == 0xC000000Du) SetLastError(ERROR_HOTKEY_NOT_REGISTERED);
        else u32_err(st);
        return FALSE;
    }
    return TRUE;
}

DLLAPI BOOL WINAPI TrackMouseEvent(LPTRACKMOUSEEVENT t)
{
    shz_input_t in;
    if (!t || t->cbSize != sizeof *t) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_TRACKMOUSE;
    in.a = (int64_t)(uintptr_t)t->hwndTrack;
    in.b = t->dwFlags;
    in.c = t->dwHoverTime;
    if (input_op(&in) < 0) return FALSE;
    if (t->dwFlags & TME_QUERY) {
        t->hwndTrack = U2H(in.out0);
        t->dwFlags = (DWORD)(in.out1 & 0xffffffffu);
        t->dwHoverTime = (DWORD)(in.out1 >> 32);
    }
    return TRUE;
}

/* ---------------------------------------------------------------- double clicks, caret */
static UINT g_dblclk_ms = 500, g_caret_ms = 530;
DLLAPI UINT WINAPI GetDoubleClickTime(void) { return g_dblclk_ms; }
DLLAPI BOOL WINAPI SetDoubleClickTime(UINT ms) { g_dblclk_ms = ms ? (ms > 5000 ? 5000 : ms) : 500; return TRUE; }
DLLAPI UINT WINAPI GetCaretBlinkTime(void) { return g_caret_ms; }
DLLAPI BOOL WINAPI SetCaretBlinkTime(UINT ms) { g_caret_ms = ms; return TRUE; }
DLLAPI BOOL WINAPI SwapMouseButton(BOOL swap) { (void)swap; return FALSE; }   /* returns the previous state: never swapped */

/* ---------------------------------------------------------------- the keyboard layout (US only) */
#define US_HKL ((HKL)(ULONG_PTR)0x04090409)

DLLAPI HKL WINAPI GetKeyboardLayout(DWORD tid) { (void)tid; return US_HKL; }
DLLAPI int WINAPI GetKeyboardLayoutList(int n, HKL *list)
{
    if (n > 0 && list) list[0] = US_HKL;
    return 1;
}
DLLAPI BOOL WINAPI GetKeyboardLayoutNameW(LPWSTR name)
{
    if (!name) { SetLastError(ERROR_NOACCESS); return FALSE; }
    memcpy(name, L"00000409", 9 * sizeof(WCHAR));
    return TRUE;
}
DLLAPI BOOL WINAPI GetKeyboardLayoutNameA(LPSTR name)
{
    if (!name) { SetLastError(ERROR_NOACCESS); return FALSE; }
    memcpy(name, "00000409", 9);
    return TRUE;
}

static int is_us_name(LPCWSTR n)
{
    static const WCHAR us[] = L"00000409";
    int i;
    if (!n) return 0;
    for (i = 0; us[i]; ++i) if (n[i] != us[i]) return 0;
    return n[i] == 0;
}

DLLAPI HKL WINAPI LoadKeyboardLayoutW(LPCWSTR name, UINT flags)
{
    (void)flags;
    if (is_us_name(name)) return US_HKL;
    SetLastError(ERROR_FILE_NOT_FOUND);                                /* only the US layout exists */
    return 0;
}

DLLAPI HKL WINAPI ActivateKeyboardLayout(HKL hkl, UINT flags)
{
    (void)flags;
    if (hkl == US_HKL || hkl == (HKL)HKL_NEXT || hkl == (HKL)HKL_PREV) return US_HKL;
    SetLastError(ERROR_INVALID_PARAMETER);
    return 0;
}

DLLAPI BOOL WINAPI UnloadKeyboardLayout(HKL hkl) { (void)hkl; SetLastError(ERROR_ACCESS_DENIED); return FALSE; }   /* the system layout stays */

DLLAPI int WINAPI GetKeyboardType(int what)
{
    switch (what) {
    case 0: return 4;                                                  /* IBM enhanced 101/102-key */
    case 1: return 0;
    case 2: return 12;                                                 /* function keys */
    default: return 0;
    }
}

DLLAPI UINT WINAPI GetKBCodePage(void) { return GetOEMCP(); }

/* the character a key produces with the given modifier state (US layout); 0 if none */
static WCHAR key_char(UINT vk, const BYTE *state)
{
    const int shift = (state[VK_SHIFT] & 0x80) != 0, ctrl = (state[VK_CONTROL] & 0x80) != 0, alt = (state[VK_MENU] & 0x80) != 0;
    const int caps = (state[VK_CAPITAL] & 1) != 0;
    uint16_t plain, shifted;
    if (ctrl && alt) return 0;                                         /* AltGr: the US layout has no third level */
    if (vk >= 'A' && vk <= 'Z') {
        if (ctrl) return (WCHAR)(vk - 'A' + 1);
        return (WCHAR)((shift ^ caps) ? vk : vk + 32);
    }
    if (ctrl) {
        switch (vk) {
        case VK_OEM_4: return 0x1b;                                    /* Ctrl+[ */
        case VK_OEM_6: return 0x1d;                                    /* Ctrl+] */
        case VK_OEM_5: case VK_OEM_102: return 0x1c;                   /* Ctrl+\ */
        case VK_RETURN: return '\n';
        case VK_BACK: return 0x7f;
        case VK_SPACE: return ' ';
        case VK_CANCEL: return 3;
        case VK_ESCAPE: return 0x1b;
        case '6': return shift ? 0x1e : 0;
        case VK_OEM_MINUS: return shift ? 0x1f : 0;
        default: return 0;
        }
    }
    if (!shz_kbd_chars((uint8_t)vk, &plain, &shifted)) return 0;
    return (WCHAR)(shift ? shifted : plain);
}

DLLAPI int WINAPI ToUnicodeEx(UINT vk, UINT scan, const BYTE *state, LPWSTR buf, int n, UINT flags, HKL hkl)
{
    WCHAR c;
    (void)flags; (void)hkl;
    if (!state || !buf || n <= 0) return 0;
    if (scan & 0x8000) return 0;                                       /* key release */
    c = key_char(vk & 0xff, state);
    if (!c) return 0;
    buf[0] = c;
    if (n > 1) buf[1] = 0;
    return 1;
}

DLLAPI int WINAPI ToUnicode(UINT vk, UINT scan, const BYTE *state, LPWSTR buf, int n, UINT flags)
{
    return ToUnicodeEx(vk, scan, state, buf, n, flags, US_HKL);
}

DLLAPI int WINAPI ToAsciiEx(UINT vk, UINT scan, const BYTE *state, LPWORD out, UINT flags, HKL hkl)
{
    WCHAR c[2];
    const int r = ToUnicodeEx(vk, scan, state, c, 2, flags, hkl);
    if (r <= 0 || !out) return 0;
    if (c[0] > 0x7f) return 0;
    *out = c[0];
    return 1;
}

DLLAPI int WINAPI ToAscii(UINT vk, UINT scan, const BYTE *state, LPWORD out, UINT flags) { return ToAsciiEx(vk, scan, state, out, flags, US_HKL); }

DLLAPI SHORT WINAPI VkKeyScanExW(WCHAR ch, HKL hkl)
{
    unsigned vk;
    (void)hkl;
    if (ch >= 'a' && ch <= 'z') return (SHORT)(ch - 32);
    if (ch >= 'A' && ch <= 'Z') return (SHORT)(0x100 | ch);
    for (vk = 1; vk < 0xff; ++vk) {
        uint16_t p, s;
        if (vk >= 0x60 && vk <= 0x6f) continue;                        /* prefer the main block over the keypad */
        if (!shz_kbd_chars((uint8_t)vk, &p, &s)) continue;
        if (p == ch) return (SHORT)vk;
        if (s == ch) return (SHORT)(0x100 | vk);
    }
    for (vk = 0x60; vk <= 0x6f; ++vk) {
        uint16_t p, s;
        if (shz_kbd_chars((uint8_t)vk, &p, &s) && p == ch) return (SHORT)vk;
    }
    if (ch >= 1 && ch <= 26) return (SHORT)(0x200 | (ch + 'A' - 1));  /* other control characters: Ctrl+letter */
    return -1;
}

DLLAPI SHORT WINAPI VkKeyScanW(WCHAR ch) { return VkKeyScanExW(ch, US_HKL); }
DLLAPI SHORT WINAPI VkKeyScanA(CHAR ch) { return VkKeyScanExW((WCHAR)(BYTE)ch, US_HKL); }

DLLAPI DWORD WINAPI OemKeyScan(WORD oem)
{
    const SHORT v = VkKeyScanExW(oem, US_HKL);
    int ext;
    uint16_t sc;
    if (v == -1 || (v & 0x200)) return 0xffffffffu;
    sc = shz_kbd_vk_to_scan((uint8_t)v, &ext);
    if (!sc || ext) return 0xffffffffu;
    return sc | ((v & 0x100) ? 0x10000u : 0);
}

DLLAPI UINT WINAPI MapVirtualKeyExW(UINT code, UINT type, HKL hkl)
{
    int ext;
    (void)hkl;
    switch (type) {
    case MAPVK_VK_TO_VSC:
    case MAPVK_VK_TO_VSC_EX: {
        uint16_t sc;
        unsigned i;
        if (code > 0xff) return 0;
        if (type == MAPVK_VK_TO_VSC_EX)                                /* keys that exist as E0 keys (arrows, Home, ...) */
            for (i = 0; i < 0x60; ++i)
                if (code != VK_RETURN && shz_kbd_e0((uint8_t)i) == code) return 0xe000u | i;
        sc = shz_kbd_vk_to_scan((uint8_t)code, &ext);
        if (!sc) return 0;
        if (code == VK_PAUSE && type == MAPVK_VK_TO_VSC_EX) return 0xe11d;
        return ext && type == MAPVK_VK_TO_VSC_EX ? (0xe000u | sc) : sc;
    }
    case MAPVK_VSC_TO_VK:
    case MAPVK_VSC_TO_VK_EX: {
        const unsigned e0 = (code & 0xff00) == 0xe000, sc = code & 0xff;
        uint8_t vk = e0 ? shz_kbd_e0((uint8_t)sc) : (sc < sizeof shz_kbd_set1 ? shz_kbd_set1[sc] : 0);
        if (!vk) return 0;
        if (type == MAPVK_VSC_TO_VK) {                                 /* the generic modifier keys */
            if (vk == VK_LSHIFT || vk == VK_RSHIFT) vk = VK_SHIFT;
            else if (vk == VK_LCONTROL || vk == VK_RCONTROL) vk = VK_CONTROL;
            else if (vk == VK_LMENU || vk == VK_RMENU) vk = VK_MENU;
        }
        return vk;
    }
    case MAPVK_VK_TO_CHAR: {
        uint16_t p, s;
        if (code >= 'A' && code <= 'Z') return code;
        if (code > 0xff || !shz_kbd_chars((uint8_t)code, &p, &s)) return 0;
        return p;
    }
    default:
        return 0;
    }
}

DLLAPI UINT WINAPI MapVirtualKeyW(UINT code, UINT type) { return MapVirtualKeyExW(code, type, US_HKL); }
DLLAPI UINT WINAPI MapVirtualKeyA(UINT code, UINT type) { return MapVirtualKeyExW(code, type, US_HKL); }

/* Key names as the US layout of Windows spells them (by scan code; E0 keys have their own names). */
static const char *key_name(unsigned sc, int ext)
{
    static const char *const base[0x59] = {
        0, "Esc", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "-", "=", "Backspace", "Tab",
        "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "[", "]", "Enter", "Ctrl", "A", "S",
        "D", "F", "G", "H", "J", "K", "L", ";", "'", "`", "Shift", "\\", "Z", "X", "C", "V",
        "B", "N", "M", ",", ".", "/", "Right Shift", "Num *", "Alt", "Space", "Caps Lock", "F1", "F2", "F3", "F4", "F5",
        "F6", "F7", "F8", "F9", "F10", "Pause", "Scroll Lock", "Num 7", "Num 8", "Num 9", "Num -", "Num 4", "Num 5", "Num 6", "Num +", "Num 1",
        "Num 2", "Num 3", "Num 0", "Num Del", "Sys Req", 0, "\\", "F11", "F12" };
    if (ext) {
        switch (sc) {
        case 0x1c: return "Num Enter";
        case 0x1d: return "Right Ctrl";
        case 0x35: return "Num /";
        case 0x37: return "Prnt Scrn";
        case 0x38: return "Right Alt";
        case 0x45: return "Num Lock";
        case 0x46: return "Break";
        case 0x47: return "Home";
        case 0x48: return "Up";
        case 0x49: return "Page Up";
        case 0x4b: return "Left";
        case 0x4d: return "Right";
        case 0x4f: return "End";
        case 0x50: return "Down";
        case 0x51: return "Page Down";
        case 0x52: return "Insert";
        case 0x53: return "Delete";
        case 0x5b: return "Left Windows";
        case 0x5c: return "Right Windows";
        case 0x5d: return "Application";
        default: return 0;
        }
    }
    return sc < 0x59 ? base[sc] : 0;
}

DLLAPI int WINAPI GetKeyNameTextW(LONG lparam, LPWSTR buf, int n)
{
    unsigned sc = (lparam >> 16) & 0xff;
    int ext = (lparam >> 24) & 1, i;
    const char *name;
    if (!buf || n <= 0) return 0;
    if ((lparam & (1 << 25)) && (sc == 0x36 || (sc == 0x1d) || sc == 0x38)) {   /* "don't care" left/right distinction */
        if (sc == 0x36) sc = 0x2a;
        ext = 0;
    }
    name = key_name(sc, ext);
    if (!name) { buf[0] = 0; return 0; }
    for (i = 0; name[i] && i < n - 1; ++i) buf[i] = (WCHAR)(unsigned char)name[i];
    buf[i] = 0;
    return i;
}

DLLAPI int WINAPI GetKeyNameTextA(LONG lparam, LPSTR buf, int n)
{
    WCHAR w[64];
    int r, i;
    if (!buf || n <= 0) return 0;
    r = GetKeyNameTextW(lparam, w, n < 64 ? n : 64);
    for (i = 0; i < r; ++i) buf[i] = (char)w[i];
    buf[r] = 0;
    return r;
}

/* ---------------------------------------------------------------- TranslateMessage */
DLLAPI BOOL WINAPI TranslateMessage(const MSG *msg)
{
    BYTE state[256];
    WCHAR ch[4];
    int n, i;
    if (!msg) return FALSE;
    if (msg->message == WM_KEYUP || msg->message == WM_SYSKEYUP) return TRUE;
    if (msg->message != WM_KEYDOWN && msg->message != WM_SYSKEYDOWN) return FALSE;
    if (LOWORD(msg->wParam) == VK_PACKET) {                            /* SendInput KEYEVENTF_UNICODE: the character itself */
        PostMessageW(msg->hwnd, msg->message == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, HIWORD(msg->wParam), msg->lParam);
        return TRUE;
    }
    if (!GetKeyboardState(state)) return TRUE;
    n = ToUnicodeEx((UINT)msg->wParam, (UINT)((msg->lParam >> 16) & 0xff), state, ch, 4, 0, US_HKL);
    for (i = 0; i < n; ++i)
        PostMessageW(msg->hwnd, msg->message == WM_KEYDOWN ? WM_CHAR : WM_SYSCHAR, ch[i], msg->lParam);
    return TRUE;
}

/* ---------------------------------------------------------------- pointer image */
static void cursor_init(u32_thread_t *t)
{
    if (t->cursor_init) return;
    t->cursor_init = 1;
    t->cursor_count = (u32_input_info() & SHZ_INFO_MOUSE) ? 0 : -1;   /* no mouse: the cursor starts hidden, as on Windows */
}

void u32_cursor_push(void)
{
    u32_thread_t *t = u32_ts();
    shz_input_t in;
    uint32_t pix[32 * 32];
    int w = 0, h = 0, hx = 0, hy = 0;
    if (!t || !u32_display(0)) return;
    cursor_init(t);
    memset(&in, 0, sizeof in);
    in.op = SHZ_IN_SETCURSOR;
    if (t->cursor && u32_icon_argb32(t->cursor, pix, &w, &h, &hx, &hy)) {
        in.a = (int64_t)(uintptr_t)t->cursor;
        in.b = w | (h << 16);
        in.c = hx | (hy << 16);
        in.buf = (uint64_t)(uintptr_t)pix;
        in.buf_len = (uint32_t)(w * h * 4);
    }
    in.d = t->cursor_count < 0;
    NtUserInput(&in);
}

int u32_cursor_count(int delta)
{
    u32_thread_t *t = u32_ts();
    if (!t) return 0;
    cursor_init(t);
    t->cursor_count += delta;
    if (delta && ((t->cursor_count < 0) != (t->cursor_count - delta < 0))) u32_cursor_push();
    return t->cursor_count;
}

DLLAPI BOOL WINAPI GetCursorInfo(PCURSORINFO ci)
{
    shz_input_t in;
    POINT pt;
    if (!ci || ci->cbSize != sizeof *ci) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    U32_NEED_GFX(FALSE);
    if (input_simple(SHZ_IN_CURSORINFO, 0, 0, 0, 0, &in) < 0 || !GetCursorPos(&pt)) return FALSE;
    ci->flags = in.out1 ? CURSOR_SHOWING : 0;
    ci->hCursor = (HCURSOR)(uintptr_t)in.out0;                         /* 1: the system arrow shown over the desktop */
    if (in.out0 == 1) ci->hCursor = LoadCursorW(0, (LPCWSTR)IDC_ARROW);
    ci->ptScreenPos = pt;
    return TRUE;
}

/* ---------------------------------------------------------------- mouse-message translation (GetMessage/PeekMessage) */
static int iabs(int v) { return v < 0 ? -v : v; }
static int is_down_msg(UINT m) { return m == WM_LBUTTONDOWN || m == WM_RBUTTONDOWN || m == WM_MBUTTONDOWN || m == WM_XBUTTONDOWN; }

int u32_mouse_translate(shz_msg_t *m, int remove)
{
    HWND hwnd = U2H(m->hwnd);
    const UINT raw = m->message;
    const POINT pt = { m->pt.x, m->pt.y };
    const int captured = (m->pad0 & SHZ_MSGF_CAPTURED) != 0, down = is_down_msg(raw);
    const WORD xbtn = HIWORD(m->wparam);
    LRESULT hit = HTCLIENT;
    int eat = 0, client;
    UINT msg;
    if (!captured) {
        for (;;) {
            HWND parent;
            hit = SendMessageW(hwnd, WM_NCHITTEST, 0, MAKELPARAM((WORD)pt.x, (WORD)pt.y));
            if (hit != HTTRANSPARENT) break;
            parent = (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD) ? GetParent(hwnd) : 0;
            if (!parent || !IsWindow(parent)) return 0;                /* nothing of this thread below: dropped */
            hwnd = parent;
        }
        if (!IsWindow(hwnd)) return 0;
        m->hwnd = H2U(hwnd);
        if (remove) {
            if (down) {
                HWND top = GetAncestor(hwnd, GA_ROOT);
                if (top && top != GetForegroundWindow()) {
                    const LRESULT ma = SendMessageW(hwnd, WM_MOUSEACTIVATE, (WPARAM)top, MAKELPARAM((WORD)hit, (WORD)raw));
                    if ((ma == MA_ACTIVATE || ma == MA_ACTIVATEANDEAT) && IsWindow(top) &&
                        !(GetWindowLongW(top, GWL_EXSTYLE) & WS_EX_NOACTIVATE))
                        SetForegroundWindow(top);
                    eat = ma == MA_ACTIVATEANDEAT || ma == MA_NOACTIVATEANDEAT;
                }
            }
            if (IsWindow(hwnd)) SendMessageW(hwnd, WM_SETCURSOR, (WPARAM)hwnd, MAKELPARAM((WORD)hit, (WORD)raw));
            if (eat || !IsWindow(hwnd)) return 0;
        }
    }
    client = captured || hit == HTCLIENT;
    if (client) {
        POINT c = pt;
        ScreenToClient(hwnd, &c);
        m->lparam = (int64_t)(uint32_t)MAKELPARAM((WORD)c.x, (WORD)c.y);
        msg = raw;
    } else {
        msg = raw - WM_MOUSEFIRST + WM_NCMOUSEMOVE;
        m->wparam = (raw == WM_XBUTTONDOWN || raw == WM_XBUTTONUP) ? MAKEWPARAM((WORD)hit, xbtn) : (WPARAM)(WORD)hit;
    }
    if (down) {
        u32_thread_t *t = u32_ts();
        const int cx = u32_metric(SM_CXDOUBLECLK) / 2, cy = u32_metric(SM_CYDOUBLECLK) / 2;
        const int ok = !client || (GetClassLongW(hwnd, GCL_STYLE) & CS_DBLCLKS);
        if (t && ok && t->dbl_msg == raw && t->dbl_hwnd == hwnd && t->dbl_client == client && t->dbl_x == xbtn &&
            m->time - t->dbl_time <= GetDoubleClickTime() && iabs(pt.x - t->dbl_pt.x) <= cx && iabs(pt.y - t->dbl_pt.y) <= cy) {
            msg += 2;                                                  /* WM_xBUTTONDBLCLK / WM_NCxBUTTONDBLCLK */
            if (remove) t->dbl_msg = 0;                                /* a third click starts a new pair */
        } else if (t && remove) {
            t->dbl_msg = raw; t->dbl_hwnd = hwnd; t->dbl_time = m->time; t->dbl_pt = pt; t->dbl_client = client; t->dbl_x = xbtn;
        }
    }
    m->message = msg;
    return 1;
}

/* ---------------------------------------------------------------- DefWindowProc: mouse and keyboard */
static HWND parent_of_child(HWND hwnd)
{
    return (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD) ? GetParent(hwnd) : 0;
}

static LRESULT set_cursor_for_hit(HWND hwnd, int hit, UINT mouse_msg)
{
    LPCWSTR id = (LPCWSTR)IDC_ARROW;
    switch (hit) {
    case HTERROR:
        if (is_down_msg(mouse_msg)) MessageBeep(0);
        break;
    case HTCLIENT: {
        HCURSOR c = (HCURSOR)GetClassLongPtrW(hwnd, GCLP_HCURSOR);
        if (!c) return FALSE;                                          /* the window sets its own (or keeps the current one) */
        SetCursor(c);
        return TRUE;
    }
    case HTLEFT: case HTRIGHT: id = (LPCWSTR)IDC_SIZEWE; break;
    case HTTOP: case HTBOTTOM: id = (LPCWSTR)IDC_SIZENS; break;
    case HTTOPLEFT: case HTBOTTOMRIGHT: id = (LPCWSTR)IDC_SIZENWSE; break;
    case HTTOPRIGHT: case HTBOTTOMLEFT: id = (LPCWSTR)IDC_SIZENESW; break;
    default: break;
    }
    SetCursor(LoadCursorW(0, id));
    return TRUE;
}

/* The modal move/size loop of DefWindowProc (SC_MOVE / SC_SIZE): runs with the mouse captured until the button is
 * released, moving or resizing the window as the pointer moves. WM_ENTERSIZEMOVE, WM_MOVING / WM_SIZING, WM_EXITSIZEMOVE
 * are sent like on Windows; Escape restores the original rectangle. */
static void move_size_loop(HWND hwnd, int hit)
{
    RECT orig, cur;
    POINT start;
    MSG msg;
    const int moving = hit == HTCAPTION;
    const int minw = u32_metric(SM_CXMINTRACK), minh = u32_metric(SM_CYMINTRACK);
    int done = 0;
    WPARAM edge = 0;
    {
        const DWORD mp = GetMessagePos();                              /* where the button went down, not where the pointer is now */
        start.x = (short)LOWORD(mp);
        start.y = (short)HIWORD(mp);
    }
    if (!GetWindowRect(hwnd, &orig)) return;
    if (GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD) {                  /* a child moves in its parent's client coordinates */
        HWND p = GetParent(hwnd);
        MapWindowPoints(0, p, (POINT *)&orig, 2);
    }
    switch (hit) {
    case HTLEFT: edge = WMSZ_LEFT; break;
    case HTRIGHT: edge = WMSZ_RIGHT; break;
    case HTTOP: edge = WMSZ_TOP; break;
    case HTBOTTOM: edge = WMSZ_BOTTOM; break;
    case HTTOPLEFT: edge = WMSZ_TOPLEFT; break;
    case HTTOPRIGHT: edge = WMSZ_TOPRIGHT; break;
    case HTBOTTOMLEFT: edge = WMSZ_BOTTOMLEFT; break;
    case HTBOTTOMRIGHT: edge = WMSZ_BOTTOMRIGHT; break;
    default: break;
    }
    if (u32_cbt(HCBT_MOVESIZE, (WPARAM)hwnd, (LPARAM)&orig)) return;   /* a CBT hook vetoed it */
    SetCapture(hwnd);
    u32_winevent(EVENT_SYSTEM_MOVESIZESTART, hwnd, OBJID_WINDOW, CHILDID_SELF);
    SendMessageW(hwnd, WM_ENTERSIZEMOVE, 0, 0);
    cur = orig;
    while (!done && GetCapture() == hwnd && GetMessageW(&msg, 0, 0, 0)) {
        switch (msg.message) {
        case WM_MOUSEMOVE: case WM_NCMOUSEMOVE: {                     /* input routed before the capture comes in NC form */
            const int dx = msg.pt.x - start.x, dy = msg.pt.y - start.y;
            RECT r = orig;
            if (moving) { OffsetRect(&r, dx, dy); SendMessageW(hwnd, WM_MOVING, 0, (LPARAM)&r); }
            else {
                if (edge == WMSZ_LEFT || edge == WMSZ_TOPLEFT || edge == WMSZ_BOTTOMLEFT) r.left = orig.left + dx < orig.right - minw ? orig.left + dx : orig.right - minw;
                if (edge == WMSZ_RIGHT || edge == WMSZ_TOPRIGHT || edge == WMSZ_BOTTOMRIGHT) r.right = orig.right + dx > orig.left + minw ? orig.right + dx : orig.left + minw;
                if (edge == WMSZ_TOP || edge == WMSZ_TOPLEFT || edge == WMSZ_TOPRIGHT) r.top = orig.top + dy < orig.bottom - minh ? orig.top + dy : orig.bottom - minh;
                if (edge == WMSZ_BOTTOM || edge == WMSZ_BOTTOMLEFT || edge == WMSZ_BOTTOMRIGHT) r.bottom = orig.bottom + dy > orig.top + minh ? orig.bottom + dy : orig.top + minh;
                SendMessageW(hwnd, WM_SIZING, edge, (LPARAM)&r);
            }
            if (!EqualRect(&r, &cur)) {
                cur = r;
                SetWindowPos(hwnd, 0, r.left, r.top, r.right - r.left, r.bottom - r.top,
                             SWP_NOZORDER | SWP_NOACTIVATE | (moving ? SWP_NOSIZE : 0));
            }
            break;
        }
        case WM_LBUTTONUP: case WM_NCLBUTTONUP: done = 1; break;
        case WM_KEYDOWN:
            if (msg.wParam == VK_ESCAPE) {
                SetWindowPos(hwnd, 0, orig.left, orig.top, orig.right - orig.left, orig.bottom - orig.top, SWP_NOZORDER | SWP_NOACTIVATE);
                done = 1;
            } else if (msg.wParam == VK_RETURN) done = 1;
            break;
        default:
            if ((msg.message < WM_MOUSEFIRST || msg.message > WM_MOUSELAST) && (msg.message < WM_NCMOUSEMOVE || msg.message > WM_NCXBUTTONDBLCLK)) {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
            break;
        }
        if (msg.message == WM_QUIT) { PostQuitMessage((int)msg.wParam); break; }
    }
    if (GetCapture() == hwnd) ReleaseCapture();
    if (IsWindow(hwnd)) SendMessageW(hwnd, WM_EXITSIZEMOVE, 0, 0);
    u32_winevent(EVENT_SYSTEM_MOVESIZEEND, hwnd, OBJID_WINDOW, CHILDID_SELF);
}

LRESULT u32_def_mouse(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp, int *handled)
{
    HWND parent;
    *handled = 1;
    switch (msg) {
    case WM_SETCURSOR: {
        const int hit = (short)LOWORD(lp);
        if ((hit < HTSIZEFIRST || hit > HTSIZELAST) && (parent = parent_of_child(hwnd)) != 0 &&
            SendMessageW(parent, WM_SETCURSOR, wp, lp))
            return TRUE;
        return set_cursor_for_hit(hwnd, hit, HIWORD(lp));
    }
    case WM_MOUSEACTIVATE:
        if ((parent = parent_of_child(hwnd)) != 0) {
            const LRESULT r = SendMessageW(parent, WM_MOUSEACTIVATE, wp, lp);
            if (r) return r;
        }
        return MA_ACTIVATE;
    case WM_MOUSEWHEEL:
    case WM_MOUSEHWHEEL:
    case WM_APPCOMMAND:
        if ((parent = parent_of_child(hwnd)) != 0) return SendMessageW(parent, msg, wp, lp);
        return 0;
    case WM_CONTEXTMENU:
        if ((parent = parent_of_child(hwnd)) != 0) SendMessageW(parent, msg, wp, lp);
        return 0;
    case WM_RBUTTONUP: {
        POINT p = { (short)LOWORD(lp), (short)HIWORD(lp) };
        ClientToScreen(hwnd, &p);
        SendMessageW(hwnd, WM_CONTEXTMENU, (WPARAM)hwnd, MAKELPARAM((WORD)p.x, (WORD)p.y));
        return 0;
    }
    case WM_NCRBUTTONUP:
        if (wp == HTCAPTION || wp == HTSYSMENU) SendMessageW(hwnd, WM_CONTEXTMENU, (WPARAM)hwnd, lp);
        return 0;
    case WM_NCLBUTTONDOWN:
        if (wp == HTCAPTION) {
            HWND top = GetAncestor(hwnd, GA_ROOT);
            if (top && top != GetForegroundWindow()) SetForegroundWindow(top);
            SendMessageW(hwnd, WM_SYSCOMMAND, SC_MOVE | HTCAPTION, lp);
        } else if (wp >= HTSIZEFIRST && wp <= HTSIZELAST && (GetWindowLongW(hwnd, GWL_STYLE) & WS_THICKFRAME)) {
            SendMessageW(hwnd, WM_SYSCOMMAND, SC_SIZE | (wp - HTSIZEFIRST + WMSZ_LEFT), lp);
        }
        return 0;
    case WM_NCLBUTTONDBLCLK:
        if (wp == HTCAPTION && (GetWindowLongW(hwnd, GWL_STYLE) & WS_MAXIMIZEBOX))
            SendMessageW(hwnd, WM_SYSCOMMAND, IsZoomed(hwnd) ? SC_RESTORE : SC_MAXIMIZE, lp);
        return 0;
    case WM_SYSKEYDOWN:
        if (wp == VK_F4 && (lp & (1 << 29)) && !(GetWindowLongW(hwnd, GWL_STYLE) & WS_CHILD))
            SendMessageW(hwnd, WM_SYSCOMMAND, SC_CLOSE, 0);
        return 0;
    case WM_SYSCHAR:
        return 0;
    default:
        *handled = 0;
        return 0;
    }
}

/* SC_MOVE / SC_SIZE of DefWindowProc's WM_SYSCOMMAND (user32_core.c forwards them here). */
void u32_sys_move_size(HWND hwnd, WPARAM cmd)
{
    const UINT sc = (UINT)(cmd & 0xfff0);
    if (IsZoomed(hwnd) || IsIconic(hwnd)) return;
    if (sc == SC_MOVE) move_size_loop(hwnd, HTCAPTION);
    else if (sc == SC_SIZE) {
        const UINT e = (UINT)(cmd & 0xf);
        if (e >= WMSZ_LEFT && e <= WMSZ_BOTTOMRIGHT) move_size_loop(hwnd, (int)(e - WMSZ_LEFT + HTSIZEFIRST));
    }
}
