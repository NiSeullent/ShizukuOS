/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: console attachment, the screen buffer model, console input in UTF-16 and control handlers.
 *
 * The Kernel64 console is the system's serial console: a line-oriented character device shared by every process (kernel64
 * sysfile.c; each output line is tagged with the writing process), with no input source yet (reads report end of file). Every
 * process starts attached to it with console standard handles.
 *
 *  - FreeConsole detaches the process: console functions then fail with ERROR_INVALID_HANDLE until AllocConsole or
 *    AttachConsole attaches it again (both open new CONIN$/CONOUT$ handles and make them the standard handles).
 *  - Screen buffer: the device has no geometry, so kernel32 keeps the model Windows programs expect: an 80x25 buffer that is
 *    also the window, a cursor that follows the text this process writes to its console handles (WriteConsole, and WriteFile to
 *    a standard output/error handle; CR, LF, BS, TAB and wrapping at column 80 as in processed-output mode, scrolling at the
 *    bottom row), and the current text attribute. The serial line carries no colour, so an attribute changes only the model.
 *  - Control handlers are kept in registration order and SetConsoleCtrlHandler(NULL, TRUE) sets the "ignore CTRL+C" flag. The
 *    serial console delivers no CTRL+C / CTRL+BREAK / close events, so no handler is ever called.
 */
#include "k32.h"
#ifndef LF_FACESIZE
#define LF_FACESIZE 32                                    /* wingdi.h (not included by kernel32) */
#endif
#include <wincon.h>

#define CON_COLS 80
#define CON_ROWS 25

static volatile LONG g_detached;
static SRWLOCK g_con_lock = SRWLOCK_INIT;
static SHORT g_x, g_y;
static WORD g_attr = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;       /* 0x07, the default */

int k32_console_attached(void) { return !g_detached; }

/* k32_file.c: is `h` a console handle (FILE_ATTRIBUTE_DEVICE console object) and which standard slot holds it (-1 none) */
int k32_console_handle(HANDLE h, int *std_slot);

void k32_console_track(const char *s, DWORD n)
{
    DWORD i;
    AcquireSRWLockExclusive(&g_con_lock);
    for (i = 0; i < n; ++i) {
        const unsigned char c = (unsigned char)s[i];
        if ((c & 0xc0) == 0x80) continue;                 /* UTF-8 continuation byte: same character cell */
        switch (c) {
        case '\n': g_x = 0; ++g_y; break;
        case '\r': g_x = 0; break;
        case '\b': if (g_x) --g_x; break;
        case '\t': g_x = (SHORT)((g_x + 8) & ~7); break;
        case 7: break;                                    /* BEL moves nothing */
        default: ++g_x; break;
        }
        if (g_x >= CON_COLS) { g_x = 0; ++g_y; }
        if (g_y >= CON_ROWS) g_y = CON_ROWS - 1;          /* the buffer scrolls up one line */
    }
    ReleaseSRWLockExclusive(&g_con_lock);
}

static BOOL out_handle(HANDLE h)
{
    int slot = -1;
    if (g_detached || !k32_console_handle(h, &slot) || slot == 0) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    return TRUE;
}

K32API BOOL WINAPI GetConsoleScreenBufferInfo(HANDLE h, PCONSOLE_SCREEN_BUFFER_INFO info)
{
    if (!out_handle(h)) return FALSE;
    if (!info) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockShared(&g_con_lock);
    info->dwSize.X = CON_COLS; info->dwSize.Y = CON_ROWS;
    info->dwCursorPosition.X = g_x; info->dwCursorPosition.Y = g_y;
    info->wAttributes = g_attr;
    info->srWindow.Left = 0; info->srWindow.Top = 0; info->srWindow.Right = CON_COLS - 1; info->srWindow.Bottom = CON_ROWS - 1;
    info->dwMaximumWindowSize.X = CON_COLS; info->dwMaximumWindowSize.Y = CON_ROWS;
    ReleaseSRWLockShared(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI SetConsoleTextAttribute(HANDLE h, WORD attr)
{
    if (!out_handle(h)) return FALSE;
    AcquireSRWLockExclusive(&g_con_lock);
    g_attr = attr;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI GetConsoleDisplayMode(LPDWORD flags)
{
    if (!flags) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (g_detached) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    *flags = 0;                                           /* neither CONSOLE_FULLSCREEN nor CONSOLE_FULLSCREEN_HARDWARE */
    return TRUE;
}

K32API BOOL WINAPI ReadConsoleW(HANDLE h, LPVOID buf, DWORD n, LPDWORD got, LPVOID ctl)
{
    char tmp[512];
    DWORD bytes = 0;
    int chars;
    int slot = -1;
    (void)ctl;
    if (g_detached || !k32_console_handle(h, &slot)) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    if (!buf) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n > sizeof tmp) n = sizeof tmp;                   /* UTF-8 never yields more characters than bytes */
    if (!ReadFile(h, tmp, n, &bytes, 0)) return FALSE;
    chars = bytes ? MultiByteToWideChar(CP_UTF8, 0, tmp, (int)bytes, (LPWSTR)buf, (int)n) : 0;
    if (got) *got = (DWORD)chars;
    return TRUE;
}

/* ---------------------------------------------------------------- attachment */
static BOOL attach_new(void)
{
    HANDLE in = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    HANDLE out = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    HANDLE err;
    if (in == INVALID_HANDLE_VALUE || out == INVALID_HANDLE_VALUE) {
        if (in != INVALID_HANDLE_VALUE) CloseHandle(in);
        if (out != INVALID_HANDLE_VALUE) CloseHandle(out);
        return FALSE;
    }
    if (!DuplicateHandle(GetCurrentProcess(), out, GetCurrentProcess(), &err, 0, FALSE, DUPLICATE_SAME_ACCESS)) err = out;
    SetStdHandle(STD_INPUT_HANDLE, in);
    SetStdHandle(STD_OUTPUT_HANDLE, out);
    SetStdHandle(STD_ERROR_HANDLE, err);
    AcquireSRWLockExclusive(&g_con_lock);
    g_x = 0; g_y = 0;
    ReleaseSRWLockExclusive(&g_con_lock);
    InterlockedExchange(&g_detached, 0);
    return TRUE;
}

K32API BOOL WINAPI AllocConsole(void)
{
    if (!g_detached) { shz_set_last_error(ERROR_ACCESS_DENIED); return FALSE; }       /* one console per process */
    return attach_new();
}

K32API BOOL WINAPI FreeConsole(void)
{
    if (g_detached) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    InterlockedExchange(&g_detached, 1);
    return TRUE;
}

K32API BOOL WINAPI AttachConsole(DWORD pid)
{
    ULONG v[6];
    if (!g_detached) { shz_set_last_error(ERROR_ACCESS_DENIED); return FALSE; }
    if (pid == ATTACH_PARENT_PROCESS) {
        if (NtShzQueryK32(K32Q_PROCESS_INFO, GetCurrentProcess(), v, sizeof v, 0) || !v[3]) {
            shz_set_last_error(ERROR_INVALID_HANDLE);   /* started by the kernel: no parent process, so no parent console */
            return FALSE;
        }
    } else {
        struct { ULONG pid, ppid, threads, cls; char name[32]; } list[64];
        ULONG need = 0, i, hit = 0;
        if (NtShzQueryK32(K32Q_PROCESS_LIST, 0, list, sizeof list, &need) == 0)
            for (i = 0; i < need / sizeof list[0]; ++i) hit |= list[i].pid == pid;
        if (!hit) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    }
    return attach_new();                                  /* every Kernel64 process runs on the one system console */
}

/* ---------------------------------------------------------------- control handlers */
static PHANDLER_ROUTINE *g_handlers;
static unsigned g_nhandlers, g_caphandlers;
static volatile LONG g_ignore_ctrl_c;

K32API BOOL WINAPI SetConsoleCtrlHandler(PHANDLER_ROUTINE fn, BOOL add)
{
    unsigned i;
    BOOL ok = TRUE;
    if (!fn) { InterlockedExchange(&g_ignore_ctrl_c, add ? 1 : 0); return TRUE; }
    AcquireSRWLockExclusive(&g_con_lock);
    if (add) {
        if (g_nhandlers == g_caphandlers) {
            unsigned cap = g_caphandlers ? g_caphandlers * 2 : 8;
            PHANDLER_ROUTINE *n = g_handlers ? RtlReAllocateHeap(ShzProcessHeap(), 0, g_handlers, cap * sizeof *n)
                                             : RtlAllocateHeap(ShzProcessHeap(), 0, cap * sizeof *n);
            if (!n) { ReleaseSRWLockExclusive(&g_con_lock); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
            g_handlers = n;
            g_caphandlers = cap;
        }
        g_handlers[g_nhandlers++] = fn;
    } else {
        for (i = g_nhandlers; i > 0 && g_handlers[i - 1] != fn; --i) { }       /* the most recent registration goes first */
        if (!i) ok = FALSE;
        else { memmove(&g_handlers[i - 1], &g_handlers[i], (g_nhandlers - i) * sizeof *g_handlers); --g_nhandlers; }
    }
    ReleaseSRWLockExclusive(&g_con_lock);
    if (!ok) shz_set_last_error(ERROR_INVALID_PARAMETER);
    return ok;
}
