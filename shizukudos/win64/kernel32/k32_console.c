/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: console attachment, the screen buffer model, console input in UTF-16 and control handlers.
 *
 * The Kernel64 console is the system's serial console: a line-oriented character device shared by every process (kernel64
 * sysfile.c; each output line is tagged with the writing process), with no input source yet (reads report end of file). Every
 * process starts attached to it with console standard handles.
 *
 *  - FreeConsole detaches the process: console functions then fail with ERROR_INVALID_HANDLE until AllocConsole or
 *    AttachConsole attaches it again (both open new CONIN$/CONOUT$ handles and make them the standard handles).
 *  - Screen buffer: the serial device has no geometry, so kernel32 keeps the model Windows programs expect: an 80x25 cell store that is
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

BOOL k32_console_check(HANDLE h, int kind, DWORD access);
DWORD k32_console_output_mode(void);
static CHAR_INFO g_cells[CON_COLS * CON_ROWS];
static int g_cells_init;
static CONDITION_VARIABLE g_input_cv = CONDITION_VARIABLE_INIT;
static INPUT_RECORD *g_input;
static DWORD g_input_count, g_input_cap;

static void cells_init(void)                         /* g_con_lock held */
{
    unsigned i;
    if (g_cells_init) return;
    for (i = 0; i < CON_COLS * CON_ROWS; ++i) { g_cells[i].Char.UnicodeChar = ' '; g_cells[i].Attributes = g_attr; }
    g_cells_init = 1;
}

static void scroll_model(void)
{
    unsigned i;
    if (g_y < CON_ROWS) return;
    memmove(g_cells, g_cells + CON_COLS, (CON_ROWS - 1) * CON_COLS * sizeof *g_cells);
    for (i = (CON_ROWS - 1) * CON_COLS; i < CON_ROWS * CON_COLS; ++i) {
        g_cells[i].Char.UnicodeChar = ' '; g_cells[i].Attributes = g_attr;
    }
    g_y = CON_ROWS - 1;
}

static void track_char(WCHAR ch, DWORD mode)
{
    if (mode & ENABLE_PROCESSED_OUTPUT) {
        switch (ch) {
        case '\n': g_x = 0; ++g_y; scroll_model(); return;
        case '\r': g_x = 0; return;
        case '\b': if (g_x) --g_x; return;
        case '\t': {
            unsigned spaces = 8 - (g_x & 7);
            while (spaces--) track_char(' ', mode);
            return;
        }
        case 7: return;
        }
    }
    g_cells[g_y * CON_COLS + g_x].Char.UnicodeChar = ch;
    g_cells[g_y * CON_COLS + g_x].Attributes = g_attr;
    if (++g_x >= CON_COLS) {
        if (mode & ENABLE_WRAP_AT_EOL_OUTPUT) { g_x = 0; ++g_y; scroll_model(); }
        else g_x = CON_COLS - 1;
    }
}

void k32_console_track(const char *s, DWORD n)
{
    DWORD i = 0, mode = k32_console_output_mode();
    AcquireSRWLockExclusive(&g_con_lock);
    cells_init();
    while (i < n) {
        const unsigned char c = (unsigned char)s[i];
        DWORD bytes = c < 0x80 ? 1 : (c & 0xe0) == 0xc0 ? 2 : (c & 0xf0) == 0xe0 ? 3 : (c & 0xf8) == 0xf0 ? 4 : 1;
        WCHAR w[2];
        int count, j;
        if (bytes > n - i) bytes = 1;
        count = k32_utf8_to_wide(s + i, (int)bytes, w, 2);
        for (j = 0; j < count; ++j) track_char(w[j], mode);
        i += bytes;
    }
    ReleaseSRWLockExclusive(&g_con_lock);
}

static BOOL out_handle(HANDLE h) { return k32_console_check(h, 1, GENERIC_READ); }
static BOOL out_write_handle(HANDLE h) { return k32_console_check(h, 1, GENERIC_WRITE); }
static BOOL in_handle(HANDLE h) { return k32_console_check(h, 0, GENERIC_READ); }

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
    if (!out_write_handle(h)) return FALSE;
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
    (void)slot;
    if (got) *got = 0;
    if (!in_handle(h)) return FALSE;
    if (ctl) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
    if (!n) return TRUE;
    if (!buf) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (n > sizeof tmp) n = sizeof tmp;                   /* UTF-8 never yields more characters than bytes */
    if (!ReadFile(h, tmp, n, &bytes, 0)) return FALSE;
    chars = bytes ? MultiByteToWideChar(CP_UTF8, 0, tmp, (int)bytes, (LPWSTR)buf, (int)n) : 0;
    if (bytes && !chars) return FALSE;
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
    AcquireSRWLockExclusive(&g_con_lock);
    InterlockedExchange(&g_detached, 1);
    g_input_count = 0;
    WakeAllConditionVariable(&g_input_cv);
    ReleaseSRWLockExclusive(&g_con_lock);
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

/* ---------------------------------------------------------------- cursor, title, cell store and synthetic input
 * This is a process-local model of the shared serial device, not a display server. Cell fills
 * mutate readable state; input records can be injected and read by threads of this process.
 * Empty ReadConsoleInputW waits on the model's condition variable; FreeConsole wakes readers
 * with ERROR_INVALID_HANDLE. Native waits on a console handle and other processes cannot see
 * this queue yet. No keyboard source or terminal colour/cursor protocol is claimed.
 */
static DWORD g_cursor_size = 25;
static BOOL g_cursor_visible = TRUE;
static WCHAR *g_title;
static DWORD g_title_len;

K32API BOOL WINAPI SetConsoleCursorPosition(HANDLE h, COORD pos)
{
    if (!out_write_handle(h)) return FALSE;
    if (pos.X < 0 || pos.X >= CON_COLS || pos.Y < 0 || pos.Y >= CON_ROWS) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockExclusive(&g_con_lock);
    g_x = pos.X; g_y = pos.Y;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI GetConsoleCursorInfo(HANDLE h, PCONSOLE_CURSOR_INFO info)
{
    if (!out_handle(h)) return FALSE;
    if (!info) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockShared(&g_con_lock);
    info->dwSize = g_cursor_size; info->bVisible = g_cursor_visible;
    ReleaseSRWLockShared(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI SetConsoleCursorInfo(HANDLE h, const CONSOLE_CURSOR_INFO *info)
{
    if (!out_write_handle(h)) return FALSE;
    if (!info || info->dwSize < 1 || info->dwSize > 100) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockExclusive(&g_con_lock);
    g_cursor_size = info->dwSize; g_cursor_visible = !!info->bVisible;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

static BOOL cell_reach(HANDLE h, DWORD len, COORD at, LPDWORD count, int write)
{
    DWORD room;
    if (!(write ? out_write_handle(h) : out_handle(h))) return FALSE;
    if (!count) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    *count = 0;
    if (at.X < 0 || at.X >= CON_COLS || at.Y < 0 || at.Y >= CON_ROWS) {
        shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE;
    }
    room = CON_COLS * CON_ROWS - ((DWORD)at.Y * CON_COLS + (DWORD)at.X);
    *count = len < room ? len : room;
    return TRUE;
}

K32API BOOL WINAPI FillConsoleOutputCharacterW(HANDLE h, WCHAR ch, DWORD len, COORD at, LPDWORD written)
{
    DWORD i, start;
    if (!cell_reach(h, len, at, written, 1)) return FALSE;
    start = (DWORD)at.Y * CON_COLS + (DWORD)at.X;
    AcquireSRWLockExclusive(&g_con_lock);
    cells_init();
    for (i = 0; i < *written; ++i) g_cells[start + i].Char.UnicodeChar = ch;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI FillConsoleOutputAttribute(HANDLE h, WORD attr, DWORD len, COORD at, LPDWORD written)
{
    DWORD i, start;
    if (!cell_reach(h, len, at, written, 1)) return FALSE;
    start = (DWORD)at.Y * CON_COLS + (DWORD)at.X;
    AcquireSRWLockExclusive(&g_con_lock);
    cells_init();
    for (i = 0; i < *written; ++i) g_cells[start + i].Attributes = attr;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI ReadConsoleOutputCharacterW(HANDLE h, LPWSTR buf, DWORD len, COORD at, LPDWORD got)
{
    DWORD i, start;
    if (!buf && len) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!cell_reach(h, len, at, got, 0)) return FALSE;
    start = (DWORD)at.Y * CON_COLS + (DWORD)at.X;
    AcquireSRWLockExclusive(&g_con_lock);
    cells_init();
    for (i = 0; i < *got; ++i) buf[i] = g_cells[start + i].Char.UnicodeChar;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI ReadConsoleOutputAttribute(HANDLE h, LPWORD buf, DWORD len, COORD at, LPDWORD got)
{
    DWORD i, start;
    if (!buf && len) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!cell_reach(h, len, at, got, 0)) return FALSE;
    start = (DWORD)at.Y * CON_COLS + (DWORD)at.X;
    AcquireSRWLockExclusive(&g_con_lock);
    cells_init();
    for (i = 0; i < *got; ++i) buf[i] = g_cells[start + i].Attributes;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI SetConsoleTitleW(LPCWSTR title)
{
    size_t n;
    WCHAR *copy, *old;
    if (g_detached) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    if (!title) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    n = k32_wlen(title);
    if (n >= 32768) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    copy = RtlAllocateHeap(ShzProcessHeap(), 0, (n + 1) * sizeof *copy);
    if (!copy) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    memcpy(copy, title, (n + 1) * sizeof *copy);
    AcquireSRWLockExclusive(&g_con_lock);
    old = g_title; g_title = copy; g_title_len = (DWORD)n;
    ReleaseSRWLockExclusive(&g_con_lock);
    if (old) RtlFreeHeap(ShzProcessHeap(), 0, old);
    return TRUE;
}

K32API DWORD WINAPI GetConsoleTitleW(LPWSTR title, DWORD cap)
{
    DWORD n;
    if (g_detached) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    if (!title || !cap) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    AcquireSRWLockShared(&g_con_lock);
    n = g_title_len < cap - 1 ? g_title_len : cap - 1;
    if (n) memcpy(title, g_title, n * sizeof *title);
    title[n] = 0;
    ReleaseSRWLockShared(&g_con_lock);
    return n;
}

K32API BOOL WINAPI GetNumberOfConsoleInputEvents(HANDLE h, LPDWORD n)
{
    if (!in_handle(h)) return FALSE;
    if (!n) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockShared(&g_con_lock);
    *n = g_input_count;
    ReleaseSRWLockShared(&g_con_lock);
    return TRUE;
}

static BOOL input_read(HANDLE h, PINPUT_RECORD buf, DWORD len, LPDWORD got, int peek)
{
    DWORD count;
    if (got) *got = 0;
    if (!in_handle(h)) return FALSE;
    if ((!buf && len) || !got) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!len) return TRUE;
    AcquireSRWLockExclusive(&g_con_lock);
    while (!g_input_count && !peek) {
        if (g_detached) { ReleaseSRWLockExclusive(&g_con_lock); shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
        if (!SleepConditionVariableSRW(&g_input_cv, &g_con_lock, INFINITE, 0)) {
            ReleaseSRWLockExclusive(&g_con_lock); return FALSE;
        }
    }
    if (g_detached) { ReleaseSRWLockExclusive(&g_con_lock); shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    count = len < g_input_count ? len : g_input_count;
    if (count) memcpy(buf, g_input, count * sizeof *buf);
    if (!peek && count) {
        g_input_count -= count;
        memmove(g_input, g_input + count, g_input_count * sizeof *g_input);
    }
    *got = count;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI ReadConsoleInputW(HANDLE h, PINPUT_RECORD buf, DWORD len, LPDWORD got)
{
    return input_read(h, buf, len, got, 0);
}
K32API BOOL WINAPI PeekConsoleInputW(HANDLE h, PINPUT_RECORD buf, DWORD len, LPDWORD got)
{
    return input_read(h, buf, len, got, 1);
}
K32API BOOL WINAPI FlushConsoleInputBuffer(HANDLE h)
{
    if (!k32_console_check(h, 0, GENERIC_WRITE)) return FALSE;
    AcquireSRWLockExclusive(&g_con_lock);
    g_input_count = 0;
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}

K32API BOOL WINAPI WriteConsoleInputW(HANDLE h, const INPUT_RECORD *buf, DWORD len, LPDWORD written)
{
    DWORD need, cap;
    INPUT_RECORD *copy;
    if (written) *written = 0;
    if (!k32_console_check(h, 0, GENERIC_WRITE)) return FALSE;
    if ((!buf && len) || !written) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!len) return TRUE;
    AcquireSRWLockExclusive(&g_con_lock);
    if (len > 0xffffffffu - g_input_count) {
        ReleaseSRWLockExclusive(&g_con_lock); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE;
    }
    need = g_input_count + len;
    if (need > g_input_cap) {
        cap = need < 32 ? 32 : need;
        copy = RtlAllocateHeap(ShzProcessHeap(), 0, (SIZE_T)cap * sizeof *copy);
        if (!copy) { ReleaseSRWLockExclusive(&g_con_lock); shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        if (g_input_count) memcpy(copy, g_input, g_input_count * sizeof *copy);
        if (g_input) RtlFreeHeap(ShzProcessHeap(), 0, g_input);
        g_input = copy; g_input_cap = cap;
    }
    memcpy(g_input + g_input_count, buf, (SIZE_T)len * sizeof *buf);
    g_input_count = need;
    *written = len;
    WakeAllConditionVariable(&g_input_cv);
    ReleaseSRWLockExclusive(&g_con_lock);
    return TRUE;
}
