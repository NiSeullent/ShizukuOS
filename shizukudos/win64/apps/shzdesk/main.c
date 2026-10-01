/* SPDX-License-Identifier: GPL-2.0-only
 * Persistent ShizukuDOS desktop. All tools perform their work through the Win64
 * runtime; none of the action markers substitutes for an API result.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"
/* The shell-only API is exported by user32, but absent from MinGW's public header. */
__declspec(dllimport) BOOL WINAPI SetShellWindow(HWND hwnd);

#define PATH_CAP 260
#define TEXT_CAP 32768
#define FILE_CAP 128
#define CHILD_CAP 8
#define BAR_HEIGHT 38

static HINSTANCE g_instance;
static HWND g_desktop, g_files, g_editor;
static int g_width, g_height, g_start, g_exit_confirm, g_desktop_painted;
static WCHAR g_status[160] = L"Ready. F2 Files   F3 Editor   F4 Run hello   F10 End session";
static WCHAR g_directory[PATH_CAP] = L"C:\\";
static WCHAR g_document[PATH_CAP] = L"D:\\DESKTOP.TXT";
static WCHAR g_path_input[PATH_CAP];
static int g_path_edit, g_path_replace;
static char g_text[TEXT_CAP], g_scratch[TEXT_CAP];
static DWORD g_text_bytes, g_caret;
static int g_dirty, g_editor_scroll;
static struct file_row {
    WCHAR name[PATH_CAP];
    DWORD attrs;
    unsigned long long bytes;
} g_rows[FILE_CAP];
static unsigned g_row_count, g_total_count, g_top;
static int g_selected = -1;
static struct child {
    HANDLE process;
    DWORD pid;
} g_children[CHILD_CAP];

static void wcopy(WCHAR *dst, unsigned cap, const WCHAR *src)
{
    unsigned i = 0;
    if (!cap) return;
    while (src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}

static void ascii(WCHAR *dst, unsigned cap, const char *src)
{
    unsigned i = 0;
    while (src[i] && i + 1 < cap) { dst[i] = (WCHAR)(unsigned char)src[i]; ++i; }
    dst[i] = 0;
}

static void narrow(char *dst, unsigned cap, const WCHAR *src)
{
    unsigned i = 0;
    while (src[i] && i + 1 < cap) { dst[i] = src[i] < 128 ? (char)src[i] : '?'; ++i; }
    dst[i] = 0;
}

static void redraw(HWND hwnd) { if (hwnd) InvalidateRect(hwnd, 0, TRUE); }

static void status(const WCHAR *text)
{
    wcopy(g_status, 160, text);
    redraw(g_desktop);
    redraw(g_files);
    redraw(g_editor);
}

static void failure(const char *operation, DWORD error)
{
    char line[160];
    snprintf(line, sizeof line, "%s failed: error %lu. Your unsaved text is retained.", operation, (unsigned long)error);
    ascii(g_status, 160, line);
    printf("SHZ-DESKTOP ERROR operation=%s error=%lu\n", operation, (unsigned long)error);
    redraw(g_desktop); redraw(g_files); redraw(g_editor);
}

static void fill(HDC dc, int l, int t, int r, int b, COLORREF color)
{
    RECT rc = { l, t, r, b };
    HBRUSH brush = CreateSolidBrush(color);
    if (brush) { FillRect(dc, &rc, brush); DeleteObject(brush); }
}

static void label(HDC dc, int x, int y, const WCHAR *text, COLORREF color)
{
    SetTextColor(dc, color);
    TextOutW(dc, x, y, text, lstrlenW(text));
}

static void button(HDC dc, int x, int y, int width, const WCHAR *text, int pressed)
{
    fill(dc, x, y, x + width, y + 28, RGB(192, 192, 192));
    fill(dc, x, y, x + width, y + 1, pressed ? RGB(64, 64, 64) : RGB(255, 255, 255));
    fill(dc, x, y, x + 1, y + 28, pressed ? RGB(64, 64, 64) : RGB(255, 255, 255));
    fill(dc, x, y + 27, x + width, y + 28, pressed ? RGB(255, 255, 255) : RGB(64, 64, 64));
    fill(dc, x + width - 1, y, x + width, y + 28, pressed ? RGB(255, 255, 255) : RGB(64, 64, 64));
    label(dc, x + 8, y + 6, text, RGB(0, 0, 0));
}

static int join_path(WCHAR *out, const WCHAR *directory, const WCHAR *name)
{
    unsigned a = (unsigned)lstrlenW(directory), b = (unsigned)lstrlenW(name), i;
    int slash = a && directory[a - 1] != '\\';
    if (a + b + (unsigned)slash >= PATH_CAP) return 0;
    wcopy(out, PATH_CAP, directory);
    if (slash) out[a++] = '\\';
    for (i = 0; i <= b; ++i) out[a + i] = name[i];
    return 1;
}

static void content_marker(void)
{
    char escaped[1025];
    unsigned i, n = 0;
    for (i = 0; i < g_text_bytes && i < 128; ++i) {
        const unsigned char c = (unsigned char)g_text[i];
        if (c == '\n' || c == '\r' || c == '\t' || c == '\\') {
            escaped[n++] = '\\';
            escaped[n++] = c == '\n' ? 'n' : c == '\r' ? 'r' : c == '\t' ? 't' : '\\';
        } else escaped[n++] = c >= 32 && c < 127 ? (char)c : '?';
    }
    escaped[n] = 0;
    printf("SHZ-DESKTOP CONTENT %s\n", escaped);
    if (g_text_bytes > 128) printf("SHZ-DESKTOP CONTENT-TRUNCATED bytes=%lu\n", (unsigned long)g_text_bytes);
}

static int read_document(const WCHAR *path, DWORD *bytes)
{
    LARGE_INTEGER size;
    DWORD offset = 0, got, error;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) { failure("Open", GetLastError()); return 0; }
    if (!GetFileSizeEx(file, &size)) {
        error = GetLastError(); CloseHandle(file); failure("File size", error); return 0;
    }
    if (size.QuadPart < 0 || size.QuadPart >= TEXT_CAP) {
        CloseHandle(file); failure("File larger than 32767 bytes", ERROR_FILE_TOO_LARGE); return 0;
    }
    while (offset < (DWORD)size.QuadPart) {
        if (!ReadFile(file, g_scratch + offset, (DWORD)size.QuadPart - offset, &got, 0) || !got) {
            error = GetLastError(); CloseHandle(file); failure("Read", error ? error : ERROR_HANDLE_EOF); return 0;
        }
        offset += got;
    }
    if (!CloseHandle(file)) { failure("Close after read", GetLastError()); return 0; }
    g_scratch[offset] = 0;
    *bytes = offset;
    return 1;
}

static int open_document(const WCHAR *path)
{
    DWORD bytes, i;
    char name[PATH_CAP];
    if (g_dirty) {
        status(L"Save your changes first with Ctrl+S before opening another file.");
        printf("SHZ-DESKTOP REFUSED operation=Open reason=unsaved-text\n");
        return 0;
    }
    if (!read_document(path, &bytes)) return 0;
    for (i = 0; i < bytes; ++i) {
        const unsigned char c = (unsigned char)g_scratch[i];
        if ((c < 32 && c != '\n' && c != '\r' && c != '\t') || c > 126) {
            failure("ASCII text only", ERROR_NO_UNICODE_TRANSLATION); return 0;
        }
    }
    memcpy(g_text, g_scratch, bytes + 1);
    g_text_bytes = bytes; g_caret = bytes; g_editor_scroll = 0; g_dirty = 0;
    wcopy(g_document, PATH_CAP, path);
    narrow(name, sizeof name, g_document);
    printf("SHZ-DESKTOP OPENED path=%s bytes=%lu\n", name, (unsigned long)bytes);
    content_marker();
    status(L"File opened. ASCII text editor: Ctrl+S saves; Ctrl+L changes the path.");
    redraw(g_editor);
    return 1;
}

static void save_document(void)
{
    HANDLE file;
    DWORD offset = 0, written, error, bytes;
    char name[PATH_CAP];
    file = CreateFileW(g_document, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) { failure("Save", GetLastError()); return; }
    while (offset < g_text_bytes) {
        if (!WriteFile(file, g_text + offset, g_text_bytes - offset, &written, 0) || !written) {
            error = GetLastError(); CloseHandle(file); failure("Write", error ? error : ERROR_WRITE_FAULT); return;
        }
        offset += written;
    }
    if (!FlushFileBuffers(file)) {
        error = GetLastError(); CloseHandle(file); failure("Flush", error); return;
    }
    if (!CloseHandle(file)) { failure("Close after save", GetLastError()); return; }
    if (!read_document(g_document, &bytes)) return;
    if (bytes != g_text_bytes || memcmp(g_text, g_scratch, bytes)) {
        failure("Read-back verification", ERROR_CRC); return;
    }
    g_dirty = 0; g_exit_confirm = 0;
    narrow(name, sizeof name, g_document);
    printf("SHZ-DESKTOP SAVED path=%s bytes=%lu verified=1\n", name, (unsigned long)bytes);
    content_marker();
    status(L"Saved and read back: all bytes match. Ctrl+O reopens the saved file.");
}

static void list_directory(void)
{
    WIN32_FIND_DATAW fd;
    WCHAR pattern[PATH_CAP];
    char directory[PATH_CAP];
    HANDLE find;
    DWORD error = ERROR_SUCCESS;
    g_row_count = g_total_count = g_top = 0; g_selected = -1;
    if (!join_path(pattern, g_directory, L"*")) { failure("Directory path", ERROR_FILENAME_EXCED_RANGE); return; }
    find = FindFirstFileW(pattern, &fd);
    if (find == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        if (error != ERROR_FILE_NOT_FOUND) { failure("List directory", error); return; }
        if (GetFileAttributesW(g_directory) == INVALID_FILE_ATTRIBUTES) { failure("Directory unavailable", GetLastError()); return; }
    } else {
        do {
            char name[PATH_CAP];
            if ((fd.cFileName[0] == '.' && !fd.cFileName[1]) ||
                (fd.cFileName[0] == '.' && fd.cFileName[1] == '.' && !fd.cFileName[2])) continue;
            if (g_row_count < FILE_CAP) {
                struct file_row *r = &g_rows[g_row_count++];
                wcopy(r->name, PATH_CAP, fd.cFileName);
                r->attrs = fd.dwFileAttributes;
                r->bytes = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                narrow(name, sizeof name, r->name);
                printf("SHZ-DESKTOP FILE name=%s dir=%d bytes=%llu\n", name,
                       (r->attrs & FILE_ATTRIBUTE_DIRECTORY) != 0, r->bytes);
            }
            ++g_total_count;
        } while (FindNextFileW(find, &fd));
        error = GetLastError();
        FindClose(find);
        if (error != ERROR_NO_MORE_FILES) { failure("Directory enumeration", error); return; }
    }
    narrow(directory, sizeof directory, g_directory);
    printf("SHZ-DESKTOP FILES path=%s count=%u displayed=%u\n", directory, g_total_count, g_row_count);
    status(g_total_count > FILE_CAP ? L"Directory loaded; the first 128 entries are shown." : L"Directory loaded. Select a file and press Enter to open it.");
}

static void poll_children(void)
{
    unsigned i;
    for (i = 0; i < CHILD_CAP; ++i) if (g_children[i].process) {
        DWORD result = WaitForSingleObject(g_children[i].process, 0), code;
        if (result == WAIT_OBJECT_0) {
            char text[120];
            if (GetExitCodeProcess(g_children[i].process, &code)) {
                printf("SHZ-DESKTOP APP-EXIT pid=%lu code=%lu\n", (unsigned long)g_children[i].pid, (unsigned long)code);
                snprintf(text, sizeof text, "Application %lu exited with code %lu.", (unsigned long)g_children[i].pid, (unsigned long)code);
                ascii(g_status, 160, text); redraw(g_desktop);
            } else failure("Get application exit code", GetLastError());
            CloseHandle(g_children[i].process); g_children[i].process = 0;
        } else if (result == WAIT_FAILED) {
            failure("Wait for application", GetLastError());
            CloseHandle(g_children[i].process); g_children[i].process = 0;
        }
    }
}

static void launch_application(const WCHAR *path)
{
    WCHAR command[PATH_CAP + 4], cwd[PATH_CAP];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    unsigned slot, n, i;
    char name[PATH_CAP], text[120];
    poll_children();
    for (slot = 0; slot < CHILD_CAP && g_children[slot].process; ++slot) { }
    if (slot == CHILD_CAP) { failure("Eight tracked applications already running", ERROR_TOO_MANY_OPEN_FILES); return; }
    n = (unsigned)lstrlenW(path);
    if (n >= PATH_CAP) { failure("Application path", ERROR_FILENAME_EXCED_RANGE); return; }
    command[0] = '"';
    for (i = 0; i < n; ++i) command[i + 1] = path[i];
    command[n + 1] = '"'; command[n + 2] = 0;
    wcopy(cwd, PATH_CAP, path);
    while (n && cwd[n - 1] != '\\') --n;
    cwd[n > 3 ? n - 1 : n] = 0;
    memset(&si, 0, sizeof si); memset(&pi, 0, sizeof pi); si.cb = sizeof si;
    if (!CreateProcessW(path, command, 0, 0, FALSE, 0, 0, cwd[0] ? cwd : 0, &si, &pi)) {
        failure("Launch application", GetLastError()); return;
    }
    CloseHandle(pi.hThread);
    g_children[slot].process = pi.hProcess; g_children[slot].pid = pi.dwProcessId;
    narrow(name, sizeof name, path);
    printf("SHZ-DESKTOP LAUNCHED pid=%lu path=%s\n", (unsigned long)pi.dwProcessId, name);
    snprintf(text, sizeof text, "Application started as process %lu; its exit code will be reported.", (unsigned long)pi.dwProcessId);
    ascii(g_status, 160, text); redraw(g_desktop);
}

static void show_files(void)
{
    g_start = 0;
    list_directory();
    ShowWindow(g_files, SW_RESTORE); SetForegroundWindow(g_files); SetFocus(g_files); redraw(g_files); redraw(g_desktop);
}

static void show_editor(void)
{
    char path[PATH_CAP];
    g_start = 0;
    ShowWindow(g_editor, SW_RESTORE); SetForegroundWindow(g_editor); SetFocus(g_editor); redraw(g_editor); redraw(g_desktop);
    narrow(path, sizeof path, g_document);
    printf("SHZ-DESKTOP EDITOR path=%s bytes=%lu dirty=%d\n", path, (unsigned long)g_text_bytes, g_dirty);
}

static void up_directory(void)
{
    unsigned n = (unsigned)lstrlenW(g_directory);
    if (n <= 3) return;
    if (g_directory[n - 1] == '\\') --n;
    while (n > 3 && g_directory[n - 1] != '\\') --n;
    g_directory[n] = 0;
    list_directory();
}

static void open_selection(void)
{
    WCHAR path[PATH_CAP];
    const struct file_row *row;
    unsigned n;
    if (g_selected < 0 || (unsigned)g_selected >= g_row_count) return;
    row = &g_rows[g_selected];
    if (!join_path(path, g_directory, row->name)) { failure("File path", ERROR_FILENAME_EXCED_RANGE); return; }
    if (row->attrs & FILE_ATTRIBUTE_DIRECTORY) {
        wcopy(g_directory, PATH_CAP, path); list_directory(); redraw(g_files); return;
    }
    n = (unsigned)lstrlenW(path);
    if (n >= 4 && path[n - 4] == '.' && (path[n - 3] == 'e' || path[n - 3] == 'E') &&
        (path[n - 2] == 'x' || path[n - 2] == 'X') && (path[n - 1] == 'e' || path[n - 1] == 'E')) {
        launch_application(path); return;
    }
    if (open_document(path)) show_editor();
}

static void begin_path_edit(void)
{
    wcopy(g_path_input, PATH_CAP, g_document); g_path_edit = g_path_replace = 1;
    status(L"Type an absolute path, then Enter. Escape cancels. Example: E:\\DESKTOP.TXT");
}

static void finish_path_edit(void)
{
    const unsigned n = (unsigned)lstrlenW(g_path_input);
    if (n < 4 || g_path_input[1] != ':' || g_path_input[2] != '\\' || g_path_input[n - 1] == '\\') {
        status(L"Use an absolute file path such as D:\\DESKTOP.TXT. Escape cancels."); return;
    }
    wcopy(g_document, PATH_CAP, g_path_input); g_path_edit = 0;
    status(L"Path changed. Ctrl+S writes your text; Ctrl+O opens this path.");
}

static void insert_character(char c)
{
    DWORD i;
    if (g_text_bytes + 1 >= TEXT_CAP) { failure("Text buffer full", ERROR_INSUFFICIENT_BUFFER); return; }
    for (i = g_text_bytes; i > g_caret; --i) g_text[i] = g_text[i - 1];
    g_text[g_caret++] = c; g_text[++g_text_bytes] = 0; g_dirty = 1;
    g_exit_confirm = 0;
}

static void erase_character(int backward)
{
    DWORD i;
    if (backward) { if (!g_caret) return; --g_caret; }
    else if (g_caret >= g_text_bytes) return;
    for (i = g_caret; i < g_text_bytes; ++i) g_text[i] = g_text[i + 1];
    --g_text_bytes; g_dirty = 1; g_exit_confirm = 0;
}

static void paint_desktop(HDC dc)
{
    const int bar = g_height - BAR_HEIGHT;
    fill(dc, 0, 0, g_width, bar, RGB(0, 128, 128));
    label(dc, 20, 18, L"ShizukuDOS", RGB(255, 255, 255));
    button(dc, 20, 52, 144, L"Files   [F2]", 0);
    button(dc, 20, 98, 144, L"Editor  [F3]", 0);
    button(dc, 20, 144, 144, L"Hello   [F4]", 0);
    label(dc, 20, bar - 32, g_status, RGB(255, 255, 255));
    fill(dc, 0, bar, g_width, g_height, RGB(192, 192, 192));
    fill(dc, 0, bar, g_width, bar + 1, RGB(255, 255, 255));
    button(dc, 4, bar + 5, 78, L"Start", g_start > 0);
    button(dc, 90, bar + 5, 132, L"Files [F2]", IsWindowVisible(g_files));
    button(dc, 230, bar + 5, 140, L"Editor [F3]", IsWindowVisible(g_editor));
    label(dc, 390, bar + 12, L"F10: End session", RGB(0, 0, 0));
    if (g_start > 0) {
        const int top = bar - 136;
        fill(dc, 4, top, 238, bar, RGB(192, 192, 192));
        button(dc, 8, top + 4, 226, L"Files         F2", 0);
        button(dc, 8, top + 36, 226, L"Text editor   F3", 0);
        button(dc, 8, top + 68, 226, L"Run hello     F4", 0);
        button(dc, 8, top + 100, 226, L"End session   F10", 0);
    }
}

static void paint_files(HDC dc, int width, int height)
{
    unsigned i, visible = height > 160 ? (unsigned)(height - 160) / 20 : 1;
    WCHAR text[160];
    char value[80];
    fill(dc, 0, 0, width, height, RGB(255, 255, 255));
    fill(dc, 0, 0, width, 84, RGB(192, 192, 192));
    button(dc, 8, 6, 52, L"C:", g_directory[0] == 'C');
    button(dc, 68, 6, 52, L"D:", g_directory[0] == 'D');
    button(dc, 128, 6, 52, L"E:", g_directory[0] == 'E');
    button(dc, 188, 6, 60, L"Up", 0);
    button(dc, 256, 6, 110, L"Refresh F5", 0);
    button(dc, width - 40, 6, 32, L"X", 0);
    label(dc, 8, 44, g_directory, RGB(0, 0, 0));
    label(dc, 8, 66, L"Name                                   Bytes", RGB(0, 0, 0));
    for (i = 0; i < visible && g_top + i < g_row_count; ++i) {
        const struct file_row *r = &g_rows[g_top + i];
        int y = 90 + (int)i * 20, selected = g_selected == (int)(g_top + i);
        COLORREF color = selected ? RGB(255, 255, 255) : RGB(0, 0, 0);
        if (selected) fill(dc, 4, y - 2, width - 4, y + 18, RGB(0, 0, 128));
        label(dc, 8, y, (r->attrs & FILE_ATTRIBUTE_DIRECTORY) ? L"[DIR]" : L"     ", color);
        {
            RECT clip = { 60, y, width - 150, y + 18 };
            SetTextColor(dc, color);
            DrawTextW(dc, r->name, -1, &clip, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
        }
        snprintf(value, sizeof value, "%llu", r->bytes); ascii(text, 160, value);
        label(dc, width - 136, y, text, color);
    }
    fill(dc, 0, height - 56, width, height, RGB(192, 192, 192));
    label(dc, 8, height - 50, L"Enter: open/launch  Arrows: select  Backspace: up  Esc: close", RGB(0, 0, 0));
    { RECT clip = { 8, height - 26, width - 8, height - 6 };
      DrawTextW(dc, g_status, -1, &clip, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX); }
}

static void paint_editor(HDC dc, int width, int height)
{
    DWORD i, line = 0, caret_line = 0, caret_column = 0, column = 0;
    const unsigned columns = width > 32 ? (unsigned)(width - 32) / 8 : 1;
    const unsigned visible = height > 150 ? (unsigned)(height - 150) / 18 : 1;
    WCHAR row[256];
    unsigned n = 0;
    char info[80];
    WCHAR text[160];
    for (i = 0; i < g_caret; ++i) {
        if (g_text[i] == '\n') { ++caret_line; caret_column = 0; }
        else if (g_text[i] != '\r' && ++caret_column >= columns) { ++caret_line; caret_column = 0; }
    }
    if ((int)caret_line < g_editor_scroll) g_editor_scroll = (int)caret_line;
    if (caret_line >= (unsigned)g_editor_scroll + visible) g_editor_scroll = (int)(caret_line - visible + 1);
    fill(dc, 0, 0, width, height, RGB(255, 255, 255));
    fill(dc, 0, 0, width, 80, RGB(192, 192, 192));
    button(dc, 8, 6, 100, L"Save ^S", 0);
    button(dc, 116, 6, 100, L"Open ^O", 0);
    button(dc, 224, 6, 100, L"Path ^L", g_path_edit);
    button(dc, 332, 6, 72, L"New ^N", 0);
    button(dc, width - 40, 6, 32, L"X", 0);
    label(dc, 8, 44, g_path_edit ? g_path_input : g_document, RGB(0, 0, 0));
    snprintf(info, sizeof info, "%lu bytes   %s   ASCII / LF", (unsigned long)g_text_bytes, g_dirty ? "unsaved" : "saved");
    ascii(text, 160, info); label(dc, 8, 64, text, RGB(0, 0, 0));
    for (i = 0; i <= g_text_bytes; ++i) {
        char c = i < g_text_bytes ? g_text[i] : '\n';
        if (c == '\r') continue;
        if (c == '\n' || column >= columns || n >= 254) {
            if (line >= (unsigned)g_editor_scroll && line < (unsigned)g_editor_scroll + visible) {
                row[n] = 0; label(dc, 12, 90 + ((int)line - g_editor_scroll) * 18, row, RGB(0, 0, 0));
            }
            ++line; n = 0; column = 0;
            if (c == '\n') continue;
        }
        row[n++] = c == '\t' ? ' ' : (WCHAR)(unsigned char)c; ++column;
    }
    if (!g_path_edit) fill(dc, 12 + (int)caret_column * 8, 90 + ((int)caret_line - g_editor_scroll) * 18 + 15,
                          20 + (int)caret_column * 8, 107 + ((int)caret_line - g_editor_scroll) * 18, RGB(0, 0, 0));
    fill(dc, 0, height - 48, width, height, RGB(192, 192, 192));
    label(dc, 8, height - 44, L"Type text. Ctrl+S save  Ctrl+O open  Ctrl+L path  Esc close", RGB(0, 0, 0));
    { RECT clip = { 8, height - 24, width - 8, height - 4 };
      DrawTextW(dc, g_status, -1, &clip, DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX); }
}

static void end_session(void)
{
    unsigned i;
    if (g_dirty) {
        status(L"Unsaved text: Ctrl+S before ending the session. F10 again discards it.");
        if (!g_exit_confirm) { g_exit_confirm = 1; printf("SHZ-DESKTOP REFUSED operation=Exit reason=unsaved-text\n"); return; }
    }
    poll_children();
    for (i = 0; i < CHILD_CAP; ++i) if (g_children[i].process) {
        CloseHandle(g_children[i].process); g_children[i].process = 0;
    }
    printf("SHZ-DESKTOP EXIT requested=1\n");
    PostQuitMessage(0);
}

static int key(HWND hwnd, WPARAM vk)
{
    int ctrl = GetKeyState(VK_CONTROL) < 0;
    if (vk != VK_F10) g_exit_confirm = 0;
    if (vk == VK_F2) { show_files(); return 1; }
    if (vk == VK_F3) { show_editor(); return 1; }
    if (vk == VK_F4) { launch_application(L"C:\\SHZ\\TESTS\\T_HELLO.EXE"); return 1; }
    if (vk == VK_F10) { end_session(); return 1; }
    if (vk == VK_ESCAPE) {
        if (hwnd == g_editor && g_path_edit) { g_path_edit = 0; status(L"Path edit cancelled."); return 1; }
        if (hwnd != g_desktop) { ShowWindow(hwnd, SW_HIDE); SetForegroundWindow(g_desktop); SetFocus(g_desktop); }
        g_start = 0; redraw(g_desktop); return 1;
    }
    if (hwnd == g_files) {
        if (vk == 'C' || vk == 'D' || vk == 'E') {
            g_directory[0] = (WCHAR)vk; g_directory[1] = ':'; g_directory[2] = '\\'; g_directory[3] = 0;
            list_directory();
        } else if (vk == VK_F5) list_directory();
        else if (vk == VK_BACK) up_directory();
        else if (vk == VK_RETURN) open_selection();
        else if (vk == VK_DOWN && g_row_count) { if (g_selected < (int)g_row_count - 1) ++g_selected; }
        else if (vk == VK_UP && g_selected > 0) --g_selected;
        else return 0;
        if (g_selected >= 0) {
            RECT r; unsigned visible;
            GetClientRect(g_files, &r); visible = r.bottom > 160 ? (unsigned)(r.bottom - 160) / 20 : 1;
            if ((unsigned)g_selected < g_top) g_top = (unsigned)g_selected;
            if ((unsigned)g_selected >= g_top + visible) g_top = (unsigned)g_selected - visible + 1;
        }
        redraw(g_files); return 1;
    }
    if (hwnd == g_editor) {
        if (g_path_edit) return 0;
        if (ctrl && vk == 'S') { save_document(); return 1; }
        if (ctrl && vk == 'O') { open_document(g_document); return 1; }
        if (ctrl && vk == 'L') { begin_path_edit(); return 1; }
        if (ctrl && vk == 'N') {
            if (g_dirty) status(L"Save your changes with Ctrl+S before starting a new document.");
            else { g_text[0] = 0; g_text_bytes = g_caret = 0; g_editor_scroll = 0; status(L"New empty document."); }
            return 1;
        }
        if (vk == VK_LEFT && g_caret) --g_caret;
        else if (vk == VK_RIGHT && g_caret < g_text_bytes) ++g_caret;
        else if (vk == VK_HOME) { while (g_caret && g_text[g_caret - 1] != '\n') --g_caret; }
        else if (vk == VK_END) { while (g_caret < g_text_bytes && g_text[g_caret] != '\n') ++g_caret; }
        else if (vk == VK_DELETE) erase_character(0);
        else return 0;
        redraw(g_editor); return 1;
    }
    return 0;
}

static void click(HWND hwnd, int x, int y)
{
    RECT r;
    GetClientRect(hwnd, &r);
    if (hwnd == g_desktop) {
        int bar = g_height - BAR_HEIGHT;
        if (g_start > 0 && x >= 8 && x < 234 && y >= bar - 132 && y < bar) {
            int item = (y - (bar - 132)) / 32;
            g_start = 0;
            if (item == 0) show_files(); else if (item == 1) show_editor();
            else if (item == 2) launch_application(L"C:\\SHZ\\TESTS\\T_HELLO.EXE"); else end_session();
        } else if (y >= bar && x < 82) g_start = g_start > 0 ? 0 : 1;
        else if ((y >= bar && x >= 90 && x < 222) || (x >= 20 && x < 164 && y >= 52 && y < 80)) show_files();
        else if ((y >= bar && x >= 230 && x < 370) || (x >= 20 && x < 164 && y >= 98 && y < 126)) show_editor();
        else if (x >= 20 && x < 164 && y >= 144 && y < 172) launch_application(L"C:\\SHZ\\TESTS\\T_HELLO.EXE");
        else g_start = 0;
        redraw(g_desktop); return;
    }
    if (y >= 6 && y < 34 && x >= r.right - 40) { key(hwnd, VK_ESCAPE); return; }
    if (hwnd == g_files) {
        if (y >= 6 && y < 34) {
            if (x >= 8 && x < 60) key(hwnd, 'C'); else if (x >= 68 && x < 120) key(hwnd, 'D');
            else if (x >= 128 && x < 180) key(hwnd, 'E'); else if (x >= 188 && x < 248) key(hwnd, VK_BACK);
            else if (x >= 256 && x < 366) key(hwnd, VK_F5);
        } else if (y >= 88 && y < r.bottom - 56) {
            unsigned index = g_top + (unsigned)(y - 88) / 20;
            if (index < g_row_count) {
                int previous = g_selected; g_selected = (int)index;
                if (previous == g_selected) open_selection();
            }
        }
        redraw(g_files);
    } else if (hwnd == g_editor && y >= 6 && y < 34) {
        if (x >= 8 && x < 108) save_document(); else if (x >= 116 && x < 216) open_document(g_document);
        else if (x >= 224 && x < 324) begin_path_edit();
        else if (x >= 332 && x < 404) {
            if (g_dirty) status(L"Save your changes first with Ctrl+S.");
            else { g_text[0] = 0; g_text_bytes = g_caret = 0; redraw(g_editor); }
        }
    }
}

static LRESULT CALLBACK window_proc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam)
{
    switch (message) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        RECT r;
        HDC dc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &r); SetBkMode(dc, TRANSPARENT);
        if (hwnd == g_desktop) {
            paint_desktop(dc);
        }
        else if (hwnd == g_files) paint_files(dc, r.right, r.bottom);
        else if (hwnd == g_editor) paint_editor(dc, r.right, r.bottom);
        if (EndPaint(hwnd, &ps) && dc && hwnd == g_desktop) g_desktop_painted = 1;
        return 0;
    }
    case WM_KEYDOWN: case WM_SYSKEYDOWN:
        if ((lparam & ((LPARAM)1 << 30)) &&
            (wparam == VK_F2 || wparam == VK_F3 || wparam == VK_F4 || wparam == VK_F10)) return 0;
        if (key(hwnd, wparam)) return 0;
        break;
    case WM_CHAR:
        if (hwnd == g_editor) {
            if (g_path_edit) {
                unsigned n = (unsigned)lstrlenW(g_path_input);
                if (wparam == '\r') finish_path_edit();
                else if (wparam == '\b') {
                    if (g_path_replace) { g_path_input[0] = 0; g_path_replace = 0; }
                    else if (n) g_path_input[n - 1] = 0;
                } else if (wparam >= 32 && wparam < 127) {
                    if (g_path_replace) { n = 0; g_path_replace = 0; }
                    if (n + 1 < PATH_CAP) { g_path_input[n] = (WCHAR)wparam; g_path_input[n + 1] = 0; }
                }
            } else if (wparam == '\b') erase_character(1);
            else if (wparam == '\r') insert_character('\n');
            else if (wparam == '\t' || (wparam >= 32 && wparam < 127)) insert_character((char)wparam);
            redraw(g_editor); return 0;
        }
        break;
    case WM_LBUTTONDOWN:
        click(hwnd, (short)LOWORD(lparam), (short)HIWORD(lparam)); return 0;
    case WM_MOUSEWHEEL:
        if (hwnd == g_files) {
            int delta = (short)HIWORD(wparam);
            if (delta > 0) g_top = g_top > 3 ? g_top - 3 : 0;
            else if (g_top + 3 < g_row_count) g_top += 3;
            redraw(g_files); return 0;
        }
        break;
    case WM_TIMER:
        if (hwnd == g_desktop && wparam == 1) { poll_children(); return 0; }
        break;
    case WM_CLOSE:
        if (hwnd == g_desktop) end_session(); else key(hwnd, VK_ESCAPE);
        return 0;
    case WM_DESTROY:
        if (hwnd == g_desktop) PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, message, wparam, lparam);
}

int main(void)
{
    WNDCLASSEXW wc;
    MSG message;
    int result, code = 0;
    unsigned i;
    g_instance = GetModuleHandleW(0);
    g_width = GetSystemMetrics(SM_CXSCREEN); g_height = GetSystemMetrics(SM_CYSCREEN);
    if (g_width < 640 || g_height < 480) {
        printf("SHZ-DESKTOP ERROR operation=Display error=%u width=%d height=%d\n", ERROR_NOT_SUPPORTED, g_width, g_height);
        return 1;
    }
    memset(&wc, 0, sizeof wc);
    wc.cbSize = sizeof wc; wc.style = CS_HREDRAW | CS_VREDRAW; wc.lpfnWndProc = window_proc;
    wc.hInstance = g_instance; wc.lpszClassName = L"ShzDesktopWindow"; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    if (!RegisterClassExW(&wc)) { failure("Register desktop class", GetLastError()); return 1; }
    g_desktop = CreateWindowExW(0, wc.lpszClassName, L"ShizukuDOS Desktop", WS_POPUP | WS_VISIBLE,
                               0, 0, g_width, g_height, 0, 0, g_instance, 0);
    g_files = CreateWindowExW(0, wc.lpszClassName, L"Files", WS_OVERLAPPEDWINDOW,
                            48, 40, g_width - 96, g_height - 108, 0, 0, g_instance, 0);
    g_editor = CreateWindowExW(0, wc.lpszClassName, L"Text Editor", WS_OVERLAPPEDWINDOW,
                             72, 54, g_width - 144, g_height - 136, 0, 0, g_instance, 0);
    if (!g_desktop || !g_files || !g_editor) { failure("Create desktop windows", GetLastError()); code = 1; }
    else if (!SetShellWindow(g_desktop) || GetShellWindow() != g_desktop) {
        failure("Register shell window", GetLastError()); code = 1;
    }
    else if (!SetTimer(g_desktop, 1, 200, 0)) { failure("Application completion timer", GetLastError()); code = 1; }
    else {
        SetForegroundWindow(g_desktop); SetFocus(g_desktop);
        if (!UpdateWindow(g_desktop) || !g_desktop_painted) {
            failure("Initial desktop paint", GetLastError()); code = 1;
        } else {
            printf("SHZ-DESKTOP SHELL registered=1 hwnd=%llx\n", (unsigned long long)(uintptr_t)g_desktop);
            printf("SHZ-DESKTOP READY width=%d height=%d\n", g_width, g_height);
            while ((result = GetMessageW(&message, 0, 0, 0)) > 0) {
                TranslateMessage(&message); DispatchMessageW(&message);
            }
            if (result < 0) { failure("Desktop message loop", GetLastError()); code = 1; }
        }
    }
    for (i = 0; i < CHILD_CAP; ++i) if (g_children[i].process) CloseHandle(g_children[i].process);
    if (g_desktop) KillTimer(g_desktop, 1);
    if (g_editor) DestroyWindow(g_editor);
    if (g_files) DestroyWindow(g_files);
    if (g_desktop) DestroyWindow(g_desktop);
    UnregisterClassW(wc.lpszClassName, g_instance);
    return code;
}
