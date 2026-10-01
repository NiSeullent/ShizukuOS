/* SPDX-License-Identifier: GPL-2.0-only
 * Dedicated E1 initial-blocker probe. Exercises actual process-local console state and
 * documented failure boundaries; no claim of terminal rendering, keyboard input, cross-process
 * console sharing, or Electron application compatibility. Exit 0 requires every check.
 */
#define _WIN32_WINNT 0x0A00
#include "k32test.h"
#include <wincon.h>
#include <string.h>
#ifndef APPMODEL_ERROR_NO_PACKAGE
#define APPMODEL_ERROR_NO_PACKAGE 15700L
#endif
LONG WINAPI GetCurrentPackageFullName(UINT32 *, PWSTR);
LONG WINAPI GetPackageFamilyName(HANDLE, UINT32 *, PWSTR);

struct reader { HANDLE input, ready; BOOL ok; DWORD count, error; INPUT_RECORD record; };
static DWORD WINAPI read_worker(void *arg)
{
    struct reader *r = arg;
    SetEvent(r->ready);
    r->ok = ReadConsoleInputW(r->input, &r->record, 1, &r->count);
    r->error = GetLastError();
    return 0;
}

static void eager_errors(void)
{
    UINT saved = GetErrorMode();
    UINT32 len = 0;
    WCHAR name[8] = { 'Q', 0 };
    IO_COUNTERS io, before;
    HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(SetErrorMode(SEM_FAILCRITICALERRORS) == saved, "SetErrorMode returns previous process value");
    CHECK(GetErrorMode() == SEM_FAILCRITICALERRORS, "GetErrorMode observes update");
    SetErrorMode(saved);
    CHECK(!CancelSynchronousIo(GetCurrentThread()) && GetLastError() == ERROR_NOT_SUPPORTED,
          "valid thread cancellation explicitly unsupported");
    CHECK(!CancelSynchronousIo(event) && GetLastError() == ERROR_INVALID_HANDLE, "cancellation rejects non-thread object");
    CHECK(!CreateSymbolicLinkW(NULL, L"target", 0) && GetLastError() == ERROR_INVALID_PARAMETER, "symlink null name rejected");
    CHECK(!CreateSymbolicLinkW(L"link", L"target", 4) && GetLastError() == ERROR_INVALID_PARAMETER, "symlink unknown flags rejected");
    CHECK(!CreateSymbolicLinkW(L"link", L"target", 0) && GetLastError() == ERROR_NOT_SUPPORTED, "symlink reports filesystem limitation");
    memset(&io, 0x5a, sizeof io); before = io;
    CHECK(!GetProcessIoCounters(GetCurrentProcess(), &io) && GetLastError() == ERROR_NOT_SUPPORTED && !memcmp(&io, &before, sizeof io),
          "unsupported process I/O counters preserve output");
    CHECK(!GetProcessIoCounters(event, &io) && GetLastError() == ERROR_INVALID_HANDLE, "I/O counters reject non-process object");
    CHECK(!GetProcessIoCounters(GetCurrentProcess(), NULL) && GetLastError() == ERROR_NOACCESS, "I/O counters reject null output");
    SetLastError(0x1234);
    CHECK(GetCurrentPackageFullName(&len, NULL) == APPMODEL_ERROR_NO_PACKAGE && !len && GetLastError() == 0x1234,
          "unpackaged current process returns status without mutating length or LastError");
    CHECK(GetCurrentPackageFullName(NULL, NULL) == ERROR_INVALID_PARAMETER, "package length pointer required");
    len = 8;
    CHECK(GetCurrentPackageFullName(&len, NULL) == ERROR_INVALID_PARAMETER, "package nonzero capacity requires buffer");
    CHECK(GetPackageFamilyName(GetCurrentProcess(), &len, name) == APPMODEL_ERROR_NO_PACKAGE && len == 8 && name[0] == 'Q',
          "package family outputs preserved when no identity");
    CHECK(GetPackageFamilyName(event, &len, name) == ERROR_INVALID_HANDLE, "package family validates process handle");
    {
        WCHAR old[1024];
        DWORD n = GetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", old, 1024);
        SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", NULL);
        CHECK(NeedCurrentDirectoryForExePathW(L"app.exe"), "executable current directory enabled when variable absent");
        SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", L"1");
        CHECK(!NeedCurrentDirectoryForExePathW(L"app.exe"), "present search-control variable disables current directory");
        CHECK(NeedCurrentDirectoryForExePathW(L"sub\\app.exe"), "explicit backslash path requires current directory");
        SetEnvironmentVariableW(L"NoDefaultCurrentDirectoryInExePath", n && n < 1024 ? old : NULL);
    }
    CloseHandle(event);
}

static void console_model(void)
{
    HANDLE in = CreateFileW(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE out = CreateFileW(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ro, duplicate;
    CONSOLE_CURSOR_INFO ci, original;
    CONSOLE_SCREEN_BUFFER_INFO si;
    COORD at = { 79, 24 }, origin = { 0, 0 };
    WCHAR text[8], title[400], title_copy[400];
    WORD attrs[4];
    DWORD n, got, mode;
    INPUT_RECORD input[3], records[3];
    BOOL ok;
    unsigned i;
    CHECK(in != INVALID_HANDLE_VALUE && out != INVALID_HANDLE_VALUE, "open distinct input and output console objects");
    if (in == INVALID_HANDLE_VALUE || out == INVALID_HANDLE_VALUE) return;
    CHECK(!GetConsoleCursorInfo(in, &ci) && GetLastError() == ERROR_INVALID_HANDLE, "cursor query rejects input object");
    CHECK(!GetNumberOfConsoleInputEvents(out, &n) && GetLastError() == ERROR_INVALID_HANDLE, "input event query rejects output object");
    GetConsoleCursorInfo(out, &original);
    ci.dwSize = 100; ci.bVisible = FALSE;
    CHECK(SetConsoleCursorInfo(out, &ci) && GetConsoleCursorInfo(out, &ci) && ci.dwSize == 100 && !ci.bVisible, "cursor shape and visibility round trip");
    ci.dwSize = 0;
    CHECK(!SetConsoleCursorInfo(out, &ci) && GetLastError() == ERROR_INVALID_PARAMETER, "cursor size zero rejected");
    ci.dwSize = 101;
    CHECK(!SetConsoleCursorInfo(out, &ci) && GetLastError() == ERROR_INVALID_PARAMETER, "cursor size over 100 rejected");
    SetConsoleCursorInfo(out, &original);
    ok = FillConsoleOutputCharacterW(out, 0x03a9, 10, at, &n);
    ok = ok && n == 1 && ReadConsoleOutputCharacterW(out, text, 4, at, &got) && got == 1 && text[0] == 0x03a9;
    BOOL character_fill_ok = ok;
    ok = FillConsoleOutputAttribute(out, 0x1e, 10, at, &n);
    ok = ok && n == 1 && ReadConsoleOutputAttribute(out, attrs, 4, at, &got) && got == 1 && attrs[0] == 0x1e;
    ok = ok && ReadConsoleOutputCharacterW(out, text, 1, at, &got) && text[0] == 0x03a9;
    CHECK(character_fill_ok, "fill changes actual character cell and clips at buffer end");
    CHECK(ok, "attribute fill changes attribute while preserving character");
    at.X = -1;
    CHECK(!FillConsoleOutputCharacterW(out, 'X', 1, at, &n) && !n && GetLastError() == ERROR_INVALID_PARAMETER, "negative fill coordinate rejected");
    CHECK(!FillConsoleOutputAttribute(out, 7, 1, origin, NULL) && GetLastError() == ERROR_INVALID_PARAMETER, "fill requires count output");
    at.X = 80; at.Y = 0;
    CHECK(!SetConsoleCursorPosition(out, at) && GetLastError() == ERROR_INVALID_PARAMETER, "cursor outside buffer rejected");
    for (i = 0; i < 399; ++i) title[i] = (WCHAR)('a' + i % 26);
    title[399] = 0;
    CHECK(SetConsoleTitleW(title) && GetConsoleTitleW(title_copy, 400) == 399 && !memcmp(title, title_copy, sizeof title), "399-unit title retained without silent truncation");
    CHECK(GetConsoleTitleW(title_copy, 8) == 7 && !title_copy[7], "small title buffer is terminated");
    GetConsoleMode(out, &mode);
    SetConsoleMode(out, ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT);
    SetConsoleCursorPosition(out, origin);
    ok = WriteConsoleW(out, L"X\n", 2, &n, NULL) && n == 2 && GetConsoleScreenBufferInfo(out, &si) && si.dwCursorPosition.X == 0 && si.dwCursorPosition.Y == 1;
    CHECK(ok, "WriteConsoleW preserves final newline byte (E1 regression)");
    SetConsoleCursorPosition(out, origin);
    {
        const WCHAR data[3] = { 'A', 0, 'Z' };
        ok = WriteConsoleW(out, data, 3, &n, NULL) && n == 3 && ReadConsoleOutputCharacterW(out, text, 3, origin, &got) && got == 3 && text[0] == 'A' && !text[1] && text[2] == 'Z';
        CHECK(ok, "WriteConsoleW explicit length preserves embedded NUL and last character");
    }
    SetConsoleMode(out, mode);
    CHECK(DuplicateHandle(GetCurrentProcess(), out, GetCurrentProcess(), &duplicate, 0, FALSE, DUPLICATE_SAME_ACCESS), "duplicate console output handle");
    ok = SetConsoleCursorPosition(duplicate, origin) && WriteConsoleW(duplicate, L"Q", 1, &n, NULL) && GetConsoleScreenBufferInfo(out, &si) && si.dwCursorPosition.X == 1;
    CHECK(ok, "duplicate console output tracked exactly once");
    CloseHandle(duplicate);
    ro = CreateFileW(L"CONOUT$", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(!FillConsoleOutputCharacterW(ro, 'X', 1, origin, &n) && GetLastError() == ERROR_ACCESS_DENIED, "read-only output handle cannot fill cells");
    CloseHandle(ro);
    FlushConsoleInputBuffer(in);
    memset(input, 0, sizeof input);
    for (i = 0; i < 3; ++i) { input[i].EventType = KEY_EVENT; input[i].Event.KeyEvent.bKeyDown = TRUE; input[i].Event.KeyEvent.wRepeatCount = 1; input[i].Event.KeyEvent.uChar.UnicodeChar = (WCHAR)('a' + i); }
    CHECK(WriteConsoleInputW(in, input, 3, &n) && n == 3 && GetNumberOfConsoleInputEvents(in, &got) && got == 3, "input injection changes actual queue count");
    CHECK(PeekConsoleInputW(in, records, 2, &got) && got == 2 && !memcmp(records, input, 2 * sizeof *records) && GetNumberOfConsoleInputEvents(in, &n) && n == 3, "peek preserves event bytes and does not consume queue");
    CHECK(ReadConsoleInputW(in, records, 2, &got) && got == 2 && !memcmp(records, input, 2 * sizeof *records), "read consumes FIFO records");
    CHECK(ReadConsoleInputW(in, records, 3, &got) && got == 1 && records[0].Event.KeyEvent.uChar.UnicodeChar == 'c', "read returns available event count");
    CHECK(PeekConsoleInputW(in, records, 3, &got) && !got, "empty peek returns zero without blocking");
    CHECK(!WriteConsoleInputW(out, input, 1, &n) && !n && GetLastError() == ERROR_INVALID_HANDLE, "injection rejects output device");
    ro = CreateFileW(L"CONIN$", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(!WriteConsoleInputW(ro, input, 1, &n) && GetLastError() == ERROR_ACCESS_DENIED, "read-only input handle cannot inject events");
    CloseHandle(ro);
    {
        struct reader r;
        HANDLE thread;
        memset(&r, 0, sizeof r); r.input = in; r.ready = CreateEventW(NULL, TRUE, FALSE, NULL);
        thread = CreateThread(NULL, 0, read_worker, &r, 0, NULL);
        CHECK(thread && WaitForSingleObject(r.ready, 2000) == WAIT_OBJECT_0 && WaitForSingleObject(thread, 20) == WAIT_TIMEOUT,
              "empty ReadConsoleInputW waits for an event");
        WriteConsoleInputW(in, input, 1, &n);
        CHECK(WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0 && r.ok && r.count == 1 && r.record.Event.KeyEvent.uChar.UnicodeChar == 'a',
              "injected input wakes a waiting reader with actual event");
        CloseHandle(thread); CloseHandle(r.ready);
    }
    CloseHandle(in); CloseHandle(out);
}

static void files_and_pipes(void)
{
    const WCHAR *names[] = { L"nul", L"NUL:", L"\\\\.\\NUL" };
    DWORD n, mode;
    char byte = 'x';
    HANDLE h;
    unsigned i;
    for (i = 0; i < 3; ++i) {
        h = CreateFileW(names[i], GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_CHAR, "NUL alias is FILE_TYPE_CHAR");
        CHECK(WriteFile(h, &byte, 1, &n, NULL) && n == 1 && ReadFile(h, &byte, 1, &n, NULL) && !n, "NUL discards writes and reads EOF");
        CHECK(!GetConsoleMode(h, &mode) && GetLastError() == ERROR_INVALID_HANDLE, "NUL rejected by console APIs");
        CloseHandle(h);
    }
    h = CreateFileW(L"C:\\T_E1_K32.TMP", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "create ordinary file for handle boundaries");
    CHECK(!GetConsoleMode(h, &mode) && GetLastError() == ERROR_INVALID_HANDLE, "ordinary file rejected by console APIs");
    CHECK(ReOpenFile(h, GENERIC_READ, FILE_SHARE_READ, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_NOT_SUPPORTED, "reopen reports missing object-identity backend");
    CHECK(ReOpenFile(h, GENERIC_READ, 8, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER, "reopen rejects unknown share flags");
    CloseHandle(h); DeleteFileW(L"C:\\T_E1_K32.TMP");
    CHECK(ReOpenFile(INVALID_HANDLE_VALUE, GENERIC_READ, 0, 0) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_HANDLE, "reopen rejects invalid original handle");
    h = CreateNamedPipeW(L"\\\\?\\PiPe\\e1-k32-verbatim", PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE, 1, 256, 256, 10, NULL);
    CHECK(h != INVALID_HANDLE_VALUE && GetFileType(h) == FILE_TYPE_PIPE, "verbatim mixed-case named-pipe prefix accepted by backend");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CHECK(CreateNamedPipeW(L"\\\\?\\pipe\\", PIPE_ACCESS_DUPLEX, 0, 1, 1, 1, 10, NULL) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_NAME,
          "empty pipe suffix rejected");
    CHECK(CreateNamedPipeW(L"\\\\?\\pipe\\x", 0, 0, 1, 1, 1, 10, NULL) == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER,
          "pipe requires a valid access direction");
}

int main(void)
{
    eager_errors();
    console_model();
    files_and_pipes();
    return k32t_finish("T_E1_KERNEL32");
}
