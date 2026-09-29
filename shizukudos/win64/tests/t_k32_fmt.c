/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 message formatting and environment expansion: FormatMessageW/A (strings, message table resources, system messages,
 * inserts, escapes, buffers) and ExpandEnvironmentStringsW/A. Expected texts are the documented Windows results. */
#include "k32test.h"
#include <stdarg.h>

static DWORD fmt_va(DWORD flags, LPCVOID src, LPWSTR buf, DWORD size, ...)
{
    DWORD n;
    va_list ap;
    va_start(ap, size);
    n = FormatMessageW(flags, src, 0, 0, buf, size, &ap);
    va_end(ap);
    return n;
}

static DWORD fmt_va_a(DWORD flags, LPCVOID src, LPSTR buf, DWORD size, ...)
{
    DWORD n;
    va_list ap;
    va_start(ap, size);
    n = FormatMessageA(flags, src, 0, 0, buf, size, &ap);
    va_end(ap);
    return n;
}

#define AA FORMAT_MESSAGE_ARGUMENT_ARRAY
#define FS FORMAT_MESSAGE_FROM_STRING

static DWORD fmtw(DWORD flags, LPCWSTR fmt, DWORD_PTR *args, LPWSTR buf, DWORD size)
{
    return FormatMessageW(flags | FS | (args ? AA : 0), fmt, 0, 0, buf, size, (va_list *)args);
}

static void test_strings(void)
{
    WCHAR b[256];
    DWORD n;
    DWORD_PTR a1[] = { (DWORD_PTR)L"World", 42 };
    n = fmtw(0, L"Hello %1!s!, %2!d!", a1, b, 256);
    CHECKV(n == 15 && k32t_weq(b, L"Hello World, 42"), "%1!s! and %2!d! from an argument array", "n=%u", (unsigned)n);
    n = fmtw(0, L"[%1]", a1, b, 256);
    CHECK(n == 7 && k32t_weq(b, L"[World]"), "a bare %1 is a string insert");
    n = fmt_va(FS, L"%1!s!-%2!d!-%1!s!", b, 256, L"ab", 7);
    CHECK(n == 7 && k32t_weq(b, L"ab-7-ab"), "va_list arguments, an insert used twice");
    n = fmt_va(FS, L"%2 %1", b, 256, L"one", L"two");
    CHECK(k32t_weq(b, L"two one"), "inserts may appear in any order");
    n = fmtw(0, L"A%nB%rC%tD", 0, b, 256);
    CHECK(n == 8 && b[0] == 'A' && b[1] == '\r' && b[2] == '\n' && b[3] == 'B' && b[4] == '\r' && b[5] == 'C' && b[6] == '\t' && b[7] == 'D', "%n %r %t escapes");
    n = fmtw(0, L"50%%!%.%!", 0, b, 256);
    CHECK(n == 6 && k32t_weq(b, L"50%!.!"), "%% %. %! escapes");
    n = fmtw(0, L"abc%0def", 0, b, 256);
    CHECK(n == 3 && k32t_weq(b, L"abc"), "%0 ends the message");
    n = fmtw(0, L"x%1!05d!|%1!-5d!|%1!5d!", (DWORD_PTR[]){ 42 }, b, 256);
    CHECK(k32t_weq(b, L"x00042|42   |   42"), "zero padding, left justification, width");
    n = fmtw(0, L"%1!x! %1!X! %1!#x! %1!o!", (DWORD_PTR[]){ 255 }, b, 256);
    CHECK(k32t_weq(b, L"ff FF 0xff 377"), "hex, octal and the # flag");
    n = fmtw(0, L"%1!d! %1!+d! %1!u!", (DWORD_PTR[]){ (DWORD_PTR)-5 }, b, 256);
    CHECK(k32t_weq(b, L"-5 -5 4294967291"), "signed and unsigned views of the same 32-bit argument");
    n = fmtw(0, L"%1!I64d! %1!lld! %1!I64x!", (DWORD_PTR[]){ 0x123456789ull }, b, 256);
    CHECK(k32t_weq(b, L"4886718345 4886718345 123456789"), "64-bit arguments");
    n = fmtw(0, L"[%1!5.2s!][%1!-6.3s!][%1!.1s!]", (DWORD_PTR[]){ (DWORD_PTR)L"abcdef" }, b, 256);
    CHECK(k32t_weq(b, L"[   ab][abc   ][a]"), "string width and precision");
    n = fmtw(0, L"%1!c!%1!c!", (DWORD_PTR[]){ 'Q' }, b, 256);
    CHECK(k32t_weq(b, L"QQ"), "%c is a wide character in FormatMessageW");
    n = fmtw(0, L"%1!*.*s! %4 %5!*s!", (DWORD_PTR[]){ 4, 2, (DWORD_PTR)L"Bill", (DWORD_PTR)L"Bob", 6, (DWORD_PTR)L"Bill" }, b, 256);
    CHECKV(k32t_weq(b, L"  Bi Bob   Bill"), "the documented * width/precision example", "n=%u", (unsigned)n);
    n = fmtw(FORMAT_MESSAGE_IGNORE_INSERTS, L"Value %1 and %2!d!%n", (DWORD_PTR[]){ 1, 2 }, b, 256);
    CHECK(k32t_weq(b, L"Value %1 and %2!d!\r\n"), "IGNORE_INSERTS passes inserts through but still expands %n");
    n = fmtw(0xFF, L"one%ntwo\r\nthree\nfour", 0, b, 256);
    CHECK(k32t_weq(b, L"one\r\ntwo three four"), "MAX_WIDTH_MASK 0xFF: hard line breaks become blanks, %n stays");
    n = fmtw(0, L"plain text", 0, b, 256);
    CHECK(n == 10 && k32t_weq(b, L"plain text"), "a message without inserts needs no arguments");
    /* errors */
    SetLastError(0);
    CHECK(FormatMessageW(FS, L"abc", 0, 0, b, 3, 0) == 0, "a buffer that is too small fails");
    CHECK_ERR(ERROR_INSUFFICIENT_BUFFER, "small buffer: ERROR_INSUFFICIENT_BUFFER");
    n = FormatMessageW(FS, L"abc", 0, 0, b, 4, 0);
    CHECK(n == 3, "a buffer of exactly length+1 is enough");
    SetLastError(0);
    CHECK_W(FormatMessageW(FS | FORMAT_MESSAGE_FROM_SYSTEM, L"abc", 0, 0, b, 256, 0) == 0, "FROM_STRING with FROM_SYSTEM fails");
    CHECK_W(GetLastError() == ERROR_INVALID_PARAMETER, "FROM_STRING|FROM_SYSTEM: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(FormatMessageW(FS, NULL, 0, 0, b, 256, 0) == 0, "FROM_STRING without a string fails");
    CHECK_W(GetLastError() == ERROR_INVALID_PARAMETER, "no string: ERROR_INVALID_PARAMETER");
    SetLastError(0);
    CHECK(FormatMessageW(0, NULL, 0, 0, b, 256, 0) == 0, "no source flag fails");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "no source: ERROR_INVALID_PARAMETER");
}

static void test_system(void)
{
    WCHAR b[256];
    DWORD n;
    LPWSTR p = NULL;
    char a[256];
    LPSTR pa = NULL;
    static const struct { DWORD id; const WCHAR *text; } t[] = {
        { ERROR_FILE_NOT_FOUND, L"The system cannot find the file specified.\r\n" },
        { ERROR_PATH_NOT_FOUND, L"The system cannot find the path specified.\r\n" },
        { ERROR_ACCESS_DENIED, L"Access is denied.\r\n" },
        { ERROR_INVALID_HANDLE, L"The handle is invalid.\r\n" },
        { ERROR_INVALID_PARAMETER, L"The parameter is incorrect.\r\n" },
        { ERROR_ALREADY_EXISTS, L"Cannot create a file when that file already exists.\r\n" },
        { ERROR_INSUFFICIENT_BUFFER, L"The data area passed to a system call is too small.\r\n" },
        { ERROR_MOD_NOT_FOUND, L"The specified module could not be found.\r\n" },
        { ERROR_PROC_NOT_FOUND, L"The specified procedure could not be found.\r\n" },
        { ERROR_SHARING_VIOLATION, L"The process cannot access the file because it is being used by another process.\r\n" },
        { ERROR_NOT_ENOUGH_MEMORY, L"Not enough memory resources are available to process this command.\r\n" },
        { ERROR_NO_MORE_FILES, L"There are no more files.\r\n" },
        { ERROR_MORE_DATA, L"More data is available.\r\n" },
        { ERROR_DIR_NOT_EMPTY, L"The directory is not empty.\r\n" },
        { ERROR_INVALID_NAME, L"The filename, directory name, or volume label syntax is incorrect.\r\n" },
        { ERROR_BROKEN_PIPE, L"The pipe has been ended.\r\n" },
        { ERROR_ENVVAR_NOT_FOUND, L"The system could not find the environment option that was entered.\r\n" },
        { ERROR_INVALID_FLAGS, L"Invalid flags.\r\n" },
        { ERROR_NOACCESS, L"Invalid access to memory location.\r\n" },
        { ERROR_IO_PENDING, L"Overlapped I/O operation is in progress.\r\n" },
        { ERROR_NO_MORE_ITEMS, L"No more data is available.\r\n" },
        { ERROR_SUCCESS, L"The operation completed successfully.\r\n" },
        { ERROR_HANDLE_EOF, L"Reached the end of the file.\r\n" },
        { ERROR_FILENAME_EXCED_RANGE, L"The filename or extension is too long.\r\n" },
        { ERROR_RESOURCE_TYPE_NOT_FOUND, L"The specified resource type cannot be found in the image file.\r\n" },
    };
    unsigned i;
    for (i = 0; i < sizeof t / sizeof t[0]; ++i) {
        char what[96];
        n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, t[i].id, 0, b, 256, 0);
        snprintf(what, sizeof what, "system message for error %u", (unsigned)t[i].id);
        CHECKV_W(n == (DWORD)k32t_wlen(t[i].text) && k32t_weq(b, t[i].text), what, "n=%u", (unsigned)n);
    }
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_FILE_NOT_FOUND, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US), b, 256, 0);
    CHECK_W(n == 44, "explicit en-US language id");
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_FILE_NOT_FOUND, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), b, 256, 0);
    CHECK_W(n == 44, "neutral/default language id");
    {
        DWORD_PTR ins[] = { (DWORD_PTR)L"foo.exe" };
        n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | AA, NULL, ERROR_BAD_EXE_FORMAT, 0, b, 256, (va_list *)ins);
        CHECK_W(k32t_weq(b, L"foo.exe is not a valid Win32 application.\r\n"), "system message with an insert");
    }
    SetLastError(0);
    CHECK(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0x7fff1234, 0, b, 256, 0) == 0, "an unknown message id fails");
    CHECK_ERR(ERROR_MR_MID_NOT_FOUND, "unknown id: ERROR_MR_MID_NOT_FOUND");
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, ERROR_ACCESS_DENIED, 0, (LPWSTR)&p, 0, 0);
    CHECK(p != NULL && n > 0 && n == (DWORD)k32t_wlen(p), "ALLOCATE_BUFFER returns a buffer");
    CHECK_W(p != NULL && n == 19 && k32t_weq(p, L"Access is denied.\r\n"), "ALLOCATE_BUFFER buffer holds the message");
    CHECK(p != NULL && LocalFree(p) == NULL, "the allocated buffer is freed with LocalFree");
    n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, ERROR_ACCESS_DENIED, 0, (LPWSTR)&p, 200, 0);
    CHECK(p != NULL && n > 0 && LocalSize(p) >= 200 * sizeof(WCHAR), "nSize is the minimum size of the allocation");
    if (p) LocalFree(p);
    /* ANSI */
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_ACCESS_DENIED, 0, a, 256, 0);
    CHECK_W(n == 19 && !strcmp(a, "Access is denied.\r\n"), "FormatMessageA system message");
    n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, ERROR_PATH_NOT_FOUND, 0, (LPSTR)&pa, 0, 0);
    CHECK(n > 0 && pa != NULL && n == (DWORD)strlen(pa), "FormatMessageA with ALLOCATE_BUFFER");
    CHECK_W(pa != NULL && !strcmp(pa, "The system cannot find the path specified.\r\n"), "FormatMessageA ALLOCATE_BUFFER text");
    if (pa) LocalFree(pa);
    {
        DWORD_PTR ins[] = { (DWORD_PTR)"there", 7 };
        n = FormatMessageA(FS | AA, "Hi %1 %2!d!", 0, 0, a, 256, (va_list *)ins);
        CHECK_W(n == 10 && !strcmp(a, "Hi there 7"), "FormatMessageA: %s takes a narrow string");
    }
    {
        DWORD_PTR ins[] = { (DWORD_PTR)L"wide" };
        n = FormatMessageA(FS | AA, "[%1!S!]", 0, 0, a, 256, (va_list *)ins);
        CHECK(n == 6 && !strcmp(a, "[wide]"), "FormatMessageA: %S takes a wide string");
    }
    n = fmt_va_a(FS, "%2-%1", a, 256, "x", "y");
    CHECK(!strcmp(a, "y-x"), "FormatMessageA with va_list");
    SetLastError(0);
    CHECK(FormatMessageA(FS, "abc", 0, 0, a, 3, 0) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "FormatMessageA short buffer");
}

static void test_module_messages(void)
{
    WCHAR b[256];
    DWORD n;
    DWORD_PTR ins[] = { (DWORD_PTR)L"World", 3 };
    n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | AA, NULL, 0x1000, 0, b, 256, (va_list *)ins);
    CHECKV(k32t_weq(b, L"Hello World, you have 3 messages.\r\n"), "message table entry with inserts (ANSI entry)", "n=%u", (unsigned)n);
    n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, GetModuleHandleW(NULL), 0x1001, 0, b, 256, 0);
    CHECKV(n == 17 && k32t_weq(b, L"Unicode entry \xe9\r\n"), "message table entry stored as Unicode", "n=%u", (unsigned)n);
    n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE, NULL, 0x1002, 0, b, 256, 0);
    CHECK(n == 18 && k32t_weq(b, L"Line one\r\nLine two"), "%n inside a message and %0 at its end");
    n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0x2000, 0, b, 256, 0);
    CHECK(k32t_weq(b, L"Second block entry\r\n"), "an id in the second block");
    SetLastError(0);
    CHECK(FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, 0x1003, 0, b, 256, 0) == 0, "an id between the blocks is not found");
    CHECK_ERR(ERROR_MR_MID_NOT_FOUND, "missing id: ERROR_MR_MID_NOT_FOUND");
    n = FormatMessageW(FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_ACCESS_DENIED, 0, b, 256, 0);
    CHECK(n > 0, "FROM_HMODULE|FROM_SYSTEM falls back to the system table");
    CHECK_W(k32t_weq(b, L"Access is denied.\r\n"), "the fallback text");
}

static void test_env(void)
{
    WCHAR b[300];
    char a[300];
    DWORD n;
    SetEnvironmentVariableW(L"SHZ_T1", L"value1");
    SetEnvironmentVariableW(L"SHZ_EMPTY", L"");
    SetEnvironmentVariableW(L"SHZ_UNDEF", NULL);
    n = ExpandEnvironmentStringsW(L"a%SHZ_T1%b", b, 300);
    CHECK(n == 9 && k32t_weq(b, L"avalue1b"), "a variable is replaced (size includes the terminator)");
    n = ExpandEnvironmentStringsW(L"x%SHZ_UNDEF%y", b, 300);
    CHECK(n == 14 && k32t_weq(b, L"x%SHZ_UNDEF%y"), "an undefined variable is left unchanged");
    n = ExpandEnvironmentStringsW(L"50%", b, 300);
    CHECK(n == 4 && k32t_weq(b, L"50%"), "an unmatched percent sign is literal");
    n = ExpandEnvironmentStringsW(L"%shz_t1%|%SHZ_T1%", b, 300);
    CHECK(k32t_weq(b, L"value1|value1"), "variable names are case-insensitive");
    n = ExpandEnvironmentStringsW(L"[%SHZ_EMPTY%]", b, 300);
    CHECK(n == 3 && k32t_weq(b, L"[]"), "a variable with an empty value expands to nothing");
    n = ExpandEnvironmentStringsW(L"plain", b, 300);
    CHECK(n == 6 && k32t_weq(b, L"plain"), "text without variables is copied");
    CHECK(ExpandEnvironmentStringsW(L"a%SHZ_T1%b", 0, 0) == 9, "size query");
    n = ExpandEnvironmentStringsW(L"a%SHZ_T1%b", b, 4);
    CHECK(n == 9, "a buffer that is too small: the return value is the needed size");
    n = ExpandEnvironmentStringsA("%SHZ_T1%!", a, 300);
    CHECK(n == 8 && !strcmp(a, "value1!"), "ExpandEnvironmentStringsA");
    CHECK(ExpandEnvironmentStringsA("%SHZ_T1%!", 0, 0) == 8, "ANSI size query");
    SetEnvironmentVariableW(L"SHZ_T1", NULL);
    SetEnvironmentVariableW(L"SHZ_EMPTY", NULL);
}

int main(void)
{
    test_strings();
    test_system();
    test_module_messages();
    test_env();
    return k32t_finish("t_k32_fmt");
}
