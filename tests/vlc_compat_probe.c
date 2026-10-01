/* SPDX-License-Identifier: GPL-2.0-only
 * Native Win98 evidence only when this PE actually executes in the guest.
 * Fresh report/file paths are confined to the private VXDLAB trial.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../src/m98_vlc_compat.h"
static HANDLE report = INVALID_HANDLE_VALUE;
static unsigned checks, failures;
static int io_failed;
static void put(const char *s) {
    DWORD n = 0, wrote;
    while (s[n]) ++n;
    if (!WriteFile(report, s, n, &wrote, NULL) || wrote != n) io_failed = 1;
}
static void check(const char *name, int ok) {
    ++checks;
    if (!ok) ++failures;
    put(ok ? "VLC_API_PASS=" : "VLC_API_FAIL="); put(name); put("\r\n");
}
static void number(const char *label, unsigned value) {
    char buffer[11]; unsigned n = 0, i;
    do { buffer[n++] = (char)('0' + value % 10); value /= 10; } while (value);
    put(label);
    for (i = n; i; --i) { char digit[2] = {buffer[i - 1], 0}; put(digit); }
    put("\r\n");
}
static int same(const void *a, const void *b, unsigned n) {
    unsigned i;
    for (i = 0; i < n; ++i) if (((const BYTE *)a)[i] != ((const BYTE *)b)[i]) return 0;
    return 1;
}
static int wide_equal(const WCHAR *a, const WCHAR *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
void WINAPI entry(void) {
    HMODULE dll;
    SYSTEM_INFO ordinary, native;
    OSVERSIONINFOA os;
    LARGE_INTEGER distance, position;
    HANDLE file;
    DWORD wrote, read;
    ULONG lfh = 2;
    HWND window;
    WNDCLASSEXA base_class;
    WCHAR wide[256];
    char data[4];
    BOOL copied;
    unsigned i;
    void (WINAPI *system_info)(LPSYSTEM_INFO);
    union { FARPROC generic; void (WINAPI *typed)(LPSYSTEM_INFO); } info_export;
    BOOL (WINAPI *seek)(HANDLE,LARGE_INTEGER,PLARGE_INTEGER,DWORD);
    BOOL (WINAPI *heap_info)(HANDLE,DWORD,PVOID,SIZE_T);
    BOOL (WINAPI *remove_font)(LPCWSTR,DWORD,PVOID);
    BOOL (WINAPI *remove_memory_font)(HANDLE);
    UINT (WINAPI *window_class)(HWND,LPWSTR,UINT);
    report = CreateFileA("C:\\VXDLAB\\VLCAPI.LOG", GENERIC_WRITE, 0, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    for (i = 0; i < sizeof(os); ++i) ((BYTE *)&os)[i] = 0;
    os.dwOSVersionInfoSize = sizeof(os);
    check("REAL_WIN98_HOST", GetVersionExA(&os) && os.dwMajorVersion == 4 &&
          os.dwMinorVersion == 10 && (os.dwBuildNumber & 65535) == 2222 && os.dwPlatformId == 1);
    dll = LoadLibraryA("C:\\VXDLAB\\M98VLC.DLL");
    check("NATIVE_DLL_LOAD", dll != NULL);
    if (!dll) goto finish;
    /* Native PE32 function pointers share one representation. Use the typed
     * union for a void-returning export; do not relax the SDK cast warnings. */
    info_export.generic = GetProcAddress(dll, "GetNativeSystemInfo");
    system_info = info_export.typed;
    seek = (BOOL (WINAPI *)(HANDLE,LARGE_INTEGER,PLARGE_INTEGER,DWORD))GetProcAddress(dll, "SetFilePointerEx");
    heap_info = (BOOL (WINAPI *)(HANDLE,DWORD,PVOID,SIZE_T))GetProcAddress(dll, "HeapSetInformation");
    remove_font = (BOOL (WINAPI *)(LPCWSTR,DWORD,PVOID))GetProcAddress(dll, "RemoveFontResourceExW");
    remove_memory_font = (BOOL (WINAPI *)(HANDLE))GetProcAddress(dll, "RemoveFontMemResourceEx");
    window_class = (UINT (WINAPI *)(HWND,LPWSTR,UINT))GetProcAddress(dll, "RealGetWindowClassW");
    check("SIX_ACTUAL_EXPORTS", system_info && seek && heap_info && remove_font && remove_memory_font && window_class);
    if (!system_info || !seek || !heap_info || !remove_font || !remove_memory_font || !window_class) goto unload;
    for (i = 0; i < sizeof(ordinary); ++i) { ((BYTE *)&ordinary)[i] = 0; ((BYTE *)&native)[i] = 0; }
    GetSystemInfo(&ordinary); system_info(&native);
    check("NATIVE_SYSTEM_INFO_ALL_FIELDS", same(&ordinary, &native, sizeof(native)) && native.dwNumberOfProcessors > 0 && native.dwPageSize > 0);
    file = CreateFileA("C:\\VXDLAB\\VLCFILE.DAT", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                       CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    check("FRESH_FILE_CREATE", file != INVALID_HANDLE_VALUE);
    if (file != INVALID_HANDLE_VALUE) {
        check("REAL_FILE_WRITE", WriteFile(file, "VLC seek test", 13, &wrote, NULL) && wrote == 13);
        distance.QuadPart = 3; SetLastError(0x1234);
        check("SEEK_BEGIN_REAL_POSITION", seek(file, distance, &position, FILE_BEGIN) && position.QuadPart == 3);
        check("SEEK_SUCCESS_LAST_ERROR", GetLastError() == 0x1234);
        distance.QuadPart = 2;
        check("SEEK_CURRENT_POSITIVE", seek(file, distance, &position, FILE_CURRENT) && position.QuadPart == 5);
        distance.QuadPart = -2;
        check("SEEK_CURRENT_NEGATIVE", seek(file, distance, &position, FILE_CURRENT) && position.QuadPart == 3);
        check("READ_AFTER_REAL_SEEK", ReadFile(file, data, 4, &read, NULL) && read == 4 && same(data, " see", 4));
        distance.QuadPart = 0;
        check("SEEK_END_REAL_LENGTH", seek(file, distance, &position, FILE_END) && position.QuadPart == 13);
        position.QuadPart = 0x12345;
        check("INVALID_METHOD_NO_OUTPUT_WRITE", !seek(file, distance, &position, 99) && GetLastError() == ERROR_INVALID_PARAMETER && position.QuadPart == 0x12345);
        FlushFileBuffers(file); CloseHandle(file);
    }
    distance.QuadPart = 0; position.QuadPart = 0x12345;
    check("INVALID_HANDLE_NATIVE_ERROR", !seek(INVALID_HANDLE_VALUE, distance, &position, FILE_BEGIN) && GetLastError() == ERROR_INVALID_HANDLE && position.QuadPart == 0x12345);
    check("HEAP_LFH_UNSUPPORTED_NO_FAKE_ACTIVATION", !heap_info(GetProcessHeap(), 0, &lfh, sizeof(lfh)) && GetLastError() == ERROR_NOT_SUPPORTED);
    check("HEAP_CORRUPTION_TERMINATION_UNSUPPORTED", !heap_info(NULL, 1, NULL, 0) && GetLastError() == ERROR_NOT_SUPPORTED);
    check("HEAP_INVALID_CLASS", !heap_info(GetProcessHeap(), 99, NULL, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
    check("HEAP_INVALID_LFH_ARGUMENT", !heap_info(GetProcessHeap(), 0, NULL, 0) && GetLastError() == ERROR_INVALID_PARAMETER);
    copied = CopyFileA("C:\\WINDOWS\\FONTS\\ARIAL.TTF", "C:\\VXDLAB\\VLCFONT.TTF", TRUE);
    check("ACTUAL_OWNED_FONT_COPY", copied);
    if (copied) {
        int added = AddFontResourceA("C:\\VXDLAB\\VLCFONT.TTF");
        check("ACTUAL_PUBLIC_FONT_ADD", added > 0);
        if (added > 0) {
            BOOL removed = remove_font(L"C:\\VXDLAB\\VLCFONT.TTF", 0, NULL);
            check("ACTUAL_PUBLIC_FONT_REMOVE", removed);
            if (!removed) RemoveFontResourceA("C:\\VXDLAB\\VLCFONT.TTF");
        }
        check("ACTUAL_OWNED_FONT_FILE_DELETE", DeleteFileA("C:\\VXDLAB\\VLCFONT.TTF"));
    }
    check("FONT_PRIVATE_FLAG_HONEST_FAILURE", !remove_font(L"C:\\VXDLAB\\FONT.TTF", 0x10, NULL) && GetLastError() == ERROR_NOT_SUPPORTED);
    check("FONT_RESERVED_ARGUMENT", !remove_font(L"C:\\VXDLAB\\FONT.TTF", 0, (void *)1) && GetLastError() == ERROR_INVALID_PARAMETER);
    /* An isolated surrogate has no genuine ACP filename representation.
     * It must never be translated into a different filename and removed. */
    check("FONT_LOSSY_UNICODE_REJECTED", !remove_font(L"C:\\VXDLAB\\\xD83D.TTF", 0, NULL) && GetLastError() == ERROR_NO_UNICODE_TRANSLATION);
    check("MEMORY_FONT_NULL_HANDLE", !remove_memory_font(NULL) && GetLastError() == ERROR_INVALID_HANDLE);
    check("MEMORY_FONT_UNSUPPORTED_HANDLE", !remove_memory_font((HANDLE)1) && GetLastError() == ERROR_NOT_SUPPORTED);
    /* Use a new superclass of the native Button control. Real class is Button,
     * while ordinary GetClassName returns our registered superclass name. */
    for (i = 0; i < sizeof(base_class); ++i) ((BYTE *)&base_class)[i] = 0;
    base_class.cbSize = sizeof(base_class);
    check("GET_NATIVE_BUTTON_CLASS", GetClassInfoExA(NULL, "Button", &base_class));
    base_class.hInstance = GetModuleHandleA(NULL); base_class.lpszClassName = "VLCQABTN";
    check("REGISTER_NATIVE_SUPERCLASS", RegisterClassExA(&base_class) != 0);
    window = CreateWindowExA(0, "VLCQABTN", "native class proof", WS_POPUP, 0, 0, 40, 20,
                             NULL, NULL, base_class.hInstance, NULL);
    check("CREATE_REAL_NATIVE_WINDOW", window != NULL);
    if (window) {
        check("REAL_CLASS_SUPERCLASS_IDENTITY", window_class(window, wide, 256) == 6 && wide_equal(wide, L"Button"));
        wide[0] = 0xffff; wide[1] = 0xffff;
        check("REAL_CLASS_TRUNCATION_NULL", window_class(window, wide, 2) == 1 && wide[0] == L'B' && wide[1] == 0);
        check("REAL_CLASS_BAD_BUFFER", !window_class(window, NULL, 1) && GetLastError() == ERROR_INVALID_PARAMETER);
        DestroyWindow(window);
    }
    UnregisterClassA("VLCQABTN", base_class.hInstance);
unload:
    FreeLibrary(dll);
finish:
    number("CHECKS=", checks); number("FAILURES=", failures);
    put(failures || io_failed ? "STATUS=FAIL\r\n" : "STATUS=SCOPED_NATIVE_API_PASS\r\n");
    put("UNSUPPORTED=NT_LFH_HEAP_TERMINATION_PRIVATE_AND_MEMORY_FONTS\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(failures || io_failed ? 31 : 0);
}
