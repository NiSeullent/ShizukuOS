/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <string.h>
#include "vlc_compat_host/windows.h"
#include "../src/m98_vlc_compat.h"
static unsigned checks, failures, file_calls, seek_calls, font_calls, heap_calls;
static DWORD last_error, native_type, type_error, seek_error, seek_low, seek_method;
static LONG seek_high, input_high, input_low;
static int conversion_mode, conversion_flags, real_present;
static SYSTEM_INFO system_value;
static char removed_path[MAX_PATH];
static void check(const char *name, int ok) {
    ++checks; if (!ok) ++failures;
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
}
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD error) { last_error = error; }
DWORD GetFileType(HANDLE file) { (void)file; ++file_calls; last_error = type_error; return native_type; }
DWORD SetFilePointer(HANDLE file, LONG low, LONG *high, DWORD method) {
    (void)file; ++seek_calls; input_low = low; input_high = *high; seek_method = method;
    *high = seek_high; last_error = seek_error; return seek_low;
}
void GetSystemInfo(LPSYSTEM_INFO info) { *info = system_value; }
BOOL HeapValidate(HANDLE heap, DWORD flags, const void *block) {
    (void)flags; (void)block; ++heap_calls; return heap == (HANDLE)1;
}
int WideCharToMultiByte(UINT page, DWORD flags, LPCWSTR value, int length,
                       LPSTR output, int capacity, const char *replacement, BOOL *loss) {
    int i = 0;
    (void)page; (void)length; (void)replacement; conversion_flags = (int)flags;
    if (conversion_mode == 3) { last_error = 321; return 0; }
    while (value[i] && i + 1 < capacity) { output[i] = (char)value[i]; ++i; }
    output[i] = 0; *loss = conversion_mode == 1;
    if (conversion_mode == 2) output[0] = 'X'; /* genuine best-fit candidate */
    return i + 1;
}
int MultiByteToWideChar(UINT page, DWORD flags, const char *value, int length,
                       LPWSTR output, int capacity) {
    int i = 0; (void)page; (void)flags; (void)length;
    while (value[i] && i + 1 < capacity) { output[i] = (unsigned char)value[i]; ++i; }
    output[i] = 0; return i + 1;
}
BOOL RemoveFontResourceA(const char *path) {
    ++font_calls; strcpy(removed_path, path); last_error = 444; return TRUE;
}
HMODULE GetModuleHandleA(const char *name) { return !strcmp(name, "USER32.DLL") ? (HMODULE)1 : NULL; }
static UINT native_real_class(HWND window, LPSTR output, UINT capacity) {
    const char *name = "Button";
    if (!window) { last_error = 1400; return 0; }
    if (capacity < 7) return 0;
    memcpy(output, name, 7); return 6;
}
FARPROC GetProcAddress(HMODULE module, const char *name) {
    union { UINT (*typed)(HWND, LPSTR, UINT); FARPROC generic; } pointer;
    if (module && real_present && !strcmp(name, "RealGetWindowClass")) {
        pointer.typed = native_real_class; return pointer.generic;
    }
    return NULL;
}
static void seek_reset(void) {
    native_type = FILE_TYPE_DISK; type_error = seek_error = 0;
    seek_low = 12; seek_high = 0; last_error = 777; seek_calls = file_calls = 0;
}
int main(void) {
    LARGE_INTEGER distance, output; SYSTEM_INFO info; WCHAR wide[8];
    WCHAR name[] = {'F','O','N','T','.','T','T','F',0};
    ULONG lfh = 2; unsigned i;
    distance.QuadPart = -2; output.QuadPart = 42; seek_reset();
    seek_low = 0xffffffffu; seek_high = 1;
    check("AMBIGUOUS_FFFFFFFF_NATIVE_SUCCESS", m98_vlc_SetFilePointerEx((HANDLE)1, distance, &output, FILE_CURRENT) && output.QuadPart == 0x1ffffffffll);
    check("NATIVE_64BIT_DISTANCE_AND_METHOD", input_low == -2 && input_high == -1 && seek_method == FILE_CURRENT);
    check("SUCCESS_RESTORES_CALLER_ERROR", last_error == 777);
    seek_reset(); seek_low = 0xffffffffu; seek_error = 112; output.QuadPart = 42;
    check("AMBIGUOUS_FFFFFFFF_REAL_FAILURE", !m98_vlc_SetFilePointerEx((HANDLE)1, distance, &output, FILE_END) && last_error == 112 && output.QuadPart == 42);
    seek_reset();
    check("INVALID_METHOD_NO_NATIVE_EFFECT", !m98_vlc_SetFilePointerEx((HANDLE)1, distance, &output, 99) && last_error == 87 && !seek_calls && !file_calls);
    seek_reset(); native_type = FILE_TYPE_PIPE;
    check("NONSEEKABLE_HANDLE_REJECTED", !m98_vlc_SetFilePointerEx((HANDLE)1, distance, &output, FILE_BEGIN) && last_error == 1 && !seek_calls);
    seek_reset(); native_type = FILE_TYPE_UNKNOWN; type_error = 6;
    check("NATIVE_HANDLE_ERROR_PRESERVED", !m98_vlc_SetFilePointerEx(NULL, distance, &output, FILE_BEGIN) && last_error == 6 && output.QuadPart == 42 && !seek_calls);
    seek_reset(); native_type = FILE_TYPE_UNKNOWN;
    check("UNKNOWN_FILETYPE_NO_FAKE_SEEK", !m98_vlc_SetFilePointerEx((HANDLE)1, distance, &output, FILE_BEGIN) && last_error == 1 && !seek_calls);
    seek_reset();
    check("OPTIONAL_POSITION_POINTER", m98_vlc_SetFilePointerEx((HANDLE)1, distance, NULL, FILE_END) && seek_calls == 1);
    for (i = 0; i < 12; ++i) system_value.opaque[i] = 0x12340000 + i;
    memset(&info, 0, sizeof(info)); m98_vlc_GetNativeSystemInfo(&info);
    check("SYSTEM_INFO_PASSED_THROUGH", !memcmp(&info, &system_value, sizeof(info)));
    heap_calls = 0;
    check("VALID_HEAP_LFH_HONEST_UNSUPPORTED", !m98_vlc_HeapSetInformation((HANDLE)1, 0, &lfh, sizeof(lfh)) && last_error == 50 && heap_calls == 1);
    check("CORRUPTION_TERMINATION_HONEST_UNSUPPORTED", !m98_vlc_HeapSetInformation(NULL, 1, NULL, 0) && last_error == 50);
    check("INVALID_LFH_BUFFER", !m98_vlc_HeapSetInformation((HANDLE)1, 0, NULL, 0) && last_error == 87);
    check("INVALID_HEAP_CLASS", !m98_vlc_HeapSetInformation((HANDLE)1, 99, NULL, 0) && last_error == 87);
    font_calls = 0; conversion_mode = 0;
    check("NATIVE_PUBLIC_FONT_REMOVAL", m98_vlc_RemoveFontResourceExW(name, 0, NULL) && font_calls == 1 && !strcmp(removed_path, "FONT.TTF"));
    check("OLD_NATIVE_CONVERSION_FLAGS_ZERO", conversion_flags == 0);
    check("NATIVE_FONT_RESULT_ERROR_PRESERVED", last_error == 444);
    font_calls = 0; conversion_mode = 1;
    check("DEFAULT_CHAR_NO_FONT_REMOVAL", !m98_vlc_RemoveFontResourceExW(name, 0, NULL) && last_error == 1113 && !font_calls);
    conversion_mode = 2;
    check("BEST_FIT_ROUNDTRIP_NO_FONT_REMOVAL", !m98_vlc_RemoveFontResourceExW(name, 0, NULL) && last_error == 1113 && !font_calls);
    conversion_mode = 3;
    check("NATIVE_CONVERSION_FAILURE_PRESERVED", !m98_vlc_RemoveFontResourceExW(name, 0, NULL) && last_error == 321 && !font_calls);
    check("PRIVATE_FONT_SEMANTICS_NO_GLOBAL_REMOVAL", !m98_vlc_RemoveFontResourceExW(name, 0x10, NULL) && last_error == 50 && !font_calls);
    check("RESERVED_FONT_ARGUMENT_REJECTED", !m98_vlc_RemoveFontResourceExW(name, 0, (void *)1) && last_error == 87 && !font_calls);
    check("MEMORY_FONT_NULL_HANDLE", !m98_vlc_RemoveFontMemResourceEx(NULL) && last_error == 6);
    check("MEMORY_FONT_NO_FAKE_REMOVAL", !m98_vlc_RemoveFontMemResourceEx((HANDLE)1) && last_error == 50);
    real_present = 1; wide[0] = 0xffff;
    check("EXACT_NATIVE_REAL_CLASS_EXPORT", m98_vlc_RealGetWindowClassW((HWND)1, wide, 8) == 6 && wide[0] == 'B' && wide[6] == 0);
    check("NATIVE_CLASS_TRUNCATION_NUL", m98_vlc_RealGetWindowClassW((HWND)1, wide, 2) == 1 && wide[0] == 'B' && wide[1] == 0);
    check("ZERO_CLASS_BUFFER_REJECTED", !m98_vlc_RealGetWindowClassW((HWND)1, wide, 0) && last_error == 87);
    check("NULL_CLASS_BUFFER_REJECTED", !m98_vlc_RealGetWindowClassW((HWND)1, NULL, 8) && last_error == 87);
    check("NATIVE_CLASS_ERROR_PRESERVED", !m98_vlc_RealGetWindowClassW(NULL, wide, 8) && last_error == 1400);
    real_present = 0;
    check("ABSENT_NATIVE_CLASS_EXPORT_NOT_FAKED", !m98_vlc_RealGetWindowClassW((HWND)1, wide, 8) && last_error == 120);
    printf("CHECKS=%u FAILURES=%u\n", checks, failures);
    return failures ? 1 : 0;
}
