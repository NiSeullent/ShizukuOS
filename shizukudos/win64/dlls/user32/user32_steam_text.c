/* SPDX-License-Identifier: GPL-2.0-only
 * Steam text imports over actual Unicode windows/dialogs and the existing UCRT
 * formatter. Matches wineport/glue/user32_text.c's 1024-unit/legacy-wide policy.
 * Native windows retain this runtime's existing Unicode callback procedures.
 * Cross-width wsprintf text is supported for ASCII; the UCRT C locale is not
 * the UTF-8 ACP, so non-ASCII cross-width text fails explicitly before output.
 */
#include "user32_int.h"
#include <limits.h>

__declspec(dllimport) int __cdecl __stdio_common_vsprintf(uint64_t, char *, size_t, const char *, void *, va_list);
__declspec(dllimport) int __cdecl __stdio_common_vswprintf(uint64_t, WCHAR *, size_t, const WCHAR *, void *, va_list);
#define PRINTF_LEGACY_WIDE 4ull
#define WSPRINTF_LIMIT 1024

static unsigned format_unit(const void *format, int wide, size_t i)
{
    return wide ? ((const WCHAR *)format)[i] : ((const BYTE *)format)[i];
}

/* Validate the documented no-float Win32 subset and the CRT's code-page limit.
 * A copied va_list leaves the actual formatter's argument sequence unchanged. */
static int supported_format(const void *format, int wide, va_list arguments)
{
    size_t i = 0;
    va_list scan;
    int supported = TRUE;
    va_copy(scan, arguments);
    while (format_unit(format, wide, i)) {
        unsigned type, prefix = 0;
        int bits64 = 0, width = 0, precision = -1;
        if (i >= 65536) { supported = FALSE; break; }
        if (format_unit(format, wide, i++) != '%') continue;
        if (format_unit(format, wide, i) == '%') { ++i; continue; }
        while ((type = format_unit(format, wide, i)) == '-' || type == '#' || type == '0') ++i;
        while ((type = format_unit(format, wide, i)) >= '0' && type <= '9') {
            if (width > 65536) { supported = FALSE; break; }
            width = width * 10 + (int)(type - '0'); ++i;
        }
        if (!supported || width > 65536) { supported = FALSE; break; }
        if (type == '.') {
            precision = 0; ++i;
            while ((type = format_unit(format, wide, i)) >= '0' && type <= '9') {
                if (precision > 65536) { supported = FALSE; break; }
                precision = precision * 10 + (int)(type - '0'); ++i;
            }
            if (!supported || precision > 65536) { supported = FALSE; break; }
        }
        if (type == 'h' || type == 'l') { prefix = type; type = format_unit(format, wide, ++i); }
        else if (type == 'I') {
            ++i; bits64 = 1;
            if (format_unit(format, wide, i) == '6' && format_unit(format, wide, i + 1) == '4') i += 2;
            else if (format_unit(format, wide, i) == '3' && format_unit(format, wide, i + 1) == '2') { bits64 = 0; i += 2; }
            type = format_unit(format, wide, i);
        }
        if (!type) { supported = FALSE; break; }
        ++i;
        if (type == 'd' || type == 'i' || type == 'u' || type == 'x' || type == 'X') {
            if (bits64) (void)va_arg(scan, long long); else (void)va_arg(scan, int);
        } else if (type == 'p') {
            if (prefix || bits64) { supported = FALSE; break; }
            (void)va_arg(scan, void *);
        } else if (type == 's' || type == 'S' || type == 'c' || type == 'C') {
            const int text_wide = prefix == 'l' || (!prefix && ((type == 's' || type == 'c') ? wide : !wide));
            if (bits64) { supported = FALSE; break; }
            if (type == 'c' || type == 'C') {
                unsigned c = (unsigned)va_arg(scan, int);
                if (text_wide != wide && c > 127) { supported = FALSE; break; }
            } else {
                const void *text = va_arg(scan, const void *);
                if (text && text_wide != wide) {
                    size_t n = 0;
                    while ((precision < 0 || n < (size_t)precision) && format_unit(text, text_wide, n)) {
                        if (n >= 65536 || format_unit(text, text_wide, n) > 127) { supported = FALSE; break; }
                        ++n;
                    }
                    if (!supported) break;
                }
            }
        } else { supported = FALSE; break; }
    }
    va_end(scan);
    return supported;
}

DLLAPI int WINAPI wvsprintfA(LPSTR output, LPCSTR format, va_list arguments)
{
    int result;
    if (!output || !format) { if (output) output[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!supported_format(format, 0, arguments)) { output[0] = 0; SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    result = __stdio_common_vsprintf(PRINTF_LEGACY_WIDE, output, WSPRINTF_LIMIT, format, 0, arguments);
    if (result == -2) { output[WSPRINTF_LIMIT - 1] = 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return WSPRINTF_LIMIT - 1; }
    if (result < 0) { output[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return result;
}
DLLAPI int WINAPI wvsprintfW(LPWSTR output, LPCWSTR format, va_list arguments)
{
    int result;
    if (!output || !format) { if (output) output[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!supported_format(format, 1, arguments)) { output[0] = 0; SetLastError(ERROR_NOT_SUPPORTED); return 0; }
    result = __stdio_common_vswprintf(PRINTF_LEGACY_WIDE, output, WSPRINTF_LIMIT, format, 0, arguments);
    if (result == -2) { output[WSPRINTF_LIMIT - 1] = 0; SetLastError(ERROR_INSUFFICIENT_BUFFER); return WSPRINTF_LIMIT - 1; }
    if (result < 0) { output[0] = 0; SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return result;
}
DLLAPI int WINAPIV wsprintfA(LPSTR output, LPCSTR format, ...)
{
    va_list arguments; int result;
    va_start(arguments, format); result = wvsprintfA(output, format, arguments); va_end(arguments); return result;
}
DLLAPI int WINAPIV wsprintfW(LPWSTR output, LPCWSTR format, ...)
{
    va_list arguments; int result;
    va_start(arguments, format); result = wvsprintfW(output, format, arguments); va_end(arguments); return result;
}

DLLAPI int WINAPI GetWindowTextLengthA(HWND window)
{
    DWORD previous_error = GetLastError();
    int units = GetWindowTextLengthW(window), copied, bytes;
    WCHAR *text;
    if (units <= 0) return 0;
    if (units == INT_MAX) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    text = HeapAlloc(GetProcessHeap(), 0, ((SIZE_T)units + 1) * sizeof(WCHAR));
    if (!text) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    copied = GetWindowTextW(window, text, units + 1);
    bytes = copied > 0 ? WideCharToMultiByte(CP_ACP, 0, text, copied, 0, 0, 0, 0) : 0;
    HeapFree(GetProcessHeap(), 0, text);
    if (bytes > 0) SetLastError(previous_error);
    return bytes;
}

DLLAPI INT_PTR WINAPI DialogBoxParamA(HINSTANCE instance, LPCSTR resource, HWND owner, DLGPROC procedure, LPARAM init)
{
    WCHAR *converted = 0;
    LPCWSTR name;
    INT_PTR result;
    int units;
    if (!resource) { SetLastError(ERROR_INVALID_PARAMETER); return -1; }
    if (owner && !IsWindow(owner)) return 0;                 /* documented invalid-owner return */
    if (IS_INTRESOURCE(resource)) name = (LPCWSTR)resource;
    else {
        units = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, resource, -1, 0, 0);
        if (!units) return -1;
        converted = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)units * sizeof(WCHAR));
        if (!converted) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return -1; }
        if (!MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, resource, -1, converted, units)) {
            DWORD error = GetLastError(); HeapFree(GetProcessHeap(), 0, converted); SetLastError(error); return -1;
        }
        name = converted;
    }
    result = DialogBoxParamW(instance, name, owner, procedure, init);
    if (converted) { DWORD error = GetLastError(); HeapFree(GetProcessHeap(), 0, converted); SetLastError(error); }
    return result;
}
