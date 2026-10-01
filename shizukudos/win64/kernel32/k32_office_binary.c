/* SPDX-License-Identifier: GPL-2.0-only
 * GetBinaryTypeW/A: classify actual on-disk headers with bounded reads.
 * Reviewed Wine11 db11d0fe6a169c457e23d007e20404643d067aa8
 * dlls/kernel32/module.c and ReactOS
 * 9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8
 * dll/win32/kernel32/client/vdm.c. Original implementation; no code copied.
 * Unlike the old ReactOS parser, PE32+ is distinguished and DLLs rejected,
 * matching the reviewed Wine11 application contract. Explicit NE targets
 * are supported; ambiguous old NE and LE/LX fail rather than guess.
 */
#include "k32.h"
#include "k32_office_binary.h"

static unsigned binary_file_read(void *context, uint64_t offset, void *out, size_t size)
{
    LARGE_INTEGER position;
    DWORD got;
    position.QuadPart = (LONGLONG)offset;
    if (!SetFilePointerEx(context, position, NULL, FILE_BEGIN)) return shz_last_error() ? shz_last_error() : ERROR_READ_FAULT;
    if (!ReadFile(context, out, (DWORD)size, &got, NULL)) return shz_last_error() ? shz_last_error() : ERROR_READ_FAULT;
    return got == size ? 0 : ERROR_BAD_EXE_FORMAT;
}
static int binary_extension(LPCWSTR path, const char *extension)
{
    const WCHAR *dot = NULL;
    unsigned c;
    for (; *path; ++path) {
        if (*path == '/' || *path == '\\') dot = NULL;
        else if (*path == '.') dot = path;
    }
    if (!dot) return 0;
    while ((c = *dot++)) {
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
        if (c != (unsigned char)*extension++) return 0;
    }
    return *extension == 0;
}
K32API BOOL WINAPI GetBinaryTypeW(LPCWSTR path, LPDWORD output)
{
    HANDLE file;
    LARGE_INTEGER length;
    struct shz_binary_reader reader;
    struct shz_binary_result result;
    unsigned error;
    if (!path || !*path || !output) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    if (!GetFileSizeEx(file, &length)) {
        error = shz_last_error(); CloseHandle(file); shz_set_last_error(error ? error : ERROR_READ_FAULT); return FALSE;
    }
    if (length.QuadPart < 0) { CloseHandle(file); shz_set_last_error(ERROR_BAD_EXE_FORMAT); return FALSE; }
    reader.read = binary_file_read; reader.context = file; reader.length = (uint64_t)length.QuadPart;
    error = shz_binary_classify(&reader, &result);
    CloseHandle(file);
    if (error == ERROR_BAD_EXE_FORMAT && !result.mz) {
        if (binary_extension(path, ".com")) { result.type = SCS_DOS_BINARY; error = 0; }
        else if (binary_extension(path, ".pif")) { result.type = SCS_PIF_BINARY; error = 0; }
    }
    if (error) { shz_set_last_error(error); return FALSE; }
    *output = result.type;
    return TRUE;
}
K32API BOOL WINAPI GetBinaryTypeA(LPCSTR path, LPDWORD output)
{
    WCHAR *wide;
    int units;
    BOOL result;
    DWORD error;
    if (!path || !*path || !output) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    units = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
    if (!units) return FALSE;
    wide = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)units * sizeof *wide);
    if (!wide) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, wide, units)) {
        error = shz_last_error(); HeapFree(GetProcessHeap(), 0, wide); shz_set_last_error(error); return FALSE;
    }
    result = GetBinaryTypeW(wide, output); error = shz_last_error();
    HeapFree(GetProcessHeap(), 0, wide); shz_set_last_error(error);
    return result;
}
