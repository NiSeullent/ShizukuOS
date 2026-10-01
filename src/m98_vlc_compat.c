/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded native Win98 bridges for the official VLC3.0.24 Qt/local-media path.
 * No guest structures are patched; unsupported heap/private-font operations
 * return real failures. Microsoft API contracts are listed in the triage doc.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "kex_abi.h"
#include "m98_vlc_compat.h"

void WINAPI m98_vlc_GetNativeSystemInfo(LPSYSTEM_INFO info)
{
    /* Genuine Win98 is native x86, with no WOW64 alternate architecture. */
    GetSystemInfo(info);
}

BOOL WINAPI m98_vlc_SetFilePointerEx(HANDLE file, LARGE_INTEGER distance,
                                   PLARGE_INTEGER position, DWORD method)
{
    DWORD before = GetLastError(), low, error, type;
    if (method != FILE_BEGIN && method != FILE_CURRENT && method != FILE_END) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    SetLastError(NO_ERROR);
    type = GetFileType(file);
    error = GetLastError();
    if (type != FILE_TYPE_DISK) {
        SetLastError(type == FILE_TYPE_UNKNOWN && error ? error : ERROR_INVALID_FUNCTION);
        return FALSE;
    }
    /* INVALID_SET_FILE_POINTER is also a valid low word. Clear LastError so
     * that genuine native failures can be distinguished from that position.
     * The original native API retains its actual filesystem/64-bit limits. */
    SetLastError(NO_ERROR);
    low = SetFilePointer(file, (LONG)distance.LowPart, &distance.HighPart, method);
    error = GetLastError();
    if (low == INVALID_SET_FILE_POINTER && error != NO_ERROR) {
        SetLastError(error);
        return FALSE;
    }
    distance.LowPart = low;
    if (position) *position = distance;
    SetLastError(before);
    return TRUE;
}

BOOL WINAPI m98_vlc_HeapSetInformation(HANDLE heap, DWORD kind,
                                     PVOID information, SIZE_T bytes)
{
    if (kind == 0) { /* HeapCompatibilityInformation: only LFH activation. */
        if (!heap || !information || bytes != sizeof(ULONG)) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (!HeapValidate(heap, 0, NULL)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
        if (*(const ULONG *)information != 2) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
    } else if (kind == 1) { /* HeapEnableTerminationOnCorruption */
        if (information || bytes) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (heap && !HeapValidate(heap, 0, NULL)) {
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
    } else {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Win98 has neither LFH nor NT heap termination-on-corruption. Returning
     * TRUE here would falsely claim that these requested features are active. */
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

BOOL WINAPI m98_vlc_RemoveFontResourceExW(LPCWSTR name, DWORD flags, PVOID reserved)
{
    char ansi[MAX_PATH];
    WCHAR roundtrip[MAX_PATH];
    unsigned length = 0;
    BOOL loss = FALSE;
    int result;
    if (!name || reserved || (flags & ~0x30u)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    /* Native Win98 does not supply NT private/non-enumerable font ownership.
     * Do not silently remove a global font while claiming those semantics. */
    if (flags) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }
    while (length < MAX_PATH && name[length]) ++length;
    if (!length || length == MAX_PATH) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    result = WideCharToMultiByte(CP_ACP, 0, name, -1,
                                ansi, sizeof(ansi), NULL, &loss);
    if (!result) return FALSE;
    if (loss) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return FALSE;
    }
    /* A native flags-zero round trip also catches best-fit mappings without
     * assuming that an old Win9x converter accepts newer conversion flags. */
    result = MultiByteToWideChar(CP_ACP, 0, ansi, -1, roundtrip, MAX_PATH);
    if (!result) return FALSE;
    if ((unsigned)result != length + 1) {
        SetLastError(ERROR_NO_UNICODE_TRANSLATION);
        return FALSE;
    }
    for (length = 0; roundtrip[length]; ++length) {
        if (roundtrip[length] != name[length]) {
            SetLastError(ERROR_NO_UNICODE_TRANSLATION);
            return FALSE;
        }
    }
    return RemoveFontResourceA(ansi);
}

BOOL WINAPI m98_vlc_RemoveFontMemResourceEx(HANDLE resource)
{
    /* No native memory-font handles are created by this provider; ordinary
     * old KernelEx AddFontMemResourceEx already fails. Never report that an
     * arbitrary pointer or unrelated native object was successfully removed. */
    SetLastError(resource ? ERROR_NOT_SUPPORTED : ERROR_INVALID_HANDLE);
    return FALSE;
}

UINT WINAPI m98_vlc_RealGetWindowClassW(HWND window, LPWSTR output, UINT capacity)
{
    typedef UINT (WINAPI *real_class_a)(HWND, LPSTR, UINT);
    real_class_a get_class;
    HMODULE user;
    char ansi[256];
    WCHAR wide[256];
    UINT count, copied, i;
    int converted;
    if (!output || !capacity) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return 0;
    }
    user = GetModuleHandleA("USER32.DLL");
    get_class = user ? (real_class_a)GetProcAddress(user, "RealGetWindowClass") : NULL;
    if (!get_class) {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
        return 0;
    }
    count = get_class(window, ansi, sizeof(ansi));
    if (!count) return 0;
    if (count >= sizeof(ansi)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }
    ansi[count] = 0;
    converted = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, ansi, -1, wide, 256);
    if (!converted) return 0;
    copied = (UINT)converted - 1;
    if (copied >= capacity) copied = capacity - 1;
    for (i = 0; i < copied; ++i) output[i] = wide[i];
    output[copied] = 0;
    return copied;
}

#define API(name, implementation) { name, (unsigned long)(implementation) }
static const m98_named_api kernel_entries[] = {
    API("GetNativeSystemInfo", m98_vlc_GetNativeSystemInfo),
    API("HeapSetInformation", m98_vlc_HeapSetInformation),
    API("SetFilePointerEx", m98_vlc_SetFilePointerEx)
};
static const m98_named_api gdi_entries[] = {
    API("RemoveFontMemResourceEx", m98_vlc_RemoveFontMemResourceEx),
    API("RemoveFontResourceExW", m98_vlc_RemoveFontResourceExW)
};
static const m98_named_api user_entries[] = {
    API("RealGetWindowClassW", m98_vlc_RealGetWindowClassW)
};
static const m98_api_table tables[] = {
    /* KernelEx parse_overrides appends .DLL to the Core.INI module before
     * merge compares target_library; table position is not an API variant id. */
    { "KERNEL32.DLL", kernel_entries, sizeof(kernel_entries) / sizeof(kernel_entries[0]), NULL, 0 },
    { "GDI32.DLL", gdi_entries, sizeof(gdi_entries) / sizeof(gdi_entries[0]), NULL, 0 },
    { "USER32.DLL", user_entries, sizeof(user_entries) / sizeof(user_entries[0]), NULL, 0 },
    { NULL, NULL, 0, NULL, 0 }
};

__declspec(dllexport) const m98_api_table *get_api_table(void)
{
    return tables;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
