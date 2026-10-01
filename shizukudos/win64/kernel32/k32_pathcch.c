/* SPDX-License-Identifier: GPL-2.0-only
 * API-set api-ms-win-core-path-l1-1-0 is hosted by the kernelbase/kernel32
 * alias in Kernel64. Delegate the complete lexical family to the real Wine
 * pathcch module, loaded from SYS64. Missing mandatory dependencies return
 * a failure HRESULT (or FALSE plus LastError), never a success-shaped stub.
 * Module references are balanced on every call; returned pointers refer to
 * caller input or a LocalAlloc allocation, not to module storage.
 */
#ifdef SHZ_PATHCCH_WRAPPER_HOST_TEST
#include "../dlls/pathcch/tests/pathcch_wrapper_host.h"
#else
#include "k32.h"
#endif

static FARPROC pathcch_proc(const char *name, HMODULE *module, HRESULT *error)
{
    FARPROC result;
    DWORD code;
    *module = LoadLibraryExW(L"pathcch.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!*module) {
        code = GetLastError();
        if (!code) code = ERROR_MOD_NOT_FOUND;
        SetLastError(code);
        *error = HRESULT_FROM_WIN32(code);
        return NULL;
    }
    result = GetProcAddress(*module, name);
    if (!result) {
        code = GetLastError();
        if (!code) code = ERROR_PROC_NOT_FOUND;
        FreeLibrary(*module);
        *module = NULL;
        SetLastError(code);
        *error = HRESULT_FROM_WIN32(code);
    }
    return result;
}

K32API HRESULT WINAPI PathAllocCanonicalize(const WCHAR *path_in, DWORD flags, WCHAR **path_out)
{
    typedef HRESULT (WINAPI *operation)(const WCHAR *path_in, DWORD flags, WCHAR **path_out);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathAllocCanonicalize", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path_in, flags, path_out);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathAllocCombine(const WCHAR *path1, const WCHAR *path2, DWORD flags, WCHAR **out)
{
    typedef HRESULT (WINAPI *operation)(const WCHAR *path1, const WCHAR *path2, DWORD flags, WCHAR **out);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathAllocCombine", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path1, path2, flags, out);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchAddBackslash(WCHAR *path, SIZE_T size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchAddBackslash", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchAddBackslashEx(WCHAR *path, SIZE_T size, WCHAR **end, SIZE_T *remaining)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size, WCHAR **end, SIZE_T *remaining);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchAddBackslashEx", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size, end, remaining);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchAddExtension(WCHAR *path, SIZE_T size, const WCHAR *extension)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size, const WCHAR *extension);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchAddExtension", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size, extension);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchAppend(WCHAR *path1, SIZE_T size, const WCHAR *path2)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path1, SIZE_T size, const WCHAR *path2);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchAppend", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path1, size, path2);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchAppendEx(WCHAR *path1, SIZE_T size, const WCHAR *path2, DWORD flags)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path1, SIZE_T size, const WCHAR *path2, DWORD flags);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchAppendEx", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path1, size, path2, flags);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchCanonicalize(WCHAR *out, SIZE_T size, const WCHAR *in)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *out, SIZE_T size, const WCHAR *in);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchCanonicalize", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(out, size, in);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchCanonicalizeEx(WCHAR *out, SIZE_T size, const WCHAR *in, DWORD flags)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *out, SIZE_T size, const WCHAR *in, DWORD flags);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchCanonicalizeEx", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(out, size, in, flags);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchCombine(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchCombine", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(out, size, path1, path2);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchCombineEx(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2, DWORD flags)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *out, SIZE_T size, const WCHAR *path1, const WCHAR *path2, DWORD flags);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchCombineEx", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(out, size, path1, path2, flags);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchFindExtension(const WCHAR *path, SIZE_T size, const WCHAR **extension)
{
    typedef HRESULT (WINAPI *operation)(const WCHAR *path, SIZE_T size, const WCHAR **extension);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchFindExtension", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size, extension);
    FreeLibrary(module);
    return result;
}

K32API BOOL WINAPI PathCchIsRoot(const WCHAR *path)
{
    typedef BOOL (WINAPI *operation)(const WCHAR *path);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchIsRoot", &module, &failure);
    BOOL result;
    if (!function) return FALSE;
    result = function(path);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchRemoveBackslash(WCHAR *path, SIZE_T path_size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T path_size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchRemoveBackslash", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, path_size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchRemoveBackslashEx(WCHAR *path, SIZE_T path_size, WCHAR **path_end, SIZE_T *free_size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T path_size, WCHAR **path_end, SIZE_T *free_size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchRemoveBackslashEx", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, path_size, path_end, free_size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchRemoveExtension(WCHAR *path, SIZE_T size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchRemoveExtension", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchRemoveFileSpec(WCHAR *path, SIZE_T size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchRemoveFileSpec", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchRenameExtension(WCHAR *path, SIZE_T size, const WCHAR *extension)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size, const WCHAR *extension);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchRenameExtension", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size, extension);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchSkipRoot(const WCHAR *path, const WCHAR **root_end)
{
    typedef HRESULT (WINAPI *operation)(const WCHAR *path, const WCHAR **root_end);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchSkipRoot", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, root_end);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchStripPrefix(WCHAR *path, SIZE_T size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchStripPrefix", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size);
    FreeLibrary(module);
    return result;
}

K32API HRESULT WINAPI PathCchStripToRoot(WCHAR *path, SIZE_T size)
{
    typedef HRESULT (WINAPI *operation)(WCHAR *path, SIZE_T size);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathCchStripToRoot", &module, &failure);
    HRESULT result;
    if (!function) return failure;
    result = function(path, size);
    FreeLibrary(module);
    return result;
}

K32API BOOL WINAPI PathIsUNCEx(const WCHAR *path, const WCHAR **server)
{
    typedef BOOL (WINAPI *operation)(const WCHAR *path, const WCHAR **server);
    HMODULE module;
    HRESULT failure;
    operation function = (operation)(ULONG_PTR)pathcch_proc("PathIsUNCEx", &module, &failure);
    BOOL result;
    if (!function) return FALSE;
    result = function(path, server);
    FreeLibrary(module);
    return result;
}
