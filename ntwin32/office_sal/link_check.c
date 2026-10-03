/* SPDX-License-Identifier: GPL-2.0-only
 * Link-only control: the declarations used by the LIBO_WIN98 SAL patch must
 * bind through the OFFSAL import library to the undecorated DLL exports.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
BOOL WINAPI OfsSetProcessDEPPolicy(DWORD);
BOOL WINAPI OfsSetDllDirectoryW(LPCWSTR);
BOOL WINAPI OfsSetSearchPathMode(DWORD);
DWORD WINAPI OfsGetProcessId(HANDLE);
BOOL WINAPI OfsRegisterProcessHandle(HANDLE, DWORD);
BOOL WINAPI OfsForgetProcessHandle(HANDLE);
BOOL WINAPI OfsGetModuleHandleExW(DWORD, LPCWSTR, HMODULE *);
BOOL WINAPI OfsGetFileSizeEx(HANDLE, LARGE_INTEGER *);
BOOL WINAPI OfsSetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER *, DWORD);
BOOL WINAPI OfsReplaceFileW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
HANDLE WINAPI OfsCreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DWORD WINAPI OfsGetFileAttributesW(LPCWSTR);
INT WINAPI OfsInetPtonW(INT, LPCWSTR, PVOID);
INT WINAPI OfsGetAddrInfoW(LPCWSTR, LPCWSTR, const void *, void **);
VOID WINAPI OfsFreeAddrInfoW(void *);
INT WINAPI OfsGetNameInfoW(const void *, INT, LPWSTR, DWORD, LPWSTR, DWORD, INT);
HANDLE WINAPI OfsCreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
USHORT WINAPI OfsCaptureStackBackTrace(DWORD, DWORD, PVOID *, PDWORD);
void WINAPI link_entry(void)
{
    HMODULE m = 0; LARGE_INTEGER a, b;
    UINT ok;
    a.QuadPart = 0;
    ok = !OfsSetProcessDEPPolicy(1) && !OfsSetDllDirectoryW(L"") && !OfsSetSearchPathMode(0x8001)
         && OfsGetProcessId(GetCurrentProcess()) == GetCurrentProcessId()
         && OfsRegisterProcessHandle((HANDLE)4, 9) && OfsForgetProcessHandle((HANDLE)4)
         && OfsGetModuleHandleExW(6, (LPCWSTR)link_entry, &m)
         && !OfsGetFileSizeEx(INVALID_HANDLE_VALUE, &b) && !OfsSetFilePointerEx(INVALID_HANDLE_VALUE, a, &b, 0)
         && !OfsReplaceFileW(L"C:\\x", L"C:\\y", 0, 0, 0, 0);
    {   /* Unicode layer + resolver: expected-failure paths must be truthful errors, never success */
        PVOID fr[4]; DWORD ip = 0;
        ok = ok && OfsCreateFileW(L"\\\\?\\C:\\x", GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0) == INVALID_HANDLE_VALUE
             && GetLastError() == 123 && OfsGetFileAttributesW(0) == 0xFFFFFFFFu
             && OfsInetPtonW(2, L"127.0.0.1", &ip) == 1 && ip == 0x0100007Fu && OfsInetPtonW(2, L"1.2.3", &ip) == 0
             && OfsGetAddrInfoW(0, 0, 0, 0) != 0
             && OfsCreateNamedPipeW(L"\\\\.\\pipe\\x", 3, 0, 1, 0, 0, 0, 0) == INVALID_HANDLE_VALUE && GetLastError() == 120
             && OfsCaptureStackBackTrace(0, 4, fr, 0) <= 4;
        (void)OfsFreeAddrInfoW; (void)OfsGetNameInfoW;
    }
    ExitProcess(ok ? 0u : 1u);
}
