/* SPDX-License-Identifier: GPL-2.0-only
 * Windows version as programs see it: GetVersionExW honours the application manifest (this program declares Windows 10
 * compatibility in t_k32_ver.rc, so it gets the true version, the one RtlGetVersion and the PEB report; t_k32_sys.exe has
 * no manifest and gets 6.2.9200), and the system DLLs carry a VERSIONINFO whose numeric file version is that same build
 * (Chromium's base::win::OSInfo::Kernel32Version() CHECKs that kernel32.dll has one; crashpad lists module versions). */
#include "k32test.h"
#include <winver.h>

typedef LONG NTSTATUS_;
NTSTATUS_ NTAPI RtlGetVersion(OSVERSIONINFOW *);
VOID NTAPI RtlGetDeviceFamilyInfoEnum(ULONGLONG *, ULONG *, ULONG *);
DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR, LPDWORD);
BOOL WINAPI GetFileVersionInfoW(LPCWSTR, DWORD, DWORD, LPVOID);
BOOL WINAPI VerQueryValueW(LPCVOID, LPCWSTR, LPVOID *, PUINT);

static void check_dll_version(const WCHAR *dll, const char *label, DWORD major, DWORD minor, DWORD build)
{
    DWORD h = 0, n = GetFileVersionInfoSizeW(dll, &h);
    static BYTE buf[8192];
    VS_FIXEDFILEINFO *ffi = 0;
    UINT len = 0;
    printf("-- %s\n", label);
    CHECKV(n > 0 && n <= sizeof buf, "GetFileVersionInfoSizeW finds a version resource", "size %lu err %lu", (unsigned long)n, (unsigned long)GetLastError());
    if (!n || n > sizeof buf) return;
    CHECK(GetFileVersionInfoW(dll, 0, n, buf) && VerQueryValueW(buf, L"\\", (LPVOID *)&ffi, &len) && ffi && len >= sizeof *ffi && ffi->dwSignature == 0xFEEF04BD,
          "GetFileVersionInfoW + VerQueryValueW(\\) give the fixed file information");
    if (!ffi) return;
    CHECKV(HIWORD(ffi->dwFileVersionMS) == major && LOWORD(ffi->dwFileVersionMS) == minor && HIWORD(ffi->dwFileVersionLS) == build,
           "the file version is the PEB's OS version (10.0.22631)", "%u.%u.%u.%u", HIWORD(ffi->dwFileVersionMS), LOWORD(ffi->dwFileVersionMS),
           HIWORD(ffi->dwFileVersionLS), LOWORD(ffi->dwFileVersionLS));
    CHECK(ffi->dwFileType == 2 /* VFT_DLL */ && ffi->dwFileOS == 0x40004 /* VOS_NT_WINDOWS32 */, "... typed as an NT DLL");
}

int main(void)
{
    OSVERSIONINFOW rtl;
    OSVERSIONINFOEXW ex;
    HMODULE me = GetModuleHandleW(0);
    HRSRC r = FindResourceW(me, MAKEINTRESOURCEW(1), MAKEINTRESOURCEW(24));
    memset(&rtl, 0, sizeof rtl); rtl.dwOSVersionInfoSize = sizeof rtl;
    memset(&ex, 0, sizeof ex); ex.dwOSVersionInfoSize = sizeof ex;
    CHECK(r != 0 && SizeofResource(me, r) > 100, "this program carries an RT_MANIFEST resource (id 1)");
    CHECK(RtlGetVersion(&rtl) == 0 && rtl.dwMajorVersion == 10 && rtl.dwMinorVersion == 0 && rtl.dwBuildNumber == 22631,
          "RtlGetVersion reports the PEB's 10.0.22631");
    {   /* Chromium resolves this with GetProcAddress(ntdll) and CHECKs the pointer */
        ULONGLONG ver = 0;
        ULONG fam = 99, form = 99;
        FARPROC fn = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetDeviceFamilyInfoEnum");
        CHECK(fn != 0, "ntdll exports RtlGetDeviceFamilyInfoEnum (GetProcAddress finds it)");
        if (fn) ((VOID (NTAPI *)(ULONGLONG *, ULONG *, ULONG *))(void *)fn)(&ver, &fam, &form);   /* called through the pointer Chromium would get */
        CHECKV(ver == ((10ull << 48) | (0ull << 32) | (22631ull << 16) | 1) && fam == 3 && form == 0,
               "RtlGetDeviceFamilyInfoEnum: UAP version = the PEB's 10.0.22631.1, family DESKTOP (3), form UNKNOWN (0)", "%llx %lu %lu", ver, (unsigned long)fam, (unsigned long)form);
        RtlGetDeviceFamilyInfoEnum(0, 0, 0);
        CHECK(1, "NULL output pointers are allowed");
    }
    CHECK(GetVersionExW((LPOSVERSIONINFOW)&ex), "GetVersionExW (OSVERSIONINFOEXW)");
    CHECKV(ex.dwMajorVersion == rtl.dwMajorVersion && ex.dwMinorVersion == rtl.dwMinorVersion && ex.dwBuildNumber == rtl.dwBuildNumber,
           "with the Windows 10 supportedOS GUID in the manifest GetVersionExW reports the true version", "%lu.%lu.%lu",
           (unsigned long)ex.dwMajorVersion, (unsigned long)ex.dwMinorVersion, (unsigned long)ex.dwBuildNumber);
    CHECK(ex.dwPlatformId == VER_PLATFORM_WIN32_NT && ex.wProductType == VER_NT_WORKSTATION && ex.wServicePackMajor == 0 && ex.szCSDVersion[0] == 0,
          "platform NT, workstation, no service pack");
    memset(&ex, 0, sizeof ex); ex.dwOSVersionInfoSize = sizeof(OSVERSIONINFOW);
    CHECK(GetVersionExW((LPOSVERSIONINFOW)&ex) && ex.dwBuildNumber == rtl.dwBuildNumber && ex.wProductType == 0, "the short OSVERSIONINFOW form leaves the EX fields alone");
    ex.dwOSVersionInfoSize = 4;
    SetLastError(0);
    CHECK(!GetVersionExW((LPOSVERSIONINFOW)&ex) && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "a too-small dwOSVersionInfoSize is ERROR_INSUFFICIENT_BUFFER");
    {   /* by the loaded modules' full paths (version.dll's bare-name search order is its own concern; Chromium asks by the bare
         * name "kernel32.dll", which is why that search must exist in version.dll) */
        static WCHAR k32[MAX_PATH], nt[MAX_PATH];
        CHECK(GetModuleFileNameW(GetModuleHandleW(L"kernel32.dll"), k32, MAX_PATH) > 12 && GetModuleFileNameW(GetModuleHandleW(L"ntdll.dll"), nt, MAX_PATH) > 9,
              "GetModuleFileNameW of kernel32.dll and ntdll.dll");
        check_dll_version(k32, "kernel32.dll by its module path", rtl.dwMajorVersion, rtl.dwMinorVersion, rtl.dwBuildNumber);
        check_dll_version(nt, "ntdll.dll by its module path", rtl.dwMajorVersion, rtl.dwMinorVersion, rtl.dwBuildNumber);
        check_dll_version(L"C:\\SHZ\\SYS64\\kernel32.dll", "C:\\SHZ\\SYS64\\kernel32.dll", rtl.dwMajorVersion, rtl.dwMinorVersion, rtl.dwBuildNumber);
    }
    return k32t_finish("t_k32_ver");
}
