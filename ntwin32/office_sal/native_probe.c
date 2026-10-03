/* SPDX-License-Identifier: GPL-2.0-only
 * OFSALPRB.EXE: native Windows 98 probe for OFFSAL.DLL. Runs LibreOffice SAL's
 * startup/process/module/file call sequence against real files in C:\VXDLAB and
 * writes C:\VXDLAB\OFSAL.LOG. Exit 0 only if every expectation held; the log,
 * not this source, is runtime evidence once run natively.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HANDLE log_file;
static int bad;
static void put(const char *s) { DWORD w; WriteFile(log_file, s, (DWORD)lstrlenA(s), &w, 0); }
static void res(const char *k, DWORD v, int ok) { char b[96]; wsprintfA(b, "%s=%lu %s\r\n", k, (unsigned long)v, ok ? "ok" : "BAD"); put(b); if (!ok) bad = 1; }

static const WCHAR A[] = L"C:\\VXDLAB\\OFSAL_A.TMP", B[] = L"C:\\VXDLAB\\OFSAL_B.TMP", U[] = L"C:\\VXDLAB\\\x4E2D\x6587.TMP";
static void make(const char *p, const char *text)
{
    DWORD w; HANDLE h = CreateFileA(p, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (h != INVALID_HANDLE_VALUE) { WriteFile(h, text, (DWORD)lstrlenA(text), &w, 0); CloseHandle(h); }
}

void WINAPI probe_entry(void)
{
    typedef BOOL (WINAPI *b1)(DWORD); typedef BOOL (WINAPI *bw)(LPCWSTR); typedef DWORD (WINAPI *ph)(HANDLE);
    typedef BOOL (WINAPI *gm)(DWORD, LPCWSTR, HMODULE *); typedef BOOL (WINAPI *gs)(HANDLE, LARGE_INTEGER *);
    typedef BOOL (WINAPI *sp)(HANDLE, LARGE_INTEGER, LARGE_INTEGER *, DWORD);
    typedef BOOL (WINAPI *rf)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPVOID, LPVOID);
    HMODULE dll, mod = 0; LARGE_INTEGER li, np; HANDLE f; char buf[8]; DWORD n;
    b1 dep, mode; bw dlldir; ph pid; gm getmod; gs size; sp seek; rf repl;
    log_file = CreateFileA("C:\\VXDLAB\\OFSAL.LOG", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (log_file == INVALID_HANDLE_VALUE) ExitProcess(2);
    dll = LoadLibraryA("OFFSAL.DLL");
    if (!dll) { res("load_error", GetLastError(), 0); goto done; }
    dep = (b1)GetProcAddress(dll, "OfsSetProcessDEPPolicy"); dlldir = (bw)GetProcAddress(dll, "OfsSetDllDirectoryW");
    mode = (b1)GetProcAddress(dll, "OfsSetSearchPathMode"); pid = (ph)GetProcAddress(dll, "OfsGetProcessId");
    getmod = (gm)GetProcAddress(dll, "OfsGetModuleHandleExW"); size = (gs)GetProcAddress(dll, "OfsGetFileSizeEx");
    seek = (sp)GetProcAddress(dll, "OfsSetFilePointerEx"); repl = (rf)GetProcAddress(dll, "OfsReplaceFileW");
    if (!dep || !dlldir || !mode || !pid || !getmod || !size || !seek || !repl) { put("export_missing\r\n"); bad = 1; goto done; }
    res("dep_policy_err", dep(1) ? 0 : GetLastError(), GetLastError() == 120);
    res("dlldir_err", dlldir(L"") ? 0 : GetLastError(), GetLastError() == 120);
    res("searchmode_err", mode(0x8001) ? 0 : GetLastError(), GetLastError() == 120);
    res("searchmode_bad", mode(7) ? 0 : GetLastError(), GetLastError() == 87);
    res("pid_self", pid(GetCurrentProcess()), pid(GetCurrentProcess()) == GetCurrentProcessId());
    res("pid_unreg", pid(GetCurrentThread()), pid(GetCurrentThread()) == 0 && GetLastError() == 50);
    res("module_exe", getmod(2, 0, &mod) ? 1 : 0, mod == GetModuleHandleA(0));
    res("module_addr", getmod(6, (LPCWSTR)probe_entry, &mod) ? 1 : 0, mod == GetModuleHandleA(0));
    res("module_pin", getmod(1, 0, &mod) ? 0 : GetLastError(), GetLastError() == 50);
    make("C:\\VXDLAB\\OFSAL_A.TMP", "old-content"); make("C:\\VXDLAB\\OFSAL_B.TMP", "newer");
    f = CreateFileA("C:\\VXDLAB\\OFSAL_A.TMP", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    li.QuadPart = 0;
    res("size_ok", size(f, &li) ? (DWORD)li.QuadPart : 0, li.QuadPart == 11);
    li.QuadPart = 4; np.QuadPart = -1;
    res("seek_ok", seek(f, li, &np, FILE_BEGIN) ? (DWORD)np.QuadPart : 0, np.QuadPart == 4);
    ReadFile(f, buf, 3, &n, 0);
    res("read_after_seek", n, n == 3 && buf[0] == 'c');
    li.QuadPart = -100;
    res("seek_negative", seek(f, li, &np, FILE_BEGIN) ? 0 : GetLastError(), GetLastError() == 131);
    CloseHandle(f);
    res("replace_ok", repl(A, B, 0, 1, 0, 0) ? 0 : GetLastError(), GetFileAttributesA("C:\\VXDLAB\\OFSAL_B.TMP") == 0xFFFFFFFFu);
    f = CreateFileA("C:\\VXDLAB\\OFSAL_A.TMP", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    li.QuadPart = 0; res("replaced_size", size(f, &li) ? (DWORD)li.QuadPart : 0, li.QuadPart == 5); CloseHandle(f);
    res("replace_missing", repl(A, B, 0, 0, 0, 0) ? 0 : GetLastError(), GetLastError() == 2);
    res("replace_unicode", repl(U, A, 0, 0, 0, 0) ? 0 : GetLastError(), GetLastError() == 1113 || GetACP() == 936 || GetACP() == 950);
    DeleteFileA("C:\\VXDLAB\\OFSAL_A.TMP");
done:
    res("exit", bad, !bad);
    CloseHandle(log_file);
    ExitProcess(bad ? 1 : 0);
}
