/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine Windows 98 backend and stdcall entry points of OFFSAL.DLL. Imports only
 * Windows 98 SE KERNEL32 exports (gated by build.py). W paths are converted to the
 * ANSI code page with round-trip validation; unrepresentable names are refused.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include "office_sal.h"

static volatile LONG table_lock;
static struct ofs_proc_table procs;
static void lock(void) { while (InterlockedExchange((LONG *)&table_lock, 1)) Sleep(0); }
static void unlock(void) { InterlockedExchange((LONG *)&table_lock, 0); }

static int b_to_ansi(void *c, const uint16_t *w, int n, char *out, int cap, int *lossy)
{
    BOOL used = FALSE;
    int r = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)w, n, out, cap, NULL, &used);
    (void)c; *lossy = used ? 1 : 0;
    return r;
}
static int b_to_wide(void *c, const char *a, int n, uint16_t *out, int cap)
{ (void)c; return MultiByteToWideChar(CP_ACP, 0, a, n, (LPWSTR)out, cap); }
static int b_exists(void *c, const char *p) { (void)c; return GetFileAttributesA(p) != 0xFFFFFFFFu; }

static int b_same_volume(void *c, const char *a, const char *b)
{
    char fa[MAX_PATH], fb[MAX_PATH], *p;
    int slashes = 0, i;
    (void)c;
    if (!GetFullPathNameA(a, MAX_PATH, fa, &p) || !GetFullPathNameA(b, MAX_PATH, fb, &p)) return 0;
    if (fa[0] == '\\' && fa[1] == '\\') {      /* UNC: compare \\server\share */
        if (fb[0] != '\\' || fb[1] != '\\') return 0;
        for (i = 0; fa[i] && fb[i]; ++i) {
            char x = fa[i] >= 'a' && fa[i] <= 'z' ? (char)(fa[i] - 32) : fa[i];
            char y = fb[i] >= 'a' && fb[i] <= 'z' ? (char)(fb[i] - 32) : fb[i];
            if (x != y) return 0;
            if (i >= 2 && fa[i] == '\\' && ++slashes == 2) return 1;
        }
        return 0;
    }
    return fa[1] == ':' && fb[1] == ':' && ((fa[0] ^ fb[0]) & ~0x20) == 0;
}

static uint32_t b_move(void *c, const char *s, const char *d)
{ (void)c; return MoveFileExA(s, d, MOVEFILE_REPLACE_EXISTING) ? 0u : GetLastError(); }
static uint32_t b_remove(void *c, const char *p) { (void)c; return DeleteFileA(p) ? 0u : GetLastError(); }
static uint32_t b_flush(void *c, const char *p)
{
    HANDLE h; uint32_t e = 0;
    (void)c;
    h = CreateFileA(p, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return GetLastError();
    if (!FlushFileBuffers(h)) e = GetLastError();
    CloseHandle(h);
    return e;
}

static uint32_t b_set_fp(void *c, void *h, int32_t lo, int32_t *hi, uint32_t method, uint32_t *err)
{
    DWORD r;
    (void)c;
    SetLastError(0);
    r = SetFilePointer((HANDLE)h, lo, (PLONG)hi, method);
    *err = r == INVALID_SET_FILE_POINTER ? GetLastError() : 0;
    return r;
}
static uint32_t b_get_size(void *c, void *h, uint32_t *hi, uint32_t *err)
{
    DWORD r;
    (void)c;
    SetLastError(0);
    r = GetFileSize((HANDLE)h, (LPDWORD)hi);
    *err = r == 0xFFFFFFFFu ? GetLastError() : 0;
    return r;
}

static void *b_mod_name(void *c, const char *n) { (void)c; return GetModuleHandleA(n); }
static void *b_mod_addr(void *c, const void *addr)
{
    MEMORY_BASIC_INFORMATION mbi;
    MODULEENTRY32 me;
    HANDLE snap;
    void *found = NULL;
    BOOL ok;
    (void)c;
    if (!VirtualQuery(addr, &mbi, sizeof mbi) || !mbi.AllocationBase || mbi.State != MEM_COMMIT) return NULL;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    if (snap == INVALID_HANDLE_VALUE) return NULL;
    me.dwSize = sizeof me;
    for (ok = Module32First(snap, &me); ok; ok = Module32Next(snap, &me))
        if ((void *)me.modBaseAddr == mbi.AllocationBase) { found = mbi.AllocationBase; break; }
    CloseHandle(snap);
    return found;
}
static uint32_t b_mod_addref(void *c, void *m)
{
    char path[MAX_PATH];
    (void)c;
    if (m == (void *)GetModuleHandleA(NULL)) return 0;      /* executable: no reference count */
    if (!GetModuleFileNameA((HMODULE)m, path, MAX_PATH)) return GetLastError();
    return LoadLibraryA(path) ? 0u : GetLastError();
}

const struct ofs_backend ofs_win98_backend = {
    0, b_to_ansi, b_to_wide, b_exists, b_same_volume, b_move, b_remove, b_flush,
    b_set_fp, b_get_size, b_mod_name, b_mod_addr, b_mod_addref
};

static BOOL fail(uint32_t e) { SetLastError(e); return FALSE; }

BOOL WINAPI OfsSetProcessDEPPolicy(DWORD flags)
{
    (void)flags;      /* Windows 98 has no data execution prevention */
    return fail(OFS_ERROR_CALL_NOT_IMPLEMENTED);
}

BOOL WINAPI OfsSetDllDirectoryW(LPCWSTR path)
{
    (void)path;       /* LoadLibrary search order cannot be changed on Windows 98 */
    return fail(OFS_ERROR_CALL_NOT_IMPLEMENTED);
}

BOOL WINAPI OfsSetSearchPathMode(DWORD flags) { return fail(ofs_search_path_mode_check(flags)); }

DWORD WINAPI OfsGetProcessId(HANDLE process)
{
    uint32_t pid = 0, e;
    if (process == GetCurrentProcess()) return GetCurrentProcessId();
    lock(); e = ofs_proc_lookup(&procs, process, &pid); unlock();
    if (e) { SetLastError(e); return 0; }
    return pid;
}

BOOL WINAPI OfsRegisterProcessHandle(HANDLE process, DWORD pid)
{
    uint32_t e;
    lock(); e = ofs_proc_register(&procs, process, pid); unlock();
    return e ? fail(e) : TRUE;
}

BOOL WINAPI OfsForgetProcessHandle(HANDLE process)
{
    uint32_t e;
    lock(); e = ofs_proc_forget(&procs, process); unlock();
    return e ? fail(e) : TRUE;
}

BOOL WINAPI OfsGetModuleHandleExW(DWORD flags, LPCWSTR name_or_addr, HMODULE *out)
{
    void *m = NULL;
    uint32_t e = ofs_get_module_handle_ex(&ofs_win98_backend, flags, (const uint16_t *)name_or_addr, &m);
    if (out) *out = (HMODULE)m;
    return e ? fail(e) : TRUE;
}

BOOL WINAPI OfsGetFileSizeEx(HANDLE file, LARGE_INTEGER *size)
{
    int64_t v = 0;
    uint32_t e = ofs_get_file_size_ex(&ofs_win98_backend, file, &v);
    if (e) return fail(e);
    size->QuadPart = v;
    return TRUE;
}

BOOL WINAPI OfsSetFilePointerEx(HANDLE file, LARGE_INTEGER dist, LARGE_INTEGER *newpos, DWORD method)
{
    int64_t v = 0;
    uint32_t e = ofs_set_file_pointer_ex(&ofs_win98_backend, file, dist.QuadPart, &v, method);
    if (e) return fail(e);
    if (newpos) newpos->QuadPart = v;
    return TRUE;
}

BOOL WINAPI OfsReplaceFileW(LPCWSTR replaced, LPCWSTR replacement, LPCWSTR backup, DWORD flags, LPVOID r1, LPVOID r2)
{
    uint32_t e = ofs_replace_file(&ofs_win98_backend, (const uint16_t *)replaced, (const uint16_t *)replacement,
                                  (const uint16_t *)backup, flags, r1, r2);
    return e ? fail(e) : TRUE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) DisableThreadLibraryCalls(instance);
    return TRUE;
}
