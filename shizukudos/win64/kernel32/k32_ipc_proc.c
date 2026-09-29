/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: the Windows process model over Kernel64 (kernel64/ipc_proc.c) - CreateProcess with STARTUPINFOEX
 * attribute lists and handle inheritance, OpenProcess/OpenThread, cross-process memory and threads, suspension, handle
 * flags, user APCs, jobs and process information.
 *
 * Process attributes: PARENT_PROCESS, HANDLE_LIST and JOB_LIST change what CreateProcess does. The security attributes
 * this system cannot enforce (it has no tokens, integrity levels or mitigation machinery) - MITIGATION_POLICY,
 * CHILD_PROCESS_POLICY, SECURITY_CAPABILITIES, PROTECTION_LEVEL, DESKTOP_APP_POLICY, ALL_APPLICATION_PACKAGES_POLICY -
 * are validated and stored like on Windows but not enforced; unknown attributes fail with ERROR_NOT_SUPPORTED.
 */
#include "k32_ipc.h"

/* ---------------------------------------------------------------- PROC_THREAD_ATTRIBUTE_LIST */
typedef struct { DWORD_PTR attribute; SIZE_T size; PVOID value; } k32_attr_t;
typedef struct { DWORD flags, count, capacity, magic; k32_attr_t entries[1]; } k32_attr_list_t;
#define ATTR_MAGIC 0x41545452u                                  /* "RTTA" */
#define ATTR_HEADER 16u

K32API BOOL WINAPI InitializeProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD count, DWORD flags, PSIZE_T size)
{
    const SIZE_T need = ATTR_HEADER + (SIZE_T)(count ? count : 1) * sizeof(k32_attr_t);
    k32_attr_list_t *l = (k32_attr_list_t *)list;
    if (!size || flags) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!list || *size < need) { *size = need; shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memset(l, 0, need);
    l->capacity = count;
    l->magic = ATTR_MAGIC;
    *size = need;
    return TRUE;
}

static int attr_size_ok(DWORD_PTR a, SIZE_T n)
{
    switch (a) {
    case PROC_THREAD_ATTRIBUTE_PARENT_PROCESS: return n == sizeof(HANDLE);
    case PROC_THREAD_ATTRIBUTE_HANDLE_LIST: return n && n % sizeof(HANDLE) == 0;
    case 0x0002000Du /* JOB_LIST */: return n && n % sizeof(HANDLE) == 0;
    case 0x00020007u /* MITIGATION_POLICY */: return n == 8 || n == 16 || n == 24;
    case 0x0002000Eu /* CHILD_PROCESS_POLICY */: case 0x00020012u /* DESKTOP_APP_POLICY */:
    case 0x0002000Fu /* ALL_APPLICATION_PACKAGES_POLICY */: case 0x0002000Bu /* PROTECTION_LEVEL */: return n == 4;
    case 0x00020009u /* SECURITY_CAPABILITIES */: return n == 32;
    case 0x00030003u /* GROUP_AFFINITY */: return n == 16;
    case 0x00030005u /* IDEAL_PROCESSOR */: return n == 4;
    case 0x00020004u /* PREFERRED_NODE */: return n == 2;
    default: return -1;
    }
}

K32API BOOL WINAPI UpdateProcThreadAttribute(LPPROC_THREAD_ATTRIBUTE_LIST list, DWORD flags, DWORD_PTR attribute, PVOID value,
                                             SIZE_T size, PVOID prev, PSIZE_T ret)
{
    k32_attr_list_t *l = (k32_attr_list_t *)list;
    DWORD i;
    int ok;
    (void)prev; (void)ret;
    if (!l || l->magic != ATTR_MAGIC || flags) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    ok = attr_size_ok(attribute, size);
    if (ok < 0) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
    if (!ok || !value) { shz_set_last_error(ERROR_BAD_LENGTH); return FALSE; }
    for (i = 0; i < l->count; ++i)
        if (l->entries[i].attribute == attribute) { shz_set_last_error(ERROR_OBJECT_NAME_EXISTS); return FALSE; }
    if (l->count >= l->capacity) { shz_set_last_error(ERROR_GEN_FAILURE); return FALSE; }
    l->entries[l->count].attribute = attribute;
    l->entries[l->count].size = size;
    l->entries[l->count].value = value;                         /* referenced, not copied: it must outlive CreateProcess */
    ++l->count;
    return TRUE;
}

K32API VOID WINAPI DeleteProcThreadAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST list)
{
    k32_attr_list_t *l = (k32_attr_list_t *)list;
    if (l && l->magic == ATTR_MAGIC) { l->count = 0; l->magic = 0; }
}

static const k32_attr_t *attr_find(const k32_attr_list_t *l, DWORD_PTR a)
{
    DWORD i;
    for (i = 0; l && i < l->count; ++i) if (l->entries[i].attribute == a) return &l->entries[i];
    return 0;
}

/* ---------------------------------------------------------------- CreateProcess */
static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

static int is_file(const WCHAR *path)
{
    const DWORD a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

/* Full path of `name` in `dir` (with ".exe" appended when the name has no extension) if that file exists. */
static int try_dir(const WCHAR *dir, size_t dlen, const WCHAR *name, size_t nlen, WCHAR *out, size_t cap)
{
    size_t n = 0, i, k;
    int dot = 0;
    if (dlen + nlen + 6 >= cap) return 0;
    for (i = 0; i < dlen; ++i) out[n++] = dir[i];
    if (n && out[n - 1] != '\\' && out[n - 1] != '/') out[n++] = '\\';
    for (i = 0; i < nlen; ++i) out[n++] = name[i];
    for (k = nlen; k > 0; --k) { if (name[k - 1] == '.') { dot = 1; break; } if (name[k - 1] == '\\' || name[k - 1] == '/') break; }
    out[n] = 0;
    if (!dot) { out[n++] = '.'; out[n++] = 'e'; out[n++] = 'x'; out[n++] = 'e'; out[n] = 0; }
    return is_file(out);
}

/* CreateProcess search order for a bare name: the caller's image directory, the current directory, the system and the
 * Windows directories, then PATH. A name with a path component is used as given (relative to the current directory). */
static int search_image(const WCHAR *name, size_t nlen, WCHAR *out, size_t cap)
{
    WCHAR dir[300];
    size_t i;
    int has_path = 0;
    DWORD n;
    for (i = 0; i < nlen; ++i) if (name[i] == '\\' || name[i] == '/' || name[i] == ':') has_path = 1;
    if (has_path) {
        if (nlen >= 2 && name[1] == ':') return try_dir(0, 0, name, nlen, out, cap);
        if (name[0] == '\\' || name[0] == '/') return try_dir(0, 0, name, nlen, out, cap);
        n = GetCurrentDirectoryW(300, dir);
        return n && n < 300 && try_dir(dir, n, name, nlen, out, cap);
    }
    n = GetModuleFileNameW(0, dir, 300);
    if (n && n < 300) {
        while (n && dir[n - 1] != '\\') --n;
        if (n && try_dir(dir, n, name, nlen, out, cap)) return 1;
    }
    n = GetCurrentDirectoryW(300, dir);
    if (n && n < 300 && try_dir(dir, n, name, nlen, out, cap)) return 1;
    n = GetSystemDirectoryW(dir, 300);
    if (n && n < 300 && try_dir(dir, n, name, nlen, out, cap)) return 1;
    n = GetWindowsDirectoryW(dir, 300);
    if (n && n < 300 && try_dir(dir, n, name, nlen, out, cap)) return 1;
    {
        static const WCHAR path_name[] = { 'P', 'A', 'T', 'H', 0 };
        WCHAR path[1024];
        DWORD pl = GetEnvironmentVariableW(path_name, path, 1024), s = 0, e;
        if (pl && pl < 1024) {
            for (e = 0; e <= pl; ++e)
                if (e == pl || path[e] == ';') {
                    if (e > s && try_dir(path + s, e - s, name, nlen, out, cap)) return 1;
                    s = e + 1;
                }
        }
    }
    return 0;
}

static WCHAR *heap_wdup_env(const void *env, BOOL unicode, ULONG *chars)
{
    WCHAR *w;
    size_t n = 0;
    if (unicode) {
        const WCHAR *e = env;
        while (e[n] || e[n + 1]) ++n;                          /* up to the empty string that ends the block */
        n += 2;
        if (n > 32767) return 0;
        w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR));
        if (w) memcpy(w, e, n * sizeof(WCHAR));
    } else {
        const char *e = env;
        size_t bytes = 0;
        int got;
        while (e[bytes] || e[bytes + 1]) ++bytes;
        bytes += 2;
        w = HeapAlloc(GetProcessHeap(), 0, bytes * sizeof(WCHAR));
        if (!w) return 0;
        got = k32_utf8_to_wide(e, (int)bytes, w, (int)bytes);
        if (got <= 0 || got > 32767) { HeapFree(GetProcessHeap(), 0, w); return 0; }
        n = (size_t)got;
    }
    *chars = (ULONG)n;
    return w;
}

K32API BOOL WINAPI CreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                  DWORD flags, LPVOID env, LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    WCHAR image[300], cwd[300], *cmdline = 0, *envw = 0;
    SHZ_CREATE_PROCESS c;
    const k32_attr_list_t *attrs = 0;
    const k32_attr_t *a;
    ULONG env_chars = 0;
    NTSTATUS st;
    DWORD n;
    (void)pa; (void)ta;
    if (!pi || !si || (!app && !cmd)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (flags & (DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS)) { shz_set_last_error(ERROR_NOT_SUPPORTED); return FALSE; }
    if (flags & EXTENDED_STARTUPINFO_PRESENT) {
        if (si->cb < sizeof(STARTUPINFOEXW)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
        attrs = (const k32_attr_list_t *)((STARTUPINFOEXW *)si)->lpAttributeList;
        if (attrs && attrs->magic != ATTR_MAGIC) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    }
    /* the image */
    if (app) {
        if (!search_image(app, wlen(app), image, 300)) { shz_set_last_error(ERROR_FILE_NOT_FOUND); return FALSE; }
    } else if (cmd[0] == '"') {
        size_t e = 1;
        while (cmd[e] && cmd[e] != '"') ++e;
        if (!search_image(cmd + 1, e - 1, image, 300)) { shz_set_last_error(ERROR_FILE_NOT_FOUND); return FALSE; }
    } else {                                                    /* unquoted: every space-delimited prefix, shortest first */
        size_t e = 0;
        int found = 0;
        for (;;) {
            while (cmd[e] && cmd[e] != ' ' && cmd[e] != '\t') ++e;
            if (search_image(cmd, e, image, 300)) { found = 1; break; }
            if (!cmd[e]) break;
            ++e;
        }
        if (!found) { shz_set_last_error(ERROR_FILE_NOT_FOUND); return FALSE; }
    }
    /* the command line (the application name, quoted, when there is none) */
    if (cmd) {
        cmdline = cmd;
    } else {
        const size_t l = wlen(app);
        cmdline = HeapAlloc(GetProcessHeap(), 0, (l + 3) * sizeof(WCHAR));
        if (!cmdline) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return FALSE; }
        cmdline[0] = '"';
        memcpy(cmdline + 1, app, l * sizeof(WCHAR));
        cmdline[l + 1] = '"';
        cmdline[l + 2] = 0;
    }
    /* current directory: given (must be a directory) or the caller's */
    if (dir) {
        const DWORD at = GetFileAttributesW(dir);
        if (at == INVALID_FILE_ATTRIBUTES || !(at & FILE_ATTRIBUTE_DIRECTORY) ||
            !(n = GetFullPathNameW(dir, 300, cwd, 0)) || n >= 300) {
            if (!cmd) HeapFree(GetProcessHeap(), 0, cmdline);
            shz_set_last_error(ERROR_DIRECTORY);
            return FALSE;
        }
    } else {
        n = GetCurrentDirectoryW(300, cwd);
        if (!n || n >= 300) { cwd[0] = 'C'; cwd[1] = ':'; cwd[2] = '\\'; cwd[3] = 0; n = 3; }
    }
    /* environment: given (ANSI unless CREATE_UNICODE_ENVIRONMENT) or a copy of the caller's current one */
    envw = heap_wdup_env(env ? env : GetEnvironmentStringsW(), !env || (flags & CREATE_UNICODE_ENVIRONMENT), &env_chars);
    if (!envw) {
        if (!cmd) HeapFree(GetProcessHeap(), 0, cmdline);
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    memset(&c, 0, sizeof c);
    c.Version = SHZ_CUP_VERSION;
    c.ImagePath = image; c.ImagePathChars = (ULONG)wlen(image);
    c.CommandLine = cmdline; c.CommandLineChars = (ULONG)wlen(cmdline);
    c.CurrentDirectory = cwd; c.CurrentDirectoryChars = (ULONG)wlen(cwd);
    c.Environment = envw; c.EnvironmentChars = env_chars;
    if (flags & CREATE_SUSPENDED) c.Flags |= SHZ_CUP_SUSPENDED;
    if (inherit) c.Flags |= SHZ_CUP_INHERIT_HANDLES;
    if (flags & CREATE_BREAKAWAY_FROM_JOB) c.Flags |= SHZ_CUP_BREAKAWAY;
    if (si->dwFlags & STARTF_USESTDHANDLES) {
        c.Flags |= SHZ_CUP_STD_HANDLES;
        c.StdHandle[0] = si->hStdInput; c.StdHandle[1] = si->hStdOutput; c.StdHandle[2] = si->hStdError;
    }
    if ((a = attr_find(attrs, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS))) c.ParentProcess = *(HANDLE *)a->value;
    if ((a = attr_find(attrs, PROC_THREAD_ATTRIBUTE_HANDLE_LIST))) {
        if (!inherit) {                                         /* a handle list needs bInheritHandles */
            HeapFree(GetProcessHeap(), 0, envw);
            if (!cmd) HeapFree(GetProcessHeap(), 0, cmdline);
            shz_set_last_error(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        c.Flags |= SHZ_CUP_HANDLE_LIST;
        c.HandleList = a->value;
        c.HandleCount = (ULONG)(a->size / sizeof(HANDLE));
    }
    if ((a = attr_find(attrs, 0x0002000Du))) { c.JobList = a->value; c.JobCount = (ULONG)(a->size / sizeof(HANDLE)); }
    st = NtShzCreateUserProcess(&c);
    HeapFree(GetProcessHeap(), 0, envw);
    if (!cmd) HeapFree(GetProcessHeap(), 0, cmdline);
    if (st) {
        if (st == STATUS_INVALID_IMAGE_FORMAT) shz_set_last_error(ERROR_BAD_EXE_FORMAT);
        else if (st == (NTSTATUS)0xC0000044) shz_set_last_error(ERROR_NOT_ENOUGH_QUOTA);    /* job active-process limit */
        else k32_nt_error(st);
        return FALSE;
    }
    pi->hProcess = c.ProcessHandle;
    pi->hThread = c.ThreadHandle;
    pi->dwProcessId = c.ProcessId;
    pi->dwThreadId = c.ThreadId;
    shz_set_last_error(0);
    return TRUE;
}

K32API BOOL WINAPI CreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa, LPSECURITY_ATTRIBUTES ta, BOOL inherit,
                                  DWORD flags, LPVOID env, LPCSTR dir, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
    WCHAR wapp[300], wcmd[2048], wdir[300];
    STARTUPINFOEXW siw;
    if (!si) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (app && k32_utf8_to_wide(app, -1, wapp, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (cmd && k32_utf8_to_wide(cmd, -1, wcmd, 2048) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    if (dir && k32_utf8_to_wide(dir, -1, wdir, 300) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    memset(&siw, 0, sizeof siw);
    siw.StartupInfo.cb = (flags & EXTENDED_STARTUPINFO_PRESENT) ? sizeof siw : sizeof siw.StartupInfo;
    siw.StartupInfo.dwFlags = si->dwFlags;
    siw.StartupInfo.wShowWindow = si->wShowWindow;
    siw.StartupInfo.hStdInput = si->hStdInput;
    siw.StartupInfo.hStdOutput = si->hStdOutput;
    siw.StartupInfo.hStdError = si->hStdError;
    if ((flags & EXTENDED_STARTUPINFO_PRESENT) && si->cb >= sizeof(STARTUPINFOEXA))
        siw.lpAttributeList = ((STARTUPINFOEXA *)si)->lpAttributeList;
    return CreateProcessW(app ? wapp : 0, cmd ? wcmd : 0, pa, ta, inherit, flags, env, dir ? wdir : 0, &siw.StartupInfo, pi);
}

/* ---------------------------------------------------------------- opening, ids, information */
K32API HANDLE WINAPI OpenProcess(DWORD access, BOOL inherit, DWORD pid)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_CLIENT_ID cid = { (HANDLE)(ULONG_PTR)pid, 0 };
    HANDLE h = 0;
    NTSTATUS st;
    if (!pid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    k32_ipc_oa(0, inherit, FALSE, &oa, 0);
    st = NtOpenProcess(&h, access, &oa, &cid);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenThread(DWORD access, BOOL inherit, DWORD tid)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_CLIENT_ID cid = { 0, (HANDLE)(ULONG_PTR)tid };
    HANDLE h = 0;
    NTSTATUS st;
    if (!tid) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    k32_ipc_oa(0, inherit, FALSE, &oa, 0);
    st = NtOpenThread(&h, access, &oa, &cid);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

typedef struct { LONG64 exit_status; ULONG64 peb, affinity; LONG64 prio; ULONG64 pid, ppid; } k32_pbi_t;
typedef struct { LONG64 exit_status; ULONG64 teb, pid, tid, affinity; LONG prio, base; } k32_tbi_t;

K32API DWORD WINAPI GetProcessId(HANDLE h)
{
    k32_pbi_t b;
    NTSTATUS st = NtQueryInformationProcess(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)b.pid;
}

K32API DWORD WINAPI GetThreadId(HANDLE h)
{
    k32_tbi_t b;
    NTSTATUS st = NtQueryInformationThread(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)b.tid;
}

K32API DWORD WINAPI GetProcessIdOfThread(HANDLE h)
{
    k32_tbi_t b;
    NTSTATUS st = NtQueryInformationThread(h, 0, &b, sizeof b, 0);
    if (st) { k32_nt_error(st); return 0; }
    return (DWORD)b.pid;
}

K32API BOOL WINAPI QueryFullProcessImageNameW(HANDLE h, DWORD flags, LPWSTR buf, PDWORD size)
{
    union { SHZ_UNICODE_STRING us; BYTE raw[16 + 520]; } u;
    ULONG ret = 0;
    DWORD n;
    NTSTATUS st;
    if (!buf || !size || (flags & ~1u)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtQueryInformationProcess(h, (flags & 1) ? 27 : 43, &u, sizeof u, &ret);    /* PROCESS_NAME_NATIVE */
    if (st) { k32_nt_error(st); return FALSE; }
    n = u.us.Length / 2;
    if (n >= *size) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(buf, u.us.Buffer, n * sizeof(WCHAR));
    buf[n] = 0;
    *size = n;
    return TRUE;
}

K32API BOOL WINAPI QueryFullProcessImageNameA(HANDLE h, DWORD flags, LPSTR buf, PDWORD size)
{
    WCHAR w[300];
    DWORD n = 300;
    int r;
    if (!buf || !size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!QueryFullProcessImageNameW(h, flags, w, &n)) return FALSE;
    r = k32_wide_to_utf8(w, (int)n + 1, buf, (int)*size);
    if (r <= 0) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    *size = (DWORD)r - 1;
    return TRUE;
}

K32API BOOL WINAPI GetProcessTimes(HANDLE h, LPFILETIME create, LPFILETIME exit_t, LPFILETIME kernel, LPFILETIME user)
{
    LONG64 t[4];
    NTSTATUS st = NtQueryInformationProcess(h, 4, t, sizeof t, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    if (create) { create->dwLowDateTime = (DWORD)t[0]; create->dwHighDateTime = (DWORD)(t[0] >> 32); }
    if (exit_t) { exit_t->dwLowDateTime = (DWORD)t[1]; exit_t->dwHighDateTime = (DWORD)(t[1] >> 32); }
    if (kernel) { kernel->dwLowDateTime = (DWORD)t[2]; kernel->dwHighDateTime = (DWORD)(t[2] >> 32); }
    if (user) { user->dwLowDateTime = (DWORD)t[3]; user->dwHighDateTime = (DWORD)(t[3] >> 32); }
    return TRUE;
}

K32API BOOL WINAPI GetProcessHandleCount(HANDLE h, PDWORD count)
{
    ULONG n = 0;
    NTSTATUS st = NtQueryInformationProcess(h, 20, &n, sizeof n, 0);
    if (st) { k32_nt_error(st); return FALSE; }
    *count = n;
    return TRUE;
}

K32API BOOL WINAPI ProcessIdToSessionId(DWORD pid, DWORD *session)
{
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return FALSE;
    CloseHandle(h);
    *session = 0;                                               /* one session */
    return TRUE;
}

/* ---------------------------------------------------------------- cross-process memory */
K32API BOOL WINAPI ReadProcessMemory(HANDLE h, LPCVOID addr, LPVOID buf, SIZE_T n, SIZE_T *done)
{
    SIZE_T got = 0;
    NTSTATUS st = NtReadVirtualMemory(h, (PVOID)addr, buf, n, &got);
    if (done) *done = got;
    return st ? k32_ipc_fail(st) : TRUE;
}

/* Like Windows: a write into read-only or executable pages makes them writable for the copy, then restores them. */
K32API BOOL WINAPI WriteProcessMemory(HANDLE h, LPVOID addr, LPCVOID buf, SIZE_T n, SIZE_T *done)
{
    MEMORY_BASIC_INFORMATION m;
    SIZE_T got = 0, ret = 0;
    NTSTATUS st;
    ULONG old = 0;
    int reprotect = 0;
    if (n && NtQueryVirtualMemory(h, addr, 0, &m, sizeof m, &ret) == 0 && m.State == MEM_COMMIT &&
        (m.Protect & 0xff) != PAGE_READWRITE && (m.Protect & 0xff) != PAGE_EXECUTE_READWRITE &&
        (m.Protect & 0xff) != PAGE_WRITECOPY && (m.Protect & 0xff) != PAGE_EXECUTE_WRITECOPY &&
        (m.Protect & 0xff) != PAGE_NOACCESS) {
        PVOID b = addr;
        SIZE_T sz = n;
        const ULONG want = (m.Protect & 0xf0) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        if (NtProtectVirtualMemory(h, &b, &sz, want, &old) == 0) reprotect = 1;
    }
    st = NtWriteVirtualMemory(h, addr, buf, n, &got);
    if (reprotect) {
        PVOID b = addr;
        SIZE_T sz = n;
        ULONG tmp;
        NtProtectVirtualMemory(h, &b, &sz, old, &tmp);
    }
    if (done) *done = got;
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI VirtualProtectEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD prot, PDWORD old)
{
    PVOID b = addr;
    SIZE_T sz = size;
    ULONG o = 0;
    NTSTATUS st = NtProtectVirtualMemory(h, &b, &sz, prot, &o);
    if (st) return k32_ipc_fail(st);
    if (old) *old = o;
    return TRUE;
}

K32API SIZE_T WINAPI VirtualQueryEx(HANDLE h, LPCVOID addr, PMEMORY_BASIC_INFORMATION mbi, SIZE_T len)
{
    SIZE_T ret = 0;
    NTSTATUS st;
    if (len < sizeof *mbi) { shz_set_last_error(ERROR_BAD_LENGTH); return 0; }
    st = NtQueryVirtualMemory(h, (PVOID)addr, 0, mbi, sizeof *mbi, &ret);
    if (st) { k32_nt_error(st); return 0; }
    return sizeof *mbi;
}

K32API BOOL WINAPI VirtualFreeEx(HANDLE h, LPVOID addr, SIZE_T size, DWORD type)
{
    PVOID b = addr;
    SIZE_T sz = size;
    NTSTATUS st;
    if (type == MEM_RELEASE && size) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    st = NtFreeVirtualMemory(h, &b, &sz, type);
    return st ? k32_ipc_fail(st) : TRUE;
}

/* ---------------------------------------------------------------- threads */
K32API HANDLE WINAPI CreateRemoteThreadEx(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start,
                                          LPVOID param, DWORD flags, LPPROC_THREAD_ATTRIBUTE_LIST attrs, LPDWORD tid)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    HANDLE h = 0;
    NTSTATUS st;
    const SIZE_T commit = (flags & STACK_SIZE_PARAM_IS_A_RESERVATION) ? 0 : stack;
    const SIZE_T reserve = (flags & STACK_SIZE_PARAM_IS_A_RESERVATION) ? stack : 0;
    (void)attrs;
    if (flags & ~(DWORD)(CREATE_SUSPENDED | STACK_SIZE_PARAM_IS_A_RESERVATION)) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    k32_ipc_oa(0, sa && sa->bInheritHandle, FALSE, &oa, 0);
    st = NtCreateThreadEx(&h, THREAD_ALL_ACCESS, &oa, proc, (PVOID)start, param,
                          (flags & CREATE_SUSPENDED) ? SHZ_THREAD_CREATE_FLAGS_CREATE_SUSPENDED : 0, 0, commit, reserve, 0);
    if (st) { k32_nt_error(st); return 0; }
    if (tid) *tid = GetThreadId(h);
    return h;
}

K32API HANDLE WINAPI CreateRemoteThread(HANDLE proc, LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start,
                                        LPVOID param, DWORD flags, LPDWORD tid)
{
    return CreateRemoteThreadEx(proc, sa, stack, start, param, flags, 0, tid);
}

K32API HANDLE WINAPI CreateThread(LPSECURITY_ATTRIBUTES sa, SIZE_T stack, LPTHREAD_START_ROUTINE start, LPVOID param,
                                  DWORD flags, LPDWORD tid)
{
    return CreateRemoteThreadEx(CURRENT_PROCESS, sa, stack, start, param, flags, 0, tid);
}

K32API DWORD WINAPI SuspendThread(HANDLE h)
{
    ULONG prev = 0;
    NTSTATUS st = NtSuspendThread(h, &prev);
    if (st) { k32_nt_error(st); return (DWORD)-1; }
    return prev;
}

K32API DWORD WINAPI ResumeThread(HANDLE h)
{
    ULONG prev = 0;
    NTSTATUS st = NtResumeThread(h, &prev);
    if (st) { k32_nt_error(st); return (DWORD)-1; }
    return prev;
}

K32API BOOL WINAPI TerminateThread(HANDLE h, DWORD code)
{
    NTSTATUS st;
    if (!h) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    st = NtTerminateThread(h, (NTSTATUS)code);
    return st ? k32_ipc_fail(st) : TRUE;
}

/* ---------------------------------------------------------------- handle flags */
K32API BOOL WINAPI GetHandleInformation(HANDLE h, LPDWORD flags)
{
    BOOLEAN v[2];
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, 4 /* ObjectHandleFlagInformation */, v, sizeof v, &ret);
    if (st) return k32_ipc_fail(st);
    *flags = (v[0] ? HANDLE_FLAG_INHERIT : 0) | (v[1] ? HANDLE_FLAG_PROTECT_FROM_CLOSE : 0);
    return TRUE;
}

K32API BOOL WINAPI SetHandleInformation(HANDLE h, DWORD mask, DWORD flags)
{
    BOOLEAN v[2];
    ULONG ret = 0;
    NTSTATUS st = NtQueryObject(h, 4, v, sizeof v, &ret);
    if (st) return k32_ipc_fail(st);
    if (mask & HANDLE_FLAG_INHERIT) v[0] = (flags & HANDLE_FLAG_INHERIT) != 0;
    if (mask & HANDLE_FLAG_PROTECT_FROM_CLOSE) v[1] = (flags & HANDLE_FLAG_PROTECT_FROM_CLOSE) != 0;
    st = NtSetInformationObject(h, 4, v, sizeof v);
    return st ? k32_ipc_fail(st) : TRUE;
}

/* ---------------------------------------------------------------- user APCs and alertable sleeps */
static VOID NTAPI user_apc_trampoline(PVOID fn, PVOID data, PVOID unused)
{
    (void)unused;
    ((PAPCFUNC)fn)((ULONG_PTR)data);
}

K32API DWORD WINAPI QueueUserAPC(PAPCFUNC fn, HANDLE thread, ULONG_PTR data)
{
    NTSTATUS st = NtQueueApcThread(thread, (PVOID)user_apc_trampoline, (PVOID)fn, (PVOID)data, 0);
    if (st) { k32_nt_error(st); return 0; }
    return 1;
}

K32API DWORD WINAPI SleepEx(DWORD ms, BOOL alertable)
{
    LARGE_INTEGER li;
    NTSTATUS st;
    if (ms == INFINITE) li.QuadPart = INT64_MIN + 1;
    else li.QuadPart = -(LONGLONG)ms * 10000;
    if (!alertable && ms == 0) { NtYieldExecution(); return 0; }
    st = NtDelayExecution(alertable != 0, &li);
    return st == STATUS_USER_APC ? WAIT_IO_COMPLETION : 0;
}

/* ---------------------------------------------------------------- jobs */
K32API HANDLE WINAPI CreateJobObjectW(LPSECURITY_ATTRIBUTES sa, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e = k32_ipc_oa(name, sa && sa->bInheritHandle, TRUE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    st = NtCreateJobObject(&h, JOB_OBJECT_ALL_ACCESS, &oa);
    if (st == STATUS_OBJECT_NAME_EXISTS) { shz_set_last_error(ERROR_ALREADY_EXISTS); return h; }
    if (st) { k32_nt_error(st); return 0; }
    shz_set_last_error(0);
    return h;
}

K32API HANDLE WINAPI CreateJobObjectA(LPSECURITY_ATTRIBUTES sa, LPCSTR name)
{
    WCHAR w[128];
    if (name && k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return CreateJobObjectW(sa, name ? w : 0);
}

K32API HANDLE WINAPI OpenJobObjectW(DWORD access, BOOL inherit, LPCWSTR name)
{
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    HANDLE h = 0;
    NTSTATUS st;
    DWORD e;
    if (!name) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    e = k32_ipc_oa(name, inherit, FALSE, &oa, &us);
    if (e) { shz_set_last_error(e); return 0; }
    st = NtOpenJobObject(&h, access, &oa);
    if (st) { k32_nt_error(st); return 0; }
    return h;
}

K32API HANDLE WINAPI OpenJobObjectA(DWORD access, BOOL inherit, LPCSTR name)
{
    WCHAR w[128];
    if (!name || k32_utf8_to_wide(name, -1, w, 128) <= 0) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return OpenJobObjectW(access, inherit, w);
}

K32API BOOL WINAPI AssignProcessToJobObject(HANDLE job, HANDLE proc)
{
    NTSTATUS st = NtAssignProcessToJobObject(job, proc);
    if (st == (NTSTATUS)0xC0000044) { shz_set_last_error(ERROR_NOT_ENOUGH_QUOTA); return FALSE; }
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI SetInformationJobObject(HANDLE job, JOBOBJECTINFOCLASS cls, LPVOID info, DWORD len)
{
    NTSTATUS st = NtSetInformationJobObject(job, (ULONG)cls, info, len);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI QueryInformationJobObject(HANDLE job, JOBOBJECTINFOCLASS cls, LPVOID info, DWORD len, LPDWORD ret)
{
    ULONG n = 0;
    NTSTATUS st = NtQueryInformationJobObject(job, (ULONG)cls, info, len, &n);
    if (ret) *ret = n;
    if (st == STATUS_BUFFER_OVERFLOW) { shz_set_last_error(ERROR_MORE_DATA); return FALSE; }
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI TerminateJobObject(HANDLE job, UINT code)
{
    NTSTATUS st = NtTerminateJobObject(job, (NTSTATUS)code);
    return st ? k32_ipc_fail(st) : TRUE;
}

K32API BOOL WINAPI IsProcessInJob(HANDLE proc, HANDLE job, PBOOL result)
{
    NTSTATUS st = NtIsProcessInJob(proc, job);
    if (st == (NTSTATUS)0x00000124) { *result = TRUE; return TRUE; }            /* STATUS_PROCESS_IN_JOB */
    if (st == (NTSTATUS)0x00000123) { *result = FALSE; return TRUE; }           /* STATUS_PROCESS_NOT_IN_JOB */
    return k32_ipc_fail(st);
}
