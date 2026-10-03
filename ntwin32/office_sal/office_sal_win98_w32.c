/* SPDX-License-Identifier: GPL-2.0-only
 * Windows 98 backend and stdcall entry points of the OFFSAL Unicode path layer, resolver, named-pipe,
 * shell-folder, user-name and stack-capture contracts. Static imports: Windows 98 SE KERNEL32 only
 * (gated by build.py); WS2_32, MPR, SHELL32 and ADVAPI32 are resolved at run time and their absence
 * is reported as a Win32 error.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "office_sal_unicode.h"
#include "office_sal_net.h"
#include "office_sal_diag.h"

extern const struct ofs_backend ofs_win98_backend;
typedef char find_a_size_check[sizeof(struct ofu_find_a) == sizeof(WIN32_FIND_DATAA) ? 1 : -1];
typedef char find_w_size_check[sizeof(struct ofu_find_w) == sizeof(WIN32_FIND_DATAW) ? 1 : -1];

static BOOL fail(uint32_t e) { SetLastError(e); return FALSE; }

#define OK_OR(e) ((e) ? fail(e) : TRUE)

static uint32_t lasterr(void) { DWORD e = GetLastError(); return e ? e : 31u; }  /* ERROR_GEN_FAILURE if API forgot */

static uint32_t f_create(void *c, const char *p, uint32_t a, uint32_t s, const void *sa, uint32_t d, uint32_t f, void *t, void **h)
{
    (void)c; SetLastError(0);
    *h = CreateFileA(p, a, s, (LPSECURITY_ATTRIBUTES)sa, d, f, (HANDLE)t);
    return *h == INVALID_HANDLE_VALUE ? lasterr() : 0;
}
static uint32_t f_getattr(void *c, const char *p, uint32_t *a)
{ (void)c; SetLastError(0); *a = GetFileAttributesA(p); return *a == 0xFFFFFFFFu ? lasterr() : 0; }
static uint32_t f_getattrex(void *c, const char *p, uint32_t l, void *i)
{ (void)c; return GetFileAttributesExA(p, (GET_FILEEX_INFO_LEVELS)l, i) ? 0u : lasterr(); }
static uint32_t f_setattr(void *c, const char *p, uint32_t a) { (void)c; return SetFileAttributesA(p, a) ? 0u : lasterr(); }
static uint32_t f_mkdir(void *c, const char *p, const void *sa) { (void)c; return CreateDirectoryA(p, (LPSECURITY_ATTRIBUTES)sa) ? 0u : lasterr(); }
static uint32_t f_rmdir(void *c, const char *p) { (void)c; return RemoveDirectoryA(p) ? 0u : lasterr(); }
static uint32_t f_del(void *c, const char *p) { (void)c; return DeleteFileA(p) ? 0u : lasterr(); }
static uint32_t f_move(void *c, const char *s, const char *d, uint32_t f) { (void)c; return MoveFileExA(s, d, f) ? 0u : lasterr(); }
static uint32_t f_copy(void *c, const char *s, const char *d, int fie) { (void)c; return CopyFileA(s, d, fie) ? 0u : lasterr(); }
static uint32_t f_ffirst(void *c, const char *p, struct ofu_find_a *d, void **h)
{
    (void)c;
    *h = FindFirstFileA(p, (WIN32_FIND_DATAA *)d);
    return *h == INVALID_HANDLE_VALUE ? lasterr() : 0;
}
static uint32_t f_fnext(void *c, void *h, struct ofu_find_a *d) { (void)c; return FindNextFileA((HANDLE)h, (WIN32_FIND_DATAA *)d) ? 0u : lasterr(); }
static uint32_t f_fclose(void *c, void *h) { (void)c; return FindClose((HANDLE)h) ? 0u : lasterr(); }
static uint32_t f_setcwd(void *c, const char *p) { (void)c; return SetCurrentDirectoryA(p) ? 0u : lasterr(); }
static uint32_t f_drive(void *c, const char *r, uint32_t *t) { (void)c; *t = GetDriveTypeA(r); return 0; }
static uint32_t f_str(void *c, int which, const char *arg, void *mod, char *out, uint32_t cap, uint32_t *len)
{
    char *part;
    (void)c; SetLastError(0);
    switch (which) {
    case OFU_FULLPATH: *len = GetFullPathNameA(arg, cap, out, &part); break;
    case OFU_CWD: *len = GetCurrentDirectoryA(cap, out); break;
    case OFU_TEMP: *len = GetTempPathA(cap, out); break;
    case OFU_MODULE: *len = GetModuleFileNameA((HMODULE)mod, out, cap); if (*len >= cap) *len = cap; break;
    case OFU_LONGPATH: *len = GetLongPathNameA(arg, out, cap); break;
    default: return OFS_ERROR_INVALID_PARAMETER;
    }
    return *len ? 0u : lasterr();
}

static const struct ofu_fs fs = {
    0, f_create, f_getattr, f_getattrex, f_setattr, f_mkdir, f_rmdir, f_del, f_move, f_copy,
    f_ffirst, f_fnext, f_fclose, f_setcwd, f_drive, f_str
};
#define CV (&ofs_win98_backend)

HANDLE WINAPI OfsCreateFileW(LPCWSTR p, DWORD a, DWORD s, LPSECURITY_ATTRIBUTES sa, DWORD d, DWORD f, HANDLE t)
{
    void *h = INVALID_HANDLE_VALUE;
    uint32_t e = ofu_create_file(CV, &fs, (const uint16_t *)p, a, s, sa, d, f, t, &h);
    if (e) { SetLastError(e); return INVALID_HANDLE_VALUE; }
    return (HANDLE)h;
}
DWORD WINAPI OfsGetFileAttributesW(LPCWSTR p)
{
    uint32_t a = 0xFFFFFFFFu, e = ofu_get_attr(CV, &fs, (const uint16_t *)p, &a);
    if (e) { SetLastError(e); return 0xFFFFFFFFu; }
    return a;
}
BOOL WINAPI OfsGetFileAttributesExW(LPCWSTR p, DWORD level, LPVOID info) { return OK_OR(ofu_get_attr_ex(CV, &fs, (const uint16_t *)p, level, info)); }
BOOL WINAPI OfsSetFileAttributesW(LPCWSTR p, DWORD a) { return OK_OR(ofu_set_attr(CV, &fs, (const uint16_t *)p, a)); }
BOOL WINAPI OfsCreateDirectoryW(LPCWSTR p, LPSECURITY_ATTRIBUTES sa) { return OK_OR(ofu_mkdir(CV, &fs, (const uint16_t *)p, sa)); }
BOOL WINAPI OfsRemoveDirectoryW(LPCWSTR p) { return OK_OR(ofu_rmdir(CV, &fs, (const uint16_t *)p)); }
BOOL WINAPI OfsDeleteFileW(LPCWSTR p) { return OK_OR(ofu_delete(CV, &fs, (const uint16_t *)p)); }
BOOL WINAPI OfsMoveFileW(LPCWSTR s, LPCWSTR d) { return OK_OR(ofu_move(CV, &fs, (const uint16_t *)s, (const uint16_t *)d, 0)); }
BOOL WINAPI OfsMoveFileExW(LPCWSTR s, LPCWSTR d, DWORD f) { return OK_OR(ofu_move(CV, &fs, (const uint16_t *)s, (const uint16_t *)d, f)); }
BOOL WINAPI OfsCopyFileW(LPCWSTR s, LPCWSTR d, BOOL fie) { return OK_OR(ofu_copy(CV, &fs, (const uint16_t *)s, (const uint16_t *)d, fie)); }
HANDLE WINAPI OfsFindFirstFileW(LPCWSTR p, LPWIN32_FIND_DATAW d)
{
    void *h = INVALID_HANDLE_VALUE;
    uint32_t e = ofu_find_first(CV, &fs, (const uint16_t *)p, (struct ofu_find_w *)d, &h);
    if (e) { SetLastError(e); return INVALID_HANDLE_VALUE; }
    return (HANDLE)h;
}
BOOL WINAPI OfsFindNextFileW(HANDLE h, LPWIN32_FIND_DATAW d) { return OK_OR(ofu_find_next(CV, &fs, h, (struct ofu_find_w *)d)); }
BOOL WINAPI OfsSetCurrentDirectoryW(LPCWSTR p) { return OK_OR(ofu_set_cwd(CV, &fs, (const uint16_t *)p)); }

static DWORD getstr(int which, LPCWSTR arg, HMODULE m, LPWSTR out, DWORD cap)
{
    uint32_t ret = 0, e = ofu_get_string(CV, &fs, which, (const uint16_t *)arg, m, (uint16_t *)out, cap, &ret);
    if (e) { SetLastError(e); return 0; }
    return ret;
}
DWORD WINAPI OfsGetFullPathNameW(LPCWSTR p, DWORD cap, LPWSTR out, LPWSTR *part)
{
    DWORD n = getstr(OFU_FULLPATH, p, 0, out, cap), i, last = 0;
    if (part) {
        *part = 0;
        if (n && n < cap) {
            for (i = 0; i < n; ++i) if (out[i] == L'\\' || out[i] == L'/' || out[i] == L':') last = i + 1;
            if (last < n && out[n - 1] != L'\\') *part = out + last;
        }
    }
    return n;
}
DWORD WINAPI OfsGetLongPathNameW(LPCWSTR p, LPWSTR out, DWORD cap) { return getstr(OFU_LONGPATH, p, 0, out, cap); }
DWORD WINAPI OfsGetCurrentDirectoryW(DWORD cap, LPWSTR out) { return getstr(OFU_CWD, 0, 0, out, cap); }
DWORD WINAPI OfsGetTempPathW(DWORD cap, LPWSTR out) { return getstr(OFU_TEMP, 0, 0, out, cap); }
DWORD WINAPI OfsGetModuleFileNameW(HMODULE m, LPWSTR out, DWORD cap) { return getstr(OFU_MODULE, 0, m, out, cap); }
UINT WINAPI OfsGetDriveTypeW(LPCWSTR root)
{
    uint32_t t = 0, e = ofu_drive_type(CV, &fs, (const uint16_t *)root, &t);
    if (e) { SetLastError(e); return 1; }     /* DRIVE_NO_ROOT_DIR */
    return t;
}
BOOL WINAPI OfsGetVolumeNameForVolumeMountPointW(LPCWSTR mp, LPWSTR out, DWORD cap)
{ (void)mp; (void)out; (void)cap; return fail(OFS_ERROR_CALL_NOT_IMPLEMENTED); }   /* no volume GUID paths on Win98 */

/* ---- named pipes: Windows 98 cannot create or connect local named pipes (server side absent) ---- */
HANDLE WINAPI OfsCreateNamedPipeW(LPCWSTR n, DWORD om, DWORD pm, DWORD max, DWORD o, DWORD i, DWORD t, LPSECURITY_ATTRIBUTES sa)
{ (void)n; (void)om; (void)pm; (void)max; (void)o; (void)i; (void)t; (void)sa; fail(OFS_ERROR_CALL_NOT_IMPLEMENTED); return INVALID_HANDLE_VALUE; }
BOOL WINAPI OfsWaitNamedPipeW(LPCWSTR n, DWORD t) { (void)n; (void)t; return fail(OFS_ERROR_CALL_NOT_IMPLEMENTED); }

/* ---- run-time resolved legacy providers ---- */
static HMODULE load_once(volatile HMODULE *slot, const char *name)
{
    HMODULE m = *slot;
    if (!m) { m = LoadLibraryA(name); if (m) *slot = m; }
    return m;
}
static void *sym(const char *dll, volatile HMODULE *slot, const char *fn)
{ HMODULE m = load_once(slot, dll); return m ? (void *)GetProcAddress(m, fn) : 0; }

struct hostent_ { char *name; char **aliases; short type; short len; char **list; };
struct servent_ { char *name; char **aliases; short port; char *proto; };
typedef struct hostent_ *(WINAPI *pgethostbyname)(const char *);
typedef struct hostent_ *(WINAPI *pgethostbyaddr)(const char *, int, int);
typedef struct servent_ *(WINAPI *pgetservbyname)(const char *, const char *);
typedef struct servent_ *(WINAPI *pgetservbyport)(int, const char *);
typedef int (WINAPI *pwsastartup)(WORD, void *);
typedef int (WINAPI *pwsagle)(void);
static volatile HMODULE ws2, mpr, shell, adv;
static volatile LONG wsa_up;

static int wsa_ready(void)
{
    pwsastartup st;
    char data[512];
    if (wsa_up) return 1;
    st = (pwsastartup)sym("WS2_32.DLL", &ws2, "WSAStartup");
    if (!st || st(0x0202, data)) return 0;
    InterlockedExchange((LONG *)&wsa_up, 1);        /* process lifetime: no WSACleanup */
    return 1;
}
static int wsa_err(void)
{
    pwsagle g = (pwsagle)sym("WS2_32.DLL", &ws2, "WSAGetLastError");
    int e = g ? g() : 0;
    return e ? e : (int)OFN_WSAHOST_NOT_FOUND;
}
static int n_resolve(void *c, const char *name, uint8_t a[][4], int max, char canon[256])
{
    pgethostbyname f; struct hostent_ *h; int n = 0;
    (void)c;
    if (!wsa_ready()) return -(int)OFN_WSAHOST_NOT_FOUND;
    f = (pgethostbyname)sym("WS2_32.DLL", &ws2, "gethostbyname");
    if (!f) return -(int)OFS_ERROR_CALL_NOT_IMPLEMENTED;
    h = f(name);
    if (!h) return -wsa_err();
    if (h->type != 2 || h->len != 4) return 0;
    for (; h->list[n] && n < max; ++n) { int k; for (k = 0; k < 4; ++k) a[n][k] = (uint8_t)h->list[n][k]; }
    canon[0] = 0;
    if (h->name) { int i; for (i = 0; h->name[i] && i < 255; ++i) canon[i] = h->name[i]; canon[i] = 0; }
    return n;
}
static int n_byaddr(void *c, const uint8_t a[4], char name[256])
{
    pgethostbyaddr f; struct hostent_ *h; int i;
    (void)c;
    if (!wsa_ready()) return (int)OFN_WSAHOST_NOT_FOUND;
    f = (pgethostbyaddr)sym("WS2_32.DLL", &ws2, "gethostbyaddr");
    if (!f) return (int)OFS_ERROR_CALL_NOT_IMPLEMENTED;
    h = f((const char *)a, 4, 2);
    if (!h || !h->name) return wsa_err();
    for (i = 0; h->name[i] && i < 255; ++i) name[i] = h->name[i];
    name[i] = 0;
    return 0;
}
static int n_svc(void *c, const char *name, const char *proto, uint16_t *port)
{
    pgetservbyname f; struct servent_ *s;
    (void)c;
    if (!wsa_ready()) return -1;
    f = (pgetservbyname)sym("WS2_32.DLL", &ws2, "getservbyname");
    s = f ? f(name, proto) : 0;
    if (!s) return -1;
    *port = (uint16_t)(((uint16_t)s->port >> 8) | ((uint16_t)s->port << 8));
    return 0;
}
static int n_port(void *c, uint16_t port, const char *proto, char name[64])
{
    pgetservbyport f; struct servent_ *s; int i;
    (void)c;
    if (!wsa_ready()) return -1;
    f = (pgetservbyport)sym("WS2_32.DLL", &ws2, "getservbyport");
    s = f ? f((int)(uint16_t)((port >> 8) | (port << 8)), proto) : 0;
    if (!s || !s->name) return -1;
    for (i = 0; s->name[i] && i < 63; ++i) name[i] = s->name[i];
    name[i] = 0;
    return 0;
}
static void *n_alloc(void *c, size_t n) { (void)c; return HeapAlloc(GetProcessHeap(), 0, n); }
static void n_free(void *c, void *p) { (void)c; HeapFree(GetProcessHeap(), 0, p); }
static const struct ofn_backend net = { 0, n_resolve, n_byaddr, n_svc, n_port, n_alloc, n_free };

static void wsa_set(uint32_t e)
{
    typedef void (WINAPI *pset)(int);
    pset f = (pset)sym("WS2_32.DLL", &ws2, "WSASetLastError");
    if (f) f((int)e);
    SetLastError(e);
}

INT WINAPI OfsInetPtonW(INT family, LPCWSTR text, PVOID dst)
{
    uint32_t err = 0;
    int r = ofn_inet_pton(family, (const uint16_t *)text, dst, &err);
    if (r < 0) wsa_set(err);
    return r;
}
LPCWSTR WINAPI OfsInetNtopW(INT family, const VOID *addr, LPWSTR buf, DWORD size)
{
    uint32_t e;
    if (family != 2) { wsa_set(OFN_WSAEAFNOSUPPORT); return 0; }
    e = ofn_inet_ntop4((const uint8_t *)addr, (uint16_t *)buf, size);
    if (e) { wsa_set(e); return 0; }
    return buf;
}
INT WINAPI OfsGetAddrInfoW(LPCWSTR node, LPCWSTR service, const void *hints, void **res)
{
    uint32_t e = ofn_getaddrinfo(&net, (const uint16_t *)node, (const uint16_t *)service, (const struct ofn_addrinfow *)hints,
                                 (struct ofn_addrinfow **)res);
    if (e) wsa_set(e);
    return (INT)e;
}
VOID WINAPI OfsFreeAddrInfoW(void *ai) { ofn_freeaddrinfo(&net, (struct ofn_addrinfow *)ai); }
INT WINAPI OfsGetNameInfoW(const void *sa, INT salen, LPWSTR host, DWORD hostlen, LPWSTR serv, DWORD servlen, INT flags)
{
    uint32_t e = ofn_getnameinfo(&net, sa, salen < 0 ? 0 : (size_t)salen, (uint16_t *)host, hostlen, (uint16_t *)serv, servlen, flags);
    if (e) wsa_set(e);
    return (INT)e;
}

/* ---- shell folder / user name (Windows 98: ANSI providers only) ---- */
BOOL WINAPI OfsGetSpecialFolderPathW(INT csidl, LPWSTR out, DWORD cap)
{
    typedef BOOL (WINAPI *pf)(HWND, char *, int, BOOL);
    char a[OFS_PATH_MAX]; uint16_t w[OFS_PATH_MAX]; uint32_t e, n = 0, len = 0, i;
    pf f = (pf)sym("SHELL32.DLL", &shell, "SHGetSpecialFolderPathA");
    if (!f) return fail(OFS_ERROR_CALL_NOT_IMPLEMENTED);
    SetLastError(0);
    if (!f(0, a, csidl, TRUE)) return fail(lasterr());
    while (a[len] && len < OFS_PATH_MAX) ++len;
    /* reuse the validated converter through the path layer: current-directory-free round trip */
    { uint16_t probe[OFS_PATH_MAX]; int k = MultiByteToWideChar(CP_ACP, 0, a, (int)len, (LPWSTR)probe, OFS_PATH_MAX - 1);
      char back[OFS_PATH_MAX]; BOOL used = FALSE; int bn;
      if (k <= 0 || (bn = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)probe, k, back, sizeof back, NULL, &used)) != (int)len || used)
          return fail(OFS_ERROR_NO_UNICODE_TRANSLATION);
      for (i = 0; i < len; ++i) if (back[i] != a[i]) return fail(OFS_ERROR_NO_UNICODE_TRANSLATION);
      for (i = 0; i < (uint32_t)k; ++i) w[i] = probe[i];
      w[k] = 0; n = (uint32_t)k; }
    if (cap < n + 1) return fail(OFS_ERROR_INSUFFICIENT_BUFFER);
    for (i = 0; i <= n; ++i) out[i] = w[i];
    e = 0; (void)e;
    return TRUE;
}
BOOL WINAPI OfsGetUserNameW(LPWSTR out, LPDWORD size)
{
    typedef DWORD (WINAPI *pw)(const char *, char *, DWORD *);
    typedef BOOL (WINAPI *pu)(char *, DWORD *);
    char a[256]; DWORD asz = sizeof a, n, i; DWORD r = 1;
    pw w = (pw)sym("MPR.DLL", &mpr, "WNetGetUserA");
    pu u = (pu)sym("ADVAPI32.DLL", &adv, "GetUserNameA");
    if (!out || !size) return fail(OFS_ERROR_INVALID_PARAMETER);
    if (w) r = w(0, a, &asz);
    if (r != 0) {                                  /* NO_ERROR == 0 */
        asz = sizeof a;
        if (!u || !u(a, &asz)) return fail(OFS_ERROR_NOT_SUPPORTED);
    }
    for (n = 0; a[n] && n < sizeof a; ++n) if ((unsigned char)a[n] > 0x7F) return fail(OFS_ERROR_NO_UNICODE_TRANSLATION);
    if (!n) return fail(OFS_ERROR_NOT_SUPPORTED);
    if (*size < n + 1) { *size = n + 1; return fail(OFS_ERROR_INSUFFICIENT_BUFFER); }
    for (i = 0; i <= n; ++i) out[i] = (WCHAR)(unsigned char)a[i];
    *size = n + 1;
    return TRUE;
}

/* ---- stack capture ---- */
static int rd2(void *c, uintptr_t addr, uintptr_t out[2])
{
    (void)c;
    if (IsBadReadPtr((const void *)addr, 2 * sizeof(uintptr_t))) return 0;
    out[0] = ((const uintptr_t *)addr)[0]; out[1] = ((const uintptr_t *)addr)[1];
    return 1;
}
USHORT WINAPI OfsCaptureStackBackTrace(DWORD skip, DWORD count, PVOID *frames, PDWORD hash)
{
    uintptr_t buf[64];
    uint32_t n, i;
    if (hash) *hash = 0;
    if (!frames || !count) return 0;
    if (count > 64) count = 64;
    n = ofd_walk_frames((uintptr_t)__builtin_frame_address(0), rd2, 0, skip, count, buf);
    for (i = 0; i < n; ++i) { frames[i] = (PVOID)buf[i]; if (hash) *hash += (DWORD)buf[i]; }
    return (USHORT)n;
}
