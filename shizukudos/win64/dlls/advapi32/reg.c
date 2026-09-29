/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku advapi32.dll, registry part (Reg*): the Win32 registry API over the Kernel64 native registry system calls
 * (NtCreateKey ... in ntdll, implemented by kernel64/registry.c + sysreg.c).
 *
 * Semantics and documented deviations
 *  - Errors are returned as Win32 codes (they are NOT stored in GetLastError), translated with RtlNtStatusToDosError:
 *    ERROR_FILE_NOT_FOUND for a missing key/value, ERROR_MORE_DATA when a buffer is too small, ERROR_NO_MORE_ITEMS at the
 *    end of an enumeration, ERROR_ACCESS_DENIED when the handle lacks the needed right or the key still has sub-keys.
 *  - Predefined keys map to native paths: HKLM -> \Registry\Machine, HKU -> \Registry\User, HKCU -> \Registry\User\<SID of
 *    the single system user>, HKCC -> ...\Hardware Profiles\Current, HKCR -> \Registry\Machine\Software\Classes. The last is
 *    a simplification: Windows presents HKCR as a merged view of HKCU and HKLM class data. HKEY_PERFORMANCE_DATA,
 *    HKEY_DYN_DATA and HKEY_CURRENT_USER_LOCAL_SETTINGS are not supported (ERROR_NOT_SUPPORTED). Predefined handles are not
 *    cached: each call opens the native key it needs and closes it again, so RegDisablePredefinedCache has nothing to do.
 *  - RegNotifyChangeKeyValue: one-shot notifications on key handles, asynchronous (event) or blocking. Notifications on the
 *    predefined keys use a native handle kept open for the life of the process (opened on first use), because a notification
 *    dies with the handle it was registered on. REG_NOTIFY_THREAD_AGNOSTIC is implied: a notification is not tied to the
 *    registering thread.
 *  - There is one registry view: KEY_WOW64_32KEY / KEY_WOW64_64KEY are accepted and change nothing (no Wow6432Node).
 *  - Security attributes are ignored, the registry is volatile (see kernel64/registry.c for the whole list of limits).
 *  - "ANSI" means the process ANSI code page as kernel32 reports it (UTF-8 on this system).
 */
#define _ADVAPI32_
#include "nt.h"
#include <string.h>
#include <winnls.h>
#include <winreg.h>
#include "ntreg.h"

#define ALLOC(n) RtlAllocateHeap(ShzProcessHeap(), 0, (n))
#define FREE(p) RtlFreeHeap(ShzProcessHeap(), 0, (p))

static LONG werr(NTSTATUS st) { return st == STATUS_SUCCESS ? ERROR_SUCCESS : (LONG)RtlNtStatusToDosError(st); }

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

/* ---------------------------------------------------------------- predefined keys */
static const WCHAR *const predef_paths[8] = {
    L"\\Registry\\Machine\\Software\\Classes",                                                 /* HKEY_CLASSES_ROOT */
    L"\\Registry\\User\\" SHZ_USER_SID_W,                                                      /* HKEY_CURRENT_USER */
    L"\\Registry\\Machine",                                                                    /* HKEY_LOCAL_MACHINE */
    L"\\Registry\\User",                                                                       /* HKEY_USERS */
    0,                                                                                         /* HKEY_PERFORMANCE_DATA */
    L"\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current",             /* HKEY_CURRENT_CONFIG */
    0,                                                                                         /* HKEY_DYN_DATA */
    0,                                                                                         /* HKEY_CURRENT_USER_LOCAL_SETTINGS */
};

/* 0x80000000..0x80000007, sign-extended (as the SDK macros are) or zero-extended (as many callers write them). */
static BOOL is_predef(HKEY k, unsigned *idx)
{
    const ULONG_PTR v = (ULONG_PTR)k;
    const ULONG hi = (ULONG)(v >> 32), lo = (ULONG)v;
    if ((hi == 0 || hi == 0xFFFFFFFFu) && (lo & 0xFFFFFFF8u) == 0x80000000u) {
        if (idx) *idx = lo & 7;
        return TRUE;
    }
    return FALSE;
}

/* ---------------------------------------------------------------- native names */
typedef struct {
    SHZ_OBJECT_ATTRIBUTES oa;
    SHZ_UNICODE_STRING us;
    WCHAR small[160];
    WCHAR *heap;
} objname_t;

static void objname_free(objname_t *n)
{
    if (n->heap) FREE(n->heap);
    n->heap = 0;
}

/* (hkey, subkey) -> OBJECT_ATTRIBUTES. A predefined hkey becomes an absolute path; otherwise it is the root handle. */
static LONG objname_init(objname_t *n, HKEY hkey, LPCWSTR sub)
{
    const size_t sublen = sub ? wlen(sub) : 0;
    unsigned idx;
    size_t total;
    WCHAR *buf;
    n->heap = 0;
    if (sublen && sub[0] == L'\\') return ERROR_BAD_PATHNAME;               /* names are relative to the key */
    if (!hkey) return ERROR_INVALID_HANDLE;
    n->oa.Length = sizeof n->oa;
    n->oa.RootDirectory = 0;
    n->oa.ObjectName = &n->us;
    n->oa.Attributes = 0x40;                                                  /* OBJ_CASE_INSENSITIVE */
    n->oa.SecurityDescriptor = n->oa.SecurityQualityOfService = 0;
    if (is_predef(hkey, &idx)) {
        const WCHAR *root = predef_paths[idx];
        size_t rl;
        if (!root) return ERROR_NOT_SUPPORTED;
        rl = wlen(root);
        total = rl + (sublen ? 1 + sublen : 0);
        if (total > 32767) return ERROR_INVALID_PARAMETER;
        if (total < sizeof n->small / sizeof(WCHAR)) buf = n->small;
        else {
            buf = n->heap = ALLOC((total + 1) * sizeof(WCHAR));
            if (!buf) return ERROR_NOT_ENOUGH_MEMORY;
        }
        memcpy(buf, root, rl * sizeof(WCHAR));
        if (sublen) {
            buf[rl] = L'\\';
            memcpy(buf + rl + 1, sub, sublen * sizeof(WCHAR));
        }
        buf[total] = 0;
    } else {
        total = sublen;
        if (total > 32767) return ERROR_INVALID_PARAMETER;
        n->oa.RootDirectory = (HANDLE)hkey;
        buf = (WCHAR *)sub;
    }
    n->us.Buffer = buf;
    n->us.Length = (USHORT)(total * sizeof(WCHAR));
    n->us.MaximumLength = n->us.Length;
    return ERROR_SUCCESS;
}

/* A native handle for an HKEY: predefined keys are opened for the duration of one call. */
typedef struct { HANDLE h; BOOL temp; } natkey_t;

static LONG natkey_acquire(HKEY hkey, ACCESS_MASK access, natkey_t *nk)
{
    unsigned idx;
    if (!hkey) return ERROR_INVALID_HANDLE;
    if (is_predef(hkey, &idx)) {
        objname_t n;
        HANDLE h = 0;
        LONG e = objname_init(&n, hkey, 0);
        NTSTATUS st;
        if (e) return e;
        st = NtOpenKey(&h, access, &n.oa);
        objname_free(&n);
        if (st) return werr(st);
        nk->h = h;
        nk->temp = TRUE;
        return ERROR_SUCCESS;
    }
    nk->h = (HANDLE)hkey;
    nk->temp = FALSE;
    return ERROR_SUCCESS;
}

static void natkey_release(natkey_t *nk) { if (nk->temp) NtClose(nk->h); }

static void init_us(SHZ_UNICODE_STRING *us, LPCWSTR s)
{
    if (s) RtlInitUnicodeString(us, s);
    else { us->Length = us->MaximumLength = 0; us->Buffer = 0; }       /* NULL value name == the default value */
}

/* ---------------------------------------------------------------- ANSI conversion */
static LONG a2w(LPCSTR s, WCHAR **out)
{
    int n;
    WCHAR *w;
    *out = 0;
    if (!s) return ERROR_SUCCESS;
    n = MultiByteToWideChar(CP_ACP, 0, s, -1, 0, 0);
    if (n <= 0) return ERROR_NO_UNICODE_TRANSLATION;
    w = ALLOC((size_t)n * sizeof(WCHAR));
    if (!w) return ERROR_NOT_ENOUGH_MEMORY;
    if (MultiByteToWideChar(CP_ACP, 0, s, -1, w, n) <= 0) { FREE(w); return ERROR_NO_UNICODE_TRANSLATION; }
    *out = w;
    return ERROR_SUCCESS;
}

static BOOL is_string_type(DWORD t) { return t == REG_SZ || t == REG_EXPAND_SZ || t == REG_MULTI_SZ; }

/* ---------------------------------------------------------------- open / create / close */
static LONG open_w(HKEY hkey, LPCWSTR sub, DWORD options, REGSAM sam, PHKEY out)
{
    objname_t n;
    HANDLE h = 0;
    LONG e;
    NTSTATUS st;
    if (!out) return ERROR_INVALID_PARAMETER;
    if (options & ~(DWORD)(REG_OPTION_OPEN_LINK | REG_OPTION_BACKUP_RESTORE)) return ERROR_INVALID_PARAMETER;
    e = objname_init(&n, hkey, sub);
    if (e) return e;
    st = NtOpenKeyEx(&h, sam, &n.oa, options);
    objname_free(&n);
    if (st) return werr(st);
    *out = (HKEY)h;
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    return open_w(hKey, lpSubKey, ulOptions, samDesired, phkResult);
}

DLLAPI LONG WINAPI RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)
{
    WCHAR *w;
    LONG e = a2w(lpSubKey, &w);
    if (e) return e;
    e = open_w(hKey, w, ulOptions, samDesired, phkResult);
    if (w) FREE(w);
    return e;
}

static LONG create_w(HKEY hkey, LPCWSTR sub, LPWSTR cls, DWORD options, REGSAM sam, PHKEY out, LPDWORD disp)
{
    objname_t n;
    SHZ_UNICODE_STRING us_class, *pc = 0;
    HANDLE h = 0;
    ULONG d = 0;
    LONG e;
    NTSTATUS st;
    if (!out) return ERROR_INVALID_PARAMETER;
    e = objname_init(&n, hkey, sub);
    if (e) return e;
    if (cls) { RtlInitUnicodeString(&us_class, cls); pc = &us_class; }
    st = NtCreateKey(&h, sam, &n.oa, 0, pc, options, &d);
    objname_free(&n);
    if (st) return werr(st);
    *out = (HKEY)h;
    if (disp) *disp = d;                                    /* REG_CREATED_NEW_KEY (1) or REG_OPENED_EXISTING_KEY (2) */
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI RegCreateKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD Reserved, LPWSTR lpClass, DWORD dwOptions,
                                   REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult,
                                   LPDWORD lpdwDisposition)
{
    (void)Reserved; (void)lpSecurityAttributes;             /* security is ignored on this system */
    return create_w(hKey, lpSubKey, lpClass, dwOptions, samDesired, phkResult, lpdwDisposition);
}

DLLAPI LONG WINAPI RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions,
                                   REGSAM samDesired, LPSECURITY_ATTRIBUTES lpSecurityAttributes, PHKEY phkResult,
                                   LPDWORD lpdwDisposition)
{
    WCHAR *w, *c;
    LONG e = a2w(lpSubKey, &w);
    (void)Reserved; (void)lpSecurityAttributes;
    if (e) return e;
    e = a2w(lpClass, &c);
    if (e) { if (w) FREE(w); return e; }
    e = create_w(hKey, w, c, dwOptions, samDesired, phkResult, lpdwDisposition);
    if (w) FREE(w);
    if (c) FREE(c);
    return e;
}

DLLAPI LONG WINAPI RegCloseKey(HKEY hKey)
{
    if (!hKey) return ERROR_INVALID_HANDLE;
    if (is_predef(hKey, 0)) return ERROR_SUCCESS;           /* predefined keys are never really open */
    return werr(NtClose((HANDLE)hKey));
}

DLLAPI LONG WINAPI RegFlushKey(HKEY hKey)
{
    natkey_t nk;
    LONG e = natkey_acquire(hKey, KEY_QUERY_VALUE, &nk);
    if (e) return e;
    e = werr(NtFlushKey(nk.h));                             /* the registry lives in memory: nothing to write out */
    natkey_release(&nk);
    return e;
}

DLLAPI LONG WINAPI RegDisablePredefinedCache(void)
{
    return ERROR_SUCCESS;                                   /* predefined handles are never cached here, see the file header */
}

/* ---------------------------------------------------------------- delete */
static LONG delete_key_w(HKEY hkey, LPCWSTR sub)
{
    objname_t n;
    HANDLE h = 0;
    LONG e;
    NTSTATUS st;
    if (!sub) return ERROR_INVALID_PARAMETER;
    e = objname_init(&n, hkey, sub);
    if (e) return e;
    st = NtOpenKey(&h, 0x10000 /* DELETE */, &n.oa);
    objname_free(&n);
    if (st) return werr(st);
    st = NtDeleteKey(h);                                    /* STATUS_CANNOT_DELETE (sub-keys present) -> ERROR_ACCESS_DENIED */
    NtClose(h);
    return werr(st);
}

DLLAPI LONG WINAPI RegDeleteKeyW(HKEY hKey, LPCWSTR lpSubKey) { return delete_key_w(hKey, lpSubKey); }

DLLAPI LONG WINAPI RegDeleteKeyExW(HKEY hKey, LPCWSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
    (void)samDesired; (void)Reserved;                       /* one registry view: the WOW64 flags select nothing */
    return delete_key_w(hKey, lpSubKey);
}

DLLAPI LONG WINAPI RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey)
{
    WCHAR *w;
    LONG e;
    if (!lpSubKey) return ERROR_INVALID_PARAMETER;
    e = a2w(lpSubKey, &w);
    if (e) return e;
    e = delete_key_w(hKey, w);
    FREE(w);
    return e;
}

DLLAPI LONG WINAPI RegDeleteKeyExA(HKEY hKey, LPCSTR lpSubKey, REGSAM samDesired, DWORD Reserved)
{
    (void)samDesired; (void)Reserved;
    return RegDeleteKeyA(hKey, lpSubKey);
}

static LONG delete_value_w(HKEY hkey, LPCWSTR name)
{
    natkey_t nk;
    SHZ_UNICODE_STRING us;
    LONG e = natkey_acquire(hkey, KEY_SET_VALUE, &nk);
    if (e) return e;
    init_us(&us, name);
    e = werr(NtDeleteValueKey(nk.h, &us));
    natkey_release(&nk);
    return e;
}

DLLAPI LONG WINAPI RegDeleteValueW(HKEY hKey, LPCWSTR lpValueName) { return delete_value_w(hKey, lpValueName); }

DLLAPI LONG WINAPI RegDeleteValueA(HKEY hKey, LPCSTR lpValueName)
{
    WCHAR *w;
    LONG e = a2w(lpValueName, &w);
    if (e) return e;
    e = delete_value_w(hKey, w);
    if (w) FREE(w);
    return e;
}

/* ---------------------------------------------------------------- set / query values */
static LONG set_value_w(HKEY hkey, LPCWSTR name, DWORD type, const BYTE *data, DWORD size)
{
    natkey_t nk;
    SHZ_UNICODE_STRING us;
    LONG e;
    if (!data && size) return ERROR_INVALID_PARAMETER;
    e = natkey_acquire(hkey, KEY_SET_VALUE, &nk);
    if (e) return e;
    init_us(&us, name);
    e = werr(NtSetValueKey(nk.h, &us, 0, type, (PVOID)data, size));
    natkey_release(&nk);
    return e;
}

DLLAPI LONG WINAPI RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE *lpData, DWORD cbData)
{
    (void)Reserved;
    return set_value_w(hKey, lpValueName, dwType, lpData, cbData);
}

DLLAPI LONG WINAPI RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE *lpData, DWORD cbData)
{
    WCHAR *wname, *wdata = 0;
    LONG e;
    (void)Reserved;
    e = a2w(lpValueName, &wname);
    if (e) return e;
    if (is_string_type(dwType) && lpData && cbData) {         /* the registry stores Unicode: convert the ANSI text */
        const int n = MultiByteToWideChar(CP_ACP, 0, (LPCCH)lpData, (int)cbData, 0, 0);
        if (n <= 0) { if (wname) FREE(wname); return ERROR_NO_UNICODE_TRANSLATION; }
        wdata = ALLOC((size_t)n * sizeof(WCHAR));
        if (!wdata) { if (wname) FREE(wname); return ERROR_NOT_ENOUGH_MEMORY; }
        if (MultiByteToWideChar(CP_ACP, 0, (LPCCH)lpData, (int)cbData, wdata, n) <= 0) {
            FREE(wdata);
            if (wname) FREE(wname);
            return ERROR_NO_UNICODE_TRANSLATION;
        }
        e = set_value_w(hKey, wname, dwType, (const BYTE *)wdata, (DWORD)n * sizeof(WCHAR));
        FREE(wdata);
    } else {
        e = set_value_w(hKey, wname, dwType, lpData, cbData);
    }
    if (wname) FREE(wname);
    return e;
}

/* Clamp for the temporary query buffer: the kernel never stores more than 256 KiB in one value. */
#define QV_MAX 0x40010u

/* Raw NtQueryValueKey with Windows RegQueryValueEx buffer semantics (data == NULL: size query). */
static LONG query_value_raw(HKEY hkey, LPCWSTR name, LPDWORD type, LPBYTE data, LPDWORD cb)
{
    natkey_t nk;
    SHZ_UNICODE_STRING us;
    SHZ_KEY_VALUE_PARTIAL_INFORMATION *pi;
    BYTE stackbuf[SHZ_KEY_VALUE_PARTIAL_HEADER + 64] __attribute__((aligned(8)));
    ULONG cap, alloc_cap, res = 0;
    NTSTATUS st;
    LONG e;
    if (data && !cb) return ERROR_INVALID_PARAMETER;
    e = natkey_acquire(hkey, KEY_QUERY_VALUE, &nk);
    if (e) return e;
    init_us(&us, name);
    cap = data ? *cb : 0;
    alloc_cap = cap > QV_MAX ? QV_MAX : cap;
    if (alloc_cap <= 64) pi = (void *)stackbuf;
    else {
        pi = ALLOC(SHZ_KEY_VALUE_PARTIAL_HEADER + alloc_cap);
        if (!pi) { natkey_release(&nk); return ERROR_NOT_ENOUGH_MEMORY; }
    }
    st = NtQueryValueKey(nk.h, &us, SHZ_KeyValuePartialInformation, pi, SHZ_KEY_VALUE_PARTIAL_HEADER + alloc_cap, &res);
    natkey_release(&nk);
    if (st == STATUS_SUCCESS || st == STATUS_BUFFER_OVERFLOW) {
        if (type) *type = pi->Type;
        if (st == STATUS_SUCCESS) {
            if (data && pi->DataLength) memcpy(data, pi->Data, pi->DataLength);
            if (cb) *cb = pi->DataLength;
            e = ERROR_SUCCESS;
        } else {
            if (cb) *cb = pi->DataLength;                    /* the size the caller must provide */
            e = data ? ERROR_MORE_DATA : ERROR_SUCCESS;      /* a pure size query is a success */
        }
    } else {
        e = werr(st);
    }
    if (pi != (void *)stackbuf) FREE(pi);
    return e;
}

/* Value data in a heap block (retrying if the value changes between the size query and the read). Caller FREE()s. */
static LONG query_value_alloc(HKEY hkey, LPCWSTR name, DWORD *type, BYTE **out, DWORD *size)
{
    int attempt;
    for (attempt = 0; attempt < 8; ++attempt) {
        DWORD need = 0, t = 0, have;
        BYTE *buf;
        LONG e = query_value_raw(hkey, name, &t, 0, &need);
        if (e) return e;
        have = need + 8;                                     /* slack: room for terminators the caller may add */
        buf = ALLOC(have);
        if (!buf) return ERROR_NOT_ENOUGH_MEMORY;
        e = query_value_raw(hkey, name, &t, buf, &have);
        if (e == ERROR_SUCCESS) {
            if (type) *type = t;
            *out = buf;
            *size = have;
            return ERROR_SUCCESS;
        }
        FREE(buf);
        if (e != ERROR_MORE_DATA) return e;
    }
    return ERROR_MORE_DATA;
}

DLLAPI LONG WINAPI RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    return query_value_raw(hKey, lpValueName, lpType, lpData, lpcbData);
}

DLLAPI LONG WINAPI RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    WCHAR *wname;
    BYTE *raw = 0;
    DWORD type = 0, rawlen = 0;
    LONG e;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (lpData && !lpcbData) return ERROR_INVALID_PARAMETER;
    e = a2w(lpValueName, &wname);
    if (e) return e;
    /* not a string type: identical to the Unicode call */
    e = query_value_raw(hKey, wname, &type, 0, &rawlen);
    if (e == ERROR_SUCCESS && !is_string_type(type)) {
        e = query_value_raw(hKey, wname, lpType, lpData, lpcbData);
        if (wname) FREE(wname);
        return e;
    }
    if (e) { if (wname) FREE(wname); return e; }
    e = query_value_alloc(hKey, wname, &type, &raw, &rawlen);
    if (wname) FREE(wname);
    if (e) return e;
    if (!is_string_type(type)) {                            /* changed under us: report it raw */
        if (lpType) *lpType = type;
        if (!lpData) { if (lpcbData) *lpcbData = rawlen; e = ERROR_SUCCESS; }
        else if (rawlen > *lpcbData) { *lpcbData = rawlen; e = ERROR_MORE_DATA; }
        else { memcpy(lpData, raw, rawlen); *lpcbData = rawlen; e = ERROR_SUCCESS; }
    } else {
        const int wchars = (int)(rawlen / 2);
        int alen = 0;
        if (wchars) alen = WideCharToMultiByte(CP_ACP, 0, (LPCWCH)raw, wchars, 0, 0, 0, 0);
        if (wchars && alen <= 0) e = ERROR_NO_UNICODE_TRANSLATION;
        else {
            if (lpType) *lpType = type;
            if (!lpData) { if (lpcbData) *lpcbData = (DWORD)alen; e = ERROR_SUCCESS; }
            else if ((DWORD)alen > *lpcbData) { *lpcbData = (DWORD)alen; e = ERROR_MORE_DATA; }
            else {
                if (alen && WideCharToMultiByte(CP_ACP, 0, (LPCWCH)raw, wchars, (LPSTR)lpData, alen, 0, 0) <= 0) e = ERROR_NO_UNICODE_TRANSLATION;
                else { *lpcbData = (DWORD)alen; e = ERROR_SUCCESS; }
            }
        }
    }
    FREE(raw);
    return e;
}

/* ---------------------------------------------------------------- RegGetValue */
/* %NAME% expansion with kernel32's environment (unknown names are left as written, like ExpandEnvironmentStrings).
 * Returns the length in characters of the expansion (without NUL); writes at most `cap` characters + NUL. */
static size_t expand_env(const WCHAR *src, size_t n, WCHAR *dst, size_t cap)
{
    size_t i = 0, o = 0;
    while (i < n && src[i]) {
        if (src[i] == L'%') {
            size_t j = i + 1;
            while (j < n && src[j] && src[j] != L'%') ++j;
            if (j < n && src[j] == L'%' && j > i + 1) {
                WCHAR name[128];
                const size_t nl = j - i - 1;
                if (nl < 128) {
                    WCHAR val[512];
                    DWORD got;
                    memcpy(name, src + i + 1, nl * sizeof(WCHAR));
                    name[nl] = 0;
                    got = GetEnvironmentVariableW(name, val, 512);
                    if (got && got < 512) {
                        size_t k;
                        for (k = 0; k < got; ++k) { if (dst && o < cap) dst[o] = val[k]; ++o; }
                        i = j + 1;
                        continue;
                    }
                }
                {                                            /* unknown or too long: copy "%NAME%" literally */
                    size_t k;
                    for (k = i; k <= j; ++k) { if (dst && o < cap) dst[o] = src[k]; ++o; }
                    i = j + 1;
                    continue;
                }
            }
        }
        if (dst && o < cap) dst[o] = src[i];
        ++o;
        ++i;
    }
    if (dst && cap) dst[o < cap ? o : cap] = 0;
    return o;
}

DLLAPI LONG WINAPI RegGetValueW(HKEY hkey, LPCWSTR lpSubKey, LPCWSTR lpValue, DWORD dwFlags, LPDWORD pdwType, PVOID pvData, LPDWORD pcbData)
{
    HKEY sub = 0;
    BYTE *raw = 0;
    DWORD type = 0, size = 0, outsize;
    LONG e;
    const DWORD rt = dwFlags & RRF_RT_ANY;
    const DWORD caller_cap = pcbData ? *pcbData : 0;            /* *pcbData is overwritten with the needed size on failure */
    if (pvData && !pcbData) return ERROR_INVALID_PARAMETER;
    if (lpSubKey && *lpSubKey) {
        e = open_w(hkey, lpSubKey, 0, KEY_QUERY_VALUE, &sub);
        if (e) goto fail;
        hkey = sub;
    }
    e = query_value_alloc(hkey, lpValue, &type, &raw, &size);
    if (sub) RegCloseKey(sub);
    if (e) goto fail;
    /* type restriction (Windows: REG_EXPAND_SZ is delivered as an expanded REG_SZ unless RRF_NOEXPAND) */
    {
        const BOOL expand = type == REG_EXPAND_SZ && !(dwFlags & RRF_NOEXPAND) && (rt & RRF_RT_REG_SZ);
        DWORD bit;
        switch (type) {
        case REG_NONE: bit = RRF_RT_REG_NONE; break;
        case REG_SZ: bit = RRF_RT_REG_SZ; break;
        case REG_EXPAND_SZ: bit = expand ? RRF_RT_REG_SZ : RRF_RT_REG_EXPAND_SZ; break;
        case REG_BINARY: bit = RRF_RT_REG_BINARY; break;
        case REG_DWORD: bit = RRF_RT_REG_DWORD; break;
        case REG_MULTI_SZ: bit = RRF_RT_REG_MULTI_SZ; break;
        case REG_QWORD: bit = RRF_RT_REG_QWORD; break;
        default: bit = 0;
        }
        if (!(rt & bit)) { e = ERROR_UNSUPPORTED_TYPE; goto fail_free; }
        /* RRF_RT_DWORD / RRF_RT_QWORD accept binary data only if it has exactly that size */
        if (type == REG_BINARY && (rt == RRF_RT_DWORD ? size != 4 : rt == RRF_RT_QWORD && size != 8)) {
            e = ERROR_DATATYPE_MISMATCH;
            goto fail_free;
        }
        if (is_string_type(type)) {
            /* guarantee termination: a stored string may lack its NUL(s); the reported size includes them */
            const DWORD chars = size / 2;
            WCHAR *w = (WCHAR *)raw;
            if (type == REG_MULTI_SZ) {
                if (chars < 2 || w[chars - 1] || w[chars - 2]) { w[chars] = 0; w[chars + 1] = 0; size = (chars + 2) * 2; }
            } else if (!chars || w[chars - 1]) {
                w[chars] = 0;
                size = (chars + 1) * 2;
            }
        }
        if (expand) {
            const size_t n = size / 2;
            const size_t need = expand_env((WCHAR *)raw, n, 0, 0) + 1;
            if (pvData && need * 2 <= *pcbData) expand_env((WCHAR *)raw, n, (WCHAR *)pvData, need - 1);
            outsize = (DWORD)(need * 2);
            if (pdwType) *pdwType = REG_SZ;
            if (pvData && need * 2 > *pcbData) { *pcbData = outsize; e = ERROR_MORE_DATA; goto fail_free; }
            if (pcbData) *pcbData = outsize;
            FREE(raw);
            return ERROR_SUCCESS;
        }
        if (pdwType) *pdwType = type;
        if (pvData) {
            if (size > *pcbData) { *pcbData = size; e = ERROR_MORE_DATA; goto fail_free; }
            memcpy(pvData, raw, size);
        }
        if (pcbData) *pcbData = size;
    }
    FREE(raw);
    return ERROR_SUCCESS;
fail_free:
    FREE(raw);
fail:
    if ((dwFlags & RRF_ZEROONFAILURE) && pvData) memset(pvData, 0, caller_cap);
    return e;
}

/* ---------------------------------------------------------------- enumeration */
/* One sub-key record (KeyNodeInformation) in a heap block. Retries with a bigger buffer on STATUS_BUFFER_OVERFLOW. */
static LONG enum_key_alloc(HKEY hkey, DWORD index, SHZ_KEY_NODE_INFORMATION **out)
{
    natkey_t nk;
    ULONG cap = 1024, res = 0;
    LONG e = natkey_acquire(hkey, KEY_ENUMERATE_SUB_KEYS, &nk);
    if (e) return e;
    for (;;) {
        SHZ_KEY_NODE_INFORMATION *ni = ALLOC(cap);
        NTSTATUS st;
        if (!ni) { natkey_release(&nk); return ERROR_NOT_ENOUGH_MEMORY; }
        st = NtEnumerateKey(nk.h, index, SHZ_KeyNodeInformation, ni, cap, &res);
        if (st == STATUS_SUCCESS) { *out = ni; natkey_release(&nk); return ERROR_SUCCESS; }
        FREE(ni);
        if (st != STATUS_BUFFER_OVERFLOW && st != STATUS_BUFFER_TOO_SMALL) { natkey_release(&nk); return werr(st); }
        cap = res + 16;
    }
}

DLLAPI LONG WINAPI RegEnumKeyExW(HKEY hKey, DWORD dwIndex, LPWSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPWSTR lpClass,
                                 LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
    SHZ_KEY_NODE_INFORMATION *ni;
    LONG e;
    DWORD nchars, cchars;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (!lpName || !lpcchName) return ERROR_INVALID_PARAMETER;
    if (lpClass && !lpcchClass) return ERROR_INVALID_PARAMETER;
    e = enum_key_alloc(hKey, dwIndex, &ni);
    if (e) return e;
    nchars = ni->NameLength / 2;
    cchars = ni->ClassLength / 2;
    if (nchars + 1 > *lpcchName) { FREE(ni); return ERROR_MORE_DATA; }
    if (lpClass && cchars + 1 > *lpcchClass) { *lpcchClass = cchars; FREE(ni); return ERROR_MORE_DATA; }
    memcpy(lpName, ni->Name, nchars * sizeof(WCHAR));
    lpName[nchars] = 0;
    *lpcchName = nchars;
    if (lpClass) {
        if (cchars) memcpy(lpClass, (BYTE *)ni + ni->ClassOffset, cchars * sizeof(WCHAR));
        lpClass[cchars] = 0;
    }
    if (lpcchClass) *lpcchClass = cchars;
    if (lpftLastWriteTime) { lpftLastWriteTime->dwLowDateTime = (DWORD)ni->LastWriteTime; lpftLastWriteTime->dwHighDateTime = (DWORD)((ULONGLONG)ni->LastWriteTime >> 32); }
    FREE(ni);
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved, LPSTR lpClass,
                                 LPDWORD lpcchClass, PFILETIME lpftLastWriteTime)
{
    SHZ_KEY_NODE_INFORMATION *ni;
    LONG e;
    DWORD nchars, cchars;
    int alen = 0, clen = 0;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (!lpName || !lpcchName) return ERROR_INVALID_PARAMETER;
    if (lpClass && !lpcchClass) return ERROR_INVALID_PARAMETER;
    e = enum_key_alloc(hKey, dwIndex, &ni);
    if (e) return e;
    nchars = ni->NameLength / 2;
    cchars = ni->ClassLength / 2;
    if (nchars) alen = WideCharToMultiByte(CP_ACP, 0, ni->Name, (int)nchars, 0, 0, 0, 0);
    if (cchars) clen = WideCharToMultiByte(CP_ACP, 0, (LPCWCH)((BYTE *)ni + ni->ClassOffset), (int)cchars, 0, 0, 0, 0);
    if ((nchars && alen <= 0) || (cchars && clen <= 0)) { FREE(ni); return ERROR_NO_UNICODE_TRANSLATION; }
    if ((DWORD)alen + 1 > *lpcchName) { FREE(ni); return ERROR_MORE_DATA; }
    if (lpClass && (DWORD)clen + 1 > *lpcchClass) { *lpcchClass = (DWORD)clen; FREE(ni); return ERROR_MORE_DATA; }
    if (alen) WideCharToMultiByte(CP_ACP, 0, ni->Name, (int)nchars, lpName, alen, 0, 0);
    lpName[alen] = 0;
    *lpcchName = (DWORD)alen;
    if (lpClass) {
        if (clen) WideCharToMultiByte(CP_ACP, 0, (LPCWCH)((BYTE *)ni + ni->ClassOffset), (int)cchars, lpClass, clen, 0, 0);
        lpClass[clen] = 0;
    }
    if (lpcchClass) *lpcchClass = (DWORD)clen;
    if (lpftLastWriteTime) { lpftLastWriteTime->dwLowDateTime = (DWORD)ni->LastWriteTime; lpftLastWriteTime->dwHighDateTime = (DWORD)((ULONGLONG)ni->LastWriteTime >> 32); }
    FREE(ni);
    return ERROR_SUCCESS;
}

static LONG enum_value_alloc(HKEY hkey, DWORD index, SHZ_KEY_VALUE_FULL_INFORMATION **out)
{
    natkey_t nk;
    ULONG cap = 1024, res = 0;
    LONG e = natkey_acquire(hkey, KEY_QUERY_VALUE, &nk);
    if (e) return e;
    for (;;) {
        SHZ_KEY_VALUE_FULL_INFORMATION *vi = ALLOC(cap);
        NTSTATUS st;
        if (!vi) { natkey_release(&nk); return ERROR_NOT_ENOUGH_MEMORY; }
        st = NtEnumerateValueKey(nk.h, index, SHZ_KeyValueFullInformation, vi, cap, &res);
        if (st == STATUS_SUCCESS) { *out = vi; natkey_release(&nk); return ERROR_SUCCESS; }
        FREE(vi);
        if (st != STATUS_BUFFER_OVERFLOW && st != STATUS_BUFFER_TOO_SMALL) { natkey_release(&nk); return werr(st); }
        cap = res + 16;
    }
}

DLLAPI LONG WINAPI RegEnumValueW(HKEY hKey, DWORD dwIndex, LPWSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved,
                                 LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    SHZ_KEY_VALUE_FULL_INFORMATION *vi;
    LONG e;
    DWORD nchars;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (!lpValueName || !lpcchValueName) return ERROR_INVALID_PARAMETER;
    if (lpData && !lpcbData) return ERROR_INVALID_PARAMETER;
    e = enum_value_alloc(hKey, dwIndex, &vi);
    if (e) return e;
    nchars = vi->NameLength / 2;
    if (nchars + 1 > *lpcchValueName) {
        if (lpcbData) *lpcbData = vi->DataLength;
        FREE(vi);
        return ERROR_MORE_DATA;
    }
    if (lpData && vi->DataLength > *lpcbData) {
        *lpcbData = vi->DataLength;
        FREE(vi);
        return ERROR_MORE_DATA;
    }
    memcpy(lpValueName, vi->Name, nchars * sizeof(WCHAR));
    lpValueName[nchars] = 0;
    *lpcchValueName = nchars;
    if (lpType) *lpType = vi->Type;
    if (lpData && vi->DataLength) memcpy(lpData, (BYTE *)vi + vi->DataOffset, vi->DataLength);
    if (lpcbData) *lpcbData = vi->DataLength;
    FREE(vi);
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI RegEnumValueA(HKEY hKey, DWORD dwIndex, LPSTR lpValueName, LPDWORD lpcchValueName, LPDWORD lpReserved,
                                 LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)
{
    SHZ_KEY_VALUE_FULL_INFORMATION *vi;
    LONG e;
    DWORD nchars;
    int alen = 0, dlen;
    const BYTE *data;
    BOOL str;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (!lpValueName || !lpcchValueName) return ERROR_INVALID_PARAMETER;
    if (lpData && !lpcbData) return ERROR_INVALID_PARAMETER;
    e = enum_value_alloc(hKey, dwIndex, &vi);
    if (e) return e;
    nchars = vi->NameLength / 2;
    data = (const BYTE *)vi + vi->DataOffset;
    str = is_string_type(vi->Type);
    dlen = (int)vi->DataLength;
    if (nchars) alen = WideCharToMultiByte(CP_ACP, 0, vi->Name, (int)nchars, 0, 0, 0, 0);
    if (nchars && alen <= 0) { FREE(vi); return ERROR_NO_UNICODE_TRANSLATION; }
    if (str) {
        dlen = 0;
        if (vi->DataLength / 2) dlen = WideCharToMultiByte(CP_ACP, 0, (LPCWCH)data, (int)(vi->DataLength / 2), 0, 0, 0, 0);
        if (vi->DataLength / 2 && dlen <= 0) { FREE(vi); return ERROR_NO_UNICODE_TRANSLATION; }
    }
    if ((DWORD)alen + 1 > *lpcchValueName) {
        if (lpcbData) *lpcbData = (DWORD)dlen;
        FREE(vi);
        return ERROR_MORE_DATA;
    }
    if (lpData && (DWORD)dlen > *lpcbData) { *lpcbData = (DWORD)dlen; FREE(vi); return ERROR_MORE_DATA; }
    if (alen) WideCharToMultiByte(CP_ACP, 0, vi->Name, (int)nchars, lpValueName, alen, 0, 0);
    lpValueName[alen] = 0;
    *lpcchValueName = (DWORD)alen;
    if (lpType) *lpType = vi->Type;
    if (lpData && dlen) {
        if (str) WideCharToMultiByte(CP_ACP, 0, (LPCWCH)data, (int)(vi->DataLength / 2), (LPSTR)lpData, dlen, 0, 0);
        else memcpy(lpData, data, (size_t)dlen);
    }
    if (lpcbData) *lpcbData = (DWORD)dlen;
    FREE(vi);
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- RegQueryInfoKey */
DLLAPI LONG WINAPI RegQueryInfoKeyW(HKEY hKey, LPWSTR lpClass, LPDWORD lpcchClass, LPDWORD lpReserved, LPDWORD lpcSubKeys,
                                    LPDWORD lpcbMaxSubKeyLen, LPDWORD lpcbMaxClassLen, LPDWORD lpcValues, LPDWORD lpcbMaxValueNameLen,
                                    LPDWORD lpcbMaxValueLen, LPDWORD lpcbSecurityDescriptor, PFILETIME lpftLastWriteTime)
{
    natkey_t nk;
    SHZ_KEY_FULL_INFORMATION *fi;
    ULONG cap, res = 0, clen;
    NTSTATUS st;
    LONG e;
    if (lpReserved) return ERROR_INVALID_PARAMETER;
    if (lpClass && !lpcchClass) return ERROR_INVALID_PARAMETER;
    e = natkey_acquire(hKey, KEY_QUERY_VALUE, &nk);
    if (e) return e;
    cap = SHZ_KEY_FULL_HEADER + (lpClass ? (*lpcchClass > 0x8000 ? 0x8000 : *lpcchClass) * 2 : 0) + 8;
    fi = ALLOC(cap);
    if (!fi) { natkey_release(&nk); return ERROR_NOT_ENOUGH_MEMORY; }
    st = NtQueryKey(nk.h, SHZ_KeyFullInformation, fi, cap, &res);
    natkey_release(&nk);
    if (st != STATUS_SUCCESS && st != STATUS_BUFFER_OVERFLOW) { FREE(fi); return werr(st); }
    clen = fi->ClassLength / 2;
    if (lpClass && clen + 1 > *lpcchClass) {                /* the class name does not fit */
        *lpcchClass = clen;
        FREE(fi);
        return ERROR_MORE_DATA;
    }
    if (lpClass) {
        if (clen) memcpy(lpClass, (BYTE *)fi + fi->ClassOffset, clen * sizeof(WCHAR));
        lpClass[clen] = 0;
    }
    if (lpcchClass) *lpcchClass = clen;
    if (lpcSubKeys) *lpcSubKeys = fi->SubKeys;
    if (lpcbMaxSubKeyLen) *lpcbMaxSubKeyLen = fi->MaxNameLen / 2;               /* characters, without the NUL */
    if (lpcbMaxClassLen) *lpcbMaxClassLen = fi->MaxClassLen / 2;
    if (lpcValues) *lpcValues = fi->Values;
    if (lpcbMaxValueNameLen) *lpcbMaxValueNameLen = fi->MaxValueNameLen / 2;
    if (lpcbMaxValueLen) *lpcbMaxValueLen = fi->MaxValueDataLen;               /* bytes */
    if (lpcbSecurityDescriptor) *lpcbSecurityDescriptor = 0;                    /* keys carry no security descriptor */
    if (lpftLastWriteTime) { lpftLastWriteTime->dwLowDateTime = (DWORD)fi->LastWriteTime; lpftLastWriteTime->dwHighDateTime = (DWORD)((ULONGLONG)fi->LastWriteTime >> 32); }
    FREE(fi);
    return ERROR_SUCCESS;
}

/* ---------------------------------------------------------------- change notification */
static HANDLE g_notify_roots[8];           /* native handles behind predefined keys, for notifications only */

static LONG notify_handle(HKEY hkey, HANDLE *out)
{
    unsigned idx;
    if (!hkey) return ERROR_INVALID_HANDLE;
    if (!is_predef(hkey, &idx)) { *out = (HANDLE)hkey; return ERROR_SUCCESS; }
    if (!g_notify_roots[idx]) {
        objname_t n;
        HANDLE h = 0;
        LONG e = objname_init(&n, hkey, 0);
        NTSTATUS st;
        if (e) return e;
        st = NtOpenKey(&h, KEY_NOTIFY | KEY_QUERY_VALUE, &n.oa);
        objname_free(&n);
        if (st) return werr(st);
        if (__sync_val_compare_and_swap(&g_notify_roots[idx], (HANDLE)0, h)) NtClose(h);      /* another thread opened it first */
    }
    *out = g_notify_roots[idx];
    return ERROR_SUCCESS;
}

DLLAPI LONG WINAPI RegNotifyChangeKeyValue(HKEY hKey, BOOL bWatchSubtree, DWORD dwNotifyFilter, HANDLE hEvent, BOOL fAsynchronous)
{
    HANDLE kh = 0, ev = 0;
    NTSTATUS st;
    LONG e;
    const DWORD any = REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_ATTRIBUTES | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_CHANGE_SECURITY;
    if (dwNotifyFilter & ~(DWORD)REG_LEGAL_CHANGE_FILTER) return ERROR_INVALID_PARAMETER;
    if (!(dwNotifyFilter & any)) return ERROR_INVALID_PARAMETER;          /* at least one kind of change to watch for */
    if (fAsynchronous && !hEvent) return ERROR_INVALID_PARAMETER;
    e = notify_handle(hKey, &kh);
    if (e) return e;
    if (fAsynchronous) {
        st = NtNotifyChangeKey(kh, hEvent, 0, 0, 0, dwNotifyFilter, (BOOLEAN)(bWatchSubtree != 0), 0, 0, TRUE);
        return st == STATUS_PENDING ? ERROR_SUCCESS : werr(st);
    }
    st = NtCreateEvent(&ev, EVENT_ALL_ACCESS, 0, 0 /* NotificationEvent */, FALSE);
    if (st) return werr(st);
    st = NtNotifyChangeKey(kh, ev, 0, 0, 0, dwNotifyFilter, (BOOLEAN)(bWatchSubtree != 0), 0, 0, TRUE);
    if (st == STATUS_PENDING) st = NtWaitForSingleObject(ev, FALSE, 0);   /* returns on a change, key deletion or handle close */
    NtClose(ev);
    return NT_SUCCESS(st) ? ERROR_SUCCESS : werr(st);
}
