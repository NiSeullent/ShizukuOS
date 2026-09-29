/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: miscellaneous Win32 functions called by the DLLs ported from Wine (wineport):
 *   CompareFileTime, FileTimeToLocalFileTime / LocalFileTimeToFileTime (local time is UTC on this system),
 *   GetTempFileName, IsBad*Ptr (answered from VirtualQuery instead of probing with exceptions),
 *   ExpandEnvironmentStrings, the delay-load resolver (ResolveDelayLoadedAPI, DelayLoadFailureHook) and FormatMessage.
 * FormatMessage: FROM_STRING and FROM_HMODULE (RT_MESSAGETABLE) are implemented with the documented insert syntax
 * (%1..%99 with !printf-format!, %0 %n %% %t %space %. %! and FORMAT_MESSAGE_MAX_WIDTH_MASK line joining). There is no
 * system message table on this system, so FROM_SYSTEM alone fails with ERROR_MR_MID_NOT_FOUND.
 */
#include "k32_winecompat.h"

/* ---------------------------------------------------------------- time */
K32API LONG WINAPI CompareFileTime(const FILETIME *a, const FILETIME *b)
{
    ULONGLONG x, y;
    if (!a || !b) return 0;
    x = ((ULONGLONG)a->dwHighDateTime << 32) | a->dwLowDateTime;
    y = ((ULONGLONG)b->dwHighDateTime << 32) | b->dwLowDateTime;
    return x < y ? -1 : x > y ? 1 : 0;
}
K32API BOOL WINAPI FileTimeToLocalFileTime(const FILETIME *in, LPFILETIME out) { *out = *in; return TRUE; }
K32API BOOL WINAPI LocalFileTimeToFileTime(const FILETIME *in, LPFILETIME out) { *out = *in; return TRUE; }

/* ---------------------------------------------------------------- pointers */
static BOOL range_ok(const void *p, UINT_PTR n, BOOL write)
{
    const BYTE *a = p, *end;
    MEMORY_BASIC_INFORMATION mbi;
    if (!n) return TRUE;
    if (!p) return FALSE;
    end = a + n;
    if (end < a) return FALSE;
    while (a < end) {
        DWORD prot;
        if (!VirtualQuery(a, &mbi, sizeof mbi) || mbi.State != MEM_COMMIT) return FALSE;
        prot = mbi.Protect & 0xff;
        if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return FALSE;
        if (write && !(prot & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) return FALSE;
        if (!write && !(prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                PAGE_EXECUTE_WRITECOPY))) return FALSE;
        a = (const BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    return TRUE;
}
K32API BOOL WINAPI IsBadReadPtr(const void *p, UINT_PTR n) { return !range_ok(p, n, FALSE); }
K32API BOOL WINAPI IsBadWritePtr(LPVOID p, UINT_PTR n) { return !range_ok(p, n, TRUE); }
K32API BOOL WINAPI IsBadCodePtr(FARPROC p) { return !range_ok((const void *)p, 1, FALSE); }
K32API BOOL WINAPI IsBadStringPtrA(LPCSTR s, UINT_PTR max)
{
    UINT_PTR i;
    if (!max) return FALSE;
    for (i = 0; i < max; ++i) {
        if (i == 0 || !(((UINT_PTR)(s + i)) & 0xfff)) if (!range_ok(s + i, 1, FALSE)) return TRUE;
        if (!s[i]) break;
    }
    return FALSE;
}
K32API BOOL WINAPI IsBadStringPtrW(LPCWSTR s, UINT_PTR max)
{
    UINT_PTR i;
    if (!max) return FALSE;
    for (i = 0; i < max; ++i) {
        if (i == 0 || !(((UINT_PTR)(s + i)) & 0xfff)) if (!range_ok(s + i, sizeof(WCHAR), FALSE)) return TRUE;
        if (!s[i]) break;
    }
    return FALSE;
}

/* ---------------------------------------------------------------- environment */
K32API DWORD WINAPI ExpandEnvironmentStringsW(LPCWSTR src, LPWSTR dst, DWORD cap)
{
    DWORD n = 0;
    WCHAR name[256], val[1024];
    if (!src) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    while (*src) {
        const WCHAR *end = src + 1;
        DWORD k, vn = 0;
        if (*src == '%') while (*end && *end != '%') end++;
        if (*src == '%' && *end == '%' && end - src - 1 > 0 && (size_t)(end - src - 1) < ARRAYSIZE(name)) {
            memcpy(name, src + 1, (end - src - 1) * sizeof(WCHAR));
            name[end - src - 1] = 0;
            vn = GetEnvironmentVariableW(name, val, ARRAYSIZE(val));
            if (vn && vn < ARRAYSIZE(val)) {
                for (k = 0; k < vn; ++k) { if (n < cap) dst[n] = val[k]; n++; }
                src = end + 1;
                continue;
            }
        }
        if (n < cap) dst[n] = *src;
        n++;
        src++;
    }
    if (n < cap) dst[n] = 0;
    n++;
    return n;
}
K32API DWORD WINAPI ExpandEnvironmentStringsA(LPCSTR src, LPSTR dst, DWORD cap)
{
    WCHAR *ws, *wd;
    int wn;
    DWORD r;
    if (!src) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    wn = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (!(ws = HeapAlloc(GetProcessHeap(), 0, wn * sizeof(WCHAR)))) return 0;
    MultiByteToWideChar(CP_ACP, 0, src, -1, ws, wn);
    r = ExpandEnvironmentStringsW(ws, NULL, 0);
    if (!(wd = HeapAlloc(GetProcessHeap(), 0, r * sizeof(WCHAR)))) { HeapFree(GetProcessHeap(), 0, ws); return 0; }
    ExpandEnvironmentStringsW(ws, wd, r);
    r = (DWORD)WideCharToMultiByte(CP_ACP, 0, wd, -1, NULL, 0, NULL, NULL);
    if (dst && cap >= r) WideCharToMultiByte(CP_ACP, 0, wd, -1, dst, cap, NULL, NULL);
    HeapFree(GetProcessHeap(), 0, wd);
    HeapFree(GetProcessHeap(), 0, ws);
    return r;
}

/* ---------------------------------------------------------------- temporary file names */
K32API UINT WINAPI GetTempFileNameW(LPCWSTR path, LPCWSTR prefix, UINT unique, LPWSTR buffer)
{
    static const WCHAR hex[] = L"0123456789ABCDEF";
    WCHAR *p;
    UINT num, start, i;
    size_t len;
    if (!path || !buffer) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    len = lstrlenW(path);
    if (len + 3 + 4 + 5 >= MAX_PATH) { SetLastError(ERROR_BUFFER_OVERFLOW); return 0; }
    memcpy(buffer, path, (len + 1) * sizeof(WCHAR));
    p = buffer + len;
    if (len && p[-1] != '\\' && p[-1] != '/') *p++ = '\\';
    for (i = 0; prefix && prefix[i] && i < 3; ++i) *p++ = prefix[i];
    num = unique ? (unique & 0xffff) : (GetTickCount() & 0xffff);
    if (!num) num = 1;
    start = num;
    for (;;) {
        HANDLE h;
        p[0] = hex[(num >> 12) & 15]; p[1] = hex[(num >> 8) & 15]; p[2] = hex[(num >> 4) & 15]; p[3] = hex[num & 15];
        memcpy(p + 4, L".tmp", 5 * sizeof(WCHAR));
        if (unique) return unique;
        h = CreateFileW(buffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return num; }
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS &&
            GetLastError() != ERROR_SHARING_VIOLATION)
            return 0;
        if (!(num = (num + 1) & 0xffff)) num = 1;
        if (num == start) { SetLastError(ERROR_FILE_EXISTS); return 0; }
    }
}
K32API UINT WINAPI GetTempFileNameA(LPCSTR path, LPCSTR prefix, UINT unique, LPSTR buffer)
{
    WCHAR wp[MAX_PATH], wpre[8] = { 0 }, wb[MAX_PATH];
    UINT r;
    if (!path || !buffer || !MultiByteToWideChar(CP_ACP, 0, path, -1, wp, MAX_PATH)) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (prefix) MultiByteToWideChar(CP_ACP, 0, prefix, -1, wpre, ARRAYSIZE(wpre) - 1);
    if (!(r = GetTempFileNameW(wp, wpre, unique, wb))) return 0;
    WideCharToMultiByte(CP_ACP, 0, wb, -1, buffer, MAX_PATH, NULL, NULL);
    return r;
}

/* ---------------------------------------------------------------- delay-load resolution */
typedef struct {
    DWORD Attributes, DllNameRVA, ModuleHandleRVA, ImportAddressTableRVA, ImportNameTableRVA, BoundImportAddressTableRVA,
          UnloadInformationTableRVA, TimeDateStamp;
} SHZ_DELAYLOAD_DESCRIPTOR;

static ULONGLONG __attribute__((ms_abi)) delay_fail_mod(void) { SetLastError(ERROR_MOD_NOT_FOUND); return 0; }
static ULONGLONG __attribute__((ms_abi)) delay_fail_proc(void) { SetLastError(ERROR_PROC_NOT_FOUND); return 0; }

/* Called when a delay-loaded DLL or function is missing: report it and hand back a stub that fails with
 * ERROR_MOD_NOT_FOUND / ERROR_PROC_NOT_FOUND and returns 0, so the calling API reports failure. */
K32API PVOID WINAPI DelayLoadFailureHook(LPCSTR dll, LPCSTR proc)
{
    char msg[200];
    int k = 0;
    const char *parts[4] = { "kernel32: delay load of ", dll ? dll : "?", !IS_INTRESOURCE(proc) ? "!" : "", "" };
    unsigned i;
    for (i = 0; i < 3; ++i) { const char *s = parts[i]; while (*s && k < 150) msg[k++] = *s++; }
    if (!IS_INTRESOURCE(proc)) { const char *s = proc; while (*s && k < 190) msg[k++] = *s++; }
    msg[k++] = ' '; msg[k++] = 'f'; msg[k++] = 'a'; msg[k++] = 'i'; msg[k++] = 'l'; msg[k++] = 'e'; msg[k++] = 'd';
    msg[k++] = '\n'; msg[k] = 0;
    OutputDebugStringA(msg);
    return (PVOID)(dll && GetModuleHandleA(dll) ? delay_fail_proc : delay_fail_mod);
}

typedef PVOID (WINAPI *delay_sys_hook)(LPCSTR, LPCSTR);

K32API PVOID WINAPI ResolveDelayLoadedAPI(PVOID base, const SHZ_DELAYLOAD_DESCRIPTOR *desc, PVOID dll_hook, delay_sys_hook sys_hook,
                                          PIMAGE_THUNK_DATA thunk, ULONG flags)
{
    BYTE *b = base;
    BOOL rva = desc->Attributes & 1;
#define PTR(v) ((void *)(rva ? b + (v) : (BYTE *)(ULONG_PTR)(v)))
    const char *dll = PTR(desc->DllNameRVA);
    HMODULE *slot = PTR(desc->ModuleHandleRVA), mod;
    IMAGE_THUNK_DATA *iat = PTR(desc->ImportAddressTableRVA), *names = PTR(desc->ImportNameTableRVA);
    ULONG_PTR index = thunk - iat;
    LPCSTR proc;
    PVOID fn = NULL;
#undef PTR
    (void)dll_hook; (void)flags;
    if (IMAGE_SNAP_BY_ORDINAL(names[index].u1.Ordinal)) proc = (LPCSTR)(ULONG_PTR)IMAGE_ORDINAL(names[index].u1.Ordinal);
    else proc = (const char *)((IMAGE_IMPORT_BY_NAME *)(rva ? b + names[index].u1.AddressOfData
                                                           : (BYTE *)(ULONG_PTR)names[index].u1.AddressOfData))->Name;
    if (!(mod = *slot)) {
        if ((mod = LoadLibraryA(dll))) {
            HMODULE prev = InterlockedCompareExchangePointer((PVOID *)slot, mod, NULL);
            if (prev) { FreeLibrary(mod); mod = prev; }
        }
    }
    if (mod) fn = (PVOID)GetProcAddress(mod, proc);
    if (!fn) fn = sys_hook ? sys_hook(dll, proc) : DelayLoadFailureHook(dll, proc);
    if (fn) thunk->u1.Function = (ULONG_PTR)fn;
    return fn;
}

/* ---------------------------------------------------------------- FormatMessage */
typedef struct { WCHAR *buf; DWORD cap, n; } outbuf;
static void ob_put(outbuf *o, WCHAR c)
{
    if (o->n + 1 >= o->cap) {
        DWORD ncap = o->cap ? o->cap * 2 : 256;
        WCHAR *nb = HeapAlloc(GetProcessHeap(), 0, ncap * sizeof(WCHAR));
        if (!nb) return;
        if (o->buf) { memcpy(nb, o->buf, o->n * sizeof(WCHAR)); HeapFree(GetProcessHeap(), 0, o->buf); }
        o->buf = nb;
        o->cap = ncap;
    }
    o->buf[o->n++] = c;
}
static void ob_str(outbuf *o, const WCHAR *s, int max) { while (*s && max--) ob_put(o, *s++); }
static void ob_astr(outbuf *o, const char *s, int max)
{
    WCHAR w[512];
    int n;
    while (*s && max) {
        int chunk = 0;
        while (s[chunk] && chunk < 200 && chunk < max) chunk++;
        n = MultiByteToWideChar(CP_ACP, 0, s, chunk, w, ARRAYSIZE(w));
        ob_str(o, w, n);
        s += chunk;
        max -= chunk;
        if (n <= 0) break;
    }
}

/* one insert with a printf-style !format! (flags - 0 + space #, width/precision numbers or *, sizes h l ll I64 w) */
static void format_insert(outbuf *o, const WCHAR *spec, int speclen, ULONG_PTR (*next)(void *), void *ctx, BOOL ansi)
{
    int left = 0, zero = 0, plus = 0, space = 0, alt = 0, width = 0, prec = -1, i = 0, is64 = 0, wide = -1;
    WCHAR conv, digits[70];
    int nd = 0, pad;
    for (; i < speclen; ++i) {
        WCHAR c = spec[i];
        if (c == '-') left = 1; else if (c == '0') zero = 1; else if (c == '+') plus = 1; else if (c == ' ') space = 1;
        else if (c == '#') alt = 1; else break;
    }
    if (i < speclen && spec[i] == '*') { width = (int)next(ctx); i++; }
    else while (i < speclen && spec[i] >= '0' && spec[i] <= '9') width = width * 10 + (spec[i++] - '0');
    if (i < speclen && spec[i] == '.') {
        prec = 0; i++;
        if (i < speclen && spec[i] == '*') { prec = (int)next(ctx); i++; }
        else while (i < speclen && spec[i] >= '0' && spec[i] <= '9') prec = prec * 10 + (spec[i++] - '0');
    }
    for (; i < speclen; ++i) {
        WCHAR c = spec[i];
        if (c == 'l') wide = 1;
        else if (c == 'w') wide = 1;
        else if (c == 'h') wide = 0;
        else if (c == 'I' && i + 2 < speclen && spec[i + 1] == '6' && spec[i + 2] == '4') { is64 = 1; i += 2; }
        else if (c == 'I') is64 = 1;
        else break;
    }
    conv = i < speclen ? spec[i] : 's';
    if (conv == 's' || conv == 'S') {
        ULONG_PTR p = next(ctx);
        int isw = wide >= 0 ? wide : (conv == 's') != ansi;      /* s = the caller's character width, S = the other */
        int len = 0, maxc = prec >= 0 ? prec : 0x7fffffff;
        if (!p) p = isw ? (ULONG_PTR)L"(null)" : (ULONG_PTR)"(null)";
        if (isw) { while (len < maxc && ((const WCHAR *)p)[len]) len++; }
        else { while (len < maxc && ((const char *)p)[len]) len++; }
        pad = width > len ? width - len : 0;
        if (!left) while (pad-- > 0) ob_put(o, ' ');
        if (isw) ob_str(o, (const WCHAR *)p, len); else ob_astr(o, (const char *)p, len);
        if (left) while (pad-- > 0) ob_put(o, ' ');
        return;
    }
    if (conv == 'c' || conv == 'C') {
        WCHAR c = (WCHAR)next(ctx);
        pad = width > 1 ? width - 1 : 0;
        if (!left) while (pad-- > 0) ob_put(o, ' ');
        ob_put(o, c);
        if (left) while (pad-- > 0) ob_put(o, ' ');
        return;
    }
    {
        ULONG_PTR raw = next(ctx);
        ULONGLONG v = is64 ? (ULONGLONG)raw : (ULONGLONG)(ULONG)raw;
        int neg = 0, base = conv == 'x' || conv == 'X' || conv == 'p' ? 16 : conv == 'o' ? 8 : 10;
        const WCHAR *hx = conv == 'X' || conv == 'p' ? L"0123456789ABCDEF" : L"0123456789abcdef";
        WCHAR pre[3] = { 0 };
        int pl = 0, zeros = 0;
        if (conv == 'p') { v = raw; if (prec < 0) prec = 16; }
        if ((conv == 'd' || conv == 'i') && (is64 ? (LONGLONG)v < 0 : (LONG)(ULONG)v < 0)) {
            neg = 1;
            v = is64 ? (ULONGLONG)(-(LONGLONG)v) : (ULONGLONG)(-(LONGLONG)(LONG)(ULONG)v);
        }
        do { digits[nd++] = hx[v % (unsigned)base]; v /= (unsigned)base; } while (v);
        if (neg) pre[pl++] = '-'; else if (plus && (conv == 'd' || conv == 'i')) pre[pl++] = '+';
        else if (space && (conv == 'd' || conv == 'i')) pre[pl++] = ' ';
        if (alt && base == 16) { pre[pl++] = '0'; pre[pl++] = conv == 'X' ? 'X' : 'x'; }
        if (prec > nd) zeros = prec - nd;
        pad = width > pl + zeros + nd ? width - pl - zeros - nd : 0;
        if (!left && !(zero && prec < 0)) while (pad-- > 0) ob_put(o, ' ');
        ob_str(o, pre, pl);
        if (!left && zero && prec < 0) while (pad-- > 0) ob_put(o, '0');
        while (zeros-- > 0) ob_put(o, '0');
        while (nd) ob_put(o, digits[--nd]);
        if (left) while (pad-- > 0) ob_put(o, ' ');
    }
}

/* On x64 a va_list is a pointer to consecutive 8-byte argument slots, so both argument forms are read as an array
 * (inserts may appear in any order, as on Windows). An insert with '*' width/precision uses the following slots. */
struct argsrc { ULONG_PTR *array; int index; int consumed; };
static ULONG_PTR next_arg(void *p)
{
    struct argsrc *a = p;
    return a->array[a->index + a->consumed++];
}

static BOOL format_text(const WCHAR *fmt, DWORD flags, va_list *va, outbuf *o, BOOL ansi)
{
    DWORD width = flags & FORMAT_MESSAGE_MAX_WIDTH_MASK;
    ULONG_PTR *array = !va ? NULL : (flags & FORMAT_MESSAGE_ARGUMENT_ARRAY) ? (ULONG_PTR *)va : (ULONG_PTR *)*va;
    while (*fmt) {
        if (*fmt == '%' && !(flags & FORMAT_MESSAGE_IGNORE_INSERTS)) {
            fmt++;
            if (*fmt >= '1' && *fmt <= '9') {
                int num = *fmt++ - '0';
                const WCHAR *spec = L"s";
                int speclen = 1;
                struct argsrc src = { array, 0, 0 };
                if (*fmt >= '0' && *fmt <= '9') num = num * 10 + (*fmt++ - '0');
                if (*fmt == '!') {
                    const WCHAR *e = fmt + 1;
                    while (*e && *e != '!') e++;
                    if (!*e) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
                    spec = fmt + 1;
                    speclen = (int)(e - fmt - 1);
                    fmt = e + 1;
                }
                if (!array) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
                src.index = num - 1;
                format_insert(o, spec, speclen, next_arg, &src, ansi);
                continue;
            }
            switch (*fmt) {
            case '0': goto done;
            case 'n': ob_put(o, '\r'); ob_put(o, '\n'); fmt++; break;
            case 'r': ob_put(o, '\r'); fmt++; break;
            case 't': ob_put(o, '\t'); fmt++; break;
            case 0: break;
            default: ob_put(o, *fmt++); break;                  /* %% %. %! %space and any other char: literal */
            }
            continue;
        }
        if (width == FORMAT_MESSAGE_MAX_WIDTH_MASK && (*fmt == '\r' || *fmt == '\n')) {
            if (*fmt == '\r' && fmt[1] == '\n') fmt++;
            ob_put(o, ' ');
            fmt++;
            continue;
        }
        if (*fmt == '\n' && (o->n == 0 || o->buf[o->n - 1] != '\r')) { ob_put(o, '\r'); ob_put(o, '\n'); fmt++; continue; }
        ob_put(o, *fmt++);
    }
done:
    ob_put(o, 0);
    return o->buf != NULL;
}

static WCHAR *message_from_module(HMODULE mod, DWORD id, DWORD lang)
{
    HRSRC r = FindResourceExW(mod, MAKEINTRESOURCEW(11) /* RT_MESSAGETABLE */, MAKEINTRESOURCEW(1), (WORD)lang);
    const BYTE *data;
    DWORD blocks, i;
    if (!r && lang) r = FindResourceExW(mod, MAKEINTRESOURCEW(11), MAKEINTRESOURCEW(1), 0);
    if (!r || !(data = LoadResource(mod, r))) return NULL;
    blocks = *(const DWORD *)data;
    for (i = 0; i < blocks; ++i) {
        const DWORD *blk = (const DWORD *)(data + 4 + i * 12);
        if (id >= blk[0] && id <= blk[1]) {
            const BYTE *e = data + blk[2];
            DWORD k;
            WORD len, flags;
            for (k = blk[0]; k < id; ++k) e += *(const WORD *)e;
            len = ((const WORD *)e)[0];
            flags = ((const WORD *)e)[1];
            if (flags & 1) {
                WCHAR *w = HeapAlloc(GetProcessHeap(), 0, len);
                if (w) { memcpy(w, e + 4, len - 4); w[(len - 4) / 2] = 0; }
                return w;
            } else {
                int n = MultiByteToWideChar(CP_ACP, 0, (const char *)e + 4, len - 4, NULL, 0);
                WCHAR *w = HeapAlloc(GetProcessHeap(), 0, (n + 1) * sizeof(WCHAR));
                if (w) { MultiByteToWideChar(CP_ACP, 0, (const char *)e + 4, len - 4, w, n); w[n] = 0; }
                return w;
            }
        }
    }
    return NULL;
}

static DWORD format_message(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPWSTR buffer, DWORD size, va_list *args, BOOL ansi)
{
    WCHAR *fmt = NULL;
    BOOL own = FALSE;
    outbuf o = { NULL, 0, 0 };
    DWORD len;
    if (!buffer) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & FORMAT_MESSAGE_FROM_STRING) fmt = (WCHAR *)source;
    else {
        if (flags & FORMAT_MESSAGE_FROM_HMODULE) fmt = message_from_module((HMODULE)source, id, lang);
        if (!fmt && (flags & FORMAT_MESSAGE_FROM_SYSTEM)) fmt = message_from_module(GetModuleHandleW(L"kernel32.dll"), id, lang);
        if (!fmt) { SetLastError(ERROR_MR_MID_NOT_FOUND); return 0; }
        own = TRUE;
    }
    if (!fmt) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (!format_text(fmt, flags, args, &o, ansi)) {
        if (own) HeapFree(GetProcessHeap(), 0, fmt);
        if (o.buf) HeapFree(GetProcessHeap(), 0, o.buf);
        return 0;
    }
    if (own) HeapFree(GetProcessHeap(), 0, fmt);
    len = o.n - 1;
    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
        DWORD alloc = o.n > size ? o.n : size;
        WCHAR *p = LocalAlloc(LMEM_FIXED, alloc * sizeof(WCHAR));
        if (!p) { HeapFree(GetProcessHeap(), 0, o.buf); SetLastError(ERROR_NOT_ENOUGH_MEMORY); return 0; }
        memcpy(p, o.buf, o.n * sizeof(WCHAR));
        *(LPWSTR *)buffer = p;
    } else {
        if (o.n > size) { HeapFree(GetProcessHeap(), 0, o.buf); SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        memcpy(buffer, o.buf, o.n * sizeof(WCHAR));
    }
    HeapFree(GetProcessHeap(), 0, o.buf);
    return len;
}

K32API DWORD WINAPI FormatMessageW(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPWSTR buffer, DWORD size, va_list *args)
{
    return format_message(flags, source, id, lang, buffer, size, args, FALSE);
}

K32API DWORD WINAPI FormatMessageA(DWORD flags, LPCVOID source, DWORD id, DWORD lang, LPSTR buffer, DWORD size, va_list *args)
{
    WCHAR *wsrc = NULL, *wout = NULL;
    DWORD n, an;
    if (!buffer) { SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    if (flags & FORMAT_MESSAGE_FROM_STRING) {
        int k = MultiByteToWideChar(CP_ACP, 0, source, -1, NULL, 0);
        if (!(wsrc = HeapAlloc(GetProcessHeap(), 0, k * sizeof(WCHAR)))) return 0;
        MultiByteToWideChar(CP_ACP, 0, source, -1, wsrc, k);
        source = wsrc;
    }
    n = format_message(flags | FORMAT_MESSAGE_ALLOCATE_BUFFER, source, id, lang, (LPWSTR)&wout, 0, args, TRUE);
    if (wsrc) HeapFree(GetProcessHeap(), 0, wsrc);
    if (!n && !wout) return 0;
    an = (DWORD)WideCharToMultiByte(CP_ACP, 0, wout, -1, NULL, 0, NULL, NULL);
    if (flags & FORMAT_MESSAGE_ALLOCATE_BUFFER) {
        char *p = LocalAlloc(LMEM_FIXED, an > size ? an : size);
        if (!p) { LocalFree(wout); return 0; }
        WideCharToMultiByte(CP_ACP, 0, wout, -1, p, an, NULL, NULL);
        *(LPSTR *)buffer = p;
    } else {
        if (an > size) { LocalFree(wout); SetLastError(ERROR_INSUFFICIENT_BUFFER); return 0; }
        WideCharToMultiByte(CP_ACP, 0, wout, -1, buffer, size, NULL, NULL);
    }
    LocalFree(wout);
    return an - 1;
}
