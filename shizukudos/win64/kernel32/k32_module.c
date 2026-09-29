/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: module handles and enumeration (GetModuleHandleEx, PSAPI module functions of the current process) and PE
 * resource access (FindResource, LoadResource, LockResource, SizeofResource, EnumResource*).
 *
 * Modules come from the loader database in the PEB (InLoadOrderModuleList), the same list Kernel64 publishes and ntdll walks.
 * PSAPI calls are answered for the calling process only: reading another process' loader data would need cross-process memory
 * access, so such handles fail with ERROR_NOT_SUPPORTED instead of returning invented data.
 *
 * Resources are read straight from the mapped image (an HRSRC is a pointer to the IMAGE_RESOURCE_DATA_ENTRY, an HGLOBAL from
 * LoadResource is the data pointer, exactly as for images loaded by the system loader). Language lookup: an explicit language must
 * match exactly (ERROR_RESOURCE_LANG_NOT_FOUND otherwise); LANG_NEUTRAL tries en-US, then neutral, then the first language present.
 */
#include "k32.h"
#include <psapi.h>

NTSTATUS NTAPI LdrAddRefDll(ULONG flags, PVOID base);
#define LDR_ADDREF_DLL_PIN 1
#define MAKEINTRES(i) ((LPWSTR)(ULONG_PTR)(WORD)(i))

/* ---------------------------------------------------------------- module database */
static SHZ_LDR_ENTRY *find_entry(HMODULE m)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    if (!m) m = PEB_IMAGE_BASE(shz_peb());
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if (e->DllBase == m) return e;
    }
    return 0;
}

static SHZ_LDR_ENTRY *find_entry_by_address(const void *addr)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if ((const uint8_t *)addr >= (const uint8_t *)e->DllBase && (const uint8_t *)addr < (const uint8_t *)e->DllBase + e->SizeOfImage) return e;
    }
    return 0;
}

static BOOL get_module_handle_ex(DWORD flags, LPCWSTR name, HMODULE *out)
{
    HMODULE h;
    const DWORD known = GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS;
    if (out) *out = 0;
    if (!out || (flags & ~known) ||
        ((flags & GET_MODULE_HANDLE_EX_FLAG_PIN) && (flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT))) {
        shz_set_last_error(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    if (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) {
        SHZ_LDR_ENTRY *e = find_entry_by_address(name);
        if (!e) { shz_set_last_error(ERROR_MOD_NOT_FOUND); return FALSE; }
        h = e->DllBase;
    } else if (!name) {
        *out = PEB_IMAGE_BASE(shz_peb());                                 /* the executable: no reference count applies */
        return TRUE;
    } else {
        h = GetModuleHandleW(name);
        if (!h) return FALSE;                                             /* GetModuleHandleW set ERROR_MOD_NOT_FOUND */
    }
    if (!(flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT)) {
        const NTSTATUS st = LdrAddRefDll((flags & GET_MODULE_HANDLE_EX_FLAG_PIN) ? LDR_ADDREF_DLL_PIN : 0, h);
        if (st) { k32_nt_error(st); return FALSE; }
    }
    *out = h;
    return TRUE;
}

K32API BOOL WINAPI GetModuleHandleExW(DWORD flags, LPCWSTR name, HMODULE *out) { return get_module_handle_ex(flags, name, out); }
K32API BOOL WINAPI GetModuleHandleExA(DWORD flags, LPCSTR name, HMODULE *out)
{
    WCHAR w[260];
    if ((flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) || !name) return get_module_handle_ex(flags, (LPCWSTR)name, out);
    if (k32_utf8_to_wide(name, -1, w, 260) <= 0) { if (out) *out = 0; shz_set_last_error(ERROR_INVALID_NAME); return FALSE; }
    return get_module_handle_ex(flags, w, out);
}

K32API VOID WINAPI FreeLibraryAndExitThread(HMODULE m, DWORD code)
{
    FreeLibrary(m);
    ExitThread(code);
}

/* ---------------------------------------------------------------- PSAPI (current process) */
static int is_current_process(HANDLE h)
{
    struct { LONG64 es; ULONG64 peb, aff; LONG64 prio; ULONG64 pid, ppid; } b;
    if (h == CURRENT_PROCESS) return 1;
    if (NtQueryInformationProcess(h, 0, &b, sizeof b, 0)) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    if (b.pid != shz_pid()) { shz_set_last_error(ERROR_NOT_SUPPORTED); return 0; }
    return 1;
}

K32API BOOL WINAPI K32GetModuleInformation(HANDLE proc, HMODULE m, LPMODULEINFO info, DWORD cb)
{
    SHZ_LDR_ENTRY *e;
    if (!is_current_process(proc)) return FALSE;
    if (cb < sizeof(MODULEINFO)) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    e = find_entry(m);
    if (!e || !m) { shz_set_last_error(ERROR_INVALID_HANDLE); return FALSE; }
    info->lpBaseOfDll = e->DllBase;
    info->SizeOfImage = e->SizeOfImage;
    info->EntryPoint = e->EntryPoint;
    return TRUE;
}

/* A view of a module's path: the whole FullDllName, or its last component. The base name is taken from the full name, not from the
 * loader's BaseDllName, so it has the case of the file name as stored (Kernel64 keeps BaseDllName lower-cased for lookups). */
typedef void (*pick_fn)(const SHZ_LDR_ENTRY *, const WCHAR **, DWORD *);
static void pick_full(const SHZ_LDR_ENTRY *e, const WCHAR **s, DWORD *n) { *s = e->FullDllName.Buffer; *n = e->FullDllName.Length / 2; }
static void pick_base(const SHZ_LDR_ENTRY *e, const WCHAR **s, DWORD *n)
{
    DWORD len = e->FullDllName.Length / 2, i = len;
    const WCHAR *full = e->FullDllName.Buffer;
    while (i && full[i - 1] != '\\' && full[i - 1] != '/') --i;
    *s = full + i;
    *n = len - i;
}

static DWORD module_string(HANDLE proc, HMODULE m, pick_fn pick, LPWSTR buf, DWORD cap)
{
    const SHZ_LDR_ENTRY *e;
    const WCHAR *s;
    DWORD n;
    if (!is_current_process(proc)) return 0;
    e = find_entry(m);
    if (!e) { shz_set_last_error(ERROR_INVALID_HANDLE); return 0; }
    pick(e, &s, &n);
    if (n >= cap) {
        if (cap) { memcpy(buf, s, (cap - 1) * sizeof(WCHAR)); buf[cap - 1] = 0; }
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return cap ? cap - 1 : 0;
    }
    memcpy(buf, s, n * sizeof(WCHAR));
    buf[n] = 0;
    return n;
}

K32API DWORD WINAPI K32GetModuleFileNameExW(HANDLE proc, HMODULE m, LPWSTR buf, DWORD cap) { return module_string(proc, m, pick_full, buf, cap); }
K32API DWORD WINAPI K32GetModuleBaseNameW(HANDLE proc, HMODULE m, LPWSTR buf, DWORD cap) { return module_string(proc, m, pick_base, buf, cap); }

static DWORD module_string_a(HANDLE proc, HMODULE m, pick_fn pick, LPSTR buf, DWORD cap)
{
    WCHAR w[300];
    DWORD n = module_string(proc, m, pick, w, 300);
    int r;
    if (!n) return 0;
    if (!cap) { shz_set_last_error(ERROR_INSUFFICIENT_BUFFER); return 0; }
    r = k32_wide_to_utf8(w, (int)n + 1, buf, (int)cap);
    if (r <= 0) {                                                        /* truncate at a character boundary */
        char tmp[900];
        int len = k32_wide_to_utf8(w, (int)n, tmp, sizeof tmp);
        if (len > (int)cap - 1) len = (int)cap - 1;
        while (len > 0 && ((unsigned char)tmp[len] & 0xc0) == 0x80) --len;
        memcpy(buf, tmp, (size_t)len);
        buf[len] = 0;
        shz_set_last_error(ERROR_INSUFFICIENT_BUFFER);
        return (DWORD)len;
    }
    return (DWORD)r - 1;
}
K32API DWORD WINAPI K32GetModuleFileNameExA(HANDLE proc, HMODULE m, LPSTR buf, DWORD cap) { return module_string_a(proc, m, pick_full, buf, cap); }
K32API DWORD WINAPI K32GetModuleBaseNameA(HANDLE proc, HMODULE m, LPSTR buf, DWORD cap) { return module_string_a(proc, m, pick_base, buf, cap); }

K32API BOOL WINAPI K32EnumProcessModulesEx(HANDLE proc, HMODULE *mods, DWORD cb, LPDWORD needed, DWORD filter)
{
    SHZ_PEB_LDR_DATA *ldr = PEB_LDR(shz_peb());
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList, *l;
    DWORD count = 0;
    if (!is_current_process(proc)) return FALSE;
    if (filter > LIST_MODULES_ALL) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!needed) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (filter == LIST_MODULES_32BIT) { *needed = 0; return TRUE; }       /* a 64-bit process has no 32-bit modules */
    for (l = head->Flink; l != head; l = l->Flink) {
        SHZ_LDR_ENTRY *e = CONTAINING_RECORD(l, SHZ_LDR_ENTRY, InLoadOrderLinks);
        if ((count + 1) * sizeof(HMODULE) <= cb && mods) mods[count] = e->DllBase;
        ++count;
    }
    *needed = count * (DWORD)sizeof(HMODULE);
    return TRUE;
}
K32API BOOL WINAPI K32EnumProcessModules(HANDLE proc, HMODULE *mods, DWORD cb, LPDWORD needed)
{
    return K32EnumProcessModulesEx(proc, mods, cb, needed, LIST_MODULES_DEFAULT);
}

/* ---------------------------------------------------------------- resources */
#define RES_DIR(base, va) ((IMAGE_RESOURCE_DIRECTORY *)((uint8_t *)(base) + (va)))

typedef struct { const uint8_t *base, *rsrc; DWORD size; } res_ctx;

static int res_open(HMODULE m, res_ctx *c)
{
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *d;
    if (!m) m = PEB_IMAGE_BASE(shz_peb());
    dos = (const IMAGE_DOS_HEADER *)m;
    if (!m || dos->e_magic != IMAGE_DOS_SIGNATURE) { shz_set_last_error(ERROR_BAD_EXE_FORMAT); return 0; }
    nt = (const IMAGE_NT_HEADERS64 *)((const uint8_t *)m + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { shz_set_last_error(ERROR_BAD_EXE_FORMAT); return 0; }
    d = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!d->VirtualAddress || !d->Size) { shz_set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND); return 0; }
    c->base = (const uint8_t *)m;
    c->rsrc = c->base + d->VirtualAddress;
    c->size = d->Size;
    return 1;
}

static int wide_ieq(const WCHAR *a, const WCHAR *b, int n)
{
    int i;
    for (i = 0; i < n; ++i) {
        WCHAR x = a[i], y = b[i];
        if (x >= 'a' && x <= 'z') x -= 32;
        if (y >= 'a' && y <= 'z') y -= 32;
        if (x != y) return 0;
    }
    return 1;
}

/* Resolves an id or name (MAKEINTRESOURCE or a string, with "#123" meaning the integer 123) to a directory entry. */
static const IMAGE_RESOURCE_DIRECTORY_ENTRY *dir_find(const res_ctx *c, const IMAGE_RESOURCE_DIRECTORY *dir, LPCWSTR key)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(dir + 1);
    unsigned i;
    int as_id = 0;
    ULONG_PTR id = 0;
    if ((ULONG_PTR)key >> 16 == 0) { as_id = 1; id = (ULONG_PTR)key; }
    else if (key[0] == '#') {
        const WCHAR *p = key + 1;
        int ok = *p != 0;
        ULONG_PTR v = 0;
        for (; *p; ++p) { if (*p < '0' || *p > '9') { ok = 0; break; } v = v * 10 + (ULONG_PTR)(*p - '0'); }
        if (ok && v <= 0xffff) { as_id = 1; id = v; }
    }
    if (as_id) {
        for (i = dir->NumberOfNamedEntries; i < (unsigned)dir->NumberOfNamedEntries + dir->NumberOfIdEntries; ++i)
            if (!e[i].NameIsString && e[i].Id == id) return &e[i];
        return 0;
    }
    {
        size_t klen = k32_wlen(key);
        for (i = 0; i < dir->NumberOfNamedEntries; ++i) {
            const IMAGE_RESOURCE_DIR_STRING_U *s;
            if (!e[i].NameIsString) continue;
            s = (const IMAGE_RESOURCE_DIR_STRING_U *)(c->rsrc + e[i].NameOffset);
            if (s->Length == klen && wide_ieq(s->NameString, key, (int)klen)) return &e[i];
        }
    }
    return 0;
}

static const IMAGE_RESOURCE_DIRECTORY *sub_dir(const res_ctx *c, const IMAGE_RESOURCE_DIRECTORY_ENTRY *e)
{
    return e->DataIsDirectory ? (const IMAGE_RESOURCE_DIRECTORY *)(c->rsrc + e->OffsetToDirectory) : 0;
}

static HRSRC find_resource(HMODULE m, LPCWSTR name, LPCWSTR type, WORD lang)
{
    res_ctx c;
    const IMAGE_RESOURCE_DIRECTORY *root, *tdir, *ndir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *te, *ne, *le;
    unsigned i;
    if (!res_open(m, &c)) return 0;
    root = (const IMAGE_RESOURCE_DIRECTORY *)c.rsrc;
    te = dir_find(&c, root, type);
    if (!te || !(tdir = sub_dir(&c, te))) { shz_set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND); return 0; }
    ne = dir_find(&c, tdir, name);
    if (!ne || !(ndir = sub_dir(&c, ne))) { shz_set_last_error(ERROR_RESOURCE_NAME_NOT_FOUND); return 0; }
    le = 0;
    if (lang) {
        le = dir_find(&c, ndir, MAKEINTRES(lang));
        if (!le) { shz_set_last_error(ERROR_RESOURCE_LANG_NOT_FOUND); return 0; }
    } else {
        le = dir_find(&c, ndir, MAKEINTRES(0x0409));
        if (!le) le = dir_find(&c, ndir, MAKEINTRES(0));
        if (!le) {
            const IMAGE_RESOURCE_DIRECTORY_ENTRY *all = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ndir + 1);
            const unsigned n = (unsigned)ndir->NumberOfNamedEntries + ndir->NumberOfIdEntries;
            for (i = 0; i < n; ++i) if (!all[i].DataIsDirectory) { le = &all[i]; break; }
        }
        if (!le) { shz_set_last_error(ERROR_RESOURCE_LANG_NOT_FOUND); return 0; }
    }
    if (le->DataIsDirectory) { shz_set_last_error(ERROR_RESOURCE_DATA_NOT_FOUND); return 0; }
    return (HRSRC)(c.rsrc + le->OffsetToData);
}

K32API HRSRC WINAPI FindResourceExW(HMODULE m, LPCWSTR type, LPCWSTR name, WORD lang) { return find_resource(m, name, type, lang); }
K32API HRSRC WINAPI FindResourceW(HMODULE m, LPCWSTR name, LPCWSTR type) { return find_resource(m, name, type, 0); }

static const WCHAR *widen_arg(LPCSTR s, WCHAR *buf, int cap)
{
    if ((ULONG_PTR)s >> 16 == 0) return (const WCHAR *)s;
    if (k32_utf8_to_wide(s, -1, buf, cap) <= 0) return 0;
    return buf;
}
K32API HRSRC WINAPI FindResourceExA(HMODULE m, LPCSTR type, LPCSTR name, WORD lang)
{
    WCHAR wt[128], wn[128];
    const WCHAR *t = widen_arg(type, wt, 128), *n = widen_arg(name, wn, 128);
    if (!t || !n) { shz_set_last_error(ERROR_INVALID_NAME); return 0; }
    return find_resource(m, n, t, lang);
}
K32API HRSRC WINAPI FindResourceA(HMODULE m, LPCSTR name, LPCSTR type) { return FindResourceExA(m, type, name, 0); }

K32API HGLOBAL WINAPI LoadResource(HMODULE m, HRSRC r)
{
    const IMAGE_RESOURCE_DATA_ENTRY *d = (const IMAGE_RESOURCE_DATA_ENTRY *)r;
    if (!m) m = PEB_IMAGE_BASE(shz_peb());
    if (!r) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return (HGLOBAL)((const uint8_t *)m + d->OffsetToData);
}
K32API LPVOID WINAPI LockResource(HGLOBAL h) { return h; }
K32API DWORD WINAPI SizeofResource(HMODULE m, HRSRC r)
{
    (void)m;
    if (!r) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    return ((const IMAGE_RESOURCE_DATA_ENTRY *)r)->Size;
}

/* Enumeration: the callbacks receive MAKEINTRESOURCE values for integer ids and pointers to NUL-terminated copies of the names. */
static LPWSTR entry_name(const res_ctx *c, const IMAGE_RESOURCE_DIRECTORY_ENTRY *e, WCHAR *buf, int cap)
{
    if (!e->NameIsString) return MAKEINTRES(e->Id);
    {
        const IMAGE_RESOURCE_DIR_STRING_U *s = (const IMAGE_RESOURCE_DIR_STRING_U *)(c->rsrc + e->NameOffset);
        int n = s->Length < cap - 1 ? s->Length : cap - 1;
        memcpy(buf, s->NameString, (size_t)n * sizeof(WCHAR));
        buf[n] = 0;
        return buf;
    }
}

K32API BOOL WINAPI EnumResourceTypesW(HMODULE m, ENUMRESTYPEPROCW proc, LONG_PTR lparam)
{
    res_ctx c;
    const IMAGE_RESOURCE_DIRECTORY *root;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    unsigned i, n;
    WCHAR name[256];
    if (!proc) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!res_open(m, &c)) return FALSE;
    root = (const IMAGE_RESOURCE_DIRECTORY *)c.rsrc;
    e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(root + 1);
    n = (unsigned)root->NumberOfNamedEntries + root->NumberOfIdEntries;
    for (i = 0; i < n; ++i)
        if (!proc(m ? m : PEB_IMAGE_BASE(shz_peb()), entry_name(&c, &e[i], name, 256), lparam)) return FALSE;
    return TRUE;
}

K32API BOOL WINAPI EnumResourceNamesW(HMODULE m, LPCWSTR type, ENUMRESNAMEPROCW proc, LONG_PTR lparam)
{
    res_ctx c;
    const IMAGE_RESOURCE_DIRECTORY *tdir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *te, *e;
    unsigned i, n;
    WCHAR name[256];
    if (!proc) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!res_open(m, &c)) return FALSE;
    te = dir_find(&c, (const IMAGE_RESOURCE_DIRECTORY *)c.rsrc, type);
    if (!te || !(tdir = sub_dir(&c, te))) { shz_set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
    e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(tdir + 1);
    n = (unsigned)tdir->NumberOfNamedEntries + tdir->NumberOfIdEntries;
    for (i = 0; i < n; ++i)
        if (!proc(m ? m : PEB_IMAGE_BASE(shz_peb()), (LPWSTR)type, entry_name(&c, &e[i], name, 256), lparam)) return FALSE;
    return TRUE;
}

K32API BOOL WINAPI EnumResourceLanguagesW(HMODULE m, LPCWSTR type, LPCWSTR name, ENUMRESLANGPROCW proc, LONG_PTR lparam)
{
    res_ctx c;
    const IMAGE_RESOURCE_DIRECTORY *tdir, *ndir;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *te, *ne, *e;
    unsigned i, n;
    if (!proc) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!res_open(m, &c)) return FALSE;
    te = dir_find(&c, (const IMAGE_RESOURCE_DIRECTORY *)c.rsrc, type);
    if (!te || !(tdir = sub_dir(&c, te))) { shz_set_last_error(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
    ne = dir_find(&c, tdir, name);
    if (!ne || !(ndir = sub_dir(&c, ne))) { shz_set_last_error(ERROR_RESOURCE_NAME_NOT_FOUND); return FALSE; }
    e = (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(ndir + 1);
    n = (unsigned)ndir->NumberOfNamedEntries + ndir->NumberOfIdEntries;
    for (i = 0; i < n; ++i)
        if (!proc(m ? m : PEB_IMAGE_BASE(shz_peb()), (LPWSTR)type, (LPWSTR)name, e[i].NameIsString ? 0 : (WORD)e[i].Id, lparam)) return FALSE;
    return TRUE;
}

/* ANSI enumeration converts each name for the callback. */
typedef struct { ENUMRESNAMEPROCA proc; LONG_PTR lparam; LPCSTR type; } enum_a_ctx;
static BOOL CALLBACK enum_names_thunk(HMODULE m, LPCWSTR type, LPWSTR name, LONG_PTR lp)
{
    enum_a_ctx *x = (enum_a_ctx *)lp;
    char a[600];
    (void)type;
    if ((ULONG_PTR)name >> 16 == 0) return x->proc(m, x->type, (LPSTR)name, x->lparam);
    if (k32_wide_to_utf8(name, -1, a, sizeof a) <= 0) return TRUE;
    return x->proc(m, x->type, a, x->lparam);
}
K32API BOOL WINAPI EnumResourceNamesA(HMODULE m, LPCSTR type, ENUMRESNAMEPROCA proc, LONG_PTR lparam)
{
    WCHAR wt[128];
    enum_a_ctx x = { proc, lparam, type };
    const WCHAR *t = widen_arg(type, wt, 128);
    if (!t || !proc) { shz_set_last_error(!proc ? ERROR_INVALID_PARAMETER : ERROR_INVALID_NAME); return FALSE; }
    return EnumResourceNamesW(m, t, (ENUMRESNAMEPROCW)enum_names_thunk, (LONG_PTR)&x);
}
