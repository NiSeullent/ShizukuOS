/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll: PE resources (FindResource*, LoadResource, LockResource, SizeofResource, EnumResource*), added for the
 * DLLs ported from Wine (wineport), which keep their strings, registry scripts and dialogs in resources.
 *
 * The resource directory of a mapped image is walked in place (PE/COFF specification, ".rsrc Section"): three levels
 * type -> name -> language; named entries are counted UTF-16 strings compared case-insensitively (ASCII folding, as
 * resource compilers store names upper-case); "#123" strings mean the integer id 123. An HRSRC is the address of the
 * IMAGE_RESOURCE_DATA_ENTRY; LoadResource returns the data in the image (resources are never copied or unloaded).
 * Language choice when the exact language is absent: same primary language, LANG_NEUTRAL, en-US, then the first one.
 */
#include "k32_winecompat.h"

static const IMAGE_RESOURCE_DIRECTORY *res_root(HMODULE mod, BYTE **base)
{
    const IMAGE_DOS_HEADER *dos;
    const IMAGE_NT_HEADERS64 *nt;
    const IMAGE_DATA_DIRECTORY *dir;
    if (!mod) mod = GetModuleHandleW(NULL);
    dos = (const IMAGE_DOS_HEADER *)((ULONG_PTR)mod & ~(ULONG_PTR)3);  /* LOAD_LIBRARY_AS_DATAFILE flag bits */
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (const IMAGE_NT_HEADERS64 *)((const BYTE *)dos + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_RESOURCE)
        return NULL;
    dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    if (!dir->VirtualAddress || !dir->Size) return NULL;
    *base = (BYTE *)dos;
    return (const IMAGE_RESOURCE_DIRECTORY *)((const BYTE *)dos + dir->VirtualAddress);
}

static WCHAR fold(WCHAR c) { return c >= 'a' && c <= 'z' ? (WCHAR)(c - 32) : c; }

/* integer id of a resource name/type argument, or -1 for a string name */
static int res_id(LPCWSTR name)
{
    ULONG v = 0;
    if (IS_INTRESOURCE(name)) return LOWORD((ULONG_PTR)name);
    if (name[0] != '#') return -1;
    for (name++; *name >= '0' && *name <= '9'; name++) v = v * 10 + (*name - '0');
    return *name ? -1 : (int)(v & 0xffff);
}

static const IMAGE_RESOURCE_DIRECTORY_ENTRY *dir_entries(const IMAGE_RESOURCE_DIRECTORY *d)
{
    return (const IMAGE_RESOURCE_DIRECTORY_ENTRY *)(d + 1);
}

static const IMAGE_RESOURCE_DIRECTORY_ENTRY *find_entry(const IMAGE_RESOURCE_DIRECTORY *root, const IMAGE_RESOURCE_DIRECTORY *d,
                                                        LPCWSTR name)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e = dir_entries(d);
    unsigned i, n = d->NumberOfNamedEntries + d->NumberOfIdEntries;
    int id = res_id(name);
    for (i = 0; i < n; ++i) {
        if (id >= 0) {
            if (!e[i].NameIsString && e[i].Id == (WORD)id) return &e[i];
        } else if (e[i].NameIsString) {
            const IMAGE_RESOURCE_DIR_STRING_U *s = (const void *)((const BYTE *)root + e[i].NameOffset);
            unsigned k;
            for (k = 0; k < s->Length && name[k] && fold(name[k]) == fold(s->NameString[k]); ++k) { }
            if (k == s->Length && !name[k]) return &e[i];
        }
    }
    return NULL;
}

static const IMAGE_RESOURCE_DIRECTORY *subdir(const IMAGE_RESOURCE_DIRECTORY *root, const IMAGE_RESOURCE_DIRECTORY_ENTRY *e)
{
    if (!e || !e->DataIsDirectory) return NULL;
    return (const IMAGE_RESOURCE_DIRECTORY *)((const BYTE *)root + e->OffsetToDirectory);
}

static const IMAGE_RESOURCE_DATA_ENTRY *pick_language(const IMAGE_RESOURCE_DIRECTORY *root, const IMAGE_RESOURCE_DIRECTORY *d,
                                                      WORD lang)
{
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e = dir_entries(d), *hit = NULL;
    unsigned i, n = d->NumberOfNamedEntries + d->NumberOfIdEntries;
    WORD wanted[4] = { lang, 0, 0, MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US) };
    unsigned pass;
    if (!n) return NULL;
    for (pass = 0; pass < 4 && !hit; ++pass) {
        for (i = 0; i < n && !hit; ++i) {
            if (e[i].NameIsString || e[i].DataIsDirectory) continue;
            if (pass == 1 ? (PRIMARYLANGID(e[i].Id) == PRIMARYLANGID(lang) && lang) : e[i].Id == wanted[pass]) hit = &e[i];
        }
    }
    if (!hit) for (i = 0; i < n && !hit; ++i) if (!e[i].DataIsDirectory) hit = &e[i];
    return hit ? (const IMAGE_RESOURCE_DATA_ENTRY *)((const BYTE *)root + hit->OffsetToData) : NULL;
}

K32API HRSRC WINAPI FindResourceExW(HMODULE mod, LPCWSTR type, LPCWSTR name, WORD lang)
{
    BYTE *base;
    const IMAGE_RESOURCE_DIRECTORY *root = res_root(mod, &base), *d;
    const IMAGE_RESOURCE_DATA_ENTRY *data;
    if (!root) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return NULL; }
    if (!(d = subdir(root, find_entry(root, root, type)))) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return NULL; }
    if (!(d = subdir(root, find_entry(root, d, name)))) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return NULL; }
    if (!(data = pick_language(root, d, lang))) { SetLastError(ERROR_RESOURCE_LANG_NOT_FOUND); return NULL; }
    return (HRSRC)data;
}

K32API HRSRC WINAPI FindResourceW(HMODULE mod, LPCWSTR name, LPCWSTR type)
{
    return FindResourceExW(mod, type, name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
}

static WCHAR *name_to_w(LPCSTR a)
{
    int n;
    WCHAR *w;
    if (IS_INTRESOURCE(a)) return (WCHAR *)a;
    n = MultiByteToWideChar(CP_ACP, 0, a, -1, NULL, 0);
    if (!(w = HeapAlloc(GetProcessHeap(), 0, n * sizeof(WCHAR)))) return NULL;
    MultiByteToWideChar(CP_ACP, 0, a, -1, w, n);
    return w;
}
static void name_free(const WCHAR *w, LPCSTR a) { if (!IS_INTRESOURCE(a) && w) HeapFree(GetProcessHeap(), 0, (void *)w); }

K32API HRSRC WINAPI FindResourceExA(HMODULE mod, LPCSTR type, LPCSTR name, WORD lang)
{
    WCHAR *t = name_to_w(type), *n = name_to_w(name);
    HRSRC r = (t && n) ? FindResourceExW(mod, t, n, lang) : NULL;
    name_free(t, type);
    name_free(n, name);
    return r;
}
K32API HRSRC WINAPI FindResourceA(HMODULE mod, LPCSTR name, LPCSTR type)
{
    return FindResourceExA(mod, type, name, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));
}

K32API HGLOBAL WINAPI LoadResource(HMODULE mod, HRSRC res)
{
    BYTE *base;
    if (!res) return NULL;
    if (!res_root(mod, &base)) return NULL;
    return (HGLOBAL)(base + ((const IMAGE_RESOURCE_DATA_ENTRY *)res)->OffsetToData);
}
K32API LPVOID WINAPI LockResource(HGLOBAL h) { return h; }
K32API BOOL WINAPI FreeResource(HGLOBAL h) { (void)h; return FALSE; }
K32API DWORD WINAPI SizeofResource(HMODULE mod, HRSRC res)
{
    (void)mod;
    if (!res) { SetLastError(ERROR_INVALID_HANDLE); return 0; }
    return ((const IMAGE_RESOURCE_DATA_ENTRY *)res)->Size;
}

/* ---------------------------------------------------------------- enumeration */
/* entry name as the callback sees it: MAKEINTRESOURCE(id) or a temporary NUL-terminated copy of the string */
static LPWSTR entry_name(const IMAGE_RESOURCE_DIRECTORY *root, const IMAGE_RESOURCE_DIRECTORY_ENTRY *e, WCHAR *buf, size_t cap)
{
    const IMAGE_RESOURCE_DIR_STRING_U *s;
    size_t n;
    if (!e->NameIsString) return MAKEINTRESOURCEW(e->Id);
    s = (const void *)((const BYTE *)root + e->NameOffset);
    n = s->Length < cap - 1 ? s->Length : cap - 1;
    memcpy(buf, s->NameString, n * sizeof(WCHAR));
    buf[n] = 0;
    return buf;
}

K32API BOOL WINAPI EnumResourceTypesW(HMODULE mod, ENUMRESTYPEPROCW fn, LONG_PTR param)
{
    BYTE *base;
    const IMAGE_RESOURCE_DIRECTORY *root = res_root(mod, &base);
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    WCHAR buf[256];
    unsigned i, n;
    if (!root) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
    e = dir_entries(root);
    n = root->NumberOfNamedEntries + root->NumberOfIdEntries;
    for (i = 0; i < n; ++i) if (!fn(mod, entry_name(root, &e[i], buf, ARRAYSIZE(buf)), param)) break;
    return TRUE;
}

K32API BOOL WINAPI EnumResourceNamesW(HMODULE mod, LPCWSTR type, ENUMRESNAMEPROCW fn, LONG_PTR param)
{
    BYTE *base;
    const IMAGE_RESOURCE_DIRECTORY *root = res_root(mod, &base), *d;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    WCHAR buf[256];
    unsigned i, n;
    if (!root) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
    if (!(d = subdir(root, find_entry(root, root, type)))) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
    e = dir_entries(d);
    n = d->NumberOfNamedEntries + d->NumberOfIdEntries;
    for (i = 0; i < n; ++i) if (!fn(mod, type, entry_name(root, &e[i], buf, ARRAYSIZE(buf)), param)) break;
    return TRUE;
}

K32API BOOL WINAPI EnumResourceLanguagesW(HMODULE mod, LPCWSTR type, LPCWSTR name, ENUMRESLANGPROCW fn, LONG_PTR param)
{
    BYTE *base;
    const IMAGE_RESOURCE_DIRECTORY *root = res_root(mod, &base), *d;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *e;
    unsigned i, n;
    if (!root) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
    if (!(d = subdir(root, find_entry(root, root, type)))) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
    if (!(d = subdir(root, find_entry(root, d, name)))) { SetLastError(ERROR_RESOURCE_NAME_NOT_FOUND); return FALSE; }
    e = dir_entries(d);
    n = d->NumberOfNamedEntries + d->NumberOfIdEntries;
    for (i = 0; i < n; ++i) if (!e[i].NameIsString && !fn(mod, type, name, e[i].Id, param)) break;
    return TRUE;
}

struct enum_a { void *fn; LONG_PTR param; };
static char *name_to_a(LPCWSTR w, char *buf, int cap)
{
    if (IS_INTRESOURCE(w)) return (char *)w;
    WideCharToMultiByte(CP_ACP, 0, w, -1, buf, cap, NULL, NULL);
    buf[cap - 1] = 0;
    return buf;
}
static BOOL CALLBACK names_a_thunk(HMODULE mod, LPCWSTR type, LPWSTR name, LONG_PTR p)
{
    struct enum_a *e = (struct enum_a *)p;
    char tb[256], nb[256];
    return ((ENUMRESNAMEPROCA)e->fn)(mod, name_to_a(type, tb, sizeof tb), name_to_a(name, nb, sizeof nb), e->param);
}
K32API BOOL WINAPI EnumResourceNamesA(HMODULE mod, LPCSTR type, ENUMRESNAMEPROCA fn, LONG_PTR param)
{
    struct enum_a e = { (void *)fn, param };
    WCHAR *t = name_to_w(type);
    BOOL r = t ? EnumResourceNamesW(mod, t, names_a_thunk, (LONG_PTR)&e) : FALSE;
    name_free(t, type);
    return r;
}
static BOOL CALLBACK types_a_thunk(HMODULE mod, LPWSTR type, LONG_PTR p)
{
    struct enum_a *e = (struct enum_a *)p;
    char tb[256];
    return ((ENUMRESTYPEPROCA)e->fn)(mod, name_to_a(type, tb, sizeof tb), e->param);
}
K32API BOOL WINAPI EnumResourceTypesA(HMODULE mod, ENUMRESTYPEPROCA fn, LONG_PTR param)
{
    struct enum_a e = { (void *)fn, param };
    return EnumResourceTypesW(mod, types_a_thunk, (LONG_PTR)&e);
}
