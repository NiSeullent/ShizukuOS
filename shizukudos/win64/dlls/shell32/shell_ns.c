/* SPDX-License-Identifier: GPL-2.0-only
 * shell32.dll - the shell namespace functions Chromium/Electron delay-load, over what exists here: the file systems
 * Kernel64 mounts, the user32 window manager, the COM class table of ole32 and propsys' in-memory property stores.
 * There is no Explorer process, no notification area, no file-type associations and no icon library, and none of that
 * is imitated: the corresponding calls fail with the code Windows documents for the missing piece.
 *
 * Item ID lists (PIDLs): the shell's PIDL format is opaque to programs (only the shell functions interpret it), so this
 * DLL uses its own: one SHITEMID per path component, cb = 2 + the UTF-16 component with its NUL, a 2-byte terminator.
 * ILCreateFromPathW/A, SHSimpleIDListFromPath, SHParseDisplayName, SHGetSpecialFolderLocation/SHGetFolderLocation/
 * SHGetKnownFolderIDList build them (a path that does not exist is ERROR_FILE_NOT_FOUND, as on Windows, except
 * SHSimpleIDListFromPath, which is documented not to check), SHGetPathFromIDListW / SHGetNameFromIDList read them back,
 * and the IL* helpers (ILClone, ILCloneFirst, ILCombine, ILFindLastID, ILGetNext, ILGetSize, ILIsEqual, ILIsParent,
 * ILRemoveLastID, ILAppendID, ILFree) work on them with their documented semantics; the pinned ordinals are Windows'.
 * SHCreateItemFromParsingName / SHCreateItemFromIDList: an IShellItem over a file-system path (GetDisplayName for
 * SIGDN_FILESYSPATH, DESKTOPABSOLUTEPARSING, the PARENTRELATIVE forms, NORMALDISPLAY, GetAttributes from the file attributes,
 * GetParent, Compare, BindToHandler E_NOINTERFACE), the only namespace there is.
 * SHGetFileInfoW: attributes, display name and type name of a file (SHGFI_ATTRIBUTES/DISPLAYNAME/TYPENAME, and
 * SHGFI_USEFILEATTRIBUTES); icon requests fail (no icon library: hIcon NULL, return 0).
 * DragQueryFileW/DragQueryPoint/DragFinish: the documented HDROP (DROPFILES) layout.
 * SHChangeNotifyRegister/Deregister (ordinals 2/4) keep a table; SHChangeNotify posts the registered message to the
 * windows whose event mask matches (that is all the shell does with it; no Explorer is listening besides).
 * SHGetPropertyStoreForWindow: one propsys in-memory store per window, kept while the window exists.
 * IsUserAnAdmin: the token's Administrators membership (advapi32 CheckTokenMembership).
 * SHQueryUserNotificationState: QUNS_ACCEPTS_NOTIFICATIONS (a user is at the console, nothing is full-screen or locked).
 * ShellExecuteW/A/ExW: an executable (or a file whose name ends in .exe/.com/.bat is not run - only PE images) is started
 * with CreateProcessW for the "open"/"runas"/NULL verbs; everything else needs a file-type association that does not exist:
 * SE_ERR_NOASSOC (ShellExecute) / FALSE + ERROR_NO_ASSOCIATION (ShellExecuteEx); a missing file is SE_ERR_FNF / ERROR_FILE_NOT_FOUND.
 * Shell_NotifyIconW, SHAppBarMessage: FALSE / 0 - there is no notification area and no taskbar (ERROR_NOT_SUPPORTED).
 * SHGetDesktopFolder: E_FAIL (documented failure; no IShellFolder namespace). SHGetStockIconInfo:
 * HRESULT_FROM_WIN32(ERROR_RESOURCE_TYPE_NOT_FOUND) (no icon resources). SHOpenFolderAndSelectItems:
 * HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED) (no Explorer window can open). SHCreateAssociationRegistration: the COM class
 * CLSID_ApplicationAssociationRegistration is not registered: REGDB_E_CLASSNOTREG (via CoCreateInstance).
 */
/* mingw's shlobj.h/shellapi.h declare the shell functions DECLSPEC_IMPORT; this file defines them, so the
 * "redeclared without dllimport" note is expected and silenced here only. */
#pragma GCC diagnostic ignored "-Wattributes"
#define _SHELL32_                                   /* this is shell32: SHGetFolderPathW etc. are local, not __imp_ */
#include "nt.h"
#include <string.h>
#define COBJMACROS
#include <objbase.h>
#include <shlobj.h>
#include <shellapi.h>
#include <propsys.h>
#include "shz_wupper.h"

#define E_INVALIDARG_ ((HRESULT)0x80070057)
#define E_OUTOFMEMORY_ ((HRESULT)0x8007000E)
#define E_NOINTERFACE_ ((HRESULT)0x80004002)
#define E_POINTER_ ((HRESULT)0x80004003)
#define E_FAIL_ ((HRESULT)0x80004005)
#define HR_FROM_WIN32(e) ((HRESULT)(0x80070000u | (e)))


static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int wieq(const WCHAR *a, const WCHAR *b) { while (*a && shz_wupper(*a) == shz_wupper(*b)) { ++a; ++b; } return *a == *b; }

/* ================================================================ PIDLs */
static LPITEMIDLIST il_alloc(SIZE_T n) { return CoTaskMemAlloc(n); }

/* the path -> PIDL builder: "C:\a\b" -> ["C:", "a", "b"]; a UNC "\\srv\share\x" -> ["\\srv", "share", "x"] */
static LPITEMIDLIST il_from_path(const WCHAR *path)
{
    size_t n = wlen(path), i, start = 0, total = 2;
    LPITEMIDLIST il;
    BYTE *p;
    if (!n) return 0;
    for (i = 0; i <= n; ++i) {                       /* measure */
        if (i == n || path[i] == '\\' || path[i] == '/') {
            if (i > start || (i == start && start == 0)) total += 2 + (i - start + 1) * 2;
            start = i + 1;
        }
    }
    il = il_alloc(total);
    if (!il) return 0;
    p = (BYTE *)il;
    start = 0;
    for (i = 0; i <= n; ++i) {
        if (i == n || path[i] == '\\' || path[i] == '/') {
            if (i > start || (i == start && start == 0)) {
                USHORT cb = (USHORT)(2 + (i - start + 1) * 2);
                *(USHORT *)p = cb;
                memcpy(p + 2, path + start, (i - start) * 2);
                *(WCHAR *)(p + 2 + (i - start) * 2) = 0;
                p += cb;
            }
            start = i + 1;
        }
    }
    *(USHORT *)p = 0;
    return il;
}

static const WCHAR *il_text(LPCITEMIDLIST id) { return (const WCHAR *)((const BYTE *)id + 2); }
static LPCITEMIDLIST il_next(LPCITEMIDLIST id) { return (LPCITEMIDLIST)((const BYTE *)id + id->mkid.cb); }

/* PIDL -> path; returns the character count without the NUL, or 0 for an empty/invalid list */
static size_t il_to_path(LPCITEMIDLIST il, WCHAR *out, size_t cap)
{
    size_t n = 0;
    int first = 1;
    if (!il) return 0;
    while (il->mkid.cb) {
        const WCHAR *t = il_text(il);
        size_t k = wlen(t);
        if (il->mkid.cb < 4 || il->mkid.cb != 2 + (k + 1) * 2) return 0;
        if (!first) { if (out && n + 1 < cap) out[n] = '\\'; ++n; }
        if (out && n + k < cap) memcpy(out + n, t, k * 2);
        n += k;
        first = 0;
        il = il_next(il);
    }
    if (out) out[n < cap ? n : cap - 1] = 0;
    return n;
}

DLLAPI void WINAPI ILFree(LPITEMIDLIST il) { if (il) CoTaskMemFree(il); }

DLLAPI UINT WINAPI ILGetSize(LPCITEMIDLIST il)
{
    UINT n = 0;
    if (!il) return 0;
    while (il->mkid.cb) { n += il->mkid.cb; il = il_next(il); }
    return n + 2;
}

DLLAPI LPITEMIDLIST WINAPI ILClone(LPCITEMIDLIST il)
{
    UINT n = ILGetSize(il);
    LPITEMIDLIST c;
    if (!il) return 0;
    c = il_alloc(n);
    if (c) memcpy(c, il, n);
    return c;
}

DLLAPI LPITEMIDLIST WINAPI ILCloneFirst(LPCITEMIDLIST il)
{
    LPITEMIDLIST c;
    if (!il || !il->mkid.cb) return 0;
    c = il_alloc(il->mkid.cb + 2);
    if (!c) return 0;
    memcpy(c, il, il->mkid.cb);
    *(USHORT *)((BYTE *)c + il->mkid.cb) = 0;
    return c;
}

DLLAPI LPITEMIDLIST WINAPI ILGetNext(LPCITEMIDLIST il)
{
    if (!il || !il->mkid.cb) return 0;
    il = il_next(il);
    return il->mkid.cb ? (LPITEMIDLIST)il : 0;
}

DLLAPI LPITEMIDLIST WINAPI ILFindLastID(LPCITEMIDLIST il)
{
    LPCITEMIDLIST last = il;
    if (!il) return 0;
    while (il->mkid.cb) { last = il; il = il_next(il); }
    return (LPITEMIDLIST)last;
}

DLLAPI BOOL WINAPI ILRemoveLastID(LPITEMIDLIST il)
{
    LPITEMIDLIST last;
    if (!il || !il->mkid.cb) return FALSE;
    last = ILFindLastID(il);
    last->mkid.cb = 0;
    return TRUE;
}

DLLAPI LPITEMIDLIST WINAPI ILCombine(LPCITEMIDLIST a, LPCITEMIDLIST b)
{
    UINT na, nb;
    LPITEMIDLIST c;
    if (!a && !b) return 0;
    if (!a) return ILClone(b);
    if (!b) return ILClone(a);
    na = ILGetSize(a) - 2;
    nb = ILGetSize(b);
    c = il_alloc(na + nb);
    if (!c) return 0;
    memcpy(c, a, na);
    memcpy((BYTE *)c + na, b, nb);
    return c;
}

DLLAPI LPITEMIDLIST WINAPI ILAppendID(LPITEMIDLIST il, LPCSHITEMID id, BOOL append)
{
    BYTE one[600];
    LPITEMIDLIST r;
    if (!id || id->cb > sizeof one - 2) { ILFree(il); return 0; }
    memcpy(one, id, id->cb);
    *(USHORT *)(one + id->cb) = 0;
    if (!il) return ILClone((LPCITEMIDLIST)one);
    r = append ? ILCombine(il, (LPCITEMIDLIST)one) : ILCombine((LPCITEMIDLIST)one, il);
    ILFree(il);
    return r;
}

DLLAPI BOOL WINAPI ILIsEqual(LPCITEMIDLIST a, LPCITEMIDLIST b)
{
    WCHAR pa[MAX_PATH], pb[MAX_PATH];
    if (!a || !b) return a == b;
    if (!il_to_path(a, pa, MAX_PATH) && ILGetSize(a) > 2) return FALSE;
    if (!il_to_path(b, pb, MAX_PATH) && ILGetSize(b) > 2) return FALSE;
    return wieq(pa, pb);
}

DLLAPI BOOL WINAPI ILIsParent(LPCITEMIDLIST parent, LPCITEMIDLIST child, BOOL immediate)
{
    WCHAR pp[MAX_PATH], pc[MAX_PATH];
    size_t np, nc, i;
    if (!parent || !child) return FALSE;
    np = il_to_path(parent, pp, MAX_PATH);
    nc = il_to_path(child, pc, MAX_PATH);
    if (nc <= np) return FALSE;
    for (i = 0; i < np; ++i) if (shz_wupper(pp[i]) != shz_wupper(pc[i])) return FALSE;
    if (pc[np] != '\\') return FALSE;
    if (immediate) for (i = np + 1; i < nc; ++i) if (pc[i] == '\\') return FALSE;
    return TRUE;
}

DLLAPI LPITEMIDLIST WINAPI ILCreateFromPathW(LPCWSTR path)
{
    if (!path || !*path) return 0;
    if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 0;        /* the item must exist (last error kept) */
    return il_from_path(path);
}

DLLAPI LPITEMIDLIST WINAPI ILCreateFromPathA(LPCSTR path)
{
    WCHAR w[MAX_PATH];
    size_t i;
    if (!path) return 0;
    for (i = 0; i < MAX_PATH - 1 && path[i]; ++i) w[i] = (WCHAR)(unsigned char)path[i];
    w[i] = 0;
    return ILCreateFromPathW(w);
}

DLLAPI LPITEMIDLIST WINAPI SHSimpleIDListFromPath(PCWSTR path) { return path && *path ? il_from_path(path) : 0; }

DLLAPI BOOL WINAPI SHGetPathFromIDListW(LPCITEMIDLIST il, LPWSTR out)
{
    if (!out) return FALSE;
    out[0] = 0;
    if (!il) return FALSE;
    return il_to_path(il, out, MAX_PATH) > 0;
}

DLLAPI BOOL WINAPI SHGetPathFromIDListEx(LPCITEMIDLIST il, PWSTR out, DWORD cap, int flags)
{
    (void)flags;
    if (!out || !cap) return FALSE;
    out[0] = 0;
    return il && il_to_path(il, out, cap) > 0;
}

DLLAPI HRESULT WINAPI SHParseDisplayName(PCWSTR name, IBindCtx *bc, LPITEMIDLIST *out, SFGAOF in_attr, SFGAOF *out_attr)
{
    DWORD attr;
    (void)bc;
    if (!out) return E_POINTER_;
    *out = 0;
    if (out_attr) *out_attr = 0;
    if (!name || !*name) return E_INVALIDARG_;
    attr = GetFileAttributesW(name);
    if (attr == INVALID_FILE_ATTRIBUTES) return HR_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_FILE_NOT_FOUND);
    *out = il_from_path(name);
    if (!*out) return E_OUTOFMEMORY_;
    if (out_attr) *out_attr = in_attr & (SFGAO_FILESYSTEM | SFGAO_CANCOPY | SFGAO_CANMOVE | SFGAO_CANDELETE | SFGAO_CANRENAME | SFGAO_HASPROPSHEET |
                                        ((attr & FILE_ATTRIBUTE_DIRECTORY) ? (SFGAO_FOLDER | SFGAO_FILESYSANCESTOR | SFGAO_DROPTARGET | SFGAO_STORAGE | SFGAO_HASSUBFOLDER | SFGAO_BROWSABLE) : SFGAO_STREAM));
    return S_OK;
}

DLLAPI HRESULT WINAPI SHGetSpecialFolderLocation(HWND hwnd, int csidl, LPITEMIDLIST *out)
{
    WCHAR path[MAX_PATH];
    HRESULT hr;
    if (!out) return E_INVALIDARG_;
    *out = 0;
    hr = SHGetFolderPathW(hwnd, csidl, 0, 0, path);
    if (FAILED(hr)) return hr;
    *out = il_from_path(path);
    return *out ? S_OK : E_OUTOFMEMORY_;
}

DLLAPI HRESULT WINAPI SHGetFolderLocation(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPITEMIDLIST *out)
{
    (void)token; (void)flags;
    return SHGetSpecialFolderLocation(hwnd, csidl, out);
}

DLLAPI HRESULT WINAPI SHGetKnownFolderIDList(const GUID *id, DWORD flags, HANDLE token, LPITEMIDLIST *out)
{
    PWSTR path = 0;
    HRESULT hr;
    if (!out) return E_INVALIDARG_;
    *out = 0;
    hr = SHGetKnownFolderPath(id, flags, token, &path);
    if (FAILED(hr)) return hr;
    *out = il_from_path(path);
    CoTaskMemFree(path);
    return *out ? S_OK : E_OUTOFMEMORY_;
}

/* ================================================================ IShellItem over a file-system path */
static const GUID iid_shellitem = { 0x43826d1e, 0xe718, 0x42ee, { 0xbc, 0x55, 0xa1, 0xe2, 0x61, 0xc3, 0x7b, 0xfe } };
static const GUID iid_unknown_ = { 0x00000000, 0x0000, 0x0000, { 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 } };

typedef struct { const IShellItemVtbl *vt; LONG refs; WCHAR path[MAX_PATH]; } shitem;

static HRESULT shitem_create(const WCHAR *path, IShellItem **out);

static HRESULT STDMETHODCALLTYPE si_qi(IShellItem *self, REFIID iid, void **out)
{
    if (!out) return E_POINTER_;
    if (!memcmp(iid, &iid_unknown_, sizeof(IID)) || !memcmp(iid, &iid_shellitem, sizeof(IID))) { *out = self; IShellItem_AddRef(self); return S_OK; }
    *out = 0;
    return E_NOINTERFACE_;
}
static ULONG STDMETHODCALLTYPE si_addref(IShellItem *self) { return (ULONG)InterlockedIncrement(&((shitem *)self)->refs); }
static ULONG STDMETHODCALLTYPE si_release(IShellItem *self)
{
    ULONG r = (ULONG)InterlockedDecrement(&((shitem *)self)->refs);
    if (!r) CoTaskMemFree(self);
    return r;
}
static HRESULT STDMETHODCALLTYPE si_bind(IShellItem *self, IBindCtx *bc, REFGUID handler, REFIID iid, void **out)
{
    (void)self; (void)bc; (void)handler; (void)iid;
    if (out) *out = 0;
    return E_NOINTERFACE_;
}
static HRESULT STDMETHODCALLTYPE si_parent(IShellItem *self, IShellItem **out)
{
    shitem *s = (shitem *)self;
    WCHAR parent[MAX_PATH];
    size_t n = wlen(s->path), i;
    if (!out) return E_POINTER_;
    *out = 0;
    for (i = n; i > 0 && s->path[i - 1] != '\\'; --i) ;
    if (i <= 1) return HR_FROM_WIN32(ERROR_FILE_NOT_FOUND);              /* a root has no parent (MK_E_NOOBJECT on Windows) */
    memcpy(parent, s->path, (i - 1) * 2);
    parent[i - 1] = 0;
    if (i - 1 == 2 && parent[1] == ':') { parent[2] = '\\'; parent[3] = 0; }
    return shitem_create(parent, out);
}
static HRESULT STDMETHODCALLTYPE si_name(IShellItem *self, SIGDN sigdn, LPWSTR *out)
{
    shitem *s = (shitem *)self;
    const WCHAR *src = s->path, *last;
    size_t n;
    if (!out) return E_POINTER_;
    *out = 0;
    switch (sigdn) {
    case SIGDN_FILESYSPATH: case SIGDN_DESKTOPABSOLUTEPARSING: case SIGDN_DESKTOPABSOLUTEEDITING: case SIGDN_URL:
        break;
    case SIGDN_NORMALDISPLAY: case SIGDN_PARENTRELATIVE: case SIGDN_PARENTRELATIVEPARSING: case SIGDN_PARENTRELATIVEEDITING:
    case SIGDN_PARENTRELATIVEFORADDRESSBAR: case SIGDN_PARENTRELATIVEFORUI:
        for (last = src; *src; ++src) if (*src == '\\' && src[1]) last = src + 1;
        src = last;
        break;
    default:
        return E_INVALIDARG_;
    }
    n = wlen(src);
    if (sigdn == SIGDN_URL) {
        static const WCHAR pre[] = L"file:///";
        size_t i;
        *out = CoTaskMemAlloc((8 + n + 1) * 2);
        if (!*out) return E_OUTOFMEMORY_;
        memcpy(*out, pre, 16);
        for (i = 0; i <= n; ++i) (*out)[8 + i] = src[i] == '\\' ? '/' : src[i];
        return S_OK;
    }
    *out = CoTaskMemAlloc((n + 1) * 2);
    if (!*out) return E_OUTOFMEMORY_;
    memcpy(*out, src, (n + 1) * 2);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE si_attr(IShellItem *self, SFGAOF mask, SFGAOF *out)
{
    shitem *s = (shitem *)self;
    DWORD a = GetFileAttributesW(s->path);
    SFGAOF v;
    if (!out) return E_POINTER_;
    *out = 0;
    if (a == INVALID_FILE_ATTRIBUTES) return HR_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_FILE_NOT_FOUND);
    v = SFGAO_FILESYSTEM | SFGAO_CANCOPY | SFGAO_CANMOVE | SFGAO_CANDELETE | SFGAO_CANRENAME | SFGAO_HASPROPSHEET;
    if (a & FILE_ATTRIBUTE_DIRECTORY) v |= SFGAO_FOLDER | SFGAO_FILESYSANCESTOR | SFGAO_DROPTARGET | SFGAO_STORAGE | SFGAO_HASSUBFOLDER | SFGAO_BROWSABLE;
    else v |= SFGAO_STREAM;
    if (a & FILE_ATTRIBUTE_HIDDEN) v |= SFGAO_HIDDEN;
    if (a & FILE_ATTRIBUTE_READONLY) v |= SFGAO_READONLY;
    *out = v & mask;
    return (*out == mask) ? S_OK : S_FALSE;
}
static HRESULT STDMETHODCALLTYPE si_compare(IShellItem *self, IShellItem *other, SICHINTF hint, int *order)
{
    LPWSTR a = 0, b = 0;
    HRESULT hr;
    (void)hint;
    if (!other || !order) return E_POINTER_;
    *order = 0;
    hr = IShellItem_GetDisplayName(other, SIGDN_FILESYSPATH, &b);
    if (FAILED(hr)) return hr;
    hr = IShellItem_GetDisplayName(self, SIGDN_FILESYSPATH, &a);
    if (SUCCEEDED(hr)) {
        const WCHAR *x = a, *y = b;
        while (*x && shz_wupper(*x) == shz_wupper(*y)) { ++x; ++y; }
        *order = (int)shz_wupper(*x) - (int)shz_wupper(*y);
        CoTaskMemFree(a);
    }
    CoTaskMemFree(b);
    if (FAILED(hr)) return hr;
    return *order ? S_FALSE : S_OK;
}
static const IShellItemVtbl shitem_vtbl = { si_qi, si_addref, si_release, si_bind, si_parent, si_name, si_attr, si_compare };

static HRESULT shitem_create(const WCHAR *path, IShellItem **out)
{
    shitem *s;
    size_t n = wlen(path);
    if (n >= MAX_PATH) return HR_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    s = CoTaskMemAlloc(sizeof *s);
    if (!s) return E_OUTOFMEMORY_;
    s->vt = &shitem_vtbl;
    s->refs = 1;
    memcpy(s->path, path, (n + 1) * 2);
    *out = (IShellItem *)s;
    return S_OK;
}

DLLAPI HRESULT WINAPI SHCreateItemFromParsingName(PCWSTR name, IBindCtx *bc, REFIID iid, void **out)
{
    IShellItem *item = 0;
    HRESULT hr;
    (void)bc;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!name || !*name || !iid) return E_INVALIDARG_;
    if (GetFileAttributesW(name) == INVALID_FILE_ATTRIBUTES) return HR_FROM_WIN32(GetLastError() ? GetLastError() : ERROR_FILE_NOT_FOUND);
    hr = shitem_create(name, &item);
    if (FAILED(hr)) return hr;
    hr = IShellItem_QueryInterface(item, iid, out);
    IShellItem_Release(item);
    return hr;
}

DLLAPI HRESULT WINAPI SHCreateItemFromIDList(LPCITEMIDLIST il, REFIID iid, void **out)
{
    WCHAR path[MAX_PATH];
    if (!out) return E_POINTER_;
    *out = 0;
    if (!il || !il_to_path(il, path, MAX_PATH)) return E_INVALIDARG_;
    return SHCreateItemFromParsingName(path, 0, iid, out);
}

DLLAPI HRESULT WINAPI SHGetIDListFromObject(IUnknown *unk, LPITEMIDLIST *out)
{
    IShellItem *si = 0;
    LPWSTR path = 0;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!unk) return E_INVALIDARG_;
    hr = IUnknown_QueryInterface(unk, &iid_shellitem, (void **)&si);
    if (FAILED(hr)) return E_NOINTERFACE_;
    hr = IShellItem_GetDisplayName(si, SIGDN_FILESYSPATH, &path);
    IShellItem_Release(si);
    if (FAILED(hr)) return hr;
    *out = il_from_path(path);
    CoTaskMemFree(path);
    return *out ? S_OK : E_OUTOFMEMORY_;
}

DLLAPI HRESULT WINAPI SHGetNameFromIDList(LPCITEMIDLIST il, SIGDN sigdn, PWSTR *out)
{
    IShellItem *si = 0;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    hr = SHCreateItemFromIDList(il, &iid_shellitem, (void **)&si);
    if (FAILED(hr)) return hr;
    hr = IShellItem_GetDisplayName(si, sigdn, out);
    IShellItem_Release(si);
    return hr;
}

/* ================================================================ SHGetFileInfoW, HDROP */
DLLAPI DWORD_PTR WINAPI SHGetFileInfoW(LPCWSTR path, DWORD attr, SHFILEINFOW *info, UINT size, UINT flags)
{
    DWORD a = attr;
    const WCHAR *last;
    size_t n;
    if (!path) return 0;
    if (info) { if (size < sizeof *info) return 0; memset(info, 0, sizeof *info); }
    if (!(flags & SHGFI_USEFILEATTRIBUTES)) {
        a = GetFileAttributesW(path);
        if (a == INVALID_FILE_ATTRIBUTES) return 0;
    }
    if (flags & (SHGFI_ICON | SHGFI_SYSICONINDEX | SHGFI_ICONLOCATION | SHGFI_OPENICON | SHGFI_SHELLICONSIZE | SHGFI_PIDL)) {
        SetLastError(ERROR_NOT_SUPPORTED);                 /* no icon library, no PIDL argument form */
        return 0;
    }
    if (!info) return 1;
    if (flags & SHGFI_ATTRIBUTES) {
        SFGAOF v = SFGAO_FILESYSTEM | SFGAO_CANCOPY | SFGAO_CANMOVE | SFGAO_CANDELETE | SFGAO_CANRENAME | SFGAO_HASPROPSHEET;
        if (a & FILE_ATTRIBUTE_DIRECTORY) v |= SFGAO_FOLDER | SFGAO_FILESYSANCESTOR | SFGAO_DROPTARGET | SFGAO_STORAGE | SFGAO_HASSUBFOLDER | SFGAO_BROWSABLE;
        else v |= SFGAO_STREAM;
        if (a & FILE_ATTRIBUTE_HIDDEN) v |= SFGAO_HIDDEN;
        if (a & FILE_ATTRIBUTE_READONLY) v |= SFGAO_READONLY;
        info->dwAttributes = (flags & SHGFI_ATTR_SPECIFIED) ? (v & info->dwAttributes) : v;
    }
    if (flags & SHGFI_DISPLAYNAME) {
        for (last = path; *path; ++path) if ((*path == '\\' || *path == '/') && path[1]) last = path + 1;
        n = wlen(last);
        if (n >= MAX_PATH) n = MAX_PATH - 1;
        memcpy(info->szDisplayName, last, n * 2);
        info->szDisplayName[n] = 0;
    }
    if (flags & SHGFI_TYPENAME) {
        static const WCHAR folder[] = L"File folder", file[] = L"File";
        memcpy(info->szTypeName, (a & FILE_ATTRIBUTE_DIRECTORY) ? folder : file, (a & FILE_ATTRIBUTE_DIRECTORY) ? sizeof folder : sizeof file);
    }
    return 1;
}

DLLAPI UINT WINAPI DragQueryFileW(HDROP drop, UINT index, LPWSTR out, UINT cap)
{
    const DROPFILES *df = GlobalLock(drop);
    UINT count = 0, r = 0;
    if (!df) return 0;
    if (df->fWide) {
        const WCHAR *p = (const WCHAR *)((const BYTE *)df + df->pFiles), *hit = 0;
        while (*p) { if (count == index) hit = p; ++count; p += wlen(p) + 1; }
        if (index == 0xFFFFFFFF) r = count;
        else if (hit) {
            UINT n = (UINT)wlen(hit);
            if (!out) r = n;
            else if (cap) { UINT c = n < cap ? n : cap - 1; memcpy(out, hit, c * 2); out[c] = 0; r = c; }
        }
    } else {
        const char *p = (const char *)df + df->pFiles, *hit = 0;
        while (*p) { if (count == index) hit = p; ++count; p += strlen(p) + 1; }
        if (index == 0xFFFFFFFF) r = count;
        else if (hit) {
            UINT n = (UINT)strlen(hit), i;
            if (!out) r = n;
            else if (cap) { UINT c = n < cap ? n : cap - 1; for (i = 0; i < c; ++i) out[i] = (WCHAR)(unsigned char)hit[i]; out[c] = 0; r = c; }
        }
    }
    GlobalUnlock(drop);
    return r;
}

DLLAPI BOOL WINAPI DragQueryPoint(HDROP drop, POINT *pt)
{
    const DROPFILES *df = GlobalLock(drop);
    BOOL in;
    if (!df) return FALSE;
    if (pt) *pt = df->pt;
    in = !df->fNC;
    GlobalUnlock(drop);
    return in;
}

DLLAPI void WINAPI DragFinish(HDROP drop) { if (drop) GlobalFree(drop); }

/* ================================================================ change notifications */
typedef struct chnotify { struct chnotify *next; ULONG id; HWND hwnd; UINT msg; LONG events; int sources; } chnotify;
static SRWLOCK g_ch_lock = SRWLOCK_INIT;
static chnotify *g_ch;
static ULONG g_ch_next = 1;

DLLAPI ULONG WINAPI SHChangeNotifyRegister(HWND hwnd, int sources, LONG events, UINT msg, int count, const SHChangeNotifyEntry *entries)
{
    chnotify *e;
    (void)count; (void)entries;
    if (!hwnd || !msg) return 0;
    e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *e);
    if (!e) return 0;
    e->hwnd = hwnd; e->msg = msg; e->events = events; e->sources = sources;
    AcquireSRWLockExclusive(&g_ch_lock);
    e->id = g_ch_next++;
    e->next = g_ch;
    g_ch = e;
    ReleaseSRWLockExclusive(&g_ch_lock);
    return e->id;
}

DLLAPI BOOL WINAPI SHChangeNotifyDeregister(ULONG id)
{
    chnotify *e, **pp;
    AcquireSRWLockExclusive(&g_ch_lock);
    for (pp = &g_ch; (e = *pp) != 0; pp = &e->next) if (e->id == id) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_ch_lock);
    if (!e) return FALSE;
    HeapFree(GetProcessHeap(), 0, e);
    return TRUE;
}

DLLAPI void WINAPI SHChangeNotify(LONG event, UINT flags, LPCVOID item1, LPCVOID item2)
{
    chnotify *e;
    (void)flags; (void)item1; (void)item2;
    AcquireSRWLockShared(&g_ch_lock);
    for (e = g_ch; e; e = e->next)
        if ((e->events & event) && IsWindow(e->hwnd)) PostMessageW(e->hwnd, e->msg, 0, (LPARAM)event);
    ReleaseSRWLockShared(&g_ch_lock);
}

/* ================================================================ per-window property stores */
typedef struct wprop { struct wprop *next; HWND hwnd; IPropertyStore *store; } wprop;
static SRWLOCK g_wp_lock = SRWLOCK_INIT;
static wprop *g_wp;
typedef HRESULT (WINAPI *ps_create_t)(REFIID, void **);

DLLAPI HRESULT WINAPI SHGetPropertyStoreForWindow(HWND hwnd, REFIID iid, void **out)
{
    wprop *e, **pp;
    IPropertyStore *store = 0;
    HRESULT hr;
    if (!out) return E_POINTER_;
    *out = 0;
    if (!IsWindow(hwnd) || !iid) return E_INVALIDARG_;
    AcquireSRWLockExclusive(&g_wp_lock);
    for (pp = &g_wp; (e = *pp) != 0;) {                      /* drop the stores of windows that are gone */
        if (!IsWindow(e->hwnd)) { *pp = e->next; IPropertyStore_Release(e->store); HeapFree(GetProcessHeap(), 0, e); continue; }
        if (e->hwnd == hwnd) store = e->store;
        pp = &e->next;
    }
    if (!store) {
        HMODULE ps = LoadLibraryW(L"propsys.dll");
        ps_create_t create = ps ? (ps_create_t)GetProcAddress(ps, "PSCreateMemoryPropertyStore") : 0;
        static const GUID iid_ps = { 0x886d8eeb, 0x8cf2, 0x4446, { 0x8d, 0x02, 0xcd, 0xba, 0x1d, 0xbd, 0xcf, 0x99 } };
        if (!create) { ReleaseSRWLockExclusive(&g_wp_lock); return HR_FROM_WIN32(ERROR_MOD_NOT_FOUND); }
        hr = create(&iid_ps, (void **)&store);
        if (FAILED(hr)) { ReleaseSRWLockExclusive(&g_wp_lock); return hr; }
        e = HeapAlloc(GetProcessHeap(), 0, sizeof *e);
        if (!e) { IPropertyStore_Release(store); ReleaseSRWLockExclusive(&g_wp_lock); return E_OUTOFMEMORY_; }
        e->hwnd = hwnd; e->store = store; e->next = g_wp; g_wp = e;
    }
    hr = IPropertyStore_QueryInterface(store, iid, out);
    ReleaseSRWLockExclusive(&g_wp_lock);
    return hr;
}

/* ================================================================ user, notifications, taskbar, execution */
DLLAPI BOOL WINAPI IsUserAnAdmin(void)
{
    BYTE sid[16];
    SID *s = (SID *)sid;
    BOOL member = FALSE;
    s->Revision = SID_REVISION;
    s->SubAuthorityCount = 2;
    memset(&s->IdentifierAuthority, 0, 6);
    s->IdentifierAuthority.Value[5] = 5;
    s->SubAuthority[0] = 32;                                 /* S-1-5-32-544: BUILTIN\Administrators */
    s->SubAuthority[1] = 544;
    return CheckTokenMembership(0, s, &member) && member;
}

DLLAPI HRESULT WINAPI SHQueryUserNotificationState(QUERY_USER_NOTIFICATION_STATE *out)
{
    if (!out) return E_INVALIDARG_;
    *out = QUNS_ACCEPTS_NOTIFICATIONS;
    return S_OK;
}

DLLAPI BOOL WINAPI Shell_NotifyIconW(DWORD msg, PNOTIFYICONDATAW data)
{
    (void)msg; (void)data;
    SetLastError(ERROR_NOT_SUPPORTED);                       /* no notification area */
    return FALSE;
}

DLLAPI BOOL WINAPI Shell_NotifyIconA(DWORD msg, PNOTIFYICONDATAA data)
{
    (void)msg; (void)data;
    SetLastError(ERROR_NOT_SUPPORTED);
    return FALSE;
}

DLLAPI UINT_PTR WINAPI SHAppBarMessage(DWORD msg, PAPPBARDATA data)
{
    (void)msg; (void)data;
    SetLastError(ERROR_NOT_SUPPORTED);                       /* no taskbar, no appbars */
    return 0;
}

DLLAPI HRESULT WINAPI SHGetDesktopFolder(IShellFolder **out)
{
    if (!out) return E_INVALIDARG_;
    *out = 0;
    return E_FAIL_;                                          /* no IShellFolder namespace exists (documented failure code) */
}

DLLAPI HRESULT WINAPI SHGetStockIconInfo(SHSTOCKICONID id, UINT flags, SHSTOCKICONINFO *info)
{
    (void)id; (void)flags;
    if (!info || info->cbSize != sizeof *info) return E_INVALIDARG_;
    return HR_FROM_WIN32(ERROR_RESOURCE_TYPE_NOT_FOUND);     /* no icon resources */
}

DLLAPI HRESULT WINAPI SHOpenFolderAndSelectItems(LPCITEMIDLIST folder, UINT count, LPCITEMIDLIST *items, DWORD flags)
{
    (void)count; (void)items; (void)flags;
    if (!folder) return E_INVALIDARG_;
    return HR_FROM_WIN32(ERROR_NOT_SUPPORTED);               /* no Explorer window can be opened */
}

DLLAPI HRESULT WINAPI SHCreateAssociationRegistration(REFIID iid, void **out)
{
    static const GUID clsid_aar = { 0x591209c7, 0x767b, 0x42b2, { 0x9f, 0xba, 0x44, 0xee, 0x46, 0x15, 0xf2, 0xc7 } };
    if (!out) return E_POINTER_;
    return CoCreateInstance(&clsid_aar, 0, CLSCTX_INPROC_SERVER, iid, out);   /* REGDB_E_CLASSNOTREG: the class is not registered */
}

static int ends_with_exe(const WCHAR *s)
{
    size_t n = wlen(s);
    return n > 4 && s[n - 4] == '.' && shz_wupper(s[n - 3]) == 'E' && shz_wupper(s[n - 2]) == 'X' && shz_wupper(s[n - 1]) == 'E';
}

static BOOL verb_runs(const WCHAR *verb)
{
    static const WCHAR open_[] = L"open", runas[] = L"runas";
    return !verb || !*verb || wieq(verb, open_) || wieq(verb, runas);
}

/* Starts `file` with CreateProcessW when it is an executable; sets the documented SE_ERR_* / Win32 code otherwise. */
static HINSTANCE shell_run(const WCHAR *verb, const WCHAR *file, const WCHAR *params, const WCHAR *dir, int show, HANDLE *process)
{
    WCHAR cmd[2048];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD attr;
    size_t n, k;
    if (process) *process = 0;
    if (!file || !*file) { SetLastError(ERROR_FILE_NOT_FOUND); return (HINSTANCE)SE_ERR_FNF; }
    attr = GetFileAttributesW(file);
    if (attr == INVALID_FILE_ATTRIBUTES) { SetLastError(ERROR_FILE_NOT_FOUND); return (HINSTANCE)SE_ERR_FNF; }
    if (!verb_runs(verb) || (attr & FILE_ATTRIBUTE_DIRECTORY) || !ends_with_exe(file)) { SetLastError(ERROR_NO_ASSOCIATION); return (HINSTANCE)SE_ERR_NOASSOC; }
    n = wlen(file);
    k = params ? wlen(params) : 0;
    if (n + k + 4 >= sizeof cmd / sizeof cmd[0]) { SetLastError(ERROR_FILENAME_EXCED_RANGE); return (HINSTANCE)SE_ERR_FNF; }
    cmd[0] = '"';
    memcpy(cmd + 1, file, n * 2);
    cmd[n + 1] = '"';
    cmd[n + 2] = 0;
    if (k) { cmd[n + 2] = ' '; memcpy(cmd + n + 3, params, (k + 1) * 2); }
    memset(&si, 0, sizeof si);
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = (WORD)show;
    if (!CreateProcessW(file, cmd, 0, 0, FALSE, 0, 0, dir && *dir ? dir : 0, &si, &pi)) {
        DWORD err = GetLastError();
        return (HINSTANCE)(ULONG_PTR)(err == ERROR_ACCESS_DENIED ? SE_ERR_ACCESSDENIED : err == ERROR_NOT_ENOUGH_MEMORY ? SE_ERR_OOM : SE_ERR_FNF);
    }
    CloseHandle(pi.hThread);
    if (process) *process = pi.hProcess; else CloseHandle(pi.hProcess);
    return (HINSTANCE)42;                                    /* > 32: success */
}

DLLAPI HINSTANCE WINAPI ShellExecuteW(HWND hwnd, LPCWSTR verb, LPCWSTR file, LPCWSTR params, LPCWSTR dir, INT show)
{
    (void)hwnd;
    return shell_run(verb, file, params, dir, show, 0);
}

DLLAPI HINSTANCE WINAPI ShellExecuteA(HWND hwnd, LPCSTR verb, LPCSTR file, LPCSTR params, LPCSTR dir, INT show)
{
    WCHAR wv[64], wf[MAX_PATH], wp[1024], wd[MAX_PATH];
    size_t i;
#define WIDEN(src, dst) do { if (src) { for (i = 0; i + 1 < sizeof dst / sizeof dst[0] && (src)[i]; ++i) dst[i] = (WCHAR)(unsigned char)(src)[i]; dst[i] = 0; } } while (0)
    WIDEN(verb, wv); WIDEN(file, wf); WIDEN(params, wp); WIDEN(dir, wd);
#undef WIDEN
    return ShellExecuteW(hwnd, verb ? wv : 0, file ? wf : 0, params ? wp : 0, dir ? wd : 0, show);
}

DLLAPI BOOL WINAPI ShellExecuteExW(SHELLEXECUTEINFOW *info)
{
    HINSTANCE r;
    HANDLE proc = 0;
    if (!info || info->cbSize != sizeof *info) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    if (info->fMask & SEE_MASK_INVOKEIDLIST) { SetLastError(ERROR_NOT_SUPPORTED); info->hInstApp = (HINSTANCE)SE_ERR_NOASSOC; return FALSE; }
    r = shell_run(info->lpVerb, info->lpFile, info->lpParameters, info->lpDirectory, info->nShow, (info->fMask & SEE_MASK_NOCLOSEPROCESS) ? &proc : 0);
    info->hInstApp = r;
    info->hProcess = proc;
    return (ULONG_PTR)r > 32;
}
