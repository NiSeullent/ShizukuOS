/* SPDX-License-Identifier: GPL-2.0-only
 * shell32 file-system operations a native shell / file manager and installers call:
 *   SHFileOperationW/A        FO_COPY, FO_MOVE, FO_DELETE, FO_RENAME over kernel32 (CopyFileW, MoveFileExW,
 *                             DeleteFileW, CreateDirectoryW, RemoveDirectoryW, FindFirstFileW); double-NUL source /
 *                             destination lists, wildcards in the last component, FOF_MULTIDESTFILES, FOF_FILESONLY,
 *                             FOF_NORECURSION, recursive directory copy/move/delete, cross-volume move by copy+delete,
 *                             SHChangeNotify events for every change.
 *   SHCreateDirectory, SHCreateDirectoryExW/A   absolute path with every missing parent.
 *   SHGetFolderPathAndSubDirW, SHGetFolderPathA (over this DLL's SHGetFolderPathW), PathYetAnotherMakeUniqueName,
 *   SHAlloc / SHFree (COM task allocator). SHGetDiskFreeSpaceEx* are kernel32 forwarders (module.json), as on Windows.
 *
 * Honest limits (no success is reported for work that was not done):
 *   - This shell32 has no dialogs. An operation that Windows would confirm (any FO_DELETE; copy/move/rename onto an
 *     existing top-level target; creating a missing destination folder) is refused with ERROR_NOT_SUPPORTED before any
 *     change unless the caller passes FOF_NOCONFIRMATION (or FOF_NOCONFIRMMKDIR for the folder case) -- the same
 *     outcome as "Yes to all". No progress UI is shown (FOF_SILENT is the observable behaviour).
 *   - There is no Recycle Bin yet: FO_DELETE with FOF_ALLOWUNDO fails ERROR_NOT_SUPPORTED instead of deleting
 *     permanently. FOF_RENAMEONCOLLISION and FOF_WANTMAPPINGHANDLE (name-mapping objects) are not implemented and fail
 *     ERROR_NOT_SUPPORTED. Undo history for copy/move (FOF_ALLOWUNDO) is not recorded; the operation itself is real.
 *   - Paths are limited to MAX_PATH (ERROR_FILENAME_EXCED_RANGE).
 * Return values follow Windows: 0, a Win32 error code, or DE_SAMEFILE (0x71) / DE_DESTSUBTREE (0x76).
 * Semantics follow the Microsoft SHFileOperation documentation and the behaviour exercised by Wine's
 * dlls/shell32/tests/shlfileop.c and ReactOS dll/win32/shell32/shlfileop.cpp; original project source, no code copied.
 */
/* mingw's shlobj.h/shellapi.h declare these DECLSPEC_IMPORT; this is shell32, so they are local (as in shell_ns.c). */
#pragma GCC diagnostic ignored "-Wattributes"
#define _SHELL32_
#include "nt.h"
#include <string.h>
#include <objbase.h>
#include <shlobj.h>
#include <shellapi.h>

#define DE_SAMEFILE_ 0x71
#define DE_DESTSUBTREE_ 0x76
#define NEED_UI ERROR_NOT_SUPPORTED
#define CSIDL_FLAG_CREATE_ 0x8000
#define CSIDL_FLAG_DONT_VERIFY_ 0x4000

static size_t wl(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static int is_sep(WCHAR c) { return c == '\\' || c == '/'; }
static int has_wild(const WCHAR *s) { for (; *s; ++s) if (*s == '*' || *s == '?') return 1; return 0; }
static const WCHAR *base_name(const WCHAR *s) { const WCHAR *b = s; for (; *s; ++s) if (is_sep(*s) || *s == ':') b = s + 1; return b; }
static int is_dots(const WCHAR *n) { return n[0] == '.' && (!n[1] || (n[1] == '.' && !n[2])); }

/* out = dir + '\' + name (dir may already end in a separator). Returns 0 or ERROR_FILENAME_EXCED_RANGE. */
static DWORD join(WCHAR *out, const WCHAR *dir, const WCHAR *name)
{
    size_t a = wl(dir), b = wl(name), sep = a && !is_sep(dir[a - 1]);
    if (a + sep + b >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    memmove(out, dir, a * sizeof(WCHAR));
    if (sep) out[a] = '\\';
    memcpy(out + a + sep, name, (b + 1) * sizeof(WCHAR));
    return 0;
}

static DWORD full_path(const WCHAR *in, WCHAR *out)
{
    DWORD n = GetFullPathNameW(in, MAX_PATH, out, 0);
    if (!n) return GetLastError();
    if (n >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    while (n > 3 && is_sep(out[n - 1])) out[--n] = 0;          /* "C:\dir\" -> "C:\dir" (keep "C:\") */
    return 0;
}

static void notify(LONG event, const WCHAR *a, const WCHAR *b) { SHChangeNotify(event, SHCNF_PATHW, a, b); }

/* ---------------------------------------------------------------- trees */
/* Calls fn for every child of dir (dir/dst are MAX_PATH buffers extended in place and restored). */
typedef DWORD (*child_fn)(WCHAR *src, WCHAR *dst, DWORD flags);

static DWORD for_children(WCHAR *src, WCHAR *dst, DWORD flags, child_fn fn)
{
    WIN32_FIND_DATAW *fd = HeapAlloc(GetProcessHeap(), 0, sizeof *fd);
    size_t ls = wl(src), ld = dst ? wl(dst) : 0;
    HANDLE f;
    DWORD e = 0;
    if (!fd) return ERROR_NOT_ENOUGH_MEMORY;
    if ((e = join(src, src, L"*")) != 0) { HeapFree(GetProcessHeap(), 0, fd); return e; }
    f = FindFirstFileW(src, fd);
    src[ls] = 0;
    if (f == INVALID_HANDLE_VALUE) {
        e = GetLastError();
        HeapFree(GetProcessHeap(), 0, fd);
        return e == ERROR_FILE_NOT_FOUND || e == ERROR_NO_MORE_FILES ? 0 : e;
    }
    do {
        if (is_dots(fd->cFileName)) continue;
        if ((flags & FOF_NORECURSION) && (fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if ((e = join(src, src, fd->cFileName)) != 0) break;
        if (dst && (e = join(dst, dst, fd->cFileName)) != 0) { src[ls] = 0; break; }
        e = fn(src, dst, flags);
        src[ls] = 0;
        if (dst) dst[ld] = 0;
        if (e) break;
    } while (FindNextFileW(f, fd));
    if (!e && GetLastError() != ERROR_NO_MORE_FILES) e = GetLastError();
    FindClose(f);
    HeapFree(GetProcessHeap(), 0, fd);
    return e;
}

static DWORD copy_tree(WCHAR *src, WCHAR *dst, DWORD flags)
{
    DWORD a = GetFileAttributesW(src), d, e;
    if (a == INVALID_FILE_ATTRIBUTES) return GetLastError();
    d = GetFileAttributesW(dst);
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) {
        if (d != INVALID_FILE_ATTRIBUTES && (d & FILE_ATTRIBUTE_DIRECTORY)) return ERROR_ALREADY_EXISTS;
        if (!CopyFileW(src, dst, FALSE)) return GetLastError();
        notify(SHCNE_CREATE, dst, 0);
        return 0;
    }
    if (d == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(dst, 0)) return GetLastError();
        notify(SHCNE_MKDIR, dst, 0);
    } else if (!(d & FILE_ATTRIBUTE_DIRECTORY)) return ERROR_ALREADY_EXISTS;
    e = for_children(src, dst, flags, copy_tree);
    return e;
}

static DWORD delete_tree(WCHAR *src, WCHAR *dst, DWORD flags)
{
    DWORD a = GetFileAttributesW(src), e;
    (void)dst;
    if (a == INVALID_FILE_ATTRIBUTES) return GetLastError();
    if (a & FILE_ATTRIBUTE_DIRECTORY) {
        if ((e = for_children(src, 0, flags, delete_tree)) != 0) return e;
        if ((a & FILE_ATTRIBUTE_READONLY) && !SetFileAttributesW(src, a & ~FILE_ATTRIBUTE_READONLY)) return GetLastError();
        if (!RemoveDirectoryW(src)) return GetLastError();
        notify(SHCNE_RMDIR, src, 0);
        return 0;
    }
    /* The confirmed shell delete also removes read-only files. */
    if ((a & FILE_ATTRIBUTE_READONLY) && !SetFileAttributesW(src, a & ~FILE_ATTRIBUTE_READONLY)) return GetLastError();
    if (!DeleteFileW(src)) return GetLastError();
    notify(SHCNE_DELETE, src, 0);
    return 0;
}

static DWORD move_one(WCHAR *src, WCHAR *dst, DWORD flags, DWORD attr, BOOL replace)
{
    DWORD e;
    BOOL dir = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (MoveFileExW(src, dst, MOVEFILE_COPY_ALLOWED | (replace && !dir ? MOVEFILE_REPLACE_EXISTING : 0))) {
        notify(dir ? SHCNE_RENAMEFOLDER : SHCNE_RENAMEITEM, src, dst);
        return 0;
    }
    e = GetLastError();
    /* A folder onto an existing folder (merge) or across volumes: copy the tree, then remove the source tree. */
    if (!dir || !(e == ERROR_NOT_SAME_DEVICE || (replace && (e == ERROR_ALREADY_EXISTS || e == ERROR_ACCESS_DENIED))))
        return e;
    if ((e = copy_tree(src, dst, flags)) != 0) return e;
    return delete_tree(src, 0, flags);
}

/* ---------------------------------------------------------------- operation list */
typedef struct { WCHAR src[MAX_PATH], dst[MAX_PATH]; DWORD attr; BOOL dst_exists; } op_item;
typedef struct { op_item *v; size_t n, cap; } op_list;

static op_item *push(op_list *l)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 8;
        op_item *v = l->v ? HeapReAlloc(GetProcessHeap(), 0, l->v, cap * sizeof *v) : HeapAlloc(GetProcessHeap(), 0, cap * sizeof *v);
        if (!v) return 0;
        l->v = v; l->cap = cap;
    }
    return &l->v[l->n++];
}

/* Expands one pFrom entry (wildcards in the last component) into absolute source paths. */
static DWORD expand(const WCHAR *spec, DWORD flags, op_list *l, size_t *added)
{
    WCHAR fullspec[MAX_PATH], dir[MAX_PATH];
    WIN32_FIND_DATAW fd;
    HANDLE f;
    DWORD e;
    op_item *it;
    *added = 0;
    if ((e = full_path(spec, fullspec)) != 0) return e;
    if (!has_wild(base_name(fullspec))) {
        DWORD a = GetFileAttributesW(fullspec);
        if (a == INVALID_FILE_ATTRIBUTES) return GetLastError();
        if (!(it = push(l))) return ERROR_NOT_ENOUGH_MEMORY;
        memcpy(it->src, fullspec, sizeof fullspec);
        it->attr = a;
        *added = 1;
        return 0;
    }
    memcpy(dir, fullspec, sizeof dir);
    dir[base_name(dir) - dir] = 0;
    f = FindFirstFileW(fullspec, &fd);
    if (f == INVALID_HANDLE_VALUE) { e = GetLastError(); return e == ERROR_NO_MORE_FILES ? ERROR_FILE_NOT_FOUND : e; }
    e = 0;
    do {
        if (is_dots(fd.cFileName)) continue;
        if ((flags & (FOF_FILESONLY | FOF_NORECURSION)) && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (!(it = push(l))) { e = ERROR_NOT_ENOUGH_MEMORY; break; }
        if ((e = join(it->src, dir, fd.cFileName)) != 0) { --l->n; break; }
        it->attr = fd.dwFileAttributes;
        ++*added;
    } while (FindNextFileW(f, &fd));
    FindClose(f);
    return e;
}

static int path_eq(const WCHAR *a, const WCHAR *b) { return CompareStringOrdinal(a, -1, b, -1, TRUE) == CSTR_EQUAL; }
static int path_under(const WCHAR *child, const WCHAR *parent)
{
    size_t n = wl(parent);
    return wl(child) > n && (is_sep(child[n]) || is_sep(parent[n - 1])) &&
           CompareStringOrdinal(child, (int)n, parent, (int)n, TRUE) == CSTR_EQUAL;
}

static DWORD file_operation(UINT func, const WCHAR *from, const WCHAR *to, FILEOP_FLAGS flags)
{
    op_list l = { 0, 0, 0 };
    const WCHAR *p, *q;
    WCHAR target[MAX_PATH];
    size_t nfrom = 0, nto = 0, i, added, first;
    BOOL wild = FALSE, multi = (flags & FOF_MULTIDESTFILES) != 0, confirm = (flags & FOF_NOCONFIRMATION) != 0;
    BOOL into_dir = FALSE, make_dir = FALSE;
    DWORD e = 0, ta = INVALID_FILE_ATTRIBUTES;

    if (func < FO_MOVE || func > FO_RENAME || !from || !*from) return ERROR_INVALID_PARAMETER;
    if (flags & (FOF_RENAMEONCOLLISION | FOF_WANTMAPPINGHANDLE)) return ERROR_NOT_SUPPORTED;
    if (func == FO_DELETE && (flags & FOF_ALLOWUNDO)) return ERROR_NOT_SUPPORTED;     /* no Recycle Bin */
    if (func == FO_DELETE && !confirm) return NEED_UI;
    for (p = from; *p; p += wl(p) + 1) { ++nfrom; if (has_wild(base_name(p))) wild = TRUE; }
    if (func != FO_DELETE) {
        if (to && *to) for (q = to; *q; q += wl(q) + 1) ++nto;
        if (func == FO_RENAME && (nfrom != 1 || nto != 1 || wild)) return ERROR_INVALID_PARAMETER;
        if (multi && (nto != nfrom || wild)) return ERROR_INVALID_PARAMETER;
        if (!multi && nto > 1) return ERROR_INVALID_PARAMETER;
        if (!multi) {
            if ((e = full_path(nto ? to : L".", target)) != 0) return e;
            ta = GetFileAttributesW(target);
            into_dir = func != FO_RENAME && ((ta != INVALID_FILE_ATTRIBUTES && (ta & FILE_ATTRIBUTE_DIRECTORY)) || nfrom > 1 || wild);
            if (into_dir && ta == INVALID_FILE_ATTRIBUTES) {
                make_dir = TRUE;
                if (!(flags & (FOF_NOCONFIRMMKDIR | FOF_NOCONFIRMATION))) return NEED_UI;
            } else if (into_dir && !(ta & FILE_ATTRIBUTE_DIRECTORY)) return ERROR_ALREADY_EXISTS;
        }
    }
    /* Pass 1: expand, resolve destinations and validate everything before the first change. */
    for (p = from, q = to; *p; p += wl(p) + 1) {
        first = l.n;
        if ((e = expand(p, flags, &l, &added)) != 0) goto done;
        for (i = first; i < l.n; ++i) {
            op_item *it = &l.v[i];
            if (func == FO_DELETE) continue;
            if (multi) {
                WCHAR t[MAX_PATH];
                DWORD a;
                if ((e = full_path(q, t)) != 0) goto done;
                a = GetFileAttributesW(t);
                if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) && !path_eq(t, it->src)) e = join(it->dst, t, base_name(it->src));
                else memcpy(it->dst, t, sizeof t);
            } else if (into_dir) e = join(it->dst, target, base_name(it->src));
            else memcpy(it->dst, target, sizeof target);
            if (e) goto done;
            if (func == FO_RENAME) {                     /* a bare new name stays in the source's folder */
                const WCHAR *nm = to;
                if (base_name(nm) == nm) {
                    WCHAR dir[MAX_PATH];
                    memcpy(dir, it->src, sizeof dir);
                    dir[base_name(dir) - dir] = 0;
                    if ((e = join(it->dst, dir, nm)) != 0) goto done;
                }
            }
            if (path_eq(it->src, it->dst)) { e = DE_SAMEFILE_; goto done; }
            if ((it->attr & FILE_ATTRIBUTE_DIRECTORY) && path_under(it->dst, it->src)) { e = DE_DESTSUBTREE_; goto done; }
            it->dst_exists = GetFileAttributesW(it->dst) != INVALID_FILE_ATTRIBUTES;
            if (it->dst_exists && func == FO_RENAME) { e = ERROR_ALREADY_EXISTS; goto done; }
            if (it->dst_exists && !confirm) { e = NEED_UI; goto done; }
        }
        if (multi && func != FO_DELETE) q += wl(q) + 1;
    }
    /* Pass 2: perform. */
    if (make_dir) {
        if ((e = SHCreateDirectoryExW(0, target, 0)) != 0) goto done;
    }
    for (i = 0; i < l.n && !e; ++i) {
        op_item *it = &l.v[i];
        switch (func) {
        case FO_DELETE: e = delete_tree(it->src, 0, flags); break;
        case FO_COPY:   e = copy_tree(it->src, it->dst, flags); break;
        case FO_MOVE:   e = move_one(it->src, it->dst, flags, it->attr, it->dst_exists); break;
        case FO_RENAME:
            if (!MoveFileExW(it->src, it->dst, 0)) e = GetLastError();
            else notify((it->attr & FILE_ATTRIBUTE_DIRECTORY) ? SHCNE_RENAMEFOLDER : SHCNE_RENAMEITEM, it->src, it->dst);
            break;
        }
    }
done:
    if (l.v) HeapFree(GetProcessHeap(), 0, l.v);
    return e;
}

DLLAPI int WINAPI SHFileOperationW(LPSHFILEOPSTRUCTW op)
{
    if (!op) return ERROR_INVALID_PARAMETER;
    op->fAnyOperationsAborted = FALSE;                  /* nothing is ever cancelled by a user here */
    op->hNameMappings = 0;
    return (int)file_operation(op->wFunc, op->pFrom, op->pTo, op->fFlags);
}

/* Double-NUL ANSI list -> heap wide list. */
static WCHAR *widen_list(LPCSTR s)
{
    size_t n = 0;
    int w;
    WCHAR *out;
    if (!s) return 0;
    while (s[n] || s[n + 1]) ++n;
    n += 2;
    w = MultiByteToWideChar(CP_ACP, 0, s, (int)n, 0, 0);
    if (w <= 0 || !(out = HeapAlloc(GetProcessHeap(), 0, (size_t)w * sizeof(WCHAR)))) return 0;
    MultiByteToWideChar(CP_ACP, 0, s, (int)n, out, w);
    return out;
}

DLLAPI int WINAPI SHFileOperationA(LPSHFILEOPSTRUCTA op)
{
    WCHAR *from, *to = 0;
    int r;
    if (!op || !op->pFrom) return ERROR_INVALID_PARAMETER;
    op->fAnyOperationsAborted = FALSE;
    op->hNameMappings = 0;
    if (!(from = widen_list(op->pFrom))) return ERROR_NOT_ENOUGH_MEMORY;
    if (op->pTo && *op->pTo && !(to = widen_list(op->pTo))) { HeapFree(GetProcessHeap(), 0, from); return ERROR_NOT_ENOUGH_MEMORY; }
    r = (int)file_operation(op->wFunc, from, to, op->fFlags);
    HeapFree(GetProcessHeap(), 0, from);
    if (to) HeapFree(GetProcessHeap(), 0, to);
    return r;
}

/* ---------------------------------------------------------------- directories */
DLLAPI int WINAPI SHCreateDirectoryExW(HWND hwnd, LPCWSTR path, const SECURITY_ATTRIBUTES *sa)
{
    WCHAR buf[MAX_PATH];
    size_t n, i, root;
    DWORD a, e;
    (void)hwnd;
    if (!path || !*path) return ERROR_BAD_PATHNAME;
    n = wl(path);
    if (n >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
    if (n >= 3 && path[1] == ':' && is_sep(path[2])) root = 3;                       /* C:\ */
    else if (n >= 2 && is_sep(path[0]) && is_sep(path[1])) {                         /* \\server\share\ */
        size_t k = 2, parts = 0;
        while (k < n && parts < 2) { if (is_sep(path[k])) ++parts; ++k; }
        if (parts < 2) return ERROR_BAD_PATHNAME;
        root = k;
    } else return ERROR_BAD_PATHNAME;                                                /* relative paths are refused */
    memcpy(buf, path, (n + 1) * sizeof(WCHAR));
    while (n > root && is_sep(buf[n - 1])) buf[--n] = 0;
    a = GetFileAttributesW(buf);
    if (a != INVALID_FILE_ATTRIBUTES) return (a & FILE_ATTRIBUTE_DIRECTORY) ? ERROR_ALREADY_EXISTS : ERROR_FILE_EXISTS;
    for (i = root; i <= n; ++i) {
        WCHAR c = buf[i];
        if (i != n && !is_sep(c)) continue;
        if (i > root && !is_sep(buf[i - 1])) {
            buf[i] = 0;
            if (!CreateDirectoryW(buf, (LPSECURITY_ATTRIBUTES)sa)) {
                e = GetLastError();
                a = GetFileAttributesW(buf);
                if (e != ERROR_ALREADY_EXISTS || a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) {
                    buf[i] = c;
                    return (int)(e == ERROR_ALREADY_EXISTS ? ERROR_PATH_NOT_FOUND : e);   /* a file is in the way */
                }
            }
            buf[i] = c;
        }
    }
    notify(SHCNE_MKDIR, buf, 0);
    return ERROR_SUCCESS;
}

DLLAPI int WINAPI SHCreateDirectoryExA(HWND hwnd, LPCSTR path, const SECURITY_ATTRIBUTES *sa)
{
    WCHAR w[MAX_PATH];
    if (!path) return ERROR_BAD_PATHNAME;
    if (!MultiByteToWideChar(CP_ACP, 0, path, -1, w, MAX_PATH)) return ERROR_FILENAME_EXCED_RANGE;
    return SHCreateDirectoryExW(hwnd, w, sa);
}

DLLAPI int WINAPI SHCreateDirectory(HWND hwnd, LPCWSTR path) { return SHCreateDirectoryExW(hwnd, path, 0); }

/* ---------------------------------------------------------------- folders */
DLLAPI HRESULT WINAPI SHGetFolderPathAndSubDirW(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPCWSTR sub, LPWSTR path)
{
    HRESULT hr;
    DWORD a;
    int e;
    if (!path) return E_INVALIDARG;
    path[0] = 0;
    hr = SHGetFolderPathW(hwnd, csidl & ~CSIDL_FLAG_CREATE_, token, flags, path);
    if (FAILED(hr)) return hr;
    if (sub && *sub) {
        WCHAR tmp[MAX_PATH];
        if (join(tmp, path, sub)) { path[0] = 0; return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE); }
        memcpy(path, tmp, sizeof tmp);
    }
    if (csidl & CSIDL_FLAG_CREATE_) {
        e = SHCreateDirectoryExW(hwnd, path, 0);
        if (e && e != ERROR_ALREADY_EXISTS) { path[0] = 0; return HRESULT_FROM_WIN32(e); }
    } else if (!(csidl & CSIDL_FLAG_DONT_VERIFY_)) {
        a = GetFileAttributesW(path);
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY)) { path[0] = 0; return HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND); }
    }
    return S_OK;
}

DLLAPI HRESULT WINAPI SHGetFolderPathA(HWND hwnd, int csidl, HANDLE token, DWORD flags, LPSTR path)
{
    WCHAR w[MAX_PATH];
    HRESULT hr;
    if (!path) return E_INVALIDARG;
    path[0] = 0;
    hr = SHGetFolderPathW(hwnd, csidl, token, flags, w);
    if (FAILED(hr)) return hr;
    if (!WideCharToMultiByte(CP_ACP, 0, w, -1, path, MAX_PATH, 0, 0)) { path[0] = 0; return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE); }
    return S_OK;
}

/* "<path>\<long name>", or "<stem> (N)<ext>" for the first free N in 2..1000 -- the shell's "New Folder (2)" naming. */
DLLAPI BOOL WINAPI PathYetAnotherMakeUniqueName(LPWSTR out, LPCWSTR path, LPCWSTR shortname, LPCWSTR longname)
{
    WCHAR name[MAX_PATH], cand[MAX_PATH], num[16];
    const WCHAR *src = longname ? longname : shortname, *dot;
    size_t stem, n, k;
    unsigned i;
    if (!out || !path || !src) return FALSE;
    if (join(cand, path, src)) return FALSE;
    if (GetFileAttributesW(cand) == INVALID_FILE_ATTRIBUTES) { memcpy(out, cand, (wl(cand) + 1) * sizeof(WCHAR)); return TRUE; }
    n = wl(src);
    for (dot = src + n; dot > src && *dot != '.'; --dot) ;
    stem = (dot > src) ? (size_t)(dot - src) : n;
    for (i = 2; i <= 1000; ++i) {
        unsigned v = i;
        k = 0;
        num[k++] = ' '; num[k++] = '(';
        { WCHAR d[8]; size_t m = 0; do { d[m++] = (WCHAR)('0' + v % 10); v /= 10; } while (v); while (m) num[k++] = d[--m]; }
        num[k++] = ')'; num[k] = 0;
        if (stem + k + (n - stem) >= MAX_PATH) return FALSE;
        memcpy(name, src, stem * sizeof(WCHAR));
        memcpy(name + stem, num, k * sizeof(WCHAR));
        memcpy(name + stem + k, src + stem, (n - stem + 1) * sizeof(WCHAR));
        if (join(cand, path, name)) return FALSE;
        if (GetFileAttributesW(cand) == INVALID_FILE_ATTRIBUTES) { memcpy(out, cand, (wl(cand) + 1) * sizeof(WCHAR)); return TRUE; }
    }
    return FALSE;
}

DLLAPI LPVOID WINAPI SHAlloc(SIZE_T size) { return CoTaskMemAlloc(size); }
DLLAPI void WINAPI SHFree(LPVOID p) { CoTaskMemFree(p); }
