/* SPDX-License-Identifier: GPL-2.0-only
 * version.dll - GetFileVersionInfoSizeW / GetFileVersionInfoW / VerQueryValueW for PE32 and PE32+ images.
 *
 * The version resource is found the way the format defines it: DOS header -> NT headers -> IMAGE_DIRECTORY_ENTRY_RESOURCE
 * -> resource tree RT_VERSION (16) / id 1 (VS_VERSION_INFO) / language. The image file is read with kernel32
 * CreateFile/SetFilePointerEx/ReadFile (there is no file mapping API); nothing is loaded or executed. When several
 * languages exist the neutral one is used, then en-US, then the first entry (real Windows picks by the thread's UI language).
 *
 * The buffer handed back by GetFileVersionInfoW is the raw VS_VERSIONINFO block; VerQueryValueW walks it exactly as
 * documented: "\" = the VS_FIXEDFILEINFO, "\VarFileInfo\Translation" = the LANGID/codepage pairs,
 * "\StringFileInfo\<lang><codepage>\<name>" = a string (length in characters, including the NUL as stored by rc).
 * Key comparison is ASCII case-insensitive.
 *
 * A bare file name ("kernel32.dll") is located through the DLL search order (application directory, system directory,
 * current directory; ".dll" appended when there is no extension), as Windows does through LoadLibraryEx as a data file.
 * GetFileVersionInfo{Size}ExW accept the FILE_VER_GET_* flags; without MUI satellite resources they select nothing.
 *
 * Not provided: the *A entry points, VerLanguageName*, VerFindFile*, VerInstallFile*.
 */
#include "nt.h"
#include <string.h>

#define VS_FFI_SIGNATURE 0xFEEF04BDu
#define MAX_RES_SIZE (1u << 20)

typedef struct { WORD wLength, wValueLength, wType; } vs_node;

static int read_at(HANDLE h, ULONGLONG off, void *buf, DWORD n)
{
    LARGE_INTEGER li;
    DWORD got = 0;
    li.QuadPart = (LONGLONG)off;
    if (!SetFilePointerEx(h, li, 0, FILE_BEGIN)) return 0;
    if (!ReadFile(h, buf, n, &got, 0) || got != n) return 0;
    return 1;
}

static DWORD rd32(const unsigned char *p) { return (DWORD)p[0] | (DWORD)p[1] << 8 | (DWORD)p[2] << 16 | (DWORD)p[3] << 24; }
static WORD rd16(const unsigned char *p) { return (WORD)(p[0] | p[1] << 8); }

typedef struct { DWORD va, vsize, raw_off, raw_size; } section_t;

static int rva_to_off(const section_t *s, unsigned n, DWORD rva, ULONGLONG *off, DWORD *avail)
{
    unsigned i;
    for (i = 0; i < n; ++i) {
        const DWORD span = s[i].vsize > s[i].raw_size ? s[i].vsize : s[i].raw_size;
        if (rva >= s[i].va && rva - s[i].va < span) {
            if (rva - s[i].va >= s[i].raw_size) return 0;         /* uninitialised tail: no file bytes */
            *off = (ULONGLONG)s[i].raw_off + (rva - s[i].va);
            *avail = s[i].raw_size - (rva - s[i].va);
            return 1;
        }
    }
    return 0;
}

/* Find one entry with numeric id `id` (or, if id == 0xffffffff, the best language entry) in a resource directory at
 * file offset `dir_off`. Returns the raw OffsetToData field, or 0xffffffff if absent. */
static DWORD find_entry(HANDLE h, ULONGLONG dir_off, DWORD id, int pick_language)
{
    unsigned char hdr[16], e[8];
    unsigned nnamed, nid, i;
    DWORD best = 0xffffffffu, first = 0xffffffffu;
    int best_rank = 99;
    if (!read_at(h, dir_off, hdr, 16)) return 0xffffffffu;
    nnamed = rd16(hdr + 12);
    nid = rd16(hdr + 14);
    if (nid > 4096) return 0xffffffffu;
    for (i = 0; i < nid; ++i) {
        DWORD name, data;
        if (!read_at(h, dir_off + 16 + (ULONGLONG)(nnamed + i) * 8, e, 8)) return 0xffffffffu;
        name = rd32(e);
        data = rd32(e + 4);
        if (name & 0x80000000u) continue;
        if (!pick_language) {
            if (name == id) return data;
        } else {
            int rank = name == 0 ? 0 : name == 0x0409 ? 1 : 2;       /* neutral, then en-US, then the first one */
            if (first == 0xffffffffu) first = data;
            if (rank < best_rank) { best_rank = rank; best = data; }
        }
    }
    return pick_language ? (best != 0xffffffffu ? best : first) : 0xffffffffu;
}

/* Locate the VS_VERSIONINFO data. On success returns 0 and gives the file offset and size of the resource data;
 * otherwise a Win32 error code. */
static DWORD locate_version(HANDLE h, ULONGLONG *data_off, DWORD *data_size)
{
    unsigned char dos[64], nt[24 + 240], sect[40 * 96];
    DWORD lfanew, nsec, optsize, rsrc_rva, rsrc_size, e, dr, nread;
    unsigned magic, dd_off, i;
    section_t secs[96];
    ULONGLONG rsrc_off, off;
    LARGE_INTEGER fsize;
    DWORD avail;
    if (!GetFileSizeEx(h, &fsize) || fsize.QuadPart < 64) return ERROR_BAD_EXE_FORMAT;
    if (!read_at(h, 0, dos, 64) || rd16(dos) != 0x5a4d) return ERROR_BAD_EXE_FORMAT;
    lfanew = rd32(dos + 60);
    if (lfanew < 64 || (ULONGLONG)lfanew + 24 + 2 > (ULONGLONG)fsize.QuadPart) return ERROR_BAD_EXE_FORMAT;
    nread = (ULONGLONG)fsize.QuadPart - lfanew < sizeof nt ? (DWORD)((ULONGLONG)fsize.QuadPart - lfanew) : (DWORD)sizeof nt;
    if (!read_at(h, lfanew, nt, nread)) return ERROR_BAD_EXE_FORMAT;
    if (rd32(nt) != 0x00004550u) return ERROR_BAD_EXE_FORMAT;
    nsec = rd16(nt + 6);
    optsize = rd16(nt + 20);
    magic = rd16(nt + 24);
    if (nsec == 0 || nsec > 96) return ERROR_BAD_EXE_FORMAT;
    if (magic == 0x20b) dd_off = 24 + 112;                                            /* PE32+: data directories at +112 */
    else if (magic == 0x10b) dd_off = 24 + 96;                                        /* PE32: at +96 */
    else return ERROR_BAD_EXE_FORMAT;
    if (optsize < dd_off - 24 + 3 * 8 || dd_off + 3 * 8 > nread || rd32(nt + 24 + (magic == 0x20b ? 108 : 92)) < 3)
        return ERROR_RESOURCE_DATA_NOT_FOUND;                                        /* no resource directory entry */
    rsrc_rva = rd32(nt + dd_off + 2 * 8);
    rsrc_size = rd32(nt + dd_off + 2 * 8 + 4);
    if (!read_at(h, (ULONGLONG)lfanew + 24 + optsize, sect, nsec * 40)) return ERROR_BAD_EXE_FORMAT;
    for (i = 0; i < nsec; ++i) {
        secs[i].vsize = rd32(sect + i * 40 + 8);
        secs[i].va = rd32(sect + i * 40 + 12);
        secs[i].raw_size = rd32(sect + i * 40 + 16);
        secs[i].raw_off = rd32(sect + i * 40 + 20);
    }
    if (!rsrc_rva || !rsrc_size || !rva_to_off(secs, nsec, rsrc_rva, &rsrc_off, &avail)) return ERROR_RESOURCE_DATA_NOT_FOUND;
    /* type level: RT_VERSION = 16 */
    e = find_entry(h, rsrc_off, 16, 0);
    if (e == 0xffffffffu || !(e & 0x80000000u)) return ERROR_RESOURCE_DATA_NOT_FOUND;
    /* name level: id 1 (VS_VERSION_INFO) */
    e = find_entry(h, rsrc_off + (e & 0x7fffffffu), 1, 0);
    if (e == 0xffffffffu || !(e & 0x80000000u)) return ERROR_RESOURCE_DATA_NOT_FOUND;
    /* language level */
    e = find_entry(h, rsrc_off + (e & 0x7fffffffu), 0, 1);
    if (e == 0xffffffffu || (e & 0x80000000u)) return ERROR_RESOURCE_DATA_NOT_FOUND;
    {
        unsigned char de[16];
        if (!read_at(h, rsrc_off + e, de, 16)) return ERROR_BAD_EXE_FORMAT;
        dr = rd32(de);                                                                /* RVA of the data */
        *data_size = rd32(de + 4);
    }
    if (!*data_size || *data_size > MAX_RES_SIZE || !rva_to_off(secs, nsec, dr, &off, &avail) || avail < *data_size)
        return ERROR_RESOURCE_DATA_NOT_FOUND;
    *data_off = off;
    return 0;
}

static size_t wlen_(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

static int has_separator(const WCHAR *s)
{
    for (; *s; ++s) if (*s == '\\' || *s == '/' || *s == ':') return 1;
    return 0;
}

/* Opens the image `name` the way Windows' GetFileVersionInfo does: a name with a path component is opened as given; a
 * bare name goes through the DLL search order (LoadLibraryEx as a data file: the application directory, the system
 * directory, then the current directory), ".dll" being appended when it has no extension, exactly as LoadLibrary does.
 * That is how a program asks for the version of "kernel32.dll" without knowing where it lives. */
static HANDLE open_image(LPCWSTR name)
{
    WCHAR path[MAX_PATH + 16], base[MAX_PATH + 16];
    HANDLE h;
    size_t n, i, dir, k;
    int dot = 0;
    if (has_separator(name)) return CreateFileW(name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    n = wlen_(name);
    if (n == 0 || n >= MAX_PATH) return INVALID_HANDLE_VALUE;
    for (i = 0; i < n; ++i) if (name[i] == '.') dot = 1;
    memcpy(base, name, (n + 1) * sizeof(WCHAR));
    if (!dot && name[n - 1] != '.') { base[n++] = '.'; base[n++] = 'd'; base[n++] = 'l'; base[n++] = 'l'; base[n] = 0; }
    for (k = 0; k < 3; ++k) {
        DWORD len = 0;
        if (k == 0) {                                                       /* application directory */
            len = GetModuleFileNameW(0, path, MAX_PATH);
            if (!len || len >= MAX_PATH) continue;
            for (dir = len; dir > 0 && path[dir - 1] != '\\' && path[dir - 1] != '/'; --dir) ;
            len = (DWORD)dir;
        } else if (k == 1) {                                                /* system directory */
            len = GetSystemDirectoryW(path, MAX_PATH);
            if (!len || len >= MAX_PATH) continue;
            path[len++] = '\\';
        } else {                                                            /* current directory */
            len = GetCurrentDirectoryW(MAX_PATH, path);
            if (!len || len >= MAX_PATH) continue;
            if (path[len - 1] != '\\') path[len++] = '\\';
        }
        if (len + n + 1 > sizeof path / sizeof path[0]) continue;
        memcpy(path + len, base, (n + 1) * sizeof(WCHAR));
        h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
        if (h != INVALID_HANDLE_VALUE) return h;
    }
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

/* Reads the version resource of `name` into a heap block; *len receives VS_VERSIONINFO.wLength (the size a caller must
 * provide). Returns 0 or a Win32 error code. */
static DWORD load_version(LPCWSTR name, void **out, DWORD *len)
{
    HANDLE h;
    ULONGLONG off;
    DWORD size, err, wlen;
    unsigned char *buf;
    if (!name || !*name) return ERROR_INVALID_PARAMETER;
    h = open_image(name);
    if (h == INVALID_HANDLE_VALUE) { err = GetLastError(); return err ? err : ERROR_FILE_NOT_FOUND; }
    err = locate_version(h, &off, &size);
    if (err) { CloseHandle(h); return err; }
    buf = HeapAlloc(GetProcessHeap(), 0, size);
    if (!buf) { CloseHandle(h); return ERROR_NOT_ENOUGH_MEMORY; }
    if (!read_at(h, off, buf, size)) { HeapFree(GetProcessHeap(), 0, buf); CloseHandle(h); return ERROR_BAD_EXE_FORMAT; }
    CloseHandle(h);
    wlen = rd16(buf);
    if (wlen < sizeof(vs_node) + 2 || wlen > size) { HeapFree(GetProcessHeap(), 0, buf); return ERROR_RESOURCE_DATA_NOT_FOUND; }
    *out = buf;
    *len = wlen;
    return 0;
}

DLLAPI DWORD WINAPI GetFileVersionInfoSizeW(LPCWSTR name, LPDWORD handle)
{
    void *buf = 0;
    DWORD len = 0, err;
    if (handle) *handle = 0;
    err = load_version(name, &buf, &len);
    if (err) { SetLastError(err); return 0; }
    HeapFree(GetProcessHeap(), 0, buf);
    SetLastError(ERROR_SUCCESS);
    return len;
}

DLLAPI BOOL WINAPI GetFileVersionInfoW(LPCWSTR name, DWORD handle, DWORD len, LPVOID data)
{
    void *buf = 0;
    DWORD need = 0, err;
    (void)handle;
    if (!data) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    err = load_version(name, &buf, &need);
    if (err) { SetLastError(err); return FALSE; }
    if (len < need) { HeapFree(GetProcessHeap(), 0, buf); SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
    memcpy(data, buf, need);
    HeapFree(GetProcessHeap(), 0, buf);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

/* The Ex variants take a FILE_VER_GET_* flag word: FILE_VER_GET_LOCALISED/NEUTRAL select the MUI resource language and
 * FILE_VER_GET_PREFETCHED skips the disk read. This system has no MUI satellite files, so the resource in the image is the
 * only one and every flag combination yields the same block; the flags are validated (unknown bits are an error, as on
 * Windows) and otherwise have nothing to select. */
#define FILE_VER_KNOWN_FLAGS (0x1u | 0x2u | 0x4u)

DLLAPI DWORD WINAPI GetFileVersionInfoSizeExW(DWORD flags, LPCWSTR name, LPDWORD handle)
{
    if (flags & ~FILE_VER_KNOWN_FLAGS) { if (handle) *handle = 0; SetLastError(ERROR_INVALID_PARAMETER); return 0; }
    return GetFileVersionInfoSizeW(name, handle);
}

DLLAPI BOOL WINAPI GetFileVersionInfoExW(DWORD flags, LPCWSTR name, DWORD handle, DWORD len, LPVOID data)
{
    if (flags & ~FILE_VER_KNOWN_FLAGS) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    return GetFileVersionInfoW(name, handle, len, data);
}

/* ---------------------------------------------------------------- VerQueryValue */
static DWORD align4(DWORD v) { return (v + 3) & ~3u; }

static int key_eq_i(const WCHAR *key, const WCHAR *name, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        WCHAR a = key[i], b = name[i];
        if (a >= 'A' && a <= 'Z') a = (WCHAR)(a + 32);
        if (b >= 'A' && b <= 'Z') b = (WCHAR)(b + 32);
        if (a != b || !a) return 0;
    }
    return key[n] == 0;
}

/* Layout helpers for one node at `p` inside a block ending at `end`. */
static int node_layout(const unsigned char *p, const unsigned char *end, const WCHAR **key, const unsigned char **value,
                       DWORD *value_bytes, const unsigned char **children, const unsigned char **node_end, const unsigned char *root)
{
    const vs_node *n = (const vs_node *)p;
    size_t klen;
    DWORD voff, coff;
    if (end - p < (long)sizeof(vs_node) + 2 || n->wLength < sizeof(vs_node) + 2 || n->wLength > end - p) return 0;
    *key = (const WCHAR *)(p + sizeof(vs_node));
    klen = 0;
    while ((const unsigned char *)(*key + klen + 1) <= p + n->wLength && (*key)[klen]) ++klen;
    if ((const unsigned char *)(*key + klen + 1) > p + n->wLength) return 0;         /* unterminated key */
    voff = align4((DWORD)(p - root) + (DWORD)sizeof(vs_node) + (DWORD)(klen + 1) * 2) - (DWORD)(p - root);
    *value_bytes = n->wType == 1 ? (DWORD)n->wValueLength * 2 : n->wValueLength;
    if (voff > n->wLength || *value_bytes > n->wLength - voff) {
        if (voff > n->wLength) return 0;
        /* some producers store a text value length that overshoots the node: clamp to the node */
        *value_bytes = n->wLength - voff;
    }
    coff = align4((DWORD)(p - root) + voff + *value_bytes) - (DWORD)(p - root);
    *value = p + voff;
    *children = coff < n->wLength ? p + coff : p + n->wLength;
    *node_end = p + n->wLength;
    return 1;
}

DLLAPI BOOL WINAPI VerQueryValueW(LPCVOID block, LPCWSTR sub, LPVOID *out_buf, PUINT out_len)
{
    const unsigned char *root = block, *cur, *cur_end, *children;
    const WCHAR *key;
    const unsigned char *value, *node_end;
    DWORD vbytes;
    static const WCHAR vsi[] = { 'V', 'S', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N', '_', 'I', 'N', 'F', 'O', 0 };
    int is_text = 0;
    if (out_buf) *out_buf = 0;
    if (out_len) *out_len = 0;
    if (!block || !sub || !out_buf || !out_len) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    {
        const vs_node *r = block;
        if (r->wLength < sizeof(vs_node) + 2 * 16) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
        cur_end = root + r->wLength;
    }
    cur = root;
    if (!node_layout(cur, cur_end, &key, &value, &vbytes, &children, &node_end, root) || !key_eq_i(key, vsi, 15)) {
        SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND);
        return FALSE;
    }
    while (*sub == '\\') ++sub;
    if (!*sub) {                                                              /* the root: VS_FIXEDFILEINFO */
        const DWORD *sig = (const DWORD *)value;
        if (vbytes < 52 || *sig != VS_FFI_SIGNATURE) { SetLastError(ERROR_RESOURCE_DATA_NOT_FOUND); return FALSE; }
        *out_buf = (LPVOID)value;
        *out_len = 52;
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }
    /* walk the components; at each level the children of the current node are scanned for the component name */
    for (;;) {
        const WCHAR *comp = sub;
        size_t clen = 0;
        const unsigned char *child, *child_end = node_end;
        int found = 0;
        while (comp[clen] && comp[clen] != '\\') ++clen;
        for (child = children; child < child_end; ) {
            const WCHAR *ckey;
            const unsigned char *cvalue, *cchildren, *cend;
            DWORD cvbytes;
            const vs_node *cn = (const vs_node *)child;
            if (!node_layout(child, child_end, &ckey, &cvalue, &cvbytes, &cchildren, &cend, root)) break;
            if (key_eq_i(ckey, comp, clen)) {
                found = 1;
                value = cvalue; vbytes = cvbytes; children = cchildren; node_end = cend;
                is_text = cn->wType == 1;
                (void)wlen_;
                break;
            }
            child = root + align4((DWORD)(cend - root));
        }
        if (!found) { SetLastError(ERROR_RESOURCE_TYPE_NOT_FOUND); return FALSE; }
        sub += clen;
        while (*sub == '\\') ++sub;
        if (!*sub) break;
    }
    *out_buf = (LPVOID)value;
    *out_len = is_text ? vbytes / 2 : vbytes;                                   /* characters for text values, bytes otherwise */
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}
