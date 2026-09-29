/* SPDX-License-Identifier: GPL-2.0-only
 * shlwapi.dll - the path and string helpers that can be implemented exactly without a shell, registry or locale
 * database. Only Unicode (W) entry points exist.
 *
 * Path functions follow the documented shlwapi semantics (MSDN, "Path Functions"): backslash is the separator, buffers
 * are MAX_PATH wide characters, PathCanonicalize/PathCombine/PathRemoveFileSpec use the classic algorithms.
 * PathFileExists/PathIsDirectory call the real kernel32 file attribute query.
 *
 * "Case-insensitive" means: equal simple upper-case mappings of the UTF-16 code units (shz_wupper.h, generated from the
 * Unicode database). This system has no NLS tables, so the Str*Cmp* family compares by code unit (ordinal) and returns
 * <0 / 0 / >0 by code-unit order; real shlwapi compares linguistically for the locale (word sort), which can order
 * (and, for hyphens and apostrophes, even equate) strings differently. Programs that only test for equality or sort
 * ASCII text behave identically.
 *
 * Not provided (they need a registry, a shell or exact locale tables): AssocQueryString*, Url*, SH* reg helpers,
 * StrFormatByteSize*, wnsprintf*, all ANSI (A) variants.
 */
#include "nt.h"
#include <string.h>
#include "shz_wupper.h"

#define STIF_DEFAULT 0
#define STIF_SUPPORT_HEX 1

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static WCHAR up(WCHAR c) { return shz_wupper(c); }
static int is_space(WCHAR c) { return c == ' ' || (c >= 9 && c <= 13); }
static int is_xdigit(WCHAR c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }
static WCHAR next_char_lower_ascii(WCHAR c) { return (c >= 'A' && c <= 'Z') ? (WCHAR)(c + 32) : c; }

/* ================================================================ paths */
DLLAPI LPWSTR WINAPI PathFindFileNameW(LPCWSTR path)
{
    const WCHAR *last = path;
    while (path && *path) {
        if ((*path == '\\' || *path == '/' || *path == ':') && path[1] && path[1] != '\\' && path[1] != '/') last = path + 1;
        ++path;
    }
    return (LPWSTR)last;
}

DLLAPI LPWSTR WINAPI PathFindExtensionW(LPCWSTR path)
{
    const WCHAR *last_dot = 0;
    if (path) {
        while (*path) {
            if (*path == '\\' || *path == ' ') last_dot = 0;             /* an extension cannot span a separator or a space */
            else if (*path == '.') last_dot = path;
            ++path;
        }
    }
    return (LPWSTR)(last_dot ? last_dot : path);
}

DLLAPI void WINAPI PathRemoveExtensionW(LPWSTR path)
{
    if (path) {
        path = PathFindExtensionW(path);
        if (path && *path) *path = 0;
    }
}

DLLAPI BOOL WINAPI PathIsRelativeW(LPCWSTR path)
{
    if (!path || !*path) return TRUE;
    if (*path == '\\' || path[1] == ':') return FALSE;
    return TRUE;
}

DLLAPI BOOL WINAPI PathIsUNCW(LPCWSTR path) { return path && path[0] == '\\' && path[1] == '\\'; }

static BOOL is_unc_server_share(LPCWSTR path)
{
    BOOL seen = FALSE;
    if (path && *path++ == '\\' && *path++ == '\\') {
        while (*path) {
            if (*path == '\\') {
                if (seen) return FALSE;
                seen = TRUE;
            }
            ++path;
        }
        return seen;
    }
    return FALSE;
}

DLLAPI BOOL WINAPI PathIsRootW(LPCWSTR path)
{
    if (path && *path) {
        if (*path == '\\') {
            if (!path[1]) return TRUE;                                   /* "\" */
            if (path[1] == '\\') {                                       /* \\server or \\server\share */
                BOOL seen = FALSE;
                path += 2;
                while (*path) {
                    if (*path == '\\') {
                        if (seen) return FALSE;
                        seen = TRUE;
                    }
                    ++path;
                }
                return TRUE;
            }
        } else if (path[1] == ':' && path[2] == '\\' && path[3] == 0) {
            return TRUE;                                                 /* "X:\" */
        }
    }
    return FALSE;
}

DLLAPI LPWSTR WINAPI PathAddBackslashW(LPWSTR path)
{
    size_t n;
    if (!path) return 0;
    n = wlen(path);
    if (!n) return path;
    if (path[n - 1] != '\\') {
        if (n + 1 >= MAX_PATH) return 0;                                 /* no room for the backslash */
        path[n++] = '\\';
        path[n] = 0;
    }
    return path + n;
}

DLLAPI LPWSTR WINAPI PathRemoveBackslashW(LPWSTR path)
{
    size_t n;
    if (!path) return 0;
    n = wlen(path);
    if (n && path[n - 1] == '\\' && !PathIsRootW(path)) path[--n] = 0;
    return path + n;
}

DLLAPI BOOL WINAPI PathRemoveFileSpecW(LPWSTR path)
{
    WCHAR *spec = path;
    BOOL modified = FALSE;
    if (path) {
        if (*path == '\\') spec = ++path;                                /* skip a leading "\" or "\\" (UNC) */
        if (*path == '\\') spec = ++path;
        while (*path) {
            if (*path == '\\') {
                spec = path;                                             /* candidate: the last directory separator */
            } else if (*path == ':') {
                spec = ++path;                                           /* drive: keep "X:" and a following "\" */
                if (*path == '\\') ++spec;
            }
            if (!*path) break;
            ++path;
        }
        if (*spec) {
            *spec = 0;
            modified = TRUE;
        }
    }
    return modified;
}

DLLAPI BOOL WINAPI PathStripToRootW(LPWSTR path)
{
    if (!path) return FALSE;
    while (!PathIsRootW(path))
        if (!PathRemoveFileSpecW(path)) return FALSE;
    return TRUE;
}

DLLAPI void WINAPI PathStripPathW(LPWSTR path)
{
    if (path) {
        WCHAR *file = PathFindFileNameW(path);
        if (file != path) memmove(path, file, (wlen(file) + 1) * sizeof(WCHAR));
    }
}

DLLAPI LPWSTR WINAPI PathSkipRootW(LPCWSTR path)
{
    if (!path || !*path) return 0;
    if (path[0] == '\\' && path[1] == '\\') {                            /* \\server\share\ */
        const WCHAR *p = path + 2;
        while (*p && *p != '\\') ++p;
        if (!*p) return 0;
        ++p;
        while (*p && *p != '\\') ++p;
        if (*p) ++p;
        return (LPWSTR)p;
    }
    if (path[0] && path[1] == ':' && path[2] == '\\') return (LPWSTR)path + 3;
    return 0;
}

DLLAPI BOOL WINAPI PathCanonicalizeW(LPWSTR buf, LPCWSTR path)
{
    WCHAR *dst = buf;
    const WCHAR *src = path;
    if (buf) *dst = 0;
    if (!buf || !path) { shz_set_last_error(ERROR_INVALID_PARAMETER); return FALSE; }
    if (!*path) {                                                        /* documented: an empty path becomes "\" */
        *buf++ = '\\';
        *buf = 0;
        return TRUE;
    }
    if (*src == '\\') {
        *dst++ = *src++;
    } else if (*src && src[1] == ':') {                                  /* drive letter */
        *dst++ = *src++;
        *dst++ = *src++;
        *dst = 0;
    }
    while (*src) {
        if (*src == '.') {
            if (src[1] == '\\' && (src == path || src[-1] == '\\' || src[-1] == ':')) {
                src += 2;                                                /* ".\" */
            } else if (src[1] == '.' && (dst == buf || dst[-1] == '\\')) {
                /* "\.." backs up one component, never above the root; never removes a UNC server name */
                if (dst != buf) {
                    *dst = 0;
                    if (dst > buf + 1 && dst[-1] == '\\' && (dst[-2] != '\\' || dst > buf + 2)) {
                        if (dst[-2] == ':' && (dst > buf + 3 || dst[-3] == ':')) {
                            dst -= 2;
                            while (dst > buf && *dst != '\\') --dst;
                            if (*dst == '\\') ++dst;
                            else dst = buf;
                        } else if (dst[-2] != ':' && !is_unc_server_share(buf)) {
                            dst -= 2;
                        }
                    }
                    while (dst > buf && *dst != '\\') --dst;
                    if (dst == buf) {
                        *dst++ = '\\';
                        ++src;
                    }
                }
                src += 2;                                                /* skip ".." */
            } else {
                *dst++ = *src++;
            }
        } else {
            *dst++ = *src++;
        }
    }
    if (dst - buf == 2 && dst[-1] == ':') *dst++ = '\\';                 /* naked drive: "C:" -> "C:\" */
    *dst = 0;
    return TRUE;
}

DLLAPI LPWSTR WINAPI PathCombineW(LPWSTR dest, LPCWSTR dir, LPCWSTR file)
{
    WCHAR tmp[MAX_PATH];
    BOOL both = FALSE, strip = FALSE;
    size_t n;
    if (!dest || (!dir && !file)) return 0;
    if (!dir) dir = L"";
    if (!file || !*file) {
        for (n = 0; dir[n] && n < MAX_PATH - 1; ++n) tmp[n] = dir[n];            /* file part empty: canonicalize dir */
        tmp[n] = 0;
    } else if (!dir || !*dir || !PathIsRelativeW(file)) {
        if (!dir || !*dir || *file != '\\' || PathIsUNCW(file)) {                /* the file part wins */
            for (n = 0; file[n] && n < MAX_PATH - 1; ++n) tmp[n] = file[n];
            tmp[n] = 0;
        } else {                                                                 /* "\file" is relative to dir's root */
            both = TRUE;
            strip = TRUE;
        }
    } else {
        both = TRUE;
    }
    if (both) {
        size_t fl;
        for (n = 0; dir[n] && n < MAX_PATH - 1; ++n) tmp[n] = dir[n];
        tmp[n] = 0;
        if (strip) {
            PathStripToRootW(tmp);
            ++file;                                                              /* skip the '\' */
        }
        if (!PathAddBackslashW(tmp)) return 0;
        fl = wlen(file);
        if (wlen(tmp) + fl >= MAX_PATH) return 0;
        memcpy(tmp + wlen(tmp), file, (fl + 1) * sizeof(WCHAR));
    }
    PathCanonicalizeW(dest, tmp);
    return dest;
}

DLLAPI BOOL WINAPI PathAppendW(LPWSTR path, LPCWSTR more)
{
    if (path && more) {
        if (!PathIsUNCW(more))
            while (*more == '\\') ++more;                                        /* "a" + "\b" appends, it does not replace */
        if (PathCombineW(path, path, more)) return TRUE;
    }
    return FALSE;
}

DLLAPI BOOL WINAPI PathFileExistsW(LPCWSTR path)
{
    if (!path) return FALSE;
    return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

DLLAPI BOOL WINAPI PathIsDirectoryW(LPCWSTR path)
{
    DWORD a;
    if (!path) return FALSE;
    a = GetFileAttributesW(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

DLLAPI LPWSTR WINAPI PathGetArgsW(LPCWSTR path)
{
    BOOL quoted = FALSE;
    if (path) {
        while (*path) {
            if (*path == ' ' && !quoted) return (LPWSTR)path + 1;
            if (*path == '"') quoted = !quoted;
            ++path;
        }
    }
    return (LPWSTR)path;
}

DLLAPI void WINAPI PathRemoveArgsW(LPWSTR path)
{
    if (path) {
        WCHAR *args = PathGetArgsW(path);
        if (*args) args[-1] = 0;
        else if (args > path && args[-1] == ' ') args[-1] = 0;
    }
}

DLLAPI void WINAPI PathUnquoteSpacesW(LPWSTR path)
{
    if (path && *path == '"') {
        size_t n = wlen(path);
        if (n >= 2 && path[n - 1] == '"') {
            path[n - 1] = 0;
            memmove(path, path + 1, n * sizeof(WCHAR));
        }
    }
}

DLLAPI BOOL WINAPI PathAddExtensionW(LPWSTR path, LPCWSTR ext)
{
    size_t n, e;
    if (!path) return FALSE;
    if (*PathFindExtensionW(path)) return FALSE;                                 /* already has one */
    if (!ext) ext = L".exe";
    n = wlen(path);
    e = wlen(ext);
    if (n + e >= MAX_PATH) return FALSE;
    memcpy(path + n, ext, (e + 1) * sizeof(WCHAR));
    return TRUE;
}

/* PathMatchSpec: MS-DOS wildcards, '*' any run, '?' any one character, several specs separated by ';' (leading blanks
 * of each spec are skipped), case-insensitive. */
static BOOL match_one(const WCHAR *name, const WCHAR *mask)
{
    while (*name && *mask && *mask != ';') {
        if (*mask == '*') {
            do {
                if (match_one(name, mask + 1)) return TRUE;
            } while (*name++);
            return FALSE;
        }
        if (up(*mask) != up(*name) && *mask != '?') return FALSE;
        ++name;
        ++mask;
    }
    if (!*name) {
        while (*mask == '*') ++mask;
        if (!*mask || *mask == ';') return TRUE;
    }
    return FALSE;
}

DLLAPI BOOL WINAPI PathMatchSpecW(LPCWSTR file, LPCWSTR spec)
{
    if (!file || !spec) return FALSE;
    if (spec[0] == '*' && !spec[1]) return TRUE;
    while (*spec) {
        while (*spec == ' ') ++spec;
        if (match_one(file, spec)) return TRUE;
        while (*spec && *spec != ';') ++spec;
        if (*spec == ';') ++spec;
    }
    return FALSE;
}

/* ================================================================ strings */
DLLAPI LPWSTR WINAPI StrChrW(LPCWSTR s, WCHAR c)
{
    if (s)
        for (; *s; ++s)
            if (*s == c) return (LPWSTR)s;
    return 0;
}

DLLAPI LPWSTR WINAPI StrChrIW(LPCWSTR s, WCHAR c)
{
    if (s) {
        c = up(c);
        for (; *s; ++s)
            if (up(*s) == c) return (LPWSTR)s;
    }
    return 0;
}

DLLAPI LPWSTR WINAPI StrRChrW(LPCWSTR s, LPCWSTR end, WCHAR c)
{
    const WCHAR *ret = 0;
    if (!s) return 0;
    if (!end) end = s + wlen(s);
    for (; s < end; ++s)
        if (*s == c) ret = s;
    return (LPWSTR)ret;
}

DLLAPI LPWSTR WINAPI StrRChrIW(LPCWSTR s, LPCWSTR end, WCHAR c)
{
    const WCHAR *ret = 0;
    if (!s) return 0;
    if (!end) end = s + wlen(s);
    c = up(c);
    for (; s < end; ++s)
        if (up(*s) == c) ret = s;
    return (LPWSTR)ret;
}

DLLAPI LPWSTR WINAPI StrStrW(LPCWSTR s, LPCWSTR find)
{
    size_t fl;
    if (!s || !find || !*find) return 0;
    fl = wlen(find);
    for (; *s; ++s) {
        size_t i = 0;
        while (i < fl && s[i] == find[i]) ++i;
        if (i == fl) return (LPWSTR)s;
        if (!s[i]) break;
    }
    return 0;
}

DLLAPI LPWSTR WINAPI StrStrIW(LPCWSTR s, LPCWSTR find)
{
    size_t fl;
    if (!s || !find || !*find) return 0;
    fl = wlen(find);
    for (; *s; ++s) {
        size_t i = 0;
        while (i < fl && s[i] && up(s[i]) == up(find[i])) ++i;
        if (i == fl) return (LPWSTR)s;
        if (!s[i]) break;
    }
    return 0;
}

DLLAPI int WINAPI StrCmpW(LPCWSTR a, LPCWSTR b)
{
    while (*a && *a == *b) { ++a; ++b; }
    return *a < *b ? -1 : *a > *b ? 1 : 0;
}

DLLAPI int WINAPI StrCmpIW(LPCWSTR a, LPCWSTR b)
{
    while (*a && up(*a) == up(*b)) { ++a; ++b; }
    return up(*a) < up(*b) ? -1 : up(*a) > up(*b) ? 1 : 0;
}

DLLAPI int WINAPI StrCmpNW(LPCWSTR a, LPCWSTR b, int n)
{
    for (; n > 0; --n, ++a, ++b) {
        if (*a != *b) return *a < *b ? -1 : 1;
        if (!*a) return 0;
    }
    return 0;
}

DLLAPI int WINAPI StrCmpNIW(LPCWSTR a, LPCWSTR b, int n)
{
    for (; n > 0; --n, ++a, ++b) {
        WCHAR x = up(*a), y = up(*b);
        if (x != y) return x < y ? -1 : 1;
        if (!*a) return 0;
    }
    return 0;
}

DLLAPI BOOL WINAPI StrIsIntlEqualW(BOOL case_sensitive, LPCWSTR a, LPCWSTR b, int n)
{
    return (case_sensitive ? StrCmpNW(a, b, n) : StrCmpNIW(a, b, n)) == 0;
}

DLLAPI int WINAPI StrCSpnW(LPCWSTR s, LPCWSTR set)
{
    int n = 0;
    if (!s || !set) return 0;
    while (s[n] && !StrChrW(set, s[n])) ++n;
    return n;
}

DLLAPI int WINAPI StrCSpnIW(LPCWSTR s, LPCWSTR set)
{
    int n = 0;
    if (!s || !set) return 0;
    while (s[n] && !StrChrIW(set, s[n])) ++n;
    return n;
}

DLLAPI int WINAPI StrSpnW(LPCWSTR s, LPCWSTR set)
{
    int n = 0;
    if (!s || !set) return 0;
    while (s[n] && StrChrW(set, s[n])) ++n;
    return n;
}

DLLAPI LPWSTR WINAPI StrPBrkW(LPCWSTR s, LPCWSTR set)
{
    if (s && set)
        for (; *s; ++s)
            if (StrChrW(set, *s)) return (LPWSTR)s;
    return 0;
}

DLLAPI LPWSTR WINAPI StrCpyNW(LPWSTR dst, LPCWSTR src, int max)
{
    int i = 0;
    if (!dst || !src || max <= 0) return dst;
    while (i < max - 1 && src[i]) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
    return dst;
}

DLLAPI LPWSTR WINAPI StrCatBuffW(LPWSTR dst, LPCWSTR src, int cch_dst)
{
    int n;
    if (!dst || !src || cch_dst <= 0) return dst;
    n = (int)wlen(dst);
    if (n < cch_dst - 1) StrCpyNW(dst + n, src, cch_dst - n);
    return dst;
}

DLLAPI LPWSTR WINAPI StrDupW(LPCWSTR s)
{
    size_t n;
    WCHAR *p;
    if (!s) return 0;
    n = wlen(s) + 1;
    p = LocalAlloc(LMEM_FIXED, n * sizeof(WCHAR));                       /* documented: release with LocalFree */
    if (p) memcpy(p, s, n * sizeof(WCHAR));
    return p;
}

DLLAPI BOOL WINAPI StrTrimW(LPWSTR s, LPCWSTR trim)
{
    BOOL changed = FALSE;
    if (s && *s && trim) {
        WCHAR *rd = s;
        size_t n;
        while (*rd && StrChrW(trim, *rd)) ++rd;
        n = wlen(rd);
        if (rd != s) {
            memmove(s, rd, (n + 1) * sizeof(WCHAR));
            changed = TRUE;
        }
        if (n) {
            rd = s + n - 1;
            while (rd >= s && StrChrW(trim, *rd)) --rd;
            if (rd != s + n - 1) {
                *(++rd) = 0;
                changed = TRUE;
            }
        }
    }
    return changed;
}

DLLAPI BOOL WINAPI StrToInt64ExW(LPCWSTR s, DWORD flags, LONGLONG *out)
{
    BOOL neg = FALSE;
    LONGLONG v = 0;
    if (!s || !out) return FALSE;
    while (is_space(*s)) ++s;
    if (*s == '-') { neg = TRUE; ++s; }
    else if (*s == '+') ++s;
    if ((flags & STIF_SUPPORT_HEX) && s[0] == '0' && next_char_lower_ascii(s[1]) == 'x') {
        s += 2;
        if (!is_xdigit(*s)) return FALSE;
        while (is_xdigit(*s)) {
            WCHAR c = next_char_lower_ascii(*s);
            v = v * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
            ++s;
        }
        *out = v;                                                        /* hex values are not negated */
        return TRUE;
    }
    if (*s < '0' || *s > '9') return FALSE;
    while (*s >= '0' && *s <= '9') v = v * 10 + (*s++ - '0');
    *out = neg ? -v : v;
    return TRUE;
}

DLLAPI BOOL WINAPI StrToIntExW(LPCWSTR s, DWORD flags, int *out)
{
    LONGLONG v;
    if (!StrToInt64ExW(s, flags, &v)) return FALSE;
    if (out) *out = (int)v;
    return TRUE;
}

DLLAPI int WINAPI StrToIntW(LPCWSTR s)
{
    int v = 0;
    if (!s) return 0;
    if (*s == '-' || (*s >= '0' && *s <= '9')) StrToIntExW(s, STIF_DEFAULT, &v);
    return v;
}
