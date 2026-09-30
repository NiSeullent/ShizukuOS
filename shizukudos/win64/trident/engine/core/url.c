/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - URL resolution (see url.h).
 */
#include "url.h"

typedef struct {
    size_t scheme;                      /* length of the scheme (0 = none) */
    int has_auth;
    size_t auth_start, auth_end;
    size_t path_start, path_end;
    int has_query;
    size_t query_start, query_end;      /* query_start points at '?' */
    int has_frag;
    size_t frag_start;                  /* points at '#' */
    size_t len;
} url_parts;

size_t shz_url_scheme_len(const shz_char *url, size_t n)
{
    size_t i;
    if (!n || !shz_is_ascii_alpha(url[0])) return 0;
    for (i = 1; i < n; ++i) {
        shz_char c = url[i];
        if (c == ':') return i;
        if (!shz_is_ascii_alnum(c) && c != '+' && c != '-' && c != '.') return 0;
    }
    return 0;
}

int shz_url_has_scheme(const shz_char *url, const char *scheme)
{
    size_t n = shz_strlen(url), s = shz_url_scheme_len(url, n);
    return s && shz_strnieq_ascii(url, s, scheme);
}

static int is_special(const shz_char *url, size_t scheme)
{
    return scheme && (shz_strnieq_ascii(url, scheme, "http") || shz_strnieq_ascii(url, scheme, "https")
                      || shz_strnieq_ascii(url, scheme, "file") || shz_strnieq_ascii(url, scheme, "ftp"));
}

static int is_slash(shz_char c, int special)
{
    return c == '/' || (special && c == '\\');
}

static void split(const shz_char *u, size_t n, url_parts *p, int special_hint)
{
    size_t i;
    int special;
    memset(p, 0, sizeof(*p));
    p->len = n;
    p->scheme = shz_url_scheme_len(u, n);
    special = p->scheme ? is_special(u, p->scheme) : special_hint;
    i = p->scheme ? p->scheme + 1 : 0;
    if (i + 1 < n && is_slash(u[i], special) && is_slash(u[i + 1], special)) {
        p->has_auth = 1;
        i += 2;
        p->auth_start = i;
        while (i < n && !is_slash(u[i], special) && u[i] != '?' && u[i] != '#') ++i;
        p->auth_end = i;
    }
    p->path_start = i;
    while (i < n && u[i] != '?' && u[i] != '#') ++i;
    p->path_end = i;
    if (i < n && u[i] == '?') {
        p->has_query = 1;
        p->query_start = i;
        while (i < n && u[i] != '#') ++i;
        p->query_end = i;
    }
    if (i < n && u[i] == '#') {
        p->has_frag = 1;
        p->frag_start = i;
    }
}

/* RFC 3986 5.2.4 remove_dot_segments on path (special: '\' counts as '/'), appended to out */
static void put_path(shz_buf *out, const shz_char *path, size_t n, int special)
{
    shz_buf in;
    size_t i = 0, start = out->len;
    shz_buf_init(&in);
    for (i = 0; i < n; ++i) shz_buf_putc(&in, special && path[i] == '\\' ? '/' : path[i]);
    i = 0;
    while (i < in.len) {
        const shz_char *s = in.s + i;
        size_t left = in.len - i;
        if (left >= 3 && s[0] == '.' && s[1] == '.' && s[2] == '/') { i += 3; continue; }
        if (left >= 2 && s[0] == '.' && s[1] == '/') { i += 2; continue; }
        if (left >= 3 && s[0] == '/' && s[1] == '.' && s[2] == '/') { i += 2; continue; }
        if (left == 2 && s[0] == '/' && s[1] == '.') { in.s[i + 1] = '/'; i += 1; continue; }
        if ((left >= 4 && s[0] == '/' && s[1] == '.' && s[2] == '.' && s[3] == '/')
            || (left == 3 && s[0] == '/' && s[1] == '.' && s[2] == '.')) {
            /* remove the last segment of the output */
            size_t k = out->len;
            while (k > start && out->s[k - 1] != '/') --k;
            if (k > start) --k;
            out->len = k;
            if (left == 3) { in.s[i + 2] = '/'; i += 2; }
            else i += 3;
            continue;
        }
        if ((left == 1 && s[0] == '.') || (left == 2 && s[0] == '.' && s[1] == '.')) break;
        /* move the first segment (with its leading '/') */
        {
            size_t k = 0;
            if (s[0] == '/') shz_buf_putc(out, s[k++]);
            while (k < left && s[k] != '/') shz_buf_putc(out, s[k++]);
            i += k;
        }
    }
    shz_buf_free(&in);
}

shz_char *shz_url_resolve(const shz_char *base, const shz_char *rel_in)
{
    const shz_char *rel = rel_in ? rel_in : base;
    size_t rn, bn = shz_strlen(base);
    url_parts b, r;
    shz_buf out;
    int special;
    if (!rel) return shz_alloc(sizeof(shz_char));
    rn = shz_strlen(rel);
    /* strip leading/trailing C0 controls and spaces */
    while (rn && *rel <= ' ') { ++rel; --rn; }
    while (rn && rel[rn - 1] <= ' ') --rn;
    shz_buf_init(&out);
    split(rel, rn, &r, 0);
    if (r.scheme) {
        size_t scheme = r.scheme;
        special = is_special(rel, scheme);
        /* absolute: normalize the path of hierarchical URLs */
        split(rel, rn, &r, special);
        if (!special && !r.has_auth) return shz_strndup(rel, rn);
        shz_buf_put(&out, rel, scheme + 1);
        if (r.has_auth) {
            shz_buf_put_ascii(&out, "//");
            shz_buf_put(&out, rel + r.auth_start, r.auth_end - r.auth_start);
        }
        put_path(&out, rel + r.path_start, r.path_end - r.path_start, special);
        shz_buf_put(&out, rel + r.path_end, rn - r.path_end);
        return shz_buf_detach(&out);
    }
    if (!base || !bn) return shz_strndup(rel, rn);
    split(base, bn, &b, 0);
    special = b.scheme && is_special(base, b.scheme);
    if (!b.scheme || (!b.has_auth && !special && (b.path_end == b.path_start || base[b.path_start] != '/'))) {
        /* opaque base (about:blank, mailto:...): only a fragment can be resolved */
        if (rn && rel[0] == '#') {
            shz_buf_put(&out, base, b.has_frag ? b.frag_start : bn);
            shz_buf_put(&out, rel, rn);
            return shz_buf_detach(&out);
        }
        return shz_strndup(rel, rn);
    }
    split(rel, rn, &r, special);
    shz_buf_put(&out, base, b.scheme + 1);
    if (r.has_auth) {
        shz_buf_put_ascii(&out, "//");
        shz_buf_put(&out, rel + r.auth_start, r.auth_end - r.auth_start);
        put_path(&out, rel + r.path_start, r.path_end - r.path_start, special);
        shz_buf_put(&out, rel + r.path_end, rn - r.path_end);
        return shz_buf_detach(&out);
    }
    if (b.has_auth) {
        shz_buf_put_ascii(&out, "//");
        shz_buf_put(&out, base + b.auth_start, b.auth_end - b.auth_start);
    }
    if (r.path_end == r.path_start) {
        shz_buf_put(&out, base + b.path_start, b.path_end - b.path_start);
        if (r.has_query) shz_buf_put(&out, rel + r.query_start, rn - r.query_start);
        else {
            if (b.has_query) shz_buf_put(&out, base + b.query_start, b.query_end - b.query_start);
            shz_buf_put(&out, rel + r.path_end, rn - r.path_end);
        }
        return shz_buf_detach(&out);
    }
    if (is_slash(rel[r.path_start], special)) {
        put_path(&out, rel + r.path_start, r.path_end - r.path_start, special);
    } else {
        /* merge: base path up to its last '/' + rel path */
        shz_buf merged;
        size_t k = b.path_end;
        shz_buf_init(&merged);
        while (k > b.path_start && !is_slash(base[k - 1], special)) --k;
        if (b.has_auth && b.path_end == b.path_start) shz_buf_putc(&merged, '/');
        else shz_buf_put(&merged, base + b.path_start, k - b.path_start);
        shz_buf_put(&merged, rel + r.path_start, r.path_end - r.path_start);
        put_path(&out, merged.s, merged.len, special);
        shz_buf_free(&merged);
    }
    shz_buf_put(&out, rel + r.path_end, rn - r.path_end);
    return shz_buf_detach(&out);
}

shz_char *shz_url_file_path(const shz_char *url)
{
    size_t n = shz_strlen(url), i, end;
    shz_buf out;
    if (!shz_url_has_scheme(url, "file")) return NULL;
    i = 5;
    if (i + 1 < n && (url[i] == '/' || url[i] == '\\') && (url[i + 1] == '/' || url[i + 1] == '\\')) {
        i += 2;
        /* host: only empty or "localhost" */
        if (shz_starts_with_ascii_ci(url + i, n - i, "localhost")) i += 9;
    }
    end = i;
    while (end < n && url[end] != '?' && url[end] != '#') ++end;
    /* "/C:/..." -> "C:/..." */
    if (end - i >= 3 && (url[i] == '/' || url[i] == '\\') && shz_is_ascii_alpha(url[i + 1])
        && (url[i + 2] == ':' || url[i + 2] == '|'))
        ++i;
    shz_buf_init(&out);
    while (i < end) {
        shz_char c = url[i];
        if (c == '%' && i + 2 < end && shz_is_ascii_hex(url[i + 1]) && shz_is_ascii_hex(url[i + 2])) {
            /* decode a UTF-8 percent sequence */
            uint8_t bytes[4];
            size_t nb = 0, k = i;
            uint32_t cp;
            while (nb < 4 && k + 2 < end && url[k] == '%' && shz_is_ascii_hex(url[k + 1]) && shz_is_ascii_hex(url[k + 2])) {
                bytes[nb] = (uint8_t)(shz_hex_value(url[k + 1]) * 16 + shz_hex_value(url[k + 2]));
                if (nb == 0 && bytes[0] < 0x80) { ++nb; k += 3; break; }
                if (nb > 0 && (bytes[nb] & 0xC0) != 0x80) break;
                ++nb;
                k += 3;
                if (nb == 2 && (bytes[0] & 0xE0) == 0xC0) break;
                if (nb == 3 && (bytes[0] & 0xF0) == 0xE0) break;
            }
            if (bytes[0] < 0x80) cp = bytes[0];
            else if (nb == 2 && (bytes[0] & 0xE0) == 0xC0) cp = ((uint32_t)(bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
            else if (nb == 3 && (bytes[0] & 0xF0) == 0xE0)
                cp = ((uint32_t)(bytes[0] & 0x0F) << 12) | ((uint32_t)(bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
            else if (nb == 4 && (bytes[0] & 0xF8) == 0xF0)
                cp = ((uint32_t)(bytes[0] & 0x07) << 18) | ((uint32_t)(bytes[1] & 0x3F) << 12)
                     | ((uint32_t)(bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
            else { cp = 0xFFFD; if (k == i) k = i + 3; }
            shz_buf_put_cp(&out, cp);
            i = k;
            continue;
        }
        shz_buf_putc(&out, c == '|' ? ':' : c);
        ++i;
    }
    return shz_buf_detach(&out);
}

shz_char *shz_url_strip_fragment(const shz_char *url)
{
    size_t n = shz_strlen(url), i;
    for (i = 0; i < n; ++i)
        if (url[i] == '#') break;
    return shz_strndup(url, i);
}
