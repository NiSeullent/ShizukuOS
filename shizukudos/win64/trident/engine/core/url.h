/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - URL helpers (core). RFC 3986 reference resolution with the WHATWG URL Standard's leniencies
 * that matter for old pages (backslashes are slashes in http/https/file URLs, surrounding whitespace is stripped).
 */
#ifndef SHZ_URL_H
#define SHZ_URL_H

#include "base.h"

/* Resolve rel against base (absolute URL). Allocated; NULL on OOM. When base cannot serve as a base (NULL, or a
 * non-hierarchical URL like "about:blank") a relative rel is returned unchanged (trimmed). */
shz_char *shz_url_resolve(const shz_char *base, const shz_char *rel);
/* Does url start with "<scheme>:" (ASCII case-insensitive)? */
int       shz_url_has_scheme(const shz_char *url, const char *scheme);
/* Length of the scheme of an absolute URL (0 if rel is relative). */
size_t    shz_url_scheme_len(const shz_char *url, size_t n);
/* For a file: URL, the local path with percent-escapes decoded: "file:///C:/A%20B/x.png" -> "C:/A B/x.png",
 * "file:///tmp/x" -> "/tmp/x", "file://localhost/C:/x" -> "C:/x". NULL for other URLs. */
shz_char *shz_url_file_path(const shz_char *url);
/* Remove the fragment ("#...") part; allocated. */
shz_char *shz_url_strip_fragment(const shz_char *url);

#endif /* SHZ_URL_H */
