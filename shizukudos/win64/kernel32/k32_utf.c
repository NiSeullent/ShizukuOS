/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32.dll internal: UTF-8 <-> UTF-16 conversion and wide string length. The system ANSI code page is UTF-8 (65001), so
 * the *A entry points convert through these. Malformed UTF-8 becomes U+FFFD; unpaired surrogates are written as three-byte
 * sequences (WTF-8), so no information is lost on the wide side. */
#include "k32.h"

size_t k32_wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }

int k32_utf8_to_wide(const char *s, int n, WCHAR *w, int cap)
{
    int o = 0, i = 0;
    if (n < 0) { n = 0; while (s[n]) ++n; ++n; }
    while (i < n) {
        unsigned c = (unsigned char)s[i++];
        unsigned cp;
        if (c < 0x80) cp = c;
        else if ((c & 0xe0) == 0xc0 && i < n) { cp = ((c & 0x1f) << 6) | (s[i++] & 0x3f); }
        else if ((c & 0xf0) == 0xe0 && i + 1 < n) { cp = ((c & 0x0f) << 12) | ((s[i] & 0x3f) << 6) | (s[i + 1] & 0x3f); i += 2; }
        else if ((c & 0xf8) == 0xf0 && i + 2 < n) { cp = ((c & 7) << 18) | ((s[i] & 0x3f) << 12) | ((s[i + 1] & 0x3f) << 6) | (s[i + 2] & 0x3f); i += 3; }
        else cp = 0xfffd;
        if (cp >= 0x10000) {
            if (o + 2 > cap) return 0;
            cp -= 0x10000;
            w[o++] = (WCHAR)(0xd800 + (cp >> 10));
            w[o++] = (WCHAR)(0xdc00 + (cp & 0x3ff));
        } else {
            if (o + 1 > cap) return 0;
            w[o++] = (WCHAR)cp;
        }
    }
    return o;
}

int k32_wide_to_utf8(const WCHAR *w, int n, char *s, int cap)
{
    int o = 0, i = 0;
    if (n < 0) { n = 0; while (w[n]) ++n; ++n; }
    while (i < n) {
        unsigned cp = w[i++];
        if (cp >= 0xd800 && cp < 0xdc00 && i < n && w[i] >= 0xdc00 && w[i] < 0xe000) cp = 0x10000 + ((cp - 0xd800) << 10) + (w[i++] - 0xdc00);
        if (cp < 0x80) { if (o + 1 > cap) return 0; s[o++] = (char)cp; }
        else if (cp < 0x800) { if (o + 2 > cap) return 0; s[o++] = (char)(0xc0 | (cp >> 6)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
        else if (cp < 0x10000) { if (o + 3 > cap) return 0; s[o++] = (char)(0xe0 | (cp >> 12)); s[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
        else { if (o + 4 > cap) return 0; s[o++] = (char)(0xf0 | (cp >> 18)); s[o++] = (char)(0x80 | ((cp >> 12) & 0x3f)); s[o++] = (char)(0x80 | ((cp >> 6) & 0x3f)); s[o++] = (char)(0x80 | (cp & 0x3f)); }
    }
    return o;
}
