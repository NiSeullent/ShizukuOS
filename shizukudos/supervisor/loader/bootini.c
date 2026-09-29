/* SPDX-License-Identifier: GPL-2.0-only
 * Strict parser for \EFI\SHIZUKU\BOOT.INI (see bootini.h for the grammar).
 * Original code; no libc so it links into the freestanding UEFI loader.
 */
#include "bootini.h"

typedef struct {
    char *buf;
    size_t cap, len;
} msg_t;

static void msg_add(msg_t *m, const char *s)
{
    while (*s && m->len + 1 < m->cap)
        m->buf[m->len++] = *s++;
    m->buf[m->len] = 0;
}

/* Appends at most `n` bytes of `s`, replacing anything unprintable, so a hostile
 * file cannot put control sequences on the firmware console. */
static void msg_add_n(msg_t *m, const char *s, size_t n)
{
    size_t i;
    for (i = 0; i < n && m->len + 1 < m->cap; ++i) {
        const char c = s[i];
        m->buf[m->len++] = (c >= 0x20 && c < 0x7f) ? c : '?';
    }
    m->buf[m->len] = 0;
}

static int fail(msg_t *m, int line, const char *a, const char *quoted, size_t qlen, const char *b)
{
    msg_add(m, a);
    if (quoted) {
        msg_add(m, "'");
        msg_add_n(m, quoted, qlen > 40 ? 40 : qlen);
        msg_add(m, qlen > 40 ? "...'" : "'");
    }
    if (b)
        msg_add(m, b);
    return line;
}

static char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c - 'A' + 'a') : c; }

/* Case-insensitive comparison of s[0..n) with a lowercase NUL-terminated word. */
static int word_is(const char *s, size_t n, const char *word)
{
    size_t i;
    for (i = 0; i < n; ++i)
        if (!word[i] || lower(s[i]) != word[i])
            return 0;
    return word[n] == 0;
}

static int is_space(char c) { return c == ' ' || c == '\t'; }

void bootini_defaults(bootini_policy_t *p)
{
    const char *d = BOOTINI_DEFAULT_CSM_PATH;
    size_t i;
    p->mode = BOOT_MODE_AUTO;
    for (i = 0; d[i]; ++i)
        p->csm_path[i] = d[i];
    p->csm_path[i] = 0;
    p->mode_set = p->csm_path_set = 0;
}

const char *bootini_mode_name(int mode)
{
    return mode == BOOT_MODE_SUPERVISOR ? "supervisor" : mode == BOOT_MODE_CSM ? "csm" : "auto";
}

/* An absolute FAT path on the boot volume: \COMPONENT\...\FILE, printable ASCII. */
static const char *path_problem(const char *v, size_t n)
{
    size_t i, comp_start = 1;
    if (n + 1 > BOOTINI_PATH_MAX)
        return "is longer than 127 characters";
    if (v[0] != '\\')
        return "must be absolute and start with '\\' (e.g. \\EFI\\SHIZUKU\\CSMWRAP.EFI)";
    for (i = 1; i <= n; ++i) {
        const char c = i < n ? v[i] : '\\';            /* a virtual separator ends the last component */
        const size_t comp = i - comp_start;
        if (c == '/')
            return "uses '/'; UEFI file paths use '\\'";
        if (c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            return "contains a character that is not allowed in a FAT file name";
        if (c != '\\')
            continue;
        if (comp == 0)
            return i == n ? "does not name a file (ends with '\\')" : "contains an empty path component ('\\\\')";
        if (v[comp_start] == '.' && (comp == 1 || (comp == 2 && v[comp_start + 1] == '.')))
            return "contains a '.' or '..' component";
        comp_start = i + 1;
    }
    return 0;
}

int bootini_parse(const char *text, size_t len, bootini_policy_t *p, char *err, size_t errlen)
{
    msg_t m;
    size_t pos = 0;
    int line = 0;

    m.buf = err;
    m.cap = errlen;
    m.len = 0;
    if (errlen)
        err[0] = 0;
    bootini_defaults(p);
    if (len > BOOTINI_MAX_BYTES)
        return fail(&m, 1, "file is larger than 4096 bytes", 0, 0, 0);
    if (len >= 2 && (((unsigned char)text[0] == 0xff && (unsigned char)text[1] == 0xfe) ||
                     ((unsigned char)text[0] == 0xfe && (unsigned char)text[1] == 0xff)))
        return fail(&m, 1, "file is UTF-16; save it as plain ASCII", 0, 0, 0);
    if (len >= 3 && (unsigned char)text[0] == 0xef && (unsigned char)text[1] == 0xbb &&
        (unsigned char)text[2] == 0xbf)
        pos = 3;                                        /* UTF-8 byte order mark */

    while (pos < len) {
        size_t start = pos, end, k, kend, v, vend, i;
        ++line;
        while (pos < len && text[pos] != '\n')
            ++pos;
        end = pos;
        if (pos < len)
            ++pos;                                      /* consume LF */
        if (end > start && text[end - 1] == '\r')
            --end;                                      /* CRLF */
        if (end - start > 255)
            return fail(&m, line, "line is longer than 255 characters", 0, 0, 0);
        for (i = start; i < end; ++i) {
            const unsigned char c = (unsigned char)text[i];
            if ((c < 0x20 && c != '\t') || c >= 0x7f)
                return fail(&m, line, c >= 0x7f ? "non-ASCII byte in line" : "control character in line", 0, 0, 0);
        }
        while (start < end && is_space(text[start]))
            ++start;
        while (end > start && is_space(text[end - 1]))
            --end;
        if (start == end || text[start] == ';' || text[start] == '#')
            continue;
        for (k = start; k < end && text[k] != '='; ++k)
            ;
        if (k == end)
            return fail(&m, line, "expected 'key = value', got ", text + start, end - start, 0);
        kend = k;
        while (kend > start && is_space(text[kend - 1]))
            --kend;
        v = k + 1;
        while (v < end && is_space(text[v]))
            ++v;
        vend = end;
        if (kend == start)
            return fail(&m, line, "missing key before '='", 0, 0, 0);
        if (word_is(text + start, kend - start, "mode")) {
            if (p->mode_set)
                return fail(&m, line, "duplicate key 'mode'", 0, 0, 0);
            if (v == vend)
                return fail(&m, line, "empty value for 'mode' (expected auto, supervisor or csm)", 0, 0, 0);
            if (word_is(text + v, vend - v, "auto"))
                p->mode = BOOT_MODE_AUTO;
            else if (word_is(text + v, vend - v, "supervisor"))
                p->mode = BOOT_MODE_SUPERVISOR;
            else if (word_is(text + v, vend - v, "csm"))
                p->mode = BOOT_MODE_CSM;
            else
                return fail(&m, line, "invalid mode ", text + v, vend - v, " (expected auto, supervisor or csm)");
            p->mode_set = 1;
        } else if (word_is(text + start, kend - start, "csm_path")) {
            const char *why;
            if (p->csm_path_set)
                return fail(&m, line, "duplicate key 'csm_path'", 0, 0, 0);
            if (v == vend)
                return fail(&m, line, "empty value for 'csm_path'", 0, 0, 0);
            why = path_problem(text + v, vend - v);
            if (why) {
                fail(&m, line, "csm_path ", text + v, vend - v, " ");
                msg_add(&m, why);
                return line;
            }
            for (i = 0; i < vend - v; ++i)
                p->csm_path[i] = text[v + i];
            p->csm_path[i] = 0;
            p->csm_path_set = 1;
        } else {
            return fail(&m, line, "unknown key ", text + start, kend - start, " (allowed: mode, csm_path)");
        }
    }
    return 0;
}
