/* SPDX-License-Identifier: GPL-2.0-only
 * Sound-event scheme policy; see sndscheme.h. */
#include "sndscheme.h"

static const struct { const char *alias, *file; } g_events[] = {
    { "SystemStart", "TheMicrosoftSound.wav" }, { "WindowsLogon", "WindowsNTLogonSound.wav" },
    { "WindowsLogoff", "WindowsNTLogoffSound.wav" }, { "SystemExit", "tada.wav" },
    { "SystemAsterisk", "ding.wav" }, { "Notification.Default", "chimes.wav" }, { "MailBeep", "chimes.wav" },
    { "SystemExclamation", "chord.wav" }, { "SystemHand", "chord.wav" }, { ".Default", "ding.wav" },
    { "DeviceConnect", "ringin.wav" }, { "DeviceDisconnect", "ringout.wav" },
    { "MenuCommand", "Start.wav" }, { "Navigating", "Start.wav" },
};

static uint16_t lower(uint16_t c) { return c >= 'A' && c <= 'Z' ? (uint16_t)(c + 32) : c; }
static size_t wlen(const uint16_t *s) { size_t n = 0; while (s[n]) ++n; return n; }

int shz_scheme_alias_valid(const uint16_t *a)
{
    size_t i;
    if (!a) return 0;
    for (i = 0; a[i]; ++i) {
        const uint16_t c = a[i];
        if (i >= SHZ_SCHEME_ALIAS_MAX + 1u) return 0;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return 0;
    }
    return i >= 1 && i <= SHZ_SCHEME_ALIAS_MAX;
}

static int same(const uint16_t *w, const char *a)
{
    size_t i;
    for (i = 0; w[i] && a[i]; ++i) if (lower(w[i]) != lower((unsigned char)a[i])) return 0;
    return !w[i] && !a[i];
}

const char *shz_scheme_default_file(const uint16_t *alias)
{
    size_t i;
    if (!shz_scheme_alias_valid(alias)) return 0;
    for (i = 0; i < sizeof g_events / sizeof g_events[0]; ++i) if (same(alias, g_events[i].alias)) return g_events[i].file;
    return 0;
}

static int put(uint16_t *out, size_t cap, size_t *n, uint16_t c)
{
    if (*n + 1 >= cap) return 0;
    out[(*n)++] = c;
    return 1;
}

static int is_abs(const uint16_t *v)
{
    return v[0] == '\\' || v[0] == '/' || (((v[0] | 32) >= 'a' && (v[0] | 32) <= 'z') && v[1] == ':' && (v[2] == '\\' || v[2] == '/'));
}

/* Relative value: no ':' anywhere, no empty/".." component, no leading separator (that is the absolute case). */
static int rel_ok(const uint16_t *v)
{
    size_t i = 0, start = 0;
    for (;; ++i) {
        if (v[i] == ':') return 0;
        if (!v[i] || v[i] == '\\' || v[i] == '/') {
            const size_t n = i - start;
            if (n == 0 || (n == 2 && v[start] == '.' && v[start + 1] == '.') || (n == 1 && v[start] == '.')) return 0;
            if (!v[i]) return 1;
            start = i + 1;
        }
    }
}

int shz_scheme_resolve(const uint16_t *alias, const uint16_t *ini, const uint16_t *windir, uint16_t *out, size_t cap)
{
    static const char media[] = "\\MEDIA\\";
    size_t n = 0, i;
    const char *def = 0;
    int isabs = 0;
    if (!out || !cap) return SHZ_SCHEME_E_SPACE;
    out[0] = 0;
    if (!shz_scheme_alias_valid(alias) || !windir || !*windir) return SHZ_SCHEME_E_ALIAS;
    if (ini && ini[0] == '-' && !ini[1]) return SHZ_SCHEME_E_MUTED;
    if (ini && ini[0]) {
        isabs = is_abs(ini);
        if (!isabs && !rel_ok(ini)) return SHZ_SCHEME_E_PATH;
        if (isabs && ini[0] != '\\' && ini[0] != '/' && wlen(ini) < 4) return SHZ_SCHEME_E_PATH;
        if (isabs) {
            for (i = 0; ini[i]; ++i) if (!put(out, cap, &n, ini[i])) { out[0] = 0; return SHZ_SCHEME_E_SPACE; }
            out[n] = 0;
            return SHZ_SCHEME_OK;
        }
    } else {
        def = shz_scheme_default_file(alias);
        if (!def) return SHZ_SCHEME_E_NONE;
    }
    for (i = wlen(windir); i && (windir[i - 1] == '\\' || windir[i - 1] == '/'); --i) { }
    { size_t k; for (k = 0; k < i; ++k) if (!put(out, cap, &n, windir[k])) { out[0] = 0; return SHZ_SCHEME_E_SPACE; } }
    for (i = 0; media[i]; ++i) if (!put(out, cap, &n, (uint16_t)media[i])) { out[0] = 0; return SHZ_SCHEME_E_SPACE; }
    if (def) { for (i = 0; def[i]; ++i) if (!put(out, cap, &n, (uint16_t)(unsigned char)def[i])) { out[0] = 0; return SHZ_SCHEME_E_SPACE; } }
    else { for (i = 0; ini[i]; ++i) if (!put(out, cap, &n, ini[i])) { out[0] = 0; return SHZ_SCHEME_E_SPACE; } }
    out[n] = 0;
    return SHZ_SCHEME_OK;
}
