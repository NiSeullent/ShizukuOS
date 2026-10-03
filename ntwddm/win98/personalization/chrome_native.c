/* SPDX-License-Identifier: GPL-2.0-only
 * Per-user modern-retro window metrics via the real Win98 SystemParametersInfo path.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
#include <string.h>
#include "chrome_core.h"
#include "chrome_native.h"

static void to_metrics(const NONCLIENTMETRICSA *n, szc_metrics *m)
{
    m->v[SZC_BORDER] = n->iBorderWidth; m->v[SZC_CAPTION_W] = n->iCaptionWidth; m->v[SZC_CAPTION_H] = n->iCaptionHeight;
    m->v[SZC_SMCAPTION_W] = n->iSmCaptionWidth; m->v[SZC_SMCAPTION_H] = n->iSmCaptionHeight;
    m->v[SZC_MENU_W] = n->iMenuWidth; m->v[SZC_MENU_H] = n->iMenuHeight;
    m->v[SZC_SCROLL_W] = n->iScrollWidth; m->v[SZC_SCROLL_H] = n->iScrollHeight;
}
static void from_metrics(const szc_metrics *m, NONCLIENTMETRICSA *n)
{
    n->iBorderWidth = m->v[SZC_BORDER]; n->iCaptionWidth = m->v[SZC_CAPTION_W]; n->iCaptionHeight = m->v[SZC_CAPTION_H];
    n->iSmCaptionWidth = m->v[SZC_SMCAPTION_W]; n->iSmCaptionHeight = m->v[SZC_SMCAPTION_H];
    n->iMenuWidth = m->v[SZC_MENU_W]; n->iMenuHeight = m->v[SZC_MENU_H];
    n->iScrollWidth = m->v[SZC_SCROLL_W]; n->iScrollHeight = m->v[SZC_SCROLL_H];
}
static DWORD get_current(NONCLIENTMETRICSA *n, szc_metrics *m)
{
    memset(n, 0, sizeof *n); n->cbSize = sizeof *n;
    if (!SystemParametersInfoA(SPI_GETNONCLIENTMETRICS, sizeof *n, n, 0)) return GetLastError();
    to_metrics(n, m);
    return szc_valid(m) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}
/* Apply base (the full current struct, so fonts stay untouched) with target values and verify. */
static DWORD set_verified(NONCLIENTMETRICSA *base, const szc_metrics *target)
{
    NONCLIENTMETRICSA back; szc_metrics got; DWORD error;
    from_metrics(target, base);
    if (!SystemParametersInfoA(SPI_SETNONCLIENTMETRICS, sizeof *base, base, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE))
        return GetLastError();
    error = get_current(&back, &got);
    if (error != ERROR_SUCCESS) return error;
    return szc_equal(&got, target) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}
static DWORD get_dword(HKEY key, const char *name, DWORD *value)
{
    DWORD type = 0, size = sizeof *value, error = (DWORD)RegQueryValueExA(key, name, NULL, &type, (BYTE *)value, &size);
    if (error == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof *value)) error = ERROR_INVALID_DATA;
    return error;
}
static DWORD put_dword(HKEY key, const char *name, DWORD value)
{
    DWORD back = 0, error = (DWORD)RegSetValueExA(key, name, 0, REG_DWORD, (const BYTE *)&value, sizeof value);
    if (error == ERROR_SUCCESS) error = get_dword(key, name, &back);
    if (error == ERROR_SUCCESS && back != value) error = ERROR_INVALID_DATA;
    return error;
}
/* Saved values are stored as "Saved<Name>"; Applied is the flag. */
static void saved_name(char out[24], unsigned i) { lstrcpyA(out, "Saved"); lstrcatA(out, szc_names[i]); }
static DWORD load_saved(HKEY key, szc_metrics *m)
{
    unsigned i; char name[24]; DWORD value, error;
    for (i = 0; i < SZC_COUNT; i++) {
        saved_name(name, i);
        error = get_dword(key, name, &value);
        if (error != ERROR_SUCCESS) return error;
        m->v[i] = (int32_t)value;
    }
    return szc_valid(m) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}
static DWORD open_key(HKEY *key)
{
    DWORD disposition;
    return (DWORD)RegCreateKeyExA(HKEY_CURRENT_USER, SZC_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                                  KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, key, &disposition);
}
int szc_native_is_applied(void)
{
    HKEY key; DWORD v = 0, error;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, SZC_KEY, 0, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) return 0;
    error = get_dword(key, "Applied", &v);
    RegCloseKey(key);
    return error == ERROR_SUCCESS && v == 1;
}
DWORD szc_native_apply(void)
{
    NONCLIENTMETRICSA base; szc_metrics current, modern; HKEY key; DWORD error, applied = 0, rollback; unsigned i; char name[24];
    error = get_current(&base, &current);
    if (error != ERROR_SUCCESS) return error;
    if (!szc_modern(&current, &modern)) return ERROR_INVALID_DATA;
    error = open_key(&key);
    if (error != ERROR_SUCCESS) return error;
    if (get_dword(key, "Applied", &applied) != ERROR_SUCCESS) applied = 0;
    if (applied != 1) {  /* first apply: back up the user's real metrics before touching anything */
        for (i = 0; i < SZC_COUNT && error == ERROR_SUCCESS; i++) {
            saved_name(name, i); error = put_dword(key, name, (DWORD)current.v[i]);
        }
        if (error == ERROR_SUCCESS) error = put_dword(key, "Applied", 1);
        if (error == ERROR_SUCCESS) error = (DWORD)RegFlushKey(key);
        if (error != ERROR_SUCCESS) { RegCloseKey(key); return error; }
    }
    error = set_verified(&base, &modern);
    if (error != ERROR_SUCCESS && applied != 1) {  /* undo: put back what was there and drop the flag */
        NONCLIENTMETRICSA again; szc_metrics now;
        if (get_current(&again, &now) == ERROR_SUCCESS) set_verified(&again, &current);
        rollback = put_dword(key, "Applied", 0); (void)rollback;
    }
    RegCloseKey(key);
    return error;
}
DWORD szc_native_restore(void)
{
    NONCLIENTMETRICSA base; szc_metrics now, saved; HKEY key; DWORD error, applied = 0;
    error = (DWORD)RegOpenKeyExA(HKEY_CURRENT_USER, SZC_KEY, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (error == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;  /* never applied: nothing to restore */
    if (error != ERROR_SUCCESS) return error;
    error = get_dword(key, "Applied", &applied);
    if (error == ERROR_FILE_NOT_FOUND || (error == ERROR_SUCCESS && applied != 1)) { RegCloseKey(key); return ERROR_SUCCESS; }
    if (error == ERROR_SUCCESS) error = load_saved(key, &saved);
    if (error == ERROR_SUCCESS) error = get_current(&base, &now);
    if (error == ERROR_SUCCESS) error = set_verified(&base, &saved);
    if (error == ERROR_SUCCESS) error = put_dword(key, "Applied", 0);
    if (error == ERROR_SUCCESS) error = (DWORD)RegFlushKey(key);
    RegCloseKey(key);
    return error;
}
