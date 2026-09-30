/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: __wine_register_resources / __wine_unregister_resources.
 *
 * Wine DLLs describe their registry entries as ATL registrar scripts stored as "WINE_REGISTRY" resources (.rgs files;
 * widl generates them for COM classes). Wine hands them to atl100's IRegistrar. There is no atl100 here, so this file
 * interprets the same script language directly:
 *   script  := { rootkey '{' body '}' }
 *   body    := { [NoRemove | ForceRemove | Delete] name [ '=' type value ] [ '{' body '}' ]
 *              | 'val' name '=' type value }
 *   type    := s (REG_SZ) | e (REG_EXPAND_SZ) | d (REG_DWORD) | b (REG_BINARY, hex digits) | m (REG_MULTI_SZ)
 *   name/value: 'quoted' ('' escapes a quote) or a bare word; %MODULE% and %SystemRoot% are replaced.
 * Registration creates keys and values (ForceRemove deletes an existing key first, Delete removes a key);
 * unregistration deletes every key not marked NoRemove, with its sub-tree.
 */
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include "windef.h"
#include "winbase.h"
#include "winnls.h"
#include "winreg.h"
#include "winerror.h"

typedef struct {
    const WCHAR *p;
    WCHAR module[MAX_PATH];
    WCHAR sysroot[MAX_PATH];
    BOOL do_register;
    LONG error;
} parser;

static void skip_ws(parser *ps)
{
    for (;;) {
        while (*ps->p == ' ' || *ps->p == '\t' || *ps->p == '\r' || *ps->p == '\n') ps->p++;
        if (ps->p[0] == '/' && ps->p[1] == '/') { while (*ps->p && *ps->p != '\n') ps->p++; continue; }
        break;
    }
}

/* next token into buf (replacements applied); returns 0 at end of text */
static int next_token(parser *ps, WCHAR *buf, int cap, BOOL *quoted)
{
    int n = 0;
    skip_ws(ps);
    *quoted = FALSE;
    if (!*ps->p) return 0;
    if (*ps->p == '{' || *ps->p == '}' || *ps->p == '=') { buf[0] = *ps->p++; buf[1] = 0; return 1; }
    if (*ps->p == '\'') {
        *quoted = TRUE;
        ps->p++;
        while (*ps->p) {
            if (*ps->p == '\'') {
                if (ps->p[1] == '\'') { if (n < cap - 1) buf[n++] = '\''; ps->p += 2; continue; }
                ps->p++;
                break;
            }
            if (*ps->p == '%') {
                const WCHAR *end = wcschr(ps->p + 1, '%');
                const WCHAR *rep = NULL;
                if (end && end - ps->p == 7 && !wcsncmp(ps->p + 1, L"MODULE", 6)) rep = ps->module;
                else if (end && end - ps->p == 11 && !wcsncmp(ps->p + 1, L"SystemRoot", 10)) rep = ps->sysroot;
                else if (end == ps->p + 1) { if (n < cap - 1) buf[n++] = '%'; ps->p += 2; continue; }
                if (rep) {
                    while (*rep && n < cap - 1) buf[n++] = *rep++;
                    ps->p = end + 1;
                    continue;
                }
            }
            if (n < cap - 1) buf[n++] = *ps->p;
            ps->p++;
        }
    } else {
        while (*ps->p && !wcschr(L" \t\r\n{}=", *ps->p)) { if (n < cap - 1) buf[n++] = *ps->p; ps->p++; }
    }
    buf[n] = 0;
    return 1;
}

static HKEY root_key(const WCHAR *name)
{
    static const struct { const WCHAR *n; HKEY k; } roots[] = {
        { L"HKCR", HKEY_CLASSES_ROOT }, { L"HKEY_CLASSES_ROOT", HKEY_CLASSES_ROOT },
        { L"HKCU", HKEY_CURRENT_USER }, { L"HKEY_CURRENT_USER", HKEY_CURRENT_USER },
        { L"HKLM", HKEY_LOCAL_MACHINE }, { L"HKEY_LOCAL_MACHINE", HKEY_LOCAL_MACHINE },
        { L"HKU", HKEY_USERS }, { L"HKEY_USERS", HKEY_USERS },
        { L"HKCC", HKEY_CURRENT_CONFIG }, { L"HKEY_CURRENT_CONFIG", HKEY_CURRENT_CONFIG },
    };
    unsigned i;
    for (i = 0; i < ARRAY_SIZE(roots); ++i) if (!_wcsicmp(name, roots[i].n)) return roots[i].k;
    return NULL;
}

static LONG delete_tree(HKEY parent, const WCHAR *name)
{
    HKEY k;
    WCHAR sub[256];
    LONG r = RegOpenKeyExW(parent, name, 0, KEY_ALL_ACCESS, &k);
    if (r) return r;
    for (;;) {
        DWORD len = ARRAY_SIZE(sub);
        if (RegEnumKeyExW(k, 0, sub, &len, NULL, NULL, NULL, NULL)) break;
        if (delete_tree(k, sub)) break;
    }
    RegCloseKey(k);
    return RegDeleteKeyW(parent, name);
}

static void set_value(parser *ps, HKEY key, const WCHAR *name, WCHAR type, const WCHAR *text)
{
    LONG r = ERROR_SUCCESS;
    switch (type | 0x20) {
    case 's': case 'e':
        r = RegSetValueExW(key, name, 0, (type | 0x20) == 's' ? REG_SZ : REG_EXPAND_SZ, (const BYTE *)text,
                           (DWORD)(wcslen(text) + 1) * sizeof(WCHAR));
        break;
    case 'm': {
        size_t n = wcslen(text);
        WCHAR *m = calloc(n + 2, sizeof(WCHAR));           /* "\0"-separated in the script; one string here */
        if (!m) { ps->error = ERROR_OUTOFMEMORY; return; }
        memcpy(m, text, n * sizeof(WCHAR));
        r = RegSetValueExW(key, name, 0, REG_MULTI_SZ, (const BYTE *)m, (DWORD)(n + 2) * sizeof(WCHAR));
        free(m);
        break;
    }
    case 'd': {
        DWORD v = wcstoul(text, NULL, 0);
        r = RegSetValueExW(key, name, 0, REG_DWORD, (const BYTE *)&v, sizeof v);
        break;
    }
    case 'b': {
        size_t n = wcslen(text) / 2, i;
        BYTE *b = malloc(n ? n : 1);
        if (!b) { ps->error = ERROR_OUTOFMEMORY; return; }
        for (i = 0; i < n; ++i) {
            WCHAR h[3] = { text[2 * i], text[2 * i + 1], 0 };
            b[i] = (BYTE)wcstoul(h, NULL, 16);
        }
        r = RegSetValueExW(key, name, 0, REG_BINARY, b, (DWORD)n);
        free(b);
        break;
    }
    default:
        r = ERROR_INVALID_DATA;
    }
    if (r) ps->error = r;
}

/* parse "body" up to the matching '}' below key (NULL key = inside a removed/ignored key) */
static void parse_body(parser *ps, HKEY key)
{
    WCHAR tok[1024], name[1024], val[4096];
    BOOL q;
    while (next_token(ps, tok, ARRAY_SIZE(tok), &q)) {
        int flag = 0;                                       /* 1 NoRemove, 2 ForceRemove, 3 Delete */
        HKEY sub = NULL;
        DWORD disp;
        if (!q && !wcscmp(tok, L"}")) return;
        if (!q && !_wcsicmp(tok, L"val")) {
            WCHAR type[8];
            if (!next_token(ps, name, ARRAY_SIZE(name), &q) || !next_token(ps, tok, ARRAY_SIZE(tok), &q) || wcscmp(tok, L"=") ||
                !next_token(ps, type, ARRAY_SIZE(type), &q) || !next_token(ps, val, ARRAY_SIZE(val), &q)) {
                ps->error = ERROR_INVALID_DATA;
                return;
            }
            if (key && ps->do_register) set_value(ps, key, name, type[0], val);
            continue;
        }
        if (!q && !_wcsicmp(tok, L"NoRemove")) flag = 1;
        else if (!q && !_wcsicmp(tok, L"ForceRemove")) flag = 2;
        else if (!q && !_wcsicmp(tok, L"Delete")) flag = 3;
        if (flag) { if (!next_token(ps, name, ARRAY_SIZE(name), &q)) { ps->error = ERROR_INVALID_DATA; return; } }
        else wcscpy(name, tok);
        if (key) {
            if (ps->do_register) {
                if (flag == 2 || flag == 3) delete_tree(key, name);
                if (flag != 3 && RegCreateKeyExW(key, name, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &sub, &disp)) {
                    ps->error = ERROR_CANTWRITE;
                    sub = NULL;
                }
            } else if (flag == 1) {
                if (RegOpenKeyExW(key, name, 0, KEY_ALL_ACCESS, &sub)) sub = NULL;
            }
        }
        skip_ws(ps);
        if (*ps->p == '=') {                               /* default value of the key */
            WCHAR type[8];
            ps->p++;
            if (!next_token(ps, type, ARRAY_SIZE(type), &q) || !next_token(ps, val, ARRAY_SIZE(val), &q)) {
                ps->error = ERROR_INVALID_DATA;
                return;
            }
            if (sub && ps->do_register) set_value(ps, sub, NULL, type[0], val);
        }
        skip_ws(ps);
        if (*ps->p == '{') { ps->p++; parse_body(ps, sub); }
        if (sub) RegCloseKey(sub);
        if (key && !ps->do_register && flag != 1) delete_tree(key, name);
        if (ps->error == ERROR_INVALID_DATA) return;
    }
}

static LONG run_script(HMODULE module, const WCHAR *script, BOOL do_register)
{
    parser ps;
    WCHAR tok[256];
    BOOL q;
    memset(&ps, 0, sizeof ps);
    ps.p = script;
    ps.do_register = do_register;
    GetModuleFileNameW(module, ps.module, MAX_PATH);
    if (!GetEnvironmentVariableW(L"SystemRoot", ps.sysroot, MAX_PATH)) GetWindowsDirectoryW(ps.sysroot, MAX_PATH);
    while (next_token(&ps, tok, ARRAY_SIZE(tok), &q)) {
        HKEY root = root_key(tok);
        if (!root || !next_token(&ps, tok, ARRAY_SIZE(tok), &q) || wcscmp(tok, L"{")) return ERROR_INVALID_DATA;
        parse_body(&ps, root);
        if (ps.error == ERROR_INVALID_DATA) break;
    }
    return ps.error;
}

struct enum_ctx { BOOL do_register; LONG error; };

static BOOL CALLBACK one_resource(HMODULE module, LPCWSTR type, LPWSTR name, LONG_PTR arg)
{
    struct enum_ctx *ctx = (struct enum_ctx *)arg;
    HRSRC r = FindResourceW(module, name, type);
    const char *text = r ? LoadResource(module, r) : NULL;
    DWORD len = r ? SizeofResource(module, r) : 0;
    int n;
    WCHAR *w;
    if (!text) { ctx->error = ERROR_RESOURCE_DATA_NOT_FOUND; return FALSE; }
    n = MultiByteToWideChar(CP_UTF8, 0, text, (int)len, NULL, 0);
    if (!(w = malloc((n + 1) * sizeof(WCHAR)))) { ctx->error = ERROR_OUTOFMEMORY; return FALSE; }
    MultiByteToWideChar(CP_UTF8, 0, text, (int)len, w, n);
    w[n] = 0;
    ctx->error = run_script(module, w, ctx->do_register);
    free(w);
    return !ctx->error;
}

static HRESULT run_all(BOOL do_register)
{
    extern IMAGE_DOS_HEADER __ImageBase;
    struct enum_ctx ctx = { do_register, 0 };
    EnumResourceNamesW((HMODULE)&__ImageBase, L"WINE_REGISTRY", one_resource, (LONG_PTR)&ctx);
    return ctx.error ? HRESULT_FROM_WIN32(ctx.error) : S_OK;
}

HRESULT __cdecl __wine_register_resources(void) { return run_all(TRUE); }
HRESULT __cdecl __wine_unregister_resources(void) { return run_all(FALSE); }
