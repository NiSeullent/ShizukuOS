/* SPDX-License-Identifier: GPL-2.0-only */
#include "guard.h"
#include <stdio.h>
#include <string.h>
static int checks, failures;
static void expect(int cond, const char *text, int line) {
    ++checks;
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static int seen;
static void *lookup(void *user, const char *dll, const ntw_delay_symbol *symbol) {
    (void)user;
    C(strcmp(dll, "KERNEL32.dll") == 0);
    if (symbol->by_ordinal) return symbol->ordinal == 7 ? (void *)0x40 : NULL;
    if (strcmp(symbol->name, "Sleep") == 0) return (void *)0x10;
    if (strcmp(symbol->name, "Missing") == 0) { ++seen; return NULL; }
    return NULL;
}
int main(void) {
    uint32_t cookie = NTW_MSVC_X86_DEFAULT_COOKIE;
    uint8_t table[12];
    ntw_delay_symbol symbols[2];
    uintptr_t iat[2];
    memset(table, 0, sizeof table);
    table[0] = 0x00; table[1] = 0x10; table[2] = 0; table[3] = 0;
    table[4] = 0x00; table[5] = 0x20;
    C(ntw_init_security_cookie(NULL, 1) == NTW_GUARD_INVALID);
    C(ntw_init_security_cookie(&cookie, 0) == NTW_GUARD_INVALID && cookie == NTW_MSVC_X86_DEFAULT_COOKIE);
    C(ntw_init_security_cookie(&cookie, NTW_MSVC_X86_DEFAULT_COOKIE) == NTW_GUARD_INVALID);
    C(ntw_init_security_cookie(&cookie, 0x12345678u) == NTW_GUARD_OK && cookie == 0x12345678u);
    C(ntw_init_security_cookie(&cookie, 0x99u) == NTW_GUARD_OK && cookie == 0x12345678u);
    C(ntw_cfg_allows(table, 0, 4, 0x1000) == NTW_GUARD_DENIED);
    C(ntw_cfg_allows(NULL, 2, 4, 0x1000) == NTW_GUARD_INVALID);
    C(ntw_cfg_allows(table, 2, 4, 0) == NTW_GUARD_DENIED);
    C(ntw_cfg_allows(table, 2, 4, 0x1000) == NTW_GUARD_OK);
    C(ntw_cfg_allows(table, 2, 4, 0x2000) == NTW_GUARD_OK);
    C(ntw_cfg_allows(table, 2, 4, 0x1001) == NTW_GUARD_DENIED);
    C(ntw_cfg_allows(table, 2, 3, 0x1000) == NTW_GUARD_INVALID);
    symbols[0] = (ntw_delay_symbol){0, 0, "Sleep"};
    symbols[1] = (ntw_delay_symbol){0, 0, "Missing"};
    iat[0] = 0x55;
    iat[1] = 0x66;
    C(ntw_delay_bind(iat, symbols, 2, "KERNEL32.dll", lookup, NULL) == NTW_GUARD_NOT_FOUND);
    C(iat[0] == 0x55 && iat[1] == 0x66 && seen == 1);
    symbols[1] = (ntw_delay_symbol){1, 7, NULL};
    C(ntw_delay_bind(iat, symbols, 2, "KERNEL32.dll", lookup, NULL) == NTW_GUARD_OK);
    C(iat[0] == 0x10 && iat[1] == 0x40);
    C(ntw_delay_bind(NULL, symbols, 1, "KERNEL32.dll", lookup, NULL) == NTW_GUARD_INVALID);
    if (failures) {
        fprintf(stderr, "{\"passed\":false,\"checks\":%d,\"failures\":%d}\n", checks, failures);
        return 1;
    }
    printf("{\"passed\":true,\"checks\":%d,\"cfg_denied\":true,\"delay_rolled_back\":true}\n", checks);
    return 0;
}
