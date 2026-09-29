/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98-side contracts after reading, and not copying:
 * ReactOS ntdll LdrpInitializeTls family (see ntwin32/tls/PROVENANCE.md),
 * Wine dlls/ntdll/loader.c security-cookie and delay-load shape at
 * df15af3652511150490934682202d45af892f887, and Microsoft's
 * IMAGE_LOAD_CONFIG_DIRECTORY32 / delay-load descriptor layout.
 * CFG returns denied for every target that is not an exact table RVA.
 * The default MSVC x86 cookie 0xBB40E64E is replaced only by nonzero
 * non-default entropy. Delay bind rolls back the IAT if any name is missing.
 */
#include "guard.h"
#include <stddef.h>
static uint32_t read32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
int ntw_init_security_cookie(uint32_t *slot, uint32_t entropy) {
    if (!slot) return NTW_GUARD_INVALID;
    if (*slot != NTW_MSVC_X86_DEFAULT_COOKIE) return NTW_GUARD_OK;
    if (entropy == 0 || entropy == NTW_MSVC_X86_DEFAULT_COOKIE) return NTW_GUARD_INVALID;
    *slot = entropy;
    return NTW_GUARD_OK;
}
int ntw_cfg_allows(const uint8_t *table, uint32_t count, uint32_t stride, uint32_t target_rva) {
    uint32_t n;
    if (stride < 4 || stride > 16) return NTW_GUARD_INVALID;
    if (!target_rva) return NTW_GUARD_DENIED;
    if (!count) return NTW_GUARD_DENIED;
    if (!table) return NTW_GUARD_INVALID;
    for (n = 0; n < count; ++n) {
        if (read32(table + (size_t)n * stride) == target_rva) return NTW_GUARD_OK;
    }
    return NTW_GUARD_DENIED;
}
int ntw_delay_bind(uintptr_t *iat, const ntw_delay_symbol *symbols, uint32_t count,
                   const char *dll, ntw_delay_lookup lookup, void *user) {
    uintptr_t saved[256];
    uint32_t n;
    if (!iat || !symbols || !count || count > 256 || !dll || !*dll || !lookup)
        return NTW_GUARD_INVALID;
    for (n = 0; n < count; ++n) saved[n] = iat[n];
    for (n = 0; n < count; ++n) {
        void *resolved;
        if (symbols[n].by_ordinal) {
            if (!symbols[n].ordinal || symbols[n].ordinal > 0xffffu) return NTW_GUARD_INVALID;
        } else if (!symbols[n].name || !symbols[n].name[0]) {
            return NTW_GUARD_INVALID;
        }
        resolved = lookup(user, dll, &symbols[n]);
        if (!resolved) {
            uint32_t i;
            for (i = 0; i < count; ++i) iat[i] = saved[i];
            return NTW_GUARD_NOT_FOUND;
        }
        iat[n] = (uintptr_t)resolved;
    }
    return NTW_GUARD_OK;
}
