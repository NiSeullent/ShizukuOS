/* SPDX-License-Identifier: GPL-2.0-only
 * Load-config cookie, CFG membership and delay-import bind contracts.
 * Fail closed: an unlisted target or a missing procedure does not succeed.
 * See PROVENANCE.md.
 */
#ifndef NTW_GUARD_H
#define NTW_GUARD_H
#include <stdint.h>
#define NTW_MSVC_X86_DEFAULT_COOKIE 0xBB40E64Eu
enum ntw_guard_status { NTW_GUARD_OK = 0, NTW_GUARD_INVALID = -1, NTW_GUARD_DENIED = -2,
    NTW_GUARD_NOT_FOUND = -3 };
typedef struct ntw_delay_symbol {
    int by_ordinal;
    uint32_t ordinal;
    const char *name;
} ntw_delay_symbol;
typedef void *(*ntw_delay_lookup)(void *user, const char *dll, const ntw_delay_symbol *symbol);
int ntw_init_security_cookie(uint32_t *slot, uint32_t entropy);
int ntw_cfg_allows(const uint8_t *table, uint32_t count, uint32_t stride, uint32_t target_rva);
int ntw_delay_bind(uintptr_t *iat, const ntw_delay_symbol *symbols, uint32_t count,
                   const char *dll, ntw_delay_lookup lookup, void *user);
#endif
