/* SPDX-License-Identifier: GPL-2.0-only
 * SDDL revision 1 to a self-relative security descriptor.
 * The grammar is the public ace-string contract. Unknown accounts and
 * malformed strings fail; they are not turned into an empty descriptor.
 */
#ifndef NTW_SDDL_H
#define NTW_SDDL_H
#include <stdint.h>
#define NTW_SDDL_PARAM 87u
#define NTW_SDDL_REVISION 1305u
#define NTW_SDDL_NONE_MAPPED 1332u
int ntw_sddl_build(const uint16_t *text, uint32_t revision, uint8_t *dst, uint32_t cap,
                   uint32_t *bytes, uint32_t *error);
int ntw_explicit_access(uint8_t *out, const uint16_t *name, uint32_t perms, uint32_t mode,
                        uint32_t inherit, uint32_t *error);
int ntw_merge_grant(const uint8_t *old, uint32_t old_bytes, const uint16_t *name, uint32_t perms,
                    uint32_t inherit, uint8_t *dst, uint32_t cap, uint32_t *bytes, uint32_t *error);
#endif
