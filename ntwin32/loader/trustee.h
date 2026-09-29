/* SPDX-License-Identifier: GPL-2.0-only
 * BuildTrusteeWithSidW. A null trustee or an invalid SID fails. The SID is
 * stored, not copied. Wine aclapi was not copied.
 */
#ifndef NTW_TRUSTEE_H
#define NTW_TRUSTEE_H
#include <stdint.h>
int ntw_trustee_with_sid(void *trustee, const void *sid, int sid_ok, uint32_t *error);
uint32_t ntw_acl_set_entries(uint32_t count, const void *entries, void **out, void *(*alloc)(unsigned bytes));
#endif
