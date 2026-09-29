/* SPDX-License-Identifier: GPL-2.0-only
 * Microsoft BuildTrusteeWithSidW writes a 20-byte TRUSTEE_W: no multiple
 * trustee, form TRUSTEE_IS_SID, type TRUSTEE_IS_UNKNOWN, and the SID pointer.
 */
#include "trustee.h"
int ntw_trustee_with_sid(void *trustee, const void *sid, int sid_ok, uint32_t *error) {
    uint32_t *words;
    if (!trustee || !sid || !sid_ok) {
        if (error) *error = 87;
        return 0;
    }
    words = trustee;
    words[0] = 0;
    words[1] = 0;
    words[2] = 0;
    words[3] = 0;
    words[4] = (uint32_t)(unsigned long)sid;
    if (error) *error = 0;
    return 1;
}
uint32_t ntw_acl_set_entries(uint32_t count, const void *entries, void **out, void *(*alloc)(unsigned bytes)) {
    uint8_t *acl;
    if (out) *out = 0;
    if (!out || (count && !entries) || count > 16u || !alloc) return 87;
    acl = alloc(8);
    if (!acl) return 8;
    acl[0] = 2;
    acl[1] = 0;
    acl[2] = 8;
    acl[3] = 0;
    acl[4] = 0;
    acl[5] = 0;
    acl[6] = 0;
    acl[7] = 0;
    *out = acl;
    return 0;
}
