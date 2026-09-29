/* SPDX-License-Identifier: GPL-2.0-only */
#include "sddl.h"
#include <stdio.h>
static int failures;
static void expect(int cond, const char *text, int line) {
    if (!cond) { fprintf(stderr, "line %d: %s\n", line, text); ++failures; }
}
#define C(x) expect((x), #x, __LINE__)
static void wide(const char *ascii, uint16_t *out) {
    while (*ascii) *out++ = (uint16_t)(unsigned char)*ascii++;
    *out = 0;
}
static uint16_t ru16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t ru32(const uint8_t *p) { return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24); }
static int sid_is(const uint8_t *sid, uint32_t auth, uint32_t sub0, int nsub, uint32_t sub1) {
    uint32_t i;
    if (sid[0] != 1 || sid[1] != nsub) return 0;
    if (sid[2] || sid[3] || sid[4] || sid[5]) return 0;
    if (sid[6] != (uint8_t)(auth >> 8) || sid[7] != (uint8_t)auth) return 0;
    if (ru32(sid + 8) != sub0) return 0;
    if (nsub > 1 && ru32(sid + 12) != sub1) return 0;
    for (i = (uint32_t)(nsub > 1 ? 2 : 1); i < (uint32_t)nsub; ++i) if (ru32(sid + 8 + i * 4)) return 0;
    return 1;
}
int main(void) {
    uint8_t blob[1536];
    uint16_t text[160];
    uint32_t bytes = 0, error = 99, dacl, sacl, ace, ace2, mask;
    const uint8_t *acl, *sid;
    wide("D:(A;;GA;;;SY)(A;;GWGR;;;S-1-15-2-1)S:(ML;;;;;S-1-16-0)", text);
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 1);
    C(error == 0 && bytes > 20 && blob[0] == 1 && ru16(blob + 2) == 0x8014);
    C(ru32(blob + 4) == 0 && ru32(blob + 8) == 0);
    dacl = ru32(blob + 16);
    sacl = ru32(blob + 12);
    C(dacl >= 20 && sacl > dacl && sacl < bytes);
    acl = blob + dacl;
    C(acl[0] == 2 && ru16(acl + 4) == 2);
    ace = dacl + 8;
    C(blob[ace] == 0 && ru32(blob + ace + 4) == 0x10000000u);
    sid = blob + ace + 8;
    C(sid_is(sid, 5, 18, 1, 0));
    ace2 = ace + ru16(blob + ace + 2);
    mask = ru32(blob + ace2 + 4);
    C(blob[ace2] == 0 && mask == 0xC0000000u);
    C(sid_is(blob + ace2 + 8, 15, 2, 2, 1));
    acl = blob + sacl;
    C(acl[0] == 2 && ru16(acl + 4) == 1 && blob[sacl + 8] == 0x11 && ru32(blob + sacl + 12) == 0);
    C(sid_is(blob + sacl + 16, 16, 0, 1, 0));
    wide("D:(A;;GA;;;ZZ)", text);
    error = 0;
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 0 && error == 1332);
    wide("", text);
    error = 0;
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 0 && error == 87);
    wide("D:(A;;GA;;;SY)", text);
    C(ntw_sddl_build(text, 2, blob, sizeof blob, &bytes, &error) == 0 && error == 1305);
    wide("D:(Z;;GA;;;SY)", text);
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 0 && error == 87);
    wide("D:P(A;;GA;;;WD)", text);
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 1);
    C((ru16(blob + 2) & 0x1004) == 0x1004);
    dacl = ru32(blob + 16);
    C(sid_is(blob + dacl + 16, 1, 0, 1, 0));
    wide("not a descriptor", text);
    C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 0 && error == 87);
    {
        uint8_t access[32], merged[1536];
        uint16_t account[16];
        uint32_t merged_bytes = 0, merged_dacl, merged_sacl;
        wide("SY", account);
        C(ntw_explicit_access(0, account, 0x10000000u, 1, 0, &error) == 0 && error == 87);
        C(ntw_explicit_access(access, account, 0x10000000u, 1, 0, &error) == 1);
        C(ru32(access) == 0x10000000u && ru32(access + 4) == 1 && ru32(access + 20) == 1 && ru32(access + 28) == (uint32_t)(unsigned long)account);
        wide("D:(A;;GA;;;SY)(A;;GWGR;;;S-1-15-2-1)S:(ML;;;;;S-1-16-0)", text);
        C(ntw_sddl_build(text, 1, blob, sizeof blob, &bytes, &error) == 1);
        wide("CURRENT_USER", account);
        C(ntw_merge_grant(blob, bytes, account, 0x10000000u, 0, merged, sizeof merged, &merged_bytes, &error) == 0);
        C(error == 1332);
        wide("BA", account);
        C(ntw_merge_grant(blob, bytes, account, 0x10000000u, 0, merged, sizeof merged, &merged_bytes, &error) == 1);
        merged_dacl = ru32(merged + 16);
        merged_sacl = ru32(merged + 12);
        C(ru16(merged + merged_dacl + 4) == 3);
        {
            uint32_t ace_off = merged_dacl + 8, skip;
            for (skip = 0; skip < 2; ++skip) ace_off += ru16(merged + ace_off + 2);
            C(merged[ace_off] == 0 && ru32(merged + ace_off + 4) == 0x10000000u);
            C(sid_is(merged + ace_off + 8, 5, 32, 2, 544));
        }
        C(merged[merged_sacl + 8] == 0x11);
    }
    if (failures) { fprintf(stderr, "failures %d\n", failures); return 1; }
    printf("{\"passed\":true,\"sddl\":true}\n");
    return 0;
}
