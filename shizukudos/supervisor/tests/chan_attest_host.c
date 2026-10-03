/* Host control for the Supervisor channel attestation policy and the Kernel64 identity predicates (wire b5).
 * Exercises the exact header functions compiled into domain.c / subsys64.c / w64_gui_service.c. */
#include <stdio.h>
#include <string.h>
#include "../src/chan_attest.h"
#include "../../abi/shz_w64_gui.h"
static int fails;
#define T(n, c) do { if (c) printf("PASS %s\n", n); else { printf("FAIL %s\n", n); ++fails; } } while (0)
int main(void)
{
    shz_chan_attest_rec_t r; uint64_t out, b, g; const uint64_t D = SHZ_CHAN_ATTEST_W64_DERIVED_OWNER;
    const uint32_t tokA = SHZ_W64_OWNER_CAP_DERIVED | 7u, tokB = SHZ_W64_OWNER_CAP_DERIVED | 8u;
    memset(&r, 0, sizeof r);
    T("unmapped channel", shz_chan_attest_decide(&r, 0, 1, 1, 1, 1, D, 5, 1, &out) == SHZ_E_NOENT);
    T("ring3/V86/non-Win98 caller denied", shz_chan_attest_decide(&r, 1, 0, 1, 1, 1, D, 5, 1, &out) == SHZ_E_DENIED);
    T("peer not Kernel64 denied", shz_chan_attest_decide(&r, 1, 1, 0, 1, 1, D, 5, 1, &out) == SHZ_E_DENIED);
    T("zero bits invalid", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, 0, 5, 1, &out) == SHZ_E_INVALID);
    T("unknown bits invalid", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, D | 2, 5, 1, &out) == SHZ_E_INVALID);
    T("generation 0 stale", shz_chan_attest_decide(&r, 1, 1, 1, 0, 0, D, 5, 1, &out) == SHZ_E_STALE);
    T("generation != header stale", shz_chan_attest_decide(&r, 1, 1, 1, 2, 1, D, 5, 1, &out) == SHZ_E_STALE);
    T("nothing recorded after refusals", shz_chan_attest_lookup(&r, 1, 1, &b, &g) == SHZ_E_NOENT);
    T("first attest ok", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, D, 5, 1, &out) == SHZ_OK && out == D);
    T("idempotent same bits", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, D, 5, 1, &out) == SHZ_OK);
    T("restarted attester same gen busy", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, D, 5, 2, &out) == SHZ_E_BUSY);
    T("lookup live", shz_chan_attest_lookup(&r, 1, 1, &b, &g) == SHZ_OK && b == D && g == 1);
    T("lookup attester dead", shz_chan_attest_lookup(&r, 1, 0, &b, &g) == SHZ_E_NOENT && !b && !g);
    T("K64 attested for gen 1", shz_chan_attested_for(SHZ_OK, D, 1, 1, D));
    T("K64 stale generation refused", !shz_chan_attested_for(SHZ_OK, D, 1, 2, D));
    T("K64 old Supervisor refused", !shz_chan_attested_for(SHZ_E_UNSUPPORTED, D, 1, 1, D));
    T("K64 missing bit refused", !shz_chan_attested_for(SHZ_OK, 0, 1, 1, D));
    T("newer generation rebinds", shz_chan_attest_decide(&r, 1, 1, 1, 3, 3, D, 5, 2, &out) == SHZ_OK);
    T("rollback refused", shz_chan_attest_decide(&r, 1, 1, 1, 1, 1, D, 5, 2, &out) == SHZ_E_STALE);
    /* identity: owner A created the slot */
    T("GUI unattested channel denied", !shz_w64_gui_subject_ok(tokA, tokA, 1, 0));
    T("GUI owner on attested channel ok", shz_w64_gui_subject_ok(tokA, tokA, 1, 1));
    T("GUI foreign owner denied", !shz_w64_gui_subject_ok(tokA, tokB, 1, 1));
    T("GUI non-derived (forged app value) denied", !shz_w64_gui_subject_ok(7u, 7u, 1, 1));
    T("console foreign derived owner denied", !shz_w64_console_owner_ok(1, tokA, tokB));
    T("console own owner ok", shz_w64_console_owner_ok(1, tokA, tokA));
    T("console in-VxD endpoint ok", shz_w64_console_owner_ok(1, tokA, 0));
    T("console legacy unattested kept", shz_w64_console_owner_ok(0, tokA, tokB));
    /* batch6 P1-1: Supervisor-side revocation with the SAME channel header generation must reach Kernel64 at the next
     * authorization. Chain = domain.c chan_attest_get (attester_alive + lookup) -> subsys64.c chan_auth
     * (shz_chan_auth_state, one fresh answer per authorization) -> owner_ok / GUI subject. */
    {
        static const struct { const char *why; uint32_t gen; uint32_t state; } rv[] = {
            { "Win98 EXITED", 4, SHZ_DS_EXITED }, { "Win98 FAILED", 4, SHZ_DS_FAILED },
            { "Win98 domain generation changed", 5, SHZ_DS_RUNNABLE }, { "Win98 slot UNUSED", 4, SHZ_DS_UNUSED } };
        unsigned i;
        for (i = 0; i < sizeof rv / sizeof rv[0]; ++i) {
            shz_chan_attest_rec_t q; uint32_t ever = 0, hdr = 9; int a; long st; char n[160];
            memset(&q, 0, sizeof q);
            a = shz_chan_auth_state(SHZ_E_NOENT, 0, 0, hdr, D, &ever);
            snprintf(n, sizeof n, "[%s] before attest: legacy, not revoked", rv[i].why);
            T(n, a == SHZ_CHAN_AUTH_LEGACY && !ever);
            snprintf(n, sizeof n, "[%s] attest gen 9 by Win98 dom 1 gen 4", rv[i].why);
            T(n, shz_chan_attest_decide(&q, 1, 1, 1, hdr, hdr, D, 1, 4, &out) == SHZ_OK);
            st = shz_chan_attest_lookup(&q, 1, shz_chan_attester_alive(&q, 1, 4, SHZ_DS_RUNNABLE), &b, &g);
            a = shz_chan_auth_state(st, b, g, hdr, D, &ever);
            snprintf(n, sizeof n, "[%s] live attester: authorization 1 attested", rv[i].why);
            T(n, a == SHZ_CHAN_AUTH_ATTESTED && shz_w64_console_owner_auth(1, 0, tokA, tokA) &&
                     shz_w64_gui_subject_ok(tokA, tokA, 1, a == SHZ_CHAN_AUTH_ATTESTED));
            st = shz_chan_attest_lookup(&q, 1, shz_chan_attester_alive(&q, 1, rv[i].gen, rv[i].state), &b, &g);
            a = shz_chan_auth_state(st, b, g, hdr, D, &ever);    /* header generation still 9 */
            snprintf(n, sizeof n, "[%s] same header gen: authorization 2 REVOKED", rv[i].why);
            T(n, st == SHZ_E_NOENT && a == SHZ_CHAN_AUTH_REVOKED);
            snprintf(n, sizeof n, "[%s] revoked: owner, in-VxD and GUI all refused (no legacy)", rv[i].why);
            T(n, !shz_w64_console_owner_auth(a == SHZ_CHAN_AUTH_ATTESTED, a == SHZ_CHAN_AUTH_REVOKED, tokA, tokA) &&
                     !shz_w64_console_owner_auth(a == SHZ_CHAN_AUTH_ATTESTED, a == SHZ_CHAN_AUTH_REVOKED, tokA, 0) &&
                     !shz_w64_gui_subject_ok(tokA, tokA, 1, a == SHZ_CHAN_AUTH_ATTESTED));
            a = shz_chan_auth_state(SHZ_E_UNSUPPORTED, 0, 0, hdr, D, &ever);
            snprintf(n, sizeof n, "[%s] later old-Supervisor/none answer stays REVOKED", rv[i].why);
            T(n, a == SHZ_CHAN_AUTH_REVOKED);
            snprintf(n, sizeof n, "[%s] restarted attester cannot rebind same header gen", rv[i].why);
            T(n, shz_chan_attest_decide(&q, 1, 1, 1, hdr, hdr, D, 1, 5, &out) == SHZ_E_BUSY);
        }
    }
    printf("%s %d failure(s)\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}
