/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the installed driver catalog v2 parser (shizukudos/kernel64/ntdrv_catalog.c pure part).
 * cc -std=gnu11 -Wall -Wextra -Werror -DSHZ_CATALOG_HOST drivers/common/tests/test_shz_catalog.c -o /tmp/t && /tmp/t
 */
#define SHZ_CATALOG_HOST 1
#include "../../../shizukudos/kernel64/ntdrv_catalog.c"
#include <stdio.h>
#include <string.h>

#define K64 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define IMG "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define HDR "; comment\r\n[Catalog]\r\nSchema=shizuku-driver-catalog/2\r\nSelection=default\r\nInstallGeneration=7\r\nKernel64Sha256=" K64 "\r\n"
#define B0 "\r\n[Driver.0]\r\nPackage=driver-ahci\r\nKind=builtin\r\nMatch=class 01:06:01\r\nImageSha256=" K64 "\r\nStart=boot\r\nPath=SHZ/x\r\nBytes=12\r\nSha256=" IMG "\r\n"
#define S1 "\r\n[Driver.1]\r\nPackage=driver-e1000\r\nKind=service\r\nMatch=8086:100e, 8086:10d3-10d4\r\nService=e1000\r\nImage=\\SHZ\\DRIVERS\\E1000\\E1000.SYS\r\nImageSha256=" IMG "\r\nStart=demand\r\n"
#define SUM(n) "\r\n[Summary]\r\nCount=" #n "\r\n"

static int fails, calls_service, calls_builtin_leak;
static int verify(void *c, const char *image, const uint8_t sha[32])
{
    uint8_t want[32];
    (void)c;
    memset(want, 0xbb, 32);
    return strcmp(image, "\\SHZ\\DRIVERS\\E1000\\E1000.SYS") || memcmp(sha, want, 32) ? -1 : 0;
}
static void svc(void *c, const shz_cat_row_t *r) { (void)c; ++calls_service; if (r->kind != SHZ_CAT_KIND_SERVICE) ++calls_builtin_leak; }
static int run(const char *name, const char *text, size_t len, int want_rc, int want_acc, int want_rej, int want_svc, uint64_t gen)
{
    shz_cat_result_t res;
    shz_cat_ops_t ops = { 0, gen, verify, svc };
    int rc;
    calls_service = 0;
    rc = shz_catalog_parse(text, len, &ops, &res);
    if (rc != want_rc || (int)res.accepted != want_acc || (int)res.rejected != want_rej || calls_service != want_svc || calls_builtin_leak) {
        printf("FAIL %s: rc=%d acc=%u rej=%u svc=%d leak=%d\n", name, rc, res.accepted, res.rejected, calls_service, calls_builtin_leak);
        ++fails;
        return 0;
    }
    printf("ok   %s: rc=%d accepted=%u rejected=%u service_callbacks=%d\n", name, rc, res.accepted, res.rejected, calls_service);
    return 1;
}
#define RUN(n, t, rc, a, r, s) run(n, t, strlen(t), rc, a, r, s, 0)

int main(void)
{
    static char big[SHZ_CAT_MAX_BYTES + 64];
    RUN("valid v2", HDR B0 S1 SUM(2), 0, 2, 0, 1);
    run("valid v2 attested generation", HDR B0 S1 SUM(2), strlen(HDR B0 S1 SUM(2)), 0, 2, 0, 1, 7);
    run("generation mismatch", HDR B0 S1 SUM(2), strlen(HDR B0 S1 SUM(2)), SHZ_CAT_E_GENERATION, 0, 0, 0, 8);
    RUN("duplicate key in row", HDR B0 "\r\n[Driver.1]\r\nPackage=driver-x\r\nPackage=driver-y\r\nKind=builtin\r\nMatch=class 01:08:02\r\nStart=boot\r\n" SUM(2), 0, 1, 1, 0);
    RUN("duplicate header key", HDR "Selection=x\r\n" B0 SUM(1), SHZ_CAT_E_HEADER, 0, 0, 0);
    RUN("gap index", HDR B0 "\r\n[Driver.2]\r\nPackage=driver-n\r\nKind=builtin\r\nMatch=class 01:08:02\r\nStart=boot\r\n" SUM(2), 0, 1, 1, 0);
    RUN("bad hex match", HDR "\r\n[Driver.0]\r\nPackage=driver-q\r\nKind=builtin\r\nMatch=class 0g:06:01\r\nStart=boot\r\n" SUM(1), 0, 0, 1, 0);
    RUN("bad hex kernel sha", "[Catalog]\r\nSchema=shizuku-driver-catalog/2\r\nSelection=d\r\nInstallGeneration=1\r\nKernel64Sha256=zz" K64 "\r\n" SUM(0), SHZ_CAT_E_HEADER, 0, 0, 0);
    RUN("count mismatch", HDR B0 S1 SUM(3), SHZ_CAT_E_SUMMARY, 0, 0, 0);
    RUN("unknown section", HDR B0 "\r\n[Extra]\r\n" SUM(1), SHZ_CAT_E_SECTION, 0, 0, 0);
    RUN("unknown row key", HDR "\r\n[Driver.0]\r\nPackage=driver-a\r\nKind=builtin\r\nMatch=class 01:06:01\r\nStart=boot\r\nColor=red\r\n" SUM(1), 0, 0, 1, 0);
    RUN("service hash mismatch", HDR "\r\n[Driver.0]\r\nPackage=driver-e\r\nKind=service\r\nMatch=8086:100e\r\nService=e1000\r\nImage=\\SHZ\\DRIVERS\\E1000\\E1000.SYS\r\nImageSha256=" K64 "\r\nStart=demand\r\n" SUM(1), 0, 0, 1, 0);
    RUN("image path traversal", HDR "\r\n[Driver.0]\r\nPackage=driver-e\r\nKind=service\r\nMatch=8086:100e\r\nService=e1000\r\nImage=\\SHZ\\DRIVERS\\..\\X.SYS\r\nImageSha256=" IMG "\r\nStart=demand\r\n" SUM(1), 0, 0, 1, 0);
    RUN("builtin xHCI unlinked", HDR "\r\n[Driver.0]\r\nPackage=driver-xhci\r\nKind=builtin\r\nMatch=class 0c:03:30\r\nStart=boot\r\n" SUM(1), 0, 0, 1, 0);
    RUN("builtin with service keys", HDR "\r\n[Driver.0]\r\nPackage=driver-a\r\nKind=builtin\r\nMatch=class 01:06:01\r\nService=ahci\r\nStart=boot\r\n" SUM(1), 0, 0, 1, 0);
    RUN("builtin hash != kernel", HDR "\r\n[Driver.0]\r\nPackage=driver-a\r\nKind=builtin\r\nMatch=class 01:06:01\r\nImageSha256=" IMG "\r\nStart=boot\r\n" SUM(1), 0, 0, 1, 0);
    RUN("duplicate service", HDR B0 S1 "\r\n[Driver.2]\r\nPackage=driver-e2\r\nKind=service\r\nMatch=8086:100f\r\nService=E1000\r\nImage=\\SHZ\\DRIVERS\\E1000\\E1000.SYS\r\nImageSha256=" IMG "\r\nStart=demand\r\n" SUM(3), 0, 2, 1, 1);
    RUN("missing summary", HDR B0, SHZ_CAT_E_SUMMARY, 0, 0, 0);
    RUN("control byte", HDR "\x01\r\n" SUM(0), SHZ_CAT_E_SYNTAX, 0, 0, 0);
    memset(big, ';', sizeof big);
    run("oversize", big, sizeof big, SHZ_CAT_E_SIZE, 0, 0, 0, 0);
    {
        shz_cat_result_t res;
        shz_cat_ops_t ops = { 0, 0, verify, svc };
        int m;
        shz_catalog_parse(HDR B0 S1 SUM(2), strlen(HDR B0 S1 SUM(2)), &ops, &res);
        m = shz_catalog_row_matches(&res.row[1], 0x8086, 0x10d4, 2, 0, 0) && !shz_catalog_row_matches(&res.row[1], 0x8086, 0x10d5, 2, 0, 0) &&
            res.row[0].builtin_driver == SHZ_BRINGUP_DRV_AHCI;
        printf("%s match ranges / builtin driver id\n", m ? "ok  " : "FAIL");
        fails += !m;
    }
    printf("builtin rows never reached service_row: %s\n", calls_builtin_leak ? "FAIL" : "ok");
    printf("%s (%d failure(s))\n", fails ? "FAIL" : "PASS", fails);
    return fails != 0;
}
