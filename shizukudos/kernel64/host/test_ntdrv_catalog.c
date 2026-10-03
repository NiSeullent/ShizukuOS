/* SPDX-License-Identifier: GPL-2.0-only
 * Host unit test for kernel64/ntdrv_catalog.c: PCI ID generation, catalogue rank/selection, binding classification
 * against an owner string, and GOP mode validation. Host-only evidence: identities below are test input, not guest
 * hardware. Build: cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -I.. test_ntdrv_catalog.c
 *                  ../ntdrv_catalog.c
 */
#include <stdio.h>
#include <string.h>
#include "../ntdrv_catalog.h"

static int failures;
#define CHECK(c) do { if (!(c)) { ++failures; fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

static int find(const char *service)
{
    unsigned i;
    for (i = 0; i < shz_k64_catalog_count; ++i)
        if (!strcmp(shz_k64_catalog[i].service, service)) return (int)i;
    return -2;
}

int main(void)
{
    shz_pci_ident_t bga = { 0x1234, 0x1111, 0x1af4, 0x1100, 0x03, 0x00, 0x00, 0x02, 1 };
    shz_pci_ident_t ahci = { 0x8086, 0x2922, 0x1af4, 0x1100, 0x01, 0x06, 0x01, 0x02, 1 };
    shz_pci_ident_t xhci = { 0x1b36, 0x000d, 0x1af4, 0x1100, 0x0c, 0x03, 0x30, 0x01, 1 };
    shz_pci_ident_t ide = { 0x8086, 0x7010, 0, 0, 0x01, 0x01, 0x80, 0x00, 1 };
    shz_pci_ids_t ids;
    shz_drvcat_result_t r;
    const char *m = 0;
    shz_gop_mode_t g;

    /* Microsoft PCI identifier order: 4 hardware IDs, 7 compatible IDs, upper-case hex, SUBSYS = device<<16|vendor. */
    CHECK(shz_pci_ids_build(&bga, &ids) == 0);
    CHECK(ids.n_hw == 4 && ids.n_compat == 7);
    CHECK(!strcmp(ids.hw[0], "PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4&REV_02"));
    CHECK(!strcmp(ids.hw[1], "PCI\\VEN_1234&DEV_1111&SUBSYS_11001AF4"));
    CHECK(!strcmp(ids.hw[2], "PCI\\VEN_1234&DEV_1111&CC_030000"));
    CHECK(!strcmp(ids.hw[3], "PCI\\VEN_1234&DEV_1111&CC_0300"));
    CHECK(!strcmp(ids.compat[0], "PCI\\VEN_1234&DEV_1111&REV_02"));
    CHECK(!strcmp(ids.compat[1], "PCI\\VEN_1234&DEV_1111"));
    CHECK(!strcmp(ids.compat[4], "PCI\\VEN_1234"));
    CHECK(!strcmp(ids.compat[5], "PCI\\CC_030000"));
    CHECK(!strcmp(ids.compat[6], "PCI\\CC_0300"));
    CHECK(shz_pci_ids_build(0, &ids) == -1 && shz_pci_ids_build(&bga, 0) == -1);

    /* Rank: VEN&DEV (compat index 1) beats the class match (compat index 6); both in band 0x2000; lowercase accepted. */
    CHECK(shz_drvcat_rank(&shz_k64_catalog[find("gfx_bga")], &ids, &m) == 0x2100 && !strcmp(m, "PCI\\VEN_1234&DEV_1111"));
    CHECK(shz_drvcat_rank(&shz_k64_catalog[find("shzgop")], &ids, &m) == 0x2600);
    {
        const shz_drvcat_entry_t lower = { "x", "x", "x", { "pci\\ven_1234&dev_1111&cc_0300", 0 }, { 0 }, 0 };
        CHECK(shz_drvcat_rank(&lower, &ids, 0) == 0x0300);
    }

    /* Selection without an owner: BGA best, not started (no backend claimed it). */
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &bga, 0, 1, &r) == 0);
    CHECK(r.best == find("gfx_bga") && r.state == SHZ_BIND_MATCHED_NOT_STARTED && r.bound == -1);
    /* UEFI direct boot: BGA declined, GOP claimed the BAR owner -> bound to shzgop even though BGA ranks better. */
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &bga, "gfx_fb (UEFI GOP)", 1, &r) == 0);
    CHECK(r.state == SHZ_BIND_BOUND && r.bound == find("shzgop") && r.best == find("gfx_bga"));
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &bga, "gfx_fb (Bochs VBE)", 1, &r) == 0);
    CHECK(r.state == SHZ_BIND_BOUND && r.bound == find("gfx_bga"));
    /* An unknown VGA without a boot framebuffer: the GOP basic driver is gated off -> no driver. */
    {
        shz_pci_ident_t vga = { 0x10de, 0x2504, 0, 0, 0x03, 0x00, 0x00, 0xa1, 1 };
        CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &vga, 0, 0, &r) == 0);
        CHECK(r.state == SHZ_BIND_NO_DRIVER && r.best == -1);
        CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &vga, 0, 1, &r) == 0);
        CHECK(r.state == SHZ_BIND_MATCHED_NOT_STARTED && r.best == find("shzgop") && !strcmp(r.matched_id, "PCI\\CC_0300"));
    }
    /* Class-matched storage, hosted NT owner, unlisted owner, and an unsupported xHCI. */
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &ahci, "ahci_blk (AHCI SATA)", 0, &r) == 0);
    CHECK(r.state == SHZ_BIND_BOUND && r.bound == find("ahci_blk"));
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &ahci, "ntdrv:storahci", 0, &r) == 0);
    CHECK(r.state == SHZ_BIND_BOUND_HOSTED && r.bound == -1 && r.best == find("ahci_blk"));
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &ahci, "nvme (NVMe)", 0, &r) == 0);
    CHECK(r.state == SHZ_BIND_BOUND_UNLISTED);         /* a claim string of a non-matching entry is not accepted */
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &xhci, 0, 1, &r) == 0);
    CHECK(r.state == SHZ_BIND_NO_DRIVER);
    CHECK(shz_drvcat_match(shz_k64_catalog, shz_k64_catalog_count, &ide, 0, 1, &r) == 0 && r.state == SHZ_BIND_NO_DRIVER);
    CHECK(shz_drvcat_match(0, 1, &ide, 0, 1, &r) == -1 && shz_drvcat_match(shz_k64_catalog, 1, 0, 0, 1, &r) == -1);
    CHECK(shz_drvcat_match(shz_k64_catalog, 1, &ide, 0, 1, 0) == -1);

    /* GOP mode validation. */
    memset(&g, 0, sizeof g);
    CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_ABSENT && shz_gop_mode_check(0, 0) == SHZ_GOP_ABSENT);
    g.base = 0x80000000ull; g.size = 1280u * 4 * 800; g.width = 1280; g.height = 800; g.pitch = 1280 * 4; g.bpp = 32;
    g.format = SHZ_GOP_FMT_BGRX8888;
    CHECK(shz_gop_mode_check(&g, 64ull << 30) == SHZ_GOP_OK);
    g.format = SHZ_GOP_FMT_RGBX8888; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_OK);
    g.format = 2; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_FORMAT); g.format = 1;    /* bitmask / BLT-only */
    g.bpp = 24; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_BPP); g.bpp = 32;
    g.size -= 4; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_EXCEEDS_SIZE); g.size += 4;  /* pitch*height > size */
    g.pitch = 1279 * 4; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_PITCH);
    g.pitch = 1280 * 4 + 2; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_PITCH);
    g.pitch = 1344 * 4; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_EXCEEDS_SIZE);       /* padded pitch needs more */
    g.size = (uint64_t)g.pitch * g.height; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_OK);
    g.base = 0x80000002ull; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_BASE); g.base = 0x80000000ull;
    g.height = 0; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_BAD_GEOMETRY); g.height = 800;
    CHECK(shz_gop_mode_check(&g, 0x80000000ull + g.size - 1) == SHZ_GOP_ABOVE_LIMIT);
    CHECK(shz_gop_mode_check(&g, 0x80000000ull + g.size) == SHZ_GOP_OK);
    g.base = UINT64_MAX - 0xfff; CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_WRAPS); g.base = 0x80000000ull;
    g.width = 9000; g.pitch = 9000 * 4; g.height = 10; g.size = (uint64_t)g.pitch * 10;
    CHECK(shz_gop_mode_check(&g, 0) == SHZ_GOP_TOO_LARGE);
    CHECK(!strcmp(shz_gop_check_name(SHZ_GOP_EXCEEDS_SIZE), "pitch*height exceeds size"));

    printf("%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures != 0;
}
