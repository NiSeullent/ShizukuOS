/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "interactive_choice.h"

static plat_disk_t disks[4];
static unsigned count, reads, writes;
static unsigned dc(void *ctx) { (void)ctx; return count; }
static int di(void *ctx, unsigned i, plat_disk_t *out)
{ (void)ctx; if (i >= count) return -1; *out = disks[i]; return 0; }
static int dr(void *c, unsigned i, uint64_t l, uint32_t n, void *p)
{ (void)c; (void)i; (void)l; (void)n; (void)p; ++reads; return -1; }
static int dw(void *c, unsigned i, uint64_t l, uint32_t n, const void *p)
{ (void)c; (void)i; (void)l; (void)n; (void)p; ++writes; return -1; }

int main(void)
{
    plat_t p = {0};
    plat_disk_t chosen, before;
    char answer[1024], guard[4] = {'x','x','x','x'};
    unsigned i;
    p.disk_count = dc; p.disk_info = di; p.disk_read = dr; p.disk_write = dw;
    count = 2;
    for (i = 0; i < count; ++i) {
        disks[i].sector_size = 512; disks[i].sectors = 512u * 2048u;
        snprintf(disks[i].name, sizeof disks[i].name, "ahci%u", i);
    }
    assert(!setup_review_target(&p, 1, &chosen));
    assert(!strcmp(chosen.name, "ahci1"));
    before = chosen;
    assert(setup_build_interactive_answer(&chosen, "", 0, answer, sizeof answer));
    assert(setup_build_interactive_answer(&chosen, "ERAS", 0, answer, sizeof answer));
    assert(setup_build_interactive_answer(&chosen, "ERASE ", 0, answer, sizeof answer));
    assert(setup_build_interactive_answer(&chosen, "erase", 0, answer, sizeof answer));
    assert(!setup_build_interactive_answer(&chosen, "ERASE", 0, answer, sizeof answer));
    assert(strstr(answer, "Select=name\nName=ahci1\n"));
    assert(strstr(answer, "Confirm=ERASE-TARGET\nReboot=none\n"));
    assert(strstr(answer, "AllowNonEmpty=yes\n"));
    assert(!strstr(answer, "Select=first"));
    assert(!memcmp(&chosen, &before, sizeof chosen));
    assert(setup_build_interactive_answer(&chosen, "ERASE", 0, guard, sizeof guard));
    assert(!memcmp(guard, "xxxx", sizeof guard));
    assert(setup_build_interactive_answer(&chosen, "ERASE", 1, answer, sizeof answer));
    chosen.sectors = 2048u * 2048u;
    assert(!setup_build_interactive_answer(&chosen, "ERASE", 1, answer, sizeof answer));
    assert(strstr(answer, "Win98MiB=512\nWin98HybridMBR=yes\n"));
    chosen.flags = PLAT_DISK_READONLY;
    assert(setup_build_interactive_answer(&chosen, "ERASE", 0, answer, sizeof answer));
    chosen = before;
    strcpy(disks[0].name, "ahci1");
    assert(setup_review_target(&p, 1, &chosen));
    strcpy(disks[0].name, "ahci0");
    assert(setup_review_target(&p, 2, &chosen));
    disks[1].flags = PLAT_DISK_PARTITION;
    assert(setup_review_target(&p, 1, &chosen));
    disks[1].flags = PLAT_DISK_READONLY;
    assert(setup_review_target(&p, 1, &chosen));
    disks[1].flags = 0; disks[1].sector_size = 4096;
    assert(setup_review_target(&p, 1, &chosen));
    disks[1].sector_size = 512; disks[1].sectors = 2048;
    assert(setup_review_target(&p, 1, &chosen));
    disks[1].sectors = UINT64_MAX;
    assert(setup_review_target(&p, 1, &chosen));
    disks[1].sectors = 512u * 2048u;
    strcpy(disks[1].name, "evil\nName=x");
    assert(setup_review_target(&p, 1, &chosen));
    memset(disks[1].name, 'x', sizeof disks[1].name);
    assert(setup_review_target(&p, 1, &chosen));
    strcpy(disks[1].name, "usb0"); disks[1].flags = PLAT_DISK_REMOVABLE;
    assert(!setup_review_target(&p, 1, &chosen));
    assert(!reads && !writes);
    puts("PASS: interactive target/confirmation contract; review and refusal perform no disk I/O");
    return 0;
}
