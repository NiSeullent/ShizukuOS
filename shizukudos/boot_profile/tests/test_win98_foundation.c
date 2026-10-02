/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../win98_foundation.h"

static unsigned checks;
#define CHECK(expression) do { ++checks; if (!(expression)) { \
    fprintf(stderr, "FAIL line %u: %s\n", (unsigned)__LINE__, #expression); exit(1); \
} } while (0)

static void command(shz_bootinfo_t *bi, const char *text)
{
    size_t n = strlen(text);
    CHECK(n < sizeof bi->cmdline);
    memset(bi->cmdline, 0, sizeof bi->cmdline);
    memcpy(bi->cmdline, text, n + 1);
    bi->cmdline_size = (uint32_t)n;
}

static shz_bootinfo_t foundation(uint32_t domain)
{
    shz_bootinfo_t bi;
    memset(&bi, 0, sizeof bi);
    bi.magic = SHZ_BOOTINFO_MAGIC;
    bi.abi_major = SHZ_ABI_MAJOR;
    bi.abi_minor = SHZ_ABI_MINOR;
    bi.size = sizeof bi;
    bi.domain_id = domain;
    bi.generation = 1;
    command(&bi, "shz.foundation=win98");
    bi.channel_count = domain == SHZ_DOM_KERNEL32 ? 1u : 2u;
    bi.channel[0].gpa = SHZ_IPC_GPA_BASE;
    bi.channel[0].size = SHZ_IPC_REGION_SIZE;
    bi.channel[0].peer_domain = domain == SHZ_DOM_KERNEL32 ? SHZ_DOM_KERNEL64 : SHZ_DOM_KERNEL32;
    bi.channel[0].channel_id = 0;
    if (domain == SHZ_DOM_KERNEL64) {
        bi.channel[1].gpa = SHZ_IPC_GPA_BASE + 2ull * SHZ_IPC_REGION_SIZE;
        bi.channel[1].size = SHZ_IPC_REGION_SIZE;
        bi.channel[1].peer_domain = SHZ_DOM_WIN98;
        bi.channel[1].channel_id = 2;
    }
    return bi;
}

int main(void)
{
    shz_bootinfo_t bi, before;
    const char *bad[] = {
        "shz.foundation", "shz.foundation=", "shz.foundation=dos", "shz.foundation=WIN98",
        "shz.foundation=win98x", "shz.foundation=win98 shz.foundation=win98",
        "shz.foundation=win98 shz.foundation=dos", "shz.foundation=dos shz.foundation=win98",
        "shz.foundation=win98 shz.desktop", "shz.desktop shz.foundation=win98",
        "shz.foundation=win98 shz.setup=interactive", "shz.autorun=test shz.foundation=win98"
    };
    CHECK(shz_win98_foundation_policy(NULL) == -1);
    for (unsigned domain = SHZ_DOM_KERNEL32; domain <= SHZ_DOM_KERNEL64; ++domain) {
        bi = foundation(domain); before = bi;
#ifdef SHZ_STANDALONE
        CHECK(shz_win98_foundation_policy(&bi) == -1);
#else
        CHECK(shz_win98_foundation_policy(&bi) == 1);
#endif
        CHECK(memcmp(&bi, &before, sizeof bi) == 0);
        command(&bi, ""); CHECK(shz_win98_foundation_policy(&bi) == 0);
        command(&bi, "shz.desktop shz.autorun=test"); CHECK(shz_win98_foundation_policy(&bi) == 0);
        command(&bi, "xshz.foundation=win98 shz.foundation_other=value");
        CHECK(shz_win98_foundation_policy(&bi) == 0);
        /* Diagnostic policy does not reinterpret existing channel layouts. */
        bi.channel_count = UINT32_MAX; bi.flags = UINT32_MAX;
        CHECK(shz_win98_foundation_policy(&bi) == 0);
    }
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; ++i) {
        bi = foundation(SHZ_DOM_KERNEL64); command(&bi, bad[i]);
        CHECK(shz_win98_foundation_policy(&bi) == -1);
    }
    bi = foundation(SHZ_DOM_KERNEL64); command(&bi, "  shz.foundation=win98  ");
#ifdef SHZ_STANDALONE
    CHECK(shz_win98_foundation_policy(&bi) == -1);
#else
    CHECK(shz_win98_foundation_policy(&bi) == 1);
#endif
    /* All truncations are checked against the original writer's declared size. */
    for (unsigned size = 0; size < sizeof bi; ++size) {
        shz_bootinfo_t *bounded;
        size_t storage;
        bi = foundation(SHZ_DOM_KERNEL64); bi.size = size;
        CHECK(shz_win98_foundation_policy(&bi) ==
              (size >= __builtin_offsetof(shz_bootinfo_t, fb_base) &&
               size <= __builtin_offsetof(shz_bootinfo_t, cmdline_size) ? 0 : -1));
        /* ASan sees the actual declared allocation, not a full stack object. */
        storage = size < 176 ? 176 : size;
        bounded = malloc(storage); CHECK(bounded != NULL);
        memcpy(bounded, &bi, storage);
        CHECK(shz_win98_foundation_policy(bounded) ==
              (size >= 176 && size <= 212 ? 0 : -1));
        free(bounded);
    }
    bi = foundation(SHZ_DOM_KERNEL64); bi.size = 176; bi.abi_minor = 0;
    CHECK(shz_win98_foundation_policy(&bi) == 0);
    bi = foundation(SHZ_DOM_KERNEL64); bi.size = UINT32_MAX;
#ifdef SHZ_STANDALONE
    CHECK(shz_win98_foundation_policy(&bi) == -1);
#else
    CHECK(shz_win98_foundation_policy(&bi) == 1);
#endif
    bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline_size = SHZ_CMDLINE_MAX;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi.cmdline_size = UINT32_MAX; CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline_size--;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline_size++;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline[bi.cmdline_size] = 'x';
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline[0] = 0;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    for (unsigned byte = 0; byte <= 255; ++byte) {
        if (byte >= 32 && byte <= 126) continue;
        bi = foundation(SHZ_DOM_KERNEL64); bi.cmdline[2] = (char)byte;
        CHECK(shz_win98_foundation_policy(&bi) == -1);
    }
    bi = foundation(SHZ_DOM_KERNEL64); command(&bi, "");
    memcpy(bi.cmdline + 1, "shz.foundation=win98", 20);
    CHECK(shz_win98_foundation_policy(&bi) == 0);
    bi = foundation(SHZ_DOM_KERNEL64); memset(bi.cmdline, 'a', sizeof bi.cmdline);
    bi.cmdline[255] = 0; bi.cmdline_size = 255;
    CHECK(shz_win98_foundation_policy(&bi) == 0);
    bi.cmdline[255] = 'a'; CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.magic ^= 1;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.abi_major++;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.abi_minor = 0;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    for (unsigned flag = 0; flag < 32; ++flag) {
        bi = foundation(SHZ_DOM_KERNEL64); bi.flags = 1u << flag;
        CHECK(shz_win98_foundation_policy(&bi) == -1);
    }
    bi = foundation(SHZ_DOM_KERNEL64); bi.generation = 0;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    for (unsigned domain = 0; domain < SHZ_DOM_MAX; ++domain) {
        if (domain == SHZ_DOM_KERNEL32 || domain == SHZ_DOM_KERNEL64) continue;
        bi = foundation(SHZ_DOM_KERNEL64); bi.domain_id = domain;
        CHECK(shz_win98_foundation_policy(&bi) == -1);
    }
    bi = foundation(SHZ_DOM_KERNEL64); bi.domain_id = UINT32_MAX;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    for (unsigned domain = SHZ_DOM_KERNEL32; domain <= SHZ_DOM_KERNEL64; ++domain) {
        for (unsigned count = 0; count <= SHZ_MAX_CHANNELS + 1; ++count) {
            if (count == (domain == SHZ_DOM_KERNEL32 ? 1u : 2u)) continue;
            bi = foundation(domain); bi.channel_count = count;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
        }
        bi = foundation(domain); bi.channel_count = UINT32_MAX;
        CHECK(shz_win98_foundation_policy(&bi) == -1);
        for (unsigned c = 0; c < (domain == SHZ_DOM_KERNEL32 ? 1u : 2u); ++c) {
            bi = foundation(domain); bi.channel[c].gpa++;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].gpa = UINT64_MAX;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].size--;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].size = UINT64_MAX;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].peer_domain = domain;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].channel_id = SHZ_MAX_CHANNELS;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
            bi = foundation(domain); bi.channel[c].channel_id = UINT32_MAX;
            CHECK(shz_win98_foundation_policy(&bi) == -1);
        }
    }
    bi = foundation(SHZ_DOM_KERNEL64); bi.channel[1] = bi.channel[0];
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64); bi.channel[1].peer_domain = SHZ_DOM_KERNEL32;
    CHECK(shz_win98_foundation_policy(&bi) == -1);
    bi = foundation(SHZ_DOM_KERNEL64);
    { uint8_t temporary[sizeof bi.channel[0]];
      memcpy(temporary, &bi.channel[0], sizeof temporary);
      memcpy(&bi.channel[0], &bi.channel[1], sizeof temporary);
      memcpy(&bi.channel[1], temporary, sizeof temporary); }
#ifdef SHZ_STANDALONE
    CHECK(shz_win98_foundation_policy(&bi) == -1);
#else
    CHECK(shz_win98_foundation_policy(&bi) == 1);
#endif
    printf("PASS %u production Win98 foundation policy checks; no VM executed\n", checks);
    return 0;
}
