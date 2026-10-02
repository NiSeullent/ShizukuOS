/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit Supervisor runtime policy, using the existing ABI 1.1 command line.
 * Call on the original handoff before copying, truncating or forcing a NUL.
 * This selects a persistent worker profile; it does not attest Windows boot.
 */
#ifndef SHZ_WIN98_FOUNDATION_H
#define SHZ_WIN98_FOUNDATION_H
#include "../abi/shz_abi.h"

static inline int shz_foundation_word(const char *word, uint32_t length,
                                      const char *literal, uint32_t literal_length)
{
    uint32_t i;
    if (length != literal_length) return 0;
    for (i = 0; i < length; ++i)
        if (word[i] != literal[i]) return 0;
    return 1;
}

/* 0: diagnostic/development profile; 1: exact native Win98 foundation;
 * -1: malformed handoff or an unsupported/conflicting explicit profile.
 * A legacy writer without any command-line tail remains diagnostic. Partial
 * command-line fields are rejected without reading beyond the declared size.
 * Diagnostic channel layouts and flags retain their existing interpretation.
 */
static inline int shz_win98_foundation_policy(const shz_bootinfo_t *bi)
{
    static const char key[] = "shz.foundation";
    static const char token[] = "shz.foundation=win98";
    uint32_t i, words = 0, selected = 0, seen = 0, expected;
    if (!bi || bi->magic != SHZ_BOOTINFO_MAGIC || bi->abi_major != SHZ_ABI_MAJOR ||
        bi->size < __builtin_offsetof(shz_bootinfo_t, fb_base)) return -1;
    if (bi->size <= __builtin_offsetof(shz_bootinfo_t, cmdline_size)) return 0;
    if (!SHZ_BOOTINFO_HAS(bi, cmdline)) return -1;
    if (bi->cmdline_size >= SHZ_CMDLINE_MAX || bi->cmdline[bi->cmdline_size] != 0) return -1;
    for (i = 0; i < bi->cmdline_size; ++i) {
        const unsigned char c = (unsigned char)bi->cmdline[i];
        if (c < 32 || c > 126) return -1;
    }
    for (i = 0; i < bi->cmdline_size;) {
        uint32_t start, length;
        while (i < bi->cmdline_size && bi->cmdline[i] == ' ') ++i;
        if (i == bi->cmdline_size) break;
        start = i;
        while (i < bi->cmdline_size && bi->cmdline[i] != ' ') ++i;
        length = i - start;
        ++words;
        if (length >= sizeof key - 1 &&
            shz_foundation_word(bi->cmdline + start, sizeof key - 1, key, sizeof key - 1) &&
            (length == sizeof key - 1 || bi->cmdline[start + sizeof key - 1] == '=')) {
            if (!shz_foundation_word(bi->cmdline + start, length, token, sizeof token - 1) || selected)
                return -1;
            selected = 1;
        }
    }
    if (!selected) return 0;
    if (words != 1 || bi->flags || !bi->generation || bi->abi_minor < 1) return -1;
#ifdef SHZ_STANDALONE
    return -1; /* A boot command cannot manufacture a Supervisor or Win98 peer. */
#endif
    if (bi->domain_id == SHZ_DOM_KERNEL32) expected = 1;
    else if (bi->domain_id == SHZ_DOM_KERNEL64) expected = 2;
    else return -1;
    if (bi->channel_count != expected) return -1;
    for (i = 0; i < bi->channel_count; ++i) {
        const uint32_t id = bi->channel[i].channel_id;
        uint32_t peer;
        if (id == 0) peer = bi->domain_id == SHZ_DOM_KERNEL32 ? SHZ_DOM_KERNEL64 : SHZ_DOM_KERNEL32;
        else if (id == 2 && bi->domain_id == SHZ_DOM_KERNEL64) peer = SHZ_DOM_WIN98;
        else return -1;
        if ((seen & (1u << id)) || bi->channel[i].peer_domain != peer ||
            bi->channel[i].gpa != SHZ_IPC_GPA_BASE + (uint64_t)id * SHZ_IPC_REGION_SIZE ||
            bi->channel[i].size != SHZ_IPC_REGION_SIZE) return -1;
        seen |= 1u << id;
    }
    return seen == (bi->domain_id == SHZ_DOM_KERNEL32 ? 1u : 5u) ? 1 : -1;
}
#endif
