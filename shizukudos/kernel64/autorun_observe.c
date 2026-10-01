/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit standalone observation after the original autorun process ends.
 * Electron's genuine relaunch helper and other children remain scheduled.
 * This changes neither the original result nor application acceptance.
 * Default OFF. The Supervisor profile never waits here.
 */
#include "k64.h"

#ifdef SHZ_STANDALONE
/* 0 absent, 1 valid, -1 invalid. Exact token, no truncation or overflow. */
static int observe_timeout(const char *command, unsigned *seconds)
{
    static const char key[] = "shz.autorun-observe";
    const size_t key_length = sizeof key - 1;
    int found = 0;
    unsigned value = 0;
    const char *p = command;
    while (p && *p) {
        const char *end, *digits;
        size_t length;
        while (*p == ' ') ++p;
        if (!*p) break;
        end = p;
        while (*end && *end != ' ') ++end;
        length = (size_t)(end - p);
        if (length >= key_length && !strncmp(p, key, key_length) &&
            (length == key_length || p[key_length] == '=')) {
            if (found || length <= key_length + 1 || p[key_length] != '=') return -1;
            found = 1;
            for (digits = p + key_length + 1; digits < end; ++digits) {
                const unsigned digit = (unsigned)(*digits - '0');
                if (digit > 9 || value > (3600u - digit) / 10u) return -1;
                value = value * 10u + digit;
            }
            if (!value) return -1;
        }
        p = end;
    }
    if (found) *seconds = value;
    return found;
}
#endif

void k64_autorun_observe(void)
{
#ifdef SHZ_STANDALONE
    unsigned seconds = 0;
    const int parsed = observe_timeout(k64_boot_cmdline(), &seconds);
    uint64_t start, limit, next_beat;
    if (!parsed) return;
    if (parsed < 0 || !k64_cmdline_has("shz.autorun")) {
        kprintf("K64 observation: rejected option; requires one timeout 1..3600 s and shz.autorun\n");
        return;
    }
    limit = ((uint64_t)seconds * 1000000ull + TICK_US - 1u) / TICK_US;
    start = ticks_now();
    next_beat = 30000000ull / TICK_US;
    kprintf("K64 observation: post-autorun scheduling for at most %u s; original result retained\n", seconds);
    while (ticks_now() - start < limit) {
        const uint64_t elapsed = ticks_now() - start;
        uint64_t remaining_ms;
        if (elapsed >= limit) break;
        if (elapsed >= next_beat) {
            kprintf("K64 observation: elapsed %u s; application functionality unverified\n",
                    (unsigned)(elapsed * TICK_US / 1000000ull));
            next_beat += 30000000ull / TICK_US;
        }
        remaining_ms = ((limit - elapsed) * TICK_US + 999u) / 1000u;
        thread_sleep_ms(remaining_ms < 10u ? remaining_ms : 10u);
    }
    kprintf("K64 observation: bounded post-autorun scheduling ended; original result retained\n");
#endif
}
