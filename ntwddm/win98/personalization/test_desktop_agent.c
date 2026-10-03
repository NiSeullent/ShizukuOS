/* SPDX-License-Identifier: GPL-2.0-only
 * Host test of the production desktop_agent_core.c + core.c (no Win32). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "desktop_agent.h"
static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)
static uint32_t fnv(const unsigned char *b, size_t n) { uint32_t h = 2166136261u; while (n--) h = (h ^ *b++) * 16777619u; return h; }

int main(void)
{
    szw_settings s, d; uint32_t v[SZW_V_COUNT] = {1, 1, 20, 0, 1}; szw_state st; szw_pacer p;
    uint32_t delay, w, h, i, frames, n; unsigned char *a, *b; size_t bytes;
    szw_rect in[4] = {{10, 10, 60, 70}, {50, 50, 40, 90}, {-2147483647, 5, 3, 9}, {900, 900, 950, 950}}, out[4];

    /* settings: defaults, full record, partial, corrupt record keeps output */
    szw_defaults(&d); CHECK(szw_valid(&d) && !d.enabled && d.fps == 10 && d.battery_pause);
    CHECK(szw_settings_from_values(0x1f, v, &s) && s.enabled && s.scene == 1 && s.fps == 20 && !s.battery_pause);
    CHECK(szw_settings_from_values(1u << SZW_V_ENABLED, v, &s) && s.enabled && s.fps == 10 && s.scene == 0);
    s.scene = 7; v[SZW_V_FPS] = 15;
    CHECK(!szw_settings_from_values(0x1f, v, &s) && s.scene == 7);
    CHECK(!szw_settings_from_values(1u << 5, v, &s));
    v[SZW_V_FPS] = 5; CHECK(szw_settings_from_values(0x1f, v, &s));
    { uint32_t r[SZW_V_COUNT]; szw_settings t; szw_settings_to_values(&s, r); CHECK(szw_settings_from_values(0x1f, r, &t) && !memcmp(&s, &t, sizeof s)); }

    /* policy precedence */
    memset(&st, 0, sizeof st); st.ac = 1; st.host_ok = 1; s.enabled = 1; s.battery_pause = 1; s.fullscreen_pause = 1;
    CHECK(szw_decide(&s, &st) == SZW_RUN);
    st.ac = 0; CHECK(szw_decide(&s, &st) == SZW_PAUSE_BATTERY && !szw_reason_is_stop(SZW_PAUSE_BATTERY));
    st.ac = -1; CHECK(szw_decide(&s, &st) == SZW_PAUSE_BATTERY);
    s.battery_pause = 0; CHECK(szw_decide(&s, &st) == SZW_RUN);
    st.fullscreen = 1; CHECK(szw_decide(&s, &st) == SZW_PAUSE_FULLSCREEN);
    st.screensaver = 1; CHECK(szw_decide(&s, &st) == SZW_PAUSE_SCREENSAVER);
    st.suspended = 1; CHECK(szw_decide(&s, &st) == SZW_PAUSE_SUSPENDED);
    st.host_ok = 0; CHECK(szw_decide(&s, &st) == SZW_STOP_HOST && szw_reason_is_stop(SZW_STOP_HOST));
    st.ending = 1; CHECK(szw_decide(&s, &st) == SZW_STOP_ENDING);
    s.enabled = 0; CHECK(szw_decide(&s, &st) == SZW_STOP_DISABLED);
    s.enabled = 1; s.fps = 3; CHECK(szw_decide(&s, &st) == SZW_STOP_DISABLED);
    s.fps = 10; memset(&st, 0, sizeof st); st.host_ok = 1; st.ac = 1; st.host_hung = 1;
    CHECK(szw_decide(&s, &st) == SZW_PAUSE_HUNG_HOST);

    /* pacer: cadence, tick wraparound, no catch-up burst, rate degradation */
    CHECK(!szw_pacer_init(&p, 7) && szw_pacer_init(&p, 10));
    CHECK(szw_pacer_tick(&p, 0xFFFFFFC0u, &delay) && delay == 100);
    CHECK(!szw_pacer_tick(&p, 0xFFFFFFC0u + 50u, &delay) && delay == 50);
    CHECK(szw_pacer_tick(&p, 0xFFFFFFC0u + 100u, &delay) && delay == 100 && p.frames == 2); /* across 2^32 */
    CHECK(szw_phase(&p) == 4);
    CHECK(szw_pacer_tick(&p, 0xFFFFFFC0u + 1300u, &delay) && p.dropped == 11 && delay == 100);
    CHECK(!szw_pacer_tick(&p, 0xFFFFFFC0u + 1301u, &delay));
    CHECK(szw_phase(&p) == (3 + 11) * 2);
    for (i = 0, n = 0; i < 16; i++) n += szw_pacer_cost(&p, 80) != 0;
    CHECK(n == 1 && p.fps == 5 && p.interval == 200);
    for (i = 0, n = 0; i < 16; i++) n += szw_pacer_cost(&p, 100);
    CHECK(n == 0 && p.fps == 5);
    for (i = 0; i < 15; i++) CHECK(szw_pacer_cost(&p, 150) == 0);
    CHECK(szw_pacer_cost(&p, 150) == -1);
    szw_pacer_init(&p, 20); frames = 0;
    for (i = 0; i < 1000; i += 10) frames += (uint32_t)szw_pacer_tick(&p, i, &delay);
    CHECK(frames == 20 && szw_phase(&p) == 20);

    /* render target sizing */
    CHECK(szw_render_size(640, 480, &w, &h) && w == 320 && h == 240);
    CHECK(szw_render_size(3840, 2160, &w, &h) && w == 960 && h == 540);
    CHECK(szw_render_size(1024, 4096, &w, &h) && w <= SZW_MAX_RENDER_W && h == 540);
    CHECK(!szw_render_size(1, 480, &w, &h) && !szw_render_size(20000, 480, &w, &h));

    /* deterministic frame generator */
    w = 320; h = 240; bytes = (size_t)w * h * 4u; a = malloc(bytes); b = malloc(bytes);
    CHECK(a && b);
    if (a && b) {
        memset(a, 0xAB, bytes); memset(b, 0xCD, bytes);
        CHECK(szw_frame(a, bytes, w, h, 0, 17) && szw_frame(b, bytes, w, h, 0, 17) && !memcmp(a, b, bytes));
        CHECK(szw_frame(b, bytes, w, h, 0, 18) && memcmp(a, b, bytes));
        CHECK(szw_frame(b, bytes, w, h, 1, 17) && memcmp(a, b, bytes));
        for (i = 3; i < bytes; i += 4) if (a[i]) { CHECK(!"alpha byte nonzero"); break; }
        printf("frame scene0 phase17 fnv=%08x\n", fnv(a, bytes));
        memset(b, 0x5A, bytes);
        CHECK(!szw_frame(b, bytes - 1, w, h, 0, 1) && !szw_frame(b, bytes, w, h, 2, 1) &&
              !szw_frame(b, bytes, 961, 1, 0, 1) && !szw_frame(NULL, bytes, w, h, 0, 1));
        for (i = 0; i < bytes; i++) if (b[i] != 0x5A) { CHECK(!"invalid frame wrote pixels"); break; }
    }
    /* profile change: stop reason, ordered after ending, before host */
    s.fps = 10; memset(&st, 0, sizeof st); st.host_ok = 1; st.ac = 1; st.profile_changed = 1;
    CHECK(szw_decide(&s, &st) == SZW_STOP_PROFILE && szw_reason_is_stop(SZW_STOP_PROFILE));
    st.profile_changed = 0; CHECK(szw_decide(&s, &st) == SZW_RUN);
    {
        char t1[9], t2[9], t3[9], t4[9];
        szw_user_tag("Alice", t1); szw_user_tag("ALICE", t2); szw_user_tag("bob", t3); szw_user_tag(NULL, t4);
        CHECK(!strcmp(t1, t2) && strcmp(t1, t3) && strlen(t1) == 8 && strlen(t4) == 8);
        szw_user_tag("", t3); CHECK(!strcmp(t3, t4) && !strcmp(t4, "811c9dc5"));
    }

    free(a); free(b);

    /* icon clip validation */
    n = szw_clip_icons(in, 4, 800, 600, 2, out, 4);
    CHECK(n == 2 && out[0].left == 8 && out[0].top == 8 && out[0].right == 62 && out[0].bottom == 72);
    CHECK(out[1].left == 0 && out[1].top == 3 && out[1].right == 5 && out[1].bottom == 11);
    CHECK(szw_clip_icons(in, 4, 800, 600, 2, out, 1) == 1 && !szw_clip_icons(in, 4, 0, 600, 2, out, 4));
    CHECK(!szw_clip_icons(in, 4, 800, 600, 65, out, 4));

    printf(failures ? "desktop agent core: %d failure(s)\n" : "desktop agent core: ok\n", failures);
    return failures != 0;
}
