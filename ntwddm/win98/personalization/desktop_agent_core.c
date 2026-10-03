/* SPDX-License-Identifier: GPL-2.0-only */
#include "desktop_agent.h"
#include "core.h"

const char *const szw_value_names[SZW_V_COUNT] = {
    "Enabled", "Scene", "FramesPerSecond", "PauseOnBattery", "PauseOnFullscreen"
};

void szw_defaults(szw_settings *s)
{
    if (s) { s->enabled = 0; s->scene = 0; s->fps = 10; s->battery_pause = 1; s->fullscreen_pause = 1; }
}

int szw_valid(const szw_settings *s)
{
    return s && s->enabled < 2 && s->scene < 2 && (s->fps == 5 || s->fps == 10 || s->fps == 20) &&
           s->battery_pause < 2 && s->fullscreen_pause < 2;
}

int szw_settings_from_values(uint32_t mask, const uint32_t v[SZW_V_COUNT], szw_settings *out)
{
    szw_settings c;
    if (!v || !out || (mask >> SZW_V_COUNT)) return 0;
    szw_defaults(&c);
    if (mask & (1u << SZW_V_ENABLED)) c.enabled = v[SZW_V_ENABLED];
    if (mask & (1u << SZW_V_SCENE)) c.scene = v[SZW_V_SCENE];
    if (mask & (1u << SZW_V_FPS)) c.fps = v[SZW_V_FPS];
    if (mask & (1u << SZW_V_BATTERY)) c.battery_pause = v[SZW_V_BATTERY];
    if (mask & (1u << SZW_V_FULLSCREEN)) c.fullscreen_pause = v[SZW_V_FULLSCREEN];
    if (!szw_valid(&c)) return 0;
    *out = c;
    return 1;
}

void szw_settings_to_values(const szw_settings *s, uint32_t v[SZW_V_COUNT])
{
    if (!s || !v) return;
    v[SZW_V_ENABLED] = s->enabled; v[SZW_V_SCENE] = s->scene; v[SZW_V_FPS] = s->fps;
    v[SZW_V_BATTERY] = s->battery_pause; v[SZW_V_FULLSCREEN] = s->fullscreen_pause;
}

void szw_user_tag(const char *user, char out[9])
{
    uint32_t h = 2166136261u; unsigned i;
    for (; user && *user; user++) {
        unsigned char c = (unsigned char)*user;
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);
        h = (h ^ c) * 16777619u;
    }
    for (i = 0; i < 8; i++) out[i] = "0123456789abcdef"[(h >> (28 - 4 * i)) & 15u];
    out[8] = 0;
}

szw_reason szw_decide(const szw_settings *s, const szw_state *st)
{
    if (!szw_valid(s) || !st || !s->enabled) return SZW_STOP_DISABLED;
    if (st->ending) return SZW_STOP_ENDING;
    if (st->profile_changed) return SZW_STOP_PROFILE;
    if (!st->host_ok) return SZW_STOP_HOST;
    if (st->too_slow) return SZW_STOP_TOO_SLOW;
    if (st->suspended) return SZW_PAUSE_SUSPENDED;
    if (st->host_hung) return SZW_PAUSE_HUNG_HOST;
    if (st->screensaver) return SZW_PAUSE_SCREENSAVER;
    if (s->battery_pause && st->ac != 1) return SZW_PAUSE_BATTERY;
    if (s->fullscreen_pause && st->fullscreen) return SZW_PAUSE_FULLSCREEN;
    return SZW_RUN;
}

int szw_reason_is_stop(szw_reason r)
{
    return r == SZW_STOP_DISABLED || r == SZW_STOP_ENDING || r == SZW_STOP_PROFILE || r == SZW_STOP_HOST || r == SZW_STOP_TOO_SLOW;
}

const char *szw_reason_text(szw_reason r)
{
    switch (r) {
    case SZW_RUN: return "running";
    case SZW_STOP_DISABLED: return "disabled in HKCU settings";
    case SZW_STOP_ENDING: return "session ending";
    case SZW_STOP_PROFILE: return "logged-on user changed";
    case SZW_STOP_HOST: return "Explorer desktop list view unavailable (ActiveDesktop or no shared arena)";
    case SZW_STOP_TOO_SLOW: return "frame cost exceeds budget at 5 fps";
    case SZW_PAUSE_SUSPENDED: return "paused: suspend";
    case SZW_PAUSE_BATTERY: return "paused: battery or unknown power";
    case SZW_PAUSE_FULLSCREEN: return "paused: full-screen application";
    case SZW_PAUSE_SCREENSAVER: return "paused: screen saver active";
    case SZW_PAUSE_HUNG_HOST: return "paused: Explorer not responding";
    }
    return "unknown";
}

int szw_pacer_init(szw_pacer *p, uint32_t fps)
{
    if (!p || !(fps == 5 || fps == 10 || fps == 20)) return 0;
    p->fps = fps; p->interval = 1000u / fps; p->next_due = 0; p->frames = 0; p->dropped = 0;
    p->cost_sum = 0; p->cost_count = 0; p->started = 0; p->phase = 0;
    return 1;
}

int szw_pacer_tick(szw_pacer *p, uint32_t now, uint32_t *delay)
{
    int32_t early;
    if (!p || !delay || !p->interval) return 0;
    if (!p->started) { p->started = 1; p->next_due = now; }
    early = (int32_t)(p->next_due - now);
    if (early > 0) { *delay = (uint32_t)early; return 0; }
    if ((uint32_t)(-early) > 2u * p->interval) {
        uint32_t skipped = (uint32_t)(-early) / p->interval;
        p->dropped += skipped;
        p->phase += skipped * (20u / p->fps); /* time-based: no visual stall */
        p->next_due = now;
    }
    p->next_due += p->interval;
    p->frames++;
    p->phase += 20u / p->fps;
    early = (int32_t)(p->next_due - now);
    *delay = early > 0 ? (uint32_t)early : 1u;
    return 1;
}

int szw_pacer_cost(szw_pacer *p, uint32_t cost)
{
    uint32_t mean;
    if (!p || !p->interval) return 0;
    if (cost > 60000u) cost = 60000u;
    p->cost_sum += cost; p->cost_count++;
    if (p->cost_count < 16u) return 0;
    mean = p->cost_sum / p->cost_count;
    p->cost_sum = 0; p->cost_count = 0;
    if (mean * 10u <= p->interval * 6u) return 0;
    if (p->fps <= 5u) return -1;
    p->fps = p->fps == 20u ? 10u : 5u;
    p->interval = 1000u / p->fps;
    return 1;
}

uint32_t szw_phase(const szw_pacer *p)
{
    /* 20 phase steps per second at every rate, so a rate drop keeps the
     * same apparent speed. */
    return p ? p->phase : 0;
}

int szw_render_size(uint32_t sw, uint32_t sh, uint32_t *w, uint32_t *h)
{
    uint32_t rw, rh;
    if (!w || !h || sw < 2 || sh < 2 || sw > 16384 || sh > 16384) return 0;
    rw = sw / 2u; rh = sh / 2u;
    if (rw > SZW_MAX_RENDER_W) { rh = (uint32_t)((uint64_t)rh * SZW_MAX_RENDER_W / rw); rw = SZW_MAX_RENDER_W; }
    if (rh > SZW_MAX_RENDER_H) { rw = (uint32_t)((uint64_t)rw * SZW_MAX_RENDER_H / rh); rh = SZW_MAX_RENDER_H; }
    if (!rw || !rh) return 0;
    *w = rw; *h = rh;
    return 1;
}

int szw_frame(void *pixels, size_t bytes, uint32_t w, uint32_t h, uint32_t scene, uint32_t phase)
{
    if (!pixels || !w || !h || w > SZW_MAX_RENDER_W || h > SZW_MAX_RENDER_H) return 0;
    if ((size_t)w * 4u * h > bytes) return 0;
    return pz98_render(pixels, bytes, w, h, w * 4u, phase, scene);
}

uint32_t szw_clip_icons(const szw_rect *in, uint32_t count, int32_t cw, int32_t ch, int32_t pad,
                        szw_rect *out, uint32_t max)
{
    uint32_t i, n = 0;
    if (!in || !out || cw <= 0 || ch <= 0 || pad < 0 || pad > 64) return 0;
    if (count > SZW_MAX_ICONS) count = SZW_MAX_ICONS;
    for (i = 0; i < count && n < max; i++) {
        szw_rect r = in[i];
        if (r.left >= r.right || r.top >= r.bottom) continue;
        if (r.right <= 0 || r.bottom <= 0 || r.left >= cw || r.top >= ch) continue;
        r.left = r.left < pad ? 0 : r.left - pad;
        r.top = r.top < pad ? 0 : r.top - pad;
        r.right = r.right > cw - pad ? cw : r.right + pad;
        r.bottom = r.bottom > ch - pad ? ch : r.bottom + pad;
        out[n++] = r;
    }
    return n;
}
