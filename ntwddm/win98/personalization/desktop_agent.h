/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku desktop wallpaper agent (SHZWALL.EXE) platform-independent core.
 * Pure policy, frame pacing and settings validation; no Win32 calls here.
 * The native agent paints procedural frames into Explorer's own desktop
 * list view with icon rectangles excluded. Explorer keeps ownership of icons,
 * the taskbar and the static wallpaper, which is the fallback on any stop.
 */
#ifndef SZW_DESKTOP_AGENT_H
#define SZW_DESKTOP_AGENT_H
#include <stddef.h>
#include <stdint.h>

#define SZW_SETTINGS_KEY "Software\\ShizukuOS\\Personalization\\DesktopWallpaper"
#define SZW_RUN_KEY "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define SZW_RUN_VALUE "ShizukuOSWallpaper"
#define SZW_MAX_RENDER_W 960u
#define SZW_MAX_RENDER_H 540u
#define SZW_MAX_ICONS 256u

typedef struct szw_settings {
    uint32_t enabled, scene, fps, battery_pause, fullscreen_pause;
} szw_settings;

/* Registry value table order; mask bit i set when value i was present. */
enum { SZW_V_ENABLED, SZW_V_SCENE, SZW_V_FPS, SZW_V_BATTERY, SZW_V_FULLSCREEN, SZW_V_COUNT };
extern const char *const szw_value_names[SZW_V_COUNT];

void szw_defaults(szw_settings *);
int szw_valid(const szw_settings *);
/* Missing values take defaults. Any present invalid value rejects the whole
 * record (return 0, *out unchanged) so a corrupt setting never half-applies. */
int szw_settings_from_values(uint32_t present_mask, const uint32_t values[SZW_V_COUNT], szw_settings *out);
void szw_settings_to_values(const szw_settings *, uint32_t values[SZW_V_COUNT]);

typedef enum szw_reason {
    SZW_RUN = 0,
    SZW_STOP_DISABLED,
    SZW_STOP_ENDING,          /* WM_ENDSESSION / shutdown / logoff */
    SZW_STOP_HOST,            /* Explorer desktop list view absent, ActiveDesktop host or no shared arena */
    SZW_STOP_TOO_SLOW,        /* frame cost exceeded budget even at the minimum rate */
    SZW_STOP_PROFILE,         /* logged-on user changed: this agent belongs to another profile */
    SZW_PAUSE_SUSPENDED,
    SZW_PAUSE_BATTERY,
    SZW_PAUSE_FULLSCREEN,
    SZW_PAUSE_SCREENSAVER,    /* Win98 has no WTS sessions; screen saver = inactive session */
    SZW_PAUSE_HUNG_HOST       /* Explorer did not answer within the timeout */
} szw_reason;

typedef struct szw_state {
    int ac;            /* 1 on-line, 0 battery, -1 unknown */
    int suspended, fullscreen, screensaver, ending, host_ok, host_hung, too_slow, profile_changed;
} szw_state;

/* 8 lowercase hex chars, FNV-1a of the case-folded user name (NULL/empty allowed).
 * Used for the per-user instance mutex and window title so agents of different
 * users never share or signal each other. out needs 9 bytes. */
void szw_user_tag(const char *user, char out[9]);

szw_reason szw_decide(const szw_settings *, const szw_state *);
/* Stop reasons terminate the agent; pause reasons keep it idle and resumable. */
int szw_reason_is_stop(szw_reason);
const char *szw_reason_text(szw_reason);

/* Wraparound-safe frame pacer driven by a 32-bit millisecond tick. */
typedef struct szw_pacer {
    uint32_t interval, next_due, frames, dropped, cost_sum, cost_count, fps, phase;
    int started;
} szw_pacer;
int szw_pacer_init(szw_pacer *, uint32_t fps);
/* Returns 1 when a frame should be produced at now; *delay receives the
 * timer delay until the next check (>=1 ms). Late by more than two intervals
 * re-anchors at now and counts skipped frames without a catch-up burst. */
int szw_pacer_tick(szw_pacer *, uint32_t now, uint32_t *delay);
/* Record frame cost. Every 16 frames, if the mean cost exceeds 60% of the
 * interval, halve the rate down to 5 fps; returns -1 when even 5 fps is too
 * slow, 1 when the rate changed, 0 otherwise. */
int szw_pacer_cost(szw_pacer *, uint32_t cost_ms);
uint32_t szw_phase(const szw_pacer *);

/* Half-resolution render target inside SZW_MAX_RENDER_*; 0 on invalid input. */
int szw_render_size(uint32_t screen_w, uint32_t screen_h, uint32_t *w, uint32_t *h);
/* Deterministic frame into XRGB8888 (pitch = w*4) via the personalization
 * procedural generator. Returns 0 and writes nothing on invalid input. */
int szw_frame(void *pixels, size_t bytes, uint32_t w, uint32_t h, uint32_t scene, uint32_t phase);
/* Clip-exclusion validation for icon rectangles reported cross-process:
 * clamps to the client area, drops empty/inverted ones, inflates by pad.
 * Returns the number of usable rectangles written to out (<= max). */
typedef struct szw_rect { int32_t left, top, right, bottom; } szw_rect;
uint32_t szw_clip_icons(const szw_rect *in, uint32_t count, int32_t client_w, int32_t client_h,
                        int32_t pad, szw_rect *out, uint32_t max);
#endif
