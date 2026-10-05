/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_DEAD_SCREEN_H
#define SHZ_DEAD_SCREEN_H
#include <stddef.h>
#include <stdint.h>

/* Caller classifies an error; this module never decides whether a Win98/VMM fault
 * is recoverable. Only a fatal Shizuku-kernel caller may latch this state. */
enum ds_severity { DS_RECOVERABLE = 0, DS_KERNEL_FATAL = 1 };
enum ds_mode { DS_MENU = 0, DS_TETRIS = 1, DS_SUIKA = 2 };
enum ds_key { DS_NONE, DS_ONE, DS_TWO, DS_LEFT, DS_RIGHT, DS_UP, DS_DOWN,
              DS_DROP, DS_ESCAPE, DS_RESTART, DS_LANGUAGE, DS_TRACE };
enum ds_fatal_audio { DS_AUDIO_SILENT, DS_AUDIO_PCM, DS_AUDIO_PITCHED, DS_AUDIO_FIXED };
#define DS_REGS 16u
#define DS_FRAMES 8u
#define DS_BALLS 32u
#define DS_REASON 160u

typedef struct {
    uint64_t ip, sp, bp, flags, vector, error, cr2, cr3;
    uint64_t reg[DS_REGS]; /* AX BX CX DX SI DI BP R8 R9 R10 R11 R12 R13 R14 R15 CS */
    uint64_t frames[DS_FRAMES];
    unsigned frame_count;
    unsigned registers_valid; /* 0: caller IP/SP/BP only; 1: real interrupt frame */
    uint32_t cpu, pid, tid, context_valid; /* pre-captured at a safe scheduler boundary */
    char reason[DS_REASON];   /* counted/truncated trusted kernel metadata, copied at latch */
} ds_fault;

typedef struct {
    volatile uint32_t *pixels; /* already mapped, retained writable storage */
    uint32_t width, height, pitch_words;
    size_t span_words;
    unsigned rgbx;            /* 0 BGRX, 1 RGBX, no other formats */
} ds_surface;
typedef struct {
    uint8_t board[20][10];
    int x, y;
    unsigned piece, rotation, fall, lines, score, over;
} ds_tetris;
typedef struct {
    int32_t x, y, vx, vy; /* Q8, always bounded by the solver */
    uint8_t used, level;
    uint16_t ceiling_ticks;
} ds_ball;
typedef struct {
    ds_ball ball[DS_BALLS];
    int aim;
    unsigned next, cooldown, score, over;
} ds_suika;
typedef struct {
    ds_fault fault;
    ds_tetris tetris;
    ds_suika suika;
    uint32_t rng, ticks;
    unsigned latched, korean, mode, show_trace, graphics_failed;
    unsigned prefix, pause_bytes; /* bounded set-1 keyboard decoder */
} ds_state;

typedef int (*ds_write_fn)(void *context, const char *bytes, size_t count);
void ds_init(ds_state *s);
/* 0 recoverable: state untouched, caller must use its ordinary dialog/error path.
 * 1 first fatal latched; -1 recursive fatal (first record remains immutable).
 * All pointers must be trusted, mapped inputs. No allocation, probing or unwind. */
int ds_latch(ds_state *s, enum ds_severity severity, const ds_fault *record);
void ds_key_event(ds_state *s, enum ds_key key);
void ds_tick(ds_state *s); /* one bounded simulation step; no scheduler calls */
enum ds_key ds_scan1(ds_state *s, uint8_t byte);
enum ds_key ds_serial_key(uint8_t byte);
int ds_surface_valid(const ds_surface *surface);
int ds_surface_storage_valid(const ds_surface *surface);
int ds_render(ds_state *s, const ds_surface *surface);
/* Independent minimal ASCII path; uses only retained storage and first record.
 * -1 means unavailable/truncated, while serial fallback may still be complete. */
int ds_fallback_framebuffer(const ds_state *s, const ds_surface *surface);
int ds_nyan_framebuffer(const ds_state *, const ds_surface *, enum ds_fatal_audio);
enum ds_fatal_audio ds_nyan_audio_select(unsigned pcm_progress, unsigned pitch_control, unsigned fixed_gate);
const char *ds_nyan_audio_name(enum ds_fatal_audio);
/* Exact fallback first line, then English real-record traceback. Writer failure
 * propagates; caller must not announce success or resume the halted kernel. */
int ds_fallback(const ds_state *s, ds_write_fn writer, void *context);
/* Actual game routines are exported for closed host controls, not a user API. */
int ds_tetris_fits(const ds_tetris *t, unsigned piece, unsigned rotation, int x, int y);
unsigned ds_tetris_clear(ds_tetris *t);
void ds_suika_step(ds_suika *u);
#endif
