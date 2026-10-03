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
    uint32_t guard_head;     /* DS_GUARD_HEAD; overwritten guard => no game */
    ds_fault fault;
    ds_tetris tetris;
    ds_suika suika;
    uint32_t rng, ticks;
    unsigned latched, korean, mode, show_trace, graphics_failed;
    unsigned prefix, pause_bytes; /* bounded set-1 keyboard decoder */
    unsigned games_evaluated, games_allowed, unsafe; /* one-shot panic-time admission */
    uint32_t guard_tail;     /* DS_GUARD_TAIL */
} ds_state;

/* Panic-time game admission. Games run only in the caller-proven context below;
 * any unknown or unsafe fact refuses them while the stacked-error visual and
 * traceback remain available. Bits are reported, never silently ignored. */
#define DS_GUARD_HEAD 0x5a48535au
#define DS_GUARD_TAIL 0x44454144u
#define DS_GAME_STACK_MIN 8192u
enum ds_unsafe_bits {
    DS_UNSAFE_NOT_LATCHED = 1u << 0, /* no immutable first record */
    DS_UNSAFE_STATE       = 1u << 1, /* static state guard/invariant broken */
    DS_UNSAFE_NO_CONTEXT  = 1u << 2, /* caller supplied no proven context */
    DS_UNSAFE_INTERRUPTS  = 1u << 3, /* IF still set: re-entrancy possible */
    DS_UNSAFE_VECTOR      = 1u << 4, /* NMI(2)/#DF(8)/#MC(18): IST, machine state */
    DS_UNSAFE_STACK       = 1u << 5, /* SP outside a known stack or < headroom */
    DS_UNSAFE_SMP         = 1u << 6, /* another CPU was started; no takeover */
    DS_UNSAFE_RECURSION   = 1u << 7, /* already inside a fallback/second fault */
    DS_UNSAFE_GRAPHICS    = 1u << 8  /* renderer already failed */
};
typedef struct {
    uint64_t flags;                 /* RFLAGS sampled after CLI in the fatal path */
    uint64_t sp, stack_low, stack_high; /* current SP and the known stack holding it */
    unsigned secondary_cpus_started;
    unsigned fault_depth;           /* 0 on the first fatal entry */
    unsigned proven;                /* 1 only when every field above was measured */
} ds_context;
/* Pure predicate: 0 means safe; otherwise DS_UNSAFE_* bits. No side effects. */
unsigned ds_game_safety(const ds_state *s, const ds_context *c);
/* One-shot monotonic admission; a later call can only refuse, never re-enable.
 * Returns the unsafe bits recorded in s->unsafe (0 => games offered). */
unsigned ds_admit_games(ds_state *s, const ds_context *c);

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
/* Exact fallback first line, then English real-record traceback. Writer failure
 * propagates; caller must not announce success or resume the halted kernel. */
int ds_fallback(const ds_state *s, ds_write_fn writer, void *context);
/* Actual game routines are exported for closed host controls, not a user API. */
int ds_tetris_fits(const ds_tetris *t, unsigned piece, unsigned rotation, int x, int y);
unsigned ds_tetris_clear(ds_tetris *t);
void ds_suika_step(ds_suika *u);
#endif
