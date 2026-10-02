/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_WIN98_THEME_SELECTOR_CORE_H
#define SHZ_WIN98_THEME_SELECTOR_CORE_H
#include <stddef.h>
#include <stdint.h>

/* The legacy USER32 indices 0..24. Reserved 25 and newer indices are excluded. */
#define SHZ_THEME_COLORS 25u
#define SHZ_THEME_PROFILE_HEADER_BYTES 24u
#define SHZ_THEME_PROFILE_BYTES (SHZ_THEME_PROFILE_HEADER_BYTES + SHZ_THEME_COLORS * 8u)
#define SHZ_THEME_VALUE_BYTES 512u
#define SHZ_THEME_CLASSIC 0u
#define SHZ_THEME_SHIZUKUOS 1u
#define SHZ_THEME_REG_SZ 1u
#define SHZ_THEME_REG_EXPAND_SZ 2u
#define SHZ_THEME_REG_BINARY 3u
#define SHZ_THEME_PROFILE_VALUE 0u
#define SHZ_THEME_RUN_VALUE 1u
#define SHZ_THEME_ROLLBACK_COLORS 1u
#define SHZ_THEME_ROLLBACK_PROFILE 2u
#define SHZ_THEME_ROLLBACK_RUN 4u

typedef struct shz_theme_profile {
    uint32_t style;
    uint32_t baseline[SHZ_THEME_COLORS];
    uint32_t selected[SHZ_THEME_COLORS];
} shz_theme_profile;

typedef struct shz_theme_value {
    unsigned present;
    uint32_t type;
    uint32_t bytes;
    unsigned char data[SHZ_THEME_VALUE_BYTES];
} shz_theme_value;

enum shz_theme_phase {
    SHZ_THEME_PHASE_NONE, SHZ_THEME_PHASE_ARGUMENT,
    SHZ_THEME_PHASE_PROFILE_SNAPSHOT, SHZ_THEME_PHASE_PROFILE_INVALID,
    SHZ_THEME_PHASE_RUN_SNAPSHOT, SHZ_THEME_PHASE_RUN_INVALID,
    SHZ_THEME_PHASE_COLORS_SNAPSHOT, SHZ_THEME_PHASE_COLORS_APPLY,
    SHZ_THEME_PHASE_COLORS_READBACK, SHZ_THEME_PHASE_PROFILE_WRITE,
    SHZ_THEME_PHASE_PROFILE_FLUSH, SHZ_THEME_PHASE_PROFILE_READBACK,
    SHZ_THEME_PHASE_RUN_WRITE, SHZ_THEME_PHASE_RUN_FLUSH,
    SHZ_THEME_PHASE_RUN_READBACK
};
enum shz_theme_status {
    SHZ_THEME_OK, SHZ_THEME_FAILED, SHZ_THEME_ROLLBACK_FAILED
};
typedef struct shz_theme_result {
    enum shz_theme_status status;
    enum shz_theme_phase phase;
    uint32_t error, rollback_error;
    unsigned rollback_failed, rollback_attempted;
    unsigned colors_attempted, profile_attempted, run_attempted;
    uint32_t saved_style;
} shz_theme_result;

/* Callbacks represent real OS side effects; false may still mean partial writes.
 * read_value must return the complete bounded value, never a truncated prefix.
 * write_value with present=0 deletes only the selected value, not its key.
 * Callers serialize transactions; no callbacks run inside a loader lock. */
typedef struct shz_theme_ops {
    void *context;
    int (*get_colors)(void *, uint32_t[SHZ_THEME_COLORS], uint32_t *);
    int (*set_colors)(void *, const uint32_t[SHZ_THEME_COLORS], uint32_t *);
    int (*read_value)(void *, unsigned, shz_theme_value *, uint32_t *);
    int (*write_value)(void *, unsigned, const shz_theme_value *, uint32_t *);
    int (*flush_value)(void *, unsigned, uint32_t *);
} shz_theme_ops;

int shz_theme_make(uint32_t, const uint32_t *, shz_theme_profile *);
int shz_theme_encode(const shz_theme_profile *, unsigned char *);
int shz_theme_decode(const unsigned char *, size_t, shz_theme_profile *);
int shz_theme_startup_value(const char *, size_t, shz_theme_value *);
/* 0=no-argument UI, 1=exact /restore, -1=invalid. Length excludes the NUL. */
int shz_theme_command_mode(const char *, size_t);
int shz_theme_apply(const shz_theme_ops *, const uint32_t *,
                    uint32_t, const shz_theme_value *, shz_theme_result *);
int shz_theme_restore(const shz_theme_ops *, shz_theme_result *);
#endif
