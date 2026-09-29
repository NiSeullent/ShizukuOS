/* SPDX-License-Identifier: GPL-2.0-only */
#include "shutdown.h"
static uint32_t shutdown_level = 0x280u;
static uint32_t shutdown_flags;
int ntw_shutdown_set(uint32_t level, uint32_t flags, uint32_t *error) {
    if (!error) return 0;
    if (flags & ~1u || level > 0x4ffu) { *error = 87; return 0; }
    shutdown_level = level;
    shutdown_flags = flags;
    *error = 0;
    return 1;
}
int ntw_shutdown_get(uint32_t *level, uint32_t *flags, uint32_t *error) {
    if (!error || !level || !flags) { if (error) *error = 87; return 0; }
    *level = shutdown_level;
    *flags = shutdown_flags;
    *error = 0;
    return 1;
}
