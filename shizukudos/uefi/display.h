/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHIZUKUDOS_DISPLAY_H
#define SHIZUKUDOS_DISPLAY_H
#include "boot.h"
/* Draw the amber NTWDDMWrapper9x proof tile after ExitBootServices. */
int sd_ntwddm_demo(const SD_FRAMEBUFFER *framebuffer, void *arena, size_t arena_bytes);
#endif
