/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_SETUP_INTERACTIVE_CHOICE_H
#define SHZ_SETUP_INTERACTIVE_CHOICE_H
#include "plat.h"

/* Review and answer generation never read, write, format or flush a disk.
 * The installer core performs its complete payload/layout checks afterwards. */
int setup_review_target(const plat_t *p, unsigned index, plat_disk_t *target);
int setup_build_interactive_answer(const plat_disk_t *target, const char *confirmation,
                                   int reserve_win98, char *answer, size_t capacity);
#endif
