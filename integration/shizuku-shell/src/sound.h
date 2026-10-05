/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SHZ_SHELL_SOUND_H
#define SHZ_SHELL_SOUND_H
#include "theme.h"
enum SHZ_SOUND_EVENT { SHZ_SOUND_STARTUP, SHZ_SOUND_NOTIFICATION, SHZ_SOUND_ERROR, SHZ_SOUND_THEME };
/* Policy: 1=validated configured reference, 0=disabled/muted/no event, -1=unsupported volume, -2=unsupported ref/event.
 * No provider functions or OS calls in policy; shared exact implementation for controls and native consumer. */
int ShzSoundPolicy(const SHZ_THEME *theme, enum SHZ_SOUND_EVENT event, const char **reference);
void ShzSoundStartup(void);
void ShzSoundEvent(enum SHZ_SOUND_EVENT event);
void ShzSoundShutdown(void);
#endif
