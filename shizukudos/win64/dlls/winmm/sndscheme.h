/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS sound-event scheme: pure name/path policy for PlaySound(SND_ALIAS). No OS calls, no allocation, UTF-16 code units
 * as uint16_t so it is host-testable.
 *
 * Scheme data is %WINDIR%\SHZSOUND.INI, section [Events], key = event alias, value = WAV path (absolute "X:\..." / "\..."
 * or relative to %WINDIR%\MEDIA) or "-" for an event the user muted. Without an INI entry the built-in event->file-name
 * table below names a file in %WINDIR%\MEDIA. No audio data lives in this DLL; if the file is absent PlaySound fails closed
 * (FALSE, no substitute sound). The default file names refer to installer-provided assets whose rights are not verified here.
 */
#ifndef SHZ_SNDSCHEME_H
#define SHZ_SNDSCHEME_H
#include <stdint.h>
#include <stddef.h>
#define SHZ_SCHEME_ALIAS_MAX 63u
enum { SHZ_SCHEME_OK = 0, SHZ_SCHEME_E_ALIAS, SHZ_SCHEME_E_MUTED, SHZ_SCHEME_E_NONE, SHZ_SCHEME_E_PATH, SHZ_SCHEME_E_SPACE };

/* 1 if alias is 1..63 chars of [A-Za-z0-9._-] (a single interior space is not allowed); never reads past the NUL. */
int shz_scheme_alias_valid(const uint16_t *alias);
/* Built-in file name (ASCII, no directory) for a case-insensitive event alias, or NULL. */
const char *shz_scheme_default_file(const uint16_t *alias);
/* Builds the final path into out[cap] from the INI value (NULL/empty = not configured), the alias and windir (no trailing
 * backslash required). Returns SHZ_SCHEME_OK, _MUTED ("-"), _NONE (no mapping at all), _PATH (relative value with ".." or ':'
 * or a separator-only/odd value) or _SPACE (does not fit). out is always NUL terminated when cap > 0. */
int shz_scheme_resolve(const uint16_t *alias, const uint16_t *ini_value, const uint16_t *windir, uint16_t *out, size_t cap);
#endif
