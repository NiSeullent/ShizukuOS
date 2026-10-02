/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PZ98_CORE_H
#define PZ98_CORE_H
#include <stddef.h>
#include <stdint.h>
#define PZ98_RECORD_BYTES 16u
#define PZ98_HTML_BYTES 4096u
#define PZ98_MAX_BYTES (8u * 1024u * 1024u)
typedef struct pz98_preferences {
    unsigned scene, fps, language, paused, battery_saver;
} pz98_preferences;
void pz98_defaults(pz98_preferences *);
int pz98_valid(const pz98_preferences *);
int pz98_encode(const pz98_preferences *, unsigned char *, size_t);
int pz98_decode(const unsigned char *, size_t, pz98_preferences *);
/* AC: 1 on-line, 0 battery, -1 unknown. No animation when suspended/hidden. */
unsigned pz98_interval(const pz98_preferences *, int ac, int suspended, int visible);
/* XRGB8888 rows, max 1920x1080 and 8 MiB; invalid requests write nothing. */
int pz98_render(void *, size_t, unsigned, unsigned, unsigned, uint32_t, unsigned);
/* Offline IE4-compatible HTML, finite 300-second timer, explicit Pause button. */
int pz98_html(const pz98_preferences *, char *, size_t);
#endif
