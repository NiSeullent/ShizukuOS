/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PZ98_PROFILE_H
#define PZ98_PROFILE_H
#include <windows.h>
typedef struct pz98_paths {
    char preferences[MAX_PATH], bitmap[MAX_PATH], html[MAX_PATH];
} pz98_paths;
/* Resolve the current Windows shell profile. Never fall back to a shared
 * executable directory. Output is unchanged if any lookup or check fails. */
int pz98_profile_paths(pz98_paths *);
#endif
