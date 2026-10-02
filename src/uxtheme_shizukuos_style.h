/* SPDX-License-Identifier: GPL-2.0-only
 * Parsed ShizukuOS userland palette. Text matches uxtheme_shizukuos.ntth.
 * Existing Classic/Modern resources and their numeric selectors stay intact.
 */
#ifndef M98_UXTHEME_SHIZUKUOS_STYLE_H
#define M98_UXTHEME_SHIZUKUOS_STYLE_H
#include <stddef.h>

static const char m98_shizukuos_style_text[] =
    "name ShizukuOS\n"
    "class BUTTON\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 3D7890 filltype solid fillcolor EDF5F9 textcolor 12283B\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor 40A5C5 filltype solid fillcolor DCEFF7 textcolor 12283B\n"
    "part 1 state 3 bgtype borderfill bordersize 1 bordercolor 0E6680 filltype solid fillcolor BEDFEA textcolor 12283B\n"
    "part 1 state 4 bgtype borderfill bordersize 1 bordercolor A6B6C3 filltype solid fillcolor E8EEF2 textcolor 526575\n"
    "class WINDOW\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 102A43 filltype horzgradient fillcolor 102A43 gradient1 102A43 gradient2 167C9C textcolor FFFFFF\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor A6B6C3 filltype solid fillcolor E8EEF2 textcolor 526575\n"
    "part 7 state 1 bgtype borderfill bordersize 1 bordercolor 3D7890 filltype solid fillcolor F5F9FC textcolor 12283B\n"
    "part 8 state 1 bgtype borderfill bordersize 1 bordercolor 3D7890 filltype solid fillcolor F5F9FC textcolor 12283B\n"
    "part 9 state 1 bgtype borderfill bordersize 1 bordercolor 3D7890 filltype solid fillcolor F5F9FC textcolor 12283B\n";

static const size_t m98_shizukuos_style_length = sizeof(m98_shizukuos_style_text) - 1u;
#endif
