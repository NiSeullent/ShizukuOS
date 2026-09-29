/* SPDX-License-Identifier: GPL-2.0-only
 * Built-in style text. Bytes match theme/classic.ntth and theme/modern.ntth.
 */
#include "nttheme.h"

const char ntth_builtin_classic_text[] =
    "name Classic\n"
    "class BUTTON\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 808080 filltype solid fillcolor C0C0C0 textcolor 000000\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor 000080 filltype solid fillcolor D4D0C8 textcolor 000000\n"
    "part 1 state 3 bgtype borderfill bordersize 1 bordercolor 000000 filltype solid fillcolor A0A0A0 textcolor 000000\n"
    "part 1 state 4 bgtype borderfill bordersize 1 bordercolor 808080 filltype solid fillcolor C0C0C0 textcolor 808080\n"
    "class WINDOW\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 000040 filltype solid fillcolor 000080 textcolor FFFFFF\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor 404040 filltype solid fillcolor 808080 textcolor C0C0C0\n"
    "part 7 state 1 bgtype borderfill bordersize 1 bordercolor 808080 filltype solid fillcolor C0C0C0 textcolor 000000\n"
    "part 8 state 1 bgtype borderfill bordersize 1 bordercolor 808080 filltype solid fillcolor C0C0C0 textcolor 000000\n"
    "part 9 state 1 bgtype borderfill bordersize 1 bordercolor 808080 filltype solid fillcolor C0C0C0 textcolor 000000\n";

const char ntth_builtin_modern_text[] =
    "name Modern\n"
    "class BUTTON\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 0078D7 filltype solid fillcolor F0F0F0 textcolor 000000\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor 0078D7 filltype solid fillcolor E5F1FB textcolor 000000\n"
    "part 1 state 3 bgtype borderfill bordersize 1 bordercolor 005A9E filltype solid fillcolor CCE4F7 textcolor 000000\n"
    "part 1 state 4 bgtype borderfill bordersize 1 bordercolor C8C8C8 filltype solid fillcolor F0F0F0 textcolor A0A0A0\n"
    "class WINDOW\n"
    "part 1 state 1 bgtype borderfill bordersize 1 bordercolor 004578 filltype horzgradient fillcolor 0078D7 gradient1 0078D7 gradient2 005A9E textcolor FFFFFF\n"
    "part 1 state 2 bgtype borderfill bordersize 1 bordercolor 666666 filltype solid fillcolor CCCCCC textcolor 333333\n"
    "part 7 state 1 bgtype borderfill bordersize 1 bordercolor A0A0A0 filltype solid fillcolor F0F0F0 textcolor 000000\n"
    "part 8 state 1 bgtype borderfill bordersize 1 bordercolor A0A0A0 filltype solid fillcolor F0F0F0 textcolor 000000\n"
    "part 9 state 1 bgtype borderfill bordersize 1 bordercolor A0A0A0 filltype solid fillcolor F0F0F0 textcolor 000000\n";

const size_t ntth_builtin_classic_length = sizeof(ntth_builtin_classic_text) - 1u;
const size_t ntth_builtin_modern_length = sizeof(ntth_builtin_modern_text) - 1u;
