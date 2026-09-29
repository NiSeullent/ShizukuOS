/* SPDX-License-Identifier: GPL-2.0-only
 * The standard arrow pointer (our own artwork), ONE definition shared by user32 (IDC_ARROW, user32_icon.c), the kernel
 * (the pointer drawn where no window has set a cursor, gfx_input.c) and the host-side GUI test runner (tests/run_k64_gui.py
 * reads this file as the specification of the sprite). 'X' = black, '.' = white, ' ' = transparent; the hot spot is (0,0).
 */
#ifndef SHZ_POINTER_H
#define SHZ_POINTER_H
#define SHZ_ARROW_W 12
#define SHZ_ARROW_H 19
static const char *const shz_arrow_art[SHZ_ARROW_H] = {
    "X           ",
    "XX          ",
    "X.X         ",
    "X..X        ",
    "X...X       ",
    "X....X      ",
    "X.....X     ",
    "X......X    ",
    "X.......X   ",
    "X........X  ",
    "X.....XXXXX ",
    "X..X..X     ",
    "X.X X..X    ",
    "XX  X..X    ",
    "X    X..X   ",
    "     X..X   ",
    "      X..X  ",
    "      X..X  ",
    "       XX   ",
};
#endif
