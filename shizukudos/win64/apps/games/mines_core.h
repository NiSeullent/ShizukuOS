/* SPDX-License-Identifier: GPL-2.0-only
 * Minesweeper-style game state: pure logic, no Win32. Original ShizukuOS code. */
#ifndef SHZ_MINES_CORE_H
#define SHZ_MINES_CORE_H
#include <stdint.h>
#include <string.h>
#define MN_MAXW 24
#define MN_MAXH 24
#define MN_CELL 24
#define MN_ORGX 8
#define MN_ORGY 40
enum { MN_PLAY, MN_WON, MN_LOST };
enum { MN_F_MINE = 1, MN_F_OPEN = 2, MN_F_FLAG = 4 };
typedef struct { int w, h, mines, state, placed, opened; uint64_t rng; uint8_t f[MN_MAXH][MN_MAXW], n[MN_MAXH][MN_MAXW]; } mn_game;
static inline uint32_t mn_rand(mn_game *g) { uint64_t x = g->rng; x ^= x << 13; x ^= x >> 7; x ^= x << 17; g->rng = x; return (uint32_t)(x >> 32); }
/* Rejects out-of-range geometry; at least 9 safe cells remain so the first click can clear its neighbourhood. */
static inline int mn_init(mn_game *g, int w, int h, int mines, uint64_t seed) {
 if (w < 2 || h < 2 || w > MN_MAXW || h > MN_MAXH || mines < 1 || mines > w * h - 9) return -1;
 memset(g, 0, sizeof *g); g->w = w; g->h = h; g->mines = mines; g->rng = seed ? seed : 0x9E3779B97F4A7C15ull; return 0;
}
static inline int mn_in(const mn_game *g, int x, int y) { return x >= 0 && y >= 0 && x < g->w && y < g->h; }
/* Pixel to cell; returns 0 and leaves outputs untouched when outside the grid. */
static inline int mn_hit(const mn_game *g, int px, int py, int *cx, int *cy) {
 int x, y; if (px < MN_ORGX || py < MN_ORGY) return 0;
 x = (px - MN_ORGX) / MN_CELL; y = (py - MN_ORGY) / MN_CELL; if (!mn_in(g, x, y)) return 0; *cx = x; *cy = y; return 1;
}
static inline void mn_place(mn_game *g, int sx, int sy) {
 int left = g->mines, x, y, dx, dy;
 while (left) {
  x = (int)(mn_rand(g) % (uint32_t)g->w); y = (int)(mn_rand(g) % (uint32_t)g->h);
  if ((x >= sx - 1 && x <= sx + 1 && y >= sy - 1 && y <= sy + 1) || (g->f[y][x] & MN_F_MINE)) continue;
  g->f[y][x] |= MN_F_MINE; left--;
 }
 for (y = 0; y < g->h; y++) for (x = 0; x < g->w; x++) { int c = 0;
  for (dy = -1; dy <= 1; dy++) for (dx = -1; dx <= 1; dx++) if ((dx || dy) && mn_in(g, x + dx, y + dy) && (g->f[y + dy][x + dx] & MN_F_MINE)) c++;
  g->n[y][x] = (uint8_t)c; }
 g->placed = 1;
}
static inline void mn_check_win(mn_game *g) { if (g->state == MN_PLAY && g->opened == g->w * g->h - g->mines) g->state = MN_WON; }
/* Iterative flood (explicit bounded stack) so a large empty area cannot overflow the process stack. */
static inline void mn_open(mn_game *g, int x, int y) {
 static uint16_t st[MN_MAXW * MN_MAXH]; /* each cell is pushed at most once (marked open first) */ int sp = 0, dx, dy;
 if (g->state != MN_PLAY || !mn_in(g, x, y) || (g->f[y][x] & (MN_F_OPEN | MN_F_FLAG))) return;
 if (!g->placed) mn_place(g, x, y);
 if (g->f[y][x] & MN_F_MINE) { g->f[y][x] |= MN_F_OPEN; g->state = MN_LOST; return; }
 g->f[y][x] |= MN_F_OPEN; g->opened++; st[sp++] = (uint16_t)(y * MN_MAXW + x);
 while (sp) { int p = st[--sp], cx = p % MN_MAXW, cy = p / MN_MAXW;
  if (g->n[cy][cx]) continue;
  for (dy = -1; dy <= 1; dy++) for (dx = -1; dx <= 1; dx++) { int nx = cx + dx, ny = cy + dy;
   if (!mn_in(g, nx, ny) || (g->f[ny][nx] & (MN_F_OPEN | MN_F_FLAG | MN_F_MINE))) continue;
   g->f[ny][nx] |= MN_F_OPEN; g->opened++;
   st[sp++] = (uint16_t)(ny * MN_MAXW + nx); } }
 mn_check_win(g);
}
static inline void mn_flag(mn_game *g, int x, int y) { if (g->state == MN_PLAY && mn_in(g, x, y) && !(g->f[y][x] & MN_F_OPEN)) g->f[y][x] ^= MN_F_FLAG; }
static inline int mn_flags_left(const mn_game *g) { int x, y, c = 0; for (y = 0; y < g->h; y++) for (x = 0; x < g->w; x++) c += (g->f[y][x] & MN_F_FLAG) != 0; return g->mines - c; }
#endif
