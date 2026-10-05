/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuOS Mines: native GDI game. Left click opens, right click flags, F2 or the face restarts with a fresh seed.
 * Seed comes from NtShzRandom (shz_random_bytes); if that is refused the tick count is used and the title says so.
 */
#include <windows.h>
#include "shz_rand.h"
#include "mines_core.h"
#include <stdio.h>
static mn_game game; static int seed_kernel; static HWND wnd;
static void new_game(void) {
 uint64_t s = 0; seed_kernel = shz_random_bytes(&s, sizeof s) != 0 && s; /* shz_rand.h: 1 = success, 0 = failure */
 if (!seed_kernel) s = ((uint64_t)GetTickCount() << 32) ^ GetTickCount() ^ 0xA5A5A5A5u;
 mn_init(&game, 9, 9, 10, s);
 if (wnd) { SetWindowTextW(wnd, seed_kernel ? L"Shizuku Mines" : L"Shizuku Mines (weak seed)"); InvalidateRect(wnd, 0, TRUE); }
}
static const COLORREF numc[9] = { 0, 0xFF0000, 0x008000, 0x0000FF, 0x800000, 0x000080, 0x808000, 0, 0x808080 };
static LRESULT CALLBACK proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
 int cx, cy;
 if (m == WM_LBUTTONUP || m == WM_RBUTTONUP) {
  int x = (short)LOWORD(lp), y = (short)HIWORD(lp);
  if (x >= 100 && x < 124 && y >= 8 && y < 32) { new_game(); return 0; }
  if (mn_hit(&game, x, y, &cx, &cy)) { if (m == WM_LBUTTONUP) mn_open(&game, cx, cy); else mn_flag(&game, cx, cy); InvalidateRect(w, 0, FALSE); }
  return 0;
 }
 if (m == WM_KEYDOWN && wp == VK_F2) { new_game(); return 0; }
 if (m == WM_PAINT) {
  PAINTSTRUCT ps; HDC dc = BeginPaint(w, &ps); int x, y; WCHAR t[32]; RECT r;
  if (!dc) return 0;
  SetBkMode(dc, TRANSPARENT);
  wsprintfW(t, L"Mines %d", mn_flags_left(&game)); r = (RECT){ 8, 8, 96, 32 }; DrawTextW(dc, t, -1, &r, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
  r = (RECT){ 100, 8, 124, 32 }; Rectangle(dc, r.left, r.top, r.right, r.bottom);
  DrawTextW(dc, game.state == MN_WON ? L":D" : game.state == MN_LOST ? L"X(" : L":)", -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  for (y = 0; y < game.h; y++) for (x = 0; x < game.w; x++) {
   uint8_t f = game.f[y][x]; int show = (f & MN_F_OPEN) || (game.state == MN_LOST && (f & MN_F_MINE));
   r = (RECT){ MN_ORGX + x * MN_CELL, MN_ORGY + y * MN_CELL, MN_ORGX + (x + 1) * MN_CELL, MN_ORGY + (y + 1) * MN_CELL };
   Rectangle(dc, r.left, r.top, r.right, r.bottom);
   if (show && (f & MN_F_MINE)) DrawTextW(dc, L"*", -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
   else if (show && game.n[y][x]) { t[0] = (WCHAR)(L'0' + game.n[y][x]); t[1] = 0; SetTextColor(dc, numc[game.n[y][x]]); DrawTextW(dc, t, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE); SetTextColor(dc, 0); }
   else if (!show && (f & MN_F_FLAG)) DrawTextW(dc, L"F", -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
  }
  EndPaint(w, &ps); return 0;
 }
 if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
 return DefWindowProcW(w, m, wp, lp);
}
int main(void) {
 WNDCLASSW c = { 0 }; MSG msg;
 c.lpfnWndProc = proc; c.hInstance = GetModuleHandleW(0); c.lpszClassName = L"SHZ_MINES"; c.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1); c.hCursor = LoadCursorW(0, MAKEINTRESOURCEW(32512));
 if (!RegisterClassW(&c) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return 1;
 new_game();
 wnd = CreateWindowExW(0, c.lpszClassName, L"Shizuku Mines", WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, 120, 80, MN_ORGX * 2 + 9 * MN_CELL + 8, MN_ORGY + 9 * MN_CELL + 40, 0, 0, c.hInstance, 0);
 if (!wnd) return 1;
 SetWindowTextW(wnd, seed_kernel ? L"Shizuku Mines" : L"Shizuku Mines (weak seed)");
 ShowWindow(wnd, SW_SHOW); SetFocus(wnd);
 while (GetMessageW(&msg, 0, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessageW(&msg); }
 return 0;
}
