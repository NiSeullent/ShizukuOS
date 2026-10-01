/* SPDX-License-Identifier: GPL-2.0-only
 * Private adapters for the shared painter's actual ANSI calls. Not exports.
 * Include after windows.h/uxtheme.h; never redirect consumer USER32 calls.
 */
#ifndef M98_WIN64_THEME_TRANSPORT_H
#define M98_WIN64_THEME_TRANSPORT_H
int WINAPI m98w_DrawTextA(HDC, LPCSTR, int, LPRECT, UINT);
HANDLE WINAPI m98w_GetPropA(HWND, LPCSTR);
BOOL WINAPI m98w_SetPropA(HWND, LPCSTR, HANDLE);
HANDLE WINAPI m98w_RemovePropA(HWND, LPCSTR);
LRESULT WINAPI m98w_SendMessageA(HWND, UINT, WPARAM, LPARAM);
BOOL WINAPI m98w_SystemParametersInfoA(UINT, UINT, PVOID, UINT);
#ifndef M98_THEME_TRANSPORT_IMPLEMENTATION
#define DrawTextA m98w_DrawTextA
#define GetPropA m98w_GetPropA
#define SetPropA m98w_SetPropA
#define RemovePropA m98w_RemovePropA
#define SendMessageA m98w_SendMessageA
#define SystemParametersInfoA m98w_SystemParametersInfoA
#endif
#endif
