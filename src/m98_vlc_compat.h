/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_VLC_COMPAT_H
#define M98_VLC_COMPAT_H
#include <windows.h>
void WINAPI m98_vlc_GetNativeSystemInfo(LPSYSTEM_INFO);
BOOL WINAPI m98_vlc_SetFilePointerEx(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD);
BOOL WINAPI m98_vlc_HeapSetInformation(HANDLE, DWORD, PVOID, SIZE_T);
BOOL WINAPI m98_vlc_RemoveFontResourceExW(LPCWSTR, DWORD, PVOID);
BOOL WINAPI m98_vlc_RemoveFontMemResourceEx(HANDLE);
UINT WINAPI m98_vlc_RealGetWindowClassW(HWND, LPWSTR, UINT);
#endif
