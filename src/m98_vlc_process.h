/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_VLC_PROCESS_H
#define M98_VLC_PROCESS_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
DWORD WINAPI m98_vlc_GetProcessId(HANDLE);
HANDLE WINAPI m98_vlc_OpenThread(DWORD,BOOL,DWORD);
BOOL WINAPI m98_vlc_CheckRemoteDebuggerPresent(HANDLE,PBOOL);
VOID WINAPI m98_vlc_RtlCaptureContext(PCONTEXT);
#endif
