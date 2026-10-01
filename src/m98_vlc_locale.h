/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef M98_VLC_LOCALE_H
#define M98_VLC_LOCALE_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int WINAPI m98_vlc_GetGeoInfoW(GEOID,GEOTYPE,LPWSTR,int,LANGID);
GEOID WINAPI m98_vlc_GetUserGeoID(GEOCLASS);
LANGID WINAPI m98_vlc_GetUserDefaultUILanguage(void);
BOOL WINAPI m98_vlc_IsValidLanguageGroup(LGRPID,DWORD);
#endif
