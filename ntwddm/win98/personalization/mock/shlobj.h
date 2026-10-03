/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef PZ98_MOCK_SHLOBJ_H
#define PZ98_MOCK_SHLOBJ_H
#include <windows.h>
#define CSIDL_APPDATA 0x001a
BOOL SHGetSpecialFolderPathA(void *,char *,int,BOOL);
#endif
