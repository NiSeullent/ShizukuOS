/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef SHZ_SEARCH_H
#define SHZ_SEARCH_H
#include "shell.h"
BOOL ShzSearchRegister(void);
HWND ShzSearchOpen(void);
void ShzSearchClose(void);
void ShzSearchRelayout(void);
void ShzSearchInvalidateFiles(void);
BOOL ShzSearchCanExit(void);
#endif
