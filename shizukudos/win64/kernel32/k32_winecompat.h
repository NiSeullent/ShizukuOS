/* SPDX-License-Identifier: GPL-2.0-only
 * Internal header of the kernel32 parts added for the DLLs ported from Wine (k32_winecompat_*.c). */
#ifndef SHZ_K32_WINECOMPAT_H
#define SHZ_K32_WINECOMPAT_H
#include "k32.h"
/* winuser.h is excluded by WIN32_LEAN_AND_MEAN in nt.h; these resource macros are all kernel32 needs from it */
#ifndef IS_INTRESOURCE
#define IS_INTRESOURCE(p) ((((ULONG_PTR)(p)) >> 16) == 0)
#endif
#ifndef MAKEINTRESOURCEW
#define MAKEINTRESOURCEW(i) ((LPWSTR)(ULONG_PTR)(WORD)(i))
#define MAKEINTRESOURCEA(i) ((LPSTR)(ULONG_PTR)(WORD)(i))
#endif
#endif
