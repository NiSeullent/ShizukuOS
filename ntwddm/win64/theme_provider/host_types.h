/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed-width declarations for extension dispatch/geometry host tests only.
 * Production always uses the real MinGW Windows/uxtheme ABI headers.
 */
#ifndef M98_WIN64_THEME_HOST_TYPES_H
#define M98_WIN64_THEME_HOST_TYPES_H
#include <stdint.h>
#include <stddef.h>
#define WINAPI
typedef int32_t HRESULT;
typedef int32_t LONG;
typedef uint32_t DWORD;
typedef void *HTHEME;
typedef void *HDC;
typedef struct { LONG left, top, right, bottom; } RECT;
typedef struct { LONG cx, cy; } SIZE;
typedef struct { DWORD dwSize, dwFlags; RECT rcClip; } DTBGOPTS;
typedef enum { TS_MIN, TS_TRUE, TS_DRAW } THEMESIZE;
#define S_OK ((HRESULT)0)
#define E_NOTIMPL ((HRESULT)0x80004001u)
#define E_POINTER ((HRESULT)0x80004003u)
#define E_FAIL ((HRESULT)0x80004005u)
#define E_HANDLE ((HRESULT)0x80070006u)
#define E_OUTOFMEMORY ((HRESULT)0x8007000eu)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define FAILED(hr) ((HRESULT)(hr) < 0)
#define TMT_BGTYPE 4001
#define TMT_BORDERSIZE 2403
#define BT_BORDERFILL 1
#define DTBG_CLIPRECT 1u
#endif
