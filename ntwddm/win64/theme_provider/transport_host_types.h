/* SPDX-License-Identifier: GPL-2.0-only
 * Windows fixed-width structures for host conversion/dispatch tests only.
 */
#ifndef M98_WIN64_THEME_TRANSPORT_HOST_TYPES_H
#define M98_WIN64_THEME_TRANSPORT_HOST_TYPES_H
#include "host_types.h"
typedef int BOOL;
typedef uint32_t UINT;
typedef uint8_t BYTE;
typedef uint16_t WCHAR;
typedef void *HANDLE;
typedef void *HWND;
typedef void *PVOID;
typedef const char *LPCSTR;
typedef const WCHAR *LPCWSTR;
typedef RECT *LPRECT;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM;
typedef intptr_t LRESULT;
#define FALSE 0
#define TRUE 1
#define LF_FACESIZE 32
#define M98_FONT_NUMERIC_FIELDS LONG lfHeight, lfWidth, lfEscapement, lfOrientation, lfWeight; \
    BYTE lfItalic, lfUnderline, lfStrikeOut, lfCharSet, lfOutPrecision, lfClipPrecision, lfQuality, lfPitchAndFamily
typedef struct { M98_FONT_NUMERIC_FIELDS; char lfFaceName[LF_FACESIZE]; } LOGFONTA;
typedef struct { M98_FONT_NUMERIC_FIELDS; WCHAR lfFaceName[LF_FACESIZE]; } LOGFONTW;
#define M98_METRIC_FIELDS(FONT) UINT cbSize; int iBorderWidth, iScrollWidth, iScrollHeight, iCaptionWidth, iCaptionHeight; \
    FONT lfCaptionFont; int iSmCaptionWidth, iSmCaptionHeight; FONT lfSmCaptionFont; \
    int iMenuWidth, iMenuHeight; FONT lfMenuFont, lfStatusFont, lfMessageFont; int iPaddedBorderWidth
typedef struct { M98_METRIC_FIELDS(LOGFONTA); } NONCLIENTMETRICSA;
typedef struct { M98_METRIC_FIELDS(LOGFONTW); } NONCLIENTMETRICSW;
#define ERROR_INVALID_PARAMETER 87u
#define ERROR_NOT_SUPPORTED 50u
#define ERROR_NO_UNICODE_TRANSLATION 1113u
#define ERROR_INVALID_DATA 13u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_GEN_FAILURE 31u
#define ERROR_INSUFFICIENT_BUFFER 122u
#define CP_ACP 0u
#define MB_ERR_INVALID_CHARS 8u
#define HEAP_ZERO_MEMORY 8u
#define SPI_GETNONCLIENTMETRICS 0x29u
#define SPI_GETICONTITLELOGFONT 0x1fu
#define WM_THEMECHANGED 0x31au
#define DT_CENTER 1u
#define DT_RIGHT 2u
#define DT_VCENTER 4u
#define DT_BOTTOM 8u
#define DT_WORDBREAK 16u
#define DT_SINGLELINE 32u
#define DT_EXPANDTABS 64u
#define DT_NOCLIP 256u
#define DT_CALCRECT 1024u
#define DT_NOPREFIX 2048u
#define DT_END_ELLIPSIS 32768u
#define DT_MODIFYSTRING 65536u
DWORD GetLastError(void);
void SetLastError(DWORD);
HANDLE GetProcessHeap(void);
PVOID HeapAlloc(HANDLE, DWORD, size_t);
BOOL HeapFree(HANDLE, DWORD, PVOID);
int MultiByteToWideChar(UINT, DWORD, LPCSTR, int, WCHAR *, int);
int WideCharToMultiByte(UINT, DWORD, LPCWSTR, int, char *, int, LPCSTR, BOOL *);
HANDLE GetPropW(HWND, LPCWSTR);
BOOL SetPropW(HWND, LPCWSTR, HANDLE);
HANDLE RemovePropW(HWND, LPCWSTR);
LRESULT SendMessageW(HWND, UINT, WPARAM, LPARAM);
BOOL SystemParametersInfoW(UINT, UINT, PVOID, UINT);
int DrawTextW(HDC, LPCWSTR, int, LPRECT, UINT);
#endif
