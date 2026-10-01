/* SPDX-License-Identifier: GPL-2.0-only; host resource/pixel mocks, not native ABI proof. */
#ifndef COMPOSE_WINMOCK_H
#define COMPOSE_WINMOCK_H
#include <stdint.h>
#include <wchar.h>
typedef uint32_t DWORD,COLORREF;typedef int BOOL,LONG,HRESULT;
typedef void *HANDLE,*HDC,*HBITMAP,*HGDIOBJ,*HFONT,*HBRUSH;
typedef wchar_t WCHAR;typedef const WCHAR *LPCWSTR;
typedef struct {LONG left,top,right,bottom;} RECT;
typedef struct {DWORD biSize;LONG biWidth,biHeight;unsigned short biPlanes,biBitCount;DWORD biCompression;} BITMAPINFOHEADER;
typedef struct {BITMAPINFOHEADER bmiHeader;} BITMAPINFO;
typedef struct {int marker;} LOGFONTA;
typedef struct {DWORD cbSize;LOGFONTA lfMessageFont;int iPaddedBorderWidth;} NONCLIENTMETRICSA;
#define WINAPI
#define S_OK 0
#define BI_RGB 0u
#define DIB_RGB_COLORS 0u
#define DT_CENTER 1u
#define DT_VCENTER 4u
#define DT_SINGLELINE 32u
#define DT_WORDBREAK 16u
#define COLOR_BTNFACE 15u
#define SPI_GETNONCLIENTMETRICS 41u
#define TRANSPARENT 1
#define SRCCOPY 0xcc0020u
#define BITSPIXEL 12
#define HGDI_ERROR ((void *)(intptr_t)-1)
#define CLR_INVALID UINT32_C(0xffffffff)
HDC CreateCompatibleDC(HDC);
HBITMAP CreateDIBSection(HDC,const BITMAPINFO *,unsigned,void **,HANDLE,DWORD);
HGDIOBJ SelectObject(HDC,HGDIOBJ);
BOOL DeleteDC(HDC);BOOL DeleteObject(HGDIOBJ);
BOOL SystemParametersInfoA(unsigned,unsigned,void *,unsigned);
HFONT CreateFontIndirectA(const LOGFONTA *);
int SetBkMode(HDC,int);COLORREF SetTextColor(HDC,COLORREF);
int FillRect(HDC,const RECT *,HBRUSH);
int DrawTextA(HDC,const char *,int,RECT *,unsigned);
BOOL BitBlt(HDC,int,int,int,int,HDC,int,int,DWORD);
BOOL GdiFlush(void);COLORREF GetPixel(HDC,int,int);int GetDeviceCaps(HDC,int);
#endif
