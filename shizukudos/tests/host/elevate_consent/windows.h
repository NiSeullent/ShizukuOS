/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only USER/GDI/event/conversion boundary. No credential authentication. */
#ifndef SHZ_ELEVATE_HOST_WINDOWS_H
#define SHZ_ELEVATE_HOST_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
typedef wchar_t WCHAR;
typedef unsigned UINT;
typedef unsigned long DWORD;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM,LRESULT;
typedef int BOOL;
typedef void *HWND,*HDC,*HINSTANCE,*HBRUSH,*HCURSOR,*HMENU;
typedef struct {int left,top,right,bottom;} RECT;
typedef struct {HDC hdc;} PAINTSTRUCT;
typedef struct {HWND hwnd;UINT message;WPARAM wParam;LPARAM lParam;} MSG;
#define CALLBACK
typedef LRESULT (*WNDPROC)(HWND,UINT,WPARAM,LPARAM);
typedef struct {WNDPROC lpfnWndProc;HINSTANCE hInstance;const WCHAR *lpszClassName;HBRUSH hbrBackground;HCURSOR hCursor;} WNDCLASSW;
#define TRUE 1
#define FALSE 0
#define CP_UTF8 65001u
#define MB_ERR_INVALID_CHARS 8u
#define WM_SIZE 5u
#define WM_PAINT 15u
#define WM_CLOSE 16u
#define WM_GETTEXT 13u
#define WM_GETTEXTLENGTH 14u
#define WM_CHAR 258u
#define WM_LBUTTONUP 514u
#define WM_COPY 769u
#define WM_CUT 768u
#define WM_PASTE 770u
#define TRANSPARENT 1
#define DT_LEFT 0u
#define DT_CENTER 1u
#define DT_VCENTER 4u
#define DT_WORDBREAK 16u
#define DT_SINGLELINE 32u
#define DT_CALCRECT 1024u
#define DT_NOPREFIX 2048u
#define COLOR_WINDOW 5
#define WS_EX_TOPMOST 8u
#define WS_OVERLAPPED 0u
#define WS_CAPTION 0xc00000u
#define WS_SYSMENU 0x80000u
#define SW_SHOW 5
#define ERROR_CLASS_ALREADY_EXISTS 1410u
#define MAKEINTRESOURCEW(n) ((const WCHAR *)(uintptr_t)(n))
#define LOWORD(n) ((uint16_t)(uintptr_t)(n))
#define HIWORD(n) ((uint16_t)((uintptr_t)(n)>>16))
void *SecureZeroMemory(void *,size_t);
int WideCharToMultiByte(UINT,DWORD,const WCHAR *,int,char *,int,const char *,BOOL *);
int MultiByteToWideChar(UINT,DWORD,const char *,int,WCHAR *,int);
BOOL InvalidateRect(HWND,const RECT *,BOOL);
BOOL DestroyWindow(HWND);
HDC BeginPaint(HWND,PAINTSTRUCT *);
BOOL EndPaint(HWND,const PAINTSTRUCT *);
int SetBkMode(HDC,int);
BOOL Rectangle(HDC,int,int,int,int);
int DrawTextW(HDC,const WCHAR *,int,RECT *,UINT);
BOOL GetClientRect(HWND,RECT *);
LRESULT DefWindowProcW(HWND,UINT,WPARAM,LPARAM);
HINSTANCE GetModuleHandleW(const WCHAR *);
HCURSOR LoadCursorW(HINSTANCE,const WCHAR *);
unsigned short RegisterClassW(const WNDCLASSW *);
DWORD GetLastError(void);
HWND CreateWindowExW(DWORD,const WCHAR *,const WCHAR *,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,void *);
BOOL ShowWindow(HWND,int);
HWND SetFocus(HWND);
int GetMessageW(MSG *,HWND,UINT,UINT);
BOOL TranslateMessage(const MSG *);
LRESULT DispatchMessageW(const MSG *);
#endif
