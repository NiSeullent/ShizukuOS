/* SPDX-License-Identifier: GPL-2.0-only
 * Host-only scalar/API injection for the exact CoWait production body. */
#ifndef SHZ_COWAIT_HOST_CONTRACT_H
#define SHZ_COWAIT_HOST_CONTRACT_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD,ULONG,UINT;
typedef uint64_t ULONGLONG;
typedef uintptr_t WPARAM;
typedef intptr_t LPARAM,LRESULT;
typedef int32_t HRESULT;
typedef int BOOL,APTTYPE,APTTYPEQUALIFIER;
typedef void *HANDLE;
typedef struct { HANDLE hwnd;UINT message;WPARAM wParam;LPARAM lParam; } MSG;
typedef struct { unsigned refs,policy,unregister; } IMessageFilter;
#define DLLAPI
#define WINAPI
#define TRUE 1
#define FALSE 0
#define MAXDWORD UINT32_MAX
#define INFINITE UINT32_MAX
#define MAXIMUM_WAIT_OBJECTS 64
#define COWAIT_WAITALL 1
#define COWAIT_ALERTABLE 2
#define COWAIT_INPUTAVAILABLE 4
#define COWAIT_DISPATCH_CALLS 8
#define COWAIT_DISPATCH_WINDOW_MESSAGES 16
#define MWMO_ALERTABLE 2
#define WAIT_OBJECT_0 0
#define WAIT_ABANDONED_0 128
#define WAIT_TIMEOUT 258
#define WAIT_FAILED UINT32_MAX
#define WAIT_IO_COMPLETION 192
#define S_OK ((HRESULT)0)
#define E_FAIL ((HRESULT)0x80004005u)
#define E_INVALIDARG ((HRESULT)0x80070057u)
#define E_NOTIMPL ((HRESULT)0x80004001u)
#define RPC_E_NO_SYNC ((HRESULT)0x80010120u)
#define RPC_S_CALLPENDING ((HRESULT)0x80010115u)
#define RPC_E_CALL_CANCELED ((HRESULT)0x80010002u)
#define HRESULT_FROM_WIN32(e) ((HRESULT)(0x80070000u|((uint32_t)(e)&0xffffu)))
#define APTTYPE_STA 0
#define APTTYPE_MTA 1
#define APTTYPE_MAINSTA 3
#define PENDINGTYPE_TOPLEVEL 1
#define PENDINGMSG_CANCELCALL 0
#define PENDINGMSG_WAITNOPROCESS 1
#define PENDINGMSG_WAITDEFPROCESS 2
#define PM_REMOVE 1
#define PM_NOYIELD 2
#define QS_ALLINPUT 0x4ff
#define QS_POSTMESSAGE 0x8
#define QS_SENDMESSAGE 0x40
#define QS_ALLPOSTMESSAGE 0x100
#define QS_PAINT 0x20
#define PM_QS_PAINT (QS_PAINT<<16)
#define PM_QS_SENDMESSAGE (QS_SENDMESSAGE<<16)
#define WM_DDE_FIRST 0x3e0
#define WM_DDE_LAST 0x3e8
#define WM_QUIT 0x12
static HRESULT CoGetApartmentType(APTTYPE *,APTTYPEQUALIFIER *);
static DWORD WaitForMultipleObjectsEx(DWORD,const HANDLE *,BOOL,DWORD,BOOL);
static DWORD MsgWaitForMultipleObjectsEx(DWORD,const HANDLE *,DWORD,DWORD,DWORD);
static BOOL PeekMessageW(MSG *,HANDLE,UINT,UINT,UINT);
static BOOL TranslateMessage(const MSG *);
static LRESULT DispatchMessageW(const MSG *);
static void PostQuitMessage(int);
static DWORD GetLastError(void);
static ULONGLONG GetTickCount64(void);
static void Sleep(DWORD);
static IMessageFilter *shz_message_filter_snapshot(void);
static DWORD host_pending(IMessageFilter *,HANDLE,DWORD,DWORD);
static ULONG host_release(IMessageFilter *);
#define IMessageFilter_MessagePending host_pending
#define IMessageFilter_Release host_release
_Static_assert(sizeof(DWORD)==4&&sizeof(HANDLE)==8,"AMD64 Windows wait ABI");
#endif
