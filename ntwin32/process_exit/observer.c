/* SPDX-License-Identifier: GPL-2.0-only
 * Owned fixture only: observes native dependency detach order; no allocation.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#ifndef OBSERVER_ID
#error OBSERVER_ID required
#endif
static volatile DWORD *state;static HANDLE log=INVALID_HANDLE_VALUE;
BOOL WINAPI PXObserverBind(volatile DWORD *target,HANDLE file)
{if(!target||file==INVALID_HANDLE_VALUE||state)return FALSE;state=target;log=file;return TRUE;}
BOOL WINAPI dll_entry(HINSTANCE instance,DWORD reason,void *reserved)
{
 (void)instance;
 if(reason==DLL_PROCESS_DETACH&&state){DWORD written;const char *line;
  *state=reserved?1u:2u;
  if(OBSERVER_ID==1)line=reserved?"NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=1\r\n":"NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=0\r\n";
  else line=reserved?"NATIVE_DEPENDENCY_DETACH=B REASON=0 RESERVED_NONNULL=1\r\n":"NATIVE_DEPENDENCY_DETACH=B REASON=0 RESERVED_NONNULL=0\r\n";
  DWORD n=0;while(line[n])n++;
  if(!WriteFile(log,line,n,&written,NULL)||written!=n||!FlushFileBuffers(log)){
   const char failed[]="OBSERVER_IO_FAILED=1\r\n";*state|=0x80000000u;WriteFile(log,failed,sizeof(failed)-1,&written,NULL);FlushFileBuffers(log);
  }
 }
 return TRUE;
}
