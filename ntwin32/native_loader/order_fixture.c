/* SPDX-License-Identifier: GPL-2.0-only
 * Closed graph A-init -> later B reference rejection, with failed B rollback.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
static HINSTANCE attached;
#if defined(NP_ORDER_A) || defined(NP_ORDER_B)
static void message(const char *s)
{DWORD n=0,w;while(s[n])n++;WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),s,n,&w,NULL);}
#endif
#if defined(NP_ORDER_A)
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
 (void)reserved;if(reason==DLL_PROCESS_ATTACH){HMODULE b=GetModuleHandleA("PEORDB.DLL");
  if(!b||LoadLibraryA("PEORDB.DLL")||GetProcAddress(b,"BReady@0")){message("ORDER_A_LATER_B_INITIALIZATION_GATE_FAIL\r\n");return FALSE;}
  message("ORDER_A_LATER_B_UNINITIALIZED_LOAD_AND_EXPORT_REJECTED\r\n");attached=base;
 }
 if(reason==DLL_PROCESS_DETACH){message("ORDER_A_DETACH\r\n");attached=NULL;}return TRUE;
}
DWORD WINAPI AReady(void){return attached!=NULL;}
#elif defined(NP_ORDER_B)
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
 (void)reserved;(void)base;if(reason==DLL_PROCESS_ATTACH){
#ifdef NP_ORDER_FAIL_B
  message("ORDER_B_ATTACH_RETURN_FALSE\r\n");return FALSE;
#else
  message("ORDER_B_ATTACH_SUCCESS\r\n");attached=base;
#endif
 }
 if(reason==DLL_PROCESS_DETACH){message("ORDER_B_DETACH\r\n");attached=NULL;}return TRUE;
}
DWORD WINAPI BReady(void){return attached!=NULL;}
#else
__declspec(dllimport) DWORD WINAPI AReady(void);
__declspec(dllimport) DWORD WINAPI BReady(void);
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{(void)reserved;if(reason==DLL_PROCESS_ATTACH)attached=base;if(reason==DLL_PROCESS_DETACH)attached=NULL;return TRUE;}
DWORD WINAPI NtwPeFixture(HINSTANCE base,HANDLE report)
{
 static const char pass[]="ORDER_ROOT_BOTH_STATIC_DEPENDENCIES_INITIALIZED\r\n";DWORD w;
 if(attached!=base||!AReady()||!BReady())return 31;
 if(!WriteFile(report,pass,sizeof(pass)-1,&w,NULL)||w!=sizeof(pass)-1)return 32;return 0;
}
#endif
