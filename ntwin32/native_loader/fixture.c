/* SPDX-License-Identifier: GPL-2.0-only
 * Own-built bounded execution control, not an official app or native evidence.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
static HINSTANCE attached;
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved)
{
 (void)reserved;
#ifdef NP_FAIL_ATTACH
 if(reason==DLL_PROCESS_ATTACH||reason==DLL_PROCESS_DETACH){
  static const char attach[]="NATIVE_FIXTURE_ATTACH_RETURN_FALSE\r\n";
  static const char detach[]="NATIVE_FIXTURE_FAILED_MODULE_DETACH\r\n";
  const char *message=reason==DLL_PROCESS_ATTACH?attach:detach;DWORD written;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),message,reason==DLL_PROCESS_ATTACH?sizeof(attach)-1:sizeof(detach)-1,&written,NULL);
 }
 if(reason==DLL_PROCESS_ATTACH)return FALSE;
#endif
 if(reason==DLL_PROCESS_ATTACH)attached=instance;
 if(reason==DLL_PROCESS_DETACH)attached=NULL;
 return TRUE;
}
DWORD WINAPI NtwPeFixture(HINSTANCE mapped,HANDLE report)
{
 static const char message[]="NATIVE_FIXTURE_MAPPED_BASE_ATTACH_PASS\r\n";
 DWORD written=0;
 if(!mapped||mapped!=attached)return 31;
 if(!WriteFile(report,message,sizeof(message)-1,&written,NULL)||written!=sizeof(message)-1)return 32;
 return 0;
}
