/* SPDX-License-Identifier: GPL-2.0-only -- own fixed mapped DLL consumer. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
static HINSTANCE self;
static HRSRC info;
static HGLOBAL data;
static int attached;
static int own_resource(HINSTANCE base)
{
 static const BYTE expected[]={0x52,0x42,0x44,0x41,0x54,0x41,0x98,0};const BYTE *p;unsigned i;
 info=FindResourceExA(base,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(301),1033);
 if(!info||SizeofResource(base,info)!=8||!(data=LoadResource(base,info))||!(p=LockResource(data)))return 0;
 for(i=0;i<8;i++)if(p[i]!=expected[i])return 0;return 1;
}
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
 (void)reserved;
 if(reason==DLL_PROCESS_ATTACH){self=base;attached=own_resource(base);return attached;}
 if(reason==DLL_PROCESS_DETACH){if(!own_resource(base))return FALSE;attached=0;self=NULL;}
 return TRUE;
}
DWORD WINAPI RData(HMODULE root,HRSRC root_info,HGLOBAL root_data)
{
 DWORD observed;if(!attached||GetModuleHandleA("RBDATA.DLL")!=self||!own_resource(self))return 31;
 SetLastError(0);if(LoadResource(self,root_info))return 31;observed=GetLastError();if(observed!=ERROR_INVALID_HANDLE)return 31;
 SetLastError(0);if(SizeofResource(self,root_info))return 31;observed=GetLastError();if(observed!=ERROR_INVALID_HANDLE)return 31;
 if(!root||LockResource(root_data)!=root_data||LockResource(data)!=data)return 31;
 if(FreeResource(data)||FreeResource(data)||LockResource(data)!=data)return 31;
 return 0;
}
