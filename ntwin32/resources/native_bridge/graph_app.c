/* SPDX-License-Identifier: GPL-2.0-only -- exact own resource application graph. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
__declspec(dllimport) DWORD WINAPI RData(HMODULE,HRSRC,HGLOBAL);
static HINSTANCE self;
static DWORD checks,failures;
static void check(int okay){checks++;if(!okay)failures++;}
static void run(void)
{
 static const BYTE expected[]={0x52,0x42,0x41,0x50,0x50,0x31,0x98,0};const BYTE *bytes;unsigned i;
 HRSRC info,named;HGLOBAL data;HMODULE dep,kernel;DWORD observed;BOOL freed;
 typedef HRSRC (WINAPI *find_fn)(HMODULE,LPCSTR,LPCSTR,WORD);find_fn find;
#ifdef NRB_DLL_ROOT
 check(GetModuleHandleA(NULL)!=self);check(GetModuleHandleA("RBROOT.DLL")==self);
 check(FindResourceExA(NULL,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033)==NULL);
#else
 self=GetModuleHandleA(NULL);check(self!=NULL);check(GetModuleHandleA("RBAPP.EXE")==self);
#endif
 SetLastError(0x51a2b3c4u);info=FindResourceExA(self,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033);observed=GetLastError();check(info&&observed==0x51a2b3c4u);
#ifndef NRB_DLL_ROOT
 check(FindResourceExA(NULL,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033)==info);
#endif
 check(SizeofResource(self,info)==8);data=LoadResource(self,info);check(data!=NULL);bytes=LockResource(data);check(bytes==(const BYTE *)data);
 if(bytes)for(i=0;i<8;i++)check(bytes[i]==expected[i]);else failures++;
 named=FindResourceA(self,"named",MAKEINTRESOURCEA(10));check(named!=NULL&&SizeofResource(self,named)==6);
 check(FindResourceW(self,L"named",MAKEINTRESOURCEW(10))==named);
 check(FindResourceExW(self,MAKEINTRESOURCEW(10),L"named",1033)==named);
 check(FindResourceExA(self,"#10","#101",1033)==info);
 kernel=GetModuleHandleA("KERNEL32.DLL");check(kernel!=NULL);find=(find_fn)(void *)GetProcAddress(kernel,"FindResourceExA");check(find!=NULL);
 if(find)check(find(self,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033)==info);
 check(RData(self,info,data)==0);dep=LoadLibraryA("RBDATA.DLL");check(dep==GetModuleHandleA("RBDATA.DLL"));check(dep&&FreeLibrary(dep));check(RData(self,info,data)==0);
 check(LockResource(data)==data);SetLastError(0x51a2b3c4u);freed=FreeResource(data);observed=GetLastError();check(!freed);check(observed==0x51a2b3c4u);
 check(!FreeResource(data));check(LockResource(data)==data);
 SetLastError(0);check(LoadResource((HMODULE)(UINT_PTR)1,info)==NULL);observed=GetLastError();check(observed==ERROR_INVALID_HANDLE);
 SetLastError(0);check(LockResource((HGLOBAL)info)==NULL);observed=GetLastError();check(observed==ERROR_INVALID_HANDLE);
 SetLastError(0);check(LoadResource(self,(HRSRC)(UINT_PTR)1)==NULL);observed=GetLastError();check(observed==ERROR_INVALID_HANDLE);
}
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{(void)reserved;if(reason==DLL_PROCESS_ATTACH)self=base;return TRUE;}
void WINAPI entry(void){run();}
DWORD WINAPI NtwResourceResult(void){return checks>=35&&!failures?0:31;}
DWORD WINAPI NtwResourceChecks(void){return checks;}
DWORD WINAPI NtwPeFixture(HINSTANCE base,HANDLE report)
{(void)report;check(self==base);run();return NtwResourceResult();}
