/* SPDX-License-Identifier: GPL-2.0-only
 * Observation only: preserve the v3 original-export and manager guards.
 * No callback registration, guard relaxation or modern application launch.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "original_kernel.h"
typedef BOOL (WINAPI *init_fn)(void);
static HANDLE report;
static int failed;
static DWORD static_context=0x50445831u;
static void text(const char *s)
{
 DWORD n=0,written=0;while(s[n])n++;
 if(!WriteFile(report,s,n,&written,NULL)||written!=n)failed=1;
}
static void value(const char *label,DWORD v)
{
 char b[9];unsigned i;for(i=0;i<8;i++)b[i]="0123456789ABCDEF"[(v>>(28-4*i))&15];b[8]=0;
 text(label);text("=");text(b);text("\r\n");
}
static void string(const char *label,const char *s){text(label);text("=");text(s);text("\r\n");}
static void zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)p)[i]=0;}
static WORD u16(const BYTE *p){return (WORD)(p[0]|(WORD)p[1]<<8);}
static DWORD u32(const BYTE *p){return (DWORD)p[0]|(DWORD)p[1]<<8|(DWORD)p[2]<<16|(DWORD)p[3]<<24;}
static void memory(const char *tag,const void *p)
{
 MEMORY_BASIC_INFORMATION info;SIZE_T bytes;DWORD error;zero(&info,sizeof(info));
 SetLastError(0xE0100001u);bytes=VirtualQuery(p,&info,sizeof(info));error=GetLastError();
 string("MEMORY_TAG",tag);value("ADDRESS",(DWORD)(UINT_PTR)p);value("MBI_SIZE",sizeof(info));
 value("VIRTUALQUERY_BYTES",(DWORD)bytes);value("VIRTUALQUERY_LAST_ERROR",error);
 if(bytes){value("BASE_ADDRESS",(DWORD)(UINT_PTR)info.BaseAddress);value("ALLOCATION_BASE",(DWORD)(UINT_PTR)info.AllocationBase);
  value("ALLOCATION_PROTECT",info.AllocationProtect);value("REGION_SIZE",(DWORD)info.RegionSize);
  value("STATE",info.State);value("PROTECT",info.Protect);value("TYPE",info.Type);
  value("CURRENT_V3_COMMITTED_TEST",info.State==MEM_COMMIT);
  value("CURRENT_V3_EXECUTE_BITS_TEST",(info.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))!=0);
  value("CURRENT_V3_GUARD_NOACCESS_TEST",(info.Protect&(PAGE_GUARD|PAGE_NOACCESS))==0);
 }
}
static void module(const char *tag,HMODULE handle,const void *point)
{
 char path[MAX_PATH],name[9];DWORD n,error,nt,optional,table,count,i;BOOL unreadable;const BYTE *base=(const BYTE *)handle;
 string("MODULE_TAG",tag);value("MODULE_HANDLE",(DWORD)(UINT_PTR)handle);value("POINT",(DWORD)(UINT_PTR)point);
 if(!handle)return;SetLastError(0xE0100002u);n=GetModuleFileNameA(handle,path,sizeof(path));error=GetLastError();
 value("MODULE_FILENAME_BYTES",n);value("MODULE_FILENAME_LAST_ERROR",error);
 if(n&&n<sizeof(path)){path[n]=0;string("MODULE_FILENAME",path);}
 memory(tag,handle);
 /* This standard native pointer probe precedes every bounded PE-header read.
  * A refused read is recorded, never used as permission to bypass v3 guards. */
 unreadable=IsBadReadPtr(base,4096);value("HEADER_4096_POINTER_PROBE",unreadable);if(unreadable)return;
 value("MZ",u16(base));if(u16(base)!=0x5A4D)return;nt=u32(base+60);value("PE_OFFSET",nt);
 if(nt<64||nt>4096-24||u32(base+nt)!=0x4550)return;
 value("MACHINE",u16(base+nt+4));count=u16(base+nt+6);optional=nt+24;
 value("SECTION_COUNT",count);value("OPTIONAL_HEADER_BYTES",u16(base+nt+20));
 if(u16(base+nt+20)<96||u16(base+nt+20)>4096-optional)return;
 value("PE_MAGIC",u16(base+optional));value("DECLARED_IMAGE_BASE",u32(base+optional+28));
 value("IMAGE_BYTES",u32(base+optional+56));value("HEADER_BYTES",u32(base+optional+60));
 table=optional+u16(base+nt+20);if(!count||count>32||count>(4096-table)/40)return;
 for(i=0;i<count;i++){
  const BYTE *s=base+table+i*40;DWORD start=u32(s+12),size=u32(s+8),flags=u32(s+36),offset=(DWORD)((UINT_PTR)point-(UINT_PTR)handle);unsigned j;
  for(j=0;j<8;j++)name[j]=(char)s[j];name[8]=0;
  value("SECTION_INDEX",i);string("SECTION_NAME",name);value("SECTION_RVA",start);value("SECTION_BYTES",size);value("SECTION_FLAGS",flags);
  value("POINT_IN_SECTION",point&&(UINT_PTR)point>=(UINT_PTR)handle&&offset>=start&&offset-start<size);
 }
}
static void WINAPI native_exe_callback(void){static_context++;}
void WINAPI entry(void)
{
 HMODULE kernel,core,main,manager;FARPROC direct_exit,direct_version,resolved_exit,resolved_version;int used_exit=0,used_version=0;
 DWORD error,stack_context=0x53545831u;OSVERSIONINFOA version;BOOL okay;init_fn initialize;union {FARPROC generic;init_fn typed;} convert;
 report=CreateFileA("C:\\VXDLAB\\PXDIAG.LOG",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 text("SCOPE=NATIVE_GUARD_OBSERVATION_ONLY\r\nAPPLICATION_EXECUTED=0\r\nV3_GUARDS_CHANGED=0\r\nCALLBACKS_REGISTERED=0\r\n");
 kernel=GetModuleHandleA("KERNEL32.DLL");core=GetModuleHandleA("KERNELEX.DLL");main=GetModuleHandleA(NULL);
 value("NATIVE_VERSION_SHORT",GetVersion());value("KERNELEX_RESIDENT",(DWORD)(UINT_PTR)core);
 zero(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);SetLastError(0xE0100003u);
 okay=GetVersionExA(&version);error=GetLastError();value("IMPORTED_VERSION_QUERY_OK",okay);value("IMPORTED_VERSION_QUERY_ERROR",error);
 value("IMPORTED_VERSION_PLATFORM",version.dwPlatformId);value("IMPORTED_VERSION_MAJOR",version.dwMajorVersion);
 value("IMPORTED_VERSION_MINOR",version.dwMinorVersion);value("IMPORTED_VERSION_BUILD",version.dwBuildNumber);
 value("DIRECT_EXPORT_LOOKUPS_ATTEMPTED",kernel!=NULL);
 direct_exit=kernel?GetProcAddress(kernel,"ExitProcess"):NULL;error=kernel&&!direct_exit?GetLastError():0;
 value("DIRECT_EXIT_EXPORT_LOOKUP_ERROR",error);
 direct_version=kernel?GetProcAddress(kernel,"GetVersionExA"):NULL;error=kernel&&!direct_version?GetLastError():0;
 value("DIRECT_VERSION_EXPORT_LOOKUP_ERROR",error);
 value("IMPORTED_EXITPROCESS",(DWORD)(UINT_PTR)ExitProcess);value("DIRECT_EXPORTED_EXITPROCESS",(DWORD)(UINT_PTR)direct_exit);
 value("DIRECT_EXPORTED_VERSION",(DWORD)(UINT_PTR)direct_version);
 SetLastError(0xE0100004u);resolved_exit=px_original_kernel("ExitProcess",&used_exit);error=GetLastError();
 value("UNCHANGED_V3_ORIGINAL_EXIT",(DWORD)(UINT_PTR)resolved_exit);value("UNCHANGED_V3_ORIGINAL_EXIT_ERROR",error);value("UNCHANGED_V3_EXIT_RESOLVER_USED",used_exit);
 SetLastError(0xE0100005u);resolved_version=px_original_kernel("GetVersionExA",&used_version);error=GetLastError();
 value("UNCHANGED_V3_ORIGINAL_VERSION",(DWORD)(UINT_PTR)resolved_version);value("UNCHANGED_V3_ORIGINAL_VERSION_ERROR",error);value("UNCHANGED_V3_VERSION_RESOLVER_USED",used_version);
 value("UNCHANGED_V3_WIN98_GUARD",px_original_win98());
 memory("IMPORTED_EXITPROCESS",(void *)(UINT_PTR)ExitProcess);memory("DIRECT_EXPORTED_EXITPROCESS",(void *)(UINT_PTR)direct_exit);
 memory("DIRECT_EXPORTED_VERSION",(void *)(UINT_PTR)direct_version);
 module("KERNEL32_EXIT",kernel,(void *)(UINT_PTR)direct_exit);module("KERNEL32_VERSION",kernel,(void *)(UINT_PTR)direct_version);
 module("NATIVE_MAIN_CALLBACK",main,(void *)(UINT_PTR)native_exe_callback);
 module("NATIVE_MAIN_STATIC_CONTEXT",main,&static_context);
 memory("NATIVE_EXE_CALLBACK",(void *)(UINT_PTR)native_exe_callback);memory("NATIVE_EXE_STATIC_CONTEXT",&static_context);memory("STACK_CONTEXT_NEGATIVE",&stack_context);
 manager=LoadLibraryA("C:\\VXDLAB\\M98EXIT.DLL");error=manager?0:GetLastError();value("UNCHANGED_V3_MANAGER_MODULE",(DWORD)(UINT_PTR)manager);value("MANAGER_LOAD_ERROR",error);
 convert.generic=manager?GetProcAddress(manager,"M98ExitInitialize"):NULL;initialize=convert.typed;
 value("UNCHANGED_V3_INITIALIZE_EXPORT",(DWORD)(UINT_PTR)convert.generic);
 if(initialize){SetLastError(0xE0100006u);okay=initialize();error=GetLastError();value("UNCHANGED_V3_INITIALIZE_OK",okay);value("UNCHANGED_V3_INITIALIZE_ERROR",error);}
 text(failed?"STATUS=REPORT_WRITE_FAILED\r\n":"STATUS=GUARD_OBSERVATION_COMPLETE\r\n");
 if(!FlushFileBuffers(report))failed=1;if(!CloseHandle(report))failed=1;
 ExitProcess(failed?21:0);
}
