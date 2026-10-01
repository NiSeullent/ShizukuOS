/* SPDX-License-Identifier: GPL-2.0-only -- OWN closed fixture, not Chromium. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "win32_adapter.h"
#include "../process_exit/original_kernel.h"
#include "sha256.h"
#include "resource_pins.h"
static HANDLE report=INVALID_HANDLE_VALUE;
static int io_failed;
static nr_resources resources;
static nra_adapter adapter;
static np_image image;
static uint8_t *mapped;
static void value(const char *name,DWORD v)
{
 char out[128];DWORD n=0,w=0;unsigned i;
 while(*name&&n<sizeof(out)-12)out[n++]=*name++;
 out[n++]='=';for(i=0;i<8;i++)out[n++]="0123456789ABCDEF"[(v>>(28-i*4))&15];out[n++]='\r';out[n++]='\n';
 if(!WriteFile(report,out,n,&w,NULL)||w!=n||!FlushFileBuffers(report))io_failed=1;
}
static int equal(const void *a,const void *b,DWORD n)
{const BYTE *p=a,*q=b;while(n--)if(*p++!=*q++)return 0;return 1;}
static void copy(void *a,const void *b,DWORD n)
{BYTE *p=a;const BYTE *q=b;while(n--)*p++=*q++;}
static const uint8_t *read_memory(void *unused,const void *pointer,uint32_t bytes)
{
 uintptr_t at=(uintptr_t)pointer;uint32_t left=bytes;DWORD saved=GetLastError();
 const uint8_t *answer=pointer;(void)unused;
 if(!pointer||at>UINTPTR_MAX-bytes){answer=NULL;goto done;}
 while(left){MEMORY_BASIC_INFORMATION info;uint32_t delta,part;
  if(VirtualQuery((const void *)at,&info,sizeof(info))!=sizeof(info)||info.State!=MEM_COMMIT||
     (info.Protect!=PAGE_READONLY&&info.Protect!=PAGE_READWRITE&&info.Protect!=PAGE_WRITECOPY&&
      info.Protect!=PAGE_EXECUTE_READ&&info.Protect!=PAGE_EXECUTE_READWRITE&&info.Protect!=PAGE_EXECUTE_WRITECOPY)||
     at<(uintptr_t)info.BaseAddress){answer=NULL;goto done;}
  delta=(uint32_t)(at-(uintptr_t)info.BaseAddress);if(delta>=info.RegionSize){answer=NULL;goto done;}
  part=(uint32_t)info.RegionSize-delta;if(part>left)part=left;at+=part;left-=part;
 }
done:
 SetLastError(saved);return answer;
}
static void error_callback(void *unused,uint32_t e){(void)unused;SetLastError(e);}
static int success_last_error(void *base)
{
 const DWORD sentinel=0x51a2b3c4u;DWORD observed;int okay;void *info=NULL,*data=NULL;
 static const uint16_t name_w[]={'n','a','m','e','d',0};
 /* Capture actual thread LastError immediately after each single call, before
  * value()/WriteFile/FlushFileBuffers or any other API can change it. Named
  * Find calls and Load force the native VirtualQuery callback to execute. */
#define OBSERVE(tag,expression) do {SetLastError(sentinel);okay=!!(expression);observed=GetLastError();value(tag,observed);if(!okay||observed!=sentinel)return 0;} while(0)
 OBSERVE("SUCCESS_FIND_EX_A_LAST_ERROR",(info=nra_FindResourceExA(base,MAKEINTRESOURCEA(10),"named",1033))!=NULL);
 OBSERVE("SUCCESS_FIND_A_LAST_ERROR",nra_FindResourceA(base,"named",MAKEINTRESOURCEA(10))==info);
 OBSERVE("SUCCESS_FIND_EX_W_LAST_ERROR",nra_FindResourceExW(base,(const uint16_t *)(uintptr_t)10,name_w,1033)==info);
 OBSERVE("SUCCESS_FIND_W_LAST_ERROR",nra_FindResourceW(base,name_w,(const uint16_t *)(uintptr_t)10)==info);
 OBSERVE("SUCCESS_SIZE_LAST_ERROR",nra_SizeofResource(base,info)==6);
 OBSERVE("SUCCESS_LOAD_LAST_ERROR",(data=nra_LoadResource(base,info))!=NULL);
 OBSERVE("SUCCESS_LOCK_LAST_ERROR",nra_LockResource(data)==data);
 OBSERVE("SUCCESS_FREE_LAST_ERROR",!nra_FreeResource(data));
 OBSERVE("SUCCESS_REPEAT_FREE_LAST_ERROR",!nra_FreeResource(data));
 OBSERVE("SUCCESS_RETAINED_LOCK_LAST_ERROR",nra_LockResource(data)==data);
 OBSERVE("REFUSED_RANGE_CALLBACK_LAST_ERROR",read_memory(NULL,NULL,1)==NULL);
 OBSERVE("OVERFLOW_RANGE_CALLBACK_LAST_ERROR",read_memory(NULL,(void *)UINTPTR_MAX,2)==NULL);
#undef OBSERVE
 value("ACTUAL_THREAD_LAST_ERROR_SENTINELS",12);return !io_failed;
}
static int relocate(void *unused,uint32_t rva)
{uint32_t v=np_u32(mapped+rva)+(uint32_t)(UINT_PTR)mapped-image.base;(void)unused;copy(mapped+rva,&v,4);return 1;}
static int read_fixture(HANDLE file,uint8_t *bytes)
{
 sha256_ctx hash;BYTE digest[32],block[1];char actual[65];DWORD at=0,n,error;unsigned i;
 sha256_init(&hash);
 while(at<RR_FIXTURE_BYTES){
  if(!ReadFile(file,bytes+at,RR_FIXTURE_BYTES-at,&n,NULL)){error=GetLastError();value("FIXTURE_READ_ERROR",error);return 0;}
  if(!n||n>RR_FIXTURE_BYTES-at)return 0;sha256_update(&hash,bytes+at,n);at+=n;
 }
 if(!ReadFile(file,block,1,&n,NULL)){error=GetLastError();value("FIXTURE_EOF_ERROR",error);return 0;}
 if(n)return 0;sha256_final(&hash,digest);sha256_hex(digest,actual);
 for(i=0;i<64;i++)if(actual[i]!=RR_FIXTURE_SHA[i])return 0;
 value("FIXTURE_EXACT_SHA_AND_EOF",1);return !io_failed;
}
static int native_oracle(const char *path)
{
 typedef HMODULE (WINAPI *load_fn)(LPCSTR);
 typedef BOOL (WINAPI *unload_fn)(HMODULE);
 typedef HRSRC (WINAPI *find_ex_fn)(HMODULE,LPCSTR,LPCSTR,WORD);
 typedef HRSRC (WINAPI *find_fn)(HMODULE,LPCSTR,LPCSTR);
 typedef HGLOBAL (WINAPI *resource_load_fn)(HMODULE,HRSRC);
 typedef LPVOID (WINAPI *lock_fn)(HGLOBAL);
 typedef DWORD (WINAPI *size_fn)(HMODULE,HRSRC);
 typedef BOOL (WINAPI *free_fn)(HGLOBAL);
 load_fn load=(load_fn)(void *)px_original_kernel("LoadLibraryA",NULL);
 unload_fn unload=(unload_fn)(void *)px_original_kernel("FreeLibrary",NULL);
 find_ex_fn find_ex=(find_ex_fn)(void *)px_original_kernel("FindResourceExA",NULL);
 find_fn find=(find_fn)(void *)px_original_kernel("FindResourceA",NULL);
 resource_load_fn resource_load=(resource_load_fn)(void *)px_original_kernel("LoadResource",NULL);
 lock_fn lock=(lock_fn)(void *)px_original_kernel("LockResource",NULL);
 size_fn size=(size_fn)(void *)px_original_kernel("SizeofResource",NULL);
 free_fn free_resource=(free_fn)(void *)px_original_kernel("FreeResource",NULL);
 static const BYTE expected[]={0x52,0x4e,0x41,0x31,0x38,0,0x98,0};
 HMODULE native;HRSRC info,named;HGLOBAL data;DWORD error;int okay=0;
 if(!load||!unload||!find_ex||!find||!resource_load||!lock||!size||!free_resource)return 0;
 native=load(path);if(!native){error=GetLastError();value("OEM_FIXTURE_LOAD_ERROR",error);return 0;}
 info=find_ex(native,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033);
 if(!info){error=GetLastError();value("OEM_EXACT_RESOURCE_FIND_ERROR",error);goto done;}
 data=resource_load(native,info);
 if(!data||size(native,info)!=sizeof(expected)||!lock(data)||!equal(lock(data),expected,sizeof(expected)))goto done;
 value("OEM_EXACT_LANGUAGE_PAYLOAD_MATCH",1);
 if(find_ex(native,"#10","#101",1033)!=info)goto done;value("OEM_DECIMAL_ID_MATCH",1);
 if(find(native,MAKEINTRESOURCEA(101),MAKEINTRESOURCEA(10))!=info)goto done;value("OEM_SOLE_LANGUAGE_DEFAULT_MATCH",1);
 if(find_ex(native,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),0)!=info)goto done;value("OEM_SOLE_LANGUAGE_NEUTRAL_EX_MATCH",1);
 named=find(native,"named",MAKEINTRESOURCEA(10));if(!named)goto done;value("OEM_ASCII_CASE_INSENSITIVE_NAME",1);
 if(free_resource(data)||free_resource(data)||lock(data)!=(void *)data||!equal(lock(data),expected,sizeof(expected)))goto done;
 value("OEM_PE_FREE_NOOP_BORROWED_DATA_SURVIVES",1);okay=1;
done:
 if(!unload(native)){error=GetLastError();value("OEM_FIXTURE_UNLOAD_ERROR",error);okay=0;}
 return okay&&!io_failed;
}
void WINAPI entry(void)
{
 const char *why=0;HANDLE file=INVALID_HANDLE_VALUE;uint8_t *source=NULL;
 DWORD code=3,n,high=0,old,error,passed=0;uint32_t rva=0;const char *forward=0;int registered=0;
 typedef uint32_t (NRA_CALL *fixture_fn)(void *,const nra_api *);
 nra_api api={nra_FindResourceExA,nra_FindResourceExW,nra_FindResourceA,nra_FindResourceW,
  nra_LoadResource,nra_LockResource,nra_SizeofResource,nra_FreeResource};
 report=CreateFileA("C:\\VXDLAB\\RRPROBE.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 value("OWN_RESOURCE_PROBE_ENTRY",1);value("CHROMIUM_ENTRY_CALLS",0);value("CHROMIUM_APPLICATION_ACCEPTED",0);
 if(!px_original_win98()){value("ACTUAL_ORIGINAL_WIN98_GUARD",0);goto done;}
 value("ACTUAL_ORIGINAL_WIN98_GUARD",1);
 file=CreateFileA("C:\\VXDLAB\\RRFIX.DLL",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){error=GetLastError();value("FIXTURE_OPEN_ERROR",error);goto done;}
 SetLastError(0);n=GetFileSize(file,&high);error=GetLastError();
 if((n==INVALID_FILE_SIZE&&error)||high||n!=RR_FIXTURE_BYTES)goto done;
 source=HeapAlloc(GetProcessHeap(),0,n);if(!source||!read_fixture(file,source)||!np_parse(&image,source,n,&why))goto done;
 if(!(image.characteristics&0x2000)||image.entry||image.directory[9][0]||image.directory[1][0]||
    !np_runtime_profile(&image,&why)||!nr_parse(&image,&resources,&why)||resources.count!=4)goto done;
 value("CLOSED_FIXTURE_NO_DLL_ENTRY_TLS_OR_IMPORTS",1);
 if(!native_oracle("C:\\VXDLAB\\RRFIX.DLL"))goto done;
 mapped=VirtualAlloc((void *)(UINT_PTR)image.base,image.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!mapped)mapped=VirtualAlloc(NULL,image.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!mapped||(UINT_PTR)mapped>0xffffffffu-image.size)goto done;
 copy(mapped,source,image.headers);
 for(n=0;n<image.sections;n++){const np_section *s=&image.section[n];if(s->bytes)copy(mapped+s->va,source+s->raw,s->bytes);}
 if(!np_relocations(&image,relocate,NULL,&why)||!VirtualProtect(mapped,image.size,PAGE_READONLY,&old)||
    !FlushInstructionCache(GetCurrentProcess(),mapped,image.size))goto done;
 if(!nra_init(&adapter,read_memory,error_callback,NULL)||!nra_register(&adapter,&resources,mapped,image.size,1)||!nra_bind(&adapter))goto done;
 registered=1;value("EXPLICIT_MAPPED_RESOURCE_MODULE_REGISTERED",1);
 if(!success_last_error(mapped))goto done;
 if(!np_export(&image,"ResourceFixtureRun",0,&rva,&forward,&why)||!rva||forward||!np_memory(&image,rva,1,1))goto done;
 passed=((fixture_fn)(void *)(mapped+rva))(mapped,&api);
 value("OWN_MAPPED_RESOURCE_CONSUMER_CALLS",1);value("OWN_MAPPED_RESOURCE_CONSUMER_CHECKS",passed);
 if(passed!=23||io_failed)goto done;
 {void *info=nra_FindResourceExA(mapped,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033),*data;
  if(!info||(data=nra_LoadResource(mapped,info))==NULL||nra_LockResource(data)!=data)goto done;
  SetLastError(0);if(nra_LockResource(info)||GetLastError()!=ERROR_INVALID_HANDLE)goto done;
  value("INFORMATION_DATA_HANDLE_DISTINCTION",1);
  if(!nra_unregister(&adapter,mapped))goto done;registered=0;
  SetLastError(0);if(nra_LockResource(data)||GetLastError()!=ERROR_INVALID_HANDLE)goto done;
  value("UNREGISTERED_DATA_HANDLE_REJECTED",1);
 }
 code=0;
done:
 if(registered&&!nra_unregister(&adapter,mapped))code=3;nra_unbind(&adapter);
 if(mapped&&!VirtualFree(mapped,0,MEM_RELEASE)){error=GetLastError();value("MAPPING_FREE_ERROR",error);code=3;}
 if(source&&!HeapFree(GetProcessHeap(),0,source)){error=GetLastError();value("SOURCE_FREE_ERROR",error);code=3;}
 if(file!=INVALID_HANDLE_VALUE&&!CloseHandle(file)){error=GetLastError();value("FIXTURE_CLOSE_ERROR",error);code=3;}
 value("PROBE_SELECTED_RESULT",code);value("PROBE_OWN_OS_EXIT_REQUIRES_OUTER",1);
 if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?31:code);
}
