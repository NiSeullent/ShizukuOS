/* SPDX-License-Identifier: GPL-2.0-only
 * Exact original Chromium core: native read-only mapping and structure only.
 * Never loads a target module, resolves target imports or invokes target code.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "pe.h"
#include "sha256.h"
#define CORE "C:\\CHRLAB\\CHROME.DLL"
#define LOG "C:\\CHRLAB\\CHRLARGE.LOG"
#define CORE_BYTES 283207168u
#define IMAGE_BYTES 284966912u
#define RELOCATION_COUNT 4664381u
#define CORE_SHA "f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158"
static HANDLE report = INVALID_HANDLE_VALUE;
static int io_failed;
static BYTE block[65536];
static np_image image;
static void text(const char *s) {
 DWORD n=0,w=0;while(s[n])n++;
 if(!WriteFile(report,s,n,&w,NULL)||w!=n)io_failed=1;
}
static void value(const char *label,DWORD v) {
 char b[9];unsigned i;for(i=0;i<8;i++)b[i]="0123456789ABCDEF"[(v>>(28-i*4))&15];b[8]=0;
 text(label);text("=");text(b);text("\r\n");
}
static int equal(const char *a,const char *b) {while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int flush(void) {if(io_failed||!FlushFileBuffers(report)){io_failed=1;return 0;}return 1;}
static int checked_hash(HANDLE file) {
 sha256_ctx h;BYTE sum[32];char hex[65];DWORD n,total=0;
 sha256_init(&h);
 for(;;){
  if(!ReadFile(file,block,sizeof(block),&n,NULL)){value("READ_ERROR",GetLastError());return 0;}
  if(!n)break;
  if(total>CORE_BYTES||n>CORE_BYTES-total){text("READ_SIZE_OVERFLOW=1\r\n");return 0;}
  sha256_update(&h,block,n);total+=n;
 }
 sha256_final(&h,sum);sha256_hex(sum,hex);
 text("ACTUAL_FILE_SHA256=");text(hex);text("\r\n");value("ACTUAL_FILE_BYTES",total);
 return total==CORE_BYTES&&equal(hex,CORE_SHA)&&flush();
}
static int count_relocation(void *context,uint32_t rva) {
 uint32_t *count=context;(void)rva;(*count)++;return 1;
}
static DWORD inspect(void) {
 HANDLE file=INVALID_HANDLE_VALUE,mapping=NULL;const void *view=NULL;
 OSVERSIONINFOA os={0};DWORD low,high=0,error,result=3;uint32_t imports=0,relocations=0;
 const char *reason=NULL;np_tls_info tls;
 np_parse_limits limits={CORE_BYTES,IMAGE_BYTES,CORE_BYTES+IMAGE_BYTES};
 os.dwOSVersionInfoSize=sizeof(os);
 if(!GetVersionExA(&os)){value("NATIVE_VERSION_ERROR",GetLastError());goto done;}
 value("NATIVE_OS_PLATFORM",os.dwPlatformId);value("NATIVE_OS_MAJOR",os.dwMajorVersion);
 value("NATIVE_OS_MINOR",os.dwMinorVersion);value("NATIVE_OS_BUILD",os.dwBuildNumber&65535);
 if(os.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||os.dwMajorVersion!=4||os.dwMinorVersion!=10||
    (os.dwBuildNumber&65535)!=2222)goto done;
 file=CreateFileA(CORE,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(file==INVALID_HANDLE_VALUE){value("OPEN_ERROR",GetLastError());goto done;}
 SetLastError(0);low=GetFileSize(file,&high);error=GetLastError();
 if(low==INVALID_FILE_SIZE&&error){value("FILE_SIZE_ERROR",error);goto done;}
 if(high||low!=CORE_BYTES||!checked_hash(file))goto done;
 mapping=CreateFileMappingA(file,NULL,PAGE_READONLY,0,0,NULL);
 if(!mapping){value("MAPPING_ERROR",GetLastError());goto done;}
 view=MapViewOfFile(mapping,FILE_MAP_READ,0,0,CORE_BYTES);
 if(!view){value("VIEW_ERROR",GetLastError());goto done;}
 value("READONLY_NATIVE_VIEW",(DWORD)(UINT_PTR)view);
 value("DEFAULT_FILE_CAP",NP_FILE_LIMIT);value("DEFAULT_IMAGE_CAP",NP_IMAGE_LIMIT);
 if(np_parse(&image,view,CORE_BYTES,&reason)){text("DEFAULT_CAP_UNEXPECTED_ACCEPTANCE=1\r\n");goto done;}
 text("DEFAULT_REFUSAL=");text(reason?reason:"UNAVAILABLE");text("\r\n");
 if(!np_parse_limited(&image,view,CORE_BYTES,&limits,&reason)){
  text("LIMITED_PARSE_ERROR=");text(reason?reason:"UNAVAILABLE");text("\r\n");goto done;
 }
 value("DECLARED_IMAGE_BYTES",image.size);value("EXACT_LOGICAL_BUDGET",limits.total_bytes);
 if(image.size!=IMAGE_BYTES||!np_imports(&image,1,NULL,NULL,&imports,&reason))goto structural_error;
 value("IMPORT_RECORDS_CHECKED",imports);if(imports!=1301u)goto done;
 if(np_relocations(&image,NULL,NULL,&reason)||!equal(reason?reason:"","RELOC_LIMIT")){
  text("DEFAULT_RELOC_LIMIT_UNEXPECTED_RESULT=1\r\n");goto done;
 }
 text("DEFAULT_RELOCATION_REFUSED=RELOC_LIMIT\r\n");
 if(!np_relocations_limited(&image,count_relocation,&relocations,RELOCATION_COUNT,&reason))goto structural_error;
 value("HIGHLOW_ENTRIES_CHECKED",relocations);if(relocations!=RELOCATION_COUNT)goto done;
 if(!np_tls(&image,&tls,&reason))goto structural_error;
 value("TLS_STRUCTURE_PRESENT",tls.present);value("TLS_CALLBACKS_NOT_INVOKED",tls.count);
 if(np_execution_profile(&image,&reason)){text("EXECUTION_GATE_UNEXPECTED_ACCEPTANCE=1\r\n");goto done;}
 text("EXECUTION_PROFILE_STILL_REFUSED=1\r\n");
 if(np_runtime_profile(&image,&reason)){text("RUNTIME_GATE_UNEXPECTED_ACCEPTANCE=1\r\n");goto done;}
 text("RUNTIME_PROFILE_STILL_REFUSED=1\r\nSTATUS=NATIVE_READONLY_STRUCTURE_PASS\r\n");result=0;goto done;
structural_error:
 text("STRUCTURAL_ERROR=");text(reason?reason:"UNAVAILABLE");text("\r\n");
done:
 if(view&&!UnmapViewOfFile(view)){value("UNMAP_ERROR",GetLastError());result=3;}
 if(mapping&&!CloseHandle(mapping)){value("MAPPING_CLOSE_ERROR",GetLastError());result=3;}
 if(file!=INVALID_HANDLE_VALUE&&!CloseHandle(file)){value("FILE_CLOSE_ERROR",GetLastError());result=3;}
 return io_failed?31:result;
}
void WINAPI entry(void) {
 DWORD code;
 report=CreateFileA(LOG,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 text("SCOPE=ORIGINAL_CHROMIUM_NATIVE_READONLY_STRUCTURE_ONLY\r\nTARGET_ENTRY_CALLS=0\r\nTARGET_IMPORTS_RESOLVED=0\r\nTARGET_TLS_CALLBACK_CALLS=0\r\nAPPLICATION_FUNCTIONALITY_VERIFIED=0\r\n");
 if(!flush())code=31;else code=inspect();value("SELECTED_EXIT_CODE",code);
 if(!flush())code=31;if(!CloseHandle(report))code=31;
 ExitProcess(io_failed?31:code);
}
