/* SPDX-License-Identifier: GPL-2.0-only
 * Ordinary native Win98 DLL adapter for the project's preserved API tables.
 * It never loads KernelEx core or writes guest/host registry configuration.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "table.h"

typedef struct provider_image {
    HMODULE module;
    DWORD size,headers,table;
    WORD sections;
    IMAGE_SECTION_HEADER section[16];
} provider_image;
typedef struct provider_context {
    CRITICAL_SECTION lock;
    char directory[MAX_PATH];
    provider_image image[6];
} provider_context;
static const char *const targets[6]={"KERNEL32.DLL","SHELL32.DLL","ADVAPI32.DLL","USER32.DLL","COMCTL32.DLL","SECUR32.DLL"};
static const char *const files[6]={"M98WRAP.DLL","M98SHELL.DLL","M98AD2.DLL","M98USR1.DLL","M98CTL3.DLL","M98SSPI.DLL"};

/* Native x86 M98SSPI's v1 prefix through DecryptMessage. Do not read a host
 * pointer-sized or full modern SDK table, whose later fields are not promised.
 * Slots are one-based here, with version at word zero. */
typedef struct { uint32_t version,slot[26]; } ntwp_sspi32_prefix;
_Static_assert(sizeof(ntwp_sspi32_prefix)==108,"SSPI32 v1 prefix");
_Static_assert(offsetof(ntwp_sspi32_prefix,slot[24])==100 &&
               offsetof(ntwp_sspi32_prefix,slot[25])==104,"SSPI32 Encrypt/Decrypt");
static const unsigned char sspi_slots[13]={1,3,4,6,9,10,11,16,17,20,21,25,26};
static const char *const sspi_names[15]={
    "EnumerateSecurityPackagesA","AcquireCredentialsHandleA","FreeCredentialsHandle",
    "InitializeSecurityContextA","DeleteSecurityContext","ApplyControlToken",
    "QueryContextAttributesA","FreeContextBuffer","QuerySecurityPackageInfoA",
    "ExportSecurityContext","ImportSecurityContextA","EncryptMessage","DecryptMessage",
    "InitSecurityInterfaceA","M98SspiEndInput"
};
struct _SECURITY_FUNCTION_TABLE_A;
typedef struct _SECURITY_FUNCTION_TABLE_A *(WINAPI *init_sspi_fn)(void);

static int read_process(DWORD at,void *out,DWORD count)
{ SIZE_T got=0;return ReadProcessMemory(GetCurrentProcess(),(void *)(UINT_PTR)at,out,count,&got)&&got==count; }
static int image_read(void *opaque,uint32_t at,void *out,uint32_t count,int executable)
{
    provider_image *image=opaque;DWORD base=(DWORD)(UINT_PTR)image->module,rva;unsigned n;
    if (at<base || count>image->size || (rva=at-base)>image->size-count) return 0;
    if(!executable && rva<image->headers && count<=image->headers-rva)return read_process(at,out,count);
    for(n=0;n<image->sections;n++) {
        IMAGE_SECTION_HEADER *s=&image->section[n];DWORD span=s->Misc.VirtualSize;
        if(span<s->SizeOfRawData)span=s->SizeOfRawData;
        if(rva>=s->VirtualAddress && rva-s->VirtualAddress<=span && count<=span-(rva-s->VirtualAddress) &&
           (s->Characteristics&IMAGE_SCN_MEM_READ) && (!executable||(s->Characteristics&IMAGE_SCN_MEM_EXECUTE)))
            return read_process(at,out,count);
    }
    return 0;
}
static int sspi_export_index(const char *name)
{
    unsigned i,n;
    if((UINT_PTR)name<=65535)return -1;
    for(i=0;i<15;i++) {
        for(n=0;n<64 && name[n]==sspi_names[i][n];n++)if(!name[n])return (int)i;
    }
    return -1;
}
static int validate_sspi(provider_image *image,unsigned wanted,uint32_t *address)
{
    ntwp_sspi32_prefix table;uint32_t exports[15];unsigned i,n;unsigned char byte;
    if(wanted>=15 || !image_read(image,image->table,&table,sizeof(table),0) || table.version!=1)return 0;
    for(i=0;i<15;i++) {
        FARPROC api=GetProcAddress(image->module,sspi_names[i]);
        exports[i]=(DWORD)(UINT_PTR)api;
        if(!api || !image_read(image,exports[i],&byte,1,1))return 0;
        if(i<13 && table.slot[sspi_slots[i]-1]!=exports[i])return 0;
    }
    for(n=1;n<=26;n++) {
        for(i=0;i<13 && sspi_slots[i]!=n;i++) {}
        if(i==13 && table.slot[n-1])return 0;
    }
    *address=exports[wanted];return 1;
}
static int open_image(provider_image *image,const char *path,const char *expected)
{
    IMAGE_DOS_HEADER dos;IMAGE_NT_HEADERS32 nt;DWORD base,table;unsigned n;
    typedef const void *(__cdecl *get_table_fn)(void);
    FARPROC api;get_table_fn get_table;unsigned char byte;
    image->module=LoadLibraryA(path);if(!image->module)return 0;
    base=(DWORD)(UINT_PTR)image->module;
    if(!read_process(base,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE ||
       dos.e_lfanew<(LONG)sizeof(dos) || dos.e_lfanew>65536 || base>0xffffffffUL-(DWORD)dos.e_lfanew ||
       !read_process(base+(DWORD)dos.e_lfanew,&nt,sizeof(nt)) || nt.Signature!=IMAGE_NT_SIGNATURE ||
       nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_I386 || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
       nt.FileHeader.SizeOfOptionalHeader!=sizeof(IMAGE_OPTIONAL_HEADER32) ||
       !nt.FileHeader.NumberOfSections || nt.FileHeader.NumberOfSections>16 ||
       !nt.OptionalHeader.SizeOfImage || nt.OptionalHeader.SizeOfImage>4*1024*1024 ||
       nt.OptionalHeader.SizeOfHeaders>nt.OptionalHeader.SizeOfImage ||
       base>0xffffffffUL-nt.OptionalHeader.SizeOfImage)goto bad;
    image->size=nt.OptionalHeader.SizeOfImage;image->headers=nt.OptionalHeader.SizeOfHeaders;
    image->sections=nt.FileHeader.NumberOfSections;table=(DWORD)dos.e_lfanew+sizeof(nt);
    if(table>image->headers || image->sections*sizeof(IMAGE_SECTION_HEADER)>image->headers-table ||
       !read_process(base+table,image->section,image->sections*sizeof(IMAGE_SECTION_HEADER)))goto bad;
    for(n=0;n<image->sections;n++) {
        IMAGE_SECTION_HEADER *s=&image->section[n];DWORD span=s->Misc.VirtualSize;
        if(span<s->SizeOfRawData)span=s->SizeOfRawData;
        if(s->VirtualAddress<image->headers || s->VirtualAddress>image->size ||
           span>image->size-s->VirtualAddress)goto bad;
        {unsigned prior;for(prior=0;prior<n;prior++) {
            IMAGE_SECTION_HEADER *p=&image->section[prior];DWORD old=p->Misc.VirtualSize;
            if(old<p->SizeOfRawData)old=p->SizeOfRawData;
            if(span&&old&&s->VirtualAddress<p->VirtualAddress+old&&p->VirtualAddress<s->VirtualAddress+span)goto bad;
        }}
    }
    if(expected==targets[5]) {
        uint32_t ignored;init_sspi_fn init;
        api=GetProcAddress(image->module,"InitSecurityInterfaceA");
        if(!api || !image_read(image,(DWORD)(UINT_PTR)api,&byte,1,1))goto bad;
        /* The real native provider uses WINAPI and the SDK opaque return type. */
        init=(init_sspi_fn)(void *)api;image->table=(DWORD)(UINT_PTR)init();
        if(!validate_sspi(image,13,&ignored))goto bad;
    } else {
        api=GetProcAddress(image->module,"get_api_table");
        if(!api || !image_read(image,(DWORD)(UINT_PTR)api,&byte,1,1))goto bad;
        /* Cdecl is the published API-library ABI; the provider owns its table. */
        get_table=(get_table_fn)(void *)api;image->table=(DWORD)(UINT_PTR)get_table();
        { uint32_t ignored;
          if(ntwp_find_table(image_read,image,image->table,expected,"__NTWP_VALIDATE_ONLY__",0,&ignored)==NTWP_INVALID)goto bad;
        }
    }
    return 1;
bad:
    FreeLibrary(image->module);image->module=NULL;SetLastError(ERROR_BAD_EXE_FORMAT);return 0;
}
static int equal_module(const char *a,const char *b)
{ unsigned n;for(n=0;n<32;n++){unsigned x=(BYTE)a[n],y=(BYTE)b[n];if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;if(x!=y)return 0;if(!x)return 1;}return 0; }

void *WINAPI NtwOpenProviderDirectoryA(const char *directory)
{
    provider_context *ctx;unsigned n;
    if(!directory || !((directory[0]>='a'&&directory[0]<='z')||(directory[0]>='A'&&directory[0]<='Z')) ||
       directory[1]!=':' || directory[2]!='\\') {SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
    for(n=0;n<MAX_PATH-16 && directory[n];n++)if(directory[n]=='/'||directory[n]=='"'||directory[n]=='*'||directory[n]=='?'){SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
    if(!n || n>=MAX_PATH-16){SetLastError(ERROR_FILENAME_EXCED_RANGE);return NULL;}
    ctx=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*ctx));if(!ctx){SetLastError(ERROR_NOT_ENOUGH_MEMORY);return NULL;}
    lstrcpyA(ctx->directory,directory);if(ctx->directory[n-1]!='\\'){ctx->directory[n]='\\';ctx->directory[n+1]=0;}
    InitializeCriticalSection(&ctx->lock);return ctx;
}
FARPROC WINAPI NtwFindProviderExportA(void *context,const char *dll,const char *name)
{
    provider_context *ctx=context;unsigned n;int sspi=-1;FARPROC result=NULL;DWORD error=ERROR_PROC_NOT_FOUND;
    if(!ctx||!dll||!name){SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
    for(n=0;n<6;n++)if(equal_module(dll,targets[n]))break;
    if(n==6){SetLastError(ERROR_MOD_NOT_FOUND);return NULL;}
    if(n==5 && (sspi=sspi_export_index(name))<0){SetLastError(ERROR_PROC_NOT_FOUND);return NULL;}
    EnterCriticalSection(&ctx->lock);
    if(!ctx->image[n].module){char path[MAX_PATH];lstrcpyA(path,ctx->directory);lstrcatA(path,files[n]);
        if(!open_image(&ctx->image[n],path,targets[n])){error=GetLastError();goto done;}}
    if(n==5) {
        uint32_t address=0;
        /* Revalidate without reinitializing or unloading a cached module behind
         * existing pointers. A damaged provider stays pinned until close. */
        if(validate_sspi(&ctx->image[n],(unsigned)sspi,&address))result=(FARPROC)(UINT_PTR)address;
        else error=ERROR_BAD_EXE_FORMAT;
    } else {uint32_t address=0;int found=ntwp_find_table(image_read,&ctx->image[n],ctx->image[n].table,targets[n],
        (UINT_PTR)name<=65535?NULL:name,(UINT_PTR)name<=65535?(uint16_t)(UINT_PTR)name:0,&address);
     if(found==NTWP_FOUND)result=(FARPROC)(UINT_PTR)address;else if(found==NTWP_INVALID)error=ERROR_BAD_EXE_FORMAT;}
done:
    LeaveCriticalSection(&ctx->lock);if(!result)SetLastError(error);return result;
}
void WINAPI NtwCloseProviderDirectory(void *context)
{
    provider_context *ctx=context;unsigned n;if(!ctx)return;
    /* Caller must have joined all pointer users/callbacks and released every
     * provider-owned context, credential and SSPI buffer before this call. */
    for(n=0;n<6;n++)if(ctx->image[n].module)FreeLibrary(ctx->image[n].module);
    DeleteCriticalSection(&ctx->lock);HeapFree(GetProcessHeap(),0,ctx);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved)
{(void)instance;(void)reason;(void)reserved;return TRUE;}
