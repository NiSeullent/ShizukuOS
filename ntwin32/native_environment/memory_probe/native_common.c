/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_common.h"
#include "../../process_exit/original_kernel.h"
#include "../../process_exit/win98_guard.h"
#include "../../process_exit/win98_export.h"
int mp_report_open(mp_report *r,const char *path)
{r->failed=0;r->file=CreateFileA(path,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);return r->file!=INVALID_HANDLE_VALUE;}
void mp_value(mp_report *r,const char *name,DWORD value)
{
 char line[64];DWORD written=0,error;size_t n;DWORD saved=GetLastError();
 n=mp_line(line,sizeof(line),name,value);
 if(!n||!WriteFile(r->file,line,(DWORD)n,&written,NULL)||written!=n){error=GetLastError();(void)error;r->failed=1;}
 else if(!FlushFileBuffers(r->file)){error=GetLastError();(void)error;r->failed=1;}
 SetLastError(saved);
}
int mp_report_close(mp_report *r)
{DWORD saved=GetLastError();if(!CloseHandle(r->file))r->failed=1;r->file=INVALID_HANDLE_VALUE;SetLastError(saved);return !r->failed;}
static const unsigned char *read_native(void *opaque,uintptr_t address,size_t bytes)
{
 const px_image *image=opaque;DWORD saved=GetLastError();uintptr_t at=address;size_t left=bytes;
 const unsigned char *answer=NULL;
 if(!bytes||address<image->base||address-image->base>=image->bytes||bytes>image->bytes-(address-image->base))goto done;
 while(left){MEMORY_BASIC_INFORMATION q;size_t delta,part;
  if(VirtualQuery((void *)at,&q,sizeof(q))!=sizeof(q)||q.AllocationBase!=(void *)image->base||q.State!=MEM_COMMIT||
    (q.Protect!=PAGE_READONLY&&q.Protect!=PAGE_READWRITE&&q.Protect!=PAGE_WRITECOPY&&q.Protect!=PAGE_EXECUTE_READ&&q.Protect!=PAGE_EXECUTE_READWRITE&&q.Protect!=PAGE_EXECUTE_WRITECOPY)||at<(uintptr_t)q.BaseAddress)goto done;
  delta=at-(uintptr_t)q.BaseAddress;if(delta>=q.RegionSize)goto done;part=q.RegionSize-delta;if(part>left)part=left;at+=part;left-=part;
 }
 answer=(const unsigned char *)address;
done:SetLastError(saved);return answer;
}
FARPROC mp_original(const char *name,mp_api_identity *identity)
{
 DWORD saved=GetLastError();FARPROC resolved=NULL,answer=NULL;HMODULE kernel;MEMORY_BASIC_INFORMATION h,q;
 px_image image;px_page page;uintptr_t exact=0;size_t available;int route=0;
 if(!identity||!px_original_win98())goto done;
 resolved=px_original_kernel(name,&route);kernel=GetModuleHandleA("KERNEL32.DLL");
 if(!resolved||!kernel||VirtualQuery(kernel,&h,sizeof(h))!=sizeof(h)||h.AllocationBase!=kernel||h.BaseAddress!=kernel||h.State!=MEM_COMMIT||
    (h.Protect!=PAGE_READONLY&&h.Protect!=PAGE_EXECUTE_READ))goto done;
 available=h.RegionSize<4096?h.RegionSize:4096;
 if(!px_kernel_image(&image,kernel,available,(uintptr_t)kernel)||
    !px_named_export(&image,kernel,available,name,read_native,&image,&exact)||exact!=(uintptr_t)resolved||
    VirtualQuery((void *)(UINT_PTR)resolved,&q,sizeof(q))!=sizeof(q))goto done;
 page.allocation=(uintptr_t)q.AllocationBase;page.base=(uintptr_t)q.BaseAddress;page.bytes=q.RegionSize;page.state=q.State;page.protection=q.Protect;
 if(!px_guard_code(&image,exact,&page,1))goto done;
 identity->pointer=(DWORD)exact;identity->kernel=(DWORD)(UINT_PTR)kernel;identity->rva=(DWORD)(exact-(uintptr_t)kernel);
 identity->route=(DWORD)route;identity->page_base=(DWORD)(UINT_PTR)q.BaseAddress;identity->page_bytes=q.RegionSize;identity->protection=q.Protect;answer=resolved;
done:SetLastError(saved);return answer;
}
void mp_identity(mp_report *r,const mp_api_identity *i)
{mp_value(r,"API_POINTER",i->pointer);mp_value(r,"NATIVE_KERNEL_BASE",i->kernel);mp_value(r,"NATIVE_NAMED_EXPORT_RVA",i->rva);
 mp_value(r,"ORIGINAL_RESOLVER_SDK_ROUTE",i->route);mp_value(r,"NATIVE_CODE_PAGE_BASE",i->page_base);mp_value(r,"NATIVE_CODE_PAGE_BYTES",i->page_bytes);
 mp_value(r,"NATIVE_CODE_PROTECTION",i->protection);mp_value(r,"EXACT_NAMED_EAT_NATIVE_EXECUTABLE",1);}
