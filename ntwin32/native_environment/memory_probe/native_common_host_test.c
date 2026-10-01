/* SPDX-License-Identifier: GPL-2.0-only -- clobbering API callback controls. */
#include "native_common.h"
#include "../../process_exit/original_kernel.h"
#include "../../process_exit/win98_guard.h"
#include "../../process_exit/win98_export.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static DWORD error_state;static unsigned checks,cases,queries;static unsigned char kernel[4096];
static int os_ok=1,resolver_ok=1,image_ok=1,export_ok=1,equal_eat=1,code_ok=1,query_fail,query_write,io_fail;
#define CHECK(x) do {checks++;if(!(x)){fprintf(stderr,"line %u: %s\n",__LINE__,#x);exit(1);}} while(0)
DWORD GetLastError(void){return error_state;}
void SetLastError(DWORD e){error_state=e;}
HANDLE CreateFileA(const char *p,DWORD a,DWORD b,void *c,DWORD d,DWORD e,HANDLE f)
{(void)p;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;error_state=1001;return io_fail==1?INVALID_HANDLE_VALUE:(HANDLE)kernel;}
BOOL WriteFile(HANDLE h,const void *p,DWORD n,DWORD *w,void *o)
{(void)h;(void)p;(void)o;error_state=1002;*w=io_fail==2?n-1:n;return io_fail!=3;}
BOOL FlushFileBuffers(HANDLE h){(void)h;error_state=1003;return io_fail!=4;}
BOOL CloseHandle(HANDLE h){(void)h;error_state=1004;return io_fail!=5;}
HMODULE GetModuleHandleA(const char *name){(void)name;error_state=1005;return kernel;}
size_t VirtualQuery(const void *p,MEMORY_BASIC_INFORMATION *q,size_t n)
{(void)p;queries++;error_state=1006;if(query_fail==(int)queries)return 0;
 q->BaseAddress=kernel;q->AllocationBase=kernel;q->RegionSize=sizeof(kernel);q->State=MEM_COMMIT;q->Protect=query_write==(int)queries?PAGE_READWRITE:PAGE_READONLY;return n;}
int px_original_win98(void){error_state=1007;return os_ok;}
FARPROC px_original_kernel(const char *name,int *route){(void)name;error_state=1008;*route=1;return resolver_ok?(FARPROC)(void *)(kernel+128):NULL;}
int px_kernel_image(px_image *i,const void *p,size_t n,uintptr_t b)
{(void)p;(void)n;error_state=1009;i->base=b;i->bytes=sizeof(kernel);return image_ok;}
int px_named_export(const px_image *i,const void *p,size_t n,const char *name,px_read_image read,void *opaque,uintptr_t *exact)
{const unsigned char *got;(void)p;(void)n;(void)name;error_state=1010;got=read(opaque,i->base+64,16);CHECK(GetLastError()==1010);if(!got)return 0;*exact=i->base+(equal_eat?128:129);return export_ok;}
int px_guard_code(const px_image *i,uintptr_t p,const px_page *q,int win98)
{(void)i;(void)p;(void)q;CHECK(win98==1);error_state=1011;return code_ok;}
static void expect(int success)
{mp_api_identity identity,old;FARPROC p;memset(&identity,0xa5,sizeof(identity));old=identity;queries=0;SetLastError(0x51a2b3c4u);
 p=mp_original("GlobalMemoryStatus",&identity);CHECK(!!p==success);CHECK(GetLastError()==0x51a2b3c4u);
 if(success){CHECK(identity.rva==128&&identity.route==1&&identity.protection==PAGE_READONLY);}else CHECK(memcmp(&identity,&old,sizeof(old))==0);}
int main(void)
{
 mp_report r;int x;
 cases++;expect(1);
 cases++;os_ok=0;expect(0);os_ok=1;resolver_ok=0;expect(0);resolver_ok=1;
 cases++;image_ok=0;expect(0);image_ok=1;export_ok=0;expect(0);export_ok=1;equal_eat=0;expect(0);equal_eat=1;code_ok=0;expect(0);code_ok=1;
 cases++;for(x=1;x<=3;x++){query_fail=x;expect(0);}query_fail=0;
 cases++;query_write=1;expect(0);query_write=0;
 cases++;SetLastError(0x51a2b3c4u);CHECK(!mp_original("GlobalMemoryStatus",NULL));CHECK(GetLastError()==0x51a2b3c4u);
 cases++;CHECK(mp_report_open(&r,"mock"));SetLastError(77);mp_value(&r,"TEST_0",UINT32_MAX);CHECK(GetLastError()==77&&!r.failed);CHECK(mp_report_close(&r));CHECK(GetLastError()==77);
 cases++;for(x=2;x<=4;x++){io_fail=x;CHECK(mp_report_open(&r,"mock"));SetLastError(78);mp_value(&r,"TEST",1);CHECK(GetLastError()==78&&r.failed);CHECK(!mp_report_close(&r));CHECK(GetLastError()==78);}io_fail=0;
 cases++;CHECK(mp_report_open(&r,"mock"));SetLastError(79);mp_value(&r,"bad",1);CHECK(r.failed&&GetLastError()==79);CHECK(!mp_report_close(&r));CHECK(GetLastError()==79);
 cases++;CHECK(mp_report_open(&r,"mock"));io_fail=5;SetLastError(80);CHECK(!mp_report_close(&r));CHECK(GetLastError()==80);io_fail=1;CHECK(!mp_report_open(&r,"mock"));
 printf("RESULT PASS cases=%u checks=%u clobbering_callbacks=true native_pending=true\n",cases,checks);return 0;
}
