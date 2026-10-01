/* SPDX-License-Identifier: GPL-2.0-only -- closed caller for actual resource ABI.
 * This fixture has no DLL entry, TLS, OS imports or allocator. It calls only the
 * explicitly supplied stdcall facade. Native probe executes this OWN fixture
 * only after root releases guest testing, never any Chromium code.
 */
#include "win32_adapter.h"
static int same(const uint8_t *p,const uint8_t *q,uint32_t n)
{while(n--)if(*p++!=*q++)return 0;return 1;}
uint32_t NRA_CALL ResourceFixtureRun(void *module,const nra_api *api)
{
 static const uint8_t numeric[]={0x52,0x4e,0x41,0x31,0x38,0,0x98,0};
 static const uint8_t named[]={0x4e,0x41,0x4d,0x45,0x44,0};
 static const uint16_t name_w[]={'n','a','m','e','d',0};
 void *info,*data,*again;uint32_t passed=0;
#define CHECK(x) do {if(!(x))return 0x80000000u|passed;passed++;} while(0)
 CHECK(api&&api->find_ex_a&&api->find_ex_w&&api->find_a&&api->find_w&&api->load&&api->lock&&api->size&&api->free_resource);
 info=api->find_ex_a(module,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,1033);CHECK(info);
 CHECK(api->size(module,info)==8);
 data=api->load(module,info);CHECK(data);
 CHECK(api->lock(data)==data&&same(data,numeric,sizeof(numeric)));
 again=api->load(module,info);CHECK(again==data);
 CHECK(!api->free_resource(data));CHECK(!api->free_resource(data));
 CHECK(api->lock(data)==data&&same(data,numeric,sizeof(numeric)));
 CHECK(api->find_ex_a(module,"#10","#101",1033)==info);
 CHECK(api->find_a(module,(const char *)(uintptr_t)101,(const char *)(uintptr_t)10)==info);
 CHECK(api->find_ex_a(module,(const char *)(uintptr_t)10,(const char *)(uintptr_t)101,0)==info);
 info=api->find_a(module,"named",(const char *)(uintptr_t)10);CHECK(info);
 CHECK(api->size(module,info)==sizeof(named));data=api->load(module,info);CHECK(data&&same(api->lock(data),named,sizeof(named)));
 CHECK(api->find_w(module,name_w,(const uint16_t *)(uintptr_t)10)==info);
 CHECK(api->find_ex_w(module,(const uint16_t *)(uintptr_t)10,name_w,1033)==info);
 CHECK(!api->find_a(module,"multi",(const char *)(uintptr_t)10));
 CHECK(api->find_ex_a(module,(const char *)(uintptr_t)10,"multi",1033));
 CHECK(api->find_ex_a(module,(const char *)(uintptr_t)10,"multi",1042));
 CHECK(!api->lock(info));
 CHECK(!api->load(module,(void *)(uintptr_t)1));
 CHECK(!api->size(module,(void *)(uintptr_t)1));
 return passed;
#undef CHECK
}
