/* SPDX-License-Identifier: GPL-2.0-only */
#include "api_contract.h"
#include "../native_environment/environment.h"
#define AC_MAGIC 0x41433131u
static const uint8_t chromium_root[32]={
 0x73,0x35,0xc4,0x49,0x40,0x09,0xb2,0x48,0x42,0xf5,0xa2,0xf5,0x01,0xaf,0xb1,0x36,
 0xc6,0xb3,0x0b,0xb4,0x73,0xa9,0x73,0x1a,0x48,0x14,0x7c,0xe6,0x98,0x65,0xd8,0x23};
static int bytes_equal(const uint8_t *a,const uint8_t *b){unsigned i;for(i=0;i<32;i++)if(a[i]!=b[i])return 0;return 1;}
static int name_equal(const char *a,const char *b,int insensitive)
{
 unsigned char x,y;unsigned i;if(!a||!b)return 0;
 for(i=0;i<128;i++){x=(unsigned char)a[i];y=(unsigned char)b[i];
  if(insensitive){if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;}
  if(x!=y)return 0;if(!x)return 1;
 }return 0;
}
int ac_init(ac_target *target,const uint8_t *file,size_t bytes)
{
 env_sha state;uint8_t digest[32];unsigned i;
 if(!target)return 0;target->magic=0;
 if(!file||bytes!=2616320)return 0;
 env_sha_init(&state);env_sha_update(&state,file,bytes);env_sha_final(&state,digest);
 if(!bytes_equal(digest,chromium_root))return 0;
 for(i=0;i<32;i++)target->digest[i]=digest[i];target->magic=AC_MAGIC;return 1;
}
int ac_lookup(const ac_target *target,const char *module,const char *symbol,uint16_t ordinal,ac_route *route)
{
 if(!route)return 0;route->kind=0;route->provider=route->symbol=0;
 if(!target||target->magic!=AC_MAGIC||!bytes_equal(target->digest,chromium_root)||ordinal)return 0;
 if(name_equal(module,"API-MS-WIN-CORE-SYNCH-L1-2-0.DLL",1)&&
    (name_equal(symbol,"WaitOnAddress",0)||name_equal(symbol,"WakeByAddressSingle",0)||name_equal(symbol,"WakeByAddressAll",0))){
  route->kind=AC_PRIVATE_ADDRESS;route->provider="M98ADDR.DLL";
  route->symbol=name_equal(symbol,"WaitOnAddress",0)?"WaitOnAddress":name_equal(symbol,"WakeByAddressSingle",0)?"WakeByAddressSingle":"WakeByAddressAll";
  return 1;
 }
 if(name_equal(module,"API-MS-WIN-POWER-BASE-L1-1-0.DLL",1)&&name_equal(symbol,"CallNtPowerInformation",0)){
  route->kind=AC_NATIVE_POWER;route->provider="POWRPROF.DLL";route->symbol="CallNtPowerInformation";return 1;
 }return 0;
}
