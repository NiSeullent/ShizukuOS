/* SPDX-License-Identifier: GPL-2.0-only */
#include "native_syscall.h"
#include <string.h>
#ifdef _WIN32
__declspec(dllimport) int32_t __stdcall NtShzSetupNative(shz_native_call_v1 *,uint64_t);
#endif
void shz_native_call_init(shz_native_call_v1 *r,uint32_t op)
{ if(r){memset(r,0,sizeof *r);r->version=SHZ_NATIVE_SYS_VERSION;r->bytes=sizeof *r;r->operation=op;} }
int32_t shz_native_call(shz_native_call_v1 *r)
{
 if(!r||r->version!=SHZ_NATIVE_SYS_VERSION||r->bytes!=sizeof *r||r->reserved||r->tail_reserved)return (int32_t)0xc000000du;
#ifdef _WIN32
 return NtShzSetupNative(r,sizeof *r);
#else
 return (int32_t)0xc00000bbu;
#endif
}
