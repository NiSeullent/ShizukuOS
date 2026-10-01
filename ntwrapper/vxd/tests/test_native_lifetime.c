/* SPDX-License-Identifier: GPL-2.0-only. Actual native.c page residency binding;
 * VMM services and broker/core readiness are modeled, no guest execution. */
#include "../pma_endpoint.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x);exit(1);} } while(0)
__asm__(".globl ntwv_text_begin,ntwv_text_last,ntwv_data_begin,ntwv_data_last\n.set ntwv_text_begin,0x100003\n.set ntwv_text_last,0x10a900\n.set ntwv_data_begin,0x900400\n.set ntwv_data_last,0x907fff\n");
static unsigned core_live,broker_live,locked,lock_calls,unlocks,fail_lock,fail_unlock,owner_busy,unload_safe=1;
uintptr_t ntwv_irq_enter(void *p){(void)p;return 0x202;}
void ntwv_irq_leave(void *p,uintptr_t f){(void)p;CHECK(f==0x202);}
uint32_t ntwv_vmm_check(uint32_t a,uint32_t b,uint32_t c){(void)a;(void)c;return b;}
uint32_t ntwv_vmm_lock(uint32_t page,uint32_t n,uint32_t flags){CHECK(!flags);CHECK((page==0x100 && n==11)||(page==0x900 && n==8));++lock_calls;if(lock_calls==fail_lock)return 0; ++locked;return 1;}
uint32_t ntwv_vmm_unlock(uint32_t page,uint32_t n,uint32_t flags){CHECK(!flags && locked);CHECK((page==0x100 && n==11)||(page==0x900 && n==8));++unlocks;if(unlocks==fail_unlock)return 0;--locked;return 1;}
uint32_t ntwv_vmm_ptes(uint32_t a,uint32_t b,uint32_t *c,uint32_t d){(void)a;(void)b;(void)c;(void)d;return 0;}
uint32_t ntwv_vmm_map_phys(uint32_t a,uint32_t b,uint32_t c){(void)a;(void)b;(void)c;return 0;}
int32_t ntwv_vmcall(uint32_t a,uint32_t b,uint32_t c,uint32_t *d,uint32_t *e){(void)a;(void)b;(void)c;(void)d;(void)e;return SHZ_E_UNSUPPORTED;}
void ntwv_cpuid(uint32_t l,uint32_t r[4]){(void)l;memset(r,0,16);}
uint32_t ntwv_vmm_system_vm(void){return 0x100;}
uint32_t ntwv_vmm_current_vm(void){return 0x100;}
uint32_t ntwv_vmm_current_thread(void){return 0x200;}
uint32_t ntwv_vmm_now_ms(void){return 0;}
uint32_t ntwv_vmm_open_event(uint32_t h){return h;}
int ntwv_vmm_set_event(uint32_t h){(void)h;return 1;}
int ntwv_vmm_close_event(uint32_t h){(void)h;return 1;}
uint32_t ntwv_vmm_schedule_event(uint32_t r){return r;}
uint32_t ntwv_vmm_schedule_timeout(uint32_t m,uint32_t r){(void)m;return r;}
void ntwv_vmm_cancel_event(uint32_t h){(void)h;}
void ntwv_vmm_cancel_timeout(uint32_t h){(void)h;}
int ntwv_initialize(const struct ntw_lock_ops *o){(void)o;if(core_live)return 0;core_live=1;return 1;}
int ntwv_shutdown(void){if(!core_live)return 0;core_live=0;return 1;}
void ntwv_w64_reset(void){}
int ntwv_pma_initialize(const struct ntwv_pma_services *s,const struct ntwv_hv *h){(void)s;(void)h;CHECK(!broker_live);broker_live=1;return 1;}
int ntwv_pma_unload_safe(void){return (int)unload_safe;}
int ntwv_pma_shutdown(void){if(owner_busy)return 0;broker_live=0;return 1;}
void ntwv_pma_resume(void){broker_live=1;}
void ntwv_pma_owner_departed(uint32_t v,uint32_t t,uint32_t d,uint32_t p){(void)v;(void)t;(void)d;(void)p;}
uint32_t ntwv_dioc_ex(const struct ntwv_dioc *r,const struct ntwv_pages *p,const struct ntwv_hv *h){(void)r;(void)p;(void)h;return 0;}
int main(int argc,char **argv){
 const char *mode=argc>1?argv[1]:"normal";
 if(!strcmp(mode,"init-failure")){fail_lock=2;CHECK(!ntwv_native_init());CHECK(!locked && !core_live && !broker_live);}
 else if(!strcmp(mode,"init-unlock-failure")){fail_lock=2;fail_unlock=1;CHECK(!ntwv_native_init() && locked==1);CHECK(!ntwv_native_init() && lock_calls==2);fail_unlock=0;CHECK(ntwv_native_exit() && !locked);}
 else {CHECK(ntwv_native_init());CHECK(locked==2 && core_live && broker_live);CHECK(!ntwv_native_init() && lock_calls==2);
  owner_busy=1;CHECK(!ntwv_native_exit() && locked==2 && !unlocks && core_live && broker_live);owner_busy=0;
  if(!strcmp(mode,"reload-fence")){unload_safe=0;CHECK(!ntwv_native_exit() && locked==2 && !unlocks && core_live && broker_live);unload_safe=1;CHECK(ntwv_native_exit());}
  else if(!strcmp(mode,"unlock-failure")){fail_unlock=1;CHECK(!ntwv_native_exit() && locked==2);fail_unlock=0;CHECK(ntwv_native_exit());}
  else CHECK(ntwv_native_exit());
  CHECK(!locked && !core_live && !broker_live);
 }
 printf("PASS: native image lifetime %s (privileged boundaries modeled)\n",mode);return 0;
}
