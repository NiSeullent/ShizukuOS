/* SPDX-License-Identifier: GPL-2.0-only -- pure ownership/failure controls */
#include "mapped_snapshot.h"
#include <stdio.h>
#include <string.h>
static unsigned checks;
static int code(void *opaque,uint32_t rva){return !opaque&&(rva==0x1000||rva==0x1100);}
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line %d\n",__LINE__);return 1;}}while(0)
static mx_spec valid(void){mx_spec s={0};s.image_base=0x400000;s.image_bytes=0x4000;s.tls_slot=12;s.dependencies=MX_KERNEL32;s.entry_rva=0x1000;s.callback_count=1;s.callbacks[0]=0x1100;s.owner_count=2;s.owners[0]=(mx_owner){101,0x10000,32,0x11111111};s.owners[1]=(mx_owner){102,0x20000,32,0x33333333};return s;}
int main(void)
{
 mx_spec s;mx_snapshot out={0},before;unsigned n;
 s=valid();CHECK(mx_seal(&out,&s,code,NULL)==MX_OK);before=out;
 CHECK(mx_seal(&out,&s,code,NULL)==MX_BAD_STATE);CHECK(!memcmp(&out,&before,sizeof(out)));
 CHECK(mx_dispatch_guard(&out,101,0x10000,0)==MX_OK);CHECK(mx_dispatch_guard(&out,102,0x20000,MX_OWN_OBSERVER)==MX_OK);
 CHECK(mx_dispatch_guard(&out,101,0,0)==MX_MISSING_TLS);CHECK(mx_dispatch_guard(&out,101,0x20000,0)==MX_BAD_OWNER);
 CHECK(mx_dispatch_guard(&out,103,0x10000,0)==MX_BAD_OWNER);CHECK(mx_dispatch_guard(&out,0,0x10000,0)==MX_BAD_OWNER);
 CHECK(mx_dispatch_guard(&out,101,0x10000,MX_KERNEL32)==MX_DETACHED_DEPENDENCY);
 s=valid();s.dependencies|=MX_OWN_OBSERVER;memset(&out,0,sizeof(out));CHECK(mx_seal(&out,&s,code,NULL)==MX_OK);
 CHECK(mx_dispatch_guard(&out,101,0x10000,MX_OWN_OBSERVER)==MX_DETACHED_DEPENDENCY);
 CHECK(mx_dispatch_guard(&out,101,0,MX_OWN_OBSERVER)==MX_DETACHED_DEPENDENCY);
 for(n=0;n<22;n++){
  s=valid();memset(&out,0,sizeof(out));
  switch(n){case 0:s.image_base=0;break;case 1:s.image_base++;break;case 2:s.image_base=UINTPTR_MAX&~(uintptr_t)4095;break;case 3:s.image_bytes=4095;break;case 4:s.image_bytes=1024*1024+1;break;case 5:s.tls_slot=64;break;case 6:s.owner_count=0;break;case 7:s.owner_count=MX_OWNERS+1;break;case 8:s.dependencies=0;break;case 9:s.dependencies=5;break;case 10:s.entry_rva=0;break;case 11:s.entry_rva=s.image_bytes;break;case 12:s.entry_rva=0x1200;break;case 13:s.callback_count=0;break;case 14:s.callback_count=MX_CALLBACKS+1;break;case 15:s.callbacks[0]=s.image_bytes;break;case 16:s.owners[0].thread_id=0;break;case 17:s.owners[1].thread_id=s.owners[0].thread_id;break;case 18:s.owners[1].tls_data=s.owners[0].tls_data;break;case 19:s.owners[0].tls_data=0;break;case 20:s.owners[0].tls_data=UINTPTR_MAX-1;break;case 21:s.owners[0].tls_bytes=3;break;}
  CHECK(mx_seal(&out,&s,code,NULL)!=MX_OK);CHECK(out.sealed==0);
 }
 s=valid();s.callback_count=2;s.callbacks[1]=s.callbacks[0];memset(&out,0,sizeof(out));CHECK(mx_seal(&out,&s,code,NULL)==MX_BAD_CODE);
 s=valid();CHECK(mx_seal(&out,&s,code,&out)==MX_BAD_CODE);CHECK(mx_seal(NULL,&s,code,NULL)==MX_BAD_STATE);
 memset(&out,0,sizeof(out));CHECK(mx_dispatch_guard(&out,101,0x10000,0)==MX_BAD_STATE);
 out=before;out.spec.owner_count=MX_OWNERS+1;CHECK(mx_dispatch_guard(&out,101,0x10000,0)==MX_BAD_STATE);
 out=before;out.spec.dependencies=0x80000000;CHECK(mx_dispatch_guard(&out,101,0x10000,0)==MX_DETACHED_DEPENDENCY);
 printf("PASS %u pure ownership/failure controls; native_executed=false\n",checks);return 0;
}
