/* SPDX-License-Identifier: GPL-2.0-only
 * Original interpreter for a bounded WABT JSON-derived numeric command profile.
 * Foreign test scripts are not executed. Test operands/expected bits are kept. */
#include <stdio.h>
#include <string.h>
#include "m98_wasm.h"
#include "wasm_spec_vectors.h"
static int matches(m98_wasm_value actual,m98_wasm_value expected,unsigned nan){uint64_t abs,exp,quiet,payload;
 if(actual.kind!=expected.kind)return 0;
 if(!nan)return actual.bits==expected.bits;
 if(actual.kind==M98_WASM_F32){abs=actual.bits&UINT32_C(0x7fffffff);exp=UINT32_C(0x7f800000);quiet=UINT32_C(0x00400000);payload=UINT32_C(0x007fffff);}
 else if(actual.kind==M98_WASM_F64){abs=actual.bits&UINT64_C(0x7fffffffffffffff);exp=UINT64_C(0x7ff0000000000000);quiet=UINT64_C(0x0008000000000000);payload=UINT64_C(0x000fffffffffffff);}
 else return 0;
 return (abs&exp)==exp&&(nan==1?(abs&payload)==quiet:(abs&quiet)!=0);
}
int main(void){m98_wasm_options options={33554432,65536,100000,256};uint32_t store=0,module=0,instance=0,i,j,m=0;unsigned passed=0,failed=0;int r;m98_wasm_value result[8];m98_wasm_info info;
 if(m98_wasm_open(&options,NULL,0,&store)){puts("SETUP_FAIL");return 2;}
 for(i=0;i<sizeof(spec_commands)/sizeof(spec_commands[0]);i++){const spec_command *c=&spec_commands[i];int ok=0;
  if(c->kind==0){if(instance)m98_wasm_instance_close(store,instance);if(module)m98_wasm_unload(store,module);instance=module=0;r=m98_wasm_load(store,c->bytes,c->length,&module);if(!r)r=m98_wasm_instantiate(store,module,&instance);ok=r==0;}
  else if(c->kind==3){r=m98_wasm_load(store,c->bytes,c->length,&m);ok=r==M98_WASM_VALIDATE;if(!r)m98_wasm_unload(store,m);}
  else{
   memset(result,0,sizeof(result));r=m98_wasm_call(store,instance,c->name,c->args,c->count,result,c->results);
   if(c->kind==2){m98_wasm_inspect(store,&info);ok=r==M98_WASM_TRAP&&strstr(info.diagnostic,c->trap)!=NULL;}
   else{ok=r==0;for(j=0;j<c->results&&ok;j++){ok=matches(result[j],c->expected[j],c->nan[j]);if(!ok)printf("VALUE %u result %u kind %u expected %u actual %016llx expected %016llx nan_class %u\n",i,j,result[j].kind,c->expected[j].kind,(unsigned long long)result[j].bits,(unsigned long long)c->expected[j].bits,c->nan[j]);}}
  }
  if(ok)passed++;else{failed++;m98_wasm_inspect(store,&info);printf("FAIL %u %s %u status %d %s\n",i,c->suite,c->line,r,info.diagnostic);}
 }
 r=m98_wasm_close(store);if(r){printf("TEARDOWN_FAIL %d\n",r);failed++;}
 printf("SPEC_RESULT %u %u %u\n",(unsigned)(sizeof(spec_commands)/sizeof(spec_commands[0])),passed,failed);return failed?1:0;
}
