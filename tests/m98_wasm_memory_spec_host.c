/* SPDX-License-Identifier: GPL-2.0-only
 * Real selected ORIGINAL memory WAST numeric binary oracle protocol. */
#include "m98_wasm.h"
#include <stdio.h>
#include <string.h>
#include "wasm_memory_spec_vectors.h"
int main(void){m98_wasm_options options={33554432,65536,10000000,256};uint32_t store=0,module=0,instance=0,i,j,m=0;unsigned passed=0,failed=0;int r; m98_wasm_value result[8];m98_wasm_info info;
 if(m98_wasm_open(&options,NULL,0,&store)){puts("SETUP_FAIL");return 2;}
 for(i=0;i<sizeof(spec_commands)/sizeof(spec_commands[0]);i++){const spec_command *c=&spec_commands[i];int ok=0;
  if(c->kind==0){if(instance&&m98_wasm_instance_close(store,instance))return 2;if(module&&m98_wasm_unload(store,module))return 2;instance=module=0;
   r=m98_wasm_load(store,c->bytes,c->length,&module);if(!r)r=m98_wasm_instantiate(store,module,&instance);ok=r==0;}
  else if(c->kind==3){r=m98_wasm_load(store,c->bytes,c->length,&m);ok=r==M98_WASM_VALIDATE;if(!r&&m98_wasm_unload(store,m))return 2;}
  else{memset(result,0,sizeof(result));r=m98_wasm_call(store,instance,c->name,c->args,c->count,result,c->results);
   if(c->kind==2){m98_wasm_inspect(store,&info);ok=r==M98_WASM_TRAP&&strstr(info.diagnostic,c->trap)!=NULL;}
   else{ok=r==0;for(j=0;j<c->results&&ok;j++)ok=result[j].kind==c->expected[j].kind&&result[j].bits==c->expected[j].bits;}
  }
  if(ok)passed++;else{failed++;m98_wasm_inspect(store,&info);printf("FAIL %u %s %u status %d %s\n",i,c->suite,c->line,r,info.diagnostic);}
 }
 r=m98_wasm_close(store);if(r){printf("TEARDOWN_FAIL %d\n",r);return 2;}
 printf("MEMORY_SPEC_RESULT %u %u %u\n",(unsigned)(sizeof(spec_commands)/sizeof(spec_commands[0])),passed,failed);return failed?1:0;
}
