/* SPDX-License-Identifier: GPL-2.0-only */
/* These are project binary fault controls, not an official SIMD spec suite. */
#include "m98_wasm.h"
#include "wasm_simd_faults.h"
#include <stdio.h>
#include <string.h>
static unsigned total,passed,failed;
#define CHECK(x) do {total++;if(x)passed++;else{failed++;fprintf(stderr,"FAIL %u line %u: %s\n",total,(unsigned)__LINE__,#x);}}while(0)
extern uint32_t m98_wasm_test_accounted_bytes(void);
int main(void) {
 m98_wasm_options o={8*1024*1024,65536,100000,32};uint32_t s=0,m=0,i=0,n;unsigned k; m98_wasm_info before,after;m98_wasm_value out={M98_WASM_I32,0};unsigned char byte=0;
 CHECK(m98_wasm_open(&o,NULL,0,&s)==0);
 for(k=0;k<sizeof(faults)/sizeof(faults[0]);k++) {
  m=0x12345678;CHECK(m98_wasm_inspect(s,&before)==0);CHECK(m98_wasm_load(s,faults[k].bytes,faults[k].length,&m)==M98_WASM_VALIDATE);
  CHECK(m==0x12345678);CHECK(m98_wasm_inspect(s,&after)==0&&after.modules==before.modules&&after.instances==before.instances&&after.used_bytes==before.used_bytes);
  if(faults[k].unsupported)CHECK(strstr(after.diagnostic,"unsupported scalar SIMD instruction")!=NULL);
 }
 /* Valid non-minimal u32 LEB encodings are decoded, not mistaken for opcode 140. */
 CHECK(m98_wasm_load(s,fixture_overlong,sizeof(fixture_overlong),&m)==0);CHECK(m98_wasm_instantiate(s,m,&i)==0);CHECK(m98_wasm_call(s,i,"read",NULL,0,&out,1)==0&&out.kind==M98_WASM_I32&&out.bits==UINT64_C(3735928559));CHECK(m98_wasm_instance_close(s,i)==0);CHECK(m98_wasm_unload(s,m)==0);
 CHECK(m98_wasm_load(s,fixture_boundary,sizeof(fixture_boundary),&m)==0);CHECK(m98_wasm_instantiate(s,m,&i)==0);CHECK(m98_wasm_call(s,i,"vector",NULL,0,&out,1)==M98_WASM_TYPE);CHECK(m98_wasm_memory_read(s,i,0,0,&byte,1)==0&&byte==0);CHECK(m98_wasm_instance_close(s,i)==0);CHECK(m98_wasm_unload(s,m)==0);
 CHECK(m98_wasm_load(s,fixture_importvector,sizeof(fixture_importvector),&m)==0);i=0x12345678;CHECK(m98_wasm_instantiate(s,m,&i)==M98_WASM_LINK&&i==0x12345678);CHECK(m98_wasm_unload(s,m)==0);
 CHECK(m98_wasm_inspect(s,&after)==0&&after.modules==0&&after.instances==0);CHECK(m98_wasm_close(s)==0);CHECK(m98_wasm_test_accounted_bytes()==0);(void)n;
 printf("SIMD_FAULT_RESULT %u %u %u\n",total,passed,failed);return failed?1:0;
}
