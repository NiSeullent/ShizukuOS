/* SPDX-License-Identifier: GPL-2.0-only
 * Actual engine host tests. Original CRT/basic math host adapters are NOT
 * native Win98 evidence. Deliberate faults verify this executable is instrumented. */
#include "m98_wasm_qjs.h"
#include "m98_trident_script_port.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "wasm_qjs_fixtures.h"
static JSContext *context;static JSRuntime *runtime;static m98_wasm_qjs *owner;
static unsigned total,passed,failed,callback_count;static int callback_mode;
void *m98_script_scratch_alloc(size_t n){return runtime?js_malloc_rt(runtime,n):NULL;}
void m98_script_scratch_free(void *p){if(runtime)js_free_rt(runtime,p);}
static void check(int ok,const char *name){total++;if(ok)passed++;else{failed++;fprintf(stderr,"FAIL %u %s\n",total,name);}}
static void exception(const char *label){JSValue e=JS_GetException(context);const char *s=JS_ToCString(context,e);fprintf(stderr,"JS %s: %s\n",label,s?s:"<exception>");JS_FreeCString(context,s);JS_FreeValue(context,e);}
static int eval(const char *s,const char *label){size_t n=strlen(s);char *source=malloc(n+16);JSValue v;int ok;
 if(!source){check(0,"host fixture allocation");return 0;}memcpy(source,"(()=>{",6);memcpy(source+6,s,n);memcpy(source+6+n,"})()",5);
 v=JS_Eval(context,source,n+10,label,JS_EVAL_TYPE_GLOBAL);free(source);ok=!JS_IsException(v);if(!ok)exception(label);JS_FreeValue(context,v);check(ok,label);return ok;}
static JSValue assertion(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv){
 int truth=argc?JS_ToBool(ctx,argv[0]):0;const char *name=argc>1?JS_ToCString(ctx,argv[1]):NULL;
 check(truth==1,name?name:"JavaScript assertion");JS_FreeCString(ctx,name);if(truth!=1)return JS_ThrowInternalError(ctx,"host assertion failed");return JS_UNDEFINED;
}
static JSValue collect(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv){JS_RunGC(JS_GetRuntime(ctx));return JS_UNDEFINED;}
static JSValue detach_buffer(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv){if(argc!=1)return JS_ThrowTypeError(ctx,"one ArrayBuffer");JS_DetachArrayBuffer(ctx,argv[0]);return JS_UNDEFINED;}
static JSValue rounding(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv){int32_t mode=0;unsigned short cw;if(argc&&JS_ToInt32(ctx,&mode,argv[0])<0)return JS_EXCEPTION;
 __asm__ volatile("fnstcw %0":"=m"(cw));cw=(cw&~0x0c00)|((mode&3)<<10);__asm__ volatile("fldcw %0"::"m"(cw));return JS_UNDEFINED;}
static JSValue rounding_mode(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv){unsigned short cw;__asm__ volatile("fnstcw %0":"=m"(cw));return JS_NewInt32(ctx,(cw>>10)&3);}
static int callback(void *user,const m98_wasm_value *args,uint32_t count,m98_wasm_value *out){
 (void)user;callback_count++;check(count==1&&args[0].kind==M98_WASM_I32,"actual native import args");
 if(callback_mode==2)return 1;
 if(callback_mode==3){JSValue global=JS_GetGlobalObject(context),token=JS_GetPropertyStr(context,global,"token");JS_FreeValue(context,global);JS_Throw(context,token);return 1;}
 check(m98_wasm_qjs_detach(&owner)==M98_WASM_BUSY&&owner!=NULL,"detach rejected during native callback");
 {m98_wasm_info info;check(m98_wasm_qjs_inspect(owner,&info)==M98_WASM_BUSY,"inspect rejected during native callback");}
 if(callback_mode==1){const char *source="assert(throwsCode(()=>seam.info(),-3),'callback JS reentry rejected');gc()";JSValue v=JS_Eval(context,source,strlen(source),"callback",JS_EVAL_TYPE_GLOBAL);
  if(JS_IsException(v)){exception("callback");JS_FreeValue(context,v);return 1;}JS_FreeValue(context,v);}
 out->kind=M98_WASM_I32;out->bits=(uint32_t)args[0].bits+17;return 0;
}
static void *foreign(void *unused){m98_wasm_qjs *copy=owner;m98_wasm_info info;
 check(m98_wasm_qjs_inspect(copy,&info)==M98_WASM_THREAD,"foreign thread inspect rejected");
 check(m98_wasm_qjs_detach(&copy)==M98_WASM_THREAD&&copy==owner,"foreign thread detach rejected unchanged");return NULL;}
static int interrupt(JSRuntime *rt,void *p){unsigned *remaining=p;return !(*remaining)--;}
static void fixture(const char *name,const unsigned char *bytes,size_t length){JSValue global=JS_GetGlobalObject(context);check(JS_SetPropertyStr(context,global,name,JS_NewArrayBufferCopy(context,bytes,length))>=0,"actual fixture ArrayBuffer");JS_FreeValue(context,global);}
static __attribute__((no_sanitize("undefined"),noinline)) void asan_control(void){volatile unsigned char *p=malloc(1);p[2]=1;free((void*)p);}
/* M98_MEMORY_ADDITIONS_BEGIN
 * New tests over the frozen genuine private seam and corrected real memory
 * profile. All memory operations execute the JavaScript methods; C inspection
 * observes allocator counters only. The fault hook is pre-attach-only. */
extern void m98_wasm_test_fail_allocation_after(uint32_t);
extern uint32_t m98_wasm_test_accounted_bytes(void);
static int new_context(const m98_wasm_options *options,unsigned fault){
 JSValue api=JS_UNDEFINED,global;int r;
 m98_wasm_test_fail_allocation_after(fault);owner=NULL;
 runtime=JS_NewRuntime();check(runtime!=NULL,"new genuine memory-test runtime");if(!runtime)return M98_WASM_LIMIT;
 JS_SetMemoryLimit(runtime,32*1024*1024);JS_SetMaxStackSize(runtime,262144);
 context=JS_NewContext(runtime);check(context!=NULL,"new genuine memory-test context");if(!context)return M98_WASM_LIMIT;
 api=JS_NewInt32(context,71);r=m98_wasm_qjs_attach(context,options,NULL,0,&owner,&api);
 if(r){check(r==M98_WASM_LIMIT&&owner==NULL&&JS_IsNumber(api)&&JS_VALUE_GET_INT(api)==71,"actual faulted attach preserves outputs");JS_FreeValue(context,api);return r;}
 global=JS_GetGlobalObject(context);check(JS_SetPropertyStr(context,global,"seam",api)>=0,"explicit memory-test private API");
 JS_SetPropertyStr(context,global,"assert",JS_NewCFunction(context,assertion,"assert",2));
 JS_SetPropertyStr(context,global,"gc",JS_NewCFunction(context,collect,"gc",0));JS_FreeValue(context,global);
 eval("globalThis.throwsCode=(f,c)=>{try{f()}catch(e){return e.code===c}return false};assert(typeof WebAssembly==='undefined','memory profile remains private');globalThis.zero=(buffer)=>new Uint8Array(buffer).every(v=>v===0)","memory private setup");
 return 0;
}
static void finish_context(void){
 if(owner)check(m98_wasm_qjs_detach(&owner)==0&&owner==NULL,"memory context detach before destruction");
 check(m98_wasm_test_accounted_bytes()==0,"actual VM tracked memory empty after memory-test detach");
 if(context){if(JS_HasException(context)){JSValue e=JS_GetException(context);JS_FreeValue(context,e);}JS_RunGC(runtime);JS_FreeContext(context);context=NULL;}
 if(runtime){JS_FreeRuntime(runtime);runtime=NULL;}
 check(m98_wasm_test_accounted_bytes()==0,"actual VM memory empty after JS cyclic cleanup");
}
static int global_int(const char *name){
 JSValue global=JS_GetGlobalObject(context),value=JS_GetPropertyStr(context,global,name);int32_t n=INT32_MIN;
 int r=JS_ToInt32(context,&n,value);JS_FreeValue(context,value);JS_FreeValue(context,global);
 check(r==0,"actual JavaScript integer observation");return n;
}
static void captured_integer_fp(void){
 unsigned k;unsigned short cw;unsigned char prior[108],before[108],after[108];
 JSValue global=JS_GetGlobalObject(context),api=JS_GetPropertyStr(context,global,"seam"),function=JS_GetPropertyStr(context,api,"memoryGrow");
 JSValue instance,args[3],result;
 JS_FreeValue(context,global);
 for(k=0;k<4;k++){
  eval("globalThis.fpInstance=seam.instantiate(fpModule)","fresh instance for actual growth under each rounding mode");
  global=JS_GetGlobalObject(context);instance=JS_GetPropertyStr(context,global,"fpInstance");JS_FreeValue(context,global);
  args[0]=instance;args[1]=JS_NewInt32(context,0);args[2]=JS_NewInt32(context,1);memset(before,0,108);memset(after,0,108);
  __asm__ volatile("fnsave %0":"=m"(prior)::"memory");cw=(unsigned short)(0x027f|(k<<10));
  __asm__ volatile("fninit\n\tfldcw %0\n\tfldz\n\tfldz\n\tfdivp\n\tfld1"::"m"(cw):"memory");
  __asm__ volatile("fnsave %0\n\tfrstor %0":"+m"(before)::"memory");
  result=JS_Call(context,function,api,3,args);
  __asm__ volatile("fnsave %0\n\tfrstor %1":"=m"(after):"m"(prior):"memory");
  check(!JS_IsException(result)&&JS_VALUE_GET_TAG(result)==JS_TAG_INT&&JS_VALUE_GET_INT(result)==2,"captured integer grow executes actual engine");
  check(!memcmp(before,after,108)&&(before[4]&1)&&(after[4]&1),"captured integer grow preserves complete seeded x87 state");
  if(JS_IsException(result))exception("captured integer grow");JS_FreeValue(context,result);
  JS_FreeValue(context,instance);eval("seam.instanceClose(fpInstance);fpInstance=null;gc()","captured integer FP instance teardown");
 }
 JS_FreeValue(context,function);JS_FreeValue(context,api);
}
static void memory_properties(void){
 m98_wasm_options options={8*1024*1024,65536,2000,4};
 check(new_context(&options,0)==0,"corrected memory properties attach");if(!owner){finish_context();return;}
 fixture("noGrowBytes",fixture_no_grow,sizeof(fixture_no_grow));fixture("coalescedBytes",fixture_coalesced,sizeof(fixture_coalesced));
 eval("for(let [bytes,initial,max] of [[noGrowBytes,1,3],[coalescedBytes,2,4]]){let mm=seam.load(bytes),ii=seam.instantiate(mm);assert(seam.memorySize(ii,0)===initial,'declared page count without grow opcode');assert(zero(seam.memoryRead(ii,0,0,initial*65536)),'complete initial linear bytes zero');assert(seam.memoryRead(ii,0,initial*65536,0).byteLength===0&&throwsCode(()=>seam.memoryRead(ii,0,initial*65536+1,0),-10),'exact logical end zero-length bounds');assert(throwsCode(()=>seam.memoryRead(ii,0,initial*65536,1),-10),'exact initial page boundary out of range');let prefix=new Uint8Array(initial*65536);for(let n=0;n<prefix.length;n++)prefix[n]=(n*13+7)&255;seam.memoryWrite(ii,0,0,prefix);assert(seam.memoryGrow(ii,0,0)===initial&&seam.memorySize(ii,0)===initial,'zero growth exact count');let token={},caught;try{seam.memoryGrow(ii,0,{valueOf(){throw token}})}catch(e){caught=e}assert(caught===token&&seam.memorySize(ii,0)===initial,'grow conversion exception has no effect');let old=seam.memoryGrow(ii,0,{valueOf(){assert(throwsCode(()=>seam.memoryGrow(ii,0,1),-3),'grow getter reentry blocked');gc();return 1}});assert(old===initial&&seam.memorySize(ii,0)===initial+1,'grow independent of module opcodes');assert(zero(seam.memoryRead(ii,0,initial*65536,65536)),'complete successful new page zero');let retained=new Uint8Array(seam.memoryRead(ii,0,0,prefix.length));assert(retained.every((v,n)=>v===prefix[n]),'complete retained prefix after grow');assert(throwsCode(()=>seam.memoryWrite(ii,0,(initial+1)*65536,new Uint8Array([1])),-10),'exact new page end write rejected');assert(seam.memoryGrow(ii,0,max-initial-1)===initial+1&&seam.memorySize(ii,0)===max,'grow to declared module maximum');assert(zero(seam.memoryRead(ii,0,(max-1)*65536,65536)),'last maximum page zero');let used=seam.info().usedBytes;assert(seam.memoryGrow(ii,0,1)===-1&&seam.memoryGrow(ii,0,4294967295)===-1&&seam.memorySize(ii,0)===max&&seam.info().usedBytes===used,'maximum and overflow failure preserves accounting');assert(new Uint8Array(seam.memoryRead(ii,0,0,prefix.length)).every((v,n)=>v===prefix[n]),'failure preserves complete prefix');retained[0]=99;assert(new Uint8Array(seam.memoryRead(ii,0,0,1))[0]===7,'returned snapshot remains independent after growth');seam.instanceClose(ii);ii=seam.instantiate(mm);assert(zero(seam.memoryRead(ii,0,0,initial*65536)),'dirty block reinstantiate initial zero');seam.instanceClose(ii);seam.unload(mm)}gc();assert(seam.info().modules===0&&seam.info().instances===0,'corrected memory property native lifetimes')","genuine JS memory properties");
 eval("globalThis.fpModule=seam.load(coalescedBytes)","captured integer FP setup");
 captured_integer_fp();
 eval("seam.unload(fpModule);fpModule=null;gc()","captured integer FP teardown");
 finish_context();
}
static void allocator_recovery_js(const unsigned char *bytes,unsigned length,unsigned initial){
 m98_wasm_options options={8*1024*1024,65536,2000,4};unsigned point,found=0;m98_wasm_info before,after;int phase,old,r;
 for(point=1;point<=192&&!found;point++){
  r=new_context(&options,point);
  if(!r){
   fixture("bytes",bytes,length);
   eval("globalThis.tm=null;globalThis.ti=null;globalThis.phase=0;globalThis.faultCode=0;try{tm=seam.load(bytes)}catch(e){phase=1;faultCode=e.code}if(tm){try{ti=seam.instantiate(tm)}catch(e){phase=2;faultCode=e.code}}","real JS allocation trial load/instantiate");
   phase=global_int("phase");
   if(phase){int code=global_int("faultCode");check(phase==1?(code==M98_WASM_LIMIT||code==M98_WASM_VALIDATE):(phase==2&&(code==M98_WASM_LINK||code==M98_WASM_LIMIT)),"actual allocation failure phase and native code");}
   else{
    char source[768];
    /* Set the sentinel before inspecting; only growth lies between observations. */
    {char write[128];snprintf(write,sizeof(write),"seam.memoryWrite(ti,0,%u,new Uint8Array([109]))",initial*65536-1);eval(write,"allocation trial sentinel");}
    check(m98_wasm_qjs_inspect(owner,&before)==0,"actual counters immediately before JS growth");
    eval("globalThis.old=seam.memoryGrow(ti,0,1)","actual one-shot JS realloc attempt");
    check(m98_wasm_qjs_inspect(owner,&after)==0,"actual counters immediately after JS growth");old=global_int("old");
    if(old==-1){
     found=1;check(after.denied_allocations==before.denied_allocations+1&&after.used_bytes==before.used_bytes,"actual allocator denial and unchanged accounting");
     snprintf(source,sizeof(source),"assert(seam.memorySize(ti,0)===%u&&new Uint8Array(seam.memoryRead(ti,0,%u,1))[0]===109,'allocation failure preserves count and prefix');assert(throwsCode(()=>seam.memoryRead(ti,0,%u,1),-10),'failed allocation does not expose new page');assert(seam.memoryGrow(ti,0,1)===%u&&seam.memorySize(ti,0)===%u,'same-instance one-shot allocation recovery');assert(new Uint8Array(seam.memoryRead(ti,0,%u,1))[0]===109&&zero(seam.memoryRead(ti,0,%u,65536)),'recovered allocation preserves prefix and zeroes entire tail')",initial,initial*65536-1,initial*65536,initial,initial+1,initial*65536-1,initial*65536);
     eval(source,"real JS allocator rollback and recovery");printf("REAL_JS_REALLOC_RECOVERY initial=%u allocation_point=%u\n",initial,point);
    }else check(old==(int)initial,"allocation trial genuine successful growth");
   }
  }
  finish_context();
 }
 check(found==1,"bounded actual JS realloc-failure point found");m98_wasm_test_fail_allocation_after(0);
}
static void byte_budget_js(void){
 m98_wasm_options options={8*1024*1024,65536,2000,4};m98_wasm_info before,after;uint32_t measured;
 check(new_context(&options,0)==0,"byte-budget actual footprint calibration attach");if(!owner){finish_context();return;}
 fixture("bytes",fixture_no_grow,sizeof(fixture_no_grow));
 eval("globalThis.tm=seam.load(bytes);globalThis.ti=seam.instantiate(tm)","byte-budget actual footprint calibration instance");
 check(m98_wasm_qjs_inspect(owner,&before)==0,"byte-budget actual initial allocation footprint");measured=before.used_bytes;
 check(measured>=163840&&measured<8*1024*1024-98304,"measured footprint permits a bounded one-page/two-page budget interval");finish_context();
 options.memory_bytes=measured+98304;
 check(new_context(&options,0)==0,"bounded byte-budget JS attach");if(!owner){finish_context();return;}
 fixture("bytes",fixture_no_grow,sizeof(fixture_no_grow));
 eval("globalThis.tm=seam.load(bytes);globalThis.ti=seam.instantiate(tm);seam.memoryWrite(ti,0,65535,new Uint8Array([92]))","byte-budget real instance");
 check(m98_wasm_qjs_inspect(owner,&before)==0&&before.used_bytes==measured&&before.used_bytes+65536<options.memory_bytes&&before.used_bytes+131072>options.memory_bytes,"byte-budget actual counters and measured growth interval");
 printf("REAL_JS_BYTE_BUDGET initial_used=%u limit=%u\n",before.used_bytes,options.memory_bytes);
 eval("assert(seam.memoryGrow(ti,0,2)===-1&&seam.memorySize(ti,0)===1,'actual byte-budget denied JS growth')","byte-budget actual growth denial");
 check(m98_wasm_qjs_inspect(owner,&after)==0&&after.denied_allocations==before.denied_allocations+1&&after.used_bytes==before.used_bytes,"byte-budget failure preserves actual accounting");
 eval("assert(new Uint8Array(seam.memoryRead(ti,0,65535,1))[0]===92&&throwsCode(()=>seam.memoryRead(ti,0,65536,1),-10),'byte-budget failure preserves prefix and bounds');assert(seam.memoryGrow(ti,0,1)===1&&seam.memorySize(ti,0)===2,'smaller genuine grow recovers after budget denial');assert(new Uint8Array(seam.memoryRead(ti,0,65535,1))[0]===92&&zero(seam.memoryRead(ti,0,65536,65536)),'budget recovery retains prefix and zeros full tail')","byte-budget recovery");
 finish_context();
}
static void memory_integration(void){
 memory_properties();allocator_recovery_js(fixture_no_grow,sizeof(fixture_no_grow),1);allocator_recovery_js(fixture_coalesced,sizeof(fixture_coalesced),2);byte_budget_js();
}
/* M98_MEMORY_ADDITIONS_END */
int main(int argc,char **argv){
 m98_wasm_options options={8*1024*1024,65536,2000,3};m98_wasm_import imports={"env","visit","(i)i",callback,NULL};JSValue api,global;pthread_t t;
 if(argc==2&&!strcmp(argv[1],"asan")){asan_control();return 0;}
 if(argc==2&&!strcmp(argv[1],"ubsan")){volatile int32_t x=INT32_MAX;return x+1;}
 runtime=JS_NewRuntime();check(runtime!=NULL,"genuine QuickJS runtime");if(!runtime)return 1;
 JS_SetMemoryLimit(runtime,32*1024*1024);JS_SetMaxStackSize(runtime,262144);context=JS_NewContext(runtime);check(context!=NULL,"genuine QuickJS context");if(!context)return 1;
 {m98_wasm_qjs *unchanged=(void*)1;JSValue output=JS_NewInt32(context,71);m98_wasm_options invalid=options;invalid.instruction_limit=0;
  check(m98_wasm_qjs_attach(context,&invalid,&imports,1,&unchanged,&output)==M98_WASM_ARGUMENT,"invalid attach fails actual ABI");
  check(unchanged==(void*)1&&JS_VALUE_GET_INT(output)==71,"failed attach outputs unchanged");JS_FreeValue(context,output);}
 check(m98_wasm_qjs_attach(context,&options,&imports,1,&owner,&api)==0,"actual bridge attach");if(!owner)return 1;
 global=JS_GetGlobalObject(context);check(JS_SetPropertyStr(context,global,"seam",api)>=0,"explicit private test seam");
 JS_SetPropertyStr(context,global,"assert",JS_NewCFunction(context,assertion,"assert",2));JS_SetPropertyStr(context,global,"gc",JS_NewCFunction(context,collect,"gc",0));
 JS_SetPropertyStr(context,global,"detach",JS_NewCFunction(context,detach_buffer,"detach",1));JS_FreeValue(context,global);
 global=JS_GetGlobalObject(context);JS_SetPropertyStr(context,global,"rounding",JS_NewCFunction(context,rounding,"rounding",1));JS_SetPropertyStr(context,global,"roundingMode",JS_NewCFunction(context,rounding_mode,"roundingMode",0));JS_FreeValue(context,global);
 fixture("numericBytes",fixture_numeric,sizeof(fixture_numeric));fixture("callbackBytes",fixture_callback,sizeof(fixture_callback));fixture("missingBytes",fixture_missing,sizeof(fixture_missing));fixture("startBytes",fixture_start_loop,sizeof(fixture_start_loop));
 fixture("noGrowBytes",fixture_no_grow,sizeof(fixture_no_grow));fixture("coalescedBytes",fixture_coalesced,sizeof(fixture_coalesced));
 fixture("startCallbackBytes",fixture_start_callback,sizeof(fixture_start_callback));
 eval("globalThis.throwsCode=(f,c)=>{try{f()}catch(e){return e.code===c}return false};globalThis.throws=(f)=>{try{f()}catch(e){return true}return false};globalThis.D=(p,r)=>({params:p,results:r});globalThis.read=()=>new DataView(seam.memoryRead(i,0,0,4)).getInt32(0,true);assert(typeof WebAssembly==='undefined','no partial global namespace');globalThis.m=seam.load(numericBytes);globalThis.i=seam.instantiate(m);assert(seam.info().modules===1&&seam.info().instances===1,'actual live counts')","setup");
 eval("assert(seam.call(i,'add',D(['i32','i32'],1),[7,9])===16,'actual differing args 16');assert(seam.call(i,'add',D(['i32','i32'],1),[-11,30])===19,'actual differing args 19');assert(seam.call(i,'add',D(['i32','i32'],1),[4294967297,2])===3,'ToInt32 modulo');assert(seam.call(i,'wide',D(['i64'],1),[9007199254740993n])===9007199254740994n,'i64 beyond Number precision');assert(seam.call(i,'wide',D(['i64'],1),[(1n<<64n)+4n])===5n,'i64 modulo64');assert(seam.call(i,'wide',D(['i64'],1),[(1n<<63n)-1n])===-(1n<<63n),'signed BigInt output');assert(throws(()=>seam.call(i,'wide',D(['i64'],1),[4])),'Number cannot replace i64 BigInt');assert(seam.call(i,'wide',D(['i64'],1),[Object(9n)])===10n,'actual ToBigInt wrapper');assert(seam.call(i,'wide',D(['i64'],1),['11'])===12n,'actual ToBigInt string')","numeric");
 eval("assert(Object.is(seam.call(i,'f32',D(['f32'],1),[-0]),-0),'f32 sign zero');assert(Object.is(seam.call(i,'f64',D(['f64'],1),[-0]),-0),'f64 sign zero');assert(seam.call(i,'f32',D(['f32'],1),[16777217])===16777216,'f32 round to actual bits');assert(seam.call(i,'f32',D(['f32'],1),[2**-149])===2**-149,'f32 subnormal');assert(seam.call(i,'f64',D(['f64'],1),[Number.MIN_VALUE])===Number.MIN_VALUE,'f64 subnormal');assert(Number.isNaN(seam.call(i,'f64',D(['f64'],1),[NaN])),'actual NaN class');assert(seam.call(i,'f32',D(['f32'],1),[Infinity])===Infinity,'actual infinity');let values=seam.call(i,'mixed',D(['i64','f32','f64'],3),[9007199254741001n,-0,1.25]);assert(values[0]===9007199254741001n&&Object.is(values[1],-0)&&values[2]===1.25,'actual multi-result kinds');assert(seam.call(i,'store',D(['i32'],1),[12345])===91&&read()===12345,'actual store and result');assert(throwsCode(()=>seam.call(i,'store',D(['i32'],0),[77]),-9)&&read()===12345,'result count rejected before side effect');assert(throwsCode(()=>seam.call(i,'store',D(['f64'],1),[77]),-9)&&read()===12345,'parameter kind rejected before side effect');assert(throwsCode(()=>seam.call(i,'add',D(['i32'],1),[77]),-9),'actual arity mismatch');assert(throwsCode(()=>seam.call(i,'absent',D([],0),[]),-1),'actual missing export');assert(throwsCode(()=>seam.call(i,'trap',D([],0),[]),-8),'actual unreachable trap');assert(throwsCode(()=>seam.call(i,'loop',D([],0),[]),-8),'actual dispatch instruction budget');assert(seam.call(i,'add',D(['i32','i32'],1),[1,2])===3,'call after trap resets fuel')","float and traps");
 eval("globalThis.token={marker:1};let caught;try{seam.call(i,'store',{get params(){throw token}},[9])}catch(e){caught=e}assert(caught===token&&read()===12345,'descriptor getter original exception and no effect');let args=[{valueOf(){assert(throwsCode(()=>seam.instanceClose(i),-3),'coercion reentry blocked');gc();return 222}}];assert(seam.call(i,'store',D(['i32'],1),args)===91&&read()===222,'coercion GC actual store');args=[{valueOf(){throw token}}];caught=null;try{seam.call(i,'store',D(['i32'],1),args)}catch(e){caught=e}assert(caught===token&&read()===222,'argument exception preserves original and transaction');assert(throws(()=>seam.call(i,'store',D(['reference'],1),[1]))&&read()===222,'unknown descriptor no effect');assert(throws(()=>seam.call(i,'store',D(['i32'],9),[1]))&&read()===222,'bounded result count');assert(throws(()=>seam.call(i,'store\\0bad',D(['i32'],1),[1]))&&read()===222,'NUL export name rejected');assert(throws(()=>seam.call(i,'store',D(['i32'],1),[]))&&read()===222,'argument array count transaction')","getter and reentry");
 eval("let src=new Uint8Array([1,2,3,4,5,6]);seam.memoryWrite(i,0,8,src.subarray(1,5),1,2);assert(Array.from(new Uint8Array(seam.memoryRead(i,0,8,2))).join(',')==='3,4','typed view and subrange');seam.memoryWrite(i,0,10,new DataView(src.buffer,2,3));assert(Array.from(new Uint8Array(seam.memoryRead(i,0,10,3))).join(',')==='3,4,5','genuine DataView offsets');let snap=new Uint8Array(seam.memoryRead(i,0,8,2));snap[0]=99;assert(new Uint8Array(seam.memoryRead(i,0,8,1))[0]===3,'read snapshot independent');assert(throwsCode(()=>seam.memoryWrite(i,0,65535,src),-10),'actual memory bound');assert(throwsCode(()=>seam.memoryRead(i,1,0,1),-10),'actual invalid memory index');assert(throws(()=>seam.memoryRead(i,0,0,1048577)),'copy byte cap');assert(throws(()=>seam.memoryWrite(i,0,0,src,5,2)),'view range rejected');assert(throws(()=>seam.memoryWrite(i,0,0,src,-1)),'negative offset rejected');assert(throws(()=>seam.memoryWrite(i,0,0,src,2**32)),'uint32 overflow rejected');assert(seam.memorySize(i,0)===1&&seam.memoryGrow(i,0,1)===1&&seam.memorySize(i,0)===2,'real memory growth');assert(seam.memoryGrow(i,0,1)===2&&seam.memoryGrow(i,0,1)===-1&&seam.memorySize(i,0)===3,'actual growth maximum');assert(new Uint8Array(seam.memoryRead(i,0,65536,8)).every(v=>v===0),'new memory zero')","memory");
 eval("let bytes=new Uint8Array(numericBytes), padded=new Uint8Array(bytes.length+10);padded.set(bytes,5);let mm=seam.load(new DataView(padded.buffer,5,bytes.length)),ii=seam.instantiate(mm);padded.fill(0);assert(seam.call(ii,'add',D(['i32','i32'],1),[21,22])===43,'module bytes copied from actual DataView');assert(throwsCode(()=>seam.unload(mm),-3),'actual instantiated module unload busy');seam.instanceClose(ii);seam.unload(mm);assert(throwsCode(()=>seam.instanceClose(ii),-5)&&throwsCode(()=>seam.instantiate(mm),-5),'explicit stale objects');mm=null;ii=null;gc();let tt=new Uint8Array(bytes.length+4);tt.set(bytes,2);mm=seam.load(tt.subarray(2,bytes.length+2));ii=seam.instantiate(mm);assert(seam.call(ii,'add',D(['i32','i32'],1),[8,9])===17,'typed module offset');seam.instanceClose(ii);seam.unload(mm);mm=null;ii=null;gc();assert(throwsCode(()=>seam.load(new Uint8Array([0,1,2,3,4,5,6,7])),-6),'actual validator failure');assert(throwsCode(()=>seam.load(new ArrayBuffer(0)),-1),'empty module ABI rejected');let ml=seam.load(missingBytes);assert(throwsCode(()=>seam.instantiate(ml),-7),'actual unresolved import link failure');seam.unload(ml);ml=null;gc();ml=seam.load(startBytes);assert(throwsCode(()=>seam.instantiate(ml),-7),'actual start instruction budget');seam.unload(ml);ml=null;gc();assert(seam.info().modules===1&&seam.info().instances===1,'failed operations cleanup actual counts')","module load and link");
 eval("let b=new ArrayBuffer(16),v=new Uint8Array(b),dv=new DataView(b);detach(b);assert(throws(()=>seam.memoryWrite(i,0,0,b)),'detached ArrayBuffer');assert(throws(()=>seam.memoryWrite(i,0,0,v)),'detached TypedArray');assert(throws(()=>seam.memoryWrite(i,0,0,dv)),'detached DataView');assert(throws(()=>seam.load(new Proxy(numericBytes,{}))),'ArrayBuffer proxy brand rejected');assert(throws(()=>seam.memoryWrite(i,0,0,new Proxy(new Uint8Array(4),{}))),'typed proxy brand rejected');assert(throws(()=>seam.memoryWrite(i,0,0,Object.create(DataView.prototype))),'DataView prototype spoof rejected');assert(throws(()=>seam.memoryWrite(i,0,0,{buffer:new ArrayBuffer(4),byteOffset:0,byteLength:4})),'plain BufferSource spoof rejected');assert(throws(()=>seam.load(new Uint8Array(1048577))),'large module copy rejected');b=new ArrayBuffer(8);v=new Uint8Array(b);assert(throws(()=>seam.memoryWrite(i,0,0,v,{valueOf(){detach(b);return 0}})),'coercion detaches before pointer copy');let shared=new SharedArrayBuffer(8);assert(throws(()=>seam.memoryWrite(i,0,0,shared)),'genuine shared buffer rejected');assert(throws(()=>seam.memoryWrite(i,0,0,new Uint8Array(shared))),'genuine shared typed buffer rejected');assert(throws(()=>seam.memoryWrite(i,0,0,new DataView(shared))),'genuine shared DataView buffer rejected')","BufferSource brands");
 eval("let proto=DataView.prototype, saved=Object.getOwnPropertyDescriptors(proto);for(let k of ['buffer','byteOffset','byteLength'])Object.defineProperty(proto,k,{configurable:true,get(){throw token}});let dv=new DataView(new Uint8Array([7,8,9]).buffer,1,2);seam.memoryWrite(i,0,24,dv);assert(Array.from(new Uint8Array(seam.memoryRead(i,0,24,2))).join(',')==='8,9','captured genuine DataView intrinsics');for(let k of ['buffer','byteOffset','byteLength'])Object.defineProperty(proto,k,saved[k]);let live=seam.instantiate(seam.load(numericBytes));gc();assert(seam.call(live,'add',D(['i32','i32'],1),[31,32])===63,'instance retains module across GC');live=null;gc();assert(seam.info().modules===1&&seam.info().instances===1,'GC closes instance then module');globalThis.cm=seam.load(callbackBytes);globalThis.ci=seam.instantiate(cm);globalThis.garbage=seam.instantiate(seam.load(numericBytes));garbage.self=garbage;garbage=null;assert(seam.info().modules===3&&seam.info().instances===3,'real cyclic garbage pending callback GC')","retained and callback setup");
 callback_mode=1;eval("assert(seam.call(ci,'invoke',D(['i32'],1),[25])===42,'real callback computes output');assert(seam.info().modules===2&&seam.info().instances===2,'GC inside native callback cleanup deferred then drained')","native callback GC");
 eval("let mm=seam.load(noGrowBytes),ii=seam.instantiate(mm);assert(seam.memorySize(ii,0)===1&&seam.memoryGrow(ii,0,1)===1&&seam.memorySize(ii,0)===2,'corrected no-grow declared pages 1/1/2');seam.instanceClose(ii);seam.unload(mm);mm=seam.load(coalescedBytes);ii=seam.instantiate(mm);assert(seam.memorySize(ii,0)===2&&seam.memoryGrow(ii,0,1)===2&&seam.memorySize(ii,0)===3&&seam.memoryRead(ii,0,131071,1).byteLength===1,'corrected two-page declared pages 2/2/3');seam.instanceClose(ii);seam.unload(mm);mm=null;ii=null;gc()","no-grow mandatory backend gaps");
 callback_mode=2;eval("assert(throwsCode(()=>seam.call(ci,'invoke',D(['i32'],1),[8]),-8),'actual native callback failure trap')","native callback trap");
 callback_mode=3;eval("let caught;try{seam.call(ci,'invoke',D(['i32'],1),[8])}catch(e){caught=e}assert(caught===token,'actual native import original JS throw identity');let mm=seam.load(startCallbackBytes);caught=null;try{seam.instantiate(mm)}catch(e){caught=e}assert(caught===token,'actual start import original JS throw identity');seam.unload(mm);mm=null;gc();assert(seam.info().modules===2&&seam.info().instances===2,'failed start callback instance cleanup')","native callback JS exception");callback_mode=0;
 eval("for(let mode=0;mode<4;mode++){rounding(mode);let value=seam.call(i,'f32',D(['f32'],1),[1.0000000596046448]);assert(value===1,'f32 halfway nearest-even');assert(roundingMode()===mode,'seam preserves ambient rounding')}rounding(0)","ambient rounding");
 check(callback_count==4,"actual callbacks executed four times");
 {int rc=pthread_create(&t,NULL,foreign,NULL);if(!rc){int joined=pthread_join(t,NULL);check(joined==0,"join independent owner thread control");}
  /* Counter writes in check() must not overlap the foreign thread's checks. */
  check(rc==0,"start independent owner thread control");}
 eval("seam.instanceClose(ci);seam.unload(cm);ci=null;cm=null;gc();assert(seam.info().modules===1&&seam.info().instances===1,'callback teardown counts');globalThis.retained=i;globalThis.oldSeam=seam;seam.close();assert(throwsCode(()=>seam.info(),-5)&&throwsCode(()=>seam.call(retained,'add',D(['i32','i32'],1),[1,2]),-5),'private close invalidates retained objects')","close");
 check(m98_wasm_qjs_detach(&owner)==0&&owner==NULL,"detach after JS close");
 check(m98_wasm_qjs_attach(context,&options,&imports,1,&owner,&api)==0,"new real store after closed teardown");global=JS_GetGlobalObject(context);JS_SetPropertyStr(context,global,"seam",api);JS_FreeValue(context,global);
 eval("assert(throwsCode(()=>seam.call(retained,'add',D(['i32','i32'],1),[1,2]),-5),'old object rejected by new owner');assert(throwsCode(()=>oldSeam.load(numericBytes),-5),'old API remains stale');assert(seam.info().modules===0&&seam.info().instances===0,'new store empty');globalThis.lastModule=seam.load(numericBytes);globalThis.lastInstance=seam.instantiate(lastModule);lastInstance.self=lastInstance","generation ownership");
 {m98_wasm_info info;check(m98_wasm_qjs_inspect(owner,&info)==0&&info.modules==1&&info.instances==1,"actual host inspector before detach");}
 check(m98_wasm_qjs_detach(&owner)==0&&owner==NULL,"host detach closes live native handles");
 eval("assert(throwsCode(()=>seam.info(),-5)&&throwsCode(()=>seam.instanceClose(lastInstance),-5),'retained API safe after host detach');lastModule=null;lastInstance=null;m=null;i=null;retained=null;oldSeam=null;seam=null;gc()","detached GC");
 {unsigned budget=10;JS_SetInterruptHandler(runtime,interrupt,&budget);JSValue v=JS_Eval(context,"for(;;){}",9,"JS budget",JS_EVAL_TYPE_GLOBAL);check(JS_IsException(v),"host JavaScript interrupt separate from Wasm fuel");if(JS_IsException(v)){JSValue e=JS_GetException(context);JS_FreeValue(context,e);}JS_FreeValue(context,v);JS_SetInterruptHandler(runtime,NULL,NULL);}
 JS_RunGC(runtime);JS_FreeContext(context);context=NULL;JS_FreeRuntime(runtime);runtime=NULL;
 printf("BRIDGE_BASELINE_RESULT %u %u %u\n",total,passed,failed);check(total==140&&passed==140&&failed==0,"all 140 historical bridge predicates retained");
 memory_integration();
 printf("BRIDGE_RESULT %u %u %u\n",total,passed,failed);return failed?1:0;
}
