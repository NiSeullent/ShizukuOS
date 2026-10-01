/* SPDX-License-Identifier: GPL-2.0-only
 * Private numeric seam between actual frozen QuickJS and WAMR. */
#include "m98_wasm_qjs.h"
#include <stdint.h>
#include <string.h>

/* Same actual platform identity as the frozen owner-thread C embedding. */
extern uint32_t m98_wasm_thread_id(void);
enum { MODULE=1, INSTANCE=2, MAX_ENTITIES=64, BYTE_LIMIT=1048576 };
typedef struct entity entity;
struct m98_wasm_qjs {
 JSContext *ctx;JSRuntime *rt;uint32_t thread,store,refs,entities;
 int busy,draining,finalizing,cleanup_error;
 JSValue anchor,dv_buffer,dv_offset,dv_length;
 JSClassID buffer_class,typed_classes[JS_TYPED_ARRAY_FLOAT64+1];
 entity *live,*pending,*tail;
};
struct entity {
 entity *next,*previous,*queued; m98_wasm_qjs *owner;
 uint32_t handle;int kind,finalized;JSValue keep;
};
static JSClassID owner_class,module_class,instance_class;

static void owner_release(m98_wasm_qjs *o){
 if(--o->refs)return;
 JS_FreeValueRT(o->rt,o->dv_buffer);JS_FreeValueRT(o->rt,o->dv_offset);
 JS_FreeValueRT(o->rt,o->dv_length);js_free_rt(o->rt,o);
}
static void owner_finalizer(JSRuntime *rt,JSValue value){
 m98_wasm_qjs *o=JS_GetOpaque(value,owner_class);(void)rt;
 if(o){JSValue a=o->dv_buffer,b=o->dv_offset,c=o->dv_length;
  JS_SetOpaque(value,NULL);o->dv_buffer=o->dv_offset=o->dv_length=JS_UNDEFINED;
  /* Cycle removal owns these JS nodes now. Only C records may be deferred. */
  JS_FreeValueRT(rt,a);JS_FreeValueRT(rt,b);JS_FreeValueRT(rt,c);owner_release(o);}
}
static void owner_mark(JSRuntime *rt,JSValueConst value,JS_MarkFunc *mark){
 m98_wasm_qjs *o=JS_GetOpaque(value,owner_class);if(!o)return;
 JS_MarkValue(rt,o->dv_buffer,mark);JS_MarkValue(rt,o->dv_offset,mark);JS_MarkValue(rt,o->dv_length,mark);
}
static void drain(m98_wasm_qjs *o){
 if(o->draining)return;
 o->draining=1;o->refs++;
 while(o->pending){entity *e,*previous=NULL,**link=&o->pending;int r=0;
  /* GC can finalize a module before its instance. Close every finalized
   * instance before any module unload, independently of JS GC list order. */
  while(*link&&(*link)->kind!=INSTANCE){previous=*link;link=&(*link)->queued;}
  if(!*link){link=&o->pending;previous=NULL;}e=*link;*link=e->queued;if(o->tail==e)o->tail=previous;
  if(o->store&&e->handle)r=e->kind==INSTANCE?m98_wasm_instance_close(o->store,e->handle):m98_wasm_unload(o->store,e->handle);
  if(r&&!o->cleanup_error)o->cleanup_error=r;
  e->handle=0;
  if(e->previous)e->previous->next=e->next;else o->live=e->next;
  if(e->next)e->next->previous=e->previous;
  o->entities--;js_free_rt(o->rt,e);owner_release(o);
 }
 o->draining=0;owner_release(o);
}
static void entity_finalizer(JSRuntime *rt,JSValue value){
 entity *e=JS_GetOpaque(value,module_class);m98_wasm_qjs *o;(void)rt;
 if(!e)e=JS_GetOpaque(value,instance_class);if(!e)return;
 JS_SetOpaque(value,NULL);if(e->finalized)return;e->finalized=1;o=e->owner;e->queued=NULL;o->finalizing++;
 if(o->tail)o->tail->queued=e;else o->pending=e;o->tail=e;
 /* Release JS references during this finalizer, while QuickJS owns the GC
  * graph. Holding them through cycle removal would leave dangling JSValues.
  * Keep ONLY native records until the next entry/leave/inspect/detach. */
 {JSValue keep=e->keep;e->keep=JS_UNDEFINED;JS_FreeValueRT(rt,keep);}
 o->finalizing--;
 if(!o->store&&!o->busy&&!o->draining&&!o->finalizing)drain(o);
}
static void entity_mark(JSRuntime *rt,JSValueConst value,JS_MarkFunc *mark){
 entity *e=JS_GetOpaque(value,module_class);if(!e)e=JS_GetOpaque(value,instance_class);
 if(e)JS_MarkValue(rt,e->keep,mark);
}
static int register_classes(JSRuntime *rt){
 static const JSClassDef owner_def={"M98PrivateWasm",owner_finalizer,owner_mark,NULL,NULL};
 static const JSClassDef module_def={"M98PrivateWasmModule",entity_finalizer,entity_mark,NULL,NULL};
 static const JSClassDef instance_def={"M98PrivateWasmInstance",entity_finalizer,entity_mark,NULL,NULL};
 if(!owner_class){JS_NewClassID(&owner_class);JS_NewClassID(&module_class);JS_NewClassID(&instance_class);}
 if((!JS_IsRegisteredClass(rt,owner_class)&&JS_NewClass(rt,owner_class,&owner_def)<0)||
    (!JS_IsRegisteredClass(rt,module_class)&&JS_NewClass(rt,module_class,&module_def)<0)||
    (!JS_IsRegisteredClass(rt,instance_class)&&JS_NewClass(rt,instance_class,&instance_def)<0))return -1;
 return 0;
}
static JSValue native_error(m98_wasm_qjs *o,JSContext *ctx,int code,const char *phase){
 m98_wasm_info info;JSValue error=JS_NewError(ctx);
 if(JS_IsException(error))return error;
 memset(&info,0,sizeof(info));if(o&&o->store)m98_wasm_inspect(o->store,&info);
 if(JS_SetPropertyStr(ctx,error,"name",JS_NewString(ctx,"M98WasmError"))<0||
    JS_SetPropertyStr(ctx,error,"code",JS_NewInt32(ctx,code))<0||
    JS_SetPropertyStr(ctx,error,"phase",JS_NewString(ctx,phase))<0||
    JS_SetPropertyStr(ctx,error,"message",JS_NewString(ctx,info.diagnostic[0]?info.diagnostic:phase))<0){JS_FreeValue(ctx,error);return JS_EXCEPTION;}
 return JS_Throw(ctx,error);
}
static m98_wasm_qjs *enter(JSContext *ctx,JSValueConst anchor){
 m98_wasm_qjs *o=JS_GetOpaque2(ctx,anchor,owner_class);if(!o)return NULL;
 if(o->ctx!=ctx){native_error(NULL,ctx,M98_WASM_ARGUMENT,"foreign JS context");return NULL;}
 if(o->thread!=m98_wasm_thread_id()){native_error(NULL,ctx,M98_WASM_THREAD,"foreign owner thread");return NULL;}
 if(o->busy){native_error(NULL,ctx,M98_WASM_BUSY,"bridge reentry");return NULL;}
 if(!o->store){native_error(NULL,ctx,M98_WASM_STALE,"closed private store");return NULL;}
 o->busy=1;o->refs++;drain(o);
 if(o->cleanup_error){native_error(o,ctx,o->cleanup_error,"native finalizer cleanup failed");o->busy=0;owner_release(o);return NULL;}
 return o;
}
static JSValue leave(m98_wasm_qjs *o,JSValue result){
 drain(o);o->busy=0;
 if(o->cleanup_error&&!JS_IsException(result)){JS_FreeValue(o->ctx,result);result=native_error(o,o->ctx,o->cleanup_error,"native finalizer cleanup failed");}
 owner_release(o);return result;
}
static entity *get_entity(m98_wasm_qjs *o,JSValueConst value,int kind){
 entity *e=JS_GetOpaque2(o->ctx,value,kind==MODULE?module_class:instance_class);
 if(!e)return NULL;
 if(e->owner!=o||e->kind!=kind||!e->handle){native_error(NULL,o->ctx,M98_WASM_STALE,"stale/foreign private object");return NULL;}
 return e;
}
static JSValue new_entity(m98_wasm_qjs *o,int kind,JSValueConst keep,entity **out){
 JSValue object;entity *e;
 if(o->entities>=MAX_ENTITIES)return native_error(o,o->ctx,M98_WASM_LIMIT,"private object limit");
 object=JS_NewObjectClass(o->ctx,kind==MODULE?module_class:instance_class);if(JS_IsException(object))return object;
 e=js_mallocz(o->ctx,sizeof(*e));if(!e){JS_FreeValue(o->ctx,object);return JS_EXCEPTION;}
 e->owner=o;e->kind=kind;e->keep=JS_DupValue(o->ctx,keep);e->next=o->live;if(o->live)o->live->previous=e;
 o->live=e;o->entities++;o->refs++;JS_SetOpaque(object,e);*out=e;return object;
}
static int index_value(JSContext *ctx,JSValueConst value,uint32_t *out){
 uint64_t n;if(JS_ToIndex(ctx,&n,value)<0)return -1;
 if(n>UINT32_MAX){JS_ThrowRangeError(ctx,"private index exceeds uint32");return -1;}*out=(uint32_t)n;return 0;
}
/* No ambient .buffer/.byteOffset/.byteLength property is trusted. All arbitrary
 * argument coercions finish BEFORE this function obtains any native pointer. */
static int buffer_source(m98_wasm_qjs *o,JSValueConst source,uint32_t offset,int has_length,uint32_t requested,
 JSValue *held,const uint8_t **bytes,uint32_t *length){
 JSContext *ctx=o->ctx;JSClassID id=JS_GetClassID(source);size_t base_length=0,view_offset=0,view_length=0;uint8_t *base;unsigned i;
 *held=JS_UNDEFINED;
 if(id==o->buffer_class){*held=JS_DupValue(ctx,source);base=JS_GetArrayBuffer(ctx,&base_length,*held);if(JS_HasException(ctx))goto failed;view_length=base_length;}
 else{
  for(i=0;i<=JS_TYPED_ARRAY_FLOAT64;i++)if(id==o->typed_classes[i])break;
  if(i<=JS_TYPED_ARRAY_FLOAT64){*held=JS_GetTypedArrayBuffer(ctx,source,&view_offset,&view_length,NULL);if(JS_IsException(*held))goto failed;}
  else{JSValue v;uint64_t n;
   *held=JS_Call(ctx,o->dv_buffer,source,0,NULL);if(JS_IsException(*held))goto failed;
   v=JS_Call(ctx,o->dv_offset,source,0,NULL);if(JS_IsException(v))goto failed;
   if(JS_ToIndex(ctx,&n,v)<0){JS_FreeValue(ctx,v);goto failed;}JS_FreeValue(ctx,v);if(n>SIZE_MAX)goto range;view_offset=(size_t)n;
   v=JS_Call(ctx,o->dv_length,source,0,NULL);if(JS_IsException(v))goto failed;
   if(JS_ToIndex(ctx,&n,v)<0){JS_FreeValue(ctx,v);goto failed;}JS_FreeValue(ctx,v);if(n>SIZE_MAX)goto range;view_length=(size_t)n;
  }
  if(JS_GetClassID(*held)!=o->buffer_class){JS_ThrowTypeError(ctx,"shared buffers are outside the private seam");goto failed;}
  base=JS_GetArrayBuffer(ctx,&base_length,*held);if(JS_HasException(ctx))goto failed;
 }
 if(view_offset>base_length||view_length>base_length-view_offset||offset>view_length)goto range;
 {size_t available=view_length-offset,n=has_length?requested:available;
  if(n>available||n>BYTE_LIMIT)goto range;
  *length=(uint32_t)n;*bytes=n?base+view_offset+offset:NULL;return 0;}
 range:JS_ThrowRangeError(ctx,"private BufferSource range/byte limit");
 failed:JS_FreeValue(ctx,*held);*held=JS_UNDEFINED;return -1;
}
static int close_store(m98_wasm_qjs *o){
 int r=m98_wasm_close(o->store);entity *e;if(r)return r;o->store=0;
 for(e=o->live;e;e=e->next)e->handle=0;return 0;
}
enum { LOAD,INSTANTIATE,CALL,UNLOAD,INSTANCE_CLOSE,READ,WRITE,GROW,SIZE,INFO,CLOSE };
static const char *const type_names[]={"i32","i64","f32","f64"};
/* Direct binary64 -> binary32 nearest-even. Restore the host's complete x87
 * stack/control/status state; C casts cannot move across this one block. */
static uint32_t nearest_f32_bits(double value){
 unsigned char saved[108];unsigned short control=0x027f;uint32_t bits;
 __asm__ volatile("fnsave %0\n\tfwait\n\tfninit\n\tfldcw %2\n\tfldl %3\n\tfstps %1\n\tfrstor %0"
  :"=m"(saved),"=m"(bits):"m"(control),"m"(value):"memory");return bits;
}
static int input_value(JSContext *ctx,uint32_t kind,JSValueConst value,m98_wasm_value *out){
 int32_t i;int64_t wide;double d;out->kind=kind;out->bits=0;
 if(kind==M98_WASM_I32){if(JS_ToInt32(ctx,&i,value)<0)return -1;out->bits=(uint32_t)i;}
 else if(kind==M98_WASM_I64){if(JS_ToBigInt64(ctx,&wide,value)<0)return -1;memcpy(&out->bits,&wide,8);}
 else{if(JS_ToFloat64(ctx,&d,value)<0)return -1;
  if(kind==M98_WASM_F32)out->bits=nearest_f32_bits(d);else memcpy(&out->bits,&d,8);}
 return 0;
}
static JSValue output_value(JSContext *ctx,const m98_wasm_value *value){
 int32_t i;int64_t wide;float f;double d;uint32_t bits;
 switch(value->kind){
 case M98_WASM_I32:bits=(uint32_t)value->bits;memcpy(&i,&bits,4);return JS_NewInt32(ctx,i);
 case M98_WASM_I64:memcpy(&wide,&value->bits,8);return JS_NewBigInt64(ctx,wide);
 case M98_WASM_F32:bits=(uint32_t)value->bits;memcpy(&f,&bits,4);return JS_NewFloat64(ctx,(double)f);
 case M98_WASM_F64:memcpy(&d,&value->bits,8);return JS_NewFloat64(ctx,d);
 default:return native_error(NULL,ctx,M98_WASM_TYPE,"unknown actual result kind");}
}
static JSValue dispatch(JSContext *ctx,JSValueConst this_value,int argc,JSValueConst *argv,int method,JSValue *data){
 m98_wasm_qjs *o=enter(ctx,data[0]);entity *e=NULL,*fresh=NULL;JSValue result=JS_EXCEPTION,held=JS_UNDEFINED;
 uint32_t a=0,b=0,c=0,d=0,n=0;int r=0;(void)this_value;
 if(!o)return JS_EXCEPTION;
 if(method==LOAD){const uint8_t *bytes;
  if(argc<1||argc>3)goto argument;
  if((argc>=2&&index_value(ctx,argv[1],&a)<0)||(argc>=3&&index_value(ctx,argv[2],&b)<0))goto done;
  result=new_entity(o,MODULE,data[0],&fresh);if(JS_IsException(result))goto done;
  if(buffer_source(o,argv[0],a,argc>=3,b,&held,&bytes,&n)<0)goto discard;
  r=m98_wasm_load(o->store,bytes,n,&fresh->handle);if(r)goto native_failure;goto done;
 }
 if(method==INSTANTIATE){if(argc!=1)goto argument;e=get_entity(o,argv[0],MODULE);if(!e)goto done;
  result=new_entity(o,INSTANCE,argv[0],&fresh);if(JS_IsException(result))goto done;
  r=m98_wasm_instantiate(o->store,e->handle,&fresh->handle);if(r)goto native_failure;if(JS_HasException(ctx))goto discard;goto done;
 }
 if(method==CALL){m98_wasm_value inputs[8],outputs[8];JSValue params=JS_UNDEFINED,v=JS_UNDEFINED;const char *name=NULL;size_t name_length;uint32_t count=0,results=0,i;
  if(argc!=4)goto argument;e=get_entity(o,argv[0],INSTANCE);if(!e)goto done;
  name=JS_ToCStringLen(ctx,&name_length,argv[1]);if(!name)goto call_done;
  if(!name_length||name_length>=128||memchr(name,0,name_length)){JS_ThrowTypeError(ctx,"bounded nonempty export name required");goto call_done;}
  params=JS_GetPropertyStr(ctx,argv[2],"params");if(JS_IsException(params))goto call_done;
  if(JS_IsArray(ctx,params)!=1){if(!JS_HasException(ctx))JS_ThrowTypeError(ctx,"parameter kind array required");goto call_done;}
  v=JS_GetPropertyStr(ctx,params,"length");if(JS_IsException(v)||index_value(ctx,v,&count)<0)goto call_done;JS_FreeValue(ctx,v);v=JS_UNDEFINED;
  if(count>8){JS_ThrowRangeError(ctx,"at most eight parameters");goto call_done;}
  v=JS_GetPropertyStr(ctx,argv[2],"results");if(JS_IsException(v)||index_value(ctx,v,&results)<0)goto call_done;JS_FreeValue(ctx,v);v=JS_UNDEFINED;
  if(results>8){JS_ThrowRangeError(ctx,"at most eight actual results");goto call_done;}
  if(JS_IsArray(ctx,argv[3])!=1){if(!JS_HasException(ctx))JS_ThrowTypeError(ctx,"argument array required");goto call_done;}
  v=JS_GetPropertyStr(ctx,argv[3],"length");if(JS_IsException(v)||index_value(ctx,v,&n)<0)goto call_done;JS_FreeValue(ctx,v);v=JS_UNDEFINED;
  if(n!=count){JS_ThrowTypeError(ctx,"descriptor/argument count differs");goto call_done;}
  for(i=0;i<count;i++){const char *kind;size_t length;uint32_t k;
   v=JS_GetPropertyUint32(ctx,params,i);if(JS_IsException(v))goto call_done;
   kind=JS_ToCStringLen(ctx,&length,v);JS_FreeValue(ctx,v);v=JS_UNDEFINED;if(!kind)goto call_done;
   for(k=0;k<4;k++)if(length==3&&!memcmp(kind,type_names[k],3))break;JS_FreeCString(ctx,kind);
   if(k==4){JS_ThrowTypeError(ctx,"numeric parameter kind required");goto call_done;}
   v=JS_GetPropertyUint32(ctx,argv[3],i);if(JS_IsException(v)||input_value(ctx,k,v,&inputs[i])<0)goto call_done;JS_FreeValue(ctx,v);v=JS_UNDEFINED;
  }
  r=m98_wasm_call(o->store,e->handle,name,inputs,count,outputs,results);
  if(r){if(!JS_HasException(ctx))result=native_error(o,ctx,r,"actual typed export call");goto call_done;}
  if(JS_HasException(ctx))goto call_done;
  if(!results)result=JS_UNDEFINED;else if(results==1)result=output_value(ctx,&outputs[0]);
  else{result=JS_NewArray(ctx);if(!JS_IsException(result))for(i=0;i<results;i++){
    v=output_value(ctx,&outputs[i]);if(JS_IsException(v))goto call_discard;
    if(JS_SetPropertyUint32(ctx,result,i,v)<0){v=JS_UNDEFINED;goto call_discard;}v=JS_UNDEFINED;
   }}
  goto call_done;
  call_discard:JS_FreeValue(ctx,result);result=JS_EXCEPTION;
  call_done:JS_FreeValue(ctx,v);JS_FreeValue(ctx,params);if(name)JS_FreeCString(ctx,name);goto done;
 }
 if(method==UNLOAD||method==INSTANCE_CLOSE){if(argc!=1)goto argument;e=get_entity(o,argv[0],method==UNLOAD?MODULE:INSTANCE);if(!e)goto done;
  r=method==UNLOAD?m98_wasm_unload(o->store,e->handle):m98_wasm_instance_close(o->store,e->handle);
  if(r)goto native_failure;e->handle=0;if(method==INSTANCE_CLOSE){JSValue keep=e->keep;e->keep=JS_UNDEFINED;JS_FreeValue(ctx,keep);}result=JS_UNDEFINED;goto done;
 }
 if(method==READ||method==WRITE||method==GROW||method==SIZE){
  if((method==READ&&argc!=4)||(method==WRITE&&(argc<4||argc>6))||(method==GROW&&argc!=3)||(method==SIZE&&argc!=2))goto argument;
  e=get_entity(o,argv[0],INSTANCE);if(!e)goto done;
  if(index_value(ctx,argv[1],&a)<0||(method!=SIZE&&index_value(ctx,argv[2],&b)<0))goto done;
  if(method==SIZE){r=m98_wasm_memory_size(o->store,e->handle,a,&c);if(r)goto native_failure;result=JS_NewUint32(ctx,c);goto done;}
  if(method==GROW){int32_t old;r=m98_wasm_memory_grow(o->store,e->handle,a,b,&old);if(r)goto native_failure;result=JS_NewInt32(ctx,old);goto done;}
  if(method==READ){uint8_t *bytes;
   if(index_value(ctx,argv[3],&c)<0)goto done;if(c>BYTE_LIMIT){JS_ThrowRangeError(ctx,"private memory copy limit");goto done;}
   bytes=c?js_malloc(ctx,c):NULL;if(c&&!bytes)goto done;
   r=m98_wasm_memory_read(o->store,e->handle,a,b,bytes,c);
   if(!r)result=JS_NewArrayBufferCopy(ctx,bytes,c);js_free(ctx,bytes);if(r)goto native_failure;goto done;
  }else{const uint8_t *bytes;
   if((argc>=5&&index_value(ctx,argv[4],&c)<0)||(argc>=6&&index_value(ctx,argv[5],&d)<0))goto done;
   if(buffer_source(o,argv[3],c,argc>=6,d,&held,&bytes,&n)<0)goto done;
   r=m98_wasm_memory_write(o->store,e->handle,a,b,bytes,n);if(r)goto native_failure;result=JS_UNDEFINED;goto done;
  }
 }
 if(method==INFO){m98_wasm_info info;if(argc)goto argument;r=m98_wasm_inspect(o->store,&info);if(r)goto native_failure;
  result=JS_NewObject(ctx);if(JS_IsException(result))goto done;
  if(JS_SetPropertyStr(ctx,result,"modules",JS_NewUint32(ctx,info.modules))<0||
     JS_SetPropertyStr(ctx,result,"instances",JS_NewUint32(ctx,info.instances))<0||
     JS_SetPropertyStr(ctx,result,"usedBytes",JS_NewUint32(ctx,info.used_bytes))<0||
     JS_SetPropertyStr(ctx,result,"objects",JS_NewUint32(ctx,o->entities))<0)goto discard;goto done;
 }
 if(method==CLOSE){if(argc)goto argument;r=close_store(o);if(r)goto native_failure;result=JS_UNDEFINED;goto done;}
 argument:JS_ThrowTypeError(ctx,"private method argument count");goto done;
 native_failure:JS_FreeValue(ctx,result);result=JS_EXCEPTION;if(!JS_HasException(ctx))result=native_error(o,ctx,r,"actual native operation");goto done;
 discard:JS_FreeValue(ctx,result);result=JS_EXCEPTION;
 done:JS_FreeValue(ctx,held);return leave(o,result);
}
static int intrinsic_getter(JSContext *ctx,JSValueConst prototype,const char *name,JSValue *out){
 JSPropertyDescriptor desc;JSAtom atom=JS_NewAtom(ctx,name);int r;
 if(atom==JS_ATOM_NULL)return -1;memset(&desc,0,sizeof(desc));r=JS_GetOwnProperty(ctx,&desc,prototype,atom);JS_FreeAtom(ctx,atom);
 if(r<=0)return -1;
 JS_FreeValue(ctx,desc.value);JS_FreeValue(ctx,desc.setter);
 if(!JS_IsFunction(ctx,desc.getter)){JS_FreeValue(ctx,desc.getter);return -1;}*out=desc.getter;return 0;
}
int m98_wasm_qjs_attach(JSContext *ctx,const m98_wasm_options *options,const m98_wasm_import *imports,uint32_t count,m98_wasm_qjs **out,JSValue *private_api){
 static const char *const names[]={"load","instantiate","call","unload","instanceClose","memoryRead","memoryWrite","memoryGrow","memorySize","info","close"};
 m98_wasm_qjs *o;JSValue global=JS_UNDEFINED,constructor=JS_UNDEFINED,prototype=JS_UNDEFINED,sample=JS_UNDEFINED;unsigned i;int r;
 if(!ctx||!out||!private_api)return M98_WASM_ARGUMENT;
 o=js_mallocz(ctx,sizeof(*o));if(!o)return M98_WASM_LIMIT;
 o->ctx=ctx;o->rt=JS_GetRuntime(ctx);o->thread=m98_wasm_thread_id();o->refs=1;o->busy=1;
 o->anchor=o->dv_buffer=o->dv_offset=o->dv_length=JS_UNDEFINED;
 r=m98_wasm_open(options,imports,count,&o->store);if(r)goto fail;
 if(register_classes(o->rt)<0){r=M98_WASM_LIMIT;goto fail;}
 global=JS_GetGlobalObject(ctx);constructor=JS_GetPropertyStr(ctx,global,"DataView");if(JS_IsException(constructor))goto js_fail;
 prototype=JS_GetPropertyStr(ctx,constructor,"prototype");if(JS_IsException(prototype))goto js_fail;
 if(intrinsic_getter(ctx,prototype,"buffer",&o->dv_buffer)<0||intrinsic_getter(ctx,prototype,"byteOffset",&o->dv_offset)<0||
    intrinsic_getter(ctx,prototype,"byteLength",&o->dv_length)<0)goto js_fail;
 sample=JS_NewArrayBufferCopy(ctx,NULL,0);if(JS_IsException(sample))goto js_fail;o->buffer_class=JS_GetClassID(sample);JS_FreeValue(ctx,sample);sample=JS_UNDEFINED;
 for(i=0;i<=JS_TYPED_ARRAY_FLOAT64;i++){JSValue zero=JS_NewInt32(ctx,0);sample=JS_NewTypedArray(ctx,1,&zero,(JSTypedArrayEnum)i);
  if(JS_IsException(sample))goto js_fail;o->typed_classes[i]=JS_GetClassID(sample);JS_FreeValue(ctx,sample);sample=JS_UNDEFINED;}
 o->anchor=JS_NewObjectClass(ctx,owner_class);if(JS_IsException(o->anchor))goto js_fail;
 o->refs++;JS_SetOpaque(o->anchor,o);
 for(i=0;i<sizeof(names)/sizeof(*names);i++){JSValue f=JS_NewCFunctionData(ctx,dispatch,0,(int)i,1,&o->anchor);
  if(JS_IsException(f)||JS_DefinePropertyValueStr(ctx,o->anchor,names[i],f,JS_PROP_ENUMERABLE)<0)goto js_fail;}
 JS_FreeValue(ctx,global);JS_FreeValue(ctx,constructor);JS_FreeValue(ctx,prototype);
 o->busy=0;*private_api=JS_DupValue(ctx,o->anchor);*out=o;return 0;
 js_fail:r=M98_WASM_ARGUMENT;if(!JS_HasException(ctx))JS_ThrowTypeError(ctx,"fresh trusted DataView/typed-array context required");
 fail:JS_FreeValue(ctx,sample);JS_FreeValue(ctx,prototype);JS_FreeValue(ctx,constructor);JS_FreeValue(ctx,global);
 if(o->store)close_store(o);o->busy=0;JS_FreeValue(ctx,o->anchor);o->anchor=JS_UNDEFINED;owner_release(o);return r;
}
int m98_wasm_qjs_detach(m98_wasm_qjs **pointer){
 m98_wasm_qjs *o;int r;if(!pointer||!*pointer)return M98_WASM_ARGUMENT;o=*pointer;
 if(o->thread!=m98_wasm_thread_id())return M98_WASM_THREAD;if(o->busy)return M98_WASM_BUSY;
 o->busy=1;if(o->store){r=close_store(o);if(r){o->busy=0;return r;}}drain(o);o->busy=0;
 {JSValue anchor=o->anchor;o->anchor=JS_UNDEFINED;JS_FreeValue(o->ctx,anchor);}*pointer=NULL;owner_release(o);return 0;
}
int m98_wasm_qjs_inspect(m98_wasm_qjs *o,m98_wasm_info *out){
 int r;
 if(!o||!out)return M98_WASM_ARGUMENT;if(o->thread!=m98_wasm_thread_id())return M98_WASM_THREAD;
 if(o->busy)return M98_WASM_BUSY;if(!o->store)return M98_WASM_STALE;
 o->busy=1;o->refs++;drain(o);r=o->cleanup_error?o->cleanup_error:m98_wasm_inspect(o->store,out);o->busy=0;owner_release(o);return r;
}
