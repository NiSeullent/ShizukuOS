/* SPDX-License-Identifier: GPL-2.0-only
 * Actual bounded interpreter embedding; no DOM or COM implementation. */
#include "m98_trident_script.h"
#include "quickjs.h"
#include <string.h>
#define CONTEXTS 4
#define OBJECTS 128
#define FUNCTIONS 256
#define RESULTS 16
#define STR_UNITS 65536u
extern uint32_t m98_script_thread_id(void);
extern int m98_script_platform_ready(void);
typedef struct script script;
typedef struct object {script *owner;uint32_t cookie;int retained;JSValue value;} object;
typedef struct function {uint32_t cookie,target,units;uint16_t *method;JSValue value;} function;
typedef struct result {uint32_t cookie;uint16_t *string;} result;
struct script {
    uint32_t cookie;
    JSRuntime *runtime;JSContext *context;
    m98_script_options options;m98_script_host host;
    m98_script_details detail;
    object objects[OBJECTS];function functions[FUNCTIONS];result results[RESULTS];
    int interrupted,host_failed;
};
static script states[CONTEXTS];
static uint32_t owner_thread,next_cookie;
static script *active_script;
void *m98_script_scratch_alloc(size_t n){return active_script&&active_script->runtime?js_malloc_rt(active_script->runtime,n):NULL;}
void m98_script_scratch_free(void *p){if(active_script&&active_script->runtime)js_free_rt(active_script->runtime,p);}
static volatile int entered;
static JSClassID object_class;
extern void m98_script_fp_enter(void);
extern void m98_script_fp_leave(void);
extern void m98_script_fp_save(void *);
extern void m98_script_fp_restore(const void *);
/* Native Automation code can change its own x87 state. Isolate every host
 * callback, including error cleanup/finalization, from interpreter arithmetic. */
#define HOST_RESULT(target,call) do{unsigned char saved[108] __attribute__((aligned(16))); \
    m98_script_fp_save(saved);target=(call);m98_script_fp_restore(saved);}while(0)
#define HOST_VOID(call) do{unsigned char saved[108] __attribute__((aligned(16))); \
    m98_script_fp_save(saved);call;m98_script_fp_restore(saved);}while(0)
static int enter(void){if(!__sync_bool_compare_and_swap(&entered,0,1))return 0;m98_script_fp_enter();return 1;}
static void leave(void){m98_script_fp_leave();active_script=NULL;__sync_lock_release(&entered);}
static uint32_t fresh(void){return next_cookie==UINT32_MAX?0:++next_cookie;}
static script *find(uint32_t cookie){unsigned i;for(i=0;i<CONTEXTS;++i)if(cookie&&states[i].cookie==cookie)return &states[i];return NULL;}
static int acquire(uint32_t cookie,script **out){
    if(!enter())return M98_SCRIPT_BUSY;
    if(!owner_thread||m98_script_thread_id()!=owner_thread){leave();return M98_SCRIPT_THREAD;}
    *out=find(cookie);if(!*out){leave();return M98_SCRIPT_STATE;}active_script=*out;return 0;
}
static int names(const uint16_t *p,uint32_t n){uint32_t i;if(!p||!n||n>256)return 0;for(i=0;i<n;++i)if(!p[i])return 0;return 1;}
static int valid_utf8(const unsigned char *p,uint32_t n){uint32_t i=0;while(i<n){uint32_t c=p[i++],more,minimum;
    if(!c)return 0;
    if(c<128)continue;
    if(c>=0xc2&&c<=0xdf){more=1;minimum=128;c&=31;}
    else if(c>=0xe0&&c<=0xef){more=2;minimum=2048;c&=15;}
    else if(c>=0xf0&&c<=0xf4){more=3;minimum=65536;c&=7;}else return 0;
    if(more>n-i)return 0;
    while(more--){uint32_t d=p[i++];if((d&192)!=128)return 0;c=(c<<6)|(d&63);}
    if(c<minimum||c>0x10ffff||(c>=0xd800&&c<=0xdfff))return 0;
}return 1;}
static JSValue from_utf16(script *s,const uint16_t *p,uint32_t n){uint32_t i,k=0;char *bytes;JSValue value;
    if(n>STR_UNITS||(!p&&n))return JS_ThrowRangeError(s->context,"UTF-16 bound");
    bytes=js_malloc(s->context,(size_t)n*3+1);if(!bytes)return JS_EXCEPTION;
    for(i=0;i<n;++i){uint32_t c=p[i];if(c<128)bytes[k++]=(char)c;
        else if(c<2048){bytes[k++]=(char)(192|(c>>6));bytes[k++]=(char)(128|(c&63));}
        else{bytes[k++]=(char)(224|(c>>12));bytes[k++]=(char)(128|((c>>6)&63));bytes[k++]=(char)(128|(c&63));}}
    value=JS_NewStringLen(s->context,bytes,k);js_free(s->context,bytes);return value;
}
static uint16_t *to_utf16(script *s,JSValueConst value,uint32_t *units){const unsigned char *bytes;size_t n,i=0;uint32_t count=0;uint16_t *out;
    bytes=(const unsigned char *)JS_ToCStringLen2(s->context,&n,value,1);if(!bytes)return NULL;
    if(n>STR_UNITS*3u){JS_FreeCString(s->context,(const char *)bytes);JS_ThrowRangeError(s->context,"UTF-16 bound");return NULL;}
    out=js_malloc(s->context,(n+1)*sizeof(uint16_t));if(!out){JS_FreeCString(s->context,(const char *)bytes);return NULL;}
    while(i<n){uint32_t c=bytes[i++],more;
        if(c<128)more=0;else if(c<224){c&=31;more=1;}else{c&=15;more=2;}
        if(more>n-i){js_free(s->context,out);out=NULL;break;}
        while(more--)c=(c<<6)|(bytes[i++]&63);
        if(count==STR_UNITS){js_free(s->context,out);out=NULL;break;}out[count++]=(uint16_t)c;
    }
    JS_FreeCString(s->context,(const char *)bytes);
    if(!out){JS_ThrowRangeError(s->context,"UTF-16 bound");return NULL;}out[count]=0;*units=count;return out;
}
static void init_value(m98_script_value *v){memset(v,0,sizeof(*v));v->size=sizeof(*v);}
static int valid_value(const m98_script_value *v,int host_output){
    if(!v||v->size!=sizeof(*v)||v->type>M98_SCRIPT_METHOD||(!host_output&&v->type==M98_SCRIPT_METHOD))return 0;
    if(v->type!=M98_SCRIPT_BOOL&&v->type!=M98_SCRIPT_INT32&&v->integer)return 0;
    if(v->type==M98_SCRIPT_BOOL&&v->integer!=0&&v->integer!=1)return 0;
    if(v->type!=M98_SCRIPT_NUMBER&&v->number!=0)return 0;
    if(v->type==M98_SCRIPT_OBJECT||v->type==M98_SCRIPT_FUNCTION||v->type==M98_SCRIPT_METHOD){if(!v->cookie)return 0;}else if(v->cookie)return 0;
    if(v->type==M98_SCRIPT_STRING){if(v->units>STR_UNITS||(!v->string&&v->units))return 0;}
    else if(v->type==M98_SCRIPT_METHOD){if(!names(v->string,v->units))return 0;}
    else if(v->string||v->units)return 0;
    return 1;
}
static JSValue host_exception(script *s,int32_t hr){s->host_failed=1;s->detail.host_hresult=hr;
    return JS_ThrowInternalError(s->context,"Automation HRESULT %d",hr);
}
static void object_finalizer(JSRuntime *runtime,JSValue value){object *o=JS_GetOpaque(value,object_class);(void)runtime;
    if(o&&o->retained){o->retained=0;HOST_VOID(o->owner->host.release(o->owner->host.user,o->cookie));}
}
static JSValue proxy(script *s,uint32_t cookie){unsigned i;object *o;int32_t hr;JSValue value;
    for(i=0;i<OBJECTS;++i)if(s->objects[i].cookie==cookie)return JS_DupValue(s->context,s->objects[i].value);
    for(i=0;i<OBJECTS&&s->objects[i].cookie;++i){}
    if(i==OBJECTS)return JS_ThrowRangeError(s->context,"host object identity bound");
    if(!s->host.retain)return host_exception(s,(int32_t)0x80004001u);
    HOST_RESULT(hr,s->host.retain(s->host.user,cookie));if(hr<0)return host_exception(s,hr);
    o=&s->objects[i];o->owner=s;o->cookie=cookie;o->retained=1;
    value=JS_NewObjectProtoClass(s->context,JS_NULL,object_class);
    if(JS_IsException(value)){o->retained=0;o->cookie=0;HOST_VOID(s->host.release(s->host.user,cookie));return value;}
    JS_SetOpaque(value,o);o->value=JS_DupValue(s->context,value);return value;
}
static uint32_t save_function(script *s,JSValueConst value){unsigned i;uint32_t cookie;
    for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie&&JS_VALUE_GET_PTR(s->functions[i].value)==JS_VALUE_GET_PTR(value))return s->functions[i].cookie;
    for(i=0;i<FUNCTIONS&&s->functions[i].cookie;++i){}
    if(i==FUNCTIONS||!(cookie=fresh())){JS_ThrowRangeError(s->context,"function identity bound");return 0;}
    s->functions[i].cookie=cookie;s->functions[i].value=JS_DupValue(s->context,value);return cookie;
}
static int export_value(script *s,JSValueConst value,m98_script_value *out){object *o;init_value(out);
    if(JS_IsUndefined(value))return 0;
    if(JS_IsNull(value)){out->type=M98_SCRIPT_NULL;return 0;}
    if(JS_IsBool(value)){out->type=M98_SCRIPT_BOOL;out->integer=JS_ToBool(s->context,value);return 0;}
    if(JS_VALUE_GET_TAG(value)==JS_TAG_INT){out->type=M98_SCRIPT_INT32;out->integer=JS_VALUE_GET_INT(value);return 0;}
    if(JS_IsNumber(value)){double number;uint64_t bits;if(JS_ToFloat64(s->context,&number,value))return -1;
        memcpy(&bits,&number,sizeof(bits));
        if(number>=INT32_MIN&&number<=INT32_MAX&&number==(int32_t)number&&bits!=UINT64_C(0x8000000000000000)){
            out->type=M98_SCRIPT_INT32;out->integer=(int32_t)number;
        }else{out->type=M98_SCRIPT_NUMBER;out->number=number;}return 0;
    }
    if(JS_IsString(value)){out->type=M98_SCRIPT_STRING;out->string=to_utf16(s,value,&out->units);return out->string?0:-1;}
    if((o=JS_GetOpaque(value,object_class))&&o->owner==s){out->type=M98_SCRIPT_OBJECT;out->cookie=o->cookie;return 0;}
    if(JS_IsFunction(s->context,value)){out->type=M98_SCRIPT_FUNCTION;out->cookie=save_function(s,value);return out->cookie?0:-1;}
    JS_ThrowTypeError(s->context,"unsupported Automation value");return -1;
}
static void free_export(script *s,m98_script_value *value){if(value->type==M98_SCRIPT_STRING)js_free(s->context,(void *)value->string);init_value(value);}
static JSValue import_value(script *,const m98_script_value *,int);
static int property_name(script *s,JSAtom atom,uint16_t **name,uint32_t *n){JSValue text=JS_AtomToString(s->context,atom);
    if(JS_IsException(text))return 0;
    *name=to_utf16(s,text,n);JS_FreeValue(s->context,text);
    if(!*name)return 0;
    if(!names(*name,*n)){js_free(s->context,*name);*name=NULL;JS_ThrowTypeError(s->context,"host member name bound");return 0;}return 1;
}
static JSValue host_get(JSContext *ctx,JSValueConst obj,JSAtom atom,JSValueConst receiver){object *o=JS_GetOpaque(obj,object_class);script *s;uint16_t *name;uint32_t n;m98_script_value returned;JSValue value;int32_t hr;(void)ctx;(void)receiver;
    if(!o)return JS_UNDEFINED;
    s=o->owner;
    if(!property_name(s,atom,&name,&n))return JS_EXCEPTION;
    init_value(&returned);HOST_RESULT(hr,s->host.get(s->host.user,o->cookie,name,n,&returned));js_free(s->context,name);
    value=hr<0?host_exception(s,hr):import_value(s,&returned,1);
    HOST_VOID(s->host.release_result(s->host.user,&returned));return value;
}
static int host_set(JSContext *ctx,JSValueConst obj,JSAtom atom,JSValueConst value,JSValueConst receiver,int flags){object *o=JS_GetOpaque(obj,object_class);script *s;uint16_t *name;uint32_t n;m98_script_value input;int32_t hr;(void)ctx;(void)receiver;(void)flags;
    if(!o)return -1;
    s=o->owner;if(!property_name(s,atom,&name,&n))return -1;
    if(export_value(s,value,&input)){js_free(s->context,name);return -1;}
    HOST_RESULT(hr,s->host.set(s->host.user,o->cookie,name,n,&input));free_export(s,&input);js_free(s->context,name);
    if(hr<0){host_exception(s,hr);return -1;}return 1;
}
static JSValue method_call(JSContext *ctx,JSValueConst self,int argc,JSValueConst *argv,int magic,JSValue *data){script *s=JS_GetContextOpaque(ctx);m98_script_value input[32],returned;uint16_t *name;uint32_t n,cookie;int i;int32_t hr;JSValue value;(void)self;(void)magic;
    if(argc<0||argc>32)return JS_ThrowRangeError(ctx,"host argument bound");
    if(JS_ToUint32(ctx,&cookie,data[0]))return JS_EXCEPTION;
    name=to_utf16(s,data[1],&n);if(!name)return JS_EXCEPTION;
    for(i=0;i<argc;++i)if(export_value(s,argv[i],&input[i])){while(i--)free_export(s,&input[i]);js_free(ctx,name);return JS_EXCEPTION;}
    init_value(&returned);HOST_RESULT(hr,s->host.call(s->host.user,cookie,name,n,input,(uint32_t)argc,&returned));
    for(i=0;i<argc;++i)free_export(s,&input[i]);
    js_free(ctx,name);
    value=hr<0?host_exception(s,hr):import_value(s,&returned,1);HOST_VOID(s->host.release_result(s->host.user,&returned));return value;
}
static JSValue import_value(script *s,const m98_script_value *v,int host_output){unsigned i;JSValue data[2],value,target;
    if(!valid_value(v,host_output))return host_exception(s,(int32_t)0x80070057u);
    switch(v->type){
    case M98_SCRIPT_UNDEFINED:return JS_UNDEFINED;
    case M98_SCRIPT_NULL:return JS_NULL;
    case M98_SCRIPT_BOOL:return JS_NewBool(s->context,v->integer);
    case M98_SCRIPT_INT32:return JS_NewInt32(s->context,v->integer);
    case M98_SCRIPT_NUMBER:return JS_NewFloat64(s->context,v->number);
    case M98_SCRIPT_STRING:return from_utf16(s,v->string,v->units);
    case M98_SCRIPT_OBJECT:return proxy(s,v->cookie);
    case M98_SCRIPT_FUNCTION:
        for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie==v->cookie)return JS_DupValue(s->context,s->functions[i].value);
        return JS_ThrowTypeError(s->context,"stale function cookie");
    case M98_SCRIPT_METHOD:
        for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie&&s->functions[i].target==v->cookie&&s->functions[i].units==v->units&&
            !memcmp(s->functions[i].method,v->string,(size_t)v->units*2))return JS_DupValue(s->context,s->functions[i].value);
        target=proxy(s,v->cookie);if(JS_IsException(target))return target;JS_FreeValue(s->context,target);
        data[0]=JS_NewUint32(s->context,v->cookie);data[1]=from_utf16(s,v->string,v->units);
        if(JS_IsException(data[1]))return JS_EXCEPTION;
        value=JS_NewCFunctionData(s->context,method_call,0,0,2,data);JS_FreeValue(s->context,data[1]);
        if(JS_IsException(value))return value;
        if(!save_function(s,value)){JS_FreeValue(s->context,value);return JS_EXCEPTION;}
        for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie&&JS_VALUE_GET_PTR(s->functions[i].value)==JS_VALUE_GET_PTR(value))break;
        s->functions[i].method=js_malloc(s->context,(size_t)v->units*2);
        if(!s->functions[i].method){JS_FreeValue(s->context,value);JS_FreeValue(s->context,s->functions[i].value);memset(&s->functions[i],0,sizeof(s->functions[i]));return JS_EXCEPTION;}
        memcpy(s->functions[i].method,v->string,(size_t)v->units*2);s->functions[i].units=v->units;s->functions[i].target=v->cookie;return value;
    }return JS_EXCEPTION;
}
static JSClassExoticMethods exotic={.get_property=host_get,.set_property=host_set};
static int interrupt(JSRuntime *rt,void *opaque){script *s=opaque;(void)rt;
    if(++s->detail.interrupt_checks>s->options.interrupt_checks){s->interrupted=1;return 1;}return 0;
}
static JSModuleDef *no_module(JSContext *ctx,const char *name,void *opaque){(void)name;(void)opaque;JS_ThrowReferenceError(ctx,"external modules disabled");return NULL;}
static void begin(script *s){memset(&s->detail,0,sizeof(s->detail));s->detail.size=sizeof(s->detail);s->interrupted=s->host_failed=0;}
static int exception(script *s){JSValue error=JS_GetException(s->context);
    s->detail.result=s->interrupted?M98_SCRIPT_LIMIT:s->host_failed?M98_SCRIPT_HOST:M98_SCRIPT_EXCEPTION;
    memcpy(s->detail.exception_utf8,"script exception",17);s->detail.exception_utf8_bytes=16;
    /* Inspect only an actual Error's own data string. Do not execute exception
     * getters, proxies or user toString while reporting a bounded failure. */
    if(JS_IsError(s->context,error)){JSAtom atom=JS_NewAtom(s->context,"message");
        JSPropertyDescriptor desc={.value=JS_UNDEFINED,.getter=JS_UNDEFINED,.setter=JS_UNDEFINED};
        if(atom!=JS_ATOM_NULL&&JS_GetOwnProperty(s->context,&desc,error,atom)>0&&JS_IsString(desc.value)){
            size_t n;const char *message=JS_ToCStringLen(s->context,&n,desc.value);
            if(message){if(n>255)n=255;memcpy(s->detail.exception_utf8,message,n);s->detail.exception_utf8[n]=0;s->detail.exception_utf8_bytes=(uint32_t)n;JS_FreeCString(s->context,message);}
        }JS_FreeValue(s->context,desc.value);JS_FreeValue(s->context,desc.getter);JS_FreeValue(s->context,desc.setter);if(atom!=JS_ATOM_NULL)JS_FreeAtom(s->context,atom);
    }JS_FreeValue(s->context,error);return s->detail.result;
}
static int result_available(script *s){unsigned i;for(i=0;i<RESULTS;++i)if(!s->results[i].cookie)return next_cookie!=UINT32_MAX;return 0;}
static int publish(script *s,JSValue value,m98_script_result *out){unsigned i;m98_script_value v;uint32_t cookie;
    if(JS_IsException(value))return exception(s);
    for(i=0;i<RESULTS&&s->results[i].cookie;++i){}
    if(i==RESULTS||!(cookie=fresh())){JS_FreeValue(s->context,value);s->detail.result=M98_SCRIPT_LIMIT;return M98_SCRIPT_LIMIT;}
    if(export_value(s,value,&v)){JS_FreeValue(s->context,value);return exception(s);}JS_FreeValue(s->context,value);
    s->results[i].cookie=cookie;s->results[i].string=v.type==M98_SCRIPT_STRING?(uint16_t *)v.string:NULL;
    out->lease=cookie;out->value=v;return 0;
}
static void destroy(script *s){unsigned i;
    if(s->context){
        for(i=0;i<RESULTS;++i)if(s->results[i].cookie)js_free(s->context,s->results[i].string);
        for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie){js_free(s->context,s->functions[i].method);JS_FreeValue(s->context,s->functions[i].value);}
        for(i=0;i<OBJECTS;++i)if(s->objects[i].cookie)JS_FreeValue(s->context,s->objects[i].value);
        JS_FreeContext(s->context);
    }
    if(s->runtime)JS_FreeRuntime(s->runtime);
    memset(s,0,sizeof(*s));
}
int m98_script_open(const m98_script_options *o,m98_script_context *out){unsigned i;script *s;JSClassDef def={.class_name="M98Automation",.finalizer=object_finalizer,.exotic=&exotic};uint32_t thread,cookie;
    if(!out)return M98_SCRIPT_INVALID;
    *out=0;if(!enter())return M98_SCRIPT_BUSY;
    if(!o||o->size!=sizeof(*o)||o->memory_bytes<262144||o->memory_bytes>33554432||o->stack_bytes<16384||o->stack_bytes>262144||
       !o->interrupt_checks||o->interrupt_checks>100000||!o->job_limit||o->job_limit>10000||
       (o->host&&(o->host->size!=sizeof(*o->host)||!o->host->get||!o->host->set||!o->host->call||!o->host->retain||!o->host->release||!o->host->release_result))){leave();return M98_SCRIPT_INVALID;}
    thread=m98_script_thread_id();if(!thread||(owner_thread&&thread!=owner_thread)){leave();return M98_SCRIPT_THREAD;}
    if(m98_script_platform_ready()){leave();return M98_SCRIPT_STATE;}
    for(i=0;i<CONTEXTS&&states[i].cookie;++i){}
    if(i==CONTEXTS||!(cookie=fresh())){leave();return M98_SCRIPT_LIMIT;}
    owner_thread=thread;s=&states[i];memset(s,0,sizeof(*s));active_script=s;s->options=*o;if(o->host)s->host=*o->host;
    s->runtime=JS_NewRuntime();if(!s->runtime){destroy(s);leave();return M98_SCRIPT_MEMORY;}
    JS_SetMemoryLimit(s->runtime,o->memory_bytes);JS_SetMaxStackSize(s->runtime,o->stack_bytes);
    JS_SetInterruptHandler(s->runtime,interrupt,s);JS_SetModuleLoaderFunc(s->runtime,NULL,no_module,NULL);
    if(!object_class)JS_NewClassID(&object_class);
    if(JS_NewClass(s->runtime,object_class,&def)<0||(s->context=JS_NewContext(s->runtime))==NULL){destroy(s);leave();return M98_SCRIPT_MEMORY;}
    /* Shared-memory construction is outside this single UI-thread profile.
     * Do not leave an exposed constructor merely because Atomics was omitted. */
    JSValue global=JS_GetGlobalObject(s->context);
    JSAtom shared=JS_NewAtom(s->context,"SharedArrayBuffer");
    if(JS_IsException(global)||shared==JS_ATOM_NULL||JS_DeleteProperty(s->context,global,shared,JS_PROP_THROW)<0){
        JS_FreeValue(s->context,global);if(shared!=JS_ATOM_NULL)JS_FreeAtom(s->context,shared);destroy(s);leave();return M98_SCRIPT_MEMORY;
    }
    JS_FreeAtom(s->context,shared);JS_FreeValue(s->context,global);
    JS_SetContextOpaque(s->context,s);s->cookie=cookie;begin(s);*out=cookie;leave();return 0;
}
int m98_script_bind_root(m98_script_context h,const uint16_t *name,uint32_t n,uint32_t cookie){script *s;JSValue global,text,value;JSAtom atom;int r=acquire(h,&s);
    if(r)return r;
    if(!names(name,n)||!cookie||!s->host.get){leave();return M98_SCRIPT_INVALID;}begin(s);
    text=from_utf16(s,name,n);if(JS_IsException(text)){r=exception(s);leave();return r;}
    atom=JS_ValueToAtom(s->context,text);JS_FreeValue(s->context,text);if(atom==JS_ATOM_NULL){r=exception(s);leave();return r;}
    global=JS_GetGlobalObject(s->context);r=JS_HasProperty(s->context,global,atom);
    if(r){JS_FreeAtom(s->context,atom);JS_FreeValue(s->context,global);if(r<0)r=exception(s);else r=M98_SCRIPT_STATE;leave();return r;}
    value=proxy(s,cookie);if(JS_IsException(value))r=exception(s);
    else if(JS_DefinePropertyValue(s->context,global,atom,value,JS_PROP_ENUMERABLE)<0)r=exception(s);else r=0;
    JS_FreeAtom(s->context,atom);JS_FreeValue(s->context,global);leave();return r;
}
static int prepare_result(m98_script_result *out){if(!out||out->size!=sizeof(*out)||out->lease)return 0;init_value(&out->value);return 1;}
int m98_script_eval(m98_script_context h,const char *source,uint32_t bytes,m98_script_result *out){script *s;JSValue value;char *copy;int r;
    if(!prepare_result(out)||!source||!bytes||bytes>(1u<<20)||!valid_utf8((const unsigned char *)source,bytes))return M98_SCRIPT_INVALID;
    r=acquire(h,&s);if(r)return r;begin(s);if(!result_available(s)){s->detail.result=M98_SCRIPT_LIMIT;leave();return M98_SCRIPT_LIMIT;}copy=js_malloc(s->context,(size_t)bytes+1);
    if(!copy){r=exception(s);leave();return r;}memcpy(copy,source,bytes);copy[bytes]=0;
    value=JS_Eval(s->context,copy,bytes,"explicit-local-script",JS_EVAL_TYPE_GLOBAL);js_free(s->context,copy);
    r=publish(s,value,out);s->detail.result=r;leave();return r;
}
int m98_script_invoke_this(m98_script_context h,uint32_t cookie,const m98_script_value *receiver,const m98_script_value *argv,uint32_t argc,m98_script_result *out){script *s;JSValue values[32],returned,func=JS_UNDEFINED,this_value=JS_UNDEFINED;unsigned i,j;int r;
    if(!prepare_result(out)||argc>32||(!argv&&argc)||!cookie)return M98_SCRIPT_INVALID;
    r=acquire(h,&s);if(r)return r;begin(s);if(!result_available(s)){s->detail.result=M98_SCRIPT_LIMIT;leave();return M98_SCRIPT_LIMIT;}
    for(i=0;i<FUNCTIONS;++i)if(s->functions[i].cookie==cookie){func=s->functions[i].value;break;}
    if(i==FUNCTIONS){leave();return M98_SCRIPT_STATE;}
    if(receiver){this_value=import_value(s,receiver,0);if(JS_IsException(this_value)){r=exception(s);leave();return r;}}
    for(i=0;i<argc;++i){values[i]=import_value(s,&argv[i],0);if(JS_IsException(values[i])){for(j=0;j<i;++j)JS_FreeValue(s->context,values[j]);JS_FreeValue(s->context,this_value);r=exception(s);leave();return r;}}
    returned=JS_Call(s->context,func,this_value,(int)argc,values);JS_FreeValue(s->context,this_value);for(i=0;i<argc;++i)JS_FreeValue(s->context,values[i]);
    r=publish(s,returned,out);s->detail.result=r;leave();return r;
}
int m98_script_invoke(m98_script_context h,uint32_t cookie,const m98_script_value *argv,uint32_t argc,m98_script_result *out){return m98_script_invoke_this(h,cookie,NULL,argv,argc,out);}
int m98_script_jobs(m98_script_context h,uint32_t *done){script *s;JSContext *context;int r;
    if(!done)return M98_SCRIPT_INVALID;
    *done=0;r=acquire(h,&s);if(r)return r;begin(s);
    while(JS_IsJobPending(s->runtime)){
        if(s->detail.jobs==s->options.job_limit){s->detail.result=M98_SCRIPT_LIMIT;*done=s->detail.jobs;leave();return M98_SCRIPT_LIMIT;}
        r=JS_ExecutePendingJob(s->runtime,&context);if(r<0){r=exception(s);*done=s->detail.jobs;leave();return r;}
        if(!r)break;
        ++s->detail.jobs;
    }*done=s->detail.jobs;leave();return 0;
}
int m98_script_release_result(m98_script_context h,uint32_t cookie){script *s;unsigned i;int r=acquire(h,&s);if(r)return r;
    for(i=0;i<RESULTS;++i)if(cookie&&s->results[i].cookie==cookie){js_free(s->context,s->results[i].string);memset(&s->results[i],0,sizeof(s->results[i]));leave();return 0;}
    leave();return M98_SCRIPT_STATE;
}
int m98_script_info(m98_script_context h,m98_script_details *out){script *s;int r;if(!out||out->size!=sizeof(*out))return M98_SCRIPT_INVALID;r=acquire(h,&s);if(r)return r;*out=s->detail;leave();return 0;}
int m98_script_close(m98_script_context h){script *s;int r=acquire(h,&s);if(r)return r;destroy(s);leave();return 0;}
