/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded adapter to real IDispatch/IDispatchEx, not a DOM model. */
#include "m98_trident_automation.h"
#ifdef M98_AUTOMATION_HOST_TEST
#include "m98_trident_automation_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <oleauto.h>
#include <dispex.h>
#endif
#include <new>
#include <stdint.h>
#include <string.h>

static const GUID g_unknown={0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID g_dispatch={0x20400,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID g_dispatchex={0xa6ef9860,0xc720,0x11d0,{0x93,0x37,0,0xa0,0xc9,0x0d,0xca,0xa9}};
static const GUID g_null={0,0,0,{0,0,0,0,0,0,0,0}};
static bool eq(const GUID &a,const GUID &b){return memcmp(&a,&b,sizeof a)==0;}
static void zero(void *p,size_t n){memset(p,0,n);}
static void init(m98_script_value *v){zero(v,sizeof *v);v->size=sizeof *v;}
static void vi(VARIANT *v){zero(v,sizeof *v);}
static bool bad(HRESULT h){return h<0;}
static bool name_ok(const uint16_t *s,uint32_t n){
    if(!s||!n||n>256)return false;
    for(uint32_t i=0;i<n;i++)if(!s[i])return false;
    return true;
}
struct Object {uint32_t cookie,refs;IUnknown *identity;IDispatch *dispatch;IDispatchEx *ex;};
class Callback;
struct Pending {uint32_t function,count,has_receiver;m98_script_value receiver,args[32];};
struct Context {
    uint32_t cookie,thread,pumping,queuing,head,count;
    m98_automation_options options;
    m98_automation_error error;
    Object objects[128];Callback *callbacks[64];Pending pending[32];BSTR strings[128];
};
static Context contexts[4];
static LONG ui_thread;
static uint32_t next_cookie=1,com_depth;
static uint32_t fresh(){if(next_cookie==UINT32_MAX)return 0;return next_cookie++;}
static Context *lookup(uint32_t cookie){
    if(!cookie)return 0;
    for(unsigned i=0;i<4;i++)if(contexts[i].cookie==cookie)return &contexts[i];
    return 0;
}
static HRESULT enter(uint32_t cookie,Context **out,bool allow_pump=false){
    // Reject foreign threads before touching UI-owned slots or com_depth.
    LONG owner=InterlockedCompareExchange(&ui_thread,0,0);
    if(!owner)return M98_AUTO_STATE;
    if(owner!=(LONG)GetCurrentThreadId())return M98_AUTO_THREAD;
    Context *c=lookup(cookie);if(!c)return M98_AUTO_STATE;
    if(com_depth||(!allow_pump&&c->pumping))return M98_AUTO_BUSY;
    *out=c;return S_OK;
}
struct COMScope {COMScope(){++com_depth;}~COMScope(){--com_depth;}};
static Object *object(Context *c,uint32_t cookie){
    if(!cookie)return 0;
    for(unsigned i=0;i<128;i++)if(c->objects[i].cookie==cookie)return &c->objects[i];
    return 0;
}
static HRESULT remember(Context *c,IUnknown *source,uint32_t *cookie){
    if(!source)return E_INVALIDARG;
    IUnknown *identity=0;IDispatch *dispatch=0;IDispatchEx *ex=0;
    HRESULT h=source->QueryInterface(g_unknown,(void **)&identity);
    if(bad(h)||!identity){if(identity)identity->Release();return bad(h)?h:E_NOINTERFACE;}
    for(unsigned i=0;i<128;i++)if(c->objects[i].identity==identity){
        identity->Release();
        if(c->objects[i].refs==UINT32_MAX)return M98_AUTO_LIMIT;
        ++c->objects[i].refs;*cookie=c->objects[i].cookie;return S_OK;
    }
    Object *o=0;for(unsigned i=0;i<128;i++)if(!c->objects[i].cookie){o=&c->objects[i];break;}
    if(!o){identity->Release();return M98_AUTO_LIMIT;}
    h=source->QueryInterface(g_dispatch,(void **)&dispatch);
    if(bad(h)||!dispatch){if(dispatch)dispatch->Release();identity->Release();return bad(h)?h:E_NOINTERFACE;}
    h=source->QueryInterface(g_dispatchex,(void **)&ex);
    if(bad(h)){if(ex)ex->Release();ex=0;if(h!=E_NOINTERFACE){dispatch->Release();identity->Release();return h;}}
    uint32_t token=fresh();if(!token){if(ex)ex->Release();dispatch->Release();identity->Release();return M98_AUTO_LIMIT;}
    o->cookie=token;o->refs=1;o->identity=identity;o->dispatch=dispatch;o->ex=ex;*cookie=token;return S_OK;
}
static HRESULT retain(Context *c,uint32_t cookie){Object *o=object(c,cookie);if(!o)return M98_AUTO_STATE;
    if(o->refs==UINT32_MAX)return M98_AUTO_LIMIT;
    ++o->refs;return S_OK;}
static HRESULT release(Context *c,uint32_t cookie){Object *o=object(c,cookie);if(!o)return M98_AUTO_STATE;
    if(--o->refs==0){IUnknown *u=o->identity;IDispatch *d=o->dispatch;IDispatchEx *x=o->ex;zero(o,sizeof *o);
        if(x)x->Release();
        d->Release();u->Release();}return S_OK;}
static HRESULT own_string(Context *c,const OLECHAR *s,uint32_t n,BSTR *out){
    unsigned i;for(i=0;i<128;i++)if(!c->strings[i])break;
    if(i==128)return M98_AUTO_LIMIT;
    BSTR b=SysAllocStringLen(s,n);if(!b)return E_OUTOFMEMORY;
    c->strings[i]=b;*out=b;return S_OK;
}
static HRESULT free_string(Context *c,const uint16_t *s){
    for(unsigned i=0;i<128;i++)if(c->strings[i]==(BSTR)s){
        if(!s)return E_INVALIDARG;
        c->strings[i]=0;SysFreeString((BSTR)s);return S_OK;
    }
    return E_INVALIDARG;
}
static HRESULT clear_value(Context *c,m98_script_value *v){
    HRESULT h=S_OK;
    if(v->type==M98_SCRIPT_STRING||v->type==M98_SCRIPT_METHOD){h=free_string(c,v->string);if(bad(h))return h;}
    if(v->type==M98_SCRIPT_OBJECT||v->type==M98_SCRIPT_METHOD)h=release(c,v->cookie);
    init(v);return h;
}
static HRESULT own_function(Context *,IUnknown *,uint32_t *);
static HRESULT from_variant(Context *c,const VARIANT *v,m98_script_value *out){
    init(out); // Unsupported BYREF, SAFEARRAY, DATE/CY/DECIMAL/ERROR fail explicitly.
    switch(v->vt){
    case VT_EMPTY:out->type=M98_SCRIPT_UNDEFINED;return S_OK;
    case VT_NULL:out->type=M98_SCRIPT_NULL;return S_OK;
    case VT_BOOL:out->type=M98_SCRIPT_BOOL;out->integer=v->boolVal!=VARIANT_FALSE;return S_OK;
    case VT_I1:out->integer=v->cVal;break;case VT_UI1:out->integer=v->bVal;break;
    case VT_I2:out->integer=v->iVal;break;case VT_UI2:out->integer=v->uiVal;break;
    case VT_I4:case VT_INT:out->integer=v->lVal;break;
    case VT_UI4:case VT_UINT:out->type=M98_SCRIPT_NUMBER;out->number=v->ulVal;return S_OK;
    case VT_R4:out->type=M98_SCRIPT_NUMBER;out->number=v->fltVal;return S_OK;
    case VT_R8:out->type=M98_SCRIPT_NUMBER;out->number=v->dblVal;return S_OK;
    case VT_BSTR:{uint32_t n=v->bstrVal?SysStringLen(v->bstrVal):0;if(n>65536)return M98_AUTO_LIMIT;
        BSTR s=0;HRESULT h=own_string(c,v->bstrVal,n,&s);if(bad(h))return h;
        out->type=M98_SCRIPT_STRING;out->string=(uint16_t *)s;out->units=n;return S_OK;}
    case VT_DISPATCH:case VT_UNKNOWN:{IUnknown *u=v->vt==VT_DISPATCH?(IUnknown *)v->pdispVal:v->punkVal;
        if(!u){out->type=M98_SCRIPT_NULL;return S_OK;}
        HRESULT h=own_function(c,u,&out->cookie);if(bad(h))return h;
        if(h==S_OK){out->type=M98_SCRIPT_FUNCTION;return S_OK;}
        h=remember(c,u,&out->cookie);if(bad(h))return h;out->type=M98_SCRIPT_OBJECT;return S_OK;}
    default:return M98_AUTO_TYPE;
    }out->type=M98_SCRIPT_INT32;return S_OK;
}
static HRESULT resolve(Object *o,const uint16_t *name,uint32_t n,DISPID *id){
    BSTR s=SysAllocStringLen((const OLECHAR *)name,n);if(!s)return E_OUTOFMEMORY;
    HRESULT h;
    if(o->ex)h=o->ex->GetDispID(s,fdexNameCaseSensitive,id);
    else {OLECHAR *names[]={s};h=o->dispatch->GetIDsOfNames(g_null,names,1,LOCALE_USER_DEFAULT,id);}
    SysFreeString(s);return h;
}
static void diagnostic(Context *c,HRESULT h,EXCEPINFO *e,UINT arg,uint32_t count){
    zero(&c->error,sizeof c->error);c->error.size=sizeof c->error;c->error.hresult=h;
    c->error.argument=(arg<count)?count-arg-1:UINT32_MAX;
    if(h==DISP_E_EXCEPTION&&e->pfnDeferredFillIn){HRESULT fill=e->pfnDeferredFillIn(e);if(bad(fill)&&!e->scode)e->scode=fill;}
    c->error.exception_scode=e->scode;
    if(e->bstrDescription){uint32_t n=SysStringLen(e->bstrDescription);if(n>256)n=256;
        for(uint32_t i=0;i<n;i++)c->error.description[i]=e->bstrDescription[i];
        c->error.description_units=n;}
    SysFreeString(e->bstrSource);SysFreeString(e->bstrDescription);SysFreeString(e->bstrHelpFile);
}
static HRESULT capabilities(Object *o,DISPID id,DWORD request,DWORD *flags){
    *flags=0;
    if(o->ex){HRESULT h=o->ex->GetMemberProperties(id,request,flags);
        if(!bad(h)){*flags&=request;return S_OK;}
        if(h!=E_NOTIMPL)return h;
    }
    ITypeInfo *info=0;HRESULT h=o->dispatch->GetTypeInfo(0,LOCALE_USER_DEFAULT,&info);
    if(bad(h)||!info){if(info)info->Release();return bad(h)?h:E_NOINTERFACE;}
    TYPEATTR *a=0;h=info->GetTypeAttr(&a);
    if(!bad(h)&&a){if(a->cFuncs>4096)h=M98_AUTO_LIMIT;else for(UINT i=0;i<a->cFuncs;i++){
        FUNCDESC *f=0;h=info->GetFuncDesc(i,&f);if(bad(h)||!f){if(f)info->ReleaseFuncDesc(f);if(!bad(h))h=E_FAIL;break;}
        if(f->memid==id){
            if(f->invkind&INVOKE_FUNC)*flags|=request&fdexPropCanCall;
            if(f->invkind&INVOKE_PROPERTYPUT)*flags|=request&fdexPropCanPut;
            if(f->invkind&INVOKE_PROPERTYPUTREF)*flags|=request&fdexPropCanPutRef;
        }
        info->ReleaseFuncDesc(f);
    }}else if(!bad(h))h=E_FAIL;
    if(a)info->ReleaseTypeAttr(a);
    info->Release();return h;
}
static HRESULT to_variant(Context *,const m98_script_value *,VARIANT *);

class Callback final:public IDispatchEx {
    volatile LONG refs;
public:
    Context *context;uint32_t generation,function,thread;
    Callback(Context *c,uint32_t f):refs(1),context(c),generation(c->cookie),function(f),thread(c->thread){}
    LONG count(){return InterlockedCompareExchange(&refs,0,0);}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void **p){
        if(!p)return E_POINTER;
        *p=0;
        if(eq(iid,g_unknown)||eq(iid,g_dispatch)||eq(iid,g_dispatchex)){*p=(IDispatchEx *)this;AddRef();return S_OK;}return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef(){return (ULONG)InterlockedIncrement(&refs);}
    ULONG STDMETHODCALLTYPE Release(){LONG r=InterlockedDecrement(&refs);if(!r){this->~Callback();HeapFree(GetProcessHeap(),0,this);}return (ULONG)r;}
    HRESULT STDMETHODCALLTYPE GetTypeInfoCount(UINT *n){if(!n)return E_POINTER;*n=0;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetTypeInfo(UINT,LCID,ITypeInfo **p){if(p)*p=0;return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetIDsOfNames(REFIID riid,LPOLESTR *names,UINT n,LCID,DISPID *ids){
        if(!eq(riid,g_null))return DISP_E_UNKNOWNINTERFACE;
        if(!names||!ids||n!=1)return E_INVALIDARG;
        if(names[0]&&names[0][0]==0){ids[0]=DISPID_VALUE;return S_OK;}ids[0]=DISPID_UNKNOWN;return DISP_E_UNKNOWNNAME;
    }
    HRESULT enqueue(DISPID id,WORD flags,DISPPARAMS *p,VARIANT *r){
        if(r)vi(r);
        if(thread!=GetCurrentThreadId())return M98_AUTO_THREAD;
        if(context->cookie!=generation)return RPC_E_DISCONNECTED;
        if(context->queuing)return M98_AUTO_BUSY;
        if(id!=DISPID_VALUE||(flags!=DISPATCH_METHOD&&flags!=(DISPATCH_METHOD|DISPATCH_PROPERTYGET)))return DISP_E_MEMBERNOTFOUND;
        if(!p||p->cNamedArgs>1||p->cNamedArgs>p->cArgs||p->cArgs-p->cNamedArgs>32||(!p->rgvarg&&p->cArgs))return DISP_E_BADPARAMCOUNT;
        if(p->cNamedArgs&&(!p->rgdispidNamedArgs||p->rgdispidNamedArgs[0]!=DISPID_THIS))return DISP_E_BADPARAMCOUNT;
        if(!context->options.dispatch)return E_NOTIMPL;
        if(context->count==32)return M98_AUTO_LIMIT;
        COMScope scope;context->queuing=1;
        Pending *q=&context->pending[(context->head+context->count)%32];zero(q,sizeof *q);
        q->function=function;
        if(p->cNamedArgs){HRESULT h=from_variant(context,&p->rgvarg[0],&q->receiver);
            if(bad(h)){zero(q,sizeof *q);context->queuing=0;return h;}q->has_receiver=1;}
        for(UINT i=0;i<p->cArgs-p->cNamedArgs;i++){
            HRESULT h=from_variant(context,&p->rgvarg[p->cArgs-1-i],&q->args[i]);
            if(bad(h)){for(UINT j=0;j<i;j++)clear_value(context,&q->args[j]);if(q->has_receiver)clear_value(context,&q->receiver);zero(q,sizeof *q);context->queuing=0;return h;}
            ++q->count;
        }
        ++context->count;context->queuing=0;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Invoke(DISPID id,REFIID riid,LCID,WORD flags,DISPPARAMS *p,VARIANT *r,EXCEPINFO *,UINT *){
        if(!eq(riid,g_null))return DISP_E_UNKNOWNINTERFACE;
        return enqueue(id,flags,p,r);
    }
    HRESULT STDMETHODCALLTYPE GetDispID(BSTR s,DWORD flags,DISPID *id){
        if(!id||!s)return E_INVALIDARG;
        *id=DISPID_UNKNOWN;
        if(flags!=fdexNameCaseSensitive&&flags!=fdexNameCaseInsensitive)return E_INVALIDARG;
        if(!SysStringLen(s)){*id=DISPID_VALUE;return S_OK;}return DISP_E_UNKNOWNNAME;
    }
    HRESULT STDMETHODCALLTYPE InvokeEx(DISPID id,LCID,WORD f,DISPPARAMS *p,VARIANT *r,EXCEPINFO *,IServiceProvider *){return enqueue(id,f,p,r);}
    HRESULT STDMETHODCALLTYPE DeleteMemberByName(BSTR,DWORD){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE DeleteMemberByDispID(DISPID){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetMemberProperties(DISPID id,DWORD request,DWORD *out){if(!out)return E_POINTER;if(id!=DISPID_VALUE)return DISP_E_MEMBERNOTFOUND;*out=request&fdexPropCanCall;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetMemberName(DISPID id,BSTR *out){if(!out)return E_POINTER;*out=0;if(id!=DISPID_VALUE)return DISP_E_MEMBERNOTFOUND;*out=SysAllocStringLen(0,0);return *out?S_OK:E_OUTOFMEMORY;}
    HRESULT STDMETHODCALLTYPE GetNextDispID(DWORD,DISPID id,DISPID *out){if(!out)return E_POINTER;*out=DISPID_UNKNOWN;if(id==DISPID_STARTENUM){*out=DISPID_VALUE;return S_OK;}return S_FALSE;}
    HRESULT STDMETHODCALLTYPE GetNameSpaceParent(IUnknown **out){if(!out)return E_POINTER;*out=0;return S_OK;}
};
static HRESULT own_function(Context *c,IUnknown *source,uint32_t *function){
    IUnknown *identity=0;HRESULT h=source->QueryInterface(g_unknown,(void **)&identity);
    if(bad(h)||!identity){if(identity)identity->Release();return bad(h)?h:E_NOINTERFACE;}
    bool found=false;
    for(unsigned i=0;i<64;i++)if(c->callbacks[i]&&(IUnknown *)(IDispatchEx *)c->callbacks[i]==identity){
        *function=c->callbacks[i]->function;found=true;break;
    }
    identity->Release();return found?S_OK:S_FALSE;
}
static void collect(Context *c){
    for(unsigned i=0;i<64;i++)if(c->callbacks[i]&&c->callbacks[i]->count()==1){
        Callback *p=c->callbacks[i];c->callbacks[i]=0;p->Release();
    }
}
static HRESULT callback(Context *c,uint32_t function,IDispatch **out){
    if(!function)return E_INVALIDARG;
    for(unsigned i=0;i<64;i++)if(c->callbacks[i]&&c->callbacks[i]->function==function){*out=c->callbacks[i];(*out)->AddRef();return S_OK;}
    collect(c);unsigned index=64;for(unsigned i=0;i<64;i++)if(!c->callbacks[i]){index=i;break;}
    if(index==64)return M98_AUTO_LIMIT;
    void *memory=HeapAlloc(GetProcessHeap(),0,sizeof(Callback));if(!memory)return E_OUTOFMEMORY;
    Callback *p=new(memory)Callback(c,function);c->callbacks[index]=p;*out=p;p->AddRef();return S_OK;
}
static HRESULT to_variant(Context *c,const m98_script_value *v,VARIANT *out){
    vi(out);if(!v||v->size!=sizeof *v)return E_INVALIDARG;
    if(v->type>M98_SCRIPT_FUNCTION)return M98_AUTO_TYPE;
    if((v->type==M98_SCRIPT_OBJECT||v->type==M98_SCRIPT_FUNCTION)&&!v->cookie)return E_INVALIDARG;
    if((v->type!=M98_SCRIPT_BOOL&&v->type!=M98_SCRIPT_INT32&&v->integer)||
       (v->type!=M98_SCRIPT_NUMBER&&v->number!=0)||
       (v->type!=M98_SCRIPT_OBJECT&&v->type!=M98_SCRIPT_FUNCTION&&v->cookie)||
       (v->type!=M98_SCRIPT_STRING&&(v->string||v->units)))return E_INVALIDARG;
    switch(v->type){
    case M98_SCRIPT_UNDEFINED:out->vt=VT_EMPTY;break;
    case M98_SCRIPT_NULL:out->vt=VT_NULL;break;
    case M98_SCRIPT_BOOL:if(v->integer!=0&&v->integer!=1)return E_INVALIDARG;out->vt=VT_BOOL;out->boolVal=v->integer?VARIANT_TRUE:VARIANT_FALSE;break;
    case M98_SCRIPT_INT32:out->vt=VT_I4;out->lVal=v->integer;break;
    case M98_SCRIPT_NUMBER:out->vt=VT_R8;out->dblVal=v->number;break;
    case M98_SCRIPT_STRING:if(v->units>65536||(!v->string&&v->units))return E_INVALIDARG;
        out->bstrVal=SysAllocStringLen((const OLECHAR *)v->string,v->units);if(!out->bstrVal)return E_OUTOFMEMORY;out->vt=VT_BSTR;break;
    case M98_SCRIPT_OBJECT:{Object *o=object(c,v->cookie);if(!o)return M98_AUTO_STATE;
        out->vt=VT_DISPATCH;out->pdispVal=o->dispatch;o->dispatch->AddRef();break;}
    case M98_SCRIPT_FUNCTION:{HRESULT h=callback(c,v->cookie,&out->pdispVal);if(bad(h))return h;out->vt=VT_DISPATCH;break;}
    default:return M98_AUTO_TYPE;
    }return S_OK;
}
static HRESULT invoke(Context *c,uint32_t cookie,const uint16_t *name,uint32_t n,
                      WORD flags,const m98_script_value *args,uint32_t count,m98_script_value *out){
    if(out)init(out);
    EXCEPINFO early;zero(&early,sizeof early);
    if(!name_ok(name,n)||count>32||(!args&&count)){diagnostic(c,E_INVALIDARG,&early,UINT32_MAX,count);return E_INVALIDARG;}
    Object *o=object(c,cookie);if(!o){diagnostic(c,M98_AUTO_STATE,&early,UINT32_MAX,count);return M98_AUTO_STATE;}
    COMScope scope;DISPID id=DISPID_UNKNOWN;HRESULT h=resolve(o,name,n,&id);
    if(bad(h)){diagnostic(c,h,&early,UINT32_MAX,count);return h;}
    if(flags==DISPATCH_PROPERTYPUTREF){
        DWORD setters=0;h=capabilities(o,id,fdexPropCanPut|fdexPropCanPutRef,&setters);
        if(!bad(h)){
            if(setters&fdexPropCanPutRef)flags=DISPATCH_PROPERTYPUTREF;
            else if(setters&fdexPropCanPut)flags=DISPATCH_PROPERTYPUT;
            else h=DISP_E_MEMBERNOTFOUND;
        }
        if(bad(h)){diagnostic(c,h,&early,UINT32_MAX,count);return h;}
    }
    VARIANT converted[32],result;EXCEPINFO ex;zero(converted,sizeof converted);vi(&result);zero(&ex,sizeof ex);
    UINT arg_error=UINT32_MAX;uint32_t made=0;
    for(;made<count;made++){h=to_variant(c,&args[count-1-made],&converted[made]);if(bad(h))break;}
    if(!bad(h)){
        DISPID put=DISPID_PROPERTYPUT;DISPPARAMS p={converted,0,count,0};
        if(flags==DISPATCH_PROPERTYPUT||flags==DISPATCH_PROPERTYPUTREF){p.rgdispidNamedArgs=&put;p.cNamedArgs=1;}
        if(o->ex)h=o->ex->InvokeEx(id,LOCALE_USER_DEFAULT,flags,&p,&result,&ex,0);
        else h=o->dispatch->Invoke(id,g_null,LOCALE_USER_DEFAULT,flags,&p,&result,&ex,&arg_error);
        if(bad(h)&&flags==DISPATCH_PROPERTYGET&&(h==DISP_E_MEMBERNOTFOUND||h==DISP_E_BADPARAMCOUNT)){
            DWORD properties=0;HRESULT metadata=capabilities(o,id,fdexPropCanCall,&properties);
            if(!bad(metadata)&&(properties&fdexPropCanCall)){BSTR s=0;h=own_string(c,(const OLECHAR *)name,n,&s);
                if(!bad(h)){h=retain(c,cookie);if(bad(h))(void)free_string(c,(uint16_t *)s);else{out->type=M98_SCRIPT_METHOD;out->cookie=cookie;out->string=(uint16_t *)s;out->units=n;}}
            }
        }else if(!bad(h)&&out)h=from_variant(c,&result,out);
    }
    diagnostic(c,h,&ex,arg_error,count);
    VariantClear(&result);for(uint32_t i=0;i<made;i++)VariantClear(&converted[i]);
    return h;
}
extern "C" int32_t m98_automation_open(const m98_automation_options *options,uint32_t *out){
    if(!options||options->size!=sizeof *options||!out)return E_INVALIDARG;
    DWORD thread=GetCurrentThreadId();LONG previous=InterlockedCompareExchange(&ui_thread,(LONG)thread,0);
    if(previous&&previous!=(LONG)thread)return M98_AUTO_THREAD;
    if(com_depth)return M98_AUTO_BUSY;
    Context *c=0;for(unsigned i=0;i<4;i++)if(!contexts[i].cookie){c=&contexts[i];break;}if(!c)return M98_AUTO_LIMIT;
    uint32_t cookie=fresh();if(!cookie)return M98_AUTO_LIMIT;zero(c,sizeof *c);c->cookie=cookie;c->thread=thread;c->options=*options;
    c->error.size=sizeof c->error;c->error.argument=UINT32_MAX;*out=cookie;return S_OK;
}
extern "C" int32_t m98_automation_attach(uint32_t token,void *unknown,uint32_t *cookie){
    Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;if(!cookie||!unknown)return E_INVALIDARG;
    COMScope scope;return remember(c,(IUnknown *)unknown,cookie);
}
extern "C" int32_t m98_automation_retain(uint32_t token,uint32_t cookie){Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;return retain(c,cookie);}
extern "C" int32_t m98_automation_release(uint32_t token,uint32_t cookie){Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;COMScope scope;return release(c,cookie);}
extern "C" int32_t m98_automation_get(uint32_t token,uint32_t cookie,const uint16_t *name,uint32_t n,m98_script_value *out){
    if(!out)return E_POINTER;
    init(out);Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;return invoke(c,cookie,name,n,DISPATCH_PROPERTYGET,0,0,out);
}
extern "C" int32_t m98_automation_set(uint32_t token,uint32_t cookie,const uint16_t *name,uint32_t n,const m98_script_value *v){
    Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;
    if(!v)return E_INVALIDARG;
    WORD flags=(v->type==M98_SCRIPT_OBJECT||v->type==M98_SCRIPT_FUNCTION)?DISPATCH_PROPERTYPUTREF:DISPATCH_PROPERTYPUT;
    return invoke(c,cookie,name,n,flags,v,1,0);
}
extern "C" int32_t m98_automation_call(uint32_t token,uint32_t cookie,const uint16_t *name,uint32_t n,const m98_script_value *args,uint32_t count,m98_script_value *out){
    if(!out)return E_POINTER;
    init(out);Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;return invoke(c,cookie,name,n,DISPATCH_METHOD,args,count,out);
}
extern "C" int32_t m98_automation_release_result(uint32_t token,m98_script_value *v){
    Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;if(!v||v->size!=sizeof *v)return E_INVALIDARG;COMScope scope;return clear_value(c,v);
}
extern "C" int32_t m98_automation_error_info(uint32_t token,m98_automation_error *out){Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;if(!out||out->size!=sizeof *out)return E_INVALIDARG;*out=c->error;return S_OK;}
extern "C" int32_t m98_automation_pump(uint32_t token,uint32_t maximum,uint32_t *completed){
    Context *c=0;HRESULT h=enter(token,&c);if(bad(h))return h;if(!completed||!maximum||maximum>32)return E_INVALIDARG;
    *completed=0;c->pumping=1;
    while(c->count&&*completed<maximum){Pending q=c->pending[c->head];zero(&c->pending[c->head],sizeof(Pending));c->head=(c->head+1)%32;--c->count;
        h=c->options.dispatch(c->options.user,q.function,q.has_receiver?&q.receiver:0,q.args,q.count);
        {COMScope scope;for(unsigned i=0;i<q.count;i++)clear_value(c,&q.args[i]);if(q.has_receiver)clear_value(c,&q.receiver);}++*completed;if(bad(h))break;
    }c->pumping=0;collect(c);return h;
}
extern "C" int32_t m98_automation_close(uint32_t token){
    Context *c=0;HRESULT h=enter(token,&c);if(bad(h))return h;
    COMScope scope;c->cookie=0;
    for(unsigned i=0;i<32;i++){
        for(unsigned j=0;j<c->pending[i].count;j++)clear_value(c,&c->pending[i].args[j]);
        if(c->pending[i].has_receiver)clear_value(c,&c->pending[i].receiver);
    }
    for(unsigned i=0;i<128;i++)if(c->objects[i].cookie){Object *o=&c->objects[i];if(o->ex)o->ex->Release();o->dispatch->Release();o->identity->Release();zero(o,sizeof *o);}
    for(unsigned i=0;i<64;i++)if(c->callbacks[i]){Callback *p=c->callbacks[i];c->callbacks[i]=0;p->Release();}
    for(unsigned i=0;i<128;i++)if(c->strings[i])SysFreeString(c->strings[i]);
    zero(c,sizeof *c);return S_OK;
}
static uint32_t user_token(void *p){return (uint32_t)(uintptr_t)p;}
static int32_t host_get(void *u,uint32_t o,const uint16_t *s,uint32_t n,m98_script_value *v){return m98_automation_get(user_token(u),o,s,n,v);}
static int32_t host_set(void *u,uint32_t o,const uint16_t *s,uint32_t n,const m98_script_value *v){return m98_automation_set(user_token(u),o,s,n,v);}
static int32_t host_call(void *u,uint32_t o,const uint16_t *s,uint32_t n,const m98_script_value *a,uint32_t count,m98_script_value *v){return m98_automation_call(user_token(u),o,s,n,a,count,v);}
static int32_t host_retain(void *u,uint32_t o){return m98_automation_retain(user_token(u),o);}
static void host_release(void *u,uint32_t o){(void)m98_automation_release(user_token(u),o);}
static void host_result(void *u,m98_script_value *v){(void)m98_automation_release_result(user_token(u),v);}
extern "C" int32_t m98_automation_host(uint32_t token,m98_script_host *out){
    Context *c=0;HRESULT h=enter(token,&c,true);if(bad(h))return h;if(!out||out->size!=sizeof *out)return E_INVALIDARG;
    m98_script_host host={sizeof host,(void *)(uintptr_t)token,host_get,host_set,host_call,host_retain,host_release,host_result};*out=host;return S_OK;
}
