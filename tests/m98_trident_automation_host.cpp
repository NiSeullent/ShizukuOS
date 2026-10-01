/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the production adapter through COM/OS doubles, never claim MSHTML. */
#include "m98_trident_automation.h"
#include "m98_trident_automation_mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static unsigned assertions,strings,heaps;
static int fail_after=-1;
static DWORD thread_id=7;
#define CHECK(x) do{++assertions;if(!(x)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(1);}}while(0)
static bool fail_alloc(){if(fail_after<0)return false;if(!fail_after)return true;--fail_after;return false;}
DWORD GetCurrentThreadId(){return thread_id;}
void *GetProcessHeap(){return (void *)1;}
void *HeapAlloc(void *,DWORD,size_t n){if(fail_alloc())return 0;void *p=calloc(1,n);if(p)++heaps;return p;}
int HeapFree(void *,DWORD,void *p){if(p){CHECK(heaps>0);--heaps;free(p);}return 1;}
LONG InterlockedIncrement(volatile LONG *p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
LONG InterlockedDecrement(volatile LONG *p){return __atomic_sub_fetch(p,1,__ATOMIC_SEQ_CST);}
LONG InterlockedCompareExchange(volatile LONG *p,LONG a,LONG b){__atomic_compare_exchange_n(p,&b,a,false,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return b;}
BSTR SysAllocStringLen(const OLECHAR *s,UINT n){
    if(fail_alloc())return 0;
    uint32_t *p=(uint32_t *)malloc(4+(size_t)(n+1)*2);if(!p)return 0;*p=n;
    BSTR result=(BSTR)(p+1);if(s)memcpy(result,s,(size_t)n*2);else memset(result,0,(size_t)n*2);
    result[n]=0;++strings;return result;
}
void SysFreeString(BSTR s){if(s){CHECK(strings>0);--strings;free((uint32_t *)s-1);}}
UINT SysStringLen(BSTR s){return s?*((uint32_t *)s-1):0;}
HRESULT VariantClear(VARIANT *v){
    if(v->vt==VT_BSTR)SysFreeString(v->bstrVal);
    if(v->vt==VT_DISPATCH&&v->pdispVal)v->pdispVal->Release();
    if(v->vt==VT_UNKNOWN&&v->punkVal)v->punkVal->Release();
    memset(v,0,sizeof *v);return S_OK;
}
static const GUID unknown_id={0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID null_id={0,0,0,{0,0,0,0,0,0,0,0}};
static bool guid(const GUID &a,const GUID &b){return memcmp(&a,&b,sizeof a)==0;}
static m98_script_value scalar(uint32_t type,int32_t n=0){m98_script_value v={};v.size=sizeof v;v.type=type;v.integer=n;return v;}
static m98_script_value number(double n){m98_script_value v=scalar(M98_SCRIPT_NUMBER);v.number=n;return v;}
static m98_script_value text(const uint16_t *s,uint32_t n){m98_script_value v=scalar(M98_SCRIPT_STRING);v.string=s;v.units=n;return v;}
static m98_script_value cookie(uint32_t type,uint32_t id){m98_script_value v=scalar(type);v.cookie=id;return v;}
static const uint16_t text_name[]={'t','e','x','t'},method_name[]={'a','d','d'},event_name[]={'e','v','e','n','t'},child_name[]={'c','h','i','l','d'},fail_name[]={'f','a','i','l'},type_name[]={'t','y','p','e'},reentry_name[]={'r','e','e','n','t','e','r'},missing_name[]={'a','b','s','e','n','t'},lie_name[]={'l','i','e'};
static const uint16_t korean[]={'A',0,0xd55c,0xae00,0xd800};

class TypeInfo final: public ITypeInfo {
public:
    ULONG refs;TYPEATTR attr;FUNCDESC func[2];bool fail_func;
    TypeInfo():refs(1),attr(),func(),fail_func(false){attr.cFuncs=2;func[0].memid=2;func[0].invkind=INVOKE_FUNC;func[1].memid=4;func[1].invkind=INVOKE_PROPERTYPUTREF;}
    HRESULT QueryInterface(REFIID,void **out){*out=this;AddRef();return S_OK;}
    ULONG AddRef(){return ++refs;}ULONG Release(){CHECK(refs>1);return --refs;}
    HRESULT GetTypeAttr(TYPEATTR **out){*out=&attr;return S_OK;}
    HRESULT GetFuncDesc(UINT i,FUNCDESC **out){if(i>=2||fail_func){*out=0;return E_FAIL;}*out=&func[i];return S_OK;}
    void ReleaseTypeAttr(TYPEATTR *a){CHECK(a==&attr);}void ReleaseFuncDesc(FUNCDESC *f){CHECK(f==&func[0]||f==&func[1]);}
};
class Dispatch final: public IDispatchEx {
public:
    ULONG refs;bool extended,metadata,provide_info,event_putref;unsigned invoked,resolved;
    TypeInfo info;IDispatch *event;IDispatch *child;uint16_t content[16];uint32_t units;
    VARTYPE output_type;uint32_t context,root;HRESULT reentry_result;
    Dispatch(bool ex=true):refs(1),extended(ex),metadata(true),provide_info(true),event_putref(true),invoked(0),resolved(0),event(0),child(0),content(),units(0),output_type(VT_EMPTY),context(0),root(0),reentry_result(0){}
    ~Dispatch(){CHECK(refs==1);if(event)event->Release();}
    HRESULT QueryInterface(REFIID id,void **out){*out=0;if(guid(id,unknown_id)||id.Data1==0x20400||(id.Data1==0xa6ef9860&&extended)){*out=(IDispatchEx *)this;AddRef();return S_OK;}return E_NOINTERFACE;}
    ULONG AddRef(){return ++refs;}ULONG Release(){CHECK(refs>1);return --refs;}
    HRESULT GetTypeInfoCount(UINT *n){*n=provide_info?1:0;return S_OK;}
    HRESULT GetTypeInfo(UINT n,LCID,ITypeInfo **out){*out=0;if(n||!provide_info)return E_NOTIMPL;*out=&info;info.AddRef();return S_OK;}
    DISPID name(BSTR s){
        const uint16_t *names[]={text_name,method_name,event_name,child_name,fail_name,type_name,reentry_name,lie_name};
        const unsigned sizes[]={4,3,5,5,4,4,7,3};const DISPID ids[]={1,2,4,3,5,6,7,8};
        UINT n=SysStringLen(s);for(unsigned i=0;i<8;i++)if(n==sizes[i]&&!memcmp(s,names[i],n*2))return ids[i];return -1;
    }
    HRESULT GetIDsOfNames(REFIID id,LPOLESTR *names,UINT n,LCID,DISPID *out){CHECK(guid(id,null_id));CHECK(n==1);++resolved;*out=name(names[0]);return *out<0?DISP_E_UNKNOWNNAME:S_OK;}
    HRESULT GetDispID(BSTR s,DWORD flags,DISPID *out){CHECK(flags==fdexNameCaseSensitive);++resolved;*out=name(s);return *out<0?DISP_E_UNKNOWNNAME:S_OK;}
    static HRESULT deferred(EXCEPINFO *e){e->bstrDescription=SysAllocStringLen(korean,5);e->bstrSource=SysAllocStringLen(korean,1);e->bstrHelpFile=SysAllocStringLen(0,0);e->scode=E_INVALIDARG;return S_OK;}
    HRESULT execute(DISPID id,WORD flags,DISPPARAMS *p,VARIANT *r,EXCEPINFO *e,UINT *arg){
        ++invoked;
        if(id==1){
            if(flags==DISPATCH_PROPERTYGET){r->vt=VT_BSTR;r->bstrVal=SysAllocStringLen(content,units);return r->bstrVal?S_OK:E_OUTOFMEMORY;}
            CHECK(flags==DISPATCH_PROPERTYPUT);CHECK(p->cArgs==1&&p->cNamedArgs==1&&p->rgdispidNamedArgs[0]==DISPID_PROPERTYPUT);
            if(p->rgvarg[0].vt!=VT_BSTR)return DISP_E_TYPEMISMATCH;units=SysStringLen(p->rgvarg[0].bstrVal);CHECK(units<=16);memcpy(content,p->rgvarg[0].bstrVal,units*2);return S_OK;
        }
        if(id==2){if(flags==DISPATCH_PROPERTYGET)return DISP_E_MEMBERNOTFOUND;CHECK(flags==DISPATCH_METHOD);CHECK(p->cNamedArgs==0);
            if(p->cArgs!=3)return DISP_E_BADPARAMCOUNT;
            CHECK(p->rgvarg[0].vt==VT_I4&&p->rgvarg[0].lVal==3);CHECK(p->rgvarg[1].lVal==2);CHECK(p->rgvarg[2].lVal==1);
            r->vt=VT_I4;r->lVal=123;return S_OK;}
        if(id==3){CHECK(flags==DISPATCH_PROPERTYGET);r->vt=VT_UNKNOWN;r->punkVal=child?child:this;r->punkVal->AddRef();return S_OK;}
        if(id==4){
            if(flags==DISPATCH_PROPERTYGET){r->vt=VT_DISPATCH;r->pdispVal=event;if(event)event->AddRef();return S_OK;}
            if(p->rgvarg[0].vt==VT_NULL){CHECK(flags==DISPATCH_PROPERTYPUT);if(event)event->Release();event=0;return S_OK;}
            CHECK(flags==(event_putref?DISPATCH_PROPERTYPUTREF:DISPATCH_PROPERTYPUT));CHECK(p->cNamedArgs==1&&p->rgdispidNamedArgs[0]==DISPID_PROPERTYPUT);
            CHECK(p->cArgs==1&&p->rgvarg[0].vt==VT_DISPATCH);if(event)event->Release();event=p->rgvarg[0].pdispVal;event->AddRef();return S_OK;
        }
        if(id==5){if(arg)*arg=0;e->pfnDeferredFillIn=deferred;return DISP_E_EXCEPTION;}
        if(id==6){CHECK(flags==DISPATCH_PROPERTYGET);r->vt=output_type;switch(output_type){
            case VT_BOOL:r->boolVal=VARIANT_TRUE;break;case VT_I1:r->cVal=-128;break;case VT_UI1:r->bVal=255;break;
            case VT_I2:r->iVal=-32768;break;case VT_UI2:r->uiVal=65535;break;case VT_I4:case VT_INT:r->lVal=INT32_MIN;break;
            case VT_UI4:case VT_UINT:r->ulVal=UINT32_MAX;break;case VT_R4:r->fltVal=1.25f;break;case VT_R8:r->dblVal=INFINITY;break;
            case VT_BSTR:r->bstrVal=0;break;case VT_UNKNOWN:r->punkVal=0;break;case VT_DISPATCH:r->pdispVal=0;break;default:break;}return S_OK;}
        if(id==7){m98_script_value v;reentry_result=m98_automation_get(context,root,text_name,4,&v);r->vt=VT_EMPTY;return S_OK;}
        if(id==8)return DISP_E_MEMBERNOTFOUND;return DISP_E_MEMBERNOTFOUND;
    }
    HRESULT Invoke(DISPID id,REFIID riid,LCID,WORD flags,DISPPARAMS *p,VARIANT *r,EXCEPINFO *e,UINT *a){CHECK(guid(riid,null_id));return execute(id,flags,p,r,e,a);}
    HRESULT InvokeEx(DISPID id,LCID,WORD flags,DISPPARAMS *p,VARIANT *r,EXCEPINFO *e,IServiceProvider *caller){CHECK(caller==0);return execute(id,flags,p,r,e,0);}
    HRESULT DeleteMemberByName(BSTR,DWORD){return E_NOTIMPL;}HRESULT DeleteMemberByDispID(DISPID){return E_NOTIMPL;}
    HRESULT GetMemberProperties(DISPID id,DWORD request,DWORD *out){CHECK(request==fdexPropCanCall||request==(fdexPropCanPut|fdexPropCanPutRef));if(!metadata)return E_NOTIMPL;*out=0;
        if(id==2)*out=fdexPropCanCall&request;
        if(id==4)*out=(event_putref?fdexPropCanPutRef:fdexPropCanPut)&request;
        return S_OK;}
    HRESULT GetMemberName(DISPID,BSTR *out){*out=0;return E_NOTIMPL;}HRESULT GetNextDispID(DWORD,DISPID,DISPID *){return E_NOTIMPL;}HRESULT GetNameSpaceParent(IUnknown **p){*p=0;return S_OK;}
};
/* Different interface address, same canonical IUnknown identity. */
class Alias: public IUnknown {
    Dispatch *owner;
public:explicit Alias(Dispatch *o):owner(o){}
    HRESULT QueryInterface(REFIID i,void **p){return owner->QueryInterface(i,p);}
    ULONG AddRef(){return owner->AddRef();}ULONG Release(){return owner->Release();}
};
struct Delivery {uint32_t context,root,received,last_function;bool fail,check_args,check_receiver;};
static int32_t dispatch(void *user,uint32_t function,const m98_script_value *receiver,const m98_script_value *args,uint32_t count){
    Delivery *d=(Delivery *)user;++d->received;d->last_function=function;
    uint32_t completed=99;CHECK(m98_automation_pump(d->context,1,&completed)==M98_AUTO_BUSY);CHECK(completed==99);
    CHECK(m98_automation_close(d->context)==M98_AUTO_BUSY);
    if(d->check_args){CHECK(count==2);CHECK(args[0].type==M98_SCRIPT_STRING&&args[0].units==5&&!memcmp(args[0].string,korean,10));CHECK(args[1].type==M98_SCRIPT_INT32&&args[1].integer==42);}
    if(d->check_receiver)CHECK(receiver&&receiver->type==M98_SCRIPT_OBJECT&&receiver->cookie==d->root);
    m98_script_value v;CHECK(m98_automation_get(d->context,d->root,text_name,4,&v)==S_OK);CHECK(m98_automation_release_result(d->context,&v)==S_OK);
    return d->fail?E_FAIL:S_OK;
}
static HRESULT fire(IDispatch *event,VARIANT *args=0,UINT count=0){DISPPARAMS p={args,0,count,0};VARIANT result={};EXCEPINFO e={};UINT a=0;
    HRESULT h=event->Invoke(DISPID_VALUE,null_id,0,DISPATCH_METHOD,&p,&result,&e,&a);CHECK(result.vt==VT_EMPTY);return h;}
static void run(bool extended){
    Dispatch document(extended);Delivery delivery={};m98_automation_options options={sizeof options,&delivery,dispatch};uint32_t c=0,root=0;
    CHECK(m98_automation_open(&options,&c)==S_OK);delivery.context=c;
    CHECK(m98_automation_attach(c,&document,&root)==S_OK);delivery.root=root;document.context=c;document.root=root;
    CHECK(m98_automation_retain(c,0)==M98_AUTO_STATE);CHECK(m98_automation_release(c,0)==M98_AUTO_STATE);
    CHECK(document.refs==(extended?4u:3u));Alias alias(&document);uint32_t same=0;
    CHECK(m98_automation_attach(c,&alias,&same)==S_OK&&same==root);CHECK(document.refs==(extended?4u:3u));CHECK(m98_automation_release(c,same)==S_OK);
    m98_script_host host={};host.size=sizeof host;CHECK(m98_automation_host(c,&host)==S_OK);
    m98_script_value value=text(korean,5),out;
    CHECK(host.set(host.user,root,text_name,4,&value)==S_OK);
    CHECK(host.get(host.user,root,text_name,4,&out)==S_OK);CHECK(out.type==M98_SCRIPT_STRING&&out.units==5&&!memcmp(out.string,korean,10));host.release_result(host.user,&out);
    CHECK(host.get(host.user,root,method_name,3,&out)==S_OK);CHECK(out.type==M98_SCRIPT_METHOD&&out.cookie==root&&out.units==3&&!memcmp(out.string,method_name,6));host.release_result(host.user,&out);
    m98_script_value args[]={scalar(M98_SCRIPT_INT32,1),scalar(M98_SCRIPT_INT32,2),scalar(M98_SCRIPT_INT32,3)};
    CHECK(host.call(host.user,root,method_name,3,args,3,&out)==S_OK&&out.integer==123);host.release_result(host.user,&out);
    CHECK(host.get(host.user,root,child_name,5,&out)==S_OK&&out.type==M98_SCRIPT_OBJECT&&out.cookie==root);CHECK(host.retain(host.user,out.cookie)==S_OK);host.release_result(host.user,&out);host.release(host.user,root);
    CHECK(host.get(host.user,root,missing_name,6,&out)==DISP_E_UNKNOWNNAME);host.release_result(host.user,&out);
    CHECK(host.get(host.user,root,lie_name,3,&out)==DISP_E_MEMBERNOTFOUND);CHECK(out.type==M98_SCRIPT_UNDEFINED);host.release_result(host.user,&out);
    document.metadata=false;CHECK(host.get(host.user,root,method_name,3,&out)==S_OK&&out.type==M98_SCRIPT_METHOD);host.release_result(host.user,&out);
    document.info.fail_func=true;CHECK(host.get(host.user,root,method_name,3,&out)==DISP_E_MEMBERNOTFOUND);host.release_result(host.user,&out);document.info.fail_func=false;
    document.info.attr.cFuncs=4097;CHECK(host.get(host.user,root,method_name,3,&out)==DISP_E_MEMBERNOTFOUND);host.release_result(host.user,&out);document.info.attr.cFuncs=2;
    document.provide_info=false;CHECK(host.get(host.user,root,method_name,3,&out)==DISP_E_MEMBERNOTFOUND);host.release_result(host.user,&out);document.provide_info=true;document.metadata=true;
    CHECK(host.call(host.user,root,fail_name,4,args,3,&out)==DISP_E_EXCEPTION);host.release_result(host.user,&out);
    m98_automation_error error={};error.size=sizeof error;CHECK(m98_automation_error_info(c,&error)==S_OK);CHECK(error.hresult==DISP_E_EXCEPTION&&error.exception_scode==E_INVALIDARG&&error.description_units==5&&!memcmp(error.description,korean,10));CHECK(error.argument==(extended?UINT32_MAX:2u));
    CHECK(host.get(host.user,root,missing_name,6,&out)==DISP_E_UNKNOWNNAME);host.release_result(host.user,&out);
    CHECK(m98_automation_error_info(c,&error)==S_OK&&error.hresult==DISP_E_UNKNOWNNAME&&error.exception_scode==0&&error.description_units==0&&error.argument==UINT32_MAX);
    CHECK(host.get(host.user,root,reentry_name,7,&out)==S_OK&&document.reentry_result==M98_AUTO_BUSY);host.release_result(host.user,&out);
    const VARTYPE types[]={VT_EMPTY,VT_NULL,VT_BOOL,VT_I1,VT_UI1,VT_I2,VT_UI2,VT_I4,VT_INT,VT_UI4,VT_UINT,VT_R4,VT_R8,VT_BSTR,VT_UNKNOWN,VT_DISPATCH};
    for(unsigned i=0;i<sizeof types/sizeof *types;i++){
        document.output_type=types[i];CHECK(host.get(host.user,root,type_name,4,&out)==S_OK);
        if(types[i]==VT_UI4||types[i]==VT_UINT)CHECK(out.type==M98_SCRIPT_NUMBER&&out.number==4294967295.0);
        if(types[i]==VT_R8)CHECK(isinf(out.number));
        if(types[i]==VT_BSTR)CHECK(out.type==M98_SCRIPT_STRING&&out.units==0&&out.string);
        if(types[i]==VT_UNKNOWN||types[i]==VT_DISPATCH)CHECK(out.type==M98_SCRIPT_NULL);
        host.release_result(host.user,&out);
    }
    const VARTYPE rejected[]={VT_BYREF|VT_I4,VT_ARRAY|VT_I4,VT_CY,VT_DATE,VT_ERROR,12,14,20};
    for(unsigned i=0;i<sizeof rejected/sizeof *rejected;i++){document.output_type=rejected[i];CHECK(host.get(host.user,root,type_name,4,&out)==M98_AUTO_TYPE);host.release_result(host.user,&out);}
    unsigned before=document.invoked;value=scalar(M98_SCRIPT_BOOL,2);CHECK(host.set(host.user,root,text_name,4,&value)==E_INVALIDARG);value=number(1.25);value.cookie=33;CHECK(host.set(host.user,root,text_name,4,&value)==E_INVALIDARG);CHECK(document.invoked==before);
    value=cookie(M98_SCRIPT_OBJECT,0);before=document.invoked;CHECK(host.set(host.user,root,event_name,5,&value)==E_INVALIDARG&&document.invoked==before);
    value=cookie(M98_SCRIPT_FUNCTION,0);CHECK(host.set(host.user,root,event_name,5,&value)==E_INVALIDARG&&document.invoked==before);
    CHECK(host.get(host.user,0,text_name,4,&out)==M98_AUTO_STATE);host.release_result(host.user,&out);
    CHECK(host.call(host.user,0,method_name,3,args,3,&out)==M98_AUTO_STATE);host.release_result(host.user,&out);
    uint16_t nul_name[]={'t',0};CHECK(host.get(host.user,root,nul_name,2,&out)==E_INVALIDARG);host.release_result(host.user,&out);
    thread_id=8;CHECK(host.get(host.user,root,text_name,4,&out)==M98_AUTO_THREAD);CHECK(m98_automation_close(c)==M98_AUTO_THREAD);CHECK(m98_automation_close(0xabcdef)==M98_AUTO_THREAD);thread_id=7;
    for(int failure=0;failure<4;failure++){fail_after=failure;HRESULT h=host.get(host.user,root,text_name,4,&out);fail_after=-1;CHECK(h==S_OK||h==E_OUTOFMEMORY);host.release_result(host.user,&out);}
    value=cookie(M98_SCRIPT_FUNCTION,51);CHECK(host.set(host.user,root,event_name,5,&value)==S_OK);CHECK(document.event);
    CHECK(host.get(host.user,root,event_name,5,&out)==S_OK&&out.type==M98_SCRIPT_FUNCTION&&out.cookie==51);host.release_result(host.user,&out);
    IDispatch *event=document.event;event->AddRef();VARIANT native_args[2]={};native_args[0].vt=VT_I4;native_args[0].lVal=42;native_args[1].vt=VT_BSTR;native_args[1].bstrVal=SysAllocStringLen(korean,5);
    CHECK(fire(event,native_args,2)==S_OK&&delivery.received==0);VariantClear(&native_args[1]);delivery.check_args=true;
    uint32_t completed=0;CHECK(m98_automation_pump(c,1,&completed)==S_OK&&completed==1&&delivery.received==1&&delivery.last_function==51);delivery.check_args=false;
    VARIANT named[2]={};named[0].vt=VT_DISPATCH;named[0].pdispVal=&document;named[1].vt=VT_I4;named[1].lVal=17;DISPID this_id=DISPID_THIS;DISPPARAMS parameters={named,&this_id,2,1};VARIANT result={};EXCEPINFO exception={};
    CHECK(event->Invoke(0,null_id,0,DISPATCH_METHOD|DISPATCH_PROPERTYGET,&parameters,&result,&exception,0)==S_OK);delivery.check_receiver=true;
    CHECK(m98_automation_pump(c,1,&completed)==S_OK&&completed==1);delivery.check_receiver=false;
    this_id=DISPID_PROPERTYPUT;CHECK(event->Invoke(0,null_id,0,DISPATCH_METHOD,&parameters,&result,&exception,0)==DISP_E_BADPARAMCOUNT);
    parameters.rgdispidNamedArgs=0;CHECK(event->Invoke(0,null_id,0,DISPATCH_METHOD,&parameters,&result,&exception,0)==DISP_E_BADPARAMCOUNT);
    thread_id=8;CHECK(fire(event)==M98_AUTO_THREAD);thread_id=7;
    native_args[0].vt=VT_BYREF|VT_I4;CHECK(fire(event,native_args,1)==M98_AUTO_TYPE);
    for(unsigned i=0;i<32;i++)CHECK(fire(event)==S_OK);CHECK(fire(event)==M98_AUTO_LIMIT);
    delivery.fail=true;CHECK(m98_automation_pump(c,32,&completed)==E_FAIL&&completed==1);delivery.fail=false;
    CHECK(m98_automation_pump(c,32,&completed)==S_OK&&completed==31);
    document.event_putref=false;document.info.func[1].invkind=INVOKE_PROPERTYPUT;
    value=cookie(M98_SCRIPT_FUNCTION,52);before=document.invoked;CHECK(host.set(host.user,root,event_name,5,&value)==S_OK&&document.invoked==before+1);
    CHECK(host.get(host.user,root,event_name,5,&out)==S_OK&&out.type==M98_SCRIPT_FUNCTION&&out.cookie==52);host.release_result(host.user,&out);
    document.metadata=false;document.info.fail_func=true;before=document.invoked;
    CHECK(host.set(host.user,root,event_name,5,&value)==E_FAIL&&document.invoked==before);document.info.fail_func=false;document.metadata=true;
    value=scalar(M98_SCRIPT_NULL);CHECK(host.set(host.user,root,event_name,5,&value)==S_OK);CHECK(!document.event);
    CHECK(fire(event)==S_OK);uint32_t stale=c;CHECK(m98_automation_close(c)==S_OK);CHECK(document.refs==1);CHECK(m98_automation_close(stale)==M98_AUTO_STATE);CHECK(fire(event)==RPC_E_DISCONNECTED);
    CHECK(m98_automation_open(&options,&c)==S_OK&&c!=stale);CHECK(m98_automation_retain(c,root)==M98_AUTO_STATE);CHECK(fire(event)==RPC_E_DISCONNECTED);event->Release();CHECK(m98_automation_close(c)==S_OK);
    CHECK(strings==0&&heaps==0&&document.info.refs==1);
}
static void wrapper_and_string_bounds(){
    Dispatch document;Delivery delivery={};m98_automation_options options={sizeof options,&delivery,dispatch};uint32_t c=0,root=0;
    CHECK(m98_automation_open(&options,&c)==S_OK);delivery.context=c;CHECK(m98_automation_attach(c,&document,&root)==S_OK);delivery.root=root;
    IDispatch *wrappers[64]={};m98_script_value value,out;
    for(unsigned i=0;i<64;i++){
        value=cookie(M98_SCRIPT_FUNCTION,1000+i);CHECK(m98_automation_set(c,root,event_name,5,&value)==S_OK);wrappers[i]=document.event;wrappers[i]->AddRef();
    }
    value=cookie(M98_SCRIPT_FUNCTION,2000);CHECK(m98_automation_set(c,root,event_name,5,&value)==M98_AUTO_LIMIT);
    value=cookie(M98_SCRIPT_FUNCTION,1000);CHECK(m98_automation_set(c,root,event_name,5,&value)==S_OK&&document.event==wrappers[0]);
    for(unsigned i=1;i<64;i++)wrappers[i]->Release();uint32_t completed=99;CHECK(m98_automation_pump(c,1,&completed)==S_OK&&completed==0);
    value=cookie(M98_SCRIPT_FUNCTION,2000);CHECK(m98_automation_set(c,root,event_name,5,&value)==S_OK);
    VARIANT a[2]={};a[0].vt=VT_BYREF|VT_I4;a[1].vt=VT_BSTR;a[1].bstrVal=SysAllocStringLen(korean,5);unsigned before=strings;
    CHECK(fire(document.event,a,2)==M98_AUTO_TYPE&&strings==before);VariantClear(&a[1]);
    value=text(korean,5);CHECK(m98_automation_set(c,root,text_name,4,&value)==S_OK);
    m98_script_value outputs[128];for(unsigned i=0;i<128;i++)CHECK(m98_automation_get(c,root,text_name,4,&outputs[i])==S_OK);
    CHECK(m98_automation_get(c,root,text_name,4,&out)==M98_AUTO_LIMIT);CHECK(m98_automation_release_result(c,&out)==S_OK);
    m98_script_value copied=outputs[0];CHECK(m98_automation_release_result(c,&outputs[0])==S_OK);CHECK(m98_automation_release_result(c,&copied)==E_INVALIDARG);
    fail_after=1; // name lookup allocates once; wrapper creation then fails.
    value=cookie(M98_SCRIPT_FUNCTION,3000);CHECK(m98_automation_set(c,root,event_name,5,&value)==E_OUTOFMEMORY);fail_after=-1;
    IDispatch *last=document.event;last->AddRef();value=scalar(M98_SCRIPT_NULL);CHECK(m98_automation_set(c,root,event_name,5,&value)==S_OK);
    CHECK(m98_automation_close(c)==S_OK);CHECK(strings==0);CHECK(fire(wrappers[0])==RPC_E_DISCONNECTED);CHECK(fire(last)==RPC_E_DISCONNECTED);
    thread_id=8;wrappers[0]->Release();last->Release();thread_id=7;CHECK(heaps==0&&document.refs==1);
}
static void bounds(){
    m98_automation_options options={sizeof options,0,0};uint32_t contexts[5]={};
    for(unsigned i=0;i<4;i++)CHECK(m98_automation_open(&options,&contexts[i])==S_OK);
    CHECK(m98_automation_open(&options,&contexts[4])==M98_AUTO_LIMIT&&contexts[4]==0);
    Dispatch objects[129];uint32_t ids[129]={};
    for(unsigned i=0;i<128;i++)CHECK(m98_automation_attach(contexts[0],&objects[i],&ids[i])==S_OK);
    CHECK(m98_automation_attach(contexts[0],&objects[128],&ids[128])==M98_AUTO_LIMIT&&objects[128].refs==1&&ids[128]==0);
    uint32_t other=0;CHECK(m98_automation_attach(contexts[1],&objects[0],&other)==S_OK&&other!=ids[0]);
    CHECK(m98_automation_retain(contexts[0],other)==M98_AUTO_STATE);CHECK(m98_automation_release(contexts[1],ids[0])==M98_AUTO_STATE);
    for(unsigned i=0;i<4;i++)CHECK(m98_automation_close(contexts[i])==S_OK);
    for(unsigned i=0;i<129;i++)CHECK(objects[i].refs==1);
}
int main(){run(true);run(false);bounds();wrapper_and_string_bounds();CHECK(strings==0&&heaps==0);printf("PASS: Automation adapter %u assertions; COM/OS doubles only, no MSHTML or Win98 execution\n",assertions);return 0;}
