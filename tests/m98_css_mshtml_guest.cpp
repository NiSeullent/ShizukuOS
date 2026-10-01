/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine MSHTML CSS token consumer fixture. Site host derived from this
 * project's frozen m98_trident_automation_guest.cpp; no DOM or paint doubles. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
#include <docobj.h>
#include <mshtml.h>
#include <winver.h>
#include <stdint.h>
#include <string.h>
#include "m98_css_variables.h"
#include "m98_css_mshtml_values.h"
static_assert(sizeof(wchar_t)==2,"native BSTR units required");
static const GUID unknown_id={0,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID client_id={0x118,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID place_id={0x119,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID frame_id={0x116,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID ui_id={0x115,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID window_id={0x114,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID ole_id={0x112,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID place_object_id={0x113,0,0,{0xc0,0,0,0,0,0,0,0x46}};
static const GUID persist_id={0x7fd52380,0x4e07,0x101b,{0xae,0x2d,8,0,0x2b,0x2e,0xc7,0x13}};
static const GUID html_class={0x25336920,0x03f9,0x11cf,{0x8f,0xd0,0,0xaa,0,0x68,0x6f,0x13}};
static const GUID html2_id={0x332c4425,0x26cb,0x11d0,{0xb4,0x83,0,0xc0,0x4f,0xd9,1,0x19}};
static const GUID html3_id={0x3050f485,0x98b5,0x11cf,{0xbb,0x82,0,0xaa,0,0xbd,0xce,0x0b}};
static const GUID document_site_id={0xb722bcc7,0x4e68,0x101b,{0xa2,0xbc,0,0xaa,0,0x40,0x47,0x70}};
static const GUID ole_document_id={0xb722bcc5,0x4e68,0x101b,{0xa2,0xbc,0,0xaa,0,0x40,0x47,0x70}};
static bool equal(const GUID&a,const GUID&b){return !memcmp(&a,&b,sizeof a);}
static HWND window;static IOleObject *ole;static IOleDocumentView *view;
static IHTMLDocument2 *document;static IHTMLDocument3 *document3;
static HMODULE component;static HANDLE log_file=INVALID_HANDLE_VALUE;
static bool log_ok=true,finished,passed,baseline_seen,applied,timed_complete,ticking;static unsigned failures;
static DWORD started,baseline_at,applied_at;static HANDLE heap;
static unsigned live_allocations;static const char *phase="SETUP";
static size_t length(const char*s){size_t n=0;while(s[n])n++;return n;}
static void write(const char*s){DWORD size=(DWORD)length(s),done=0;if(log_file==INVALID_HANDLE_VALUE||!WriteFile(log_file,s,size,&done,0)||done!=size)log_ok=false;}
static void line(const char*k,const char*v){write(phase);write(".");write(k);write("=");write(v);write("\r\n");}
static void number(const char*k,DWORD v){char b[11];unsigned i=10;b[i]=0;do{b[--i]=(char)('0'+v%10);v/=10;}while(v);line(k,b+i);}
static void hex(const char*k,DWORD v){char b[9];for(unsigned i=0;i<8;i++)b[7-i]="0123456789abcdef"[(v>>(4*i))&15];b[8]=0;line(k,b);}
static bool check(const char*k,bool ok){line(k,ok?"PASS":"FAIL");if(!ok)failures++;return ok;}
static bool hr(const char*k,HRESULT h){hex(k,(DWORD)h);if(h<0){failures++;return false;}return true;}
static void *allocate(void*,size_t n){void *p=HeapAlloc(heap,0,n);if(p)live_allocations++;return p;}
static void release(void*,void*p){if(p){if(HeapFree(heap,0,p))live_allocations--;else check("ALLOCATOR_FREE",false);}}
struct CSSAPI {
 int(*compute)(const m98_css_declaration*,size_t,const m98_css_snapshot*,const m98_css_allocator*,m98_css_snapshot**);
 void(*destroy)(m98_css_snapshot**);
 int(*lookup)(const m98_css_snapshot*,const uint16_t*,size_t,const m98_css_stream**,int*);
 int(*substitute)(const m98_css_snapshot*,const uint16_t*,size_t,m98_css_stream**,int*);
 void(*stream_destroy)(m98_css_stream**);
 m98_css_value_access access;
} api;
class Site final: public IOleClientSite,public IOleInPlaceSite,public IOleInPlaceFrame,public IOleDocumentSite {
public:
    ULONG refs;Site():refs(1){}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid,void **out){
        if(!out)return E_POINTER;
        *out=0;
        if(equal(iid,unknown_id)||equal(iid,client_id))*out=(IOleClientSite *)this;
        else if(equal(iid,place_id))*out=(IOleInPlaceSite *)this;
        else if(equal(iid,frame_id)||equal(iid,ui_id))*out=(IOleInPlaceFrame *)this;
        else if(equal(iid,window_id))*out=(IOleInPlaceSite *)this;
        else if(equal(iid,document_site_id))*out=(IOleDocumentSite *)this;
        else return E_NOINTERFACE;
        AddRef();return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef(){return ++refs;}ULONG STDMETHODCALLTYPE Release(){return --refs;}
    HRESULT STDMETHODCALLTYPE SaveObject(){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetMoniker(DWORD,DWORD,IMoniker **out){if(out)*out=0;return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetContainer(IOleContainer **out){if(out)*out=0;return E_NOINTERFACE;}
    HRESULT STDMETHODCALLTYPE ShowObject(){return S_OK;}
    HRESULT STDMETHODCALLTYPE OnShowWindow(BOOL){return S_OK;}
    HRESULT STDMETHODCALLTYPE RequestNewObjectLayout(){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetWindow(HWND *out){if(!out)return E_POINTER;*out=window;return S_OK;}
    HRESULT STDMETHODCALLTYPE ContextSensitiveHelp(BOOL){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE CanInPlaceActivate(){return S_OK;}
    HRESULT STDMETHODCALLTYPE OnInPlaceActivate(){return S_OK;}
    HRESULT STDMETHODCALLTYPE OnUIActivate(){return S_OK;}
    HRESULT STDMETHODCALLTYPE GetWindowContext(IOleInPlaceFrame **frame,IOleInPlaceUIWindow **doc,RECT *pos,RECT *clip,OLEINPLACEFRAMEINFO *info){
        if(!frame||!doc||!pos||!clip||!info)return E_POINTER;
        *frame=(IOleInPlaceFrame *)this;AddRef();*doc=0;GetClientRect(window,pos);*clip=*pos;
        info->cb=sizeof *info;info->fMDIApp=FALSE;info->hwndFrame=window;info->haccel=0;info->cAccelEntries=0;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Scroll(SIZE){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE OnUIDeactivate(BOOL){return S_OK;}
    HRESULT STDMETHODCALLTYPE OnInPlaceDeactivate(){return S_OK;}
    HRESULT STDMETHODCALLTYPE DiscardUndoState(){return S_OK;}
    HRESULT STDMETHODCALLTYPE DeactivateAndUndo(){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE OnPosRectChange(const RECT *pos){
        if(!ole)return S_OK;
        IOleInPlaceObject *object=0;HRESULT h=ole->QueryInterface(place_object_id,(void **)&object);
        if(h>=0&&object){h=object->SetObjectRects(pos,pos);object->Release();}return h;
    }
    HRESULT STDMETHODCALLTYPE GetBorder(RECT *out){if(!out)return E_POINTER;GetClientRect(window,out);return S_OK;}
    HRESULT STDMETHODCALLTYPE RequestBorderSpace(LPCBORDERWIDTHS){return INPLACE_E_NOTOOLSPACE;}
    HRESULT STDMETHODCALLTYPE SetBorderSpace(LPCBORDERWIDTHS){return S_OK;}
    HRESULT STDMETHODCALLTYPE SetActiveObject(IOleInPlaceActiveObject *,LPCOLESTR){return S_OK;}
    HRESULT STDMETHODCALLTYPE InsertMenus(HMENU,LPOLEMENUGROUPWIDTHS){return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE SetMenu(HMENU,HOLEMENU,HWND){return S_OK;}
    HRESULT STDMETHODCALLTYPE RemoveMenus(HMENU){return S_OK;}
    HRESULT STDMETHODCALLTYPE SetStatusText(LPCOLESTR){return S_OK;}
    HRESULT STDMETHODCALLTYPE EnableModeless(BOOL){return S_OK;}
    HRESULT STDMETHODCALLTYPE TranslateAccelerator(LPMSG,WORD){return S_FALSE;}
    HRESULT STDMETHODCALLTYPE ActivateMe(IOleDocumentView *supplied){
        if(view)return E_UNEXPECTED;
        HRESULT h=S_OK;
        if(supplied){view=supplied;view->AddRef();}
        else {IOleDocument *d=0;h=ole->QueryInterface(ole_document_id,(void **)&d);
            if(h>=0&&d){h=d->CreateView((IOleInPlaceSite *)this,0,0,&view);d->Release();}
        }
        if(h<0||!view)return h<0?h:E_NOINTERFACE;
        RECT r;GetClientRect(window,&r);h=view->SetInPlaceSite((IOleInPlaceSite *)this);
        if(h>=0)h=view->SetRect(&r);
        if(h>=0)h=view->UIActivate(TRUE);
        if(h>=0)h=view->Show(TRUE);
        return h;
    }
};

static bool load_component(const char*directory){char wanted[MAX_PATH],actual[MAX_PATH];size_t n=length(directory);
 if(n+11>=MAX_PATH)return false;
 memcpy(wanted,directory,n);memcpy(wanted+n,"M98CSS.DLL",11);component=LoadLibraryA(wanted);if(!component)return false;
 DWORD got=GetModuleFileNameA(component,actual,MAX_PATH);line("CSS_MODULE",got&&got<MAX_PATH?actual:"invalid");
 if(!got||got>=MAX_PATH||lstrcmpiA(wanted,actual))return false;
 static const char *const exports[]={"m98_css_append","m98_css_ascii","m98_css_at","m98_css_compute","m98_css_count","m98_css_destroy","m98_css_empty","m98_css_errors","m98_css_literal","m98_css_lookup","m98_css_number","m98_css_property_count","m98_css_replacements","m98_css_serialize","m98_css_snapshot_destroy","m98_css_substitute","m98_css_tokenize","m98_css_value"};
 for(unsigned i=0;i<18;i++)if(!GetProcAddress(component,exports[i]))return false;
#define BIND(field,name) do{FARPROC address=GetProcAddress(component,name);memcpy(&api.field,&address,sizeof address);}while(0)
 BIND(compute,"m98_css_compute");BIND(destroy,"m98_css_snapshot_destroy");BIND(lookup,"m98_css_lookup");BIND(substitute,"m98_css_substitute");BIND(stream_destroy,"m98_css_destroy");
 BIND(access.count,"m98_css_count");BIND(access.at,"m98_css_at");BIND(access.value,"m98_css_value");BIND(access.number,"m98_css_number");BIND(access.ascii,"m98_css_ascii");
#undef BIND
 return true;
}
static bool actual_mshtml(){char actual[MAX_PATH],expected[MAX_PATH];HMODULE module=GetModuleHandleA("MSHTML.DLL");DWORD got=module?GetModuleFileNameA(module,actual,MAX_PATH):0;
 DWORD n=GetSystemDirectoryA(expected,MAX_PATH);bool valid=n&&n+12<MAX_PATH;
 if(valid)memcpy(expected+n,"\\MSHTML.DLL",12);
 line("MSHTML_MODULE",got&&got<MAX_PATH?actual:"invalid");
 if(!check("ACTUAL_SYSTEM_MSHTML",valid&&got&&got<MAX_PATH&&!lstrcmpiA(actual,expected)))return false;
 DWORD ignored=0,size=GetFileVersionInfoSizeA(actual,&ignored);void*info=size&&size<=65536?HeapAlloc(heap,0,size):0;
 VS_FIXEDFILEINFO *fixed=0;UINT bytes=0;
 bool queried=info&&GetFileVersionInfoA(actual,0,size,info)&&VerQueryValueA(info,"\\",(void**)&fixed,&bytes)&&fixed&&bytes>=sizeof(*fixed)&&fixed->dwSignature==0xfeef04bd;
 if(queried){number("MSHTML_VERSION_MAJOR",HIWORD(fixed->dwFileVersionMS));number("MSHTML_VERSION_MINOR",LOWORD(fixed->dwFileVersionMS));number("MSHTML_VERSION_BUILD",HIWORD(fixed->dwFileVersionLS));number("MSHTML_VERSION_REVISION",LOWORD(fixed->dwFileVersionLS));}
 bool exact=queried&&HIWORD(fixed->dwFileVersionMS)==5&&LOWORD(fixed->dwFileVersionMS)==0&&HIWORD(fixed->dwFileVersionLS)==2614&&LOWORD(fixed->dwFileVersionLS)==3500;
 if(info)HeapFree(heap,0,info);
 return check("EXACT_MSHTML_5_00_2614_3500",exact);
}
static HRESULT element(const wchar_t*id,IHTMLElement**out){BSTR name=SysAllocString(id);if(!name)return E_OUTOFMEMORY;
 HRESULT h=document3->getElementById(name,out);SysFreeString(name);return h>=0&&!*out?E_NOINTERFACE:h;}
static HRESULT attribute(IHTMLElement*e,const wchar_t*name,VARIANT*out){BSTR key=SysAllocString(name);if(!key)return E_OUTOFMEMORY;
 memset(out,0,sizeof(*out));HRESULT h=e->getAttribute(key,0,out);SysFreeString(key);
 if(h>=0&&(out->vt!=VT_BSTR||!out->bstrVal||SysStringLen(out->bstrVal)>32768))h=E_INVALIDARG;
 return h;
}
static bool snapshot(IHTMLElement*e,const m98_css_snapshot*parent,m98_css_snapshot**out){VARIANT width={},color={};bool ok=false;
 HRESULT w=attribute(e,L"data-var-width",&width),c=attribute(e,L"data-var-color",&color);
 if(hr("REAL_DOM_WIDTH_ATTRIBUTE",w)&&hr("REAL_DOM_COLOR_ATTRIBUTE",c)){
  const uint16_t name_w[]={'-','-','b','o','x','-','w','i','d','t','h'},name_c[]={'-','-','b','o','x','-','c','o','l','o','r'};
  m98_css_declaration declarations[2]={{name_w,(const uint16_t*)width.bstrVal,11,SysStringLen(width.bstrVal)},{name_c,(const uint16_t*)color.bstrVal,11,SysStringLen(color.bstrVal)}};
  m98_css_allocator a={0,allocate,release};ok=check("ACTUAL_DLL_COMPUTED_SNAPSHOT",api.compute(declarations,2,parent,&a,out)==0&&*out);
 }
 VariantClear(&width);VariantClear(&color);return ok;
}
static bool apply(IHTMLElement*e,const m98_css_snapshot*s){VARIANT width_source={};m98_css_stream*width_tokens=0;const m98_css_stream*color_tokens=0;int invalid=1,pixels=0;uint16_t color[7];bool ok=false;IHTMLStyle*style=0;
 if(!hr("REAL_DOM_USE_WIDTH",attribute(e,L"data-use-width",&width_source)))goto done;
 if(!check("ACTUAL_DLL_VAR_SUBSTITUTION",api.substitute(s,(const uint16_t*)width_source.bstrVal,SysStringLen(width_source.bstrVal),&width_tokens,&invalid)==0&&!invalid&&width_tokens))goto done;
 {const uint16_t name[]={'-','-','b','o','x','-','c','o','l','o','r'};
  if(!check("ACTUAL_DLL_COMPUTED_COLOR",api.lookup(s,name,11,&color_tokens,&invalid)==0&&!invalid&&color_tokens))goto done;}
 if(!check("REAL_TOKEN_INTEGER_PX",m98_css_mshtml_width(&api.access,width_tokens,&pixels)==0&&pixels==168))goto done;
 if(!check("REAL_TOKEN_HEX_COLOR",m98_css_mshtml_color(&api.access,color_tokens,color)==0))goto done;
 if(!hr("GENUINE_STYLE_INTERFACE",e->get_style(&style))||!style)goto done;
 {VARIANT value={};value.vt=VT_I4;value.lVal=pixels;if(!hr("GENUINE_PIXEL_WIDTH_SETTER",style->put_width(value)))goto done;
  value.vt=VT_BSTR;value.bstrVal=SysAllocStringLen((const wchar_t*)color,7);
  if(!value.bstrVal){check("COLOR_BSTR",false);goto done;}
  HRESULT h=style->put_backgroundColor(value);VariantClear(&value);if(!hr("GENUINE_BACKGROUND_SETTER",h))goto done;}
 ok=true;
 done:if(style)style->Release();api.stream_destroy(&width_tokens);VariantClear(&width_source);return ok;
}
static bool width_is(const wchar_t*id,LONG expected,const wchar_t *expected_color){IHTMLElement*e=0;IHTMLStyle*style=0;LONG pixels=-1,geometry=-1;bool ok=false,color_ok=false;VARIANT color={};
 if(element(id,&e)>=0&&e&&e->get_style(&style)>=0&&style&&style->get_pixelWidth(&pixels)>=0&&e->get_offsetWidth(&geometry)>=0)ok=pixels==expected&&geometry==expected;
 if(style&&style->get_backgroundColor(&color)>=0&&color.vt==VT_BSTR&&color.bstrVal&&SysStringLen(color.bstrVal)==7){color_ok=true;
  for(unsigned i=0;i<7;i++){wchar_t actual=color.bstrVal[i];if(actual>=L'A'&&actual<=L'F')actual+=L'a'-L'A';if(actual!=expected_color[i])color_ok=false;}
 }
 number("ACTUAL_BACKGROUND_VARTYPE",color.vt);check("ACTUAL_BACKGROUND_TYPED_VALUE",color_ok);VariantClear(&color);ok=ok&&color_ok;
 number(id[0]=='p'?"PARENT_STYLE_PIXEL_WIDTH":"CHILD_STYLE_PIXEL_WIDTH",(DWORD)pixels);number(id[0]=='p'?"PARENT_ACTUAL_OFFSET_WIDTH":"CHILD_ACTUAL_OFFSET_WIDTH",(DWORD)geometry);
 if(style)style->Release();
 if(e)e->Release();
 return ok;
}
static bool actual_parent(IHTMLElement *parent,IHTMLElement *child){
 IHTMLElement *found=0;IUnknown *a=0,*b=0;bool same=false;
 HRESULT h=child->get_parentElement(&found);
 if(h>=0&&found&&found->QueryInterface(unknown_id,(void **)&a)>=0&&a&&
    parent->QueryInterface(unknown_id,(void **)&b)>=0&&b)same=a==b;
 if(a)a->Release();
 if(b)b->Release();
 if(found)found->Release();
 return check("REAL_DOM_PARENT_CANONICAL_IDENTITY",same);
}
static bool mutate(){IHTMLElement*p=0,*c=0,*status=0;m98_css_snapshot *parent=0,*child=0;bool ok=false;
 if(!hr("REAL_PARENT_ELEMENT",element(L"parent",&p))||!hr("REAL_CHILD_ELEMENT",element(L"child",&c)))goto done;
 phase="PARENTAGE";if(!actual_parent(p,c))goto done;
 phase="PARENT_SNAPSHOT";if(!snapshot(p,0,&parent))goto done;
 phase="CHILD_SNAPSHOT";if(!snapshot(c,parent,&child))goto done;
 phase="PARENT_APPLY";if(!apply(p,parent))goto done;
 api.destroy(&parent);phase="CHILD_APPLY";
 if(!check("PARENT_RELEASED_BEFORE_CHILD_CONSUMPTION",parent==0)||!apply(c,child))goto done;
 phase="KOREAN_MUTATION";if(!hr("REAL_STATUS_ELEMENT",element(L"status",&status)))goto done;
 {const wchar_t expected[]=L"\xd55c\xae00 CSS variables: parent blue / child green / 168px";
  BSTR text=SysAllocString(expected);if(!text){check("KOREAN_BSTR",false);goto done;}
  HRESULT h=status->put_innerText(text);SysFreeString(text);if(!hr("GENUINE_KOREAN_TEXT_SETTER",h))goto done;
  BSTR observed=0;h=status->get_innerText(&observed);
  bool exact=h>=0&&observed&&SysStringLen(observed)==sizeof(expected)/sizeof(*expected)-1&&
      !memcmp(observed,expected,sizeof(expected)-sizeof(*expected));
  SysFreeString(observed);if(!check("INDEPENDENT_FULL_KOREAN_TEXT_READBACK",exact))goto done;}
 ok=true;
 done:phase="MUTATION_CLEANUP";api.destroy(&parent);api.destroy(&child);if(status)status->Release();if(p)p->Release();if(c)c->Release();
 check("ALL_CORE_ALLOCATIONS_RELEASED",live_allocations==0);return ok&&live_allocations==0;
}
static void stop(){finished=true;PostQuitMessage(0);}
static void tick(){if(finished)return;DWORD now=GetTickCount();
 if(now-started>=45000){check("FIXTURE_FINITE_DEADLINE",false);stop();return;}
 if(!baseline_seen){BSTR ready=0;HRESULT h=document->get_readyState(&ready);bool complete=h>=0&&ready&&!lstrcmpW(ready,L"complete");SysFreeString(ready);if(!complete)return;
  phase="INITIAL_PARENT";bool parent_ok=width_is(L"parent",32,L"#808080");phase="INITIAL_CHILD";bool child_ok=width_is(L"child",32,L"#808080");phase="INITIAL_SEQUENCE";
  if(!check("INITIAL_REAL_STYLES_AND_GEOMETRY",parent_ok&&child_ok)){stop();return;}
  InvalidateRect(window,0,TRUE);UpdateWindow(window);baseline_at=GetTickCount();baseline_seen=true;number("INITIAL_TICK",baseline_at);line("INITIAL_CAPTURE_REQUIRED","two gray32px boxes in real MSHTML; log is not pixel proof");return;}
 if(!applied&&now-baseline_at>=10000){DWORD initial_hold=now-baseline_at;if(!mutate()){stop();return;}InvalidateRect(window,0,TRUE);UpdateWindow(window);applied_at=GetTickCount();applied=true;phase="MODIFIED_SEQUENCE";number("MODIFIED_TICK",applied_at);number("INITIAL_HOLD_MS",initial_hold);line("MODIFIED_CAPTURE_REQUIRED","blue parent/green child168px plus Korean label; independent review required");return;}
 if(applied&&!passed&&now-applied_at>=1000){phase="FINAL_PARENT";bool parent_ok=width_is(L"parent",168,L"#10365e");phase="FINAL_CHILD";bool child_ok=width_is(L"child",168,L"#2f7a3c");phase="FINAL_SEQUENCE";passed=check("FINAL_REAL_STYLES_AND_GEOMETRY",parent_ok&&child_ok);if(!passed){stop();return;}}
 if(passed&&now-applied_at>=12000){phase="COMPLETE_SEQUENCE";number("MODIFIED_HOLD_MS",now-applied_at);timed_complete=true;stop();}
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp){
 if(message==WM_SIZE&&view){RECT r;GetClientRect(hwnd,&r);view->SetRect(&r);}
 if(message==WM_TIMER){if(ticking)return 0;ticking=true;tick();ticking=false;return 0;}
 if(message==WM_CLOSE||message==WM_DESTROY){if(!timed_complete)check("EARLY_WINDOW_CLOSE_REJECTED",false);stop();return 0;}
 return DefWindowProcA(hwnd,message,wp,lp);
}
extern "C" void mainCRTStartup(){char exe[MAX_PATH],directory[MAX_PATH],log_path[MAX_PATH];DWORD n=GetModuleFileNameA(0,exe,MAX_PATH);size_t cut=0;
 if(!n||n>=MAX_PATH||exe[1]!=':'||exe[2]!='\\')ExitProcess(2);
 for(DWORD i=0;i<n;i++)if(exe[i]=='\\')cut=i+1;
 if(!cut||cut+10>=MAX_PATH)ExitProcess(2);
 memcpy(directory,exe,cut);directory[cut]=0;memcpy(log_path,directory,cut);memcpy(log_path+cut,"CSS13.LOG",10);
 log_file=CreateFileA(log_path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(2);
 line("PROFILE","genuine-mshtml-current-css-var-consumer-v1");line("EXE_MODULE",exe);line("SCOPE","DOM fixture attributes to actual width/background styles; no selector/cascade/layout-engine/fullCSS claim");
 heap=GetProcessHeap();OSVERSIONINFOA version={};version.dwOSVersionInfoSize=sizeof(version);
 number("ACP",GetACP());
 if(!check("ACTUAL_WIN98_SE",GetVersionExA(&version)&&version.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS&&version.dwMajorVersion==4&&version.dwMinorVersion==10&&(version.dwBuildNumber&0xffff)==2222)||!check("KOREAN_ACP949",GetACP()==949)||!check("EXACT_ADJACENT_CSS_COMPONENT",load_component(directory)))goto end;
 {HRESULT initialized=CoInitialize(0);if(!hr("COM_STA_INITIALIZE",initialized))goto end;Site site;
  WNDCLASSA klass={};klass.lpfnWndProc=window_proc;klass.hInstance=GetModuleHandleA(0);klass.lpszClassName="M98CSS13";klass.hCursor=LoadCursorA(0,IDC_ARROW);
  if(!check("WINDOW_CLASS",RegisterClassA(&klass)!=0))goto com_end;
  window=CreateWindowExA(0,klass.lpszClassName,"Genuine MSHTML CSS variable consumer",WS_OVERLAPPEDWINDOW|WS_VISIBLE,80,80,710,500,0,0,klass.hInstance,0);
  if(!check("VISIBLE_NATIVE_MSHTML_HOST",window!=0))goto com_end;
  if(!hr("ACTUAL_MSHTML_CREATE",CoCreateInstance(html_class,0,CLSCTX_INPROC_SERVER,html2_id,(void**)&document))||!document||!actual_mshtml())goto com_end;
  if(!hr("MSHTML_OLE_OBJECT",document->QueryInterface(ole_id,(void**)&ole))||!ole||!hr("MSHTML_CLIENT_SITE",ole->SetClientSite((IOleClientSite*)&site)))goto com_end;
  {IPersistStreamInit*p=0;HRESULT h=document->QueryInterface(persist_id,(void**)&p);if(h>=0&&p){h=p->InitNew();p->Release();}else if(h>=0)h=E_NOINTERFACE;if(!hr("REAL_DOCUMENT_INIT",h))goto com_end;}
  {RECT area;GetClientRect(window,&area);if(!hr("REAL_VIEW_INPLACE_ACTIVATION",ole->DoVerb(OLEIVERB_INPLACEACTIVATE,0,(IOleClientSite*)&site,0,window,&area)))goto com_end;}
  {const wchar_t html[]=L"<html><body style='font:16px Arial'><h2>Genuine MSHTML + current CSS variable core</h2><p id='status'>Before: gray 32px parent and nested child. Wait for blue/green 168px boxes.</p><div id='parent' style='width:32px;height:80px;background:#808080;color:white;border:0;margin:0;padding:0' data-var-width='168px' data-var-color='#10365e' data-use-width='var(--box-width)'>Parent<div id='child' style='width:32px;height:42px;background:#808080;color:white;border:0;margin:0;padding:0' data-var-width='var(--missing,inherit)' data-var-color='var(--missing,#2f7a3c)' data-use-width='var(--box-width)'>Child</div></div><p>Local bounded component test; general browser CSS remains pending.</p></body></html>";
   SAFEARRAY*a=SafeArrayCreateVector(VT_VARIANT,0,1);VARIANT*v=0;HRESULT h=a?SafeArrayAccessData(a,(void**)&v):E_OUTOFMEMORY;
   if(h>=0){v->vt=VT_BSTR;v->bstrVal=SysAllocStringLen(html,sizeof(html)/sizeof(*html)-1);h=v->bstrVal?S_OK:E_OUTOFMEMORY;HRESULT unlocked=SafeArrayUnaccessData(a);if(unlocked<0)h=unlocked;}
   if(h>=0)h=document->write(a);
   if(a){HRESULT destroyed=SafeArrayDestroy(a);if(destroyed<0)h=destroyed;}
   if(!hr("GENUINE_DOCUMENT_WRITE",h)||!hr("GENUINE_DOCUMENT_CLOSE",document->close()))goto com_end;}
  if(!hr("REAL_DOCUMENT3",document->QueryInterface(html3_id,(void**)&document3))||!document3)goto com_end;
  started=GetTickCount();if(!check("UI_TIMER",SetTimer(window,1,100,0)!=0))goto com_end;
  {MSG message;int got;while((got=GetMessageA(&message,0,0,0))>0){TranslateMessage(&message);DispatchMessageA(&message);}if(got<0)check("UI_MESSAGE_LOOP",false);}
  check("REAL_DOCUMENT_STYLE_SEQUENCE_COMPLETED",passed&&timed_complete);
 com_end:phase="COM_CLEANUP";if(window)KillTimer(window,1);
  if(document3){document3->Release();document3=0;}
  if(view){hr("VIEW_UI_DEACTIVATE",view->UIActivate(FALSE));hr("VIEW_HIDE",view->Show(FALSE));hr("VIEW_CLOSE",view->CloseView(0));hr("VIEW_DETACH",view->SetInPlaceSite(0));view->Release();view=0;}
  if(ole){hr("OLE_CLOSE",ole->Close(OLECLOSE_NOSAVE));hr("OLE_DETACH",ole->SetClientSite(0));ole->Release();ole=0;}
  if(document){document->Release();document=0;}
  if(window){if(IsWindow(window))DestroyWindow(window);window=0;}
  check("CLIENT_SITE_REFS_RELEASED",site.refs==1);CoUninitialize();}
 end:phase="EXIT";check("ALL_CORE_ALLOCATIONS_RELEASED_AT_EXIT",live_allocations==0);if(component){check("CSS_MODULE_RELEASE",FreeLibrary(component)!=0);component=0;}
 number("FAILURES",failures);line("STATUS",passed&&timed_complete&&!failures?"PASS_COMPONENT_ONLY":"FAIL");line("NATIVE_PAINT_REVIEW","required separately; logs are not pixel proof");line("FULL_MODERN_CSS","not certified");
 bool flushed=FlushFileBuffers(log_file)!=0,closed=CloseHandle(log_file)!=0;log_file=INVALID_HANDLE_VALUE;
 ExitProcess(passed&&timed_complete&&!failures&&log_ok&&flushed&&closed?0:1);
}
