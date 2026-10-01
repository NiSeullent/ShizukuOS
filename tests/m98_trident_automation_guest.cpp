/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine installed MSHTML direct local host. No fake DOM or browser pass. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ole2.h>
#include <docobj.h>
#include <mshtml.h>
#include <stdint.h>
#include <string.h>
#include "m98_trident_automation.h"

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
static const GUID element_id={0x3050f1ff,0x98b5,0x11cf,{0xbb,0x82,0,0xaa,0,0xbd,0xce,0x0b}};
static const GUID input_id={0x3050f5d2,0x98b5,0x11cf,{0xbb,0x82,0,0xaa,0,0xbd,0xce,0x0b}};
static const GUID document_site_id={0xb722bcc7,0x4e68,0x101b,{0xa2,0xbc,0,0xaa,0,0x40,0x47,0x70}};
static const GUID ole_document_id={0xb722bcc5,0x4e68,0x101b,{0xa2,0xbc,0,0xaa,0,0x40,0x47,0x70}};
static bool equal(const GUID &a,const GUID &b){return !memcmp(&a,&b,sizeof a);}
static uint32_t length(const char *s){uint32_t n=0;while(s[n])++n;return n;}
static HANDLE log_file=INVALID_HANDLE_VALUE;static bool log_ok=true,finished,passed;
static unsigned failures,callbacks,keyups;
static HWND window;static IOleObject *ole;static IHTMLDocument2 *document;
static IOleDocumentView *view;
static IHTMLDocument3 *document3;static uint32_t automation,root,script_context;
static DWORD started,passed_at;
static HMODULE runtime;
struct ScriptAPI {
    int (*open)(const m98_script_options *,uint32_t *);
    int (*bind)(uint32_t,const uint16_t *,uint32_t,uint32_t);
    int (*eval)(uint32_t,const char *,uint32_t,m98_script_result *);
    int (*invoke_this)(uint32_t,uint32_t,const m98_script_value *,const m98_script_value *,uint32_t,m98_script_result *);
    int (*jobs)(uint32_t,uint32_t *);
    int (*release)(uint32_t,uint32_t);
    int (*info)(uint32_t,m98_script_details *);
    int (*close)(uint32_t);
    FARPROC invoke;
} api;
static void write(const char *s){DWORD n=length(s),done=0;if(log_file==INVALID_HANDLE_VALUE||!WriteFile(log_file,s,n,&done,0)||done!=n)log_ok=false;}
static void line(const char *key,const char *value){write(key);write("=");write(value);write("\r\n");}
static void value(const char *key,uint32_t n){char s[11];unsigned i=10;s[i]=0;do{s[--i]=(char)('0'+n%10);n/=10;}while(n);line(key,s+i);}
static void hex(const char *key,uint32_t n){char s[9];const char digits[]="0123456789abcdef";for(unsigned i=0;i<8;i++)s[7-i]=digits[(n>>(i*4))&15];s[8]=0;line(key,s);}
static bool check(const char *key,bool yes){line(key,yes?"PASS":"FAIL");if(!yes)++failures;return yes;}
static bool hr(const char *key,HRESULT h){hex(key,(uint32_t)h);if(h<0){++failures;return false;}return true;}
static void script_error(int result){
    hex("SCRIPT_STATUS",(uint32_t)result);m98_script_details details={};details.size=sizeof details;
    if(api.info&&script_context&&api.info(script_context,&details)==0){hex("HOST_HRESULT",(uint32_t)details.host_hresult);line("SCRIPT_EXCEPTION",details.exception_utf8);}
}
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
static const char modern[]=
    "let numbers=[1,2,3].map(n=>n*2); const status=document.getElementById('status');"
    "status.innerText=`한글 modern ${numbers.join(',')}`; globalThis.promiseSeen=false; globalThis.inputSeen=false;"
    "Promise.resolve(7).then(n=>{status.innerText=`한글 Promise ${n}`;globalThis.promiseSeen=true;});"
    "document.getElementById('entry').onkeyup=function(event){status.innerText=`입력 확인 ${this.value}`;globalThis.inputSeen=true;};true;";
static bool evaluate(const char *source,m98_script_result *result){
    memset(result,0,sizeof *result);result->size=sizeof *result;
    int status=api.eval(script_context,source,length(source),result);
    if(status){script_error(status);++failures;return false;}return true;
}
static bool release_result(m98_script_result *r){
    if(!r->lease)return true;
    int status=api.release(script_context,r->lease);r->lease=0;
    if(status){script_error(status);++failures;return false;}return true;
}
static bool flag(const char *name){m98_script_result r;if(!evaluate(name,&r))return false;
    bool yes=r.value.type==M98_SCRIPT_BOOL&&r.value.integer==1;release_result(&r);return yes;}
static int32_t dispatch_callback(void *,uint32_t function,const m98_script_value *receiver,const m98_script_value *args,uint32_t count){
    m98_script_result result={};result.size=sizeof result;
    int status=api.invoke_this(script_context,function,receiver,args,count,&result);
    if(status){script_error(status);return E_FAIL;}
    if(!release_result(&result))return E_FAIL;
    uint32_t jobs=0;status=api.jobs(script_context,&jobs);if(status){script_error(status);return E_FAIL;}
    ++callbacks;line("EVENT_EXECUTED_OUTSIDE_COM","PASS");return S_OK;
}
static bool typed_text(const uint16_t *expected,uint32_t units){
    if(!document3)return false;
    IHTMLElement *element=0;BSTR id=SysAllocStringLen(L"status",6);if(!id)return false;
    HRESULT h=document3->getElementById(id,&element);SysFreeString(id);if(h<0||!element)return false;
    BSTR text=0;h=element->get_innerText(&text);element->Release();bool yes=h>=0&&text&&
        SysStringLen(text)==units&&!memcmp(text,expected,(size_t)units*2);SysFreeString(text);return yes;
}
/* Independent typed provider reads, not another call through the adapter.
 * S_FALSE means empty input: remain pending until the tester types text. */
static HRESULT exact_input_text(){
    IHTMLElement *entry=0,*status=0;IHTMLInputElement *input=0;BSTR entered=0,actual=0;
    BSTR entry_name=SysAllocStringLen(L"entry",5),status_name=SysAllocStringLen(L"status",6);
    HRESULT h=entry_name&&status_name?S_OK:E_OUTOFMEMORY;
    if(h>=0)h=document3->getElementById(entry_name,&entry);
    if(h>=0&&!entry)h=E_NOINTERFACE;
    if(h>=0)h=entry->QueryInterface(input_id,(void **)&input);
    if(h>=0&&!input)h=E_NOINTERFACE;
    if(h>=0)h=input->get_value(&entered);
    UINT units=entered?SysStringLen(entered):0;
    if(h>=0&&units>65536)h=M98_AUTO_LIMIT;
    if(h>=0&&units){
        h=document3->getElementById(status_name,&status);
        if(h>=0&&!status)h=E_NOINTERFACE;
        if(h>=0)h=status->get_innerText(&actual);
        const uint16_t prefix[]={0xc785,0xb825,' ',0xd655,0xc778,' '};
        if(h>=0&&(!actual||SysStringLen(actual)!=6+units||memcmp(actual,prefix,12)||memcmp(actual+6,entered,(size_t)units*2)))h=E_FAIL;
    }else if(h>=0)h=S_FALSE;
    if(input)input->Release();
    if(entry)entry->Release();
    if(status)status->Release();
    SysFreeString(entry_name);SysFreeString(status_name);SysFreeString(entered);SysFreeString(actual);
    return h;
}
static void tick(){
    if(finished)return;
    if(GetTickCount()-started>=180000){check("UI_EVENT_WITHIN_DEADLINE",false);finished=true;PostQuitMessage(0);return;}
    uint32_t completed=0;HRESULT h=m98_automation_pump(automation,32,&completed);
    if(h<0){hr("CALLBACK_PUMP",h);finished=true;PostQuitMessage(0);return;}
    if(!passed&&callbacks&&keyups&&flag("globalThis.inputSeen")){
        HRESULT verified=exact_input_text();
        if(verified==S_FALSE)return;
        if(!hr("INDEPENDENT_TYPED_INPUT_VALUE_AND_FULL_STATUS",verified)){finished=true;PostQuitMessage(0);return;}
        check("NONEMPTY_ACTUAL_INPUT_MATCHES_JS_THIS_VALUE",true);
        check("UI_THREAD_KEYUP_OBSERVED",true);check("QUEUED_JS_INPUT_CALLBACK",true);
        line("EXTERNAL_INPUT_REVIEW_REQUIRED","WM_KEYUP and COM event observations alone do not prove physical or QEMU GUI input");
        line("VISUAL_REVIEW_REQUIRED","Korean mutation must be visibly reviewed in genuine MSHTML; log is not pixel proof");
        passed=true;passed_at=GetTickCount();
    }
    if(passed&&GetTickCount()-passed_at>=10000){finished=true;PostQuitMessage(0);}
}
static LRESULT CALLBACK window_proc(HWND hwnd,UINT message,WPARAM wp,LPARAM lp){
    if(message==WM_SIZE&&ole){RECT r;GetClientRect(hwnd,&r);IOleInPlaceObject *object=0;if(ole->QueryInterface(place_object_id,(void **)&object)>=0&&object){object->SetObjectRects(&r,&r);object->Release();}}
    if(message==WM_TIMER){tick();return 0;}
    if(message==WM_CLOSE){finished=true;PostQuitMessage(0);return 0;}
    if(message==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcA(hwnd,message,wp,lp);
}
static bool load_runtime(const char *directory){
    char target[MAX_PATH],actual[MAX_PATH];uint32_t n=length(directory);if(n+11>=MAX_PATH)return false;
    memcpy(target,directory,n);memcpy(target+n,"M98QJS.DLL",11);runtime=LoadLibraryA(target);
    if(!runtime)return false;
    DWORD got=GetModuleFileNameA(runtime,actual,MAX_PATH);
    line("RUNTIME_MODULE",got&&got<MAX_PATH?actual:"invalid");
    if(!got||got>=MAX_PATH||lstrcmpiA(actual,target))return false;
#define BIND(member,name) do{FARPROC address=GetProcAddress(runtime,name);if(!address)return false;memcpy(&api.member,&address,sizeof address);}while(0)
    BIND(open,"m98_script_open");BIND(bind,"m98_script_bind_root");BIND(eval,"m98_script_eval");BIND(invoke,"m98_script_invoke");
    BIND(invoke_this,"m98_script_invoke_this");BIND(jobs,"m98_script_jobs");BIND(release,"m98_script_release_result");BIND(info,"m98_script_info");BIND(close,"m98_script_close");
#undef BIND
    return true;
}
extern "C" void mainCRTStartup(){
    char exe[MAX_PATH],directory[MAX_PATH],log_path[MAX_PATH];DWORD n=GetModuleFileNameA(0,exe,MAX_PATH);uint32_t cut=0;
    if(!n||n>=MAX_PATH||exe[1]!=':'||exe[2]!='\\')ExitProcess(2);
    for(DWORD i=0;i<n;i++)if(exe[i]=='\\')cut=i+1;
    if(!cut||cut+10>=MAX_PATH)ExitProcess(2);
    memcpy(directory,exe,cut);directory[cut]=0;memcpy(log_path,directory,cut);memcpy(log_path+cut,"AUT13.LOG",10);
    log_file=CreateFileA(log_path,GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(2);
    line("PROFILE","genuine-mshtml-direct-host-v1");line("EXE_MODULE",exe);line("ADAPTER","statically embedded actual adapter source; not a DOM double");
    line("BROWSER_INTEGRATION","not tested; no global script selection/registration");
    OSVERSIONINFOA version={};version.dwOSVersionInfoSize=sizeof version;
    bool native=GetVersionExA(&version)&&version.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS&&version.dwMajorVersion==4&&version.dwMinorVersion==10&&(version.dwBuildNumber&0xffff)==2222;
    value("OS_PLATFORM",version.dwPlatformId);value("OS_MAJOR",version.dwMajorVersion);value("OS_MINOR",version.dwMinorVersion);value("OS_BUILD_LOW",version.dwBuildNumber&0xffff);value("ACP",GetACP());
    if(!check("NATIVE_WIN98_SE",native)||!check("KOREAN_ACP949",GetACP()==949))goto end;
    if(!check("EXACT_ADJACENT_RUNTIME",load_runtime(directory)))goto end;
    {
        HRESULT initialized=CoInitialize(0);if(!hr("COM_STA_INITIALIZE",initialized))goto end;
        Site site;bool adapter_open=false,runtime_open=false;
        WNDCLASSA klass={};klass.lpfnWndProc=window_proc;klass.hInstance=GetModuleHandleA(0);klass.lpszClassName="M98AUT13";klass.hCursor=LoadCursorA(0,IDC_ARROW);
        if(!RegisterClassA(&klass)){check("WINDOW_CLASS",false);goto com_end;}
        window=CreateWindowExA(0,klass.lpszClassName,"Win98 genuine MSHTML modern JS - type in the input",WS_OVERLAPPEDWINDOW|WS_VISIBLE,80,80,700,460,0,0,klass.hInstance,0);
        if(!check("VISIBLE_NATIVE_HOST",window!=0))goto com_end;
        if(!hr("ACTUAL_MSHTML_CREATE",CoCreateInstance(html_class,0,CLSCTX_INPROC_SERVER,html2_id,(void **)&document))||!document)goto com_end;
        {char module[MAX_PATH],expected[MAX_PATH];HMODULE m=GetModuleHandleA("MSHTML.DLL");DWORD got=m?GetModuleFileNameA(m,module,MAX_PATH):0;
            DWORD system=GetSystemDirectoryA(expected,MAX_PATH);bool valid=system&&system+12<MAX_PATH;
            if(valid)memcpy(expected+system,"\\MSHTML.DLL",12);
            line("MSHTML_MODULE",got&&got<MAX_PATH?module:"not found");
            if(!check("ACTUAL_SYSTEM_MSHTML_MODULE",valid&&got&&got<MAX_PATH&&!lstrcmpiA(module,expected)))goto com_end;}
        if(!hr("MSHTML_OLE_OBJECT",document->QueryInterface(ole_id,(void **)&ole))||!ole)goto com_end;
        if(!hr("MSHTML_CLIENT_SITE",ole->SetClientSite((IOleClientSite *)&site)))goto com_end;
        {IPersistStreamInit *persist=0;HRESULT h=document->QueryInterface(persist_id,(void **)&persist);if(!hr("MSHTML_PERSIST_INIT_INTERFACE",h)||!persist)goto com_end;h=persist->InitNew();persist->Release();if(!hr("MSHTML_INIT_NEW",h))goto com_end;}
        {RECT area;GetClientRect(window,&area);if(!hr("GENUINE_VIEW_INPLACE_ACTIVATE",ole->DoVerb(OLEIVERB_INPLACEACTIVATE,0,(IOleClientSite *)&site,0,window,&area)))goto com_end;}
        {
            const OLECHAR html[]=L"<html><head><title>Direct MSHTML test</title></head><body><h2>Genuine MSHTML + modern JavaScript</h2><p id='status'>Starting...</p><p>Click the input, type a few keys, then wait. Capture the Korean result.</p><input id='entry' type='text' value=''><p>This is a local component test; normal browser integration remains pending.</p></body></html>";
            SAFEARRAY *array=SafeArrayCreateVector(VT_VARIANT,0,1);VARIANT *entry=0;
            if(!check("HTML_SAFEARRAY",array!=0))goto com_end;
            HRESULT h=SafeArrayAccessData(array,(void **)&entry);
            if(h>=0){entry->vt=VT_BSTR;entry->bstrVal=SysAllocStringLen(html,sizeof html/sizeof *html-1);h=entry->bstrVal?S_OK:E_OUTOFMEMORY;HRESULT unlock=SafeArrayUnaccessData(array);if(unlock<0)h=unlock;}
            if(h>=0)h=document->write(array);
            HRESULT destroyed=SafeArrayDestroy(array);if(destroyed<0)h=destroyed;
            if(!hr("GENUINE_DOCUMENT_WRITE",h)||!hr("GENUINE_DOCUMENT_CLOSE",document->close()))goto com_end;
        }
        if(!hr("INDEPENDENT_DOCUMENT3_INTERFACE",document->QueryInterface(html3_id,(void **)&document3))||!document3)goto com_end;
        {m98_automation_options options={sizeof options,0,dispatch_callback};if(!hr("AUTOMATION_OPEN",m98_automation_open(&options,&automation)))goto com_end;adapter_open=true;}
        if(!hr("ACTUAL_DOCUMENT_CANONICAL_ATTACH",m98_automation_attach(automation,(IUnknown *)document,&root)))goto com_end;
        {
            m98_script_host host={};host.size=sizeof host;if(!hr("SCRIPT_HOST_TABLE",m98_automation_host(automation,&host)))goto com_end;
            m98_script_options options={sizeof options,8*1024*1024,65536,10000,1000,&host};int status=api.open(&options,&script_context);
            if(!check("REAL_INTERPRETER_OPEN",status==0)){script_error(status);goto com_end;}runtime_open=true;
            const uint16_t name[]={'d','o','c','u','m','e','n','t'};status=api.bind(script_context,name,8,root);
            if(!check("GENUINE_DOCUMENT_ROOT_BIND",status==0)){script_error(status);goto com_end;}
            m98_script_result result;if(!evaluate(modern,&result))goto com_end;release_result(&result);
            check("MODERN_SYNTAX_EXECUTED",true);uint32_t jobs=0;status=api.jobs(script_context,&jobs);
            if(!check("REAL_PROMISE_JOBS",status==0&&jobs>0)){script_error(status);goto com_end;}
            const uint16_t expected[]={0xd55c,0xae00,' ','P','r','o','m','i','s','e',' ','7'};
            if(!check("PROMISE_RESULT_STATE",flag("globalThis.promiseSeen"))||!check("INDEPENDENT_TYPED_MSHTML_PROMISE_TEXT",typed_text(expected,12)))goto com_end;
        }
        started=GetTickCount();if(!SetTimer(window,1,50,0)){check("UI_TIMER",false);goto com_end;}
        line("REAL_INPUT_PENDING","Click genuine MSHTML input and type; no input/event synthesis exists in fixture");
        {
            MSG message;int got;while((got=GetMessageA(&message,0,0,0))>0){if(message.message==WM_KEYUP)++keyups;TranslateMessage(&message);DispatchMessageA(&message);}
            if(got<0)check("UI_MESSAGE_LOOP",false);
        }
        check("UI_EVENT_COMPLETED",passed);
com_end:
        if(window)KillTimer(window,1);
        if(runtime_open){m98_script_result result;if(evaluate("document.getElementById('entry').onkeyup=null;true;",&result))release_result(&result);}
        if(adapter_open)hr("AUTOMATION_CLOSE_BEFORE_SCRIPT",m98_automation_close(automation));
        bool runtime_closed=!runtime_open;
        if(runtime_open){int status=api.close(script_context);runtime_closed=status==0;check("REAL_INTERPRETER_CLOSE",runtime_closed);if(status)script_error(status);}
        if(document3){document3->Release();document3=0;}
        if(view){hr("VIEW_UI_DEACTIVATE",view->UIActivate(FALSE));hr("VIEW_HIDE",view->Show(FALSE));hr("VIEW_CLOSE",view->CloseView(0));hr("VIEW_DETACH_SITE",view->SetInPlaceSite(0));view->Release();view=0;}
        if(ole){hr("MSHTML_OLE_CLOSE",ole->Close(OLECLOSE_NOSAVE));hr("MSHTML_DETACH_SITE",ole->SetClientSite(0));ole->Release();ole=0;}
        if(document){document->Release();document=0;}
        if(window){if(IsWindow(window))DestroyWindow(window);window=0;}
        check("CLIENT_SITE_REFS_RELEASED",site.refs==1);CoUninitialize();
        if(runtime_closed&&runtime){check("RUNTIME_MODULE_RELEASE",FreeLibrary(runtime)!=0);runtime=0;}
    }
end:
    value("OBSERVED_UI_KEYUPS",keyups);value("EXECUTED_QUEUED_CALLBACKS",callbacks);value("FAILURES",failures);
    line("STATUS",failures||!passed?"FAIL":"PASS_COMPONENT_ONLY");
    line("SYSTEM_WEB_STANDARDS","not certified");line("HTML5_LAYOUT_WASM","not implemented by this adapter");
    bool flushed=FlushFileBuffers(log_file)!=0;bool closed=CloseHandle(log_file)!=0;log_file=INVALID_HANDLE_VALUE;
    ExitProcess(failures||!passed||!log_ok||!flushed||!closed?2:0);
}
