/* SPDX-License-Identifier: GPL-2.0-only
 * Real native COM/Save As probe. Default is non-UI contract checks. --register
 * and --unregister are explicit guest registry changes; --save/--cancel/--veto
 * require real UI interaction. It never auto-accepts a dialog or fakes input.
 */
#include "../src/m98_file_dialog.h"
#include <olectl.h>
#include <dlgs.h>
#include <stddef.h>
#include <string.h>

typedef HRESULT (WINAPI *get_class_fn)(REFCLSID,REFIID,void **);
typedef HRESULT (WINAPI *entry_fn)(void);
typedef struct probe_events {
    IFileDialogEvents iface;
    IFileDialogControlEvents control_iface;
    LONG refs;
    UINT types,folders,selections,accepts,toggles;
    BOOL veto;
} probe_events;
static UINT failures,checks;
static HANDLE output=INVALID_HANDLE_VALUE;
static entry_fn can_unload;
static void say(const char *text)
{
    DWORD length=(DWORD)lstrlenA(text),written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),text,length,&written,NULL);
    if(output!=INVALID_HANDLE_VALUE) { WriteFile(output,text,length,&written,NULL); FlushFileBuffers(output); }
}
static void hex(DWORD value)
{ char text[11]="0x00000000"; unsigned i; for(i=0;i<8;i++) text[9-i]="0123456789abcdef"[(value>>(4*i))&15]; say(text); }
static void require(BOOL good,const char *name)
{ ++checks; say(good?"PASS: ":"FAIL: "); say(name); say("\r\n"); if(!good) ++failures; }
static BOOL option(const char *name)
{
    const char *cmd=GetCommandLineA(),*p=cmd;
    int n=lstrlenA(name);
    while(*p) { if((p==cmd || p[-1]==' ') && lstrlenA(p)>=n && !memcmp(p,name,(size_t)n) && (!p[n] || p[n]==' ')) return TRUE; ++p; }
    return FALSE;
}
void *memset(void *out,int value,size_t count)
{ volatile BYTE *p=out; while(count--) *p++=(BYTE)value; return out; }
void *memcpy(void *out,const void *in,size_t count)
{ volatile BYTE *p=out; const volatile BYTE *q=in; while(count--) *p++=*q++; return out; }
int memcmp(const void *a,const void *b,size_t count)
{ const BYTE *p=a,*q=b; while(count--) { if(*p!=*q) return (int)*p-(int)*q; ++p;++q; } return 0; }
static HRESULT WINAPI event_query(IFileDialogEvents *p,REFIID iid,void **out)
{
    if(!out) return E_POINTER;
    *out=NULL;
    if(!memcmp(iid,&IID_IUnknown,sizeof(GUID)) || !memcmp(iid,&IID_IFileDialogEvents,sizeof(GUID))) {
        *out=p; IFileDialogEvents_AddRef(p); return S_OK;
    }
    if(!memcmp(iid,&IID_IFileDialogControlEvents,sizeof(GUID))) {
        *out=&((probe_events *)p)->control_iface; IFileDialogEvents_AddRef(p); return S_OK;
    }
    return E_NOINTERFACE;
}
static ULONG WINAPI event_addref(IFileDialogEvents *p) { return (ULONG)InterlockedIncrement(&((probe_events *)p)->refs); }
static ULONG WINAPI event_release(IFileDialogEvents *p) { return (ULONG)InterlockedDecrement(&((probe_events *)p)->refs); }
static probe_events *from_controls(IFileDialogControlEvents *p)
{ return (probe_events *)((BYTE *)p - offsetof(probe_events,control_iface)); }
static HRESULT WINAPI control_query(IFileDialogControlEvents *p,REFIID iid,void **out)
{ return event_query(&from_controls(p)->iface,iid,out); }
static ULONG WINAPI control_addref(IFileDialogControlEvents *p)
{ return event_addref(&from_controls(p)->iface); }
static ULONG WINAPI control_release(IFileDialogControlEvents *p)
{ return event_release(&from_controls(p)->iface); }
static HRESULT WINAPI control_item(IFileDialogControlEvents *p,IFileDialogCustomize *custom,DWORD id,DWORD item)
{ (void)p;(void)custom;(void)id;(void)item; return E_NOTIMPL; }
static HRESULT WINAPI control_button(IFileDialogControlEvents *p,IFileDialogCustomize *custom,DWORD id)
{ (void)p;(void)custom;(void)id; return E_NOTIMPL; }
static HRESULT WINAPI control_toggle(IFileDialogControlEvents *p,IFileDialogCustomize *custom,DWORD id,BOOL checked)
{
    probe_events *events=from_controls(p);
    BOOL actual=FALSE;
    ++events->toggles;
    require(id==4 && SUCCEEDED(IFileDialogCustomize_GetCheckButtonState(custom,id,&actual)) && actual==checked,
            "real IFileDialogControlEvents callback agrees with native checkbox state");
    say("M98-FDLG CHECK-EVENT id=");hex(id);say(" checked=");hex((DWORD)checked);say("\r\n");
    return S_OK;
}
static HRESULT WINAPI control_activate(IFileDialogControlEvents *p,IFileDialogCustomize *custom,DWORD id)
{ (void)p;(void)custom;(void)id; return S_OK; }
static const IFileDialogControlEventsVtbl control_vtable={control_query,control_addref,control_release,
    control_item,control_button,control_toggle,control_activate};

typedef struct native_geometry { HWND checkbox,disabled; } native_geometry;
static BOOL CALLBACK find_native_controls(HWND hwnd,LPARAM param)
{
    native_geometry *geometry=(native_geometry *)param;
    char label[128];
    if(GetWindowTextA(hwnd,label,sizeof(label))) {
        if(!lstrcmpA(label,"Native checkbox - enable this before saving")) geometry->checkbox=hwnd;
        if(!lstrcmpA(label,"Native disabled control")) geometry->disabled=hwnd;
    }
    return TRUE;
}
static void verify_native_geometry(HWND hwnd)
{
    native_geometry geometry={0};
    RECT box,disabled,filter,window;
    EnumChildWindows(hwnd,find_native_controls,(LPARAM)&geometry);
    require(geometry.checkbox && geometry.disabled,"both custom controls are actual native child windows");
    if(!geometry.checkbox || !geometry.disabled) return;
    require(GetWindowRect(geometry.checkbox,&box) && GetWindowRect(geometry.disabled,&disabled) &&
            GetWindowRect(GetDlgItem(hwnd,cmb1),&filter) && GetWindowRect(hwnd,&window) &&
            box.top>=filter.bottom && disabled.top>=box.bottom &&
            box.left>=window.left && box.right<=window.right && disabled.bottom<=window.bottom,
            "native checkbox rows stay below standard controls and inside the live dialog");
}
static HRESULT WINAPI event_ok(IFileDialogEvents *p,IFileDialog *dialog)
{
    probe_events *e=(probe_events *)p;
    IShellItem *folder=NULL;
    LPWSTR name=NULL;
    require(SUCCEEDED(IFileDialog_GetFolder(dialog,&folder)) && folder,"OnFileOk observes actual native folder");
    if(folder) IShellItem_Release(folder);
    require(SUCCEEDED(IFileDialog_GetFileName(dialog,&name)) && name && name[0],"OnFileOk observes actual native filename");
    if(name) CoTaskMemFree(name);
    ++e->accepts;
    if(e->veto && e->accepts==1) { say("M98-FDLG VETO first-accept=1\r\n"); return S_FALSE; }
    say("M98-FDLG ACCEPT callback=1\r\n");
    return S_OK;
}
static HRESULT WINAPI event_changing(IFileDialogEvents *p,IFileDialog *d,IShellItem *item)
{ (void)p;(void)d;(void)item; return S_OK; }
static HRESULT WINAPI event_folder(IFileDialogEvents *p,IFileDialog *dialog)
{
    probe_events *e=(probe_events *)p;
    IOleWindow *window=NULL;
    HWND hwnd=NULL;
    ++e->folders;
    if(e->folders==1) {
        require(SUCCEEDED(IFileDialog_QueryInterface(dialog,&IID_IOleWindow,(void **)&window)) && window,"native dialog provides IOleWindow");
        if(window) {
            require(SUCCEEDED(IOleWindow_GetWindow(window,&hwnd)) && hwnd && IsWindow(hwnd),"IOleWindow is the real live guest window");
            if(hwnd && IsWindow(hwnd)) verify_native_geometry(hwnd);
            say("M98-FDLG READY hwnd=");hex((DWORD)(UINT_PTR)hwnd);say("\r\n");
            IOleWindow_Release(window);
        }
    }
    return S_OK;
}
static HRESULT WINAPI event_selection(IFileDialogEvents *p,IFileDialog *d)
{ (void)d; ++((probe_events *)p)->selections; return S_OK; }
static HRESULT WINAPI event_share(IFileDialogEvents *p,IFileDialog *d,IShellItem *item,FDE_SHAREVIOLATION_RESPONSE *response)
{ (void)p;(void)d;(void)item; *response=FDESVR_DEFAULT; return S_OK; }
static HRESULT WINAPI event_type(IFileDialogEvents *p,IFileDialog *d)
{ UINT index=0; ++((probe_events *)p)->types; require(SUCCEEDED(IFileDialog_GetFileTypeIndex(d,&index)) && index>0,"type callback observes a 1-based real filter index"); return S_OK; }
static HRESULT WINAPI event_overwrite(IFileDialogEvents *p,IFileDialog *d,IShellItem *item,FDE_OVERWRITE_RESPONSE *response)
{ (void)p;(void)d;(void)item; *response=FDEOR_DEFAULT; return S_OK; }
static const IFileDialogEventsVtbl event_vtable={event_query,event_addref,event_release,event_ok,event_changing,event_folder,event_selection,event_share,event_type,event_overwrite};

static void contract(IClassFactory *factory)
{
    IFileSaveDialog *d=NULL;
    IFileDialogCustomize *custom=NULL;
    IOleWindow *window=NULL;
    IUnknown *identity=NULL,*other=NULL;
    IShellItem *result=(IShellItem *)(UINT_PTR)1;
    LPWSTR text=NULL;
    COMDLG_FILTERSPEC types[2]={{L"Text",L"*.txt"},{L"All",L"*.*"}};
    DWORD options=0,cookie=0;
    BOOL checked=FALSE;
    CDCONTROLSTATEF state=0;
    UINT index=0;
    HWND hwnd=(HWND)(UINT_PTR)1;
    probe_events events={.iface={&event_vtable},.control_iface={&control_vtable},.refs=1};
    require(factory->lpVtbl->CreateInstance(factory,(IUnknown *)factory,&IID_IFileSaveDialog,(void **)&d)==CLASS_E_NOAGGREGATION && !d,"aggregation is rejected and output cleared");
    require(SUCCEEDED(IClassFactory_CreateInstance(factory,NULL,&IID_IFileSaveDialog,(void **)&d)) && d,"class factory creates real Save dialog");
    if(!d) return;
    require(IFileSaveDialog_GetResult(d,&result)==E_UNEXPECTED && !result,"GetResult cannot fabricate a pre-selection result");
    require(IFileSaveDialog_QueryInterface(d,&IID_IFileOpenDialog,(void **)&other)==E_NOINTERFACE && !other,"unsupported Open interface fails explicitly");
    require(SUCCEEDED(IFileSaveDialog_QueryInterface(d,&IID_IUnknown,(void **)&identity)),"dialog identity");
    require(SUCCEEDED(IFileSaveDialog_QueryInterface(d,&IID_IFileDialogCustomize,(void **)&custom)) && custom,"custom checkbox interface");
    if(custom) {
        require(SUCCEEDED(IFileDialogCustomize_QueryInterface(custom,&IID_IUnknown,(void **)&other)) && identity==other,"custom interface has the same IUnknown identity");
        if(other) IUnknown_Release(other);
        require(SUCCEEDED(IFileDialogCustomize_AddCheckButton(custom,4,L"Open copy after saving",FALSE)),"native checkbox configuration");
        require(IFileDialogCustomize_AddCheckButton(custom,4,L"Duplicate",FALSE)==E_INVALIDARG,"duplicate control IDs rejected");
        require(SUCCEEDED(IFileDialogCustomize_SetCheckButtonState(custom,4,TRUE)) && SUCCEEDED(IFileDialogCustomize_GetCheckButtonState(custom,4,&checked)) && checked,"checkbox state round trip");
        require(SUCCEEDED(IFileDialogCustomize_SetControlState(custom,4,CDCS_VISIBLE)) && SUCCEEDED(IFileDialogCustomize_GetControlState(custom,4,&state)) && state==CDCS_VISIBLE,"disabled visible control state round trip");
        require(IFileDialogCustomize_AddComboBox(custom,7)==E_NOTIMPL,"unsupported custom feature returns E_NOTIMPL");
        IFileDialogCustomize_Release(custom);
    }
    if(identity) IUnknown_Release(identity);
    require(SUCCEEDED(IFileSaveDialog_QueryInterface(d,&IID_IOleWindow,(void **)&window)),"OLE window interface");
    if(window) { require(IOleWindow_GetWindow(window,&hwnd)==E_FAIL && !hwnd,"no invented HWND before Show"); IOleWindow_Release(window); }
    require(SUCCEEDED(IFileSaveDialog_GetOptions(d,&options)) && (options&FOS_OVERWRITEPROMPT),"Save dialog defaults request overwrite confirmation");
    require(IFileSaveDialog_SetOptions(d,FOS_ALLOWMULTISELECT)==E_NOTIMPL,"unsupported multiple-selection semantics fail");
    require(SUCCEEDED(IFileSaveDialog_SetFileTypes(d,2,types)),"filter names and patterns accepted");
    require(IFileSaveDialog_SetFileTypes(d,2,types)==E_UNEXPECTED,"file types cannot be replaced after initialization");
    require(IFileSaveDialog_SetFileTypeIndex(d,0)==E_INVALIDARG && IFileSaveDialog_SetFileTypeIndex(d,3)==E_INVALIDARG,"invalid filter indexes rejected");
    require(SUCCEEDED(IFileSaveDialog_SetFileTypeIndex(d,2)) && SUCCEEDED(IFileSaveDialog_GetFileTypeIndex(d,&index)) && index==2,"1-based filter round trip");
    require(SUCCEEDED(IFileSaveDialog_SetFileName(d,L"Native save.txt")) && SUCCEEDED(IFileSaveDialog_GetFileName(d,&text)) && text && !memcmp(text,L"Native save.txt",sizeof(L"Native save.txt")),"CoTaskMem-owned Unicode filename round trip");
    if(text) CoTaskMemFree(text);
    require(SUCCEEDED(IFileSaveDialog_Advise(d,&events.iface,&cookie)) && cookie && events.refs==2,"Advise retains the actual event sink");
    require(SUCCEEDED(IFileSaveDialog_Unadvise(d,cookie)) && events.refs==1,"Unadvise releases the actual event sink");
    require(IFileSaveDialog_Unadvise(d,cookie)==CONNECT_E_NOCONNECTION,"stale cookie rejected");
    IFileSaveDialog_Release(d);
}
static void ui(BOOL cancel,BOOL veto)
{
    IFileSaveDialog *dialog=NULL;
    IFileDialogCustomize *custom=NULL;
    IShellItem *item=NULL,*parent=NULL;
    LPWSTR wide=NULL;
    char path[MAX_PATH],current[MAX_PATH],after[MAX_PATH];
    const char token[]="Windows98 native COM Save As proof\r\n";
    char bytes[sizeof(token)]={0};
    HANDLE file;
    DWORD written=0,read=0,cookie=0;
    SFGAOF attrs=0;
    HRESULT hr;
    BOOL checked=FALSE;
    probe_events events={.iface={&event_vtable},.control_iface={&control_vtable},.refs=1};
    COMDLG_FILTERSPEC types[2]={{L"Text files",L"*.txt"},{L"All files",L"*.*"}};
    events.veto=veto;
    hr=CoCreateInstance(&CLSID_FileSaveDialog,NULL,CLSCTX_INPROC_SERVER,&IID_IFileSaveDialog,(void **)&dialog);
    say("M98-FDLG COCREATE hr="); hex((DWORD)hr);say("\r\n");
    require(SUCCEEDED(hr) && dialog,"native registered COM activation");
    if(!dialog) return;
    require(SUCCEEDED(IFileSaveDialog_SetTitle(dialog,cancel?L"Windows98 COM Save As - Cancel proof":L"Windows98 COM Save As - Save proof")),"set native UI title");
    require(SUCCEEDED(IFileSaveDialog_SetFileTypes(dialog,2,types)) && SUCCEEDED(IFileSaveDialog_SetFileTypeIndex(dialog,1)),"set actual native filters");
    require(SUCCEEDED(IFileSaveDialog_SetDefaultExtension(dialog,L"txt")) && SUCCEEDED(IFileSaveDialog_SetFileName(dialog,L"C:\\FDLG\\SAVEQA.TXT")),"set actual target name and extension");
    require(SUCCEEDED(IFileSaveDialog_QueryInterface(dialog,&IID_IFileDialogCustomize,(void **)&custom)) && custom,"real custom interface before native UI");
    if(custom) {
        require(SUCCEEDED(IFileDialogCustomize_AddCheckButton(custom,4,L"Native checkbox - enable this before saving",FALSE)),"add actual visible checkbox");
        require(SUCCEEDED(IFileDialogCustomize_AddCheckButton(custom,5,L"Native disabled control",TRUE)) && SUCCEEDED(IFileDialogCustomize_SetControlState(custom,5,CDCS_VISIBLE)),"add actual disabled visible checkbox");
    }
    require(SUCCEEDED(IFileSaveDialog_Advise(dialog,&events.iface,&cookie)),"native event connection");
    GetCurrentDirectoryA(MAX_PATH,current);
    say(cancel?"M98-FDLG SHOW action=cancel\r\n":"M98-FDLG SHOW action=save\r\n");
    hr=IFileSaveDialog_Show(dialog,NULL);
    say("M98-FDLG SHOW-RESULT hr=");hex((DWORD)hr);say("\r\n");
    require(GetCurrentDirectoryA(MAX_PATH,after) && !lstrcmpA(current,after),"Show preserves the guest current directory");
    require(events.types && events.folders && events.selections,"real native type/folder/selection callbacks");
    if(cancel) {
        require(hr==HRESULT_FROM_WIN32(ERROR_CANCELLED),"real cancel returns ERROR_CANCELLED");
        require(IFileSaveDialog_GetResult(dialog,&item)==E_UNEXPECTED && !item,"cancel provides no selected file");
    } else if(SUCCEEDED(hr)) {
        require(events.accepts >= (veto?2u:1u),"OnFileOk executes and honors first-accept veto");
        if(custom) require(SUCCEEDED(IFileDialogCustomize_GetCheckButtonState(custom,4,&checked)) && checked,"user toggled the real checkbox");
        require(events.toggles>0,"native checkbox sends an actual IFileDialogControlEvents callback");
        require(SUCCEEDED(IFileSaveDialog_GetResult(dialog,&item)) && item,"real selected IShellItem result");
        if(item) {
            require(SUCCEEDED(IShellItem_GetDisplayName(item,SIGDN_FILESYSPATH,&wide)) && wide,"result returns actual filesystem path");
            require(SUCCEEDED(IShellItem_GetAttributes(item,SFGAO_FILESYSTEM,&attrs)) && (attrs&SFGAO_FILESYSTEM),"selected item is a filesystem item");
            require(SUCCEEDED(IShellItem_GetParent(item,&parent)) && parent,"selected item has a real parent path");
            if(parent) IShellItem_Release(parent);
            if(wide && WideCharToMultiByte(CP_ACP,0,wide,-1,path,MAX_PATH,NULL,NULL)) {
                say("M98-FDLG SELECTED path=");say(path);say("\r\n");
                require(!lstrcmpiA(path,"C:\\FDLG\\SAVEQA.TXT"),"user selected the bounded proof path");
                if(!lstrcmpiA(path,"C:\\FDLG\\SAVEQA.TXT")) {
                    file=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
                    require(file!=INVALID_HANDLE_VALUE,"caller creates the real selected file");
                    if(file!=INVALID_HANDLE_VALUE) {
                        require(WriteFile(file,token,sizeof(token)-1,&written,NULL) && written==sizeof(token)-1 && FlushFileBuffers(file),"caller writes and flushes exact proof bytes");
                        SetFilePointer(file,0,NULL,FILE_BEGIN);
                        require(ReadFile(file,bytes,sizeof(bytes),&read,NULL) && read==sizeof(token)-1 && !memcmp(bytes,token,sizeof(token)-1),"caller reads identical real disk bytes");
                        CloseHandle(file);
                    }
                }
            } else require(FALSE,"selected path converts to native filesystem encoding");
            if(wide) CoTaskMemFree(wide);
            IShellItem_Release(item);
        }
    } else require(FALSE,"real save completes successfully");
    require(SUCCEEDED(IFileSaveDialog_Unadvise(dialog,cookie)) && events.refs==1,"native event sink released after Show");
    if(custom) IFileDialogCustomize_Release(custom);
    IFileSaveDialog_Release(dialog);
    require(can_unload()==S_OK,"UI releases all live COM objects and event references");
}
void mainCRTStartup(void)
{
    HMODULE dll;
    IClassFactory *factory=NULL;
    get_class_fn get_class;
    entry_fn registration;
    OSVERSIONINFOA version;
    char path[MAX_PATH],*end;
    HRESULT hr;
    memset(&version,0,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    output=CreateFileA("C:\\FDLG\\PROBE.LOG",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    require(GetVersionExA(&version) && version.dwPlatformId==VER_PLATFORM_WIN32_WINDOWS && version.dwMajorVersion==4 && version.dwMinorVersion==10,"actual Microsoft Windows98 guest required");
    say("M98-FDLG OS platform=");hex(version.dwPlatformId);say(" major=");hex(version.dwMajorVersion);say(" minor=");hex(version.dwMinorVersion);say("\r\n");
    if(failures) goto done;
    require(SUCCEEDED(CoInitialize(NULL)),"native OLE initialization");
    if(failures) goto done;
    if(!GetModuleFileNameA(NULL,path,MAX_PATH)) { require(FALSE,"probe path"); goto uninit; }
    end=path+lstrlenA(path);while(end>path && end[-1]!='\\') --end;
    if(end-path>MAX_PATH-13) { require(FALSE,"probe path bound"); goto uninit; }
    lstrcpyA(end,"M98FDLG.DLL");
    dll=LoadLibraryA(path); require(dll!=NULL,"load exact adjacent native provider");
    if(!dll) goto uninit;
    get_class=(get_class_fn)GetProcAddress(dll,"DllGetClassObject");
    can_unload=(entry_fn)GetProcAddress(dll,"DllCanUnloadNow");
    require(get_class && can_unload,"COM server exports");
    if(!get_class || !can_unload) goto unload;
    if(option("--register") || option("--unregister")) {
        registration=(entry_fn)GetProcAddress(dll,option("--register")?"DllRegisterServer":"DllUnregisterServer");
        hr=registration?registration():E_NOTIMPL;
        say("M98-FDLG REGISTRATION hr=");hex((DWORD)hr);say("\r\n");
        require(SUCCEEDED(hr),"explicit guest-only COM registration action");
    } else if(option("--save") || option("--cancel") || option("--veto")) ui(option("--cancel"),option("--veto"));
    else {
        hr=get_class(&CLSID_FileSaveDialog,&IID_IClassFactory,(void **)&factory);
        require(SUCCEEDED(hr) && factory,"real native COM class factory");
        if(factory) { contract(factory); IClassFactory_Release(factory); }
        require(can_unload()==S_OK,"all COM objects and event sinks released");
    }
unload:
    FreeLibrary(dll);
uninit:
    CoUninitialize();
done:
    say("M98-FDLG RESULT checks=");hex(checks);say(" failures=");hex(failures);say(" native-ui=");say(option("--save")||option("--cancel")||option("--veto")?"required":"not-tested");say("\r\n");
    if(output!=INVALID_HANDLE_VALUE) CloseHandle(output);
    ExitProcess(failures?1:0);
}
