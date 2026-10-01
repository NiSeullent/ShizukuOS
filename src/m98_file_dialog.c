/* SPDX-License-Identifier: GPL-2.0-only
 * New COM implementation backed by the guest's original COMDLG32 Save As UI.
 * API contracts: Microsoft IFileDialog/IFileSaveDialog and OPENFILENAMEA docs.
 * The latest NPP v8.9.8.1 CustomFileDialog.cpp informed the required interfaces;
 * no NPP/Wine implementation body is copied. Unsupported interfaces/methods
 * fail explicitly. This is a filesystem Save dialog, not a modern Shell port.
 */
#include "m98_file_dialog.h"
#include <commdlg.h>
#include <dlgs.h>
#include <olectl.h>
#include <stddef.h>

#define M98_PATH 260
#define M98_TEXT 1024
#define M98_FILTER_BYTES 65536
#define M98_CHECKS 8
#define M98_SINKS 8
#define M98_CONTROL_BASE 0x7000
#define M98_CANCEL HRESULT_FROM_WIN32(ERROR_CANCELLED)
#define M98_CLASS_KEY "CLSID\\{C0B4E2F3-BA21-4773-8DBA-335EC946EB8B}"
#define M98_SERVER_KEY M98_CLASS_KEY "\\InprocServer32"

static HINSTANCE module;
static LONG live_objects, server_locks;
static const IFileSaveDialogVtbl dialog_vtable;
static const IFileDialogCustomizeVtbl customize_vtable;
static const IOleWindowVtbl window_vtable;
static const IShellItemVtbl item_vtable;
static const IClassFactoryVtbl factory_vtable;

/* No CRT, TLS, Vista entry points, or Unicode USER32 calls are needed. */
void *memset(void *out, int value, size_t count)
{ volatile unsigned char *p=out; while(count--) *p++=(unsigned char)value; return out; }
void *memcpy(void *out, const void *in, size_t count)
{ volatile unsigned char *p=out; const volatile unsigned char *q=in; while(count--) *p++=*q++; return out; }
static int equal_guid(REFGUID a, REFGUID b)
{ unsigned i; if(!a || !b) return 0; for(i=0;i<sizeof(GUID);i++) if(((const BYTE *)a)[i]!=((const BYTE *)b)[i]) return 0; return 1; }
static HRESULT last_error(void)
{ DWORD error=GetLastError(); return HRESULT_FROM_WIN32(error?error:ERROR_GEN_FAILURE); }
static void *allocate(SIZE_T bytes)
{ return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,bytes); }
static void deallocate(void *ptr)
{ if(ptr) HeapFree(GetProcessHeap(),0,ptr); }

/* Round-trip prevents best-fit/replacement characters from selecting a
 * different file. Win98 has no general Unicode filesystem: fail lossily
 * encoded names instead of claiming a successful conversion. */
static HRESULT ansi_from_wide(LPCWSTR text, char *out, UINT capacity)
{
    BOOL replaced=FALSE;
    WCHAR roundtrip[M98_TEXT];
    UINT i=0;
    if(!text || !out || !capacity) return E_INVALIDARG;
    while(text[i]) { if(++i>=M98_TEXT) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE); }
    if(!WideCharToMultiByte(CP_ACP,0,text,-1,out,(int)capacity,NULL,&replaced)) return last_error();
    if(replaced || !MultiByteToWideChar(CP_ACP,0,out,-1,roundtrip,M98_TEXT)) return HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION);
    for(i=0;text[i] || roundtrip[i];i++) if(text[i]!=roundtrip[i]) return HRESULT_FROM_WIN32(ERROR_NO_UNICODE_TRANSLATION);
    return S_OK;
}
static HRESULT task_wide(const char *text, LPWSTR *out)
{
    int count;
    if(!out) return E_POINTER;
    *out=NULL;
    count=MultiByteToWideChar(CP_ACP,0,text,-1,NULL,0);
    if(!count) return last_error();
    *out=CoTaskMemAlloc((SIZE_T)count*sizeof(WCHAR));
    if(!*out) return E_OUTOFMEMORY;
    if(!MultiByteToWideChar(CP_ACP,0,text,-1,*out,count)) { CoTaskMemFree(*out); *out=NULL; return last_error(); }
    return S_OK;
}
static HRESULT full_path(const char *path, char out[M98_PATH])
{
    DWORD count;
    if(!path || !*path) return E_INVALIDARG;
    count=GetFullPathNameA(path,M98_PATH,out,NULL);
    if(!count) return last_error();
    if(count>=M98_PATH) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    return S_OK;
}
static int parent_path(char *path)
{
    int n=lstrlenA(path);
    while(n>3 && (path[n-1]=='\\' || path[n-1]=='/')) path[--n]=0;
    while(n>0 && path[n-1]!='\\' && path[n-1]!='/') --n;
    if(!n) return 0;
    if(n>3) --n;
    path[n]=0;
    return 1;
}

typedef struct path_item { IShellItem iface; LONG refs; char path[M98_PATH]; } path_item;
typedef struct check_control { DWORD id; char label[M98_TEXT]; BOOL checked; CDCONTROLSTATEF state; HWND hwnd; } check_control;
typedef struct event_sink { DWORD cookie; IFileDialogEvents *events; } event_sink;
typedef struct file_dialog {
    IFileSaveDialog iface;
    IFileDialogCustomize customize;
    IOleWindow window;
    LONG refs;
    FILEOPENDIALOGOPTIONS options;
    char filename[M98_PATH], folder[M98_PATH], default_folder[M98_PATH];
    char title[M98_TEXT], extension[M98_PATH], ok_label[M98_TEXT], file_label[M98_TEXT];
    char result[M98_PATH];
    char *filters;
    UINT filter_count, filter_index;
    event_sink sinks[M98_SINKS];
    DWORD next_cookie;
    check_control controls[M98_CHECKS];
    UINT control_count;
    HWND hwnd, hook_window;
    OPENFILENAMEA *active;
    HRESULT close_result, hook_error;
    BOOL showing, closed, result_valid, initialized;
} file_dialog;
typedef struct class_factory { IClassFactory iface; LONG refs; } class_factory;
static file_dialog *from_customize(IFileDialogCustomize *p)
{ return (file_dialog *)((BYTE *)p - offsetof(file_dialog,customize)); }
static file_dialog *from_window(IOleWindow *p)
{ return (file_dialog *)((BYTE *)p - offsetof(file_dialog,window)); }
static IFileDialog *base_dialog(file_dialog *d) { return (IFileDialog *)&d->iface; }

static HRESULT new_path_item(const char *path, IShellItem **out)
{
    path_item *item;
    HRESULT hr;
    if(!out) return E_POINTER;
    *out=NULL;
    item=allocate(sizeof(*item));
    if(!item) return E_OUTOFMEMORY;
    hr=full_path(path,item->path);
    if(FAILED(hr)) { deallocate(item); return hr; }
    item->iface.lpVtbl=&item_vtable; item->refs=1;
    InterlockedIncrement(&live_objects); *out=&item->iface;
    return S_OK;
}
static ULONG WINAPI item_addref(IShellItem *p) { return (ULONG)InterlockedIncrement(&((path_item *)p)->refs); }
static ULONG WINAPI item_release(IShellItem *p)
{ ULONG refs=(ULONG)InterlockedDecrement(&((path_item *)p)->refs); if(!refs) { deallocate(p); InterlockedDecrement(&live_objects); } return refs; }
static HRESULT WINAPI item_query(IShellItem *p,REFIID iid,void **out)
{
    if(!out) return E_POINTER;
    *out=NULL;
    if(!iid) return E_INVALIDARG;
    if(!equal_guid(iid,&IID_IUnknown) && !equal_guid(iid,&IID_IShellItem)) return E_NOINTERFACE;
    *out=p; item_addref(p); return S_OK;
}
static HRESULT WINAPI item_bind(IShellItem *p,IBindCtx *ctx,REFGUID bhid,REFIID iid,void **out)
{ (void)p;(void)ctx;(void)bhid;(void)iid; if(!out) return E_POINTER; *out=NULL; return E_NOTIMPL; }
static HRESULT WINAPI item_parent(IShellItem *p,IShellItem **out)
{
    char path[M98_PATH];
    if(!out) return E_POINTER;
    *out=NULL; lstrcpyA(path,((path_item *)p)->path);
    if(!parent_path(path) || !lstrcmpiA(path,((path_item *)p)->path)) return MK_E_NOOBJECT;
    return new_path_item(path,out);
}
static HRESULT WINAPI item_name(IShellItem *p,SIGDN type,LPWSTR *out)
{
    const char *path=((path_item *)p)->path, *name=path;
    if(!out) return E_POINTER;
    *out=NULL;
    if(type==SIGDN_NORMALDISPLAY || type==SIGDN_PARENTRELATIVEPARSING || type==SIGDN_PARENTRELATIVEEDITING) {
        const char *q=path;
        while(*q) { if(q[0]=='\\' && q[1]) name=q+1; ++q; }
    } else if(type!=SIGDN_FILESYSPATH && type!=SIGDN_DESKTOPABSOLUTEPARSING && type!=SIGDN_DESKTOPABSOLUTEEDITING) return E_INVALIDARG;
    return task_wide(name,out);
}
static HRESULT WINAPI item_attributes(IShellItem *p,SFGAOF mask,SFGAOF *out)
{
    DWORD attrs;
    SFGAOF flags=SFGAO_FILESYSTEM;
    if(!out) return E_POINTER;
    attrs=GetFileAttributesA(((path_item *)p)->path);
    if(attrs!=INVALID_FILE_ATTRIBUTES) {
        if(attrs&FILE_ATTRIBUTE_DIRECTORY) flags|=SFGAO_FOLDER;
        if(attrs&FILE_ATTRIBUTE_READONLY) flags|=SFGAO_READONLY;
        if(attrs&FILE_ATTRIBUTE_HIDDEN) flags|=SFGAO_HIDDEN;
    } else {
        DWORD error=GetLastError();
        if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND) { *out=0; return HRESULT_FROM_WIN32(error); }
    }
    *out=flags&mask;
    return *out==mask?S_OK:S_FALSE;
}
static HRESULT WINAPI item_compare(IShellItem *p,IShellItem *other,SICHINTF hint,int *out)
{
    LPWSTR wide=NULL;
    char path[M98_PATH];
    HRESULT hr;
    (void)hint;
    if(!other || !out) return E_INVALIDARG;
    hr=IShellItem_GetDisplayName(other,SIGDN_FILESYSPATH,&wide);
    if(FAILED(hr)) return hr;
    hr=ansi_from_wide(wide,path,sizeof(path)); CoTaskMemFree(wide);
    if(FAILED(hr)) return hr;
    *out=lstrcmpiA(((path_item *)p)->path,path);
    return *out?S_FALSE:S_OK;
}
static const IShellItemVtbl item_vtable={item_query,item_addref,item_release,item_bind,item_parent,item_name,item_attributes,item_compare};

static ULONG WINAPI dialog_addref(IFileSaveDialog *p) { return (ULONG)InterlockedIncrement(&((file_dialog *)p)->refs); }
static ULONG WINAPI dialog_release(IFileSaveDialog *p)
{
    file_dialog *d=(file_dialog *)p;
    ULONG refs=(ULONG)InterlockedDecrement(&d->refs);
    UINT i;
    if(!refs) {
        for(i=0;i<M98_SINKS;i++) if(d->sinks[i].events) IFileDialogEvents_Release(d->sinks[i].events);
        deallocate(d->filters); deallocate(d); InterlockedDecrement(&live_objects);
    }
    return refs;
}
static HRESULT WINAPI dialog_query(IFileSaveDialog *p,REFIID iid,void **out)
{
    file_dialog *d=(file_dialog *)p;
    if(!out) return E_POINTER;
    *out=NULL;
    if(!iid) return E_INVALIDARG;
    if(equal_guid(iid,&IID_IUnknown) || equal_guid(iid,&IID_IModalWindow) || equal_guid(iid,&IID_IFileDialog) || equal_guid(iid,&IID_IFileSaveDialog)) *out=p;
    else if(equal_guid(iid,&IID_IFileDialogCustomize)) *out=&d->customize;
    else if(equal_guid(iid,&IID_IOleWindow)) *out=&d->window;
    else return E_NOINTERFACE;
    dialog_addref(p); return S_OK;
}
static HRESULT WINAPI custom_query(IFileDialogCustomize *p,REFIID iid,void **out) { return dialog_query(&from_customize(p)->iface,iid,out); }
static ULONG WINAPI custom_addref(IFileDialogCustomize *p) { return dialog_addref(&from_customize(p)->iface); }
static ULONG WINAPI custom_release(IFileDialogCustomize *p) { return dialog_release(&from_customize(p)->iface); }
static HRESULT WINAPI window_query(IOleWindow *p,REFIID iid,void **out) { return dialog_query(&from_window(p)->iface,iid,out); }
static ULONG WINAPI window_addref(IOleWindow *p) { return dialog_addref(&from_window(p)->iface); }
static ULONG WINAPI window_release(IOleWindow *p) { return dialog_release(&from_window(p)->iface); }
static HRESULT WINAPI window_get(IOleWindow *p,HWND *out)
{ if(!out) return E_POINTER; *out=from_window(p)->hwnd; return *out?S_OK:E_FAIL; }
static HRESULT WINAPI window_help(IOleWindow *p,BOOL enter) { (void)p;(void)enter; return E_NOTIMPL; }
static const IOleWindowVtbl window_vtable={window_query,window_addref,window_release,window_get,window_help};

static HRESULT WINAPI dialog_filters(IFileSaveDialog *p,UINT count,const COMDLG_FILTERSPEC *spec)
{
    file_dialog *d=(file_dialog *)p;
    char *filters;
    UINT i,used=0;
    HRESULT hr=S_OK;
    if(d->showing || d->filter_count) return E_UNEXPECTED;
    if(!count || !spec || count>512) return E_INVALIDARG;
    filters=allocate(M98_FILTER_BYTES);
    if(!filters) return E_OUTOFMEMORY;
    for(i=0;i<count;i++) {
        if(used>=M98_FILTER_BYTES-1) { hr=E_INVALIDARG; break; }
        hr=ansi_from_wide(spec[i].pszName,filters+used,M98_FILTER_BYTES-used-1);
        if(FAILED(hr)) break;
        used+=(UINT)lstrlenA(filters+used)+1;
        hr=ansi_from_wide(spec[i].pszSpec,filters+used,M98_FILTER_BYTES-used-1);
        if(FAILED(hr)) break;
        used+=(UINT)lstrlenA(filters+used)+1;
    }
    if(FAILED(hr)) { deallocate(filters); return hr; }
    filters[used]=0; d->filters=filters; d->filter_count=count;
    if(d->filter_index>count) d->filter_index=1;
    return S_OK;
}
static HRESULT WINAPI dialog_type(IFileSaveDialog *p,UINT index)
{
    file_dialog *d=(file_dialog *)p;
    if(!index || (d->filter_count && index>d->filter_count)) return E_INVALIDARG;
    d->filter_index=index;
    if(d->active) d->active->nFilterIndex=index;
    if(d->hwnd) {
        HWND combo=GetDlgItem(d->hwnd,cmb1);
        if(!combo) return E_FAIL;
        SendMessageA(combo,CB_SETCURSEL,index-1,0);
        SendMessageA(d->hwnd,WM_COMMAND,MAKEWPARAM(cmb1,CBN_SELCHANGE),(LPARAM)combo);
    }
    return S_OK;
}
static HRESULT WINAPI dialog_get_type(IFileSaveDialog *p,UINT *out)
{ if(!out) return E_POINTER; *out=((file_dialog *)p)->filter_index; return S_OK; }
static HRESULT WINAPI dialog_advise(IFileSaveDialog *p,IFileDialogEvents *sink,DWORD *cookie)
{
    file_dialog *d=(file_dialog *)p;
    UINT i;
    if(!cookie) return E_POINTER;
    *cookie=0;
    if(!sink) return E_INVALIDARG;
    for(i=0;i<M98_SINKS;i++) if(!d->sinks[i].events) {
        IFileDialogEvents_AddRef(sink);
        if(!++d->next_cookie) ++d->next_cookie;
        d->sinks[i].events=sink; d->sinks[i].cookie=d->next_cookie;
        *cookie=d->next_cookie; return S_OK;
    }
    return CONNECT_E_ADVISELIMIT;
}
static HRESULT WINAPI dialog_unadvise(IFileSaveDialog *p,DWORD cookie)
{
    file_dialog *d=(file_dialog *)p;
    UINT i;
    for(i=0;i<M98_SINKS;i++) if(d->sinks[i].events && d->sinks[i].cookie==cookie) {
        IFileDialogEvents *sink=d->sinks[i].events;
        d->sinks[i].events=NULL; d->sinks[i].cookie=0;
        IFileDialogEvents_Release(sink); return S_OK;
    }
    return CONNECT_E_NOCONNECTION;
}
static HRESULT WINAPI dialog_options(IFileSaveDialog *p,FILEOPENDIALOGOPTIONS options)
{
    const DWORD supported=FOS_OVERWRITEPROMPT|FOS_NOCHANGEDIR|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST|FOS_FILEMUSTEXIST|FOS_NOREADONLYRETURN|FOS_NOTESTFILECREATE|FOS_NODEREFERENCELINKS;
    if(((file_dialog *)p)->showing) return E_UNEXPECTED;
    if(options&~supported) return E_NOTIMPL;
    ((file_dialog *)p)->options=options; return S_OK;
}
static HRESULT WINAPI dialog_get_options(IFileSaveDialog *p,FILEOPENDIALOGOPTIONS *out)
{ if(!out) return E_POINTER; *out=((file_dialog *)p)->options; return S_OK; }
static HRESULT folder_from_item(IShellItem *item,char path[M98_PATH])
{
    LPWSTR wide=NULL;
    HRESULT hr;
    DWORD attrs;
    if(!item) return E_INVALIDARG;
    hr=IShellItem_GetDisplayName(item,SIGDN_FILESYSPATH,&wide);
    if(FAILED(hr)) return hr;
    hr=ansi_from_wide(wide,path,M98_PATH); CoTaskMemFree(wide);
    if(FAILED(hr)) return hr;
    attrs=GetFileAttributesA(path);
    if(attrs==INVALID_FILE_ATTRIBUTES) return last_error();
    return attrs&FILE_ATTRIBUTE_DIRECTORY?S_OK:HRESULT_FROM_WIN32(ERROR_DIRECTORY);
}
static HRESULT WINAPI dialog_folder(IFileSaveDialog *p,IShellItem *item)
{ file_dialog *d=(file_dialog *)p; char path[M98_PATH]; HRESULT hr; if(d->showing) return E_NOTIMPL; hr=folder_from_item(item,path); if(SUCCEEDED(hr)) lstrcpyA(d->folder,path); return hr; }
static HRESULT WINAPI dialog_default_folder(IFileSaveDialog *p,IShellItem *item)
{ file_dialog *d=(file_dialog *)p; char path[M98_PATH]; HRESULT hr; if(d->showing) return E_UNEXPECTED; hr=folder_from_item(item,path); if(SUCCEEDED(hr)) lstrcpyA(d->default_folder,path); return hr; }
static HRESULT WINAPI dialog_get_folder(IFileSaveDialog *p,IShellItem **out)
{
    file_dialog *d=(file_dialog *)p;
    char path[M98_PATH];
    if(!out) return E_POINTER;
    *out=NULL;
    if(d->hwnd) {
        LRESULT count=SendMessageA(d->hwnd,CDM_GETFOLDERPATH,M98_PATH,(LPARAM)path);
        if(count<=0 || count>M98_PATH) return E_FAIL;
    } else if(d->folder[0]) lstrcpyA(path,d->folder);
    else if(d->default_folder[0]) lstrcpyA(path,d->default_folder);
    else {
        DWORD count=GetCurrentDirectoryA(M98_PATH,path);
        if(!count) return last_error();
        if(count>=M98_PATH) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    }
    return new_path_item(path,out);
}
static HRESULT WINAPI dialog_selection(IFileSaveDialog *p,IShellItem **out)
{
    file_dialog *d=(file_dialog *)p;
    char path[M98_PATH];
    LRESULT count;
    if(!out) return E_POINTER;
    *out=NULL;
    if(!d->hwnd) return E_UNEXPECTED;
    count=SendMessageA(d->hwnd,CDM_GETFILEPATH,M98_PATH,(LPARAM)path);
    if(count<=0 || count>M98_PATH || !path[0]) return E_FAIL;
    return new_path_item(path,out);
}
static HRESULT WINAPI dialog_name(IFileSaveDialog *p,LPCWSTR name)
{
    file_dialog *d=(file_dialog *)p;
    char text[M98_PATH];
    HRESULT hr=ansi_from_wide(name,text,sizeof(text));
    if(FAILED(hr)) return hr;
    lstrcpyA(d->filename,text);
    if(d->hwnd) SendMessageA(d->hwnd,CDM_SETCONTROLTEXT,edt1,(LPARAM)d->filename);
    return S_OK;
}
static HRESULT WINAPI dialog_get_name(IFileSaveDialog *p,LPWSTR *out)
{
    file_dialog *d=(file_dialog *)p;
    char text[M98_PATH];
    LRESULT count;
    if(!out) return E_POINTER;
    *out=NULL;
    if(d->hwnd) {
        count=SendMessageA(d->hwnd,CDM_GETSPEC,M98_PATH,(LPARAM)text);
        if(count<=0 || count>M98_PATH) return E_FAIL;
        return task_wide(text,out);
    }
    return task_wide(d->filename,out);
}
static HRESULT WINAPI dialog_title(IFileSaveDialog *p,LPCWSTR text)
{ file_dialog *d=(file_dialog *)p; HRESULT hr=ansi_from_wide(text,d->title,sizeof(d->title)); if(SUCCEEDED(hr) && d->hwnd) SetWindowTextA(d->hwnd,d->title); return hr; }
static HRESULT WINAPI dialog_ok_label(IFileSaveDialog *p,LPCWSTR text)
{ file_dialog *d=(file_dialog *)p; HRESULT hr=ansi_from_wide(text,d->ok_label,sizeof(d->ok_label)); if(SUCCEEDED(hr) && d->hwnd) SendMessageA(d->hwnd,CDM_SETCONTROLTEXT,IDOK,(LPARAM)d->ok_label); return hr; }
static HRESULT WINAPI dialog_file_label(IFileSaveDialog *p,LPCWSTR text)
{ file_dialog *d=(file_dialog *)p; HRESULT hr=ansi_from_wide(text,d->file_label,sizeof(d->file_label)); if(SUCCEEDED(hr) && d->hwnd) SendMessageA(d->hwnd,CDM_SETCONTROLTEXT,stc3,(LPARAM)d->file_label); return hr; }
static HRESULT WINAPI dialog_result(IFileSaveDialog *p,IShellItem **out)
{ file_dialog *d=(file_dialog *)p; if(!out) return E_POINTER; *out=NULL; if(!d->result_valid) return E_UNEXPECTED; return new_path_item(d->result,out); }
static HRESULT WINAPI dialog_extension(IFileSaveDialog *p,LPCWSTR text)
{ file_dialog *d=(file_dialog *)p; if(d->showing) return E_NOTIMPL; return ansi_from_wide(text,d->extension,sizeof(d->extension)); }
static HRESULT WINAPI dialog_close(IFileSaveDialog *p,HRESULT hr)
{ file_dialog *d=(file_dialog *)p; if(!d->hwnd) return E_UNEXPECTED; d->closed=TRUE; d->close_result=hr; PostMessageA(d->hwnd,WM_COMMAND,IDCANCEL,0); return S_OK; }

static check_control *find_control(file_dialog *d,DWORD id)
{ UINT i; for(i=0;i<d->control_count;i++) if(d->controls[i].id==id) return &d->controls[i]; return NULL; }
static void apply_control(check_control *c)
{
    if(!c->hwnd) return;
    EnableWindow(c->hwnd,(c->state&CDCS_ENABLED)!=0);
    ShowWindow(c->hwnd,(c->state&CDCS_VISIBLE)?SW_SHOW:SW_HIDE);
    SendMessageA(c->hwnd,BM_SETCHECK,c->checked?BST_CHECKED:BST_UNCHECKED,0);
}
static HRESULT WINAPI custom_add_check(IFileDialogCustomize *p,DWORD id,LPCWSTR label,BOOL checked)
{
    file_dialog *d=from_customize(p);
    check_control *c;
    HRESULT hr;
    if(d->showing) return E_UNEXPECTED;
    if(find_control(d,id)) return E_INVALIDARG;
    if(d->control_count>=M98_CHECKS) return E_OUTOFMEMORY;
    c=&d->controls[d->control_count];
    hr=ansi_from_wide(label,c->label,sizeof(c->label));
    if(FAILED(hr)) return hr;
    c->id=id; c->checked=!!checked; c->state=CDCS_ENABLED|CDCS_VISIBLE;
    ++d->control_count; return S_OK;
}
static HRESULT WINAPI custom_label(IFileDialogCustomize *p,DWORD id,LPCWSTR label)
{ check_control *c=find_control(from_customize(p),id); HRESULT hr; if(!c) return E_INVALIDARG; hr=ansi_from_wide(label,c->label,sizeof(c->label)); if(SUCCEEDED(hr) && c->hwnd) SetWindowTextA(c->hwnd,c->label); return hr; }
static HRESULT WINAPI custom_get_state(IFileDialogCustomize *p,DWORD id,CDCONTROLSTATEF *out)
{ check_control *c=find_control(from_customize(p),id); if(!out) return E_POINTER; *out=0; if(!c) return E_INVALIDARG; *out=c->state; return S_OK; }
static HRESULT WINAPI custom_set_state(IFileDialogCustomize *p,DWORD id,CDCONTROLSTATEF state)
{ check_control *c=find_control(from_customize(p),id); if(!c || (state&~(CDCS_ENABLED|CDCS_VISIBLE))) return E_INVALIDARG; c->state=state; apply_control(c); return S_OK; }
static HRESULT WINAPI custom_get_check(IFileDialogCustomize *p,DWORD id,BOOL *out)
{ check_control *c=find_control(from_customize(p),id); if(!out) return E_POINTER; *out=FALSE; if(!c) return E_INVALIDARG; if(c->hwnd) c->checked=SendMessageA(c->hwnd,BM_GETCHECK,0,0)==BST_CHECKED; *out=c->checked; return S_OK; }
static HRESULT WINAPI custom_set_check(IFileDialogCustomize *p,DWORD id,BOOL checked)
{ check_control *c=find_control(from_customize(p),id); if(!c) return E_INVALIDARG; c->checked=!!checked; apply_control(c); return S_OK; }

/* Snapshot/AddRef every sink before invoking user code: a callback may
 * Unadvise itself or another sink. Never call a released interface pointer. */
static UINT snapshot_sinks(file_dialog *d,IFileDialogEvents *out[M98_SINKS])
{ UINT i,n=0; for(i=0;i<M98_SINKS;i++) if(d->sinks[i].events) { out[n]=d->sinks[i].events; IFileDialogEvents_AddRef(out[n]); ++n; } return n; }
enum event_kind { EVENT_TYPE,EVENT_FOLDER,EVENT_SELECTION,EVENT_OK };
static HRESULT fire_event(file_dialog *d,enum event_kind kind)
{
    IFileDialogEvents *sinks[M98_SINKS];
    UINT i,n=snapshot_sinks(d,sinks);
    HRESULT result=S_OK;
    for(i=0;i<n;i++) {
        HRESULT hr;
        if(kind==EVENT_TYPE) hr=IFileDialogEvents_OnTypeChange(sinks[i],base_dialog(d));
        else if(kind==EVENT_FOLDER) hr=IFileDialogEvents_OnFolderChange(sinks[i],base_dialog(d));
        else if(kind==EVENT_SELECTION) hr=IFileDialogEvents_OnSelectionChange(sinks[i],base_dialog(d));
        else hr=IFileDialogEvents_OnFileOk(sinks[i],base_dialog(d));
        if(kind==EVENT_OK && hr!=S_OK) result=hr==S_FALSE?S_FALSE:(FAILED(hr)?hr:S_FALSE);
        IFileDialogEvents_Release(sinks[i]);
    }
    return result;
}
static void fire_control(file_dialog *d,check_control *c)
{
    IFileDialogEvents *sinks[M98_SINKS];
    UINT i,n=snapshot_sinks(d,sinks);
    for(i=0;i<n;i++) {
        IFileDialogControlEvents *events=NULL;
        if(SUCCEEDED(IFileDialogEvents_QueryInterface(sinks[i],&IID_IFileDialogControlEvents,(void **)&events))) {
            IFileDialogControlEvents_OnCheckButtonToggled(events,&d->customize,c->id,c->checked);
            IFileDialogControlEvents_Release(events);
        }
        IFileDialogEvents_Release(sinks[i]);
    }
}
static void build_controls(file_dialog *d)
{
    RECT client,outer;
    UINT i;
    int height;
    if(!d->control_count) return;
    if(!GetClientRect(d->hook_window,&client) || !GetWindowRect(d->hwnd,&outer)) { d->hook_error=last_error(); return; }
    /* Create these controls during WM_INITDIALOG. The common dialog arranges
     * its standard and custom controls before CDN_INITDONE; adding controls
     * after that point leaves them over the standard folder toolbar on 9x.
     * Controls belong to the hook child, so WM_COMMAND reaches this hook. */
    height=22*(int)d->control_count+6;
    SetWindowPos(d->hook_window,NULL,0,0,client.right,height,SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE);
    for(i=0;i<d->control_count;i++) {
        check_control *c=&d->controls[i];
        c->hwnd=CreateWindowExA(0,"BUTTON",c->label,WS_CHILD|WS_TABSTOP|BS_AUTOCHECKBOX,
           8,4+22*(int)i,client.right>20?client.right-16:300,20,d->hook_window,
           (HMENU)(UINT_PTR)(M98_CONTROL_BASE+i),module,NULL);
        if(!c->hwnd) { d->hook_error=last_error(); return; }
        SendMessageA(c->hwnd,WM_SETFONT,SendMessageA(d->hwnd,WM_GETFONT,0,0),TRUE);
        apply_control(c);
    }
}
static UINT_PTR CALLBACK native_hook(HWND hwnd,UINT message,WPARAM wparam,LPARAM lparam)
{
    file_dialog *d=(file_dialog *)(UINT_PTR)GetWindowLongA(hwnd,DWL_USER);
    if(message==WM_INITDIALOG) {
        OPENFILENAMEA *ofn=(OPENFILENAMEA *)lparam;
        d=(file_dialog *)ofn->lCustData;
        SetWindowLongA(hwnd,DWL_USER,(LONG)(UINT_PTR)d);
        d->hook_window=hwnd; d->hwnd=GetParent(hwnd);
        build_controls(d);
        return 0;
    }
    if(!d) return 0;
    if(message==WM_COMMAND && HIWORD(wparam)==BN_CLICKED && LOWORD(wparam)>=M98_CONTROL_BASE && LOWORD(wparam)<M98_CONTROL_BASE+d->control_count) {
        check_control *c=&d->controls[LOWORD(wparam)-M98_CONTROL_BASE];
        c->checked=SendMessageA(c->hwnd,BM_GETCHECK,0,0)==BST_CHECKED;
        fire_control(d,c);
    }
    if(message==WM_NOTIFY) {
        OFNOTIFYA *notice=(OFNOTIFYA *)lparam;
        if(notice->hdr.code==CDN_INITDONE) {
            d->initialized=TRUE;
            if(d->ok_label[0]) SendMessageA(d->hwnd,CDM_SETCONTROLTEXT,IDOK,(LPARAM)d->ok_label);
            if(d->file_label[0]) SendMessageA(d->hwnd,CDM_SETCONTROLTEXT,stc3,(LPARAM)d->file_label);
            if(FAILED(d->hook_error)) PostMessageA(d->hwnd,WM_COMMAND,IDCANCEL,0);
            fire_event(d,EVENT_TYPE); fire_event(d,EVENT_FOLDER); fire_event(d,EVENT_SELECTION);
        } else if(notice->hdr.code==CDN_TYPECHANGE) {
            d->filter_index=notice->lpOFN->nFilterIndex; fire_event(d,EVENT_TYPE);
        } else if(notice->hdr.code==CDN_FOLDERCHANGE) {
            char folder[M98_PATH];
            LRESULT count=SendMessageA(d->hwnd,CDM_GETFOLDERPATH,M98_PATH,(LPARAM)folder);
            if(count>0 && count<=M98_PATH) lstrcpyA(d->folder,folder);
            fire_event(d,EVENT_FOLDER);
        }
        else if(notice->hdr.code==CDN_SELCHANGE) fire_event(d,EVENT_SELECTION);
        else if(notice->hdr.code==CDN_FILEOK) {
            HRESULT hr=fire_event(d,EVENT_OK);
            if(hr!=S_OK) { SetWindowLongA(hwnd,DWL_MSGRESULT,1); return 1; }
        }
    }
    return 0;
}
static HRESULT WINAPI dialog_show(IFileSaveDialog *p,HWND owner)
{
    file_dialog *d=(file_dialog *)p;
    OPENFILENAMEA ofn;
    DLGTEMPLATE *tpl=NULL;
    HGLOBAL handle=NULL;
    char filename[M98_PATH],cwd[M98_PATH];
    DWORD error=0;
    BOOL selected;
    UINT i;
    HRESULT hr;
    if(d->showing) return E_UNEXPECTED;
    if(owner && !IsWindow(owner)) return E_INVALIDARG;
    {
        DWORD count=GetCurrentDirectoryA(M98_PATH,cwd);
        if(!count) return last_error();
        if(count>=M98_PATH) return HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE);
    }
    memset(&ofn,0,sizeof(ofn)); lstrcpyA(filename,d->filename);
    ofn.lStructSize=OPENFILENAME_SIZE_VERSION_400A;
    ofn.hwndOwner=owner; ofn.lpstrFile=filename; ofn.nMaxFile=M98_PATH;
    ofn.lpstrFilter=d->filters?d->filters:"All files\0*.*\0\0";
    ofn.nFilterIndex=d->filter_index;
    ofn.lpstrInitialDir=d->folder[0]?d->folder:(d->default_folder[0]?d->default_folder:NULL);
    ofn.lpstrTitle=d->title[0]?d->title:NULL;
    ofn.lpstrDefExt=d->extension[0]?d->extension:NULL;
    ofn.Flags=OFN_EXPLORER|OFN_ENABLEHOOK|OFN_HIDEREADONLY|OFN_NOCHANGEDIR;
    if(d->options&FOS_OVERWRITEPROMPT) ofn.Flags|=OFN_OVERWRITEPROMPT;
    if(d->options&FOS_PATHMUSTEXIST) ofn.Flags|=OFN_PATHMUSTEXIST;
    if(d->options&FOS_NOREADONLYRETURN) ofn.Flags|=OFN_NOREADONLYRETURN;
    if(d->options&FOS_NOTESTFILECREATE) ofn.Flags|=OFN_NOTESTFILECREATE;
    if(d->options&FOS_NODEREFERENCELINKS) ofn.Flags|=OFN_NODEREFERENCELINKS;
    /* OFN_FILEMUSTEXIST is documented Open-only and cannot be passed to a
     * Save As backend. NPP requests FOS_FILEMUSTEXIST even for new saves.
     * This candidate keeps the option for GetOptions, with native Save As
     * semantics; it never creates or saves the chosen file itself. */
    ofn.lpfnHook=native_hook; ofn.lCustData=(LPARAM)d;
    if(d->control_count) {
        handle=GlobalAlloc(GMEM_FIXED|GMEM_ZEROINIT,sizeof(DLGTEMPLATE)+3*sizeof(WORD));
        if(!handle) return E_OUTOFMEMORY;
        tpl=(DLGTEMPLATE *)handle;
        tpl->style=WS_CHILD|WS_VISIBLE|WS_CLIPSIBLINGS|DS_3DLOOK|DS_CONTROL;
        tpl->cx=240; tpl->cy=(short)(14*d->control_count+4);
        ofn.hInstance=(HINSTANCE)handle; ofn.Flags|=OFN_ENABLETEMPLATEHANDLE;
    }
    d->showing=TRUE; d->closed=FALSE; d->initialized=FALSE;
    d->hook_error=S_OK; d->result_valid=FALSE; d->result[0]=0; d->active=&ofn;
    dialog_addref(p);
    selected=GetSaveFileNameA(&ofn);
    if(!selected) error=CommDlgExtendedError();
    d->filter_index=ofn.nFilterIndex;
    for(i=0;i<d->control_count;i++) { d->controls[i].hwnd=NULL; }
    d->hwnd=NULL; d->hook_window=NULL; d->active=NULL; d->showing=FALSE;
    if(handle) GlobalFree(handle);
    hr=selected?S_OK:(error?MAKE_HRESULT(SEVERITY_ERROR,FACILITY_ITF,error):M98_CANCEL);
    if(d->closed) hr=d->close_result;
    if(FAILED(d->hook_error)) hr=d->hook_error;
    if(SUCCEEDED(hr) && !selected) hr=E_FAIL; /* Close(S_OK) is not a selection. */
    if(SUCCEEDED(hr)) {
        hr=full_path(filename,d->result);
        if(SUCCEEDED(hr)) { lstrcpyA(d->filename,filename+ofn.nFileOffset); d->result_valid=TRUE; }
    }
    if(!SetCurrentDirectoryA(cwd)) { hr=last_error(); d->result_valid=FALSE; }
    dialog_release(p);
    return hr;
}

/* Typed vtable entries: unsupported features never return fabricated S_OK. */
#define D_STUB(name,args,unused) static HRESULT WINAPI name args { unused; return E_NOTIMPL; }
D_STUB(dialog_place,(IFileSaveDialog *p,IShellItem *item,FDAP where),(void)p;(void)item;(void)where)
D_STUB(dialog_guid,(IFileSaveDialog *p,REFGUID guid),(void)p;(void)guid)
D_STUB(dialog_clear,(IFileSaveDialog *p),(void)p)
D_STUB(dialog_filter,(IFileSaveDialog *p,IShellItemFilter *filter),(void)p;(void)filter)
D_STUB(dialog_save_item,(IFileSaveDialog *p,IShellItem *item),(void)p;(void)item)
D_STUB(dialog_properties,(IFileSaveDialog *p,IPropertyStore *store),(void)p;(void)store)
D_STUB(dialog_collected,(IFileSaveDialog *p,IPropertyDescriptionList *list,BOOL append),(void)p;(void)list;(void)append)
static HRESULT WINAPI dialog_get_properties(IFileSaveDialog *p,IPropertyStore **out) { (void)p; if(!out) return E_POINTER; *out=NULL; return E_NOTIMPL; }
D_STUB(dialog_apply,(IFileSaveDialog *p,IShellItem *item,IPropertyStore *store,HWND hwnd,IFileOperationProgressSink *sink),(void)p;(void)item;(void)store;(void)hwnd;(void)sink)
D_STUB(custom_id,(IFileDialogCustomize *p,DWORD id),(void)p;(void)id)
D_STUB(custom_id_label,(IFileDialogCustomize *p,DWORD id,LPCWSTR label),(void)p;(void)id;(void)label)
D_STUB(custom_edit_get,(IFileDialogCustomize *p,DWORD id,LPWSTR *out),(void)p;(void)id; if(out) *out=NULL)
D_STUB(custom_item_add,(IFileDialogCustomize *p,DWORD id,DWORD item,LPCWSTR label),(void)p;(void)id;(void)item;(void)label)
D_STUB(custom_item_id,(IFileDialogCustomize *p,DWORD id,DWORD item),(void)p;(void)id;(void)item)
D_STUB(custom_item_get_state,(IFileDialogCustomize *p,DWORD id,DWORD item,CDCONTROLSTATEF *out),(void)p;(void)id;(void)item; if(out) *out=0)
D_STUB(custom_item_set_state,(IFileDialogCustomize *p,DWORD id,DWORD item,CDCONTROLSTATEF state),(void)p;(void)id;(void)item;(void)state)
D_STUB(custom_selected,(IFileDialogCustomize *p,DWORD id,DWORD *out),(void)p;(void)id; if(out) *out=0)
D_STUB(custom_end,(IFileDialogCustomize *p),(void)p)
#undef D_STUB
static const IFileSaveDialogVtbl dialog_vtable={
    dialog_query,dialog_addref,dialog_release,dialog_show,dialog_filters,dialog_type,dialog_get_type,
    dialog_advise,dialog_unadvise,dialog_options,dialog_get_options,dialog_default_folder,dialog_folder,
    dialog_get_folder,dialog_selection,dialog_name,dialog_get_name,dialog_title,dialog_ok_label,
    dialog_file_label,dialog_result,dialog_place,dialog_extension,dialog_close,dialog_guid,dialog_clear,
    dialog_filter,dialog_save_item,dialog_properties,dialog_collected,dialog_get_properties,dialog_apply
};
static const IFileDialogCustomizeVtbl customize_vtable={
    custom_query,custom_addref,custom_release,custom_id,custom_id_label,custom_id_label,custom_id,
    custom_id,custom_add_check,custom_id_label,custom_id,custom_id_label,custom_label,
    custom_get_state,custom_set_state,custom_edit_get,custom_id_label,custom_get_check,custom_set_check,
    custom_item_add,custom_item_id,custom_id,custom_item_get_state,custom_item_set_state,custom_selected,
    custom_item_id,custom_id_label,custom_end,custom_id,custom_item_add
};

static ULONG WINAPI factory_addref(IClassFactory *p) { return (ULONG)InterlockedIncrement(&((class_factory *)p)->refs); }
static ULONG WINAPI factory_release(IClassFactory *p)
{ ULONG refs=(ULONG)InterlockedDecrement(&((class_factory *)p)->refs); if(!refs) { deallocate(p); InterlockedDecrement(&live_objects); } return refs; }
static HRESULT WINAPI factory_query(IClassFactory *p,REFIID iid,void **out)
{ if(!out) return E_POINTER; *out=NULL; if(!iid) return E_INVALIDARG; if(!equal_guid(iid,&IID_IUnknown) && !equal_guid(iid,&IID_IClassFactory)) return E_NOINTERFACE; *out=p; factory_addref(p); return S_OK; }
static HRESULT WINAPI factory_create(IClassFactory *p,IUnknown *outer,REFIID iid,void **out)
{
    file_dialog *d;
    HRESULT hr;
    (void)p;
    if(!out) return E_POINTER;
    *out=NULL;
    if(outer) return CLASS_E_NOAGGREGATION;
    d=allocate(sizeof(*d));
    if(!d) return E_OUTOFMEMORY;
    d->iface.lpVtbl=&dialog_vtable; d->customize.lpVtbl=&customize_vtable; d->window.lpVtbl=&window_vtable;
    d->refs=1; d->filter_index=1;
    d->options=FOS_OVERWRITEPROMPT|FOS_PATHMUSTEXIST|FOS_NOREADONLYRETURN|FOS_FORCEFILESYSTEM;
    InterlockedIncrement(&live_objects);
    hr=dialog_query(&d->iface,iid,out); dialog_release(&d->iface); return hr;
}
static HRESULT WINAPI factory_lock(IClassFactory *p,BOOL lock)
{ (void)p; if(lock) InterlockedIncrement(&server_locks); else { if(!server_locks) return E_UNEXPECTED; InterlockedDecrement(&server_locks); } return S_OK; }
static const IClassFactoryVtbl factory_vtable={factory_query,factory_addref,factory_release,factory_create,factory_lock};
HRESULT WINAPI DllGetClassObject(REFCLSID clsid,REFIID iid,void **out)
{
    class_factory *f;
    HRESULT hr;
    if(!out) return E_POINTER;
    *out=NULL;
    if(!equal_guid(clsid,&CLSID_FileSaveDialog)) return CLASS_E_CLASSNOTAVAILABLE;
    f=allocate(sizeof(*f));
    if(!f) return E_OUTOFMEMORY;
    f->iface.lpVtbl=&factory_vtable; f->refs=1; InterlockedIncrement(&live_objects);
    hr=factory_query(&f->iface,iid,out); factory_release(&f->iface); return hr;
}
HRESULT WINAPI DllCanUnloadNow(void) { return live_objects || server_locks?S_FALSE:S_OK; }
static HRESULT module_path(char path[M98_PATH])
{ DWORD count=GetModuleFileNameA(module,path,M98_PATH); return !count?last_error():(count>=M98_PATH?HRESULT_FROM_WIN32(ERROR_FILENAME_EXCED_RANGE):S_OK); }
HRESULT WINAPI DllRegisterServer(void)
{
    char path[M98_PATH],existing[M98_PATH];
    HKEY key;
    DWORD size=sizeof(existing),type=0;
    LONG rc;
    HRESULT hr=module_path(path);
    if(FAILED(hr)) return hr;
    rc=RegOpenKeyExA(HKEY_CLASSES_ROOT,M98_SERVER_KEY,0,KEY_QUERY_VALUE,&key);
    if(rc==ERROR_SUCCESS) {
        rc=RegQueryValueExA(key,NULL,NULL,&type,(BYTE *)existing,&size); RegCloseKey(key);
        if(rc==ERROR_SUCCESS && (type!=REG_SZ || !size || size>sizeof(existing) || existing[size-1] || lstrcmpiA(existing,path))) return HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS);
        if(rc!=ERROR_SUCCESS && rc!=ERROR_FILE_NOT_FOUND) return HRESULT_FROM_WIN32(rc);
    } else if(rc!=ERROR_FILE_NOT_FOUND) return HRESULT_FROM_WIN32(rc);
    rc=RegCreateKeyExA(HKEY_CLASSES_ROOT,M98_SERVER_KEY,0,NULL,REG_OPTION_NON_VOLATILE,KEY_SET_VALUE,NULL,&key,NULL);
    if(rc!=ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);
    rc=RegSetValueExA(key,NULL,0,REG_SZ,(const BYTE *)path,(DWORD)lstrlenA(path)+1);
    if(rc==ERROR_SUCCESS) rc=RegSetValueExA(key,"ThreadingModel",0,REG_SZ,(const BYTE *)"Apartment",10);
    RegCloseKey(key); return HRESULT_FROM_WIN32(rc);
}
HRESULT WINAPI DllUnregisterServer(void)
{
    char path[M98_PATH],existing[M98_PATH];
    HKEY key;
    DWORD size=sizeof(existing),type=0;
    LONG rc;
    HRESULT hr=module_path(path);
    if(FAILED(hr)) return hr;
    rc=RegOpenKeyExA(HKEY_CLASSES_ROOT,M98_SERVER_KEY,0,KEY_QUERY_VALUE,&key);
    if(rc==ERROR_FILE_NOT_FOUND) return S_FALSE;
    if(rc!=ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);
    rc=RegQueryValueExA(key,NULL,NULL,&type,(BYTE *)existing,&size); RegCloseKey(key);
    if(rc!=ERROR_SUCCESS) return HRESULT_FROM_WIN32(rc);
    if(type!=REG_SZ || !size || size>sizeof(existing) || existing[size-1] || lstrcmpiA(path,existing)) return HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED);
    rc=RegDeleteKeyA(HKEY_CLASSES_ROOT,M98_SERVER_KEY);
    /* Never recursively delete another provider's class children. */
    return HRESULT_FROM_WIN32(rc);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved)
{ (void)reserved; if(reason==DLL_PROCESS_ATTACH) module=instance; return TRUE; }
