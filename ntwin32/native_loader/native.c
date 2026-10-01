/* SPDX-License-Identifier: GPL-2.0-only
 * Native Windows98 services, never Linux syscalls. Targets are immutable files.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "pe.h"
#include "tls_runtime.h"
#define MODULES 16
typedef struct module {char name[128],path[MAX_PATH];np_image pe;np_tls_info tls;uint8_t *file,*mapped;HMODULE native;uint32_t dependencies,dynamic_refs;int state,attached,attaching,tls_attached,disable_thread_calls;} module;
typedef FARPROC (WINAPI *ntw_resolve_fn)(HMODULE,LPCSTR);
typedef void *(WINAPI *provider_open_fn)(LPCSTR);
typedef FARPROC (WINAPI *provider_find_fn)(void *,LPCSTR,LPCSTR);
typedef void (WINAPI *provider_close_fn)(void *);
typedef struct loader {
 module modules[MODULES];unsigned count,order[MODULES],attached,missing,blocked;
 char directory[MAX_PATH],command_line[2*MAX_PATH+3];WCHAR command_line_w[1024];int execute,root_is_dll;
 ntw_tls_plan tls;ntw_tls_thread main_tls;CRITICAL_SECTION lock;
 HANDLE threads_done;DWORD thread_slot;unsigned workers;int runtime,lock_ready,closing;
 HMODULE ntw,bridge;ntw_resolve_fn ntw_find;provider_find_fn provider_find;
 provider_close_fn provider_close;void *providers;
} loader;
typedef struct thread_job {loader *owner;LPTHREAD_START_ROUTINE start;void *argument;ntw_tls_thread tls;int entered,finished;} thread_job;
static loader *active_loader;
static HANDLE report=INVALID_HANDLE_VALUE;static int report_failed;
static char arguments[12][MAX_PATH];static unsigned argc;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static void copy(void *out,const void *in,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)out)[i]=((const BYTE *)in)[i];}
static int equal(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int equal_ci(const char *a,const char *b){for(;;a++,b++){unsigned x=(BYTE)*a,y=(BYTE)*b;if(x>='a'&&x<='z')x-=32;if(y>='a'&&y<='z')y-=32;if(x!=y)return 0;if(!x)return 1;}}
static void text(const char *s){DWORD written=0,n=length(s);if(report==INVALID_HANDLE_VALUE||!WriteFile(report,s,n,&written,NULL)||written!=n)report_failed=1;}
static void number(uint32_t v){char b[11];unsigned n=0;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);while(n){char c=b[--n];DWORD w;if(!WriteFile(report,&c,1,&w,NULL)||w!=1)report_failed=1;}}
static void line(const char *key,const char *value){text(key);text(value);text("\r\n");}
static void value(const char *key,uint32_t v){text(key);number(v);text("\r\n");}
static int join(char *out,const char *directory,const char *name)
{unsigned a=length(directory),b=length(name);if(a+b+2>MAX_PATH)return 0;copy(out,directory,a);if(a&&out[a-1]!='\\')out[a++]='\\';copy(out+a,name,b+1);return 1;}
static int absolute(const char *p){return p&&((p[0]>='A'&&p[0]<='Z')||(p[0]>='a'&&p[0]<='z'))&&p[1]==':'&&p[2]=='\\';}
static int safe_name(const char *s){unsigned n;if(!s||!*s)return 0;for(n=0;s[n];n++){unsigned c=(BYTE)s[n];if(n>=127||!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;if(c=='.'&&s[n+1]=='.')return 0;}return 1;}
static int read_file(module *m)
{
 HANDLE h;DWORD size,high,got;const char *error=0;uint32_t fnv=2166136261u,i;
 h=CreateFileA(m->path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
 if(h==INVALID_HANDLE_VALUE){line("FILE_UNAVAILABLE=",m->path);value("WIN32_ERROR=",GetLastError());return 0;}
 size=GetFileSize(h,&high);if(high||size==INVALID_FILE_SIZE||size<64||size>NP_FILE_LIMIT){CloseHandle(h);line("FILE_ERROR=","SIZE");return 0;}
 m->file=HeapAlloc(GetProcessHeap(),0,size);if(!m->file){CloseHandle(h);return 0;}
 if(!ReadFile(h,m->file,size,&got,NULL)||got!=size){CloseHandle(h);return 0;}CloseHandle(h);
 for(i=0;i<size;i++){fnv^=m->file[i];fnv*=16777619u;}
 line("FILE=",m->path);value("FILE_BYTES=",size);value("FILE_FNV1A=",fnv);
 if(!np_parse(&m->pe,m->file,size,&error)||!np_imports(&m->pe,1,NULL,NULL,NULL,&error)||
    !np_relocations(&m->pe,NULL,NULL,&error)) {line("PE_INVALID=",error?error:"UNKNOWN");return 0;}
 {uint32_t ignored;const char *forward;
  if(!np_export(&m->pe,"__NTW_VALIDATE_ONLY__",0,&ignored,&forward,&error)){line("PE_INVALID=",error);return 0;}}
 value("SUBSYSTEM_MAJOR_UNCHANGED=",m->pe.subsystem_major);value("SUBSYSTEM_MINOR_UNCHANGED=",m->pe.subsystem_minor);
 if(!np_tls(&m->pe,&m->tls,&error)){line("PE_INVALID=",error);return 0;}
 if(!(active_loader&&active_loader->runtime?np_runtime_profile(&m->pe,&error):np_execution_profile(&m->pe,&error))){line("RUNTIME_BLOCKER=",error);m->state=-1;}
 return 1;
}
static int native_module(const char *name)
{
 static const char *const names[]={"KERNEL32.DLL","USER32.DLL","GDI32.DLL","ADVAPI32.DLL","SHELL32.DLL","COMCTL32.DLL","COMDLG32.DLL","OLE32.DLL","OLEAUT32.DLL","VERSION.DLL","WINMM.DLL","WSOCK32.DLL","WS2_32.DLL","MSVCRT.DLL","IMM32.DLL","RPCRT4.DLL"};unsigned n;
 for(n=0;n<sizeof(names)/sizeof(names[0]);n++)if(equal_ci(name,names[n]))return 1;return 0;
}
static int blocked_api(const char *s)
{
 static const char *const names[]={"GetModuleHandleA","GetModuleHandleW","GetModuleFileNameA","GetModuleFileNameW","GetProcAddress","LoadLibraryA","LoadLibraryW","LoadLibraryExA","LoadLibraryExW","FreeLibrary","FindResourceA","FindResourceW","FindResourceExA","FindResourceExW","LoadResource","LockResource","SizeofResource","CreateThread","CreateRemoteThread","ExitThread","TerminateThread","DisableThreadLibraryCalls","TlsAlloc","TlsFree","TlsGetValue","TlsSetValue","GetCommandLineA","GetCommandLineW","GetStartupInfoA","GetStartupInfoW","GetProcessHeap","HeapCreate","SetUnhandledExceptionFilter","AddVectoredExceptionHandler","_beginthread","_beginthreadex","_endthread","_endthreadex","QueueUserWorkItem","RegisterWaitForSingleObject","CreateTimerQueueTimer","CreateFiber","SwitchToFiber","ConvertThreadToFiber"};unsigned n;
 if(!s)return 0;for(n=0;n<sizeof(names)/sizeof(names[0]);n++)if(equal(s,names[n]))return 1;return 0;
}
static module *load_module(loader *,const char *,const char *);
static FARPROC runtime_hook(const char *);
static FARPROC resolve(loader *l,module *m,const char *name,uint16_t ordinal,unsigned depth)
{
 FARPROC p;uint32_t rva;const char *forward=0,*error=0;LPCSTR symbol=name?name:(LPCSTR)(UINT_PTR)ordinal;
 if(depth>16){line("IMPORT_BLOCKER=","FORWARDER_DEPTH");return NULL;}
 if(!m)return NULL;
 if(l->execute&&!name){line("EXECUTION_BLOCKER=","ORDINAL_IMPORT_UNSUPPORTED");l->blocked++;return NULL;}
 if(m->native){
  if(l->runtime&&name&&equal(name,"ExitProcess")){line("EXECUTION_BLOCKER=","PROCESS_EXIT_OWNERSHIP_UNIMPLEMENTED");l->blocked++;return NULL;}
  if(l->runtime&&equal_ci(m->name,"KERNEL32.DLL")&&name){p=runtime_hook(name);if(p)return p;}
  if(l->execute&&blocked_api(name)){line("EXECUTION_BLOCKER=",name);l->blocked++;return NULL;}
  p=GetProcAddress(m->native,symbol);
  if(!p&&name&&equal_ci(m->name,"KERNEL32.DLL")&&l->ntw_find)p=l->ntw_find(m->native,symbol);
  if(!p&&l->provider_find&&l->providers)p=l->provider_find(l->providers,m->name,symbol);
  return p;
 }
 if(!np_export(&m->pe,name,ordinal,&rva,&forward,&error)){line("EXPORT_INVALID=",error);l->blocked++;return NULL;}
 if(!rva)return NULL;
 if(forward){char dll[128],export_name[512];unsigned n=0,k=0;uint32_t v=0;module *dependency;
  while(forward[n]&&forward[n]!='.'&&n<120){dll[n]=forward[n];n++;}
  if(!n||forward[n]!='.'){line("EXPORT_INVALID=","FORWARDER_SYNTAX");return NULL;}
  copy(dll+n,".DLL",5);n++;
  while(forward[n]&&k<511)export_name[k++]=forward[n++];export_name[k]=0;if(!k||forward[n])return NULL;
  if(!safe_name(dll))return NULL;dependency=load_module(l,dll,NULL);if(!dependency)return NULL;
  m->dependencies|=1u<<(unsigned)(dependency-l->modules);
  if(export_name[0]=='#'){for(n=1;export_name[n];n++){if(export_name[n]<'0'||export_name[n]>'9'||v>6553)return NULL;v=v*10+(export_name[n]-'0');}if(!v||v>65535)return NULL;return resolve(l,dependency,NULL,(uint16_t)v,depth+1);}
  return resolve(l,dependency,export_name,0,depth+1);
 }
 if(!np_memory(&m->pe,rva,1,1)){line("EXECUTION_BLOCKER=","DATA_EXPORT_UNSUPPORTED");l->blocked++;return NULL;}
 return l->execute?(FARPROC)(m->mapped+rva):(FARPROC)(UINT_PTR)1;
}
typedef struct bind_context {loader *l;module *m;} bind_context;
static int bind_import(void *opaque,const char *dll,const char *name,uint16_t ordinal,uint32_t slot,int delay)
{
 bind_context *b=opaque;loader *l=b->l;module *dependency=load_module(l,dll,NULL);FARPROC p=resolve(l,dependency,name,ordinal,0);
 if(dependency)b->m->dependencies|=1u<<(unsigned)(dependency-l->modules);
 if(l->runtime&&b->m->tls.present){np_tls_info *t=&b->m->tls;
  if((slot>=t->index_rva&&slot<t->index_rva+4)||
     (t->template_bytes&&slot<t->template_rva+t->template_bytes&&t->template_rva<slot+4)||
     (t->callbacks_rva&&slot<t->callbacks_rva+(t->count+1)*4&&t->callbacks_rva<slot+4)){
   line("EXECUTION_BLOCKER=","IAT_TLS_OVERLAP");l->blocked++;return 0;
  }
 }
 text(delay?"DELAY_IMPORT=":"IMPORT=");text(dll);text("!");if(name)text(name);else {text("#");number(ordinal);}
 text(p?" RESOLVED\r\n":" MISSING\r\n");
 if(!p)l->missing++;
 if(l->execute&&p&&!delay){uint32_t address=(uint32_t)(UINT_PTR)p;copy(b->m->mapped+slot,&address,4);}
 return 1;
}
typedef struct relocation {module *m;uint32_t delta;} relocation;
static int relocate(void *opaque,uint32_t rva){relocation *r=opaque;uint32_t value=np_u32(r->m->mapped+rva)+r->delta;copy(r->m->mapped+rva,&value,4);return 1;}
static int map_image(module *m)
{
 unsigned n;relocation r;const char *error=0;
 m->mapped=VirtualAlloc((void *)(UINT_PTR)m->pe.base,m->pe.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!m->mapped)m->mapped=VirtualAlloc(NULL,m->pe.size,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 if(!m->mapped||(UINT_PTR)m->mapped>0xffffffffu-m->pe.size)return 0;
 r.m=m;r.delta=(uint32_t)(UINT_PTR)m->mapped-m->pe.base;
 if(r.delta&&((m->pe.characteristics&1)||!m->pe.directory[5][0])){line("EXECUTION_BLOCKER=","RELOCATIONS_REQUIRED");return 0;}
 copy(m->mapped,m->file,m->pe.headers);
 for(n=0;n<m->pe.sections;n++){np_section *s=&m->pe.section[n];if(s->bytes)copy(m->mapped+s->va,m->file+s->raw,s->bytes);}
 if(r.delta&&!np_relocations(&m->pe,relocate,&r,&error)){line("EXECUTION_BLOCKER=",error);return 0;}return 1;
}
static module *load_module(loader *l,const char *name,const char *root_path)
{
 unsigned n;module *m;bind_context binding;const char *error=0;
 if(!safe_name(name)){line("IMPORT_BLOCKER=","DLL_NAME");l->blocked++;return NULL;}
 for(n=0;n<l->count;n++)if(equal_ci(l->modules[n].name,name)){
  m=&l->modules[n];if(m->state==1){line("DEPENDENCY_CYCLE=",name);l->blocked++;return NULL;}return m->state==2?m:NULL;
 }
 if(l->runtime&&l->tls.ready){line("IMPORT_BLOCKER=","DYNAMIC_MODULE_GRAPH_NOT_IMPLEMENTED");SetLastError(ERROR_NOT_SUPPORTED);return NULL;}
 if(l->count>=MODULES){line("IMPORT_BLOCKER=","MODULE_LIMIT");l->blocked++;return NULL;}
 m=&l->modules[l->count++];copy(m->name,name,length(name)+1);m->state=1;
 if(!root_path&&native_module(name)){
  char system[MAX_PATH],path[MAX_PATH];DWORD size=GetSystemDirectoryA(system,sizeof(system));
  if(!size||size>=sizeof(system)||!join(path,system,name)){m->state=-2;return NULL;}
  copy(m->path,path,length(path)+1);
  m->native=LoadLibraryA(path);if(!m->native){line("NATIVE_DLL_UNAVAILABLE=",name);value("WIN32_ERROR=",GetLastError());m->state=-2;return NULL;}m->state=2;return m;
 }
 if(root_path){copy(m->path,root_path,length(root_path)+1);}else if(!join(m->path,l->directory,name)){m->state=-2;return NULL;}
 if(!read_file(m)){m->state=-2;return NULL;}
 if(m->state==-1){l->blocked++;if(l->execute)return NULL;}m->state=1;
 if(root_path==NULL&&!(m->pe.characteristics&0x2000)){line("IMPORT_BLOCKER=","DEPENDENCY_NOT_DLL");m->state=-2;l->blocked++;return NULL;}
 if(l->execute&&!map_image(m)){m->state=-2;l->blocked++;return NULL;}
 binding.l=l;binding.m=m;
 if(!np_imports(&m->pe,1,bind_import,&binding,NULL,&error)){line("PE_INVALID=",error);m->state=-2;l->blocked++;return NULL;}
 m->state=2;return m;
}
static int protect_image(module *m)
{
 DWORD old;unsigned n;if(!VirtualProtect(m->mapped,m->pe.size,PAGE_NOACCESS,&old)||!VirtualProtect(m->mapped,m->pe.headers,PAGE_READONLY,&old))return 0;
 for(n=0;n<m->pe.sections;n++){np_section *s=&m->pe.section[n];DWORD protection;int exec=!!(s->flags&0x20000000u),write=!!(s->flags&0x80000000u),read=!!(s->flags&0x40000000u);
  if(exec&&write){line("EXECUTION_BLOCKER=","WRITABLE_EXECUTABLE_SECTION");return 0;}
  protection=exec?(read?PAGE_EXECUTE_READ:PAGE_EXECUTE):(write?PAGE_READWRITE:(read?PAGE_READONLY:PAGE_NOACCESS));
  if(!VirtualProtect(m->mapped+s->va,s->span,protection,&old))return 0;
 }return FlushInstructionCache(GetCurrentProcess(),m->mapped,m->pe.size)!=0;
}
typedef BOOL (WINAPI *dll_entry_fn)(HINSTANCE,DWORD,void *);
typedef void (WINAPI *tls_entry_fn)(void *,DWORD,void *);
static void tls_callbacks(module *m,DWORD reason)
{
 unsigned n;for(n=0;n<m->tls.count;n++)((tls_entry_fn)(void *)(m->mapped+m->tls.callback[n]))(m->mapped,reason,NULL);
}
static int prepare_runtime(loader *l)
{
 ntw_tls_ops ops;ntw_tls_spec specs[MODULES];unsigned n,count=0,k;const char *error=NULL;
 if(!l->runtime)return 1;
 InitializeCriticalSection(&l->lock);l->lock_ready=1;l->thread_slot=TlsAlloc();
 l->threads_done=CreateEventA(NULL,TRUE,TRUE,NULL);
 if(l->thread_slot==TLS_OUT_OF_INDEXES||!l->threads_done)return 0;
 for(n=0;n<l->count;n++){module *m=&l->modules[n];np_tls_info *t=&m->tls;uint32_t base=(uint32_t)(UINT_PTR)m->mapped;const uint8_t *d;
  if(m->native||!t->present)continue;
  d=m->mapped+m->pe.directory[9][0];
  if(np_u32(d)!=(t->template_rva?base+t->template_rva:0)||
     np_u32(d+4)!=(t->template_rva?base+t->template_rva+t->template_bytes:0)||
     np_u32(d+8)!=base+t->index_rva||np_u32(d+12)!=(t->callbacks_rva?base+t->callbacks_rva:0)||
     np_u32(d+16)!=t->zero_bytes||np_u32(d+20)!=np_u32(np_raw(&m->pe,m->pe.directory[9][0]+20,4))){
   line("EXECUTION_BLOCKER=","TLS_RELOCATION_OR_BINDING");return 0;
  }
  for(k=0;k<t->count;k++)if(np_u32(m->mapped+t->callbacks_rva+k*4)!=base+t->callback[k]){
   line("EXECUTION_BLOCKER=","TLS_CALLBACK_RELOCATION");return 0;
  }
  if(t->callbacks_rva&&np_u32(m->mapped+t->callbacks_rva+t->count*4))return 0;
  specs[count].initial=t->template_bytes?m->mapped+t->template_rva:NULL;
  specs[count].initialized_bytes=t->template_bytes;specs[count].zero_bytes=t->zero_bytes;
  specs[count].alignment=t->alignment;specs[count++].index_address=(uint32_t *)(void *)(m->mapped+t->index_rva);
 }
 if(!ntw_tls_native_ops(&ops)){line("EXECUTION_BLOCKER=","NATIVE_WIN98_TLS_ABI");return 0;}
 if(!ntw_tls_prepare(&l->tls,specs,count,&ops,&error)||!ntw_tls_attach(&l->tls,&l->main_tls,&error)){
  line("EXECUTION_BLOCKER=",error?error:"TLS_ATTACH");return 0;
 }return 1;
}
static int attach_module(loader *l,module *m)
{
 typedef BOOL (WINAPI *entry_fn)(HINSTANCE,DWORD,void *);unsigned n;
 if(m->native||m->attached)return 1;
 if(m->state!=2||m->attaching)return 0;m->attaching=1;
 for(n=0;n<l->count;n++)if(m->dependencies&(1u<<n))if(!attach_module(l,&l->modules[n]))return 0;
 if(l->runtime){tls_callbacks(m,DLL_PROCESS_ATTACH);m->tls_attached=1;}
 if((m->pe.characteristics&0x2000)&&m->pe.entry){if(!((entry_fn)(void *)(m->mapped+m->pe.entry))((HINSTANCE)m->mapped,DLL_PROCESS_ATTACH,NULL)){
   if(m->tls_attached){tls_callbacks(m,DLL_PROCESS_DETACH);m->tls_attached=0;}
   ((entry_fn)(void *)(m->mapped+m->pe.entry))((HINSTANCE)m->mapped,DLL_PROCESS_DETACH,NULL);return 0;
  }}m->attached=1;l->order[l->attached++]=(unsigned)(m-l->modules);
 m->attaching=0;return 1;
}
static void cleanup(loader *l)
{
 typedef BOOL (WINAPI *entry_fn)(HINSTANCE,DWORD,void *);unsigned n;
 if(l->runtime&&l->lock_ready){const char *error=NULL;
  EnterCriticalSection(&l->lock);l->closing=1;LeaveCriticalSection(&l->lock);
  if(l->workers&&(!l->threads_done||WaitForSingleObject(l->threads_done,10000)!=WAIT_OBJECT_0)){
   line("EXECUTION_BLOCKER=","TARGET_THREADS_STILL_ACTIVE");FlushFileBuffers(report);ExitProcess(24);
  }
  EnterCriticalSection(&l->lock);
  if(l->workers){line("EXECUTION_BLOCKER=","TARGET_THREADS_STILL_ACTIVE");ExitProcess(24);}
  while(l->attached){module *m=&l->modules[l->order[--l->attached]];
   if(m->tls_attached){tls_callbacks(m,DLL_PROCESS_DETACH);m->tls_attached=0;}
   if((m->pe.characteristics&0x2000)&&m->pe.entry)((entry_fn)(void *)(m->mapped+m->pe.entry))((HINSTANCE)m->mapped,DLL_PROCESS_DETACH,NULL);
  }
  if((l->main_tls.active&&!ntw_tls_detach(&l->main_tls,&error))||
     ((l->tls.ready||l->tls.count)&&!ntw_tls_dispose(&l->tls,&error))){line("EXECUTION_BLOCKER=",error?error:"TLS_CLEANUP");ExitProcess(25);}
  LeaveCriticalSection(&l->lock);DeleteCriticalSection(&l->lock);l->lock_ready=0;
  if(l->thread_slot!=TLS_OUT_OF_INDEXES)TlsFree(l->thread_slot);if(l->threads_done)CloseHandle(l->threads_done);
 }else while(l->attached){module *m=&l->modules[l->order[--l->attached]];if((m->pe.characteristics&0x2000)&&m->pe.entry)((entry_fn)(void *)(m->mapped+m->pe.entry))((HINSTANCE)m->mapped,DLL_PROCESS_DETACH,NULL);}
 for(n=l->count;n;n--){module *m=&l->modules[n-1];if(m->mapped)VirtualFree(m->mapped,0,MEM_RELEASE);if(m->native)FreeLibrary(m->native);if(m->file)HeapFree(GetProcessHeap(),0,m->file);}
 if(l->providers&&l->provider_close)l->provider_close(l->providers);
 if(l->bridge)FreeLibrary(l->bridge);if(l->ntw)FreeLibrary(l->ntw);
}
static module *by_handle(loader *l,HMODULE handle)
{
 unsigned n;if(!handle)return l->count?&l->modules[0]:NULL;
 for(n=0;n<l->count;n++){module *m=&l->modules[n];if(m->state==2&&(m->native==handle||m->mapped==(BYTE *)handle))return m;}
 return NULL;
}
static module *by_name(loader *l,LPCSTR name)
{
 unsigned n;int path=0;const char *base=name;char extended[128];if(!name)return by_handle(l,NULL);
 for(n=0;name[n];n++){if(n>=MAX_PATH)return NULL;if(name[n]=='\\'||name[n]=='/'||name[n]==':'){base=name+n+1;path=1;}}
 if(!*base)return NULL;
 for(n=0;n<l->count;n++){module *m=&l->modules[n];if(m->state==2&&(equal_ci(name,m->path)||(!path&&equal_ci(base,m->name))))return m;}
 if(path)return NULL;
 n=length(base);if(n+5>sizeof(extended))return NULL;copy(extended,base,n);copy(extended+n,".DLL",5);
 for(n=0;n<l->count;n++)if(l->modules[n].state==2&&equal_ci(extended,l->modules[n].name))return &l->modules[n];
 return NULL;
}
static int narrow(LPCWSTR in,char *out)
{unsigned n;if(!in)return 0;for(n=0;n<MAX_PATH;n++){if(in[n]>127)return 0;out[n]=(char)in[n];if(!in[n])return 1;}return 0;}
static HMODULE WINAPI mapped_handle_a(LPCSTR name)
{
 loader *l=active_loader;module *m;HMODULE result=NULL;if(!l||!l->lock_ready){SetLastError(ERROR_MOD_NOT_FOUND);return NULL;}
 if(!name&&l->root_is_dll)return GetModuleHandleA(NULL);
 EnterCriticalSection(&l->lock);m=by_name(l,name);if(m)result=m->native?m->native:(HMODULE)m->mapped;LeaveCriticalSection(&l->lock);
 if(!result)SetLastError(ERROR_MOD_NOT_FOUND);return result;
}
static HMODULE WINAPI mapped_handle_w(LPCWSTR name)
{char buffer[MAX_PATH];if(!name)return mapped_handle_a(NULL);if(!narrow(name,buffer)){SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return NULL;}return mapped_handle_a(buffer);}
static DWORD WINAPI mapped_filename_a(HMODULE handle,LPSTR out,DWORD size)
{
 loader *l=active_loader;module *m;DWORD n,result=0;if(!l||!out||!size){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
 if(l->root_is_dll&&(!handle||handle==GetModuleHandleA(NULL)))return GetModuleFileNameA(handle,out,size);
 EnterCriticalSection(&l->lock);m=by_handle(l,handle);
 if(m){if(m->native)result=GetModuleFileNameA(m->native,out,size);else{
   n=length(m->path);result=n<size?n:size;copy(out,m->path,result);if(n<size)out[n]=0;
  }}LeaveCriticalSection(&l->lock);if(!m)SetLastError(ERROR_MOD_NOT_FOUND);return result;
}
static DWORD WINAPI mapped_filename_w(HMODULE handle,LPWSTR out,DWORD size)
{
 char buffer[MAX_PATH];DWORD n,k;if(!out||!size){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
 n=mapped_filename_a(handle,buffer,sizeof(buffer));if(!n)return 0;if(n>=sizeof(buffer)){SetLastError(ERROR_INSUFFICIENT_BUFFER);return 0;}
 for(k=0;k<n&&k<size;k++)out[k]=(BYTE)buffer[k];if(n<size)out[n]=0;return n<size?n:size;
}
static FARPROC WINAPI mapped_proc(HMODULE handle,LPCSTR name)
{
 loader *l=active_loader;module *m;FARPROC p=NULL;if(!l||!handle||!name){SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
 EnterCriticalSection(&l->lock);m=by_handle(l,handle);
 if(m&&m->state==2&&(m->native||(m->attached&&!m->attaching)))p=resolve(l,m,(UINT_PTR)name>65535?name:NULL,(UINT_PTR)name<=65535?(uint16_t)(UINT_PTR)name:0,0);
 LeaveCriticalSection(&l->lock);if(!p)SetLastError(ERROR_PROC_NOT_FOUND);return p;
}
static HMODULE WINAPI mapped_load_a(LPCSTR name)
{
 loader *l=active_loader;module *m;HMODULE result=NULL;if(!l||!name){SetLastError(ERROR_INVALID_PARAMETER);return NULL;}
 EnterCriticalSection(&l->lock);m=by_name(l,name);
 if(m&&m->state==2&&(m->native||(m->attached&&!m->attaching))&&m->dynamic_refs!=UINT32_MAX&&!l->closing){m->dynamic_refs++;result=m->native?m->native:(HMODULE)m->mapped;}
 LeaveCriticalSection(&l->lock);if(!result)SetLastError(ERROR_NOT_SUPPORTED);return result;
}
static HMODULE WINAPI mapped_load_w(LPCWSTR name)
{char buffer[MAX_PATH];if(!narrow(name,buffer)){SetLastError(ERROR_CALL_NOT_IMPLEMENTED);return NULL;}return mapped_load_a(buffer);}
static HMODULE WINAPI mapped_load_ex_a(LPCSTR name,HANDLE file,DWORD flags)
{if(file||flags){SetLastError(ERROR_NOT_SUPPORTED);return NULL;}return mapped_load_a(name);}
static HMODULE WINAPI mapped_load_ex_w(LPCWSTR name,HANDLE file,DWORD flags)
{if(file||flags){SetLastError(ERROR_NOT_SUPPORTED);return NULL;}return mapped_load_w(name);}
static BOOL WINAPI mapped_free(HMODULE handle)
{
 loader *l=active_loader;module *m;BOOL result=FALSE;if(!l||!handle){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
 EnterCriticalSection(&l->lock);m=by_handle(l,handle);if(m&&m->dynamic_refs){m->dynamic_refs--;result=TRUE;}LeaveCriticalSection(&l->lock);
 if(!result)SetLastError(ERROR_INVALID_HANDLE);return result;
}
static BOOL WINAPI mapped_disable_threads(HMODULE handle)
{
 loader *l=active_loader;module *m;BOOL result=FALSE;if(!l||!handle)return FALSE;
 EnterCriticalSection(&l->lock);m=by_handle(l,handle);if(m){if(m->native)result=DisableThreadLibraryCalls(m->native);else if((m->pe.characteristics&0x2000)&&!m->tls.present){m->disable_thread_calls=1;result=TRUE;}}
 LeaveCriticalSection(&l->lock);if(!result)SetLastError(ERROR_NOT_SUPPORTED);return result;
}
static void notify_threads(loader *l,DWORD reason)
{
 unsigned n;for(n=0;n<l->attached;n++){module *m=&l->modules[l->order[reason==DLL_THREAD_ATTACH?n:l->attached-1-n]];
  if(!(m->pe.characteristics&0x2000))continue;
  tls_callbacks(m,reason);if(m->pe.entry&&!m->disable_thread_calls)
   ((dll_entry_fn)(void *)(m->mapped+m->pe.entry))((HINSTANCE)m->mapped,reason,NULL);
 }
 for(n=0;n<l->attached;n++){module *m=&l->modules[l->order[n]];if(!(m->pe.characteristics&0x2000))tls_callbacks(m,reason);}
}
static void finish_job(thread_job *job)
{
 loader *l=job->owner;const char *error=NULL;EnterCriticalSection(&l->lock);
 if(job->finished){LeaveCriticalSection(&l->lock);ExitProcess(26);}job->finished=1;
 if(job->entered)notify_threads(l,DLL_THREAD_DETACH);
 if(job->tls.active&&!ntw_tls_detach(&job->tls,&error)){line("EXECUTION_BLOCKER=",error?error:"THREAD_TLS_DETACH");ExitProcess(26);}
 if(!TlsSetValue(l->thread_slot,NULL)){line("EXECUTION_BLOCKER=","THREAD_CONTEXT_CLEAR");ExitProcess(26);}
 if(!l->workers)ExitProcess(26);l->workers--;if(!l->workers)SetEvent(l->threads_done);
 LeaveCriticalSection(&l->lock);HeapFree(GetProcessHeap(),0,job);
}
static DWORD WINAPI thread_entry(void *argument)
{
 thread_job *job=argument;loader *l=job->owner;const char *error=NULL;DWORD result;
 EnterCriticalSection(&l->lock);
 if(l->closing||!TlsSetValue(l->thread_slot,job)||!ntw_tls_attach(&l->tls,&job->tls,&error)){
  line("EXECUTION_BLOCKER=",error?error:"THREAD_CONTEXT_PUBLISH");LeaveCriticalSection(&l->lock);finish_job(job);return 27;
 }
 notify_threads(l,DLL_THREAD_ATTACH);job->entered=1;LeaveCriticalSection(&l->lock);
 result=job->start(job->argument);finish_job(job);return result;
}
static HANDLE WINAPI mapped_thread(LPSECURITY_ATTRIBUTES security,SIZE_T stack,LPTHREAD_START_ROUTINE start,LPVOID argument,DWORD flags,LPDWORD id)
{
 loader *l=active_loader;thread_job *job;HANDLE thread=NULL;unsigned n;int valid=0;DWORD local_id,error=ERROR_NOT_ENOUGH_MEMORY;
 if(!l||security||stack>16u*1024u*1024u||flags&~CREATE_SUSPENDED){SetLastError(ERROR_NOT_SUPPORTED);return NULL;}
 EnterCriticalSection(&l->lock);
 for(n=0;n<l->count;n++){module *m=&l->modules[n];UINT_PTR pointer=(UINT_PTR)start,base=(UINT_PTR)m->mapped;
  if(m->mapped&&pointer>=base&&pointer-base<m->pe.size&&np_memory(&m->pe,(uint32_t)(pointer-base),1,1)){valid=1;break;}
 }
 if(!valid||l->closing||l->workers>=64){LeaveCriticalSection(&l->lock);SetLastError(ERROR_NOT_SUPPORTED);return NULL;}
 job=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*job));
 if(job){job->owner=l;job->start=start;job->argument=argument;l->workers++;ResetEvent(l->threads_done);
  /* Modern callers may omit the ID; native Win98 receives writable storage.
   * Preserve the actual creation error across event/allocation cleanup. */
  thread=CreateThread(NULL,stack,thread_entry,job,flags,id?id:&local_id);
  if(!thread){error=GetLastError();l->workers--;if(!l->workers)SetEvent(l->threads_done);HeapFree(GetProcessHeap(),0,job);}
 }LeaveCriticalSection(&l->lock);if(!thread)SetLastError(error);return thread;
}
static void WINAPI mapped_exit_thread(DWORD result)
{
 loader *l=active_loader;thread_job *job=l?TlsGetValue(l->thread_slot):NULL;
 if(!job){line("EXECUTION_BLOCKER=","INITIAL_THREAD_EXPLICIT_EXIT");ExitProcess(28);}finish_job(job);ExitThread(result);
}
static LPSTR WINAPI mapped_command_a(void){return active_loader->root_is_dll?GetCommandLineA():active_loader->command_line;}
static LPWSTR WINAPI mapped_command_w(void)
{
 loader *l=active_loader;if(l->root_is_dll&&!MultiByteToWideChar(CP_ACP,0,GetCommandLineA(),-1,l->command_line_w,1024))return NULL;
 return l->command_line_w;
}
static FARPROC runtime_hook(const char *name)
{
#define HOOK(symbol,function) if(equal(name,symbol))return (FARPROC)(void *)function
 HOOK("GetModuleHandleA",mapped_handle_a);HOOK("GetModuleHandleW",mapped_handle_w);
 HOOK("GetModuleFileNameA",mapped_filename_a);HOOK("GetModuleFileNameW",mapped_filename_w);
 HOOK("GetProcAddress",mapped_proc);HOOK("LoadLibraryA",mapped_load_a);HOOK("LoadLibraryW",mapped_load_w);
 HOOK("LoadLibraryExA",mapped_load_ex_a);HOOK("LoadLibraryExW",mapped_load_ex_w);HOOK("FreeLibrary",mapped_free);
 HOOK("CreateThread",mapped_thread);HOOK("ExitThread",mapped_exit_thread);HOOK("DisableThreadLibraryCalls",mapped_disable_threads);
 HOOK("GetCommandLineA",mapped_command_a);HOOK("GetCommandLineW",mapped_command_w);
 HOOK("GetStartupInfoA",GetStartupInfoA);HOOK("GetStartupInfoW",GetStartupInfoW);
 HOOK("GetProcessHeap",GetProcessHeap);HOOK("HeapCreate",HeapCreate);
 HOOK("TlsAlloc",TlsAlloc);HOOK("TlsFree",TlsFree);HOOK("TlsGetValue",TlsGetValue);HOOK("TlsSetValue",TlsSetValue);
#undef HOOK
 return NULL;
}
static int parse_arguments(void)
{
 const char *s=GetCommandLineA();while(*s){unsigned n=0;int quote=0;while(*s==' '||*s=='\t')s++;if(!*s)break;if(argc>=12)return 0;
  while(*s&&(quote||(*s!=' '&&*s!='\t'))){if(*s=='"'){quote=!quote;s++;continue;}if(n>=MAX_PATH-1)return 0;arguments[argc][n++]=*s++;}
  if(quote)return 0;arguments[argc++][n]=0;
 }return argc>0;
}
static const char *option(const char *name){unsigned n;for(n=1;n+1<argc;n++)if(equal(arguments[n],name))return arguments[n+1];return NULL;}
static int valid_arguments(void)
{
 unsigned n,k,modes=0;static const char *const names[]={"--diagnose","--run-classic","--worker","--run-runtime","--worker-runtime","--log","--ntw32","--bridge","--providers","--report-handle"};
 if(!(argc&1))return 0;
 for(n=1;n<argc;n+=2){unsigned j;for(j=0;j<sizeof(names)/sizeof(names[0]);j++)if(equal(arguments[n],names[j]))break;if(j==sizeof(names)/sizeof(names[0]))return 0;
  for(k=1;k<n;k+=2)if(equal(arguments[n],arguments[k]))return 0;if(j<5)modes++;
 }
 if(modes!=1)return 0;
 if(option("--worker")||option("--worker-runtime"))return argc==5&&option("--report-handle")!=NULL;
 return option("--log")!=NULL&&option("--report-handle")==NULL;
}
static int open_providers(loader *l)
{
 const char *p=option("--ntw32"),*directory=option("--providers"),*bridge=option("--bridge");
 if(p){if(!absolute(p))return 0;l->ntw=LoadLibraryA(p);if(!l->ntw)return 0;l->ntw_find=(ntw_resolve_fn)(void *)GetProcAddress(l->ntw,"NtwGetProcAddress");if(!l->ntw_find)return 0;}
 if(directory||bridge){provider_open_fn open;
  if(!absolute(directory)||!absolute(bridge))return 0;l->bridge=LoadLibraryA(bridge);if(!l->bridge)return 0;
  open=(provider_open_fn)(void *)GetProcAddress(l->bridge,"NtwOpenProviderDirectoryA");l->provider_find=(provider_find_fn)(void *)GetProcAddress(l->bridge,"NtwFindProviderExportA");l->provider_close=(provider_close_fn)(void *)GetProcAddress(l->bridge,"NtwCloseProviderDirectory");
  if(!open||!l->provider_find||!l->provider_close||(l->providers=open(directory))==NULL)return 0;
 }return 1;
}
static DWORD perform(const char *path,int execute)
{
 loader *l=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*l));module *root;unsigned n,last=0;DWORD result=20;
 if(!l)return 20;if(!absolute(path)||length(path)>=MAX_PATH){HeapFree(GetProcessHeap(),0,l);return 20;}l->execute=execute!=0;l->runtime=execute==2;l->thread_slot=TLS_OUT_OF_INDEXES;active_loader=l;
 copy(l->directory,path,length(path)+1);for(n=0;path[n];n++)if(path[n]=='\\')last=n;l->directory[last]=0;
 l->command_line[0]='"';copy(l->command_line+1,path,length(path));l->command_line[length(path)+1]='"';l->command_line[length(path)+2]=0;
 for(n=0;n<=length(l->command_line);n++)l->command_line_w[n]=(BYTE)l->command_line[n];
 if(execute&&(option("--ntw32")||option("--providers")||option("--bridge"))){line("EXECUTION_BLOCKER=","PROVIDER_RUNTIME_NOT_VERIFIED");goto done;}
 if(!open_providers(l)){line("PROVIDER_ERROR=","UNAVAILABLE_OR_ABI");goto done;}
 root=load_module(l,path+last+1,path);
 if(root)l->root_is_dll=!!(root->pe.characteristics&0x2000);
 value("MISSING_IMPORTS=",l->missing);value("RUNTIME_BLOCKERS=",l->blocked);
 if(!root||l->missing||l->blocked){line("STATUS=","BLOCKED");goto done;}
 if(!execute){line("STATUS=","IMPORT_CLOSURE_ONLY");result=0;goto done;}
 if(!prepare_runtime(l)){line("EXECUTION_BLOCKER=","RUNTIME_PREPARATION");goto done;}
 for(n=0;n<l->count;n++)if(!l->modules[n].native&&!protect_image(&l->modules[n])){line("EXECUTION_BLOCKER=","PROTECTION_OR_CACHE");goto done;}
 if(l->runtime)EnterCriticalSection(&l->lock);
 {int attached=attach_module(l,root);if(l->runtime)LeaveCriticalSection(&l->lock);if(!attached){line("EXECUTION_BLOCKER=","DLL_ATTACH_FAILED");goto done;}}
 if(root->pe.characteristics&0x2000){
  typedef DWORD (WINAPI *fixture_fn)(HINSTANCE,HANDLE);FARPROC p=resolve(l,root,"NtwPeFixture",0,0);
  if(!p){line("EXECUTION_BLOCKER=","FIXTURE_EXPORT_MISSING");goto done;}
  result=((fixture_fn)(void *)p)((HINSTANCE)root->mapped,report);value("FIXTURE_RETURN=",result);
 }else{typedef void (WINAPI *exe_entry_fn)(void);line("ENTRY=","CALLING_CLASSIC_EXE");((exe_entry_fn)(void *)(root->mapped+root->pe.entry))();result=0;line("ENTRY=","RETURNED");}
 line("STATUS=",result?"TARGET_RETURN_NONZERO":(l->runtime?"RUNTIME_EXECUTION_RETURNED":"CLASSIC_EXECUTION_RETURNED"));
done:
 cleanup(l);active_loader=NULL;HeapFree(GetProcessHeap(),0,l);return report_failed?21:result;
}
static DWORD worker(const char *target)
{
 const char *handle=option("--report-handle");uint32_t h=0;unsigned n;if(!handle)return 20;
 for(n=0;handle[n];n++){if(handle[n]<'0'||handle[n]>'9'||h>429496729u||(h==429496729u&&handle[n]>'5'))return 20;h=h*10+(handle[n]-'0');}
 report=(HANDLE)(UINT_PTR)h;if(GetFileType(report)!=FILE_TYPE_DISK)return 20;return perform(target,option("--worker-runtime")?2:1);
}
static DWORD supervised(const char *target,int runtime)
{
 char own[MAX_PATH],command[1024],digits[11];unsigned n=0,k=0,a;DWORD wait,exit=20;STARTUPINFOA startup;PROCESS_INFORMATION process;
 DWORD h=(DWORD)(UINT_PTR)report;do{digits[n++]=(char)('0'+h%10);h/=10;}while(h);
 a=GetModuleFileNameA(NULL,own,sizeof(own));if(!a||a>=sizeof(own)||length(target)+a+64>=sizeof(command))return 20;
 command[k++]='"';copy(command+k,own,a);k+=a;
 {const char *mode=runtime?"\" --worker-runtime \"":"\" --worker \"";unsigned bytes=length(mode);copy(command+k,mode,bytes);k+=bytes;}
 copy(command+k,target,length(target));k+=length(target);copy(command+k,"\" --report-handle ",18);k+=18;while(n)command[k++]=digits[--n];command[k]=0;
 for(n=0;n<sizeof(startup);n++)((BYTE *)&startup)[n]=0;startup.cb=sizeof(startup);
 startup.dwFlags=STARTF_USESTDHANDLES;startup.hStdOutput=report;startup.hStdError=report;startup.hStdInput=GetStdHandle(STD_INPUT_HANDLE);
 if(!CreateProcessA(own,command,NULL,NULL,TRUE,0,NULL,NULL,&startup,&process)){value("CREATE_PROCESS_ERROR=",GetLastError());return 20;}
 CloseHandle(process.hThread);wait=WaitForSingleObject(process.hProcess,15000);value("WORKER_WAIT=",wait);
 if(wait==WAIT_TIMEOUT){if(TerminateProcess(process.hProcess,22))WaitForSingleObject(process.hProcess,2000);line("STATUS=","EXECUTION_TIMEOUT");}
 if(!GetExitCodeProcess(process.hProcess,&exit)){value("EXIT_QUERY_ERROR=",GetLastError());exit=20;}value("WORKER_EXIT=",exit);CloseHandle(process.hProcess);return exit==STILL_ACTIVE?22:exit;
}
void WINAPI entry(void)
{
 const char *path,*log;DWORD exit=20;SECURITY_ATTRIBUTES security;
 if(!parse_arguments()||!valid_arguments())ExitProcess(20);
 path=option("--worker");if(!path)path=option("--worker-runtime");if(path)ExitProcess(worker(path));
 path=option("--diagnose");if(!path)path=option("--run-classic");if(!path)path=option("--run-runtime");log=option("--log");
 if(!absolute(path)||!absolute(log)||equal_ci(path,log))ExitProcess(20);
 security.nLength=sizeof(security);security.lpSecurityDescriptor=NULL;security.bInheritHandle=TRUE;
 report=CreateFileA(log,GENERIC_WRITE,0,&security,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 line("LOADER=","NTWPE32_NATIVE_WINDOWS98_STAGE2");line("TARGET_HEADERS=","UNCHANGED");line("TARGET=",path);
 if((option("--run-classic")||option("--run-runtime"))&&(option("--ntw32")||option("--providers")||option("--bridge")))line("EXECUTION_BLOCKER=","PROVIDER_CALLBACK_THREAD_RUNTIME_NOT_IMPLEMENTED");
 else if(option("--run-classic")||option("--run-runtime"))exit=supervised(path,option("--run-runtime")!=NULL);else exit=perform(path,0);
 if(report_failed)exit=21;FlushFileBuffers(report);CloseHandle(report);ExitProcess(exit);
}
