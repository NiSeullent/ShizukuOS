/* SPDX-License-Identifier: GPL-2.0-only
 * Included only in a frozen patched native.c, after the real by_handle exists.
 * Uses its actual module state/mapped/native identities and existing lock.
 */
#include "ntwin32/process_exit/original_kernel.h"
typedef struct nrb_native_resource {HMODULE module;HRSRC info;HGLOBAL data;} nrb_native_resource;
static nrb_native_resource native_resources[64];
static unsigned native_resource_count;
static uint32_t resource_closing_good,resource_closing_bad;
static HMODULE native_process_root;
typedef HRSRC (WINAPI *nrb_find_a_fn)(HMODULE,LPCSTR,LPCSTR);
typedef HRSRC (WINAPI *nrb_find_w_fn)(HMODULE,LPCWSTR,LPCWSTR);
typedef HRSRC (WINAPI *nrb_ex_a_fn)(HMODULE,LPCSTR,LPCSTR,WORD);
typedef HRSRC (WINAPI *nrb_ex_w_fn)(HMODULE,LPCWSTR,LPCWSTR,WORD);
typedef HGLOBAL (WINAPI *nrb_load_fn)(HMODULE,HRSRC);
typedef LPVOID (WINAPI *nrb_lock_fn)(HGLOBAL);
typedef DWORD (WINAPI *nrb_size_fn)(HMODULE,HRSRC);
typedef BOOL (WINAPI *nrb_free_fn)(HGLOBAL);
static nrb_find_a_fn native_find_a;static nrb_find_w_fn native_find_w;
static nrb_ex_a_fn native_ex_a;static nrb_ex_w_fn native_ex_w;
static nrb_load_fn native_load;static nrb_lock_fn native_lock;static nrb_size_fn native_size;static nrb_free_fn native_free;
static void *resource_last_info,*resource_last_data;
static int resource_self_test(loader *);
static const uint8_t *resource_read(void *unused,const void *pointer,uint32_t bytes)
{
 uintptr_t at=(uintptr_t)pointer;uint32_t left=bytes;DWORD saved=GetLastError();int okay=1;(void)unused;
 if(!pointer||at>UINTPTR_MAX-bytes){SetLastError(saved);return NULL;}
 while(left){MEMORY_BASIC_INFORMATION info;uint32_t delta,part;
  if(VirtualQuery((const void *)at,&info,sizeof(info))!=sizeof(info)||info.State!=MEM_COMMIT||
     (info.Protect!=PAGE_READONLY&&info.Protect!=PAGE_READWRITE&&info.Protect!=PAGE_WRITECOPY&&
      info.Protect!=PAGE_EXECUTE_READ&&info.Protect!=PAGE_EXECUTE_READWRITE&&info.Protect!=PAGE_EXECUTE_WRITECOPY)||
     at<(uintptr_t)info.BaseAddress){okay=0;break;}
  delta=(uint32_t)(at-(uintptr_t)info.BaseAddress);if(delta>=info.RegionSize){okay=0;break;}
  part=(uint32_t)info.RegionSize-delta;if(part>left)part=left;at+=part;left-=part;
 }SetLastError(saved);return okay?pointer:NULL;
}
static void resource_error(void *unused,uint32_t e){(void)unused;SetLastError(e);}
static int resource_prepare(loader *l)
{
 unsigned n;const char *why=NULL;
 if(!l->resource_mode)return 1;
 if(!l->runtime||!l->lock_ready||!px_original_win98())return 0;
 native_process_root=GetModuleHandleA(NULL);if(!native_process_root)return 0;
 native_resource_count=0;resource_last_info=NULL;resource_last_data=NULL;
 resource_closing_good=0;resource_closing_bad=0;
 native_find_a=(nrb_find_a_fn)(void *)px_original_kernel("FindResourceA",NULL);
 native_find_w=(nrb_find_w_fn)(void *)px_original_kernel("FindResourceW",NULL);
 native_ex_a=(nrb_ex_a_fn)(void *)px_original_kernel("FindResourceExA",NULL);
 native_ex_w=(nrb_ex_w_fn)(void *)px_original_kernel("FindResourceExW",NULL);
 native_load=(nrb_load_fn)(void *)px_original_kernel("LoadResource",NULL);
 native_lock=(nrb_lock_fn)(void *)px_original_kernel("LockResource",NULL);
 native_size=(nrb_size_fn)(void *)px_original_kernel("SizeofResource",NULL);
 native_free=(nrb_free_fn)(void *)px_original_kernel("FreeResource",NULL);
 if(!native_find_a||!native_find_w||!native_ex_a||!native_ex_w||!native_load||!native_lock||!native_size||!native_free)return 0;
 if(!nrb_init(&l->resources,resource_read,resource_error,NULL))return 0;
 for(n=0;n<l->count;n++){module *m=&l->modules[n];
  if(m->native)continue;
  if(m->state!=2||!m->file||!m->mapped||!nrb_add(&l->resources,m,&m->pe,m->mapped,n==0&&!l->root_is_dll,&why)){
   line("RESOURCE_REGISTRATION_BLOCKER=",why?why:"MAPPED_OWNERSHIP_OR_CONTENT");return 0;
  }
 }if(!nrb_publish(&l->resources))return 0;line("RESOURCES=","REGISTERED_BEFORE_ATTACH");return resource_self_test(l);
}
static void resource_finish(loader *l)
{
 if(!l->resource_mode)return;
 value("RESOURCE_DETACH_SUCCESSES=",resource_closing_good);value("RESOURCE_DETACH_FAILURES=",resource_closing_bad);
 if(l->resources.bound&&(resource_closing_good!=4||resource_closing_bad))report_failed=1;
 if(!nrb_dispose(&l->resources)){line("EXECUTION_BLOCKER=","RESOURCE_UNREGISTER_FAILED");ExitProcess(29);}
 native_resource_count=0;line("RESOURCES=","UNREGISTERED_BEFORE_MAPPING_RELEASE");
}
/* NULL identity follows mapped_handle_a: an EXE root is the mapped application;
 * a DLL root has the native host EXE as its process root. No invented IDs. */
static HMODULE resource_module(loader *l,HMODULE handle,int *mapped)
{
 module *m;*mapped=0;
 if(l->root_is_dll&&(!handle||handle==native_process_root))return native_process_root;
 m=by_handle(l,handle);
 if(!m||m->state!=2)return NULL;
 if(m->native)return m->native;
 if(!nrb_owned(&l->resources,m,m->mapped))return NULL;
 *mapped=1;return (HMODULE)m->mapped;
}
static nrb_native_resource *native_info(HMODULE module,HRSRC info,int add)
{
 unsigned n;for(n=0;n<native_resource_count;n++)if(native_resources[n].module==module&&native_resources[n].info==info)return &native_resources[n];
 if(!add||!info||native_resource_count>=64)return NULL;
 native_resources[native_resource_count].module=module;native_resources[native_resource_count].info=info;
 native_resources[native_resource_count].data=NULL;return &native_resources[native_resource_count++];
}
static int native_data(HGLOBAL data)
{unsigned n;if(!data)return 0;for(n=0;n<native_resource_count;n++)if(native_resources[n].data==data)return 1;return 0;}
static loader *resource_enter(DWORD *saved)
{
 loader *l=active_loader;*saved=GetLastError();
 if(!l||!l->resource_mode||!l->lock_ready||!l->resources.bound){SetLastError(ERROR_INVALID_HANDLE);return NULL;}
 EnterCriticalSection(&l->lock);SetLastError(*saved);return l;
}
static void resource_leave(loader *l)
{DWORD error=GetLastError();LeaveCriticalSection(&l->lock);SetLastError(error);}
static void resource_observe_close(loader *l,int okay)
{if(l->closing){if(okay)resource_closing_good++;else resource_closing_bad++;}}
static HRSRC WINAPI resource_find_ex_a(HMODULE h,LPCSTR t,LPCSTR n,WORD lang)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;HRSRC result;HMODULE m;if(!l)return NULL;
 m=resource_module(l,h,&mapped);
 if(!m){SetLastError(ERROR_INVALID_HANDLE);result=NULL;}
 else if(mapped)result=nra_FindResourceExA(m,t,n,lang);
 else {result=native_ex_a(m,t,n,lang);if(result&&!native_info(m,result,1)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);result=NULL;}}
 if(result&&mapped)resource_last_info=result;resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static HRSRC WINAPI resource_find_ex_w(HMODULE h,LPCWSTR t,LPCWSTR n,WORD lang)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;HRSRC result;HMODULE m;if(!l)return NULL;
 m=resource_module(l,h,&mapped);
 if(!m){SetLastError(ERROR_INVALID_HANDLE);result=NULL;}
 else if(mapped)result=nra_FindResourceExW(m,(const uint16_t *)t,(const uint16_t *)n,lang);
 else {result=native_ex_w(m,t,n,lang);if(result&&!native_info(m,result,1)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);result=NULL;}}
 if(result&&mapped)resource_last_info=result;resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static HRSRC WINAPI resource_find_a(HMODULE h,LPCSTR n,LPCSTR t)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;HRSRC result;HMODULE m;if(!l)return NULL;
 m=resource_module(l,h,&mapped);
 if(!m){SetLastError(ERROR_INVALID_HANDLE);result=NULL;}
 else if(mapped)result=nra_FindResourceA(m,n,t);
 else {result=native_find_a(m,n,t);if(result&&!native_info(m,result,1)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);result=NULL;}}
 if(result&&mapped)resource_last_info=result;resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static HRSRC WINAPI resource_find_w(HMODULE h,LPCWSTR n,LPCWSTR t)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;HRSRC result;HMODULE m;if(!l)return NULL;
 m=resource_module(l,h,&mapped);
 if(!m){SetLastError(ERROR_INVALID_HANDLE);result=NULL;}
 else if(mapped)result=nra_FindResourceW(m,(const uint16_t *)n,(const uint16_t *)t);
 else {result=native_find_w(m,n,t);if(result&&!native_info(m,result,1)){SetLastError(ERROR_NOT_ENOUGH_MEMORY);result=NULL;}}
 if(result&&mapped)resource_last_info=result;resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static HGLOBAL WINAPI resource_load(HMODULE h,HRSRC info)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;HGLOBAL result=NULL;HMODULE m;nrb_native_resource *item;if(!l)return NULL;
 m=resource_module(l,h,&mapped);
 if(!m)SetLastError(ERROR_INVALID_HANDLE);
 else if(mapped){result=nra_LoadResource(m,info);if(result)resource_last_data=result;}
 else if((item=native_info(m,info,0))!=NULL){result=native_load(m,info);if(result)item->data=result;}
 else SetLastError(ERROR_INVALID_HANDLE);
 resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static DWORD WINAPI resource_size(HMODULE h,HRSRC info)
{
 DWORD saved;loader *l=resource_enter(&saved);int mapped;DWORD result=0;HMODULE m;if(!l)return 0;
 m=resource_module(l,h,&mapped);
 if(!m)SetLastError(ERROR_INVALID_HANDLE);
 else if(mapped)result=nra_SizeofResource(m,info);
 else if(native_info(m,info,0))result=native_size(m,info);
 else SetLastError(ERROR_INVALID_HANDLE);
 resource_observe_close(l,result!=0);resource_leave(l);return result;
}
static LPVOID WINAPI resource_lock(HGLOBAL data)
{
 DWORD saved;loader *l=resource_enter(&saved);LPVOID result;if(!l)return NULL;
 result=native_data(data)?native_lock(data):nra_LockResource(data);resource_observe_close(l,result!=NULL);resource_leave(l);return result;
}
static BOOL WINAPI resource_free(HGLOBAL data)
{
 DWORD saved;loader *l=resource_enter(&saved);BOOL result;if(!l)return FALSE;
 result=native_data(data)?native_free(data):nra_FreeResource(data);resource_leave(l);return result;
}
static int resource_self_test(loader *l)
{
 const DWORD marker=0x51a2b3c4u;DWORD saved,observed;loader *entered;HMODULE identity;int mapped,okay;
 HRSRC info,root_info;HGLOBAL data;static const uint16_t named[]={'n','a','m','e','d',0};
 /* Run only for the exact own graph, before any attach. All error observations
  * are actual thread values captured before value()/report I/O. The outer
  * preparation lock remains held; this checks real same-thread recursive entry. */
 SetLastError(marker);entered=resource_enter(&saved);observed=GetLastError();
 value("RESOURCE_LOCK_ENTER_LAST_ERROR=",observed);
 if(entered!=l||saved!=marker||observed!=marker){if(entered)resource_leave(entered);return 0;}
 SetLastError(marker);identity=resource_module(l,NULL,&mapped);observed=GetLastError();
 okay=l->root_is_dll?(!mapped&&identity==native_process_root):(mapped&&identity==(HMODULE)l->modules[0].mapped);
 value(l->root_is_dll?"NATIVE_HOST_NULL_IDENTITY_LAST_ERROR=":"MAPPED_APP_NULL_IDENTITY_LAST_ERROR=",observed);
 if(!okay||observed!=marker){resource_leave(l);return 0;}
 SetLastError(marker);resource_leave(l);observed=GetLastError();value("RESOURCE_LOCK_LEAVE_LAST_ERROR=",observed);
 if(observed!=marker)return 0;
#define RESOURCE_SENTINEL(tag,expression) do{SetLastError(marker);okay=!!(expression);observed=GetLastError();value(tag,observed);if(!okay||observed!=marker)return 0;}while(0)
 RESOURCE_SENTINEL("BRIDGE_FIND_EX_A_LAST_ERROR=",(info=resource_find_ex_a((HMODULE)l->modules[0].mapped,MAKEINTRESOURCEA(10),"named",1033))!=NULL);
 RESOURCE_SENTINEL("BRIDGE_FIND_A_LAST_ERROR=",resource_find_a((HMODULE)l->modules[0].mapped,"named",MAKEINTRESOURCEA(10))==info);
 RESOURCE_SENTINEL("BRIDGE_FIND_EX_W_LAST_ERROR=",resource_find_ex_w((HMODULE)l->modules[0].mapped,MAKEINTRESOURCEW(10),(const WCHAR *)named,1033)==info);
 RESOURCE_SENTINEL("BRIDGE_FIND_W_LAST_ERROR=",resource_find_w((HMODULE)l->modules[0].mapped,(const WCHAR *)named,MAKEINTRESOURCEW(10))==info);
 RESOURCE_SENTINEL("BRIDGE_SIZE_LAST_ERROR=",resource_size((HMODULE)l->modules[0].mapped,info)==6);
 RESOURCE_SENTINEL("BRIDGE_LOAD_LAST_ERROR=",(data=resource_load((HMODULE)l->modules[0].mapped,info))!=NULL);
 RESOURCE_SENTINEL("BRIDGE_LOCK_LAST_ERROR=",resource_lock(data)==data);
 RESOURCE_SENTINEL("BRIDGE_FREE_LAST_ERROR=",!resource_free(data));
 RESOURCE_SENTINEL("BRIDGE_REPEAT_FREE_LAST_ERROR=",!resource_free(data));
 RESOURCE_SENTINEL("BRIDGE_RETAINED_LOCK_LAST_ERROR=",resource_lock(data)==data);
#undef RESOURCE_SENTINEL
 SetLastError(marker);root_info=resource_find_ex_a(NULL,MAKEINTRESOURCEA(10),MAKEINTRESOURCEA(101),1033);observed=GetLastError();
 value("BRIDGE_NULL_RESOURCE_SELECTED_ERROR=",observed);
 if(l->root_is_dll){if(root_info||!observed||observed==marker)return 0;}
 else if(!root_info||observed!=marker)return 0;
 value("BRIDGE_NATIVE_LAST_ERROR_CONTROLS=",14);return !report_failed;
}
static FARPROC resource_hook(const char *name)
{
 if(!active_loader||!active_loader->resource_mode)return NULL;
#define RESOURCE_HOOK(n,f) if(equal(name,n))return (FARPROC)(void *)f
 RESOURCE_HOOK("FindResourceA",resource_find_a);RESOURCE_HOOK("FindResourceW",resource_find_w);
 RESOURCE_HOOK("FindResourceExA",resource_find_ex_a);RESOURCE_HOOK("FindResourceExW",resource_find_ex_w);
 RESOURCE_HOOK("LoadResource",resource_load);RESOURCE_HOOK("LockResource",resource_lock);
 RESOURCE_HOOK("SizeofResource",resource_size);RESOURCE_HOOK("FreeResource",resource_free);
#undef RESOURCE_HOOK
 return NULL;
}
