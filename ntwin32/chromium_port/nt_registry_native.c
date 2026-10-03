/* SPDX-License-Identifier: GPL-2.0-only */
/* M98NTREG.DLL: NT registry exports for chrome_elf.dll backed by the real
 * Windows 98 ADVAPI32 ANSI registry and Kernel32 code page/heap services. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "nt_registry.h"
static CRITICAL_SECTION lock;
static ntr_state state;
static HKEY root_key(unsigned root)
{
 return root==NTR_ROOT_MACHINE?HKEY_LOCAL_MACHINE:root==NTR_ROOT_USERS?HKEY_USERS:root==NTR_ROOT_CURRENT_USER?HKEY_CURRENT_USER:0;
}
static void enter(void *p){(void)p;EnterCriticalSection(&lock);}
static void leave(void *p){(void)p;LeaveCriticalSection(&lock);}
static long open_key(void *p,unsigned root,const char *path,void **key)
{
 HKEY r=root_key(root),k=0;LONG e;(void)p;if(!r)return ERROR_INVALID_PARAMETER;
 e=RegOpenKeyExA(r,path,0,KEY_READ|KEY_WRITE,&k);if(!e)*key=(void*)k;return e;
}
static long create_key(void *p,unsigned root,const char *path,void **key,int *created)
{
 HKEY r=root_key(root),k=0;DWORD disposition=0;LONG e;(void)p;if(!r)return ERROR_INVALID_PARAMETER;
 e=RegCreateKeyExA(r,path,0,0,REG_OPTION_NON_VOLATILE,KEY_READ|KEY_WRITE,0,&k,&disposition);
 if(!e){*key=(void*)k;*created=disposition==REG_CREATED_NEW_KEY;}return e;
}
static long query(void *p,void *key,const char *name,uint32_t *type,uint8_t *data,uint32_t *bytes)
{
 DWORD t=0,n=*bytes;LONG e;(void)p;e=RegQueryValueExA((HKEY)key,name,0,&t,data,&n);
 if(!e||e==ERROR_MORE_DATA){*type=t;*bytes=n;}return e;
}
static long set(void *p,void *key,const char *name,uint32_t type,const uint8_t *data,uint32_t bytes)
{(void)p;return RegSetValueExA((HKEY)key,name,0,type,data,bytes);}
static long has_subkey(void *p,void *key,int *present)
{
 DWORD subkeys=0;LONG e;(void)p;e=RegQueryInfoKeyA((HKEY)key,0,0,0,&subkeys,0,0,0,0,0,0,0);
 if(!e)*present=subkeys!=0;return e;
}
static long remove_key(void *p,unsigned root,const char *path)
{HKEY r=root_key(root);(void)p;return r?RegDeleteKeyA(r,path):ERROR_INVALID_PARAMETER;}
static long close_key(void *p,void *key){(void)p;return RegCloseKey((HKEY)key);}
static int to_ansi(void *p,const uint16_t *w,uint32_t n,char *out,uint32_t cap,uint32_t *used)
{
 BOOL lossy=FALSE;int r;(void)p;*used=0;if(!n)return 1;
 r=WideCharToMultiByte(CP_ACP,0,(LPCWSTR)w,(int)n,out,out?(int)cap:0,0,&lossy);
 if(r<=0||lossy)return 0;*used=(uint32_t)r;return 1;
}
static int to_wide(void *p,const char *a,uint32_t n,uint16_t *out,uint32_t cap,uint32_t *used)
{
 int r;(void)p;*used=0;if(!n)return 1;
 r=MultiByteToWideChar(CP_ACP,MB_ERR_INVALID_CHARS,a,(int)n,(LPWSTR)out,out?(int)cap:0);
 if(r<=0)return 0;*used=(uint32_t)r;return 1;
}
static void *alloc(void *p,uint32_t n){(void)p;return HeapAlloc(GetProcessHeap(),0,n);}
static void release(void *p,void *b){(void)p;HeapFree(GetProcessHeap(),0,b);}
LONG WINAPI m98r_create(void **h,DWORD access,const ntr_object_attributes *oa,DWORD title,const ntr_unicode_string *cls,DWORD options,DWORD *disposition)
{return ntr_create_key(&state,h,access,oa,title,cls,options,(uint32_t*)disposition);}
LONG WINAPI m98r_open(void **h,DWORD access,const ntr_object_attributes *oa,DWORD options)
{return ntr_open_key_ex(&state,h,access,oa,options);}
LONG WINAPI m98r_query(void *h,const ntr_unicode_string *name,DWORD info,void *out,DWORD length,DWORD *result)
{return ntr_query_value_key(&state,h,name,info,out,length,(uint32_t*)result);}
LONG WINAPI m98r_set(void *h,const ntr_unicode_string *name,DWORD title,DWORD type,const void *data,DWORD bytes)
{return ntr_set_value_key(&state,h,name,title,type,data,bytes);}
LONG WINAPI m98r_delete(void *h){return ntr_delete_key(&state,h);}
LONG WINAPI m98r_close(void *h){return ntr_close(&state,h);}
LONG WINAPI m98r_format_user(ntr_unicode_string *out){return ntr_format_current_user_key_path(&state,out);}
void WINAPI m98r_init_string(ntr_unicode_string *d,const uint16_t *s){ntr_init_unicode_string(d,s);}
void WINAPI m98r_free_string(ntr_unicode_string *s){ntr_free_unicode_string(&state,s);}
DWORD WINAPI m98r_live(void){return ntr_live_handles(&state);}
BOOL WINAPI dll_entry(HINSTANCE instance,DWORD reason,LPVOID reserved)
{
 (void)instance;
 if(reason==DLL_PROCESS_ATTACH){
  ntr_backend ops={0,enter,leave,open_key,create_key,query,set,has_subkey,remove_key,close_key,to_ansi,to_wide,alloc,release};
  InitializeCriticalSection(&lock);
  if(!ntr_init(&state,&ops)){DeleteCriticalSection(&lock);return FALSE;}
  return TRUE;
 }
 /* FreeLibrary detach closes owned keys; process termination leaves them to
  * the OS without calling into ADVAPI32 from a terminating loader lock. */
 if(reason==DLL_PROCESS_DETACH){if(!reserved)ntr_shutdown(&state);DeleteCriticalSection(&lock);}
 return TRUE;
}
