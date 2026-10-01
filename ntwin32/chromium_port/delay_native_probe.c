/* SPDX-License-Identifier: GPL-2.0-only
 * Real Win98 Kernel32/critical-section/thread controls for the resolver core.
 * Never launches Chromium, Steam, Legcord, LibreOffice or another application.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "delay_fixture.h"
typedef struct backend {CRITICAL_SECTION lock;DWORD opens,finds,closes,last_error;} backend;
static HANDLE log_file=INVALID_HANDLE_VALUE;static DWORD checks,failures;static int log_failed;
static backend backend_state;
static ntw_delay_context *context;
static uint8_t file[DF_FILE_BYTES],*mapped;
static np_image image;
static const char *error;
static DWORD length(const char *s){DWORD n=0;while(s[n])n++;return n;}
static void write(const char *s){DWORD n=length(s),got=0;if(!WriteFile(log_file,s,n,&got,0)||got!=n)log_failed=1;}
static void number(DWORD v){char b[11];DWORD n=0;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);while(n){char one[2];one[0]=b[--n];one[1]=0;write(one);}}
static void check(const char *name,int condition){checks++;write(condition?"PASS ":"FAIL ");write(name);write("\r\n");if(!condition)failures++;}
static int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static int enter(void *p){EnterCriticalSection(&((backend *)p)->lock);return 1;}
static void leave(void *p){LeaveCriticalSection(&((backend *)p)->lock);}
static uint32_t open_dll(void *p,const char *name)
{
 backend *b=p;char path[MAX_PATH];DWORD n,i;HMODULE handle;b->opens++;
 if(!same(name,"KERNEL32.DLL")){b->last_error=ERROR_NOT_SUPPORTED;return 0;}
 n=GetSystemDirectoryA(path,MAX_PATH);if(!n||n>=MAX_PATH-14){b->last_error=GetLastError();return 0;}
 path[n++]='\\';for(i=0;name[i];i++)path[n++]=name[i];path[n]=0;
 handle=LoadLibraryA(path);b->last_error=handle?0:GetLastError();return (uint32_t)(UINT_PTR)handle;
}
static uint32_t find_export(void *p,uint32_t handle,const char *name,uint16_t ordinal)
{backend *b=p;FARPROC address;b->finds++;address=GetProcAddress((HMODULE)(UINT_PTR)handle,ordinal?(LPCSTR)(UINT_PTR)ordinal:name);b->last_error=address?0:GetLastError();return (uint32_t)(UINT_PTR)address;}
static int close_dll(void *p,uint32_t handle)
{backend *b=p;BOOL closed;b->closes++;closed=FreeLibrary((HMODULE)(UINT_PTR)handle);b->last_error=closed?0:GetLastError();return closed!=0;}
static void build(void)
{df_build(file,mapped,(uint32_t)(UINT_PTR)mapped);}
static int init(void)
{ntw_delay_ops ops={&backend_state,enter,leave,open_dll,find_export,close_dll};return np_parse(&image,file,sizeof(file),&error)&&ntw_delay_init(context,&image,mapped,DF_IMAGE_BYTES,(uint32_t)(UINT_PTR)mapped,&ops,&error);}
static uint32_t hash(const uint8_t *bytes,DWORD n){uint32_t v=2166136261u,i;for(i=0;i<n;i++){v^=bytes[i];v*=16777619u;}return v;}
typedef struct thread_result {uint32_t address,slot;int okay;} thread_result;
static DWORD WINAPI worker(void *opaque)
{thread_result *result=opaque;DWORD i;uint32_t address;result->okay=1;for(i=0;i<100;i++)if(!ntw_delay_resolve(context,DF_DESCRIPTOR,result->slot,&address,0)||address!=result->address){result->okay=0;break;}return result->okay?0:1;}
static int controls(void)
{
 DWORD version=GetVersion(),start,end,wait,exit,i;uint32_t address,tick,string,before;HMODULE kernel=GetModuleHandleA("KERNEL32.DLL");HANDLE threads[2];thread_result results[2];
 check("actual Win98 4.10",(version&0xffff)==0x0a04&&(version&0x80000000u));if(failures)return 1;
 context=HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(*context));mapped=VirtualAlloc(0,DF_IMAGE_BYTES,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
 check("native context and mapping allocation",context&&mapped);if(!context||!mapped)return 1;
 InitializeCriticalSection(&backend_state.lock);build();before=hash(mapped,DF_IMAGE_BYTES);
 check("validated owned PE32 delay table",init());if(!context->magic)goto done;
 check("init opens no libraries and writes no slots",!backend_state.opens&&before==hash(mapped,DF_IMAGE_BYTES));
 check("named native GetTickCount resolution",ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT,&tick,&error));if(!tick)goto done;
 check("actual Kernel32 GetProcAddress matches",tick==(uint32_t)(UINT_PTR)GetProcAddress(kernel,"GetTickCount"));
 start=((DWORD (WINAPI *)(void))(UINT_PTR)tick)();Sleep(35);end=((DWORD (WINAPI *)(void))(UINT_PTR)tick)();
 check("resolved real clock advances",end-start>=20&&end-start<5000);
 check("named native lstrlenA resolution",ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT+4,&string,&error));if(!string)goto done;
 check("actual native string function executes",((int (WINAPI *)(LPCSTR))(UINT_PTR)string)("Chromium delay import")==21);
 check("real retained HMODULE published",np_u32(mapped+DF_HANDLE)==(uint32_t)(UINT_PTR)kernel&&backend_state.opens==1);
 check("cached IAT resolution performs no repeated lookup",ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT,&address,&error)&&address==tick&&backend_state.finds==2);
 /* An ordinal is checked against the real export table, never called by a
  * guessed signature. The owned fixture deliberately does not identify it. */
 address=(uint32_t)(UINT_PTR)GetProcAddress(kernel,(LPCSTR)(UINT_PTR)7);
 if(address)check("ordinal native export matches exact ordinal",ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT+8,&before,&error)&&before==address);
 else check("absent ordinal reports unresolved",!ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT+8,&before,&error)&&before==0);
 results[0]=(thread_result){tick,DF_IAT,0};results[1]=(thread_result){string,DF_IAT+4,0};
 for(i=0;i<2;i++)threads[i]=CreateThread(0,0,worker,&results[i],0,0);
 check("two real native threads created",threads[0]&&threads[1]);
 for(i=0;i<2;i++)if(threads[i]){wait=WaitForSingleObject(threads[i],5000);exit=STILL_ACTIVE;
  check(i?"second native worker joined":"first native worker joined",wait==WAIT_OBJECT_0&&GetExitCodeThread(threads[i],&exit)&&exit==0&&results[i].okay);
  if(wait!=WAIT_OBJECT_0){write("STATUS=LIVE_WORKER_UNSAFE_TO_DISPOSE\r\n");FlushFileBuffers(log_file);ExitProcess(20);}check("real worker handle closed",CloseHandle(threads[i]));
 }
 check("dispose refuses unjoined declaration",!ntw_delay_dispose(context,0,&error));
 check("native quiescent disposal closes own library",ntw_delay_dispose(context,1,&error)&&backend_state.closes==1);
 check("native disposal restores linker slots",np_u32(mapped+DF_HANDLE)==0&&np_u32(mapped+DF_IAT)==(uint32_t)(UINT_PTR)mapped+0x1000);
 build();file[1024+0x182+11]='Z';mapped[0x2182+11]='Z';before=hash(mapped,DF_IMAGE_BYTES);
 check("unknown export fixture validates",init());
 check("real GetProcAddress failure is preserved",!ntw_delay_resolve(context,DF_DESCRIPTOR,DF_IAT,&address,&error)&&address==0&&same(error,"DELAY_GET_PROC_FAILED"));
 check("failed native export leaves mapping unchanged",before==hash(mapped,DF_IMAGE_BYTES));
 check("failed lookup closes its new reference",backend_state.opens==2&&backend_state.closes==2);
 check("failed native lookup context disposes",ntw_delay_dispose(context,1,&error));
 build();df_put32(file+1024+20,0x2200);df_put32(mapped+DF_DESCRIPTOR+20,0x2200);before=hash(mapped,DF_IMAGE_BYTES);
 check("unsupported bound state rejected before effects",!init()&&!context->magic&&backend_state.opens==2&&before==hash(mapped,DF_IMAGE_BYTES));
done:
 if(context&&context->magic&&!ntw_delay_dispose(context,1,&error))failures++;
 DeleteCriticalSection(&backend_state.lock);
 check("mapping allocation released",VirtualFree(mapped,0,MEM_RELEASE));check("context allocation released",HeapFree(GetProcessHeap(),0,context));
 return failures?1:0;
}
void WINAPI entry(void)
{
 DWORD result;log_file=CreateFileA("C:\\VXDLAB\\CHDLY.LOG",GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);
 if(log_file==INVALID_HANDLE_VALUE)ExitProcess(10);
 write("NATIVE_CHROMIUM_DELAY_CORE=1\r\nAPPLICATION_EXECUTED=0\r\n");result=controls();write("CHECKS=");number(checks);write(" FAILURES=");number(failures);write("\r\n");
 write(result?"STATUS=FAIL\r\n":"STATUS=SCOPED_NATIVE_DELAY_CORE_PASS\r\n");if(!FlushFileBuffers(log_file))result=11;if(!CloseHandle(log_file))result=12;ExitProcess(log_failed?13:result);
}
