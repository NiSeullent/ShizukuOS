/* SPDX-License-Identifier: GPL-2.0-only
 * Win98 desktop-only field access interpreter. Debug API thread handles are
 * borrowed: Windows closes them when their exit event is continued. Only
 * PROCESS_INFORMATION handles and event image-file handles are ours to close.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "environment.h"
#include "profiles.h"
#define THREADS 128
typedef struct { DWORD id;HANDLE handle;DWORD old0,old1,old6,old7;DWORD hits[2];int used; } thread_record;
static thread_record threads[THREADS];
static HANDLE log_file=INVALID_HANDLE_VALUE,process;
static DWORD pid,base,records,hits[2],armed,retired,other_exceptions,loader_break;
static uint32_t image;
static const env_profile *profile;
static env_model model;
static int io_failed;
static unsigned len(const char *s){unsigned n=0;while(s[n])n++;return n;}
static int eq(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void put(const char *s){DWORD n=len(s),got;if(!WriteFile(log_file,s,n,&got,NULL)||got!=n)io_failed=1;}
static void hex(DWORD x){static const char alphabet[]="0123456789abcdef";char b[9];unsigned i;for(i=0;i<8;i++)b[i]=alphabet[(x>>(28-4*i))&15];b[8]=0;put(b);}
static void line(const char *key,DWORD value){put(key);put("=");hex(value);put("\r\n");}
static void zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)p)[i]=0;}
static int read_remote(DWORD address,void *p,DWORD n){SIZE_T got=0;return ReadProcessMemory(process,(const void *)(UINT_PTR)address,p,n,&got)&&got==n;}
static int within(DWORD address,DWORD count){return address>=base&&address-base<=image&&count<=image-(address-base);}
static thread_record *find_thread(DWORD id){unsigned i;for(i=0;i<THREADS;i++)if(threads[i].used&&threads[i].id==id)return &threads[i];return NULL;}
static int live_code(void){BYTE a[18],b[19];uint32_t kind,skip;
 return within(base+profile->verifier_rva,18)&&within(base+profile->secure_rva,19)&&read_remote(base+profile->verifier_rva,a,18)&&read_remote(base+profile->secure_rva,b,19)&&env_decode(a,18,&kind,&skip)&&kind==ENV_VERIFIER&&env_decode(b,19,&kind,&skip)&&kind==ENV_SECURE;
}
static int context_read(HANDLE h,CONTEXT *c){zero(c,sizeof(*c));c->ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_DEBUG_REGISTERS|CONTEXT_SEGMENTS;return GetThreadContext(h,c);}
static int arm_thread(DWORD id,HANDLE handle){thread_record *r=NULL;CONTEXT c,verify;unsigned i;
 if(!handle||find_thread(id))return 0;for(i=0;i<THREADS;i++)if(!threads[i].used){r=&threads[i];break;}if(!r||!context_read(handle,&c))return 0;
 /* Refuse a pre-existing debugger's enabled breakpoint or trap flag. */
 if((c.Dr7&255u)||(c.EFlags&0x100u))return 0;
 r->old0=c.Dr0;r->old1=c.Dr1;r->old6=c.Dr6;r->old7=c.Dr7;
 c.Dr0=base+profile->verifier_rva;c.Dr1=base+profile->secure_rva;c.Dr6=0;
 c.Dr7=(c.Dr7&~0x00ff00ffu)|5u;
 c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if(!SetThreadContext(handle,&c)||!context_read(handle,&verify)||verify.Dr0!=c.Dr0||verify.Dr1!=c.Dr1||(verify.Dr7&0x00ff00ffu)!=5u)return 0;
 r->id=id;r->handle=handle;r->used=1;r->hits[0]=r->hits[1]=0;records++;armed++;
 put("DR_SET_READBACK=PASS THREAD=");hex(id);put(" DR0=");hex(c.Dr0);put(" DR1=");hex(c.Dr1);put(" DR7=");hex(verify.Dr7);put("\r\n");return 1;
}
static int emulate_event(thread_record *r,const DEBUG_EVENT *event){CONTEXT c,after;env_context interpreted;BYTE code[19];DWORD index,entry,n;uint32_t mask;
 if(!r||!event->u.Exception.dwFirstChance||!context_read(r->handle,&c))return 0;
 mask=c.Dr6&0xe00fu;if(mask==1){index=0;entry=profile->verifier_rva;n=18;}else if(mask==2){index=1;entry=profile->secure_rva;n=19;}else return 0;
 if(c.Dr0!=base+profile->verifier_rva||c.Dr1!=base+profile->secure_rva||(c.Dr7&0x00ff00ffu)!=5u||c.Eip!=base+entry||(DWORD)(UINT_PTR)event->u.Exception.ExceptionRecord.ExceptionAddress!=c.Eip||!read_remote(c.Eip,code,n))return 0;
 interpreted.eax=c.Eax;interpreted.eip=c.Eip;interpreted.eflags=c.EFlags;
 if(!env_emulate(&model,base,image,entry,c.Dr6,code,n,&interpreted))return 0;
 put("FIELD_LOAD=INTERPRETED THREAD=");hex(r->id);put(" KIND=");put(index?"SECURE":"VERIFIER");put(" INPUT_EIP=");hex(c.Eip);put(" DR6=");hex(c.Dr6);put(" VALUE=");hex(interpreted.eax);put(" RESUME_EIP=");hex(interpreted.eip);put("\r\n");
 c.Eax=interpreted.eax;c.Eip=interpreted.eip;c.Dr6=0;c.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_DEBUG_REGISTERS;
 if(!SetThreadContext(r->handle,&c)||!context_read(r->handle,&after)||after.Eax!=c.Eax||after.Eip!=c.Eip||after.EFlags!=c.EFlags||after.SegFs!=c.SegFs||after.SegGs!=c.SegGs||after.SegEs!=c.SegEs||after.SegDs!=c.SegDs||after.SegCs!=c.SegCs||after.SegSs!=c.SegSs||after.Ebx!=c.Ebx||after.Ecx!=c.Ecx||after.Edx!=c.Edx||after.Esi!=c.Esi||after.Edi!=c.Edi||after.Ebp!=c.Ebp||after.Esp!=c.Esp||after.Dr0!=c.Dr0||after.Dr1!=c.Dr1||after.Dr2!=c.Dr2||after.Dr3!=c.Dr3||(after.Dr6&0xe00fu)||(after.Dr7&0x00ff00ffu)!=5u)return -1;
 r->hits[index]++;hits[index]++;return 1;
}
static int log_path(const char *s){unsigned n,i,start;
 if(!(s[0]=='C'&&s[1]==':'&&s[2]=='\\'))return 0;n=len(s);if(n>120)return 0;
 if(n>10&&s[3]=='V'&&s[4]=='X'&&s[5]=='D'&&s[6]=='L'&&s[7]=='A'&&s[8]=='B'&&s[9]=='\\')start=10;
 else if(n>10&&s[3]=='N'&&s[4]=='P'&&s[5]=='P'&&s[6]=='L'&&s[7]=='A'&&s[8]=='B'&&s[9]=='\\')start=10;else return 0;
 for(i=start;i<n;i++)if(!((s[i]>='A'&&s[i]<='Z')||(s[i]>='0'&&s[i]<='9')||s[i]=='_'||s[i]=='.'))return 0;
 return n-start>=5&&n-start<=64&&s[n-1]!='.';
}
static unsigned arguments(char *buffer,char **args){char *p=buffer;unsigned n=0;while(*p){int quoted=0;while(*p==' '||*p=='\t')p++;if(!*p)break;if(n==8)return 0;if(*p=='"'){quoted=1;p++;}args[n++]=p;while(*p&&(quoted?*p!='"':*p!=' '&&*p!='\t'))p++;if(quoted){if(*p!='"')return 0;*p++=0;if(*p&&*p!=' '&&*p!='\t')return 0;}else if(*p)*p++=0;}return n;}
static int drain_owned_exit(DWORD timeout,const PROCESS_INFORMATION *pi,int *process_auto,int *thread_auto){DEBUG_EVENT event;DWORD start=GetTickCount();unsigned i;
 while(GetTickCount()-start<timeout){DWORD continuation=DBG_CONTINUE;int exit_event=0;
  if(!WaitForDebugEvent(&event,100)){if(GetLastError()==ERROR_SEM_TIMEOUT)continue;put("REAP=WAIT_FAILED\r\n");return 0;}
  if(event.dwProcessId!=pid){put("REAP=FOREIGN_EVENT\r\n");return 0;}
  if(event.dwDebugEventCode==CREATE_PROCESS_DEBUG_EVENT){
   if(event.u.CreateProcessInfo.hFile&&event.u.CreateProcessInfo.hFile!=INVALID_HANDLE_VALUE)CloseHandle(event.u.CreateProcessInfo.hFile);
   *process_auto=event.u.CreateProcessInfo.hProcess==pi->hProcess;
   *thread_auto=event.u.CreateProcessInfo.hThread==pi->hThread;
   /* Creation-event thread/process handles remain borrowed. Even during
    * failure drain the OS retires them after the continued exit event. */
  }
  if(event.dwDebugEventCode==EXCEPTION_DEBUG_EVENT)continuation=DBG_EXCEPTION_NOT_HANDLED;
  if(event.dwDebugEventCode==LOAD_DLL_DEBUG_EVENT&&event.u.LoadDll.hFile&&event.u.LoadDll.hFile!=INVALID_HANDLE_VALUE)CloseHandle(event.u.LoadDll.hFile);
  if(event.dwDebugEventCode==EXIT_THREAD_DEBUG_EVENT){thread_record *r=find_thread(event.dwThreadId);if(r){r->used=0;r->handle=NULL;records--;retired++;}}
  if(event.dwDebugEventCode==EXIT_PROCESS_DEBUG_EVENT){line("TERMINATED_ACTUAL_EXIT",event.u.ExitProcess.dwExitCode);exit_event=1;}
  if(!ContinueDebugEvent(event.dwProcessId,event.dwThreadId,continuation)){put("REAP=CONTINUE_FAILED\r\n");return 0;}
  if(exit_event){for(i=0;i<THREADS;i++)if(threads[i].used){threads[i].used=0;threads[i].handle=NULL;records--;retired++;}put("REAP=OWNED_EXIT_EVENT_CONTINUED\r\n");return 1;}
 }
 put("REAP=UNCONFIRMED_TIMEOUT\r\n");return 0;
}
void WINAPI entry(void){char commandline[1024],*args[8],child_command[256];STARTUPINFOA si;PROCESS_INFORMATION pi;OSVERSIONINFOA os;DEBUG_EVENT event;DWORD target_size,high=0,got,start,exit=STILL_ACTIVE,result=30;HANDLE target=INVALID_HANDLE_VALUE;BYTE *file=NULL;unsigned i,argc;int fixture=0,created=0,initial_break=0,exited=0;
 int pi_process_auto=0,pi_thread_auto=0;
 const char *cmd=GetCommandLineA();if(len(cmd)>=sizeof(commandline))ExitProcess(20);for(i=0;(commandline[i]=cmd[i]);i++){}argc=arguments(commandline,args);
 if(argc!=5||(!eq(args[1],"--fixture")&&!eq(args[1],"--npp"))||!eq(args[2],"--log")||!log_path(args[3]))ExitProcess(20);
 fixture=eq(args[1],"--fixture");if(!eq(args[4],fixture?"C:\\VXDLAB\\ENVFIX.EXE":"C:\\NPPLAB\\APP\\NPP.EXE"))ExitProcess(20);
 log_file=CreateFileA(args[3],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(21);
 put("HELPER=NTW_NATIVE_ENVIRONMENT\r\nTARGET=");put(args[4]);put("\r\n");zero(&os,sizeof(os));os.dwOSVersionInfoSize=sizeof(os);
 if(!GetVersionExA(&os)||!env_model_make(fixture?ENV_OWNED_FIXTURE:ENV_DESKTOP,os.dwMajorVersion,os.dwMinorVersion,os.dwBuildNumber&65535,os.dwPlatformId,&model)){put("ERROR=UNSUPPORTED_HOST_ABI\r\n");goto finish;}
 put(fixture?"MODEL=OWNED_NONZERO_TEST_FIELDS\r\n":"MODEL=WIN98_ORDINARY_DESKTOP_NO_NT_SECURE_ATTRIBUTE_NO_NT_VERIFIER\r\n");line("MODEL_NTGLOBALFLAG",model.nt_global_flags);line("MODEL_PROCESS_FLAGS",model.process_flags);
 profile=fixture?&fixture_profile:&npp_profile;
 {HMODULE kernel=GetModuleHandleA("KERNEL32.DLL");FARPROC breakpoint=kernel?GetProcAddress(kernel,"DebugBreak"):NULL;
  if(!kernel||!breakpoint||(DWORD)(UINT_PTR)breakpoint!=(DWORD)(UINT_PTR)kernel+kernel_debugbreak_rva){put("ERROR=PINNED_NATIVE_DEBUGBREAK_EXPORT\r\n");goto finish;}loader_break=(DWORD)(UINT_PTR)breakpoint;line("NATIVE_DEBUGBREAK_ADDRESS",loader_break);}
 /* Keep the successfully hashed target file open, without share-write or
  * share-delete, through child execution. */
 target=CreateFileA(args[4],GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(target==INVALID_HANDLE_VALUE){put("ERROR=TARGET_OPEN\r\n");goto finish;}
 target_size=GetFileSize(target,&high);if(high||target_size!=profile->bytes||target_size>32u*1024u*1024u){put("ERROR=TARGET_SIZE\r\n");goto finish;}
 file=HeapAlloc(GetProcessHeap(),0,target_size);if(!file||!ReadFile(target,file,target_size,&got,NULL)||got!=target_size||!env_pe_gate(file,target_size,profile,&image)){put("ERROR=TARGET_HASH_OR_PE_OR_EXACT_CHAIN\r\n");goto finish;}HeapFree(GetProcessHeap(),0,file);file=NULL;put("TARGET_HASH_PE_CHAINS=PASS\r\n");
 zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);child_command[0]='"';for(i=0;args[4][i];i++)child_command[i+1]=args[4][i];child_command[i+1]='"';child_command[i+2]=0;
 if(!CreateProcessA(args[4],child_command,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,fixture?"C:\\VXDLAB":"C:\\NPPLAB\\APP",&si,&pi)){put("ERROR=CREATE_PROCESS\r\n");goto finish;}
 created=1;pid=pi.dwProcessId;start=GetTickCount();line("CHILD_PID",pid);
 while(!exited){DWORD continuation=DBG_CONTINUE;int fail=0;
  if(GetTickCount()-start>(fixture?30000u:300000u)){put("ERROR=OWNED_CHILD_TIMEOUT\r\n");result=124;break;}
  if(!WaitForDebugEvent(&event,500)){DWORD error=GetLastError();if(error==ERROR_SEM_TIMEOUT)continue;put("ERROR=WAIT_DEBUG_EVENT\r\n");line("WIN32_ERROR",error);break;}
  if(event.dwProcessId!=pid){put("ERROR=FOREIGN_PROCESS_EVENT\r\n");fail=1;}
  else switch(event.dwDebugEventCode){
   case CREATE_PROCESS_DEBUG_EVENT:
    if(event.u.CreateProcessInfo.hFile&&event.u.CreateProcessInfo.hFile!=INVALID_HANDLE_VALUE)CloseHandle(event.u.CreateProcessInfo.hFile);
    pi_process_auto=event.u.CreateProcessInfo.hProcess==pi.hProcess;
    pi_thread_auto=event.u.CreateProcessInfo.hThread==pi.hThread;
    process=event.u.CreateProcessInfo.hProcess;base=(DWORD)(UINT_PTR)event.u.CreateProcessInfo.lpBaseOfImage;
    if(records||!process||base>UINT32_MAX-image||!live_code()||!arm_thread(event.dwThreadId,event.u.CreateProcessInfo.hThread)){put("ERROR=INITIAL_THREAD_ARM\r\n");fail=1;}break;
   case CREATE_THREAD_DEBUG_EVENT:
    if(!process||!live_code()||!arm_thread(event.dwThreadId,event.u.CreateThread.hThread)){put("ERROR=WORKER_THREAD_ARM\r\n");fail=1;}break;
   case EXIT_THREAD_DEBUG_EVENT:{thread_record *r=find_thread(event.dwThreadId);if(!r){put("ERROR=UNKNOWN_THREAD_EXIT\r\n");fail=1;}else{put("THREAD_EXIT=");hex(r->id);put(" CODE=");hex(event.u.ExitThread.dwExitCode);put(" VERIFIER_HITS=");hex(r->hits[0]);put(" SECURE_HITS=");hex(r->hits[1]);put("\r\n");r->used=0;r->handle=NULL;records--;retired++;}break;}
   case EXIT_PROCESS_DEBUG_EVENT:
    exit=event.u.ExitProcess.dwExitCode;exited=1;line("ACTUAL_PROCESS_EXIT",exit);
    /* Address space may already be gone at EXIT_PROCESS; final preservation
     * is proved by every intercepted chain and the owned fixture itself. */
    for(i=0;i<THREADS;i++)if(threads[i].used){threads[i].used=0;threads[i].handle=NULL;records--;retired++;}
    break;
   case LOAD_DLL_DEBUG_EVENT:if(event.u.LoadDll.hFile&&event.u.LoadDll.hFile!=INVALID_HANDLE_VALUE)CloseHandle(event.u.LoadDll.hFile);break;
   case EXCEPTION_DEBUG_EVENT:{int emulated=0;DWORD code=event.u.Exception.ExceptionRecord.ExceptionCode;continuation=DBG_EXCEPTION_NOT_HANDLED;
    if(code==EXCEPTION_SINGLE_STEP)emulated=emulate_event(find_thread(event.dwThreadId),&event);
    if(emulated==1)continuation=DBG_CONTINUE;
    else if(emulated<0){put("ERROR=FIELD_CONTEXT_WRITE_READBACK\r\n");fail=1;}
    else if(code==EXCEPTION_BREAKPOINT&&event.u.Exception.dwFirstChance&&!initial_break&&!hits[0]&&!hits[1]&&event.dwThreadId==pi.dwThreadId&&(DWORD)(UINT_PTR)event.u.Exception.ExceptionRecord.ExceptionAddress==loader_break){BYTE bytes[2];
     if(read_remote(loader_break,bytes,2)&&bytes[0]==0xcc&&bytes[1]==0xc3){initial_break=1;put("INITIAL_LOADER_BREAKPOINT=PINNED_NATIVE_DEBUGBREAK\r\n");line("LOADER_BREAK_ADDRESS",loader_break);continuation=DBG_CONTINUE;}else{put("ERROR=LOADER_BREAK_BYTES\r\n");fail=1;}}
    else{other_exceptions++;put("UNHANDLED_EXCEPTION=PASS_TO_OS CODE=");hex(code);put(" ADDRESS=");hex((DWORD)(UINT_PTR)event.u.Exception.ExceptionRecord.ExceptionAddress);put(" FIRST_CHANCE=");hex(event.u.Exception.dwFirstChance);put("\r\n");}
    break;}
   case OUTPUT_DEBUG_STRING_EVENT:case UNLOAD_DLL_DEBUG_EVENT:break;
   default:put("ERROR=UNEXPECTED_DEBUG_EVENT\r\n");fail=1;break;
  }
  FlushFileBuffers(log_file);
  if(!ContinueDebugEvent(event.dwProcessId,event.dwThreadId,continuation)){put("ERROR=CONTINUE_DEBUG_EVENT\r\n");result=32;break;}
  if(fail){result=32;break;}
 }
 if(exited&&result!=32){
  if(exit==0&&armed>=1&&hits[1]>=1&&(!fixture||(armed==2&&hits[0]==6&&hits[1]==6&&retired==2))&&!io_failed){result=0;put(fixture?"STATUS=OWNED_DR_FIXTURE_EXECUTION_PASS\r\n":"STATUS=SCOPED_NPP_DESKTOP_EXIT_ZERO\r\n");}
  else{result=31;put("STATUS=ACTUAL_EXIT_OR_EVENT_CONTRACT_FAIL\r\n");}
 }
 if(!exited){put("STATUS=FAIL_OWNED_CHILD_TERMINATION_REQUESTED\r\n");if(!TerminateProcess(pi.hProcess,result?result:33))line("TERMINATE_ERROR",GetLastError());if(!drain_owned_exit(5000,&pi,&pi_process_auto,&pi_thread_auto)){put("OWNED_CHILD_CLOSURE=UNCONFIRMED\r\n");result=35;}}
 line("ARMED_THREADS",armed);line("RETIRED_THREADS",retired);line("VERIFIER_EVENTS",hits[0]);line("SECURE_EVENTS",hits[1]);line("OTHER_EXCEPTIONS_PASSED",other_exceptions);
finish:
 if(file)HeapFree(GetProcessHeap(),0,file);if(target!=INVALID_HANDLE_VALUE)CloseHandle(target);
 if(created){if(!pi_thread_auto)CloseHandle(pi.hThread);if(!pi_process_auto)CloseHandle(pi.hProcess);}if(io_failed)result=34;
 line("HELPER_EXIT",result);FlushFileBuffers(log_file);CloseHandle(log_file);ExitProcess(result);
}
