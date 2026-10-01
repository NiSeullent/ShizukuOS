/* SPDX-License-Identifier: GPL-2.0-only
 * Native diagnostic only. Borrowed debug-event process/thread handles are
 * retired by Windows after continued exit events; image-file handles are ours.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "observer.h"
#include "../native_environment/environment.h"
#include "profiles.h"
static rpc_runtime runtime;
static HANDLE process,report=INVALID_HANDLE_VALUE;
static DWORD pid,initial_tid,loader_break,other_exceptions,events;
static unsigned io_failed,loader_seen,timeout_seen;
static char buffer[4096];static DWORD buffered,total;
static unsigned length(const char *s){unsigned n=0;while(s[n])n++;return n;}
static int equal(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void zero(void *p,unsigned n){unsigned i;for(i=0;i<n;i++)((BYTE *)p)[i]=0;}
static void flush(void){DWORD n;if(buffered){if(!WriteFile(report,buffer,buffered,&n,NULL)||n!=buffered)io_failed=1;total+=buffered;buffered=0;}if(!FlushFileBuffers(report))io_failed=1;}
static void put(const char *s){while(*s){if(io_failed)return;if(total+buffered>=1024u*1024u){io_failed=1;return;}if(buffered==sizeof(buffer))flush();if(!io_failed)buffer[buffered++]=*s++;}}
static void hex(DWORD x){static const char a[]="0123456789ABCDEF";char b[9];unsigned i;for(i=0;i<8;i++)b[i]=a[(x>>(28-i*4))&15];b[8]=0;put(b);}
static void field(const char *key,DWORD value){put(key);put("=");hex(value);put(" ");}
static void line(const char *key,DWORD value){field(key,value);put("\r\n");}
static void from_native(const CONTEXT *c,rpc_context *r){
 r->v[R_EAX]=c->Eax;r->v[R_EBX]=c->Ebx;r->v[R_ECX]=c->Ecx;r->v[R_EDX]=c->Edx;r->v[R_ESI]=c->Esi;r->v[R_EDI]=c->Edi;r->v[R_EBP]=c->Ebp;r->v[R_ESP]=c->Esp;r->v[R_EIP]=c->Eip;r->v[R_FLAGS]=c->EFlags;
 r->v[R_CS]=c->SegCs;r->v[R_SS]=c->SegSs;r->v[R_DS]=c->SegDs;r->v[R_ES]=c->SegEs;r->v[R_FS]=c->SegFs;r->v[R_GS]=c->SegGs;
 r->v[R_DR0]=c->Dr0;r->v[R_DR1]=c->Dr1;r->v[R_DR2]=c->Dr2;r->v[R_DR3]=c->Dr3;r->v[R_DR6]=c->Dr6;r->v[R_DR7]=c->Dr7;
}
static int read_context(void *opaque,uintptr_t h,rpc_context *r){CONTEXT c;(void)opaque;zero(&c,sizeof(c));c.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_SEGMENTS|CONTEXT_DEBUG_REGISTERS;if(!GetThreadContext((HANDLE)h,&c))return 0;from_native(&c,r);return 1;}
static int write_context(uintptr_t h,const rpc_context *r,int resume){CONTEXT c;zero(&c,sizeof(c));c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 c.Dr0=r->v[R_DR0];c.Dr1=r->v[R_DR1];c.Dr2=r->v[R_DR2];c.Dr3=r->v[R_DR3];c.Dr6=r->v[R_DR6];c.Dr7=r->v[R_DR7];
 if(resume){c.ContextFlags|=CONTEXT_CONTROL;c.Ebp=r->v[R_EBP];c.Esp=r->v[R_ESP];c.Eip=r->v[R_EIP];c.EFlags=r->v[R_FLAGS];c.SegCs=r->v[R_CS];c.SegSs=r->v[R_SS];}
 /* No CONTEXT_INTEGER or CONTEXT_SEGMENTS writes. CS/SS/EIP/ESP remain exact;
  * CONTROL is required solely to publish RF for the original instruction. */
 return SetThreadContext((HANDLE)h,&c);
}
static int write_debug(void *p,uintptr_t h,const rpc_context *c){(void)p;return write_context(h,c,0);}
static int write_resume(void *p,uintptr_t h,const rpc_context *c){(void)p;return write_context(h,c,1);}
static int read_memory(void *p,uint32_t address,void *out,uint32_t n){SIZE_T got=0;(void)p;return n&&address<=UINT32_MAX-n&&ReadProcessMemory(process,(const void *)(UINT_PTR)address,out,n,&got)&&got==n;}
static rpc_ops ops={NULL,read_context,write_debug,write_resume,read_memory};
static uint32_t word(const BYTE *p){return p[0]|((DWORD)p[1]<<8)|((DWORD)p[2]<<16)|((DWORD)p[3]<<24);}
static int image_header(DWORD base,const rpc_profile *p){BYTE head[64],nt[88];DWORD pe;
 if(base>UINT32_MAX-p->image_bytes||!read_memory(NULL,base,head,64)||head[0]!='M'||head[1]!='Z')return 0;
 pe=word(head+60);if(pe!=p->pe_offset||pe>p->image_bytes||sizeof(nt)>p->image_bytes-pe||!read_memory(NULL,base+pe,nt,sizeof(nt)))return 0;
 return word(nt)==0x4550&&nt[4]==0x4c&&nt[5]==1&&((unsigned)nt[6]|((unsigned)nt[7]<<8))==p->sections&&
        word(nt+8)==p->timestamp&&nt[20]==224&&!nt[21]&&((unsigned)nt[22]|((unsigned)nt[23]<<8))==p->characteristics&&
        nt[24]==0x0b&&nt[25]==1&&word(nt+24+16)==p->entry_rva&&word(nt+24+28)==p->preferred_base&&
        word(nt+24+56)==p->image_bytes&&word(nt+24+60)==p->size_headers;
}
static int hash_handle(HANDLE h,DWORD size,const BYTE expected[32]){BYTE block[8192],digest[32];env_sha sha;DWORD original,got,left=size;int ok=0;
 original=SetFilePointer(h,0,NULL,FILE_CURRENT);if(original==INVALID_SET_FILE_POINTER)return 0;
 if(SetFilePointer(h,0,NULL,FILE_BEGIN)==INVALID_SET_FILE_POINTER)return 0;env_sha_init(&sha);
 while(left){DWORD want=left<sizeof(block)?left:(DWORD)sizeof(block);if(!ReadFile(h,block,want,&got,NULL)||got!=want)goto restore;env_sha_update(&sha,block,want);left-=want;}
 env_sha_final(&sha,digest);ok=1;for(got=0;got<32;got++)if(digest[got]!=expected[got])ok=0;
restore:
 if(SetFilePointer(h,(LONG)original,NULL,FILE_BEGIN)==INVALID_SET_FILE_POINTER)ok=0;return ok;
}
static int candidate(HANDLE h,DWORD base,const rpc_profile *profile){DWORD high=0,size,original,got;BYTE *data;int bound=0;
 if(!h||h==INVALID_HANDLE_VALUE){if(image_header(base,profile)){put("GAP=RPC_LIKE_MAPPING_WITHOUT_FILE_IDENTITY\r\n");rpc_gap(&runtime);}return 0;}
 size=GetFileSize(h,&high);if(high||size==INVALID_FILE_SIZE){put("GAP=UNINSPECTABLE_DLL_FILE\r\n");rpc_gap(&runtime);return 0;}
 if(size!=profile->file_bytes){if(image_header(base,profile)){put("GAP=RPC_LIKE_MAPPING_SIZE_MISMATCH\r\n");rpc_gap(&runtime);}return 0;}
 original=SetFilePointer(h,0,NULL,FILE_CURRENT);if(original==INVALID_SET_FILE_POINTER){rpc_gap(&runtime);return 0;}
 data=HeapAlloc(GetProcessHeap(),0,size);if(!data){rpc_gap(&runtime);return 0;}
 if(SetFilePointer(h,0,NULL,FILE_BEGIN)!=INVALID_SET_FILE_POINTER&&ReadFile(h,data,size,&got,NULL)&&got==size)bound=rpc_file_gate(data,size,profile);
 if(SetFilePointer(h,(LONG)original,NULL,FILE_BEGIN)==INVALID_SET_FILE_POINTER){bound=0;rpc_gap(&runtime);}
 HeapFree(GetProcessHeap(),0,data);
 if(!bound){if(image_header(base,profile)){put("GAP=RPC_LIKE_MAPPING_HASH_OR_FILE_GATE_FAILED\r\n");rpc_gap(&runtime);}return 0;}
 if(!image_header(base,profile)){put("GAP=BOUND_FILE_LIVE_HEADER_MISMATCH\r\n");rpc_gap(&runtime);return 0;}
 put("MODULE=EXACT_FULL_FILE_AND_LIVE_HEADER ");field("BASE",base);field("FILE_BYTES",size);put("\r\n");return rpc_bind_module(&runtime,profile,base,&ops);
}
static void unsafe_hold(const char *reason){put("STATUS=INCOMPLETE_CONTEXT_OR_EVENT_UNCONFIRMED ");put(reason);put("\r\nNO_CHILD_TERMINATION_OR_SUCCESS_FORCED=1\r\nOUTER_VM_HARD_CAP_REQUIRED=1\r\n");flush();for(;;)Sleep(100);}
static unsigned arguments(char *s,char **v){unsigned n=0;char *p=s;while(*p){int quoted=0;while(*p==' '||*p=='\t')p++;if(!*p)break;if(n==5)return 0;if(*p=='"'){quoted=1;p++;}v[n++]=p;while(*p&&(quoted?*p!='"':*p!=' '&&*p!='\t'))p++;if(quoted){if(*p!='"')return 0;*p++=0;if(*p&&*p!=' '&&*p!='\t')return 0;}else if(*p)*p++=0;}return n;}
void WINAPI entry(void){char cli[512],*argv[5];const char *command=GetCommandLineA(),*target,*log;const rpc_profile *profile;const BYTE *target_sha;DWORD target_bytes,high=0,child_exit=STILL_ACTIVE,start,result=30;HANDLE target_handle=INVALID_HANDLE_VALUE;STARTUPINFOA si;PROCESS_INFORMATION pi;OSVERSIONINFOA version;DEBUG_EVENT e;unsigned i,argc;int fixture,exited=0,created=0,process_alias=0,thread_alias=0;
 char fixture_command[]="\"C:\\VXDLAB\\RPCFIX.EXE\"";
 char vlc_command[]="C:\\VLCLAB\\VLC\\VLC.EXE --no-plugins-cache --no-media-library --no-one-instance --vout=wingdi --aout=waveout --file-logging --logfile=C:\\VLCLAB\\VIDEO.LOG --verbose=2 C:\\VLCLAB\\MEDIA\\VIDEO.AVI";
 if(length(command)>=sizeof(cli))ExitProcess(20);for(i=0;(cli[i]=command[i]);i++){}argc=arguments(cli,argv);
 if(argc!=4||(!equal(argv[1],"--fixture")&&!equal(argv[1],"--vlc"))||!equal(argv[2],"--log"))ExitProcess(20);
 fixture=equal(argv[1],"--fixture");log=fixture?"C:\\VXDLAB\\RPCDBG.LOG":"C:\\VXDLAB\\RPCVLC.LOG";if(!equal(argv[3],log))ExitProcess(20);
 target=fixture?"C:\\VXDLAB\\RPCFIX.EXE":"C:\\VLCLAB\\VLC\\VLC.EXE";profile=fixture?&fixture_profile:&native_rpc_profile;target_sha=fixture?fixture_target_sha:vlc_target_sha;target_bytes=fixture?fixture_target_bytes:vlc_target_bytes;
 report=CreateFileA(log,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 put("HELPER=RPC_LIFECYCLE_OBSERVER\r\nNO_OEM_CODE_OR_STATE_WRITES=1\r\nNO_EIP_SKIP_OR_FIELD_EMULATION=1\r\nAPPLICATION_PASS=0\r\nMODE=");put(fixture?"OWNED_FIXTURE":"FIXED_UNCHANGED_VLC");put("\r\n");
 zero(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);if(!GetVersionExA(&version)||version.dwMajorVersion!=4||version.dwMinorVersion!=10||(version.dwBuildNumber&65535)!=2222||version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS){put("ERROR=NATIVE_WIN98_ABI_REQUIRED\r\n");goto finish;}
 {HMODULE kernel=GetModuleHandleA("KERNEL32.DLL");FARPROC f=kernel?GetProcAddress(kernel,"DebugBreak"):NULL;if(!kernel||!f||(DWORD)(UINT_PTR)f!=(DWORD)(UINT_PTR)kernel+kernel_debugbreak_rva){put("ERROR=NATIVE_DEBUGBREAK_IDENTITY\r\n");goto finish;}loader_break=(DWORD)(UINT_PTR)f;}
 target_handle=CreateFileA(target,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);if(target_handle==INVALID_HANDLE_VALUE||GetFileSize(target_handle,&high)!=target_bytes||high||!hash_handle(target_handle,target_bytes,target_sha)){put("ERROR=EXACT_TARGET_FILE_IDENTITY\r\n");goto finish;}
 zero(&si,sizeof(si));zero(&pi,sizeof(pi));si.cb=sizeof(si);if(!CreateProcessA(target,fixture?fixture_command:vlc_command,NULL,NULL,FALSE,DEBUG_ONLY_THIS_PROCESS,NULL,fixture?"C:\\VXDLAB":"C:\\VLCLAB\\VLC",&si,&pi)){DWORD error=GetLastError();line("CREATE_PROCESS_ERROR",error);goto finish;}
 created=1;pid=pi.dwProcessId;initial_tid=pi.dwThreadId;start=GetTickCount();line("CREATED_PID",pid);put("TIME_BUDGET_GUEST_MS=000927C0\r\nTIMEOUT_CONTINUES_TRANSPARENTLY_UNTIL_REAL_EXIT_OR_OUTER_VM_CAP=1\r\n");
 while(!exited){DWORD continuation=DBG_CONTINUE,retire=0;int process_exit=0,action=0;
  if(!timeout_seen&&GetTickCount()-start>=600000u){timeout_seen=1;rpc_gap(&runtime);put("INCOMPLETE=GUEST_TIME_BUDGET_EXCEEDED_NO_TERMINATION\r\n");}
  if(!WaitForDebugEvent(&e,500)){DWORD error=GetLastError();if(error==ERROR_SEM_TIMEOUT)continue;rpc_gap(&runtime);line("WAIT_DEBUG_ERROR",error);unsafe_hold("WAIT_DEBUG_EVENT_FAILED");}
  if(e.dwProcessId!=pid)unsafe_hold("FOREIGN_PROCESS_EVENT");if(events==UINT32_MAX){rpc_gap(&runtime);}else events++;
  field("EVENT",e.dwDebugEventCode);field("TID",e.dwThreadId);field("NUMBER",events);put("\r\n");
  switch(e.dwDebugEventCode){
   case CREATE_PROCESS_DEBUG_EVENT:
    process_alias=e.u.CreateProcessInfo.hProcess==pi.hProcess;thread_alias=e.u.CreateProcessInfo.hThread==pi.hThread;process=e.u.CreateProcessInfo.hProcess;
    if(e.u.CreateProcessInfo.hFile&&e.u.CreateProcessInfo.hFile!=INVALID_HANDLE_VALUE&&!CloseHandle(e.u.CreateProcessInfo.hFile)){rpc_gap(&runtime);}
    if(!process)unsafe_hold("NO_BORROWED_PROCESS_HANDLE");field("CREATE_INITIAL_START",(DWORD)(UINT_PTR)e.u.CreateProcessInfo.lpStartAddress);field("TDB",(DWORD)(UINT_PTR)e.u.CreateProcessInfo.lpThreadLocalBase);put("\r\n");action=rpc_add_thread(&runtime,e.dwThreadId,(uintptr_t)e.u.CreateProcessInfo.hThread,&ops);break;
   case CREATE_THREAD_DEBUG_EVENT:
    field("CREATE_THREAD_START_APPROX",(DWORD)(UINT_PTR)e.u.CreateThread.lpStartAddress);field("TDB",(DWORD)(UINT_PTR)e.u.CreateThread.lpThreadLocalBase);put("\r\n");action=rpc_add_thread(&runtime,e.dwThreadId,(uintptr_t)e.u.CreateThread.hThread,&ops);break;
   case LOAD_DLL_DEBUG_EVENT:
    field("LOAD_BASE",(DWORD)(UINT_PTR)e.u.LoadDll.lpBaseOfDll);field("FILE_HANDLE_AVAILABLE",e.u.LoadDll.hFile&&e.u.LoadDll.hFile!=INVALID_HANDLE_VALUE);put("\r\n");
    action=candidate(e.u.LoadDll.hFile,(DWORD)(UINT_PTR)e.u.LoadDll.lpBaseOfDll,profile);
    if(e.u.LoadDll.hFile&&e.u.LoadDll.hFile!=INVALID_HANDLE_VALUE&&!CloseHandle(e.u.LoadDll.hFile))rpc_gap(&runtime);break;
   case UNLOAD_DLL_DEBUG_EVENT:
    line("UNLOAD_BASE",(DWORD)(UINT_PTR)e.u.UnloadDll.lpBaseOfDll);if(runtime.base==(DWORD)(UINT_PTR)e.u.UnloadDll.lpBaseOfDll)action=rpc_unbind_module(&runtime,&ops);break;
   case EXIT_THREAD_DEBUG_EVENT:line("THREAD_ACTUAL_EXIT",e.u.ExitThread.dwExitCode);retire=e.dwThreadId;break;
   case EXIT_PROCESS_DEBUG_EVENT:child_exit=e.u.ExitProcess.dwExitCode;line("CHILD_ACTUAL_EXIT",child_exit);process_exit=1;break;
   case EXCEPTION_DEBUG_EVENT:{rpc_context c;DWORD code=e.u.Exception.ExceptionRecord.ExceptionCode,address=(DWORD)(UINT_PTR)e.u.Exception.ExceptionRecord.ExceptionAddress;continuation=DBG_EXCEPTION_NOT_HANDLED;
    action=rpc_observe(&runtime,e.dwThreadId,code,e.u.Exception.dwFirstChance,address,&ops,&c);
    if(action==RPC_ENTRY||action==RPC_STORE){DWORD state_value=0,flag=0,stack[8];int state_ok=read_memory(NULL,runtime.base+profile->state_rva,&state_value,4),flag_ok=read_memory(NULL,runtime.base+profile->flag_rva,&flag,4),stack_ok=read_memory(NULL,c.v[R_ESP],stack,sizeof(stack));
     put(action==RPC_ENTRY?"OBSERVE=DLL_ENTRY_PRE_INSTRUCTION ":"OBSERVE=STATE_STORE_PRE_INSTRUCTION ");field("TID",e.dwThreadId);field("EIP",c.v[R_EIP]);field("EAX",c.v[R_EAX]);field("EDI_STORE_VALUE",c.v[R_EDI]);field("STATE_VALID",state_ok);field("STATE",state_value);field("FLAG_VALID",flag_ok);field("FLAG",flag);field("ESP",c.v[R_ESP]);field("FS",c.v[R_FS]);field("DR6_INPUT",c.v[R_DR6]);put("\r\n");
     if(stack_ok){put("STACK=");for(i=0;i<8;i++){hex(stack[i]);put(" ");}put("\r\n");if(action==RPC_ENTRY){field("RETURN_ADDRESS",stack[0]);field("HINSTANCE",stack[1]);field("REASON",stack[2]);field("RESERVED",stack[3]);put("\r\n");if(stack[1]!=runtime.base||stack[2]>3)rpc_gap(&runtime);}}
     else{rpc_gap(&runtime);put("GAP=STACK_READ\r\n");}if(!state_ok||!flag_ok)rpc_gap(&runtime);put("RESUME=ORIGINAL_EIP_RF_ONLY_OWNED_DR_STATUS_CLEARED_CONTEXT_READBACK_PASS\r\n");continuation=DBG_CONTINUE;
    }else if(action==RPC_PASS&&code==EXCEPTION_BREAKPOINT&&e.u.Exception.dwFirstChance==1&&!loader_seen&&e.dwThreadId==initial_tid&&address==loader_break){BYTE bytes[2];if(read_memory(NULL,loader_break,bytes,2)&&bytes[0]==0xcc&&bytes[1]==0xc3){loader_seen=1;put("INITIAL_BREAK=EXACT_NATIVE_DEBUGBREAK_ONE_TIME\r\n");continuation=DBG_CONTINUE;}}
    if(continuation==DBG_EXCEPTION_NOT_HANDLED){if(other_exceptions==UINT32_MAX)rpc_gap(&runtime);else other_exceptions++;put("EXCEPTION=PASS_TO_ORIGINAL_OS ");field("CODE",code);field("ADDRESS",address);field("FIRST_CHANCE",e.u.Exception.dwFirstChance);put("\r\n");}break;
   }
   case OUTPUT_DEBUG_STRING_EVENT:put("OUTPUT_DEBUG_STRING=NOT_DEREFERENCED\r\n");break;
   default:rpc_gap(&runtime);put("GAP=UNSUPPORTED_DEBUG_EVENT\r\n");break;
  }
  if(action==RPC_UNSAFE)unsafe_hold("CONTEXT_WRITE_OR_READBACK_UNCONFIRMED");flush();if(io_failed)rpc_gap(&runtime);
  /* Never wait for another event or retire borrowed handles until this exact
   * event has been successfully continued. Persistent failure holds it. */
  if(!ContinueDebugEvent(e.dwProcessId,e.dwThreadId,continuation)){DWORD error=GetLastError();line("CONTINUE_DEBUG_ERROR",error);unsafe_hold("CONTINUE_EVENT_UNCONFIRMED");}
  if(retire)rpc_retire_thread(&runtime,retire);if(process_exit){rpc_retire_process(&runtime);exited=1;}
 }
 result=rpc_complete(&runtime)&&loader_seen&&!io_failed?0:31;put(result?"STATUS=TRACE_INCOMPLETE\r\n":"STATUS=TRACE_COMPLETE_CHILD_EXIT_OBSERVED_NO_APPLICATION_VERDICT\r\n");
 line("THREADS_CREATED",runtime.created);line("THREAD_EXIT_EVENTS",runtime.exit_threads);line("PROCESS_EXIT_RETIRED",runtime.process_retired);line("ARMS",runtime.arms);line("RESTORES",runtime.restores);line("MODULE_GENERATIONS",runtime.generations);line("ENTRY_HITS",runtime.hits[0]);line("STORE_HITS",runtime.hits[1]);line("OTHER_EXCEPTIONS_PASSED",other_exceptions);line("CHILD_ACTUAL_EXIT_REPEATED",child_exit);
finish:
 if(target_handle!=INVALID_HANDLE_VALUE&&!CloseHandle(target_handle))io_failed=1;
 if(created){if(!thread_alias&&!CloseHandle(pi.hThread))io_failed=1;if(!process_alias&&!CloseHandle(pi.hProcess))io_failed=1;}
 line("OBSERVER_SELECTED_EXIT",io_failed?34:result);put("OBSERVER_OWN_OS_EXIT_REQUIRES_OUTER_NATIVE_WAIT=1\r\nAPPLICATION_PASS=0\r\n");flush();if(!CloseHandle(report))io_failed=1;ExitProcess(io_failed?34:result);
}
