/* SPDX-License-Identifier: GPL-2.0-only
 * Native Kernel32-only probe; the provider is loaded explicitly, not installed.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "../src/kex_abi.h"
typedef DWORD (WINAPI *getpid_fn)(HANDLE);
typedef HANDLE (WINAPI *open_fn)(DWORD,BOOL,DWORD);
typedef BOOL (WINAPI *debug_fn)(HANDLE,PBOOL);
typedef VOID (WINAPI *capture_fn)(PCONTEXT);
typedef const m98_api_table *(__cdecl *table_fn)(void);
capture_fn capture_api;
CONTEXT captured;
DWORD expected_sp,expected_ip,returned_sp,returned_flags,returned_regs[7];
static HANDLE log_file=INVALID_HANDLE_VALUE;
static unsigned failures,checks;
static int io_failed;
static void text(const char *s){DWORD n=0,got;while(s[n])n++;if(!WriteFile(log_file,s,n,&got,NULL)||got!=n)io_failed=1;}
static void number(DWORD x){static const char hex[]="0123456789abcdef";char b[9];unsigned i;for(i=0;i<8;i++)b[i]=hex[(x>>(28-i*4))&15];b[8]=0;text(b);}
static void check(const char *name,int ok){checks++;if(!ok)failures++;text(ok?"VLCCTX_PASS=":"VLCCTX_FAIL=");text(name);text("\r\n");}
static int same(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static WORD current_fs(void){WORD value;__asm__ __volatile__("movw %%fs,%0":"=r"(value));return value;}
__attribute__((naked)) static void test_capture(void){
 __asm__ __volatile__(
  "pushfl\n\tpushal\n\tmovl %esp,_expected_sp\n\tmovl $1f,_expected_ip\n\tpushl $_captured\n\t"
  "xorl %eax,%eax\n\tstc\n\tmovl $0x11111111,%eax\n\tmovl $0x22222222,%ebx\n\tmovl $0x33333333,%ecx\n\tmovl $0x44444444,%edx\n\t"
  "movl $0x55555555,%esi\n\tmovl $0x66666666,%edi\n\tmovl $0x77777777,%ebp\n\tcall *_capture_api\n\t1:\n\t"
  "movl %eax,_returned_regs\n\tmovl %ebx,_returned_regs+4\n\tmovl %ecx,_returned_regs+8\n\tmovl %edx,_returned_regs+12\n\t"
  "movl %esi,_returned_regs+16\n\tmovl %edi,_returned_regs+20\n\tmovl %ebp,_returned_regs+24\n\tmovl %esp,_returned_sp\n\tpushfl\n\tpopl _returned_flags\n\tpopal\n\tpopfl\n\tret\n\t");
}
void WINAPI entry(void){HMODULE dll;getpid_fn getpid;open_fn openthread;debug_fn debugger;table_fn table;BOOL present=(BOOL)0x13579bdf;DWORD error,exit_code=STILL_ACTIVE;HANDLE thread,event;unsigned i;const m98_api_table *t;
 union {FARPROC generic;getpid_fn getpid;open_fn open;debug_fn debug;capture_fn capture;table_fn table;} address;
 log_file=CreateFileA("C:\\VXDLAB\\VLCCTX.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(log_file==INVALID_HANDLE_VALUE)ExitProcess(20);
 dll=LoadLibraryA("C:\\VXDLAB\\M98CTX.DLL");check("LOAD_OWN_EXACT_PROVIDER",dll!=NULL);if(!dll)goto done;
 address.generic=GetProcAddress(dll,"GetProcessId");getpid=address.getpid;
 address.generic=GetProcAddress(dll,"OpenThread");openthread=address.open;
 address.generic=GetProcAddress(dll,"CheckRemoteDebuggerPresent");debugger=address.debug;
 address.generic=GetProcAddress(dll,"RtlCaptureContext");capture_api=address.capture;
 address.generic=GetProcAddress(dll,"get_api_table");table=address.table;
 check("EXACT_FOUR_APIS_AND_TABLE",getpid&&openthread&&debugger&&capture_api&&table);if(!getpid||!openthread||!debugger||!capture_api||!table)goto unload;
 t=table();check("KEX_KERNEL32_FOUR_SORTED_ROUTES",t&&same(t[0].target_library,"KERNEL32")&&t[0].named_apis_count==4&&!t[1].target_library&&same(t[0].named_apis[0].name,"CheckRemoteDebuggerPresent")&&same(t[0].named_apis[3].name,"RtlCaptureContext"));
 check("NATIVE_SELF_PROCESS_ID",getpid(GetCurrentProcess())==GetCurrentProcessId());SetLastError(0);check("INVALID_NULL_PROCESS_ID",getpid(NULL)==0&&GetLastError()==ERROR_INVALID_HANDLE);
 check("REAL_SELF_DEBUGGER_QUERY",debugger(GetCurrentProcess(),&present));check("REAL_SELF_DEBUGGER_VALUE",present==IsDebuggerPresent());
 SetLastError(0);check("INVALID_NULL_DEBUGGER_OUTPUT",!debugger(GetCurrentProcess(),NULL)&&GetLastError()==ERROR_INVALID_PARAMETER);
 present=(BOOL)0x13579bdf;SetLastError(0);check("INVALID_PROCESS_DEBUGGER_OUTPUT_UNTOUCHED",!debugger(NULL,&present)&&GetLastError()==ERROR_INVALID_HANDLE&&present==(BOOL)0x13579bdf);
 thread=openthread(THREAD_QUERY_INFORMATION|SYNCHRONIZE,FALSE,GetCurrentThreadId());check("REAL_SELF_THREAD_OPEN",thread!=NULL);
 if(thread){check("REAL_THREAD_EXIT_QUERY",GetExitCodeThread(thread,&exit_code));check("REAL_CURRENT_THREAD_ACTIVE",exit_code==STILL_ACTIVE);check("REAL_THREAD_HANDLE_CLOSE",CloseHandle(thread));}
 SetLastError(0);check("INVALID_ZERO_THREAD_ID",!openthread(THREAD_QUERY_INFORMATION,FALSE,0)&&GetLastError()==ERROR_INVALID_PARAMETER);
 event=CreateEventA(NULL,FALSE,FALSE,NULL);check("REAL_EVENT_CREATE",event!=NULL);
 if(event){SetLastError(0);error=0;exit_code=getpid(event);error=GetLastError();check("NON_PROCESS_HANDLE_REJECTED",exit_code==0&&(error==ERROR_CALL_NOT_IMPLEMENTED||error==ERROR_INVALID_HANDLE||error==ERROR_ACCESS_DENIED));CloseHandle(event);}
 test_capture();check("CONTEXT_FLAGS_FULL_INTEGER_SEGMENTS_CONTROL",captured.ContextFlags==CONTEXT_FULL);
 check("ACTUAL_CALLER_EAX",captured.Eax==0x11111111);check("ACTUAL_CALLER_EBX",captured.Ebx==0x22222222);check("ACTUAL_CALLER_ECX",captured.Ecx==0x33333333);check("ACTUAL_CALLER_EDX",captured.Edx==0x44444444);
 check("ACTUAL_CALLER_ESI",captured.Esi==0x55555555);check("ACTUAL_CALLER_EDI",captured.Edi==0x66666666);check("ACTUAL_CALLER_EBP_WITHOUT_FRAME_POINTER",captured.Ebp==0x77777777);
 check("ACTUAL_RETURN_EIP",captured.Eip==expected_ip);check("ACTUAL_POST_STDCALL_ESP",captured.Esp==expected_sp&&returned_sp==expected_sp);
 check("ACTUAL_NATIVE_FS_SELECTOR",captured.SegFs==current_fs());check("ACTUAL_EFLAGS_CF_ZF_PF",(captured.EFlags&0x845)==0x45&&(returned_flags&0x845)==0x45);
 for(i=0;i<7;i++)check("RETURNED_REGISTERS_PRESERVED",returned_regs[i]==0x11111111u*(i+1));
unload:FreeLibrary(dll);
done:text("CHECKS=");number(checks);text("\r\nFAILURES=");number(failures);text("\r\nSTATUS=");text(failures||io_failed?"FAIL\r\n":"PASS\r\n");if(!FlushFileBuffers(log_file))io_failed=1;if(!CloseHandle(log_file))io_failed=1;ExitProcess(failures||io_failed?31:0);
}
