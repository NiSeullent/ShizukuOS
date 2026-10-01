/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
static HANDLE report=INVALID_HANDLE_VALUE;
static CRITICAL_SECTION lock;
static unsigned failures,checks;
static int bad_io;
__attribute__((naked,noinline)) DWORD __cdecl env_verifier(void){__asm__ __volatile__(".byte 0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x68,0xc1,0xe8,8,0x24,1,0xc3");}
__attribute__((naked,noinline)) DWORD __cdecl env_secure(void){__asm__ __volatile__(".byte 0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x10,0x8b,0x40,8,0xc1,0xe8,0x1f,0xc3");}
static void check(const char *s,int ok){DWORD n=0,wrote;const char *prefix=ok?"ENVFIX_PASS=":"ENVFIX_FAIL=";
 EnterCriticalSection(&lock);checks++;if(!ok)failures++;while(prefix[n])n++;if(!WriteFile(report,prefix,n,&wrote,NULL)||wrote!=n)bad_io=1;n=0;while(s[n])n++;if(!WriteFile(report,s,n,&wrote,NULL)||wrote!=n)bad_io=1;
 if(!WriteFile(report,"\r\n",2,&wrote,NULL)||wrote!=2)bad_io=1;
 LeaveCriticalSection(&lock);
}
static DWORD fsword(unsigned off){DWORD value;__asm__ __volatile__("movl %%fs:(%1),%0":"=r"(value):"r"(off):"memory");return value;}
static int functions_unchanged(void){
 static const unsigned char a[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x68,0xc1,0xe8,8,0x24,1,0xc3};
 static const unsigned char b[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x10,0x8b,0x40,8,0xc1,0xe8,0x1f,0xc3};unsigned i;
 for(i=0;i<sizeof(a);i++)if(((const unsigned char *)(UINT_PTR)env_verifier)[i]!=a[i])return 0;
 for(i=0;i<sizeof(b);i++)if(((const unsigned char *)(UINT_PTR)env_secure)[i]!=b[i])return 0;return 1;
}
static DWORD WINAPI worker(void *arg){DWORD tib=fsword(0x18),pdb=fsword(0x30),tls=fsword(0x2c);unsigned i;(void)arg;
 for(i=0;i<3;i++){check("WORKER_VERIFIER_NATIVE_SHIFT_AND",env_verifier()==0x00135701u);check("WORKER_SECURE_NATIVE_SHIFT",env_secure()==1);}
 check("WORKER_ORIGINAL_FS_SELF_PDB_TLS",tib==fsword(0x18)&&pdb==fsword(0x30)&&tls==fsword(0x2c));check("WORKER_ORIGINAL_CODE",functions_unchanged());return failures?41:0;
}
void WINAPI entry(void){HANDLE thread;DWORD id,exit=STILL_ACTIVE,wait,tib=fsword(0x18),pdb=fsword(0x30),tls=fsword(0x2c);unsigned i;
 report=CreateFileA("C:\\VXDLAB\\ENVFIX.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(20);InitializeCriticalSection(&lock);
 for(i=0;i<3;i++){check("MAIN_VERIFIER_NATIVE_SHIFT_AND",env_verifier()==0x00135701u);check("MAIN_SECURE_NATIVE_SHIFT",env_secure()==1);}
 check("MAIN_ORIGINAL_FS_SELF_PDB_TLS",tib==fsword(0x18)&&pdb==fsword(0x30)&&tls==fsword(0x2c));check("MAIN_ORIGINAL_CODE",functions_unchanged());
 thread=CreateThread(NULL,0,worker,NULL,0,&id);check("REAL_THREAD_CREATE",thread!=NULL);
 if(thread){wait=WaitForSingleObject(thread,10000);check("REAL_THREAD_WAIT",wait==WAIT_OBJECT_0);if(wait!=WAIT_OBJECT_0){FlushFileBuffers(report);ExitProcess(42);}check("REAL_THREAD_EXIT_QUERY",GetExitCodeThread(thread,&exit));check("REAL_THREAD_EXIT_ZERO",exit==0);CloseHandle(thread);}
 DeleteCriticalSection(&lock);FlushFileBuffers(report);CloseHandle(report);ExitProcess(failures||bad_io?31:0);
}
