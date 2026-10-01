/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
typedef DWORD (WINAPI *snapshot_fn)(void);
static HANDLE report=INVALID_HANDLE_VALUE;
static unsigned failed,checks,io_failed;
static snapshot_fn snapshot;
static BYTE entry_copy[32],store_copy[6];
static const BYTE *entry_code,*store;
static DWORD fs_self(void){DWORD x;__asm__ volatile("movl %%fs:0x18,%0":"=r"(x));return x;}
static DWORD fs_pdb(void){DWORD x;__asm__ volatile("movl %%fs:0x30,%0":"=r"(x));return x;}
static DWORD fs_tls(void){DWORD x;__asm__ volatile("movl %%fs:0x2c,%0":"=r"(x));return x;}
static WORD fs_word(void){WORD x;__asm__ volatile("movw %%fs,%0":"=r"(x));return x;}
static void put(const char *s){DWORD n=0,written;while(s[n])n++;if(!WriteFile(report,s,n,&written,NULL)||written!=n)io_failed=1;}
static void check(const char *name,int ok){checks++;if(!ok)failed++;put(ok?"RPCFIX_PASS ":"RPCFIX_FAIL ");put(name);put("\r\n");}
static void fail_live_worker(void){put("STATUS=FAIL_LIVE_WORKER_NO_DLL_UNMAP\r\n");if(!FlushFileBuffers(report))io_failed=1;if(!CloseHandle(report))io_failed=1;ExitProcess(42);}
static int same_code(void){unsigned i;for(i=0;i<32;i++)if(entry_code[i]!=entry_copy[i])return 0;for(i=0;i<6;i++)if(store[i]!=store_copy[i])return 0;return 1;}
static DWORD WINAPI worker(void *p){DWORD self=fs_self(),pdb=fs_pdb(),tls=fs_tls();WORD segment=fs_word();(void)p;
 check("REAL_DLL_THREAD_ATTACH_PUBLISHED_STATE",(snapshot()&3u)==1u);
 check("ORIGINAL_ENTRY_AND_STORE_BYTES",same_code());
 check("NATIVE_FS_SELF_PDB_TLS_SEGMENT_UNCHANGED",self==fs_self()&&pdb==fs_pdb()&&tls==fs_tls()&&segment==fs_word());return 0;
}
static int generation(void){HMODULE module=LoadLibraryA("C:\\VXDLAB\\RPFIX.DLL");HANDLE thread;DWORD tid,exit=STILL_ACTIVE,wait;BOOL queried;unsigned i;union{FARPROC generic;snapshot_fn typed;}f;DWORD self=fs_self(),pdb=fs_pdb(),tls=fs_tls();WORD segment=fs_word();
 check("REAL_NATIVE_LOAD_DLL",module!=NULL);if(!module)return 0;
 f.generic=GetProcAddress(module,"rpcfix_snapshot");snapshot=f.typed;entry_code=(const BYTE *)module;
 {DWORD pe=*(const DWORD *)(entry_code+60);entry_code=(const BYTE *)module+*(const DWORD *)((const BYTE *)module+pe+24+16);}
 store=(const BYTE *)(UINT_PTR)GetProcAddress(module,"rpcfix_store_site");check("ACTUAL_OWN_EXPORTS",snapshot!=NULL&&store!=NULL);if(!snapshot||!store){FreeLibrary(module);return 0;}
 for(i=0;i<32;i++)entry_copy[i]=entry_code[i];for(i=0;i<6;i++)store_copy[i]=store[i];
 check("REAL_PROCESS_ATTACH_STATE",(snapshot()&3u)==1u);
 for(i=0;i<3;i++){
  thread=CreateThread(NULL,0,worker,NULL,0,&tid);check("REAL_NATIVE_THREAD_CREATE",thread!=NULL);if(!thread){FreeLibrary(module);return 0;}
  wait=WaitForSingleObject(thread,10000);queried=GetExitCodeThread(thread,&exit);
  check("REAL_NATIVE_THREAD_WAIT",wait==WAIT_OBJECT_0);
  if(wait!=WAIT_OBJECT_0)fail_live_worker();
  check("REAL_NATIVE_THREAD_EXIT_QUERY",queried);check("REAL_NATIVE_THREAD_EXIT_ZERO",queried&&exit==0);
  if(!CloseHandle(thread))io_failed=1;
 }
 check("ORIGINAL_CODE_AFTER_NATIVE_CALLBACKS",same_code());
 {DWORD value=snapshot();check("REAL_DLL_THREAD_NOTIFY_COUNTS",((value>>8)&255u)>=3u&&((value>>16)&255u)>=3u);}
 check("NATIVE_MAIN_FS_SELF_PDB_TLS_SEGMENT_UNCHANGED",self==fs_self()&&pdb==fs_pdb()&&tls==fs_tls()&&segment==fs_word());
 check("REAL_NATIVE_FREE_DLL",FreeLibrary(module));snapshot=NULL;entry_code=store=NULL;return 1;
}
void WINAPI entry(void){OSVERSIONINFOA os={0};report=CreateFileA("C:\\VXDLAB\\RPCFIX.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);if(report==INVALID_HANDLE_VALUE)ExitProcess(20);
 put("SCOPE=OWNED_REAL_DLL_THREAD_AND_RF_TRANSPARENCY_FIXTURE\r\nNO_MICROSOFT_MODULE_REPLACED=1\r\n");os.dwOSVersionInfoSize=sizeof(os);check("ACTUAL_NATIVE_WIN98",GetVersionExA(&os)&&os.dwMajorVersion==4&&os.dwMinorVersion==10&&(os.dwBuildNumber&65535)==2222&&os.dwPlatformId==1);
 if(!failed&&generation())generation();put(failed||io_failed?"STATUS=FAIL\r\n":"STATUS=OWNED_FIXTURE_PASS\r\n");
 if(!FlushFileBuffers(report))io_failed=1;if(!CloseHandle(report))io_failed=1;ExitProcess(failed||io_failed?31:0);
}
