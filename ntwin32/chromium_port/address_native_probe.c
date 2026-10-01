/* SPDX-License-Identifier: GPL-2.0-only
 * Executes only owned process-local wait code and classic Win98 services. */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
typedef BOOL (WINAPI *wait_fn)(volatile void *,void *,SIZE_T,DWORD);
typedef void (WINAPI *wake_fn)(void *);
typedef DWORD (WINAPI *pending_fn)(void);
typedef BOOL (WINAPI *cleanup_fn)(DWORD);
static wait_fn address_wait;static wake_fn wake_single,wake_all;
static pending_fn pending;static cleanup_fn cleanup;
static HANDLE log=INVALID_HANDLE_VALUE;static unsigned checks,failures;static int io_failed;
static DWORD address,other,compare;
typedef struct result {BOOL okay;DWORD error;} result;
static DWORD length(const char *s){DWORD n=0;while(s[n])n++;return n;}
static void text(const char *s){DWORD n=length(s),written=0;if(!WriteFile(log,s,n,&written,0)||written!=n)io_failed=1;}
static void check(const char *label,int okay){checks++;text(okay?"PASS ":"FAIL ");text(label);text("\r\n");if(!okay)failures++;}
static void number(DWORD n){char digits[12];unsigned i=0;do{digits[i++]=(char)('0'+n%10);n/=10;}while(n);while(i){char s[2]={digits[--i],0};text(s);}}
static int registered(DWORD n){DWORD start=GetTickCount();do{if(pending()==n)return 1;Sleep(1);}while(GetTickCount()-start<2000);return 0;}
static DWORD WINAPI worker(void *p){result *r=p;r->okay=address_wait(&address,&compare,4,3000);r->error=r->okay?0:GetLastError();return r->okay?0:1;}
static void run(void)
{
 HMODULE dll=0;DWORD start,version=GetVersion(),exit_code,i;HANDLE threads[3]={0};result results[3]={{0}};int may_unload=1;
 check("actual native Win98 4.10",(version&0xffff)==0x0a04&&(version&0x80000000u));if(failures)return;
 dll=LoadLibraryA("C:\\VXDLAB\\M98ADDR.DLL");check("private owned address provider loaded",dll!=0);if(!dll)return;
 address_wait=(wait_fn)(UINT_PTR)GetProcAddress(dll,"WaitOnAddress");wake_single=(wake_fn)(UINT_PTR)GetProcAddress(dll,"WakeByAddressSingle");wake_all=(wake_fn)(UINT_PTR)GetProcAddress(dll,"WakeByAddressAll");
 pending=(pending_fn)GetProcAddress(dll,"M98AddressPending");cleanup=(cleanup_fn)GetProcAddress(dll,"M98AddressCleanup");
 check("five exact stdcall provider exports",address_wait&&wake_single&&wake_all&&pending&&cleanup);if(failures)goto done;
 compare=1;check("different address value returns immediately",address_wait(&address,&compare,4,1000));compare=0;
 check("invalid comparison size reports 87",!address_wait(&address,&compare,3,100)&&GetLastError()==ERROR_INVALID_PARAMETER);
 check("zero timeout reports real timeout error",!address_wait(&address,&compare,4,0)&&GetLastError()==ERROR_TIMEOUT);
 start=GetTickCount();check("real event wait times out",!address_wait(&address,&compare,4,30)&&GetLastError()==ERROR_TIMEOUT);
 check("actual native event timeout elapsed",GetTickCount()-start>=15&&GetTickCount()-start<1500);
 check("cleanup requires explicit joined declaration",!cleanup(0)&&GetLastError()==ERROR_BUSY);
 for(i=0;i<3;i++){threads[i]=CreateThread(0,0,worker,&results[i],0,0);check("native waiter thread created",threads[i]!=0);if(!threads[i])break;check("native waiter registered in FIFO",registered(i+1));}
 if(i==3&&!failures){
  wake_all(&other);check("different address wakes no thread",pending()==3&&WaitForSingleObject(threads[0],0)==WAIT_TIMEOUT);
  check("live waiter cleanup refused",!cleanup(1)&&GetLastError()==ERROR_BUSY);
  wake_single(&address);check("first registered real native worker wakes",WaitForSingleObject(threads[0],1500)==WAIT_OBJECT_0&&GetExitCodeThread(threads[0],&exit_code)&&exit_code==0&&results[0].okay);
  check("single wake leaves second and third asleep",WaitForSingleObject(threads[1],0)==WAIT_TIMEOUT&&WaitForSingleObject(threads[2],0)==WAIT_TIMEOUT);
 }
 wake_all(&address);
 for(i=0;i<3;i++)if(threads[i]){
  DWORD wait=WaitForSingleObject(threads[i],5000);
  check("every native worker joined normally",wait==WAIT_OBJECT_0&&GetExitCodeThread(threads[i],&exit_code)&&exit_code==0&&results[i].okay&&!results[i].error);
  if(wait!=WAIT_OBJECT_0){text("STATUS=LIVE_WORKER_NO_PROVIDER_UNLOAD\r\n");FlushFileBuffers(log);ExitProcess(30);}
  check("real native worker handle closed",CloseHandle(threads[i]));
 }
 check("no native waiters remain",!pending());may_unload=cleanup(1);check("explicit joined provider cleanup",may_unload);
done:
 if(may_unload)check("owned provider unloaded after joined workers",FreeLibrary(dll));
 else text("OWNED_PROVIDER_RETAINED_UNTIL_PROCESS_EXIT=1\r\n");
}
void WINAPI entry(void)
{
 log=CreateFileA("C:\\VXDLAB\\CHADDR.LOG",GENERIC_WRITE,0,0,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,0);if(log==INVALID_HANDLE_VALUE)ExitProcess(10);
 text("SCOPE=OWNED_NATIVE_ADDRESS_WAIT_NOT_APPLICATION_ACCEPTANCE\r\nAPPLICATION_EXECUTED=0\r\n");run();text("CHECKS=");number(checks);text(" FAILURES=");number(failures);text("\r\n");text(failures?"STATUS=FAIL\r\n":"STATUS=SCOPED_NATIVE_ADDRESS_WAIT_PASS\r\n");
 if(!FlushFileBuffers(log))io_failed=1;if(!CloseHandle(log))io_failed=1;ExitProcess(io_failed?11:failures?1:0);
}
