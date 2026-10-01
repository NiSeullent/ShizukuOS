/* SPDX-License-Identifier: GPL-2.0-only */
#define SHZ_SEARCH_PATH_HOST_TEST
#include "../kernel32/k32_search_path.c"
static unsigned checks, registry_reads, registry_closes;
static int registry_value=-1;
static DWORD registry_type=4, registry_length=4;
static const WCHAR *files[]={L"C:\\sys\\kernel32.dll",L"D:\\cwd\\kernel32.dll",L"D:\\cwd\\tool.exe",L"E:\\path\\remote.exe",L"D:\\cwd\\thing.dat",L"D:\\cwd\\\ub3c4\uad6c.exe",NULL};
static int eq(const WCHAR*a,const WCHAR*b){while(*a&&*a==*b){++a;++b;}return *a==*b;}
#define VERIFY(v) do {++checks;if(!(v)){fprintf(stderr,"FAIL line%d\n",__LINE__);exit(1);}}while(0)
static DWORD copy_w(LPCWSTR in,LPWSTR out,DWORD cap){DWORD n=(DWORD)k32_wlen(in);if(cap<=n)return n+1;memcpy(out,in,(n+1)*2);return n;}
static NTSTATUS NtOpenKey(HANDLE*h,DWORD access,SHZ_OBJECT_ATTRIBUTES*a){++registry_reads;VERIFY(access==1&&a->Attributes==0x40&&eq(a->ObjectName->Buffer,L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager"));if(registry_value<0)return (NTSTATUS)0xc0000034;*h=(HANDLE)(uintptr_t)7;return 0;}
static NTSTATUS NtQueryValueKey(HANDLE h,SHZ_UNICODE_STRING*n,DWORD cls,void*out,ULONG cap,ULONG*len){DWORD result[4]={0,registry_type,registry_length,(DWORD)registry_value};VERIFY(h==(HANDLE)(uintptr_t)7&&cls==2&&cap==16&&eq(n->Buffer,L"SafeProcessSearchMode"));memcpy(out,result,16);*len=16;return 0;}
static NTSTATUS NtClose(HANDLE h){VERIFY(h==(HANDLE)(uintptr_t)7);++registry_closes;return 0;}
static DWORD GetFileAttributesW(LPCWSTR path){unsigned i;if(eq(path,L"D:\\cwd\\dir"))return FILE_ATTRIBUTE_DIRECTORY;for(i=0;files[i];++i)if(eq(path,files[i]))return 0x20;SetLastError(ERROR_FILE_NOT_FOUND);return INVALID_FILE_ATTRIBUTES;}
static DWORD GetFullPathNameW(LPCWSTR p,DWORD cap,LPWSTR out,LPWSTR*part){DWORD r=copy_w(p,out,cap);if(r<cap&&part){WCHAR*at=out;*part=out;while(*at){if(*at=='\\')*part=at+1;++at;}}return r;}
static DWORD GetModuleFileNameW(HMODULE h,LPWSTR out,DWORD cap){(void)h;return copy_w(L"C:\\app\\probe.exe",out,cap);}
static DWORD GetSystemDirectoryW(LPWSTR out,DWORD cap){return copy_w(L"C:\\sys",out,cap);}
static DWORD GetWindowsDirectoryW(LPWSTR out,DWORD cap){return copy_w(L"C:\\win",out,cap);}
static DWORD GetCurrentDirectoryW(DWORD cap,LPWSTR out){return copy_w(L"D:\\cwd",out,cap);}
static DWORD GetEnvironmentVariableW(LPCWSTR name,LPWSTR out,DWORD cap){VERIFY(eq(name,L"PATH"));return copy_w(L"E:\\missing;E:\\path",out,cap);}
/* Host adapter exercises ASCII ANSI buffer/error contracts only. Genuine
 * Unicode conversion is covered by the unchanged native platform codec. */
static int MultiByteToWideChar(unsigned cp,DWORD flags,LPCSTR s,int len,LPWSTR out,int cap){int n=0;(void)cp;(void)flags;VERIFY(len==-1);while(s[n]){if((unsigned char)s[n]>127)return 0;++n;}++n;if(n>cap)return 0;for(int i=0;i<n;++i)out[i]=(unsigned char)s[i];return n;}
static int WideCharToMultiByte(unsigned cp,DWORD flags,LPCWSTR s,int len,LPSTR out,int cap,LPCSTR def,BOOL*used){int n=0;(void)cp;(void)flags;(void)def;(void)used;VERIFY(len==-1);while(s[n]){if(s[n]>127)return 0;++n;}++n;if(!out)return n;if(n>cap)return 0;for(int i=0;i<n;++i)out[i]=(char)s[i];return n;}
static void expect_path(const WCHAR*want){WCHAR out[260];VERIFY(SearchPathW(NULL,L"kernel32.dll",NULL,260,out,NULL)==k32_wlen(want));VERIFY(eq(out,want));}
static void *race_mode(void *arg){uintptr_t id=(uintptr_t)arg;for(unsigned i=0;i<5000;++i){DWORD f=(i+id)%2?1:0x10000;if(!SetSearchPathMode(f)||last_error==ERROR_INVALID_PARAMETER)return (void*)1;}return NULL;}
int main(void){WCHAR out[520],before[520],*part=(WCHAR*)(uintptr_t)0x1234;char ansi[520],*apart;DWORD count;
expect_path(L"D:\\cwd\\kernel32.dll");registry_value=1;expect_path(L"C:\\sys\\kernel32.dll");registry_value=0;expect_path(L"D:\\cwd\\kernel32.dll");registry_type=1;registry_value=1;expect_path(L"D:\\cwd\\kernel32.dll");registry_type=4;registry_length=8;expect_path(L"D:\\cwd\\kernel32.dll");registry_length=4;
for(unsigned i=0;i<8;++i){DWORD invalid[]={0,2,0x80,0x8000,0x10001,0x18000,0x80000001,0xffffffff};VERIFY(!SetSearchPathMode(invalid[i])&&last_error==ERROR_INVALID_PARAMETER);}VERIFY(process_search_mode==0);
last_error=0xabc;VERIFY(SetSearchPathMode(1)&&last_error==0xabc);count=registry_reads;registry_value=0;expect_path(L"C:\\sys\\kernel32.dll");VERIFY(registry_reads==count);VERIFY(SetSearchPathMode(0x10000));expect_path(L"D:\\cwd\\kernel32.dll");
VERIFY(SearchPathW(L"C:\\sys;D:\\cwd",L"kernel32.dll",NULL,520,out,&part)>0&&eq(out,L"C:\\sys\\kernel32.dll")&&eq(part,L"kernel32.dll"));
VERIFY(SearchPathW(NULL,L"tool",L".exe",520,out,NULL)>0&&eq(out,L"D:\\cwd\\tool.exe"));VERIFY(SearchPathW(NULL,L"thing.dat",L".exe",520,out,NULL)>0&&eq(out,L"D:\\cwd\\thing.dat"));VERIFY(SearchPathW(NULL,L"remote",L".exe",520,out,NULL)>0&&eq(out,L"E:\\path\\remote.exe"));VERIFY(SearchPathW(NULL,L"D:\\cwd\\\ub3c4\uad6c",L".exe",520,out,NULL)>0&&eq(out,L"D:\\cwd\\\ub3c4\uad6c.exe"));
memset(out,0x55,sizeof out);memcpy(before,out,sizeof out);part=(WCHAR*)(uintptr_t)0x1234;VERIFY(SearchPathW(NULL,L"tool.exe",NULL,1,out,&part)==16&&memcmp(out,before,sizeof out)==0&&part==(WCHAR*)(uintptr_t)0x1234);
VERIFY(SearchPathW(NULL,L"tool.exe",NULL,0,NULL,NULL)==16);VERIFY(!SearchPathW(NULL,NULL,NULL,0,NULL,NULL)&&last_error==ERROR_INVALID_PARAMETER);VERIFY(!SearchPathW(NULL,L"tool.exe",NULL,1,NULL,NULL)&&last_error==ERROR_INVALID_PARAMETER);VERIFY(!SearchPathW(NULL,L"dir",NULL,520,out,NULL)&&last_error==ERROR_FILE_NOT_FOUND);
VERIFY(SearchPathA(NULL,"tool.exe",NULL,520,ansi,&apart)==15&&strcmp(ansi,"D:\\cwd\\tool.exe")==0&&strcmp(apart,"tool.exe")==0);VERIFY(SearchPathA(NULL,"tool.exe",NULL,0,NULL,NULL)==16);VERIFY(!SearchPathA(NULL,"\xff",NULL,520,ansi,NULL));
last_error=0;pthread_t ts[8];for(uintptr_t i=0;i<8;++i)VERIFY(!pthread_create(&ts[i],NULL,race_mode,(void*)i));for(unsigned i=0;i<8;++i){void*r;VERIFY(!pthread_join(ts[i],&r)&&!r);}
VERIFY(SetSearchPathMode(0x8001));expect_path(L"C:\\sys\\kernel32.dll");VERIFY(!SetSearchPathMode(1)&&last_error==ERROR_ACCESS_DENIED);VERIFY(!SetSearchPathMode(0x10000)&&last_error==ERROR_ACCESS_DENIED);VERIFY(SetSearchPathMode(0x8001));VERIFY(!SetSearchPathMode(0)&&last_error==ERROR_INVALID_PARAMETER);expect_path(L"C:\\sys\\kernel32.dll");VERIFY(registry_closes==4);printf("SEARCH_PATH_HOST: %u checks PASS;40000 concurrent mode transitions\n",checks);return 0;}
