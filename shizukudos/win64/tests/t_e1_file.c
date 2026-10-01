/* SPDX-License-Identifier: GPL-2.0-only
 * E1 kernel file contracts: NUL device and native FileAllInformation.
 * Layout/length contract: Microsoft FILE_ALL_INFORMATION (ntifs.h); independent canary and scalar assertions. */
#define _WIN32_WINNT 0x0A00
#include "k32test.h"
#include <stddef.h>
typedef struct { LONG status; ULONG pad; ULONG_PTR information; } ios_t;
typedef LONG (NTAPI *query_t)(HANDLE, ios_t *, void *, ULONG, ULONG);
static ULONG get32(const BYTE *p) { ULONG x; memcpy(&x,p,4); return x; }
static ULONGLONG get64(const BYTE *p) { ULONGLONG x; memcpy(&x,p,8); return x; }
static int untouched(const BYTE *p, unsigned from, unsigned end) { unsigned i; for(i=from;i<end;i++) if(p[i]!=0xA5)return 0; return 1; }
int main(void)
{
 HANDLE h; DWORD n=0; BYTE b[1024]; ios_t io; LONG st;
 query_t query=(query_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationFile");
 static const WCHAR path[]=L"C:\\T_E1_FILE\\unicode_\u00e9_\u4e2d.txt";
 static const WCHAR name[]=L"\\T_E1_FILE\\unicode_\u00e9_\u4e2d.txt";
 CHECK(query!=NULL,"native file query is exported"); if(!query)return k32t_finish("T_E1_FILE");
 h=CreateFileW(L"NuL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
 CHECK(h!=INVALID_HANDLE_VALUE,"case-insensitive NUL opens");
 if(h!=INVALID_HANDLE_VALUE){
 CHECK(GetFileType(h)==FILE_TYPE_CHAR,"NUL is a character device");
 CHECK(WriteFile(h,"discard-me",10,&n,NULL)&&n==10,"NUL discards every written byte");
 b[0]=0xA5;n=99;CHECK(ReadFile(h,b,1,&n,NULL)&&n==0&&b[0]==0xA5,"NUL reads end of file without changing caller data");
 CHECK(CloseHandle(h),"NUL handle closes");
 }
 h=CreateFileW(L"\\\\.\\NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,OPEN_EXISTING,0,NULL);
 CHECK(h!=INVALID_HANDLE_VALUE,"device-prefix NUL opens");
 if(h!=INVALID_HANDLE_VALUE){n=99;CHECK(!WriteFile(h,"x",1,&n,NULL)&&GetLastError()==ERROR_ACCESS_DENIED,"NUL enforces read-only access");CloseHandle(h);}
 CreateDirectoryW(L"C:\\T_E1_FILE",NULL);
 h=CreateFileW(path,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
 CHECK(h!=INVALID_HANDLE_VALUE,"Unicode test file created");
 if(h!=INVALID_HANDLE_VALUE){
 CHECK(WriteFile(h,"hello",5,&n,NULL)&&n==5,"test file stores five bytes");
 memset(b,0xA5,sizeof b);memset(&io,0,sizeof io);st=query(h,&io,b,sizeof b,18);
 CHECK(st==0&&io.status==0,"FileAllInformation succeeds");
 CHECK(get64(b+48)==5&&get64(b+80)==5,"file length and current position match the actual write");
 CHECK(get64(b+64)!=0&&get32(b+88)==0x20,"file id is nonzero and synchronous mode matches open flags");
 CHECK(get32(b+96)==sizeof(name)-2&&memcmp(b+100,name,sizeof(name)-2)==0,"native full name preserves Unicode exactly");
 CHECK(io.information==100+sizeof(name)-2,"IOSB records exactly the initialized bytes");
 CHECK(untouched(b,(unsigned)io.information,sizeof b),"full query leaves bytes beyond returned length untouched");
 memset(b,0xA5,sizeof b);st=query(h,&io,b,103,18);
 CHECK((ULONG)st==0xC0000004u&&untouched(b,0,sizeof b),"undersized fixed structure is rejected without buffer writes");
 memset(b,0xA5,sizeof b);st=query(h,&io,b,104,18);
 CHECK((ULONG)st==0x80000005u&&io.information==104&&get32(b+96)==sizeof(name)-2,"truncated name reports overflow and full required name length");
 CHECK(memcmp(b+100,name,4)==0&&untouched(b,104,sizeof b),"truncated copy uses whole UTF-16 units and preserves canary");
 CloseHandle(h);DeleteFileW(path);
 }
 {
 WCHAR deep[120]=L"C:\\T_E1_FILE"; int i,len=k32t_wlen(deep); BOOL made=TRUE;
 for(i=0;i<26;i++){deep[len++]='\\';deep[len++]='x';deep[len]=0;if(!CreateDirectoryW(deep,NULL))made=FALSE;}
 CHECK(made,"26 nested directories created without hitting the old 24-node truncation");
 deep[len++]='\\';deep[len++]='f';deep[len]=0;
 h=CreateFileW(deep,GENERIC_READ|GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
 CHECK(h!=INVALID_HANDLE_VALUE,"deep test file opens");
 if(h!=INVALID_HANDLE_VALUE){
 st=query(h,&io,b,sizeof b,18);
 CHECK(st==0&&get32(b+96)==(ULONG)(len-2)*2&&memcmp(b+100,deep+2,(len-2)*2)==0,"FileAllInformation includes every directory past depth 24");
 st=query(h,&io,b,sizeof b,9);
 CHECK(st==0&&get32(b)==(ULONG)(len-2)*2&&memcmp(b+4,deep+2,(len-2)*2)==0,"FileNameInformation uses the same complete deep name");
 CloseHandle(h);DeleteFileW(deep);
 }
 len-=2;deep[len]=0;
 for(i=0;i<26;i++){RemoveDirectoryW(deep);len-=2;deep[len]=0;}
 }
 RemoveDirectoryW(L"C:\\T_E1_FILE");
 return k32t_finish("T_E1_FILE");
}
