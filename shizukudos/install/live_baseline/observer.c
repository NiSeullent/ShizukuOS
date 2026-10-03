/* SPDX-License-Identifier: GPL-2.0-only
 * Owner-nonce-bound readonly Win98 version/Display observer. No approval.
 * Output is a fresh private C:\BASEOBS.JSON; no product key or registry dump.
 */
#ifdef SHZ_BASELINE_OBSERVER_HOSTTEST
#include "observer_host.h"
#else
#include <windows.h>
#endif
#define MAX_KEYS 16384u
#define MAX_DEPTH 8u
#define MAX_PATH_BYTES 256u
static HANDLE output=INVALID_HANDLE_VALUE;
static HANDLE nonce_file=INVALID_HANDLE_VALUE;
static unsigned char nonce[32];
static unsigned report_bytes;
static DWORD started,keys,devices;
static unsigned length(const char *s){unsigned n=0;while(s[n])++n;return n;}
static int write_bytes(const char *s,unsigned n){DWORD done=0;if(n>(4u<<20)-report_bytes)return 0;
    if(!WriteFile(output,s,n,&done,NULL)||done!=n)return 0;
    report_bytes+=n;return 1;}
static int text(const char *s){return write_bytes(s,length(s));}
static int quoted(const char *s)
{
    static const char hex[]="0123456789abcdef";
    if(!text("\""))return 0;
    for(unsigned i=0;s[i];++i){unsigned char c=(unsigned char)s[i];
        if(c=='\\'||c=='\"'){char b[2]={'\\',(char)c};if(!write_bytes(b,2))return 0;}
        else if(c<32||c>=127){char b[6]={'\\','u','0','0',hex[c>>4],hex[c&15]};if(!write_bytes(b,6))return 0;}
        else if(!write_bytes(s+i,1))return 0;
    }
    return text("\"");
}
static int number(DWORD n){char b[11];unsigned at=sizeof b;b[--at]=0;do{b[--at]=(char)('0'+n%10);n/=10;}while(n);return text(b+at);}
static int value(HKEY key,const char *name,char *buffer,DWORD cap,int optional)
{
    DWORD size=cap,type=0;LONG result=RegQueryValueExA(key,name,NULL,&type,(LPBYTE)buffer,&size);
    if(result==ERROR_FILE_NOT_FOUND&&optional)return 0;
    if(result!=ERROR_SUCCESS||type!=REG_SZ||!size||size>cap||buffer[size-1])return -1;
    for(DWORD i=0;i+1<size;++i)if(!buffer[i])return -1;
    return 1;
}
static int visit(HKEY key,const char *path,unsigned depth)
{
    char klass[32],driver[256];int found;
    if(++keys>MAX_KEYS||(DWORD)(GetTickCount()-started)>60000u)return 0;
    found=value(key,"Class",klass,sizeof klass,1);if(found<0)return 0;
    if(found&&lstrcmpiA(klass,"Display")==0){
        if(value(key,"Driver",driver,sizeof driver,0)!=1)return 0;
        if((devices&&!text(","))||!text("{\"enum_key\":")||!quoted(path)||!text(",\"driver\":")||!quoted(driver)||!text("}"))return 0;
        ++devices;
    }
    for(DWORD index=0;;++index){
        char name[MAX_PATH_BYTES],child[MAX_PATH_BYTES];DWORD size=sizeof name;HKEY opened=NULL;
        LONG result=RegEnumKeyExA(key,index,name,&size,NULL,NULL,NULL,NULL);
        if(result==ERROR_NO_MORE_ITEMS)return 1;
        if(result!=ERROR_SUCCESS||!size||size>=sizeof name||name[size]||depth>=MAX_DEPTH)return 0;
        unsigned parent=length(path);if(parent+1+size>=sizeof child)return 0;
        for(unsigned i=0;i<parent;++i)child[i]=path[i];
        child[parent]='\\';
        for(DWORD i=0;i<=size;++i)child[parent+1+i]=name[i];
        result=RegOpenKeyExA(key,name,0,KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS,&opened);
        if(result!=ERROR_SUCCESS)return 0;
        int ok=visit(opened,child,depth+1);if(RegCloseKey(opened)!=ERROR_SUCCESS)ok=0;
        if(!ok)return 0;
    }
}
static int nonce_read(unsigned char out[32]) {
    DWORD high=0,done=0;
    return GetFileSize(nonce_file,&high)==32 && !high &&
           SetFilePointer(nonce_file,0,NULL,FILE_BEGIN)==0 &&
           ReadFile(nonce_file,out,32,&done,NULL) && done==32;
}
static int nonce_current(void) {
    unsigned char current[32];
    if(!nonce_read(current))return 0;
    for(unsigned i=0;i<32;i++)if(current[i]!=nonce[i])return 0;
    return 1;
}
static int nonce_text(void) {
    static const char hex[]="0123456789abcdef";char pair[2];
    if(!text("\""))return 0;
    for(unsigned i=0;i<32;i++){pair[0]=hex[nonce[i]>>4];pair[1]=hex[nonce[i]&15];if(!write_bytes(pair,2))return 0;}
    return text("\"");
}
static void version_zero(OSVERSIONINFOA *version) {
    unsigned char *bytes=(unsigned char *)version;
    for(unsigned i=0;i<sizeof *version;++i)bytes[i]=0;
    version->dwOSVersionInfoSize=sizeof *version;
}
void mainCRTStartup(void)
{
    OSVERSIONINFOA version,second;HKEY root=NULL;int ok=0;unsigned nonzero=0;
    version_zero(&version);
    if(!GetVersionExA(&version)||version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||version.dwMajorVersion!=4||version.dwMinorVersion!=10)ExitProcess(2);
    nonce_file=CreateFileA("C:\\BASENONC.BIN",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(nonce_file==INVALID_HANDLE_VALUE)ExitProcess(7);
    if(!nonce_read(nonce)){CloseHandle(nonce_file);ExitProcess(7);}
    for(unsigned i=0;i<32;i++)nonzero|=nonce[i];
    if(!nonzero){CloseHandle(nonce_file);ExitProcess(7);}
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"Enum",0,KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS,&root)!=ERROR_SUCCESS){CloseHandle(nonce_file);ExitProcess(3);}
    output=CreateFileA("C:\\BASEOBS.JSON",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(output==INVALID_HANDLE_VALUE){RegCloseKey(root);CloseHandle(nonce_file);ExitProcess(4);}
    started=GetTickCount();keys=devices=report_bytes=0;
    ok=text("{\"schema\":\"shizukuos.win98-baseline-observation.v1\",\"nonce_hex\":")&&nonce_text()&&
       text(",\"platform_id\":")&&number(version.dwPlatformId)&&text(",\"major\":")&&number(version.dwMajorVersion)&&
       text(",\"minor\":")&&number(version.dwMinorVersion)&&text(",\"build_raw\":")&&number(version.dwBuildNumber)&&
       text(",\"scope\":\"Win9x4.10 and HKLM Enum Display Class/Driver only\",\"devices\":[")&&visit(root,"Enum",0)&&devices&&
       text("],\"display_count\":")&&number(devices)&&text(",\"observation_only\":true,\"source_approval\":false,\"Windows98_on_ShizukuDOS\":false}\r\n");
    if(RegCloseKey(root)!=ERROR_SUCCESS)ok=0;
    version_zero(&second);
    if(!GetVersionExA(&second)||second.dwPlatformId!=version.dwPlatformId||second.dwMajorVersion!=version.dwMajorVersion||
       second.dwMinorVersion!=version.dwMinorVersion||second.dwBuildNumber!=version.dwBuildNumber||!nonce_current())ok=0;
    if(!CloseHandle(nonce_file))ok=0;
    nonce_file=INVALID_HANDLE_VALUE;
    if(ok&&!FlushFileBuffers(output))ok=0;
    if(!CloseHandle(output))ok=0;
    output=INVALID_HANDLE_VALUE;
    if(!ok){if(!DeleteFileA("C:\\BASEOBS.JSON"))ExitProcess(6);ExitProcess(5);}
    ExitProcess(0);
}
