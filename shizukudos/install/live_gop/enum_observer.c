/* SPDX-License-Identifier: GPL-2.0-only
 * Read-only Win98 Display registry observer. No setup/class/default mutation.
 * Output is a fresh private C:\GPENUM.JSON; no product key or registry dump.
 */
#ifdef SHZ_ENUM_OBSERVER_HOSTTEST
#include "enum_observer_host.h"
#else
#include <windows.h>
#endif
#define MAX_KEYS 16384u
#define MAX_DEPTH 8u
#define MAX_PATH_BYTES 256u
static HANDLE output=INVALID_HANDLE_VALUE;
static DWORD started,keys,devices;
static unsigned length(const char *s){unsigned n=0;while(s[n])++n;return n;}
static int write_bytes(const char *s,unsigned n){DWORD done=0;return WriteFile(output,s,n,&done,NULL)&&done==n;}
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
void mainCRTStartup(void)
{
    OSVERSIONINFOA version;unsigned char *bytes=(unsigned char *)&version;HKEY root=NULL;int ok=0;
    for(unsigned i=0;i<sizeof version;++i)bytes[i]=0;
    version.dwOSVersionInfoSize=sizeof version;
    if(!GetVersionExA(&version)||version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||version.dwMajorVersion!=4||version.dwMinorVersion!=10)ExitProcess(2);
    if(RegOpenKeyExA(HKEY_LOCAL_MACHINE,"Enum",0,KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS,&root)!=ERROR_SUCCESS)ExitProcess(3);
    output=CreateFileA("C:\\GPENUM.JSON",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(output==INVALID_HANDLE_VALUE){RegCloseKey(root);ExitProcess(4);}
    started=GetTickCount();keys=devices=0;
    ok=text("{\"schema\":\"shizukuos.win98-display-enum-observation.v1\",\"scope\":\"HKLM Enum Display and Driver only\",\"devices\":[")&&visit(root,"Enum",0)&&devices&&
       text("],\"display_count\":")&&number(devices)&&text(",\"default_GOP_registered\":false,\"Windows98_on_ShizukuDOS\":false}\r\n");
    if(RegCloseKey(root)!=ERROR_SUCCESS)ok=0;
    if(ok&&!FlushFileBuffers(output))ok=0;
    if(!CloseHandle(output))ok=0;
    output=INVALID_HANDLE_VALUE;
    if(!ok){if(!DeleteFileA("C:\\GPENUM.JSON"))ExitProcess(6);ExitProcess(5);}
    ExitProcess(0);
}
