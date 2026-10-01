/* SPDX-License-Identifier: GPL-2.0-only
 * Opt-in Win98 native network probe. It has no endpoint or CA defaults. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "m98_tls13_native.h"
#ifndef M98_NET_PROBE_NONCE
#error A fresh frozen nonce is required
#endif
#ifndef M98_NET_SHA256
#error Frozen adjacent adapter identity is required
#endif
#ifndef M98_CLIENT_SHA256
#error Frozen adjacent backend identity is required
#endif
_Static_assert(sizeof(m98_net_options)==36,"native API ABI");
_Static_assert(sizeof(m98_net_details)==36,"native diagnostics ABI");
static HANDLE log_file=INVALID_HANDLE_VALUE;
static int log_good=1;
static void clear(void *p,size_t n){unsigned char *b=p;while(n--)*b++=0;}
static size_t length(const char *s){size_t n=0;while(s[n])++n;return n;}
static void log_text(const char *s){DWORD done,n=(DWORD)length(s);
    if(!WriteFile(log_file,s,n,&done,NULL)||done!=n)log_good=0;
}
static void number(uint32_t n){char b[11];unsigned i=sizeof(b);b[--i]=0;
    do{b[--i]=(char)('0'+n%10);n/=10;}while(n);log_text(b+i);
}
static void signed_number(int32_t n){if(n<0){log_text("-");number((uint32_t)(-(int64_t)n));}else number((uint32_t)n);}
static void field(const char *name,uint32_t value){log_text(name);log_text("=");number(value);log_text("\r\n");}
static void result_field(const char *name,int value){log_text(name);log_text("=");signed_number(value);log_text("\r\n");}
static int module_at(HMODULE module,const char *path){char actual[MAX_PATH];DWORD n;
    n=GetModuleFileNameA(module,actual,sizeof(actual));return n&&n<sizeof(actual)&&!lstrcmpiA(actual,path);
}
static int read_file(const char *path,unsigned char *p,DWORD capacity,DWORD *bytes){HANDLE file;DWORD high=0,n,done=0;int ok;
    file=CreateFileA(path,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)return 0;
    n=GetFileSize(file,&high);ok=!high&&n!=INVALID_FILE_SIZE&&n>0&&n<capacity;
    if(ok)ok=ReadFile(file,p,n,&done,NULL)&&done==n;
    if(!CloseHandle(file))ok=0;
    if(ok){p[n]=0;*bytes=n;}return ok;
}
static int line(char **cursor,const char *key,char **value){char *p=*cursor;size_t i;
    for(i=0;key[i];++i)if(p[i]!=key[i])return 0;
    p+=i;*value=p;
    while(*p&&*p!='\r'){if((unsigned char)*p<32||(unsigned char)*p>126)return 0;++p;}
    if(!*p||p[1]!='\n')return 0;
    *p=0;*cursor=p+2;return 1;
}
static int decimal(const char *p,uint32_t max,uint32_t *out){uint32_t n=0;unsigned count=0;
    if(!*p)return 0;
    while(*p){unsigned d=(unsigned char)*p++-'0';if(d>9||++count>10||n>(max-d)/10)return 0;n=n*10+d;}
    *out=n;return 1;
}
static int ipv4(char *p,uint8_t out[4]){unsigned i;char *start=p;uint32_t n;
    for(i=0;i<4;++i){while(*p&&*p!='.')++p;
        if(i<3){if(*p!='.')return 0;*p++=0;}else if(*p)return 0;
        if(!decimal(start,255,&n))return 0;
        out[i]=(uint8_t)n;start=p;
    }return 1;
}
static int config(char *buf,m98_net_options *o){char *cursor=buf,*value;uint32_t n;
    if(!line(&cursor,"ipv4=",&value)||!ipv4(value,o->ipv4))return 0;
    if(!line(&cursor,"port=",&value)||!decimal(value,65535,&n)||!n)return 0;
    o->port=(uint16_t)n;
    if(!line(&cursor,"hostname=",&value)||!length(value)||length(value)>253)return 0;
    o->hostname=value;
    if(!line(&cursor,"connect_ms=",&value)||!decimal(value,300000,&o->connect_ms)||!o->connect_ms)return 0;
    if(!line(&cursor,"handshake_ms=",&value)||!decimal(value,300000,&o->handshake_ms)||!o->handshake_ms)return 0;
    if(!line(&cursor,"io_ms=",&value)||!decimal(value,300000,&o->io_ms)||!o->io_ms)return 0;
    return !*cursor;
}
#define BIND(field,name) do{FARPROC address=GetProcAddress(module,name);size_t bi; \
    if(!address||sizeof(address)!=sizeof(field))goto finish; \
    for(bi=0;bi<sizeof(field);++bi)((unsigned char *)&field)[bi]=((unsigned char *)&address)[bi]; \
}while(0)
void mainCRTStartup(void){OSVERSIONINFOA version;HMODULE module=NULL;unsigned char *ca=NULL;
    char configuration[512];DWORD bytes=0;uint32_t i,started;size_t count,total;
    unsigned char forward[3072],reverse[1021];m98_net_options options;m98_net_handle handle=0;
    m98_net_details detail;int passed=0,result=-999,closed=1;DWORD exit_code=2;
    int (*open_net)(const m98_net_options *,m98_net_handle *)=NULL;
    int (*write_net)(m98_net_handle,const void *,size_t,size_t *)=NULL;
    int (*read_net)(m98_net_handle,void *,size_t,size_t *)=NULL;
    int (*shutdown_net)(m98_net_handle)=NULL;
    int (*close_net)(m98_net_handle)=NULL;
    int (*info_net)(m98_net_handle,m98_net_details *)=NULL;
    log_file=CreateFileA("C:\\GOPLAB\\NET13.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(2);
    log_text("M98NET native network probe v1\r\nnonce=" M98_NET_PROBE_NONCE "\r\n");
    log_text("expected_adapter_sha256=" M98_NET_SHA256 "\r\nexpected_backend_sha256=" M98_CLIENT_SHA256 "\r\n");
    clear(&version,sizeof(version));version.dwOSVersionInfoSize=sizeof(version);
    if(!GetVersionExA(&version))goto finish;
    field("os_major",version.dwMajorVersion);field("os_minor",version.dwMinorVersion);
    field("os_build",version.dwBuildNumber&0xffff);field("os_platform",version.dwPlatformId);
    if(version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS||version.dwMajorVersion!=4||version.dwMinorVersion!=10||
       (version.dwBuildNumber&0xffff)!=2222||!module_at(NULL,"C:\\GOPLAB\\NET13PR.EXE"))goto finish;
    clear(&options,sizeof(options));options.size=sizeof(options);
    if(!read_file("C:\\GOPLAB\\NET13.CFG",(unsigned char *)configuration,sizeof(configuration),&bytes))goto finish;
    for(i=0;i<bytes;++i)if(!configuration[i])goto finish;
    if(!config(configuration,&options))goto finish;
    log_text("hostname=");log_text(options.hostname);log_text("\r\n");
    field("port",options.port);field("connect_ms",options.connect_ms);field("handshake_ms",options.handshake_ms);field("io_ms",options.io_ms);
    ca=HeapAlloc(GetProcessHeap(),0,1u<<20);if(!ca)goto finish;
    if(!read_file("C:\\GOPLAB\\NETCA.PEM",ca,1u<<20,&bytes))goto finish;
    options.ca_pem=ca;options.ca_bytes=bytes+1;field("ca_file_bytes",bytes);
    module=LoadLibraryA("C:\\GOPLAB\\M98NET.DLL");
    if(!module||!module_at(module,"C:\\GOPLAB\\M98NET.DLL"))goto finish;
    field("adapter_path_verified",1);
    BIND(open_net,"m98_net_open");BIND(write_net,"m98_net_write");BIND(read_net,"m98_net_read");
    BIND(shutdown_net,"m98_net_shutdown");BIND(close_net,"m98_net_close");BIND(info_net,"m98_net_info");
    result=open_net(&options,&handle);result_field("open_result",result);if(result||!handle)goto finish;
    if(!module_at(GetModuleHandleA("M98TLS13.DLL"),"C:\\GOPLAB\\M98TLS13.DLL"))goto finish;
    field("backend_path_verified",1);detail.size=sizeof(detail);
    if(info_net(handle,&detail)||detail.phase!=M98_NET_READY||!detail.established||detail.verify_flags)goto finish;
    field("client_verify_flags",detail.verify_flags);field("client_established",detail.established);
    for(i=0;i<sizeof(forward);++i)forward[i]=(unsigned char)(i*17+3);
    count=0;result=write_net(handle,forward,sizeof(forward),&count);result_field("write_result",result);field("written",(uint32_t)count);
    if(result||count!=sizeof(forward))goto finish;
    total=0;started=GetTickCount();
    for(i=0;i<sizeof(reverse)&&total<sizeof(reverse);++i){
        if(GetTickCount()-started>=options.io_ms)goto finish;
        count=0;result=read_net(handle,reverse+total,sizeof(reverse)-total,&count);
        if(result||!count||count>sizeof(reverse)-total)goto finish;
        total+=count;
    }
    field("read_bytes",(uint32_t)total);if(total!=sizeof(reverse))goto finish;
    for(i=0;i<sizeof(reverse);++i)if(reverse[i]!=(unsigned char)(i*31+9))goto finish;
    field("bidirectional_payload_verified",1);
    result=shutdown_net(handle);result_field("shutdown_result",result);if(result)goto finish;
    passed=1;
finish:
    if(handle&&info_net){detail.size=sizeof(detail);if(!info_net(handle,&detail)){
        result_field("last_result",detail.result);result_field("backend_error",detail.backend_error);
        field("verify_flags",detail.verify_flags);field("os_error",detail.os_error);
        field("cleanup_pending",detail.cleanup_pending);field("cleanup_error",detail.cleanup_error);
    }}
    if(handle){closed=close_net&&close_net(handle)==0;if(!closed)passed=0;field("owned_handle_closed",closed);}
    if(ca){clear(ca,1u<<20);if(!HeapFree(GetProcessHeap(),0,ca))passed=0;}
    if(module&&closed&&!FreeLibrary(module))passed=0;
    log_text(passed?"component_result=PASS\r\n":"component_result=FAIL\r\n");
    log_text("peer_authenticated_close_verified=0\r\nos_tls_integrated=0\r\napplications_verified=0\r\n");
    log_text("actual_child_exit=externally_observed_only\r\n");
    if(passed&&log_good&&FlushFileBuffers(log_file))exit_code=0;
    if(!CloseHandle(log_file))exit_code=2;
    ExitProcess(exit_code);
}
