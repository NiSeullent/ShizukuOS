/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98 Winsock 1.1/CryptoAPI platform. No external state mutation.
 */
#define M98_NET_IMPLEMENTATION
#ifdef M98_NET_WIN32_TEST
#include "../tests/m98_tls13_native_win32_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <winsock.h>
#include <wincrypt.h>
#endif
#include "m98_tls13_native.h"
static HMODULE own_module, backend_module, socket_module, crypto_module;
static SOCKET owned_socket=INVALID_SOCKET;
static HCRYPTPROV provider;
static int wsa_live;
static uint32_t last_error;
static int (WINAPI *net_start)(WORD,LPWSADATA);
static int (WINAPI *net_stop)(void);
static SOCKET (WINAPI *net_socket)(int,int,int);
static int (WINAPI *net_ioctl)(SOCKET,long,u_long *);
static int (WINAPI *net_connect)(SOCKET,const struct sockaddr *,int);
static int (WINAPI *net_select)(int,fd_set *,fd_set *,fd_set *,const struct timeval *);
static int (WINAPI *net_getopt)(SOCKET,int,int,char *,int *);
static int (WINAPI *net_send)(SOCKET,const char *,int,int);
static int (WINAPI *net_recv)(SOCKET,char *,int,int);
static int (WINAPI *net_close)(SOCKET);
static int (WINAPI *net_shutdown)(SOCKET,int);
static int (WINAPI *net_error)(void);
static BOOL (WINAPI *crypto_acquire)(HCRYPTPROV *,LPCSTR,LPCSTR,DWORD,DWORD);
static BOOL (WINAPI *crypto_random)(HCRYPTPROV,DWORD,BYTE *);
static BOOL (WINAPI *crypto_release)(HCRYPTPROV,DWORD);
static void zero(void *p,size_t n){unsigned char *b=p;while(n--)*b++=0;}
static size_t text_length(const char *s){size_t n=0;while(s[n])++n;return n;}
static int checked_path(HMODULE module,const char *expected){char actual[MAX_PATH];DWORD n;
    n=GetModuleFileNameA(module,actual,sizeof(actual));
    return n&&n<sizeof(actual)&&lstrcmpiA(actual,expected)==0;
}
static HMODULE load_at(char *path,const char *name,UINT prefix){size_t i,n=text_length(name);HMODULE module;
    if(!prefix||prefix>=MAX_PATH||n>=MAX_PATH-prefix){last_error=ERROR_BAD_PATHNAME;return NULL;}
    for(i=0;i<=n;++i)path[prefix+i]=name[i];
    module=LoadLibraryA(path);
    if(!module){last_error=GetLastError();return NULL;}
    if(!checked_path(module,path)){
        last_error=ERROR_INVALID_DATA;
        /* Preserve even an unexpected loaded handle until controlled cleanup. */
        return module;
    }
    return module;
}
#define BIND(module,field,name) do { \
    FARPROC fn=GetProcAddress(module,name); \
    if(!fn||sizeof(fn)!=sizeof(field)){last_error=ERROR_PROC_NOT_FOUND;return M98_NET_LOAD;} \
    {const unsigned char *from=(const unsigned char *)&fn;unsigned char *to=(unsigned char *)&(field);size_t bi; \
     for(bi=0;bi<sizeof(field);++bi)to[bi]=from[bi];} \
}while(0)
static int start(m98_net_backend *api){char adjacent[MAX_PATH],system[MAX_PATH],crt_path[MAX_PATH];
    UINT prefix;DWORD n;WSADATA data;int status;size_t i;
    if(backend_module||socket_module||crypto_module||provider||wsa_live||owned_socket!=INVALID_SOCKET)
        return M98_NET_CLEANUP;
    last_error=0;
    n=GetModuleFileNameA(own_module,adjacent,sizeof(adjacent));
    if(!own_module||!n||n>=sizeof(adjacent)){last_error=ERROR_BAD_PATHNAME;return M98_NET_LOAD;}
    while(n&&adjacent[n-1]!='\\')--n;
    backend_module=load_at(adjacent,"M98TLS13.DLL",n);
    if(!backend_module||last_error)return M98_NET_LOAD;
    BIND(backend_module,api->create,"m98_tls_create");
    BIND(backend_module,api->handshake,"m98_tls_handshake");
    BIND(backend_module,api->write,"m98_tls_write");
    BIND(backend_module,api->read,"m98_tls_read");
    BIND(backend_module,api->shutdown,"m98_tls_shutdown");
    BIND(backend_module,api->backend_error,"m98_tls_backend_error");
    BIND(backend_module,api->verify_flags,"m98_tls_verify_flags");
    BIND(backend_module,api->is_established,"m98_tls_is_established");
    BIND(backend_module,api->free,"m98_tls_free");
    prefix=GetSystemDirectoryA(system,sizeof(system));
    if(!prefix||prefix>=MAX_PATH-14){last_error=ERROR_BAD_PATHNAME;return M98_NET_LOAD;}
    system[prefix++]='\\';system[prefix]=0;
    for(i=0;i<=prefix;++i)crt_path[i]=system[i];
    for(i=0;i<sizeof("MSVCRT.DLL");++i)crt_path[prefix+i]="MSVCRT.DLL"[i];
    {HMODULE crt=GetModuleHandleA("MSVCRT.DLL");
     if(!crt||!checked_path(crt,crt_path)){last_error=ERROR_INVALID_DATA;return M98_NET_LOAD;}}
    socket_module=load_at(system,"WSOCK32.DLL",prefix);
    if(!socket_module||last_error)return M98_NET_LOAD;
    BIND(socket_module,net_start,"WSAStartup");BIND(socket_module,net_stop,"WSACleanup");
    BIND(socket_module,net_socket,"socket");BIND(socket_module,net_ioctl,"ioctlsocket");
    BIND(socket_module,net_connect,"connect");BIND(socket_module,net_select,"select");
    BIND(socket_module,net_getopt,"getsockopt");BIND(socket_module,net_send,"send");
    BIND(socket_module,net_recv,"recv");BIND(socket_module,net_close,"closesocket");
    BIND(socket_module,net_shutdown,"shutdown");
    BIND(socket_module,net_error,"WSAGetLastError");
    crypto_module=load_at(system,"ADVAPI32.DLL",prefix);
    if(!crypto_module||last_error)return M98_NET_LOAD;
    BIND(crypto_module,crypto_acquire,"CryptAcquireContextA");
    BIND(crypto_module,crypto_random,"CryptGenRandom");
    BIND(crypto_module,crypto_release,"CryptReleaseContext");
    zero(&data,sizeof(data));status=net_start(0x0101,&data);
    if(status){last_error=(uint32_t)status;return M98_NET_IO;}
    wsa_live=1;
    if(data.wVersion!=0x0101){last_error=WSAVERNOTSUPPORTED;return M98_NET_IO;}
    if(!crypto_acquire(&provider,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT)){
        last_error=GetLastError();return M98_TLS_ENTROPY;
    }
    return 0;
}
static int connect_tcp(const uint8_t *ip,uint16_t port){struct sockaddr_in address;u_long nonblocking=1;int status;
    owned_socket=net_socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(owned_socket==INVALID_SOCKET){last_error=net_error();return M98_NET_IO;}
    if(net_ioctl(owned_socket,FIONBIO,&nonblocking)==SOCKET_ERROR){last_error=net_error();return M98_NET_IO;}
    zero(&address,sizeof(address));address.sin_family=AF_INET;
    ((unsigned char *)&address.sin_port)[0]=(unsigned char)(port>>8);
    ((unsigned char *)&address.sin_port)[1]=(unsigned char)port;
    {unsigned i;for(i=0;i<4;++i)((unsigned char *)&address.sin_addr.s_addr)[i]=ip[i];}
    status=net_connect(owned_socket,(const struct sockaddr *)&address,sizeof(address));
    if(!status){last_error=0;return 0;}
    last_error=net_error();return last_error==WSAEWOULDBLOCK?M98_TLS_WANT_WRITE:M98_NET_IO;
}
static int member(const fd_set *set){return set->fd_count==1&&set->fd_array[0]==owned_socket;}
static int wait_socket(int want,uint32_t ms,int connecting){fd_set chosen,except;struct timeval timeout;int result;
    if(owned_socket==INVALID_SOCKET||!ms||(want!=M98_TLS_WANT_READ&&want!=M98_TLS_WANT_WRITE))return M98_NET_IO;
    zero(&chosen,sizeof(chosen));zero(&except,sizeof(except));
    chosen.fd_count=except.fd_count=1;chosen.fd_array[0]=except.fd_array[0]=owned_socket;
    timeout.tv_sec=(long)(ms/1000);timeout.tv_usec=(long)(ms%1000)*1000;
    result=net_select(0,want==M98_TLS_WANT_READ?&chosen:NULL,
                      want==M98_TLS_WANT_WRITE?&chosen:NULL,&except,&timeout);
    if(result==SOCKET_ERROR){last_error=net_error();return M98_NET_IO;}
    if(!result){last_error=WSAETIMEDOUT;return M98_NET_TIMEOUT;}
    if(chosen.fd_count>1||except.fd_count>1||
       (chosen.fd_count&&!member(&chosen))||(except.fd_count&&!member(&except))){last_error=WSAEINVAL;return M98_NET_IO;}
    if(member(&except)){
        int error=0,n=sizeof(error);
        if(net_getopt(owned_socket,SOL_SOCKET,SO_ERROR,(char *)&error,&n)==SOCKET_ERROR){last_error=net_error();return M98_NET_IO;}
        last_error=(uint32_t)error;return M98_NET_IO;
    }
    if(!member(&chosen)){last_error=WSAEINVAL;return M98_NET_IO;}
    (void)connecting;last_error=0;return 0;
}
static int finish_connect(void){int error=0,n=sizeof(error);
    if(net_getopt(owned_socket,SOL_SOCKET,SO_ERROR,(char *)&error,&n)==SOCKET_ERROR){last_error=net_error();return M98_NET_IO;}
    if(n!=sizeof(error)||error){last_error=n!=sizeof(error)?WSAEINVAL:(uint32_t)error;return M98_NET_IO;}
    last_error=0;return 0;
}
static int half_close(void){
    if(net_shutdown(owned_socket,1)==SOCKET_ERROR){last_error=net_error();return M98_NET_IO;}
    return 0;
}
static int send_bytes(void *user,const unsigned char *p,size_t n){int result;(void)user;
    if(n>4096)n=4096;
    result=net_send(owned_socket,(const char *)p,(int)n,0);
    if(result!=SOCKET_ERROR){last_error=0;return result;}
    last_error=net_error();return last_error==WSAEWOULDBLOCK?-2:-1;
}
static int recv_bytes(void *user,unsigned char *p,size_t n){int result;(void)user;
    if(n>4096)n=4096;
    result=net_recv(owned_socket,(char *)p,(int)n,0);
    if(result!=SOCKET_ERROR){last_error=0;return result;}
    last_error=net_error();return last_error==WSAEWOULDBLOCK?-2:-1;
}
static int random_bytes(void *user,unsigned char *p,size_t n){(void)user;
    if(!provider||n>UINT32_MAX)return 0;
    if(n&&!crypto_random(provider,(DWORD)n,p)){last_error=GetLastError();return 0;}
    return 1;
}
static int64_t utc_seconds(void *user){FILETIME file;uint64_t ticks;int64_t seconds;(void)user;
    GetSystemTimeAsFileTime(&file);ticks=((uint64_t)file.dwHighDateTime<<32)|file.dwLowDateTime;
    if(ticks<=UINT64_C(116444736000000000))return -1;
    seconds=(int64_t)((ticks-UINT64_C(116444736000000000))/UINT64_C(10000000));
    return seconds>=1&&seconds<=INT64_C(253402300799)?seconds:-1;
}
static uint32_t ticks(void){return GetTickCount();}
static uint32_t error(void){return last_error;}
static int unload(HMODULE *module){
    if(*module){if(!FreeLibrary(*module)){last_error=GetLastError();return M98_NET_CLEANUP;}*module=NULL;}
    return 0;
}
static int stop(void){
    /* Do not unload function pointers or abandon handles after a failed release. */
    if(owned_socket!=INVALID_SOCKET){if(net_close(owned_socket)==SOCKET_ERROR){last_error=net_error();return M98_NET_CLEANUP;}owned_socket=INVALID_SOCKET;}
    if(wsa_live){if(net_stop()==SOCKET_ERROR){last_error=net_error();return M98_NET_CLEANUP;}wsa_live=0;}
    if(provider){if(!crypto_release(provider,0)){last_error=GetLastError();return M98_NET_CLEANUP;}provider=0;}
    if(unload(&crypto_module)||unload(&socket_module)||unload(&backend_module))return M98_NET_CLEANUP;
    return 0;
}
const m98_net_platform_ops m98_net_platform={start,connect_tcp,wait_socket,finish_connect,half_close,
    send_bytes,recv_bytes,random_bytes,utc_seconds,ticks,error,stop};
#ifndef M98_NET_WIN32_TEST
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){(void)reserved;
    if(reason==DLL_PROCESS_ATTACH)own_module=module;
    /* All resource cleanup is explicit, outside the Windows loader lock. */
    return TRUE;
}
#endif
