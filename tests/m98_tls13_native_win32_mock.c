/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Win32 platform source with failing OS doubles. No native claim. */
#define M98_NET_WIN32_TEST
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../src/m98_tls13_native_win32.c"
static unsigned checks;
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#x);exit(1);}}while(0)
enum {NORMAL,BACKEND_MISSING,BACKEND_ALIAS,BACKEND_EXPORT,CRT_ALIAS,WSOCK_MISSING,CRYPTO_ALIAS,
      SOCKET_EXPORT,CRYPTO_EXPORT,WSA_START_FAIL,WSA_VERSION,CRYPTO_ACQUIRE_FAIL,
      SOCKET_FAIL,IOCTL_FAIL,CONNECT_FAIL,SELECT_TIMEOUT,SELECT_FAIL,SELECT_EXCEPTION,
      SELECT_WRONG_FD,GETOPT_FAIL,GETOPT_ERROR,GETOPT_SHORT,SEND_BLOCK,SEND_FAIL,
      RECV_BLOCK,RECV_FAIL,RECV_EOF,RANDOM_FAIL,CLOSE_FAIL,WSA_STOP_FAIL,RELEASE_FAIL,UNLOAD_FAIL,SHUTDOWN_FAIL};
static struct {int fault,loads,wsa,sock,crypto,closes,stops,releases,unloads,once;
    uint32_t error;char paths[4][MAX_PATH];uint64_t filetime;
} mock;
static HMODULE module(unsigned n){return (HMODULE)(uintptr_t)n;}
static int mock_error(void){return (int)mock.error;}
DWORD GetLastError(void){return mock.error;}
DWORD GetTickCount(void){return 100;}
int lstrcmpiA(const char *a,const char *b){while(*a&&tolower((unsigned char)*a)==tolower((unsigned char)*b)){++a;++b;}return (unsigned char)*a-(unsigned char)*b;}
UINT GetSystemDirectoryA(char *p,UINT n){C(n>=18);strcpy(p,"C:\\WINDOWS\\SYSTEM");return 17;}
HMODULE GetModuleHandleA(const char *name){C(!strcmp(name,"MSVCRT.DLL"));return module(5);}
DWORD GetModuleFileNameA(HMODULE m,char *p,DWORD n){const char *path=NULL;
    if(m==module(1))path="C:\\LAB\\M98NET.DLL";
    else if(m==module(2))path=mock.fault==BACKEND_ALIAS?"C:\\OTHER\\M98TLS13.DLL":mock.paths[1];
    else if(m==module(3))path=mock.paths[2];
    else if(m==module(4))path=mock.fault==CRYPTO_ALIAS?"C:\\OTHER\\ADVAPI32.DLL":mock.paths[3];
    else if(m==module(5))path=mock.fault==CRT_ALIAS?"C:\\OTHER\\MSVCRT.DLL":"C:\\WINDOWS\\SYSTEM\\MSVCRT.DLL";
    C(path!=NULL&&strlen(path)<n);strcpy(p,path);return (DWORD)strlen(p);
}
HMODULE LoadLibraryA(const char *path){unsigned id;
    if(strstr(path,"M98TLS13.DLL")){if(mock.fault==BACKEND_MISSING){mock.error=126;return NULL;}id=2;}
    else if(strstr(path,"WSOCK32.DLL")){if(mock.fault==WSOCK_MISSING){mock.error=126;return NULL;}id=3;}
    else{C(strstr(path,"ADVAPI32.DLL"));id=4;}
    C(strlen(path)<MAX_PATH);strcpy(mock.paths[id-1],path);++mock.loads;return module(id);
}
BOOL FreeLibrary(HMODULE m){C(m==module(2)||m==module(3)||m==module(4));
    if(mock.fault==UNLOAD_FAIL&&!mock.once++){mock.error=6;return 0;}
    --mock.loads;++mock.unloads;return 1;
}
static void dummy(void){}
static int startup(WORD version,LPWSADATA data){C(version==0x101);
    if(mock.fault==WSA_START_FAIL)return 10091;
    mock.wsa=1;data->wVersion=mock.fault==WSA_VERSION?0x202:0x101;return 0;
}
static int cleanup_wsa(void){C(mock.wsa&&!mock.sock);if(mock.fault==WSA_STOP_FAIL&&!mock.once++){mock.error=10093;return SOCKET_ERROR;}
    mock.wsa=0;++mock.stops;return 0;
}
static SOCKET make_socket(int family,int type,int protocol){C(mock.wsa&&family==AF_INET&&type==SOCK_STREAM&&protocol==IPPROTO_TCP);
    if(mock.fault==SOCKET_FAIL){mock.error=10055;return INVALID_SOCKET;}mock.sock=1;return 44;
}
static int ioctl_socket(SOCKET sock,long cmd,u_long *value){C(sock==44&&cmd==FIONBIO&&*value==1);
    if(mock.fault==IOCTL_FAIL){mock.error=10022;return SOCKET_ERROR;}return 0;
}
static int connect_socket(SOCKET sock,const struct sockaddr *arg,int n){const struct sockaddr_in *a=(const struct sockaddr_in *)arg;
    C(sock==44&&n==sizeof(*a)&&a->sin_family==AF_INET);
    C(((unsigned char *)&a->sin_port)[0]==0x10&&((unsigned char *)&a->sin_port)[1]==0xe1);
    C(!memcmp(&a->sin_addr.s_addr,"\x7f\0\0\x01",4));
    mock.error=mock.fault==CONNECT_FAIL?10061:WSAEWOULDBLOCK;return SOCKET_ERROR;
}
static int select_socket(int nfds,fd_set *rd,fd_set *wr,fd_set *except,const struct timeval *t){fd_set *chosen=rd?rd:wr;
    C(nfds==0&&chosen&&except&&chosen->fd_count==1&&chosen->fd_array[0]==44);
    C(t&&t->tv_sec==1&&t->tv_usec==234000);
    if(mock.fault==SELECT_TIMEOUT){chosen->fd_count=except->fd_count=0;return 0;}
    if(mock.fault==SELECT_FAIL){mock.error=10038;return SOCKET_ERROR;}
    if(mock.fault==SELECT_EXCEPTION){chosen->fd_count=0;return 1;}
    except->fd_count=0;if(mock.fault==SELECT_WRONG_FD)chosen->fd_array[0]=99;return 1;
}
static int get_option(SOCKET sock,int level,int option,char *p,int *n){C(sock==44&&level==SOL_SOCKET&&option==SO_ERROR&&*n==sizeof(int));
    if(mock.fault==GETOPT_FAIL){mock.error=10038;return SOCKET_ERROR;}
    *(int *)p=mock.fault==GETOPT_ERROR||mock.fault==SELECT_EXCEPTION?10061:0;
    if(mock.fault==GETOPT_SHORT)*n=1;return 0;
}
static int send_socket(SOCKET sock,const char *p,int n,int flags){C(sock==44&&p&&n>0&&n<=4096&&!flags);
    if(mock.fault==SEND_BLOCK||mock.fault==SEND_FAIL){mock.error=mock.fault==SEND_BLOCK?WSAEWOULDBLOCK:10054;return SOCKET_ERROR;}return n>9?9:n;
}
static int recv_socket(SOCKET sock,char *p,int n,int flags){C(sock==44&&p&&n>0&&n<=4096&&!flags);
    if(mock.fault==RECV_BLOCK||mock.fault==RECV_FAIL){mock.error=mock.fault==RECV_BLOCK?WSAEWOULDBLOCK:10054;return SOCKET_ERROR;}
    if(mock.fault==RECV_EOF)return 0;memset(p,'x',n>7?7:(size_t)n);return n>7?7:n;
}
static int close_socket(SOCKET sock){C(sock==44&&mock.sock);
    if(mock.fault==CLOSE_FAIL&&!mock.once++){mock.error=10035;return SOCKET_ERROR;}
    mock.sock=0;++mock.closes;return 0;
}
static int shutdown_socket(SOCKET sock,int how){C(sock==44&&how==1);
    if(mock.fault==SHUTDOWN_FAIL){mock.error=10054;return SOCKET_ERROR;}return 0;}
static BOOL acquire(HCRYPTPROV *p,LPCSTR container,LPCSTR name,DWORD type,DWORD flags){C(!container&&!name&&type==1&&flags==CRYPT_VERIFYCONTEXT);
    if(mock.fault==CRYPTO_ACQUIRE_FAIL){mock.error=0x80090016u;return 0;}mock.crypto=1;*p=77;return 1;
}
static BOOL generate(HCRYPTPROV p,DWORD n,BYTE *out){C(p==77&&mock.crypto&&out);
    if(mock.fault==RANDOM_FAIL){mock.error=0x80090020u;return 0;}memset(out,0xa9,n);return 1;
}
static BOOL release(HCRYPTPROV p,DWORD flags){C(p==77&&mock.crypto&&!flags);
    if(mock.fault==RELEASE_FAIL&&!mock.once++){mock.error=0x80090020u;return 0;}
    mock.crypto=0;++mock.releases;return 1;
}
void GetSystemTimeAsFileTime(FILETIME *f){f->dwLowDateTime=(DWORD)mock.filetime;f->dwHighDateTime=(DWORD)(mock.filetime>>32);}
FARPROC GetProcAddress(HMODULE m,const char *name){
    if((m==module(2)&&mock.fault==BACKEND_EXPORT)||(m==module(3)&&mock.fault==SOCKET_EXPORT)||(m==module(4)&&mock.fault==CRYPTO_EXPORT))return NULL;
    if(m==module(2))return dummy;
#define FN(text,fn) if(!strcmp(name,text))return (FARPROC)(fn)
    FN("WSAStartup",startup);FN("WSACleanup",cleanup_wsa);FN("socket",make_socket);
    FN("ioctlsocket",ioctl_socket);FN("connect",connect_socket);FN("select",select_socket);
    FN("getsockopt",get_option);FN("send",send_socket);FN("recv",recv_socket);
    FN("closesocket",close_socket);FN("shutdown",shutdown_socket);FN("WSAGetLastError",mock_error);
    FN("CryptAcquireContextA",acquire);FN("CryptGenRandom",generate);FN("CryptReleaseContext",release);
#undef FN
    C(0);return NULL;
}
static void reset(int fault){C(!backend_module&&!socket_module&&!crypto_module&&!provider&&!wsa_live&&owned_socket==INVALID_SOCKET);
    memset(&mock,0,sizeof(mock));mock.fault=fault;own_module=module(1);mock.filetime=UINT64_C(116444736000000000)+UINT64_C(1790856000)*10000000;
}
static void end(void){C(stop()==0&&!mock.loads&&!mock.sock&&!mock.wsa&&!mock.crypto);}
int main(void){m98_net_backend api;unsigned i;unsigned char bytes[5000];const uint8_t ip[]={127,0,0,1};
    for(i=BACKEND_MISSING;i<=CRYPTO_ACQUIRE_FAIL;++i){reset((int)i);C(start(&api)!=0);end();}
    for(i=SOCKET_FAIL;i<=CONNECT_FAIL;++i){reset((int)i);C(start(&api)==0);C(connect_tcp(ip,4321)==M98_NET_IO);end();}
    for(i=SELECT_TIMEOUT;i<=SELECT_WRONG_FD;++i){reset((int)i);C(start(&api)==0&&connect_tcp(ip,4321)==2);
        C(wait_socket(2,1234,1)==(i==SELECT_TIMEOUT?M98_NET_TIMEOUT:M98_NET_IO));end();}
    for(i=GETOPT_FAIL;i<=GETOPT_SHORT;++i){reset((int)i);C(start(&api)==0&&connect_tcp(ip,4321)==2&&wait_socket(2,1234,1)==0);
        C(finish_connect()==M98_NET_IO);end();}
    reset(NORMAL);C(start(&api)==0&&connect_tcp(ip,4321)==2&&wait_socket(2,1234,1)==0&&finish_connect()==0);
    C(send_bytes(NULL,bytes,sizeof(bytes))==9&&recv_bytes(NULL,bytes,sizeof(bytes))==7);
    C(half_close()==0);
    C(random_bytes(NULL,bytes,32)==1&&bytes[31]==0xa9);C(utc_seconds(NULL)==INT64_C(1790856000));
    mock.filetime=UINT64_C(116444736000000000);C(utc_seconds(NULL)==-1);mock.filetime=UINT64_MAX;C(utc_seconds(NULL)==-1);end();
    for(i=SEND_BLOCK;i<=RANDOM_FAIL;++i){reset((int)i);C(start(&api)==0&&connect_tcp(ip,4321)==2);
        if(i==SEND_BLOCK||i==SEND_FAIL)C(send_bytes(NULL,bytes,1)==(i==SEND_BLOCK?-2:-1));
        else if(i==RECV_BLOCK||i==RECV_FAIL||i==RECV_EOF)C(recv_bytes(NULL,bytes,1)==(i==RECV_BLOCK?-2:i==RECV_FAIL?-1:0));
        else C(random_bytes(NULL,bytes,32)==0);end();}
    for(i=CLOSE_FAIL;i<=UNLOAD_FAIL;++i){reset((int)i);C(start(&api)==0&&connect_tcp(ip,4321)==2);C(stop()==M98_NET_CLEANUP);
        C(backend_module!=NULL);end();C(mock.closes==1&&mock.stops==1&&mock.releases==1);}
    reset(SHUTDOWN_FAIL);C(start(&api)==0&&connect_tcp(ip,4321)==2);
    C(half_close()==M98_NET_IO&&error()==10054&&mock.sock);end();
    printf("PASS: native Win32 platform %u assertions; OS doubles only\n",checks);return 0;
}
