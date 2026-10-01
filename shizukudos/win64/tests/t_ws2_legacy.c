/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine services/protocols/hosts catalogs plus real A transport metadata.
 * Requires the separately pinned actual catalogs; no DNS/PTR claim. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "k32test.h"
_Static_assert(sizeof(struct protoent)==24 && offsetof(struct protoent,p_proto)==16,"Win64 PROTOENT");
_Static_assert(sizeof(struct hostent)==32 && offsetof(struct hostent,h_addr_list)==24,"Win64 HOSTENT");
_Static_assert(sizeof(WSAPROTOCOL_INFOA)==372 && sizeof(WSAPROTOCOL_INFOW)==628
               && offsetof(WSAPROTOCOL_INFOA,szProtocol)==116,"Win64 protocol-info A/W");
static HANDLE acquired, release_worker;
static struct protoent *worker_protocol;
static struct hostent *worker_host;
static DWORD WINAPI legacy_worker(void *unused)
{
    const unsigned char address[4]={127,0,0,1};
    DWORD result;
    (void)unused;
    worker_protocol=getprotobynumber(1);
    worker_host=gethostbyaddr((const char *)address,4,AF_INET);
    if (!SetEvent(acquired)) return 2;
    if (WaitForSingleObject(release_worker,5000)!=WAIT_OBJECT_0) return 3;
    result=worker_protocol && worker_protocol->p_proto==1 && !strcmp(worker_protocol->p_name,"icmp")
        && worker_host && !strcmp(worker_host->h_name,"localhost") && worker_host->h_length==4
        && !memcmp(worker_host->h_addr_list[0],address,4) ? 0 : 1;
    return result;
}
static int alias(char **list,const char *name)
{
    unsigned i;
    if (!list) return 0;
    for (i=0;i<100000 && list[i];++i) if (!strcmp(list[i],name)) return 1;
    return 0;
}
int main(void)
{
    static const unsigned char address[4]={127,0,0,1}, unknown[4]={192,0,2,255};
    WSADATA data;
    WSAPROTOCOL_INFOA a[2];WSAPROTOCOL_INFOW w[2];
    DWORD size,wide_size,exit_code=1;
    struct servent *service;
    struct protoent *protocol;
    struct hostent *host,*same;
    HMODULE ws=GetModuleHandleW(L"ws2_32.dll");HANDLE thread=NULL;
    SOCKET socket_handle;
    INT only_udp[]={IPPROTO_UDP,0}, no_protocol[]={253,0};
    CHECK(!getservbyport(htons(80),"tcp") && WSAGetLastError()==WSANOTINITIALISED,"actual port lookup requires successful Winsock startup");
    CHECK(!getprotobyname("tcp") && WSAGetLastError()==WSANOTINITIALISED,"actual protocol lookup requires Winsock startup");
    CHECK(!gethostbyaddr((const char *)address,4,AF_INET) && WSAGetLastError()==WSANOTINITIALISED,"actual reverse hosts lookup requires Winsock startup");
    CHECK(WSAStartup(MAKEWORD(2,2),&data)==0,"real Winsock startup succeeds");
    CHECK(ws && GetProcAddress(ws,"gethostbyaddr") && GetProcAddress(ws,"gethostbyaddr")==GetProcAddress(ws,(LPCSTR)(uintptr_t)51),"actual ordinal51 binds gethostbyaddr");
    CHECK(ws && GetProcAddress(ws,"getprotobyname") && GetProcAddress(ws,"getprotobyname")==GetProcAddress(ws,(LPCSTR)(uintptr_t)53),"actual ordinal53 binds getprotobyname");
    CHECK(ws && GetProcAddress(ws,"getprotobynumber") && GetProcAddress(ws,"getprotobynumber")==GetProcAddress(ws,(LPCSTR)(uintptr_t)54),"actual ordinal54 binds getprotobynumber");
    CHECK(ws && GetProcAddress(ws,"getservbyport") && GetProcAddress(ws,"getservbyport")==GetProcAddress(ws,(LPCSTR)(uintptr_t)56),"actual ordinal56 binds getservbyport");
    service=getservbyport(htons(80),"tcp");
    CHECK(service && !strcmp(service->s_name,"http") && !strcmp(service->s_proto,"tcp")
          && (u_short)service->s_port==htons(80) && alias(service->s_aliases,"www"),"actual services supplies canonical HTTP, aliases and network-order port");
    CHECK(getservbyname("ftp","tcp")==service && service && !strcmp(service->s_name,"ftp"),"name and port calls share one real thread service structure");
    CHECK(!getservbyport(htons(80),"codex-absent") && WSAGetLastError()==WSANO_DATA,"known port with absent protocol returns honest no-data error");
    protocol=getprotobyname("TCP");
    CHECK(protocol && protocol->p_proto==6 && !strcmp(protocol->p_name,"tcp") && alias(protocol->p_aliases,"TCP"),"actual protocols database supplies canonical TCP and alias in host order");
    CHECK(getprotobynumber(17)==protocol && protocol && protocol->p_proto==17 && !strcmp(protocol->p_name,"udp"),"name and number share the calling thread protocol structure");
    CHECK(!getprotobyname(NULL) && WSAGetLastError()==WSAEFAULT,"NULL protocol name returns a real caller error");
    CHECK(!getprotobynumber(65536) && WSAGetLastError()==WSAHOST_NOT_FOUND,"out-of-range protocol never manufactures a record");
    host=gethostbyaddr((const char *)address,4,AF_INET);
    CHECK(host && !strcmp(host->h_name,"localhost") && host->h_addrtype==AF_INET && host->h_length==4
          && host->h_addr_list && !memcmp(host->h_addr_list[0],address,4) && !host->h_addr_list[1]
          && alias(host->h_aliases,"localhost.localdomain"),"actual hosts catalog supplies canonical loopback and genuine aliases/address");
    same=host ? gethostbyaddr(host->h_addr_list[0],4,AF_INET) : NULL;
    CHECK(same==host && same,"reverse call safely accepts its previous borrowed address as input");
    same=gethostbyname("127.0.0.1");
    CHECK(same && same==host && !strcmp(same->h_name,"127.0.0.1") && !memcmp(same->h_addr_list[0],address,4),"existing numeric forward resolver and reverse calls share one real thread hostent");
    CHECK(!gethostbyaddr((const char *)unknown,4,AF_INET) && WSAGetLastError()==WSAHOST_NOT_FOUND,"address absent from the genuine catalog never gets a fabricated numeric name");
    CHECK(!gethostbyaddr(NULL,4,AF_INET) && WSAGetLastError()==WSAEFAULT,"NULL address is rejected");
    CHECK(!gethostbyaddr((const char *)address,3,AF_INET) && WSAGetLastError()==WSAEFAULT,"short IPv4 address is rejected");
    CHECK(!gethostbyaddr((const char *)address,16,AF_INET6) && WSAGetLastError()==WSAEAFNOSUPPORT,"absent IPv6 reverse provider reports unsupported family");
    size=0;
    CHECK(WSAEnumProtocolsA(NULL,NULL,&size)==SOCKET_ERROR && WSAGetLastError()==WSAENOBUFS && size==sizeof a,"ANSI enum reports exact A byte requirement");
    size=sizeof a;wide_size=sizeof w;
    CHECK(WSAEnumProtocolsA(NULL,a,&size)==2 && WSAEnumProtocolsW(NULL,w,&wide_size)==2,"real ANSI and wide enumerations expose the two actual transport providers");
    CHECK(size==sizeof a && wide_size==sizeof w && !memcmp(&a[0],&w[0],offsetof(WSAPROTOCOL_INFOA,szProtocol))
          && !memcmp(&a[1],&w[1],offsetof(WSAPROTOCOL_INFOA,szProtocol)),"actual A/W transport numeric metadata is identical with distinct structure sizes");
    CHECK(a[0].iProtocol==IPPROTO_TCP && a[1].iProtocol==IPPROTO_UDP && a[0].iAddressFamily==AF_INET
          && !strcmp(a[0].szProtocol,"Shizuku Tcpip [TCP/IP]"),"ANSI enum retains actual provider identities and description");
    socket_handle=WSASocketA(FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,FROM_PROTOCOL_INFO,&a[0],0,0);
    CHECK(socket_handle!=INVALID_SOCKET,"actual enumerated ANSI TCP metadata opens a genuine socket");
    if (socket_handle!=INVALID_SOCKET) CHECK(closesocket(socket_handle)==0,"genuine TCP socket closes");
    size=sizeof a;
    CHECK(WSAEnumProtocolsA(only_udp,a,&size)==1 && size==sizeof a[0] && a[0].iProtocol==IPPROTO_UDP,"ANSI enum filters real UDP and returns exact single-record bytes");
    size=0;CHECK(WSAEnumProtocolsA(no_protocol,NULL,&size)==0 && size==0,"absent protocol filter returns a genuinely empty catalogue");
    host=gethostbyaddr((const char *)address,4,AF_INET);protocol=getprotobyname("tcp");
    acquired=CreateEventW(NULL,TRUE,FALSE,NULL);release_worker=CreateEventW(NULL,TRUE,FALSE,NULL);
    if (acquired && release_worker) thread=CreateThread(NULL,0,legacy_worker,NULL,0,NULL);
    CHECK(thread,"real second native thread performs independent catalogue lookups");
    if (thread) {
        DWORD ready=WaitForSingleObject(acquired,5000);
        CHECK(ready==WAIT_OBJECT_0,"worker publishes actual lookup results");
        if (ready==WAIT_OBJECT_0) {
            CHECK(worker_protocol && protocol && worker_protocol!=protocol && worker_host && host && worker_host!=host,"real threads own distinct protocol and host records");
            CHECK(getprotobynumber(17)==protocol && gethostbyname("127.0.0.1")==host,"main thread reuses only its own structures");
            CHECK(worker_protocol && !strcmp(worker_protocol->p_name,"icmp") && worker_host && !strcmp(worker_host->h_name,"localhost"),"main thread updates preserve worker's live borrowed payloads");
        }
        CHECK(SetEvent(release_worker),"worker release event signals");
        if (WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0) { CHECK(0,"worker must join before cleanup");return k32t_finish("T_WS2_LEGACY"); }
        CHECK(GetExitCodeThread(thread,&exit_code) && !exit_code,"actual worker verifies retained per-thread records before exit");
        CHECK(CloseHandle(thread),"joined worker handle closes");
    }
    if (acquired) CHECK(CloseHandle(acquired),"owned acquired event closes");
    if (release_worker) CHECK(CloseHandle(release_worker),"owned release event closes");
    CHECK(WSACleanup()==0,"real Winsock startup reference balances");
    return k32t_finish("T_WS2_LEGACY");
}
