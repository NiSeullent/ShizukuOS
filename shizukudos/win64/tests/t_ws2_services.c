/* SPDX-License-Identifier: GPL-2.0-only
 * Real Winsock service-database and fixed ordinal55 contracts. Requires a real
 * OS catalog at GetSystemDirectoryW()\\drivers\\etc\\services. Never writes it.
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "k32test.h"
_Static_assert(sizeof(struct servent)==32, "Windows AMD64 SERVENT size");
_Static_assert(offsetof(struct servent,s_name)==0 && offsetof(struct servent,s_aliases)==8
               && offsetof(struct servent,s_proto)==16 && offsetof(struct servent,s_port)==24, "Windows AMD64 SERVENT fields");
typedef struct servent *(WSAAPI *service_fn)(const char *,const char *);
typedef struct servent *(WSAAPI *service_port_fn)(int,const char *);
static HANDLE acquired,release_worker;
static struct servent *worker_entry;
static DWORD WINAPI service_worker(void *unused)
{
    (void)unused;
    worker_entry=getservbyname("ftp","tcp");
    SetEvent(acquired);
    if (WaitForSingleObject(release_worker,5000)!=WAIT_OBJECT_0) return 2;
    return worker_entry && !strcmp(worker_entry->s_name,"ftp") && (u_short)worker_entry->s_port==htons(21) ? 0 : 1;
}
static int alias_present(const struct servent *s,const char *name)
{
    unsigned i;
    if (!s || !s->s_aliases) return 0;
    for (i=0;i<100000 && s->s_aliases[i];++i) if (!strcmp(s->s_aliases[i],name)) return 1;
    return 0;
}
int main(void)
{
    WSADATA data;HMODULE ws=GetModuleHandleW(L"ws2_32.dll");HANDLE thread;
    struct servent *s,*same;service_fn named,numbered;service_port_fn port_named,port_numbered;DWORD exit_code=1;
    CHECK(getservbyname("http","tcp")==NULL && WSAGetLastError()==WSANOTINITIALISED,
          "actual getservbyname requires real successful WSAStartup");
    CHECK(WSAStartup(MAKEWORD(2,2),&data)==0,"real Winsock startup succeeds");
    named=ws ? (service_fn)GetProcAddress(ws,"getservbyname") : NULL;
    numbered=ws ? (service_fn)GetProcAddress(ws,(LPCSTR)(uintptr_t)55u) : NULL;
    CHECK(named!=NULL && named==numbered,"actual named and ordinal55 exports select the same service function");
    CHECK(ws && (FARPROC)numbered!=GetProcAddress(ws,"WSAResetEvent"),"actual ordinal55 never selects WSAResetEvent");
    port_named=ws ? (service_port_fn)GetProcAddress(ws,"getservbyport") : NULL;
    port_numbered=ws ? (service_port_fn)GetProcAddress(ws,(LPCSTR)(uintptr_t)56u) : NULL;
    CHECK(port_named && port_named==port_numbered,
          "actual named and ordinal56 exports select the same port lookup function");
    same=port_numbered ? port_numbered(htons(80),"tcp") : NULL;
    CHECK(same && !strcmp(same->s_name,"http") && (u_short)same->s_port==htons(80),
          "actual ordinal56 call returns the genuine HTTP service record");
    s=getservbyname("http","tcp");
    CHECK(s && !strcmp(s->s_name,"http") && !strcmp(s->s_proto,"tcp") && (u_short)s->s_port==htons(80),
          "actual OS catalog supplies canonical HTTP TCP and network-order port80");
    CHECK(alias_present(s,"www"),"actual OS HTTP record supplies its genuine www alias");
    same=getservbyname("www","tcp");
    CHECK(same && same==s && !strcmp(same->s_name,"http"),"actual alias lookup retains canonical name and per-thread structure");
    same=getservbyname("HTTP","TcP");
    CHECK(same && !strcmp(same->s_name,"http") && !strcmp(same->s_proto,"tcp"),"actual names and protocol comparison ignore ASCII case");
    same=getservbyname("http",NULL);
    CHECK(same && !strcmp(same->s_name,"http") && !strcmp(same->s_proto,"tcp"),"NULL protocol selects the first genuine HTTP catalog record");
    CHECK(getservbyname(NULL,NULL)==NULL && WSAGetLastError()==WSAEFAULT,"NULL service name is an honest caller error");
    CHECK(getservbyname("codex-unregistered-01a0f3d0-cb43","tcp")==NULL && WSAGetLastError()==WSAHOST_NOT_FOUND,
          "unknown service never manufactures a record");
    CHECK(getservbyname("http","codex-unregistered-protocol")==NULL && WSAGetLastError()==WSANO_DATA,
          "unknown requested protocol never manufactures a transport match");
    s=getservbyname("http","tcp");
    acquired=CreateEventW(NULL,TRUE,FALSE,NULL);release_worker=CreateEventW(NULL,TRUE,FALSE,NULL);
    thread=acquired && release_worker ? CreateThread(NULL,0,service_worker,NULL,0,NULL) : NULL;
    CHECK(thread!=NULL,"actual second native thread starts service lookup");
    if (thread) {
        CHECK(WaitForSingleObject(acquired,5000)==WAIT_OBJECT_0,"actual worker publishes its genuine service result");
        CHECK(s && worker_entry && s!=worker_entry && !strcmp(s->s_name,"http") && !strcmp(worker_entry->s_name,"ftp"),
              "native threads own distinct service structures without overwriting the other thread");
        same=getservbyname("domain","udp");
        CHECK(same==s && same && !strcmp(same->s_name,"domain") && (u_short)same->s_port==htons(53),
              "another real query reuses only the calling thread structure");
        CHECK(worker_entry && !strcmp(worker_entry->s_name,"ftp"),"main-thread query leaves live worker record intact");
        CHECK(SetEvent(release_worker),"worker release event genuinely signals");
        if (WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0) {
            CHECK(0,"worker must actually join before cleanup");return k32t_finish("T_WS2_SERVICES");
        }
        CHECK(GetExitCodeThread(thread,&exit_code) && exit_code==0,"actual worker exits after verifying retained thread-owned record");
        CHECK(CloseHandle(thread),"joined worker handle closes");
    }
    if (acquired) CHECK(CloseHandle(acquired),"owned acquired event closes");
    if (release_worker) CHECK(CloseHandle(release_worker),"owned release event closes");
    CHECK(WSACleanup()==0,"real Winsock startup reference balances");
    return k32t_finish("T_WS2_SERVICES");
}
