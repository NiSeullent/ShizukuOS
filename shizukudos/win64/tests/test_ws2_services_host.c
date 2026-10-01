/* SPDX-License-Identifier: GPL-2.0-only
 * Read an actual host OS services catalog through the production Windows file
 * interface. Positive records and aliases come from that catalog. Fault
 * injection covers primitive failure contracts; no invented service success.
 */
#define _POSIX_C_SOURCE 200809L
#include "ws2_services_host_contract.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>
#include "actual_services_expected.inc"
static _Thread_local DWORD last_error, thread_id;
static _Thread_local void *tls_values[8];
static _Thread_local int fail_heap_after = -1, fail_tls_alloc, fail_tls_set, fail_read, short_read;
static _Atomic unsigned next_tid = 1, heap_live, file_live, checks;
static unsigned tls_used;
static pthread_mutex_t tls_lock = PTHREAD_MUTEX_INITIALIZER;
static const char *system_directory;
#define CHECK(x) do { atomic_fetch_add(&checks,1); if (!(x)) { fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD e) { last_error=e; }
DWORD GetCurrentThreadId(void) { if (!thread_id) thread_id=atomic_fetch_add(&next_tid,1); return thread_id; }
void AcquireSRWLockExclusive(SRWLOCK *l) { if (pthread_mutex_lock(l)) abort(); }
void ReleaseSRWLockExclusive(SRWLOCK *l) { if (pthread_mutex_unlock(l)) abort(); }
UINT GetSystemDirectoryW(WCHAR *out, UINT cap)
{
    size_t n=strlen(system_directory),i;
    if (cap<=n) return (UINT)n+1;
    for (i=0;i<=n;++i) out[i]=(WCHAR)(unsigned char)system_directory[i];
    return (UINT)n;
}
HANDLE CreateFileW(const WCHAR *name,DWORD access,DWORD share,void *security,DWORD creation,DWORD flags,HANDLE template)
{
    char path[MAX_PATH]; unsigned i; FILE *f;
    (void)security;(void)template;
    CHECK(access==GENERIC_READ && share==(FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE));
    CHECK(creation==OPEN_EXISTING && flags==FILE_ATTRIBUTE_NORMAL);
    for (i=0;i<MAX_PATH && name[i];++i) { CHECK(name[i]<128); path[i]=name[i]=='\\' ? '/' : (char)name[i]; }
    CHECK(i<MAX_PATH);path[i]=0;f=fopen(path,"rb");
    if (!f) { SetLastError((DWORD)errno); return INVALID_HANDLE_VALUE; }
    atomic_fetch_add(&file_live,1);return f;
}
BOOL GetFileSizeEx(HANDLE file,LARGE_INTEGER *size)
{
    FILE *f=file;long n;
    if (fseek(f,0,SEEK_END) || (n=ftell(f))<0 || fseek(f,0,SEEK_SET)) return 0;
    size->QuadPart=n;return 1;
}
BOOL ReadFile(HANDLE file,void *data,DWORD count,DWORD *got,void *overlapped)
{
    CHECK(overlapped==NULL);
    if (fail_read) { *got=0;return 0; }
    if (short_read && count>13) count=13;
    *got=(DWORD)fread(data,1,count,file);return !ferror(file);
}
BOOL CloseHandle(HANDLE file) { atomic_fetch_sub(&file_live,1);return fclose(file)==0; }
HANDLE GetProcessHeap(void) { return (void *)(uintptr_t)1; }
void *HeapAlloc(HANDLE heap,DWORD flags,size_t n)
{
    void *p;(void)heap;
    if (fail_heap_after==0) return NULL;
    if (fail_heap_after>0) --fail_heap_after;
    p=flags & HEAP_ZERO_MEMORY ? calloc(1,n) : malloc(n);
    if (p) atomic_fetch_add(&heap_live,1);
    return p;
}
BOOL HeapFree(HANDLE heap,DWORD flags,void *p)
{ (void)heap;(void)flags;CHECK(p!=NULL);free(p);atomic_fetch_sub(&heap_live,1);return 1; }
DWORD TlsAlloc(void)
{
    unsigned i;if (fail_tls_alloc) return TLS_OUT_OF_INDEXES;
    pthread_mutex_lock(&tls_lock);
    for (i=0;i<8;++i) if (!(tls_used&(1u<<i))) { tls_used|=1u<<i;break; }
    pthread_mutex_unlock(&tls_lock);
    /* Match the actual runtime: allocation/free need not clear another thread's old slot value. */
    return i<8 ? i : TLS_OUT_OF_INDEXES;
}
void *TlsGetValue(DWORD slot) { last_error=0;return slot<8 ? tls_values[slot] : NULL; }
BOOL TlsSetValue(DWORD slot,void *value) { if (fail_tls_set || slot>=8) return 0;tls_values[slot]=value;return 1; }
BOOL TlsFree(DWORD slot) { if (slot>=8) return 0;pthread_mutex_lock(&tls_lock);tls_used&=~(1u<<slot);pthread_mutex_unlock(&tls_lock);return 1; }
#include "service_production.inc"
static struct servent *query(const char *name,const char *proto,const char *canonical,unsigned port)
{
    struct servent *s=getservbyname(name,proto);
    CHECK(s!=NULL && !strcmp(s->s_name,canonical));
    CHECK((u_short)s->s_port==htons((u_short)port));
    CHECK(s->s_aliases!=NULL && s->s_proto!=NULL && (!proto || !strcmp(s->s_proto,proto)));
    return s;
}
static void reset_storage(void)
{
    CHECK(DllMain(NULL,DLL_PROCESS_DETACH,NULL));
    CHECK(atomic_load(&heap_live)==0 && atomic_load(&file_live)==0 && g_svc_threads==NULL && g_svc_tls==TLS_OUT_OF_INDEXES);
}
static pthread_barrier_t ready,release;
static struct servent *worker_entry;
static void *worker(void *unused)
{
    (void)unused;
    worker_entry=query("ftp","tcp","ftp",21);
    pthread_barrier_wait(&ready);pthread_barrier_wait(&release);
    CHECK(!strcmp(worker_entry->s_name,"ftp") && (u_short)worker_entry->s_port==htons(21));
    CHECK(DllMain(NULL,DLL_THREAD_DETACH,NULL));
    return NULL;
}
static void missing_and_faults(const char *catalog)
{
    char moved[MAX_PATH + 8];
    snprintf(moved,sizeof moved,"%s.saved",catalog);
    CHECK(rename(catalog,moved)==0);
    CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSANO_RECOVERY);
    CHECK(rename(moved,catalog)==0);
    CHECK(getservbyname("codex-unregistered-01a0f3d0-cb43","tcp")==NULL && GetLastError()==WSAHOST_NOT_FOUND);
    CHECK(getservbyname("http","codex-unregistered-protocol")==NULL && GetLastError()==WSANO_DATA);
    CHECK(getservbyname("80","tcp")==NULL && GetLastError()==WSAHOST_NOT_FOUND);
    fail_read=1;CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSANO_RECOVERY);fail_read=0;
    CHECK(atomic_load(&file_live)==0);
    short_read=1;query("http","tcp","http",80);short_read=0;
}
int main(int argc,char **argv)
{
    struct servent *s,*next;pthread_t thread;char catalog[MAX_PATH];unsigned i;
    CHECK(argc==2);system_directory=argv[1];snprintf(catalog,sizeof catalog,"%s/drivers/etc/services",system_directory);
    CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSANOTINITIALISED);
    CHECK(getservbyname(NULL,NULL)==NULL && GetLastError()==WSANOTINITIALISED);
    g_started=1;CHECK(DllMain(NULL,DLL_PROCESS_ATTACH,NULL));
    CHECK(getservbyname(NULL,NULL)==NULL && GetLastError()==WSAEFAULT);
    SetLastError(0x12345678);s=query("http","tcp","http",80);CHECK(GetLastError()==0x12345678);
    CHECK(!strcmp(s->s_aliases[0],ACTUAL_HTTP_ALIAS) && s->s_aliases[ACTUAL_HTTP_ALIAS_COUNT]==NULL);
    next=query(ACTUAL_HTTP_ALIAS,"tcp","http",80);CHECK(next==s);
    CHECK(getservbyname("HTTP","TcP")==s && !strcmp(s->s_name,"http") && !strcmp(s->s_proto,"tcp"));
    CHECK(getservbyname("http",NULL)==s && !strcmp(s->s_proto,ACTUAL_HTTP_FIRST_PROTO));
    query(ACTUAL_HIGH_NAME,ACTUAL_HIGH_PROTO,ACTUAL_HIGH_NAME,ACTUAL_HIGH_PORT);
    s=query("http","tcp","http",80);next=getservbyname(s->s_name,s->s_proto);CHECK(next==s && !strcmp(next->s_name,"http"));
    pthread_barrier_init(&ready,NULL,2);pthread_barrier_init(&release,NULL,2);
    CHECK(pthread_create(&thread,NULL,worker,NULL)==0);pthread_barrier_wait(&ready);
    CHECK(worker_entry!=s && !strcmp(s->s_name,"http"));
    query("domain","udp","domain",53);CHECK(!strcmp(worker_entry->s_name,"ftp"));
    pthread_barrier_wait(&release);CHECK(pthread_join(thread,NULL)==0);
    pthread_barrier_destroy(&ready);pthread_barrier_destroy(&release);
    CHECK(atomic_load(&heap_live)==2);
    missing_and_faults(catalog);reset_storage();
    for (i=0;i<3;++i) {
        fail_heap_after=(int)i;
        CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSAENOBUFS);
        fail_heap_after=-1;CHECK(atomic_load(&heap_live)==0 && atomic_load(&file_live)==0);
        reset_storage();
    }
    fail_tls_alloc=1;CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSAENOBUFS);fail_tls_alloc=0;
    CHECK(atomic_load(&heap_live)==0);query("http","tcp","http",80);reset_storage();
    fail_tls_set=1;CHECK(getservbyname("http","tcp")==NULL && GetLastError()==WSAENOBUFS);fail_tls_set=0;
    CHECK(atomic_load(&heap_live)==0);query("http","tcp","http",80);reset_storage();
    tls_values[0]=(void *)(uintptr_t)0xdeadbeef;
    query("http","tcp","http",80);reset_storage();
    query("http","tcp","http",80);CHECK(DllMain(NULL,DLL_PROCESS_DETACH,(void *)(uintptr_t)1));
    CHECK(atomic_load(&heap_live)==2);reset_storage();
    printf("PASS %u checks; actual OS catalog, aliases, network port, thread storage, failure cleanup\n",atomic_load(&checks));
    return 0;
}
