/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production socket wrappers + queued kernel IRPs + actual handle hooks.
 * Host TCP adapters inject handshake/flow control/fault/close transitions.
 */
#define SHZ_NET_EXT_HOST_TEST
#define SHZ_WS2_EXT_HOST_TEST
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_HANDLES 64
#define KASSERT assert
#define STATUS_SUCCESS 0
#define STATUS_PENDING 0x103
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_INVALID_PARAMETER ((int32_t)0xc000000d)
#define STATUS_OBJECT_TYPE_MISMATCH ((int32_t)0xc0000024)
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define STATUS_INSUFFICIENT_RESOURCES ((int32_t)0xc000009a)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xc0000004)
#define STATUS_CANCELLED ((int32_t)0xc0000120)
#define NT_ERROR(s) ((uint32_t)(s) >= 0xc0000000u)
#define IRPF_NO_EVENT_ON_HANDLE 1
#define IRPF_SKIP_COMPLETION_PORT_ON_SUCCESS 2u
#define OB_SOCKET 0x21
#define OB_FILE 0x10
#define OB_EVENT 1
#define OB_THREAD 2
#define OB_PROCESS 3
#define OB_TIMER 4
#define OB_SEMAPHORE 5
#define OB_MUTANT 6
#define OB_IS_IPC(t) ((t)>=0x60 && (t)<0x70)
#define OB_NPIPE 0x61
#define OB_IOCP 0x62
#define OB_JOB 0x63
#define HANDLE_FLAG_INHERIT_BIT 1
#define TS_BLOCKED 2
#define NET_ERR(w) ((int32_t)(0xe0a00000u | (uint32_t)(w)))
enum { WSAEINTR=10004, WSAEFAULT=10014, WSAEINVAL=10022, WSAEALREADY=10037, WSAENOTSOCK=10038,
       WSAEOPNOTSUPP=10045, WSAEAFNOSUPPORT=10047, WSAEADDRNOTAVAIL=10049, WSAECONNABORTED=10053,
       WSAENOBUFS=10055, WSAEISCONN=10056, WSAENOTCONN=10057, WSAECONNREFUSED=10061,
       WSA_IO_PENDING=997, WSA_OPERATION_ABORTED=995, WSANOTINITIALISED=10093 };
typedef struct process process_t;
typedef struct thread thread_t;
typedef struct object kobject_t;
typedef struct { kobject_t *obj; uint32_t access, inherit; } handle_entry_t;
struct object {
    uint32_t type, refs;
    int signaled;
    union { struct { void *sock; } net; struct { void *file; uint32_t access; void *io; } file;
            struct { int count; } sem; struct { thread_t *owner; } mutant; } u;
};
struct thread { int state; kobject_t *object; };
struct process { kobject_t *object; int teardown; handle_entry_t handles[MAX_HANDLES]; unsigned handle_count; };
typedef struct { int waiting; } ipc_thread_t;
typedef uint32_t ip4_t;
typedef struct bchunk { struct bchunk *next; uint64_t pad; } bchunk_t;
typedef struct { bchunk_t *head, *tail; uint32_t hoff, toff, len, limit; } bq_t;
struct ipc_iosb { uint64_t status, information; };
struct shz_sockaddr_in { uint16_t family, port_be; uint32_t addr_be; uint8_t zero[8]; };
#define SHZ_AF_INET 2
static uint16_t bs16(uint16_t n) { return (uint16_t)((n << 8) | (n >> 8)); }
static uint32_t bs32(uint32_t n) { return __builtin_bswap32(n); }
#include "production_types.h"

static unsigned checked, failed, allocations, frees, ipc_stat_irps, aborts, transport_closes;
static unsigned irq_disabled, net_locked, net_lock_calls, packet_count;
static int allocation_failure, copy_failure, connect_failure, auto_establish;
static uint64_t packet_key, packet_context, packet_bytes;
static int32_t packet_status;
static uintptr_t last_error;
static int winsock_started=1;
static unsigned char delivered[262144];
static size_t delivered_count;
static process_t process;
static kobject_t process_object = { .type=2, .refs=1 }, event_object = { .type=OB_EVENT, .refs=1 }, port_object = { .type=OB_IOCP, .refs=1 };
static uint32_t event_handle, port_handle;
static thread_t thread;
static tcb_t *retired[64];
static unsigned retired_count;
sock_t *g_socks;
tcb_t *g_tcbs;
static void (*preempt)(void);
static int snapshot_active;
static kobject_t *snapshot_socket;
static void replace_snapshot(void);
#define CHECK(c) do { ++checked; if (!(c)) { ++failed; fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #c); } } while (0)

static uint64_t irq_save(void) { uint64_t old=irq_disabled; irq_disabled=1; return old; }
static void irq_restore(uint64_t old) { irq_disabled=(unsigned)old; if (!old && preempt) { void (*f)(void)=preempt; preempt=NULL; f(); } }
static void *kzalloc(size_t size) { if (allocation_failure && --allocation_failure == 0) return NULL; void *p=calloc(1,size); if (p) ++allocations; return p; }
static void kfree(void *p) { if (p) { ++frees; free(p); } }
static int copy_from_user(process_t *p, void *out, uint64_t in, uint64_t size) { (void)p; if (in<4096 || size>UINTPTR_MAX-in || copy_failure) return 1; memcpy(out,(void *)(uintptr_t)in,(size_t)size); return 0; }
static int copy_to_user(process_t *p, uint64_t out, const void *in, uint64_t size) { (void)p; if (out<4096 || size>UINTPTR_MAX-out || copy_failure) return 1; memcpy((void *)(uintptr_t)out,in,(size_t)size); return 0; }
static void ob_ref(kobject_t *o) {
    if (snapshot_active && o==&port_object) {
        snapshot_active=0; CHECK(irq_disabled);
        if (irq_disabled) preempt=replace_snapshot;
        else replace_snapshot();                       /* deterministic old snapshot interleaving */
    }
    assert(o->refs); ++o->refs;
}
void ioctx_free(kobject_t *o);
static void ob_deref(kobject_t *o) { assert(o->refs); if (--o->refs==0) { if (o->type==OB_SOCKET) { assert(!o->u.net.sock); ioctx_free(o); } kfree(o); } }
static void ob_reset_event(kobject_t *o) { o->signaled=0; }
static void ob_signal_event(kobject_t *o) { o->signaled=1; }
static void ob_release_check(kobject_t *o) { (void)o; }
static thread_t *thread_current(void) { return &thread; }
static int thread_must_die(thread_t *t) { (void)t; return 0; }
static ipc_thread_t *ipc_thread(thread_t *t, int create) { static ipc_thread_t x; (void)t; (void)create; return &x; }
static void thread_wake(thread_t *t) { t->state=0; }
static void thread_block_current(void) { abort(); }
static void apc_queue(thread_t *t, uint64_t a, uint64_t b, uint64_t c, uint64_t d) { (void)t;(void)a;(void)b;(void)c;(void)d;abort(); }
int32_t iocp_post(kobject_t *o,uint64_t key,uint64_t context,int32_t status,uint64_t bytes) { assert(o==&port_object); ++packet_count; packet_key=key; packet_context=context; packet_status=status; packet_bytes=bytes; return 0; }
static int32_t handle_insert(process_t *, kobject_t *, uint32_t, uint32_t *);
static int32_t handle_ref(process_t *,uint64_t,uint32_t,kobject_t **,uint32_t *);
static int32_t handle_close(process_t *,uint64_t);
static int32_t ipc_ref_handle(process_t *p,uint64_t h,uint32_t type,kobject_t **o,uint32_t *access) { return handle_ref(p,h&~3ull,type,o,access); }
static void net_socket_handle_closing(kobject_t *);
static void net_socket_last_handle_closed(kobject_t *);
static void ipc_handle_closed(process_t *,kobject_t *);
static void file_object_closed(kobject_t *o) { (void)o; abort(); }
static void ntdrv_device_handle_closing(kobject_t *o) { (void)o; abort(); }
static void notify_handle_closed(kobject_t *o) { (void)o; }
static void npfs_handle_closed(kobject_t *o) { (void)o; }
static void iocp_handle_closed(kobject_t *o) { (void)o; }
static void job_handle_closed(kobject_t *o) { (void)o; }
#include "production_irp.h"
#include "production_objects.h"
#include "production_core.h"

static void sock_extension_progress(sock_t *);
static void sock_extension_closed(sock_t *);
static int32_t read_sa(process_t *,uint64_t,uint64_t,ip4_t *,uint16_t *);
static void net_lock(void) { assert(!net_locked && !irq_disabled); net_locked=1; ++net_lock_calls; }
static void net_unlock(void) { assert(net_locked); if (auto_establish) { auto_establish=0; for(sock_t *s=g_socks;s;s=s->next) if(s->tcb) { s->tcb->state=TCPS_ESTABLISHED; s->tcb->was_est=1; sock_extension_progress(s); } } net_locked=0; }
static void net_wake_all(void) {}
void sock_release(sock_t *s) { assert(s->refs>0); if (--s->refs==0 && s->dead) kfree(s); }
static void sock_unlink(sock_t *s) { sock_t **p=&g_socks; while(*p && *p!=s) p=&(*p)->next; if(*p) *p=s->next; }
static int ip_is_broadcast(ip4_t ip) { return ip==0xffffffffu; }
int tcp_can_write(const tcb_t *t) { return t->state==TCPS_ESTABLISHED || t->state==TCPS_CLOSE_WAIT; }
void tcp_abort(tcb_t *t,int rst) { (void)rst; assert(net_locked); ++aborts; t->state=TCPS_CLOSED; }
void tcp_sock_closed(sock_t *s) { assert(net_locked); if(s->tcb) { ++transport_closes; assert(retired_count<64); retired[retired_count++]=s->tcb; s->tcb->sock=NULL; s->tcb=NULL; } }
tcb_t *tcp_connect(sock_t *s,ip4_t ip,uint16_t port,int32_t *status) {
    assert(net_locked && !s->tcb); if(connect_failure) { *status=NET_ERR(WSAECONNREFUSED); return NULL; }
    tcb_t *t=calloc(1,sizeof *t); assert(t); t->sock=s; t->state=TCPS_SYN_SENT; t->sndq.limit=32768; t->rcvq.limit=65536; s->tcb=t; s->rip=ip; s->rport=port; return t;
}
void tcp_output(tcb_t *t) { (void)t; assert(net_locked); }
uint32_t bq_space(const bq_t *q) { return q->limit-q->len; }
int32_t bq_write_user(bq_t *q,process_t *p,uint64_t data,uint32_t size,uint32_t *got) {
    assert(net_locked); *got=0; if(copy_failure) return STATUS_ACCESS_VIOLATION;
    assert(size<=bq_space(q) && delivered_count+size<=sizeof delivered);
    if(copy_from_user(p,delivered+delivered_count,data,size)) return STATUS_ACCESS_VIOLATION;
    delivered_count+=size; q->len+=size; *got=size; return 0;
}
#include "../../kernel64/net_sock_extensions.h"
#include "production_sock.h"

/* Windows primitive ABI for the exact production wrapper body. */
#define WINAPI
#define NTAPI
#define SOL_SOCKET 0xffffu
#define SO_TYPE 0x1008u
#define FALSE 0
#define TRUE 1
#define SOCKET_ERROR (-1)
typedef int BOOL;
typedef int32_t LONG;
typedef uint32_t DWORD,ULONG;
typedef uintptr_t ULONG_PTR,SOCKET;
typedef ULONG *PULONG;
typedef struct { uint16_t family; char bytes[14]; } sockaddr_unused;
struct sockaddr { uint16_t family; char bytes[14]; };
struct sockaddr_in { uint16_t family,port; uint32_t address; unsigned char zero[8]; };
typedef struct { ULONG_PTR Internal,InternalHigh,Offset,hEvent; } OVERLAPPED;
static void SetLastError(DWORD value) { last_error=value; }
static int shz_ws2_extensions_started(void) { return winsock_started; }
LONG NTAPI NtShzSockIoctl(ULONG_PTR h,ULONG_PTR command,const void *in,ULONG_PTR size,void *out,ULONG_PTR outsize,PULONG ret) {
    (void)out;(void)outsize;(void)ret; return sock_extension_ioctl(&process,h,(uint32_t)command,(uintptr_t)in,size);
}
LONG NTAPI NtShzSockGetOpt(ULONG_PTR h,ULONG_PTR level,ULONG_PTR option,void *out,PULONG size) {
    kobject_t *o; int32_t status=handle_ref(&process,h,OB_SOCKET,&o,NULL);
    (void)level;(void)option; if(status) return status;
    if(!o->u.net.sock) status=STATUS_INVALID_HANDLE;
    else if(*size<4) status=STATUS_ACCESS_VIOLATION;
    else { *(uint32_t *)out=(uint32_t)((sock_t *)o->u.net.sock)->type; *size=4; }
    ob_deref(o); return status;
}
#include "../dlls/ws2_32/ws2_extensions.c"

static uint32_t new_socket(int type)
{
    kobject_t *o=kzalloc(sizeof *o); sock_t *s=kzalloc(sizeof *s); uint32_t h;
    assert(o && s); o->type=OB_SOCKET; o->refs=1; o->u.net.sock=s;
    ioctx_t *io=ipc_ioctx(o,1); assert(io); io->handles=1; io->sync=0;
    s->type=type; s->refs=1; s->bound=1; s->lport=32100; s->next=g_socks; g_socks=s;
    assert(!handle_insert(&process,o,0x1fffff,&h)); ob_deref(o); return h;
}
static kobject_t *socket_object(uint32_t h) { return process.handles[h/4-1].obj; }
static sock_t *socket_state(uint32_t h) { return socket_object(h)->u.net.sock; }
static int issue(uint32_t h,OVERLAPPED *ov,const void *buffer,DWORD size)
{
    struct sockaddr_in address={2,0x5000,0x0100007f,{0}};
    return extension_connect(h,(struct sockaddr *)&address,sizeof address,(void *)buffer,size,NULL,ov);
}
static void bind_port(uint32_t h,uint64_t key)
{
    uint64_t value[2]={port_handle,key}; CHECK(!ipc_set_completion_info(&process,socket_object(h),30,(uintptr_t)value,sizeof value));
}
static void establish(uint32_t h)
{
    sock_t *s=socket_state(h); net_lock(); s->tcb->state=TCPS_ESTABLISHED; s->tcb->was_est=1; sock_extension_progress(s); net_unlock();
}
static void reap(void) { net_lock(); sock_extensions_poll(); net_unlock(); }
static void assert_idle(void) { CHECK(!all_irps && !ipc_stat_irps && process_object.refs==1 && !irq_disabled && !net_locked); }
static void published(void) { for(unsigned i=0;i<MAX_HANDLES;i++) if(process.handles[i].obj && process.handles[i].obj->type==OB_SOCKET) CHECK(((ioctx_t *)process.handles[i].obj->u.file.io)->handles==2); }
static void replace_snapshot(void)
{
    uint64_t value[2]={0,0xbeef};
    CHECK(!ipc_set_completion_info(&process,snapshot_socket,61,(uintptr_t)value,sizeof value));
}

int main(void)
{
    uint32_t h,dup; sock_t *s; kobject_t *o; int found;
    OVERLAPPED ov={0}; char data[40000]; memset(data,0x5a,sizeof data);
    process.object=&process_object; thread.object=&process_object;
    CHECK(offsetof(kobject_t,u.file.io)-offsetof(kobject_t,u.net.sock)==16);
    assert(!handle_insert(&process,&event_object,0,&event_handle)); assert(!handle_insert(&process,&port_object,0,&port_handle));
    h=new_socket(SK_STREAM); s=socket_state(h); s->bound=0;
    CHECK(!sock_initial_flags(&process,h,s,0) && ((ioctx_t *)socket_object(h)->u.file.io)->sync && process.handles[h/4-1].inherit==1);
    CHECK(!sock_initial_flags(&process,h,s,0x81) && !((ioctx_t *)socket_object(h)->u.file.io)->sync && !process.handles[h/4-1].inherit);
    CHECK(sock_initial_flags(&process,h,s,2)==NET_ERR(WSAEINVAL));
    ob_ref(socket_object(h)); CHECK(!ipc_give_handle(&process,socket_object(h),0x1fffff,0,0,&dup));
    CHECK(sock_initial_flags(&process,h,s,0)==NET_ERR(WSAEINVAL)); CHECK(!handle_close(&process,dup));
    s->bound=1; CHECK(sock_initial_flags(&process,h,s,0)==NET_ERR(WSAEINVAL));
    CHECK(!handle_close(&process,h)); assert_idle();
    h=new_socket(SK_STREAM); ov.hEvent=event_handle; bind_port(h,0x123);
    delivered_count=packet_count=0; CHECK(!issue(h,&ov,data,9) && last_error==WSA_IO_PENDING);
    ((ioctx_t *)socket_object(h)->u.file.io)->key=0x999;
    ((ioctx_t *)socket_object(h)->u.file.io)->notify=1;
    CHECK((int32_t)ov.Internal==STATUS_PENDING && !event_object.signaled && packet_count==0 && ipc_stat_irps==1);
    s=socket_state(h); CHECK(s->refs==2 && socket_object(h)->refs==2); establish(h);
    CHECK(ov.Internal==0 && ov.InternalHigh==9 && event_object.signaled && packet_count==1);
    CHECK(obj_signaled(socket_object(h),&thread));
    CHECK(packet_key==0x123 && packet_context==(uintptr_t)&ov && packet_bytes==9 && packet_status==0);
    CHECK(delivered_count==9 && !memcmp(delivered,data,9) && s->connected && s->extension_context_pending && !s->extension && s->refs==1);
    assert_idle();
    CHECK(extension_disconnect(h,&ov,2,0) && ov.Internal==0 && !ov.InternalHigh && packet_count==1 && !s->tcb && s->bound && !s->extension_no_reuse);
    CHECK(!issue(h,&ov,data,9)); establish(h); CHECK(!ov.Internal && s->tcb && s->bound);
    CHECK(extension_disconnect(h,NULL,0,0) && s->extension_no_reuse && !s->tcb);
    CHECK(!issue(h,&ov,NULL,0) && last_error==WSAEINVAL); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x222); ov.hEvent=event_handle|1u; packet_count=0;
    CHECK(!issue(h,&ov,NULL,0)); establish(h); CHECK(event_object.signaled && packet_count==0 && !ov.Internal);
    CHECK(extension_disconnect(h,&ov,2,0) && event_object.signaled && packet_count==0); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x333); ov.hEvent=0; delivered_count=packet_count=0;
    CHECK(!issue(h,&ov,data,sizeof data)); establish(h);
    s=socket_state(h); CHECK(ov.Internal==STATUS_PENDING && ov.InternalHigh==0 && s->extension && s->extension->irp->done==16384);
    CHECK(delivered_count==16384); reap(); CHECK(s->extension->irp->done==32768 && ov.Internal==STATUS_PENDING);
    net_lock(); s->tcb->sndq.len=0; sock_extension_progress(s); net_unlock();
    CHECK(!ov.Internal && ov.InternalHigh==sizeof data && delivered_count==sizeof data && !memcmp(delivered,data,sizeof data));
    CHECK(packet_count==1 && packet_bytes==sizeof data && !packet_status); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x444); ov.hEvent=event_handle; packet_count=0;
    CHECK(!issue(h,&ov,data,sizeof data)); o=socket_object(h); s=socket_state(h);
    ob_ref(o); preempt=published; CHECK(!ipc_give_handle(&process,o,0x1fffff,0,0,&dup)); CHECK(((ioctx_t *)o->u.file.io)->handles==2);
    CHECK(!handle_close(&process,h) && !s->dead && ov.Internal==STATUS_PENDING && ((ioctx_t *)o->u.file.io)->handles==1);
    unsigned locks=net_lock_calls;
    irp_cancel_matching(&process,NULL,o,(uintptr_t)&ov,&found);
    CHECK(found && net_lock_calls==locks && (int32_t)ov.Internal==STATUS_CANCELLED && event_object.signaled);
    CHECK(packet_count==1 && packet_status==STATUS_CANCELLED && !packet_bytes && s->extension && s->extension->cancelled && !s->extension->irp);
    CHECK(s->tcb && s->refs==2); reap(); CHECK(!s->extension && !s->tcb && s->refs==1); CHECK(!handle_close(&process,dup)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x555); packet_count=delivered_count=0; CHECK(!issue(h,&ov,data,sizeof data)); establish(h);
    s=socket_state(h); CHECK(s->extension && s->extension->irp->done==16384);
    CHECK(!handle_close(&process,h)); CHECK((int32_t)ov.Internal==STATUS_CANCELLED && ov.InternalHigh==16384 && packet_count==1 && packet_bytes==16384);
    CHECK(!g_socks); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x666); ov.hEvent=0; packet_count=0; CHECK(!issue(h,&ov,NULL,0));
    ipc_io_thread_exit(&thread); CHECK((int32_t)ov.Internal==STATUS_CANCELLED && packet_count==1 && packet_status==STATUS_CANCELLED);
    reap(); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); ov.hEvent=event_handle; CHECK(!issue(h,&ov,NULL,0)); process.teardown=1;
    uint64_t unchanged=ov.Internal; unsigned packets=packet_count; ipc_io_teardown(&process);
    CHECK(ov.Internal==unchanged && packet_count==packets && !all_irps && !ipc_stat_irps);
    process.teardown=0; reap(); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x777); ov.hEvent=event_handle; packet_count=0; connect_failure=1;
    CHECK(!issue(h,&ov,NULL,0) && last_error==WSAECONNREFUSED && (int32_t)ov.Internal==NET_ERR(WSAECONNREFUSED));
    CHECK(!event_object.signaled && packet_count==0 && !socket_state(h)->extension_context_pending); connect_failure=0;
    allocation_failure=1; CHECK(!issue(h,&ov,NULL,0) && last_error==WSAENOBUFS); allocation_failure=2;
    CHECK(!issue(h,&ov,NULL,0) && last_error==WSAENOBUFS); allocation_failure=0;
    ov.hEvent=0x10000; CHECK(!issue(h,&ov,NULL,0) && last_error==WSAENOTSOCK); ov.hEvent=event_handle;
    CHECK(!extension_connect(h,NULL,16,NULL,0,NULL,&ov) && last_error==WSAEFAULT);
    CHECK(!extension_connect(h,(struct sockaddr *)&data,1,NULL,0,NULL,&ov) && last_error==WSAEFAULT);
    CHECK(!extension_disconnect(h,&ov,4,0) && last_error==WSAEINVAL);
    CHECK(!extension_disconnect(h,&ov,2,1) && last_error==WSAEINVAL);
    CHECK(!extension_disconnect(h,NULL,2,0) && last_error==WSAENOTCONN);
    CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); bind_port(h,0x778); packet_count=0; ov.hEvent=0;
    snapshot_socket=socket_object(h); snapshot_active=1; CHECK(!issue(h,&ov,NULL,0));
    CHECK(!((ioctx_t *)snapshot_socket->u.file.io)->port && ((ioctx_t *)snapshot_socket->u.file.io)->key==0xbeef);
    establish(h); CHECK(packet_count==1 && packet_key==0x778 && packet_context==(uintptr_t)&ov && !packet_status);
    CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_DGRAM); CHECK(!issue(h,&ov,NULL,0) && last_error==WSAEOPNOTSUPP); CHECK(!handle_close(&process,h));
    h=new_socket(SK_STREAM); ov.hEvent=event_handle; s=socket_state(h); s->bound=0; CHECK(!issue(h,&ov,NULL,0) && last_error==WSAEINVAL); s->bound=1;
    ((ioctx_t *)socket_object(h)->u.file.io)->sync=1;
    CHECK(!issue(h,&ov,NULL,0) && last_error==WSAEINVAL);
    ((ioctx_t *)socket_object(h)->u.file.io)->sync=0;
    auto_establish=1; packet_count=0; delivered_count=0; CHECK(!issue(h,&ov,data,7) && last_error==WSA_IO_PENDING && !ov.Internal && event_object.signaled);
    CHECK(!s->extension && s->refs==1); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM); delivered_count=0; CHECK(!issue(h,&ov,data,8)); s=socket_state(h); net_lock();
    s->tcb->state=TCPS_ESTABLISHED; s->tcb->was_est=1; copy_failure=1; sock_extension_progress(s); copy_failure=0; net_unlock();
    /* Failed user copy also makes mock IOSB writes fail; saved generic IRP status is authoritative completion. */
    CHECK(!s->extension && !s->tcb && event_object.signaled); CHECK(!handle_close(&process,h)); assert_idle();

    h=new_socket(SK_STREAM);
    unsigned char guid[17]={0,0xb9,0x07,0xa2,0x25,0xf3,0xdd,0x60,0x46,0x8e,0xe9,0x76,0xe5,0x8c,0x74,0x06,0x3e};
    unsigned char output[10]; memset(output,0xa5,sizeof output); DWORD count=0; void *ptr=NULL;
    CHECK(!shz_ws2_extension_pointer(h,guid+1,16,output+1,8,&count) && count==sizeof ptr && output[0]==0xa5 && output[9]==0xa5);
    memcpy(&ptr,output+1,sizeof ptr); CHECK(ptr==(void *)extension_connect);
    CHECK(shz_ws2_extension_pointer(h,guid+1,15,output+1,8,&count)==-1 && last_error==WSAEFAULT);
    CHECK(shz_ws2_extension_pointer(h,guid+1,16,output+1,7,&count)==-1 && last_error==WSAEFAULT);
    guid[1]^=1; CHECK(shz_ws2_extension_pointer(h,guid+1,16,output+1,8,&count)==-1 && last_error==WSAEOPNOTSUPP);
    CHECK(shz_ws2_extension_pointer(0,guid+1,16,output+1,8,&count)==-1 && last_error==WSAENOTSOCK);
    CHECK(!handle_close(&process,h)); assert_idle();
    winsock_started=0;
    CHECK(!issue(0,&ov,NULL,0) && last_error==WSANOTINITIALISED);
    CHECK(!extension_disconnect(0,NULL,0,0) && last_error==WSANOTINITIALISED);
    winsock_started=1;
    CHECK(aborts>=4 && transport_closes>=8 && !g_socks);
    CHECK(!handle_close(&process,event_handle) && !handle_close(&process,port_handle));
    CHECK(event_object.refs==1 && port_object.refs==1 && process_object.refs==1 && allocations==frees);
    for(unsigned i=0;i<retired_count;i++) free(retired[i]);
    printf("net extension production host: %u checked, %u failed\n",checked,failed);
    return failed ? 1 : 0;
}
