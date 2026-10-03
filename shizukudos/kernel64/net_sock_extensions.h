/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded TCP-backed ConnectEx/DisconnectEx implementation.
 * Included in net_sock.c; the host fixture includes this exact production body.
 * All transport work runs with the net mutex held. Queue/cancel transitions also
 * disable interrupts, since generic IRP cancellation can run outside that mutex.
 * Cancel only detaches the IRP and marks the owned request; transport abort and
 * request release run at the next net timer/notification, never under a foreign
 * net-mutex owner. No user worker thread, fake completion, or AFD compatibility.
 * AcceptEx (IPv4 TCP only) uses the freestanding ntwin32/steam_socket/accept_op.c
 * registry: the owner is the issuing kernel process (pid, create tick), sockets
 * are named by never-reused (id, epoch) identities, and the completion reports
 * the actual received byte count, never the receive reservation.
 */
#ifndef SHZ_NET_EXT_HOST_TEST
#include "ipc.h"
#endif
#include "../../ntwin32/steam_socket/accept_op.c"
static void sock_acceptex_closed(sock_t *s);
static void sock_acceptex_poll(void);

#define SHZ_SOCK_CONNECT_EX 0x53480010u
#define SHZ_SOCK_DISCONNECT_EX 0x53480011u
/* 0x53480012 = private initial socket attributes (net_sock.c op_ioctl). */
#define SHZ_SOCK_ACCEPT_EX 0x53480013u
/* 0x53480014 = authenticated GetAcceptExSockaddrs allocation lease (verified
 * unused in kernel64/, win64/ and ntwin32/ before claiming; handle must be 0). */
#define SHZ_SOCK_ACCEPTEX_LOOKUP 0x53480014u
#define SHZ_SO_UPDATE_ACCEPT_CONTEXT 0x700bu
#define SHZ_ACCEPTEX_ADDRESS_LIMIT 65536u   /* local+remote reservation kernel staging bound */
#define SHZ_CONNECT_COPY_SLICE 16384u
#ifndef SHZ_SOCKET_EXTENSION_REQUEST_DEFINED
#define SHZ_SOCKET_EXTENSION_REQUEST_DEFINED
struct shz_sock_extension_request {
    uint64_t address, address_length, buffer, length, overlapped;
    uint32_t flags, reserved;
};
#endif
_Static_assert(sizeof(struct shz_sock_extension_request) == 48, "private socket extension ABI");
struct sock_extension {
    irp_t *irp;                         /* generic IRP owns proc/event/port/file references */
    sock_t *sock;                       /* separate sock ref survives IRP cancel/free */
    int cancelled;
};

static void sock_extension_cancel(irp_t *irp)
{
    struct sock_extension *request = irp->owner;
    /* Called with interrupts disabled; never acquire the net mutex here. */
    if (request && request->irp == irp) {
        request->irp = 0;
        request->cancelled = 1;
    }
    irp->owner = 0;
}

static void sock_extension_release(sock_t *s, int32_t status)
{
    struct sock_extension *request = s->extension;
    irp_t *irp = request ? request->irp : 0;
    if (!request) return;
    s->extension = 0;
    request->irp = 0;
    if (status) {
        /* Cancel/error never leaves an accidental live connection behind. */
        if (s->tcb) { tcp_abort(s->tcb, 1); tcp_sock_closed(s); }
        s->connected = s->connecting = 0;
        s->extension_context_pending = 0;
        s->rip = 0; s->rport = 0;
    } else {
        s->connected = 1;
        s->connecting = 0;
    }
    if (irp) {
        irp->owner = 0;
        irp_complete(irp, status, irp->done);
    }
    kfree(request);
    sock_release(s);                   /* request's sock reference */
}

static void sock_extension_progress(sock_t *s)
{
    const uint64_t flags = irq_save();
    struct sock_extension *request = s->extension;
    irp_t *irp;
    tcb_t *t;
    int32_t status = 0;
    if (!request || s->extension_busy) { irq_restore(flags); return; }
    s->extension_busy = 1;
    irp = request->irp;
    t = s->tcb;
    if (request->cancelled || !irp || s->dead) {
        sock_extension_release(s, STATUS_CANCELLED);
        goto out;
    }
    if (!t) { status = NET_ERR(WSAENOTCONN); goto complete; }
    if (t->err) { status = t->err; goto complete; }
    if (t->state == TCPS_SYN_SENT || (t->state == TCPS_SYN_RCVD && !t->passive)) goto out;
    if (!tcp_can_write(t) || t->fin_queued) { status = NET_ERR(WSAECONNABORTED); goto complete; }
    if (irp->done < irp->len) {
        uint32_t n = bq_space(&t->sndq), copied = 0;
        if (n > irp->len - irp->done) n = (uint32_t)(irp->len - irp->done);
        if (n > SHZ_CONNECT_COPY_SLICE) n = SHZ_CONNECT_COPY_SLICE;
        if (!n) goto out;
        status = bq_write_user(&t->sndq, irp->proc, irp->buf + irp->done, n, &copied);
        irp->done += copied;
        if (copied) tcp_output(t);
        if (status) goto complete;
        if (irp->done < irp->len) goto out;
    }
complete:
    sock_extension_release(s, status);
out:
    s->extension_busy = 0;
    irq_restore(flags);
}

void sock_extensions_poll(void)
{
    sock_t *s;
    /* Called under the net lock. The list contains one base ref per live socket. */
    for (s = g_socks; s; s = s->next) sock_extension_progress(s);
    sock_acceptex_poll();
}

static void sock_extension_closed(sock_t *s)
{
    const uint64_t flags = irq_save();
    sock_acceptex_closed(s);
    struct sock_extension *request = s->extension;
    if (request) {
        irp_t *irp = request->irp;
        if (irp) {
            sock_extension_cancel(irp);
            irp_complete(irp, STATUS_CANCELLED, irp->done);
        }
        /* Last close owns the net mutex, so no deferred transport work is needed. */
        sock_extension_release(s, STATUS_CANCELLED);
    }
    irq_restore(flags);
}

static int32_t sock_extension_prepare(process_t *p, kobject_t *object, uint64_t overlapped, irp_t **out)
{
    uint64_t value[4];                  /* exact Windows x64 OVERLAPPED: 32 bytes */
    struct ipc_iosb pending = { STATUS_PENDING, 0 };
    int32_t status;
    if (!overlapped) return NET_ERR(WSAEINVAL);
    if (copy_from_user(p, value, overlapped, sizeof value)) return STATUS_ACCESS_VIOLATION;
    if (copy_to_user(p, overlapped, &pending, sizeof pending)) return STATUS_ACCESS_VIOLATION;
    status = irp_prepare(p, object, value[3] & ~1ull, 0, (value[3] & 1) ? 0 : overlapped,
                         overlapped, IRP_WRITE, out);
    if (!status) (*out)->sync = 0;       /* ConnectEx / overlapped DisconnectEx are always asynchronous-capable */
    return status;
}

static int32_t sock_extension_ioctl(process_t *p, uint64_t h, uint32_t command, uint64_t input, uint64_t input_size)
{
    struct shz_sock_extension_request value;
    struct sock_extension *request = 0;
    kobject_t *object;
    sock_t *s;
    irp_t *irp = 0;
    ip4_t ip = 0;
    uint16_t port = 0;
    int32_t status;
    uint64_t flags;
    if (input_size != sizeof value || copy_from_user(p, &value, input, sizeof value)) return NET_ERR(WSAEFAULT);
    if (value.reserved || value.length > 0xffffffffull ||
        (command == SHZ_SOCK_CONNECT_EX ? value.flags != 0 : (value.flags & ~2u) != 0)) return NET_ERR(WSAEINVAL);
    if (command == SHZ_SOCK_CONNECT_EX) {
        if (!value.overlapped) return NET_ERR(WSAEINVAL);
        if (value.length && !value.buffer) return NET_ERR(WSAEFAULT);
        status = read_sa(p, value.address, value.address_length, &ip, &port);
        if (status) return status;
        if (!ip || !port || ip_is_broadcast(ip)) return NET_ERR(WSAEADDRNOTAVAIL);
    }
    status = ipc_ref_handle(p, h, OB_SOCKET, &object, 0);
    if (status) return status;
    net_lock();
    s = object->u.net.sock;
    if (!s || s->dead) { status = STATUS_INVALID_HANDLE; goto unlock; }
    ++s->refs;                         /* issuing operation's reference */
    sock_extension_progress(s);        /* reap a prior canceled request before reuse */
    if (s->type != SK_STREAM || s->listening) { status = NET_ERR(WSAEOPNOTSUPP); goto release; }
    if (s->extension) { status = NET_ERR(WSAEALREADY); goto release; }
    if (command == SHZ_SOCK_CONNECT_EX) {
        if (!object->u.file.io || ((ioctx_t *)object->u.file.io)->sync) { status = NET_ERR(WSAEINVAL); goto release; }
        if (!s->bound || s->extension_no_reuse) { status = NET_ERR(WSAEINVAL); goto release; }
        if (s->tcb) { status = NET_ERR(WSAEISCONN); goto release; }
        request = kzalloc(sizeof *request);
        if (!request) { status = STATUS_NO_MEMORY; goto release; }
        status = sock_extension_prepare(p, object, value.overlapped, &irp);
        if (status) { kfree(request); goto release; }
        s->extension_context_pending = 1;
        if (!tcp_connect(s, ip, port, &status)) {
            s->extension_context_pending = 0;
            kfree(request);
            irp_complete(irp, status, 0);
            goto finish;
        }
        request->irp = irp;
        request->sock = s;
        irp->owner = request;
        irp->cancel = sock_extension_cancel;
        irp->buf = value.buffer;
        irp->len = value.length;
        flags = irq_save();
        ++s->refs;                     /* queue ownership survives generic IRP cancellation */
        s->extension = request;
        s->connecting = s->want_write = 1;
        s->close_reported = 0;
        irp_mark_pending(irp);
        irq_restore(flags);
        /* Always return PENDING once queued, even when loopback completes at unlock. */
        goto finish;
    }
    if (!s->tcb || !s->tcb->was_est || s->tcb->state == TCPS_CLOSED) {
        status = NET_ERR(WSAENOTCONN); goto release;
    }
    if (value.overlapped) {
        if (((ioctx_t *)object->u.file.io)->sync) { status = NET_ERR(WSAEOPNOTSUPP); goto release; }
        status = sock_extension_prepare(p, object, value.overlapped, &irp);
        if (status) goto release;
    }
    /* Retain the socket and local binding; the real old TCB runs FIN/TIME_WAIT
     * as an orphan. tcp_connect still rejects a tuple retained by TIME_WAIT. */
    tcp_sock_closed(s);
    s->connected = s->connecting = s->shut_rd = 0;
    s->extension_context_pending = 0;
    s->extension_no_reuse = !(value.flags & 2);
    s->rip = 0; s->rport = 0;
    status = STATUS_SUCCESS;
    if (irp) {
        irp_complete(irp, status, 0);
        goto finish;
    }
release:
    sock_release(s);
unlock:
    net_unlock();
    ob_deref(object);
    return status;
finish:
    sock_release(s);
    net_unlock();
    ob_deref(object);
    return irp_finish(irp);
}

/* ---------------------------------------------------------------- AcceptEx
 * Request: address = accept SOCKET handle, buffer/length = AcceptEx buffer and
 * dwReceiveDataLength, address_length = local | (uint64)remote << 32, overlapped
 * = caller OVERLAPPED (required), flags/reserved = 0. The IRP is issued on the
 * listening socket. Pending requests are served FIFO per listener. */
struct sock_acceptex {
    struct sock_acceptex *next;
    irp_t *irp;                         /* detached by cancel (interrupts off) */
    sock_t *listen, *accept;            /* request-owned sock references */
    uint8_t *staging;                   /* encoded local+remote blocks, allocated at submit */
    uint64_t buffer;
    struct ntw_acceptex_plan plan;
    ntw_acceptex_token token;
    int cancelled;
};
static struct ntw_acceptex_table g_acceptex_table;
static struct sock_acceptex *g_acceptex_head;
static uint32_t g_acceptex_next_id, g_acceptex_epoch;
static int g_acceptex_ready, g_acceptex_busy;

static void sock_acceptex_init(void)
{
    if (g_acceptex_ready) return;
    ntw_acceptex_table_init(&g_acceptex_table);
    g_acceptex_epoch = 1;
    g_acceptex_ready = 1;
}

/* Never-reused socket identity: a 32-bit id within a 32-bit epoch. 0 = exhausted. */
static int sock_acceptex_ref(sock_t *s, struct ntw_ref *out)
{
    if (!s->acceptex_epoch) {
        if (++g_acceptex_next_id == 0) {
            if (g_acceptex_epoch == 0xffffffffu) return 0;
            ++g_acceptex_epoch;
            g_acceptex_next_id = 1;
        }
        s->acceptex_id = g_acceptex_next_id;
        s->acceptex_epoch = g_acceptex_epoch;
    }
    out->id = s->acceptex_id;
    out->generation = s->acceptex_epoch;
    return 1;
}

/* Owner = the issuing kernel process, never an application-supplied value. The
 * creation tick distinguishes a later process that reuses the pid. */
static struct ntw_ref sock_acceptex_owner(const process_t *p)
{
    struct ntw_ref r;
    r.id = (uint32_t)p->pid;
    r.generation = (uint32_t)(p->create_tick ^ (p->create_tick >> 32)) | 0x80000000u;
    return r;
}

static int32_t sock_acceptex_error(enum ntw_acceptex_status st)
{
    switch (st) {
    case NTW_ACCEPTEX_OK: return 0;
    case NTW_ACCEPTEX_FAMILY: return NET_ERR(WSAEAFNOSUPPORT);
    case NTW_ACCEPTEX_OVERFLOW: return NET_ERR(WSAEFAULT);
    case NTW_ACCEPTEX_FULL:                 /* transient: a slot frees on completion/close */
    case NTW_ACCEPTEX_EXHAUSTED:            /* permanent: every slot generation retired */
        return NET_ERR(WSAENOBUFS);
    default: return NET_ERR(WSAEINVAL);
    }
}

static void sock_acceptex_cancel(irp_t *irp)
{
    struct sock_acceptex *request = irp->owner;
    /* Interrupts disabled; never acquire the net mutex here. */
    if (request && request->irp == irp) {
        request->irp = 0;
        request->cancelled = 1;
    }
    irp->owner = 0;
}

/* Net lock held, interrupts disabled. Unlinks and frees the request. On failure
 * the registry op is cancelled and any connection already handed to the accept
 * socket is aborted, so a failed AcceptEx never leaves a live accepted socket. */
static void sock_acceptex_finish(struct sock_acceptex *request, int32_t status, uint32_t received)
{
    struct sock_acceptex **link = &g_acceptex_head;
    sock_t *as = request->accept;
    irp_t *irp = request->irp;
    while (*link && *link != request) link = &(*link)->next;
    if (*link) *link = request->next;
    request->irp = 0;
    if (status) {
        ntw_acceptex_cancel(&g_acceptex_table, request->token);
        if (as->tcb) { tcp_abort(as->tcb, 1); tcp_sock_closed(as); }
        as->connected = 0;
        as->bound = 0;
        as->lip = 0; as->lport = 0; as->rip = 0; as->rport = 0;
        received = 0;
    } else if (ntw_acceptex_complete(&g_acceptex_table, request->token, received) != NTW_ACCEPTEX_OK) {
        /* Registry refused the actual count (cannot exceed the reservation here). */
        ntw_acceptex_cancel(&g_acceptex_table, request->token);
        status = NET_ERR(WSAEINVAL);
        received = 0;
    }
    if (irp) {
        irp->owner = 0;
        irp_complete(irp, status, received);
    }
    kfree(request->staging);
    sock_release(request->listen);
    sock_release(as);
    kfree(request);
}

/* Hand one queued connection of the listener to the caller-provided socket. */
static int32_t sock_acceptex_attach(sock_t *ls, sock_t *as)
{
    tcb_t *t;
    if (as->bound || as->listening || as->tcb || as->extension || as->connected) return NET_ERR(WSAEINVAL);
    t = tcp_accept_dequeue(ls);
    if (!t) return NET_ERR(WSAECONNRESET);
    as->tcb = t;
    t->sock = as;
    as->lip = t->lip; as->lport = t->lport; as->rip = t->rip; as->rport = t->rport;
    as->bound = 1;
    as->reuse = ls->reuse; as->keepalive = ls->keepalive; as->nodelay = ls->nodelay; as->linger_on = ls->linger_on;
    as->linger_secs = ls->linger_secs; as->rcvbuf = ls->rcvbuf; as->sndbuf = ls->sndbuf;
    as->ka_idle_s = ls->ka_idle_s; as->ka_intvl_s = ls->ka_intvl_s; as->ka_cnt = ls->ka_cnt;
    as->want_write = 1;
    t->sndq.limit = as->sndbuf;
    t->rcvq.limit = as->rcvbuf;
    return 0;
}

static void sock_acceptex_encode_ip4(uint8_t out[16], ip4_t ip, uint16_t port)
{
    uint32_t i;
    for (i = 0; i < 16; ++i) out[i] = 0;
    out[0] = 2;                           /* AF_INET, little endian */
    out[2] = (uint8_t)(port >> 8); out[3] = (uint8_t)port;   /* network order */
    out[4] = (uint8_t)(ip >> 24); out[5] = (uint8_t)(ip >> 16);
    out[6] = (uint8_t)(ip >> 8); out[7] = (uint8_t)ip;
}

/* Returns 1 when the request finished (and was freed). */
static int sock_acceptex_step(struct sock_acceptex *request, int *listener_served)
{
    sock_t *ls = request->listen, *as = request->accept;
    irp_t *irp = request->irp;
    tcb_t *t;
    uint32_t received = 0;
    uint8_t local[16], remote[16];
    int32_t status;
    if (request->cancelled || !irp || ls->dead || as->dead) {
        sock_acceptex_finish(request, STATUS_CANCELLED, 0);
        return 1;
    }
    if (!as->tcb) {
        if (!ls->listening) { sock_acceptex_finish(request, NET_ERR(WSAEINVAL), 0); return 1; }
        if (*listener_served || !ls->acc_count) { *listener_served = 1; return 0; }  /* FIFO */
        status = sock_acceptex_attach(ls, as);
        if (status) { sock_acceptex_finish(request, status, 0); return 1; }
    }
    t = as->tcb;
    if (request->plan.receive_reserved) {
        /* Windows completes AcceptEx with data only after the first bytes, or at
         * orderly EOF with 0 bytes; a reset before data is the reset error. */
        if (!t->rcvq.len) {
            if (t->err) { sock_acceptex_finish(request, t->err, 0); return 1; }
            if (!t->rcvd_fin && t->state != TCPS_CLOSED) return 0;
        } else {
            received = t->rcvq.len < request->plan.receive_reserved ? t->rcvq.len : request->plan.receive_reserved;
            status = bq_read_user(&t->rcvq, irp->proc, request->buffer, received, 1);
            if (status) { sock_acceptex_finish(request, status, 0); return 1; }
            tcp_after_read(t);
        }
    }
    sock_acceptex_encode_ip4(local, as->lip, as->lport);
    sock_acceptex_encode_ip4(remote, as->rip, as->rport);
    if (ntw_acceptex_encode_blocks(&request->plan, local, 16, remote, 16, request->staging,
                                   (size_t)request->plan.local_reserved + request->plan.remote_reserved) != NTW_ACCEPTEX_OK) {
        sock_acceptex_finish(request, NET_ERR(WSAEINVAL), 0);
        return 1;
    }
    if (copy_to_user(irp->proc, request->buffer + request->plan.receive_reserved, request->staging,
                     (uint64_t)request->plan.local_reserved + request->plan.remote_reserved)) {
        sock_acceptex_finish(request, STATUS_ACCESS_VIOLATION, 0);
        return 1;
    }
    as->connected = 1;
    as->close_reported = 0;
    sock_acceptex_finish(request, STATUS_SUCCESS, received);
    return 1;
}

/* Net lock held. Progresses every pending AcceptEx, oldest first per listener. */
static void sock_acceptex_poll(void)
{
    struct sock_acceptex *request, *next, *scan;
    uint64_t flags;
    if (!g_acceptex_head || g_acceptex_busy) return;
    flags = irq_save();
    g_acceptex_busy = 1;
    for (request = g_acceptex_head; request; request = next) {
        int served = 0;
        next = request->next;
        /* An older pending request of the same listener without a connection
         * blocks this one from taking a queued connection (FIFO order). */
        for (scan = g_acceptex_head; scan != request; scan = scan->next)
            if (scan->listen == request->listen && !scan->accept->tcb) served = 1;
        if (sock_acceptex_step(request, &served)) next = g_acceptex_head;   /* list changed: rescan */
    }
    g_acceptex_busy = 0;
    irq_restore(flags);
}

/* Socket close (net lock held): cancel pending requests naming it in either
 * role, then free completed registry ops whose ACCEPTED socket it is. Closing
 * only the listener keeps a completed op: the accepted socket and its leased
 * buffer stay valid (GetAcceptExSockaddrs) until that socket closes, its owner
 * reuses the buffer, or the owner process exits. */
static void sock_acceptex_closed(sock_t *s)
{
    struct sock_acceptex *request, *next;
    struct ntw_ref ref;
    const uint64_t flags = irq_save();
    for (request = g_acceptex_head; request; request = next) {
        next = request->next;
        if (request->listen != s && request->accept != s) continue;
        if (request->irp) {
            irp_t *irp = request->irp;
            sock_acceptex_cancel(irp);
            irp_complete(irp, STATUS_CANCELLED, 0);
        }
        sock_acceptex_finish(request, STATUS_CANCELLED, 0);
        next = g_acceptex_head;
    }
    if (g_acceptex_ready && s->acceptex_epoch) {
        uint32_t i;
        ref.id = s->acceptex_id;
        ref.generation = s->acceptex_epoch;
        for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
            struct ntw_acceptex_op *op = &g_acceptex_table.op[i];
            if (op->state == NTW_ACCEPTEX_COMPLETED && ref_equal(op->accept, ref)) op_free(op);
            else if (op->state == NTW_ACCEPTEX_PENDING && (ref_equal(op->accept, ref) || ref_equal(op->listen, ref)))
                op_free(op);            /* unreachable: every pending op has a request cancelled above */
        }
    }
    irq_restore(flags);
}

static int32_t sock_acceptex_ioctl(process_t *p, uint64_t h, uint64_t input, uint64_t input_size)
{
    struct shz_sock_extension_request value;
    struct sock_acceptex *request = 0;
    struct ntw_acceptex_plan plan;
    struct ntw_ref owner, listen_ref, accept_ref;
    kobject_t *lobject, *aobject;
    sock_t *ls, *as;
    irp_t *irp = 0;
    ntw_acceptex_token token;
    enum ntw_acceptex_status ast;
    int32_t status;
    uint64_t flags;
    if (input_size != sizeof value || copy_from_user(p, &value, input, sizeof value)) return NET_ERR(WSAEFAULT);
    if (value.reserved || value.flags || value.length > 0xffffffffull) return NET_ERR(WSAEINVAL);
    if (!value.overlapped) return NET_ERR(WSAEINVAL);          /* synchronous AcceptEx is not implemented */
    if (!value.buffer) return NET_ERR(WSAEFAULT);
    ast = ntw_acceptex_plan_make(2, (uint32_t)value.length, (uint32_t)value.address_length,
                                 (uint32_t)(value.address_length >> 32), &plan);
    if (ast) return sock_acceptex_error(ast);
    if ((uint64_t)plan.local_reserved + plan.remote_reserved > SHZ_ACCEPTEX_ADDRESS_LIMIT) return NET_ERR(WSAENOBUFS);
    if (value.buffer > ~0ull - plan.total) return NET_ERR(WSAEFAULT);
    status = ipc_ref_handle(p, h, OB_SOCKET, &lobject, 0);
    if (status) return status;
    status = ipc_ref_handle(p, value.address, OB_SOCKET, &aobject, 0);
    if (status) { ob_deref(lobject); return status == STATUS_INVALID_HANDLE ? NET_ERR(WSAENOTSOCK) : status; }
    net_lock();
    sock_acceptex_init();
    ls = lobject->u.net.sock;
    as = aobject->u.net.sock;
    if (!ls || ls->dead || !as || as->dead) { status = STATUS_INVALID_HANDLE; goto unlock; }
    if (ls == as) { status = NET_ERR(WSAEINVAL); goto unlock; }
    ++ls->refs; ++as->refs;              /* issuing operation's references */
    if (ls->type != SK_STREAM || !ls->listening || as->type != SK_STREAM) { status = NET_ERR(WSAEOPNOTSUPP); goto release; }
    if (!lobject->u.file.io || ((ioctx_t *)lobject->u.file.io)->sync) { status = NET_ERR(WSAEINVAL); goto release; }
    if (as->bound || as->listening || as->tcb || as->extension || as->connected) { status = NET_ERR(WSAEINVAL); goto release; }
    owner = sock_acceptex_owner(p);
    if (!sock_acceptex_ref(ls, &listen_ref) || !sock_acceptex_ref(as, &accept_ref)) { status = NET_ERR(WSAENOBUFS); goto release; }
    request = kzalloc(sizeof *request);
    if (request) request->staging = kzalloc((size_t)plan.local_reserved + plan.remote_reserved);
    if (!request || !request->staging) { if (request) kfree(request); status = NET_ERR(WSAENOBUFS); goto release; }
    ast = ntw_acceptex_submit(&g_acceptex_table, owner, listen_ref, accept_ref, value.buffer, &plan, &token);
    if (ast) { kfree(request->staging); kfree(request); status = sock_acceptex_error(ast); goto release; }
    status = sock_extension_prepare(p, lobject, value.overlapped, &irp);
    if (status) {
        ntw_acceptex_cancel(&g_acceptex_table, token);
        kfree(request->staging); kfree(request);
        goto release;
    }
    request->irp = irp;
    request->listen = ls;
    request->accept = as;
    request->buffer = value.buffer;
    request->plan = plan;
    request->token = token;
    irp->owner = request;
    irp->cancel = sock_acceptex_cancel;
    irp->buf = value.buffer;
    irp->len = plan.total;
    flags = irq_save();
    ++ls->refs; ++as->refs;              /* queue ownership survives generic IRP cancellation */
    {
        struct sock_acceptex **link = &g_acceptex_head;
        while (*link) link = &(*link)->next;
        *link = request;                 /* FIFO */
    }
    irp_mark_pending(irp);
    irq_restore(flags);
    sock_release(ls); sock_release(as);
    net_unlock();
    ob_deref(aobject); ob_deref(lobject);
    return irp_finish(irp);              /* PENDING; net poll performs the accept */
release:
    sock_release(ls); sock_release(as);
unlock:
    net_unlock();
    ob_deref(aobject); ob_deref(lobject);
    return status;
}

/* GetAcceptExSockaddrs lease. In: {u64 buffer; u32 receive, local, remote
 * reservations; u32 0}. Out: {u32 total; u32 accepted_bytes}. Succeeds only for a
 * COMPLETED AcceptEx of the calling kernel process at exactly that buffer with
 * exactly those reservations, so the user decoder reads at most `total` bytes
 * that this kernel wrote for this owner. Never trusts an application owner. */
#ifndef SHZ_SOCKET_ACCEPTEX_LOOKUP_DEFINED
#define SHZ_SOCKET_ACCEPTEX_LOOKUP_DEFINED
struct shz_sock_acceptex_lookup { uint64_t buffer; uint32_t receive_reserved, local_reserved, remote_reserved, reserved; };
struct shz_sock_acceptex_lease { uint32_t total, accepted_bytes; };
#endif

static int32_t sock_acceptex_lookup_ioctl(process_t *p, uint64_t h, uint64_t input, uint64_t input_size,
                                          uint64_t output, uint64_t output_size, uint64_t returned)
{
    struct shz_sock_acceptex_lookup query;
    struct shz_sock_acceptex_lease lease = {0, 0};
    const struct ntw_acceptex_op *op = 0;
    enum ntw_acceptex_status ast = NTW_ACCEPTEX_NOT_FOUND;
    uint32_t count = sizeof lease;
    if (h) return NET_ERR(WSAEINVAL);
    if (input_size != sizeof query || output_size < sizeof lease || !output) return NET_ERR(WSAEFAULT);
    if (copy_from_user(p, &query, input, sizeof query)) return NET_ERR(WSAEFAULT);
    if (query.reserved || !query.buffer) return NET_ERR(WSAEINVAL);
    net_lock();
    if (g_acceptex_ready)
        ast = ntw_acceptex_lookup(&g_acceptex_table, sock_acceptex_owner(p), query.buffer, query.receive_reserved,
                                  query.local_reserved, query.remote_reserved, &op);
    if (ast == NTW_ACCEPTEX_OK) { lease.total = op->plan.total; lease.accepted_bytes = op->accepted_bytes; }
    net_unlock();
    if (ast != NTW_ACCEPTEX_OK) return NET_ERR(WSAEINVAL);
    if (copy_to_user(p, output, &lease, sizeof lease)) return NET_ERR(WSAEFAULT);
    if (returned && copy_to_user(p, returned, &count, sizeof count)) return NET_ERR(WSAEFAULT);
    return 0;
}

/* Process exit (Core process_teardown, after handles_close_all): completed
 * AcceptEx records of `p` whose sockets were inherited/duplicated into another
 * live process are released, so a dead owner never pins registry slots and a
 * later process reusing the pid cannot match them (owner also folds the create
 * tick). Pending requests are left to IRP teardown -> cancel -> next poll. */
void net_sock_process_exited(process_t *p)
{
    struct ntw_ref owner;
    uint32_t i;
    uint64_t flags;
    net_lock();
    if (g_acceptex_ready) {
        owner = sock_acceptex_owner(p);
        flags = irq_save();
        for (i = 0; i < NTW_ACCEPTEX_SLOTS; ++i) {
            const struct ntw_acceptex_op *op = &g_acceptex_table.op[i];
            if (op->state == NTW_ACCEPTEX_COMPLETED && ref_equal(op->owner, owner))
                (void)ntw_acceptex_release(&g_acceptex_table, owner, token_of(&g_acceptex_table, op));
        }
        irq_restore(flags);
    }
    net_unlock();
}

/* Private extension commands routed by net_sock.c op_ioctl (and the host fixture). */
static int sock_extension_owns(uint64_t command)
{
    return command == SHZ_SOCK_CONNECT_EX || command == SHZ_SOCK_DISCONNECT_EX ||
           command == SHZ_SOCK_ACCEPT_EX || command == SHZ_SOCK_ACCEPTEX_LOOKUP;
}

static int32_t sock_acceptex_ioctl(process_t *p, uint64_t h, uint64_t input, uint64_t input_size);
static int32_t sock_extension_command(process_t *p, uint64_t h, uint32_t command, uint64_t input, uint64_t input_size,
                                      uint64_t output, uint64_t output_size, uint64_t returned)
{
    if (command == SHZ_SOCK_ACCEPT_EX) return sock_acceptex_ioctl(p, h, input, input_size);
    if (command == SHZ_SOCK_ACCEPTEX_LOOKUP)
        return sock_acceptex_lookup_ioctl(p, h, input, input_size, output, output_size, returned);
    return sock_extension_ioctl(p, h, command, input, input_size);
}

/* setsockopt(accept, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, &listen, sizeof(SOCKET)). */
static int32_t sock_acceptex_update_context(process_t *p, uint64_t h, uint64_t value, uint64_t length)
{
    uint64_t listen_handle = 0;
    sock_t *as, *ls;
    struct ntw_ref accept_ref, listen_ref;
    int32_t status;
    if (length != 8 && length != 4) return NET_ERR(WSAEFAULT);
    if (copy_from_user(p, &listen_handle, value, length)) return STATUS_ACCESS_VIOLATION;
    net_lock();
    as = get_sock(p, h);
    if (!as) { net_unlock(); return STATUS_INVALID_HANDLE; }
    ls = get_sock(p, listen_handle);
    if (!ls) { sock_release(as); net_unlock(); return NET_ERR(WSAENOTSOCK); }
    if (!g_acceptex_ready || !as->acceptex_epoch || !ls->acceptex_epoch) status = NET_ERR(WSAEINVAL);
    else {
        accept_ref.id = as->acceptex_id; accept_ref.generation = as->acceptex_epoch;
        listen_ref.id = ls->acceptex_id; listen_ref.generation = ls->acceptex_epoch;
        status = ntw_acceptex_update_context(&g_acceptex_table, sock_acceptex_owner(p), accept_ref, listen_ref)
                 ? NET_ERR(WSAEINVAL) : 0;
        if (!status && as->tcb) tcp_keepalive_changed(as->tcb);
    }
    sock_release(ls);
    sock_release(as);
    net_unlock();
    return status;
}
