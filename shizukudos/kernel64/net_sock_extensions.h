/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded TCP-backed ConnectEx/DisconnectEx implementation.
 * Included in net_sock.c; the host fixture includes this exact production body.
 * All transport work runs with the net mutex held. Queue/cancel transitions also
 * disable interrupts, since generic IRP cancellation can run outside that mutex.
 * Cancel only detaches the IRP and marks the owned request; transport abort and
 * request release run at the next net timer/notification, never under a foreign
 * net-mutex owner. No user worker thread, fake completion, or AFD compatibility.
 */
#ifndef SHZ_NET_EXT_HOST_TEST
#include "ipc.h"
#endif

#define SHZ_SOCK_CONNECT_EX 0x53480010u
#define SHZ_SOCK_DISCONNECT_EX 0x53480011u
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
}

static void sock_extension_closed(sock_t *s)
{
    const uint64_t flags = irq_save();
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
