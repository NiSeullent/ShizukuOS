/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel sockets and the network system calls (SYSCALL_LIST_NET, 0x80-0x8f), reached from ws2_32.dll through ntdll stubs.
 *
 * A socket is a kernel object of type OB_SOCKET in the process handle table (handle value == Winsock SOCKET). The object
 * points at a sock_t owned by this file; the sock_t lives until the last handle is closed AND no system call is inside it
 * (sock_t.refs). Closing the last handle (NtClose, CloseHandle, or process teardown) runs net_socket_handle_closing() from
 * objects.c: TCP connections are orphaned and finish their close handshake in the background (RST instead if SO_LINGER
 * {1,0} was set or unread data remains), blocked callers are woken and fail.
 *
 * Blocking: a blocking call sleeps in net_sleep() slices of at most 20 ms and re-evaluates its condition, so process
 * termination (process->terminated) is noticed within one slice and the call returns; check_kill() then ends the thread.
 * Non-blocking sockets never sleep. Results are NTSTATUS values; network errors are NET_ERR(WSAE...) (see net.h).
 *
 * Syscall argument layouts (Windows x64 convention, arguments 5+ on the user stack):
 *   0x80 Socket(family, type, protocol, PHANDLE)            0x81 SockBind(h, sockaddr*, len)     0x82 SockListen(h, backlog)
 *   0x83 SockAccept(h, PHANDLE new, sockaddr*, PULONG len)  0x84 SockConnect(h, sockaddr*, len)
 *   0x85 SockSend(h, buf, len, flags, [to*, tolen, PULONG sent])    0x86 SockRecv(h, buf, len, flags, [from*, PULONG fromlen, PULONG got])
 *   0x87 SockShutdown(h, how)   0x88 SockName(h, which 0=local 1=peer, sockaddr*, PULONG len)
 *   0x89 SockSetOpt(h, level, opt, val*, [len])   0x8a SockGetOpt(h, level, opt, val*, [PULONG len])
 *   0x8b SockIoctl(h, cmd, in*, inlen, [out*, outlen, PULONG returned])   0x8c SockPoll(shz_pollent*, count, timeout_ms, PULONG ready)
 *   0x8d NetResolve(name*, namelen, results*, max, [PULONG count, server_be, server_port])
 *   0x8e NetQuery(class, buf, len, PULONG returned)          0x8f NetPing(dst_be, id<<16|seq, payload_len, timeout_ms, [PULONG rtt_ms])
 */
#include "net.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

sock_t *g_socks;

#define SOL_SOCKET 0xffff
#define IPPROTO_TCP_L 6
enum { SO_ACCEPTCONN = 0x0002, SO_REUSEADDR = 0x0004, SO_KEEPALIVE = 0x0008, SO_BROADCAST = 0x0020, SO_LINGER = 0x0080,
       SO_SNDBUF = 0x1001, SO_RCVBUF = 0x1002, SO_SNDTIMEO = 0x1005, SO_RCVTIMEO = 0x1006, SO_ERROR = 0x1007, SO_TYPE = 0x1008,
       SO_DONTLINGER = 0xff7f, SO_EXCLUSIVEADDRUSE = 0xfffb };
enum { TCP_NODELAY = 1, TCP_KEEPIDLE = 3, TCP_KEEPCNT = 16, TCP_KEEPINTVL = 17 };
enum { IOC_FIONBIO = 0x8004667e, IOC_FIONREAD = 0x4004667f, IOC_SIOCATMARK = 0x40047307, IOC_UDP_CONNRESET = 0x9800000c,
       IOC_EVENTSELECT = 0x53480001, IOC_ENUMEVENTS = 0x53480002 };
#define MSG_PEEK 2
#define MSG_WAITALL 8
#define SLICE_MS 20u

/* ---------------------------------------------------------------- socket objects */
static uint32_t bufclamp(uint32_t v) { return v < 2048 ? 2048 : v > (4u << 20) ? (4u << 20) : v; }

sock_t *sock_new(int type, int kernel_owned)
{
    sock_t *s = kzalloc(sizeof *s);
    if (!s)
        return 0;
    s->type = type;
    s->refs = 1;
    s->kernel_owned = kernel_owned ? 1 : 0;
    s->rcvbuf = 65536;
    s->sndbuf = 65536;
    s->next = g_socks;
    g_socks = s;
    return s;
}

static void sock_unlink(sock_t *s)
{
    sock_t **pp;
    for (pp = &g_socks; *pp; pp = &(*pp)->next)
        if (*pp == s) { *pp = s->next; break; }
}

static void sock_free(sock_t *s)
{
    while (s->dq_head) {
        dgram_t *d = s->dq_head;
        s->dq_head = d->next;
        kfree(d);
    }
    kfree(s);
}

void sock_release(sock_t *s)
{
    KASSERT(s->refs > 0);
    if (--s->refs == 0 && s->dead)
        sock_free(s);
}

static int32_t wsa_of(int32_t st)
{
    return ((uint32_t)st & 0xffff0000u) == 0xE0A00000u ? (int32_t)((uint32_t)st & 0xffffu) : (int32_t)WSAEINVAL;
}

int sock_port_in_use(int type, ip4_t lip, uint16_t lport, const sock_t *except, int reuse)
{
    const sock_t *o;
    for (o = g_socks; o; o = o->next) {
        if (o == except || o->type != type || o->dead || !o->bound || o->lport != lport)
            continue;
        if (o->lip && lip && o->lip != lip)
            continue;                                       /* different specific addresses do not overlap */
        if (reuse && o->reuse && !o->listening && !o->exclusive)
            continue;
        return 1;
    }
    return 0;
}

uint16_t sock_alloc_port(int type)
{
    unsigned i;
    for (i = 0; i < 4000; ++i) {
        const uint16_t p = (uint16_t)(49152 + net_rand32() % 16384);
        const tcb_t *t;
        if (sock_port_in_use(type, 0, p, 0, 0))
            continue;
        if (type == SK_STREAM) {
            for (t = g_tcbs; t; t = t->next)
                if (t->lport == p)
                    break;
            if (t)
                continue;
        }
        return p;
    }
    return 0;
}

/* ---------------------------------------------------------------- readiness */
uint32_t sock_poll_mask(sock_t *s)
{
    uint32_t m = 0;
    if (s->type == SK_DGRAM) {
        if (s->bound && !s->dead) m |= POLLWRNORM;
        if (s->dq_head || s->shut_rd) m |= POLLRDNORM;
        if (s->err) m |= POLLERR | POLLRDNORM;
        return m;
    }
    if (s->listening)
        return s->acc_count ? POLLRDNORM : 0;
    if (s->tcb) {
        const tcb_t *t = s->tcb;
        const uint32_t thresh = t->sndq.limit / 4 < 4096 ? (t->sndq.limit / 4 ? t->sndq.limit / 4 : 1) : 4096;
        if (t->state == TCPS_SYN_SENT || (t->state == TCPS_SYN_RCVD && !t->passive))
            return 0;                                       /* connect in progress */
        if (t->err) {
            m |= POLLERR | POLLHUP;
            if (t->was_est) m |= POLLRDNORM | POLLWRNORM;   /* a reset connection: reads and writes fail immediately */
            return m;
        }
        if (t->rcvq.len > 0 || t->rcvd_fin || t->state == TCPS_CLOSED || s->shut_rd) m |= POLLRDNORM;
        if (tcp_can_write(t) && !t->fin_queued && (bq_space(&t->sndq) >= thresh || t->sndq.len == 0)) m |= POLLWRNORM;
        if (t->state == TCPS_CLOSED || t->state == TCPS_TIME_WAIT || t->state == TCPS_LAST_ACK) m |= POLLHUP;
    }
    return m;
}

static void sock_evt_update(sock_t *s)
{
    uint32_t ev = 0;
    const tcb_t *t = s->tcb;
    if (!s->evt || s->dead)
        return;
    if (s->listening) {
        if (s->acc_count) ev |= EV_ACCEPT;
    } else if (s->type == SK_STREAM) {
        if (t) {
            if (t->rcvq.len) ev |= EV_READ;
            if (s->connecting && t->state != TCPS_SYN_SENT && !(t->state == TCPS_SYN_RCVD && !t->passive)) {
                ev |= EV_CONNECT;
                s->connecting = 0;
                s->evt_err[4] = t->err && !t->was_est ? wsa_of(t->err) : 0;
            }
            if (s->want_write && tcp_can_write(t) && (sock_poll_mask(s) & POLLWRNORM)) {
                ev |= EV_WRITE;
                s->want_write = 0;
            }
            if ((t->rcvd_fin || t->state == TCPS_CLOSED) && t->was_est && !s->close_reported) {
                ev |= EV_CLOSE;
                s->close_reported = 1;
                s->evt_err[5] = t->err ? wsa_of(t->err) : 0;
            }
        }
    } else {
        if (s->dq_head) ev |= EV_READ;
        if (s->want_write) { ev |= EV_WRITE; s->want_write = 0; }
    }
    ev &= s->evt_mask;
    if (ev & ~s->evt_pending) {
        s->evt_pending |= ev;
        ob_signal_event(s->evt);
    } else {
        s->evt_pending |= ev;
    }
}

void sock_notify(sock_t *s)
{
    net_wake_all();
    if (s->evt)
        sock_evt_update(s);
}

/* ---------------------------------------------------------------- closing */
static void sock_close_locked(sock_t *s)
{
    s->dead = 1;
    sock_unlink(s);
    if (s->type == SK_STREAM)
        tcp_sock_closed(s);
    if (s->evt) {
        ob_deref(s->evt);
        s->evt = 0;
    }
    net_wake_all();
    sock_release(s);                                        /* the handle's reference */
}

void sock_close_kernel(sock_t *s) { sock_close_locked(s); }

/* objects.c handle_close hook: `o` still holds the reference of the handle being closed. */
void net_socket_handle_closing(kobject_t *o)
{
    sock_t *s;
    if (o->refs != 1)
        return;                                             /* another handle (duplicate) keeps the socket alive */
    s = o->u.net.sock;
    if (!s)
        return;
    net_lock();
    o->u.net.sock = 0;
    sock_close_locked(s);
    net_unlock();
}

static sock_t *get_sock(process_t *p, uint64_t h)           /* lock held; takes a reference */
{
    kobject_t *o = handle_lookup(p, h, OB_SOCKET);
    sock_t *s = o ? (sock_t *)o->u.net.sock : 0;
    if (!s || s->dead)
        return 0;
    ++s->refs;
    return s;
}

/* One sleep step of a blocking call. Returns 0 to re-check the condition, else the status to return. */
static int32_t wait_step(sock_t *s, uint64_t deadline)
{
    uint32_t ms = SLICE_MS;
    const uint64_t now = net_now();
    if (net_current_terminating())
        return NET_ERR(WSAEINTR);
    if (deadline) {
        if (now >= deadline)
            return NET_ERR(WSAETIMEDOUT);
        if (deadline - now < ms) ms = (uint32_t)(deadline - now);
    }
    net_sleep(ms);
    if (s && s->dead)
        return NET_ERR(WSAENOTSOCK);                        /* closed by another thread while we slept */
    return 0;
}

int32_t ksock_recvfrom(sock_t *s, uint8_t *buf, uint32_t cap, uint32_t *got, ip4_t *from, uint16_t *fport, uint32_t timeout_ms)
{
    const uint64_t deadline = timeout_ms ? net_now() + timeout_ms : 0;
    for (;;) {
        dgram_t *d;
        int32_t st;
        if (s->err) { st = s->err; s->err = 0; return st; }
        d = s->dq_head;
        if (d) {
            const uint32_t n = d->len < cap ? d->len : cap;
            memcpy(buf, d->data, n);
            *got = n;
            if (from) *from = d->src;
            if (fport) *fport = d->sport;
            s->dq_head = d->next;
            if (!s->dq_head) s->dq_tail = 0;
            s->dq_bytes -= d->len;
            --s->dq_count;
            kfree(d);
            return 0;
        }
        st = wait_step(s, deadline);
        if (st)
            return st;
    }
}

/* ---------------------------------------------------------------- address helpers */
static int32_t read_sa(process_t *p, uint64_t uva, uint64_t len, ip4_t *ip, uint16_t *port)
{
    struct shz_sockaddr_in sa;
    if (!uva || len < sizeof sa)
        return NET_ERR(WSAEFAULT);
    if (copy_from_user(p, &sa, uva, sizeof sa))
        return STATUS_ACCESS_VIOLATION;
    if (sa.family != SHZ_AF_INET)
        return NET_ERR(WSAEAFNOSUPPORT);
    *ip = bs32(sa.addr_be);
    *port = bs16(sa.port_be);
    return 0;
}

static int32_t write_sa(process_t *p, uint64_t uva, uint64_t plen, ip4_t ip, uint16_t port)
{
    struct shz_sockaddr_in sa;
    uint32_t have = 0, n = sizeof sa;
    if (!uva || !plen)
        return 0;
    if (copy_from_user(p, &have, plen, 4))
        return STATUS_ACCESS_VIOLATION;
    memset(&sa, 0, sizeof sa);
    sa.family = SHZ_AF_INET;
    sa.port_be = bs16(port);
    sa.addr_be = bs32(ip);
    if (have < n) n = have;
    if (n && copy_to_user(p, uva, &sa, n))
        return STATUS_ACCESS_VIOLATION;
    have = sizeof sa;
    if (copy_to_user(p, plen, &have, 4))
        return STATUS_ACCESS_VIOLATION;
    return 0;
}

static int32_t put_u32(process_t *p, uint64_t uva, uint32_t v)
{
    return uva && copy_to_user(p, uva, &v, 4) ? STATUS_ACCESS_VIOLATION : 0;
}

/* ---------------------------------------------------------------- operations */
static int32_t new_handle(process_t *p, sock_t *s, uint32_t *h_out)
{
    kobject_t *o = ob_create(OB_SOCKET, 0);
    int32_t st;
    if (!o)
        return STATUS_NO_MEMORY;
    o->u.net.sock = s;
    st = handle_insert(p, o, 0x1fffff, h_out);
    ob_deref(o);                                            /* the handle now owns the object */
    return st;
}

static int32_t op_socket(process_t *p, uint64_t family, uint64_t type, uint64_t proto, uint64_t uh)
{
    sock_t *s;
    uint32_t h = 0;
    uint64_t hv;
    int32_t st;
    if (family != SHZ_AF_INET) return NET_ERR(WSAEAFNOSUPPORT);
    if (type == SK_STREAM) { if (proto && proto != 6) return NET_ERR(WSAEPROTONOSUPPORT); }
    else if (type == SK_DGRAM) { if (proto && proto != 17) return NET_ERR(WSAEPROTONOSUPPORT); }
    else return NET_ERR(WSAESOCKTNOSUPPORT);
    net_lock();
    s = sock_new((int)type, 0);
    net_unlock();
    if (!s)
        return NET_ERR(WSAENOBUFS);
    st = new_handle(p, s, &h);
    if (st) {
        net_lock();
        sock_close_locked(s);
        net_unlock();
        return st == STATUS_NO_MEMORY ? NET_ERR(WSAEMFILE) : st;
    }
    hv = h;
    if (copy_to_user(p, uh, &hv, 8)) {
        handle_close(p, h);                                 /* closes the socket through the hook */
        return STATUS_ACCESS_VIOLATION;
    }
    return 0;
}

static int32_t op_bind(process_t *p, uint64_t h, uint64_t sa_uva, uint64_t sa_len)
{
    ip4_t ip;
    uint16_t port;
    sock_t *s;
    int32_t st = read_sa(p, sa_uva, sa_len, &ip, &port);
    if (st)
        return st;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (s->bound || s->tcb || s->listening) st = NET_ERR(WSAEINVAL);
    else if (ip && !ip_is_local(ip)) st = NET_ERR(WSAEADDRNOTAVAIL);
    else if (!port && !(port = sock_alloc_port(s->type))) st = NET_ERR(WSAEADDRINUSE);
    else if (sock_port_in_use(s->type, ip, port, s, s->reuse)) st = NET_ERR(WSAEADDRINUSE);
    else { s->lip = ip; s->lport = port; s->bound = 1; }
    sock_release(s);
    net_unlock();
    return st;
}

static int32_t op_listen(process_t *p, uint64_t h, uint64_t backlog)
{
    sock_t *s;
    int32_t st = 0;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (s->type != SK_STREAM) st = NET_ERR(WSAEOPNOTSUPP);
    else if (!s->bound || s->tcb) st = NET_ERR(WSAEINVAL);
    else if (s->listening) st = 0;                          /* re-listen just adjusts the backlog */
    if (!st) st = tcp_listen(s, backlog > 0x7fffffffu ? 128 : (uint32_t)backlog);
    sock_release(s);
    net_unlock();
    return st;
}

static int32_t op_accept(process_t *p, uint64_t h, uint64_t uh_new, uint64_t sa_uva, uint64_t len_uva)
{
    sock_t *s, *ns;
    tcb_t *t;
    uint32_t nh = 0;
    uint64_t hv;
    int32_t st = 0;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (!s->listening) { sock_release(s); net_unlock(); return NET_ERR(WSAEINVAL); }
    for (;;) {
        if (s->dead) { st = NET_ERR(WSAENOTSOCK); break; }
        if (!s->listening) { st = NET_ERR(WSAEINVAL); break; }
        if (s->acc_count)
            break;
        if (s->nonblock) { st = NET_ERR(WSAEWOULDBLOCK); break; }
        st = wait_step(s, 0);
        if (st) break;
    }
    if (st) { sock_release(s); net_unlock(); return st; }
    t = tcp_accept_dequeue(s);
    ns = sock_new(SK_STREAM, 0);
    if (!ns) {
        tcp_abort(t, 1);
        t->sock = 0;
        sock_release(s);
        net_unlock();
        return NET_ERR(WSAENOBUFS);
    }
    ns->tcb = t;
    t->sock = ns;
    ns->lip = t->lip; ns->lport = t->lport; ns->rip = t->rip; ns->rport = t->rport;
    ns->bound = 1; ns->connected = 1;
    ns->reuse = s->reuse; ns->keepalive = s->keepalive; ns->nodelay = s->nodelay; ns->linger_on = s->linger_on;
    ns->linger_secs = s->linger_secs; ns->rcvbuf = s->rcvbuf; ns->sndbuf = s->sndbuf;
    ns->ka_idle_s = s->ka_idle_s; ns->ka_intvl_s = s->ka_intvl_s; ns->ka_cnt = s->ka_cnt;
    ns->want_write = 1;
    t->sndq.limit = ns->sndbuf;
    t->rcvq.limit = ns->rcvbuf;
    sock_release(s);
    {   /* fill in the outputs while the lock is held only for the socket bookkeeping */
        const ip4_t rip = ns->rip;
        const uint16_t rport = ns->rport;
        net_unlock();
        st = new_handle(p, ns, &nh);
        if (st) {
            net_lock();
            sock_close_locked(ns);
            net_unlock();
            return st == STATUS_NO_MEMORY ? NET_ERR(WSAEMFILE) : st;
        }
        hv = nh;
        if (copy_to_user(p, uh_new, &hv, 8) || write_sa(p, sa_uva, len_uva, rip, rport)) {
            handle_close(p, nh);
            return STATUS_ACCESS_VIOLATION;
        }
    }
    return 0;
}

static int32_t op_connect(process_t *p, uint64_t h, uint64_t sa_uva, uint64_t sa_len)
{
    ip4_t ip;
    uint16_t port;
    sock_t *s;
    tcb_t *t;
    int32_t st = 0;
    uint16_t af = 0;
    if (sa_uva && sa_len >= 2 && copy_from_user(p, &af, sa_uva, 2) == 0 && af == 0)
        ip = 0, port = 0;                                   /* AF_UNSPEC: dissolve a UDP association */
    else if ((st = read_sa(p, sa_uva, sa_len, &ip, &port)))
        return st;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (s->type == SK_DGRAM) {
        if (af == 0 && sa_uva) { s->connected = 0; s->rip = 0; s->rport = 0; }
        else if (!ip || !port) st = NET_ERR(WSAEADDRNOTAVAIL);
        else {
            if (!s->bound && !(s->lport = sock_alloc_port(SK_DGRAM))) st = NET_ERR(WSAEADDRINUSE);
            else {
                s->bound = 1;
                s->rip = ip; s->rport = port; s->connected = 1;
            }
        }
        sock_release(s);
        net_unlock();
        return st;
    }
    if (s->listening) { sock_release(s); net_unlock(); return NET_ERR(WSAEINVAL); }
    if (!ip || !port || (ip_is_broadcast(ip) && ip != 0)) { sock_release(s); net_unlock(); return NET_ERR(WSAEADDRNOTAVAIL); }
    t = s->tcb;
    if (t) {
        if (t->state == TCPS_SYN_SENT || (t->state == TCPS_SYN_RCVD && !t->passive)) {
            if (s->nonblock) { sock_release(s); net_unlock(); return NET_ERR(WSAEALREADY); }
        } else if (t->state == TCPS_CLOSED && t->err && !t->was_est) {
            const int32_t e = t->err;                       /* report the failed attempt once, then allow a retry */
            tcp_sock_closed(s);
            s->connecting = 0;
            s->rip = 0; s->rport = 0;
            sock_release(s);
            net_unlock();
            return e;
        } else {
            sock_release(s);
            net_unlock();
            return NET_ERR(WSAEISCONN);
        }
    } else {
        t = tcp_connect(s, ip, port, &st);
        if (!t) { sock_release(s); net_unlock(); return st; }
        s->connecting = 1;
        s->want_write = 1;
        s->close_reported = 0;
        if (s->nonblock) { sock_release(s); net_unlock(); return NET_ERR(WSAEWOULDBLOCK); }
    }
    for (;;) {
        t = s->tcb;
        if (s->dead || !t) { st = NET_ERR(WSAENOTSOCK); break; }
        if (t->state != TCPS_SYN_SENT && !(t->state == TCPS_SYN_RCVD && !t->passive)) {
            st = (t->state == TCPS_CLOSED && !t->was_est) ? (t->err ? t->err : NET_ERR(WSAECONNREFUSED)) : 0;
            s->connecting = 0;
            if (!st) s->connected = 1;
            break;
        }
        st = wait_step(s, 0);
        if (st) break;
    }
    sock_release(s);
    net_unlock();
    return st;
}

static int32_t send_udp(process_t *p, sock_t *s, uint64_t buf, uint32_t len, uint64_t to, uint64_t tolen, uint32_t *sent)
{
    ip4_t dip = s->rip;
    uint16_t dport = s->rport;
    uint8_t small[1536], *tmp = small;
    int32_t st;
    if (len > 65507)
        return NET_ERR(WSAEMSGSIZE);
    if (to) {
        st = read_sa(p, to, tolen, &dip, &dport);
        if (st) return st;
    } else if (!s->connected) {
        return NET_ERR(WSAEDESTADDRREQ);
    }
    if (!s->bound) {
        s->lport = sock_alloc_port(SK_DGRAM);
        if (!s->lport) return NET_ERR(WSAEADDRINUSE);
        s->bound = 1;
    }
    if (len > sizeof small) {
        tmp = kmalloc(len);
        if (!tmp) return NET_ERR(WSAENOBUFS);
    }
    if (len && copy_from_user(p, tmp, buf, len)) {
        if (tmp != small) kfree(tmp);
        return STATUS_ACCESS_VIOLATION;
    }
    st = udp_send(s, dip, dport, tmp, len, 0);
    if (tmp != small) kfree(tmp);
    if (!st) *sent = len;
    return st;
}

static int32_t op_send(process_t *p, struct regs *r, uint64_t h, uint64_t buf, uint64_t len, uint64_t flags)
{
    const uint64_t to = (uint64_t)stack_arg(p, r, 5), tolen = (uint64_t)stack_arg(p, r, 6), pout = (uint64_t)stack_arg(p, r, 7);
    sock_t *s;
    uint32_t total = 0;
    int32_t st = 0;
    uint64_t deadline;
    (void)flags;
    if (len > 0xffffffffull)
        return NET_ERR(WSAEMSGSIZE);
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (s->type == SK_DGRAM) {
        st = send_udp(p, s, buf, (uint32_t)len, to, tolen, &total);
        sock_release(s);
        net_unlock();
        if (st) return st;
        return put_u32(p, pout, total);
    }
    deadline = s->sndtimeo ? net_now() + s->sndtimeo : 0;
    for (;;) {
        tcb_t *t = s->tcb;
        uint32_t space, n, done = 0;
        int32_t st2;
        if (s->dead) { st = NET_ERR(WSAENOTSOCK); break; }
        if (!t || s->listening || t->state == TCPS_SYN_SENT || (t->state == TCPS_SYN_RCVD && !t->passive)) { st = NET_ERR(WSAENOTCONN); break; }
        if (!tcp_can_write(t) || t->fin_queued) { st = t->err ? t->err : NET_ERR(WSAESHUTDOWN); break; }
        if (total == len)
            break;
        space = bq_space(&t->sndq);
        if (space == 0) {
            s->want_write = 1;
            if (s->nonblock) { st = NET_ERR(WSAEWOULDBLOCK); break; }
            st = wait_step(s, deadline);
            if (st) break;
            continue;
        }
        n = (uint32_t)(len - total < space ? len - total : space);
        st2 = bq_write_user(&t->sndq, p, buf + total, n, &done);
        total += done;
        if (done)
            tcp_output(t);
        if (st2) { st = st2; break; }
    }
    sock_release(s);
    net_unlock();
    if (total)
        return put_u32(p, pout, total);                     /* partial progress wins over a later error, as in Winsock */
    return st;
}

static int32_t op_recv(process_t *p, struct regs *r, uint64_t h, uint64_t buf, uint64_t len, uint64_t flags)
{
    const uint64_t from = (uint64_t)stack_arg(p, r, 5), fromlen = (uint64_t)stack_arg(p, r, 6), pgot = (uint64_t)stack_arg(p, r, 7);
    sock_t *s;
    uint32_t got = 0;
    int32_t st = 0;
    uint64_t deadline;
    const int peek = (flags & MSG_PEEK) != 0;
    ip4_t src_ip = 0;
    uint16_t src_port = 0;
    if (len > 0xffffffffull)
        len = 0xffffffffull;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    deadline = s->rcvtimeo ? net_now() + s->rcvtimeo : 0;
    if (s->type == SK_DGRAM) {
        if (!s->bound) { sock_release(s); net_unlock(); return NET_ERR(WSAEINVAL); }
        for (;;) {
            dgram_t *d;
            if (s->dead) { st = NET_ERR(WSAENOTSOCK); break; }
            if (s->err) {
                st = s->err;
                s->err = 0;
                if (s->noconnreset && st == NET_ERR(WSAECONNRESET)) { st = 0; continue; }
                break;
            }
            d = s->dq_head;
            if (d) {
                const uint32_t n = d->len < len ? d->len : (uint32_t)len;
                if (n && copy_to_user(p, buf, d->data, n)) { st = STATUS_ACCESS_VIOLATION; break; }
                got = n;
                src_ip = d->src; src_port = d->sport;
                if (d->len > len) st = NET_ERR(WSAEMSGSIZE);
                if (!peek) {
                    s->dq_head = d->next;
                    if (!s->dq_head) s->dq_tail = 0;
                    s->dq_bytes -= d->len;
                    --s->dq_count;
                    kfree(d);
                }
                break;
            }
            if (s->shut_rd) break;
            if (s->nonblock) { st = NET_ERR(WSAEWOULDBLOCK); break; }
            st = wait_step(s, deadline);
            if (st) break;
        }
        if (!peek && s->evt) sock_evt_update(s);
    } else {
        const int want_all = (flags & MSG_WAITALL) && !s->nonblock && !peek;
        for (;;) {
            tcb_t *t = s->tcb;
            uint32_t n;
            if (s->dead) { st = NET_ERR(WSAENOTSOCK); break; }
            if (!t || s->listening) { st = NET_ERR(s->listening ? WSAEINVAL : WSAENOTCONN); break; }
            if (t->rcvq.len > 0 && got < len && !s->shut_rd) {
                n = t->rcvq.len < len - got ? t->rcvq.len : (uint32_t)(len - got);
                st = bq_read_user(&t->rcvq, p, buf + got, n, !peek);
                if (st) break;
                got += n;
                if (!peek) tcp_after_read(t);
                if (got == len || !want_all || peek) break;
                continue;
            }
            if (got)
                break;
            if (s->shut_rd || t->rcvd_fin || (t->state == TCPS_CLOSED && !t->err)) break;    /* orderly EOF: 0 bytes */
            if (t->err) { st = t->err; break; }
            if (t->state == TCPS_SYN_SENT || (t->state == TCPS_SYN_RCVD && !t->passive)) { st = NET_ERR(WSAENOTCONN); break; }
            if (s->nonblock) { st = NET_ERR(WSAEWOULDBLOCK); break; }
            st = wait_step(s, deadline);
            if (st) break;
        }
        if (s->tcb) { src_ip = s->tcb->rip; src_port = s->tcb->rport; }
        if (!peek && s->evt) { s->evt_pending &= ~(uint32_t)EV_READ; sock_evt_update(s); }
    }
    sock_release(s);
    net_unlock();
    if (st && !(st == NET_ERR(WSAEMSGSIZE)) && got == 0)
        return st;
    {
        int32_t st2 = put_u32(p, pgot, got);
        if (!st2 && from) st2 = write_sa(p, from, fromlen, src_ip, src_port);
        return st2 ? st2 : st;                              /* WSAEMSGSIZE still reports the truncated byte count */
    }
}

static int32_t op_shutdown(process_t *p, uint64_t h, uint64_t how)
{
    sock_t *s;
    int32_t st = 0;
    if (how > 2)
        return NET_ERR(WSAEINVAL);
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (s->type == SK_STREAM) {
        tcb_t *t = s->tcb;
        if (!t || s->listening || t->state == TCPS_SYN_SENT || t->state == TCPS_CLOSED) {
            st = t && t->err ? t->err : NET_ERR(WSAENOTCONN);
        } else {
            if (how == 0 || how == 2) s->shut_rd = 1;
            if (how == 1 || how == 2) tcp_shutdown_write(t);
        }
    } else {
        if (!s->connected) st = NET_ERR(WSAENOTCONN);
        else if (how == 0 || how == 2) s->shut_rd = 1;
    }
    sock_notify(s);
    sock_release(s);
    net_unlock();
    return st;
}

static int32_t op_name(process_t *p, uint64_t h, uint64_t which, uint64_t sa_uva, uint64_t len_uva)
{
    sock_t *s;
    ip4_t ip = 0;
    uint16_t port = 0;
    int32_t st = 0;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (which == 0) {
        if (s->tcb) { ip = s->tcb->lip; port = s->tcb->lport; }
        else if (s->bound) { ip = s->lip; port = s->lport; }
        else st = NET_ERR(WSAEINVAL);
    } else if (s->type == SK_STREAM) {
        tcb_t *t = s->tcb;
        if (t && (t->state >= TCPS_ESTABLISHED || t->was_est) && !s->listening) { ip = t->rip; port = t->rport; }
        else st = NET_ERR(WSAENOTCONN);
    } else if (s->connected) {
        ip = s->rip; port = s->rport;
    } else {
        st = NET_ERR(WSAENOTCONN);
    }
    sock_release(s);
    net_unlock();
    return st ? st : write_sa(p, sa_uva, len_uva, ip, port);
}

static int32_t op_setopt(process_t *p, struct regs *r, uint64_t h, uint64_t level, uint64_t opt, uint64_t val)
{
    const uint64_t len = (uint64_t)stack_arg(p, r, 5);
    uint32_t v = 0, v2 = 0;
    sock_t *s;
    int32_t st = 0;
    if (len < 4 || len > 8 || copy_from_user(p, &v, val, 4) || (len >= 8 && copy_from_user(p, &v2, val + 4, 4)))
        return len < 4 ? NET_ERR(WSAEFAULT) : STATUS_ACCESS_VIOLATION;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (level == SOL_SOCKET) {
        switch (opt) {
        case SO_REUSEADDR: s->reuse = v != 0; if (v) s->exclusive = 0; break;
        case SO_EXCLUSIVEADDRUSE: s->exclusive = v != 0; if (v) s->reuse = 0; break;
        case SO_BROADCAST: s->broadcast = v != 0; break;
        case SO_KEEPALIVE:
            s->keepalive = v != 0;
            if (s->tcb) tcp_keepalive_changed(s->tcb);
            break;
        case SO_LINGER:
            if (len < 4) { st = NET_ERR(WSAEFAULT); break; }
            s->linger_on = (v & 0xffff) != 0;
            s->linger_secs = v >> 16;
            break;
        case SO_DONTLINGER: s->linger_on = 0; break;
        case SO_SNDBUF:
            s->sndbuf = bufclamp(v);
            if (s->tcb) s->tcb->sndq.limit = s->sndbuf;
            break;
        case SO_RCVBUF:
            s->rcvbuf = bufclamp(v);
            if (s->tcb) s->tcb->rcvq.limit = s->rcvbuf;
            break;
        case SO_SNDTIMEO: s->sndtimeo = v; break;
        case SO_RCVTIMEO: s->rcvtimeo = v; break;
        default: st = NET_ERR(WSAENOPROTOOPT); break;
        }
    } else if (level == IPPROTO_TCP_L && s->type == SK_STREAM) {
        switch (opt) {
        case TCP_NODELAY:
            s->nodelay = v != 0;
            if (s->tcb && s->nodelay) tcp_output(s->tcb);   /* flush anything Nagle was holding */
            break;
        case TCP_KEEPIDLE: s->ka_idle_s = v; if (s->tcb) tcp_keepalive_changed(s->tcb); break;
        case TCP_KEEPINTVL: s->ka_intvl_s = v; break;
        case TCP_KEEPCNT: s->ka_cnt = v; break;
        default: st = NET_ERR(WSAENOPROTOOPT); break;
        }
    } else {
        st = NET_ERR(WSAENOPROTOOPT);
    }
    sock_release(s);
    net_unlock();
    return st;
}

static int32_t op_getopt(process_t *p, struct regs *r, uint64_t h, uint64_t level, uint64_t opt, uint64_t val)
{
    const uint64_t plen = (uint64_t)stack_arg(p, r, 5);
    uint32_t v[2] = {0, 0}, have = 0, n = 4;
    sock_t *s;
    int32_t st = 0;
    if (!plen || !val || copy_from_user(p, &have, plen, 4))
        return NET_ERR(WSAEFAULT);
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    if (level == SOL_SOCKET) {
        switch (opt) {
        case SO_TYPE: v[0] = (uint32_t)s->type; break;
        case SO_ACCEPTCONN: v[0] = s->listening; break;
        case SO_REUSEADDR: v[0] = s->reuse; break;
        case SO_EXCLUSIVEADDRUSE: v[0] = s->exclusive; break;
        case SO_BROADCAST: v[0] = s->broadcast; break;
        case SO_KEEPALIVE: v[0] = s->keepalive; break;
        case SO_LINGER: v[0] = (s->linger_on ? 1u : 0u) | (s->linger_secs << 16); break;
        case SO_SNDBUF: v[0] = s->sndbuf; break;
        case SO_RCVBUF: v[0] = s->rcvbuf; break;
        case SO_SNDTIMEO: v[0] = s->sndtimeo; break;
        case SO_RCVTIMEO: v[0] = s->rcvtimeo; break;
        case SO_ERROR:                                      /* reads (and for datagram sockets clears) the pending error */
            if (s->err) { v[0] = (uint32_t)wsa_of(s->err); s->err = 0; }
            else if (s->tcb && s->tcb->err) v[0] = (uint32_t)wsa_of(s->tcb->err);
            break;
        default: st = NET_ERR(WSAENOPROTOOPT); break;
        }
    } else if (level == IPPROTO_TCP_L && s->type == SK_STREAM) {
        switch (opt) {
        case TCP_NODELAY: v[0] = s->nodelay; break;
        case TCP_KEEPIDLE: v[0] = s->ka_idle_s ? s->ka_idle_s : 7200; break;
        case TCP_KEEPINTVL: v[0] = s->ka_intvl_s ? s->ka_intvl_s : 1; break;
        case TCP_KEEPCNT: v[0] = s->ka_cnt ? s->ka_cnt : 10; break;
        default: st = NET_ERR(WSAENOPROTOOPT); break;
        }
    } else {
        st = NET_ERR(WSAENOPROTOOPT);
    }
    sock_release(s);
    net_unlock();
    if (st)
        return st;
    if (have < n) n = have;
    if (n && copy_to_user(p, val, v, n))
        return STATUS_ACCESS_VIOLATION;
    have = n;
    return copy_to_user(p, plen, &have, 4) ? STATUS_ACCESS_VIOLATION : 0;
}

struct shz_netevents { uint32_t events; int32_t err[10]; };

static int32_t op_ioctl(process_t *p, struct regs *r, uint64_t h, uint64_t cmd, uint64_t in, uint64_t inlen)
{
    const uint64_t out = (uint64_t)stack_arg(p, r, 5), outlen = (uint64_t)stack_arg(p, r, 6), pret = (uint64_t)stack_arg(p, r, 7);
    sock_t *s;
    uint32_t v = 0, ret = 0;
    int32_t st = 0;
    net_lock();
    s = get_sock(p, h);
    if (!s) { net_unlock(); return STATUS_INVALID_HANDLE; }
    switch ((uint32_t)cmd) {
    case IOC_FIONBIO:
        if (inlen < 4 || copy_from_user(p, &v, in, 4)) { st = NET_ERR(WSAEFAULT); break; }
        s->nonblock = v != 0;
        break;
    case IOC_FIONREAD:
        if (outlen < 4) { st = NET_ERR(WSAEFAULT); break; }
        if (s->type == SK_DGRAM) v = s->dq_head ? s->dq_head->len : 0;
        else v = s->tcb ? s->tcb->rcvq.len : 0;
        st = put_u32(p, out, v);
        ret = 4;
        break;
    case IOC_SIOCATMARK:                                    /* urgent data is not implemented: never any OOB byte pending */
        st = outlen < 4 ? NET_ERR(WSAEFAULT) : put_u32(p, out, 1);
        ret = 4;
        break;
    case IOC_UDP_CONNRESET:
        if (s->type != SK_DGRAM) { st = NET_ERR(WSAEOPNOTSUPP); break; }
        if (inlen < 4 || copy_from_user(p, &v, in, 4)) { st = NET_ERR(WSAEFAULT); break; }
        s->noconnreset = (v & 0xff) == 0;
        break;
    case IOC_EVENTSELECT: {                                 /* in: {u64 event handle, u32 mask} */
        struct { uint64_t ev; uint32_t mask, pad; } a;
        kobject_t *eo = 0;
        if (inlen < 12 || copy_from_user(p, &a, in, 12)) { st = NET_ERR(WSAEFAULT); break; }
        if (a.mask) {
            eo = a.ev ? handle_lookup(p, a.ev, OB_EVENT) : 0;
            if (!eo) { st = NET_ERR(WSAEINVAL); break; }
        }
        if (s->evt) { ob_deref(s->evt); s->evt = 0; }
        s->evt_mask = a.mask;
        s->evt_pending = 0;
        if (a.mask) {
            ob_ref(eo);
            s->evt = eo;
            s->nonblock = 1;                                /* WSAEventSelect puts the socket in non-blocking mode */
            if (s->type == SK_DGRAM || (s->tcb && s->tcb->state >= TCPS_ESTABLISHED)) s->want_write = 1;
            s->close_reported = 0;
            sock_evt_update(s);
        }
        break;
    }
    case IOC_ENUMEVENTS: {
        struct shz_netevents ne;
        unsigned i;
        if (outlen < sizeof ne) { st = NET_ERR(WSAEFAULT); break; }
        memset(&ne, 0, sizeof ne);
        ne.events = s->evt_pending;
        for (i = 0; i < 6; ++i)
            if (ne.events & (1u << i)) ne.err[i] = s->evt_err[i];
        s->evt_pending = 0;
        st = copy_to_user(p, out, &ne, sizeof ne) ? STATUS_ACCESS_VIOLATION : 0;
        ret = sizeof ne;
        break;
    }
    default:
        st = NET_ERR(WSAEINVAL);
        break;
    }
    sock_release(s);
    net_unlock();
    if (!st && pret)
        st = put_u32(p, pret, ret);
    return st;
}

static int32_t op_poll(process_t *p, uint64_t uents, uint64_t count, uint64_t timeout_ms, uint64_t pready)
{
    struct shz_pollent *e;
    const int32_t tmo = (int32_t)timeout_ms;               /* -1 = infinite */
    uint64_t deadline = tmo < 0 ? 0 : net_now() + (uint32_t)tmo;
    uint32_t ready = 0, i;
    int32_t st = 0;
    if (count > 1024)
        return NET_ERR(WSAEINVAL);
    e = kmalloc(sizeof *e * (count ? count : 1));
    if (!e)
        return NET_ERR(WSAENOBUFS);
    if (count && copy_from_user(p, e, uents, count * sizeof *e)) { kfree(e); return STATUS_ACCESS_VIOLATION; }
    net_lock();
    for (;;) {
        ready = 0;
        for (i = 0; i < count; ++i) {
            kobject_t *o = handle_lookup(p, e[i].handle, OB_SOCKET);
            sock_t *s = o ? (sock_t *)o->u.net.sock : 0;
            int16_t rev = 0;
            uint32_t m;
            if (!s || s->dead) {
                rev = POLLNVAL;
            } else {
                m = sock_poll_mask(s);
                if (m & POLLERR) rev |= POLLERR;
                if (m & POLLHUP) rev |= POLLHUP;
                if ((e[i].events & POLLRDNORM) && (m & POLLRDNORM)) rev |= POLLRDNORM;
                if ((e[i].events & POLLWRNORM) && (m & POLLWRNORM)) rev |= POLLWRNORM;
            }
            e[i].revents = rev;
            if (rev) ++ready;
        }
        if (ready || tmo == 0)
            break;
        if (net_current_terminating()) { st = NET_ERR(WSAEINTR); break; }
        if (deadline && net_now() >= deadline)
            break;
        {
            uint32_t ms = SLICE_MS;
            if (deadline && deadline - net_now() < ms) ms = (uint32_t)(deadline - net_now());
            net_sleep(ms ? ms : 1);
        }
    }
    net_unlock();
    if (!st && count && copy_to_user(p, uents, e, count * sizeof *e)) st = STATUS_ACCESS_VIOLATION;
    kfree(e);
    if (!st) st = put_u32(p, pready, ready);
    return st;
}

static int32_t op_resolve(process_t *p, struct regs *r, uint64_t name_uva, uint64_t namelen, uint64_t res_uva, uint64_t maxres)
{
    const uint64_t pcount = (uint64_t)stack_arg(p, r, 5), server_be = (uint64_t)stack_arg(p, r, 6), server_port = (uint64_t)stack_arg(p, r, 7);
    char name[260];
    ip4_t addrs[8];
    uint32_t be[8], i;
    unsigned count = 0;
    int32_t st;
    if (namelen == 0 || namelen > 253 || maxres == 0)
        return NET_ERR(WSAHOST_NOT_FOUND);
    if (copy_from_user(p, name, name_uva, namelen))
        return STATUS_ACCESS_VIOLATION;
    name[namelen] = 0;
    for (i = 0; i < namelen; ++i)
        if ((uint8_t)name[i] < 0x21 || (uint8_t)name[i] > 0x7e)
            return NET_ERR(WSAHOST_NOT_FOUND);              /* only ASCII host names (IDNA is the caller's business) */
    st = dns_resolve(name, addrs, maxres > 8 ? 8 : (unsigned)maxres, &count, bs32((uint32_t)server_be), (uint16_t)server_port);
    if (st)
        return st;
    for (i = 0; i < count; ++i)
        be[i] = bs32(addrs[i]);
    if (copy_to_user(p, res_uva, be, count * 4ull) || put_u32(p, pcount, count))
        return STATUS_ACCESS_VIOLATION;
    return 0;
}

static int32_t op_query(process_t *p, uint64_t cls, uint64_t buf, uint64_t len, uint64_t pret)
{
    int32_t st = 0;
    uint32_t ret = 0;
    net_lock();
    switch (cls) {
    case 0: {
        struct shz_net_info in;
        memset(&in, 0, sizeof in);
        in.flags = (g_net.nic_present ? 1u : 0) | (g_net.link_up ? 2u : 0) | (g_net.ip ? 4u : 0) | (g_net.dhcp_state == DHCP_BOUND ? 8u : 0);
        in.ip_be = bs32(g_net.ip); in.mask_be = bs32(g_net.mask); in.gw_be = bs32(g_net.gw);
        in.dns0_be = bs32(g_net.dns[0]); in.dns1_be = bs32(g_net.dns[1]); in.dhcp_server_be = bs32(g_net.dhcp_server);
        memcpy(in.mac, g_net.mac, 6);
        in.lease_secs = g_net.lease_secs;
        if (g_net.dhcp_state == DHCP_BOUND || g_net.dhcp_state == DHCP_RENEWING || g_net.dhcp_state == DHCP_REBINDING) {
            const uint64_t end = g_net.lease_start_ms + (uint64_t)g_net.lease_secs * 1000, now = net_now();
            in.lease_remaining_secs = end > now ? (uint32_t)((end - now) / 1000) : 0;
        }
        in.dhcp_state = (uint32_t)g_net.dhcp_state;
        if (len < sizeof in) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = copy_to_user(p, buf, &in, sizeof in) ? STATUS_ACCESS_VIOLATION : 0;
        ret = sizeof in;
        break;
    }
    case 1: {                                               /* NS_COUNT stack counters, then 6 NIC counters */
        uint32_t st_arr[NS_COUNT + 6];
        unsigned i;
        for (i = 0; i < NS_COUNT; ++i) st_arr[i] = g_nstat[i];
        for (i = 0; i < 6; ++i) st_arr[NS_COUNT + i] = nic_stat(i);
        if (len < sizeof st_arr) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = copy_to_user(p, buf, st_arr, sizeof st_arr) ? STATUS_ACCESS_VIOLATION : 0;
        ret = sizeof st_arr;
        break;
    }
    case 2: {                                               /* TCP connection table */
        const unsigned max = (unsigned)(len / sizeof(struct shz_tcp_row));
        uint8_t *tmp = kmalloc(max ? max * sizeof(struct shz_tcp_row) : 16);
        unsigned n;
        if (!tmp) { st = STATUS_NO_MEMORY; break; }
        n = tcp_dump(tmp, max);
        st = n && copy_to_user(p, buf, tmp, n * sizeof(struct shz_tcp_row)) ? STATUS_ACCESS_VIOLATION : 0;
        ret = n * (uint32_t)sizeof(struct shz_tcp_row);
        kfree(tmp);
        break;
    }
    case 3: {                                               /* control: {u32 op}; 1 = DHCP renew now, 2 = flush the DNS cache, 3 = flush the ARP cache */
        uint32_t op = 0;
        if (len < 4 || copy_from_user(p, &op, buf, 4)) { st = NET_ERR(WSAEFAULT); break; }
        if (op == 1) dhcp_renew_now();
        else if (op == 2) dns_flush_cache();
        else if (op == 3) net_arp_flush();
        else st = NET_ERR(WSAEINVAL);
        break;
    }
    case 4: {                                               /* TCP state census: u32[11] indexed by TCPS_* */
        uint32_t c[11];
        unsigned i;
        for (i = 0; i < 11; ++i) c[i] = tcp_state_count((int)i);
        if (len < sizeof c) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = copy_to_user(p, buf, c, sizeof c) ? STATUS_ACCESS_VIOLATION : 0;
        ret = sizeof c;
        break;
    }
    case 5: {                                               /* resource census for leak checks: pages free, heap used, tcbs, sockets */
        uint64_t m[4];
        const tcb_t *t;
        const sock_t *sk;
        m[0] = pmm_free_count();
        m[1] = kheap_used();
        m[2] = 0;
        m[3] = 0;
        for (t = g_tcbs; t; t = t->next) ++m[2];
        for (sk = g_socks; sk; sk = sk->next) ++m[3];
        if (len < sizeof m) { st = STATUS_BUFFER_TOO_SMALL; break; }
        st = copy_to_user(p, buf, m, sizeof m) ? STATUS_ACCESS_VIOLATION : 0;
        ret = sizeof m;
        break;
    }
    default:
        st = STATUS_INVALID_INFO_CLASS;
        break;
    }
    net_unlock();
    if (!st && pret)
        st = put_u32(p, pret, ret);
    return st;
}

static int32_t op_ping(process_t *p, struct regs *r, uint64_t dst_be, uint64_t idseq, uint64_t payload, uint64_t timeout_ms)
{
    const uint64_t prtt = (uint64_t)stack_arg(p, r, 5);
    uint32_t rtt = 0;
    int32_t st;
    net_lock();
    st = net_ping(bs32((uint32_t)dst_be), (uint16_t)(idseq >> 16), (uint16_t)idseq, (uint32_t)payload,
                  timeout_ms ? (uint32_t)timeout_ms : 1000, &rtt);
    net_unlock();
    if (st)
        return st;
    return put_u32(p, prtt, rtt);
}

int32_t sys_ext_net(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    if (net_ensure_init())
        return NET_ERR(WSAENETDOWN);
    switch (num) {
    case SYS_NtShzSocket: return op_socket(cur, a1, a2, a3, a4);
    case SYS_NtShzSockBind: return op_bind(cur, a1, a2, a3);
    case SYS_NtShzSockListen: return op_listen(cur, a1, a2);
    case SYS_NtShzSockAccept: return op_accept(cur, a1, a2, a3, a4);
    case SYS_NtShzSockConnect: return op_connect(cur, a1, a2, a3);
    case SYS_NtShzSockSend: return op_send(cur, r, a1, a2, a3, a4);
    case SYS_NtShzSockRecv: return op_recv(cur, r, a1, a2, a3, a4);
    case SYS_NtShzSockShutdown: return op_shutdown(cur, a1, a2);
    case SYS_NtShzSockName: return op_name(cur, a1, a2, a3, a4);
    case SYS_NtShzSockSetOpt: return op_setopt(cur, r, a1, a2, a3, a4);
    case SYS_NtShzSockGetOpt: return op_getopt(cur, r, a1, a2, a3, a4);
    case SYS_NtShzSockIoctl: return op_ioctl(cur, r, a1, a2, a3, a4);
    case SYS_NtShzSockPoll: return op_poll(cur, a1, a2, a3, a4);
    case SYS_NtShzNetResolve: return op_resolve(cur, r, a1, a2, a3, a4);
    case SYS_NtShzNetQuery: return op_query(cur, a1, a2, a3, a4);
    case SYS_NtShzNetPing: return op_ping(cur, r, a1, a2, a3, a4);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
