/* SPDX-License-Identifier: GPL-2.0-only
 * Winsock over the loopback interface: needs no NIC, so it also runs in the plain standalone runner. Exercises ws2_32.dll,
 * the kernel socket layer and the whole TCP/UDP/IPv4 stack (loopback packets go through the real header build, checksum,
 * fragmentation/reassembly and TCP state machine). Exit 0 = every check passed. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "nettest.h"

#define LO ((u_long)0x0100007f)                         /* 127.0.0.1 in network byte order */

static SOCKET make_listener(unsigned short *port_out, int backlog)
{
    struct sockaddr_in a;
    int len = sizeof a;
    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = LO;
    if (l == INVALID_SOCKET || bind(l, (struct sockaddr *)&a, sizeof a) || listen(l, backlog) || getsockname(l, (struct sockaddr *)&a, &len))
        return INVALID_SOCKET;
    *port_out = ntohs(a.sin_port);
    return l;
}
static SOCKET tcp_connect_lo(unsigned short port)
{
    struct sockaddr_in a;
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = LO;
    if (s == INVALID_SOCKET) return s;
    if (connect(s, (struct sockaddr *)&a, sizeof a)) { closesocket(s); return INVALID_SOCKET; }
    return s;
}

/* ---- server threads ---- */
struct srv { SOCKET ls; int mode; volatile long done; unsigned crc, total; };
enum { M_ECHO = 1, M_SINK = 2, M_HALF = 3, M_RESET = 4 };

static DWORD WINAPI server_thread(LPVOID arg)
{
    struct srv *sv = arg;
    SOCKET c = accept(sv->ls, 0, 0);
    unsigned char *buf = xmalloc(65536);
    if (c == INVALID_SOCKET) { sv->done = -1; return 1; }
    if (sv->mode == M_ECHO) {
        int n;
        while ((n = recv(c, (char *)buf, 65536, 0)) > 0)
            if (send_all(c, buf, n) < 0) break;
    } else if (sv->mode == M_SINK) {                       /* count and checksum everything, answer with the CRC */
        unsigned char *all = xmalloc(4 << 20);
        int n;
        unsigned total = 0;
        while ((n = recv(c, (char *)buf, 65536, 0)) > 0) {
            if (total + (unsigned)n <= (4u << 20)) memcpy(all + total, buf, (size_t)n);
            total += (unsigned)n;
        }
        sv->total = total;
        sv->crc = shz_crc32(all, total <= (4u << 20) ? total : (4u << 20));
        send_all(c, &sv->crc, 4);
        send_all(c, &sv->total, 4);
        free(all);
    } else if (sv->mode == M_HALF) {                       /* read until the client's FIN, then still answer */
        int n, total = 0;
        while ((n = recv(c, (char *)buf, 65536, 0)) > 0) total += n;
        sv->total = (unsigned)total;
        send_all(c, "REPLY-AFTER-FIN", 15);
    } else if (sv->mode == M_RESET) {                      /* abortive close: SO_LINGER {1, 0} makes closesocket send a RST */
        struct linger l;
        recv(c, (char *)buf, 1, 0);
        l.l_onoff = 1; l.l_linger = 0;
        setsockopt(c, SOL_SOCKET, SO_LINGER, (const char *)&l, sizeof l);
    }
    closesocket(c);
    free(buf);
    sv->done = 1;
    return 0;
}
static HANDLE start_server(struct srv *sv, int mode, unsigned short *port)
{
    memset(sv, 0, sizeof *sv);
    sv->mode = mode;
    sv->ls = make_listener(port, 8);
    if (sv->ls == INVALID_SOCKET) return 0;
    return CreateThread(0, 0, server_thread, sv, 0, 0);
}

struct sender { SOCKET s; unsigned char *data; int n; volatile long done; };
static DWORD WINAPI sender_thread(LPVOID arg)
{
    struct sender *sd = arg;
    sd->done = send_all(sd->s, sd->data, sd->n) == sd->n ? 1 : -1;
    return 0;
}

static void test_basics(void)
{
    WSADATA wsa;
    SOCKET s;
    struct in_addr ia;
    unsigned char b16[16], expect6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    char text[64];
    s = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(s == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED, "socket() before WSAStartup fails with WSANOTINITIALISED (10093), got %d", WSAGetLastError());
    CHECK(WSAStartup(MAKEWORD(2, 2), &wsa) == 0 && wsa.wVersion == MAKEWORD(2, 2) && wsa.wHighVersion == MAKEWORD(2, 2), "WSAStartup(2.2) succeeds and reports 2.2");
    CHECK(WSAStartup(MAKEWORD(3, 0), &wsa) == WSAVERNOTSUPPORTED, "WSAStartup(3.0) is refused with WSAVERNOTSUPPORTED");
    CHECK(htons(0x1234) == 0x3412 && ntohs(0x3412) == 0x1234 && htonl(0x01020304) == 0x04030201 && ntohl(0x04030201) == 0x01020304, "htons/ntohs/htonl/ntohl");
    CHECK(inet_addr("10.0.2.15") == 0x0f02000a && inet_addr("127.1") == 0x0100007f && inet_addr("0x7f.1") == 0x0100007f &&
          inet_addr("256.1.1.1") == INADDR_NONE && inet_addr("1.2.3") == 0x03000201 && inet_addr("a.b.c.d") == INADDR_NONE, "inet_addr forms and rejections");
    ia.s_addr = 0x0f02000a;
    CHECK(!strcmp(inet_ntoa(ia), "10.0.2.15"), "inet_ntoa(10.0.2.15)");
    CHECK(inet_pton(AF_INET, "192.168.1.200", b16) == 1 && b16[0] == 192 && b16[3] == 200 && inet_pton(AF_INET, "192.168.1", b16) == 0 &&
          inet_pton(AF_INET, "1.2.3.4.5", b16) == 0, "inet_pton(AF_INET)");
    CHECK(inet_pton(AF_INET6, "2001:db8::1", b16) == 1 && !memcmp(b16, expect6, 16), "inet_pton(AF_INET6, 2001:db8::1)");
    CHECK(inet_ntop(AF_INET6, expect6, text, sizeof text) && !strcmp(text, "2001:db8::1"), "inet_ntop(AF_INET6) compresses the longest zero run: %s", text);
    inet_pton(AF_INET6, "::ffff:1.2.3.4", b16);
    CHECK(inet_ntop(AF_INET6, b16, text, sizeof text) && !strcmp(text, "::ffff:1.2.3.4"), "inet_ntop v4-mapped: %s", text);
    inet_pton(AF_INET6, "::1", b16);
    CHECK(inet_ntop(AF_INET6, b16, text, sizeof text) && !strcmp(text, "::1") && !inet_ntop(AF_INET, b16, text, 4) && WSAGetLastError() == WSAENOBUFS,
          "inet_ntop ::1 and a too-small buffer fails with WSAENOBUFS");
    s = socket(AF_INET6, SOCK_STREAM, 0);
    CHECK(s == INVALID_SOCKET && WSAGetLastError() == WSAEAFNOSUPPORT, "AF_INET6 sockets are refused honestly (WSAEAFNOSUPPORT)");
    s = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    CHECK(s == INVALID_SOCKET && WSAGetLastError() == WSAESOCKTNOSUPPORT, "SOCK_RAW is refused (WSAESOCKTNOSUPPORT), got %d", WSAGetLastError());
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_UDP);
    CHECK(s == INVALID_SOCKET && WSAGetLastError() == WSAEPROTONOSUPPORT, "stream socket with IPPROTO_UDP is refused (WSAEPROTONOSUPPORT)");
    CHECK(closesocket((SOCKET)0x7770) == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK, "closesocket on a bad handle fails with WSAENOTSOCK");
    CHECK(send((SOCKET)0x7770, "x", 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK, "send on a bad handle fails with WSAENOTSOCK");
    {
        HANDLE ev = CreateEventW(0, TRUE, FALSE, 0);
        CHECK(closesocket((SOCKET)ev) == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK && WaitForSingleObject(ev, 0) == WAIT_TIMEOUT,
              "closesocket on a non-socket handle fails and leaves the handle alone");
        CloseHandle(ev);
    }
}

static void test_tcp_echo(void)
{
    struct srv sv;
    unsigned short port;
    HANDLE th = start_server(&sv, M_ECHO, &port);
    SOCKET c;
    struct sockaddr_in la, pa;
    int ll = sizeof la, pl = sizeof pa;
    char out[200], in[200];
    int i;
    CHECK(th != 0, "echo server listening on 127.0.0.1:%u", port);
    c = tcp_connect_lo(port);
    CHECK(c != INVALID_SOCKET, "blocking connect() to the loopback listener");
    CHECK(getsockname(c, (struct sockaddr *)&la, &ll) == 0 && la.sin_addr.s_addr == LO && ntohs(la.sin_port) >= 49152, "client local address 127.0.0.1:%u (ephemeral)", ntohs(la.sin_port));
    CHECK(getpeername(c, (struct sockaddr *)&pa, &pl) == 0 && pa.sin_addr.s_addr == LO && ntohs(pa.sin_port) == port, "getpeername returns the listener address");
    for (i = 0; i < 200; ++i) out[i] = (char)pat((unsigned)i);
    CHECK(send_all(c, out, 200) == 200 && recv_all(c, in, 200) == 200 && !memcmp(in, out, 200), "200 bytes echoed back intact");
    CHECK(shutdown(c, SD_SEND) == 0, "shutdown(SD_SEND)");
    CHECK(recv(c, in, 10, 0) == 0, "recv returns 0 (orderly close) after the server saw our FIN and closed");
    CHECK(send(c, "x", 1, 0) == SOCKET_ERROR && WSAGetLastError() == WSAESHUTDOWN, "send after shutdown(SD_SEND) fails with WSAESHUTDOWN, got %d", WSAGetLastError());
    closesocket(c);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    closesocket(sv.ls);
}

static void test_tcp_bulk(void)
{
    struct srv sv;
    unsigned short port;
    HANDLE th = start_server(&sv, M_SINK, &port);
    SOCKET c = tcp_connect_lo(port);
    const int total = 3 << 20;
    unsigned char *data = xmalloc((size_t)total);
    unsigned resp[2] = {0, 0};
    unsigned crc;
    DWORD t0, t1;
    fill_pat(data, (size_t)total, 0);
    crc = shz_crc32(data, (size_t)total);
    t0 = GetTickCount();
    CHECK(c != INVALID_SOCKET && send_all(c, data, total) == total, "3 MiB written to the loopback connection");
    shutdown(c, SD_SEND);
    CHECK(recv_all(c, resp, 8) == 8, "server replied with CRC and byte count");
    t1 = GetTickCount();
    CHECK(resp[1] == (unsigned)total && resp[0] == crc, "server received %u bytes, CRC32 %08x == ours %08x", resp[1], resp[0], crc);
    printf("INFO: loopback bulk transfer 3 MiB in %u ms\n", (unsigned)(t1 - t0));
    closesocket(c);
    WaitForSingleObject(th, 5000);
    CloseHandle(th);
    closesocket(sv.ls);
    free(data);
}

static void test_tcp_duplex(void)
{
    struct srv sv;
    unsigned short port;
    HANDLE th = start_server(&sv, M_ECHO, &port), sth;
    SOCKET c = tcp_connect_lo(port);
    const int total = 2 << 20;
    unsigned char *data = xmalloc((size_t)total), *back = xmalloc((size_t)total);
    struct sender sd;
    fill_pat(data, (size_t)total, 77);
    sd.s = c; sd.data = data; sd.n = total; sd.done = 0;
    sth = CreateThread(0, 0, sender_thread, &sd, 0, 0);
    CHECK(th != 0 && c != INVALID_SOCKET && sth != 0, "full-duplex test: echo server + concurrent sender");
    CHECK(recv_all(c, back, total) == total, "received the whole 2 MiB echo while the sender was still writing");
    WaitForSingleObject(sth, 10000);
    CHECK(sd.done == 1 && !memcmp(back, data, (size_t)total), "2 MiB echoed back byte-identical (CRC %08x)", shz_crc32(back, (size_t)total));
    closesocket(c);
    WaitForSingleObject(th, 5000);
    CloseHandle(th); CloseHandle(sth);
    closesocket(sv.ls);
    free(data); free(back);
}

static void test_half_close_and_reset(void)
{
    struct srv sv;
    unsigned short port;
    HANDLE th = start_server(&sv, M_HALF, &port);
    SOCKET c = tcp_connect_lo(port);
    char reply[32];
    int n;
    CHECK(c != INVALID_SOCKET && send_all(c, "0123456789", 10) == 10, "half-close: client sent 10 bytes");
    CHECK(shutdown(c, SD_SEND) == 0, "half-close: client shutdown(SD_SEND)");
    n = recv_all(c, reply, 15);
    CHECK(n == 15 && !memcmp(reply, "REPLY-AFTER-FIN", 15), "half-close: reply that follows the peer's FIN is still delivered (%d bytes)", n);
    CHECK(recv(c, reply, 1, 0) == 0 && sv.total == 10, "half-close: then orderly EOF; server counted %u bytes", sv.total);
    closesocket(c);
    WaitForSingleObject(th, 5000); CloseHandle(th); closesocket(sv.ls);

    th = start_server(&sv, M_RESET, &port);
    c = tcp_connect_lo(port);
    send(c, "x", 1, 0);
    n = recv(c, reply, 10, 0);
    CHECK(n == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET, "RST (linger 0 close) surfaces as WSAECONNRESET, got n=%d err=%d", n, WSAGetLastError());
    n = send(c, "y", 1, 0);
    CHECK(n == SOCKET_ERROR && (WSAGetLastError() == WSAECONNRESET || WSAGetLastError() == WSAECONNABORTED || WSAGetLastError() == WSAESHUTDOWN), "send on a reset connection fails, err=%d", WSAGetLastError());
    { int e = 0, l = sizeof e; CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&e, &l) == 0 && e == WSAECONNRESET, "SO_ERROR reports WSAECONNRESET (%d)", e); }
    closesocket(c);
    WaitForSingleObject(th, 5000); CloseHandle(th); closesocket(sv.ls);
}

static void test_refused_and_timeout(void)
{
    struct sockaddr_in a;
    unsigned short port;
    SOCKET l = make_listener(&port, 1), s, s2;
    DWORD t0, dt, to = 300;
    char b[4];
    int r;
    closesocket(l);                                        /* nothing listens on that port any more */
    s = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = LO;
    r = connect(s, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAECONNREFUSED, "connect to a closed loopback port fails with WSAECONNREFUSED (10061), got %d", WSAGetLastError());
    closesocket(s);

    l = make_listener(&port, 1);
    s = tcp_connect_lo(port);
    s2 = accept(l, 0, 0);
    CHECK(s != INVALID_SOCKET && s2 != INVALID_SOCKET, "connected pair for the timeout test");
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof to);
    t0 = GetTickCount();
    r = recv(s, b, 4, 0);
    dt = GetTickCount() - t0;
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAETIMEDOUT && dt >= 250 && dt < 2000, "recv with SO_RCVTIMEO=300 ms times out with WSAETIMEDOUT after %u ms", (unsigned)dt);
    { DWORD v = 0; int vl = sizeof v; CHECK(getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&v, &vl) == 0 && v == 300, "SO_RCVTIMEO reads back 300"); }
    closesocket(s); closesocket(s2); closesocket(l);
}

static void test_nonblocking_select_poll(void)
{
    unsigned short port;
    SOCKET l = make_listener(&port, 4), c, a;
    u_long nb = 1;
    fd_set rd, wr, ex;
    struct timeval tv;
    struct sockaddr_in sa;
    WSAPOLLFD pf[2];
    char buf[64];
    int r, e;
    DWORD t0;
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = LO; sa.sin_port = htons(port);
    ioctlsocket(l, FIONBIO, &nb);
    a = accept(l, 0, 0);
    CHECK(a == INVALID_SOCKET && WSAGetLastError() == WSAEWOULDBLOCK, "non-blocking accept with nothing pending fails with WSAEWOULDBLOCK (10035), got %d", WSAGetLastError());
    FD_ZERO(&rd); FD_SET(l, &rd); tv.tv_sec = 0; tv.tv_usec = 50000;
    t0 = GetTickCount();
    r = select(0, &rd, 0, 0, &tv);
    CHECK(r == 0 && rd.fd_count == 0 && GetTickCount() - t0 >= 40, "select() times out with 0 ready and an emptied set (%u ms)", (unsigned)(GetTickCount() - t0));
    c = socket(AF_INET, SOCK_STREAM, 0);
    ioctlsocket(c, FIONBIO, &nb);
    r = connect(c, (struct sockaddr *)&sa, sizeof sa);
    e = WSAGetLastError();
    CHECK(r == SOCKET_ERROR && e == WSAEWOULDBLOCK, "non-blocking connect returns WSAEWOULDBLOCK, got %d", e);
    FD_ZERO(&rd); FD_SET(l, &rd); tv.tv_sec = 2; tv.tv_usec = 0;
    r = select(0, &rd, 0, 0, &tv);
    CHECK(r == 1 && FD_ISSET(l, &rd), "listening socket is readable once the connection is established");
    FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(c, &wr); FD_SET(c, &ex);
    r = select(0, 0, &wr, &ex, &tv);
    CHECK(r >= 1 && FD_ISSET(c, &wr) && !FD_ISSET(c, &ex), "connecting socket becomes writable, not exceptional");
    { int soerr = -1, l2 = sizeof soerr; CHECK(getsockopt(c, SOL_SOCKET, SO_ERROR, (char *)&soerr, &l2) == 0 && soerr == 0, "SO_ERROR after a successful non-blocking connect is 0"); }
    a = accept(l, 0, 0);
    CHECK(a != INVALID_SOCKET, "accept() takes the pending connection");
    r = recv(c, buf, sizeof buf, 0);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK, "non-blocking recv with no data fails with WSAEWOULDBLOCK");
    pf[0].fd = c; pf[0].events = POLLRDNORM; pf[0].revents = 0;
    pf[1].fd = a; pf[1].events = POLLWRNORM; pf[1].revents = 0;
    r = WSAPoll(pf, 2, 1000);
    CHECK(r == 1 && !pf[0].revents && (pf[1].revents & POLLWRNORM), "WSAPoll: only the accepted socket is writable");
    send(a, "hello", 5, 0);
    pf[0].revents = 0;
    r = WSAPoll(pf, 1, 1000);
    CHECK(r == 1 && (pf[0].revents & POLLRDNORM), "WSAPoll reports POLLRDNORM once data arrives");
    { u_long avail = 0; CHECK(ioctlsocket(c, FIONREAD, &avail) == 0 && avail == 5, "FIONREAD reports 5 bytes"); }
    r = recv(c, buf, 3, MSG_PEEK);
    CHECK(r == 3 && !memcmp(buf, "hel", 3), "MSG_PEEK returns data without consuming it");
    r = recv(c, buf, sizeof buf, 0);
    CHECK(r == 5 && !memcmp(buf, "hello", 5), "recv then returns all 5 bytes");
    closesocket(a);
    FD_ZERO(&rd); FD_SET(c, &rd); tv.tv_sec = 2;
    r = select(0, &rd, 0, 0, &tv);
    CHECK(r == 1 && FD_ISSET(c, &rd) && recv(c, buf, 8, 0) == 0, "peer close makes the socket readable and recv returns 0");
    r = select(0, 0, 0, 0, &tv);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "select with three empty sets fails with WSAEINVAL");
    closesocket(c); closesocket(l);
    FD_ZERO(&rd); FD_SET((SOCKET)0x7770, &rd); tv.tv_sec = 0; tv.tv_usec = 1000;
    r = select(0, &rd, 0, 0, &tv);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAENOTSOCK, "select on a closed socket fails with WSAENOTSOCK");
}

static void test_send_buffer_fill(void)
{
    unsigned short port;
    SOCKET l = make_listener(&port, 2), c, a;
    u_long nb = 1;
    unsigned char *blk = xmalloc(16384), *sink = xmalloc(65536);
    unsigned long long queued = 0;
    int r;
    fd_set wr;
    struct timeval tv;
    fill_pat(blk, 16384, 0);                                /* every 16384-byte block repeats: byte i of the stream is pat(i % 16384) */
    c = tcp_connect_lo(port);
    a = accept(l, 0, 0);
    ioctlsocket(c, FIONBIO, &nb);
    for (;;) {
        r = send(c, (const char *)blk, 16384, 0);
        if (r == SOCKET_ERROR) break;
        queued += (unsigned)r;
        if (r < 16384) { r = SOCKET_ERROR; WSASetLastError(WSAEWOULDBLOCK); break; }   /* partial write: block boundary shifts, stop at a whole block */
        if (queued > (64u << 20)) break;
    }
    if (r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
        /* The loopback may still be moving queued bytes into the peer's receive buffer (the network thread runs after this
         * one filled the send buffer), which frees send space again. Top it up until a send after a 20 ms pause takes
         * nothing: then both buffers are full and stay full. Partial sends continue the pattern at the stream offset. */
        int settle;
        for (settle = 0; settle < 100; ++settle) {
            const unsigned off = (unsigned)(queued % 16384);
            Sleep(20);
            r = send(c, (const char *)blk + off, 16384 - (int)off, 0);
            if (r == SOCKET_ERROR) break;
            queued += (unsigned)r;
        }
    }
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK && queued > 100000 && queued < (16u << 20),
          "non-blocking send stops with WSAEWOULDBLOCK once buffers are full (%u bytes accepted)", (unsigned)queued);
    FD_ZERO(&wr); FD_SET(c, &wr); tv.tv_sec = 0; tv.tv_usec = 20000;
    CHECK(select(0, 0, &wr, 0, &tv) == 0, "a socket with a full send buffer is not writable");
    {   /* the peer's window is closed: hold it shut long enough for the zero-window probe timer, then drain and verify the stream */
        ULONG persist0 = net_stat(NST_TCP_PERSIST);
        unsigned long long got = 0;
        int n, intact = 1;
        Sleep(1600);
        CHECK(net_stat(NST_TCP_PERSIST) > persist0, "the sender probed the zero window while the peer was not reading (%u probe(s))", (unsigned)(net_stat(NST_TCP_PERSIST) - persist0));
        while (got < queued && (n = recv(a, (char *)sink, 65536, 0)) > 0) {
            int i;
            for (i = 0; i < n; ++i)
                if (sink[i] != pat((got + (unsigned)i) % 16384)) { intact = 0; break; }
            got += (unsigned)n;
        }
        CHECK(got == queued && intact, "peer drained all %u queued bytes, stream intact despite the window probes", (unsigned)got);
    }
    FD_ZERO(&wr); FD_SET(c, &wr); tv.tv_sec = 2;
    CHECK(select(0, 0, &wr, 0, &tv) == 1, "socket is writable again after the peer read (window reopened)");
    closesocket(c); closesocket(a); closesocket(l);
    free(blk); free(sink);
}

static void test_udp(void)
{
    struct sockaddr_in a1, a2, from;
    SOCKET u1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP), u2 = socket(AF_INET, SOCK_DGRAM, 0);
    int len = sizeof a1, fl = sizeof from, r;
    char buf[100];
    unsigned char *big = xmalloc(65536), *rb = xmalloc(65536);
    memset(&a1, 0, sizeof a1); a1.sin_family = AF_INET; a1.sin_addr.s_addr = LO;
    a2 = a1;
    CHECK(bind(u1, (struct sockaddr *)&a1, sizeof a1) == 0 && bind(u2, (struct sockaddr *)&a2, sizeof a2) == 0, "two UDP sockets bound to ephemeral loopback ports");
    getsockname(u1, (struct sockaddr *)&a1, &len);
    len = sizeof a2; getsockname(u2, (struct sockaddr *)&a2, &len);
    CHECK(sendto(u1, "ping-datagram", 13, 0, (struct sockaddr *)&a2, sizeof a2) == 13, "sendto 13 bytes");
    r = recvfrom(u2, buf, sizeof buf, 0, (struct sockaddr *)&from, &fl);
    CHECK(r == 13 && !memcmp(buf, "ping-datagram", 13) && from.sin_port == a1.sin_port && from.sin_addr.s_addr == LO, "recvfrom returns the datagram and the sender address (port %u)", ntohs(from.sin_port));
    sendto(u1, "0123456789", 10, 0, (struct sockaddr *)&a2, sizeof a2);
    r = recvfrom(u2, buf, 4, 0, 0, 0);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEMSGSIZE, "datagram larger than the buffer fails with WSAEMSGSIZE (10040), got %d", WSAGetLastError());
    /* datagrams larger than the loopback MTU are fragmented and reassembled */
    fill_pat(big, 60000, 5);
    CHECK(sendto(u1, (const char *)big, 60000, 0, (struct sockaddr *)&a2, sizeof a2) == 60000, "sendto 60000 bytes (IPv4 fragmentation on the 16384-byte loopback MTU)");
    r = recvfrom(u2, (char *)rb, 65536, 0, 0, 0);
    CHECK(r == 60000 && !memcmp(rb, big, 60000), "60000-byte datagram reassembled byte-identical");
    /* connected UDP */
    CHECK(connect(u1, (struct sockaddr *)&a2, sizeof a2) == 0 && send(u1, "conn", 4, 0) == 4 && recv(u2, buf, sizeof buf, 0) == 4, "connect()+send() on a datagram socket");
    { struct sockaddr_in pn; int pl = sizeof pn; CHECK(getpeername(u1, (struct sockaddr *)&pn, &pl) == 0 && pn.sin_port == a2.sin_port, "getpeername on the connected UDP socket"); }
    /* ICMP port unreachable: send to a closed port from a connected socket, the next recv reports it */
    closesocket(u2);
    send(u1, "x", 1, 0);
    { u_long nb = 1; ioctlsocket(u1, FIONBIO, &nb); }
    {
        DWORD t0 = GetTickCount();
        r = SOCKET_ERROR;
        while (GetTickCount() - t0 < 1000) {
            r = recv(u1, buf, sizeof buf, 0);
            if (r != SOCKET_ERROR || WSAGetLastError() != WSAEWOULDBLOCK) break;
            Sleep(5);
        }
        CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAECONNRESET, "ICMP port unreachable for a connected UDP socket surfaces as WSAECONNRESET (10054), got %d", WSAGetLastError());
    }
    closesocket(u1);
    free(big); free(rb);
}

static void test_options_and_binding(void)
{
    unsigned short port;
    SOCKET l = make_listener(&port, 5), s2, s3;
    struct sockaddr_in a;
    int v, vl, r;
    struct linger lg, lg2;
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = LO; a.sin_port = htons(port);
    s2 = socket(AF_INET, SOCK_STREAM, 0);
    r = bind(s2, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEADDRINUSE, "bind to a port with a listener fails with WSAEADDRINUSE (10048), got %d", WSAGetLastError());
    a.sin_addr.s_addr = htonl(0x08080808);
    r = bind(s2, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEADDRNOTAVAIL, "bind to a non-local address fails with WSAEADDRNOTAVAIL (10049)");
    a.sin_addr.s_addr = LO; a.sin_port = 0;
    v = 1;
    CHECK(setsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (const char *)&v, sizeof v) == 0 && bind(s2, (struct sockaddr *)&a, sizeof a) == 0, "SO_REUSEADDR set, bind to port 0 gives an ephemeral port");
    r = bind(s2, (struct sockaddr *)&a, sizeof a);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "binding an already bound socket fails with WSAEINVAL");
    r = listen(socket(AF_INET, SOCK_STREAM, 0), 5);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAEINVAL, "listen on an unbound socket fails with WSAEINVAL");
    vl = sizeof v; v = 0;
    CHECK(getsockopt(s2, SOL_SOCKET, SO_REUSEADDR, (char *)&v, &vl) == 0 && v == 1, "SO_REUSEADDR reads back 1");
    vl = sizeof v; v = 0;
    CHECK(getsockopt(l, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &vl) == 0 && v == 1 && getsockopt(s2, SOL_SOCKET, SO_ACCEPTCONN, (char *)&v, &vl) == 0 && v == 0, "SO_ACCEPTCONN distinguishes listener");
    vl = sizeof v;
    CHECK(getsockopt(s2, SOL_SOCKET, SO_TYPE, (char *)&v, &vl) == 0 && v == SOCK_STREAM, "SO_TYPE == SOCK_STREAM");
    v = 32768; vl = sizeof v;
    CHECK(setsockopt(s2, SOL_SOCKET, SO_RCVBUF, (const char *)&v, sizeof v) == 0 && setsockopt(s2, SOL_SOCKET, SO_SNDBUF, (const char *)&v, sizeof v) == 0, "SO_RCVBUF/SO_SNDBUF set");
    v = 0;
    CHECK(getsockopt(s2, SOL_SOCKET, SO_RCVBUF, (char *)&v, &vl) == 0 && v == 32768 && getsockopt(s2, SOL_SOCKET, SO_SNDBUF, (char *)&v, &vl) == 0 && v == 32768, "SO_RCVBUF/SO_SNDBUF read back 32768");
    v = 1;
    CHECK(setsockopt(s2, IPPROTO_TCP, TCP_NODELAY, (const char *)&v, sizeof v) == 0 && setsockopt(s2, SOL_SOCKET, SO_KEEPALIVE, (const char *)&v, sizeof v) == 0, "TCP_NODELAY and SO_KEEPALIVE set");
    v = 0; vl = sizeof v;
    CHECK(getsockopt(s2, IPPROTO_TCP, TCP_NODELAY, (char *)&v, &vl) == 0 && v == 1 && getsockopt(s2, SOL_SOCKET, SO_KEEPALIVE, (char *)&v, &vl) == 0 && v == 1, "TCP_NODELAY and SO_KEEPALIVE read back 1");
    lg.l_onoff = 1; lg.l_linger = 7;
    setsockopt(s2, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof lg);
    vl = sizeof lg2; memset(&lg2, 0, sizeof lg2);
    CHECK(getsockopt(s2, SOL_SOCKET, SO_LINGER, (char *)&lg2, &vl) == 0 && lg2.l_onoff == 1 && lg2.l_linger == 7, "SO_LINGER {1,7} round trip");
    r = setsockopt(s2, SOL_SOCKET, 0x7fff, (const char *)&v, sizeof v);
    CHECK(r == SOCKET_ERROR && WSAGetLastError() == WSAENOPROTOOPT, "an unknown socket option fails with WSAENOPROTOOPT (10042)");
    { char one = 1; CHECK(setsockopt(s2, SOL_SOCKET, SO_BROADCAST, &one, 1) == 0, "a 1-byte BOOL option value is accepted"); }
    s3 = socket(AF_INET, SOCK_DGRAM, 0);
    vl = sizeof v;
    CHECK(getsockopt(s3, SOL_SOCKET, SO_TYPE, (char *)&v, &vl) == 0 && v == SOCK_DGRAM, "SO_TYPE == SOCK_DGRAM");
    closesocket(s2); closesocket(s3); closesocket(l);
}

static void test_many_sockets(void)
{
    enum { N = 100 };
    unsigned short port;
    SOCKET l = make_listener(&port, 128), c[N], a[N];
    int i, ok = 0, echoed = 0;
    unsigned tw_before = net_state_count(TCPS_TIME_WAIT_T);
    for (i = 0; i < N; ++i) { c[i] = INVALID_SOCKET; a[i] = INVALID_SOCKET; }
    for (i = 0; i < N; ++i) {
        c[i] = tcp_connect_lo(port);
        if (c[i] != INVALID_SOCKET) ++ok;
    }
    CHECK(ok == N, "%d simultaneous loopback connections established (backlog 128)", ok);
    for (i = 0; i < N; ++i) a[i] = accept(l, 0, 0);
    ok = 0;
    for (i = 0; i < N; ++i) if (a[i] != INVALID_SOCKET) ++ok;
    CHECK(ok == N, "%d connections accepted", ok);
    for (i = 0; i < N; ++i) {
        char b = (char)i, r = 0;
        if (send(c[i], &b, 1, 0) == 1 && recv(a[i], &r, 1, 0) == 1 && r == b && send(a[i], &r, 1, 0) == 1 && recv(c[i], &r, 1, 0) == 1 && r == b) ++echoed;
    }
    CHECK(echoed == N, "every one of the %d connections carried its own byte both ways", echoed);
    for (i = 0; i < N; ++i) { closesocket(c[i]); }
    for (i = 0; i < N; ++i) { char b; recv(a[i], &b, 1, 0); closesocket(a[i]); }
    {   /* The passive side's FINs reach the active closers through the loopback thread, which may not have run since the
         * last closesocket(): wait up to 5 s for the census to settle instead of reading it once. */
        const DWORD t0 = GetTickCount();
        while (net_state_count(TCPS_TIME_WAIT_T) < tw_before + N / 2 && GetTickCount() - t0 < 5000) Sleep(10);
    }
    CHECK(net_state_count(TCPS_TIME_WAIT_T) >= tw_before + N / 2, "active closers are in TIME_WAIT (%u now, %u before)", (unsigned)net_state_count(TCPS_TIME_WAIT_T), tw_before);
    closesocket(l);
}

static DWORD WINAPI closer_thread(LPVOID arg)
{
    Sleep(150);
    closesocket((SOCKET)arg);
    return 0;
}

static void test_close_while_blocked(void)
{
    unsigned short port;
    SOCKET l = make_listener(&port, 1), c, a;
    HANDLE th;
    DWORD t0;
    int r;
    char b;
    th = CreateThread(0, 0, closer_thread, (LPVOID)l, 0, 0);
    t0 = GetTickCount();
    a = accept(l, 0, 0);
    CHECK(a == INVALID_SOCKET && GetTickCount() - t0 < 2000, "closesocket() from another thread ends a blocking accept() (err %d, %u ms)", WSAGetLastError(), (unsigned)(GetTickCount() - t0));
    WaitForSingleObject(th, 2000); CloseHandle(th);
    l = make_listener(&port, 1);
    c = tcp_connect_lo(port);
    a = accept(l, 0, 0);
    th = CreateThread(0, 0, closer_thread, (LPVOID)c, 0, 0);
    t0 = GetTickCount();
    r = recv(c, &b, 1, 0);
    CHECK(r == SOCKET_ERROR && GetTickCount() - t0 < 2000, "closesocket() from another thread ends a blocking recv() (err %d)", WSAGetLastError());
    WaitForSingleObject(th, 2000); CloseHandle(th);
    closesocket(a); closesocket(l);
}

static void test_events(void)
{
    unsigned short port;
    SOCKET l = make_listener(&port, 2), c, a;
    WSAEVENT le = WSACreateEvent(), ce = WSACreateEvent();
    WSANETWORKEVENTS ne;
    struct sockaddr_in sa;
    char buf[16];
    DWORD w;
    memset(&sa, 0, sizeof sa); sa.sin_family = AF_INET; sa.sin_addr.s_addr = LO; sa.sin_port = htons(port);
    CHECK(WSAEventSelect(l, le, FD_ACCEPT) == 0, "WSAEventSelect(listener, FD_ACCEPT)");
    c = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(WSAEventSelect(c, ce, FD_CONNECT | FD_READ | FD_WRITE | FD_CLOSE) == 0, "WSAEventSelect(client, CONNECT|READ|WRITE|CLOSE)");
    connect(c, (struct sockaddr *)&sa, sizeof sa);
    CHECK(WSAGetLastError() == WSAEWOULDBLOCK, "connect on an event-selected socket is non-blocking");
    w = WSAWaitForMultipleEvents(1, &le, FALSE, 2000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0 && WSAEnumNetworkEvents(l, le, &ne) == 0 && (ne.lNetworkEvents & FD_ACCEPT) && ne.iErrorCode[FD_ACCEPT_BIT] == 0, "FD_ACCEPT signalled on the listener");
    a = accept(l, 0, 0);
    w = WSAWaitForMultipleEvents(1, &ce, FALSE, 2000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0 && WSAEnumNetworkEvents(c, ce, &ne) == 0 && (ne.lNetworkEvents & FD_CONNECT) && ne.iErrorCode[FD_CONNECT_BIT] == 0 && (ne.lNetworkEvents & FD_WRITE),
          "FD_CONNECT (no error) and FD_WRITE signalled on the client (events %lx)", ne.lNetworkEvents);
    CHECK(WSAWaitForMultipleEvents(1, &ce, FALSE, 30, FALSE) == WSA_WAIT_TIMEOUT, "the event is reset by WSAEnumNetworkEvents");
    send(a, "abc", 3, 0);
    w = WSAWaitForMultipleEvents(1, &ce, FALSE, 2000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0 && WSAEnumNetworkEvents(c, ce, &ne) == 0 && (ne.lNetworkEvents & FD_READ), "FD_READ signalled when data arrives");
    recv(c, buf, sizeof buf, 0);
    closesocket(a);
    w = WSAWaitForMultipleEvents(1, &ce, FALSE, 2000, FALSE);
    CHECK(w == WSA_WAIT_EVENT_0 && WSAEnumNetworkEvents(c, ce, &ne) == 0 && (ne.lNetworkEvents & FD_CLOSE) && ne.iErrorCode[FD_CLOSE_BIT] == 0, "FD_CLOSE signalled (no error) on the orderly peer close");
    CHECK(WSAEventSelect(c, 0, 0) == 0, "WSAEventSelect(s, NULL, 0) cancels the selection");
    closesocket(c); closesocket(l);
    WSACloseEvent(le); WSACloseEvent(ce);
}

static void test_names(void)
{
    struct addrinfo hints, *res = 0, *p;
    ADDRINFOW hw, *wres = 0;
    struct hostent *he;
    char host[64];
    int r, n;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    r = getaddrinfo("127.0.0.1", "8080", &hints, &res);
    CHECK(r == 0 && res && res->ai_family == AF_INET && res->ai_socktype == SOCK_STREAM && res->ai_protocol == IPPROTO_TCP &&
          ((struct sockaddr_in *)res->ai_addr)->sin_port == htons(8080) && ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == LO && !res->ai_next,
          "getaddrinfo(127.0.0.1, 8080, stream) -> one TCP sockaddr_in");
    freeaddrinfo(res);
    hints.ai_socktype = 0; hints.ai_flags = AI_PASSIVE;
    r = getaddrinfo(0, "http", &hints, &res);
    n = 0;
    for (p = res; p; p = p->ai_next) ++n;
    CHECK(r == 0 && n == 2 && ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == 0 && ((struct sockaddr_in *)res->ai_addr)->sin_port == htons(80), "AI_PASSIVE + service 'http' -> 0.0.0.0:80 for TCP and UDP");
    freeaddrinfo(res);
    hints.ai_flags = AI_CANONNAME;
    r = getaddrinfo("localhost", "443", &hints, &res);
    CHECK(r == 0 && res && res->ai_canonname && !strcmp(res->ai_canonname, "localhost") && ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr == LO, "getaddrinfo(localhost) resolves locally with AI_CANONNAME");
    freeaddrinfo(res);
    hints.ai_flags = AI_NUMERICHOST;
    r = getaddrinfo("localhost", 0, &hints, &res);
    CHECK(r == WSAHOST_NOT_FOUND && WSAGetLastError() == WSAHOST_NOT_FOUND, "AI_NUMERICHOST refuses a name (WSAHOST_NOT_FOUND 11001)");
    hints.ai_flags = 0;
    r = getaddrinfo("127.0.0.1", "no-such-service", &hints, &res);
    CHECK(r == WSATYPE_NOT_FOUND, "unknown service name fails with WSATYPE_NOT_FOUND (10109), got %d", r);
    memset(&hw, 0, sizeof hw); hw.ai_family = AF_INET; hw.ai_socktype = SOCK_DGRAM;
    r = GetAddrInfoW(L"127.0.0.1", L"53", &hw, &wres);
    CHECK(r == 0 && wres && wres->ai_socktype == SOCK_DGRAM && ((struct sockaddr_in *)wres->ai_addr)->sin_port == htons(53), "GetAddrInfoW(127.0.0.1, 53, dgram)");
    FreeAddrInfoW(wres);
    he = gethostbyname("localhost");
    CHECK(he && he->h_addrtype == AF_INET && he->h_length == 4 && he->h_addr_list[0] && *(u_long *)he->h_addr_list[0] == LO, "gethostbyname(localhost) -> 127.0.0.1");
    he = gethostbyname("192.0.2.9");
    CHECK(he && *(u_long *)he->h_addr_list[0] == inet_addr("192.0.2.9"), "gethostbyname of a literal");
    CHECK(gethostname(host, sizeof host) == 0 && host[0], "gethostname -> '%s'", host);
    CHECK(gethostname(host, 2) == SOCKET_ERROR && WSAGetLastError() == WSAEFAULT, "gethostname with a short buffer fails with WSAEFAULT");
}

/* One round of everything that allocates kernel memory: buffers of a bulk transfer, listeners, datagram queues, 30 connections. */
static void leak_workload(void)
{
    struct srv sv;
    unsigned short port;
    HANDLE th = start_server(&sv, M_SINK, &port);
    SOCKET c = tcp_connect_lo(port), u1 = socket(AF_INET, SOCK_DGRAM, 0), u2 = socket(AF_INET, SOCK_DGRAM, 0), l2, cc, aa;
    unsigned char *data = xmalloc(300000);
    unsigned resp[2];
    struct sockaddr_in a;
    int i, len = sizeof a;
    fill_pat(data, 300000, 3);
    send_all(c, data, 300000);
    shutdown(c, SD_SEND);
    recv_all(c, resp, 8);
    closesocket(c);
    WaitForSingleObject(th, 5000); CloseHandle(th); closesocket(sv.ls);
    memset(&a, 0, sizeof a); a.sin_family = AF_INET; a.sin_addr.s_addr = LO;
    bind(u1, (struct sockaddr *)&a, sizeof a); bind(u2, (struct sockaddr *)&a, sizeof a);
    getsockname(u2, (struct sockaddr *)&a, &len);
    for (i = 0; i < 20; ++i) sendto(u1, (const char *)data, 1000, 0, (struct sockaddr *)&a, sizeof a);   /* left queued, freed by close */
    closesocket(u1); closesocket(u2);
    l2 = make_listener(&port, 32);
    for (i = 0; i < 30; ++i) {
        cc = tcp_connect_lo(port);
        aa = accept(l2, 0, 0);
        send(cc, (const char *)data, 500, 0);               /* unread data on the server side forces the RST-on-close path */
        Sleep(1);
        closesocket(aa);
        closesocket(cc);
    }
    closesocket(l2);
    free(data);
}

static void test_no_leaks(void)
{
    unsigned long long m1[4], m2[4], m3[4];
    leak_workload();                                        /* warm-up: user heap growth and one-off kernel allocations */
    Sleep(50);
    CHECK(net_census(m1), "resource census");
    leak_workload();
    Sleep(50);
    leak_workload();
    Sleep(50);
    CHECK(net_census(m2) && net_census(m3), "resource census after two more rounds");
    CHECK(m2[0] + 8 >= m1[0] && m3[0] + 8 >= m1[0], "no physical page leak across %u socket rounds: free pages %llu -> %llu", 2u, m1[0], m3[0]);
    CHECK(m3[3] == m1[3] && m3[3] <= 8, "every socket object was released (%llu live)", m3[3]);
    printf("INFO: census pages %llu/%llu/%llu heap %llu/%llu/%llu tcbs %llu/%llu/%llu\n", m1[0], m2[0], m3[0], m1[1], m2[1], m3[1], m1[2], m2[2], m3[2]);
}

static DWORD WINAPI parked_thread(LPVOID arg)
{
    char b;
    recv((SOCKET)arg, &b, 1, 0);                            /* blocks forever: nobody ever sends */
    return 0;
}

int main(void)
{
    unsigned short port;
    SOCKET l, c, a;
    test_basics();
    test_tcp_echo();
    test_tcp_bulk();
    test_tcp_duplex();
    test_half_close_and_reset();
    test_refused_and_timeout();
    test_nonblocking_select_poll();
    test_send_buffer_fill();
    test_udp();
    test_options_and_binding();
    test_many_sockets();
    test_close_while_blocked();
    test_events();
    test_names();
    test_no_leaks();
    CHECK(WSACleanup() == 0, "WSACleanup balances the one successful WSAStartup");
    CHECK(WSACleanup() == SOCKET_ERROR && WSAGetLastError() == WSANOTINITIALISED, "an extra WSACleanup fails with WSANOTINITIALISED");
    WSAStartup(MAKEWORD(2, 2), &(WSADATA){0});
    /* Two threads stay blocked in the kernel (accept, recv) while the process exits: termination must interrupt them. */
    l = make_listener(&port, 1);
    c = tcp_connect_lo(port);
    a = accept(l, 0, 0);
    CreateThread(0, 0, parked_thread, (LPVOID)c, 0, 0);
    { SOCKET l2 = make_listener(&port, 1); struct srv *dummy = xmalloc(sizeof *dummy); memset(dummy, 0, sizeof *dummy); dummy->ls = l2; dummy->mode = M_ECHO; CreateThread(0, 0, server_thread, dummy, 0, 0); }
    Sleep(100);
    printf("%s: %d check(s) failed; exiting with two threads blocked in accept()/recv()\n", g_bad ? "FAIL" : "PASS", g_bad);
    (void)a;
    return g_bad ? 1 : 0;
}
