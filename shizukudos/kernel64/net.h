/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 network stack: declarations shared by net_core.c (Ethernet/ARP/IPv4/ICMP, threads, buffers),
 * net_udp.c, net_tcp.c, net_dhcp.c, net_dns.c, net_sock.c (kernel sockets + syscalls 0x80-0x8f) and the NIC driver
 * net_rtl8139.c.
 *
 * Scope and limits (documented once, here):
 *  - IPv4 only. No IPv6, no IP options on transmit, no multicast/IGMP, no source routing, no VLAN.
 *  - One Ethernet interface (RTL8139) plus a software loopback (127.0.0.0/8 and our own address). The NIC and DHCP exist
 *    only in the SHZ_STANDALONE profile (QEMU, no Supervisor): under the Supervisor no device is passed through, so the
 *    stack there runs loopback-only and every operation that needs the wire fails with an honest network error.
 *  - TCP: RFC 793 state machine with RFC 5961 challenge ACKs, RFC 6298 retransmission timer with exponential backoff,
 *    RFC 5681 slow start / congestion avoidance / fast retransmit + NewReno recovery, MSS option, Nagle, zero-window
 *    probes, keep-alive, TIME_WAIT. NOT implemented: window scaling (the receive window is at most 65535), SACK,
 *    timestamps, ECN and urgent data. Out-of-order segments are held (bounded by the receive window) and answered with a
 *    duplicate ACK; when the hole fills, one cumulative ACK covers everything (no SACK blocks are generated).
 *  - IPv4 receive reassembles fragments (RFC 815 hole bitmap, 30 s timeout, at most 4 datagrams in flight); transmit
 *    fragments datagrams larger than the MTU unless DF is set.
 *  - Every stack operation runs under the single net lock (net_lock/net_unlock). The NIC interrupt handler only
 *    acknowledges the device and posts a semaphore; frames are processed by the "net" kernel thread.
 */
#ifndef K64_NET_H
#define K64_NET_H
#include "proc_internal.h"

typedef uint32_t ip4_t;                         /* host byte order: 10.0.2.15 == 0x0a00020f */

static inline uint16_t bs16(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint32_t bs32(uint32_t v) { return __builtin_bswap32(v); }
static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }
#define IP4(a, b, c, d) ((ip4_t)(((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d)))

/* ---- errors: NTSTATUS in the customer range, low 16 bits = the Winsock error code (ws2_32.dll maps back) ---- */
#define NET_ERR(w) ((int32_t)(0xE0A00000u | (uint32_t)(w)))
enum {
    WSAEINTR = 10004, WSAEACCES = 10013, WSAEFAULT = 10014, WSAEINVAL = 10022, WSAEMFILE = 10024,
    WSAEWOULDBLOCK = 10035, WSAEINPROGRESS = 10036, WSAEALREADY = 10037, WSAENOTSOCK = 10038, WSAEDESTADDRREQ = 10039,
    WSAEMSGSIZE = 10040, WSAEPROTOTYPE = 10041, WSAENOPROTOOPT = 10042, WSAEPROTONOSUPPORT = 10043,
    WSAESOCKTNOSUPPORT = 10044, WSAEOPNOTSUPP = 10045, WSAEAFNOSUPPORT = 10047, WSAEADDRINUSE = 10048,
    WSAEADDRNOTAVAIL = 10049, WSAENETDOWN = 10050, WSAENETUNREACH = 10051, WSAECONNABORTED = 10053,
    WSAECONNRESET = 10054, WSAENOBUFS = 10055, WSAEISCONN = 10056, WSAENOTCONN = 10057, WSAESHUTDOWN = 10058,
    WSAETIMEDOUT = 10060, WSAECONNREFUSED = 10061, WSAEHOSTUNREACH = 10065,
    WSAHOST_NOT_FOUND = 11001, WSATRY_AGAIN = 11002, WSANO_RECOVERY = 11003, WSANO_DATA = 11004
};

/* ---- configuration and counters ---- */
enum { DHCP_OFF = 0, DHCP_INIT, DHCP_SELECTING, DHCP_REQUESTING, DHCP_BOUND, DHCP_RENEWING, DHCP_REBINDING };
typedef struct {
    int stack_up;                               /* net thread running */
    int nic_present, link_up;
    ip4_t ip, mask, gw, dns[2], dhcp_server;    /* ip == 0: not configured */
    uint8_t mac[6];
    uint32_t lease_secs;
    uint64_t lease_start_ms, t1_ms, t2_ms;      /* absolute deadlines (ticks_now units) of renew / rebind / expiry via lease_secs */
    int dhcp_state;
} net_cfg_t;
extern net_cfg_t g_net;

enum {
    NS_ETH_RX, NS_ETH_TX, NS_ETH_RX_DROP, NS_ARP_REQ_TX, NS_ARP_REP_RX, NS_ARP_REQ_RX, NS_ARP_REP_TX,
    NS_IP_RX, NS_IP_TX, NS_IP_BAD_CSUM, NS_IP_REASM, NS_IP_FRAG_TX,
    NS_ICMP_ECHO_RX, NS_ICMP_ECHO_TX, NS_ICMP_REPLY_RX, NS_ICMP_UNREACH_TX,
    NS_UDP_RX, NS_UDP_TX, NS_UDP_BAD_CSUM,
    NS_TCP_RX, NS_TCP_TX, NS_TCP_BAD_CSUM, NS_TCP_RETRANS, NS_TCP_FAST_RETRANS, NS_TCP_RST_TX, NS_TCP_RST_RX,
    NS_TCP_OOO, NS_TCP_DUPACK_TX, NS_TCP_PERSIST, NS_TCP_KEEPALIVE_TX,
    NS_DNS_QUERY, NS_DNS_CACHE_HIT, NS_DHCP_TX, NS_DHCP_RX, NS_LO_PKTS,
    NS_COUNT
};
extern uint32_t g_nstat[NS_COUNT];
#define NSTAT(i) (++g_nstat[i])

/* ---- locking, waiting ---- */
void net_lock(void);
void net_unlock(void);                          /* also delivers queued loopback packets before releasing */
int net_lock_held(void);
/* Sleeps at most `ms` (<= 50) with the lock released; returns with the lock held. Woken early by net_wake_all(). */
void net_sleep(uint32_t ms);
void net_wake_all(void);
int net_current_terminating(void);              /* the calling user thread's process is being terminated */
/* Lazily starts the stack (net thread, NIC probe + DHCP in the standalone profile). Call WITHOUT the lock held. */
int net_ensure_init(void);
uint32_t net_rand32(void);
uint64_t net_now(void);                         /* milliseconds (kernel tick) */

/* ---- checksums ---- */
uint32_t csum_add(uint32_t sum, const void *data, uint32_t len);
uint16_t csum_fold(uint32_t sum);
uint32_t csum_pseudo(ip4_t src, ip4_t dst, uint8_t proto, uint32_t len);

/* ---- paged byte queue (socket buffers). Data lives in 4 KiB pages taken from the page allocator, freed as drained. ---- */
#define BQ_DATA 4080u
typedef struct bchunk { struct bchunk *next; uint64_t pad; } bchunk_t;
typedef struct { bchunk_t *head, *tail; uint32_t hoff, toff, len, limit; } bq_t;
uint32_t bq_space(const bq_t *q);
uint32_t bq_write(bq_t *q, const void *src, uint32_t n);                            /* returns bytes stored */
int32_t bq_write_user(bq_t *q, process_t *p, uint64_t uva, uint32_t n, uint32_t *done);
void bq_peek(const bq_t *q, uint32_t off, void *dst, uint32_t n);                   /* off + n <= len */
int32_t bq_read_user(bq_t *q, process_t *p, uint64_t uva, uint32_t n, int consume); /* copies n bytes (n <= len) */
void bq_drop(bq_t *q, uint32_t n);
void bq_free(bq_t *q);

/* ---- NIC driver interface (net_rtl8139.c) ---- */
int nic_probe_init(uint8_t mac[6]);             /* 0 = found, initialised, IRQ armed */
int nic_send(const uint8_t *frame, uint32_t len);
int nic_link_up(void);
/* Drains the receive ring, calling `cb` per frame (valid only during the call). Returns frames delivered. */
unsigned nic_rx_drain(void (*cb)(const uint8_t *frame, uint32_t len));
extern ksem_t g_nic_kick;                       /* posted by the interrupt handler */
uint32_t nic_stat(unsigned which);              /* 0 rx frames, 1 tx frames, 2 rx overflow, 3 rx errors, 4 tx dropped, 5 irqs */

/* ---- Ethernet / ARP / IPv4 (net_core.c) ---- */
#define ETH_HLEN 14
#define IP_HLEN 20
#define NET_MTU 1500
#define LO_MTU 16384
#define IPPROTO_ICMP_ 1
#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17
/* Sends one IPv4 datagram. src == 0: chosen by routing. May fragment (unless df). Async ARP: the packet is queued while
 * the next hop resolves. Returns 0 or a NET_ERR(). Must hold the lock. */
int32_t ip_output(uint8_t proto, ip4_t src, ip4_t dst, const uint8_t *payload, uint32_t len, int df);
/* Same with the source fixed and no route lookup for unconfigured hosts: limited broadcast on the wire (DHCP). */
int32_t ip_output_broadcast(uint8_t proto, ip4_t src, const uint8_t *payload, uint32_t len);
int32_t ip_route_src(ip4_t dst, ip4_t *src, uint32_t *mtu);     /* source address and MTU the stack would use */
int ip_is_local(ip4_t a);                       /* 127/8, our address, 0.0.0.0 excluded */
int ip_is_broadcast(ip4_t a);
void arp_learn(ip4_t ip, const uint8_t mac[6]);
int32_t net_ping(ip4_t dst, uint16_t id, uint16_t seq, uint32_t payload_len, uint32_t timeout_ms, uint32_t *rtt_ms);
void icmp_send_unreach(ip4_t to, uint8_t code, const uint8_t *orig_ip_packet, uint32_t orig_len);
ip4_t net_nexthop(ip4_t dst);                   /* next hop the stack would use, 0 if unroutable */
void tcp_host_unreachable(ip4_t nexthop);       /* ARP failed for nexthop: abort connections waiting on it */
#define NET_L4_MAX 65536
extern uint8_t g_l4[];                          /* NET_L4_MAX + 128 bytes: transport composition buffer (lock held) */
void net_timers(uint64_t now);                  /* called every ~10 ms by the net thread (lock held) */
void net_dhcp_apply(ip4_t ip, ip4_t mask, ip4_t gw, ip4_t dns0, ip4_t dns1, ip4_t server, uint32_t lease);
void net_deconfigure(void);
void net_arp_flush(void);                       /* forget every neighbour (test hook, control op 3) */

/* ---- UDP (net_udp.c) ---- */
struct sock;
void udp_input(ip4_t src, ip4_t dst, const uint8_t *seg, uint32_t len, const uint8_t *ip_packet, uint32_t ip_len);
int32_t udp_send(struct sock *s, ip4_t dip, uint16_t dport, const uint8_t *data, uint32_t len, ip4_t src_override);
int32_t udp_send_raw(ip4_t src, ip4_t dst, uint16_t sport, uint16_t dport, const uint8_t *data, uint32_t len, int limited_broadcast);
void udp_icmp_error(const uint8_t *orig_ip, uint32_t len, int32_t err);

/* ---- DHCP / DNS ---- */
void dhcp_start(void);                          /* begins DISCOVER (lock held) */
void dhcp_timer(uint64_t now);
int dhcp_input(ip4_t src, const uint8_t *data, uint32_t len);     /* UDP payload to port 68; returns 1 if consumed */
void dhcp_renew_now(void);                      /* test hook: force the RENEWING transition */
/* Resolves `name` (A records only) with the configured DNS server or `server`:`port` if server != 0. Lock NOT held. */
int32_t dns_resolve(const char *name, ip4_t *out, unsigned max, unsigned *count, ip4_t server, uint16_t port);
void dns_flush_cache(void);

/* ---- sockets ---- */
enum { SK_STREAM = 1, SK_DGRAM = 2 };
enum { EV_READ = 1, EV_WRITE = 2, EV_OOB = 4, EV_ACCEPT = 8, EV_CONNECT = 16, EV_CLOSE = 32 };    /* FD_* */

typedef struct dgram {
    struct dgram *next;
    ip4_t src;
    uint16_t sport, len;
    uint8_t data[];
} dgram_t;

struct tcb;
typedef struct sock {
    struct sock *next;                          /* g_socks list */
    int type;                                   /* SK_STREAM / SK_DGRAM */
    int refs;                                   /* 1 while the handle exists + in-flight syscalls */
    int dead;                                   /* last handle closed */
    int bound;
    ip4_t lip, rip;                             /* 0 = any / unconnected */
    uint16_t lport, rport;
    uint32_t nonblock : 1, reuse : 1, broadcast : 1, keepalive : 1, nodelay : 1, linger_on : 1, listening : 1,
             connected : 1, kernel_owned : 1, shut_rd : 1, noconnreset : 1, connecting : 1, want_write : 1,
             close_reported : 1, exclusive : 1;
    uint32_t linger_secs;
    uint32_t ka_idle_s, ka_intvl_s, ka_cnt;     /* TCP_KEEPIDLE / TCP_KEEPINTVL / TCP_KEEPCNT, 0 = default (7200 s, 1 s, 10) */
    uint32_t rcvtimeo, sndtimeo;                /* ms, 0 = infinite */
    uint32_t rcvbuf, sndbuf;
    int32_t err;                                /* pending asynchronous error (SO_ERROR), 0 = none */
    dgram_t *dq_head, *dq_tail;                 /* datagram receive queue */
    uint32_t dq_bytes, dq_count;
    struct tcb *tcb;                            /* stream socket transport */
    struct tcb *acc_head, *acc_tail;            /* completed connections waiting for accept() */
    uint32_t acc_count, backlog;
    kobject_t *evt;                             /* WSAEventSelect event object (referenced) */
    uint32_t evt_mask, evt_pending;
    int32_t evt_err[6];
} sock_t;
extern sock_t *g_socks;

sock_t *sock_new(int type, int kernel_owned);
void sock_close_kernel(sock_t *s);              /* lock held */
void sock_release(sock_t *s);                   /* drops one ref; frees when dead and unreferenced (lock held) */
void sock_notify(sock_t *s);                    /* state changed: wake sleepers, signal WSAEventSelect event */
int sock_port_in_use(int type, ip4_t lip, uint16_t lport, const sock_t *except, int reuse);
uint16_t sock_alloc_port(int type);
uint32_t sock_poll_mask(sock_t *s);             /* Winsock POLL* mask */
/* Kernel-side datagram helpers (DNS resolver): lock held; block via net_sleep. */
int32_t ksock_recvfrom(sock_t *s, uint8_t *buf, uint32_t cap, uint32_t *got, ip4_t *from, uint16_t *fport, uint32_t timeout_ms);

/* ---- TCP (net_tcp.c) ---- */
enum { TCPS_CLOSED = 0, TCPS_LISTEN, TCPS_SYN_SENT, TCPS_SYN_RCVD, TCPS_ESTABLISHED, TCPS_FIN_WAIT_1, TCPS_FIN_WAIT_2, TCPS_CLOSE_WAIT,
       TCPS_CLOSING, TCPS_LAST_ACK, TCPS_TIME_WAIT };
struct tcp_ooo;
typedef struct tcb {
    struct tcb *next;                           /* g_tcbs */
    struct tcb *acc_next;                       /* accept queue link */
    sock_t *sock;                               /* owner; NULL once the application closed the socket (orphan) */
    sock_t *parent;                             /* listener that spawned this connection while it is unaccepted */
    uint8_t state;
    uint8_t fin_queued, fin_sent, fin_acked, rcvd_fin, ack_now, ack_pending, in_recovery, rtt_timing, passive;
    uint8_t shut_rd, timed_out, queued, was_est;  /* queued: sits in its listener's accept queue; was_est: reached ESTABLISHED */
    ip4_t lip, rip;
    uint16_t lport, rport;
    uint32_t iss, irs;
    uint32_t snd_una, snd_nxt, snd_max, snd_wnd, snd_wl1, snd_wl2, snd_max_wnd;
    uint32_t rcv_nxt, rcv_adv;
    uint32_t mss;                               /* effective send MSS */
    uint32_t cwnd, ssthresh, recover, dupacks;
    uint32_t srtt, rttvar, rto;                 /* ms; srtt/rttvar scaled by 8 / 4 as in BSD: srtt<<3, rttvar<<2 */
    uint32_t rtt_seq;
    uint64_t rtt_start;
    uint64_t rtx_deadline, persist_deadline, tw_deadline, ack_deadline, ka_deadline, last_rx;
    uint32_t rtx_count, persist_shift, ka_probes, rx_unacked;
    bq_t sndq, rcvq;
    struct tcp_ooo *ooo;                        /* out-of-order segments beyond a hole, sorted by sequence */
    uint32_t ooo_bytes;
    int32_t err;                                /* NET_ERR() reported to the application (sticky) */
} tcb_t;
extern tcb_t *g_tcbs;

tcb_t *tcp_connect(sock_t *s, ip4_t dst, uint16_t dport, int32_t *err);
int32_t tcp_listen(sock_t *s, uint32_t backlog);
tcb_t *tcp_accept_dequeue(sock_t *l);
void tcp_output(tcb_t *t);
void tcp_after_read(tcb_t *t);                  /* application consumed data: maybe send a window update */
void tcp_shutdown_write(tcb_t *t);
void tcp_keepalive_changed(tcb_t *t);
void tcp_abort(tcb_t *t, int send_rst);         /* RST + CLOSED */
void tcp_sock_closed(sock_t *s);                /* application closed: orphan or reset */
void tcp_input(ip4_t src, ip4_t dst, const uint8_t *seg, uint32_t len);
void tcp_timers(uint64_t now);
void tcp_flush_acks(void);
int tcp_can_write(const tcb_t *t);
uint32_t tcp_state_count(int state);
unsigned tcp_dump(uint8_t *out, unsigned max_entries);

/* ---- syscall front end ---- */
int32_t sys_ext_net(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
void net_socket_handle_closing(kobject_t *o);  /* objects.c handle_close hook for OB_SOCKET */

/* ---- ABI structures shared with ws2_32.dll (layout = Windows x64) ---- */
struct shz_sockaddr_in { uint16_t family; uint16_t port_be; uint32_t addr_be; uint8_t zero[8]; };
struct shz_pollent { uint64_t handle; int16_t events; int16_t revents; uint32_t pad; };
#define SHZ_AF_INET 2
#define POLLRDNORM 0x0100
#define POLLRDBAND 0x0200
#define POLLIN (POLLRDNORM | POLLRDBAND)
#define POLLPRI 0x0400
#define POLLWRNORM 0x0010
#define POLLOUT POLLWRNORM
#define POLLWRBAND 0x0020
#define POLLERR 0x0001
#define POLLHUP 0x0002
#define POLLNVAL 0x0004

/* NtShzNetQuery classes */
struct shz_net_info {
    uint32_t flags;                             /* bit0 NIC present, bit1 link up, bit2 configured, bit3 DHCP bound */
    uint32_t ip_be, mask_be, gw_be, dns0_be, dns1_be, dhcp_server_be;
    uint8_t mac[6];
    uint16_t pad;
    uint32_t lease_secs, lease_remaining_secs, dhcp_state;
};
struct shz_tcp_row { uint32_t lip_be, rip_be; uint16_t lport, rport; uint32_t state; uint32_t snd_una, snd_nxt, rcv_nxt, cwnd, rto; };
#endif
