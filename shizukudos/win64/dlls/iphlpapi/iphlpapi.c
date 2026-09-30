/* SPDX-License-Identifier: GPL-2.0-only
 * iphlpapi.dll - IP Helper over the Kernel64 network stack (kernel64/net_*.c, queried through NtShzNetQuery).
 *
 * The stack has exactly two interfaces, which every table here describes with Windows' own vocabulary:
 *   index 1  "Loopback Pseudo-Interface 1"   IF_TYPE_SOFTWARE_LOOPBACK, 127.0.0.1/8, always up, MTU 0xffffffff
 *   index 2  "Ethernet"                       IF_TYPE_ETHERNET_CSMACD, the RTL8139 (present only when the machine has
 *                                             one: NtShzNetQuery(0) flag bit 0), its MAC, the DHCP-assigned IPv4 address,
 *                                             mask, gateway and DNS servers; OperStatus follows the link (flag bit 1)
 * NET_LUIDs carry the interface type and NetLuidIndex 0 (loopback) / 1 (Ethernet), so the names ConvertInterfaceLuidToName*
 * produce are "loopback_0" and "ethernet_1", the form Windows uses. Interface GUIDs are fixed for the loopback and
 * derived from the MAC for the Ethernet adapter, so they are stable across boots of one machine.
 *
 * Buffer protocol of the legacy calls (GetAdaptersAddresses, GetAdaptersInfo, GetNetworkParams, GetInterfaceInfo,
 * GetIfTable, GetIpAddrTable, GetIpForwardTable, GetTcpTable): the documented "size in/out" contract, the error code for a
 * short buffer being the one each function documents (ERROR_BUFFER_OVERFLOW / ERROR_INSUFFICIENT_BUFFER). The
 * netioapi calls (GetIfTable2, GetUnicastIpAddressTable, GetIpInterfaceTable) allocate from the process heap and
 * FreeMibTable frees.
 *
 * Change notification: the kernel has no address-change event, so this DLL polls NtShzNetQuery(0) every 500 ms from one
 * watcher thread while any registration exists and compares link state, address, mask, gateway and DNS servers.
 * NotifyAddrChange / NotifyRouteChange complete the OVERLAPPED (STATUS_SUCCESS, event set) - or, without an OVERLAPPED,
 * block until a change - and CancelIPChangeNotify completes it with STATUS_CANCELLED. NotifyIpInterfaceChange,
 * NotifyUnicastIpAddressChange and NotifyRouteChange2 call back from the watcher thread (MibInitialNotification first
 * when asked); CancelMibChangeNotify2 returns only after a running callback has finished, as documented.
 *
 * IpRenewAddress asks the kernel to renew the DHCP lease now (NtShzNetQuery(3) control 1). IpReleaseAddress fails with
 * ERROR_NOT_SUPPORTED: the kernel offers no release operation (the interface would keep its address), and nothing is
 * pretended. Statistics (GetIpStatistics, GetTcpStatistics, GetUdpStatistics, the MIB_IF_ROW2 packet counters) come
 * from the kernel's stack counters (NtShzNetQuery(1)); octet counters the kernel does not keep are reported as 0.
 * Not provided: IPv6 rows (the stack is IPv4 only; IPv6 families yield adapters without addresses / ERROR_NOT_FOUND),
 * the ARP/neighbour, path and routing-protocol tables, SendARP, GetExtendedTcpTable owner-PID classes (the kernel does
 * not record the owning process of a connection).
 */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string.h>

#ifndef DLLAPI
#define DLLAPI __declspec(dllexport)
#endif

typedef LONG NTSTATUS;
NTSTATUS __stdcall NtShzNetQuery(ULONG_PTR cls, void *buf, ULONG_PTR len, PULONG ret);

/* NtShzNetQuery(0), kernel64/net.h struct shz_net_info */
struct shz_net_info {
    ULONG flags;                             /* bit0 NIC present, bit1 link up, bit2 configured, bit3 DHCP bound */
    ULONG ip_be, mask_be, gw_be, dns0_be, dns1_be, dhcp_server_be;
    BYTE mac[6];
    USHORT pad;
    ULONG lease_secs, lease_remaining_secs, dhcp_state;
};
struct shz_tcp_row { ULONG lip_be, rip_be; USHORT lport, rport; ULONG state; ULONG snd_una, snd_nxt, rcv_nxt, cwnd, rto; };
/* NtShzNetQuery(1): stack counters (kernel64/net.h NS_*), then 6 NIC counters */
enum { NST_ETH_RX, NST_ETH_TX, NST_ETH_RX_DROP, NST_ARP_REQ_TX, NST_ARP_REP_RX, NST_ARP_REQ_RX, NST_ARP_REP_TX, NST_IP_RX,
       NST_IP_TX, NST_IP_BAD_CSUM, NST_IP_REASM, NST_IP_FRAG_TX, NST_ICMP_ECHO_RX, NST_ICMP_ECHO_TX, NST_ICMP_REPLY_RX,
       NST_ICMP_UNREACH_TX, NST_UDP_RX, NST_UDP_TX, NST_UDP_BAD_CSUM, NST_TCP_RX, NST_TCP_TX, NST_TCP_BAD_CSUM, NST_TCP_RETRANS,
       NST_TCP_FAST_RETRANS, NST_TCP_RST_TX, NST_TCP_RST_RX, NST_TCP_OOO, NST_TCP_DUPACK_TX, NST_TCP_PERSIST,
       NST_TCP_KEEPALIVE_TX, NST_DNS_QUERY, NST_DNS_CACHE_HIT, NST_DHCP_TX, NST_DHCP_RX, NST_LO_PKTS, NST_COUNT };

#define STATUS_CANCELLED_ ((LONG)0xC0000120)
#define LOOPBACK_INDEX 1
#define ETHERNET_INDEX 2
#define MAX_IFACES 2

static const GUID LOOPBACK_GUID = { 0x5a2f1c60, 0x0001, 0x4c6f, { 0x8f, 0x6b, 0x53, 0x48, 0x5a, 0x4c, 0x4f, 0x30 } };
static const WCHAR LOOPBACK_ALIAS[] = L"Loopback Pseudo-Interface 1";
static const WCHAR LOOPBACK_DESC[] = L"Software Loopback Interface 1";
static const WCHAR ETHERNET_ALIAS[] = L"Ethernet";
static const WCHAR ETHERNET_DESC[] = L"Realtek RTL8139 Fast Ethernet Adapter (ShizukuDOS Kernel64 driver)";

/* one interface as the tables see it */
typedef struct iface {
    ULONG index;
    NET_LUID luid;
    GUID guid;
    IFTYPE type;
    const WCHAR *alias, *desc;
    ULONG mtu;
    BYTE mac[6];
    ULONG maclen;
    int up, has_addr, dhcp;
    ULONG ip_be, mask_be, gw_be, dns_be[2], dhcp_server_be;
    ULONG lease_secs, lease_remaining;
    ULONG64 speed;
} iface;

static ULONG bs32(ULONG v) { return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24); }

static int query_info(struct shz_net_info *in)
{
    ULONG ret = 0;
    memset(in, 0, sizeof *in);
    return NtShzNetQuery(0, in, sizeof *in, &ret) == 0 && ret == sizeof *in;
}

static int query_stats(ULONG st[NST_COUNT + 6])
{
    ULONG ret = 0;
    memset(st, 0, (NST_COUNT + 6) * sizeof(ULONG));
    return NtShzNetQuery(1, st, (NST_COUNT + 6) * sizeof(ULONG), &ret) == 0;
}

static void make_luid(NET_LUID *l, IFTYPE type, ULONG luid_index)
{
    l->Value = 0;
    l->Info.IfType = type;
    l->Info.NetLuidIndex = luid_index;
}

/* Reads the kernel state into the interface list; returns the number of interfaces (1 without a NIC, else 2). */
static unsigned enum_ifaces(iface *v)
{
    struct shz_net_info in;
    unsigned n = 0;
    memset(v, 0, sizeof(iface) * MAX_IFACES);
    v[n].index = LOOPBACK_INDEX;
    make_luid(&v[n].luid, IF_TYPE_SOFTWARE_LOOPBACK, 0);
    v[n].guid = LOOPBACK_GUID;
    v[n].type = IF_TYPE_SOFTWARE_LOOPBACK;
    v[n].alias = LOOPBACK_ALIAS;
    v[n].desc = LOOPBACK_DESC;
    v[n].mtu = 0xffffffffu;
    v[n].up = 1;
    v[n].has_addr = 1;
    v[n].ip_be = bs32(0x7f000001u);
    v[n].mask_be = bs32(0xff000000u);
    v[n].speed = 1073741824ull;
    ++n;
    if (query_info(&in) && (in.flags & 1)) {
        iface *e = &v[n];
        e->index = ETHERNET_INDEX;
        make_luid(&e->luid, IF_TYPE_ETHERNET_CSMACD, 1);
        e->guid.Data1 = 0x5a2f1c60u ^ ((ULONG)in.mac[0] << 24 | (ULONG)in.mac[1] << 16 | (ULONG)in.mac[2] << 8 | in.mac[3]);
        e->guid.Data2 = 0x0002;
        e->guid.Data3 = 0x4c6f;
        e->guid.Data4[0] = 0x8f; e->guid.Data4[1] = 0x6b;
        memcpy(e->guid.Data4 + 2, in.mac, 6);
        e->type = IF_TYPE_ETHERNET_CSMACD;
        e->alias = ETHERNET_ALIAS;
        e->desc = ETHERNET_DESC;
        e->mtu = 1500;
        memcpy(e->mac, in.mac, 6);
        e->maclen = 6;
        e->up = (in.flags & 2) != 0;
        e->has_addr = (in.flags & 4) != 0 && in.ip_be != 0;
        e->dhcp = (in.flags & 8) != 0;
        e->ip_be = in.ip_be; e->mask_be = in.mask_be; e->gw_be = in.gw_be;
        e->dns_be[0] = in.dns0_be; e->dns_be[1] = in.dns1_be;
        e->dhcp_server_be = in.dhcp_server_be;
        e->lease_secs = in.lease_secs; e->lease_remaining = in.lease_remaining_secs;
        e->speed = 100000000ull;
        ++n;
    }
    return n;
}

static const iface *find_index(const iface *v, unsigned n, ULONG index)
{
    unsigned i;
    for (i = 0; i < n; ++i) if (v[i].index == index) return &v[i];
    return 0;
}

static const iface *find_luid(const iface *v, unsigned n, const NET_LUID *luid)
{
    unsigned i;
    for (i = 0; i < n; ++i) if (v[i].luid.Value == luid->Value) return &v[i];
    return 0;
}

static unsigned mask_bits(ULONG mask_be)
{
    ULONG m = bs32(mask_be);
    unsigned n = 0;
    while (m & 0x80000000u) { ++n; m <<= 1; }
    return n;
}

static size_t wlen(const WCHAR *s) { size_t n = 0; while (s[n]) ++n; return n; }
static size_t alen(const char *s) { size_t n = 0; while (s[n]) ++n; return n; }

static char *hex2(char *p, unsigned v) { static const char h[] = "0123456789ABCDEF"; *p++ = h[v >> 4 & 15]; *p++ = h[v & 15]; return p; }

/* "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}" (38 chars + NUL) */
static void guid_text(const GUID *g, char *out)
{
    char *p = out;
    unsigned i;
    *p++ = '{';
    p = hex2(p, g->Data1 >> 24); p = hex2(p, g->Data1 >> 16 & 255); p = hex2(p, g->Data1 >> 8 & 255); p = hex2(p, g->Data1 & 255);
    *p++ = '-';
    p = hex2(p, g->Data2 >> 8); p = hex2(p, g->Data2 & 255);
    *p++ = '-';
    p = hex2(p, g->Data3 >> 8); p = hex2(p, g->Data3 & 255);
    *p++ = '-';
    p = hex2(p, g->Data4[0]); p = hex2(p, g->Data4[1]);
    *p++ = '-';
    for (i = 2; i < 8; ++i) p = hex2(p, g->Data4[i]);
    *p++ = '}';
    *p = 0;
}

static int hexval(WCHAR c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int guid_parse(const WCHAR *s, GUID *g)
{
    static const int groups[] = { 8, 4, 4, 4, 12 };
    BYTE raw[16];
    unsigned gi, k = 0;
    if (*s == '{') ++s;
    for (gi = 0; gi < 5; ++gi) {
        int i;
        if (gi) { if (*s != '-') return 0; ++s; }
        for (i = 0; i < groups[gi]; i += 2) {
            int a = hexval(s[0]), b = hexval(s[1]);
            if (a < 0 || b < 0) return 0;
            raw[k++] = (BYTE)(a << 4 | b);
            s += 2;
        }
    }
    if (*s == '}') ++s;
    if (*s) return 0;
    g->Data1 = (ULONG)raw[0] << 24 | (ULONG)raw[1] << 16 | (ULONG)raw[2] << 8 | raw[3];
    g->Data2 = (USHORT)(raw[4] << 8 | raw[5]);
    g->Data3 = (USHORT)(raw[6] << 8 | raw[7]);
    memcpy(g->Data4, raw + 8, 8);
    return 1;
}

static void ip_text(ULONG be, char *out)         /* dotted decimal into a 16-byte buffer */
{
    const BYTE *b = (const BYTE *)&be;
    unsigned i;
    char *p = out;
    for (i = 0; i < 4; ++i) {
        unsigned v = b[i];
        if (i) *p++ = '.';
        if (v >= 100) *p++ = (char)('0' + v / 100);
        if (v >= 10) *p++ = (char)('0' + v / 10 % 10);
        *p++ = (char)('0' + v % 10);
    }
    *p = 0;
}

static void set_in4(SOCKADDR_INET *a, ULONG be)
{
    memset(a, 0, sizeof *a);
    a->Ipv4.sin_family = AF_INET;
    a->Ipv4.sin_addr.s_addr = be;
}

static ULONG64 unix_now(void)
{
    FILETIME ft;
    ULONG64 t;
    GetSystemTimeAsFileTime(&ft);
    t = (ULONG64)ft.dwHighDateTime << 32 | ft.dwLowDateTime;
    return (t - 116444736000000000ull) / 10000000ull;
}

/* ================================================================ interface identity */
DLLAPI NETIO_STATUS WINAPI ConvertInterfaceIndexToLuid(NET_IFINDEX index, PNET_LUID luid)
{
    iface v[MAX_IFACES];
    const iface *f;
    if (!luid) return ERROR_INVALID_PARAMETER;
    luid->Value = 0;
    f = find_index(v, enum_ifaces(v), index);
    if (!f) return ERROR_FILE_NOT_FOUND;
    *luid = f->luid;
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceLuidToIndex(const NET_LUID *luid, PNET_IFINDEX index)
{
    iface v[MAX_IFACES];
    const iface *f;
    if (!luid || !index) return ERROR_INVALID_PARAMETER;
    *index = 0;
    f = find_luid(v, enum_ifaces(v), luid);
    if (!f) return ERROR_FILE_NOT_FOUND;
    *index = f->index;
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceLuidToGuid(const NET_LUID *luid, GUID *guid)
{
    iface v[MAX_IFACES];
    const iface *f;
    if (!luid || !guid) return ERROR_INVALID_PARAMETER;
    memset(guid, 0, sizeof *guid);
    f = find_luid(v, enum_ifaces(v), luid);
    if (!f) return ERROR_FILE_NOT_FOUND;
    *guid = f->guid;
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceGuidToLuid(const GUID *guid, PNET_LUID luid)
{
    iface v[MAX_IFACES];
    unsigned i, n;
    if (!guid || !luid) return ERROR_INVALID_PARAMETER;
    luid->Value = 0;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i)
        if (!memcmp(&v[i].guid, guid, sizeof(GUID))) { *luid = v[i].luid; return NO_ERROR; }
    return ERROR_FILE_NOT_FOUND;
}

/* Windows names an interface "<type prefix>_<NetLuidIndex>" */
static const char *luid_prefix(ULONG type)
{
    switch (type) {
    case IF_TYPE_ETHERNET_CSMACD: return "ethernet";
    case IF_TYPE_SOFTWARE_LOOPBACK: return "loopback";
    case IF_TYPE_IEEE80211: return "wireless";
    case IF_TYPE_PPP: return "ppp";
    case IF_TYPE_TUNNEL: return "tunnel";
    case IF_TYPE_ISO88025_TOKENRING: return "tokenring";
    case IF_TYPE_ATM: return "atm";
    case IF_TYPE_IEEE1394: return "firewire";
    default: return "iftype";
    }
}

static void luid_name(const NET_LUID *luid, char *out, size_t cap)      /* cap >= 32 */
{
    const char *pre = luid_prefix(luid->Info.IfType);
    ULONG64 idx = luid->Info.NetLuidIndex;
    char digits[24];
    size_t n = alen(pre), d = 0, i;
    if (n + 22 > cap) { out[0] = 0; return; }
    memcpy(out, pre, n);
    out[n++] = '_';
    do { digits[d++] = (char)('0' + idx % 10); idx /= 10; } while (idx);
    for (i = 0; i < d; ++i) out[n++] = digits[d - 1 - i];
    out[n] = 0;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceLuidToNameA(const NET_LUID *luid, char *name, SIZE_T len)
{
    char tmp[64];
    size_t n;
    if (!luid || !name) return ERROR_INVALID_PARAMETER;
    luid_name(luid, tmp, sizeof tmp);
    n = alen(tmp);
    if (len < n + 1) return ERROR_NOT_ENOUGH_MEMORY;
    memcpy(name, tmp, n + 1);
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceLuidToNameW(const NET_LUID *luid, WCHAR *name, SIZE_T len)
{
    char tmp[64];
    size_t n, i;
    if (!luid || !name) return ERROR_INVALID_PARAMETER;
    luid_name(luid, tmp, sizeof tmp);
    n = alen(tmp);
    if (len < n + 1) return ERROR_NOT_ENOUGH_MEMORY;
    for (i = 0; i <= n; ++i) name[i] = (WCHAR)(unsigned char)tmp[i];
    return NO_ERROR;
}

static NETIO_STATUS name_to_luid(const char *name, NET_LUID *luid)
{
    iface v[MAX_IFACES];
    unsigned i, n;
    char tmp[64];
    luid->Value = 0;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i) {
        luid_name(&v[i].luid, tmp, sizeof tmp);
        if (!strcmp(tmp, name)) { *luid = v[i].luid; return NO_ERROR; }
    }
    return ERROR_INVALID_NAME;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceNameToLuidA(const char *name, NET_LUID *luid)
{
    if (!name || !luid) return ERROR_INVALID_PARAMETER;
    return name_to_luid(name, luid);
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceNameToLuidW(const WCHAR *name, NET_LUID *luid)
{
    char tmp[64];
    size_t i;
    if (!name || !luid) return ERROR_INVALID_PARAMETER;
    for (i = 0; i < sizeof tmp - 1 && name[i]; ++i) tmp[i] = name[i] < 128 ? (char)name[i] : '?';
    tmp[i] = 0;
    return name_to_luid(tmp, luid);
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceLuidToAlias(const NET_LUID *luid, WCHAR *alias, SIZE_T len)
{
    iface v[MAX_IFACES];
    const iface *f;
    size_t n;
    if (!luid || !alias) return ERROR_INVALID_PARAMETER;
    f = find_luid(v, enum_ifaces(v), luid);
    if (!f) return ERROR_INVALID_PARAMETER;
    n = wlen(f->alias);
    if (len < n + 1) return ERROR_NOT_ENOUGH_MEMORY;
    memcpy(alias, f->alias, (n + 1) * sizeof(WCHAR));
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI ConvertInterfaceAliasToLuid(const WCHAR *alias, PNET_LUID luid)
{
    iface v[MAX_IFACES];
    unsigned i, n;
    if (!alias || !luid) return ERROR_INVALID_PARAMETER;
    luid->Value = 0;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i)
        if (!wcscmp(v[i].alias, alias)) { *luid = v[i].luid; return NO_ERROR; }
    return ERROR_INVALID_PARAMETER;
}

DLLAPI PCHAR WINAPI if_indextoname(NET_IFINDEX index, PCHAR name)
{
    NET_LUID luid;
    if (!name) return 0;
    if (ConvertInterfaceIndexToLuid(index, &luid) != NO_ERROR) return 0;
    if (ConvertInterfaceLuidToNameA(&luid, name, IF_NAMESIZE) != NO_ERROR) return 0;
    return name;
}

DLLAPI NET_IFINDEX WINAPI if_nametoindex(PCSTR name)
{
    NET_LUID luid;
    NET_IFINDEX index = 0;
    if (!name || ConvertInterfaceNameToLuidA(name, &luid) != NO_ERROR) return 0;
    if (ConvertInterfaceLuidToIndex(&luid, &index) != NO_ERROR) return 0;
    return index;
}

DLLAPI DWORD WINAPI GetNumberOfInterfaces(PDWORD count)
{
    iface v[MAX_IFACES];
    if (!count) return ERROR_INVALID_PARAMETER;
    *count = enum_ifaces(v);
    return NO_ERROR;
}

/* ================================================================ MIB_IF_ROW2 / MIB_IFROW */
static void fill_row2(const iface *f, MIB_IF_ROW2 *r)
{
    ULONG st[NST_COUNT + 6];
    memset(r, 0, sizeof *r);
    r->InterfaceLuid = f->luid;
    r->InterfaceIndex = f->index;
    r->InterfaceGuid = f->guid;
    memcpy(r->Alias, f->alias, (wlen(f->alias) + 1) * sizeof(WCHAR));
    memcpy(r->Description, f->desc, (wlen(f->desc) + 1) * sizeof(WCHAR));
    r->PhysicalAddressLength = f->maclen;
    memcpy(r->PhysicalAddress, f->mac, f->maclen);
    memcpy(r->PermanentPhysicalAddress, f->mac, f->maclen);
    r->Mtu = f->mtu;
    r->Type = f->type;
    r->TunnelType = TUNNEL_TYPE_NONE;
    r->MediaType = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? NdisMediumLoopback : NdisMedium802_3;
    r->PhysicalMediumType = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? NdisPhysicalMediumUnspecified : NdisPhysicalMedium802_3;
    r->AccessType = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? NET_IF_ACCESS_LOOPBACK : NET_IF_ACCESS_BROADCAST;
    r->DirectionType = NET_IF_DIRECTION_SENDRECEIVE;
    r->InterfaceAndOperStatusFlags.HardwareInterface = f->type != IF_TYPE_SOFTWARE_LOOPBACK;
    r->InterfaceAndOperStatusFlags.ConnectorPresent = f->type != IF_TYPE_SOFTWARE_LOOPBACK;
    r->InterfaceAndOperStatusFlags.NotMediaConnected = !f->up;
    r->OperStatus = f->up ? IfOperStatusUp : IfOperStatusDown;
    r->AdminStatus = NET_IF_ADMIN_STATUS_UP;
    r->MediaConnectState = f->up ? MediaConnectStateConnected : MediaConnectStateDisconnected;
    r->ConnectionType = NET_IF_CONNECTION_DEDICATED;
    r->TransmitLinkSpeed = r->ReceiveLinkSpeed = f->speed;
    if (query_stats(st)) {
        if (f->type == IF_TYPE_SOFTWARE_LOOPBACK) {
            r->InUcastPkts = r->OutUcastPkts = st[NST_LO_PKTS];
        } else {
            r->InUcastPkts = st[NST_ETH_RX];
            r->OutUcastPkts = st[NST_ETH_TX];
            r->InDiscards = st[NST_ETH_RX_DROP];
        }
    }
}

DLLAPI NETIO_STATUS WINAPI GetIfEntry2(PMIB_IF_ROW2 row)
{
    iface v[MAX_IFACES];
    const iface *f;
    unsigned n;
    if (!row) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    f = row->InterfaceLuid.Value ? find_luid(v, n, &row->InterfaceLuid) : find_index(v, n, row->InterfaceIndex);
    if (!f) return ERROR_FILE_NOT_FOUND;
    fill_row2(f, row);
    return NO_ERROR;
}

/* MIB_IF_ENTRY_LEVEL (netioapi.h of newer SDKs): MibIfEntryNormal = 0, MibIfEntryNormalWithoutStatistics = 2 */
DLLAPI NETIO_STATUS WINAPI GetIfEntry2Ex(int level, PMIB_IF_ROW2 row)
{
    if (level != 0 && level != 2) return ERROR_INVALID_PARAMETER;
    return GetIfEntry2(row);
}

DLLAPI NETIO_STATUS WINAPI GetIfTable2Ex(MIB_IF_TABLE_LEVEL level, PMIB_IF_TABLE2 *table)
{
    iface v[MAX_IFACES];
    unsigned n, i;
    MIB_IF_TABLE2 *t;
    if (!table) return ERROR_INVALID_PARAMETER;
    *table = 0;
    if (level != MibIfTableNormal && level != MibIfTableRaw && level != 2 /* MibIfTableNormalWithoutStatistics */) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FIELD_OFFSET(MIB_IF_TABLE2, Table) + n * sizeof(MIB_IF_ROW2));
    if (!t) return ERROR_NOT_ENOUGH_MEMORY;
    t->NumEntries = n;
    for (i = 0; i < n; ++i) fill_row2(&v[i], &t->Table[i]);
    *table = t;
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI GetIfTable2(PMIB_IF_TABLE2 *table) { return GetIfTable2Ex(MibIfTableNormal, table); }

DLLAPI void WINAPI FreeMibTable(PVOID memory)
{
    if (memory) HeapFree(GetProcessHeap(), 0, memory);
}

static void fill_ifrow(const iface *f, MIB_IFROW *r)
{
    ULONG st[NST_COUNT + 6];
    size_t n;
    char guid[40];
    size_t i;
    memset(r, 0, sizeof *r);
    r->dwIndex = f->index;
    /* wszName is the device name "\DEVICE\TCPIP_{guid}" */
    guid_text(&f->guid, guid);
    {
        static const WCHAR pre[] = L"\\DEVICE\\TCPIP_";
        size_t k = wlen(pre);
        memcpy(r->wszName, pre, k * sizeof(WCHAR));
        for (i = 0; guid[i] && k + i < MAX_INTERFACE_NAME_LEN - 1; ++i) r->wszName[k + i] = (WCHAR)(unsigned char)guid[i];
        r->wszName[k + i] = 0;
    }
    r->dwType = f->type;
    r->dwMtu = f->mtu;
    r->dwSpeed = f->speed > 0xffffffffull ? 0xffffffffu : (DWORD)f->speed;
    r->dwPhysAddrLen = f->maclen;
    memcpy(r->bPhysAddr, f->mac, f->maclen);
    r->dwAdminStatus = MIB_IF_ADMIN_STATUS_UP;
    r->dwOperStatus = f->up ? MIB_IF_OPER_STATUS_OPERATIONAL : MIB_IF_OPER_STATUS_NON_OPERATIONAL;
    if (query_stats(st)) {
        if (f->type == IF_TYPE_SOFTWARE_LOOPBACK) r->dwInUcastPkts = r->dwOutUcastPkts = st[NST_LO_PKTS];
        else { r->dwInUcastPkts = st[NST_ETH_RX]; r->dwOutUcastPkts = st[NST_ETH_TX]; r->dwInDiscards = st[NST_ETH_RX_DROP]; }
    }
    n = wlen(f->desc);
    if (n >= MAXLEN_IFDESCR) n = MAXLEN_IFDESCR - 1;
    for (i = 0; i < n; ++i) r->bDescr[i] = f->desc[i] < 128 ? (char)f->desc[i] : '?';
    r->bDescr[n] = 0;
    r->dwDescrLen = (DWORD)n;
}

DLLAPI DWORD WINAPI GetIfEntry(PMIB_IFROW row)
{
    iface v[MAX_IFACES];
    const iface *f;
    if (!row) return ERROR_INVALID_PARAMETER;
    f = find_index(v, enum_ifaces(v), row->dwIndex);
    if (!f) return ERROR_FILE_NOT_FOUND;
    fill_ifrow(f, row);
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetIfTable(PMIB_IFTABLE table, PULONG size, BOOL order)
{
    iface v[MAX_IFACES];
    unsigned n, i;
    ULONG need;
    (void)order;                                                       /* the rows are already in index order */
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    need = FIELD_OFFSET(MIB_IFTABLE, table) + n * sizeof(MIB_IFROW);
    if (!table || *size < need) { *size = need; return ERROR_INSUFFICIENT_BUFFER; }
    *size = need;
    table->dwNumEntries = n;
    for (i = 0; i < n; ++i) fill_ifrow(&v[i], &table->table[i]);
    return NO_ERROR;
}

/* ================================================================ addresses */
DLLAPI DWORD WINAPI GetIpAddrTable(PMIB_IPADDRTABLE table, PULONG size, BOOL order)
{
    iface v[MAX_IFACES];
    unsigned n, i, k = 0;
    ULONG need;
    (void)order;
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i) if (v[i].has_addr) ++k;
    need = FIELD_OFFSET(MIB_IPADDRTABLE, table) + k * sizeof(MIB_IPADDRROW);
    if (!table || *size < need) { *size = need; return ERROR_INSUFFICIENT_BUFFER; }
    *size = need;
    table->dwNumEntries = k;
    for (i = 0, k = 0; i < n; ++i) {
        MIB_IPADDRROW *r;
        if (!v[i].has_addr) continue;
        r = &table->table[k++];
        memset(r, 0, sizeof *r);
        r->dwAddr = v[i].ip_be;
        r->dwIndex = v[i].index;
        r->dwMask = v[i].mask_be;
        r->dwBCastAddr = 1;                                            /* Windows: "1" = the all-ones broadcast */
        r->dwReasmSize = 0xffff;
        r->wType = MIB_IPADDR_PRIMARY;
    }
    return NO_ERROR;
}

static void fill_unicast_row(const iface *f, MIB_UNICASTIPADDRESS_ROW *r)
{
    memset(r, 0, sizeof *r);
    set_in4(&r->Address, f->ip_be);
    r->InterfaceLuid = f->luid;
    r->InterfaceIndex = f->index;
    r->PrefixOrigin = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? IpPrefixOriginWellKnown : f->dhcp ? IpPrefixOriginDhcp : IpPrefixOriginManual;
    r->SuffixOrigin = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? IpSuffixOriginWellKnown : f->dhcp ? IpSuffixOriginDhcp : IpSuffixOriginManual;
    r->ValidLifetime = r->PreferredLifetime = f->dhcp ? f->lease_remaining : 0xffffffffu;
    r->OnLinkPrefixLength = (UINT8)mask_bits(f->mask_be);
    r->SkipAsSource = FALSE;
    r->DadState = IpDadStatePreferred;
    r->ScopeId.Value = 0;
    r->CreationTimeStamp.QuadPart = 0;
}

DLLAPI NETIO_STATUS WINAPI GetUnicastIpAddressTable(ADDRESS_FAMILY family, PMIB_UNICASTIPADDRESS_TABLE *table)
{
    iface v[MAX_IFACES];
    unsigned n, i, k = 0;
    MIB_UNICASTIPADDRESS_TABLE *t;
    if (!table) return ERROR_INVALID_PARAMETER;
    *table = 0;
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    if (family != AF_INET6) for (i = 0; i < n; ++i) if (v[i].has_addr) ++k;
    t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FIELD_OFFSET(MIB_UNICASTIPADDRESS_TABLE, Table) + (k ? k : 1) * sizeof(MIB_UNICASTIPADDRESS_ROW));
    if (!t) return ERROR_NOT_ENOUGH_MEMORY;
    t->NumEntries = k;
    if (family != AF_INET6) for (i = 0, k = 0; i < n; ++i) if (v[i].has_addr) fill_unicast_row(&v[i], &t->Table[k++]);
    *table = t;
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI GetUnicastIpAddressEntry(PMIB_UNICASTIPADDRESS_ROW row)
{
    iface v[MAX_IFACES];
    const iface *f;
    unsigned n;
    if (!row) return ERROR_INVALID_PARAMETER;
    if (row->Address.si_family != AF_INET) return ERROR_NOT_FOUND;
    n = enum_ifaces(v);
    f = row->InterfaceLuid.Value ? find_luid(v, n, &row->InterfaceLuid) : find_index(v, n, row->InterfaceIndex);
    if (!f) return ERROR_FILE_NOT_FOUND;
    if (!f->has_addr || f->ip_be != row->Address.Ipv4.sin_addr.s_addr) return ERROR_NOT_FOUND;
    fill_unicast_row(f, row);
    return NO_ERROR;
}

static void fill_ipif_row(const iface *f, MIB_IPINTERFACE_ROW *r)
{
    memset(r, 0, sizeof *r);
    r->Family = AF_INET;
    r->InterfaceLuid = f->luid;
    r->InterfaceIndex = f->index;
    r->MaxReassemblySize = 0xffff;
    r->UseAutomaticMetric = TRUE;
    r->UseNeighborUnreachabilityDetection = f->type != IF_TYPE_SOFTWARE_LOOPBACK;
    r->RouterDiscoveryBehavior = RouterDiscoveryDhcp;
    r->DadTransmits = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? 0 : 3;
    r->BaseReachableTime = 30000;
    r->RetransmitTime = 1000;
    r->PathMtuDiscoveryTimeout = 600000;
    r->LinkLocalAddressBehavior = LinkLocalAlwaysOff;
    r->Metric = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? 75 : 25;             /* Windows' automatic metrics for these link speeds */
    r->NlMtu = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? 0xffffffffu : f->mtu;
    r->Connected = f->up;
    r->SupportsNeighborDiscovery = f->type != IF_TYPE_SOFTWARE_LOOPBACK;
    r->ReachableTime = 30000;
}

DLLAPI NETIO_STATUS WINAPI GetIpInterfaceEntry(PMIB_IPINTERFACE_ROW row)
{
    iface v[MAX_IFACES];
    const iface *f;
    unsigned n;
    if (!row) return ERROR_INVALID_PARAMETER;
    if (row->Family != AF_INET && row->Family != AF_INET6) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    f = row->InterfaceLuid.Value ? find_luid(v, n, &row->InterfaceLuid) : find_index(v, n, row->InterfaceIndex);
    if (!f) return ERROR_FILE_NOT_FOUND;
    if (row->Family == AF_INET6) return ERROR_NOT_FOUND;                    /* IPv6 is not bound to any interface */
    fill_ipif_row(f, row);
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI GetIpInterfaceTable(ADDRESS_FAMILY family, PMIB_IPINTERFACE_TABLE *table)
{
    iface v[MAX_IFACES];
    unsigned n, i, k;
    MIB_IPINTERFACE_TABLE *t;
    if (!table) return ERROR_INVALID_PARAMETER;
    *table = 0;
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    k = family == AF_INET6 ? 0 : n;
    t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, FIELD_OFFSET(MIB_IPINTERFACE_TABLE, Table) + (k ? k : 1) * sizeof(MIB_IPINTERFACE_ROW));
    if (!t) return ERROR_NOT_ENOUGH_MEMORY;
    t->NumEntries = k;
    for (i = 0; i < k; ++i) fill_ipif_row(&v[i], &t->Table[i]);
    *table = t;
    return NO_ERROR;
}

/* ================================================================ routes */
/* Chooses the interface that reaches `dst_be`: loopback for 127/8 and the machine's own address, otherwise the Ethernet
 * adapter when it is up and configured (on-link, or through the gateway). NULL when nothing can reach it. */
static const iface *route_for(const iface *v, unsigned n, ULONG dst_be, ULONG *next_hop_be, int *on_link)
{
    const iface *lo = find_index(v, n, LOOPBACK_INDEX), *eth = find_index(v, n, ETHERNET_INDEX);
    const ULONG dst = bs32(dst_be);
    *next_hop_be = 0;
    *on_link = 1;
    if ((dst >> 24) == 127 || (eth && eth->has_addr && eth->ip_be == dst_be)) return lo;
    if (!eth || !eth->up || !eth->has_addr) return 0;
    if (((dst_be ^ eth->ip_be) & eth->mask_be) == 0 || dst_be == 0xffffffffu || (dst >> 28) == 0xe) return eth;
    if (!eth->gw_be) return 0;
    *next_hop_be = eth->gw_be;
    *on_link = 0;
    return eth;
}

DLLAPI DWORD WINAPI GetBestInterface(IPAddr dest, PDWORD index)
{
    iface v[MAX_IFACES];
    const iface *f;
    ULONG hop;
    int onlink;
    if (!index) return ERROR_INVALID_PARAMETER;
    f = route_for(v, enum_ifaces(v), dest, &hop, &onlink);
    if (!f) { *index = 0; return ERROR_NETWORK_UNREACHABLE; }
    *index = f->index;
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetBestInterfaceEx(struct sockaddr *dest, PDWORD index)
{
    if (!dest || !index) return ERROR_INVALID_PARAMETER;
    if (dest->sa_family == AF_INET) return GetBestInterface(((struct sockaddr_in *)dest)->sin_addr.s_addr, index);
    if (dest->sa_family == AF_INET6) { *index = 0; return ERROR_NETWORK_UNREACHABLE; }
    return ERROR_INVALID_PARAMETER;
}

DLLAPI NETIO_STATUS WINAPI GetBestRoute2(NET_LUID *luid, NET_IFINDEX index, const SOCKADDR_INET *source, const SOCKADDR_INET *dest,
                                          ULONG options, PMIB_IPFORWARD_ROW2 route, SOCKADDR_INET *best_source)
{
    iface v[MAX_IFACES];
    const iface *f;
    ULONG hop;
    int onlink;
    unsigned n;
    (void)options;
    if (!dest || !route || !best_source) return ERROR_INVALID_PARAMETER;
    memset(route, 0, sizeof *route);
    memset(best_source, 0, sizeof *best_source);
    if (dest->si_family == AF_INET6) return ERROR_NETWORK_UNREACHABLE;
    if (dest->si_family != AF_INET) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    if (luid && luid->Value) { if (!find_luid(v, n, luid)) return ERROR_FILE_NOT_FOUND; }
    else if (index && !find_index(v, n, index)) return ERROR_FILE_NOT_FOUND;
    f = route_for(v, n, dest->Ipv4.sin_addr.s_addr, &hop, &onlink);
    if (!f) return ERROR_NETWORK_UNREACHABLE;
    if ((luid && luid->Value && luid->Value != f->luid.Value) || (index && index != f->index)) return ERROR_NETWORK_UNREACHABLE;
    if (source && source->si_family == AF_INET && source->Ipv4.sin_addr.s_addr && source->Ipv4.sin_addr.s_addr != f->ip_be)
        return ERROR_NETWORK_UNREACHABLE;
    route->InterfaceLuid = f->luid;
    route->InterfaceIndex = f->index;
    route->DestinationPrefix.Prefix.si_family = AF_INET;
    if (onlink) {
        route->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = dest->Ipv4.sin_addr.s_addr & f->mask_be;
        route->DestinationPrefix.PrefixLength = (UINT8)mask_bits(f->mask_be);
        if (f->type == IF_TYPE_SOFTWARE_LOOPBACK || dest->Ipv4.sin_addr.s_addr == f->ip_be) {
            route->DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = dest->Ipv4.sin_addr.s_addr;
            route->DestinationPrefix.PrefixLength = 32;
        }
    }
    route->NextHop.si_family = AF_INET;
    route->NextHop.Ipv4.sin_addr.s_addr = hop;
    route->ValidLifetime = route->PreferredLifetime = 0xffffffffu;
    route->Metric = 0;
    route->Protocol = f->dhcp && !onlink ? MIB_IPPROTO_NETMGMT : MIB_IPPROTO_LOCAL;
    route->Loopback = f->type == IF_TYPE_SOFTWARE_LOOPBACK || dest->Ipv4.sin_addr.s_addr == f->ip_be;
    route->Immortal = TRUE;
    route->Origin = NlroManual;
    set_in4(best_source, f->ip_be);
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetIpForwardTable(PMIB_IPFORWARDTABLE table, PULONG size, BOOL order)
{
    iface v[MAX_IFACES];
    const iface *lo, *eth;
    unsigned n, k = 0;
    ULONG need;
    MIB_IPFORWARDROW rows[6];
    (void)order;
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    lo = find_index(v, n, LOOPBACK_INDEX);
    eth = find_index(v, n, ETHERNET_INDEX);
    memset(rows, 0, sizeof rows);
#define ROW(dst, mask, hop, idx, type, metric) do { rows[k].dwForwardDest = (dst); rows[k].dwForwardMask = (mask); \
        rows[k].dwForwardNextHop = (hop); rows[k].dwForwardIfIndex = (idx); rows[k].dwForwardType = (type); \
        rows[k].dwForwardProto = MIB_IPPROTO_LOCAL; rows[k].dwForwardMetric1 = (metric); rows[k].dwForwardAge = 0; ++k; } while (0)
    if (eth && eth->up && eth->has_addr) {
        if (eth->gw_be) { ROW(0, 0, eth->gw_be, eth->index, MIB_IPROUTE_TYPE_INDIRECT, 25); rows[k - 1].dwForwardProto = MIB_IPPROTO_NETMGMT; }
        ROW(eth->ip_be & eth->mask_be, eth->mask_be, eth->ip_be, eth->index, MIB_IPROUTE_TYPE_DIRECT, 281);
        ROW(eth->ip_be, 0xffffffffu, lo->ip_be, lo->index, MIB_IPROUTE_TYPE_DIRECT, 281);
    }
    ROW(bs32(0x7f000000u), bs32(0xff000000u), lo->ip_be, lo->index, MIB_IPROUTE_TYPE_DIRECT, 331);
    ROW(lo->ip_be, 0xffffffffu, lo->ip_be, lo->index, MIB_IPROUTE_TYPE_DIRECT, 331);
#undef ROW
    need = FIELD_OFFSET(MIB_IPFORWARDTABLE, table) + k * sizeof(MIB_IPFORWARDROW);
    if (!table || *size < need) { *size = need; return ERROR_INSUFFICIENT_BUFFER; }
    *size = need;
    table->dwNumEntries = k;
    memcpy(table->table, rows, k * sizeof(MIB_IPFORWARDROW));
    return NO_ERROR;
}

/* ================================================================ GetAdaptersAddresses */
typedef struct { BYTE *base; SIZE_T cap, used; } arena;

static void *arena_take(arena *a, SIZE_T n)
{
    void *p = a->base ? a->base + a->used : 0;
    a->used = (a->used + n + 7) & ~(SIZE_T)7;
    return p;
}

static WCHAR *arena_wstr(arena *a, const WCHAR *s)
{
    size_t n = (wlen(s) + 1) * sizeof(WCHAR);
    WCHAR *p = arena_take(a, n);
    if (p) memcpy(p, s, n);
    return p;
}

static char *arena_astr(arena *a, const char *s)
{
    size_t n = alen(s) + 1;
    char *p = arena_take(a, n);
    if (p) memcpy(p, s, n);
    return p;
}

static SOCKADDR_IN *arena_sin(arena *a, ULONG be)
{
    SOCKADDR_IN *s = arena_take(a, sizeof *s);
    if (s) { memset(s, 0, sizeof *s); s->sin_family = AF_INET; s->sin_addr.s_addr = be; }
    return s;
}

/* Lays the whole result into `a` (base NULL = only measure). */
static void build_adapters(arena *a, const iface *v, unsigned n, ULONG family, ULONG flags)
{
    IP_ADAPTER_ADDRESSES *prev = 0;
    unsigned i;
    for (i = 0; i < n; ++i) {
        const iface *f = &v[i];
        IP_ADAPTER_ADDRESSES *ad = arena_take(a, sizeof *ad);
        char guid[40];
        int v4 = f->has_addr && (family == AF_UNSPEC || family == AF_INET);
        if (ad) {
            memset(ad, 0, sizeof *ad);
            ad->Length = sizeof *ad;
            ad->IfIndex = f->index;
            if (prev) prev->Next = ad;
        }
        prev = ad;
        guid_text(&f->guid, guid);
        {
            char *nm = arena_astr(a, guid);
            WCHAR *ds = arena_wstr(a, f->desc);
            WCHAR *fr = arena_wstr(a, f->alias);
            WCHAR *sx = arena_wstr(a, L"");
            if (ad) { ad->AdapterName = nm; ad->Description = ds; ad->FriendlyName = fr; ad->DnsSuffix = sx; }
        }
        if (v4 && !(flags & GAA_FLAG_SKIP_UNICAST)) {
            IP_ADAPTER_UNICAST_ADDRESS *u = arena_take(a, sizeof *u);
            SOCKADDR_IN *sa = arena_sin(a, f->ip_be);
            if (u) {
                memset(u, 0, sizeof *u);
                u->Length = sizeof *u;
                u->Flags = 0;
                u->Address.lpSockaddr = (struct sockaddr *)sa;
                u->Address.iSockaddrLength = sizeof *sa;
                u->PrefixOrigin = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? IpPrefixOriginWellKnown : f->dhcp ? IpPrefixOriginDhcp : IpPrefixOriginManual;
                u->SuffixOrigin = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? IpSuffixOriginWellKnown : f->dhcp ? IpSuffixOriginDhcp : IpSuffixOriginManual;
                u->DadState = IpDadStatePreferred;
                u->ValidLifetime = u->PreferredLifetime = f->dhcp ? f->lease_remaining : 0xffffffffu;
                u->LeaseLifetime = f->dhcp ? f->lease_secs : 0xffffffffu;
                u->OnLinkPrefixLength = (UINT8)mask_bits(f->mask_be);
                ad->FirstUnicastAddress = u;
            }
        }
        if (v4 && !(flags & GAA_FLAG_SKIP_DNS_SERVER) && f->type != IF_TYPE_SOFTWARE_LOOPBACK) {
            IP_ADAPTER_DNS_SERVER_ADDRESS *dprev = 0;
            unsigned k;
            for (k = 0; k < 2; ++k) {
                IP_ADAPTER_DNS_SERVER_ADDRESS *d;
                SOCKADDR_IN *sa;
                if (!f->dns_be[k]) continue;
                d = arena_take(a, sizeof *d);
                sa = arena_sin(a, f->dns_be[k]);
                if (d) {
                    memset(d, 0, sizeof *d);
                    d->Length = sizeof *d;
                    d->Address.lpSockaddr = (struct sockaddr *)sa;
                    d->Address.iSockaddrLength = sizeof *sa;
                    if (dprev) dprev->Next = d; else ad->FirstDnsServerAddress = d;
                }
                dprev = d;
            }
        }
        if (v4 && (flags & GAA_FLAG_INCLUDE_PREFIX)) {
            /* Windows lists three prefixes per IPv4 address: the subnet, the address itself and the subnet broadcast */
            IP_ADAPTER_PREFIX *pprev = 0;
            unsigned k;
            for (k = 0; k < 3; ++k) {
                IP_ADAPTER_PREFIX *p = arena_take(a, sizeof *p);
                ULONG addr = k == 0 ? (f->ip_be & f->mask_be) : k == 1 ? f->ip_be : (f->ip_be | ~f->mask_be);
                SOCKADDR_IN *sa = arena_sin(a, addr);
                if (p) {
                    memset(p, 0, sizeof *p);
                    p->Length = sizeof *p;
                    p->Address.lpSockaddr = (struct sockaddr *)sa;
                    p->Address.iSockaddrLength = sizeof *sa;
                    p->PrefixLength = k == 0 ? mask_bits(f->mask_be) : 32;
                    if (pprev) pprev->Next = p; else ad->FirstPrefix = p;
                }
                pprev = p;
            }
        }
        if (v4 && (flags & GAA_FLAG_INCLUDE_GATEWAYS) && f->gw_be) {
            IP_ADAPTER_GATEWAY_ADDRESS_LH *g = arena_take(a, sizeof *g);
            SOCKADDR_IN *sa = arena_sin(a, f->gw_be);
            if (g) {
                memset(g, 0, sizeof *g);
                g->Length = sizeof *g;
                g->Address.lpSockaddr = (struct sockaddr *)sa;
                g->Address.iSockaddrLength = sizeof *sa;
                ad->FirstGatewayAddress = g;
            }
        }
        if (v4 && f->dhcp && f->dhcp_server_be) {
            SOCKADDR_IN *sa = arena_sin(a, f->dhcp_server_be);
            if (ad) { ad->Dhcpv4Server.lpSockaddr = (struct sockaddr *)sa; ad->Dhcpv4Server.iSockaddrLength = sizeof *sa; }
        }
        if (ad) {
            memcpy(ad->PhysicalAddress, f->mac, f->maclen);
            ad->PhysicalAddressLength = f->maclen;
            ad->Flags = 0;
            if (f->dhcp) ad->Dhcpv4Enabled = 1;
            if (f->type == IF_TYPE_SOFTWARE_LOOPBACK) ad->NoMulticast = 1;
            ad->Ipv4Enabled = 1;
            ad->NetbiosOverTcpipEnabled = 0;
            ad->Mtu = f->mtu;
            ad->IfType = f->type;
            ad->OperStatus = f->up ? IfOperStatusUp : IfOperStatusDown;
            ad->Ipv6IfIndex = 0;
            ad->TransmitLinkSpeed = ad->ReceiveLinkSpeed = f->speed;
            ad->Ipv4Metric = f->type == IF_TYPE_SOFTWARE_LOOPBACK ? 75 : 25;
            ad->Ipv6Metric = 0;
            ad->Luid = f->luid;
            ad->CompartmentId = 1;                                     /* NET_IF_COMPARTMENT_ID_PRIMARY */
            ad->NetworkGuid = f->guid;
            ad->ConnectionType = NET_IF_CONNECTION_DEDICATED;
            ad->TunnelType = TUNNEL_TYPE_NONE;
        }
    }
}

DLLAPI ULONG WINAPI GetAdaptersAddresses(ULONG family, ULONG flags, PVOID reserved, PIP_ADAPTER_ADDRESSES out, PULONG size)
{
    iface v[MAX_IFACES];
    unsigned n;
    arena a;
    (void)reserved;
    if (!size) return ERROR_INVALID_PARAMETER;
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    a.base = 0; a.cap = 0; a.used = 0;
    build_adapters(&a, v, n, family, flags);
    if (!out || *size < a.used) { *size = (ULONG)a.used; return ERROR_BUFFER_OVERFLOW; }
    a.base = (BYTE *)out; a.cap = *size; a.used = 0;
    build_adapters(&a, v, n, family, flags);
    *size = (ULONG)a.used;
    return NO_ERROR;
}

/* ================================================================ legacy: GetAdaptersInfo / GetInterfaceInfo / GetNetworkParams / GetPerAdapterInfo */
DLLAPI ULONG WINAPI GetAdaptersInfo(PIP_ADAPTER_INFO info, PULONG size)
{
    iface v[MAX_IFACES];
    unsigned n, i, k = 0;
    ULONG need;
    IP_ADAPTER_INFO *prev = 0;
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i) if (v[i].type != IF_TYPE_SOFTWARE_LOOPBACK) ++k;
    if (!k) return ERROR_NO_DATA;
    need = k * sizeof(IP_ADAPTER_INFO);
    if (!info || *size < need) { *size = need; return ERROR_BUFFER_OVERFLOW; }
    *size = need;
    for (i = 0; i < n; ++i) {
        const iface *f = &v[i];
        IP_ADAPTER_INFO *ad;
        size_t j;
        if (f->type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        ad = &info[prev ? (unsigned)(prev - info) + 1 : 0];
        memset(ad, 0, sizeof *ad);
        if (prev) prev->Next = ad;
        prev = ad;
        ad->ComboIndex = f->index;
        guid_text(&f->guid, ad->AdapterName);
        for (j = 0; f->desc[j] && j < MAX_ADAPTER_DESCRIPTION_LENGTH; ++j) ad->Description[j] = f->desc[j] < 128 ? (char)f->desc[j] : '?';
        ad->AddressLength = f->maclen;
        memcpy(ad->Address, f->mac, f->maclen);
        ad->Index = f->index;
        ad->Type = f->type;
        ad->DhcpEnabled = f->dhcp;
        ad->CurrentIpAddress = 0;
        if (f->has_addr) { ip_text(f->ip_be, ad->IpAddressList.IpAddress.String); ip_text(f->mask_be, ad->IpAddressList.IpMask.String); }
        else { memcpy(ad->IpAddressList.IpAddress.String, "0.0.0.0", 8); memcpy(ad->IpAddressList.IpMask.String, "0.0.0.0", 8); }
        if (f->gw_be) ip_text(f->gw_be, ad->GatewayList.IpAddress.String); else memcpy(ad->GatewayList.IpAddress.String, "0.0.0.0", 8);
        memcpy(ad->GatewayList.IpMask.String, "0.0.0.0", 8);
        if (f->dhcp) {
            ULONG64 now = unix_now();
            ip_text(f->dhcp_server_be, ad->DhcpServer.IpAddress.String);
            ad->LeaseObtained = (time_t)(now - (f->lease_secs - f->lease_remaining));
            ad->LeaseExpires = (time_t)(now + f->lease_remaining);
        }
        ad->HaveWins = FALSE;
    }
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetInterfaceInfo(PIP_INTERFACE_INFO info, PULONG size)
{
    iface v[MAX_IFACES];
    unsigned n, i, k = 0;
    ULONG need;
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i) if (v[i].type != IF_TYPE_SOFTWARE_LOOPBACK) ++k;
    if (!k) { *size = 0; return ERROR_NO_DATA; }
    need = FIELD_OFFSET(IP_INTERFACE_INFO, Adapter) + k * sizeof(IP_ADAPTER_INDEX_MAP);
    if (!info || *size < need) { *size = need; return ERROR_INSUFFICIENT_BUFFER; }
    *size = need;
    info->NumAdapters = (LONG)k;
    for (i = 0, k = 0; i < n; ++i) {
        static const WCHAR pre[] = L"\\DEVICE\\TCPIP_";
        char guid[40];
        size_t j, p = wlen(pre);
        if (v[i].type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        info->Adapter[k].Index = v[i].index;
        guid_text(&v[i].guid, guid);
        memcpy(info->Adapter[k].Name, pre, p * sizeof(WCHAR));
        for (j = 0; guid[j]; ++j) info->Adapter[k].Name[p + j] = (WCHAR)(unsigned char)guid[j];
        info->Adapter[k].Name[p + j] = 0;
        ++k;
    }
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetNetworkParams(PFIXED_INFO fi, PULONG size)
{
    iface v[MAX_IFACES];
    const iface *eth;
    unsigned n, k = 0;
    ULONG need;
    WCHAR host[MAX_HOSTNAME_LEN + 1];
    DWORD hn = MAX_HOSTNAME_LEN + 1;
    if (!size) return ERROR_INVALID_PARAMETER;
    n = enum_ifaces(v);
    eth = find_index(v, n, ETHERNET_INDEX);
    if (eth) k = (eth->dns_be[0] != 0) + (eth->dns_be[1] != 0);
    need = sizeof(FIXED_INFO) + (k > 1 ? (k - 1) * sizeof(IP_ADDR_STRING) : 0);
    if (!fi || *size < need) { *size = need; return ERROR_BUFFER_OVERFLOW; }
    *size = need;
    memset(fi, 0, need);
    if (GetComputerNameW(host, &hn)) {
        DWORD i;
        for (i = 0; i < hn && i < MAX_HOSTNAME_LEN; ++i) fi->HostName[i] = host[i] < 128 ? (char)host[i] : '?';
    }
    fi->NodeType = HYBRID_NODETYPE;
    fi->EnableRouting = 0;
    fi->EnableProxy = 0;
    fi->EnableDns = 1;
    if (k) {
        IP_ADDR_STRING *cur = &fi->DnsServerList, *extra = (IP_ADDR_STRING *)(fi + 1);
        unsigned j, written = 0;
        for (j = 0; j < 2; ++j) {
            if (!eth->dns_be[j]) continue;
            if (written) { cur->Next = extra; cur = extra++; }
            ip_text(eth->dns_be[j], cur->IpAddress.String);
            memcpy(cur->IpMask.String, "255.255.255.255", 16);
            ++written;
        }
        fi->CurrentDnsServer = 0;
    }
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetPerAdapterInfo(ULONG index, PIP_PER_ADAPTER_INFO info, PULONG size)
{
    iface v[MAX_IFACES];
    const iface *f;
    unsigned k;
    ULONG need;
    if (!size) return ERROR_INVALID_PARAMETER;
    f = find_index(v, enum_ifaces(v), index);
    if (!f) return ERROR_NO_DATA;
    k = (f->dns_be[0] != 0) + (f->dns_be[1] != 0);
    need = sizeof(IP_PER_ADAPTER_INFO) + (k > 1 ? (k - 1) * sizeof(IP_ADDR_STRING) : 0);
    if (!info || *size < need) { *size = need; return ERROR_BUFFER_OVERFLOW; }
    *size = need;
    memset(info, 0, need);
    info->AutoconfigEnabled = 0;
    info->AutoconfigActive = 0;
    if (k) {
        IP_ADDR_STRING *cur = &info->DnsServerList, *extra = (IP_ADDR_STRING *)(info + 1);
        unsigned j, written = 0;
        for (j = 0; j < 2; ++j) {
            if (!f->dns_be[j]) continue;
            if (written) { cur->Next = extra; cur = extra++; }
            ip_text(f->dns_be[j], cur->IpAddress.String);
            ++written;
        }
    }
    return NO_ERROR;
}

/* ================================================================ DHCP */
DLLAPI DWORD WINAPI IpRenewAddress(PIP_ADAPTER_INDEX_MAP map)
{
    iface v[MAX_IFACES];
    const iface *f;
    ULONG op = 1, ret = 0;
    if (!map) return ERROR_INVALID_PARAMETER;
    f = find_index(v, enum_ifaces(v), map->Index);
    if (!f || f->type == IF_TYPE_SOFTWARE_LOOPBACK) return ERROR_INVALID_PARAMETER;
    if (!f->dhcp) return ERROR_INVALID_PARAMETER;                       /* not a DHCP-configured adapter */
    if (NtShzNetQuery(3, &op, sizeof op, &ret)) return ERROR_GEN_FAILURE;
    return NO_ERROR;
}

DLLAPI DWORD WINAPI IpReleaseAddress(PIP_ADAPTER_INDEX_MAP map)
{
    iface v[MAX_IFACES];
    const iface *f;
    if (!map) return ERROR_INVALID_PARAMETER;
    f = find_index(v, enum_ifaces(v), map->Index);
    if (!f || f->type == IF_TYPE_SOFTWARE_LOOPBACK) return ERROR_INVALID_PARAMETER;
    return ERROR_NOT_SUPPORTED;                                         /* the kernel has no DHCP release operation */
}

/* ================================================================ statistics */
DLLAPI DWORD WINAPI GetIpStatisticsEx(PMIB_IPSTATS s, DWORD family)
{
    ULONG st[NST_COUNT + 6];
    iface v[MAX_IFACES];
    unsigned n, i, addrs = 0;
    if (!s) return ERROR_INVALID_PARAMETER;
    if (family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    memset(s, 0, sizeof *s);
    if (family == AF_INET6) return ERROR_NOT_SUPPORTED;
    n = enum_ifaces(v);
    for (i = 0; i < n; ++i) addrs += v[i].has_addr;
    query_stats(st);
    s->dwForwarding = MIB_IP_NOT_FORWARDING;
    s->dwDefaultTTL = 64;
    s->dwInReceives = st[NST_IP_RX];
    s->dwInHdrErrors = st[NST_IP_BAD_CSUM];
    s->dwInDelivers = st[NST_IP_RX] > st[NST_IP_BAD_CSUM] ? st[NST_IP_RX] - st[NST_IP_BAD_CSUM] : 0;
    s->dwOutRequests = st[NST_IP_TX];
    s->dwReasmTimeout = 60;
    s->dwReasmOks = st[NST_IP_REASM];
    s->dwFragOks = st[NST_IP_FRAG_TX];
    s->dwNumIf = n;
    s->dwNumAddr = addrs;
    s->dwNumRoutes = 2 + (n > 1 ? 3 : 0);
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetIpStatistics(PMIB_IPSTATS s) { return GetIpStatisticsEx(s, AF_INET); }

DLLAPI DWORD WINAPI GetTcpStatisticsEx(PMIB_TCPSTATS s, DWORD family)
{
    ULONG st[NST_COUNT + 6], c[11], ret = 0;
    if (!s) return ERROR_INVALID_PARAMETER;
    if (family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    memset(s, 0, sizeof *s);
    if (family == AF_INET6) return ERROR_NOT_SUPPORTED;
    query_stats(st);
    s->dwRtoAlgorithm = MIB_TCP_RTO_VANJ;
    s->dwRtoMin = 300;
    s->dwRtoMax = 120000;
    s->dwMaxConn = (DWORD)-1;
    s->dwInSegs = st[NST_TCP_RX];
    s->dwOutSegs = st[NST_TCP_TX];
    s->dwRetransSegs = st[NST_TCP_RETRANS] + st[NST_TCP_FAST_RETRANS];
    s->dwInErrs = st[NST_TCP_BAD_CSUM];
    s->dwOutRsts = st[NST_TCP_RST_TX];
    memset(c, 0, sizeof c);
    if (NtShzNetQuery(4, c, sizeof c, &ret) == 0) s->dwCurrEstab = c[4] + c[7];   /* ESTABLISHED + CLOSE_WAIT, as RFC 1213 counts */
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetTcpStatistics(PMIB_TCPSTATS s) { return GetTcpStatisticsEx(s, AF_INET); }

DLLAPI DWORD WINAPI GetUdpStatisticsEx(PMIB_UDPSTATS s, DWORD family)
{
    ULONG st[NST_COUNT + 6];
    if (!s) return ERROR_INVALID_PARAMETER;
    if (family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    memset(s, 0, sizeof *s);
    if (family == AF_INET6) return ERROR_NOT_SUPPORTED;
    query_stats(st);
    s->dwInDatagrams = st[NST_UDP_RX];
    s->dwOutDatagrams = st[NST_UDP_TX];
    s->dwInErrors = st[NST_UDP_BAD_CSUM];
    return NO_ERROR;
}

DLLAPI DWORD WINAPI GetUdpStatistics(PMIB_UDPSTATS s) { return GetUdpStatisticsEx(s, AF_INET); }

DLLAPI ULONG WINAPI GetTcpTable(PMIB_TCPTABLE table, PULONG size, BOOL order)
{
    struct shz_tcp_row rows[256];
    ULONG ret = 0, need;
    unsigned n, i;
    (void)order;
    if (!size) return ERROR_INVALID_PARAMETER;
    if (NtShzNetQuery(2, rows, sizeof rows, &ret)) return ERROR_GEN_FAILURE;
    n = ret / sizeof rows[0];
    need = FIELD_OFFSET(MIB_TCPTABLE, table) + n * sizeof(MIB_TCPROW);
    if (!table || *size < need) { *size = need; return ERROR_INSUFFICIENT_BUFFER; }
    *size = need;
    table->dwNumEntries = n;
    for (i = 0; i < n; ++i) {
        MIB_TCPROW *r = &table->table[i];
        r->dwState = rows[i].state + 1;                                 /* kernel 0 = CLOSED ... 10 = TIME_WAIT; MIB values are 1-based */
        r->dwLocalAddr = rows[i].lip_be;
        r->dwLocalPort = (DWORD)(USHORT)((rows[i].lport >> 8) | (rows[i].lport << 8));
        r->dwRemoteAddr = rows[i].rip_be;
        r->dwRemotePort = (DWORD)(USHORT)((rows[i].rport >> 8) | (rows[i].rport << 8));
    }
    return NO_ERROR;
}

/* ================================================================ change notification */
typedef struct notify {
    struct notify *next;
    int kind;                       /* 0 addr (OVERLAPPED), 1 route (OVERLAPPED), 2 ipinterface cb, 3 unicast cb, 4 route2 cb */
    LPOVERLAPPED ovl;
    HANDLE event;                   /* internal event: signalled on completion (the blocking form waits on it) */
    void *callback, *context;
    ADDRESS_FAMILY family;
} notify;

static SRWLOCK g_lock = SRWLOCK_INIT;      /* the registration list */
static SRWLOCK g_cb_lock = SRWLOCK_INIT;   /* held shared while callbacks run, exclusive by CancelMibChangeNotify2 */
static notify *g_list;
static HANDLE g_thread;
static struct shz_net_info g_last;

static int info_changed(const struct shz_net_info *a, const struct shz_net_info *b, int *route)
{
    int addr = ((a->flags ^ b->flags) & 6) || a->ip_be != b->ip_be || a->mask_be != b->mask_be || a->dns0_be != b->dns0_be || a->dns1_be != b->dns1_be;
    *route = ((a->flags ^ b->flags) & 6) || a->gw_be != b->gw_be || a->ip_be != b->ip_be || a->mask_be != b->mask_be;
    return addr || *route;
}

static void complete_overlapped(notify *e, LONG status)
{
    if (e->ovl) {
        e->ovl->Internal = (ULONG_PTR)(ULONG)status;             /* the NTSTATUS, as the I/O manager stores it: 32 bits */
        e->ovl->InternalHigh = 0;
        if (e->ovl->hEvent) SetEvent(e->ovl->hEvent);
    }
    if (e->event) SetEvent(e->event);
}

static DWORD WINAPI watcher(LPVOID arg)
{
    (void)arg;
    for (;;) {
        struct shz_net_info now;
        int route = 0;
        notify *e, *fired = 0, **pp;
        Sleep(500);
        if (!query_info(&now)) continue;
        AcquireSRWLockExclusive(&g_lock);
        if (!g_list) { g_thread = 0; ReleaseSRWLockExclusive(&g_lock); return 0; }
        if (!info_changed(&g_last, &now, &route)) { ReleaseSRWLockExclusive(&g_lock); continue; }
        g_last = now;
        /* one-shot OVERLAPPED registrations leave the list and complete; callback registrations stay */
        for (pp = &g_list; (e = *pp) != 0;) {
            if (e->kind == 0 || (e->kind == 1 && route)) { *pp = e->next; e->next = fired; fired = e; }
            else pp = &e->next;
        }
        ReleaseSRWLockExclusive(&g_lock);
        while (fired) { notify *n = fired->next; complete_overlapped(fired, 0); fired = n; }
        AcquireSRWLockShared(&g_cb_lock);
        AcquireSRWLockShared(&g_lock);
        for (e = g_list; e; e = e->next) {
            iface v[MAX_IFACES];
            unsigned n = enum_ifaces(v);
            const iface *eth = find_index(v, n, ETHERNET_INDEX);
            if (!eth) continue;
            if (e->kind == 2) {
                MIB_IPINTERFACE_ROW row;
                fill_ipif_row(eth, &row);
                ((PIPINTERFACE_CHANGE_CALLBACK)e->callback)(e->context, &row, MibParameterNotification);
            } else if (e->kind == 3) {
                MIB_UNICASTIPADDRESS_ROW row;
                fill_unicast_row(eth, &row);
                if (!eth->has_addr) row.Address.Ipv4.sin_addr.s_addr = g_last.ip_be;
                ((PUNICAST_IPADDRESS_CHANGE_CALLBACK)e->callback)(e->context, &row, eth->has_addr ? MibAddInstance : MibDeleteInstance);
            } else if (e->kind == 4 && route) {
                MIB_IPFORWARD_ROW2 row;
                memset(&row, 0, sizeof row);
                row.InterfaceLuid = eth->luid;
                row.InterfaceIndex = eth->index;
                row.DestinationPrefix.Prefix.si_family = AF_INET;
                row.NextHop.si_family = AF_INET;
                row.NextHop.Ipv4.sin_addr.s_addr = eth->gw_be;
                row.Protocol = MIB_IPPROTO_NETMGMT;
                ((PIPFORWARD_CHANGE_CALLBACK)e->callback)(e->context, &row, eth->gw_be ? MibAddInstance : MibDeleteInstance);
            }
        }
        ReleaseSRWLockShared(&g_lock);
        ReleaseSRWLockShared(&g_cb_lock);
    }
}

/* Adds `e` to the list, starting the watcher when it is the first registration. Called with g_lock held exclusive. */
static DWORD register_locked(notify *e)
{
    if (!g_thread) {
        query_info(&g_last);
        g_thread = CreateThread(0, 0, watcher, 0, 0, 0);
        if (!g_thread) return GetLastError() ? GetLastError() : ERROR_NOT_ENOUGH_MEMORY;
    }
    e->next = g_list;
    g_list = e;
    return NO_ERROR;
}

static DWORD notify_overlapped(int kind, PHANDLE handle, LPOVERLAPPED ovl)
{
    notify *e;
    DWORD err;
    if (!handle) return ERROR_INVALID_PARAMETER;
    e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *e);
    if (!e) return ERROR_NOT_ENOUGH_MEMORY;
    e->kind = kind;
    e->ovl = ovl;
    e->event = CreateEventW(0, TRUE, FALSE, 0);
    if (!e->event) { HeapFree(GetProcessHeap(), 0, e); return ERROR_NOT_ENOUGH_MEMORY; }
    if (ovl) { ovl->Internal = (ULONG_PTR)(ULONG)STATUS_PENDING; ovl->InternalHigh = 0; }
    AcquireSRWLockExclusive(&g_lock);
    err = register_locked(e);
    ReleaseSRWLockExclusive(&g_lock);
    if (err) { CloseHandle(e->event); HeapFree(GetProcessHeap(), 0, e); return err; }
    *handle = e->event;
    if (ovl) return ERROR_IO_PENDING;
    WaitForSingleObject(e->event, INFINITE);                            /* the blocking form: returns after a change */
    CloseHandle(e->event);
    HeapFree(GetProcessHeap(), 0, e);
    *handle = 0;
    return NO_ERROR;
}

DLLAPI DWORD WINAPI NotifyAddrChange(PHANDLE handle, LPOVERLAPPED ovl) { return notify_overlapped(0, handle, ovl); }
DLLAPI DWORD WINAPI NotifyRouteChange(PHANDLE handle, LPOVERLAPPED ovl) { return notify_overlapped(1, handle, ovl); }

DLLAPI BOOL WINAPI CancelIPChangeNotify(LPOVERLAPPED ovl)
{
    notify *e, **pp;
    if (!ovl) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    AcquireSRWLockExclusive(&g_lock);
    for (pp = &g_list; (e = *pp) != 0; pp = &e->next)
        if ((e->kind == 0 || e->kind == 1) && e->ovl == ovl) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_lock);
    if (!e) { SetLastError(ERROR_INVALID_PARAMETER); return FALSE; }
    complete_overlapped(e, STATUS_CANCELLED_);
    CloseHandle(e->event);
    HeapFree(GetProcessHeap(), 0, e);
    return TRUE;
}

static NETIO_STATUS notify_callback(int kind, ADDRESS_FAMILY family, void *cb, void *ctx, BOOLEAN initial, HANDLE *handle)
{
    notify *e;
    DWORD err;
    if (!cb || !handle) return ERROR_INVALID_PARAMETER;
    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) return ERROR_INVALID_PARAMETER;
    *handle = 0;
    e = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof *e);
    if (!e) return ERROR_NOT_ENOUGH_MEMORY;
    e->kind = kind;
    e->callback = cb;
    e->context = ctx;
    e->family = family;
    AcquireSRWLockExclusive(&g_lock);
    err = register_locked(e);
    ReleaseSRWLockExclusive(&g_lock);
    if (err) { HeapFree(GetProcessHeap(), 0, e); return err; }
    *handle = (HANDLE)e;
    if (initial) {
        AcquireSRWLockShared(&g_cb_lock);
        if (kind == 2) ((PIPINTERFACE_CHANGE_CALLBACK)cb)(ctx, 0, MibInitialNotification);
        else if (kind == 3) ((PUNICAST_IPADDRESS_CHANGE_CALLBACK)cb)(ctx, 0, MibInitialNotification);
        else ((PIPFORWARD_CHANGE_CALLBACK)cb)(ctx, 0, MibInitialNotification);
        ReleaseSRWLockShared(&g_cb_lock);
    }
    return NO_ERROR;
}

DLLAPI NETIO_STATUS WINAPI NotifyIpInterfaceChange(ADDRESS_FAMILY family, PIPINTERFACE_CHANGE_CALLBACK cb, PVOID ctx, BOOLEAN initial, HANDLE *handle)
{ return notify_callback(2, family, (void *)cb, ctx, initial, handle); }

DLLAPI NETIO_STATUS WINAPI NotifyUnicastIpAddressChange(ADDRESS_FAMILY family, PUNICAST_IPADDRESS_CHANGE_CALLBACK cb, PVOID ctx, BOOLEAN initial, HANDLE *handle)
{ return notify_callback(3, family, (void *)cb, ctx, initial, handle); }

DLLAPI NETIO_STATUS WINAPI NotifyRouteChange2(ADDRESS_FAMILY family, PIPFORWARD_CHANGE_CALLBACK cb, PVOID ctx, BOOLEAN initial, HANDLE *handle)
{ return notify_callback(4, family, (void *)cb, ctx, initial, handle); }

DLLAPI NETIO_STATUS WINAPI CancelMibChangeNotify2(HANDLE handle)
{
    notify *e, **pp;
    if (!handle) return ERROR_INVALID_PARAMETER;
    AcquireSRWLockExclusive(&g_lock);
    for (pp = &g_list; (e = *pp) != 0; pp = &e->next)
        if (e == (notify *)handle && e->kind >= 2) { *pp = e->next; break; }
    ReleaseSRWLockExclusive(&g_lock);
    if (!e) return ERROR_INVALID_PARAMETER;
    AcquireSRWLockExclusive(&g_cb_lock);                                /* a callback still running finishes first */
    ReleaseSRWLockExclusive(&g_cb_lock);
    HeapFree(GetProcessHeap(), 0, e);
    return NO_ERROR;
}
