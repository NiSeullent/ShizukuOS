/* SPDX-License-Identifier: GPL-2.0-only
 * iphlpapi.dll: the interface, address, route and statistics tables and the change notifications, checked against the
 * documented contracts (MSDN: GetAdaptersAddresses/GetAdaptersInfo/GetInterfaceInfo buffer protocol and error codes,
 * netioapi.h row semantics, the "<type>_<index>" interface names of ConvertInterfaceLuidToName, NotifyAddrChange's
 * ERROR_IO_PENDING/OVERLAPPED contract, CancelIPChangeNotify) and against the kernel's own view of the network
 * (NtShzNetQuery(0), the same source tests/t_net_nic.c uses), which is the ground truth the tables must agree with.
 * Runs with or without a NIC: without one only the loopback interface exists and every Ethernet check adapts. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "u_check.h"

typedef LONG NTSTATUS;
NTSTATUS __stdcall NtShzNetQuery(ULONG cls, PVOID buf, ULONG len, PULONG ret);
struct shz_net_info {
    unsigned flags, ip_be, mask_be, gw_be, dns0_be, dns1_be, dhcp_server_be;
    unsigned char mac[6]; unsigned short pad;
    unsigned lease_secs, lease_remaining_secs, dhcp_state;
};

static unsigned bs32(unsigned v) { return (v >> 24) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) | (v << 24); }

static volatile LONG g_cb_calls, g_cb_initial;
static void WINAPI ipif_cb(PVOID ctx, PMIB_IPINTERFACE_ROW row, MIB_NOTIFICATION_TYPE type)
{
    if (ctx == (PVOID)0x1234 && !row && type == MibInitialNotification) InterlockedIncrement((LONG *)&g_cb_initial);
    InterlockedIncrement((LONG *)&g_cb_calls);
}

int main(void)
{
    struct shz_net_info in;
    ULONG ret = 0;
    int nic;
    static unsigned char buf[16384];
    ULONG size;
    DWORD rc;

    memset(&in, 0, sizeof in);
    U_CHECK("NtShzNetQuery(0) describes the network (the reference for every table below)", NtShzNetQuery(0, &in, sizeof in, &ret) == 0 && ret == sizeof in);
    nic = (in.flags & 1) != 0;
    printf("INFO: NIC %s, link %s, address %s\n", nic ? "present" : "absent", (in.flags & 2) ? "up" : "down", (in.flags & 4) ? "configured" : "none");

    /* ---------------- GetAdaptersAddresses ---------------- */
    size = 0;
    rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS, 0, 0, &size);
    U_CHECKF("GetAdaptersAddresses(NULL, 0) reports ERROR_BUFFER_OVERFLOW with the size needed", rc == ERROR_BUFFER_OVERFLOW && size > sizeof(IP_ADAPTER_ADDRESSES) && size < sizeof buf, "rc=%u size=%u", (unsigned)rc, (unsigned)size);
    U_CHECK("GetAdaptersAddresses(size = NULL) fails with ERROR_INVALID_PARAMETER", GetAdaptersAddresses(AF_UNSPEC, 0, 0, (PIP_ADAPTER_ADDRESSES)buf, 0) == ERROR_INVALID_PARAMETER);
    U_CHECK("GetAdaptersAddresses with an unknown family fails with ERROR_INVALID_PARAMETER", GetAdaptersAddresses(AF_IPX, 0, 0, (PIP_ADAPTER_ADDRESSES)buf, &size) == ERROR_INVALID_PARAMETER);
    {
        ULONG small = size - 1;
        U_CHECK("...a buffer one byte short is ERROR_BUFFER_OVERFLOW and size is updated", GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS, 0, (PIP_ADAPTER_ADDRESSES)buf, &small) == ERROR_BUFFER_OVERFLOW && small == size);
    }
    memset(buf, 0xcc, sizeof buf);
    rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS, 0, (PIP_ADAPTER_ADDRESSES)buf, &size);
    U_CHECKF("GetAdaptersAddresses fills the buffer", rc == NO_ERROR, "rc=%u", (unsigned)rc);
    if (rc == NO_ERROR) {
        const IP_ADAPTER_ADDRESSES *a = (const IP_ADAPTER_ADDRESSES *)buf, *lo = 0, *eth = 0;
        int count = 0, all_inside = 1;
        for (; a; a = a->Next) {
            ++count;
            if ((const unsigned char *)a < buf || (const unsigned char *)a + sizeof *a > buf + size) all_inside = 0;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) lo = a;
            if (a->IfType == IF_TYPE_ETHERNET_CSMACD) eth = a;
        }
        U_CHECKF("the list has the loopback and, with a NIC, the Ethernet adapter (%d adapters)", count == 1 + nic && lo && (!nic || eth) && all_inside, "count=%d nic=%d", count, nic);
        if (lo) {
            const IP_ADAPTER_UNICAST_ADDRESS *u = lo->FirstUnicastAddress;
            U_CHECK("loopback: Length = sizeof(IP_ADAPTER_ADDRESSES), IfIndex 1, OperStatus up, MTU 0xffffffff, no MAC", lo->Length == sizeof *lo && lo->IfIndex == 1 && lo->OperStatus == IfOperStatusUp && lo->Mtu == 0xffffffffu && lo->PhysicalAddressLength == 0);
            U_CHECK("loopback: exactly one unicast address, 127.0.0.1/8 with a 16-byte sockaddr_in", u && !u->Next && u->Address.iSockaddrLength == sizeof(struct sockaddr_in) && u->Address.lpSockaddr->sa_family == AF_INET && ((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr == bs32(0x7f000001u) && u->OnLinkPrefixLength == 8);
            U_CHECK("loopback: LUID type 24 / index 0, NetLuidIndex-based name, GUID text as AdapterName", lo->Luid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK && lo->Luid.Info.NetLuidIndex == 0 && lo->AdapterName && lo->AdapterName[0] == '{' && strlen(lo->AdapterName) == 38);
            U_CHECK("loopback: Description and FriendlyName are set, DnsSuffix is an empty string", lo->Description && lo->Description[0] && lo->FriendlyName && lo->FriendlyName[0] && lo->DnsSuffix && !lo->DnsSuffix[0]);
            U_CHECK("loopback: three prefixes (subnet /8, host /32, broadcast /32) as Windows lists them", lo->FirstPrefix && lo->FirstPrefix->PrefixLength == 8 && lo->FirstPrefix->Next && lo->FirstPrefix->Next->PrefixLength == 32 && lo->FirstPrefix->Next->Next && lo->FirstPrefix->Next->Next->PrefixLength == 32 && !lo->FirstPrefix->Next->Next->Next);
            U_CHECK("loopback: no gateway, no DNS server, Ipv4Enabled, NoMulticast", !lo->FirstGatewayAddress && !lo->FirstDnsServerAddress && lo->Ipv4Enabled && lo->NoMulticast);
        }
        if (nic && eth) {
            const IP_ADAPTER_UNICAST_ADDRESS *u = eth->FirstUnicastAddress;
            U_CHECK("ethernet: IfIndex 2, the kernel's MAC (6 bytes), MTU 1500, LUID type 6", eth->IfIndex == 2 && eth->PhysicalAddressLength == 6 && !memcmp(eth->PhysicalAddress, in.mac, 6) && eth->Mtu == 1500 && eth->Luid.Info.IfType == IF_TYPE_ETHERNET_CSMACD);
            U_CHECK("ethernet: OperStatus follows the link state the kernel reports", eth->OperStatus == ((in.flags & 2) ? IfOperStatusUp : IfOperStatusDown));
            if (in.flags & 4) {
                U_CHECK("ethernet: the unicast address, prefix length and DHCP flag match the kernel", u && ((struct sockaddr_in *)u->Address.lpSockaddr)->sin_addr.s_addr == in.ip_be && eth->Dhcpv4Enabled == ((in.flags & 8) != 0));
                U_CHECK("ethernet: the gateway (GAA_FLAG_INCLUDE_GATEWAYS) and first DNS server match the kernel", (!in.gw_be || (eth->FirstGatewayAddress && ((struct sockaddr_in *)eth->FirstGatewayAddress->Address.lpSockaddr)->sin_addr.s_addr == in.gw_be)) && (!in.dns0_be || (eth->FirstDnsServerAddress && ((struct sockaddr_in *)eth->FirstDnsServerAddress->Address.lpSockaddr)->sin_addr.s_addr == in.dns0_be)));
                if (in.flags & 8) U_CHECK("ethernet: Dhcpv4Server is the DHCP server the lease came from", eth->Dhcpv4Server.lpSockaddr && ((struct sockaddr_in *)eth->Dhcpv4Server.lpSockaddr)->sin_addr.s_addr == in.dhcp_server_be);
            } else {
                U_CHECK("ethernet without an address: no unicast address", !u);
            }
        }
    }
    {
        ULONG s6 = sizeof buf;
        rc = GetAdaptersAddresses(AF_INET6, 0, 0, (PIP_ADAPTER_ADDRESSES)buf, &s6);
        U_CHECK("GetAdaptersAddresses(AF_INET6) lists the adapters but no addresses (IPv4-only stack)", rc == NO_ERROR && !((PIP_ADAPTER_ADDRESSES)buf)->FirstUnicastAddress);
    }

    /* ---------------- MIB_IF_ROW2 / MIB_IF_TABLE2 ---------------- */
    {
        PMIB_IF_TABLE2 t = 0;
        MIB_IF_ROW2 row;
        rc = GetIfTable2(&t);
        U_CHECKF("GetIfTable2 allocates a table with one row per interface", rc == NO_ERROR && t && t->NumEntries == (ULONG)(1 + nic), "rc=%u n=%u", (unsigned)rc, t ? (unsigned)t->NumEntries : 0u);
        if (rc == NO_ERROR && t) {
            const MIB_IF_ROW2 *r = &t->Table[0];
            U_CHECK("row 1: loopback, InterfaceIndex 1, Alias/Description set, MediaConnectState connected", r->Type == IF_TYPE_SOFTWARE_LOOPBACK && r->InterfaceIndex == 1 && r->Alias[0] && r->Description[0] && r->MediaConnectState == MediaConnectStateConnected && r->OperStatus == IfOperStatusUp && r->AccessType == NET_IF_ACCESS_LOOPBACK);
            if (nic) {
                r = &t->Table[1];
                U_CHECK("row 2: Ethernet, the kernel's MAC, HardwareInterface, ConnectorPresent, 100 Mbit/s", r->Type == IF_TYPE_ETHERNET_CSMACD && r->PhysicalAddressLength == 6 && !memcmp(r->PhysicalAddress, in.mac, 6) && r->InterfaceAndOperStatusFlags.HardwareInterface && r->InterfaceAndOperStatusFlags.ConnectorPresent && r->TransmitLinkSpeed == 100000000ull);
            }
            memset(&row, 0, sizeof row);
            row.InterfaceLuid = t->Table[0].InterfaceLuid;
            U_CHECK("GetIfEntry2 by LUID returns the same row as the table", GetIfEntry2(&row) == NO_ERROR && row.InterfaceIndex == 1 && !memcmp(&row.InterfaceGuid, &t->Table[0].InterfaceGuid, sizeof(GUID)));
            FreeMibTable(t);
        }
        memset(&row, 0, sizeof row);
        row.InterfaceIndex = 1 + nic;
        U_CHECK("GetIfEntry2 by index finds the last interface", GetIfEntry2(&row) == NO_ERROR && row.InterfaceIndex == (ULONG)(1 + nic));
        memset(&row, 0, sizeof row);
        row.InterfaceIndex = 77;
        U_CHECK("GetIfEntry2 with an unknown index fails with ERROR_FILE_NOT_FOUND", GetIfEntry2(&row) == ERROR_FILE_NOT_FOUND);
        U_CHECK("GetIfEntry2(NULL) fails with ERROR_INVALID_PARAMETER", GetIfEntry2(0) == ERROR_INVALID_PARAMETER);
    }
    {
        MIB_IFROW r;
        ULONG sz = 0;
        memset(&r, 0, sizeof r);
        r.dwIndex = 1;
        U_CHECK("GetIfEntry(1): loopback row with the \\DEVICE\\TCPIP_{guid} name and OPERATIONAL status", GetIfEntry(&r) == NO_ERROR && r.dwType == IF_TYPE_SOFTWARE_LOOPBACK && r.dwOperStatus == MIB_IF_OPER_STATUS_OPERATIONAL && r.wszName[0] == '\\' && r.dwDescrLen == strlen((const char *)r.bDescr));
        U_CHECK("GetIfTable(NULL) returns ERROR_INSUFFICIENT_BUFFER with the size", GetIfTable(0, &sz, TRUE) == ERROR_INSUFFICIENT_BUFFER && sz == FIELD_OFFSET(MIB_IFTABLE, table) + (1 + nic) * sizeof(MIB_IFROW));
        U_CHECK("GetIfTable fills the rows", GetIfTable((PMIB_IFTABLE)buf, &sz, TRUE) == NO_ERROR && ((PMIB_IFTABLE)buf)->dwNumEntries == (DWORD)(1 + nic) && ((PMIB_IFTABLE)buf)->table[0].dwIndex == 1);
    }

    /* ---------------- names, LUIDs, GUIDs ---------------- */
    {
        NET_LUID luid, back;
        NET_IFINDEX idx = 0;
        GUID guid;
        char name[IF_NAMESIZE];
        WCHAR wname[IF_NAMESIZE];
        U_CHECK("ConvertInterfaceIndexToLuid(1) = loopback LUID", ConvertInterfaceIndexToLuid(1, &luid) == NO_ERROR && luid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK && luid.Info.NetLuidIndex == 0);
        U_CHECK("ConvertInterfaceLuidToIndex round-trips", ConvertInterfaceLuidToIndex(&luid, &idx) == NO_ERROR && idx == 1);
        U_CHECK("ConvertInterfaceLuidToNameA gives \"loopback_0\" (Windows' <type>_<NetLuidIndex> form)", ConvertInterfaceLuidToNameA(&luid, name, sizeof name) == NO_ERROR && !strcmp(name, "loopback_0"));
        U_CHECK("ConvertInterfaceLuidToNameW gives the same name, and a 5-character buffer is ERROR_NOT_ENOUGH_MEMORY", ConvertInterfaceLuidToNameW(&luid, wname, IF_NAMESIZE) == NO_ERROR && u_ascii_eq_w(wname, "loopback_0") && ConvertInterfaceLuidToNameW(&luid, wname, 5) == ERROR_NOT_ENOUGH_MEMORY);
        U_CHECK("ConvertInterfaceNameToLuidW(\"loopback_0\") round-trips; an unknown name is ERROR_INVALID_NAME", ConvertInterfaceNameToLuidW(L"loopback_0", &back) == NO_ERROR && back.Value == luid.Value && ConvertInterfaceNameToLuidW(L"tunnel_9", &back) == ERROR_INVALID_NAME);
        U_CHECK("ConvertInterfaceLuidToGuid / ConvertInterfaceGuidToLuid round-trip", ConvertInterfaceLuidToGuid(&luid, &guid) == NO_ERROR && ConvertInterfaceGuidToLuid(&guid, &back) == NO_ERROR && back.Value == luid.Value);
        U_CHECK("if_indextoname(1) = loopback_0, if_nametoindex(loopback_0) = 1", if_indextoname(1, name) == name && !strcmp(name, "loopback_0") && if_nametoindex("loopback_0") == 1);
        U_CHECK("if_indextoname(unknown) = NULL, if_nametoindex(unknown) = 0", if_indextoname(99, name) == 0 && if_nametoindex("ethernet_77") == 0);
        if (nic) {
            U_CHECK("with a NIC: index 2 is ethernet_1 and its LUID has type 6", ConvertInterfaceIndexToLuid(2, &luid) == NO_ERROR && luid.Info.IfType == IF_TYPE_ETHERNET_CSMACD && if_indextoname(2, name) && !strcmp(name, "ethernet_1"));
            U_CHECK("ConvertInterfaceLuidToAlias(ethernet) = \"Ethernet\"", ConvertInterfaceLuidToAlias(&luid, wname, IF_NAMESIZE) == NO_ERROR && u_ascii_eq_w(wname, "Ethernet"));
        }
        luid.Value = 0x1234;
        U_CHECK("an unknown LUID is ERROR_FILE_NOT_FOUND", ConvertInterfaceLuidToIndex(&luid, &idx) == ERROR_FILE_NOT_FOUND && ConvertInterfaceLuidToGuid(&luid, &guid) == ERROR_FILE_NOT_FOUND);
    }

    /* ---------------- addresses and routes ---------------- */
    {
        PMIB_UNICASTIPADDRESS_TABLE t = 0;
        PMIB_IPINTERFACE_TABLE it = 0;
        MIB_IPINTERFACE_ROW ir;
        ULONG want = 1 + (nic && (in.flags & 4) && in.ip_be ? 1 : 0);
        rc = GetUnicastIpAddressTable(AF_INET, &t);
        U_CHECKF("GetUnicastIpAddressTable(AF_INET): one row per configured address, 127.0.0.1 first", rc == NO_ERROR && t && t->NumEntries == want && t->Table[0].Address.Ipv4.sin_addr.s_addr == bs32(0x7f000001u) && t->Table[0].OnLinkPrefixLength == 8 && t->Table[0].InterfaceIndex == 1, "rc=%u n=%u", (unsigned)rc, t ? (unsigned)t->NumEntries : 0u);
        if (rc == NO_ERROR) {
            if (want == 2) U_CHECK("...the Ethernet row carries the kernel's address and the DHCP origin", t->Table[1].Address.Ipv4.sin_addr.s_addr == in.ip_be && t->Table[1].InterfaceIndex == 2 && t->Table[1].PrefixOrigin == ((in.flags & 8) ? IpPrefixOriginDhcp : IpPrefixOriginManual));
            FreeMibTable(t);
        }
        U_CHECK("GetUnicastIpAddressTable(AF_INET6) is empty", GetUnicastIpAddressTable(AF_INET6, &t) == NO_ERROR && t && t->NumEntries == 0);
        FreeMibTable(t);
        U_CHECK("GetIpInterfaceTable(AF_INET) has every interface with Family AF_INET", GetIpInterfaceTable(AF_INET, &it) == NO_ERROR && it && it->NumEntries == (ULONG)(1 + nic) && it->Table[0].Family == AF_INET && it->Table[0].Connected);
        FreeMibTable(it);
        memset(&ir, 0, sizeof ir);
        ir.Family = AF_INET;
        ir.InterfaceIndex = 1;
        U_CHECK("GetIpInterfaceEntry(AF_INET, 1): NlMtu 0xffffffff, Metric 75 (Windows' loopback metric)", GetIpInterfaceEntry(&ir) == NO_ERROR && ir.NlMtu == 0xffffffffu && ir.Metric == 75 && ir.InterfaceLuid.Info.IfType == IF_TYPE_SOFTWARE_LOOPBACK);
        U_CHECK("GetIpInterfaceEntry with an unknown family is ERROR_INVALID_PARAMETER", (ir.Family = AF_IPX, GetIpInterfaceEntry(&ir)) == ERROR_INVALID_PARAMETER);
    }
    {
        MIB_IPFORWARD_ROW2 route;
        SOCKADDR_INET dst, src;
        DWORD idx = 0;
        memset(&dst, 0, sizeof dst);
        dst.Ipv4.sin_family = AF_INET;
        dst.Ipv4.sin_addr.s_addr = bs32(0x7f000001u);
        U_CHECK("GetBestRoute2(127.0.0.1): loopback interface, /32 route, next hop 0.0.0.0, Loopback flag", GetBestRoute2(0, 0, 0, &dst, 0, &route, &src) == NO_ERROR && route.InterfaceIndex == 1 && route.DestinationPrefix.PrefixLength == 32 && route.NextHop.Ipv4.sin_addr.s_addr == 0 && route.Loopback && src.Ipv4.sin_addr.s_addr == bs32(0x7f000001u));
        U_CHECK("GetBestInterface(127.0.0.1) = 1", GetBestInterface(bs32(0x7f000001u), &idx) == NO_ERROR && idx == 1);
        dst.Ipv4.sin_addr.s_addr = bs32(0xc0000201u);                   /* 192.0.2.1 (TEST-NET-1, never on-link here) */
        if (nic && (in.flags & 2) && (in.flags & 4) && in.gw_be) {
            U_CHECK("GetBestRoute2(192.0.2.1) goes through the Ethernet adapter via the DHCP gateway", GetBestRoute2(0, 0, 0, &dst, 0, &route, &src) == NO_ERROR && route.InterfaceIndex == 2 && route.NextHop.Ipv4.sin_addr.s_addr == in.gw_be && !route.Loopback && src.Ipv4.sin_addr.s_addr == in.ip_be);
            U_CHECK("GetBestInterface(192.0.2.1) = 2", GetBestInterface(bs32(0xc0000201u), &idx) == NO_ERROR && idx == 2);
            dst.Ipv4.sin_addr.s_addr = in.ip_be;
            U_CHECK("GetBestRoute2(own address) is a loopback route", GetBestRoute2(0, 0, 0, &dst, 0, &route, &src) == NO_ERROR && route.InterfaceIndex == 1 && route.Loopback);
        } else {
            U_CHECK("GetBestRoute2(192.0.2.1) without an uplink is ERROR_NETWORK_UNREACHABLE", GetBestRoute2(0, 0, 0, &dst, 0, &route, &src) == ERROR_NETWORK_UNREACHABLE);
            U_CHECK("GetBestInterface(192.0.2.1) without an uplink is ERROR_NETWORK_UNREACHABLE", GetBestInterface(bs32(0xc0000201u), &idx) == ERROR_NETWORK_UNREACHABLE);
        }
        dst.si_family = AF_INET6;
        U_CHECK("GetBestRoute2(IPv6 destination) is ERROR_NETWORK_UNREACHABLE (no IPv6)", GetBestRoute2(0, 0, 0, &dst, 0, &route, &src) == ERROR_NETWORK_UNREACHABLE);
        U_CHECK("GetBestRoute2(NULL destination) is ERROR_INVALID_PARAMETER", GetBestRoute2(0, 0, 0, 0, 0, &route, &src) == ERROR_INVALID_PARAMETER);
    }
    {
        ULONG sz = 0;
        PMIB_IPFORWARDTABLE ft = (PMIB_IPFORWARDTABLE)buf;
        PMIB_IPADDRTABLE at = (PMIB_IPADDRTABLE)buf;
        U_CHECK("GetIpForwardTable: size query then the table, with the 127.0.0.0/8 loopback route", GetIpForwardTable(0, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER && sz && GetIpForwardTable(ft, &sz, FALSE) == NO_ERROR && ft->dwNumEntries >= 2 && ft->table[ft->dwNumEntries - 2].dwForwardDest == bs32(0x7f000000u) && ft->table[ft->dwNumEntries - 2].dwForwardMask == bs32(0xff000000u) && ft->table[ft->dwNumEntries - 2].dwForwardIfIndex == 1);
        sz = 0;
        U_CHECK("GetIpAddrTable: 127.0.0.1/255.0.0.0 on index 1, primary", GetIpAddrTable(0, &sz, FALSE) == ERROR_INSUFFICIENT_BUFFER && GetIpAddrTable(at, &sz, FALSE) == NO_ERROR && at->dwNumEntries >= 1 && at->table[0].dwAddr == bs32(0x7f000001u) && at->table[0].dwMask == bs32(0xff000000u) && at->table[0].dwIndex == 1 && at->table[0].wType == MIB_IPADDR_PRIMARY);
    }

    /* ---------------- legacy adapter calls ---------------- */
    {
        ULONG sz = 0;
        rc = GetAdaptersInfo(0, &sz);
        if (nic) {
            PIP_ADAPTER_INFO ai = (PIP_ADAPTER_INFO)buf;
            U_CHECKF("GetAdaptersInfo(NULL): ERROR_BUFFER_OVERFLOW with one IP_ADAPTER_INFO", rc == ERROR_BUFFER_OVERFLOW && sz == sizeof(IP_ADAPTER_INFO), "rc=%u sz=%u", (unsigned)rc, (unsigned)sz);
            rc = GetAdaptersInfo(ai, &sz);
            U_CHECK("GetAdaptersInfo: the Ethernet adapter (loopback excluded), MAC, index 2, dotted-decimal address", rc == NO_ERROR && !ai->Next && ai->Index == 2 && ai->Type == MIB_IF_TYPE_ETHERNET && ai->AddressLength == 6 && !memcmp(ai->Address, in.mac, 6) && ai->AdapterName[0] == '{' && ai->DhcpEnabled == ((in.flags & 8) != 0) && strchr(ai->IpAddressList.IpAddress.String, '.'));
            if (in.flags & 8) U_CHECK("GetAdaptersInfo: LeaseExpires - LeaseObtained = the lease time", ai->LeaseExpires - ai->LeaseObtained == (time_t)in.lease_secs);
        } else {
            U_CHECKF("GetAdaptersInfo without a NIC is ERROR_NO_DATA (the loopback is never listed)", rc == ERROR_NO_DATA, "rc=%u", (unsigned)rc);
        }
        sz = 0;
        rc = GetInterfaceInfo(0, &sz);
        if (nic) {
            PIP_INTERFACE_INFO ii = (PIP_INTERFACE_INFO)buf;
            IP_ADAPTER_INDEX_MAP map;
            U_CHECK("GetInterfaceInfo: size query, then one \\DEVICE\\TCPIP_{guid} adapter with index 2", rc == ERROR_INSUFFICIENT_BUFFER && GetInterfaceInfo(ii, &sz) == NO_ERROR && ii->NumAdapters == 1 && ii->Adapter[0].Index == 2 && ii->Adapter[0].Name[0] == '\\' && ii->Adapter[0].Name[8] == 'T');
            map = ii->Adapter[0];
            U_CHECK("IpReleaseAddress fails explicitly with ERROR_NOT_SUPPORTED (the kernel has no DHCP release)", IpReleaseAddress(&map) == ERROR_NOT_SUPPORTED);
            map.Index = 1;
            U_CHECK("IpRenewAddress on the loopback index is ERROR_INVALID_PARAMETER", IpRenewAddress(&map) == ERROR_INVALID_PARAMETER);
        } else {
            U_CHECK("GetInterfaceInfo without a NIC is ERROR_NO_DATA", rc == ERROR_NO_DATA);
        }
        {
            IP_ADAPTER_INDEX_MAP bad;
            bad.Index = 55;
            U_CHECK("IpRenewAddress / IpReleaseAddress with an unknown index are ERROR_INVALID_PARAMETER", IpRenewAddress(&bad) == ERROR_INVALID_PARAMETER && IpReleaseAddress(&bad) == ERROR_INVALID_PARAMETER && IpRenewAddress(0) == ERROR_INVALID_PARAMETER);
        }
        sz = 0;
        rc = GetNetworkParams(0, &sz);
        U_CHECK("GetNetworkParams(NULL): ERROR_BUFFER_OVERFLOW with at least sizeof(FIXED_INFO)", rc == ERROR_BUFFER_OVERFLOW && sz >= sizeof(FIXED_INFO));
        rc = GetNetworkParams((PFIXED_INFO)buf, &sz);
        U_CHECK("GetNetworkParams: the computer name, hybrid node type, DNS enabled", rc == NO_ERROR && ((PFIXED_INFO)buf)->HostName[0] && ((PFIXED_INFO)buf)->NodeType == HYBRID_NODETYPE && ((PFIXED_INFO)buf)->EnableDns == 1);
        if (nic && in.dns0_be) U_CHECK("GetNetworkParams: the first DNS server is the one DHCP supplied", strchr(((PFIXED_INFO)buf)->DnsServerList.IpAddress.String, '.') != 0);
    }

    /* ---------------- statistics ---------------- */
    {
        MIB_IPSTATS ip; MIB_TCPSTATS tcp; MIB_UDPSTATS udp; DWORD n = 0;
        U_CHECK("GetIpStatistics: not forwarding, TTL 64, dwNumIf = the interface count, dwNumAddr >= 1", GetIpStatistics(&ip) == NO_ERROR && ip.dwForwarding == MIB_IP_NOT_FORWARDING && ip.dwDefaultTTL == 64 && ip.dwNumIf == (DWORD)(1 + nic) && ip.dwNumAddr >= 1);
        U_CHECK("GetTcpStatistics: Van Jacobson RTO, unlimited connections", GetTcpStatistics(&tcp) == NO_ERROR && tcp.dwRtoAlgorithm == MIB_TCP_RTO_VANJ && tcp.dwMaxConn == (DWORD)-1);
        U_CHECK("GetUdpStatistics succeeds; the IPv6 variants fail explicitly with ERROR_NOT_SUPPORTED", GetUdpStatistics(&udp) == NO_ERROR && GetIpStatisticsEx(&ip, AF_INET6) == ERROR_NOT_SUPPORTED && GetTcpStatisticsEx(&tcp, AF_INET6) == ERROR_NOT_SUPPORTED);
        U_CHECK("GetNumberOfInterfaces counts loopback + NIC", GetNumberOfInterfaces(&n) == NO_ERROR && n == (DWORD)(1 + nic));
        {
            ULONG sz = 0;
            rc = GetTcpTable(0, &sz, TRUE);
            U_CHECK("GetTcpTable: size query is ERROR_INSUFFICIENT_BUFFER, then the kernel's connection table", rc == ERROR_INSUFFICIENT_BUFFER && sz >= FIELD_OFFSET(MIB_TCPTABLE, table) && GetTcpTable((PMIB_TCPTABLE)buf, &sz, TRUE) == NO_ERROR);
        }
    }

    /* ---------------- change notification ---------------- */
    {
        OVERLAPPED ovl;
        HANDLE h = 0, cb = 0;
        memset(&ovl, 0, sizeof ovl);
        ovl.hEvent = CreateEventW(0, TRUE, FALSE, 0);
        rc = NotifyAddrChange(&h, &ovl);
        U_CHECKF("NotifyAddrChange with an OVERLAPPED returns ERROR_IO_PENDING, a handle and a pending status", rc == ERROR_IO_PENDING && h && ovl.Internal == (ULONG_PTR)STATUS_PENDING, "rc=%u", (unsigned)rc);
        U_CHECK("...and the event stays unsignalled while nothing changes (400 ms)", WaitForSingleObject(ovl.hEvent, 400) == WAIT_TIMEOUT);
        U_CHECK("CancelIPChangeNotify completes it: event set, Internal = STATUS_CANCELLED", CancelIPChangeNotify(&ovl) && WaitForSingleObject(ovl.hEvent, 0) == WAIT_OBJECT_0 && ovl.Internal == (ULONG_PTR)0xC0000120);
        U_CHECK("cancelling it again fails", !CancelIPChangeNotify(&ovl));
        U_CHECK("NotifyAddrChange(NULL handle) is ERROR_INVALID_PARAMETER", NotifyAddrChange(0, &ovl) == ERROR_INVALID_PARAMETER);
        ResetEvent(ovl.hEvent);
        U_CHECK("NotifyRouteChange follows the same contract", NotifyRouteChange(&h, &ovl) == ERROR_IO_PENDING && CancelIPChangeNotify(&ovl) && WaitForSingleObject(ovl.hEvent, 0) == WAIT_OBJECT_0);
        CloseHandle(ovl.hEvent);
        rc = NotifyIpInterfaceChange(AF_UNSPEC, ipif_cb, (PVOID)0x1234, TRUE, &cb);
        U_CHECKF("NotifyIpInterfaceChange(InitialNotification) calls back once with a NULL row and MibInitialNotification", rc == NO_ERROR && cb && g_cb_initial == 1 && g_cb_calls == 1, "rc=%u init=%d calls=%d", (unsigned)rc, (int)g_cb_initial, (int)g_cb_calls);
        U_CHECK("CancelMibChangeNotify2 unregisters; a second cancel is ERROR_INVALID_PARAMETER", CancelMibChangeNotify2(cb) == NO_ERROR && CancelMibChangeNotify2(cb) == ERROR_INVALID_PARAMETER);
        U_CHECK("NotifyIpInterfaceChange(NULL callback) is ERROR_INVALID_PARAMETER", NotifyIpInterfaceChange(AF_INET, 0, 0, FALSE, &cb) == ERROR_INVALID_PARAMETER);
    }
    return u_finish("t_u_iphlpapi");
}
