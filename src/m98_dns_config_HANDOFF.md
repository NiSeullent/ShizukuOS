# Opt-in native DNS configuration adapter

`M98DNS.DLL` exports only the standard six-argument stdcall `DnsQueryConfig`.
It reads the actual installed system `IPHLPAPI.DLL!GetNetworkParams`. It does
not send a DNS request, resolve a name, supply DNS records, install a DLL,
write registry settings, register with KernelEx, or update a peer loader.

Build with `python3 tools/build_dns_config.py` into `build/dns-config-v2`.
Historical `build/dns-config` v1 receipts and binaries remain unchanged.
Optimized Python execution is rejected before any output mutation.
The normal host controls and
ASan/UBSan controls exercise real bounded binary/string marshaling, malformed
linked lists, output ownership and allocation failure. The PE gates verify
i486 PE32 GUI OS/subsystem4.10, original OEM KERNEL32 imports only, relocation,
zero timestamp, and absent static TLS/load-config/delay/CLR directories.
Both PE files explicitly reserve2MiB/commit64KiB of stack, covering the bounded
combined probe/provider/core call stack without compiler stack probing.
These results establish no native execution or application functionality.

## Public request and snapshot contract

Implemented types: primary domain (0/1/2), IPv4 DNS-server list (6), host name
(12/13/14), and fully qualified host name (15/16/17). String variants are
UTF16, exact current ACP bytes and UTF8, respectively. An IP Helper hostname
that is already qualified is retained verbatim for FQDN output, even when its
suffix differs in case or from the separately configured domain. Host-only
queries return its first label. A short host is combined with the actual
nonempty domain for FQDN output; an empty host remains empty. Sizes are bytes,
including the terminating NUL. With flags0 a NULL string buffer or short
string buffer returns122; a NULL server buffer returns0 and the required
size, while a short non-NULL server buffer returns234. Successful calls update
the byte count. Server output is the little-endian count followed by original
network-order IPv4 bytes. Exact duplicate addresses are removed in original
order; empty/zero provider entries represent no configured address. An empty
real server list is a successful four-byte count0, with no invented server.

Flags1 treats `pBuffer` as a pointer to a pointer, ignores the incoming byte
count, allocates one exact `LMEM_FIXED` block and publishes it only on success.
The caller owns it and frees it with the original `LocalFree`. Failed allocation
returns8 with the pointer and length unchanged. Other flags, missing length,
non-NULL reserved data, or missing allocation outputs return87. Any adapter
pointer or unsupported type returns50. These errors and capture errors leave
caller outputs untouched. Adapter-specific settings, registration policy,
search suffix lists, IPv6 DNS servers and modern extended configuration
types are unavailable. Invalid memory supplied by callers is subject to
ordinary Win32 pointer requirements; this is not a memory-safety sandbox.

The independently authored portable `m98_dns_snapshot` ABI contains bounded
ACP and UTF16 host/domain strings and up to64 actual IPv4 addresses. A peer
backend can populate it from actual DHCP/IPHLPAPI state, then call
`m98_dns_query`; it must supply mutually coherent lossless ACP/UTF16 strings.
The query copies the result and requires a stable snapshot and serialized
non-reentrant allocator callback for the duration of the call. There is no
global snapshot or cross-process cache. Kernel64's existing real IP Helper
backend can reuse the core without editing or pretending to supply Win98
network/graphics services. It must bind the actual standard module/export
requested by an application and implement other requested DNS APIs separately.

The Win98 capture parser takes the original32-bit FIXED_INFO layout plus its
real virtual base. It validates every complete list node inside the owned
allocation, rejects cycles, overlapping nodes, pointers into unrelated fields,
truncations and malformed IPv4 strings. Microsoft's reserved CurrentDnsServer
field is ignored completely. It accepts only the embedded head or aligned appended
nodes. Snapshots remain untouched on failure. The system module is loaded by
absolute system-directory path and checked against the loaded module path.
The bounded dynamic buffer retries allow genuine configuration growth.
ACP conversions use Win98-compatible flags0 with exact byte roundtrip and
reject substitutions or changed best fits. No UTF8 OS API is required.

## Native probe handoff

Freeze `build/dns-config-v2/result.json`, `M98DNS.DLL` and `M98DNSPR.EXE` hashes.
Copy the two binaries to the same new writable directory of a disposable
installed Win98 SE clone. Run `M98DNSPR.EXE fresh-unique-nonce` in that directory.
It creates `DNSCF.LOG` with `CREATE_NEW`, refusing to overwrite any prior log.
The probe requires actual Win98 SE4.10/build-low2222, records the loaded module
path and real host/domain/server settings, binds the DLL to the probe's absolute
EXE-directory path, independently calls the installed GetNetworkParams
provider and derives expected ANSI/UTF16/UTF8/FQDN bytes from that direct
snapshot. It tests short-buffer, allocated-output and actual
LocalFree behavior. There is no NIC or DNS transaction requirement. An empty
real DNS list is logged as `EMPTY_DNS_SETTINGS=1`, never as successful resolution.

Retain the immutable binary hashes, fresh nonce, actual stopped-guest log and
externally observed full child exit0 before calling native configuration PASS.
Source/build output alone is `native_win98=not_tested`. Configuration PASS
cannot establish DNS lookup, TLS sockets, app online functionality or a
Windows98→64-bit application display/input bridge.

## Source and license lineage

All new source is original GPL-2.0-only project code. No Wine/ReactOS
implementation body was copied; compiler SDK headers are build dependencies.
The public [Microsoft DnsQueryConfig contract](https://learn.microsoft.com/en-us/windows/win32/api/windns/nf-windns-dnsqueryconfig),
[DNS_CONFIG_TYPE values](https://learn.microsoft.com/en-us/windows/win32/api/windns/ne-windns-dns_config_type),
[IP4_ARRAY layout](https://learn.microsoft.com/en-us/windows/win32/api/windns/ns-windns-ip4_array),
and [GetNetworkParams contract](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getnetworkparams)
were consulted. Microsoft's GetNetworkParams remarks explicitly include Win98.
The [FIXED_INFO field contract](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-fixed_info_w2ksp1)
defines the reserved current pointer and potentially already-qualified host.
Pinned [Wine query.c](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/dnsapi/query.c)
(LGPL-2.1-or-later) was reviewed for server-list sizing and query boundaries.
Its NT/Unix resolver and its incomplete flag handling are not linked or copied.
The string byte counts and allocation contract follow Microsoft; unsupported
type/adapter failures and stronger bounded provider validation are this
implementation's explicit limits, not a claim of the complete DNSAPI surface.
