# WS2 legacy import family

The fixed Windows ordinals 51/53/54/56 now select gethostbyaddr,
getprotobyname, getprotobynumber and getservbyport. WSAEnumProtocolsA is a
named export with a provider-private ordinal above 500. Existing modern
private ordinals remain unchanged; every other absent legacy slot stays zero.

The service lookup reads actual system drivers/etc/services. The port argument
and returned s_port are network order; NULL protocol selects the first matching
record. Name and port calls reuse the calling thread's service structure.
Protocols come from the real drivers/etc/protocols file, including canonical
name, aliases and a host-order protocol number. Hosts reverse lookup reads
actual IPv4 drivers/etc/hosts records, canonical names, aliases and addresses.
Missing files/read failures return WSANO_RECOVERY, absent entries return
WSAHOST_NOT_FOUND, a known service with another protocol returns WSANO_DATA.
All three files are opened read-only and bounded to 16 MiB. No embedded database
or numeric/localhost fallback is introduced. IPv6, NetBIOS and DNS PTR reverse
providers remain absent; reverse results outside the actual hosts catalog fail.
The existing forward resolver behavior is retained, with its returned hostent
adapted to the same per-thread storage as gethostbyaddr. Service, protocol and
host records have separate payloads. Allocation failure retains the previous
borrowed record; thread exit/normal unload frees each owned payload exactly once.

ANSI enumeration uses the exact existing wide TCP/IPv4 and UDP/IPv4 transport
metadata. Windows A/W layouts and byte sizes are asserted. The real provider's
ASCII descriptions convert exactly; buffer sizing, filters and absence errors
are honored. No unsupported transport is inserted into the enumeration.

Primary contracts: Microsoft [getservbyport](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getservbyport),
[getprotobyname](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-getprotobyname),
[gethostbyaddr](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-gethostbyaddr)
and [WSAEnumProtocolsA](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaenumprotocolsa).
Pinned Wine db11d0fe6a169c457e23d007e20404643d067aa8 ws2_32.spec supplies the
canonical ordinal declarations. No Wine implementation body is copied.

Host tests use explicit Windows file/heap/TLS adapters and temporary copies of
the actual host services, protocols and hosts files. Catalog provenance is
recorded; the host files are not modified. Host adapters are separate from
native provider evidence. The compiled native fixture checks actual named/
ordinal bindings, real catalogue records, common forward/reverse storage,
real A/W metadata, a real socket opened from ANSI metadata and live native
thread isolation. Root alone owns actual guest/application execution.
