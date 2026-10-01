# Winsock service lookup

`getservbyname` uses the system `drivers\etc\services` file through real read-only
file calls. It returns the file's canonical name, all aliases, selected protocol,
and network-order 16-bit port in the Windows AMD64 `SERVENT` layout. A NULL
protocol selects the first matching record. No synthetic service table is used.

Unknown names return `WSAHOST_NOT_FOUND`; a known name with no requested protocol
record returns `WSANO_DATA`; an unavailable or unreadable database
returns `WSANO_RECOVERY`; storage/TLS failures return `WSAENOBUFS`. Successful
lookup requires `WSAStartup`. Per-thread storage survives fiber changes, is
replaced by that thread's next successful service query, and is released by
thread detach or normal DLL unload. Process termination skips locks while the
OS reclaims process resources. Service name/port queries share their per-thread
structure; forward/reverse host queries share a separate host structure, as
described in [the legacy family](README-ws2-legacy.md).

The host runner copies the explicitly selected catalog into its owned temporary
system directory. Positive service, alias, and high-port expectations
come from that genuine catalog and the host OS lookup. GCC and Clang sanitizers
exercise the exact production block, actual file reads, thread isolation, stale
TLS values, absent database, unknown names/protocols, partial reads and primitive
failure cleanup. API adapters are host contract evidence.

The native fixture requires an OS catalog containing HTTP/TCP with `www`,
FTP/TCP and domain/UDP. It never writes the catalog. The root integration owner
includes the pinned public Debian netbase/Alpine catalogs through
`tools/public_network_catalogs.py` in both runtime archives. No host configuration
is copied or changed. The actual PE export check must prove `getservbyname` is
ordinal 55 and differs from `WSAResetEvent`; the native fixture verifies the
implemented ordinal 56 selects `getservbyport` and actually calls it. Other
absent legacy ordinals remain empty. Newer named exports use provider-private
ordinals at 501 or above, without claiming undocumented Windows numbers.

Primary contracts: [Microsoft getservbyname](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-getservbyname),
[Microsoft SERVENT](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/ns-winsock2-servent),
and pinned [Wine ordinal specification](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ws2_32/ws2_32.spec)
and [service-file implementation](https://github.com/wine-mirror/wine/blob/db11d0fe6a169c457e23d007e20404643d067aa8/dlls/ws2_32/protocol.c).
Production code is an original GPL implementation; no Wine function body is copied.
