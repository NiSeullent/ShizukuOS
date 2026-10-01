# Trident HTTPS integration handoff

The user requires modern Trident-based web support; a complete WebKit port is
not a prerequisite. This handoff identifies an existing browser seam and the
implementation still needed. It is not a working HTTPS consumer or evidence
of modern HTML/CSS/JavaScript/WebAssembly conformance.

## Existing native browser seam

The retained native IE snapshot is
`/root/Win98-Modern-boot/build/iewebkit-win98-ie5-browser-83bd/source/host/`.
Its `navigation_handoff.cpp` registers a process-local URLMon `https`
namespace with `CoInternetGetSession` and `RegisterNameSpace`. The normal BHO
in `navigation_bho.cpp` enables it only when its separate engine is ready.

`HandoffProtocol::Start` accepts one explicitly armed URL and bodyless GET.
It reports a custom DocObject CLSID and
`application/x-iewebkit-document`, then zero response bytes. Its `Read`
returns `S_FALSE` with zero bytes. Nonmatching requests delegate to an
explicitly created `CLSID_HttpSProtocol`. These behaviors establish a
navigation handoff, not TLS transport or an HTML loader.

`/root/Win98-Modern-boot/tools/iewebkit_port/core_ie_protocol_native.cpp`
opens a separate `CLSID_InternetExplorer` local-server process. Loading a TLS
DLL in that external harness would not select it inside IE's URLMon process.
`ntwin32/legacy_provider_bridge/native.c` dispatches five other Windows DLL
tables; it has no Secur32 or WinINet table. Neither inspected browser tree
contains an existing `M98SSPI` consumer.

## Smallest separate implementation

Implement a real-byte `IInternetProtocol` HTTPS consumer inside IE's STA or
an in-process WebBrowser host. Load the private `M98SSPI.dll` explicitly;
select its ANSI function table and supported call shapes from
`sspi_native_HANDOFF.md`. Connect credential/context initialization and
authenticated record encryption/decryption to actual Winsock input/output.
Honor MISSING, EXTRA, retained-token retries, authenticated closure and
`M98SspiEndInput` on transport EOF. Keep the DLL alive through every context,
credential, owned token and callback.

Parse a real HTTP response, report its actual HTML MIME/body, and return
those authenticated bytes through `ReportData` and `Read`. Complete async
notifications, cancellation, `Abort`/`Terminate`, callback reentry,
redirect/URL policy, bounds and cleanup before treating it as a browser
transport. The existing empty custom-DocObject route cannot substitute for
these operations. This separate route can feed existing Trident without
waiting for a full WebKit engine. It does not supply new DOM/layout or JS/WASM
features by itself.

First acceptance should use a real Winsock loopback TLS server and a page in
the genuine disposable Win98 guest. Verify exact response bytes, Trident DOM
and visible content, wrong hostname/root, altered/truncated records,
fragmentation, cancellation, repeated navigation and full caller exit.
Public-site trust and OS-wide provider dispatch need separate acceptance.
The adapter currently validates certificates with its TLS engine and bounded
native ROOT snapshots; this is not complete Windows chain-policy parity.

## Ownership and execution boundaries

The native IE snapshot/protocol evidence belongs to boot session 83bd. Its
canonical `/home/almalinux/workspace/iewebkit` source belongs to a separate
IE session. Coordinate source ownership before changes; the snapshot above
was reviewed read-only. The browser/Win64 app work in
`Win98-Modern-codex-20260930` and `Win98-Modern-apps-cb43` belongs to cb43.

The current campaign report records separate x64 Steam TLS/Valve downloads.
That runtime is not a native x86 `M98SSPI` consumer. Disabled Wine
Secur32/WinHTTP entries in an older inspected source snapshot do not disprove
the newer separate campaign, and its success does not prove this x86 route.

The 7707 changes remain in `ntwin32/secure_transport`. Do not modify original
system DLLs, globally register a provider, change trust stores, or mutate
another session's browser/VM as part of this handoff. Store-reading uses
explicit existing/read-only flags; missing stores fail without creation.
Actual native DLL/ROOT, socket/URLMon, browser standards and application
acceptance must retain distinct verdicts.
