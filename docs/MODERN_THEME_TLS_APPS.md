# Modern theme, TLS 1.3 and application checkpoint

The requested target remains functioning themes, current Legcord/Discord,
Signal and open-source Office, broader modern application support, and OS TLS
1.3. The new components are working foundations. Actual installed Windows 98 component API and comparison-screen evidence is now retained.
System API integration and functional application runs remain acceptance gates.
The browser direction is now Trident modernization toward HTML5, WebAssembly
and current JavaScript standards. A full WebKit port is optional. See
`TRIDENT_MODERNIZATION_HANDOFF.md` for the inspected integration seams and limits.

## Theme implementation

`tools/build_theme_engine.py` builds a standalone, opt-in `M98THEME.DLL`
and Windows 98 probes below `build/theme-engine/`. The DLL uses the existing
`ntwddm` painter and native GDI rather than returning a theme-shaped success
without painting. It provides actual Classic/Modern pushbutton states and
window caption/frame drawing, colors, margins, message fonts, and text.

The application selects `M98SetThemeStyle(1)` for Classic or `(2)` for Modern;
`(0)` disables the provider. It then closes/reopens its handles on
`WM_THEMECHANGED`. Unsupported classes, parts and options fail explicitly.
Handles carry generations, style changes invalidate old drawing handles,
and the capacity supports 128 simultaneously open application handles.
Native text must round-trip exactly through the guest code page; unrepresentable
characters fail rather than silently changing text. This is a temporary text
boundary until a full Unicode font/rendering path is available.

The build verifies actual painter/lifecycle behavior, memory safety and the
native PE32/4.10 import/export contract. It also produces dynamic and static
import probes for the guest owner. The existing unthemed UXTHEME/KernelEx
routes are preserved until a new provider is installed and verified. Ordinary
system controls, all modern UXTHEME classes, arbitrary `.msstyles` files,
and automatic shell/non-client interception have not been implemented here.

## Native theme execution

The frozen v1 direct and static-import probes both passed on an actual installed
Korean Windows 98 SE4.10/build2222 guest, with the supervisor observing full
child exit0 and successful output flush/close. The production DLL is unchanged.
A fresh v3 trial captured visible Classic/Modern fills, borders and labels for
both separately titled modes, plus ACP949 and the direct child exit0. Its manual
finish occurred just before the final static child completed; the current static
probe completion remains unverified. Original v1, interrupted v2 and partial v3
receipts remain distinct. The ignored `build/theme-engine/native-v3-visual-review.json`
binds the two reviewed frames to their hashes and records this limitation.

## Transport TLS 1.3 implementation

`tools/build_tls13.py` pins official **Mbed TLS 4.2.0** and its included
**TF-PSA-Crypto 1.2.0**. The archive SHA-256 is
`2bed9d713b4668f76553b097e72b8aa30bc8f112a940d7ae228d524bbde6ffea`.
The exact LICENSE files offer Apache-2.0 OR GPL-2.0-or-later; this build selects
GPL version 2. Sources remain in ignored private build storage and are verified
against the pinned archive on every build.

`src/m98_tls13.h` exposes a callback-based client. It requires an already seeded
CSPRNG, reliable UTC clock, explicit trust anchors, expected DNS hostname and
bounded transport callbacks. It enforces TLS 1.3, certificate verification and
SNI, rejects missing prerequisites, and permits application data only after
verified handshake completion. One client may exist at a time until the global
PSA state receives a reviewed concurrency adapter. Calls and callbacks must
follow the header's serialization/lifetime contract.

`tests/m98_tls13_integration.py` starts temporary servers bound to `127.0.0.1`
and tests actual encrypted HTTP request/response plus rejection of incorrect
hostnames, untrusted/expired certificates, failed entropy, invalid clocks and
TLS 1.2-only servers. Fragmented records and retryable I/O exercise the BIO.
`tests/m98_tls13_pe98.py` separately verifies the cross-built Win98 DLL.

This component is not yet wired into OS Schannel, WinHTTP or WinINet. The
Kernel64 `secur32` and `winhttp` implementations require their own credential,
context, socket and HTTP state-machine integration. Electron's own TLS and
native modules require additional compatibility work. `ntwin32/tls` continues
to mean PE thread-local storage; it is unrelated to encrypted network transport.

Primary dependency sources: [Mbed TLS 4.2.0 release](https://github.com/Mbed-TLS/mbedtls/releases/tag/mbedtls-4.2.0),
[exact license](https://raw.githubusercontent.com/Mbed-TLS/mbedtls/mbedtls-4.2.0/LICENSE).

## Native TLS and OS adapter work

A frozen no-CRT GUI probe and child supervisor load the latest client DLL and
an independent Mbed TLS3.6.7 server DLL in a fresh Windows98 guest. Each DLL
owns separate PSA state. The fixture uses actual CryptoAPI randomness and UTC,
real TLS1.3 records, bounded memory queues, authenticated bidirectional data,
and explicit certificate/entropy/ciphertext rejection. Executables reserve2MiB
and commit64KiB of stack. Host controller and supervisor fault tests are models;
42 evidence-parser regressions refuse missing checks, stale logs and failed
actual child exits. Actual v4 failed its combined handshake predicate and the
supervisor observed child exit1. Original evidence remains preserved. The
fixture incorrectly required zero server certificate flags despite no requested
client certificate; v7 corrects that assertion and logs each endpoint, while
retaining required client certificate/hostname verification and TLS1.3. A real
host latest/LTS exchange observes server flags128 and completes encrypted HTTP
and shutdown. v7 is frozen for a fresh native trial. Its first preparation stopped
before QEMU because concurrent disk growth removed the required copy budget;
zero captures and no probe execution were recorded. A retry still requires stable
space and the shared guest queue. Neither v4 nor the host result is a native
sockets pass. See
`tests/m98_tls13_guest_interop_HANDOFF.md` for exact frozen inputs and readback.

A separate additive `M98NET.DLL` adapter connects the latest backend to Win98
nonblocking TCP, CryptoAPI and UTC, with explicit endpoint, DNS identity, CA and
finite deadlines. Its independently reviewed v3 passes40571 controller and799 native-platform
mock assertions, each normally and under sanitizers, eight real host TCP/TLS
cases, and two Win98 PE/OEM/stack gates. The actual-platform source is exercised
against OS doubles; those results do not establish installed Win98 behavior.
Native networking execution and global provider installation remain unverified.
Schannel/WinHTTP/WinINet consumer integration remains required for OS support.
See `src/m98_tls13_native_HANDOFF.md` for bounds and exact API ownership.
The reviewed source is committed as c39f6c9; native observers and strict evidence
verifiers are committed as b872beb. Neither commit installs a global provider.

## DNS configuration port

Commit66912e3 adds opt-in M98DNS.DLL and an original portable DnsQueryConfig
core, capturing the actual installed IP Helper settings. Supported hostname,
domain/FQDN, ACP/UTF16/UTF8 and IPv4-server results follow byte-sizing and
LocalAlloc/LocalFree ownership. Bounded parsing rejects malformed lists and
never invents a DNS server. Independent review corrected reserved-provider-field,
already-qualified-host, native identity, encoding evidence and stack issues.
The v2 build passes11609 normal and sanitizer checks and two native PE gates.
Native configuration execution, full DNS resolution and application operation
remain unverified. Peer runtime owners can feed their actual DHCP snapshot into
the portable core; their standard-module binding and other DNS exports need
separate integration. See `src/m98_dns_config_HANDOFF.md`.

## Current applications and exact evidence

`benchmarks/modern-app-targets-v1.json` freezes the selected current targets and
required functions. A newer release needs new source/version/hash evidence.
Older successful applications cannot substitute for these targets.

| Application | Selected target | Required execution work |
| --- | --- | --- |
| Legcord / Discord | 1.3.0, Electron 43.2.0, official ia32 ZIP | Modern x86 loader, NT runtime, sockets, graphics/audio and native addon support |
| Signal Desktop | 8.28.0, Electron 44.1.0, libsignal/RingRTC/SQLCipher | Genuine Win64 runtime or current-source x86 port including native dependencies |
| LibreOffice | 26.8.0, current Windows x64/ARM64 packages | Genuine Win64 runtime or current-source x86 port; Writer/Calc/Impress functional tests |

`tools/modern_app_inventory.py` keeps machine/header identity, ordinary and
delay imports, static thread-local storage, load configuration and `.node`
addons. It reads foreign ELF/Mach-O addons separately because a Windows
package may carry optional binaries for multiple platforms. Bundled addon
architectures are not confused with the application's entry-point architecture.
Malformed or incomplete metadata produces a visible error rather than an empty
success. It does not calculate a compatibility percentage or run an executable.

The official Legcord ZIP has been privately downloaded, its publisher digest
verified, and all 224 members CRC checked. The entry point is genuinely ia32
PE32 with subsystem 10.0; its bytes and loader metadata remain untouched.
Its SHA-256 is
`c598fd176f9198f2a4f5639249105126016c1458d3e648e9f7883649f19bfb3c`.
The entry point imports 531 symbols from seven direct modules and 732 from
50 delay modules. These numbers describe porting requirements, not support.
The complete inventory has 25 binaries/addons: ten Windows PE files and 15
foreign addons. `--archive` verifies all regular application payloads, including
`app.asar`, scripts and locales, against the same opened pinned official archive
before reporting target identity verified. Source directory symlinks and special
files are rejected, and file reads are bounded. Foreign identification currently
covers ELF and thin Mach-O; universal Mach-O is not part of this probe corpus.

Primary application evidence is linked beside each target in the manifest.
Private archive and inventory receipts are under
`benchmarks/media/legcord-1.3.0/`; app archives are not committed or redistributed.

## Reproduce the current checks

Run from the repository worktree:

```sh
python3 -m unittest discover -s tests -p test_modern_app_inventory.py -v
python3 tools/build_theme_engine.py
python3 tools/build_tls13.py --profile host --jobs 2
python3 tests/m98_tls13_integration.py
python3 tools/build_tls13.py --profile pe32 --jobs 2
python3 tests/m98_tls13_pe98.py
python3 tools/modern_app_inventory.py --app legcord \
  --root benchmarks/media/legcord-1.3.0/package \
  --archive benchmarks/media/legcord-1.3.0/Legcord-1.3.0-win-ia32.zip \
  --output benchmarks/media/legcord-1.3.0/inventory.json
```

The application inventory command requires its reproducible extracted package;
that copy was removed after all182 payload hashes and the pinned publisher ZIP
were verified to reclaim401MiB. The retained ZIP is sufficient to restore it
when another inventory is needed; no application/source artifact was lost.

The TLS build downloads only its pinned source when absent. Integration tests
create private test certificates/keys and temporary loopback-only servers;
none are production trust material. No command installs a DLL, changes global
client settings, takes over an active VM, or promotes a guest capability.

## Remaining acceptance and coordination

The frozen original direct/static probes have actual native exit0 evidence.
The longer current probes have reviewed comparison frames, but still require
a complete final static child log. Peer6970 owns interactive presentation
integration and its complete redraw/style-switch/exit acceptance. Ordinary
control/shell integration and modern-app theme functionality remain separate.

The TLS native fixture is checking actual DLL, entropy and time prerequisites
with explicit fixture trust. The separate TCP adapter must then pass isolated
real network encrypted request/response and equivalent negative cases. Kernel64's
RNG readiness must be proven before it is used for TLS. System-wide support
also requires the Schannel/WinHTTP/WinINet adapters.

Legcord must pass login, messages, attachments, voice, normal exit and relaunch.
Signal must pass user-owned device linking, messages, attachments, voice and
encrypted database reopening. LibreOffice must create/edit/save/reopen Writer,
Calc and Impress files and export/read back PDF. None has a new functional
Windows 98 pass in this checkpoint.

Peer ownership and handoff are in `docs/modern-apps-coordination-5abe.md`.
The established guest harness maintains a selected20GiB disk reserve and a
measured sparse-copy/dirty budget. A separate disk agent shares only identical
allocations of closed verified experiment copies, retaining full logical hashes,
metadata and evidence. The verified official Legcord archive is retained after
removing its reproducible extracted copy. Free space fluctuates with peer work;
each new trial must pass the unchanged guard and shared native queue check.
The native presentation lane is coordinated with peer6970; peer7707 retains
the independent LTS fixture and cb43/c009 retain application-runtime integration.

The completed host checkpoint passes 312 new theme checks normally and under
ASan/UBSan, the existing ntwddm regression/freestanding checks, 16 real TLS
loopback cases, and 19 application-inventory regression tests. Theme and TLS
artifacts also pass their native PE/import gates. The exact artifacts and
receipts are bound by `docs/MODERN_THEME_TLS_CHECKPOINT.json`; native component evidence is recorded separately, and application functionality
is not promoted by host/PE checks.
