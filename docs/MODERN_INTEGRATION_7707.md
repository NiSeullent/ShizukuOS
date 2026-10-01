# Combined modern themes, TLS and app checkpoint

This private integration branch is `codex/tls13-7707`, based on `abc160b`.
It contains transport commit `2c5e2a6` and peer theme/client/inventory commit
`a12a4a9`, imported as `9560069`. Existing peer worktrees, runtime/kernel
branches, boot images and running guests were not modified by this integration.
The shared ownership ledger acknowledged by peer 5abe is
`/root/Win98-Modern-boot/docs/modern-apps-coordination-7707.md`.

The user target remains actual persistent themes, current Legcord/Discord,
Signal, current open-source Office suites, broad modern applications and
OS TLS 1.3. This is a reproducible source/build checkpoint. It supplies no
new Windows 98 theme, OS TLS or application functional pass.

## Components available together

| Component | Actual behavior | Integration boundary |
| --- | --- | --- |
| `M98THEME.DLL` | Native GDI plus ntwddm Classic/Modern BUTTON/WINDOW rendering, text, theme handles, query properties and style changes | Opt-in application provider; full shell/control interception, settings persistence, all theme classes and guest checks remain pending |
| `M98TLS13.dll` | Mbed TLS 4.2.0/TF-PSA-Crypto 1.2.0 authenticated TLS 1.3 client | Caller-owned CSPRNG, UTC clock, transport and trust anchors; latest client path for adapter work |
| `M98TLS.dll` / `TLS13PROB.exe` | Maintained Mbed TLS 3.6.7 LTS TLS 1.3 client/server and native ANSI CryptoAPI/UTC bridge | Separate backend and offline guest fixture; no automatic OS provider installation |
| `modern_app_inventory.py` | Publisher-bound application tree, PE/import/delay import/static TLS/native addon evidence | Describes requirements; does not execute or score app compatibility |

The two TLS backends have different RNG/status/clock/lifetime contracts.
`m98_tls13` entropy returns **1** on full success; `ntwst` randomness returns
**0** on full success. Their similarly numbered error values are not a common
ABI. Each requires external serialization, no callback reentry and exclusive
ownership of its linked PSA state. Do not silently cast callbacks, combine
static PSA implementations in one program, or infer concurrent connection
support. Use a reviewed adapter or separately loaded components, then test
the actual application/provider path.

Use [m98_tls13_HANDOFF.md](../src/m98_tls13_HANDOFF.md) for the latest client,
[uxtheme_engine_HANDOFF.md](../src/uxtheme_engine_HANDOFF.md) for theme drawing,
and [secure transport README](../ntwin32/secure_transport/README.md) for the
LTS/native fixture, exact source pin, reproducible build and handoff verifier.
Both selected Mbed TLS license options are GPL version 2; full upstream and
toolchain notices remain required for a later binary distribution. No binary
release or global DLL/provider configuration was performed here.

## Combined-branch verification

Fresh builds in this branch passed 312 theme checks normally and under
ASan/UBSan, three theme PE/import gates, 16 authenticated TLS 1.3 loopback
cases against OpenSSL, the latest TLS client PE/import gate, and 19 application
inventory regression tests. The LTS transport's frozen eleven-case host result,
three PE artifacts, thirteen DLL exports, real x86 relocation entries and eight
staged DOS inputs were independently reverified. Six deliberately modified
handoffs were rejected, including changed EXE/certificate, mismatched nonce
and delayed exit observation.

The inherited ntwddm regression passed 308,637 core checks, 88 theme checks,
53 presentation checks, and both native and i386 freestanding symbol checks.
These are host/static checks. No new guest/application capability follows.

The exact **new combined-branch** receipts and artifacts are bound by
[secure-transport-checkpoint-7707.json](../benchmarks/secure-transport-checkpoint-7707.json).
The imported `MODERN_THEME_TLS_CHECKPOINT.json` retains the original peer
branch's evidence; its relative receipt hashes should be resolved in that
peer's recorded worktree rather than treated as the new build's receipts.

## Actual acceptance still required

The exact current package pins and meaningful checks are in
[MODERN_APP_REQUIREMENTS_7707.md](MODERN_APP_REQUIREMENTS_7707.md) and its
[machine-readable contract](../benchmarks/modern-app-requirements-7707.json).
ONLYOFFICE remains required alongside LibreOffice. Current source ports must
retain upstream version/patch/library/architecture identity.

Guest owners must test native DLL loading/relocation, actual entropy, clock,
CRT shutdown and protocol behavior on a fresh installed Windows 98 clone.
The established guest harness keeps its 20 GiB reserve. The original v3 DOS
staging is historical; use the dated continuation below for current receipts.

After native foundations, wire and test the supported OS public networking
API/provider, sockets/DNS, trust anchors and certificate failures. A library
handshake does not implement Schannel/SSPI, WinHTTP or WinINet; Electron and
Signal native components also have their own networking and crypto paths.

Themes must be selectable in real settings, applied to actual desktop and
app controls, and preserved through cold boot. The current opt-in painter
does not establish those requirements. Legcord needs login, messages,
attachments and voice; Signal needs device linking, encrypted DB/messages,
attachments and calls; each Office suite needs document/sheet/presentation
editing, formulas, save/reopen and PDF checks. Keep all absent receipts
explicitly unresolved.

The related Chromium/Steam/Office/Legcord owner remains on
`Win98-Modern-codex-20260930`; the PE load-config family remains owned by
chat c009. Their active changes were not imported while under development.
Use their completed commits and guest receipts for the next integration.

## Continuation on 2026-10-01

The user clarified that a full WebKit port is not a mandatory prerequisite.
Extend the existing Trident-based browser with actual modern HTML5/DOM/CSS,
WebAssembly and modern JavaScript features. The precise tested subset and
remaining conformance gaps must be recorded. Chromium/Electron application
requirements remain separate. This direction was sent to the active agents
and the shared peer handoff; the requirements contract adds four pending
Trident conformance groups.

The native TLS v2 trial reached genuine Windows 98 SE but its console child
timed out in the unsupported DOS display host. The GUI v3 trial was interrupted
by a host restart before execution. The GUI v4 trial created the real child,
observed normal wait completion and its full exit code **2**, and retained
`TLSOBS.LOG`; no `TLS13.LOG` was produced. These trials do not establish a
native TLS pass. Their original evidence and immutable sources were preserved.

The native startup checked an undefined return register from the pre-XP
MSVCRT `__getmainargs` ABI. It now ignores that return value and validates
initialized argument outputs. Twelve actual-source host ABI fault cases pass.
Fresh v5 host/native builds pass eleven real host protocol cases, three native
PE gates and the frozen fixture verifier. The v5 guest launch was refused
before a VM started because its disk reserve was insufficient; its zero-capture
failure is distinct from guest execution. The current eight-input handoff is
`/root/Win98-Modern-boot/build/secure-transport-7707/tls-observed-v5-crt/guest-files.json`,
SHA-256 `1097b2e9b239fc83f5a85c7731360cf0d544156638ca97b87c706238c82c2213`.

The portable outbound SSPI stream core in `ntwin32/secure_transport/sspi_stream.c`
passes fourteen real protocol/stream groups, normally and under ASan/UBSan.
It implements bounded token/input continuation, authenticated records,
fragmentation, retry, extra input, closure and truncation behavior over the
3.6.7 engine. This core is not a native security package or OS provider.
Its exact receipt SHA-256 is
`fd5b420a454a36cbd3b75c86db77614525afab957b1634cf8a2e46b4df5b30e7`;
see `sspi_stream_HANDOFF.md` for ownership, limits and reproduction.
The separate native ANSI ABI/ROOT-store adapter now builds as an explicitly
loaded `M98SSPI.dll`. Its fourteen ABI/lifetime groups pass normally and under
ASan/UBSan, including eight concurrent callers performing 200 lifecycle
sequences each. The model executes actual adapter code with mocked Windows
and stream APIs; it does not execute cryptography or native Windows APIs.
The native PE gate checks fifteen exact exports, forty-seven original-OEM
imports and 6,577 HIGHLOW relocations. Source and artifact receipt bindings
were independently rechecked. Independent review found that the simplified store opener could create an
absent ROOT store. The corrected adapter uses `CertOpenStore` with explicit
read-only and open-existing flags; a missing-store regression checks that no
store is created. Fresh ABI/sanitizer/native receipts bind that correction,
and the earlier opener receipts remain historical. Actual DLL load, ROOT
enumeration, socket traffic, OS registration and application acceptance
remain unverified.
See `sspi_native_HANDOFF.md` for supported call shapes, limits and reproduction.

The dedicated disk agent removed only two reviewed v5 source-extraction
caches, totaling 106,160,128 allocated bytes. All 358 protected files retained
their content hashes and logical metadata. Concurrent peer writes caused
filesystem free space to decrease during this operation, so the cache total
is not a filesystem-wide net-reclamation claim. The later v5 launch attempt
could not acquire the cooperative guest lock and created no run. Theme and
application owners continue their independent native tests; the TLS clone
waited for both the shared lock and the unchanged disk-reserve gate. The
single fresh `run-win98-gop-tls-observed-v5-7707-20261001T0718` clone is now
preparing after acquiring that lock; execution has not yet been observed.

The user-authorized independent evaluation site is <https://m98.nyase.kr/>.
Release `M98EVAL-20261001-R2` explicitly states **독자 사이트** and
**정품인증을 제공하지 않습니다** and records the Trident direction as pending.
It distributes only the unchanged reviewed GOP/NPP components plus complete
corresponding sources, licenses and manual evaluation notes. New TLS/theme
test binaries are not distributed. The original evaluation download remains
byte-exact; R2 has a separate URL and checksum. Sixty-one loopback HTTPS
origin bodies matched the reviewed hashes. External edge access has not been
verified. Publication receipt:
`/root/Win98-Modern-release-7707-v2/published-20261001T064000621364.json`,
SHA-256 `f6d3f2830613a564e3f2b9a9604f5e8ce2906dd6bf4c9ba4751071ae70fe0613`.
