# Modern theme, TLS 1.3 and application checkpoint

The requested target remains functioning themes, current Legcord/Discord,
Signal and open-source Office, broader modern application support, and OS TLS
1.3. The new components are working foundations. Actual installed Windows 98 component API and comparison-screen evidence is now retained.
System API integration and functional application runs remain acceptance gates.
The browser direction is now Trident modernization toward HTML5, current
JavaScript and CSS, modern WebAssembly, WebGPU and WebGL. All six listed
standards families are mandatory targets; a full WebKit port is optional. See
`TRIDENT_MODERNIZATION_HANDOFF.md` for the inspected integration seams and limits.
The subsequent requirement and primary specification editions are recorded in
`benchmarks/modern-web-targets-v1.json`; none is marked fully supported.

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
and shutdown. The original v7 preparation stopped
before QEMU because concurrent disk growth removed the required copy budget;
zero captures and no probe execution were recorded. The subsequent complete
executable-byte audit rejected the actual latest TLS DLL: upstream X509 code and
prebuilt MinGW formatting contain post-i486 CMOV instructions. The old v7 stage
must not launch as an i486-compatible trial. All original bytes, failed
disassembly and previous results remain preserved. An isolated corrective port
recompiles every upstream/adapter unit for i486 and replaces formatting with an
original bounded formatter. Its initial source-preparation rejection is retained;
corrective v2 now passes both full linked DLL gates and twelve actual encrypted
latest/LTS Linux cases. Commit3b429e1 retains471 translation-unit macro maps,
978 successful build steps and original archive aliases. Its formatter passes
18974 assertions normally and under full ASan/UBSan; ten actual owned-server
startup controls cover partial lines, EOF and absolute deadlines. Corrected
Windows execution remains pending. A fresh stage requires stable space and the
actual shared guest queue. The original configuration-assertion unit checks
and temporarily clears formatter definitions; any exception must identify that
exact original unit and prove it contains no formatting calls.
Neither v4 nor the host result is a native
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

## Trident implementation checkpoint

The user clarified that a full WebKit port is optional. The inspected historical
seams and missing functionality remain recorded in
`TRIDENT_MODERNIZATION_HANDOFF.md`; subsequent implementation uses a separate
modern-script runtime and actual Microsoft MSHTML Automation binding. It does
not advertise QuickJS as the independent provider's named JavaScriptCore bit.

Reviewed commit09e6285 adds the real IUnknown/IDispatch/IDispatchEx adapter,
the genuine installed-MSHTML document/view fixture, a stable explicit script
ABI and separate runtime/MSHTML child observers. The adapter preserves canonical
COM identity, UTF16 BSTR contents, typed values and HRESULTs, selects actual
property setters from member metadata, and queues real event calls for explicit
UI-thread dispatch. The native fixture independently reads the actual input
through IHTMLInputElement and requires the complete resulting text to match.
It synthesizes no input event and provides no fake DOM or painted replacement.
Strict Automation missing-member behavior and asynchronous callback limitations
remain explicit; ordinary website DOM semantics need separate implementation.

Frozen Automationv4 passed3799 production-adapter OS-double assertions normally
and under ASan/UBSan, plus its own OEM import/GUI PE32 gate. Its fixture reserves
2MiB and commits512KiB, independently of the observer's64KiB commit. Observerv2
passed3022 script and3031 Automation fault-model assertions in both modes and
two original-OEM/i486 PE gates. Independent source/artifact/log review cleared
both checkpoints. These results do not establish installed MSHTML execution.
Reviewed commiteb85c4d supplies the frozen QuickJS2026-06-04 port with selected
current musl mathematics, actual x87 state preservation at API/callback
boundaries, bounded UI-thread contexts and explicit lifetime ownership. Runtimev10
passes1293 interpreter,32 formatting and510 actual-platform OS-double assertions,
normally and under memory/undefined-behavior checks. Its DLL and native probe
pass complete decoded i486 instruction, original OEM import, exact export and
PE32/OS4.10/stack gates. Shared-memory/Atomics are disabled in this profile; full
language conformance and installed Windows98 execution remain unverified.

Official pinned Test262 fixtures execute through that actual runtime, using a
limited synchronous protocol and fresh realms. Checkpointv5 records338 variants:
334 pass and four fail on the separately proposed immutable-arraybuffer feature;
four original detach-buffer tests are explicitly excluded because host bindings
are absent. Failed cases cause a nonzero command exit. Original fixtures and
failed earlier adapter trials remain preserved. See `TRIDENT_TEST262_SELECTED.md`.

Commits0acecf9 and89a6df0 add strict native Automation/runtime verifiers and fresh
canonical boot stages. Automation retains146 frozen files; runtime-only retains176.
The runtime parser requires all307 ordered guest checks and independently
observed actual child completion. Its44 regression methods pass normally and
with optimized Python; these are parser/staging controls, not guest execution.
Runtime and genuine document trials are staged without global registration and
remain queued behind existing native owners. See `TRIDENT_SCRIPT_NATIVE_EVIDENCE.md`
and `TRIDENT_NATIVE_STAGE_HANDOFF.md`.

Native modern-JavaScript MSHTML display, trusted input and pixel review, actual child/supervisor
exits, ordinary browser script selection/navigation, origin-bound networking,
HTML5 parser/layout and WebAssembly remain unverified or unimplemented.
See `src/m98_trident_automation_HANDOFF.md` and
`tests/m98_trident_guest_runner_HANDOFF.md` for exact boundaries and evidence.

## CSS, Wasm and graphics implementation checkpoint

CSS corev4 executes real Syntax3 tokenization and Variables1 substitution with
parent snapshots, fallback dependencies and cycle handling. Normal and
ASan/UBSan processes pass11,827 syntax and13,289 variable assertions. The actual
zero-import `M98CSS.DLL` has18 exports. Selected WPT references and original
CSSWG documents retain their hashes, licenses and attribution; foreign browser
tests have not run.

Genuine MSHTML fixturev9 adds a nested parent/child DOM trial, typed width/color
application, independent geometry/color readback and full Korean text readback.
Its real-token consumer passes213 assertions normally and under sanitizers.
CSS observerv4 passes3,025 control-flow fault assertions in both modes. The
canonical CSS stagev3 retains all source, original command logs and artifacts;
independent review cleared87 provenance members and every executable byte of
all three inputs. Native acceptance's eight test methods pass normally and with
optimized Python using explicitly synthetic stopped-run evidence. A separate
actual Win98 retry passes bounded DOM/styles, independent32-to168 geometry,
both painted states and full Korean text. The owned child exits DWORD0; actual
supervisor exit remains unverified. Old failed native evidence is preserved;
complete modern CSS remains unfinished. See
`TRIDENT_CSS_NATIVE_STAGE.md`.

The old regex used by frozen Script/Automation builders could skip a modern
instruction after an operandless instruction. Corrected supplemental proof now
checks every actual staged executable byte, including linked helpers; all six
canonical Script/Automation inputs pass. Original frozen recipes and partial
counts remain historical. The next launch and native acceptance must consume
the corrected proof. The same full coverage gate supplies current CSS/Wasm/Mesa
artifact checks. See `I486_NATIVE_INPUT_AUDIT.md`.

WAMR runtimev24 executes actual modules from the pinned current interpreter and
passes1,237 embedding assertions normally and under full ASan/UBSan. It meters
normal, tail-call and start execution, accounts real allocations, separates
validation/instantiation, enforces lifetimes and preserves the full x87 state.
Selected official numeric suitesv5 pass5,896 commands in each execution mode;
eight text-only malformed-source cases remain explicitly excluded. The real
DLL's155,996 executable bytes contain54,602 checked i486/x87 instructions.
Current macro maps retain114 actual interpreter-TU switches per configuration.
Browser JS bindings, SIMD/EH and remaining modern Wasm proposals still require
implementation/validation. A fresh actual Win98 numericv24 trial passes265
ordered checks with original system MSVCRT, full x87 preservation and actual
owned-child DWORD0; selected official native suites and memoryv8 remain pending. See
`TRIDENT_WASM_RUNTIME.md` and `TRIDENT_WASM_SPEC_SELECTED.md`.

Mesa foundationv2 constructs genuine TGSI fragment programs from bounded typed
IR and executes actual quad interpolation, divergent branches, discard, fine
derivatives, uniforms and scalar math lowering. Normal and ASan/UBSan executions
each pass3,120 assertions. The real DLL and probe pass complete executable-byte,
original OEM import, export and Win98 PE/stack gates. Native execution is pending.
Full Gallium rendering, GLSL ES, GLES, WebGL2 and WebGPU/WGSL/device/compute
remain mandatory unfinished work. See `MESA_SOFTPIPE_PORT_FEASIBILITY.md`.

Independent final-byte review rechecked19,744 source/log/header/cache/artifact
observations across the Wasm/spec/Mesa receipts. It does not provide native
browser or application acceptance. All full standards and application flags
remain false. These changes are saved in scoped local commits; nothing has been
published or globally installed.

## Disk optimization and retry boundary

The separate disk agent finished its bounded approved scope. All20 final receipt
digests were independently rechecked. Twelve old closed clones show a measured
2,249,388,032-byte decrease in unshared FIEMAP extents; this is not a claim about
the net free-space change while other sessions write concurrently. The final VLC
pass covered44 of559 planned ranges and verified six destinations in full;
the active native-api image was skipped. Original contents, SHA256, identity,
mtime and prior evidence were preserved. No additional deletion candidate had
both ownership and regeneration evidence. Interrupted themev2 remains unaccepted.

The final timestamped space reading was20.639GiB and a later reading20.477GiB.
Readiness requires the unchanged20GiB reserve, measured sparse-copy allocation,
dirty budget and staging overhead, remeasured before every attempt. Subsequent
concurrent cleanup can change that reading; a newly attempted trial needs its
own result rather than inheriting a prior preparation or component result.
Final private evidence is
`build/disk-cleanup-5abe-20261001/bounded-maintenance-checkpoint.json`.

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
`docs/NATIVE_QA_SCHEDULING_SCOPE.md` corrects the earlier broad interpretation of
the ZUKU lab skill: this project's admission checks the cooperative lock and
actual other Win98 native disks, while positively identified separate XP and
Kernel64 runners count toward resource usage. The owned admission wrapper checks
the queue again under the lock, every frozen CSS stage member, the harness and
the actual cold-source hash before creating one private offline run. The
09:44:50 UTC attempt found peer boot's VLC/Qt Win98 disk active outside the
vacant cooperative lock and returned before native run creation.

The committed Script/Automation supplemental guard replays all six immutable
native inputs against their original raw disassembly: 471637 instructions and
1481240 executable VirtualSize bytes. The original 16-method normal and
Python-optimized controls pass. Independent review checked 335 unique evidence
members across the two stage receipts, including final provenance drift checks.
The guard must run freshly both before launching either component and as a
required conjunct of final acceptance. It does not replace the original native
verifiers or certify actual execution. The frozen sources and stages remain
unchanged. See `docs/TRIDENT_I486_SUPPLEMENT.md`.

The private numeric QuickJS/WAMR bridge is committed in `7b2dbff`: actual
normal and full ASan/UBSan tests each pass140 checks, including BigInt, branded
buffer views, imported exceptions and cyclic-GC/native cleanup. Its v11 receipt
is `b3e0e6ef6b966b9c9cb0beaaaf41d8227e048fbe6245232b73d825d0584705ac`.
This private embedding is not the standard browser WebAssembly namespace.
Original no-grow modules exposed real page coalescing and growth failures;
additive guarded memory profilev8, committed as76cb02b, corrects those semantics,
zero-fill,32-bit allocation narrowing and table-arena alignment. Both normal
and full ASan/UBSan executions pass386 targeted checks and4641 unchanged selected
official memory/growth/bulk-memory commands. Root baseline regression also
passes1237 predicates in both modes through a prepared observation copy that
collects foreign-thread results after join. Original tests and failures remain
preserved; JavaScript memory integration and native profile execution remain pending.

Actual software triangle rasterization through the genuine frozen Mesa TGSI
fragment API is committed in `601e2fd`. Raster v3 passes33792 assertions in
each normal/full ASan-UBSan run; receipt
`26d7055953bb6e0915df675ea0c0797c07e0c5704b00ef16f077e1867da3164f`
binds complete native PE/OEM/i486 code. The bounded raster profile covers
literal edges, helper derivatives, depth, defined straight-alpha composition
and transactional failure. Its floating-point guarantee covers the three outer
raster provider callbacks; nested trusted Mesa providers must preserve the
internal FP environment. See `docs/TRIDENT_SOFTWARE_RASTER.md`.
Standard browser WebAssembly reflection, complete modern Wasm proposals,
GLSL ES/WebGL resources and WebGPU/WGSL/compute remain mandatory unfinished work.

The first actual CSS native run was strictly rejected: genuine original
MSHTML5.00.2614.3500 activated, but style width32 corresponded to offsets46/36.
The original zero-border/padding fixture and failed child exit1 remain retained.
Correction `71710ba` changes only the long box labels to `P`/`C`, preserving
the independent32-to168 geometry oracle. Fresh fixture v9 passes213 normal
and full-sanitizer checks. Its new canonical stage v3 has manifest
`11a2aa48b735e26212db048a78dfb5c64f6da1e95f8ef436fd4f5c4a2f18d7da`.
A separate actual native retry passed genuine styles, independent32-to168
offset geometry, both actual gray and blue/green/Korean painted states, exact
Korean UTF16 readback and released resources. The owned child PID4294516485
exited with full DWORD0; requested supervisor exit0 remains separate from
unverified actual supervisor completion. Strict native acceptance receipt is
`c5abb5104fb8d1e51f6d6cf4d805fd02a2253a64d21d6cbccfa9453acdf86ee3`,
with106 actual stage/native/source files rehashed before and after acceptance.
Original disks and frozen sources remain unchanged. This bounded consumer
does not certify arbitrary
stylesheet selectors, cascade, layout or complete modern CSS.

Numeric native Wasm probe/observer source is committed in `8ea3da3`; its actual
host/full-sanitizer shared probe checks each pass244. The stage/verifier source
commits `778cfd6` and `0f163b1` freeze2785 evidence members, require an independent
approved provenance hash and exactly265 ordered native checks. The corrective
final check rehashes all seven consumed native executable/harness/log files
after the final stage replay. Normal/Python-optimized controls pass6 log and7
acceptance methods; explicitly synthetic controls are not native evidence.
Fresh canonical numeric stage v2 manifest is
`d0948ad22afc556cf57398c6361326729e2c7afe50b6ce360513d9392f973b8b`,
provenance `9e87ddbe5ddb43ecba1edc7d5ac49b5a6bc88a9b56f6adb27c847a9a06738587`.
Native numericv24 acceptance now passes; full browser Wasm remains false.
Earlier admission preserved a queue refusal behind peer VLC PID3026413. After
that guest naturally ended, fresh admission observed a vacant Win98 slot and
positively identified the separate Kernel64 Chromium runner by exact PID,
start identity, image and ELF boot source. The fresh private numericv24 trial
normally stopped QEMU PID3404150 and released its cooperative lock. Strict
acceptance375493e73d749079e931caae98e8e0c589649cf68e19602fd94927e9fa1a0812
checks all265 ordered predicates, original system MSVCRT, full x87 preservation,
actual owned-child PID4294877739/DWORD0, flushed output and closed handles.
Root independently rehashed2827 current/frozen/native paths twice; originals
and prepared sources remain unchanged. Actual supervisor exit remains
unverified. This pass does not establish memoryv8, browser WebAssembly or full
standards. A subsequent runtime-only JavaScript admission queued before run
creation behind peer theme Win98 PID3455405 and the occupied cooperative lock.
No peer process or guest is controlled.

The isolated TLS i486 v1 receipt
`1123b84ae84c35981cbf5e6e3ea9c4d4b6848cac00d2ee0b22e61be7237167b3`
passes both complete linked native DLL CPU/ABI gates and12 actual encrypted
Linux latest/LTS exchanges, with exact60-byte positive responses. Its frozen
sources and evidence remain retained. Fresh v2 completes the owned-server
partial-startup-line deadline correction and exact1MiB formatter boundary checks.
Its accepted authority is98c526151545be95fe5f6cd58140ae2dfdc52d21038fe1de893387290dea1819;
root and independent full-byte reviews clear the six committed source files.
Corrected Windows execution, real WinSock transport and
OS Schannel/WinHTTP/WinINet integration remain distinct mandatory gates.
The native presentation lane is coordinated with peer6970; peer7707 retains
the independent LTS fixture and cb43/c009 retain application-runtime integration.

The completed host checkpoint passes 312 new theme checks normally and under
ASan/UBSan, the existing ntwddm regression/freestanding checks, 16 real TLS
loopback cases, and 19 application-inventory regression tests. Theme and TLS
artifacts also pass their native PE/import gates. The exact artifacts and
receipts are bound by `docs/MODERN_THEME_TLS_CHECKPOINT.json`; native component evidence is recorded separately, and application functionality
is not promoted by host/PE checks.
