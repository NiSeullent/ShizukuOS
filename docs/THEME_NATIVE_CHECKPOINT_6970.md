# Interactive native theme checkpoint — 6970

This branch reuses the app-local M98THEME implementation from peer commit
`a12a4a95e9f3fbddcea82d69f124876d22fb660f` (local cherry-pick `536bc69`).
The engine remains opt-in; this work does not install a system-wide theme hook.
The existing TLS and modern-application ports retain their respective owners.

`ntwddm/win98/theme_probe/probe.c` builds as `NTTHGUI.EXE`. It dynamically loads
the absolute EXE-local `M98THEME.DLL`, checks native Windows 98 platform/version,
opens real native GDI windows, and draws caption and button states through the
shared provider. Classic/Modern switch by C/M keys or mouse, automatically at
10 and 20 seconds, and close after 30 seconds. Handles are reopened on each
selection and checked during teardown. No registry change, installation,
network access, or guest startup is performed by this build.

Build and acceptance checks:

```text
python3 -B ntwddm/win98/theme_probe/build.py
python3 -B -m unittest discover -s ntwddm/win98/theme_probe -p 'test_*.py'
```

The builder retains unique immutable run directories and a separate latest
receipt under `ntwddm/win98/theme_probe/build`. Receipts bind source hashes,
exact commands, compiler versions, normal/sanitized host checks and all three native
artifact hashes. The PE gate requires i386 GUI PE32 4.10, native OEM imports,
relocations, and the shared provider's exact exports. A build PASS explicitly
records `native_win98: not_tested` and does not establish visible guest output.

`observer.c` builds as `NTTHRUN.EXE`. It requires actual Windows 98 SE build
2222, a fresh nonce, and absent logs; creates only the exact EXE-local child;
waits at most 60 seconds; and records the full actual DWORD exit after a normal
wait. Failure handling can stop and reap only that owned child. The initial
host mocks exercised 4,749 assertions; the bounded entry/privacy diagnostics
raise the current count to 18,383 in normal and sanitized runs.

For a current guest handoff, copy the frozen DLL, `NTTHGUI.EXE`, `NTTHRUN.EXE`
and the exact fresh 32-byte lower-case hexadecimal `THNONCE.TXT` challenge to
a new private clone's `C:\VXDLAB`, with all three output logs absent. Freeze
the copied build receipt and four input hashes, then launch
`C:\VXDLAB\NTTHRUN.EXE --nonce=<nonce>`. Capture Modern between 10 and 20 seconds,
Classic before 10 or after 20 seconds, and keyboard/mouse interaction. Use the
observer's actual child exit after normal termination; a shell launch or
proposed exit field is insufficient. Stop the exclusively owned guest before
independent readback of all three binaries and both logs. The canonical runner
collects logs, but diagnostic binary readbacks must be extracted separately.

The verifier is read-only. Supply `--build-receipt`, its frozen
`--build-receipt-sha256`, `--log`, `--nonce`, `--exit-code`, `--provider-path`,
`--guest-dll`, `--guest-probe`, `--guest-observer`, and `--observer-log`. It requires fresh log start/final nonce,
exact native OS identity, successful paint counts for both styles, two or more
selections, cleanup, final PASS, actual exit zero, and original/readback artifact
hashes. It rejects stale/partial/error logs, duplicate fields and changed
artifacts. `THOBS.LOG` must independently report normal wait, actual zero exit,
correct nonce/OS/child path, and checked process/thread cleanup. A parent log
cannot observe its own final log close or external exit; these are explicitly
kept unverified. Its result keeps `native_visibility_verified: false`: visible
screenshots and guest lifecycle require independent review. It also cannot
establish system-wide themes, persistence, or modern application functionality.

Native VM ownership and sequencing are coordinated in each session's record
under `/root/Win98-Modern/.codex-collaboration`. Session 5abe owns the shared
engine and native theme supervisor; 7707 owns the LTS TLS fixture. This session
owns the complementary interactive probe and evidence verifier, and does not
write another owner's VM control file or disk. Preserve the unchanged 20 GiB
floor plus private-copy and log budgets for each native trial.

Disk recovery used the kernel's byte-comparison deduplication of unopened
Legcord/LibreOffice staging images. The verified operations shared 477,102,080
and 1,409,892,352 bytes respectively, retaining all files, paths and content.
Full hashes and file identities match before/after. Independent physical free
space can change while other sessions write. Receipts are retained at
`/root/Win98-Modern-boot/build/space-recovery-6970/20261001T014517Z/result.json`
and `20261001T032612Z/result.json` in the same parent directory. Original and
active Windows images, application corpora, and prior evidence were preserved.

The 2026-10-01 continuation retains a source-bound three-artifact build at
`ntwddm/win98/theme_probe/build/20261001T060013Z-1a4c9773/result.json`.
Its 312 provider checks and 4,749 observer assertions pass both normally and
under ASan/UBSan. All three native PE gates pass; the verifier's 19 regression
tests pass. The first interactive trial is retained as FAIL with zero captures:
the measured copy budget was below the unchanged reserve, so QEMU never started.
This source and host evidence does not establish a native visible-theme pass.

## Required application packages

`tools/signal_desktop_corpus.py` inventories local, publisher-pinned packages
without executing them. It verifies publisher size/digest before and after the
read, validates bounded archive names and extents, streams native PE imports,
and records the Signal ASAR package and native-module versions. Its 19 tests
include the real NSIS distinction between helper entries with unknown sizes
and the selected, size-bound nested application archive.

Actual publisher packages are retained outside Git beneath
`build/modern-required-apps-6970`. Signal 8.28.0 passes its official SHA-512
and inventory: 13 native files, AMD64 PE32+, and a Windows 10 declared OS version.
ONLYOFFICE 9.4.0 x86 passes its official release SHA-256 and inventory: 335 native
files and an ia32 entry point. These are package facts, not compatibility results.
The official ONLYOFFICE 9.4.0 x64 package also passes its release SHA-256 and
actual inventory (335 native files). Its complete publisher layout is prepared
for the AMD64 Kernel64 runner; the ia32 package remains available for a separate
native port.

`tools/required_app_runtime_handoff.py` supplies explicit package preparation,
standalone image construction and diagnostic execution stages. It rejects an
ia32 entry before extraction, preserves complete publisher layouts, and binds
the selected peer runtime source to the receipt. Runtime diagnostics cannot
claim application functionality or Windows 98 execution. Full extraction and
execution remain subject to the same storage reserve and separately verified
guest lifecycle; the native Win98-to-Kernel64 GUI bridge remains unverified.

## Integrated peer network source

Reviewed peer commits `66912e3`, `b872beb`, and `c39f6c9` are integrated here as
`1046391`, `55b9eba`, and `701149b`. They add opt-in DNS configuration, native
theme/TLS child observers, and a Win98 TCP/CryptoAPI/UTC adapter for the verified
TLS backend. The integrated evidence verifiers pass 31 theme and 42 TLS tests
in this worktree. The peer retains ownership of native TLS execution and its
failure/retry records. This integration supplies source and strict evidence
contracts; it does not establish a native network handshake, global Schannel,
WinHTTP/WinINet support, or network functionality in the required applications.


## 2026-10-01 real retry and storage recovery

The dedicated disk agents completed content-preserving allocation sharing and
narrow removal of inactive, disposable dependency-cache payload. Phase 1 newly
shared 4,201,721,856 bytes; phase 2 independently confirmed 4,649,242,624 bytes
(4,297,510,912 sharing plus 351,731,712 exclusive cache payload removed).
The original images, active clones, publisher packages, final executables and
failure receipts remain. These amounts exclude unrelated cleanup by other
sessions. The final phase-2 checkpoint is
`/root/Win98-Modern-boot/build/disk-optimizer-6970-phase2/checkpoint.json`.
The native reserve remains 20 GiB plus the private 256 MiB COW headroom.

The v6 private native KVM trial actually started and produced 94 captures.
SYSTEM.INI reported missing `mshbios`; after the prompt was dismissed, inspected
screens were black and the QMP connection reset. No desktop was observed, the
observer was not launched, and THEME.LOG/THOBS.LOG are absent. Independent
stopped-clone readback matched all three prepared binary hashes. This is a
native FAIL, separately from successful original/COW preservation checks.
Evidence is beneath
`build/theme-native-runs/win98-gop-theme-6970-20261001-v6`.
The v7 trial used the unchanged cold-v3 lineage which peer 5abe previously
observed reaching the desktop. It reached the actual Korean Win98 desktop and
Run dialog, and the owned VM exited normally with code zero after 427.8 seconds.
The exact fresh-nonce observer command is independently present in Run history.
Nevertheless, no probe window or observer/child log was observed; theme
acceptance remains FAIL. All three stopped-clone binary hashes match. The
harness does not type `=` directly, so an owned split input action supplied
that key explicitly. A bounded early-entry diagnostic is being added to locate
the observer pre-log failure without weakening nonce or exit requirements.

## Private AMD64 Modern theme integration

`ntwddm/win64/theme_provider` supplies an application-local AMD64 `UXTHEME.DLL`
using the shared real painter. It adds checked 64-bit handle transport, private
ANSI-to-Unicode calls, borderfill size queries, and documented partial extended
background drawing with real ordinal 47. The explicit Modern build initializes
its style once after lazy engine creation. All 1,889 host assertions pass
normally and with ASan/UBSan; those checks do not execute Windows ABI endpoints.
See that module's README for exact supported behavior and source lineage.

`tools/required_theme_runtime.py` validates the actual SHZARC01 archive,
preserves all 141 original members byte-for-byte and in order, and appends only
this provider. Its 36 imports resolve through the actual archive's 43 AMD64
system DLLs. Inputs include the exact generated adapter/font sources. The v2
receipt at `build/required-theme-runtime-6970-v2/theme-overlay.json` binds the
derived archive SHA-256
`cac9b31ad2a9835847d8ac12372307553ff801df3e8dcf3aad5d6c6349947e2a`.
Sixteen consumer tests pass. The run stage retains the unchanged handoff's
source, recipe, image, firmware and resource checks, then records the actual
sealed derived archive. It supplies neither a native Win98 AMD64 GUI bridge
nor system-wide theme registration.

## Required-app execution observations

The isolated QEMU firmware fix freezes the explicitly selected split firmware
roots into each owned run directory and supplies that private directory with
`-L`. Twenty-nine handoff tests cover the real missing-BIOS failure and the
sealed union's ambiguity, bounds and preservation checks. Earlier BIOS-failed
Signal evidence remains unchanged; it was not an application compatibility
result.

Real Signal 8.28.0 baseline `signal-run-v2` mapped the publisher executable,
started pid 60 and emitted a ten-second heartbeat, then timed out at 90.1
seconds without a normal application exit or demonstrated UI. The Modern
trial `signal-themed-run-v1` also started pid 60 and timed out at 90.2 seconds.
The previous UXTHEME file-not-found trace disappeared; named provider ordinal
probes and additional DirectWrite initialization appeared. This establishes
loader progress, not visible theme painting or messaging. Remaining diagnostics
include the fibers/appmodel API-set versions, KERNELBASE, downlevel Shell32,
power notifications and modern virtual-memory entry probes. Some may be
optional probes; their absence alone is not a proven cause of the timeout.
All original/sealed runtime, firmware, image, tree and recipe guards pass.
The baseline archive SHA is `2f3a3fac...16f0`; compare full hashes in each receipt.

Real ONLYOFFICE 9.4.0 x64 baseline `onlyoffice-run-v1` mounted its complete
publisher tree and mapped DesktopEditors.exe, Qt5Widgets.dll and Qt5Gui.dll.
The loader stopped before creating the application process because Qt5Gui
normally imports `D3D11CreateDevice` from absent D3D11.DLL. Qt also requires
DXGI; environment flags cannot bypass a required normal import. The shipped
D3D compiler and ANGLE libraries are present, but are not a replacement for
D3D11. The run ended after 11.8 seconds, with all preservation checks passing.
The guest self-test exit zero does not establish Office execution. The Modern
comparison `onlyoffice-themed-run-v1` reproduced the same failure after 14.9
seconds. Its wrapper verified the actual sealed derived archive and all input
preservation checks; no theme drawing occurred before this graphics gap.

These diagnostics use standalone ShizukuDOS Kernel64, have no network attached,
and keep application functionality and native Windows 98 execution unverified.
Legcord/LibreOffice rendering and the native TLS fixture remain peer-owned;
the broad user objective is still incomplete.


## Actual AMD64 painter acceptance

The fresh `build/tp64-run-v2/theme-acceptance.json` trial passes 94 actual
Windows ABI assertions and all 16,800 independently expected Classic/Modern
button pixels in QEMU's visible framebuffer. A real USER32 window was painted;
the exact nonce-bearing app pid 60 exited normally with code zero, and the
kernel's raw `proc_wait` result was zero (successful teardown/reaping).
The original and sealed source/runtime/image/firmware inputs remain unchanged.
The minimum free space was 58,240,233,472 bytes and peak private writes plus
captures were 2,578,355 bytes, within unchanged reserve/output limits.

The first guest trial retained a FAIL because its host gate interpreted
`reaped` as a Boolean; guest assertions and pixels alone could not override
that verdict. After binding the real kernel caller's return-code semantics,
the new trial used a fresh nonce and preparation. The corrected evidence gate's
24 regression tests pass. All older attempts remain unchanged.

This proves the exercised application-local AMD64 painter and visible button
backgrounds. Text/font rendering, persisted/global themes, native Windows 98
integration, Signal messaging and Office document editing remain unverified.
See `ntwddm/win64/theme_probe/README.md` for supported cases and exact receipts.

## Native redraw continuation and memory acceptance

The immutable v9 strict verifier passes actual Windows 98 SE identity,
fresh nonce, both styles, normal child exit zero and checked cleanup. Its
screens visibly identify Classic and Modern, with incomplete repaint limits.
Removing the probe's periodic full-window redraw is committed as `d3f2f60`;
the initial paint, explicit controls and 10/20/30-second lifecycle remain.

V10 and v11 preserve separate incomplete results. Boot and shell focus delays
consumed their bounded trials. V11 launched the exact observer at 885.4 seconds
and stopped at 902.0 seconds, before normal completion. Its full settled
Classic scene proves the visual improvement, but its empty THEME.LOG and
182-byte THOBS.LOG establish no child exit or Modern transition. All four
input and three output readbacks and 20 source hashes match; original guards
pass, with 520,192 bytes of private COW growth. Evidence is under
`build/theme-native-runs/win98-gop-theme-6970-20261001-v11`. A separately
guarded automatic-start helper is being prepared; no weaker observer verdict
or stale-log reuse is allowed. The native lane has been released.

The new AMD64 basic memory bridge is committed as `ee51ef8` with its sealed
append-only runtime consumer. Actual `build/mp64-run-v1/memory-diagnostic.json`
passes 69 guest assertions: exact live SYS64 file/header, ANSI/Unicode basename
and absolute loads, direct memory APIs and a genuine Kernel32 forwarder,
zeroed allocation, reserve/commit, coherent read-only mappings, private COW,
refusal/ownership checks and cleanup. The nonce-bearing child exits normally
with code zero; raw `proc_wait=0` verifies successful reaping.

The passing probe and retained failing Signal run use byte-identical actual
kernel, archive, QEMU and firmware, with identical reviewed runtime/consumer
sources. Their machine configuration differs in RAM (1 GiB versus 4 GiB);
application payload, arguments and working directory also differ. A new
same-input Signal comparison changes RAM alone. These results establish the
exercised memory subset without proving Signal functionality or explaining
its earlier KERNELBASE failure. Exact provenance and gaps are recorded in
`docs/MEMORY_RUNTIME_LOADER_AUDIT_6970.md` and
`docs/MODERN_MEMORY_CHECKPOINT_6970.md`.

## Automatic native startup and full graphics requirement

V12 replaces the late shell Run delivery with an independently guarded native
bootstrap on its own COW clone. A verified empty `[windows] run=` in WIN.INI
receives only the no-argument bootstrap path; the bootstrap reads a newly staged
32-hex nonce and creates the unchanged exact observer command. The original
WIN.INI SHA-256 `fa45041ccc42257781a0503b425cac60cce06be897aab7a1039edef05acaf12c`
is retained. Independent patched readback matches the frozen plan and all other
bytes, attributes and boot sectors remain unchanged. The shared lane was
acquired after its prior owner released normally; actual KVM startup was
observed at 10:59:40 UTC. Results are pending in
`build/theme-native-runs/win98-gop-theme-6970-autostart-v12`. The 1200-second
trial retains the 20-GiB floor, 256-MiB private-write and 16-MiB output limits.
Full native Classic/Modern visibility and checked completion are still required.

The user's additional requirement includes Direct2D, DirectWrite and every
DirectX family listed in `benchmarks/modern-graphics-requirements-6970.json`.
A separate graphics agent is implementing the genuine pinned Mesa resource and
rendering foundation, under independent ownership/source review. This does not
resolve the actual Office D3D11CreateDevice/DXGI blocker yet. Full export/COM
contracts, native integration and actual Office/app functional acceptance remain
required; successful DLL loading or a private triangle is insufficient.

The separately integrated TLS/SSPI correction in `bcb4a34` now passes actual
linked i486 and OEM Win98 import/PE gates for all four artifacts, plus fresh host
TLS and SSPI stream/lifetime checks. Native communication and OS-wide TLS remain
unverified. See `docs/TLS_SSPI_INTEGRATION_6970.md` for retained source and receipts.

## Stopped v12 automatic-start result

V12 completed with the unchanged strict verifier PASS and actual Windows 98 SE
identity. The frozen bootstrap independently witnessed normal observer exit
zero; the observer witnessed normal theme-child exit zero, with no termination
and checked handle cleanup. The bootstrap's own final log IO/exit is explicitly
unobserved. Theme logs record three Classic paints, one Modern paint, three
style selections and cleanup PASS.

Independent readback matches all five staged inputs, four logs, patched WIN.INI
and unchanged MBR/VBR. Final source guards pass 44 source/compiler checks.
QEMU exited zero at 694.1 seconds with 143 captures; private COW growth is
495,616 bytes. The immutable evidence index SHA-256 is
`a0edd4726c5e3b80a69bb4cecffd2a33fdd42c638f15aad5a1be586df65e5d31`.

The visual verdict remains PARTIAL: complete Classic is visible, while Modern
shows its label/palette with missing style captions/caption background and an
interrupted pressed rectangle. Modern appeared before the manual M action, so
that action receives no credit. A new separate offscreen-composition probe will
check palette and full native text masks, then compare final visible output.
No original provider, child, observer, startup or v12 proof is changed for that
diagnostic. Full native theme and global theme requirements remain incomplete.

## Native composition v13: pixels and lifecycle verified, strict receipt refused

The separate `ntwddm/win98/theme_composition` diagnostic composes the client
scene into an owned 32bpp DIB, compares complete caption/button text masks with
independent native Windows message-font rendering, then transfers the completed
scene once. Host and sanitizer builds each pass 22,807 ownership, failure-path,
pixel and transfer assertions; six parser tests and the OEM/i486 PE gates pass.
The original theme provider, observer and startup executable remain exact copies.

The stopped genuine Win98 SE v13 trial independently reads back all ten inputs,
logs and WIN.INI. Classic -> Modern -> Classic gives 84 matching fixed background
samples, 21 complete native-reference text masks and 63 matching destination
samples at 32bpp. Both the theme child and observer actually exit zero without
termination; the bootstrap's own external exit remains unobserved. QEMU exits
zero after 509.6 seconds and 104 captures; private COW growth is 499,712 bytes.
The 20-GiB reserve and existing write/output limits remain unchanged.

The general strict verifier retains FAIL: this new builder used the literal
`NOT-TESTED` for `native_win98`, while its static receipt schema requires
`not_tested`. The sealed receipt, strict FAIL and raw evidence are preserved.
The independent pixel/lifecycle results do not override that gate. A fresh
candidate must correct the metadata and rerun the full gate.

Actual screenshots show the complete Classic/Modern caption and six button
regions, with Welcome overlapping the footer and later transient display
damage. Complete visible client output and global themes remain unverified.
The v13 evidence index is
`build/theme-native-runs/win98-gop-theme-6970-autostart-v13/handoff-evidence-index.json`,
SHA-256 `a6f6c191ae2d44146f474bf6c5e3c78444a3193383b4d781fe19be1fda956c28`.
Root independently rehashes its 35 files, 55 source/compiler inputs and ten
readbacks, reparses the actual composition and lifecycle logs, and verifies
actual KVM descriptors and the stopped owned PID. Its separate audit is
`build/native-v13-root-audit-v1/audit.json`, SHA-256
`65e6578d4d458f45a26ec33f71ddf14cbc27f8240b0a8220f2a8f9e1587c3794`.

## Fresh v14: corrected source, resource-stop before native acceptance

Commit `2e153ec` corrects the static metadata and checks the owned window before
requesting foreground once. Normal and sanitizer composition runs each pass
22,807 assertions plus 11 foreground assertions; 14 builder/verifier cases and
the i486/OEM PE gate pass. These results do not replace a fresh native verdict.

The new v14 nonce is `0e71805ae8b57cd85263f2aee6580672`. Actual KVM descriptors
were observed for the owned QEMU PID 3766355. The unchanged 20-GiB guard stopped
only this VM when free space reached 21,463,748,608 bytes, 11,087,872 bytes below
the floor. Fifty-one captures were retained; no desktop, theme child or native
observer completion was established. Four expected native logs were genuinely
absent. The 94,208-byte private COW, all five staged files, exact WIN.INI change,
unchanged MBR/VBR and 48 source/compiler/receipt hashes were checked. No verifier
PASS or normal child exit is invented.

The preserved index is
`build/theme-native-runs/win98-gop-theme-6970-autostart-v14/handoff-evidence-index.json`,
SHA-256 `f864ef30ff55dfa9822712eac1910db9afdd4f5bde3ced7f6a25475aa197a52f`.
Its status is `FAIL-RESOURCE-FLOOR-NATIVE-UNVERIFIED`. A later retry needs a new
nonce, fresh source-bound preparation, sufficient resource headroom and a new
independently observed native result. V13 evidence remains immutable.

## Publication and continuation checkpoint

All current source work is being merged into GitHub `main` at the user's request.
Publication is a development checkpoint. Genuine Korean/Latin DirectWrite
trial v2 retains FAIL despite real alpha/Latin/framebuffer progress; see
[DirectWrite probe](DIRECTWRITE_PROBE_6970.md). The full Wine graphics compiler
repair is not yet sanitizer-verified; see [Wine graphics port](DIRECTX_WINE_PORT_6970.md).
System-wide themes, complete DirectX/Direct2D/DirectWrite, Signal, Legcord,
Office functionality and OS-wide TLS 1.3 remain required and incomplete.

## Fresh v15 after disk recovery: native component progress

The resource-guard repair is committed as
`d7220eb23da8b565b986c31e2a5125c163341d6e`; root repeated all 60 runner/startup
tests before selecting a new preparation. This one actual retry used plan
SHA-256 `5495b55ec066d20facf8ab402f0b3af3e338ce47f3c11aad7efe9818e50d3c29`
and fresh nonce `c91d358237284e97789d37ea0ec50796`. The protected installed
Windows 98 base and old failed v14 artifacts were preserved. This is an OEM
native control, not proof that ShizukuDOS has replaced MS-DOS.

Actual Windows 98 4.10.2222 launched the bootstrap, observer and theme child.
The component log records Classic → Modern → Classic, 84 background samples,
21 text regions and 63 live screen samples with no mismatches. Cleanup is PASS.
The observer independently recorded child exit 0, reaping and closed handles,
without forced termination; the bootstrap recorded the observer's actual exit
0. The bootstrap's own external exit remains NOT-OBSERVED. Root read the exact
four guest logs and inspected existing Classic/Modern/Classic-back screenshots.
The Modern and Classic-back clients are fully in front of Welcome. Initial
native title/background repaint and post-close desktop damage remain visible.

The owned QEMU exited normally after the recorded control queue finish; both
owned process IDs disappeared and the shared lane was released. Ninety captures
and 452.8 seconds are retained. Execution's final aggregate host output was
16,134,086 bytes against 16,777,216; minimum VM free space was 22,912,917,504
bytes against the unchanged 21,474,836,480 reserve. Final/peak net exclusive
COW growth was 499,712 bytes against 268,435,456. Final receipt byte accounting,
originals and frozen source/input guards passed.

The preserved run receipt is
`build/theme-native-runs/win98-gop-theme-6970-autostart-v15-diskretry/result.json`,
SHA-256 `f4cc185263f7dc1c3789576d4260715cdfc7bc7a93971c1ba8088e62e4acbc6d`.
Its canonical NEEDS-VISUAL-REVIEW and startup NEEDS-NATIVE-AND-VISUAL-REVIEW
statuses are retained. A separate raw framebuffer capture could not fit the
remaining host budget and was omitted; that gate remains unverified. The
records demonstrate app-local composition and child lifecycle progress. Native
desktop repaint, full visible output, system-wide themes and the ShizukuDOS
Windows 98 replacement path still require implementation and validation.

The immutable scoped review in the counted bootstrap output root has SHA-256
`d8aebc95f63db82e6e491bf8781ca1712b678662ff879856a80455dd0053804f`.
It preserves these limitations and separately accounts for the post-trial
review: 16,152,909 bytes, still below the fixed 16 MiB limit. Root's independent
log/image review SHA-256 is
`ce2bc646c581857e5c1f324abc8f64d45b1a31a5659a243a9f00f9a03a633bda`.
# Actual Windows 98 system palette selector — 2026-10-01

The new `ntwddm/win98/theme_selector/` is a native ANSI Windows 98 application,
not the K64 development shell or the older process-local renderer diagnostic.
Its Classic/ShizukuOS buttons call genuine `SetSysColors` for system indices
0–24. It preserves the first validated Classic baseline, saves a fixed-size,
versioned HKCU profile, reads the complete value back, and registers a bounded,
quoted local executable command for noninteractive startup restoration.
Failures restore the previous palette, profile and startup value; partial
rollback failures remain explicit. Fonts and Korean character sets are retained.
Gradient indices 26–28 and custom application renderers are not covered by this
increment. The historical provider ABI and diagnostic records remain intact.

Root executed the shared production codec/transaction tests: **139 checks passed
normally and 139 passed under ASan/UBSan**. Four resource acceptance regressions
passed. An initial native compile failed on two strict indentation diagnostics;
that FAIL receipt remains at
`build/win98-global-theme-selector/20261001T161312Z-7726f0b5/result.json`, SHA256
`adc13863b4500a702b2b9937f60e2b3bf23eec44ccb355fad5fe7566f0db7d51`.
The source fixes subsequently passed the actual compiler, linker and OEM PE32
gate without relaxing warnings. A separate intervening admission rejection at
19,726,491,648 free bytes produced no new build and is not a successful retry.

Final source-bound build receipt:
`build/win98-global-theme-selector/20261001T162314Z-9271b7bd/result.json`, SHA256
`bc88ada224d499bd141d594e2b60b8a8399718168cb192a78adde93b8daa6738`.
`SHZTHEME.EXE` is 27,477 bytes, SHA256
`fa0f0149770bed9fc5a72366535b087ad382f2ce50dd2241ab7a5f680654f832`.
The actual i486 PE32 has OS/GUI subsystem 4.10, parsed HIGHLOW relocations, no
unsupported modern PE flags, and 36 named imports present in the pinned OEM
inventory: ADVAPI32 7, KERNEL32 11 and USER32 18. Final build outputs including
the receipt total 2,209,746 bytes, within the admitted 8 MiB build limit; the
recorded free-space sample is 22,374,227,968 bytes, above the unchanged 20 GiB floor.

**Actual Win98 execution, independent process repaint, native failure rollback,
two cold boots, automatic persistence and complete visible-theme acceptance
remain unverified.** A separately owned read-only native observer and a new
single-COW two-cold-boot adapter are being prepared; the old v15 startup plans
cannot validate this new component. No final ISO or production release was made
by this source/build checkpoint. ShizukuDOS still must replace MS-DOS under real
Windows 98, and Kernel32/Kernel64 must serve that system; this compiled component
does not establish that architecture or all requested application functionality.

The dedicated optimizer independently confirmed 378,695,680 additional bytes
of sharing across three immutable derived binary pairs, with zero deletions and
unchanged whole-file hashes/inodes/lengths/mtimes. Earlier reclaim is excluded;
subsequent shared-host free-space changes belong to other workstreams.

## Independent global palette observer and two cold epochs

The shared native build gate now distinguishes the palette selector from its
independent observer. Four additional import/relocation regressions bring its
actual passing count to eight. A fresh product build passed the same 139 host
and 139 ASan/UBSan checks and produced the identical selector binary above.
Its receipt is
`build/win98-global-theme-selector/20261001T163426Z-f30fc76d/result.json`, SHA256
`7d2edfec0e8d97d6e65c52f84b5201aea3d9b59dc2f7fbaee10dde538e59a642`.

`ntwddm/win98/theme_global_probe/observer.c` independently reads all 25 native
system colors, the complete profile and exact startup bytes. It creates an
unrelated native witness window and owns only the selector child it launches.
It requires real system-color broadcasts, repaint, native background pixels,
normal child exit zero, and a final full readback after that exit. Temporary
disabled buttons, unequal reads and pending repaint share a latched deadline;
an expired stage cannot accept subsequently settled values. The observer's
imports cannot mutate system colors or registry values, resolve dynamic code,
or terminate a process.

The actual observer compiler and OEM PE gate passed. Receipt:
`build/win98-global-theme-observer/20261001T164450Z-89a8a48a/result.json`, SHA256
`96c0b05de65224b6a0cfe82c5d350b2232a3023c4f1034295ac560a1799e7019`.
`SHZOBS.EXE` is 37,208 bytes, SHA256
`2d48d00faaddbe70e6c6f51c520e9ce49752071ac20a3f16b3fcde955e75ee35`.
It has 47 native OEM imports and genuine i486 PE32 4.10/HIGHLOW relocations.
There is no guest result for this binary yet.

The new `tools/global_theme_trial.py` source uses one pinned private reflink
for two distinct, fully stopped cold hardware epochs and keeps the original
pre-injection COW baseline. Phase 1 is Classic baseline, ShizukuOS, Classic,
ShizukuOS and normal close. Phase 2 must observe saved ShizukuOS restoration
before launching a new selector child, then witness Classic return and normal
close. Its exact four output roots include all logs and receipts; only the
pinned private disk is excluded from the 16 MiB aggregate output budget. The
20 GiB reserve and cumulative 256 MiB exclusive COW budget remain mandatory.
This source is undergoing review; no cold epoch has executed. Observer self
logs do not prove observer or automatic restoration process exit, and visible
output and full-frame evidence remain separate incomplete gates.

A separate completed range-sharing audit recovered exactly 99,532,800 bytes
across three closed historical derived VM disks through 552 successful kernel
comparisons. Full source and destination hashes and identities remain intact,
with zero deletions. The unique frozen checkpoint is
`/root/Win98-Modern-boot/build/disk-optimizer-6970-closed-ranges-20261001T1632/checkpoint.json`.
This excludes the earlier 378,695,680-byte result and unrelated free-space
changes. Native admission still requires a fresh full-budget space check.

The independent adapter review identified and closed gaps in actual compiler
receipt formats, guest binary readback, pointer admission and complete image
validation. Root executed all **23 offline adapter regressions successfully**
with bytecode disabled and temporary fixtures on `/dev/shm`, avoiding new
physical-disk outputs while unrelated writers held the filesystem below its
reserve. Root separately passed `build_input` on both actual immutable compiler
receipts above, binding ten selector and eight observer command/source records.
The tests reject old startup plans, changed COW identity or baseline, stale and
partial native logs, wrong final post-exit state, missing compiler execution,
altered guest binaries/case/INI, unsupported absolute input and truncated or
corrupt native rasters. The observer's singular compiler version is validated
under its explicit role; it never substitutes for executed compiler evidence.

After each fully stopped epoch, the adapter independently reads both guest
executables and compares every byte to the staged and compiled artifacts. It
also verifies the exact case nonce/phase and unchanged byte-preserved WIN.INI
and FAT attributes. The separate verifier checks both epoch records and repeats
the final stopped-disk readback. Only keyboard input or a reported current
absolute pointer is admitted. Native PPM captures require complete raster bytes;
every QMP screenshot error aborts. Supported PNG readbacks additionally need
complete chunks, CRCs, exact bounded decompression and valid raster filter bytes.

Use `python3 -B tools/global_theme_trial.py prepare --help` for the explicit
selected-build, QEMU, firmware and GOP inputs. `prepare` never boots; `execute`
requires its exact new plan path/hash and the shared guest lease for both cold
epochs. `queue` admits bounded, nonce-bound GUI input, and `verify` independently
reads the stopped evidence. The retained absolute base/peer paths are specific
to this laboratory and are not private media supplied through public source.
No prepare or native epoch has executed at this checkpoint. No source-only
test proves ShizukuDOS boot, actual persistence, visible desktop output or
the final ISO.

The first actual preparation stopped before any guest-file injection or VM
launch. The host's four mtools aliases resolve to one executable, whose
dispatcher requires the original invocation name; invoking the resolved binary
directly returned exit 1. The exact failed clone remains byte-identical to the
protected base. Its guarded, self-inclusive failure receipt is
`build/global-theme-6970-bootstrap-4d67d317adf6/preparation-failure.json`, SHA256
`3928f574e24cb2405cfcd61fe3bdfa4a66f5d53802f71660b46368d4703d0b54`;
the four roots total 263,504 bytes, excluding that one pinned private COW.

The fix pins the resolved executable and supplies only a whitelisted mtools
role as `argv[0]` through `Popen(executable=...)`, without a shell. All four
actual role/version calls returned zero; read-only directory, attributes and
WIN.INI calls on the stopped failed clone also succeeded. The three added
regressions bring the actual passing adapter count to **26**. Independent
read-only review found no remaining material issue in this fix. Retry requires
entirely new roots, nonce and source-bound plan; the failed trial is preserved.

The dedicated optimizer subsequently confirmed 736,251,904 more bytes of
kernel/FIEMAP sharing across seven closed derived targets, with unchanged
whole-file contents and identities and no deletion or logical content write.
This excludes both earlier optimizer results above. While other writers held
the filesystem below reserve, exact plans and receipts were capped in private
RAM directories; immutable disk copies were made only after the unchanged
20 GiB floor plus pending receipt bytes and headroom was restored. Native and
build admission gates were never lowered. Durable batch checkpoints are under
`/root/Win98-Modern-boot/build/disk-optimizer-6970-ram-ranges-20261001T1657-batch{2,3,4}/`.

## Corrected preparation and parent-owned observer follow-up

The corrected v1 preparation actually passed on a fresh four-root trial.
The selected plan was
`build/global-theme-6970-stage-cc79ca47794a/global-theme-plan.json`, SHA256
`ed1a9bef1bc69fe276b87b090870c693090a6945ae4310510106a65f03220cdd`,
nonce `d3260ebb3e3449d48c425c5f37e50cd9`. The 2 GiB private disk remained inode
82113189 on device 2307 and had 139,264 exclusive bytes after injection. The
unchanged original baseline, staged native binaries, exact case, byte-preserved
WIN.INI and FAT attributes were actually checked.

Execution subsequently failed **before either epoch or QEMU was started**
because other host allocations crossed the unchanged 20 GiB reserve. The
failure receipt is
`build/global-theme-6970-run-cc79ca47794a/trial-result.json`, SHA256
`443a515718d163d641efe02921a3b7d7797183f0b9b7d6b9ce6f39ebc52def29`.
It retains `status=FAIL`, `epochs=[]` and 305,283 aggregate host-output bytes.
Keep this receipt, the private disk and `execute.claim`; this failed plan is
not reusable. A new source revision requires fresh roots and a new nonce.

The follow-up adds a fixed, argument-free `SHZGBOOT.EXE` native parent. Its
owned handle observes the independent observer's real wait and full DWORD
exit code. Each observer log now records its native PID; the separate parent
log must match that PID, nonce, phase and OS identity, with actual wait/query
and successful handle closure. Parent final log IO and its own external exit
remain explicitly unobserved. The separate automatic Run process also has no
owned handle. These incomplete gates are retained rather than inferred from
a completion message.

The v2 adapter requires schema 2, kind
`native-win98-global-selector-two-cold-boots-v2`, all three actual native build
receipts and both independently decoded parent/observer log pairs. It retains
the original single-COW baseline across two reaped QEMU epochs. Its primary
live QMP connection queries KVM before input; the reply must report actual
enabled acceleration and is frozen into the epoch evidence. Four offline KVM
gate tests and 34 adapter regressions passed in root's combined 38-test run.
Those tests, compiler results and historical preparation are separate from
new native execution, which has not happened.

Fresh source-bound product build:
`build/win98-global-theme-selector/20261001T172426Z-1ce398d8/result.json`, SHA256
`bcf2a0f6f21642d323892999835483aba0c06d1c063e509a56c3b1decff2ee05`.
The selector binary is unchanged; 139 host checks, 139 ASan/UBSan checks and
12 native import/resource regressions passed. Fresh PID observer build:
`build/win98-global-theme-observer/20261001T172441Z-8d392a9f/result.json`, SHA256
`2a9033a089f2121975b6a80d5b40b02c48d8239dacb6bc0d789fc3293fad71b1`.
Its 37,934-byte executable SHA256 is
`b8f79529dceb0fb8ae31d0d51bf96ce9fbc1b269a42374ea8aa02b1fd088f2a4`,
with 48 OEM imports. Root's v2 `build_input` actually accepted ten selector
and eight observer command/source records. The native parent build and new
trial still require their own fresh results.

The replacement architecture remains the
[ShizukuDOS → genuine Windows 98 contract](SHIZUKUOS_ARCHITECTURE_CONTRACT.md).
These theme controls do not establish replacement boot, modern application
functionality or a final ISO.

Independent review subsequently found that duplicate import descriptors for
one DLL could hide an earlier forbidden import from the role check. Root
reproduced both bootstrap termination and observer registry-setter hiding in
a failing regression, then made the shared gate reject duplicate normalized
DLL descriptors. No actual built PE had duplicate descriptors. All **13**
import/resource regressions passed, and all three native components were
rebuilt against that final shared gate:

| Component | Actual current receipt | Receipt SHA256 | Artifact |
| --- | --- | --- | --- |
| Selector | `build/win98-global-theme-selector/20261001T173205Z-782106c7/result.json` | `ec5f5b1ad05754fb0b2072a071f7f5e06b3a28707de192356091fdb4acfbb7fb` | same 27,477-byte `fa0f0149…` executable, HOST/SAN 139 each |
| Observer | `build/win98-global-theme-observer/20261001T173344Z-0b39a3e9/result.json` | `3dac28fe33b7ac52820b3376151ed843271befa6fe3143350498a122da7aa69f` | same 37,934-byte `b8f79529…` executable, 48 OEM imports |
| Parent | `build/win98-global-theme-bootstrap/20261001T173408Z-7183decb/result.json` | `a2e5083e48feff2e6af4a70f40976f8c00fbff228bdc04c19f21600cbd9e556f` | 13,897 bytes, SHA256 `c42b8039c7e73f4337dbe7f64fba1f1ae465c44dbd53be1cc70b6f37c1558f1c`, 14 OEM KERNEL32 imports |

The parent host and ASan/UBSan runs each completed **5,374** assertions. These
exercise real launcher code under the host API shim, including strict case,
path/arguments and OS gates, process creation, wait failure/timeout, full
nonzero DWORD exit codes, handle cleanup and final log IO failures. They are
host evidence, not native Win98 lifecycle results. Each final build stays
within its admitted 8 MiB output and retains the unchanged 20 GiB reserve.
Observer import totals are corrected from the actual receipt lists (47 before
the PID addition, 48 afterward); earlier prose totals were off by one and no
immutable result or artifact hash was altered.

The final adapter also checks the complete actual compiler recipe. Native
source operands must be the expected canonical files under the selected
source root and members of its hash closure. Host/SAN inputs include the real
launcher, host test and mock header. Extra or swapped sources, object/library
paths, response files, forced headers and compiler plugins are rejected. Root
then accepted all three genuine current receipts above, with ten selector,
eight observer and ten parent command/source bindings. The final combined
source suite passed **41 tests** (37 adapter and four KVM gate tests). No new
guest execution is implied by these source and compiler checks.
