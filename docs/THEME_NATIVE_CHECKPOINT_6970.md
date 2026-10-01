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
wait. Failure handling can stop and reap only that owned child. Host mocks
exercise 4,749 ownership, lifecycle, exit and log assertions under sanitizers.

For a guest handoff, copy the frozen DLL, `NTTHGUI.EXE` and `NTTHRUN.EXE` to a
new private clone's `C:\VXDLAB`, with absent `THEME.LOG` and `THOBS.LOG`, and
freeze the copied build receipt and artifact hashes. Generate a fresh
32-character lowercase hexadecimal nonce and launch
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
