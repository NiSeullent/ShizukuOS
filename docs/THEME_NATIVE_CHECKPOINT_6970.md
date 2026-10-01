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
The separate official ONLYOFFICE x64 pin is recorded for the AMD64 Kernel64
runner; the ia32 package remains available for a separate native port.

`tools/required_app_runtime_handoff.py` supplies explicit package preparation,
standalone image construction and diagnostic execution stages. It rejects an
ia32 entry before extraction, preserves complete publisher layouts, and binds
the selected peer runtime source to the receipt. Runtime diagnostics cannot
claim application functionality or Windows 98 execution. Full extraction and
execution remain subject to the same storage reserve and separately verified
guest lifecycle; the native Win98-to-Kernel64 GUI bridge remains unverified.
