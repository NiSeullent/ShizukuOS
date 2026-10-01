# Interactive native theme checkpoint — 6970

This branch reuses the app-local M98THEME implementation from peer commit
`a12a4a95e9f3fbddcea82d69f124876d22fb660f` (local cherry-pick `536bc69`).
The engine remains opt-in; this work does not install a system-wide theme hook.
The existing TLS and modern-application ports retain their respective owners.

`ntwddm/win98/theme_probe/probe.c` builds as `NTTHGUI.EXE`. It dynamically loads
the absolute EXE-local `M98THEME.DLL`, checks native Windows 98 platform/version,
opens real native GDI windows, and draws caption and button states through the
shared provider. Classic/Modern switch by C/M keys or mouse, automatically at
3 and 6 seconds, and close after 10 seconds. Handles are reopened on each
selection and checked during teardown. No registry change, installation,
network access, or guest startup is performed by this build.

Build and acceptance checks:

```text
python3 -B ntwddm/win98/theme_probe/build.py
python3 -B -m unittest discover -s ntwddm/win98/theme_probe -p 'test_*.py'
```

The builder retains unique immutable run directories and a separate latest
receipt under `ntwddm/win98/theme_probe/build`. Receipts bind source hashes,
exact commands, compiler versions, normal/sanitized host checks and both native
artifact hashes. The PE gate requires i386 GUI PE32 4.10, native OEM imports,
relocations, and the shared provider's exact exports. A build PASS explicitly
records `native_win98: not_tested` and does not establish visible guest output.

For a guest handoff, copy only the frozen DLL and EXE to a new private clone's
`C:\VXDLAB`, with absent `THEME.LOG`, and freeze the copied build receipt and
artifact hashes. Generate a new 32-character lowercase hexadecimal nonce and
launch `C:\VXDLAB\NTTHGUI.EXE --nonce=<nonce>` through an actual native process
observer. Capture the Modern frame between 3 and 6 seconds, the Classic frame
before 3 or after 6 seconds, and keyboard/mouse interaction. A ten-second
periodic screenshot interval can miss Modern entirely. Obtain the actual full
process exit code after termination; a shell launch or proposed exit field is
insufficient. Stop the exclusively owned guest before independent readback.

The verifier is read-only. Supply `--build-receipt`, its frozen
`--build-receipt-sha256`, `--log`, `--nonce`, `--exit-code`, `--provider-path`,
`--guest-dll`, and `--guest-probe`. It requires fresh log start/final nonce,
exact native OS identity, successful paint counts for both styles, two or more
selections, cleanup, final PASS, actual exit zero, and original/readback artifact
hashes. It rejects stale/partial/error logs, duplicate fields and changed
artifacts. Its result keeps `native_visibility_verified: false`: visible
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
