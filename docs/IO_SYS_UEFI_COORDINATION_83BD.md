# Original IO.SYS UEFI coordination — 83BD

Evidence review and parallel-session handoff, 2026-09-30. The target
is the original Microsoft Windows 98 IO.SYS and Windows VMM boot path through
UEFI GOP and the existing CSMWrap real-mode adapter. This document records
observations and artifact boundaries. Later native trials establish the
original IO.SYS entry/resume and a Windows 98 GOP desktop. File-save and full
WebKit rendering acceptance remain separate and have not passed.

## Ownership and source boundary

| Work | Owner and boundary |
| --- | --- |
| Original IO.SYS capsule | 83BD subagent: new `shizukudos/iosys_uefi/prepare.py` and `README.md` |
| Direct IO.SYS runtime hook | Parallel firmware agent: `shizukudos/iosys_uefi/patches/0001-direct-iosys.patch` |
| Isolated build and guest wrapper | Root: `shizukudos/iosys_uefi/build.py` and `boot.py` |
| Native GOP `.DRV`/VxD and persistent locator | Existing main session; do not edit or duplicate its dirty source |
| This review | Root-owned coordination document and retained evidence; native probes use isolated guest clones |

The capsule source API and ABI are documented in
[the IO.SYS profile README](/root/Win98-Modern-boot/shizukudos/iosys_uefi/README.md).
Root reports that the 30 synthetic capsule tests and CLI help passed. The
preparer reads a complete immutable disk snapshot, verifies the complete
original IO.SYS hash, derives its FAT32 location, and creates a private capsule
using `xb`. Original IO.SYS, source disks and extracted licensed inputs remain
outside tracked source. This is a bootstrap and in-memory entry-hook port;
the original Windows kernel continues afterward.

## Isolated firmware checkpoint

The current root build receipt is
[build-result.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/firmware/build-result.json),
dated `2026-09-30T15:02:51Z`. Its private source tree is
`build/shizukudos/iosys-uefi-port/firmware/work-20260930T150045/csmwrap/`.

| Artifact | SHA-256 |
| --- | --- |
| `CSMWRAP.EFI`, 483,328 bytes | `e88a7f0e5d247af44045aad7c5d20c24c0a3a95fa39ac5f8d72ceac412354cd1` |
| `Csm16.bin` | `039f38c9759add2b192aee7dd80172f975d1c7cbc801d71c37d15634ab653649` |
| `vgabios.bin` | `4dc749ad92671d8264ed7f96903060218378e66d955336bf5c27ea998af2f210` |

The receipt includes the helper identity patch, the current main-owned
`0002-force-firmware-gop.patch` with its durable `SHZLOC1` locator, and the
isolated direct IO.SYS patch. The latter uses original IO.SYS bytes supplied
only by the private capsule. CSMWrap is pinned at
`7f30b740c352ee952eb596bf10ae263a8a5da4c7` and SeaBIOS at
`578d260b94f62150bf6ab9149784287bd1154f06`.

A patch-context issue initially placed direct entry too early. Root reanchored
the hook to the unique `Legacy16Boot` context. The current builder applies
patches with `--fuzz=0` and checks that `Legacy16PrepareToBoot` precedes
`iosys_uefi_boot()` and that ordinary `Legacy16Boot` follows it. Keep this
semantic check when incorporating newer main-owned GOP patches. The initial
host build issues with `xxd -n` embedding and the missing printf declaration
were separately corrected. A successful firmware build establishes compilation
and linkage; it does not establish guest acceptance.

## Current original-entry probes

Root's isolated probe directory is
`build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930a/`.
The parallel direct probe is
`build/shizukudos/iosys-uefi-port/runs/run-ios-gop-7acd-direct-01/`.
Do not run either disk in place or change its files while its owning trial is
active. Aggregate acceptance requires each run's final `result.json` and
`iosys-entry-result.json`; live serial text is an intermediate observation.

The root probe's retained
[GDB log](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930a/native-entry/gdb.log)
records a hardware trap at original MSLOAD resume with
`CS=0070`, `IP=0208`, `SS=DS=ES=0000`, `SP=7bf0`, `BP=7c00`, `SI=0000`,
`DI=e348`, `BX=0700`, `CX=0000`, and `FLAGS=0202`. Its serial log contains
`SHZLOC1 preserved through SeaBIOS PrepareToBoot`, `IO98:ENTRY-HOOK-ARMED` and
`IO98:GOP-CONSUMED`. These are real partial entry observations.

That capture then fails on its first `dump binary memory` output filename,
reporting `No such file or directory` for the quoted `entry.bin` path. Therefore
the independent entry, descriptor, stack and consumed-marker memory dumps are
incomplete. The parallel run's
[entry result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/run-ios-gop-7acd-direct-01/iosys-entry-result.json)
is `FAIL`: resume registers and serial consumption passed, but completed GDB
capture and the memory-proof checks did not. These runs must not be labeled
entry-proof PASS. Root's now-retained
[entry result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930a/iosys-entry-result.json)
also reports `FAIL` with the same capture boundary and confirms that its
original archive and complete IO.SYS file remained unchanged. Its retained
BOOTLOG stops while loading `mshbios`; this separate trial does not yet reach
the later USER boundary observed in the main-session run below.
Root repaired the capture command and retained new private trials below;
no additional firmware patch followed from this host capture error.

The audited complete original IO.SYS hash is
`1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430`.
Its native entry context is derived from the private extraction/disassembly at
`build/shizukudos/iosys-uefi-port/io-entry-audit/`, rather than an assumed
`DL=80` convention. Source-only capsule reports retain `guest_executed=false`;
guest evidence belongs to the separate run receipt.

## Main-session USER initialization observations

The stopped main-session run is
`build/shizukudos/csm/run-win98-uefi-q35-kvm-gop-anchor-installed-probe/`.
Its [serial log](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-gop-anchor-installed-probe/serial.log)
records the actual SHZGOP VxD accepting its locator and mapping a framebuffer
at `80000000`, with `1280x800`, 32-bit pixels and a 5,120-byte pitch. It records
`Device_Init_proc DONE`, then later `Driver destroyed` during Windows teardown.
It contains no `SHZGOP MODE` message from the backend's `VESA_setmode()`.

The retained
[BOOTLOG.TXT](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-uefi-q35-kvm-gop-anchor-installed-probe/guest-logs/BOOTLOG.TXT)
continues beyond `mshbios`/`vhbiosd` load failures. It records successful GDI,
USER32, keyboard and mouse initialization, then `DISPLAY.drv` failure code
`0002`, successful `vga.drv`, another successful `DISPLAY.drv` load, and finally
`user.exe` failure code `0000` followed by Windows termination. Thus the old
MSHBIOS prompt is not sufficient to explain this later failure. Its precise
loader/initialization branch has not been captured.

Earlier commentary incorrectly described `minidrv.h` as unconditionally
disabling 16-bit debug output. The macro is actually under `#else`; the builder
passes `-DDBGPRINT`. That explanation is withdrawn. Absent `DriverInit: ENTER`
and `Enable:` serial output remains an observation, not proof of which
instruction executed or whether COM output was virtualized.

An independent byte inspection finds a definite structural defect in the
older installed NE display driver. `installed-copy-SHZGOP.DRV` declares two
segments, with code at file offset `04f2`, size `3128`, and 92 relocations
starting after `361a`. The relocation record at file offset `3644` is
`02 00 1b 22 03 00 00 00`: it requests a selector fixup at code offset `221b`
targeting absent segment 3. Its old linker map shows an empty `_TEXT FAR_DATA`
segment 3 near the dummy `pText` used by `GlobalSmartPageLock`.

The main session already owns the correction in
`drivers/shizuku_gop/build.py`: obtain the actual `CS` selector and validate NE
relocation/import targets. Its new private
[driver build receipt](/root/Win98-Modern-boot/build/shizukudos/shizuku-gop-ne-selector/build-result.json)
records two segments, entry `0001:220c`, and all 92 relocation targets valid.
This fixes the observed binary structure. The subsequent main-owned
`run-win98-uefi-q35-kvm-gop-ne-selector-probe` reaches the Windows 98 desktop;
root's later direct IO.SYS trials use a receipt-bound clone of that corrected
driver installation. Do not duplicate its source patch. The old run above
remains failed evidence and is not retroactively labeled a success.

The successful helper-ID GUI run and the failing GOP run both report CMOS
extended memory of 7,240 KiB with a contiguous-RAM boundary at `0812000`.
That shared observation does not support changing their low-memory reporting
as a fix for this particular USER failure. The current evidence likewise does
not justify a new SeaBIOS/CSMWrap compatibility patch.

See [PREVIEW_EVIDENCE.md](/root/Win98-Modern-boot/docs/PREVIEW_EVIDENCE.md) for
the separate boundaries between firmware entry, original Windows desktop,
driver activation and application acceptance.

The subsequent root trial
[IO.SYS entry result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930b/iosys-entry-result.json)
passes all ten native checks. The physical GDB breakpoint at `0908` captures
original `0070:0208` execution, expected register/flag values, the complete
VBR/stack and INT1E pointer, checksum-valid GOP metadata, and the IO entry
hook's consumed marker. Both the archive and original IO.SYS file remain
unchanged. The preceding capture failure remains part of the evidence and
does not invalidate or substitute for this later successful trial. This is an
entry/resume result; the later native desktop result follows below.

## Integrated original Windows 98 GOP desktop

The root `win98-iosys-gop-83bd-20260930c` and `...20260930d` trials use the
same isolated IO.SYS-port firmware and the main owner's corrected installed
GOP driver. Both pass all ten IO.SYS entry checks. In trial d, serial evidence
records the durable locator, native SHZGOP mapping of physical `80000000`,
and `SHZGOP MODE 1280x800x32 pitch=5120`. Windows reaches its actual Korean
desktop, Start menu, Notepad and Save As dialog. A fresh per-run token is
visibly typed into Notepad.

Trial d captures the actual 4,096,000-byte framebuffer at `80000000`, bound to
its checksum-valid durable locator. Root decoded that BGRX32 memory and
visually reviewed the Windows 98 desktop/Notepad/Save As dialog. The retained
GOP memory and independent QMP screen differ at only 16 of 1,024,000 RGB
pixels. Samples are sequential; no cause is asserted for those differences.
This supplies direct memory-to-visible-screen evidence, in addition to the
IO.SYS resume trap and native driver initialization. Reproducible comparison:

```sh
python3 -B shizukudos/iosys_uefi/review_framebuffer.py \
  --run build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930d \
  --capture 25
```

The saved comparison receipt is
[screen-025-gop-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930d/screen-025-gop-review.json).
It refuses overwrite, so do not rerun into the same retained output. Its
decoded raster is
[screen-025-physical-gop.png](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930d/screen-025-physical-gop.png).
The helper compares memory and pixels; visual Windows/app acceptance is a
separate root review and is not an automatic helper verdict.
The hash-bound root visual review is
[desktop-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-83bd-20260930d/desktop-review.json):
entry, native GOP desktop and Notepad launch/input pass; fresh-file saving
fails; full WebKit rendering and physical-hardware behavior remain unverified.

## Review corrections after trial d

The independent read-only review found two issues in the pre-d sources:
`boot.py` discarded the native runner's failure exit code when IO entry passed,
and the C capsule validator omitted the complete volume-end 32-bit LBA bound
already required by `prepare.py`. Root corrected both. The wrapper now binds
the native result digest/status/exit code and returns failure for failed native
checks even when its separate entry result passes. Trial d's old executed
wrapper and failed native receipt are preserved; its historical exit 0 is not
used as whole-workflow success evidence.

Four new regression tests pass. They compile the actual C parser extracted
from the source patch: ordinary geometry and the exact LBA limit are accepted;
overflowing whole volumes are rejected even when the IO prefix fits. Failure
aggregation rejects a failed GUI/file trial and an unknown native status.

The corrected isolated firmware is
[firmware-reviewed/build-result.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/firmware-reviewed/build-result.json).
Its `CSMWRAP.EFI` SHA-256 is
`bfd125a20191bbd597274bba2f19ff4c4f8c5b80d7c85caa98ca94341598d134`.
SeaBIOS and VGA BIOS hashes are unchanged. The later root
`win98-iosys-gop-ie-memory-83bd-20260930e` trial passes all ten original IO.SYS
entry checks using this corrected firmware. The receipt includes the separate
native runner status/exit and result digest. The initial captured Windows GOP
desktop is visually reviewed. Archive, original IO.SYS, source disk and frozen
guest inputs remain unchanged; owned QEMU exits cleanly.

The integrated IE memory probe does **not** pass in e. Its console-subsystem
launch meets a native Windows 98 display-mode warning; the fullscreen attempt
leaves a blank screen, and neither target nor memory log returns. Separately,
the frozen v1 batch incorrectly treats IETARGET's expected absent-provider
exit 3 as a target failure; root did not run that batch. Both observations are
preserved in
[integration-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-ie-memory-83bd-20260930e/integration-review.json).
The following source-identical GUI-subsystem probes require new executable
hashes and their own native evidence. The helper-firmware guest's earlier
console fixture results do not establish console support on this GOP driver.
The earlier firmware and captured d desktop evidence remain independent.

The strict fresh-file test in both c and d is `FAIL`. In d, the returned
`UEFIQA.TXT` still contains an inherited token, not its new
`windows98 uefi gui proof 3bfb284be5ef1bf4`. The saved bytes and baseline digest
are identical despite the native runner's `freshness` label. Treat that file
as unchanged; the complete native `result.json` correctly rejects acceptance.
GUI keyboard/menu actions and disk-save acceptance must not be inferred from
the action-delivery receipts. The original archive and original IO.SYS remain
unchanged, the source clone remains unchanged, and the owned VM exits cleanly.

Retired root trial a/b/c disks are losslessly compressed in place to private
`windows-uefi.retained.qcow2` files to preserve build headroom. Each
`retained-disk.json` binds the raw digest, compressed digest, successful full
virtual-byte comparison and restoration command. Their original native
receipts and failure evidence are retained unchanged; restore and verify the
raw digest before using an older run as a prepared source.

The IE integration lane adds consuming tools `tools/iewebkit_build_win98.py`
and `tools/iewebkit_target_probe.cpp`, plus an actual pinned WTF Win9x RunLoop
port in `tools/iewebkit_port/`. Its independent Win98 native fixture run is
`build/shizukudos/csm/run-win98-uefi-83bd-ie-native-diagnostics`; it uses a
private helper-ID firmware clone and has separate ownership from the root
GOP trial. Full WebKit/JSC rendering requires a linked engine/provider and is
not inferred from those host or platform fixtures.

## GUI memory diagnostic after e

Root adds `tools/iewebkit_port/core_memory_gui.c` and
`core_memory_gui_build.py`. The adapter includes the unchanged pinned
`core_memory_native.c` and calls its renamed entry with a single bounded nonce.
It creates no console and replaces no memory implementation. The new GUI
executable has its own binary hash; the earlier console receipt remains intact.

The private build receipt is
[MEM9XG.receipt.json](/root/Win98-Modern-boot/build/iewebkit-core-83bd/memory-gui-root-83bd/native-v1/MEM9XG.receipt.json),
SHA-256 `1deeab0045fb7a08547a0fca5d1d73134b1a372840a0982d5b2ca60d679686d6`.
The PE32 GUI executable is
`3b5b0284ca852b8e69d4e9cb4682fcf2d3696983a3be95fe02779b2010b2c22b`.
Compilation and complete native-export import checks pass. Native execution
remains unverified until a later owned GOP run returns its fresh memory log.
The log provenance must bind the original source/header and this new GUI
binary/receipt, rather than the earlier console executable.

## Cold integrated GOP run g

Trial f stops during preparation, before QEMU, because measured free space
falls below the 20 GiB reserve plus the 256 MiB dirty reserve. The baseline
runner removes its unstarted disk; source receipts and hash-bound
`preparation-review.json` remain. This is an unexecuted trial, not an IO.SYS
entry regression.

Root's opt-in `boot.py --reflink-source` freezes a separately hashed private
runner. Two exact source anchors select `cp --reflink=always --sparse=auto` and
a 4 MiB metadata estimate for the initial copy. Unsupported filesystems and
changed/ambiguous source contracts fail closed. A real XFS copy/overwrite check
proves separate inodes and unchanged source contents. Source/clone full hashes,
the 20 GiB free-space guard and the 256 MiB reserved headroom remain required.
The canonical native runner is unchanged. Historical g's `st_blocks` growth
check does not measure exclusive COW allocations; its independent free-space
guard remains active. A separate FIEMAP accounting correction is being reviewed
for subsequent runs, without changing g's executed source or receipts.

Cold trial `win98-iosys-gop-ie-gui-83bd-20260930g` passes all ten original IO.SYS
entry/resume checks with corrected firmware. Actual Windows 98 starts on GOP.
Its final physical framebuffer at `80000000` is 1280×800 BGRX32; all 1,024,000
RGB pixels match the sequential QMP screen sample exactly. The decoded desktop
is visually reviewed. The owned VM exits cleanly; archive, original IO.SYS,
prepared source and frozen fixture inputs remain unchanged.

The GUI memory probe now **passes natively**. It returns the fresh fixture
nonce and all four source/header/GUI binary/receipt hashes. A real 2 MiB
allocation is touched and freed; committed private virtual bytes change from
491,520 to 2,588,672 and recover to 491,520. Shared pressure-policy boundaries
pass. This does not measure resident working set or execute JavaScript.

Actual IE5 on Win98SE 4.10.2222 passes target checks, diagnostic registration,
new unique IEXPLORE activation, BHO interception and custom DocObject activation.
Owned IE shutdown, both component unregisters, key absence and exact restoration
of the wizard value pass. The complete document URL check **fails with exit 29**:
`Document.show` reaches `engine_missing`, but `Document.Load` and
`Document.remote_https` are absent. The pinned diagnostic Show returns a missing
module error before the later IPersistMoniker Load callback. Custom document
activation is not document URL ingress or a WebKit rendering pass.

The hash-bound component review is
[integration-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-ie-gui-83bd-20260930g/integration-review.json),
SHA-256 `a61ce83f62143091764b46d02be60a1cf969b94b17f2d9f83650df81f68b3a3d`.
The physical image is
[screen-044-physical-gop.png](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-ie-gui-83bd-20260930g/screen-044-physical-gop.png).
The wrapper's health exit 0 is not the integrated document acceptance verdict.
Full WebKit rendering, JavaScript, TLS and physical-machine boot remain unverified.

Only root's three earlier failed firmware trees are losslessly archived as
`work-*.retained.tar.gz`. Their companion manifests verify every regular file
hash and symlink, retain a restoration command and preserve the failed source
versions. Successful firmware trees and other sessions' artifacts are untouched.

## Allocation guard and unexecuted application trial h

The next private runner replaces `st_blocks` growth with strict Linux XFS
FIEMAP net exclusive data growth. The independent free-space floor remains
20 GiB, enforced by the IO.SYS wrapper even when a lower reserve is requested.
The optional 128 MiB quota is stricter than the default 256 MiB quota. A genuine
WTF/ICU executable requires an explicit 64 MiB total input bound; at most eight
digest-bound inputs and all existing scope and receipt gates remain required.
Canonical runner source is unchanged. The complete private variant and helper
are frozen separately. Eight actual XFS accounting tests pass, including a
1 MiB COW overwrite that changes exclusive allocation while `st_blocks` stays
unchanged. The owned-process abort regression tests also pass.

Trial `win98-iosys-gop-wtf-protocol-83bd-20260930h` aborts before the desktop:
guest writes overlap the two allocation observations. The strict helper refuses
the unstable observation, and the private exception path immediately kills
only the owned VM. Nine captured original-entry checks pass, including resume,
GOP consumption and unchanged archive/IO.SYS. Native health fails, so the
aggregate entry and trial receipts remain **FAIL**. The final stopped-file
allocation observation passes. No WTF or IE application command was sent;
all seven declared outputs are independently read back as absent.

This failure is retained in
[pre-application-abort-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930h/pre-application-abort-review.json),
SHA-256 `24917d539af52fe2692f699a8ee9d30482f20d325827f8628d83ceab1eb9d99a`.
The subsequent source variant pauses its owned running VM, verifies paused
state, takes strict FIEMAP observations, checks quota/free space and a five-second
bound, then resumes only after successful verification. Errors leave the writer
paused for immediate owned-process abort. QEMU 10.1 upstream's
[stop handler](https://github.com/qemu/qemu/blob/v10.1.0/monitor/qmp-cmds.c#L46)
uses a [VM-stop implementation](https://github.com/qemu/qemu/blob/v10.1.0/system/cpus.c#L274)
that drains and flushes block devices. The actual installed version is 10.1.0;
the strict two-map check remains required independently of this source inference.
The failed h receipt is not revised by the new variant.

## Quiescent allocation sampling and integrated trial i

The corrected wrapper pauses only its owned, already-running QEMU before
each allocation sample, verifies paused state and two stable FIEMAP scans,
then checks the selected quota and 20 GiB free-space floor before resuming.
Any failed check leaves the writer paused for immediate owned-process abort.
The five-second deadline is checked before the resume request; it is not an
absolute timeout on a blocking kernel call. Four real subprocess abort tests
and eleven sampling/order/failure tests pass. The complete 57-test IO.SYS host
regression passes with no skips; its retained receipt is
[host-regression-57-root-83bd.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/host-regression-57-root-83bd.json),
SHA-256 `fcbe9840eb06032dcee312de5f900b425ff0ed2e2012f1dd07353470cd42bbd5`.

Cold trial `win98-iosys-gop-wtf-protocol-83bd-20260930i` uses corrected
firmware and passes all ten original IO.SYS entry/resume checks. During its
398.3-second native interval, 1,652 quiescent COW observations complete; the
longest takes 0.167 seconds. Peak and final net exclusive data growth are
3,010,560 bytes, below the 128 MiB quota. The lowest observed host free space
is 21,525,778,432 bytes, above the 20 GiB floor. The stopped-file allocation
review also passes. Original media, complete original IO.SYS, prepared source
and frozen inputs remain unchanged. The owned VM exits with code 0. These
health checks do not establish either application component's acceptance.

The retained [entry result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/iosys-entry-result.json)
has SHA-256 `c70a1509c85b409c954cc13820a4aeda67eb7610681982e65d0fb73b292bc35d`.
The [native result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/result.json)
has SHA-256 `5ba49a59956e378171a21fdafb4dc2a0e2a69c6c99f5406425e3bdfeaac98871`.
The final requested physical GOP sample remains 1280×800 BGRX32 at
`80000000`, with 16 of 1,024,000 RGB pixels different from the sequential
QMP sample. Its [comparison receipt](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/screen-047-gop-review.json)
and [decoded image](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/screen-047-physical-gop.png)
are retained. Blank IE frame pixels remain in that image despite the logged
owned IE shutdown and absent IE taskbar entry. Their cause is not established;
this capture does not certify complete erase/repaint behavior or page rendering.

The actual IE protocol component now passes its bounded URLMon ingress and
cleanup review: fresh exact URL/nonce, real `GetBindInfo`, GET/body eligibility,
pending-state clearing before callbacks, custom CLSID/MIME/data reports and
owned-process/registration/wizard cleanup are verified. The overall DocObject
criterion remains **FAIL(29)** because `IPersistMoniker::Load` is absent and
Show reaches `engine_missing`. The diagnostic report is aborted and never
reports successful page completion. Independent review validates 59 digest
bindings in [independent-ie-protocol-review.json](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/independent-ie-protocol-review.json),
SHA-256 `b6302b306cbb86a761e0c48c83cf49c95b0060ea830481ff91d89ea9389152af`.

The genuine linked WTF v3 executable fails during allocator initialization.
Windows reports `EIP=005d2316`; disassembly of the exact frozen PE locates
`__mi_theap_default + 6`, reading `mov %fs:0(,%edx,4), %eax` with
`EDX=000005e5`. Its NT TLS-layout assumption is incompatible with this
measured Win98 thread layout. The authoritative stopped-disk log contains
the fresh nonce, exact target, Unicode CryptoAPI failure 120 and successful
ANSI acquisition/random generation. An earlier zero-byte live FAT read is
superseded by that returned log. WTF initialization, dispatch and timers
remain unestablished. The hash-bound [crash review](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/runs/win98-iosys-gop-wtf-protocol-83bd-20260930i/wtf-native-crash-review.json)
has SHA-256 `2069b089ffee1cb07ece93d65f9ea40ff6476b423ea1408a1118212046e6eee6`.
The next private source port uses real Win9x TLS APIs and ANSI CryptoAPI;
native acceptance still requires a fresh frozen candidate and trial.

## Preserved evidence and build headroom

Only stopped root-owned a/b/c/e retained qcow2 containers receive exact-byte
XFS deduplication. The kernel compares 227 aligned ranges, reports SAME for
every complete request and preserves each container's existing SHA-256 and
identity/size/timestamps. Stable FIEMAP physical-data union accounting measures
202,686,464 bytes reclaimed. The larger change in summed exclusive flags is
not used as reclaimed-space evidence because it double-counts sharing changes.
No guest disk content, d/g/h/i raw image or peer-owned artifact is changed.
The 20 GiB floor is enforced throughout. The retained
[dedupe result](/root/Win98-Modern-boot/build/shizukudos/iosys-uefi-port/retained-dedupe-83bd-20260930/result.json)
has SHA-256 `83dc57d179d3b4db0640b905447955ab1f4db805506473f8bda35fcc39a5b456`;
its bounded plan and operation journal remain alongside it.

## Separate owner application's later GOP acceptance

The existing driver/app owner has since retained two successful genuine
Windows 98 GOP trials for unchanged official Notepad++ 8.9.8.1 using its
explicit native ordinary-desktop field interpreter. Root reads their scoped
receipts and independently confirms the receipt digests; it does not rerun
or edit those peer-owned images. The first owner's 26-gate
[GOP application review](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-latest-npp-environment-v3-20260930T1748/native-gop-latest-npp-review.json)
has SHA-256 `4969701e15e2170caa6927bdb9cd2c40a34367d3666d7487caa00f8170e1bfa5`:
fresh 44-byte save, warm reopen and normal application/helper/outer-process
exit zero. Its separate 25-gate
[cold keyboard review](/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807/native-gop-latest-npp-cold-keyboard-review.json)
has SHA-256 `e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175`:
the 44-byte file persists into another GOP boot; distinct keyboard input is
saved as a fresh 39-byte file and all three final file contents are checked.
The mistaken shortcut and restoration of the old private document remain
explicit in that review. The native field interpreter is required; earlier
unassisted application exit failures remain failed. These later owner trials
do not revise root c/d's failed original Notepad save or establish WebKit,
VLC, Chromium, GPU 3D or physical-machine behavior. The preview remains owned
and validated by the existing driver/app session.
