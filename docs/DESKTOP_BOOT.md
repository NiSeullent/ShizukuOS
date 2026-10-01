# Persistent desktop and Windows 98 UEFI validation

The continuation worktree is `codex/uefi-desktop`, based on `main` at
`abc160b429f5498a2a5328b05af29e099964d54a`. Existing worktrees and running VMs
are independent of this work.

The requested end state still includes Microsoft Windows 98 GUI boot through
UEFI, working storage and input drivers, a usable desktop, and the project's
complete implementation goals. The ShizukuDOS shell and a firmware handoff
alone do not establish that end state.

## Implemented boot profile

`shz.desktop` starts `C:\SHZ\SYS64\SHZDESK.EXE` instead of the kernel QA
workload. The kernel waits for the real process without a session timeout;
an explicit session exit flushes writable volumes and reports errors.

The persistent shell provides a desktop, taskbar, file browser, ASCII editor
and application launcher. It registers a real shared shell window; other
processes can query it and cannot replace it. Window/process cleanup removes
the registration. See `shizukudos/win64/apps/shzdesk/README.md` for controls
and precise limitations.

`tools/build_shizuku_se_iso.py --reuse-builds --desktop --skip-qemu` selects
the desktop on UEFI and BIOS boots and includes it in the installed system.
The installer consumes the source archive's actual system programs, Wine DLLs
and fonts, verifies its receipt hash, and rejects missing shell files. Default
builds retain the QA profile. The installed profile also retains the one Hello
demo selected by the shell's launcher, while excluding the remaining QA suite.
Desktop installation payloads must be explicitly
built with `shizukudos/install/mkpayload.py --desktop`.

## Verification commands and evidence scope

```sh
python3 shizukudos/win64/build.py
python3 shizukudos/kbuild.py
python3 shizukudos/dos16/build.py
python3 shizukudos/supervisor/build.py
python3 shizukudos/tests/run_k64_gop.py --qemu /usr/libexec/qemu-kvm --display std --timeout 900 --png
python3 shizukudos/tests/run_k64_desktop.py --qemu /usr/libexec/qemu-kvm --accel kvm
python3 tools/build_shizuku_se_iso.py --reuse-builds --desktop --skip-qemu
python3 shizukudos/tests/run_k64_desktop.py --qemu /usr/libexec/qemu-kvm --accel kvm --boot-iso build/windows98-shizuku-second-edition.iso --out build/desktop-harness-iso
```

The desktop runner requires source-bound build receipts. Two cold UEFI boots
must exercise real keyboard input, directory enumeration, editor save/reopen,
an actual Win64 child process, an intentional session exit and volume flushing.
The host independently reads the persisted FAT32 file and checks exact bytes.
Screenshots are captured from the guest. ISO mode also verifies shipped EFI
files and boot configuration without replacing them.

Builds and host tests are prerequisites; they do not prove guest behavior.
The actual desktop acceptance run at
`build/desktop-harness/20260930T122603-091uzkk8/result.json` passed two cold
OVMF/Q35/KVM boots. It records 26 common checks, 28 first-boot checks and 27
second-boot checks: real 1280x800 GOP screenshots, keyboard-driven browsing,
save/reopen, a real child exiting with code 7, idle persistence and explicit
session exit. Host extraction and FAT checking passed after both boots. The
25 persisted bytes have SHA-256
`22d8f82bf677991bcd1e0c07ebe4c8de20f1e04b1f4e8181d348849a4237bd99`.

The first attempt's exit gate exposed FAT32 mounting through `fs_mount` alone,
so the common volume table was empty and its flush reported success without
flushing the disk. FAT now uses the common mount registration. The passing
run records actual device flushes and `K64 vfs: shutdown D: ...: rc 0`.

GOP QA on the baseline `qemu64` CPU originally failed with #UD in `mem_init`:
the host GCC defaults to x86-64-v3 and emitted BMI2 `shlx`. Kernel and native
Supervisor builds now explicitly select x86-64; the BIOS stub selects i486.
The unchanged GOP runner then completed with 84/85 applications passing;
its display, status and input checks passed, including the shared-shell tests.
`T_DELAY.EXE` alone faulted writing a delay IAT placed in read-only `.idata`
by the actual toolchain. Frozen inputs, disassembly and results are retained at
`build/gop-provenance/20260930T122640/`. A narrow resolver fix temporarily
changes pointer-page protection, publishes atomically and restores the original
protection. Its regression covers actual delay thunks, protected module/IAT
slots, concurrent resolution and explicit failure paths. The next complete
source-bound GOP run executed all 85 applications without the previous fault;
84 passed. `T_DELAY` alone reported a rejecting-hook error mismatch, while
all protected-slot and concurrency checks passed. Its frozen evidence is at
`build/gop-provenance/20260930T125605/`. The first lazy trace-environment lookup
overwrote the resolver's error with `ERROR_ENVVAR_NOT_FOUND`; tracing now
preserves the caller's error. A fresh-child regression checks the first and
cached missing-procedure results. The rebuilt runtime then passed all 85 applications in the unchanged GOP
runner (`build/gop-provenance/20260930T131556/result.json`). This fix does not establish the
separate ntdll direct/bulk delay resolver's protected-slot behavior.

The shipped desktop ISO also passed two cold boots, including exact on-disk
file persistence and the genuine child process, at
`build/desktop-harness-iso/20260930T132352-fr68teka/result.json` (43 common
checks, 28 first-boot and 27 second-boot checks). Its SHA-256 is
`fd54efaf64577ff0a15e4aa271ffea6770fcd00dbcb207354f97aea2e0494da0`.
That immutable ISO predates the later QA kill-readiness correction.

A refreshed QA run exposed a race: the parent killed the child before its
expected console banner appeared. The parent now waits for that exact child
banner with a bounded deadline, then performs the same kill and exit checks.
The unchanged complete GOP run at
`build/gop-provenance/20260930T141023/result.json` passed 85/85 apps,
26 guest checks and 40 source/artifact checks in 290.8 seconds. The killed
child actually emitted its banner and exited with 119 and zero faults.
Kernel SHA-256 is
`293ad4517cb881a69133410123f86751564d4edd9b7b445434e196817158a02a`.

Build-host memory contention can delay
even small compiler and file-reading operations. Per-invocation
`SHZ_COMMAND_TIMEOUT_SECONDS=1200` extends the default command timeout while
leaving explicitly bounded test timeouts intact.

## Microsoft Windows 98 UEFI path

`shizukudos/csm/test_win98_uefi.py` restores only an installed disk snapshot
into disposable files. It verifies the compressed checkpoint and original
files before and after the run, preserves the Windows MBR/boot sector while
adding CSMWrap's EFI entry, and boots private OVMF variables with at least two
CPUs. It records actual screens, VGA text, registers and firmware logs.

The first executed Q35/KVM attempt reached OVMF, the CSM BIOS proxy and
`Booting from Hard Disk...`, then QEMU paused with a KVM emulation failure
(flat protected-mode EIP `f000ff53`). Its screenshots do not show Windows 98.
The initial receipt's `NEEDS-VISUAL-REVIEW` verdict is insufficient: the
recorded KVM failure contradicts GUI completion. Subsequent accelerator and
controller comparisons are recorded below. Original checkpoint files remained unchanged.

Q35/TCG and PC/TCG reached the authentic Windows 98 startup splash but did
not establish desktop entry. A fresh logged Q35 diagnostic isolated a stall
while loading `HIMEM.SYS`; original inherited logs were explicitly excluded
from that conclusion. A disposable configuration with `/MACHINE:1 /VERBOSE`
then recorded `HIMEM.SYS`, `DBLBUFF.SYS` and `IFSHLP.SYS` loading successfully
and an actual ScanDisk screen. Default HIMEM memory testing was preserved.
The exact private configuration,
fresh logs, screenshots, CPU state and source-preservation checks are retained
under `build/shizukudos/csm/run-win98-uefi-q35-tcg-himem-machine1/`.
The longer logged run subsequently reached the actual protected, paged Windows
98 kernel: fresh logs recorded VMM, NTKERN, CONFIGMG and IOS initialization,
then `DEVICEINIT=UDF`. The screen still did not establish a desktop. A repeated
KVM run's per-CPU capture identified the early firmware failure on CPU1, the
BIOS proxy AP, while CPU0 remained in real-mode SeaBIOS. Those evidence scopes
are distinct from the TCG kernel progress.

The 600-second logged Q35/TCG run then reached the genuine Korean Windows 98
desktop, icons and taskbar with its initial Welcome window. Its unchanged
receipt, screenshots, fresh boot log and separate visual review are retained
under `build/shizukudos/csm/run-win98-uefi-q35-tcg-himem-machine1-kernel600/`.
That establishes GUI entry, while application interaction needs separate proof.

The proxy AP's failure was traced to reading its ID through xAPIC MMIO after
the trampoline disables the local APIC. The pinned original SeaBIOS source
is retained, with `shizukudos/csm/patches/0001-helper-id-with-disabled-lapic.patch`
using CPUID's initial APIC ID only in the disabled-APIC path. Enabled xAPIC and
x2APIC behavior is retained. A separate patched build and the subsequent
default build produced the identical EFI SHA-256
`b269a841a1f45df6eda59daf26b0df172abd6f97a0a9ca80792ea6740a5aa51d`.
Original firmware artifacts remain frozen separately.

The patched Q35/KVM run reached the genuine Windows 98 desktop in about one
minute and remained running through its 180-second observation. Its final
QEMU exit was zero, its fresh boot log was independently extracted, and
original checkpoint and prepared-source files remained unchanged. See
`build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-m1-full/` for the preserved
receipt, screenshots and separate visual review. A first keyboard trial
successfully closed Welcome, opened Start and Run, launched Microsoft Notepad
and entered text; its requested save failed, so the interaction verdict remains
FAIL. Fixed-time inputs also proved unreliable while the Welcome window was
still busy. A later screen-guided run saved an actual new Notepad file and the host
read back its exact 43 bytes, SHA-256
`8e2308c32f7974f21111ff4fd8934f55a85819c174f241455af7d6a236af2582`,
at `build/shizukudos/csm/run-win98-uefi-q35-kvm-helper-id-gui-manual/`.
A fresh cold clone reopened the persisted file (screen 015 of the
`native-vxd-shared-data` run). The earlier input/save failures remain recorded.
These Windows screenshots use the legacy VGA option-ROM path; they do not
prove the new GOP driver.

The patched firmware passed the actual DOS UEFI and legacy BIOS TCG comparison,
including disk reads/writes, the BIOS interrupt tests and the one-CPU refusal.
The KVM comparison exposed the same A20-disable wrap failure on both paths;
its failed evidence is preserved in `build/shizukudos/csm/dos-kvm-a20-failure/`
and the checks were retained. The successful TCG comparison is at
`build/shizukudos/csm/run-uefi-csmwrap/result.json`.

Microsoft's archived [Windows 98 Msdosdrv.txt (KB191473)](https://ftp.zx.net.nz/pub/archive/ftp.microsoft.com/MISC/KB/en-us/191/473.HTM)
documents the machine-handler override. This is a measured QEMU compatibility
experiment, not a general hardware setting. The measured GUI results above
apply to those explicit private QEMU configurations.

## Installer media prerequisites

The default QA ISO and raw installation disk were built and independently
read back with valid EFI/BIOS layout and FAT checks. The initial selected ISO trial completed all 85 apps without faults but
failed its hardcoded firmware-memory-hole assertion. Inspection found an
actual 4 KiB reserved runtime page rather than the assumed 8 MiB NVS hole.
The matrix now checks the real handoff map, checksum, PMM exclusion and
actual heap chain. Its next run passed those checks but exposed the child
kill-readiness race above. Both original failed receipts are preserved.
The refreshed source-bound ISO trial passed at
`build/qa-iso-provenance/20260930T153901/result.json`: all85 runtime tests,
41 guest checks and40 source/media preservation checks passed, process exit0.
Its exact ISO SHA-256 is
`998e0717cb3dc094ed740ae431088f1f91c9fcc37ad90753ccda125ed9d65424`.
The earlier IPC deadline was shorter than the declared ten network-child
wait budgets; its outer budget now derives from those existing waits. A later
genuine SRW lock lost-wake was fixed by publishing the wait marker while the
parking bucket lock still protects the current owner. The actual-source
deterministic interleaving test distinguishes the failing old predicate from
the correction. The fresh complete ISO trial retains the original inner delay
test and parent deadlines. All earlier failures remain preserved.
Desktop-profile media uses a
separate payload and ISO so its shipped boot configuration can be exercised
without modifying the QA media.

The native VxD build originally failed because Clang 21 lowered an IOCTL switch
to a biased lookup-table relocation outside the LE object's address range.
`-fno-jump-tables` selects branches for that build; the strict LE writer and
driver logic retain their checks. The rebuilt production driver passed its
11 host tests, including sanitized bridge and Win64 wire tests. This resolves
media packaging, not the separately recorded native Windows 98 VXDLDR failure.
Six isolated control-only LE/DDB fixtures and a separate actual Watcom-linked
fixture and explicit byte-verifying DOS
loader programs are prepared under `ntwrapper/vxd/minimal/`. Each generated
COM passed 731 synthetic CPU scenarios and 72,771 assertions, retaining raw
loader-result recording and unload ownership checks. The private CPU tool's
wheel, package files and actual loaded native library were verified. Frozen
native-trial inputs are at `build/minimal-vxd-native-trial-20260930T1313/`;
these host results alone do not establish native Windows 98 loader acceptance.

Two subsequent genuine Windows 98 SE trials passed byte/EOF verification,
VXDLDR load and unload with CF=0, AX=0, and DOS exit 0: the original
`shared-nonresident` fixture and the actual Watcom LE fixture. Their runs are
`build/shizukudos/csm/run-win98-uefi-q35-kvm-native-vxd-shared-nonresident/`
and `...-native-vxd-watcom-le/`. Other flag/layout variants retained the
CF=1, AX=0006 failures. Removing the permanent-resident flag was isolated
in the minimal fixture; the full NTWRAP9X driver still requires its own trial.
See [Shizuku basic graphics](SHIZUKU_BASIC_GRAPHICS.md) for the separate
GOP firmware and native display package. Its fixed-mode native Windows98
monitor output and GDI fill/copy/readback passed in two corrected cold GOP
runs. The additional audit corrects an earlier mistaken final black-monitor
verdict from the actual late original QMP screenshots; earlier raw receipts
and reviews remain unchanged. GPU3D, automatic prompt-free startup and all
latest-app functionality remain outstanding.

AHCI reads/writes in Kernel64, USB descriptor enumeration, driver
`DriverEntry` probes, and Supervisor DOS/K32/K64 tests establish distinct
capabilities. They do not prove Windows 98 IOS storage drivers, USB HID input,
all hardware support, or the selected applications' complete functionality.
Those remain part of the full objective.
