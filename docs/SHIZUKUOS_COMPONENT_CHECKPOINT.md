# ShizukuOS component checkpoint — 2026-10-01

ShizukuDOS replaces MS-DOS for actual Windows 98. Kernel32, Kernel64,
Supervisor and WDDMWrapper serve that architecture. The repository's
`AGENTS.md` carries this requirement into future delegated work.

## Normal DOS10 startup

The normal DOS10 image automatically runs SHZSTART and leaves a permanent
COMMAND.COM prompt. The previous conformance image intentionally ended with
SHZEXIT; it remains a separately selected developer input. Supervisor's normal
ESP uses DOS10 and its `esp-conformance.img` is explicitly for QA.

The frozen DOS10 handoff was verified against all 17 source hashes before
integration. Its final image SHA-256 was
`290ec74ecc99d98f3c5378c14a41a558275189b9c1980fdd7cbb7a5487c18378`.
The owner ran two normal BIOS cold boots, three recovery cases, and two
UEFI-CSMWrap cold boots. These seven disposable-guest checks passed without
pre-start keyboard input, including keyboard-created file persistence.
The integration owner subsequently rebuilt DOS10 (56.345 seconds, exit 0)
and repeated all seven runs using QEMU/KVM on fresh disk and firmware copies.
All passed: BIOS normal cold boots plus three recovery cases, and two UEFI
cold boots. Actual PS/2 commands created files; independent FAT byte readback
and the second cold boot's TYPE output agreed. The source image stayed intact.
The BIOS and UEFI result receipt hashes were respectively
`7f452ad4fe4afc9e6caa72b64a5579d4e76d2fe88653f97a23fe66b16fe14bb7`
and `db85bfa3f10f0b0dc69f73aef384d7908154671e95a5afce8a6c37535fe2d23d`.
The initial long-path attempt failed before boot because its Unix socket path
exceeded the host limit. A short temporary socket directory fixes portability;
all five BIOS cases then passed under the original long evidence directory.

The owner also freshly compiled the Supervisor and checked normal and QA ESP
member bytes. Those test ESPs omitted optional K32/K64/Win64 guest inputs and
must not be reused as a complete product ISO. Physical USB, the DOS-to-VMM
connection and native Windows 98 startup remain unverified by these checks.

## Own installer and userland themes

SHZSETUP has a native userland installer frontend over the existing disk writer.
Disk review and confirmation generation perform no disk reads or writes. The
frontend selects an unambiguous whole disk, reviews its metadata again, and
requires the normalized ERASE confirmation before the writer starts. Escape
cancels before installation. A Windows 98 data partition is optional; it is
not an installed Windows 98 system and does not supply Microsoft media.

The production target-selection helper passed strict GCC and Clang ASan/UBSan
host contracts. The current frontend and disk writer compiled and linked via
the actual `build_setup()` function; its EXE SHA-256 was
`e2f6b625a07048d49010751027aa05f173580bcedf815940a99c0f43b82ac387`.
Independent source review found and corrected the F2 input collision, hidden
row click range and runtime minimum-size handling. The production runtime
rebuild subsequently completed in 1942.049 seconds (exit 0), preserving all
778 recorded source bytes plus the syscall-header guard. It includes enabled
Wine adapters, 149 C checks, one C++ check, ten Wine checks, the installer,
desktop and four development drivers. WIN64.IMG contains 221 members
(22,337,355 bytes, SHA-256
`f3f48eb6854eec1a09798566e87699fe40919ee2072b7ed4e734f5d3e39028dd`).
At that checkpoint, installation and installed-system cold boots were separate
acceptance gates; the later four-phase result is recorded below.
Compiling this runtime does not establish Chromium,
Discord, Office or Steam behavior.

The integration owner freshly compiled native and standalone Kernel32/Kernel64
with the installer startup and block-device guards (468.317 seconds, exit 0).
The installer profile inventories devices without mounting target filesystems,
so a previous mounted filesystem cannot later flush stale state over a new
partition table. The shared raw-write guard still refuses mounted disks and
their whole-device/child relationships. Independent strict and sanitized host
checks cover those guards; guest disk installation remains a separate gate.

The production media embeds INSTALL.IMG inside its UEFI boot filesystem, adds
the explicit interactive installer policy, and defaults to a persistent desktop.
An unattended/self-test build requires explicit development options. Packaging
rejects stale source-bound component receipts. Current media excludes the
retired ShizukuDOS 0.1 input. Nine media-contract tests and eighteen actual
image-I/O/ISO extent tests passed. No new complete ISO boot is claimed here.

The diagnostic matrix now validates only selected media, accepts the current
DOS10 menu without the retired input, and checks PS/2-created RAM-disk files
instead of expecting the conformance profile to exit. It selects CSM explicitly
from the UEFI menu and checks the recorded firmware policy. Production desktop
media cannot pass as a diagnostic direct-boot profile. Fifteen input/policy
regressions passed; current ISO matrix guest runs remain a separate gate.
The additional cases cover the actual qualified DOS image names in media
receipts, reject missing or ambiguous inputs, and retain byte-hash validation.

## Optional native Windows 98 domain

The 32-file native-domain handoff was checked against its frozen hashes and
reviewed independently. Only its small deltas were applied to the loader and
Kernel64 entry point, preserving interactive installation. The integration
owner freshly compiled all native and standalone kernels (173.893 seconds,
exit 0), the merged Supervisor, and ten strict/sanitized C programs with 6,358
checks. Supervisor's normal and conformance ESP build also passed with the
current kernels/runtime (32.381 seconds, exit 0).

The native domain requires explicit Supervisor policy, an exact opt-in config,
an owned SHA-pinned installed disk and an explicit SeaBIOS ROM. Preparing or
compiling this path does not verify its actual VMCS boot or replace the disk's
original DOS. A separate newly cloned UEFI original-DOS control reached the
actual Korean Windows 98 desktop while recording DOS/VMM calls. Its Windows
GUI is a comparison control, not replacement-DOS acceptance. Private media
and raw control evidence are excluded from public source commits.

A subsequent explicit native-domain VM actually entered VMX and created the
Windows 98 VMCS, then failed after 528 exits with a guest triple fault. The
actual SeaBIOS trace reported an absent bridge before the fault at CS 8,
RIP `0xe002a`, CR0 `0x31`; IO.SYS, VMM and the Windows GUI were not reached.
The result SHA-256 was
`2475085ffd4afef3d1f43a5fbd267cd1588509538b70087f059b2236b7bba24b`.
The source disk, frozen components and original ESP stayed unchanged. This
failure is retained separately from the successful original-DOS GUI control.
Passive, bounded exit diagnostics then identified an uninitialized low-ROM
callee. Shadowing the full pinned 256 KiB ROM allowed the actual BIOS to
relocate and continue initialization. A subsequent VM failed at an unsupported
MTRRCAP MSR read because CPUID advertised MTRR. Clearing that native-domain
feature bit removed the observed fault; the next actual VM reached 568 exits
and failed at an unmapped LAPIC-address read at GPA `0xfee00030`. Its result
SHA-256 was
`e82897d16ea654a84d044826be5d326bf547379019ad4283ad6f450ecbcc6f46`.
Each failure, original source disk and frozen input set remains intact. None
of these faulted native runs establishes replacement-DOS boot.

A bounded, read-only absent-LAPIC compatibility page then removed the actual
`0xfee00030` read fault without advertising an APIC or creating IRQ behavior.
The following actual 300-second native VM entered the original Microsoft DOS
boot path and displayed genuine ScanDisk at 99% through native text-VRAM/GOP
output. No fatal native domain fault was recorded, but VMM/Windows GUI boot
remained unverified. Its result SHA-256 was
`66207f3ebb0e373dc6c95cee7883d822da58da14bd2f9800187a397119ec6afc`.
The captures show the same ScanDisk frame throughout the recorded interval;
there is no claimed desktop progress. No blind keypress or disk dirty-bit
change was used. The original disk and all pinned inputs stayed unchanged.
This run uses a preserved earlier runtime input set and original DOS. Its old
Kernel64 conformance/IPC failures are retained; it is not a current runtime
pass or ShizukuDOS replacement acceptance.

## DOS-to-Windows contract increment

The DOSMGR patch reports only implemented capabilities and distinguishes the
DX request selector for its CDS response. It does not enable unimplemented
Windows instancing or enable WIN31SUPPORT by default. An opt-in tracing TSR
preserves the interrupted flags and register state while recording selected
DOS/Windows calls. Seventeen contract and actual 16-bit instruction tests
passed; default DOS10 also compiled with the new patch. These are contract
checks, not proof that Windows 98 has booted on the replacement DOS.

The development shell's F6/Theme window offers Classic and ShizukuOS palettes
with durable data-disk setting storage. Its real palette/record/persistence
helper passed 583 checks in both plain and ASan/UBSan builds, and the AMD64
shell compiled with warnings as errors. These checks do not establish native
Windows 98 or whole-system theme integration.

## Actual desktop and full-runtime VM checkpoint

Two fresh production desktop QEMU/KVM cold boots passed. Actual GOP output,
PS/2 editing, save/reopen, independent writable-disk byte verification, a child
process, and reopening the saved file after a second cold boot were checked.
Eight actual VM screenshots were retained. The result SHA-256 was
`0c53865144e7e374d5e2f97ff55190aa603f9c30219cd10f751b3f817c39a939`.
This is the Shizuku development userland, not the native Windows 98 desktop.

The separate UEFI GOP full-runtime VM failed after 442.691 seconds: 23 of
26 runner checks passed, with guest exit 1. Its result SHA-256 was
`541454ebe77d3710c11894161476a310fdd2331ebf8106a40f83da2294dd5eb1`.
The original result, serial trace and screenshots remain unchanged. The
128-program ceiling omitted checks; console identity confused access rights
with endpoint direction; token querying lacked its access check; section
duplication required object-security-descriptor controls. Missing loader
fixtures, public certificate inputs and production MPR/OLEACC ports also
surfaced. Steam's integer-scaling check selected an older browser adapter
instead of the canonical base API. Corrections require a coherent fresh
runtime/kernel build and another actual VM run before a pass can be claimed.

The console correction passed 3,688 checks across strict GCC and sanitized
Clang, plus complete native/standalone kernel and Win64 object compilation.
Both real integer-scaling provider bodies passed 13,375 arithmetic cases per
compiler. The actual production OLEACC source/IDL/resource module linked in
an isolated output. Pinned public certificate inputs retain ordinary signature,
hostname and time verification; host verification is separate from guest TLS
verification. None of these host checks establishes application acceptance.
The first section correction passed 97,228 host checks per compiler, but used
an incorrect unconditional source-rights ceiling. Actual Chromium-oriented VM
checks exposed that regression: a section with an explicit NULL DACL permits
access expansion, while an empty DACL denies it. The old host pass is retained
as superseded evidence. The next correction must check the current object
descriptor and keep both allow and deny controls; it cannot obtain a pass by
removing either control. The corrected implementation now evaluates the
current descriptor and classifies explicit section-execute access. Both real
duplicate routes, ownership/failure cleanup and all six section-right masks
passed 705,935 checks per compiler under strict GCC and Clang ASan/UBSan;
the four complete production objects and the guest fixture also compile.
The fixture retains all prior assertions and uses a real empty ACL rather
than assuming an absent descriptor denies expansion.

A coherent fresh runtime build completed in 980.389 seconds with all 819
recorded source bytes unchanged. It freshly compiled 149 C checks, one C++
check and three enabled Wine checks, plus the actual QA DLLs and runtime
providers. Fresh native/standalone kernels and Supervisor also built. The
next actual std GOP VM ran every ordinary check (151 of 151) and verified the
intentional exit-7 parent's delayed child separately. It finished in 377.376
seconds with 24 of 27 runner checks passing and guest exit 1. Seven programs
failed without a fault: T_CHROME_SECTION, T_E1_KERNEL32, T_K32_SYS,
T_U_OLEACC, T_U_VERSION, T_WS2_LEGACY and T_WS2_SERVICES. Previous loader,
MPR, local standard-accessibility, certificate-input and Steam API checks
passed in that VM. This is runtime validation, not a complete Steam client or
Chromium browser acceptance result.

The expanded VM coverage revealed that creating CONOUT$ used the CONIN$
constructor; a one-line isolated correction passed 11,126 checks per compiler
including the actual production open route and constructor. The version-error
fixture printed before capturing GetLastError, so the three error snapshots
are now captured before logging. Public, pinned Debian/Alpine services,
protocols and generic localhost catalogs are packaged into both runtime
images; no host/private network configuration is copied. Their actual WS2
parser/file/thread checks and eleven packaging controls pass. These
corrections require another coherent build and actual VM run. The original
failed serial output and screenshots remain unchanged.

The corrected section/console sources are included in a fresh all-kernel
build (100.070 seconds, exit 0), with all 190 source pins and producer receipt
matching. Its wrapper result SHA-256 is
`036ef50a3252a7de83f0cbdcfe776453b4d94e77825e697f99997cb8a12cdfbe`.
This build alone does not establish a guest pass.

A desktop installer archive contained T_HELLO twice. The producer correction
passed five actual packaging regressions, including FAT readback and the
unchanged QA system-file layout. A separate installer VM runner tests cancel
without writes, the selected disk, and installed UEFI/BIOS cold desktops.
Its resource, raw-device and write-counter controls passed. The first actual
attempt failed before guest execution because QEMU rejects a read-only IDE
disk; a subsequent mixed-device preflight found the distribution QEMU lacks
NVMe. Both launch failures are retained. An existing upstream QEMU 10.1.5
provides the genuine models: paused AHCI, NVMe and read-only virtio device
identities were checked before allowing guest instructions. Four actual VM
phases then passed: Escape cancellation with zero writes to all three devices;
confirmed installation writing only the selected NVMe target; cold UEFI boot
from that installed NVMe disk; and an independent cold BIOS boot from it.
The actual result SHA-256 is
`d90bcadbf82a580e11ff925be5249b16d53d7f4d01dada385d335aa65ed8fa15`.
The decoy AHCI disk and read-only virtio boot medium remained untouched.
Independent host audit verified GPT/ESP/system members, FAT/ext2 integrity and
the installer log. Both cold boots reached the real development desktop,
opened the editor and completed the guest's explicit flush/exit sequence.
These screenshots and source-bound inputs are retained. This proves the
Shizuku component installer, not Windows 98 setup or latest application use.
All four VM processes were reaped; original sources and input disks stayed
unchanged, with the 17 GiB free-space reserve maintained.
The pre-correction development ISO is not a validated downloadable release.

## Release boundary

Product metadata identifies the 1.0.0 target as prerelease development. The
runtime FileVersion retains its NT compatibility value independently of the
product name and version. This checkpoint is not the final 1.0.0 release.

ISO distribution is exclusive to nginx at https://m98.nyase.kr. GitHub receives
public sources and patches only. No installer ISO, user-provided Microsoft
media, installed guest image or private validation binary accompanies this
source checkpoint. The remaining real Windows 98, drivers, acceleration and
required application gates remain in `SHIZUKUOS_TARGET.md` and
`SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md`.
