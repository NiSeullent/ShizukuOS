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
row click range and runtime minimum-size handling. The full runtime rebuild,
guest installer, actual disk writes and installed-system cold boots are pending.

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
