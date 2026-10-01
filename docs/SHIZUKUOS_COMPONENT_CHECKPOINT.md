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
The integration owner has not repeated those VM runs at this checkpoint.

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
