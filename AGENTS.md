# Governing platform identity — latest absolute ShizukuOS architecture

ShizukuOS is the operating system and root platform. Its shared foundation is
ShizukuOS Core; ShizukuDOS, Kernel Layer (Kernel32/Kernel64/SHZLB.sys/VM services),
Driver Layer, Native Runtime, ShizukuVM and Linux Subsystem are its components.
Do not define ShizukuOS as another OS edition, shell replacement or skin.
Historical implementation origins do not determine platform boundaries; preserve
required license notices and accurate provenance/evidence.

The exact governing specification is docs/SHIZUKUOS_ABSOLUTE_ARCHITECTURE.md in
the owned Claude workspace. Own executable shell must extend existing code,
with Slade/Flute/Jade configurable themes, sound, ShizukuVM, chkrnl linux/msdos,
SHZLB.sys Linux sandbox, ShizukuLB (Shizuku Linux Basebuild), Nix-backed pkgs,
integrated Linux GUI windows and Terrasphere/Muzik/Sapphire/Folio/games.
Inspect and classify every requested feature before new implementation. Only
real executable paths tested inside actual ShizukuOS qualify as completed.
Earlier architecture identity and userland gates below are superseded.

# ShizukuOS architecture and delivery contract

## Latest user direction: ReactOS/Shorthorn shell and Windows 10 contracts

The user's latest 2026-10-03 instruction supersedes the earlier requirement that
original Windows98 USER/GDI/Explorer code must be the final userland. Keep the
ShizukuCore kernel structure and its DOS/32/64 components. Build the ShizukuOS
userland and directly implemented Windows-style shell by adapting ReactOS and
verified Shorthorn Project source, with Korean localization. Evaluate the user's
4074–4083 selection as shell design/version candidates; do not label public
One-Core-API source as a particular Longhorn build without evidence.

Windows 10 Win32/Win64 API and ABI compatibility is the target. Preserve correct
PE architecture, calling conventions, data layouts and real API semantics.
Upstream adoption, version strings or successful linking alone do not establish
Windows 10 compatibility. Report missing APIs and execution results accurately.
Keep license notices and source provenance at adaptation sites. Develop in
isolated lanes and preserve working installed boot paths during incremental
integration. The repository is https://github.com/NiSeullent/ShizukuOS.
Existing local workspace names are operational paths and need not be moved.

## Earlier direction (historical; latest direction takes precedence)

The user's 2026-10-03 clarification defines a mixed operating system:
**Windows98 appearance and retained Windows98 code/userland, Shizuku Kernel,
Shizuku Win32 and Shizuku Win32 (x64).** The common kernel is ShizukuCore.
Its subordinate components are ShizukuDOS (SZRm), Shizuku32 (SZPrtm),
Shizuku64 (SZLm), and ShizukuOS (Windows98). DOS is not the top-level kernel.
The kernel must progress beyond
MS-DOS/FreeDOS. ReactOS and Wine may inform implementation. This clarification
supersedes earlier documents requiring Windows98 VMM to remain the final
kernel, process or scheduling authority.

Advance service by service. Preserve working userland and compatible interfaces
while ShizukuCore Kernel assumes memory, process, scheduling, security, filesystem
and hardware/driver authority. DOS/VMM bridges can remain transitional paths;
do not make retaining them forever a completion gate. Shizuku Kernel32/64 are
kernel components, distinct from the user-mode KERNEL32.DLL API. Reuse existing
services rather than starting unrelated kernels.

Windows98 USER/GDI/Explorer behavior and existing code belong to the requested
userland. Original DLLs and VxDs may be gradually adapted or replaced with tested
Shizuku interfaces. An unrelated framebuffer desktop or source renaming alone
does not establish this userland. Declare PE32, Win16/NE and x64 support from
real execution. Follow docs/SHIZUKU_KERNEL_USERLAND_TRANSITION.md.

Keep all fifteen requirements and actual application, security, driver and
installation verification. Preserve historical results with their actual
architecture and scope. Original Microsoft-DOS controls, standalone kernels
and mocked APIs do not establish full product acceptance. Pre-Beta01 is a
finite milestone with disclosed supported conditions, not full completion.

Use the project installer. ISO distribution is exclusive to https://m98.nyase.kr
through nginx. GitHub receives public source/patches only. Never publish
Microsoft media, keys, installed private disks or secrets. User-provided
Windows98 code/media remains private; retain upstream licenses and provenance.

Respect canonical source, VM, media and publication owners. Prepare isolated
reviewed changes and handoffs; do not alter another session's running inputs.
User instructions take precedence over older architecture documents.
