# Win98-Modern architecture and delivery contract

ShizukuDOS replaces the MS-DOS foundation used by **actual Windows 98**. This
was the initial plan and remains the required architecture. Kernel32, Kernel64,
the Supervisor and WDDMWrapper are components of that Windows 98 foundation;
they do not change the final target into an independent replacement desktop.
The product and distribution name is ShizukuOS; its DOS foundation remains
ShizukuDOS.

Standalone kernels, the development shell, host tests and firmware boot tests
are useful component checks. Preserve their actual scope and original evidence.
Completion requires actual Windows 98 running on ShizukuDOS, with the requested
drivers, acceleration and applications. A boot through original Microsoft DOS
is a control result, not evidence that ShizukuDOS has replaced it.

Keep this contract in delegated tasks and handoffs. The current implementation
and remaining DOS-to-VMM and service connections are described in
`docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md` and
`docs/SHIZUKUOS_ARCHITECTURE_SUPPLEMENT.md`.

The user's complete architecture is preserved in
`docs/INTEGRATED_ARCHITECTURE.md`. Windows98 VMM remains the Windows process and
scheduling authority; PMA schedules auxiliary Shizuku workers and synchronizes
with VMM through an explicit bridge. Shizuku Kernel32 is not Microsoft's
KERNEL32.DLL. Modern application surfaces belong in Windows98 USER/GDI windows.
Reuse shared hardware services and implement real required driver contracts;
do not create a second NT kernel or report successful placeholder operations.
The full ongoing requirements and their evidence gates are tracked in
`docs/SHIZUKUOS_FULL_GOAL_ACCEPTANCE.md`.

The final 1.0.0 installer uses the project's own installation system. ISO
distribution is exclusive to https://m98.nyase.kr through nginx. GitHub receives
public development files and patches only. Never publish private files,
Microsoft installation media, installed guest images or secrets. User-provided
Windows 98 media stays private.
