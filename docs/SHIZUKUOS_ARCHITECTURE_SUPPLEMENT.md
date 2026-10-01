# ShizukuOS architecture supplement — 1.0.0 development candidate

This supplements the preserved 2026-10-01 source audit; it does not rewrite its
150-line snapshot or historical evidence. The final product name is ShizukuOS.
ShizukuDOS 10 replaces MS-DOS as the foundation for actual Microsoft Windows 98;
Kernel32 and Kernel64 belong to that same foundation. Standalone boot/app
profiles remain component tests, rather than the final independent OS product.

The source audit's unfulfilled DOS-to-VMM contract, WIN.COM/startup connection,
original IO.SYS dependencies and actual native Win98/Kernel64 GUI bridge are
still implementation work. Renaming source and building a component desktop
does not fulfill any of those ABI or native startup contracts. The DOS16,
Kernel32, Kernel64, GOP, VxD and compatibility source provenance and upstream
ABI names must remain traceable after branding changes.

User-selectable Classic and ShizukuOS themes are required in actual userland.
The SHZDESK candidate adds client-surface palette selection through F6/buttons
and validates a data-volume settings record before restoring it. Host checks
verify exact parsing and failed-I/O behavior. They do not establish native
Windows98 Explorer/themed non-client painting or guest cold-boot acceptance.
The existing native app-local M98SetThemeStyle provider and its C/M controls
remain the starting point for full Win98 theme selection/persistence tests.

Final 1.0.0 must be gated by the original requirements and user-visible app
functions: real Windows98 startup on ShizukuDOS, required hardware acceleration
and drivers, Chromium browsing, Legcord/Discord functionality, current
open-source Office document operations, Steam client/network/library/game
operations, and both complete userland themes. Intermediate results keep their
actual runtime and original pass/fail scope.

Official ISO distribution is exclusive to m98.nyase.kr. GitHub holds public
source and patches; Microsoft media and installed images remain user-provided.
The public website identifies this work as a development candidate and preserves
original screenshots, checksums, upstream versions and historical artifact paths.
See [SHIZUKUOS_TARGET.md](SHIZUKUOS_TARGET.md) for the source, theme and release
contract. A complete host build is a prerequisite for later guest verification,
not a substitute for it.
