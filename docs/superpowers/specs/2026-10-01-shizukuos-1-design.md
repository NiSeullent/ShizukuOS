# ShizukuOS 1.0.0 design and acceptance

The user requests ShizukuOS as the public product name, a self-developed install ISO, ShizukuDOS 10 as the Windows 98 MS-DOS replacement, and release 1.0.0 only at https://m98.nyase.kr. GitHub carries redistributable development files and patches; it must not receive ISO, personal Microsoft media, installed VM disks, credentials or private evidence. The existing comprehensive app, driver, acceleration, DeadScreen and multilingual-site requirements remain in scope.

## Existing code and chosen implementation

Retain the production SHZSETUP disk writer, GPT/ESP/ShizukuFS formats and independent readback checks. Add an actual in-guest graphical selection/review/install/result flow to that installer. A public install entry must ask the user to select a concrete disk and confirm erasure; unattended installation remains explicit for automated tests. Use existing user32/gdi32 and the Kernel64 display/input path, not a web installer or mocked screen. The chosen target is encoded by its unique kernel name rather than the existing `first` selector. A portable selection contract rejects invalid devices, duplicate names and incomplete confirmation before the disk writer can run.

The ISO boots the persistent ShizukuOS shell by default and offers the graphical installer and ShizukuDOS 10 recovery shell. Preserve the classic theme and add a selectable ShizukuOS userland theme. Retire ShizukuDOS 0.1 from current media and defaults; historical source/evidence may remain archived. Keep paths and API names needed by existing drivers and Windows 98 software compatible; renaming product text must not change Microsoft ABI identity or pinned third-party provenance.

Build the normal DOS10 shell separately from conformance-test media. A successful normal boot must reach a usable command prompt without a key gate or the QA program's permanent HLT. Test BIOS, UEFI direct and CSM fallback as distinct routes, with actual emitted serial markers and screenshots rather than assuming one route proves the others.

## Release acceptance

1. Public product UI, site and active release metadata say ShizukuOS. Target release is 1.0.0; development checkpoints cannot claim that release is complete.
2. All captured source branches are preserved and main is pushed without force. Inspect the final public tree and GitHub destinations for private files and install artifacts.
3. The shipped ISO boots unchanged under UEFI and BIOS/CSM. Normal DOS10 boot has no manual continuation prompt and exposes MS-DOS-compatible command and interrupt behavior; a branded FreeDOS test profile alone does not prove Windows 98 DOS replacement.
4. Install using the shipped graphical installer to a private disposable AHCI/NVMe test disk, preserve a second disk, independently verify its partitions/files, remove the ISO and boot the installed disk on UEFI and BIOS/CSM. Select/review/cancel must leave all disks unchanged.
5. Genuine Windows 98 starts through ShizukuDOS without depending on original Microsoft IO.SYS; Kernel32/64 and WDDMWrapper are integrated Windows 98 functionality. Current original-IO.SYS GOP observations and standalone component tests remain accurately scoped.
6. Chromium, Legcord/Discord, the current open-source office, Steam and the other previously requested apps perform real useful operations and exit normally on the integrated system. Drivers, acceleration, networking, persistence, theme selection and DeadScreen games require actual guest evidence.
7. m98.nyase.kr serves Korean/English homepage, preview, the final ISO and checksum through nginx. External DNS/TLS/browser checks must show the homepage rather than VNC and verify downloaded bytes. ISO is never uploaded to GitHub.

Until every requirement is evidenced, keep the comprehensive goal active and document current failures. A completed host test, successful build or standalone desktop cannot substitute for installed Windows 98, complete apps or the final release.
