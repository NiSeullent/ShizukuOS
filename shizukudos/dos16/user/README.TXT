ShizukuOS 1.0.0 - ShizukuDOS 10 normal compatibility bootstrap

BIOS: MBR -> FAT16 -> KERNEL.SYS -> COMMAND.COM -> AUTOEXEC.BAT.
UEFI x64: EFI/BOOT/BOOTX64.EFI -> CSMWrap/SeaBIOS CSM16 -> same MBR.
The normal path calls SHZSTART.BAT automatically and keeps a permanent DOS
prompt. SHZSAFE.TAG or missing/failed startup selects the recovery prompt.
F5/F8 boot-key support is retained. RECOVER.BAT provides recovery help.

This image uses pinned FreeDOS ke2046 and FreeCOM sources plus recorded
Shizuku patches. Their banners/licences are not proof of native Shizuku DOS.
The old conformance test disks remain developer-only inputs; the normal
image does not run those programs or their SHZEXIT halt automatically.

ShizukuDOS is intended to replace MS-DOS for Windows 98. Kernel32,
Kernel64 and WDDMWrapper are Windows 98 components. This current bootstrap
does not yet load Windows 98 GUI or complete that kernel bridge. Complete
MS-DOS compatibility and native Windows 98 integration remain goals.

ISO distribution: https://m98.nyase.kr/ . GitHub carries source/patches.
Keep corresponding FreeDOS/FreeCOM/CSMWrap sources and licences with any
redistributed binary media. No Microsoft system files or keys are included.
