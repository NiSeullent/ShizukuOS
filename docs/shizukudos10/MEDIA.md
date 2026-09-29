# Windows 98 Shizuku Second Edition — VM install media

One hybrid ISO is the product: `build/windows98-shizuku-second-edition.iso`, built by
`tools/build_shizuku_se_iso.py`. It boots as a CD and, written raw to a USB stick or
attached to a VM as a hard disk, as a disk, on legacy BIOS and on UEFI.
`tools/build_shizuku_se_disk.py` builds a secondary raw disk image
(`build/windows98-shizuku-second-edition-disk.img`, MBR + FAT32) with the same boot menu.
`tools/test_shizuku_se_boot_matrix.py` (also `shizukudos/tools/shz.py test --suite media`)
boots both in QEMU and judges every run from host-side evidence.

## What boots

| Firmware | Path | Result |
| --- | --- | --- |
| Legacy BIOS, CD | El Torito default entry = `isolinux.bin` (no emulation) | boot menu |
| Legacy BIOS, USB/HDD (ISO) | `isohdpfx.bin` MBR → `isolinux.bin` (isohybrid) | boot menu |
| Legacy BIOS, raw disk | syslinux `mbr.bin` → FAT32 VBR → `ldlinux.sys` | boot menu |
| UEFI | `\EFI\BOOT\BOOTX64.EFI` = Shizuku loader → Supervisor | needs Intel VMX (EPT, unrestricted guest) |
| UEFI without VMX | loader boot manager → `\EFI\SHIZUKU\CSMWRAP.EFI` → SeaBIOS CSM → the same medium's legacy boot | boot menu |

Boot menu (menu.c32; mirrored on COM1 115200 8N1, which also accepts the keys):

| Key | Entry | What runs |
| --- | --- | --- |
| K (default, 30 s) | Kernel64 + Win64 runtime | `mboot.c32 /SHZ/K64/BOOT.ELF --- KERNEL64S.BIN --- WIN64.IMG`: the standalone Long Mode kernel (no Supervisor) runs its self-tests and every `T_*.EXE` in WIN64.IMG, then prints `SHZ-EXIT:0` |
| D | ShizukuDOS 10 DOS16 (FreeDOS profile) | `memdisk harddisk` + `ShizukuDOS10/dos16/shizukudos-dos16-hd32.img` (raw disk: `\SHZDOS\DISK.IMG`): FreeDOS runs the conformance programs, `SHZ-EXIT:0` |
| 1 | ShizukuDOS 0.1 | `memdisk floppy` + `ShizukuDOS/shizukudos.img` (raw disk: `\SHZ\SHZDOS01.IMG`): the project's own shell, `A:\>` |
| I | Install ShizukuDOS 10 (only when SHZSETUP is present) | Kernel64 with `shz.setup=auto` on the Multiboot command line; files from `build/shizukudos/setup/` (or `--setup DIR`) under `\SHZ\SETUP\` |

**Interim (until the loader's boot manager is merged):** the current loader has no boot
manager. Without VMX it prints `REFUSED` and returns to the firmware; the firmware then
starts its UEFI Shell, which runs `\STARTUP.NSH` from the EFI volume, and that starts
`\EFI\SHIZUKU\CSMWRAP.EFI`. A firmware without a UEFI Shell stops at its boot menu instead:
add a boot entry for `\EFI\SHIZUKU\CSMWRAP.EFI`, or boot the VM as legacy BIOS.
`\EFI\SHIZUKU\BOOT.INI` (`mode = auto`, `csm_path = \EFI\SHIZUKU\CSMWRAP.EFI`) is already on
the medium in the boot manager's grammar (`--boot-mode` chooses the mode).

Kernel64 on UEFI + CSMWrap: SeaBIOS reports CSMWrap's E820 map, which keeps OVMF's ACPI NVS
at 8–9 MiB. The Multiboot stub (`shizukudos/kernel64/standalone/boot32.c`) takes RAM from the
Multiboot memory map and hands the gaps to Kernel64 (`standalone/memholes.h`), which keeps
them out of its page allocator (`K64: 3 firmware memory hole(s), 249 page(s) kept out ...`).

## VM profiles

Only QEMU (TCG, no KVM) was run. VirtualBox, VMware and Hyper-V lines are settings derived
from how the medium works, not test results.

| | Setting |
| --- | --- |
| RAM | 512 MiB recommended; 256 MiB minimum (Kernel64 uses up to 256 MiB; memdisk holds the 32 MiB DOS16 image) |
| vCPUs | 1 is enough on legacy BIOS; **2 or more on UEFI** (CSMWrap keeps one logical CPU and refuses with one) |
| UEFI | **Secure Boot off** (nothing is signed). Supervisor needs nested Intel VT-x; otherwise CSMWrap |
| Storage for the CSM path | IDE/SATA (AHCI), NVMe, USB, LSI/MPT/PVSCSI/MegaRAID SCSI. Not virtio, not Hyper-V VMBus |
| Serial | COM1 115200 8N1: menu mirror, keys, every result line |

- **QEMU (tested):** `-machine q35 -m 512 -smp 2 -cdrom THIS.iso` (legacy BIOS). UEFI: add
  `-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=<copy of OVMF_VARS_4M.fd>`
  (a non-Secure-Boot build with the UEFI Shell). As a disk:
  `-drive file=THIS.iso,format=raw,if=none,id=d0 -device ide-hd,drive=d0`.
- **VirtualBox (not tested):** BIOS VM with the DVD on IDE/SATA. EFI VM: *Enable EFI*, 2+ CPUs,
  SATA/IDE/NVMe controller, Secure Boot off.
- **VMware Workstation/ESXi (not tested):** BIOS firmware as legacy BIOS. UEFI firmware:
  Secure Boot off, 2+ vCPUs, SATA/IDE/NVMe or LSI/PVSCSI.
- **Hyper-V (not tested):** Generation 1 (BIOS, IDE DVD) gets the legacy menu. Generation 2 is
  UEFI-only with VMBus storage, which SeaBIOS inside CSMWrap cannot drive: use Generation 1.

## Contents of the ISO

| Path | What |
| --- | --- |
| `isolinux/` | pinned syslinux 6.04 (Ubuntu `3:6.04~git20190206.bf6db5b4+dfsg1-3ubuntu3`): isolinux.bin, ldlinux/libcom32/libutil/menu/mboot.c32, memdisk, isolinux.cfg |
| `SHZ/K64/` | BOOT.ELF (Multiboot stub), KERNEL64S.BIN, WIN64.IMG |
| `SHZ/SETUP/` | SHZSETUP files, only when present at build time |
| `ShizukuDOS10/efiboot.img` | the El Torito EFI image (also MBR partition 2 type 0xEF and a GPT entry): `\EFI\BOOT\BOOTX64.EFI`, `\EFI\SHIZUKU\{CSMWRAP.EFI,CSMWRAP.INI,BOOT.INI,README.TXT}`, `\SHZDOS\{DISK.IMG,KERNEL32.BIN,KERNEL64.BIN,WIN64.IMG}`, `\STARTUP.NSH` |
| `ShizukuDOS10/` | build outputs, receipts, `LICENSES/`, `SOURCE/` (FreeDOS, CSMWrap + submodules, syslinux Debian source package, Shizuku source), `GPL-NOTICE.TXT` |
| `ShizukuDOS/shizukudos.img` | ShizukuDOS 0.1 floppy |
| `Windows 98 Shizuku Second Edition/`, `SHZSE/` | NTWrapper9x, NTWin32Wrapper9x, NTWDDMWrapper9x binaries; SHZSE overlay installer |
| `DRIVERS/` | driver store: `DRIVERS\<package>\` as shipped, `HWIDS.TXT` (hardware/compatible ID → package, INF, models section), `MANIFEST.JSON`, `README.TXT` |
| `README.TXT`, `VMPROFIL.TXT`, `LIMITS.TXT`, `SOURCES.TXT`, `HASHES.TXT` | documentation, per-file SHA-256 |

Microsoft files are never included. `--win98-media PATH` overlays the builder's own
Windows 98 media under `WIN98/` in a separate `-private` ISO (git-ignored `build/` only).
`--driver-package DIR` (or `PACKAGE=DIR`, repeatable) copies a user-supplied driver package
unchanged; the repository ships none (tests use a synthetic INF only).

## Build and test

```
python3 tools/build_shizuku_se_iso.py            # rebuilds CSMWrap + ShizukuDOS 10, then the ISO
python3 tools/build_shizuku_se_iso.py --reuse-builds   # package existing, receipt-checked outputs
python3 tools/build_shizuku_se_disk.py           # raw disk from the same outputs
python3 tools/test_shizuku_se_boot_matrix.py     # 18 QEMU runs, one at a time
python3 tools/test_shizuku_se_boot_matrix.py --media iso-usb   # optional: the ISO as xHCI USB mass storage
python3 shizukudos/tools/shz.py test --suite media
```

The harness selects menu entries over COM1 (letter + Enter) and judges each run only from
host-side evidence: the Kernel64 COM1 log through `shizukudos/tests/run_k64_standalone.py`'s
parser plus every `T_*.EXE` of WIN64.IMG; for DOS16 memdisk's mBFT table in guest memory gives
the live RAM disk, which `shizukudos/dos16/verify.py` checks (RESULT.TXT, T_COM.OUT,
T_EXE.OUT byte-exact); for 0.1 the `A:\>` prompt and a `DIR` listing. OVMF runs also check the
ordered boot path (BDS → loader → Shell `STARTUP.NSH` → CSMWrap boot device → isolinux).
When a medium carries SHZSETUP, the Install entry is booted too.

Both builders are reproducible: fixed `SOURCE_DATE_EPOCH` for xorriso and mtools (dates and
GPT GUIDs), fixed FAT volume ids, deterministic tarballs. The receipts
(`build/windows98-shizuku-second-edition.json`, `...-disk.json`) record the sha256 and every input.
