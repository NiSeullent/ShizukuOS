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
| UEFI | `\EFI\BOOT\BOOTX64.EFI` = Shizuku loader and boot manager → its menu (5 s) → no key: Supervisor | needs Intel VMX (EPT, unrestricted guest) |
| UEFI without VMX | boot manager (no key) → `\EFI\SHIZUKU\CSMWRAP.EFI` → SeaBIOS CSM → the same medium's legacy boot | boot menu |
| UEFI, key K | boot manager → Kernel64 direct: `\SHZDOS\KERNEL64S.BIN` + `WIN64.IMG` in Long Mode | Kernel64 + Win64 runtime, no CSM, no VMX, GOP framebuffer, at most 256 MiB |

Boot menu (menu.c32; mirrored on COM1 115200 8N1, which also accepts the keys):

| Key | Entry | What runs |
| --- | --- | --- |
| K (default, 30 s) | Kernel64 + Win64 runtime | `mboot.c32 /SHZ/K64/BOOT.ELF --- KERNEL64S.BIN --- WIN64.IMG`: the standalone Long Mode kernel (no Supervisor) runs its self-tests and every `T_*.EXE` in WIN64.IMG, then prints `SHZ-EXIT:0` |
| D | ShizukuDOS 10 DOS16 (FreeDOS profile) | `memdisk harddisk` + `ShizukuDOS10/dos16/shizukudos-dos16-hd32.img` (raw disk: `\SHZDOS\DISK.IMG`): FreeDOS runs the conformance programs, `SHZ-EXIT:0` |
| 1 | ShizukuDOS 0.1 | `memdisk floppy` + `ShizukuDOS/shizukudos.img` (raw disk: `\SHZ\SHZDOS01.IMG`): the project's own shell, `A:\>` |
| I | Install ShizukuDOS 10 (SHZSETUP, agent I1) | `mboot.c32 /SHZ/K64/BOOT.ELF shz.setup=auto --- KERNEL64S.BIN --- /SHZ/SETUP/INSTALL.IMG`: SHZSETUP installs unattended with the shipped answer file (`install/shzsetup.ini`: the first disk without a partition table is ERASED) — GPT, ESP (UEFI boot manager `mode = kernel64` + syslinux for legacy BIOS), ShizukuFS — then powers off. `INSTALL.IMG` comes from `install/mkpayload.py --out build/shizukudos/install-media` (the ISO builder runs it) |

UEFI boot manager menu (C2's loader, menu added by C3; on the console and on COM1, which also takes the key).
`\EFI\SHIZUKU\BOOT.INI` on the medium: `mode = auto`, `auto_kernel64 = no`, `menu_timeout = 5`
(`--boot-mode` chooses the mode):

| Key | What runs |
| --- | --- |
| none within 5 s, A or Enter | the BOOT.INI policy: `auto` = the Supervisor with Intel VMX, otherwise CSMWrap and the legacy boot menu above |
| K | Kernel64 direct: the standalone Long Mode kernel from `\SHZDOS\KERNEL64S.BIN` with `WIN64.IMG`, ABI 1.1 boot info with the GOP framebuffer |
| C | CSM legacy BIOS (CSMWrap) |
| S | Supervisor only (refuses without Intel VMX) |

No UEFI Shell and no `startup.nsh` is involved (the interim Shell path of the first version is gone).

Kernel64 and firmware memory holes (both boot paths): OVMF with S3 on (QEMU's default) keeps
ACPI NVS at 8–9 MiB, both in its UEFI map and in the E820 map SeaBIOS reports under CSMWrap.
The Multiboot stub (`shizukudos/kernel64/standalone/boot32.c`) and the boot manager's direct
boot plan RAM the same way (`standalone/memholes.h`): holes in Kernel64's heap window
[3, 15) MiB are fenced off in the heap, holes above it are kept out of the page allocator,
holes in the kernel window [1, 3) MiB or over the initrd are refused. Under OVMF + CSMWrap
with 512 MiB: `K64: 7 firmware memory hole(s): 1492 page(s) kept out of the page allocator,
996 KiB of the heap fenced off`.

## VM profiles

Only QEMU (TCG, no KVM) was run. VirtualBox, VMware and Hyper-V lines are settings derived
from how the medium works, not test results.

| | Setting |
| --- | --- |
| RAM | 512 MiB (every test run used 512 MiB). Kernel64 needs 64 MiB or more (the Multiboot path uses what there is below 3.5 GiB, Kernel64 direct at most 256 MiB); memdisk holds the 32 MiB DOS16 image. Other sizes were not tested |
| vCPUs | 1 is enough on legacy BIOS; **2 or more on UEFI** (CSMWrap keeps one logical CPU and refuses with one) |
| UEFI | **Secure Boot off** (nothing is signed). Supervisor needs nested Intel VT-x; otherwise CSMWrap |
| Storage for the CSM path | IDE/SATA (AHCI), NVMe, USB, LSI/MPT/PVSCSI/MegaRAID SCSI. Not virtio, not Hyper-V VMBus |
| Serial | COM1 115200 8N1: menu mirror, keys, every result line |

- **QEMU (tested):** `-machine q35 -m 512 -smp 2 -cdrom THIS.iso` (legacy BIOS). UEFI: add
  `-drive if=pflash,format=raw,readonly=on,file=OVMF_CODE_4M.fd -drive if=pflash,format=raw,file=<copy of OVMF_VARS_4M.fd>`
  (a non-Secure-Boot build; S3 may stay on). As a disk:
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
| `SHZ/SETUP/` | `INSTALL.IMG` (Win64 runtime + SHZSETUP.EXE + answer file + payload), `SHZSETUP.INI` and `MANIFEST.JSON` (for reading), `README.TXT` |
| `ShizukuDOS10/efiboot.img` | the El Torito EFI image (also MBR partition 2 type 0xEF and a GPT entry): `\EFI\BOOT\BOOTX64.EFI`, `\EFI\SHIZUKU\{CSMWRAP.EFI,CSMWRAP.INI,BOOT.INI,README.TXT}`, `\SHZDOS\{DISK.IMG,KERNEL32.BIN,KERNEL64.BIN,KERNEL64S.BIN,WIN64.IMG}` |
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
python3 tools/test_shizuku_se_boot_matrix.py     # 21 boots + 2 install rows (3 QEMU runs each), one QEMU at a time
python3 tools/test_shizuku_se_boot_matrix.py --media iso-usb   # optional: the ISO as xHCI USB mass storage
python3 shizukudos/tools/shz.py test --suite media
```

The harness selects menu entries over COM1 (letter + Enter; key K at the UEFI menu for
`k64direct`, OVMF only) and judges each run only from
host-side evidence: the Kernel64 COM1 log through `shizukudos/tests/run_k64_standalone.py`'s
parser plus every `T_*.EXE` of WIN64.IMG; for DOS16 memdisk's mBFT table in guest memory gives
the live RAM disk, which `shizukudos/dos16/verify.py` checks (RESULT.TXT, T_COM.OUT,
T_EXE.OUT byte-exact); for 0.1 the `A:\>` prompt and a `DIR` listing; for Kernel64 direct C2's
`test_bootmgr.k64_checks` (RAM, ABI 1.1, GOP, holes) plus the NVS hole fenced off. OVMF runs
also check the ordered boot path (BDS → loader → BOOT.INI → menu → CSM → CSMWrap boot device →
isolinux, or menu → K → Kernel64 direct) and that the UEFI Shell never starts.
When a medium carries SHZSETUP, the Install entry is booted too.

Both builders are reproducible: fixed `SOURCE_DATE_EPOCH` for xorriso and mtools (dates and
GPT GUIDs), fixed FAT volume ids, deterministic tarballs. The receipts
(`build/windows98-shizuku-second-edition.json`, `...-disk.json`) record the sha256 and every input.

## Results

Recorded in `docs/shizukudos10/STATUS.md` section 2e. Latest: the ISO built from commit 8c083c4 (after the lead
merges up to 939a7cf; sha256 `d0050091dd1edc585710f2f31e206adbfb3616d1735101ae6023b59c9ff0bf1e`, 153,092,096 bytes,
identical over two full rebuilds) and the raw disk (`e312bff482b6bbfc8f2b18967d7c5ff8c367c377d3d03afd827f8d707e3477aa`)
passed the whole matrix, 23/23 (`shz.py test --suite media`, QEMU 8.2.2 TCG, OVMF with S3 on): SeaBIOS and OVMF, ISO as
CD / as disk / raw disk, Kernel64, DOS16, ShizukuDOS 0.1, Kernel64 direct (OVMF), and the install row (install to a
blank AHCI disk from the ISO, host verification, then the installed disk on OVMF and on SeaBIOS) on both firmwares.
WIN64.IMG now carries the Wine port; the ISO ships the Wine, FreeType and Noto licences and the Wine and FreeType
source (`ShizukuDOS10\\SOURCE`).
