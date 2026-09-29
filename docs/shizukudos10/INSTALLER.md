# ShizukuDOS 10.0 — installer (SHZSETUP)

User requirement: *"build the installation utility ourselves and package it as an ISO"*. This document covers the
installation utility: the host-side payload builder, the in-guest installer `SHZSETUP.EXE`, the Kernel64 support it
needs, and the tests. Packaging the single VM install ISO is agent C3's `tools/build_shizuku_se_iso.py`; the interface
it consumes is described in section 8.

Evidence classes as in `BASELINE.md`: `SOURCE` · `BUILT` · `HOST_TESTED` · `GUEST_RUN` · `HARDWARE` · `USER_REPORTED`.
Everything below was produced in a cloud container without KVM (QEMU 8.2 **TCG**); nothing here is `HARDWARE`.

## 1. Installed disk

| Area | Contents | Written by SHZSETUP as |
| --- | --- | --- |
| LBA 0 | protective MBR (one `0xEE` entry, UEFI 2.10 §5.2.3) + 440 bytes of BIOS boot code (`install/gptmbr.asm`) | built in memory, read back |
| LBA 1–33, last 33 LBAs | primary / backup GPT (128 entries) | built in memory (CRC32), both copies read back and checked |
| p1, LBA 2048, 128 MiB | EFI System Partition, FAT32 (`esp.img` built on the host) | the image, sector by sector, zeros included; SHA-256 of the whole partition read back |
| p2, rest of the disk | ShizukuFS v1 = ext4 on-disk format, label `SHZSYS`: `\SHZ\SYS64`, `\SHZ\DRIVERS\<pkg>`, `\SHZ\SETUP\log`, `\Users` | formatted and populated in one pass; every file read back through an independent decoder and hashed |
| p3 (optional) | empty FAT32 volume `WIN98` for the user's own Windows 98 | formatted (MS FAT spec 1.03); **nothing from Microsoft is bundled** |

ESP (`install/mkpayload.py`): `\EFI\BOOT\BOOTX64.EFI` (Shizuku UEFI loader), `\EFI\SHIZUKU\BOOT.INI` (`mode = kernel64`),
`\EFI\SHIZUKU\CSMWRAP.EFI` (when `csm/build.py` has built it), `\SHZDOS\KERNEL64S.BIN`, `WIN64.IMG` (runtime DLLs +
`T_HELLO.EXE` for the boot self-test), `DISK.IMG` (DOS16), `KERNEL32.BIN`, `KERNEL64.BIN`, `K64STUB.ELF` (Multiboot stub
for a BIOS boot loader).

Partition types: p1 ESP `C12A7328-…`, p2 Linux filesystem data `0FC63DAF-…` (the volume *is* ext4 on disk, so Linux tools
and `blkid` recognise it), p3 Microsoft basic data `EBD0A0A2-…`. p1 carries GPT attribute bit 2 (legacy BIOS bootable),
which the MBR code uses to find it. p1 must start at LBA 2048 because `esp.img`'s BPB hidden-sector field says so
(the installer refuses otherwise). Partitions are 1 MiB aligned. Only 512-byte-sector disks are accepted today.

On p2 the installer also writes `\SHZ\SYSTEM.INI` (host name, install time, target device/serial, disk/partition GUIDs,
volume UUID, driver packages), `\SHZ\SETUP\shzsetup.ini` (the answer file used), `\SHZ\SETUP\manifest.json` (the
payload manifest) and `\SHZ\SETUP\log\install.log` (the full log, ending in `SETUP-RESULT: OK`).

## 2. Payload (`shizukudos/install/mkpayload.py`)

Inputs: outputs of `kbuild.py`, `win64/build.py`, `dos16/build.py`, `supervisor/build.py`, optionally `csm/build.py`
(`--build` runs missing ones). Outputs in `build/shizukudos/install/`:

| File | Format |
| --- | --- |
| `esp.img` | FAT32, 128 MiB (`--esp-mib`), 1 KiB clusters, `mkfs.fat --invariant`, volume id `5348-5A45`, label `SHZESP`, hidden sectors 2048, fixed file times (`SOURCE_DATE_EPOCH` 1785283200), fixed order; checked with `fsck.fat -n` |
| `payload/ESP.SIM` | `SHZSIMG1` sparse image of `esp.img`: 64-byte header (magic, block size 4096, chunk count, image bytes, SHA-256 of the expanded image), chunk table `{u64 first_block, u32 blocks, u32 0}`, chunk data; blocks outside chunks are zero. Round-trip checked by an independent decoder |
| `payload/SYSTEM.ARC` | `SHZARC01` (the Kernel64 initrd format) holding the p2 tree |
| `payload/GPTMBR.BIN` | 440 bytes, `nasm -f bin install/gptmbr.asm` |
| `payload/manifest.json` | schema `shizukudos-install-manifest/1`: `mbr` {file, bytes, sha256}; `esp` {image, bytes, sha256, first_lba, label, files[] {path, bytes, sha256}}; `system` {archive, archive_sha256, label, dirs[] {path, package}, files[] {path, package, bytes, sha256}}; `packages[]` |
| `shzsetup.ini` | the answer file packed into the boot image (`--answer`, default `install/shzsetup.ini`) |
| `INSTALL.IMG` | initrd for the installer boot: `\SHZ\SYS64\*`, `\SHZ\TESTS\T_HELLO.EXE`, `\SHZ\SETUP\SHZSETUP.EXE`, `\SHZ\SETUP\SHZSETUP.INI`, `\SHZ\SETUP\PAYLOAD\{manifest.json, ESP.SIM, SYSTEM.ARC, GPTMBR.BIN}` (about 3 MB) |

Two consecutive builds produce byte-identical `esp.img` and `INSTALL.IMG` (`BUILT`, checked with `cmp`).

Driver packages: `\SHZ\DRIVERS\<name>\DRIVER.INI` descriptors, generated only for driver sources present in
`kernel64/` (today `rtl8139`, `bochs-vbe`, `ram`; `ahci`, `nvme`, `sdhci`, `virtio` appear automatically once those
tracks are merged). Kernel64 has no loadable driver model: the drivers are compiled into the kernel and the packages
only describe them.

## 3. Answer file (`install/shzsetup.ini`, schema 1)

| Section / key | Values | Default |
| --- | --- | --- |
| `[Setup] Schema` | `1` (required) | — |
| `[Setup] Confirm` | `ERASE-TARGET` (required consent; anything else refuses) | — |
| `[Setup] Reboot` | `shutdown` · `reboot` · `none` | `shutdown` |
| `[Target] Select` | `first` · `first-nvme` · `first-ahci` · `first-mmc` · `first-ram` · `largest` · `smallest` · `size` · `serial` · `name` | `first` |
| `[Target] SizeMiB` / `Serial` / `Name` | for `size` (exact MiB) / `serial` / `name` (kernel device name) | — |
| `[Target] MinSizeMiB` | disks below are not eligible | 0 (layout minimum) |
| `[Target] AllowNonEmpty` | `yes` to erase a disk that has an MBR/GPT partition table | `no` |
| `[Layout] SystemMiB` | p2 size; `0` = rest of the disk | 0 |
| `[Layout] Win98MiB` | `0` (no p3) or ≥ 64 | 0 |
| `[Layout] Win98HybridMBR` | `yes`: also an MBR entry (type `0x0C`) for p3 so a GPT-unaware OS sees it | `no` |
| `[Layout] BiosBootCode` | `no`: zero MBR boot code | `yes` |
| `[System] Hostname` | letters, digits, `-` | `SHIZUKU` |
| `[System] GuidSeed` | derive all GUIDs/UUIDs from this text (reproducible test installs) | random (bcrypt RNG) |
| `[Drivers] Install` | `all` · `none` · comma list of package names | `all` |

Eligible targets: whole devices (not partitions), writable, 512-byte sectors, large enough for ESP + 64 MiB + p3.
Unknown keys are logged and ignored; malformed values refuse the run before anything is written.

## 4. SHZSETUP.EXE

Sources `shizukudos/win64/setup/`: the portable core (`install.c`, `sfsw.c`, `gpt.c`, `fat32fmt.c`, `textparse.c`)
talks to the outside only through `plat.h`; `setup_main.c` (kernel32 files, bcrypt SHA-256 and RNG) and `blkio.c`
(installer syscalls) make it a Win64 console program; `install/tests/host_install.c` makes the same core a Linux program
for the host tests. `win64/build.py` builds it and packs it as `\SHZ\SETUP\SHZSETUP.EXE` (load-time import closure:
109 imports, 0 missing — `win64/tools/startup_chain.py`).

`SHZSETUP.EXE [/unattend <ini>] [/payload <dir>]` (defaults `C:\SHZ\SETUP\SHZSETUP.INI`, `C:\SHZ\SETUP\PAYLOAD`):

1. parse and validate the answer file and the manifest; load and hash-check `GPTMBR.BIN`;
2. enumerate block devices, select the target, refuse a non-blank one unless `AllowNonEmpty=yes`, plan the layout;
3. destructive phase: erase both partition tables; write p1 from `ESP.SIM` hashing the stream (must equal the manifest),
   read p1 back and hash again; format p2 and write every file from `SYSTEM.ARC` hashing each against the manifest,
   write the metadata, then re-open the volume with the independent reader (`sfsr_*`) and hash every file read back from
   the disk; format p3; write backup then primary GPT and the MBR last, read both back and check signature, CRC32s
   and cross-references;
4. append `SETUP-RESULT: OK` to the log, write `install.log` to p2 and read it back;
5. print `SETUP-RESULT: OK` (exit 0) or `SETUP-RESULT: FAIL <reason>` (exit 1); hand the `Reboot=` choice to the kernel.

Because the partition table is written last, a failed run leaves a disk without a partition table instead of one that
points at half-written partitions.

**ShizukuFS writer (interim).** Agent S2's portable `libsfs` (with mkfs) is not merged yet, so p2 is written by
`sfsw.c`, a one-pass ext4-format writer (like `mke2fs -d`): 4 KiB blocks, 32768 blocks/group, 256-byte inodes,
`sparse_super`, `filetype`, `extents` (depth 0 and 1), `large_file`, `extra_isize`; no journal, no `metadata_csum`, no
`dir_index`. It only creates a fresh volume from a tree known in advance. When libsfs lands, `plan_system`/
`write_system_data`/`verify_system` in `install.c` switch to `sfs_mkfs` + `sfs_mount` + `sfs_mkdir/create/write` +
`sfs_path_lookup/read`, and `sfsw.c` can be deleted.

## 5. Kernel64 support

| Piece | File | Note |
| --- | --- | --- |
| RAM block devices `ram0..3` | `kernel64/blk_ram.c` | QEMU `ivshmem-plain` BAR2 (a host file with `memory-backend-file,share=on`), serial `IVSHMEM-bb:dd.f`; standalone profile only. Interim install target until AHCI/NVMe/eMMC are merged |
| block API | `kernel64/blk_compat.h` | includes the storage track's `blk.h` when it exists; until then declares the same `blk_dev_t` shape and `blk_register/blk_first/blk_read/blk_write/blk_flush`, implemented by a minimal registry in `blk_ram.c` |
| syscalls 0xe0–0xe4 | `kernel64/setup_sys.c`, `setup_abi.h`, `ntsys.h` `SYSCALL_LIST_SETUP` | `NtShzSetupBlkQuery/Read/Write/Flush`, `NtShzSetupPower`; 1 MiB per call through a 64 KiB bounce buffer. The storage track's raw-sector syscalls own 0xf0–0xff; `SYS_MAX` is 0x100 |
| `shz.setup=auto` | `setup_autostart()` in `setup_sys.c`, **one call added in `main.c`** after `run_self_tests()` | runs `\SHZ\SETUP\SHZSETUP.EXE /unattend C:\SHZ\SETUP\SHZSETUP.INI`, waits (≤ 60 min), logs `K64 setup: SHZSETUP.EXE exit=… power request …`; `reboot` = keyboard-controller reset (standalone), `shutdown` = kmain ends the domain (standalone: `SHZ-EXIT`, QEMU exits) |
| kernel command line | `abi/shz_abi.h` 1.1 tail, `kernel64/standalone/boot32.c` | taken **verbatim** from agent C2's boot-manager change (append-only tail: `fb_*` at offset 176, `cmdline_size`, `cmdline[256]` at 216; size 472) so both branches carry the identical edit; the Multiboot stub copies the Multiboot command line |

Security limit: the raw-sector syscalls are available to any Win64 process (Kernel64 has no privilege model yet).

## 6. Tests

`python3 shizukudos/install/tests/run_host_install.py` (`HOST_TESTED`): the installer core built with ASan/UBSan
against disk images — full install with Win98 volume selected by serial among two disks (other disk byte-identical),
reinstall with `AllowNonEmpty`/`Select=size`/`SystemMiB`/`Drivers=none`, refusals (missing consent, unknown selector,
no matching serial, disk too small, bad host name) that leave the disk byte-identical, a non-empty disk refused, a
corrupted `SYSTEM.ARC` and `ESP.SIM` detected (no partition table written), `partx`/`blkid` parse the result, and the
ShizukuFS writer alone on 1.0–1.3 GiB volumes (700 MiB file → depth-1 extent tree, 700 entries in one directory).
Each install is checked by `install/tests/verify_disk.py` (below).

`python3 shizukudos/tests/run_install.py --build` (`GUEST_RUN`, QEMU TCG): section 7.

`install/tests/verify_disk.py DISK --payload build/shizukudos/install [--win98] [--drivers …]`: host verification that
reuses nothing of the installer — protective MBR + boot code = `GPTMBR.BIN`; primary/backup GPT signature, header and
array CRC32 (`zlib`), cross-references, identical entries; alignment, types, ESP attribute; p1 byte-identical to
`esp.img`, `fsck.fat -n`, every ESP file via `mcopy` against the manifest SHA-256; p2 `e2fsck -fn`, superblock, every
selected manifest file via `debugfs rdump` against its SHA-256, unselected driver packages absent, directories,
generated files, `install.log` ending in `SETUP-RESULT: OK`; p3 `fsck.fat -n`, label, hidden sectors, no files.

## 7. Results

Reproduced in this session (QEMU 8.2 TCG, no KVM; `build/shizukudos/install/host-test/result.json`,
`build/shizukudos/install/vm-test/result.json`):

| Cell | Evidence | Result |
| --- | --- | --- |
| `mkpayload.py`: `esp.img` and `INSTALL.IMG` identical across two builds | BUILT | PASS |
| `run_host_install.py`: installer core on disk images (ASan/UBSan), `verify_disk.py`, refusals, corrupted payloads, `partx`/`blkid`, ShizukuFS writer on 1.0–1.3 GiB | HOST_TESTED | **64/64 PASS** |
| Install boot: Multiboot stub → Kernel64 (`shz.setup=auto`) → self-tests 0 failures → `SHZSETUP.EXE` selects the 512 MiB ivshmem RAM disk by serial `IVSHMEM-00:05.0`, installs, verifies, `SETUP-RESULT: OK`, exit 0, shutdown (`SHZ-EXIT:0`); decoy disk still all zero | GUEST_RUN (TCG) | PASS (8 cells), install boot 22–29 s |
| Host verification of the installed image: GPT primary/backup + CRC32s, MBR boot code, p1 byte-identical to `esp.img` + `fsck.fat` + 9 ESP files via mtools, p2 `e2fsck -fn` exit 0 + 21 files via `debugfs` SHA-256 + directories + generated files + `install.log`, p3 empty FAT32 | HOST_TESTED (on the guest's output) | PASS (25 cells) |
| Second boot, UEFI (OVMF, installed disk on virtio-blk): firmware starts `\EFI\BOOT\BOOTX64.EFI` from the installed ESP | GUEST_RUN (TCG) | PASS (`ShizukuDOS 10.0-dev Supervisor loader (UEFI x64)`) |
| Second boot, UEFI: Kernel64 from the installed disk (`BOOT.INI mode = kernel64`) | — | **BLOCKED**: the loader in this tree has no direct Kernel64 boot (agent C2 not merged); it took the Supervisor path and refused (TCG `-cpu max`: "AMD SVM is usable, but the SVM backend is not implemented") |
| Second boot, BIOS (SeaBIOS): MBR code finds the legacy-bootable ESP and runs its boot sector (COM1 `SHZ-MBR ->VBR`; VGA text memory shows the ESP boot sector's own message) | GUEST_RUN (TCG) | PASS (2 cells) |
| Second boot, BIOS: Kernel64 from the installed disk | — | **BLOCKED**: needs agent C3's disk-installable SYSLINUX variant in the ESP boot sector |

VM total: 36 PASS, 0 FAIL, 2 BLOCKED. Not run: any AHCI/NVMe/eMMC target (drivers not merged), real hardware,
the Supervisor (VMX) path.

## 8. Integration points

| Agent | What changes here when it is merged |
| --- | --- |
| S1 (NVMe/eMMC, raw-sector syscalls 0xf0–0xff) | `win64/setup/blkio.c` switches to the 0xf0–0xff calls; `setup_sys.c`'s Blk* syscalls and `blk_compat.h` go away; the test adds an NVMe target (`Select=first-nvme`) |
| D1 (AHCI via `blk.h`) | `blk_compat.h` then just includes `blk.h` (automatic), `blk_ram.c` registers into the real registry; `run_install.py` gains an AHCI target; serial numbers need a `blk_dev_t` serial field (today only RAM disks report one) |
| S2 (libsfs incl. mkfs) | replace the `sfsw` calls in `install.c` (section 4); `verify_disk.py` stays as is |
| C2 (UEFI loader `mode = kernel64`) | the ESP already has `BOOT.INI` `mode = kernel64` and `\SHZDOS\KERNEL64S.BIN`/`WIN64.IMG`; `run_install.py` detects the loader's direct-boot support and turns the UEFI Kernel64 cell from BLOCKED into a real check |
| C3 (install ISO, disk SYSLINUX) | ISO: boot `build/shizukudos/kernel64s/boot.elf` with modules `KERNEL64S.BIN` and `INSTALL.IMG` and command line `shz.setup=auto` (isolinux + `mboot.c32`). Disk: a SYSLINUX variant installed into the ESP boot sector (`gptmbr.asm` hands over with the SYSLINUX `!GPT` convention) loading `\SHZDOS\K64STUB.ELF` + `KERNEL64S.BIN` + `WIN64.IMG`; then the BIOS Kernel64 cell becomes a real check |

## 9. Limits

- Install target in the VM test is a RAM block device (ivshmem); no AHCI/NVMe/eMMC disk has been installed to yet.
- 512-byte-sector disks only (the ESP image is built for 512-byte sectors at LBA 2048).
- No interactive UI: unattended only; consent is the answer file's `Confirm=ERASE-TARGET`.
- `shutdown` ends the standalone kernel (`SHZ-EXIT`); there is no ACPI power-off, so on real hardware the machine halts.
- ShizukuFS p2 has no journal (interim writer); its root spec for a later boot of the installed system is not defined yet.
- The raw-sector syscalls are unprivileged. The BIOS boot of the installed disk stops at the ESP boot sector until C3's
  SYSLINUX variant exists; the UEFI boot reaches the loader, which starts Kernel64 only with C2's boot manager.
- Nothing here ran on real hardware.
