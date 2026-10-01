# Prepare a USB

The public **Windows 98 Shizuku Modern Edition USB files** and **your own `WIN98.ISO`** can share a USB. The primary architecture is **ShizukuDOS replacing MS-DOS to boot and extend Windows 98**. Kernel32, Kernel64 and Supervisor all serve Windows 98. The current independently booted desktop is a component-validation profile, not a separate product goal.

The public bundle carries that test desktop/runtime, included driver packages, matching source and licenses. **MS-DOS replacement boot connection and Windows 98 Setup integration are in development.** Copying files is not a completed Windows 98 installation.

## Copy files

1. Download an actually published **USB files ZIP** from the [distribution page](https://m98.nyase.kr/). A plain ISO extraction is insufficient: the USB preparation also extracts the embedded EFI boot image.
2. Extract every file/folder to an already prepared **empty FAT32 USB root**. `EFI/BOOT/BOOTX64.EFI` and `SHZDOS/` must be directly under that root. Retain source/license folders.
3. Add your own Windows 98 ISO as root `WIN98.ISO` if desired. The resulting USB is **personal**. Do not publish folders, ZIPs or integrated images containing that media.
4. Select the USB in an x64 UEFI boot menu with Secure Boot off. This currently starts the **Shizuku component test desktop for Windows 98**.

Copying files does not install a BIOS USB bootloader. FAT32 permits at most 4 GiB minus 1 byte per file. Unzip on your PC; carrying the ZIP itself is unnecessary. Booting on physical USB/board hardware remains a separate verification requirement.

Carrying `WIN98.ISO` does not start Windows 98 Setup. The Shizuku installer currently installs a component test profile and writes its selected target disk. `SHZSE/INSTALL.BAT` copies five probe files inside an already installed Windows 98; it is not Windows Setup or a complete driver installer.

## Produce public files

Use a Linux host with Python 3, `xorriso` and mtools `mcopy`. The preparer refuses block devices, symbolic-link paths and existing output paths. It cannot format a USB or write an image to a device.

Supply a public desktop ISO, its builder JSON and the matching final-source result from `tools/verify_public_iso.py`. The preparer does not run that verifier for you. The ISO hash/size and final source commit must match both receipts.

```sh
mkdir -p "$HOME/shizuku-output"
python3 tools/prepare_shizuku_usb.py public \
  --iso /path/to/public-desktop.iso \
  --receipt /path/to/public-desktop.json \
  --verification /path/to/public-iso-check/result.json \
  --output "$HOME/shizuku-output/usb-public" \
  --zip "$HOME/shizuku-output/Windows98ShizukuModernEdition-USB-files.zip"
```

Both outputs must be new. The full ISO `HASHES.TXT` and EFI member receipt close the byte/SHA-256 checks. Original boot configuration bytes are retained. `SHIZUKU-USB.json` records every resulting file hash, input ISO and source commit. **It does not claim USB boot success.**

## Create a personal folder with verified media

```sh
python3 tools/prepare_shizuku_usb.py add-win98 \
  --bundle "$HOME/shizuku-output/usb-public" \
  --win98-iso /path/to/my-own-windows98.iso \
  --output "$HOME/shizuku-output/usb-personal"
```

The original public folder remains unchanged. The new folder contains root `WIN98.ISO`, byte/hash identical to the original; `WIN98-MEDIA.json` records its hash/size, ISO9660 labels, file/CAB counts and required DOS file locations. Labels do not establish authenticity, edition or licensing. The new manifest records `private: true`. Copy this personal folder's contents to your USB root.

Validation requires readable ISO9660, a `WIN98` CAB folder and `IO.SYS`, `MSDOS.SYS`, `COMMAND.COM` either loose or in cabinet name tables. It does not verify cabinet decompression, authenticity or Windows version. Presence of `SETUP.EXE` is recorded separately and does not mean Setup boots. An ISO placed on the USB is not automatically mounted as a DOS drive.

Requiring those original DOS files is a **temporary existing-media limitation**, not a reversal of the MS-DOS replacement design. The replacement boot path must still connect the preserved Windows installation source to the genuine Windows 98 GUI and kernel bridge.

## One-command personal integrated ISO

Prepare source build prerequisites as described in [CONTINUE_ON_ANOTHER_MACHINE.md](CONTINUE_ON_ANOTHER_MACHINE.md). Use a fresh `-private.iso` output outside the public source checkout.

```sh
python3 tools/prepare_shizuku_usb.py private-iso \
  --repo /path/to/Win98-Modern \
  --win98-iso /path/to/my-own-windows98.iso \
  --output "$HOME/shizuku-output/shizuku-with-my-win98-private.iso"
```

This validates your ISO, then invokes the existing desktop/private-media builder. It can download public build sources and write build/intermediate private media under the checkout's `build/`. It runs no VM and does not format/write host devices. Add `--reuse-builds` only for outputs/receipts from the exact current source. Use `private-command` instead to print the command without running it.

The resulting ISO combines the component test boot profile and unchanged Windows source files under `WIN98/`. ShizukuDOS replacement boot and Windows 98 Setup integration are still in development. Its ISO, JSON and `.media.json` are personal and must not be published. Preparing or verifying this overlay does not install Windows or certify applications.

Genuine Windows 98 UEFI/GOP, Chromium, Legcord, LibreOffice, Steam, Supermium, VLC, Notepad++, VS Code, acceleration, complete drivers and native Dead Screen remain active goals. A successful preparation is not their completion.

한국어: [USB_PREPARATION_KO.md](USB_PREPARATION_KO.md).
