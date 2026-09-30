# Windows 98 Shizuku Second Edition — ISO release

The product is one hybrid VM install ISO, `windows98-shizuku-second-edition.iso` (ShizukuDOS 10). It boots as a CD
and, attached as a hard disk or written raw to a USB stick, as a disk, on legacy BIOS and on UEFI. How the medium is
built and what each boot path does in detail: [MEDIA.md](MEDIA.md). This page is about a release: how to build one
locally, how to check it, how to boot it, and what can and cannot be shown in a web browser.

The ISO is **not published** (no GitHub release, no workflow artifact, no public download URL). A release is built
locally with `tools/build_release.py` and handed over privately as the files of one release directory.

## Build a release

On Ubuntu 24.04 (the packages the builders and the boot matrix call; the same set the `shizukudos10-tcg` CI job
installs, plus `xxd`, `patch`, `e2fsprogs`, `file`):

```
sudo apt-get install --no-install-recommends \
  gcc gcc-multilib clang libclang-rt-18-dev mingw-w64 nasm make binutils python3 python3-pil \
  qemu-system-x86 ovmf mtools dosfstools xorriso python3-pefile lld llvm flex bison \
  xxd patch e2fsprogs file xz-utils git
python3 tools/build_release.py
```

Syslinux is not taken from the host: the builders download the pinned Ubuntu 6.04 packages
(`shizukudos/upstream/manifest.json`, checked by SHA-256) and unpack them with `dpkg-deb`. The first build also
fetches the pinned FreeDOS kernel and FreeCOM, CSMWrap with SeaBIOS, Wine, FreeType and Noto trees into
`build/upstream/` and the Open Watcom snapshot into `build/tools/` (network; about 2 GB of disk for everything).

`tools/build_release.py`, from a clean checkout (it refuses uncommitted changes unless `--allow-dirty`, which the
manifest records and the directory name shows as `-dirty`):

1. builds everything from the checked-out commit in the ISO builder's order, with its fixed
   `SOURCE_DATE_EPOCH=1785283200`: `shizukudos/csm/build.py`; `shizukudos/tools/shz.py build --profile
   uefi-multikernel` (DOS16, Kernel32, Kernel64, Win64 runtime, UEFI loader); `shizukudos/install/mkpayload.py --out
   build/shizukudos/install-media`; `tools/build_shizuku_se_iso.py --reuse-builds` (packages those outputs after
   checking them against their build receipts); `tools/build_shizuku_se_disk.py`. It then checks that the ISO matches
   its receipt, was built from `HEAD` and is not a private image, and that the raw disk has the same inputs;
2. runs `shizukudos/tools/shz.py test --suite media`, the boot matrix (QEMU TCG, SeaBIOS and OVMF; ISO as CD, ISO
   as hard disk, raw disk; Kernel64, DOS16, ShizukuDOS 0.1, Kernel64 direct, install: 23 rows, one QEMU at a time).
   Unless the verdict is `VERIFIED`, every row `PASS`, on exactly the ISO and disk bytes just built, the release
   fails and no release directory is written. `--skip-tests` skips this step as an explicit, logged opt-out; the
   manifest then says `"media_suite": "skipped"`;
3. writes `build/release/windows98-shizuku-second-edition-<commit12>/`:

| File | What |
| --- | --- |
| `windows98-shizuku-second-edition.iso` | the VM install ISO |
| `windows98-shizuku-second-edition.iso.sha256` | `sha256sum` line for the ISO |
| `windows98-shizuku-second-edition-disk.img.xz` | the secondary raw disk image (MBR + FAT32, 128 MiB), xz-compressed |
| `windows98-shizuku-second-edition.json` | the ISO builder's receipt (`build/windows98-shizuku-second-edition.json`): every input with its SHA-256, the menu, the git revision |
| `windows98-shizuku-second-edition-disk.json` | the raw disk builder's receipt |
| `media-suite-results.json` | the `shz.py test --suite media` results (`build/shizukudos/results/media-*.json`) |
| `boot-matrix.json` | the matrix summary those results judged: per row status, seconds and failed checks, QEMU version, OVMF hash |
| `release-manifest.json` | see below |

`release-manifest.json` (schema 1): `tag` (`--tag`, else the tag on `HEAD`, else `null`), `commit`, `commit_date`,
`dirty`, `build_date_utc`, `builder` (command line, `SOURCE_DATE_EPOCH`, each step with its duration); `iso`,
`iso_receipt` and `disk_image` (plus its `uncompressed` image and `receipt`) each with `name`, `bytes`, `sha256`;
`media_suite`: `"skipped"`, or the verdict, the counts and every case with its status (`cases`), plus the file hashes
of the results and of `boot-matrix.json`; `host`: OS, kernel, QEMU version and package, OVMF path, package and
SHA-256 (and the values the matrix recorded).

Duration on a 4-CPU machine: the builds about 7 minutes, the boot matrix 25–40 minutes depending on the load (a
Kernel64 row takes 2–4 minutes under TCG).

## Verify the ISO

In the release directory (or wherever the files were copied, the ISO and its `.sha256` side by side):

```
sha256sum -c windows98-shizuku-second-edition.iso.sha256        # Linux
shasum -a 256 -c windows98-shizuku-second-edition.iso.sha256    # macOS
```

Windows PowerShell: `(Get-FileHash -Algorithm SHA256 windows98-shizuku-second-edition.iso).Hash` and compare it with
the first field of the `.sha256` file (case does not matter). The same SHA-256 is `iso.sha256` in
`release-manifest.json` and `sha256` in the receipt; the receipt's `git.revision` is the commit it was built from, and
`boot-matrix.json` (`media.iso.sha256`) shows that the matrix booted exactly these bytes. The raw disk:
`xz -d windows98-shizuku-second-edition-disk.img.xz`, then compare with `disk_image.uncompressed.sha256` in the
manifest.

The ISO records the commit and the branch name it was built from (for example in `ShizukuDOS10\GPL-NOTICE.TXT`),
so two builds of the same commit are byte-identical only from the same branch name and the same upstream inputs.

## Boot it

### What a VM needs

| | |
| --- | --- |
| RAM | **512 MiB** (every test run used 512 MiB). Kernel64 needs at least 64 MiB; the UEFI Kernel64-direct path uses at most 256 MiB; the DOS16 entry holds its 32 MiB disk image in RAM. Other sizes are not tested |
| CPU | x86-64. The Kernel64 entries need Long Mode. **2 or more vCPUs on UEFI** (CSMWrap keeps one CPU for itself and refuses with one); 1 is enough on legacy BIOS |
| Firmware | legacy BIOS, or UEFI with **Secure Boot off** (nothing is signed) |
| Storage for the UEFI → CSM path | IDE/SATA (AHCI), NVMe, USB, LSI/MPT/PVSCSI/MegaRAID SCSI; not virtio, not Hyper-V VMBus |
| Serial | COM1 115200 8N1 mirrors the boot menu, takes the menu keys, and carries every result line |

### QEMU, legacy BIOS (SeaBIOS)

```
qemu-system-x86_64 -machine q35 -accel tcg -cpu max -smp 2 -m 512 \
  -cdrom windows98-shizuku-second-edition.iso \
  -serial stdio -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

### QEMU, UEFI (OVMF)

```
cp /usr/share/OVMF/OVMF_VARS_4M.fd shz-vars.fd          # a writable copy of the variable store
qemu-system-x86_64 -machine q35 -accel tcg -cpu max -smp 2 -m 512 \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=shz-vars.fd \
  -cdrom windows98-shizuku-second-edition.iso \
  -serial stdio -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

The paths are Ubuntu's `ovmf` package (a build without Secure Boot; QEMU's default S3 setting may stay on). Fedora:
`/usr/share/edk2/ovmf/OVMF_CODE.fd` and `OVMF_VARS.fd`.

Variants (the same QEMU devices the matrix uses):

- **ISO as a hard disk / USB stick** (instead of `-cdrom`):
  `-drive file=windows98-shizuku-second-edition.iso,format=raw,if=none,id=d0,snapshot=on -device ide-hd,drive=d0,bus=ide.0,bootindex=1`
- **Raw disk image** (after `xz -d`; add `,snapshot=on` to the `-drive` to keep the image unchanged, as the matrix does):
  `-drive file=windows98-shizuku-second-edition-disk.img,format=raw,if=none,id=d0 -device ide-hd,drive=d0,bus=ide.0,bootindex=1`
- **Install to a blank disk** (menu entry I; it ERASES the first disk without a partition table):
  ```
  truncate -s 512M shz-target.img
  qemu-system-x86_64 -machine q35 -accel tcg -cpu max -smp 2 -m 512 -serial stdio -no-reboot \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -drive file=shz-target.img,format=raw,if=none,id=d0 -device ide-hd,drive=d0,bus=ide.0 \
    -drive file=windows98-shizuku-second-edition.iso,format=raw,if=none,id=d1,readonly=on,media=cdrom \
    -device ide-cd,drive=d1,bus=ide.1,bootindex=1
  ```
  Press I at the menu. SHZSETUP prints `SETUP-RESULT: OK` and `SHZ-EXIT:0` and powers off. Then boot
  `shz-target.img` alone (either firmware): it starts Kernel64 (UEFI: the installed boot manager with
  `mode = kernel64`; legacy BIOS: syslinux on the ESP).

With KVM (`-accel kvm -cpu host`) the same lines should run faster; KVM is not part of the release test, which uses
TCG only. `-serial stdio` puts COM1 in your terminal; the keys work there and in the QEMU window.
`isa-debug-exit` lets Kernel64 end QEMU after its last line (QEMU's exit status is then `code * 2 + 1`, so 1 for
`SHZ-EXIT:0`); without it the guest halts and QEMU stays open. Judge a run by the COM1 line, not QEMU's exit status.

### The boot menus

Legacy BIOS (and UEFI without Intel VMX, through CSMWrap) shows the syslinux menu, on screen and on COM1. Type the
letter, then Enter (on the keyboard or on COM1):

| Key | Entry | What runs | How it ends |
| --- | --- | --- | --- |
| **K** (default after 30 s) | Kernel64 + Win64 runtime | the standalone Long Mode kernel (Multiboot stub `BOOT.ELF`, `KERNEL64S.BIN`, `WIN64.IMG`): kernel self-tests, then every `T_*.EXE` Win64 test program | `SHZ-EXIT:0` on COM1 (2–4 minutes under TCG). The text results are on COM1 only; the screen switches to a 1024×768 desktop on which the Win64 GUI test programs open and close their windows, and ends on the empty desktop |
| **D** | ShizukuDOS 10 DOS16 (FreeDOS profile) | memdisk boots the 32 MiB DOS16 disk from RAM; FreeDOS runs the conformance programs | `SHZ-EXIT:0` on COM1, then the CPU halts. Nothing is written back |
| **1** | ShizukuDOS 0.1 | memdisk boots the project's own real-mode shell from a floppy image in RAM | the `A:\>` prompt (screen and COM1). `HELP` lists the commands: `DIR`, `TYPE file`, `EXEC file.COM`, `CLS`, `VER`, `MEM`, `STACK`, `CPU`, `PCI`, `BOOT`, `BOOTC`, `REBOOT` |
| **I** | Install ShizukuDOS 10 (SHZSETUP) | Kernel64 with the installer image: unattended install (GPT, ESP, ShizukuFS) to the first disk without a partition table | `SETUP-RESULT: OK`, `SHZ-EXIT:0`, power off. **Erases that disk** |

UEFI shows the Shizuku boot manager first (on screen and on COM1, 5 seconds):

| Key | What runs |
| --- | --- |
| none, A or Enter | `BOOT.INI` policy `auto`: the Supervisor when the CPU has Intel VMX (EPT, unrestricted guest), otherwise CSMWrap → SeaBIOS CSM → the legacy menu above |
| K | Kernel64 directly in Long Mode (no CSM, no VMX, GOP framebuffer, at most 256 MiB); ends with `SHZ-EXIT:0` |
| C | CSMWrap → the legacy menu |
| S | the Supervisor only (refuses without Intel VMX) |

A failure prints `SHZ-EXIT:<nonzero hex>` (for example the Multiboot stub's `SHZ-STUB: need at least 64 MiB, have
... SHZ-EXIT:fe`) or `K64 PANIC:` on COM1.

### VirtualBox, VMware, Hyper-V (not tested)

Only QEMU is tested. These settings follow from how the medium works:

- **VirtualBox:** BIOS VM with the ISO on an IDE or SATA DVD drive. EFI VM: *Enable EFI*, 2+ CPUs, SATA/IDE/NVMe
  controller, Secure Boot off.
- **VMware Workstation/ESXi:** BIOS firmware gets the legacy menu. UEFI firmware: Secure Boot off, 2+ vCPUs,
  SATA/IDE/NVMe or LSI/PVSCSI.
- **Hyper-V:** Generation 1 (BIOS, IDE DVD) gets the legacy menu. Generation 2 is UEFI-only with VMBus storage, which
  SeaBIOS inside CSMWrap cannot drive: use Generation 1.

Add a serial port (COM1, 115200 8N1) to a file or pipe to see the results.

## Live demo in a browser

### What v86 can and cannot run

[v86](https://github.com/copy/v86), the usual in-browser x86 emulator, emulates a 32-bit PC with SeaBIOS. It does
**not implement x86-64 Long Mode** and has no UEFI firmware. So from this ISO:

- **cannot run in v86:** K (Kernel64 + Win64 runtime) and I (the installer, which is Kernel64 too), and every UEFI
  path (boot manager, Kernel64 direct, CSMWrap, the Supervisor). v86 boots the ISO's El Torito BIOS entry (isolinux).
- **can run in v86:** the syslinux menu, **D** (ShizukuDOS 10 DOS16, FreeDOS profile, via memdisk) and **1**
  (ShizukuDOS 0.1, via memdisk).

Tested by us with v86 0.5.462 (npm `v86`), run under Node.js 22 with `seabios.bin` and `vgabios.bin` from v86's
`bios/` directory, `memory_size` 256 MiB, keys sent through the emulated PS/2 keyboard, an ISO built from this tree
loaded as `cdrom` from memory:

| What | Result in v86 |
| --- | --- |
| the ISO as `cdrom` | the boot menu on screen and on COM1 after about 2 s |
| key 1, Enter | ShizukuDOS 0.1 `A:\>` about 1 s later; `DIR`, `TYPE HELLO.TXT`, `EXEC DEMO.COM` and `CPU` work |
| key D, Enter | FreeDOS boots, prints `T_MODE: real mode confirmed`, `T_BIOS: platform contract OK`, `T_COM: DOS file/memory services OK`, and `SHZ-EXIT:0` reaches COM1 about 5 s later; then the CPU halts. The byte-exact checks the matrix makes on the RAM disk (`RESULT.TXT`, `T_COM.OUT`, `T_EXE.OUT`) were not repeated in v86 |
| key K, Enter, **or no key for 30 s** (K is the default) | the Multiboot stub prints `SHZ-STUB: kernel ... ram 10000000 ...`; when it starts the switch to Long Mode, v86 aborts with `panicked at src/rust/cpu/cpu.rs:857:13: Unimplemented: #GP handler` (WebAssembly `unreachable`). The emulator instance is dead; the page has to create a new one |
| `ShizukuDOS/shizukudos.img` from the ISO as `fda` | ShizukuDOS 0.1 `A:\>` directly |
| `ShizukuDOS10/dos16/shizukudos-dos16-hd32.img` from the ISO as `hda` | DOS16 to `SHZ-EXIT:0` directly |

Not tested: v86 inside a real browser (only under Node.js), loading images over HTTP (`url`, `async: true`), other
v86 versions and memory sizes.

Advice for a demo page:

1. **Boot the two small images, not the ISO.** A 1.44 MB floppy and a 32 MiB disk instead of the whole ISO, and no
   Kernel64 default to crash into. Extract them from the release ISO and check them against `HASHES.TXT` in the ISO
   root (columns `sha256  bytes  path`):
   ```
   xorriso -osirrox on -indev windows98-shizuku-second-edition.iso \
     -extract /ShizukuDOS/shizukudos.img shizukudos.img \
     -extract /ShizukuDOS10/dos16/shizukudos-dos16-hd32.img shizukudos-dos16-hd32.img \
     -extract /HASHES.TXT HASHES.TXT
   ```
   then `new V86({ fda: { url: "shizukudos.img" }, ... })` for 0.1, or `hda: { url: "shizukudos-dos16-hd32.img" }`
   for DOS16. DOS16 writes its result files to that disk; in v86 the changes stay in the page's memory.
2. **If the page boots the ISO**, choose the entry before the 30 s timeout: watch COM1 (`serial0-output-byte`) for
   `Automatic boot in`, then send `1` or `d` and Enter (`emulator.keyboard_send_text("1")`,
   `emulator.keyboard_send_scancodes([0x1c, 0x9c])`), and tell visitors not to pick K or I.
3. **Serve the images from the page's own origin.** v86 downloads disk images with HTTP requests (with `async: true`,
   as Range requests); another origin would need CORS. The ISO has no public download URL; host only what the page
   shows, and link to nothing else.
4. Say on the page that the browser demo is the 16-bit part only and that Kernel64 needs an x86-64 VM (below).

### Kernel64 in real time: a server-side VM

The Kernel64 + Win64 runtime needs an x86-64 CPU, so a live demo of it runs QEMU on a server and shows the VM in the
page. One QEMU per visitor session, read-only medium, no network, no disk:

```
qemu-system-x86_64 -machine q35 -accel tcg -cpu max -smp 2 -m 512 \
  -drive file=/srv/shz/windows98-shizuku-second-edition.iso,format=raw,if=none,id=cd,readonly=on,media=cdrom \
  -device ide-cd,drive=cd,bus=ide.0,bootindex=1 \
  -vga std -display none -vnc 127.0.0.1:0,websocket=127.0.0.1:5700 \
  -serial file:/var/log/shz/session-$SESSION.com1.log \
  -net none -monitor none -no-reboot \
  -device isa-debug-exit,iobase=0xf4,iosize=0x04
```

- `-vnc 127.0.0.1:0` is plain VNC on port 5900; `websocket=127.0.0.1:5700` makes QEMU serve the same display as a
  WebSocket, which [noVNC](https://github.com/novnc/noVNC) connects to directly (checked with QEMU 8.2.2: port 5900
  answers `RFB 003.008`, port 5700 answers the WebSocket upgrade with `101 Switching Protocols`). Without the
  `websocket=` option, run `websockify --web /usr/share/novnc 6080 127.0.0.1:5900` instead. Either way, put it behind
  the web server's TLS (`wss://`) and a per-session token; never expose the VNC ports themselves. Use a different
  display number and WebSocket port per session.
- **Show COM1 next to the screen.** Kernel64 writes its whole log (self-tests, each `T_*.EXE`, `SHZ-EXIT:0`) to COM1
  only. The screen (checked by QEMU screendumps of this command line, `-vga std`) switches to a 1024×768 desktop on
  which the Win64 GUI test programs open and close their windows (for example one titled *Input Test*), and ends on
  the empty desktop; there is no text on it. Stream the `-serial` file to the page (for example with a small
  WebSocket or server-sent-events tail), or use `-chardev socket,id=com1,path=...,server=on,wait=off,logfile=...
  -serial chardev:com1` to also send menu keys over COM1.
- The menu picks K by itself after 30 s; the visitor can also press K, D or 1 in the noVNC window. With
  `isa-debug-exit`, QEMU exits when Kernel64 finishes (`SHZ-EXIT`): end the session then, and also after a fixed time
  limit (the DOS16 and 0.1 entries do not exit QEMU; they halt or wait at `A:\>`).
- **CPU cost.** TCG needs no KVM and works on any Linux host, but it is slow: with 2 vCPUs QEMU keeps up to two host
  threads busy, and one Kernel64 run takes 2–4 minutes of that (113–217 s per Kernel64 row of the matrix including
  the boot to the menu, QEMU 8.2.2, depending on the host's load). Budget roughly one to two host cores and 600 MiB of
  RAM per concurrent session and cap the number of sessions. If the host exposes `/dev/kvm`, `-accel kvm -cpu host`
  is much faster but is not what the release test runs.
- A cheaper alternative to one VM per visitor is one shared VM that restarts on a loop, with viewers watching a
  read-only noVNC view (`view_only`) and the COM1 log; or a recording of a real run.
- The server holds the ISO; the page never offers it for download.

## What the ISO contains

- The syslinux 6.04 boot menu (`isolinux/`, pinned Ubuntu build) and the UEFI El Torito image with the Shizuku UEFI
  loader and boot manager, CSMWrap + SeaBIOS (CSM), and `\SHZDOS\` (DOS16 disk, Kernel32, Kernel64, standalone
  Kernel64, `WIN64.IMG`).
- `SHZ/K64/`: the standalone Kernel64 (Multiboot stub, `KERNEL64S.BIN`) and `WIN64.IMG`, the Win64 runtime (ntdll,
  kernel32 and friends, the Wine DLL port with FreeType, Noto and Tahoma fonts) plus the Win64 test programs.
- `SHZ/SETUP/`: the SHZSETUP installer image and its answer file.
- ShizukuDOS 10 DOS16 (FreeDOS kernel and FreeCOM, built from pinned sources with the project's patches) and
  ShizukuDOS 0.1 (the project's own shell).
- The Windows 98 SE overlay binaries (NTWrapper9x, NTWin32Wrapper9x, NTWDDMWrapper9x) and the SHZSE overlay
  installer, as files on the disc.
- `DRIVERS\` (the driver store's index files only; the repository ships no driver packages), `README.TXT`,
  `VMPROFIL.TXT`, `LIMITS.TXT`, `SOURCES.TXT`, `HASHES.TXT` (per-file SHA-256).
- Licences of every third-party part (`ShizukuDOS10\LICENSES`: FreeDOS, CSMWrap and SeaBIOS, syslinux, Wine,
  FreeType, Noto) and the corresponding source (`ShizukuDOS10\SOURCE`: FreeDOS, CSMWrap with its submodules, the
  syslinux Debian source package, Wine, FreeType, and the Shizuku source the image was built from).

## What it does not contain, and what it does not do

- **No Windows 98 media and nothing from Microsoft**: no `IO.SYS`, no `WIN98` cabinets, no product keys. The ISO
  builder's `--win98-media` option makes a separate private ISO; `tools/build_release.py` never uses it and refuses a
  private image.
- It does **not install or boot Windows 98** and is not a Windows 98 installation. The Install entry installs
  ShizukuDOS 10 (Kernel64 on ShizukuFS), not Windows.
- **Chromium does not run in the guest yet.** Chromium and Electron applications are a target whose imports are being
  measured ([ELECTRON_TARGET.md](ELECTRON_TARGET.md)); no browser is on the ISO.
- The Supervisor path (DOS and Windows 98 domains under Intel VMX) is on the medium but is **not exercised by the
  release test**: QEMU TCG has no VMX, so the matrix covers CSMWrap, the legacy menu entries and Kernel64 direct.
- The installed system (entry I) carries the Shizuku modules only, not the Wine DLLs and fonts of `WIN64.IMG`.
- VirtualBox, VMware, Hyper-V and real hardware are untested.
