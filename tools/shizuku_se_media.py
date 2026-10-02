#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Shared parts of the ShizukuOS boot media.

Used by tools/build_shizuku_se_iso.py (the product: one hybrid "VM install ISO")
and tools/build_shizuku_se_disk.py (a secondary raw USB/HDD image). Nothing here
boots anything; it resolves inputs and assembles bytes.

Boot design (exercised by tools/test_shizuku_se_boot_matrix.py, documented in
docs/shizukudos10/MEDIA.md):

  Legacy BIOS  CD       El Torito default entry = isolinux.bin (no emulation)
               USB/HDD  ISO: isohdpfx.bin MBR -> isolinux.bin (isohybrid)
                        raw disk: syslinux mbr.bin -> active FAT32 -> ldlinux.sys
               -> the same menu.c32 menu (also on COM1, 115200 8N1):
                  Kernel64   mboot.c32 BOOT.ELF --- KERNEL64S.BIN --- WIN64.IMG
                             (Multiboot stub, module 0 kernel, module 1 initrd)
                  DOS16      memdisk harddisk, the ShizukuDOS 10 FreeDOS disk image
                  Install    only when SHZSETUP (\\SHZ\\SETUP) is present: Kernel64
                             with `shz.setup=interactive` on the Multiboot command line
  UEFI         \\EFI\\BOOT\\BOOTX64.EFI = the Shizuku loader and boot manager
               (supervisor/loader). \\EFI\\SHIZUKU\\BOOT.INI: mode = auto, menu_timeout = 5.
               Its menu (console and COM1) waits 5 s for a key:
                  A/Enter or no key  auto: Supervisor with Intel VMX, otherwise CSM
                  K                  Kernel64 direct: \\SHZDOS\\KERNEL64S.BIN + WIN64.IMG in
                                     Long Mode, no Supervisor, no VMX, GOP framebuffer
                  C                  CSM: \\EFI\\SHIZUKU\\CSMWRAP.EFI (LGPL-2.1, SeaBIOS CSM
                                     LGPL-3.0) legacy-boots the SAME medium, i.e. the menu above
                  S                  Supervisor only
                  I                  Interactive self-developed installer, INSTALL.IMG on this boot volume
               No UEFI Shell and no startup.nsh is involved.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SHZ_BUILD = BUILD / "shizukudos"
sys.path.insert(0, str(ROOT / "shizukudos" / "tools"))
sys.path.insert(0, str(ROOT / "tools"))
import shzlib  # noqa: E402
import shizuku_se_drivers as drivers  # noqa: E402
import shizuku_image_io as image_io  # noqa: E402

FIXED_EPOCH = 1785283200  # 2026-07-29 00:00:00 UTC, the epoch of the DOS16 image and the ISO
MIB = 1 << 20

# ---------------------------------------------------------------------------- inputs

DEFAULT_LOADER = SHZ_BUILD / "supervisor" / "BOOTX64.EFI"
DEFAULT_CSMWRAP = SHZ_BUILD / "csm" / "CSMWRAP.EFI"
CSMWRAP_RECEIPT = SHZ_BUILD / "csm" / "build-result.json"
DEFAULT_SETUP_DIR = SHZ_BUILD / "install-media"  # install/mkpayload.py --out (agent I1's payload, shipped answer file)
SETUP_MAIN = "INSTALL.IMG"                        # initial RAM archive: Win64 runtime + SHZSETUP.EXE + answer + payload
SETUP_ISO_DIR = "SHZ/SETUP"
K64_FILES = {  # name on the media -> build output
    "BOOT.ELF": SHZ_BUILD / "kernel64s" / "boot.elf",
    "KERNEL64S.BIN": SHZ_BUILD / "kernel64s" / "KERNEL64S.BIN",
    "WIN64.IMG": SHZ_BUILD / "win64" / "WIN64.IMG",
}
SHZDOS_FILES = {  # \SHZDOS files the loader reads from its own volume (supervisor/loader/loader.c)
    "DISK.IMG": SHZ_BUILD / "dos16" / "shizukudos-dos10.img",
    "KERNEL32.BIN": SHZ_BUILD / "kernel32" / "KERNEL32.BIN",
    "KERNEL64.BIN": SHZ_BUILD / "kernel64" / "KERNEL64.BIN",
    "KERNEL64S.BIN": SHZ_BUILD / "kernel64s" / "KERNEL64S.BIN",   # boot manager: Kernel64 direct (menu key K)
    "WIN64.IMG": SHZ_BUILD / "win64" / "WIN64.IMG",
}
MENU_TIMEOUT = 5                  # BOOT.INI menu_timeout: seconds the UEFI boot manager menu waits for a key
BOOT_MODES = ("auto", "supervisor", "csm", "kernel64", "install")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Input:
    """One input file of the media and where it came from."""
    name: str
    path: Path
    origin: str
    notes: list[str] = field(default_factory=list)

    @property
    def data(self) -> bytes:
        return self.path.read_bytes()

    def record(self) -> dict:
        data = self.data
        return {"name": self.name, "path": rel(self.path), "bytes": len(data), "sha256": sha256(data),
                "origin": self.origin, "notes": self.notes}


def rel(path: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def require(path: Path, how: str) -> Path:
    if not Path(path).is_file():
        raise RuntimeError(f"{path} is missing ({how})")
    return Path(path)


def verify_source_pins(pins: dict[str, str], component: str) -> int:
    """Refuse stale component artifacts before shipping current source beside them."""
    if not isinstance(pins, dict) or not pins:
        raise RuntimeError(f"{component} has no source-bound build receipt; rebuild it")
    for name, digest in pins.items():
        if not isinstance(name, str) or Path(name).is_absolute() or ".." in Path(name).parts:
            raise RuntimeError(f"{component} has an invalid source path")
        path = (ROOT / name).resolve()
        if not path.is_relative_to(ROOT.resolve()) or not path.is_file() or shzlib.sha256_file(path) != digest:
            raise RuntimeError(f"{component} source changed or is missing: {name}; rebuild before packaging")
    return len(pins)


def loader_features(data: bytes) -> dict[str, bool]:
    """What the loader binary carries: the boot manager (it opens \\EFI\\SHIZUKU\\BOOT.INI, a UTF-16 path), its
    menu (BOOT.INI menu_timeout) and the firmware-hole plan for Kernel64 direct (kernel64/standalone/memholes.h)."""
    low = data.lower()
    return {"boot_manager": "\\efi\\shizuku\\boot.ini".encode("utf-16-le") in low,
            "menu": b"Shizuku boot manager menu" in data,
            "memholes": b"firmware hole(s) handed over at 0x6000" in data,
            "installer": "\\shz\\setup\\install.img".encode("utf-16-le") in low and
                         b"shz.setup=interactive shz.noapps" in data}


def loader_input(path: Path | None = None) -> Input:
    path = Path(path) if path else DEFAULT_LOADER
    require(path, "python3 shizukudos/supervisor/build.py (or shz.py build --profile uefi-multikernel), or pass --loader")
    data = path.read_bytes()
    if data[:2] != b"MZ":
        raise RuntimeError(f"{path} is not a PE image")
    features = loader_features(data)
    missing = [name for name, present in features.items() if not present]
    if missing:
        raise RuntimeError(f"{path} lacks {', '.join(missing)}: the media need the UEFI boot manager with its menu and "
                           "the interactive installer and Kernel64 firmware-hole plan; rebuild it with shizukudos/supervisor/build.py")
    return Input("Shizuku UEFI loader and boot manager \\EFI\\BOOT\\BOOTX64.EFI", path,
                 "--loader" if path != DEFAULT_LOADER else "shizukudos/supervisor/build.py",
                 notes=["boot manager, menu (BOOT.INI menu_timeout) and Kernel64 firmware-hole plan present"])


def csmwrap_input(path: Path | None = None) -> Input:
    path = Path(path) if path else DEFAULT_CSMWRAP
    require(path, "python3 shizukudos/csm/build.py (pinned CSMWrap 7f30b74), or pass --csmwrap")
    notes = []
    if path == DEFAULT_CSMWRAP and CSMWRAP_RECEIPT.is_file():
        receipt = json.loads(CSMWRAP_RECEIPT.read_text())
        want = receipt["artifacts"]["CSMWRAP.EFI"]["sha256"]
        if want != shzlib.sha256_file(path):
            raise RuntimeError(f"{path} does not match {rel(CSMWRAP_RECEIPT)}; rebuild with shizukudos/csm/build.py")
        up = receipt["upstream"]["csmwrap"]
        notes.append(f"CSMWrap {up['commit'][:12]}, SeaBIOS {up['seabios_version']}, matches {rel(CSMWRAP_RECEIPT)}")
    return Input("CSMWrap \\EFI\\SHIZUKU\\CSMWRAP.EFI", path,
                 "shizukudos/csm/build.py" if path == DEFAULT_CSMWRAP else "--csmwrap", notes=notes)


def k64_inputs() -> dict[str, Input]:
    how = "python3 shizukudos/kbuild.py && python3 shizukudos/win64/build.py"
    return {name: Input(f"Kernel64 standalone {name}", require(path, how),
                        "shizukudos/kbuild.py" if name != "WIN64.IMG" else "shizukudos/win64/build.py")
            for name, path in K64_FILES.items()}


def shzdos_inputs() -> dict[str, Input]:
    how = "python3 shizukudos/tools/shz.py build --profile uefi-multikernel"
    return {name: Input(f"\\SHZDOS\\{name}", require(path, how), how) for name, path in SHZDOS_FILES.items()}


def build_install_payload(directory: Path | None = None, desktop: bool = True) -> None:
    """install/mkpayload.py (agent I1) with the shipped answer file (install/shzsetup.ini) into its own directory, so
    tests/run_install.py's test payload (build/shizukudos/install) and the media's never overwrite each other."""
    directory = Path(directory) if directory else DEFAULT_SETUP_DIR
    subprocess.run([sys.executable, str(ROOT / "shizukudos" / "install" / "mkpayload.py"), "--out", str(directory),
                    "--desktop" if desktop else "--no-desktop"],
                   check=True, timeout=1800, stdout=subprocess.DEVNULL, env=dict(os.environ,
                                                                                  SOURCE_DATE_EPOCH=str(FIXED_EPOCH)))


def setup_payload(directory: Path | None, prefix: str = SETUP_ISO_DIR) -> tuple[dict[str, bytes], dict]:
    """\\SHZ\\SETUP on the media: INSTALL.IMG from install/mkpayload.py (agent I1) and, for reading, its answer file
    and receipt. The Install menu entry boots Kernel64 with INSTALL.IMG as its initial RAM image and shz.setup=interactive."""
    directory = Path(directory) if directory else DEFAULT_SETUP_DIR
    info = {"directory": rel(directory), "present": False}
    image = directory / SETUP_MAIN
    if not image.is_file():
        info["note"] = f"{rel(image)} not found (install/mkpayload.py): no \\SHZ\\SETUP and no Install menu entry"
        return {}, info
    # Public media accepts only the existing development installer envelope.
    # Private native ESP imports have a separate explicitly private producer.
    import importlib.util
    guard_path = ROOT / "shizukudos/install/native_payload_ingest.py"
    spec = importlib.util.spec_from_file_location("private_native_payload_public_guard", guard_path)
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    if image.stat().st_size > 64 << 20:
        raise ValueError("public INSTALL.IMG exceeds the development installer bound")
    for metadata in (directory / "mkpayload-result.json", directory / "payload" / "manifest.json"):
        if not 0 < metadata.stat().st_size <= guard.MAX_JSON:
            raise ValueError("public installer metadata exceeds its input bound")
    image_bytes = image.read_bytes()
    receipt = json.loads((directory / "mkpayload-result.json").read_text(), object_pairs_hook=guard.unique)
    manifest_bytes = (directory / "payload" / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes, object_pairs_hook=guard.unique)
    guard.require_public_payload(manifest, receipt, image_bytes)
    if receipt["outputs"]["INSTALL.IMG"]["sha256"] != sha256(image_bytes):
        raise RuntimeError(f"{image} does not match {directory / 'mkpayload-result.json'}")
    answer = (directory / "shzsetup.ini").read_bytes()
    if answer != (ROOT / "shizukudos" / "install" / "shzsetup.ini").read_bytes():
        raise RuntimeError(f"{directory} was built with another answer file than install/shzsetup.ini; the media ship "
                           "the product answer file (rebuild with install/mkpayload.py --out)")
    payload = {f"{prefix}/INSTALL.IMG": image_bytes, f"{prefix}/SHZSETUP.INI": answer,
               f"{prefix}/MANIFEST.JSON": manifest_bytes,
               f"{prefix}/README.TXT": (
                   "\\SHZ\\SETUP - ShizukuDOS 10 installer (SHZSETUP, install/mkpayload.py)\r\n"
                   "Boot menu entry I: Kernel64 with INSTALL.IMG as its initial RAM image and the\r\n"
                   "command line shz.setup=interactive. SHZSETUP.EXE opens its own installer UI.\r\n"
                   "Select a target, review it, type ERASE and confirm to install.\r\n"
                   "The chosen disk is erased; cancelling writes nothing. The installer\r\n"
                   "writes GPT + EFI System Partition + ShizukuFS and verifies its files.\r\n"
                   "The installed disk boots on UEFI (the Shizuku boot\r\n"
                   "manager, BOOT.INI mode = kernel64) and on legacy BIOS (syslinux on the ESP).\r\n"
                   "MANIFEST.JSON lists every file the installer writes, with SHA-256.\r\n"
                   f"INSTALL.IMG sha256 {sha256(image_bytes)}\r\n").encode("ascii")}
    info.update(present=True, bios_boot=receipt.get("bios_boot"),
                boot_profile=manifest.get("boot_profile", "self-test"), install_img_sha256=sha256(image_bytes),
                files={name: sha256(data) for name, data in payload.items()})
    return payload, info


# ---------------------------------------------------------------------------- syslinux (pinned)

SYSLINUX_MODULES = ("ldlinux.c32", "libcom32.c32", "libutil.c32", "menu.c32", "mboot.c32")


def syslinux() -> dict[str, Path]:
    """Pinned Ubuntu syslinux 6.04 files (shizukudos/upstream/manifest.json, checked by sha256)."""
    up = shzlib.ensure_deb_upstream("syslinux")
    root = up["root"]
    files = {name: root / "usr/lib/syslinux/modules/bios" / name for name in SYSLINUX_MODULES}
    files.update({"isolinux.bin": root / "usr/lib/ISOLINUX/isolinux.bin",
                  "isohdpfx.bin": root / "usr/lib/ISOLINUX/isohdpfx.bin",
                  "memdisk": root / "usr/lib/syslinux/memdisk",
                  "mbr.bin": root / "usr/lib/syslinux/mbr/mbr.bin",
                  "installer": root / "usr/bin/syslinux",
                  "_root": root, "_downloads": up["downloads"]})
    return files


def syslinux_spec() -> dict:
    return shzlib.load_manifest()["upstreams"]["syslinux"]


# ---------------------------------------------------------------------------- boot menu

MENU_TITLE = "ShizukuOS - ShizukuDOS 10"
MENU_KEYS = {"kernel64": "k", "setup": "i", "dos16": "d"}


def boot_menu(dos16_image: str, k64_dir: str = "/SHZ/K64", setup: bool = False,
              desktop: bool = True, unattended: bool = False) -> bytes:
    """Product boot menu; unattended installation is an explicit test option."""
    mboot = f"{k64_dir}/BOOT.ELF --- {k64_dir}/KERNEL64S.BIN --- {k64_dir}/WIN64.IMG"
    lines = [
        "# ShizukuOS boot menu (tools/shizuku_se_media.py).",
        "SERIAL 0 115200", "UI menu.c32", "PROMPT 0", "TIMEOUT 50",
        f"MENU TITLE {MENU_TITLE}", "DEFAULT desktop" if desktop else "DEFAULT kernel64", "",
    ]
    if desktop:
        lines += ["LABEL desktop", "  MENU LABEL ^Start ShizukuOS", "  KERNEL mboot.c32",
                  f"  APPEND {k64_dir}/BOOT.ELF shz.desktop --- {k64_dir}/KERNEL64S.BIN --- {k64_dir}/WIN64.IMG", ""]
    lines += ["LABEL kernel64", "  MENU LABEL ^Kernel64 component diagnostics", "  KERNEL mboot.c32",
              f"  APPEND {mboot}", ""]
    if setup:
        mode = "auto" if unattended else "interactive"
        label = "Unattended installer TEST - erases the first empty disk" if unattended else "Install ShizukuOS - select and confirm the target"
        lines += ["LABEL setup", f"  MENU LABEL ^{label}", "  TEXT HELP",
                  "  Built-in SHZSETUP writes and verifies GPT, ESP and ShizukuFS.",
                  "  Interactive review/cancel changes no disks." if not unattended else "  Explicit unattended test profile only.",
                  "  ENDTEXT", "  KERNEL mboot.c32",
                  f"  APPEND {k64_dir}/BOOT.ELF shz.setup={mode} shz.noapps --- {k64_dir}/KERNEL64S.BIN --- /{SETUP_ISO_DIR}/{SETUP_MAIN}", ""]
    lines += ["LABEL dos16", "  MENU LABEL ^DOS10 recovery command shell", "  TEXT HELP",
              "  ShizukuDOS 10 starts the MS-DOS compatibility bootstrap shell.",
              "  This memdisk instance is in RAM; its changes do not persist.",
              "  ENDTEXT", "  KERNEL memdisk", f"  INITRD {dos16_image}", "  APPEND harddisk", ""]
    return "\n".join(lines).encode("ascii")


# ---------------------------------------------------------------------------- UEFI side

def csmwrap_ini() -> bytes:
    """CSMWrap's own settings next to the binary: debug log on COM1 (same keys as the DOS16 dual image)."""
    return b"; CSMWrap debug log on COM1\r\nserial=true\r\nserial_port=0x3f8\r\nserial_baud=115200\r\n"


def boot_ini(mode: str, menu_timeout: int = MENU_TIMEOUT) -> bytes:
    """\\EFI\\SHIZUKU\\BOOT.INI in the boot manager's strict grammar (supervisor/loader/bootini.h)."""
    if mode not in BOOT_MODES:
        raise ValueError(f"boot mode {mode!r} not in {BOOT_MODES}")
    if not 0 <= menu_timeout <= 30:
        raise ValueError("menu_timeout must be 0..30 seconds")
    return (
        "; Shizuku UEFI boot manager policy (\\EFI\\BOOT\\BOOTX64.EFI).\r\n"
        "; auto: the Supervisor with Intel VMX, otherwise CSMWrap -> this medium's legacy menu.\r\n"
        "; The menu waits menu_timeout seconds: A/Enter = mode below, K = Kernel64 direct,\r\n"
        "; I = interactive installer, C = CSM legacy BIOS, S = Supervisor. menu_timeout = 0 turns the menu off.\r\n"
        f"mode = {mode}\r\n"
        "csm_path = \\EFI\\SHIZUKU\\CSMWRAP.EFI\r\n"
        "auto_kernel64 = no\r\n"
        f"menu_timeout = {menu_timeout}\r\n"
    ).encode("ascii")


def efi_readme(loader: Input, csm: Input, mode: str) -> bytes:
    return (
        "\\EFI - UEFI side of the ShizukuOS media\r\n"
        "\r\n"
        "\\EFI\\BOOT\\BOOTX64.EFI     Shizuku UEFI loader and boot manager (project code,\r\n"
        "  GPL-2.0-only). It reads \\EFI\\SHIZUKU\\BOOT.INI and shows a menu on the\r\n"
        "  console and COM1: A/Enter or no key = BOOT.INI mode (auto: the Supervisor\r\n"
        "  with Intel VMX, otherwise CSMWRAP.EFI); K = Kernel64 direct (\\SHZDOS\\\r\n"
        "  KERNEL64S.BIN + WIN64.IMG, Long Mode, no VMX, GOP framebuffer; firmware\r\n"
        "  holes such as OVMF's S3 ACPI NVS at 8 MiB are kept out of its memory);\r\n"
        "  I = interactive installer (\\SHZ\\SETUP\\INSTALL.IMG);\r\n"
        "  C = CSMWRAP.EFI; S = Supervisor only.\r\n" +
        "\\EFI\\SHIZUKU\\CSMWRAP.EFI  CSMWrap (LGPL-2.1) with the SeaBIOS CSM (LGPL-3.0):\r\n"
        "  PC BIOS services on UEFI-only machines; it then legacy-boots THIS\r\n"
        "  medium (El Torito default entry on a CD, the MBR on a disk), i.e. the\r\n"
        "  same boot menu a legacy BIOS shows.\r\n"
        "  Needs Secure Boot OFF (nothing here is signed) and 2 or more logical\r\n"
        "  CPUs (it keeps one for itself). Source and licences: \\ShizukuDOS10\\ on\r\n"
        "  the ISO.\r\n"
        "\\EFI\\SHIZUKU\\CSMWRAP.INI  CSMWrap settings: debug log on COM1.\r\n"
        f"\\EFI\\SHIZUKU\\BOOT.INI     boot manager policy, mode = {mode}, menu_timeout = {MENU_TIMEOUT}\r\n"
        "  (modes: auto | supervisor | csm | kernel64 | install).\r\n"
        "\\SHZDOS\\                   files the loader reads from its own volume.\r\n"
        f"BOOTX64.EFI sha256 {sha256(loader.data)}\r\n"
        f"CSMWRAP.EFI sha256 {sha256(csm.data)}\r\n"
    ).encode("ascii")


def efi_members(loader: Input, csm: Input, shzdos: dict[str, Input], mode: str,
                setup_files: dict[str, bytes] | None = None) -> dict[str, bytes]:
    """The UEFI file set: the El Torito EFI image of the ISO, and the raw disk's FAT volume root."""
    members = {
        "EFI/BOOT/BOOTX64.EFI": loader.data,
        "EFI/SHIZUKU/CSMWRAP.EFI": csm.data,
        "EFI/SHIZUKU/CSMWRAP.INI": csmwrap_ini(),
        "EFI/SHIZUKU/BOOT.INI": boot_ini(mode),
        "EFI/SHIZUKU/README.TXT": efi_readme(loader, csm, mode),
    }
    for name, item in shzdos.items():
        members[f"SHZDOS/{name}"] = item.data
    installer = f"{SETUP_ISO_DIR}/{SETUP_MAIN}"
    if setup_files:
        data = setup_files.get(installer, b"")
        if not data or len(data) > 64 * MIB:
            raise RuntimeError("the UEFI installer requires an actual INSTALL.IMG within the loader's 64 MiB limit")
        members[installer] = data
    elif mode == "install":
        raise RuntimeError("UEFI mode=install requires the actual installer payload")
    return members


# ---------------------------------------------------------------------------- FAT images

def mtools_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"MTOOLS_SKIP_CHECK": "1", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(FIXED_EPOCH), "LC_ALL": "C"})
    return env


def make_fat(image: Path, members: dict[str, bytes], size_mib: int, fat: int, label: str, volume_id: str,
             scratch: Path, offset: int = 0, hidden: int = 0) -> None:
    """A FAT12/16/32 file system with `members` (path -> bytes), reproducible (fixed id, dates, order).

    With `offset`, the file system is written into `image` at that byte offset (a partition of a
    disk image that already exists and is large enough); `hidden` is the BPB hidden-sector count."""
    fs = scratch / "fat.img" if offset else image
    fs.unlink(missing_ok=True)
    fs.parent.mkdir(parents=True, exist_ok=True)
    with open(fs, "wb") as handle:
        handle.truncate(size_mib * MIB)
    mkfs = ["mkfs.vfat", "--invariant", "-F", str(fat), "-n", label, "-i", volume_id, "-h", str(hidden)]
    if fat == 32:
        mkfs += ["-s", "1"]
    subprocess.run([*mkfs, str(fs)], check=True, stdout=subprocess.DEVNULL, env=mtools_env())
    env = mtools_env()
    directories = sorted({"/".join(name.split("/")[:depth]) for name in members
                          for depth in range(1, name.count("/") + 1)}, key=lambda d: (d.count("/"), d))
    if directories:
        subprocess.run(["mmd", "-i", str(fs), *[f"::/{d}" for d in directories]], check=True, env=env)
    source = scratch / "fat-src"
    shutil.rmtree(source, ignore_errors=True)
    for name in sorted(members):
        local = source / name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_bytes(members[name])
        subprocess.run(["mcopy", "-i", str(fs), str(local), f"::/{name}"], check=True, env=env)
    shutil.rmtree(source)
    check = subprocess.run(["fsck.vfat", "-n", str(fs)], capture_output=True, text=True)
    if check.returncode != 0:
        raise RuntimeError(f"fsck.vfat rejects {fs}:\n{check.stdout}{check.stderr}")
    if offset:
        image_io.overlay_sparse_partial(fs, image, destination_offset=offset)
        fs.unlink()


def read_fat_file(spec: str, name: str) -> bytes | None:
    """One file from an mtools image spec (path or path@@offset)."""
    result = subprocess.run(["mtype", "-i", spec, f"::/{name}"], capture_output=True, env=mtools_env())
    return result.stdout if result.returncode == 0 else None


def verify_fat_members(spec: str, members: dict[str, bytes], scratch: Path) -> int:
    """Every member reads back byte-identical (mcopy, not mtype: binary safe)."""
    scratch.mkdir(parents=True, exist_ok=True)
    out = scratch / "readback.bin"
    for name, data in members.items():
        out.unlink(missing_ok=True)
        result = subprocess.run(["mcopy", "-n", "-i", spec, f"::/{name}", str(out)], capture_output=True,
                                env=mtools_env())
        if result.returncode != 0 or out.read_bytes() != data:
            raise RuntimeError(f"{spec}: ::/{name} does not read back identical")
    out.unlink(missing_ok=True)
    return len(members)


# ---------------------------------------------------------------------------- licences and source

def deterministic_tar_gz(entries: list[tuple[str, Path]]) -> bytes:
    import gzip
    import io
    import tarfile
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as tar:
            for arcname, path in entries:
                info = tar.gettarinfo(str(path), arcname)
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                info.mtime = FIXED_EPOCH
                info.mode = 0o755 if (info.isdir() or info.mode & 0o111) else 0o644
                if info.isreg():
                    with open(path, "rb") as handle:
                        tar.addfile(info, handle)
                else:
                    tar.addfile(info)
    return buffer.getvalue()


def syslinux_payload(prefix: str) -> dict[str, bytes]:
    """Syslinux licence texts and the Debian source package the pinned binaries were built from."""
    files = syslinux()
    spec = syslinux_spec()
    payload = {}
    for relative in spec["license_files"]:
        package = relative.split("/")[3]
        payload[f"{prefix}/LICENSES/syslinux-{package}-copyright.txt"] = (files["_root"] / relative).read_bytes()
    for item in spec["source"].values():
        payload[f"{prefix}/SOURCE/syslinux/{item['file']}"] = (files["_downloads"] / item["file"]).read_bytes()
    used = {name: shzlib.sha256_file(files[name]) for name in
            ("isolinux.bin", "isohdpfx.bin", "memdisk", "mbr.bin", *SYSLINUX_MODULES)}
    payload[f"{prefix}/SOURCE/syslinux/README.TXT"] = (
        "Syslinux 6.04 (third-party boot loaders) - licence and source\r\n"
        "==============================================================\r\n"
        f"Binaries  Ubuntu 24.04 packages {spec['distribution'].split()[-1]}\r\n"
        "          (isolinux, syslinux-common; the syslinux FAT installer is only a\r\n"
        "          build tool for the raw disk image), unmodified.\r\n"
        f"Upstream  {spec['repository']} snapshot {spec['commit']}\r\n"
        f"Licence   {spec['license']}; see LICENSES\\syslinux-*-copyright.txt for the\r\n"
        "          per-file terms (most com32 modules are MIT/Expat).\r\n"
        "Source    the Debian source package in this directory (.dsc, .orig.tar.xz,\r\n"
        "          .debian.tar.xz) is the corresponding source of every binary used:\r\n"
        + "".join(f"            {name:14} sha256 {digest}\r\n" for name, digest in used.items())
    ).encode("ascii")
    return payload


def vm_profiles_text() -> str:
    return (
        "VM PROFILES - ShizukuOS VM install ISO\r\n"
        "==============================================================\r\n"
        "Tested only in QEMU (TCG, no KVM) by tools/test_shizuku_se_boot_matrix.py:\r\n"
        "SeaBIOS and OVMF (S3 on, QEMU's default), this ISO as a CD and as a hard\r\n"
        "disk, and the raw disk image. VirtualBox, VMware and Hyper-V were NOT run;\r\n"
        "their lines below are settings derived from how the medium works, not\r\n"
        "test results.\r\n"
        "\r\n"
        "All VMs\r\n"
        "  RAM      512 MiB (what every test used). Kernel64 needs 64 MiB or more;\r\n"
        "           memdisk keeps the 32 MiB DOS16 image in RAM.\r\n"
        "  CPU      x86-64. 2 or more vCPUs for the UEFI CSM path: CSMWrap keeps one\r\n"
        "           logical CPU for itself and refuses to run with one.\r\n"
        "  Serial   COM1 115200 8N1 mirrors both boot menus, takes their keys and\r\n"
        "           carries every test result (SHZ-EXIT:0 = success).\r\n"
        "  Legacy BIOS  attach the ISO as a CD (or the raw disk / the ISO file as a\r\n"
        "           disk): the menu offers Kernel64, DOS16 and ShizukuDOS 0.1.\r\n"
        "  UEFI     Secure Boot OFF (nothing is signed). \\EFI\\BOOT\\BOOTX64.EFI is the\r\n"
        "           boot manager: its menu waits 5 s (\\EFI\\SHIZUKU\\BOOT.INI). No key:\r\n"
        "           the Supervisor with Intel VMX (nested VT-x in a VM), otherwise\r\n"
        "           CSMWrap and the same legacy menu. K: Kernel64 direct (Long Mode,\r\n"
        "           no VMX, no CSM, GOP framebuffer, at most 256 MiB RAM).\r\n"
        "  CSMWrap boot devices: IDE/SATA(AHCI), NVMe, USB, LSI/MPT/PVSCSI/MegaRAID\r\n"
        "           SCSI. Not virtio-blk/virtio-scsi, not Hyper-V VMBus storage.\r\n"
        "\r\n"
        "QEMU (tested)\r\n"
        "  BIOS  qemu-system-x86_64 -machine q35 -m 512 -smp 2 -cdrom THIS.iso\r\n"
        "  UEFI  add -drive if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd\r\n"
        "        -drive if=pflash,format=raw,file=<copy of OVMF_VARS.fd>\r\n"
        "        (a non-Secure-Boot OVMF build)\r\n"
        "  Disk  -drive file=THIS.iso,format=raw,if=none,id=d0 -device ide-hd,drive=d0\r\n"
        "VirtualBox (not tested)\r\n"
        "  BIOS: DVD on IDE or SATA. EFI: 'Enable EFI', 2+ CPUs, SATA/IDE/NVMe,\r\n"
        "  Secure Boot off.\r\n"
        "VMware Workstation/ESXi (not tested)\r\n"
        "  BIOS firmware as legacy BIOS. UEFI firmware: Secure Boot off, 2+ vCPUs,\r\n"
        "  SATA/IDE/NVMe or LSI/PVSCSI controller.\r\n"
        "Hyper-V (not tested)\r\n"
        "  Generation 1 (BIOS, IDE DVD): legacy menu. Generation 2 (UEFI only):\r\n"
        "  Secure Boot off; its storage is VMBus, which SeaBIOS inside CSMWrap\r\n"
        "  cannot drive, so the CSM entries are not expected to work there; key K\r\n"
        "  (Kernel64 direct) does not need the CSM. Use Generation 1 for DOS16.\r\n"
    )


def driver_store(specs: list[str]) -> tuple[dict[str, bytes], dict]:
    return drivers.store_payload(specs)
