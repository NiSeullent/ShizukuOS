#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare USB files from an exact public ISO; optionally add owner-supplied Win98 media.

No download, device formatting, mount, boot-sector write, or VM execution occurs.
`combine` explicitly runs the existing private ISO producer in a supplied checkout.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile

FAT32_MAX = (1 << 32) - 1
RESERVE = 17 * (1 << 30)
EFI_IMAGE = "ShizukuDOS10/efiboot.img"
MANIFEST = "USB-MANIFEST.JSON"
EFI_REQUIRED = {
    "EFI/BOOT/BOOTX64.EFI", "EFI/SHIZUKU/BOOT.INI", "EFI/SHIZUKU/CSMWRAP.EFI",
    "EFI/SHIZUKU/CSMWRAP.INI", "EFI/SHIZUKU/README.TXT", "SHZDOS/DISK.IMG",
    "SHZ/SETUP/INSTALL.IMG", "SHZDOS/KERNEL32.BIN", "SHZDOS/KERNEL64.BIN", "SHZDOS/KERNEL64S.BIN", "SHZDOS/WIN64.IMG",
}
PUBLIC_REQUIRED = {
    EFI_IMAGE, "isolinux/isolinux.cfg", "SHZ/K64/BOOT.ELF", "SHZ/K64/KERNEL64S.BIN", "SHZ/K64/WIN64.IMG",
    "SHZ/SETUP/INSTALL.IMG", "SHZ/SETUP/MANIFEST.JSON", "ShizukuDOS10/GPL-NOTICE.TXT",
    "ShizukuDOS10/SOURCE/shizukudos-source.tar.gz",
    "ShizukuDOS10/LICENSES/Shizuku-LICENSE-GPL-2.0.txt",
}
CLAIMS = {
    "uefi_guest_boot_verified": False,
    "bios_file_copy_supported": False,
    "copied_windows_iso_boot_supported": False,
    "windows98_setup_verified": False,
    "native_windows98_modern_apps_verified": False,
}


class PreparationError(ValueError):
    pass


def command(argv: list[str], timeout: int = 180) -> str:
    try:
        result = subprocess.run(argv, check=True, capture_output=True, text=True, timeout=timeout,
                                env=dict(os.environ, LC_ALL="C", MTOOLS_SKIP_CHECK="1"))
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise PreparationError(f"{argv[0]} failed; no successful preparation is claimed") from exc
    return result.stdout


def input_file(path: Path, fat32: bool = False) -> Path:
    path = path.expanduser().absolute()
    if not stat.S_ISREG(path.lstat().st_mode):
        raise PreparationError("Input must be a regular file, not a symlink or device")
    if fat32 and path.stat().st_size > FAT32_MAX:
        raise PreparationError("An individual file exceeds FAT32's 4 GiB minus 1 byte limit")
    return path.resolve(strict=True)


def stamp(path: Path) -> tuple[int, ...]:
    item = path.stat()
    return item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns


def file_record(path: Path) -> dict:
    before = stamp(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    if stamp(path) != before:
        raise PreparationError("Input changed while being read")
    return {"bytes": before[2], "sha256": digest.hexdigest()}


def read_receipt(path: Path) -> tuple[dict, dict, tuple[int, ...]]:
    before = stamp(path)
    raw = path.read_bytes()
    if stamp(path) != before or len(raw) != before[2]:
        raise PreparationError("Producer receipt changed while being read")
    record = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return json.loads(raw.decode("utf-8")), record, before


def safe_name(name: str) -> str:
    path = PurePosixPath(name)
    if (not path.parts or path.is_absolute() or ".." in path.parts or "\\" in name
            or any(ord(char) < 32 for char in name)):
        raise PreparationError("Unsafe media member path")
    for part in path.parts:
        base = part.split(".", 1)[0].upper()
        if (part.endswith((" ", ".")) or any(char in '<>:"|?*' for char in part)
                or base in {"CON", "PRN", "AUX", "NUL"}
                or re.fullmatch(r"(?:COM|LPT)[1-9]", base)):
            raise PreparationError("Media member cannot be copied faithfully to FAT32")
    return path.as_posix()


def iso_names(iso: Path, kind: str = "f") -> list[str]:
    names = []
    for line in command(["xorriso", "-indev", str(iso), "-find", "/", "-type", kind]).splitlines():
        words = shlex.split(line)
        if len(words) != 1 or not words[0].startswith("/"):
            raise PreparationError("Unreadable ISO inventory")
        name = words[0].removeprefix("/")
        if name:
            names.append(safe_name(name))
    return names


def public_names(names: list[str]) -> None:
    seen = set()
    for name in names:
        upper = name.upper()
        if upper in seen:
            raise PreparationError("FAT32 would collapse distinct ISO member names")
        seen.add(upper)
        path = PurePosixPath(upper)
        if ("WIN98" in path.parts or "OWNMEDIA" in path.parts or path.suffix in
                {".CAB", ".QCOW2", ".VMDK", ".VDI", ".KEY"}
                or path.name in {"IO.SYS", "MSDOS.SYS", "WIN.COM", "VMM32.VXD", "SETUPX.DLL",
                                  "STEAM.EXE", "CHROME.EXE", "FIREFOX.EXE", "LEGCORD.EXE",
                                  "SOFFICE.EXE", "SOFFICE.BIN", MANIFEST, "USB-README.TXT"}):
            raise PreparationError("Public ISO contains private or reserved members")


def windows_iso(path: Path) -> tuple[Path, dict]:
    path = input_file(path, fat32=True)
    with path.open("rb") as stream:
        stream.seek(16 * 2048)
        header = stream.read(7)
    if header != b"\x01CD001\x01":
        raise PreparationError("Owner-supplied Windows media is not an ISO9660 image")
    names = {name.upper() for name in iso_names(path)}
    if (not ({"WIN98/SETUP.EXE", "SETUP.EXE"} & names)
            or not any(name.startswith("WIN98/") and name.endswith(".CAB") for name in names)):
        raise PreparationError("Owner ISO must contain Windows 98 SETUP.EXE and WIN98 cabinets")
    return path, file_record(path)


def fresh_output(path: Path, private: bool) -> Path:
    path = path.expanduser().absolute()
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise PreparationError("Output must be new and its parent directory must already exist")
    path = path.parent.resolve(strict=True) / path.name
    if private:
        for parent in (path.parent, *path.parent.parents):
            if (parent / ".git").exists():
                repository = subprocess.run(["git", "-C", str(parent), "rev-parse", "--show-toplevel"],
                                            capture_output=True, text=True)
                if repository.returncode != 0:
                    continue  # An empty/uninitialized .git directory is not a checkout.
                result = subprocess.run(["git", "-C", str(parent), "check-ignore", "-q", str(path)],
                                        capture_output=True)
                if result.returncode != 0:
                    raise PreparationError("Private output inside a Git checkout must be git-ignored")
                break
    return path


def reserve(parent: Path, budget: int) -> None:
    if shutil.disk_usage(parent).free < RESERVE + budget:
        raise PreparationError("17 GiB free reserve plus the preparation budget is unavailable")


def tree_records(root: Path) -> dict:
    result = {}
    folded = set()
    for path in sorted(root.rglob("*")):
        name = safe_name(path.relative_to(root).as_posix())
        mode = path.lstat().st_mode
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            raise PreparationError("Extracted tree contains a link or special file")
        if name.upper() in folded:
            raise PreparationError("Extracted tree has a FAT32 name collision")
        folded.add(name.upper())
        if stat.S_ISREG(mode):
            if path.stat().st_size > FAT32_MAX:
                raise PreparationError("Extracted file exceeds the FAT32 individual file limit")
            result[name] = file_record(path)
    return result


def assert_same(record: dict, expected: dict, what: str) -> None:
    if record != {"bytes": expected.get("bytes"), "sha256": expected.get("sha256")}:
        raise PreparationError(f"{what} bytes differ from their exact receipt")


def installer_boot_policy(proof, bios, efi):
    """Read actual policies independently of producer helpers or receipt claims."""
    if (proof.get('boot_profile') != 'installer' or proof.get('boot_mode') != 'install'
            or proof.get('installed_system_profile') not in ('desktop', 'self-test')):
        raise PreparationError('Installer media receipt and independent installed system profile required')
    lines = [' '.join(line.split()) for line in bios.decode('ascii').splitlines()
             if line.strip() and not line.lstrip().startswith('#')]
    expected = ['SERIAL 0 115200', 'DEFAULT setup', 'PROMPT 0', 'NOESCAPE 1',
                'LABEL setup', 'KERNEL mboot.c32',
                'APPEND /SHZ/K64/BOOT.ELF shz.setup=interactive shz.noapps --- '
                '/SHZ/K64/KERNEL64S.BIN --- /SHZ/SETUP/INSTALL.IMG']
    if lines != expected:
        raise PreparationError('BIOS must directly enter its single interactive installer label without a menu')
    values = {}
    for line in efi.decode('ascii').splitlines():
        line = line.strip()
        if not line or line.startswith(('#', ';', '[')):
            continue
        if '=' not in line:
            raise PreparationError('Malformed EFI boot policy')
        key, value = (part.strip() for part in line.split('=', 1))
        key = key.lower()
        if key in values:
            raise PreparationError('Duplicate EFI policy key')
        values[key] = value
    if values.get('mode') != 'install' or values.get('menu_timeout') != '0':
        raise PreparationError('UEFI must enter install with menu_timeout=0')
    return {'bios_single_interactive_installer': True, 'uefi_mode': 'install', 'menu_timeout': 0}


def stage(args: argparse.Namespace) -> dict:
    iso, receipt = input_file(args.iso), input_file(args.receipt)
    proof, receipt_before, receipt_stamp = read_receipt(receipt)
    if (proof.get("private") is not False or proof.get("boot_profile") != "installer"
            or proof.get("boot_mode") != "install" or proof.get("setup", {}).get("present") is not True
            or proof.get("git", {}).get("dirty") is not False
            or not re.fullmatch(r"[0-9a-f]{40}", str(proof.get("git", {}).get("revision", "")))):
        raise PreparationError("Clean-source public installer ISO and installer receipt required")
    iso_before = stamp(iso)
    iso_record = file_record(iso)
    assert_same(iso_record, proof, "Public ISO")
    windows, windows_record = windows_iso(args.win98_iso) if args.win98_iso else (None, None)
    windows_before = stamp(windows) if windows else None
    out = fresh_output(args.out, private=windows is not None)
    names = iso_names(iso)
    public_names(names)
    if not PUBLIC_REQUIRED <= set(names) or iso_names(iso, "l"):
        raise PreparationError("Public ISO lacks installer/source/license members or contains links")
    efi_expected = proof.get("efi_members", {})
    if not EFI_REQUIRED <= set(efi_expected):
        raise PreparationError("Producer receipt lacks the complete EFI loader/runtime inventory")
    for name in efi_expected:
        safe_name(name)
        if not name.startswith(("EFI/", "SHZDOS/")) and name != "SHZ/SETUP/INSTALL.IMG":
            raise PreparationError("Unexpected EFI volume member")
    reserve(out.parent, 3 * iso_record["bytes"] + (windows_record["bytes"] if windows_record else 0))
    work = Path(tempfile.mkdtemp(prefix=f".{out.name}-", dir=out.parent))
    try:
        usb, efi = work / "files", work / "efi"
        efi.mkdir()
        command(["xorriso", "-osirrox", "on", "-indev", str(iso), "-extract", "/", str(usb)])
        public = tree_records(usb)
        if set(public) != set(names):
            raise PreparationError("ISO extraction inventory differs from its listing")
        command(["mcopy", "-s", "-i", str(usb / EFI_IMAGE), "::/*", str(efi)])
        actual_efi = tree_records(efi)
        if set(actual_efi) != set(efi_expected):
            raise PreparationError("EFI image has missing or unexpected files")
        for name, record in actual_efi.items():
            assert_same(record, efi_expected[name], f"EFI member {name}")
            target = usb / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                assert_same(file_record(target), record, f"Existing USB member {name}")
            else:
                shutil.copyfile(efi / name, target)
        if any(Path(name).name.lower() == "menu.c32" for name in names):
            raise PreparationError("Installer ISO unexpectedly carries the boot menu module")
        boot_policy = installer_boot_policy(proof, (usb / "isolinux/isolinux.cfg").read_bytes(),
                                           (usb / "EFI/SHIZUKU/BOOT.INI").read_bytes())
        if not actual_efi["SHZ/SETUP/INSTALL.IMG"]["bytes"]:
            raise PreparationError("EFI installer archive must not be empty")
        if windows:
            destination = usb / "OWNMEDIA/WIN98.ISO"
            destination.parent.mkdir()
            shutil.copyfile(windows, destination)
            assert_same(file_record(destination), windows_record, "Copied owner Windows ISO")
        (usb / "USB-README.TXT").write_text(
            "ShizukuDOS for Windows 98: DOS replacement + Kernel32 + Kernel64 + compatibility components.\n"
            "That is the integration target; this file preparation does not prove it is complete.\n"
            "Copy these files to the ROOT of a FAT32 USB partition.\n"
            "EFI/BOOT/BOOTX64.EFI and SHZDOS must remain at their exact paths.\n"
            "File-copy preparation targets the interactive UEFI installer immediately. BIOS boot sectors are not installed.\n"
            "For BIOS, write the official hybrid ISO as an image using a tool you normally use.\n"
            "Place your own Windows 98 ISO at OWNMEDIA/WIN98.ISO; the folder then becomes PRIVATE.\n"
            "A copied Windows ISO is preserved media. It is not a bootable nested ISO or verified Setup.\n"
            "Windows 98 Setup, native Win98 integration, and all modern apps are not proved by this bundle.\n"
            "Read INSTALL_USB.md for the explicit private combined ISO producer and actual limitations.\n",
            encoding="ascii")
        result = {
            "schema": "win98-modern-usb-copy-v1", "private": windows is not None,
            "public_iso": iso_record, "producer_receipt": receipt_before,
            "source_commit": proof["git"]["revision"], "boot_profile": "installer",
            "installed_system_profile": proof["installed_system_profile"], "boot_policy": boot_policy,
            "architecture_target": "ShizukuDOS replaces MS-DOS for Windows 98; Kernel32 and Kernel64 are its components",
            "efi_members_verified": len(actual_efi), "owner_windows_iso": windows_record,
            "claims": CLAIMS, "files": tree_records(usb),
        }
        if (stamp(iso) != iso_before or file_record(iso) != iso_record
                or stamp(receipt) != receipt_stamp or file_record(receipt) != receipt_before
                or (windows and (stamp(windows) != windows_before or file_record(windows) != windows_record))):
            raise PreparationError("A source input changed during preparation")
        (usb / MANIFEST).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        usb.rename(out)
        return result
    finally:
        shutil.rmtree(work)


def verify(args: argparse.Namespace) -> dict:
    root = args.root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise PreparationError("USB root must be a directory")
    manifest = input_file(root / MANIFEST)
    proof = json.loads(manifest.read_text(encoding="utf-8"))
    if proof.get("schema") != "win98-modern-usb-copy-v1":
        raise PreparationError("Unsupported USB manifest")
    actual = tree_records(root)
    actual.pop(MANIFEST)
    expected = proof["files"]
    for name, record in expected.items():
        safe_name(name)
        if actual.get(name) != record:
            raise PreparationError("USB file content differs from the prepared manifest")
    extra = set(actual) - set(expected)
    if extra - {"OWNMEDIA/WIN98.ISO"}:
        raise PreparationError("Unexpected USB files outside the prepared manifest")
    owner = root / "OWNMEDIA/WIN98.ISO"
    windows_record = None
    if args.with_win98 or owner.exists():
        _, windows_record = windows_iso(owner)
    return {"schema": "win98-modern-usb-readback-v1", "private": windows_record is not None,
            "files_verified": len(expected), "owner_windows_iso": windows_record, "claims": CLAIMS}


def combine(args: argparse.Namespace) -> dict:
    windows, windows_record = windows_iso(args.win98_iso)
    before = stamp(windows)
    source = args.source_root.expanduser().resolve(strict=True)
    builder = input_file(source / "tools/build_shizuku_se_iso.py")
    help_text = command([sys.executable, str(builder), "--help"])
    if "--desktop" not in help_text or "--win98-media" not in help_text:
        raise PreparationError("Supplied checkout lacks the existing desktop/private media producer")
    out = fresh_output(args.out, private=True)
    if (out.suffix.lower() != ".iso" or out.with_suffix(".json").exists()
            or out.with_suffix(".txt").exists() or out.with_suffix(".combination.json").exists()):
        raise PreparationError("Private output requires a new .iso and fresh adjacent receipt/summary paths")
    reserve(out.parent, 5 * windows_record["bytes"] + (512 << 20))
    argv = [sys.executable, str(builder), "--desktop", "--win98-media", str(windows), "--output", str(out)]
    if args.reuse_builds:
        argv.append("--reuse-builds")
    # This is deliberately the only command that builds software. Its source checkout and
    # writable build/ workspace were explicitly selected by the `combine` caller.
    subprocess.run(argv, check=True, cwd=source)
    receipt = input_file(out.with_suffix(".json"))
    proof, receipt_record, receipt_stamp = read_receipt(receipt)
    record = file_record(input_file(out))
    if proof.get("private") is not True:
        raise PreparationError("Combined output did not carry the producer's private marker")
    assert_same(record, proof, "Private combined ISO")
    if stamp(windows) != before or file_record(windows) != windows_record:
        raise PreparationError("Owner Windows ISO changed during the private build")
    result = {"schema": "win98-modern-private-combination-v1", "private": True,
              "owner_windows_iso": windows_record, "combined_iso": record,
              "producer_receipt": receipt_record, "source_commit": proof.get("git", {}).get("revision"),
              "claims": CLAIMS}
    if stamp(receipt) != receipt_stamp or file_record(receipt) != receipt_record:
        raise PreparationError("Producer receipt changed during private combination")
    result_path = out.with_suffix(".combination.json")
    with result_path.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(result, indent=2) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    stage_parser = sub.add_parser("stage", help="extract an exact public ISO into a new USB-copy directory")
    stage_parser.add_argument("--iso", type=Path, required=True)
    stage_parser.add_argument("--receipt", type=Path, required=True)
    stage_parser.add_argument("--out", type=Path, required=True)
    stage_parser.add_argument("--win98-iso", type=Path)
    verify_parser = sub.add_parser("verify", help="read-only whole-file USB readback, including a user-added ISO")
    verify_parser.add_argument("--root", type=Path, required=True)
    verify_parser.add_argument("--with-win98", action="store_true")
    combine_parser = sub.add_parser("combine", help="explicitly run the existing private hybrid ISO producer")
    combine_parser.add_argument("--source-root", type=Path, required=True)
    combine_parser.add_argument("--win98-iso", type=Path, required=True)
    combine_parser.add_argument("--out", type=Path, required=True)
    combine_parser.add_argument("--reuse-builds", action="store_true")
    args = parser.parse_args()
    try:
        result = {"stage": stage, "verify": verify, "combine": combine}[args.operation](args)
    except (PreparationError, OSError, KeyError, TypeError, json.JSONDecodeError,
            subprocess.CalledProcessError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
