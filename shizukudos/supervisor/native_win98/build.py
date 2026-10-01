#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a private opt-in installed-Win98 Supervisor ESP, without running a VM.

Every disk/ROM/config/kernel input is explicit and SHA-pinned. This starts the
disk's existing DOS: ShizukuDOS DOS-to-VMM replacement remains incomplete.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
DISK_BYTES = 2 << 30
ROM_BYTES = 256 << 10
ESP_MIB = 2304
RESERVE = 17 << 30
CONFIG = (0x38395753, 1, 128, 0)


def safe_path(path):
    raw = Path(path).expanduser().absolute()
    if any(part.is_symlink() for part in (raw, *raw.parents)):
        raise ValueError("symlink input/output or parent is refused")
    resolved = raw.resolve()
    if any(resolved == base or base in resolved.parents for base in map(Path, ("/dev", "/proc", "/sys"))):
        raise ValueError("device and virtual filesystem paths are refused")
    return resolved


def fresh_output(path):
    path = safe_path(path)
    if path.exists() or not path.parent.is_dir():
        raise ValueError("a new owned output directory with an existing parent is required")
    if ROOT in path.parents:
        relative = path.relative_to(ROOT)
        if relative.parts[0] != "build":
            raise ValueError("private outputs inside the source tree must be under ignored build/")
        if (ROOT / ".git").exists():
            check = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "--no-index", str(path)],
                                   capture_output=True, timeout=10)
            if check.returncode:
                raise ValueError("private output is not git-ignored")
    return path


def stable(value):
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def pin_format(expected):
    expected = expected.lower()
    if not re.fullmatch("[0-9a-f]{64}", expected):
        raise ValueError("an exact SHA-256 identity pin is required")
    return expected


def pinned_hash(path, expected, size=None, maximum=DISK_BYTES):
    path, expected = safe_path(path), pin_format(expected)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum or (size is not None and before.st_size != size):
            raise ValueError("nonempty regular file with the required bounded geometry is required")
        digest = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            digest.update(block)
        if stable(before) != stable(os.fstat(fd)) or stable(before) != stable(path.stat()) or digest.hexdigest() != expected:
            raise ValueError("input SHA/identity changed or differs")
        return before.st_size
    finally:
        os.close(fd)


def file_sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


@contextlib.contextmanager
def read_leased(path, expected, size, maximum=DISK_BYTES):
    """An actual Linux read lease blocks writers; a break request fails the run."""
    path, expected = safe_path(path), pin_format(expected)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    previous, broken, leased = signal.getsignal(signal.SIGIO), [False], False
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < size <= maximum or before.st_size != size:
            raise ValueError("leased regular input geometry mismatch")
        signal.signal(signal.SIGIO, lambda *_: broken.__setitem__(0, True))
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid())
        fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        leased = True

        def checkpoint():
            if broken[0] or stable(before) != stable(os.fstat(fd)) or stable(before) != stable(path.stat()) or fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_RDLCK:
                raise RuntimeError("source read lease or identity changed")

        checkpoint()
        digest = hashlib.sha256()
        while block := os.read(fd, 1 << 20):
            checkpoint()
            digest.update(block)
        checkpoint()
        if digest.hexdigest() != expected:
            raise ValueError("leased source SHA mismatch")
        os.lseek(fd, 0, os.SEEK_SET)
        yield fd, checkpoint
        checkpoint()
    finally:
        try:
            if leased:
                fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        finally:
            os.close(fd)
            signal.signal(signal.SIGIO, previous)


def space(path, remaining=0):
    if shutil.disk_usage(Path(path).parent).free < RESERVE + remaining:
        raise RuntimeError("17 GiB retained free space plus the remaining preparation budget is required")


def copy_fd(fd, checkpoint, destination, expected, size, maximum=DISK_BYTES):
    destination = safe_path(destination)
    digest, written = hashlib.sha256(), 0
    with destination.open("xb") as stream:
        while block := os.read(fd, 1 << 20):
            checkpoint()  # Check after read and before any owned data write.
            space(destination, len(block))
            if stream.write(block) != len(block):
                raise OSError("partial owned input write")
            digest.update(block)
            written += len(block)
        stream.flush()
        os.fsync(stream.fileno())
    checkpoint()
    if written != size or digest.hexdigest() != pin_format(expected):
        raise ValueError("owned copy SHA/extent mismatch")
    pinned_hash(destination, expected, size, maximum=maximum)


def config_bytes():
    return struct.pack("<4I", *CONFIG)


def validate_config(data):
    if data != config_bytes():
        raise ValueError("WIN98CFG.BIN must be exact version 1 / 128 MiB / reserved-zero config")


def validate_contents(name, fd):
    """Inspect the same pinned, read-leased descriptor that supplies the copy.

    MBR/ROM checks identify a supported container, not an installed Windows OS.
    """
    os.lseek(fd, 0, os.SEEK_SET)
    if name == "WIN98CFG.BIN":
        validate_config(os.read(fd, 17))
    elif name == "SEABIOS.BIN":
        rom = os.read(fd, ROM_BYTES + 1)
        if len(rom) != ROM_BYTES or rom[-16] not in (0xEA, 0xE9) or b"SeaBIOS" not in rom:
            raise ValueError("the pinned ROM lacks the supported x86 reset jump or SeaBIOS identifier")
    elif name == "DISK.IMG":
        mbr = os.read(fd, 512)
        if len(mbr) != 512 or mbr[-2:] != b"\x55\xaa":
            raise ValueError("the owned disk lacks an MBR signature")
    os.lseek(fd, 0, os.SEEK_SET)


def source_files():
    files = {p for folder in ("shizukudos/supervisor", "shizukudos/abi", "shizukudos/uefi")
             for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in (".c", ".h", ".asm", ".ld", ".py")}
    files.update(ROOT / p for p in ("shizukudos/tools/shzlib.py", "shizukudos/kernel64/standalone/memholes.h"))
    return sorted(files)


def command(argv, receipt, cwd=None, timeout=120):
    argv = list(map(str, argv))
    receipt["commands"].append(argv)
    subprocess.run(argv, cwd=cwd, check=True, timeout=timeout, stdout=subprocess.DEVNULL)


def assemble(out, copies, loader, receipt):
    space(out, ESP_MIB << 20)
    esp = out / "esp-win98.img"
    with esp.open("xb") as stream:
        stream.truncate(ESP_MIB << 20)
    command(["mkfs.vfat", "-F", "32", "-n", "SHZWIN98", "-i", "53485739", esp], receipt)
    command(["mmd", "-i", esp, "::/EFI", "::/EFI/BOOT", "::/EFI/SHIZUKU", "::/SHZDOS"], receipt)
    policy = out / "BOOT.INI"
    policy.write_bytes(b"mode=supervisor\r\nmenu_timeout=0\r\n")
    members = {"EFI/BOOT/BOOTX64.EFI": loader, "EFI/SHIZUKU/BOOT.INI": policy,
               **{"SHZDOS/" + name: source for name, source in copies.items()}}
    for name, source in members.items():
        space(out, source.stat().st_size)
        command(["mcopy", "-i", esp, source, "::/" + name], receipt)
        readback = out / "readback-owned.tmp"
        space(out, source.stat().st_size)
        command(["mcopy", "-i", esp, "::/" + name, readback], receipt)
        if readback.stat().st_size != source.stat().st_size or file_sha(readback) != file_sha(source):
            raise ValueError("ESP byte readback mismatch: " + name)
        readback.unlink()  # Only this owned temporary is removed after a full successful check.
        space(out)
    return esp, {name: {"bytes": source.stat().st_size, "sha256": file_sha(source)} for name, source in members.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--make-config", type=Path, help="create a new public 16-byte opt-in config and print its SHA")
    for name in ("disk", "rom", "config", "kernel32", "kernel64", "win64-img"):
        parser.add_argument("--" + name, type=Path)
        parser.add_argument("--" + name + "-sha256")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--validate-only", action="store_true", help="check all explicit inputs without output or compilation")
    args = parser.parse_args(argv)
    if args.make_config:
        if any(getattr(args, name) for name in ("disk", "rom", "config", "kernel32", "kernel64", "win64_img", "out")):
            parser.error("--make-config is separate from private build inputs")
        path = safe_path(args.make_config)
        with path.open("xb") as stream:
            stream.write(config_bytes())
        print(json.dumps({"config": str(path), "bytes": 16, "sha256": file_sha(path)}))
        return 0
    required = ("disk", "rom", "config")
    if any(not getattr(args, name) or not getattr(args, name + "_sha256") for name in required):
        parser.error("explicit disk, ROM, config and each SHA-256 are required")
    if args.win64_img and not args.kernel64:
        parser.error("WIN64.IMG requires an explicit Kernel64 input")
    sizes = {"disk": DISK_BYTES, "rom": ROM_BYTES, "config": 16}
    targets = {"disk": "DISK.IMG", "rom": "SEABIOS.BIN", "config": "WIN98CFG.BIN",
               "kernel32": "KERNEL32.BIN", "kernel64": "KERNEL64.BIN", "win64_img": "WIN64.IMG"}
    # The current loader gives K64 64 MiB and puts its archive at 32 MiB.
    # Larger archives require an explicit RAM/layout change, not a success claim.
    maximum = {"kernel32": 8 << 20, "kernel64": 16 << 20, "win64_img": 32 << 20}
    inputs = {}
    for name, target in targets.items():
        path, pin = getattr(args, name), getattr(args, name + "_sha256")
        if bool(path) != bool(pin):
            parser.error("each optional input requires its SHA-256 pair")
        if path:
            path, pin = safe_path(path), pin_format(pin)
            size = pinned_hash(path, pin, sizes.get(name), maximum.get(name, DISK_BYTES))
            inputs[target] = {"path": path, "sha256": pin, "bytes": size}
    for name, item in inputs.items():
        with read_leased(item["path"], item["sha256"], item["bytes"]) as (fd, checkpoint):
            validate_contents(name, fd)
            checkpoint()
    if args.validate_only:
        print(json.dumps({"status": "PASS_EXPLICIT_INPUT_VALIDATION_NO_BUILD_OR_VM", "input_files": len(inputs),
                          "Windows98_installation_identity_verified": False, "Windows98_executed": False}))
        return 0
    if not args.out:
        parser.error("a new --out private directory is required for building")
    out = fresh_output(args.out)
    space(out, 7 << 30)
    out.mkdir()
    receipt = {"status": "FAIL_BUILD_PRESERVED", "private": True, "commands": [],
               "input_pins": {n: {**item, "path": str(item["path"])} for n, item in inputs.items()},
               "Windows98_installation_identity_verified": False, "VM_executed": False,
               "Windows98_boot_verified": False, "MS_DOS_replaced": False, "native_Win64_app_verified": False}
    try:
        copies = {}
        for name, item in inputs.items():
            destination = out / name
            with read_leased(item["path"], item["sha256"], item["bytes"]) as (fd, checkpoint):
                validate_contents(name, fd)
                checkpoint()
                copy_fd(fd, checkpoint, destination, item["sha256"], item["bytes"])
            copies[name] = destination
        files = source_files()
        pins = {str(p.relative_to(ROOT)): file_sha(p) for p in files}
        snapshot = out / "source"
        for source in files:
            relative = source.relative_to(ROOT)
            pinned_hash(source, pins[str(relative)], source.stat().st_size, 16 << 20)
            destination = snapshot / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            if file_sha(destination) != pins[str(relative)]:
                raise ValueError("source snapshot hash differs")
        components = out / "components"
        command([sys.executable, snapshot / "shizukudos/supervisor/native_win98/compile.py", "--out", components], receipt, timeout=300)
        compiled = json.loads((components / "result.json").read_text())
        if compiled["status"] != "PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN":
            raise ValueError("ordinary native component compilation did not complete")
        loader = components / "BOOTX64.EFI"
        if file_sha(loader) != compiled["artifacts"]["BOOTX64.EFI"]["sha256"]:
            raise ValueError("new loader does not match its compilation receipt")
        esp, members = assemble(out, copies, loader, receipt)
        if pins != {str(p.relative_to(ROOT)): file_sha(p) for p in files}:
            raise ValueError("public source changed during private preparation")
        for item in inputs.values():
            pinned_hash(item["path"], item["sha256"], item["bytes"])
        receipt.update(status="PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN", sources_sha256=pins,
                       members=members, artifact={"path": esp.name, "bytes": esp.stat().st_size, "sha256": file_sha(esp)},
                       source_before_after_match=True, originals_before_after_match=True,
                       boot_path="UEFI Supervisor -> explicit Win98 VMCS -> SeaBIOS -> owned disk's original DOS",
                       next_gate="Actual isolated L1/VMX Windows boot, VMM channel, GUI and app verification; DOS replacement remains separate")
    except BaseException as error:
        receipt["error"] = str(error)
        raise
    finally:
        (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "private_ESP": str(esp), "sha256": receipt["artifact"]["sha256"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
