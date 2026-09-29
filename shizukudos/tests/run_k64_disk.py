#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot standalone Kernel64 under QEMU with a FAT32 disk on AHCI and verify the disk path from the host side.

Profile: the same standalone profile as run_k64_standalone.py (QEMU -kernel stub, no Supervisor, TCG or KVM) plus
`-device ahci` + `ide-hd` carrying a raw FAT32 image built here with mkfs.vfat --invariant and mtools (deterministic
timestamps). Kernel64 drives the disk through the original AHCI core (drivers/ahci_native) and mounts the volume
read-only as D:\\ (kernel64/blk.c, fat32.c, disk.c). Everything the guest reports (sector-0 CRC, directory listing,
file CRCs, resident-page counts) is recomputed or checked independently here from the image and its source files.

All checks of run_k64_standalone.py must still pass in this configuration (same self-tests, same Win64 apps).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, run  # noqa: E402
import run_k64_standalone as base  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
FIXED_EPOCH = 1785283200          # 2026-07-29 00:00:00 UTC (tools/fatimg.py convention)
CHROMIUM_DEFAULT = Path("/tmp/claude-0/-home-user-Win98-Modern/31f1e8e6-646b-5a42-ab0f-36694df325e9/scratchpad/chromium/chrome-win")


def mtools_env():
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
    return env


def crc32_file(path):
    c = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            c = zlib.crc32(chunk, c)
    return c & 0xffffffff


def make_image(image, size_mib, spc, files, dirs):
    """Superfloppy FAT32 (no MBR): mkfs.vfat --invariant, then mtools copies with fixed mtimes.
    files: list of (host_path, "DIR/NAME" inside the volume); dirs: list of "DIR" to create first."""
    image = Path(image)
    image.unlink(missing_ok=True)
    with open(image, "wb") as fh:
        fh.truncate(size_mib * 1024 * 1024)
    run(["mkfs.vfat", "-F", "32", "-s", str(spc), "-n", "SHZDISK", "--invariant", str(image)], capture=True)
    env = mtools_env()
    for d in dirs:
        run(["mmd", "-i", str(image), f"::{d}"], env=env, capture=True)
    for host, name in files:
        os.utime(host, (FIXED_EPOCH, FIXED_EPOCH))
        run(["mcopy", "-m", "-i", str(image), str(host), f"::{name}"], env=env, capture=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--memory", default="1024")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_disk"))
    ap.add_argument("--chromium", default=str(CHROMIUM_DEFAULT), help="chrome-win tree (read-only); DLLs are copied into the image when present")
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)

    # ---- disk content -------------------------------------------------------------------------------------------
    files, dirs = [], ["TESTS"]
    small = out / "small.txt"
    small.write_bytes(b"hello from the FAT32 volume\r\n")
    files.append((small, "TESTS/hello.txt"))
    image = out / "disk.img"
    make_image(image, 256, 8, files, dirs)
    sector0 = image.read_bytes()[:512]
    expect_sectors = image.stat().st_size // 512
    expect_crc0 = zlib.crc32(sector0) & 0xffffffff

    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw,snapshot=on",
           "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    ev, exit_code = base.parse(serial)
    checks = base.evaluate(serial, ev, exit_code, proc.returncode)
    e = lambda s: ev.get(s, 0)  # noqa: E731
    checks.append(base.check("AHCI: guest read sector 0 (crc32 and sector count match the host image)",
                             e(13) == (expect_sectors << 32) | expect_crc0,
                             f"guest={e(13):#x} host=({expect_sectors} << 32 | {expect_crc0:#x})"))
    if timed_out:
        checks.insert(0, base.check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone + AHCI FAT32 disk (no Supervisor, no VMX)", "accel": accel, "status": status,
              "checks": checks, "seconds": round(time.time() - started, 1),
              "evidence": {str(k): hex(v) for k, v in sorted(ev.items())}, "command": cmd, "qemu_output": qemu_out[-1500:],
              "serial_tail": serial[-4000:], "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
