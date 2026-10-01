#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run T_TRIDENT_ENGINE.EXE (shizukudos/win64/tests/t_trident_engine.c) against a freshly built shzlite.dll inside the
standalone Kernel64 guest WITHOUT the full Win64 build and without touching build/shizukudos/win64:

 1. build shzlite.dll (build_engine.build) and T_TRIDENT_ENGINE.EXE (compiled exactly like win64/build.py build_apps:
    its COMMON flags, crt/shzcrt.c, entry ShzStart, every Shizuku module import library) into --out;
 2. copy build/shizukudos/win64/WIN64.IMG (SHZARC01) and add \\SHZ\\SYS64\\shzlite.dll,
    \\SHZ\\TESTS\\T_TRIDENT_ENGINE.EXE and every tests/data/TRIDENT*.* file (the other entries are kept);
 3. boot it with run_k64_standalone.py's QEMU command (no display) with the serial log in --out;
 4. print the test's lines from the serial log.

Exit status 0 when the kernel reports "T_TRIDENT_ENGINE.EXE exit=0 faulted=0" and the test printed no FAIL line.
Needs build/shizukudos/win64/WIN64.IMG + import libraries and build/shizukudos/kernel64s/{boot.elf,KERNEL64S.BIN}.
"""
import argparse
import importlib.util
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ENGINE = HERE.parent
REPO = ENGINE.parents[3]
SHZ = REPO / "shizukudos"
W64 = SHZ / "win64"
BUILD = REPO / "build" / "shizukudos"
K64S = BUILD / "kernel64s"
TEST_SRC = W64 / "tests" / "t_trident_engine.c"
DATA = W64 / "tests" / "data"


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def unpack_archive(blob):
    """SHZARC01 (see win64/build.py pack_archive): list of (path, bytes)."""
    if blob[:8] != b"SHZARC01":
        raise SystemExit("not a SHZARC01 archive")
    count, _ = struct.unpack_from("<II", blob, 8)
    files = []
    for i in range(count):
        base = 16 + 136 * i
        raw = blob[base:base + 120].split(b"\0", 1)[0]
        off, size = struct.unpack_from("<QQ", blob, base + 120)
        files.append((raw.decode("ascii"), blob[off:off + size]))
    return files


def build_test_exe(winbuild, out):
    """Compile t_trident_engine.c the way win64/build.py build_apps does."""
    modules = sorted(name for name, _d, _cfg in winbuild.discover_modules())
    exe = out / "t_trident_engine.exe"
    crt = W64 / "crt"
    cmd = [winbuild.CC, *winbuild.COMMON, "-nostdlib", "-Wl,--entry,ShzStart", "-Wl,--subsystem,console",
           "-Wl,--kill-at", "-Wl,--image-base,0x140000000", "-I", W64 / "include", "-I", crt, TEST_SRC,
           crt / "shzcrt.c", "-L", BUILD / "win64", *[f"-l{m}" for m in modules], "-lkernel32", "-lntdll", "-lgcc",
           "-o", exe]
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"t_trident_engine.c failed to build:\n{r.stdout}{r.stderr}")
    return exe


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(BUILD / "trident-engine" / "guest"))
    ap.add_argument("--timeout", type=int, default=420)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--memory", default="256")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for f in (K64S / "boot.elf", K64S / "KERNEL64S.BIN", BUILD / "win64" / "WIN64.IMG"):
        if not f.exists():
            print(f"missing {f}: build the kernel and the Win64 runtime first")
            return 2

    sys.path.insert(0, str(SHZ / "tools"))
    engine = load_module("build_engine", ENGINE / "build_engine.py")
    winbuild = load_module("win64_build", W64 / "build.py")
    qemu = load_module("qemu", SHZ / "tools" / "qemu.py")

    res = engine.build(out / "dll")
    exe = build_test_exe(winbuild, out)
    files = [f for f in unpack_archive((BUILD / "win64" / "WIN64.IMG").read_bytes())]
    add = {"\\SHZ\\SYS64\\shzlite.dll": res["dll"].read_bytes(),
           "\\SHZ\\TESTS\\T_TRIDENT_ENGINE.EXE": exe.read_bytes()}
    for f in sorted(DATA.glob("TRIDENT*")):
        add[f"\\SHZ\\TESTS\\{f.name.upper()}"] = f.read_bytes()
    files = [(p, d) for p, d in files if p not in add] + sorted(add.items())
    img = out / "WIN64.IMG"
    img.write_bytes(winbuild.pack_archive(files))
    print(f"image: {img} ({len(files)} entries, added {', '.join(sorted(add))})")

    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    serial = out / "serial.log"
    serial.unlink(missing_ok=True)
    cmd = [qemu.DEFAULT_QEMU, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults",
           "-display", "none", "-kernel", str(K64S / "boot.elf"), "-initrd", f"{K64S / 'KERNEL64S.BIN'},{img}",
           "-serial", f"file:{serial}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        print(f"QEMU timeout after {args.timeout}s")
    log = serial.read_text(errors="replace") if serial.exists() else ""
    lines = [l for l in log.splitlines() if "T_TRIDENT_ENGINE" in l]
    for l in lines:
        print(l)
    exit_line = re.search(r"K64 win64 app: T_TRIDENT_ENGINE\.EXE exit=(\d+) faulted=(\d+)", log)
    fails = [l for l in lines if "] FAIL:" in l]
    ok = bool(exit_line) and exit_line.group(1) == "0" and exit_line.group(2) == "0" and not fails
    print(f"guest run ({accel}, {time.time() - started:.0f}s): {'PASS' if ok else 'FAIL'}; serial log {serial}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
