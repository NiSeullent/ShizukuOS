# SPDX-License-Identifier: GPL-2.0-only
"""Shared helpers for the W3 WebKit guest runs (deps checks, T_WK_RENDER, the interactive and network milestones).

Profile: standalone Kernel64 under QEMU (the run_k64_chromium.py profile): `-kernel` Multiboot stub, KERNEL64S.BIN and
WIN64.IMG as initrd, `shz.noapps shz.autorun=D:\\K64RUN.TXT`, and a FAT32 image on AHCI mounted as D:. The image holds
one directory D:\\WK with the programs, the DLLs they need beside them, and WKRUN.TXT; the autorun program is WKRUN.EXE,
which starts every listed program in turn and prints one `WKRUN-RESULT` line per program. Static import checks before a
guest run use W1's webkit/importcheck.py.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parents[3]
sys.path.insert(0, str(SHZ / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, run  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
FIXED_EPOCH = 1785283200          # tools/fatimg.py convention


def mtools_env():
    env = dict(os.environ)
    env.update({"MTOOLS_SKIP_CHECK": "1", "TZ": "UTC", "SOURCE_DATE_EPOCH": str(FIXED_EPOCH)})
    return env


def make_image(image, files, wkrun_txt, extra_mib=64):
    """FAT32 superfloppy with D:\\WK\\<files>, D:\\WK\\WKRUN.TXT and D:\\K64RUN.TXT (autorun WKRUN.EXE)."""
    image = Path(image)
    image.parent.mkdir(parents=True, exist_ok=True)
    total = sum(Path(f).stat().st_size for f in files)
    size_mib = max(64, (total * 12 // 10 >> 20) + extra_mib)
    image.unlink(missing_ok=True)
    with open(image, "wb") as fh:
        fh.truncate(size_mib << 20)
    run(["mkfs.vfat", "-F", "32", "-s", "8", "-n", "SHZWEBKIT", "--invariant", str(image)], capture=True)
    env = mtools_env()
    run(["mmd", "-i", str(image), "::WK"], env=env, capture=True)
    stage = image.parent / (image.name + ".stage")
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir()
    for f in files:
        run(["mcopy", "-o", "-m", "-i", str(image), str(f), "::WK/" + Path(f).name], env=env, capture=True)
    (stage / "WKRUN.TXT").write_bytes(wkrun_txt.encode())
    run(["mcopy", "-o", "-i", str(image), str(stage / "WKRUN.TXT"), "::WK/WKRUN.TXT"], env=env, capture=True)
    return size_mib


def autorun(image, timeout_s, program="D:\\WK\\WKRUN.EXE", cmdline=None, cwd="D:\\WK"):
    env = mtools_env()
    stage = Path(str(image) + ".stage")
    stage.mkdir(exist_ok=True)
    (stage / "K64RUN.TXT").write_bytes((f"image={program}\r\ncmdline={cmdline or Path(program.replace(chr(92), '/')).name}"
                                        f"\r\ncwd={cwd}\r\ntimeout={timeout_s}\r\n").encode())
    run(["mcopy", "-o", "-i", str(image), str(stage / "K64RUN.TXT"), "::K64RUN.TXT"], env=env, capture=True)


def run_qemu(image, serial_path, memory="1024", timeout=3600, display="none", extra=(), qemu_bin=None, trace=True,
             monitor=None, snapshot=True):
    """Boots standalone Kernel64 with the image as D: (snapshot=False keeps what the guest writes, for get_file()).
    Returns (seconds, timed_out, qemu_output, command, accel)."""
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/win64/build.py and shizukudos/kbuild.py first")
    accel = "kvm" if Path("/dev/kvm").exists() else "tcg"
    serial_path = Path(serial_path)
    serial_path.unlink(missing_ok=True)
    cmd = [qemu_bin or qemu.DEFAULT_QEMU, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", str(memory),
           "-nodefaults", "-display", "none", *(["-vga", "std"] if display == "vga" else []),
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-append", "shz.noapps shz.autorun=D:\\K64RUN.TXT" + (" shz.k32trace shz.exctrace" if trace else ""),
           "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw{',snapshot=on' if snapshot else ''}",
           "-device", "ide-hd,drive=d0,bus=ahci0.0", *(["-qmp", f"unix:{monitor},server,nowait"] if monitor else []),
           *extra]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    return round(time.time() - started, 1), timed_out, out, [str(c) for c in cmd], accel


def get_file(image, name, dest):
    """Copies ::<name> (e.g. "WK/r1.bmp") out of the FAT32 image; returns dest, or None when the guest did not write it."""
    r = subprocess.run(["mcopy", "-o", "-i", str(image), "::" + name, str(dest)], env=mtools_env(), capture_output=True)
    return Path(dest) if r.returncode == 0 and Path(dest).exists() else None


def parse_serial(serial):
    """WKRUN-RESULT lines, program output lines and loader/exception diagnostics from the serial log."""
    res = {"results": {}, "lines": [], "loader": [], "exceptions": [], "unsupported": []}
    for m in re.finditer(r"WKRUN-RESULT (\S+) exit=(-?\d+) ms=(\d+)", serial):
        res["results"][m.group(1)] = {"exit": int(m.group(2)), "ms": int(m.group(3))}
    m = re.search(r"WKRUN-DONE pass=(\d+) fail=(\d+)", serial)
    res["done"] = {"pass": int(m.group(1)), "fail": int(m.group(2))} if m else None
    for l in serial.splitlines():
        if re.match(r"\[(win64|user) \S+ pid \d+\]", l):
            res["lines"].append(l)
        if re.search(r"K64 ldr: .*(not loaded|rejected|failed|cannot|lacks|needs)", l):
            res["loader"].append(l)
        if re.search(r"K64: process .* killed|K64 EXCEPTION|unhandled exception", l):
            res["exceptions"].append(l)
        if "K32 unsupported:" in l or "K32 RECON called:" in l:
            res["unsupported"].append(l)
    m = re.findall(r"K64 autorun: result (\w[\w-]*) exit=([0-9a-f]+) faulted=(\d)", serial)
    res["autorun"] = {"ended_by": m[-1][0], "exit": int(m[-1][1], 16), "faulted": m[-1][2] == "1"} if m else None
    return res
