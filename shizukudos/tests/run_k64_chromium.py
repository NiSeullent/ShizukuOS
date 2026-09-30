#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the 64-bit Chromium browser (chrome.exe) inside the standalone Kernel64 guest and report how far it got.

Profile: the standalone profile of run_k64_standalone.py (QEMU -kernel stub, no Supervisor, TCG or KVM) with the
Chromium chrome-win tree (read-only on the host) copied into a FAT32 image outside the repository and attached on AHCI,
mounted by Kernel64 as D:\\ (D:\\chrome-win\\chrome.exe). The kernel command line `shz.noapps shz.autorun=D:\\K64RUN.TXT`
skips the T_*.EXE self-checking programs and starts the program the control file names after the self-tests
(kernel64/autorun.c). The disk is attached with snapshot=on: what Chromium writes (profile, crash database) is thrown
away when QEMU exits, the image stays reusable.

Display: even with --headless, Chromium registers window classes and creates message-only windows (base::win::
MessageWindow) and stops ("Your computer has run out of resources") when that fails. Kernel64's window manager
(kernel64/gfx_wm.c) exists only when the machine has a display device, so by default the VM gets a Bochs VBE adapter
(`-vga std`, as run_k64_gui.py --display vga) that nobody looks at (`-display none`). --display none runs without it.

Default command (ELECTRON_TARGET.md milestone M2):
    chrome.exe --headless --no-sandbox --disable-gpu --single-process --dump-dom file:///D:/M2/M2.HTML
The fixture page contains a script, so the expected DOM line `<p id="m">ShizukuDOS M2 probe 42</p>` only exists if V8
ran it. The run PASSES only when the serial log contains that line AND chrome.exe exited with code 0 AND no process
fault was reported. Anything else is a FAIL, and the result names the furthest point reached, in this order of
precedence: loader failure (an import that did not resolve), a fatal exception (process killed by the kernel), a
Chromium FATAL/CHECK line, the first kernel32 function that failed explicitly because a feature is not implemented
("K32 unsupported: ..."), the exit code, or the timeout. Chromium's own log lines (--enable-logging=stderr) are copied
into the result as evidence.

The result is written to <out>/result.json and printed. Exit status 0 = PASS, 1 = FAIL (the expected state until M2
is reached), 2 = the run could not be performed (missing inputs).
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, run  # noqa: E402
import run_k64_disk as disk  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
DEFAULT_TREE = disk.SCRATCH / "chromium-full" / "chrome-win"
M2_PAGE = (b"<!doctype html><html><head><title>shz-m2</title></head><body><p id=\"m\">ShizukuDOS M2 probe</p><script>"
           b"document.getElementById('m').textContent += ' ' + (6*7);</script></body></html>")
M2_EXPECT = '<p id="m">ShizukuDOS M2 probe 42</p>'
DEFAULT_ARGS = ("--headless --no-sandbox --disable-gpu --single-process --no-first-run --enable-logging=stderr --v=0 "
                "--user-data-dir=D:\\prof --dump-dom file:///D:/M2/M2.HTML")


def put_file(image, data, name, work):
    """Copies bytes into the FAT32 image as ::name (overwriting), with mtools."""
    host = work / ("put_" + name.replace("/", "_"))
    host.write_bytes(data)
    parts = name.split("/")
    for i in range(1, len(parts)):
        subprocess.run(["mmd", "-D", "s", "-i", str(image), "::" + "/".join(parts[:i])], env=disk.mtools_env(),
                       capture_output=True)
    run(["mcopy", "-o", "-i", str(image), str(host), "::" + name], env=disk.mtools_env(), capture=True)


def classify(serial):
    """Furthest point reached, from the serial log after the autorun start (see the module docstring for the precedence).
    A runtime LoadLibrary that fails ("K64 ldr: X not loaded: LoadLibrary needs ...") is reported separately: programs
    probe for optional DLLs and continue without them, so it is not a failure by itself."""
    all_lines = serial.splitlines()
    start = next((i for i, l in enumerate(all_lines) if l.startswith("K64 autorun: starting")), len(all_lines))
    lines = all_lines[start:]
    res = {}
    ldr_all = [l for l in lines if re.search(r"K64 ldr: .*(not loaded|imports|rejected|failed|cannot|lacks)", l)]
    runtime_misses = [l for l in ldr_all if ": LoadLibrary needs " in l]
    ldr = [l for l in ldr_all if l not in runtime_misses]
    res["runtime_loadlibrary_misses"] = sorted(set(runtime_misses))[:40]
    killed = [l for l in lines if re.search(r"K64: process .* killed|K64 EXCEPTION|unhandled exception", l)]
    fatal = [l for l in lines if re.search(r"FATAL:|Check failed|CHECK failed|NOTREACHED", l)]
    unsup = [l for l in lines if "K32 unsupported:" in l or "K32 RECON called:" in l]
    auto = [l for l in lines if l.startswith("K64 autorun: result")]
    res["loader_failures"] = ldr[:20]
    res["exceptions"] = killed[:20]
    res["chromium_fatal"] = fatal[:20]
    res["unsupported_calls"] = unsup[:60]
    res["autorun_result"] = auto[-1] if auto else None
    m = re.search(r"K64 autorun: result (\w[\w-]*) exit=([0-9a-f]+) faulted=(\d)", auto[-1]) if auto else None
    res["exit_code"] = int(m.group(2), 16) if m else None
    res["faulted"] = bool(int(m.group(3))) if m else None
    res["ended_by"] = m.group(1) if m else None
    if ldr:
        res["furthest"] = "loader: " + ldr[0]
    elif killed:
        res["furthest"] = "exception: " + killed[0]
    elif fatal:
        res["furthest"] = "chromium fatal: " + fatal[0]
    elif unsup:
        res["furthest"] = "first unsupported kernel32 call: " + unsup[0]
    elif m:
        res["furthest"] = f"process {m.group(1)} with exit code {int(m.group(2), 16):#x}"
    else:
        res["furthest"] = "no autorun result line (guest did not finish)"
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--memory", default="3072")
    ap.add_argument("--display", choices=("vga", "none"), default="vga",
                    help="vga: a Bochs VBE adapter so the Win32 window manager is active (default); none: no display device")
    ap.add_argument("--timeout", type=int, default=1800, help="host-side QEMU timeout (s)")
    ap.add_argument("--guest-timeout", type=int, default=1200, help="seconds the guest lets chrome.exe run")
    ap.add_argument("--chromium", default=str(DEFAULT_TREE), help="chrome-win tree (read-only)")
    ap.add_argument("--chromium-image", default=str(disk.SCRATCH / "k64-chromium-fat32.img"))
    ap.add_argument("--args", default=DEFAULT_ARGS, help="chrome.exe arguments")
    ap.add_argument("--expect", default=M2_EXPECT, help="line that must appear in the output for a PASS")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_chromium"))
    ap.add_argument("--no-trace", action="store_true",
                    help="do not pass shz.k32trace and shz.exctrace (kernel32 explicit-failure and GetProcAddress-miss lines, first-chance hardware exceptions)")
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            print(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
            return 2
    tree = Path(args.chromium)
    if not (tree / "chrome.exe").exists():
        print(f"no Chromium tree at {tree} (chrome.exe missing)")
        return 2
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            print(f"required tool missing: {tool}")
            return 2
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    image = Path(args.chromium_image)
    image.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    listing = disk.build_chromium_image(tree, image)
    control = (f"image=D:\\chrome-win\\chrome.exe\r\ncmdline=chrome.exe {args.args}\r\ncwd=D:\\chrome-win\r\n"
               f"timeout={args.guest_timeout}\r\n").encode()
    put_file(image, control, "K64RUN.TXT", out)
    put_file(image, M2_PAGE, "M2/M2.HTML", out)
    image_s = round(time.time() - t0, 1)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           *(["-vga", "std"] if args.display == "vga" else []),
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-append", "shz.noapps shz.autorun=D:\\K64RUN.TXT" + ("" if args.no_trace else " shz.k32trace shz.exctrace"),
           "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
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
    seconds = round(time.time() - started, 1)
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    res = classify(serial)
    chrome_lines = [l for l in serial.splitlines() if re.match(r"\[(win64|user) chrome\.exe pid \d+\]", l)]
    expect_seen = args.expect in serial
    ok = expect_seen and res["exit_code"] == 0 and not res["faulted"] and not res["exceptions"] and not timed_out
    record = {
        "profile": "kernel64-standalone + Chromium chrome-win on AHCI FAT32 (D:), autorun", "accel": accel,
        "status": "PASS" if ok else "FAIL", "expected_line": args.expect, "expected_line_seen": expect_seen,
        "qemu_timed_out": timed_out, "seconds": seconds, "image_prepare_s": image_s,
        "image": str(image), "tree_files": len(listing), "command": cmd, "chrome_args": args.args,
        **res,
        "chrome_output_lines": chrome_lines[:400], "chrome_output_line_count": len(chrome_lines),
        "serial_tail": serial[-6000:], "qemu_output": qemu_out[-1500:], "utc": shzlib.utc_now(), "git": shzlib.git_state(),
    }
    shzlib.write_json(out / "result.json", record)
    print(f"  status: {record['status']} ({seconds} s, accel={accel})")
    print(f"  furthest point: {res['furthest']}")
    print(f"  autorun: {res['autorun_result']}")
    print(f"  expected line seen: {expect_seen}")
    for k in ("loader_failures", "exceptions", "chromium_fatal", "unsupported_calls"):
        for l in res[k][:8]:
            print(f"  [{k}] {l}")
    print(f"  chrome.exe output lines: {len(chrome_lines)} (first 20 below; all in result.json)")
    for l in chrome_lines[:20]:
        print("    " + l[:300])
    print(f"  result: {out / 'result.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
