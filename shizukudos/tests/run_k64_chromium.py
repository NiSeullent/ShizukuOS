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
ran it. The run PASSES only when that nonempty line appears after autorun starts, chrome.exe ended by exiting with
code 0, faulted is explicitly false, no exception/fatal/loader failure or timeout occurred, and QEMU exited 0 or 1
(the normal isa-debug-exit convention). Anything else is a FAIL, and the result names the furthest point reached,
in this order of precedence: loader failure (an import that did not resolve), a fatal exception (process killed by the kernel), a
Chromium FATAL/CHECK line, the first kernel32 function that failed explicitly because a feature is not implemented
("K32 unsupported: ..."), the exit code, or the timeout. Chromium's own log lines (--enable-logging=stderr) are copied
into the result as evidence.

The result is written to <out>/result.json and printed. Exit status 0 = PASS, 1 = FAIL (the expected state until M2
is reached), 2 = BLOCKED (missing inputs/tools/QEMU or a host preparation/launch error). All outcomes persist result.json.
"""
import argparse
import json
import os
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
# Inputs live outside the repository: $SHZ_SCRATCH (or the runner's own scratch default) holds chromium-full/chrome-win
# (the unpacked Win_x64 snapshot 1706750 chrome-win.zip pinned in ELECTRON_TARGET.md section 1) and the FAT32 image.
SCRATCH = Path(os.environ.get("SHZ_SCRATCH", str(disk.SCRATCH)))
DEFAULT_TREE = SCRATCH / "chromium-full" / "chrome-win"
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


def autorun_lines(serial):
    """Evidence belonging to the autorun, excluding earlier kernel self-test output."""
    lines = serial.splitlines()
    start = next((i for i, line in enumerate(lines) if line.startswith("K64 autorun: starting")), None)
    return lines[start + 1:] if start is not None else []


def classify(serial):
    """Furthest point reached, from the serial log after the autorun start (see the module docstring for the precedence).
    A runtime LoadLibrary that fails ("K64 ldr: X not loaded: LoadLibrary needs ...") is reported separately: programs
    probe for optional DLLs and continue without them, so it is not a failure by itself."""
    lines = autorun_lines(serial)
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
    # Accept the actual autorun format (including its optional reap/timing suffix), not a valid-looking prefix
    # of a malformed line. In particular, faulted must be exactly 0 or 1, never an unknown or truncated value.
    m = re.fullmatch(r"K64 autorun: result ([\w-]+) exit=([0-9a-fA-F]+) faulted=([01])"
                     r"(?: reaped=-?\d+(?: \(\d+ thread\(s\) still alive\))? after \d+ ms)?",
                     auto[-1]) if auto else None
    res["exit_code"] = int(m.group(2), 16) if m else None
    res["faulted"] = bool(int(m.group(3))) if m else None
    res["ended_by"] = m.group(1) if m else None
    res["guest_timed_out"] = res["ended_by"] == "timeout" or any(
        line.startswith("K64 autorun: timeout") for line in lines)
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


def evaluate(serial, expected, qemu_returncode, timed_out):
    """Combine guest evidence with the host outcome; unknown completion fields cannot pass."""
    res = classify(serial)
    expect_seen = bool(expected and expected.strip() and expected in "\n".join(autorun_lines(serial)))
    conditions = [
        (bool(expected and expected.strip()), "expected marker is empty"),
        (expect_seen, "expected marker not seen after autorun start"),
        (res["ended_by"] == "exited", "autorun did not end by exiting"),
        (res["exit_code"] == 0, "autorun exit code is not zero"),
        (res["faulted"] is False, "autorun faulted is not explicitly false"),
        (not res["exceptions"], "guest exception reported"),
        (not res["chromium_fatal"], "Chromium fatal line reported"),
        (not res["loader_failures"], "loader failure reported"),
        (not res["guest_timed_out"], "guest autorun timed out"),
        (not timed_out, "host QEMU timeout"),
        # isa-debug-exit encodes a guest write of zero as host status 1; ordinary clean shutdown is status 0.
        (qemu_returncode in (0, 1), "QEMU exit status is not 0 or 1"),
    ]
    failures = [reason for ok, reason in conditions if not ok]
    return {**res, "status": "FAIL" if failures else "PASS", "expected_line": expected,
            "expected_line_seen": expect_seen, "qemu_returncode": qemu_returncode, "qemu_timed_out": timed_out,
            "failure_reasons": failures}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--memory", default="3072")
    ap.add_argument("--display", choices=("vga", "none"), default="vga",
                    help="vga: a Bochs VBE adapter so the Win32 window manager is active (default); none: no display device")
    ap.add_argument("--timeout", default=1800, help="host-side QEMU timeout (positive integer seconds)")
    ap.add_argument("--guest-timeout", type=int, default=1200, help="seconds the guest lets chrome.exe run")
    ap.add_argument("--chromium", default=str(DEFAULT_TREE), help="chrome-win tree (read-only)")
    ap.add_argument("--chromium-image", default=str(SCRATCH / "k64-chromium-fat32.img"))
    ap.add_argument("--args", default=DEFAULT_ARGS, help="chrome.exe arguments")
    ap.add_argument("--expect", default=M2_EXPECT, help="line that must appear in the output for a PASS")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_chromium"))
    ap.add_argument("--trace-all-syscalls", action="store_true",
                    help="also pass shz.systrace.all: the last 70 system calls of the thread that takes the first breakpoint are printed with it")
    ap.add_argument("--no-trace", action="store_true",
                    help="do not pass shz.k32trace, shz.exctrace and shz.systrace (kernel32 explicit-failure and GetProcAddress-miss lines, first-chance hardware exceptions, failing system calls)")
    args = ap.parse_args()
    # Resolve --out before preflight so even an unavailable run leaves a discoverable result.
    out = Path(args.out).resolve()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    tree = Path(args.chromium)
    image = Path(args.chromium_image)
    command_line = f"chrome.exe {args.args}"
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    serial_path = out / "serial.log"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           *(["-vga", "std"] if args.display == "vga" else []),
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-append", "shz.noapps shz.autorun=D:\\K64RUN.TXT" + ("" if args.no_trace else " shz.k32trace shz.exctrace shz.systrace" + (" shz.systrace.all" if args.trace_all_syscalls else "")),
           "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw,snapshot=on",
           "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    # Keep the existing schema present on BLOCKED as well as completed runs. Unknown results stay None.
    record = {
        "profile": "kernel64-standalone + Chromium chrome-win on AHCI FAT32 (D:), autorun", "accel": accel,
        **evaluate("", args.expect, None, False),
        "status": "BLOCKED", "seconds": 0.0, "image_prepare_s": 0.0,
        "image": str(image), "tree_files": 0, "command": cmd, "chrome_args": args.args,
        "chrome_output_lines": [], "chrome_output_line_count": 0,
        "serial_tail": "", "qemu_output": "", "utc": shzlib.utc_now(), "git": {},
        "missing_prerequisites": [], "blocked_reason": None,
    }
    stage = "preflight"
    started = None
    try:
        out.mkdir(parents=True, exist_ok=True)
        missing = [f"missing input: {f}" for f in (stub, kernel, initrd) if not f.is_file()]
        if not (tree / "chrome.exe").is_file():
            missing.append(f"missing Chromium input: {tree / 'chrome.exe'}")
        missing.extend(f"required tool missing: {tool}" for tool in ("mkfs.vfat", "mcopy", "mmd")
                       if not shutil.which(tool))
        if not shutil.which(args.qemu):
            missing.append(f"QEMU executable missing or not executable: {args.qemu}")
        if not args.expect or not args.expect.strip():
            missing.append("expected marker is empty (--expect)")
        timeout_value = args.timeout
        try:
            args.timeout = int(timeout_value)
            if args.timeout <= 0:
                raise ValueError("not positive")
        except (TypeError, ValueError):
            missing.append(f"invalid host timeout (--timeout): {timeout_value!r}; require positive integer seconds")
        # kernel64/autorun.c stores cmdline in char[512] and silently truncates beyond 511 bytes.
        command_bytes = len(command_line.encode())
        if command_bytes > 511:
            missing.append(f"Chromium command line is {command_bytes} encoded bytes; autorun limit is 511")
        record["missing_prerequisites"] = missing
        record["git"] = shzlib.git_state()
        if missing:
            record["blocked_reason"] = "; ".join(missing)
            record["furthest"] = "preflight blocked: " + record["blocked_reason"]
        else:
            stage = "image preparation"
            t0 = time.time()
            image.parent.mkdir(parents=True, exist_ok=True)
            listing = disk.build_chromium_image(tree, image)
            record["tree_files"] = len(listing)
            control = (f"image=D:\\chrome-win\\chrome.exe\r\ncmdline={command_line}\r\ncwd=D:\\chrome-win\r\n"
                       f"timeout={args.guest_timeout}\r\n").encode()
            put_file(image, control, "K64RUN.TXT", out)
            put_file(image, M2_PAGE, "M2/M2.HTML", out)
            record["image_prepare_s"] = round(time.time() - t0, 1)
            stage = "QEMU launch/collection"
            serial_path.unlink(missing_ok=True)
            started = time.time()
            rc, qemu_out, timed_out = qemu.run_bounded(cmd, args.timeout)
            record.update(qemu_returncode=rc, qemu_timed_out=timed_out, qemu_output=qemu_out[-1500:],
                          seconds=round(time.time() - started, 1))
            stage = "serial log collection"
            serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
            record["serial_tail"] = serial[-6000:]
            record.update(evaluate(serial, args.expect, rc, timed_out))
            chrome_lines = [l for l in autorun_lines(serial) if re.match(r"\[(win64|user) chrome\.exe pid \d+\]", l)]
            record.update(chrome_output_lines=chrome_lines[:400], chrome_output_line_count=len(chrome_lines))
    except (OSError, RuntimeError, subprocess.SubprocessError, OverflowError) as exc:
        record["status"] = "BLOCKED"
        record["blocked_reason"] = f"{stage}: {type(exc).__name__}: {exc}"
        record["furthest"] = record["blocked_reason"]
        if started is not None:
            record["seconds"] = round(time.time() - started, 1)
    # A writable --out is needed to persist any evidence; report that failure explicitly if it is unavailable.
    try:
        shzlib.write_json(out / "result.json", record)
    except OSError as exc:
        print(f"  status: BLOCKED (cannot write {out / 'result.json'}: {exc})")
        return 2
    print(f"  status: {record['status']} ({record['seconds']} s, accel={accel})")
    print(f"  furthest point: {record['furthest']}")
    print(f"  autorun: {record['autorun_result']}")
    print(f"  expected line seen: {record['expected_line_seen']}")
    print(f"  QEMU exit status: {record['qemu_returncode']}")
    if record["blocked_reason"]:
        print(f"  blocked: {record['blocked_reason']}")
    for reason in record["failure_reasons"] if record["status"] == "FAIL" else []:
        print(f"  [failure] {reason}")
    for k in ("loader_failures", "exceptions", "chromium_fatal", "unsupported_calls"):
        for l in record[k][:8]:
            print(f"  [{k}] {l}")
    print(f"  chrome.exe output lines: {record['chrome_output_line_count']} (first 20 below; all in result.json)")
    for l in record["chrome_output_lines"][:20]:
        print("    " + l[:300])
    print(f"  result: {out / 'result.json'}")
    return {"PASS": 0, "FAIL": 1, "BLOCKED": 2}[record["status"]]


if __name__ == "__main__":
    sys.exit(main())
