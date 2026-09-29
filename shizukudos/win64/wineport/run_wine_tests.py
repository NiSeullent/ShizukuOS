#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run Wine's own conformance tests of the ported DLLs inside the Shizuku standalone Kernel64 (QEMU) and report
pass / fail / skip per DLL and per subtest.

The test image is WIN64.IMG (runtime + Wine DLLs, as built by win64/build.py) with the Shizuku T_*.EXE apps replaced by
T_HELLO.EXE (the kernel's own Win64 check) and the selected T_WINE_<DLL>.EXE programs. Each T_WINE program runs its
subtests as child processes (wineport/build.py DRIVER); the kernel kills an app after 60 s, so long suites are split
with --subtests, which writes WINETEST.TXT ("<dll> <subtest> ...") that the driver reads instead of its built-in list.
Results come from the guest's serial output: Wine's "N tests executed (T marked as todo, F as flaky, E failures),
S skipped" line per subtest, plus the driver's PASS/FAIL/TIMEOUT line and the kernel's exit record per app.
"""
import argparse
import json
import re
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402

WIN64 = BUILD / "win64"
K64S = BUILD / "kernel64s"


def read_archive(path):
    data = path.read_bytes()
    assert data[:8] == b"SHZARC01"
    n = struct.unpack_from("<I", data, 8)[0]
    files = []
    for i in range(n):
        off = 16 + 136 * i
        name = data[off:off + 120].split(b"\0")[0].decode("ascii")
        o, sz = struct.unpack_from("<QQ", data, off + 120)
        files.append((name, data[o:o + sz]))
    return files


def pack_archive(files):
    entries, blob = [], bytearray()
    header_size = 16 + 136 * len(files)
    for path, data in files:
        while (header_size + len(blob)) % 16:
            blob.append(0)
        entries.append((path, header_size + len(blob), len(data)))
        blob += data
    out = bytearray(b"SHZARC01" + struct.pack("<II", len(files), 0))
    for path, off, size in entries:
        out += path.encode("ascii").ljust(120, b"\0") + struct.pack("<QQ", off, size)
    return bytes(out + blob)


SUMMARY = re.compile(r"[0-9a-f]{4}:(\w+):[^ ]* (\d+) tests executed \((\d+) marked as todo, (\d+) as flaky, (\d+) failures?\), "
                     r"(\d+) skipped\.", re.M)
DRIVER = re.compile(r"wineport:(\w+):(\w+): (PASS|FAIL|TIMEOUT) \(exit (\d+)\)", re.M)
APP = re.compile(r"K64 win64 app: (T_W\w+\.EXE) exit=(-?\d+) faulted=(\d)", re.M)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dlls", nargs="*", help="DLL names (default: every built T_WINE_*.EXE)")
    ap.add_argument("--subtests", nargs="*", default=None, help="run only these subtests (with exactly one program)")
    ap.add_argument("--kind", choices=("all", "wine", "wp"), default="all",
                    help="wine: Wine's own tests (T_WINE_*), wp: the Shizuku checks (T_WP_*)")
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--memory", default="512")
    ap.add_argument("--debug", default="", help="WINEDEBUG value for the tests (written to WINETEST.TXT)")
    ap.add_argument("--out", default=str(BUILD / "win64" / "wineport" / "testrun"))
    args = ap.parse_args()
    exes = sorted([*(WIN64 / "wineport").glob("T_WINE_*.EXE"), *(WIN64 / "wineport").glob("T_WP_*.EXE")])
    if args.kind != "all":
        exes = [e for e in exes if e.name.startswith("T_WINE_" if args.kind == "wine" else "T_WP_")]
    if args.dlls:
        exes = [e for e in exes if e.stem.split("_", 2)[2].lower() in {d.lower() for d in args.dlls}]
    if not exes:
        raise SystemExit("no T_WINE_*.EXE selected; build with shizukudos/win64/build.py first")
    files = [(p, d) for p, d in read_archive(WIN64 / "WIN64.IMG")
             if not (p.upper().startswith("\\SHZ\\TESTS\\T_") and p.upper() != "\\SHZ\\TESTS\\T_HELLO.EXE")]
    # the freshest Wine DLLs (wineport/build.py may have run after win64/build.py packed WIN64.IMG)
    built = json.loads((WIN64 / "wineport" / "wineport-result.json").read_text())["modules"]
    fresh = {f"\\SHZ\\SYS64\\{n.upper()}.DLL": (WIN64 / f"{n}.dll").read_bytes() for n in built}
    files = [(p, fresh.pop(p.upper(), d)) for p, d in files] + [(f"\\SHZ\\SYS64\\{k.split(chr(92))[-1][:-4].lower()}.dll", v)
                                                                 for k, v in fresh.items()]
    for e in exes:
        files.append((f"\\SHZ\\TESTS\\{e.name}", e.read_bytes()))
    cfg = []
    if args.subtests is not None:
        if len(exes) != 1:
            raise SystemExit("--subtests needs exactly one DLL")
        stem = exes[0].stem
        label = stem[len("T_WINE_"):].lower() if stem.startswith("T_WINE_") else "wp_" + stem[len("T_WP_"):].lower()
        cfg.append(label + " " + " ".join(args.subtests))
    if args.debug:
        cfg.append("WINEDEBUG " + args.debug)
    if cfg:
        files.append(("\\SHZ\\TESTS\\WINETEST.TXT", ("\n".join(cfg) + "\n").encode()))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    img = out / "WINETEST.IMG"
    img.write_bytes(pack_archive(files))
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    cmd = [qemu.DEFAULT_QEMU, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults",
           "-display", "none", "-kernel", str(K64S / "boot.elf"), "-initrd", f"{K64S / 'KERNEL64S.BIN'},{img}",
           "-serial", f"file:{serial_path}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    report = {}
    for dll, sub, verdict, code in DRIVER.findall(serial):
        report.setdefault(dll, {})[sub] = {"verdict": verdict, "exit": int(code)}
    for sub, executed, todo, flaky, failures, skipped in SUMMARY.findall(serial):
        for dll, subs in report.items():
            if sub in subs:
                subs[sub].update(executed=int(executed), todo=int(todo), flaky=int(flaky), failures=int(failures),
                                 skipped=int(skipped))
    apps = {name: {"exit": int(code), "faulted": bool(int(f))} for name, code, f in APP.findall(serial)}
    record = {"accel": accel, "seconds": round(time.time() - started, 1), "timed_out": timed_out, "apps": apps,
              "results": report, "command": cmd, "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for dll, subs in sorted(report.items()):
        ok = sum(1 for s in subs.values() if s["verdict"] == "PASS")
        print(f"{dll}: {ok}/{len(subs)} subtests pass")
        for sub, r in sorted(subs.items()):
            detail = (f"{r.get('executed', '?')} executed, {r.get('failures', '?')} failures, {r.get('todo', '?')} todo, "
                      f"{r.get('skipped', '?')} skipped") if "executed" in r else "no summary line (crash/timeout)"
            print(f"   {sub:14} {r['verdict']:8} {detail}")
    for name, a in apps.items():
        print(f"{name}: exit={a['exit']} faulted={a['faulted']}")
    if timed_out:
        print(f"QEMU timed out after {args.timeout}s")
    return 0 if report and all(s["verdict"] == "PASS" for subs in report.values() for s in subs.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
