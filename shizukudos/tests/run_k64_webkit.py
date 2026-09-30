#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run WebKit's JavaScriptCore shell (jsc.exe, built by shizukudos/win64/webkit/build.py) inside the standalone Kernel64
guest and report the result (docs/shizukudos10/WEBKIT.md, docs/shizukudos10/reports/W1.md).

Profile: as run_k64_chromium.py. The standalone Kernel64 guest (QEMU -kernel stub, no Supervisor, TCG or KVM) boots
with WIN64.IMG; the programs under test sit on a FAT32 image outside the repository, attached on AHCI and mounted as
D:\\ (snapshot=on). `shz.noapps shz.autorun=D:\\K64RUN.TXT` skips the T_*.EXE self-checks and starts the program the
control file names (kernel64/autorun.c). Program output comes back on the serial log as `[win64 <image> pid N] line`.

Modes
  m1 (default)  D:\\WK\\jsc.exe D:\\WK\\M1.JS (shizukudos/win64/webkit/tests/m1.js). PASS only when every `W1 <part> = <v>`
                line equals the expected value, the final `W1-JSC-M1 OK parts=N intl=I fnv=H` line is printed with the FNV-1a
                hash this runner recomputes from its own expected values, jsc.exe exited 0 and no process fault was
                reported.
  stress        a list of JSTests/stress files (default: webkit/tests/stress-subset.txt) run one jsc.exe process each by
                D:\\WK\\WKBATCH.EXE (webkit/tests/wkbatch.c); pass/fail counts are reported as they are: a test passes
                when its jsc.exe exits 0 without a fault, like JSC's own run-javascriptcore-tests default mode.
  probe         any executable(s) given with --exe (plus --file extras) and --args: the toolchain experiments of
                WEBKIT.md; PASS when --expect is seen and the program exited 0 without a fault.

Writes <out>/result.json and prints it in short. Exit status 0 = PASS, 1 = FAIL, 2 = missing inputs.
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
from shzlib import BUILD, REPO, run  # noqa: E402
import run_k64_disk as disk  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
WKOUT = WIN64 / "webkit" / "out"
WKSRC = REPO / "shizukudos" / "win64" / "webkit"
UPSTREAM_WEBKIT = REPO / "build" / "upstream" / "webkit"

# The expected value of every part of tests/m1.js (checked against V8/node 22 on the host, see WEBKIT.md). The marker's
# hash is FNV-1a over "name=value" joined by ";", in this order; "intl" is present only when jsc has Intl.
M1_EXPECTED = [
    ("closure", "44"),
    ("json", '{"a":[3,6,{"b":"xé\\n"}],"n":null,"t":true}'),
    ("regexp", "84ABC|30.09.2026|a1b2c3|75|3"),
    ("date", "2000-02-29T12:34:56.789Z|2|981173106000|NaN"),
    ("typedarray", "603777093|deef|65279|-128,-127,6"),
    ("number", "0.30000000000000004|123.46|1e+21|ff|1.23e-6|3.141592654|325|9007199254740991|5e-324"),
    ("math", "1.4142135623730951|-1|5|3|-4|-1|31|5.5"),
    ("lang", "42|0491625|kj|misp|5|698635|symbol|2x"),
    ("string", "ǆSTRASSE|1|121abc|3|120|trim"),
    ("intl", "1,234,567.891|1.234.567,891|2/29/2000|abC|oneother"),
    ("promise", "sync,job,await,async42|123"),
]


def fnv1a_utf16(text):
    """The hash m1.js computes: FNV-1a 32 over the UTF-16 code units of the string."""
    h = 0x811c9dc5
    units = text.encode("utf-16-le")
    for i in range(0, len(units), 2):
        h ^= units[i] | units[i + 1] << 8
        h = (h * 0x01000193) & 0xffffffff
    return h


def m1_expected(intl):
    parts = [(n, v) for n, v in M1_EXPECTED if intl or n != "intl"]
    return parts, f"{fnv1a_utf16(';'.join(f'{n}={v}' for n, v in parts)):08x}"


def program_lines(serial, image_name):
    """stdout/stderr lines of a program, from the kernel's `[win64 <name> pid N] text` relay."""
    rx = re.compile(r"^\[(?:win64|user) " + re.escape(image_name) + r" pid \d+\] ?(.*)$", re.I)
    return [m.group(1) for m in map(rx.match, serial.splitlines()) if m]


def classify(serial):
    """Autorun result and failure evidence after the autorun start (run_k64_chromium.classify, minus Chromium)."""
    lines = serial.splitlines()
    start = next((i for i, l in enumerate(lines) if l.startswith("K64 autorun: starting")), len(lines))
    lines = lines[start:]
    ldr = [l for l in lines if re.search(r"K64 ldr: .*(not loaded|imports|rejected|failed|cannot|lacks)", l)]
    killed = [l for l in lines if re.search(r"K64: process .* killed|K64 EXCEPTION|unhandled exception", l)]
    unsup = [l for l in lines if "K32 unsupported:" in l or "K32 RECON called:" in l]
    auto = [l for l in lines if l.startswith("K64 autorun: result")]
    m = re.search(r"K64 autorun: result (\w[\w-]*) exit=([0-9a-f]+) faulted=(\d)", auto[-1]) if auto else None
    return {
        "loader_failures": ldr[:20], "exceptions": killed[:20], "unsupported_calls": unsup[:60],
        "autorun_result": auto[-1] if auto else None, "ended_by": m.group(1) if m else None,
        "exit_code": int(m.group(2), 16) if m else None, "faulted": bool(int(m.group(3))) if m else None,
    }


def make_image(image, files, out):
    """files: [(bytes or host Path, "DIR/NAME")] -> fresh FAT32 superfloppy (fixed timestamps, run_k64_disk)."""
    stage = out / "stage"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    staged, dirs = [], set()
    for src, name in files:
        host = stage / name.replace("/", "__")
        if isinstance(src, (bytes, bytearray)):
            host.write_bytes(src)
        else:
            shutil.copyfile(src, host)
        staged.append((host, name))
        parts = name.split("/")
        dirs.update("/".join(parts[:i]) for i in range(1, len(parts)))
    total = sum(h.stat().st_size for h, _ in staged)
    size_mib = max(64, (total * 12 // 10 >> 20) + 48)
    disk.make_image(image, size_mib, 8, staged, sorted(dirs, key=lambda d: d.count("/")))
    return total


def boot(args, accel, image, out, control):
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
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
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    return {"command": cmd, "control": control, "seconds": round(time.time() - started, 1), "qemu_timed_out": timed_out,
            "qemu_output": qemu_out[-1500:]}, serial


def control_file(image, cmdline, timeout):
    return (f"image={image}\r\ncmdline={cmdline}\r\ncwd=D:\\WK\r\ntimeout={timeout}\r\n").encode()


def jsc_files():
    """jsc.exe and the DLLs next to it (build.py's out/ directory)."""
    return [(p, "WK/" + p.name) for p in sorted(WKOUT.glob("*")) if p.suffix.lower() in (".exe", ".dll")]


def evaluate_m1(serial, res):
    lines = program_lines(serial, "jsc.exe")
    got = {}
    for l in lines:
        m = re.match(r"W1 (\w+) = (.*)$", l)
        if m:
            got[m.group(1)] = m.group(2)
    marker = next((l for l in lines if l.startswith("W1-JSC-M1 ")), None)
    mm = re.match(r"W1-JSC-M1 OK parts=(\d+) intl=([01]) fnv=([0-9a-f]{8})$", marker or "")
    intl = bool(mm and mm.group(2) == "1")
    parts, want_hash = m1_expected(intl)
    mismatches = [f"{n}: got {got.get(n)!r} want {v!r}" for n, v in parts if got.get(n) != v]
    ok_marker = bool(mm) and int(mm.group(1)) == len(parts) and mm.group(3) == want_hash
    ok = ok_marker and not mismatches and res["exit_code"] == 0 and not res["faulted"] and not res["exceptions"]
    return ok, {"marker_line": marker, "marker_expected_fnv": want_hash, "marker_ok": ok_marker, "intl": intl,
                "parts_seen": got, "part_mismatches": mismatches, "jsc_output_lines": lines[:400]}


def evaluate_stress(serial, res, tests):
    lines = program_lines(serial, "wkbatch.exe")
    per = {}
    for l in lines:
        m = re.match(r"WKBATCH (\S+) exit=(-?\d+|[0-9a-fx]+) ms=(\d+)(?: (\w+))?$", l)
        if m:
            per[m.group(1)] = {"exit": m.group(2), "ms": int(m.group(3)), "note": m.group(4) or ""}
    done = next((l for l in lines if l.startswith("WKBATCH DONE")), None)
    passed = sorted(t for t, r in per.items() if r["exit"] == "0" and not r["note"])
    failed = sorted(t for t in per if t not in passed)
    not_run = sorted(t for t in tests if t not in per)
    ok = done is not None and res["exit_code"] == 0 and not res["faulted"] and not failed and not not_run
    return ok, {"tests": len(tests), "passed": len(passed), "failed": len(failed), "not_run": len(not_run),
                "failed_tests": {t: per[t] for t in failed}, "not_run_tests": not_run, "per_test": per, "done_line": done,
                "jsc_output_lines": program_lines(serial, "jsc.exe")[:400]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", choices=("m1", "stress", "probe"), default="m1")
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--memory", default="2048")
    ap.add_argument("--timeout", type=int, default=2400, help="host-side QEMU timeout (s)")
    ap.add_argument("--guest-timeout", type=int, default=1800, help="seconds the guest lets the program run")
    ap.add_argument("--exe", action="append", default=[], help="probe: executable(s) to copy; the first one runs")
    ap.add_argument("--file", action="append", default=[], help="probe: extra files copied next to the executable")
    ap.add_argument("--args", default="", help="probe: arguments")
    ap.add_argument("--expect", default="", help="probe: line fragment that must appear in the program output")
    ap.add_argument("--tests", default=str(WKSRC / "tests" / "stress-subset.txt"), help="stress: list of JSTests paths")
    ap.add_argument("--per-test-timeout", type=int, default=300, help="stress: seconds per jsc.exe process")
    ap.add_argument("--image", default=str(Path(os.environ.get("SHZ_SCRATCH", str(disk.SCRATCH))) / "k64-webkit-fat32.img"))
    ap.add_argument("--out", default="")
    ap.add_argument("--no-trace", action="store_true", help="do not pass shz.k32trace and shz.exctrace")
    args = ap.parse_args()
    out = Path(args.out or BUILD / "kernel64s" / f"run_webkit_{args.mode}")
    out.mkdir(parents=True, exist_ok=True)
    for f in (K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"):
        if not f.exists():
            print(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
            return 2
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            print(f"required tool missing: {tool}")
            return 2
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    image = Path(args.image)
    image.parent.mkdir(parents=True, exist_ok=True)

    tests = []
    if args.mode == "probe":
        if not args.exe:
            print("probe: --exe is required")
            return 2
        exes = [Path(e) for e in args.exe]
        files = [(p, "WK/" + p.name) for p in exes + [Path(f) for f in args.file]]
        prog = exes[0].name
        control = control_file(f"D:\\WK\\{prog}", f"{prog} {args.args}".strip(), args.guest_timeout)
    else:
        if not (WKOUT / "jsc.exe").exists():
            print(f"missing {WKOUT / 'jsc.exe'}: run shizukudos/win64/webkit/build.py first")
            return 2
        files = jsc_files()
        if args.mode == "m1":
            files.append(((WKSRC / "tests" / "m1.js").read_bytes(), "WK/M1.JS"))
            prog = "jsc.exe"
            control = control_file("D:\\WK\\jsc.exe", "jsc.exe M1.JS", args.guest_timeout)
        else:
            if not (WKOUT / "wkbatch.exe").exists():
                print(f"missing {WKOUT / 'wkbatch.exe'}")
                return 2
            tests = [l.split("#")[0].strip() for l in Path(args.tests).read_text().splitlines()]
            tests = [t for t in tests if t]
            listing = []
            for i, t in enumerate(tests):
                src = UPSTREAM_WEBKIT / t
                if not src.exists():
                    print(f"missing {src} (fetch the webkit upstream: shizukudos/win64/webkit/build.py)")
                    return 2
                name = f"S{i:03d}.JS"                   # 8.3 names; the list maps them back
                files.append((src, "WK/ST/" + name))
                listing.append(f"ST\\{name} {t}")
            files.append((("\r\n".join(listing) + "\r\n").encode(), "WK/STRESS.TXT"))
            prog = "wkbatch.exe"
            control = control_file("D:\\WK\\wkbatch.exe",
                                   f"wkbatch.exe STRESS.TXT {args.per_test_timeout}", args.guest_timeout)
    files.append((control, "K64RUN.TXT"))
    t0 = time.time()
    total = make_image(image, files, out)
    run_info, serial = boot(args, accel, image, out, control.decode())
    res = classify(serial)
    if args.mode == "m1":
        ok, detail = evaluate_m1(serial, res)
    elif args.mode == "stress":
        ok, detail = evaluate_stress(serial, res, [t for t in tests])
        detail["per_test"] = {tests[int(k[4:7])] if re.match(r"ST\\S\d{3}\.JS", k) else k: v
                              for k, v in detail["per_test"].items()}
    else:
        lines = program_lines(serial, prog)
        seen = bool(args.expect) and any(args.expect in l for l in lines)
        ok = seen and res["exit_code"] == 0 and not res["faulted"] and not res["exceptions"]
        detail = {"expect": args.expect, "expect_seen": seen, "program_output_lines": lines[:400]}
    ok = ok and not run_info["qemu_timed_out"]
    record = {
        "profile": "kernel64-standalone + WebKit JSC on AHCI FAT32 (D:), autorun", "mode": args.mode, "accel": accel,
        "status": "PASS" if ok else "FAIL", "program": prog, "disk_bytes": total, "image_prepare_s": round(time.time() - t0 - run_info["seconds"], 1),
        **run_info, **res, **detail,
        "files": [n for _, n in files], "serial_tail": serial[-8000:], "utc": shzlib.utc_now(), "git": shzlib.git_state(),
    }
    shzlib.write_json(out / "result.json", record)
    print(f"  mode {args.mode}: {record['status']} ({run_info['seconds']} s, accel={accel})")
    print(f"  autorun: {res['autorun_result']}")
    for k in ("loader_failures", "exceptions", "unsupported_calls"):
        for l in res[k][:10]:
            print(f"  [{k}] {l}")
    if args.mode == "m1":
        print(f"  marker: {detail['marker_line']} (expected fnv {detail['marker_expected_fnv']})")
        for l in detail["part_mismatches"]:
            print(f"  mismatch: {l}")
    elif args.mode == "stress":
        print(f"  stress: {detail['passed']} passed, {detail['failed']} failed, {detail['not_run']} not run of {detail['tests']}")
    else:
        for l in detail["program_output_lines"][:30]:
            print("    " + l[:300])
    print(f"  result: {out / 'result.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
