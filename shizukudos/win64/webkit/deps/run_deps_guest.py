#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Guest checks of the W3 toolchain and WebKit dependencies on standalone Kernel64 (QEMU; TCG here).

Builds deps/tests/t_*.c(pp) (deps/build.py --tests), packs them with WKRUN.EXE, every dependency DLL
(build/shizukudos/webkit/deps/bin) and the toolchain runtime DLLs (libc++.dll, libunwind.dll) into D:\\WK, checks every
import statically against the Shizuku system DLLs (tests/wkguest.py import_check), boots Kernel64 once and lets
WKRUN.EXE run each check. A check passes when its process exits 0 and it printed no FAIL line.

Result: build/shizukudos/webkit/run_deps/result.json (+ serial.log). Exit code 0 only if every check passed.
"""
import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "tests"))
import build as deps  # noqa: E402
import toolchain as tc  # noqa: E402
import wkguest  # noqa: E402
from toolchain import BUILD, run  # noqa: E402

OUT = BUILD / "webkit" / "run_deps"


def build_wkrun():
    exe = BUILD / "webkit" / "WKRUN.EXE"
    exe.parent.mkdir(parents=True, exist_ok=True)
    run([tc.TC / "bin" / f"{tc.TRIPLE}-clang", "-O2", "-Wall", "-Wextra", "-Werror", HERE.parent / "tests" / "wkrun.c",
         "-o", exe], env=deps.env())
    return exe


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", help="comma-separated check names (t_...)")
    ap.add_argument("--memory", default="1024")
    ap.add_argument("--timeout", type=int, default=3600)
    a = ap.parse_args()
    only = set(a.only.split(",")) if a.only else None
    OUT.mkdir(parents=True, exist_ok=True)
    tests = deps.build_tests(only)
    wkrun = build_wkrun()
    dlls = sorted((deps.PREFIX / "bin").glob("*.dll")) + sorted((tc.SYSROOT / "bin").glob("*.dll"))
    data = sorted((HERE / "tests" / "data").glob("*")) if (HERE / "tests" / "data").exists() else []
    files = [wkrun, *tests.values(), *dlls, *data]
    misses, imports = wkguest.import_check([f for f in files if f.suffix.lower() in (".exe", ".dll")])
    spec = json.loads((HERE / "tests" / "tests.json").read_text())
    listing = "".join(f"{n}|600|{Path(e).name} {spec.get(n, {}).get('args', '')}".rstrip() + "\r\n"
                      for n, e in tests.items())
    image = OUT / "deps.img"
    size = wkguest.make_image(image, files, listing)
    wkguest.autorun(image, a.timeout - 120)
    serial_path = OUT / "serial.log"
    secs, timed_out, qout, cmd, accel = wkguest.run_qemu(image, serial_path, memory=a.memory, timeout=a.timeout)
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    res = wkguest.parse_serial(serial)
    checks = {}
    for name in tests:
        r = res["results"].get(name)
        lines = [l for l in res["lines"] if re.match(rf"\[win64 {re.escape(name)}\.exe pid \d+\]", l, re.I)]
        fails = [l for l in lines if re.search(r"\bFAIL\b", l)]
        passes = [l for l in lines if re.search(r"\bPASS\b", l)]
        ok = bool(r) and r["exit"] == 0 and not fails and passes
        checks[name] = {"status": "PASS" if ok else "FAIL", "exit": r["exit"] if r else None,
                        "ms": r["ms"] if r else None, "pass_lines": len(passes), "fail_lines": fails,
                        "output": lines[:200]}
    ok_all = all(c["status"] == "PASS" for c in checks.values()) and not misses and not timed_out
    record = {"status": "PASS" if ok_all else "FAIL", "accel": accel, "seconds": secs, "qemu_timed_out": timed_out,
              "memory_mib": a.memory, "image_mib": size, "command": cmd, "import_misses": misses, "checks": checks,
              "packaged": {Path(f).name: Path(f).stat().st_size for f in files}, "loader": res["loader"],
              "exceptions": [e for e in res["exceptions"] if not re.search(r"process (fault|wild|high) \(pid", e)],
              "autorun": res["autorun"], "utc": tc.shzlib.utc_now(), "git": tc.shzlib.git_state()}
    tc.shzlib.write_json(OUT / "result.json", record)
    for n, c in checks.items():
        print(f"  [{c['status']}] {n}: exit={c['exit']} ms={c['ms']} pass_lines={c['pass_lines']}"
              + (f" first_fail={c['fail_lines'][0]}" if c["fail_lines"] else ""))
    for m in misses:
        print(f"  [import miss] {m}")
    for l in record["loader"][:10] + record["exceptions"][:10]:
        print(f"  [guest] {l}")
    print(f"{record['status']} ({secs} s, accel={accel}); result: {OUT / 'result.json'}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
