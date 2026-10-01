#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the actual installer target/confirmation helper without disk I/O.

Compile the production helper and its refusal/selection contract in plain and
sanitized modes. These checks do not boot a guest or run the disk writer.
"""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
SETUP = ROOT / "shizukudos/win64/setup"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "build/shizukudos/install/interactive-host")
    args = ap.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    sources = [SETUP / "interactive_choice.c", SETUP / "interactive_choice.h",
               SETUP / "plat.h", HERE / "interactive_choice_host.c"]
    pins = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources}
    results = []
    for mode, compiler, flags in (("plain", "gcc", ["-O2"]),
                                 ("asan-ubsan", "clang", ["-O1", "-g", "-fsanitize=address,undefined",
                                                          "-fno-omit-frame-pointer"])):
        tool = shutil.which(compiler)
        if not tool:
            raise SystemExit(f"required compiler missing: {compiler}")
        exe = args.out / ("interactive-choice-" + mode)
        cmd = [tool, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags, "-I", str(SETUP),
               str(SETUP / "interactive_choice.c"), str(HERE / "interactive_choice_host.c"), "-o", str(exe)]
        compiled = subprocess.run(cmd, text=True, capture_output=True, timeout=120)
        log = compiled.stdout + compiled.stderr
        rc = compiled.returncode
        if not rc:
            checked = subprocess.run([str(exe)], text=True, capture_output=True, timeout=60)
            log += checked.stdout + checked.stderr
            rc = checked.returncode
            if not rc and "PASS: interactive target/confirmation contract" not in checked.stdout:
                rc = 1
        (args.out / (mode + ".log")).write_text(log)
        results.append({"mode": mode, "command": cmd, "returncode": rc, "status": "PASS" if rc == 0 else "FAIL"})
        print(mode + ": " + results[-1]["status"])
    stable = all(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest for name, digest in pins.items())
    ok = stable and all(r["returncode"] == 0 for r in results)
    (args.out / "receipt.json").write_text(json.dumps({"status": "PASS" if ok else "FAIL",
        "sources_sha256": pins, "sources_unchanged": stable, "checks": results,
        "scope": "host target/confirmation contract, including no disk I/O before confirmation",
        "guest_installation_verified": False, "windows98_dos_replacement_verified": False}, indent=2) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
