#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-check existing Kernel64 framebuffer handoff and present implementations.

Writes binaries, logs and a receipt under this worktree's ignored build tree.
No kernel boot, device access, downloads or network services are performed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


SHZ = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--sanitize", action="store_true")
    parser.add_argument("--out", type=Path,
                        default=SHZ / "build" / "display-contract-c957")
    args = parser.parse_args()
    cc = shutil.which(args.cc)
    if cc is None:
        raise SystemExit(f"Existing compiler required: {args.cc}; nothing installed")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    suffix = "-sanitized" if args.sanitize else ""
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O1" if args.sanitize else "-O2",
             "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"]
    if args.sanitize:
        flags += ["-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cases = {
        "boot-framebuffer": [SHZ / "tests" / "test_k64_boot_framebuffer.c"],
        "present-rect": [SHZ / "tests" / "test_gfx_present_rect.c", SHZ / "kernel64" / "gfx_fb.c"],
    }
    receipt = {"scope": "host production contracts only; no hardware or Windows98 boot proof",
               "sanitize": args.sanitize, "pass": True, "tests": {},
               "sources_sha256": {}}
    for path in [SHZ / "kernel64" / "main.c", SHZ / "kernel64" / "gfx_fb.c",
                 Path(__file__).resolve(), *[p for paths in cases.values() for p in paths]]:
        receipt["sources_sha256"][str(path.relative_to(SHZ))] = hashlib.sha256(path.read_bytes()).hexdigest()
    for name, sources in cases.items():
        exe = out / (name + suffix)
        command = [cc, *flags, *map(str, sources), "-o", str(exe)]
        build = subprocess.run(command, text=True, capture_output=True, timeout=60)
        log = build.stdout + build.stderr
        entry = {"compile_command": command, "compile_returncode": build.returncode}
        if build.returncode == 0:
            run = subprocess.run([str(exe)], text=True, capture_output=True, timeout=30)
            log += run.stdout + run.stderr
            entry["test_returncode"] = run.returncode
        entry["pass"] = build.returncode == 0 and entry.get("test_returncode") == 0
        receipt["pass"] &= entry["pass"]
        entry["log"] = str(out / (name + suffix + ".log"))
        Path(entry["log"]).write_text(log)
        receipt["tests"][name] = entry
        print(f"{name}: {'PASS' if entry['pass'] else 'FAIL'}")
        print(log, end="")
    (out / ("result" + suffix + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
