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
import shlex
import shutil
import subprocess


SHZ = Path(__file__).resolve().parents[1]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_closure(cc, cases, flags):
    """Ask the actual compiler for all project inputs, including nested headers."""
    paths = {Path(__file__).resolve()}
    for sources in cases.values():
        for source in sources:
            dep = subprocess.run([cc, *[f for f in flags if not f.startswith("-Wl,")],
                                  "-MM", "-MT", "fixture", str(source)],
                                 text=True, capture_output=True, check=True, timeout=60)
            for token in shlex.split(dep.stdout.replace("\\\n", " ").split(":", 1)[1]):
                path = Path(token).resolve()
                path.relative_to(SHZ)  # Fail if an untracked external project input appears.
                paths.add(path)
    return paths


def source_hashes(paths):
    return {str(p.relative_to(SHZ)): sha256(p) for p in sorted(paths)}


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
    cc = str(Path(cc).resolve())
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
    paths = source_closure(cc, cases, flags)
    before = source_hashes(paths)
    compiler_hash = sha256(Path(cc))
    compiler_version = subprocess.run([cc, "--version"], capture_output=True,
                                      text=True, check=True, timeout=30).stdout
    receipt = {"scope": "host production contracts only; no hardware or Windows98 boot proof",
               "sanitize": args.sanitize, "pass": True, "tests": {},
               "sources_sha256": before,
               "compiler": {"path": cc, "sha256": compiler_hash, "version": compiler_version}}
    for name, sources in cases.items():
        if source_hashes(paths) != before:
            receipt["pass"] = False
            receipt["failure"] = "Project inputs changed before compilation"
            break
        exe = out / (name + suffix)
        command = [cc, *flags, *map(str, sources), "-o", str(exe)]
        build = subprocess.run(command, text=True, capture_output=True, timeout=60)
        log = build.stdout + build.stderr
        entry = {"compile_command": command, "compile_returncode": build.returncode}
        if build.returncode == 0:
            entry["binary_sha256"] = sha256(exe)
            run = subprocess.run([str(exe)], text=True, capture_output=True, timeout=30)
            log += run.stdout + run.stderr
            entry["test_returncode"] = run.returncode
            entry["binary_unchanged"] = sha256(exe) == entry["binary_sha256"]
        entry["pass"] = (build.returncode == 0 and entry.get("test_returncode") == 0
                         and entry.get("binary_unchanged") is True)
        receipt["pass"] &= entry["pass"]
        entry["log"] = str(out / (name + suffix + ".log"))
        Path(entry["log"]).write_text(log)
        receipt["tests"][name] = entry
        print(f"{name}: {'PASS' if entry['pass'] else 'FAIL'}")
        print(log, end="")
    after_paths = source_closure(cc, cases, flags)
    receipt["sources_sha256_after"] = source_hashes(after_paths)
    receipt["sources_unchanged"] = paths == after_paths and before == receipt["sources_sha256_after"]
    receipt["compiler_unchanged"] = compiler_hash == sha256(Path(cc))
    receipt["pass"] &= receipt["sources_unchanged"] and receipt["compiler_unchanged"]
    (out / ("result" + suffix + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
    if not receipt["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
