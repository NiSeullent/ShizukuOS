#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile SHZSETUP.EXE once, against an existing minimal Win64 runtime output, into a separate --out directory.

Runs win64/build.py build_setup() and nothing else (no build_apps/build_modules/main). The runtime directory is only
read: its libntdll.a, libkernel32.a (and optional lib<module>.a named by --module-lib) are added with -L, and its
shzcrt.o is linked when present (else build_setup compiles shzcrt.c in the link). Nothing under build/shizukudos is
written unless --out points there, which is refused for the runtime directory itself.

Writes <out>/SHZSETUP.EXE and <out>/stage-setup-result.json (commands, tool versions, input/output SHA-256, source hashes
before/after). A failed compile writes no receipt and exits non-zero.
"""
import argparse
import importlib.util
import json
import shutil
import sys
from pathlib import Path

sys.dont_write_bytecode = True      # never create __pycache__ next to read-only sources
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib  # noqa: E402
from shzlib import REPO, SHZ, sha256_file  # noqa: E402


def load_win64_build():
    spec = importlib.util.spec_from_file_location("shz_win64_build_setup", SHZ / "win64" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    sys.path.insert(0, str(SHZ / "win64" / "tools"))
    spec.loader.exec_module(mod)
    return mod


def hash_sources(b):
    return {str(p.relative_to(REPO)): sha256_file(p) for p in b.runtime_source_paths()}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runtime-dir", type=Path, required=True,
                    help="completed minimal Win64 output directory (libntdll.a, libkernel32.a, optional shzcrt.o)")
    ap.add_argument("--out", type=Path, required=True, help="new or empty owned output directory for SHZSETUP.EXE")
    ap.add_argument("--module-lib", action="append", default=[], metavar="NAME",
                    help="extra import library lib<NAME>.a from the runtime directory (only if setup needs it)")
    ap.add_argument("--runtime-receipt", type=Path,
                    help="actual completed runtime producer receipt (default: runtime-dir/build-result.json)")
    args = ap.parse_args(argv)

    rt, out = args.runtime_dir.resolve(), args.out.resolve()
    if not rt.is_dir():
        raise SystemExit(f"runtime dir missing: {rt}")
    if out == rt or rt in out.parents or out in rt.parents:
        raise SystemExit("--out and --runtime-dir must be disjoint directories")
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"--out must be new or empty: {out}")
    libs = {n: rt / f"lib{n}.a" for n in ("ntdll", "kernel32", *args.module_lib)}
    missing = [str(p) for p in libs.values() if not p.is_file()]
    if missing:
        raise SystemExit("missing runtime import libraries: " + ", ".join(missing))
    crt = rt / "shzcrt.o"
    crt_obj = crt if crt.is_file() else None

    b = load_win64_build()
    for tool in (b.CC, b.WINDRES):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")

    # Minimal runtime producers need not compile Setup; verify the sources they actually used instead.
    receipt_path = (args.runtime_receipt or rt / "build-result.json").resolve()
    if not receipt_path.is_file():
        raise SystemExit(f"actual runtime producer receipt missing: {receipt_path}")
    rr = json.loads(receipt_path.read_text())
    sources = rr.get("sources_sha256", rr.get("source_after", {}))
    if not sources or rr.get("status", "PASS") != "PASS":
        raise SystemExit("runtime receipt has no verified source hashes or producer did not pass")
    mismatch = [name for name, digest in sources.items()
                if not (REPO / name).is_file() or sha256_file(REPO / name) != digest]
    artifacts = rr.get("artifacts", {})
    consumed = list(libs.values()) + ([crt_obj] if crt_obj else [])
    for path in consumed:
        entry = artifacts.get(str(path.relative_to(rt)))
        if entry is not None:
            if entry.get("sha256") != sha256_file(path):
                mismatch.append(str(path) + " (producer artifact changed)")
        elif artifacts:
            mismatch.append(str(path) + " (not pinned by actual runtime producer)")
    if not artifacts and crt_obj is not None and rr.get("crt", {}).get("sha256") != sha256_file(crt_obj):
        mismatch.append("shzcrt.o (differs from runtime receipt)")
    if mismatch:
        raise SystemExit("runtime/source cohort mismatch:\n  " + "\n  ".join(mismatch))
    notes = {"runtime_receipt": sha256_file(receipt_path), "mismatch": []}
    runtime_before = {str(path): sha256_file(path) for path in consumed}

    before = hash_sources(b)
    out.mkdir(parents=True, exist_ok=True)
    b.OUT, b.RES = out, out / "res"      # build_setup writes SHZSETUP.EXE and version resources under OUT/RES
    b.RES.mkdir(parents=True, exist_ok=True)
    commands = []
    real_run = b.run

    def recording_run(command, *a, **kw):
        command = [str(x) for x in command]
        if "-L" in command:                              # the runtime's libraries follow OUT on the link line
            i = command.index("-L") + 2
            command[i:i] = ["-L", str(rt)]
        commands.append(command)
        return real_run(command, *a, **kw)

    b.run = recording_run
    exe, _ = b.build_setup(args.module_lib, crt_obj)
    b.run = real_run
    after = hash_sources(b)
    changed = sorted(n for n in before.keys() | after.keys() if before.get(n) != after.get(n))
    if runtime_before != {str(path): sha256_file(path) for path in consumed}:
        exe.unlink(missing_ok=True)
        raise SystemExit("runtime link inputs changed during compile")
    if changed:
        exe.unlink(missing_ok=True)
        raise SystemExit("sources changed during compile: " + ", ".join(changed))

    shzlib.write_json(out / "stage-setup-result.json", {
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(),
        "runtime_dir": str(rt), "cohort": notes, "cohort_override": False,
        "runtime_inputs": {n: sha256_file(p) for n, p in libs.items()} | ({"shzcrt.o": sha256_file(crt_obj)} if crt_obj else {}),
        "crt": "runtime shzcrt.o" if crt_obj else "compiled from shzcrt.c in the link",
        "toolchain": {"mingw": shzlib.tool_version(b.CC), "windres": shzlib.tool_version(b.WINDRES)},
        "commands": commands, "sources_sha256": after, "sources_unchanged": True,
        "output": {"SHZSETUP.EXE": {"bytes": exe.stat().st_size, "sha256": sha256_file(exe)}},
    })
    print(f"{exe} {exe.stat().st_size} bytes sha256 {sha256_file(exe)}")


if __name__ == "__main__":
    main()
