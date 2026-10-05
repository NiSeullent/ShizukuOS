#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build only the Win64 modules SHZSETUP.EXE links (bcrypt, user32, gdi32 + their recursive module.json closure), on top of
an existing minimal Win64 runtime (ntdll/kernel32 + import libs + shzcrt.o), into a separate fresh --out directory.

Reuses win64/build.py build_modules() with discover_modules() filtered to the validated closure; flags, resources, exports
and base assignment are the real recipe's. The runtime directory is only read: its ntdll/kernel32 DLLs, import libraries
and CRT object are copied (hash-verified) into --out, which therefore holds a self-contained module stage. Not a full
Win64 build, no apps/WIN64.IMG/SHZSETUP.EXE, no Wine; this is not installed or runtime acceptance.

Writes <out>/build-result.json (truthful staging receipt: source/tool hashes before/after, commands, every copied and
built file hash, only the modules actually built) usable as stage_setup.py --runtime-receipt with --runtime-dir <out>.
Nothing is compiled with --plan.
"""
import argparse
import importlib.util
import json
import shutil
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True      # never create __pycache__ next to read-only sources
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib  # noqa: E402
from shzlib import REPO, SHZ, sha256_file  # noqa: E402

DEFAULT_MODULES = ("bcrypt", "user32", "gdi32")
BASE_FILES = ("ntdll.dll", "kernel32.dll", "libntdll.a", "libkernel32.a")
OPTIONAL_BASE = ("libntdll_delay.a", "libkernel32_delay.a", "ntdll.def", "kernel32.def", "shzcrt.o")
DYNAMIC_BASE = 0x40


def load_win64_build():
    spec = importlib.util.spec_from_file_location("shz_win64_build_modules", SHZ / "win64" / "build.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    sys.path.insert(0, str(SHZ / "win64" / "tools"))
    spec.loader.exec_module(mod)
    return mod


def closure(found, roots):
    """Roots plus every module reachable through module.json "libs"; unknown names are fatal, order is sorted."""
    known = {name: cfg for name, _, cfg in found}
    want, todo = set(), list(roots)
    while todo:
        name = todo.pop()
        if name in want:
            continue
        if name not in known:
            raise SystemExit(f"module {name!r} (required by the installer closure) has no win64/dlls/{name}/*.c")
        want.add(name)
        todo += [l for l in known[name].get("libs", []) if l not in ("kernel32", "ntdll")]
    return sorted(want)


def pe_layout(path):
    d = path.read_bytes()
    pe = struct.unpack_from("<I", d, 0x3C)[0]
    if d[pe:pe + 4] != b"PE\0\0" or struct.unpack_from("<H", d, pe + 24)[0] != 0x20B:
        raise SystemExit(f"{path.name}: not a PE32+ image")
    base, = struct.unpack_from("<Q", d, pe + 24 + 24)
    size, = struct.unpack_from("<I", d, pe + 24 + 56)
    dll_chars, = struct.unpack_from("<H", d, pe + 24 + 70)
    return base, size, bool(dll_chars & DYNAMIC_BASE)


def tool_pins(b):
    pins = {}
    for t in (b.CC, b.DLLTOOL, b.WINDRES):
        p = shutil.which(t)
        pins[t] = {"path": p, "sha256": sha256_file(Path(p)) if p else None}
    return pins


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runtime-dir", type=Path, required=True, help="completed minimal runtime (read only)")
    ap.add_argument("--runtime-receipt", type=Path, help="actual runtime producer receipt (default: runtime-dir/build-result.json)")
    ap.add_argument("--out", type=Path, required=True, help="new or empty owned output directory (disjoint from runtime)")
    ap.add_argument("--module", action="append", default=[], metavar="NAME",
                    help=f"root module (default {' '.join(DEFAULT_MODULES)}); its module.json closure is added")
    ap.add_argument("--plan", action="store_true", help="validate and print the closure; compile nothing, write nothing")
    args = ap.parse_args(argv)

    rt, out = args.runtime_dir.resolve(), args.out.resolve()
    if not rt.is_dir():
        raise SystemExit(f"runtime dir missing: {rt}")
    if out == rt or rt in out.parents or out in rt.parents:
        raise SystemExit("--out and --runtime-dir must be disjoint directories")
    if out.exists() and any(out.iterdir()):
        raise SystemExit(f"--out must be new or empty: {out}")

    b = load_win64_build()
    found = b.discover_modules()
    roots = args.module or list(DEFAULT_MODULES)
    names = closure(found, roots)
    print("module closure:", " ".join(names))
    if args.plan:
        return
    for tool in (b.CC, b.DLLTOOL, b.WINDRES):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")

    missing = [n for n in BASE_FILES if not (rt / n).is_file()]
    if missing:
        raise SystemExit("missing runtime files: " + ", ".join(missing))
    base_names = [*BASE_FILES, *(n for n in OPTIONAL_BASE if (rt / n).is_file())]

    # Base producer must have passed and pinned exactly the sources and files consumed.
    receipt_path = (args.runtime_receipt or rt / "build-result.json").resolve()
    if not receipt_path.is_file():
        raise SystemExit(f"actual runtime producer receipt missing: {receipt_path}")
    rr = json.loads(receipt_path.read_text())
    sources = rr.get("sources_sha256", rr.get("source_after", {}))
    if not sources or rr.get("status", "PASS") != "PASS":
        raise SystemExit("runtime receipt has no verified source hashes or producer did not pass")
    mismatch = [n for n, dg in sources.items() if not (REPO / n).is_file() or sha256_file(REPO / n) != dg]
    artifacts = rr.get("artifacts", {})
    for n in base_names:
        entry = artifacts.get(n)
        if entry is not None:
            if entry.get("sha256") != sha256_file(rt / n):
                mismatch.append(f"{n} (producer artifact changed)")
        elif artifacts and n in BASE_FILES:
            mismatch.append(f"{n} (not pinned by actual runtime producer)")
    if not artifacts and (rt / "shzcrt.o").is_file() and rr.get("crt", {}).get("sha256") != sha256_file(rt / "shzcrt.o"):
        mismatch.append("shzcrt.o (differs from runtime receipt)")
    if mismatch:
        raise SystemExit("runtime/source cohort mismatch:\n  " + "\n  ".join(mismatch))

    src_before = {str(p.relative_to(REPO)): sha256_file(p) for p in b.runtime_source_paths()}
    tools_before = tool_pins(b)
    base_before = {n: sha256_file(rt / n) for n in base_names}

    out.mkdir(parents=True, exist_ok=True)
    b.OUT, b.RES = out, out / "res"
    b.RES.mkdir(parents=True, exist_ok=True)
    for n in base_names:
        shutil.copyfile(rt / n, out / n)
        if sha256_file(out / n) != base_before[n]:
            raise SystemExit(f"copy of {n} differs from runtime")

    chosen = set(names)
    b.discover_modules = lambda: [m for m in found if m[0] in chosen]
    commands = []
    real_run = b.run

    def recording_run(command, *a, **kw):
        commands.append([str(x) for x in command])
        return real_run(command, *a, **kw)

    b.run = recording_run
    try:
        built = b.build_modules()
    finally:
        b.run = real_run
    if set(built) != chosen:
        raise SystemExit(f"built {sorted(built)} != closure {names}")

    # Coherent bases: every image relocatable, no overlap among module/ntdll/kernel32 address ranges.
    layouts = {"ntdll": pe_layout(rt / "ntdll.dll"),
               "kernel32": pe_layout(rt / "kernel32.dll")}
    layouts.update({n: pe_layout(m["dll"]) for n, m in built.items()})
    for n, (base, size, dyn) in layouts.items():
        if not dyn:
            raise SystemExit(f"{n}.dll lacks DYNAMIC_BASE")
    spans = sorted((base, base + size, n) for n, (base, size, _) in layouts.items())
    for (_, end, n1), (start, _, n2) in zip(spans, spans[1:]):
        if end > start:
            raise SystemExit(f"image base overlap: {n1}.dll and {n2}.dll")

    src_after = {str(p.relative_to(REPO)): sha256_file(p) for p in b.runtime_source_paths()}
    changed = sorted(n for n in src_before.keys() | src_after.keys() if src_before.get(n) != src_after.get(n))
    if changed or tools_before != tool_pins(b) or base_before != {n: sha256_file(rt / n) for n in base_names}:
        raise SystemExit("sources, tools or runtime inputs changed during build: " + ", ".join(changed))

    artifacts_out = {}
    for p in sorted(out.iterdir()):
        if p.is_file() and p.name != "build-result.json":
            artifacts_out[p.name] = {"sha256": sha256_file(p), "bytes": p.stat().st_size,
                                     "origin": "copied from runtime" if p.name in base_before else "built here"}
    shzlib.write_json(out / "build-result.json", {
        "status": "PASS", "scope": "installer module closure stage only; not a full Win64 build or acceptance",
        "built_utc": shzlib.utc_now(), "git": shzlib.git_state(),
        "runtime_dir": str(rt), "runtime_receipt": {"path": str(receipt_path), "sha256": sha256_file(receipt_path)},
        "toolchain": {"mingw": shzlib.tool_version(b.CC), "dlltool": shzlib.tool_version(b.DLLTOOL),
                      "windres": shzlib.tool_version(b.WINDRES)},
        "tools": tools_before, "roots": roots, "closure": names,
        "modules": {n: {"sha256": sha256_file(m["dll"]), "base": f"{m['base']:#x}", "exports": len(m["exports"]),
                        "libs": next(c for k, _, c in found if k == n).get("libs", [])} for n, m in sorted(built.items())},
        "images": {n: {"base": f"{b_:#x}", "size": s, "dynamicbase": d} for n, (b_, s, d) in sorted(layouts.items())},
        "crt": {"sha256": base_before.get("shzcrt.o")} if "shzcrt.o" in base_before else {},
        "artifacts": artifacts_out, "commands": commands,
        "sources_sha256": src_after, "source_before_equals_after": True,
    })
    print(f"built {' '.join(sorted(built))} -> {out}")
    print("next: python3 shizukudos/install/stage_setup.py --runtime-dir", out, "--runtime-receipt", out / "build-result.json",
          "--out <separate new dir>", *[f"--module-lib {n}" for n in names])


if __name__ == "__main__":
    main()
