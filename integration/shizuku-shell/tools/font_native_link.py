#!/usr/bin/env python3
"""Narrow native link control for the Noto/FreeType provider (NOT the shell build; no whole-PE build).

  python3 tools/font_native_link.py --out /fresh/dir [--runtime-dir DIR]

Strict mingw objects (-Werror) of noto_provider, noto_win32, shz_text_noto + link probe, linked -nostdlib PE64
against libfreetype.a, libshzwcrt.a (staged real Wine-port CRT) and import libraries generated from the exports of the
actual runtime DLLs (via build.py helpers, which read the runtime with `sudo -n cat` when needed). The link is run
twice: with --unresolved-symbols=report-all on a copy only to LIST unresolved symbols, then the real link, whose
failure is reported verbatim. Nothing is stubbed. Imports of the resulting EXE are checked against runtime exports.
The PE is never executed. Writes receipt.json; exit 0 only if the link succeeded and every import resolves."""
import argparse, hashlib, json, subprocess, sys, types
from pathlib import Path
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
# Execute exactly the producer bytes whose digest is recorded, rather than
# importing a second live read after the input snapshot.
BUILD_PATH = HERE / "build.py"
BUILD_BYTES = BUILD_PATH.read_bytes()
B = types.ModuleType("font_link_build")
B.__file__ = str(BUILD_PATH)
exec(compile(BUILD_BYTES, str(BUILD_PATH), "exec"), B.__dict__)
BUILD_SHA = hashlib.sha256(BUILD_BYTES).hexdigest()

REPO = B.REPO
INP = REPO / "build" / "font23-inputs-74b0"
F23 = REPO / "integration" / "shizuku-font"   # COMMON core (not the historical shell font23/ draft)
BCRYPT = REPO / "shizukudos" / "win64" / "dlls" / "bcrypt"
FN = HERE / "font23-native"
FONT_SRC = REPO / "integration" / "shizuku-font"
FLAGS = ["-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-red-zone",
         "-fno-ident", "-Wno-unused-function", "-Wno-unused-parameter", "-Wno-cast-function-type"]
MAX = 6 * 1024 * 1024

def verify_stability(rc, paths, runtime_paths):
    """Re-read every consumed input; any missing/changed input refuses success."""
    rc["sources_stable"] = False
    rc["runtime_stable"] = False
    try:
        rc["sources_after"] = {str(p.relative_to(REPO)): B.sha(p) for p in paths}
        rc["sources_stable"] = rc["sources_before"] == rc["sources_after"]
        if not rc["sources_stable"]:
            rc["reasons"].append("consumed source/header/archive changed after link")
    except Exception as e:
        rc["reasons"].append("post-hash: " + str(e))
    try:
        rc["runtime_sha256_after"] = {
            name: hashlib.sha256(B.read_runtime(p)).hexdigest() for name, p in runtime_paths.items()}
        rc["runtime_stable"] = rc["runtime_sha256_before"] == rc["runtime_sha256_after"]
        if not rc["runtime_stable"]:
            rc["reasons"].append("consumed runtime DLL changed after link")
    except Exception as e:
        rc["reasons"].append("runtime post-hash: " + str(e))
    return rc["sources_stable"] and rc["runtime_stable"] and not rc["reasons"]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True); ap.add_argument("--runtime-dir", default=str(B.DEFAULT_RUNTIME))
    ap.add_argument("--font-src", default=str(FONT_SRC))
    a = ap.parse_args()
    out = Path(a.out)
    if out.exists() and any(out.iterdir()):
        sys.exit("--out must be fresh/empty")
    (out / "obj").mkdir(parents=True, exist_ok=True); (out / "implib").mkdir()
    rc = {"steps": B.receipt["steps"], "reasons": [], "inputs": {}, "sources_before": {}, "sources_after": {},
          "runtime_sha256_before": {}, "runtime_sha256_after": {}, "loaded_build_sha256": BUILD_SHA}
    paths = []
    runtime_paths = {}
    ok = False
    try:
        srcs = [F23 / "noto_provider.c", F23 / "noto_win32.c", F23 / "noto_provider.h", F23 / "noto_win32.h",
                F23 / "noto_asset_pins.h", BCRYPT / "hashes.c", BCRYPT / "hashes.h", BCRYPT / "hash_consts.h",
                FN / "shz_text_noto.c", FN / "shz_text_diag.h", FN / "font_link_probe.c", Path(__file__).resolve(),
                Path(a.font_src) / "shz_text.h", BUILD_PATH, B.FONT_PINS]
        native_pins = json.loads(B.FONT_PINS.read_text())["native_inputs"]
        paths = list(dict.fromkeys(srcs + [INP / rel for rel in native_pins]))
        for p in paths:
            rc["inputs"][str(p.relative_to(REPO))] = {"sha256": B.sha(p), "bytes": p.stat().st_size}
        rc["sources_before"] = {k: v["sha256"] for k, v in rc["inputs"].items()}
        if rc["sources_before"][str(BUILD_PATH.relative_to(REPO))] != BUILD_SHA:
            raise RuntimeError("loaded build.py differs from the current producer input")
        for rel, meta in native_pins.items():
            if rc["inputs"][str((INP / rel).relative_to(REPO))] != meta:
                raise RuntimeError(f"native font input {rel} differs from font-input-pins.json")
        rt = Path(a.runtime_dir); exports = {}
        for dll in B.DLLS:
            name = dll + ".dll"
            runtime_paths[name] = rt / name
            data = B.read_runtime(runtime_paths[name])
            rc["runtime_sha256_before"][name] = hashlib.sha256(data).hexdigest()
            m, names = B.pe_exports(data)
            if m != 0x8664: raise RuntimeError(f"{dll}.dll not x64")
            exports[dll + ".dll"] = set(names)
            d = out / "implib" / f"{dll}.def"
            d.write_text(f"LIBRARY {dll}.dll\nEXPORTS\n" + "".join(f"  {n}\n" for n in sorted(names)))
            B.run(f"dlltool {dll}", [B.DLLTOOL, "-m", "i386:x86-64", "-d", d, "-l", out / "implib" / f"lib{dll}.a"])
        objs = []
        for s in [F23 / "noto_provider.c", F23 / "noto_win32.c", BCRYPT / "hashes.c", FN / "shz_text_noto.c", FN / "font_link_probe.c"]:
            o = out / "obj" / (s.stem + ".o")
            B.run(f"cc {s.name}", [B.CC, *FLAGS, "-c", "-I", INP / "include", "-I", F23, "-I", BCRYPT, "-I", FN, "-I", a.font_src, s, "-o", o])
            objs.append(o)
        link = [B.CC, *FLAGS, "-nostdlib", "-Wl,--entry,ShzFontProbeStart", "-Wl,--subsystem,windows", "-Wl,--kill-at",
                "-Wl,--dynamicbase", "-Wl,--nxcompat", *objs, INP / "lib" / "libfreetype.a", INP / "lib" / "libshzwcrt.a",
                "-L", out / "implib", "-lkernel32", "-lntdll", "-luser32", "-lgdi32", "-lgcc"]
        exe = out / "font_link_probe.exe"
        # diagnostic pass: report ALL unresolved symbols (output to a throwaway file, never counted as a result)
        diagnostic_cmd = [str(c) for c in link] + ["-Wl,--unresolved-symbols=report-all", "-o", str(out / "diag.exe")]
        rc["diagnostic_command"] = diagnostic_cmd
        p = subprocess.run(diagnostic_cmd,
                           capture_output=True, text=True, timeout=B.TIMEOUT)
        und = sorted({l.split("undefined reference to ")[1].strip("`'") for l in p.stderr.splitlines() if "undefined reference to" in l})
        rc["unresolved_symbols"] = und
        (out / "diag.exe").unlink(missing_ok=True)
        B.run("link", [*link, "-o", exe])
        d = exe.read_bytes()
        mach, magic, sub, imps = B.pe_imports(d)
        by = {}
        for dll, fn in imps: by.setdefault(dll, []).append(fn)
        rc["imports"] = {k: sorted(v) for k, v in by.items()}
        rc["exe"] = {"sha256": hashlib.sha256(d).hexdigest(), "bytes": len(d), "machine": hex(mach)}
        miss = {k: sorted(f for f in v if f not in exports.get(k, set())) for k, v in by.items()}
        rc["missing_exports"] = {k: v for k, v in miss.items() if v}
        rc["dlls_without_export_table"] = [k for k in by if k not in exports]
        ok = mach == 0x8664 and not rc["missing_exports"] and not rc["dlls_without_export_table"] and len(d) < MAX
    except Exception as e:
        rc["reasons"].append(str(e).splitlines()[0]); rc["failure_detail"] = str(e)[-3000:]
    stable = verify_stability(rc, paths, runtime_paths)
    rc["commands"] = [[str(x) for x in c] for c in B.COMMANDS]
    rc["compile_and_link_succeeded"] = ok
    ok = ok and stable
    rc["link_ok_and_imports_resolve"] = ok
    rc["note"] = "link/import receipt only; PE not executed; no guest font proof"
    (out / "receipt.json").write_text(json.dumps(rc, indent=2))
    print(json.dumps({k: rc.get(k) for k in ("link_ok_and_imports_resolve", "reasons", "unresolved_symbols", "missing_exports", "dlls_without_export_table")}, indent=2))
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main())
