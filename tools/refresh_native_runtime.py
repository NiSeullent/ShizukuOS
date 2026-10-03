#!/usr/bin/env python3
"""Fresh native Win64 runtime producer for the Windows98 -> Shizuku64 connection (batch 11).

Uses the real shizukudos/win64/build.py APIs (build_ntdll, build_kernel32, build_modules, build_crt, version_obj,
pack_archive) from the CURRENT tree, directing output to <out>/native (DLLs + import libraries) and <out>/runtime
(CRT, PE64 fixtures, WIN64.IMG, build-result.json). It is NOT the full Win64 QA/Wine build and does not execute
anything. build-result.json uses the schema read by tools/build_w98w64_connection.py --runtime-receipt
(archive, sources_sha256, native_cache_sha256, native_cache_dir). Any source change during the run, any lost export,
or a missing new kernel32 export aborts without a receipt.
"""
import argparse, fcntl, hashlib, importlib.util, json, os, re, signal, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / ".codex/compile.lock"
NEW_K32 = ["SetThreadStackGuarantee", "GetNumaHighestNodeNumber", "GetNumaNodeProcessorMaskEx",
           "GetProcessGroupAffinity", "GetLargePageMinimum"]
FIXTURES = (("t_hello", []), ("t_gui_native", ["gdi32", "user32"]), ("t_w98w64_runtime_topology", []))
COMPONENT_TIMEOUT = 300


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def locked(label, fn, log):
    """One flock acquisition per component, never nested; <=300 s each."""
    with open(LOCK, "a+") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        t0 = time.monotonic()

        def boom(*_):
            raise TimeoutError(f"component {label} exceeded {COMPONENT_TIMEOUT} s")
        old = signal.signal(signal.SIGALRM, boom)
        signal.alarm(COMPONENT_TIMEOUT)
        try:
            return fn()
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old)
            log.append({"component": label, "seconds": round(time.monotonic() - t0, 3)})
            print(f"[{label}] {time.monotonic() - t0:.1f}s", flush=True)


def def_exports(path):
    out, seen = set(), False
    for line in Path(path).read_text().splitlines():
        if line.strip() == "EXPORTS":
            seen = True
        elif seen and line.strip():
            out.add(line.split("=")[0].split("@")[0].strip())
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=ROOT / "build/native-runtime-refresh-b11")
    ap.add_argument("--old-kernel32-def", type=Path, default=ROOT / "build/shizukudos/win64/kernel32.def",
                    help="read-only comparison export list (not a source)")
    a = ap.parse_args()
    out = a.out.resolve()
    if not out.is_relative_to((ROOT / "build").resolve()) or out == (ROOT / "build").resolve():
        ap.error("--out must be under build/")
    sys.path[:0] = [str(ROOT / "shizukudos"), str(ROOT / "shizukudos/tools")]
    spec = importlib.util.spec_from_file_location("b11_win64_build", ROOT / "shizukudos/win64/build.py")
    r = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(r)
    native, rt = out / "native", out / "runtime"
    native.mkdir(parents=True, exist_ok=True)
    rt.mkdir(parents=True, exist_ok=True)
    start = time.monotonic()
    paths = r.runtime_source_paths()
    before = {str(p.relative_to(ROOT)): sha(p) for p in paths}
    logs, commands = [], []
    r.OUT, r.RES = native, native / "res"
    ntdll, nc, nn = locked("ntdll", r.build_ntdll, logs)
    commands.append([str(x) for x in nc])
    k32, kc, kn = locked("kernel32", lambda: r.build_kernel32(nn), logs)
    commands.append([str(x) for x in kc])
    missing = [n for n in NEW_K32 if n not in kn]
    if missing:
        raise SystemExit(f"FAIL: kernel32 lacks new exports {missing}")
    old = def_exports(a.old_kernel32_def) if a.old_kernel32_def.is_file() else None
    new_defs = def_exports(native / "kernel32.def")
    lost = sorted(old - new_defs) if old is not None else None
    if lost:
        raise SystemExit(f"FAIL: kernel32 lost exports vs old set: {lost}")
    mods = locked("modules", r.build_modules, logs)
    commands.extend([[str(x) for x in m["cmd"]] for m in mods.values()])
    dlls = [ntdll, k32, *[m["dll"] for m in mods.values()]]
    libs = [native / "libntdll.a", native / "libkernel32.a", *[native / f"lib{n}.a" for n in mods]]
    cache_paths = dlls + libs
    pins = {str(p): sha(p) for p in cache_paths}
    exports = {"ntdll": sorted(def_exports(native / "ntdll.def")), "kernel32": sorted(new_defs),
               **{n: sorted(def_exports(native / f"{n}.def")) for n in mods}}
    r.OUT, r.RES = rt, rt / "res"
    crt, cc = locked("crt", r.build_crt, logs)
    commands.append([str(x) for x in cc])
    apps = {}
    for name, extra in FIXTURES:
        def build(name=name, extra=extra):
            src = r.W64 / "tests" / f"{name}.c"
            exe = rt / f"{name}.exe"
            res = r.version_obj(f"{name}.exe", f"Shizuku64 native Windows98 connection {name}", r.verres.VFT_APP)
            cmd = [r.CC, *r.COMMON, "-nostdlib", "-Wl,--entry,ShzStart", "-Wl,--subsystem,console", "-Wl,--kill-at",
                   "-Wl,--image-base,0x140000000",
                   *(["-Wl,--disable-dynamicbase"] if name in r.FIXED_BASE_APPS else []),
                   "-I", r.W64 / "include", "-I", r.W64 / "crt", src, crt, res, "-L", native, "-lkernel32", "-lntdll",
                   *[f"-l{l}" for l in extra], "-lgcc", "-o", exe]
            r.run(cmd)
            return exe, [str(x) for x in cmd]
        exe, cmd = locked(name, build, logs)
        apps[name] = exe
        commands.append(cmd)
    files = [(f"\\SHZ\\SYS64\\{p.name}", p.read_bytes()) for p in dlls]
    files += [("\\SHZ\\TESTS\\T_HELLO.EXE", apps["t_hello"].read_bytes()),
              ("\\SHZ\\FIXTURES\\T_GUI_NATIVE.EXE", apps["t_gui_native"].read_bytes()),
              ("\\SHZ\\FIXTURES\\T_W98W64_RUNTIME_TOPOLOGY.EXE", apps["t_w98w64_runtime_topology"].read_bytes())]
    img = rt / "WIN64.IMG"
    img.write_bytes(r.pack_archive(files))
    after = {str(p.relative_to(ROOT)): sha(p) for p in paths}
    if after != before:
        raise SystemExit("FAIL: runtime source changed during compilation: " +
                         str(sorted(k for k in after if after.get(k) != before.get(k))))
    if {str(p): sha(p) for p in cache_paths} != pins:
        raise SystemExit("FAIL: compiled DLL/import library changed during assembly")
    physical = {str(p.relative_to(ROOT)): {"sha256": sha(p), "bytes": p.stat().st_size}
                for p in [*cache_paths, *apps.values(), img]}
    rec = {"scope": "FRESH_NATIVE_DLL_AND_PE64_FIXTURE_BUILD_NOT_FULL_QA_WINE_MODERN_APP_OR_VM_ACCEPTANCE",
           "producer": "tools/refresh_native_runtime.py", "git_head": subprocess.run(
               ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True,
               env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"}).stdout.strip(),
           "built_utc": r.shzlib.utc_now(), "sources_sha256": before, "sources_sha256_after": after,
           "source_before_after_equal": True,
           "native_cache_dir": str(native.relative_to(ROOT)), "native_cache_sha256": pins,
           "native_cache_provenance": "every DLL and import library rebuilt in this run by build.py APIs; no cached waiver",
           "archive": {"path": str(img), "sha256": sha(img), "bytes": img.stat().st_size, "files": [n for n, _ in files]},
           "physical_sha256": physical, "exports": {k: len(v) for k, v in exports.items()},
           "kernel32_new_exports_present": NEW_K32,
           "kernel32_old_export_comparison": None if old is None else {"old_count": len(old), "lost": lost},
           "compiler_commands": commands, "component_seconds": logs, "full_runtime_build_pass": False,
           "native_apps_verified": False, "seconds": round(time.monotonic() - start, 3)}
    (rt / "exports.json").write_text(json.dumps(exports, indent=1) + "\n")
    (rt / "build-result.json").write_text(json.dumps(rec, indent=2) + "\n")
    print(json.dumps({"status": "FRESH_NATIVE_RUNTIME_BUILT_NOT_EXECUTED", "dlls": len(dlls),
                      "archive_sha256": rec["archive"]["sha256"], "seconds": rec["seconds"]}))


if __name__ == "__main__":
    main()
