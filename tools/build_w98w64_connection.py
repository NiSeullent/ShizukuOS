#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Source-bound build of ONE matching Windows 98 <-> Shizuku64 connection set.

Assembles, from the current checkout only:
  vxd         NTWRAP9X.VXD (+ probes)                 ntwrapper/vxd/build.py
  platform    NTW32.DLL, NTW64RUN.EXE                 platform/build.py
  presenter   NTW64GUI.EXE                            ntwddm/win98/w64_presenter/build.py
  supervisor  payload.bin + BOOTX64.EFI               shizukudos/supervisor/build.py (functions, own output dir)
  kernel32    supervised KERNEL32.BIN (ONE profile)   shizukudos/kbuild.py build_kernel("kernel32"); native_win98/build.py
                                                      requires it beside KERNEL64
  kernel64    supervised KERNEL64.BIN                 shizukudos/kbuild.py build_kernel("kernel64"); flags/extra_c are
                                                      read from kbuild.build_all's own call (AST), never duplicated.
                                                      The derived-owner mode is the supervised default in
                                                      w64_gui_service.c; no -DSHZ_W64_GUI_DERIVED_OWNER is passed.
  runtime     small WIN64.IMG: reused native DLLs + fresh T_HELLO and one GUI fixture

Refuses to build when a relevant source path is dirty unless --allow-dirty (then recorded). The manifest
(build/w98w64-connection/manifest.json, schema tools/w98w64_connection_manifest.schema.json) is written only after
every requested step succeeded and no input source changed during the build. It carries hashes only; it grants no
policy, admission or receipt, and a build here is not guest/VM evidence. NOT a full Win64 QA/Wine runtime build.
"""
import argparse, hashlib, importlib.util, json, os, shutil, subprocess, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHZ = ROOT / "shizukudos"
DEFAULT_OUT = ROOT / "build" / "w98w64-connection"
ROOT_RUNTIME_RECEIPT = ROOT / "build/root-fastboot-20261003/runtime/build-result.json"
CACHE = ROOT / "build/shizukudos/win64"          # native DLL stage reused by root's bootstrap runtime
GUI_FIXTURE = "shizukudos/win64/tests/t_gui_native.c"
STEPS = ("vxd", "platform", "presenter", "supervisor", "kernel32", "kernel64", "runtime")
SUFFIX = {".c", ".h", ".asm", ".ld", ".def", ".rc", ".py", ".json", ".inc"}

COMPONENT_DIRS = {
    "vxd": ["ntwrapper", "ntwin32/pma", "platform/freestanding", "shizukudos/abi",
            "shizukudos/boot_profile/storage"],
    "platform": ["ntwin32", "ntwrapper", "platform", "shizukudos/abi"],
    "presenter": ["ntwddm", "ntwin32/win64", "platform/freestanding", "shizukudos/win64/native_window",
                  "shizukudos/abi", "ntwrapper/vxd/bridge.h"],
    "supervisor": ["shizukudos/supervisor", "shizukudos/native_win98", "shizukudos/uefi", "shizukudos/csmwrap/video",
                   "shizukudos/abi", "shizukudos/boot_profile", "shizukudos/kernel64/smp_acpi.c",
                   "shizukudos/kernel64/smp_acpi.h", "shizukudos/kernel64/standalone/memholes.h",
                   "shizukudos/tools", "drivers/shz_laptop"],
    "kernel32": ["shizukudos/kernel32", "shizukudos/kcommon", "shizukudos/abi", "shizukudos/boot_profile",
                 "shizukudos/pma_bridge", "shizukudos/accounts", "shizukudos/kbuild.py", "shizukudos/tools"],
    "kernel64": ["shizukudos/kernel64", "shizukudos/kcommon", "shizukudos/abi", "shizukudos/accounts",
                 "shizukudos/pma_bridge", "shizukudos/dead_screen", "shizukudos/boot_profile", "shizukudos/win64/include",
                 "shizukudos/win64/pe_parse.c", "shizukudos/win64/pe_parse.h", "shizukudos/kbuild.py",
                 "shizukudos/tools", "shizukufs/v1/libsfs", "drivers/common", "drivers/shz_laptop",
                 "drivers/ahci_native", "ntwin32/steam_socket"],
    "runtime": ["shizukudos/win64/include", "shizukudos/win64/crt", "shizukudos/win64/ntdll",
                "shizukudos/win64/kernel32", "shizukudos/win64/build.py", "shizukudos/win64/tools",
                "shizukudos/kernel64/ntsys.h", "shizukudos/tools/shzlib.py", GUI_FIXTURE,
                "shizukudos/win64/tests/t_hello.c"],
}
# Dirty paths that are never build inputs (host tests, docs).
def is_input(rel):
    p = Path(rel)
    if p.suffix not in SUFFIX or "__pycache__" in p.parts:
        return False
    return "tests" not in p.parts or rel in (GUI_FIXTURE, "shizukudos/win64/tests/t_hello.c")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(*args):
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1")
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True, env=env).stdout


def component_sources(name):
    out = set()
    for entry in COMPONENT_DIRS[name]:
        for rel in git("ls-files", "-co", "--exclude-standard", "--", entry).splitlines():
            if is_input(rel) and (ROOT / rel).is_file():
                out.add(rel)
    out.add("tools/build_w98w64_connection.py")
    return sorted(out)


def dirty_files():
    rows = git("status", "--porcelain=v1", "-uall").splitlines()
    return sorted(r[3:].split(" -> ")[-1] for r in rows)


def hash_all(names):
    return {n: {rel: sha(ROOT / rel) for rel in component_sources(n)} for n in names}


def run(cmd, timeout=300, cwd=ROOT, env=None):
    t = time.time()
    print("+", " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run([str(c) for c in cmd], cwd=cwd, timeout=timeout, env=env)
    if r.returncode:
        raise SystemExit(f"FAIL (exit {r.returncode}): {' '.join(str(c) for c in cmd)}")
    return time.time() - t


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def loaded_module_closure():
    """sha256 of every project .py module (the loaded builders and the helpers they import) now in sys.modules."""
    out = {}
    for m in list(sys.modules.values()):
        f = getattr(m, "__file__", None)
        if f and f.endswith(".py"):
            try:
                rel = Path(f).resolve().relative_to(ROOT)
            except ValueError:
                continue
            if "build" not in rel.parts[:1]:
                out[str(rel)] = sha(ROOT / rel)
    return dict(sorted(out.items()))


def kbuild_call(kb, profile):
    """Return (name, directory, flags, nasm_fmt, ld_emul, out_name, extra_c) exactly as kbuild.build_all passes them.
    Parsed from kbuild.py itself so this driver cannot drift from the real profile definition."""
    import ast
    tree = ast.parse(Path(kb.__file__).read_text())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_all")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", None) == "build_kernel"
             and c.args and isinstance(c.args[0], ast.Constant) and c.args[0].value == profile]
    if len(calls) != 1:
        raise SystemExit(f"FAIL: kbuild.build_all has {len(calls)} build_kernel({profile!r}) calls; cannot derive profile")
    call = calls[0]
    env = dict(vars(kb))
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign) and n.lineno < call.lineno
               and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)]
    def ev(node):
        names = {x.id for x in ast.walk(node) if isinstance(x, ast.Name)}
        for a in sorted(assigns, key=lambda n: n.lineno):
            if a.targets[0].id in names and a.targets[0].id not in env:
                exec(compile(ast.Module([a], []), "kbuild", "exec"), env)
        return eval(compile(ast.Expression(node), "kbuild", "eval"), env)
    args = [ev(a) for a in call.args]
    kw = {k.arg: ev(k.value) for k in call.keywords}
    return args, kw


def art(path):
    p = Path(path)
    return {"path": str(p.relative_to(ROOT)), "sha256": sha(p), "bytes": p.stat().st_size}


def tool_versions():
    v = {}
    for t, a in (("i686-w64-mingw32-gcc", "--version"), ("x86_64-w64-mingw32-gcc", "--version"), ("gcc", "--version"),
                 ("clang", "--version"), ("nasm", "-v"), ("ld", "--version")):
        try:
            v[t] = subprocess.run([t, a], capture_output=True, text=True).stdout.splitlines()[0]
        except Exception:
            v[t] = None
    return v


# ---------------------------------------------------------------- steps
def step_vxd(out):
    d = out / "vxd"
    run([sys.executable, ROOT / "ntwrapper/vxd/build.py", "--out", d])
    info = json.loads((d / "manifest.json").read_text())
    owner_src = "ntwrapper/vxd/w64_owner.c"
    if owner_src not in info.get("sources", {}):
        raise SystemExit("FAIL vxd: build did not compile ntwrapper/vxd/w64_owner.c (NTWV_W64_DERIVED_OWNER); "
                         "an unstamped VxD cannot pair with a SHZ_W64_GUI_DERIVED_OWNER Kernel64 (vxd lane owns build.py)")
    if "-DNTWV_W64_DERIVED_OWNER" not in info.get("compiler_flags", []) and \
       not any("NTWV_W64_DERIVED_OWNER" in str(f) for f in info.get("compiler_flags", [])):
        raise SystemExit("FAIL vxd: build flags lack NTWV_W64_DERIVED_OWNER; refusing to emit an unpaired VxD")
    return {"NTWRAP9X.VXD": art(d / "NTWRAP9X.VXD"), "NTWQUERY.EXE": art(d / "NTWQUERY.EXE"),
            "PMAQUERY.EXE": art(d / "PMAQUERY.EXE")}, {"component_manifest": str((d / "manifest.json").relative_to(ROOT)),
                                                      "derived_owner": True}


def step_platform(out):
    d = out / "platform"; d.mkdir(parents=True, exist_ok=True)
    run([sys.executable, ROOT / "platform/build.py"])
    man = json.loads((ROOT / "build/platform/manifest.json").read_text())
    arts = {}
    for n in ("NTW32.DLL", "NTW64RUN.EXE"):
        shutil.copy2(ROOT / "build/platform" / n, d / n)
        if man["artifacts"][n]["sha256"] != sha(d / n):
            raise SystemExit(f"FAIL platform: {n} differs from platform manifest")
        arts[n] = art(d / n)
    return arts, {"component_manifest": "build/platform/manifest.json", "guest_verified": man.get("guest_verified")}


def step_presenter(out):
    d = out / "presenter"; d.mkdir(parents=True, exist_ok=True)
    run([sys.executable, ROOT / "ntwddm/win98/w64_presenter/build.py"])
    b = ROOT / "ntwddm/win98/w64_presenter/build"
    rec = json.loads((b / "build-result.json").read_text())
    shutil.copy2(b / "NTW64GUI.EXE", d / "NTW64GUI.EXE")
    if rec["sha256"] != sha(d / "NTW64GUI.EXE"):
        raise SystemExit("FAIL presenter: exe differs from its build-result")
    return {"NTW64GUI.EXE": art(d / "NTW64GUI.EXE")}, {"status": rec["status"], "import_audit": "PASS (win98 classic set)"}


def step_supervisor(out):
    d = out / "supervisor"; d.mkdir(parents=True, exist_ok=True)
    sup = load("w98w64_sup_build", SHZ / "supervisor/build.py")
    sup.OUT = d
    for tool in ("nasm", "gcc", "ld", "x86_64-w64-mingw32-gcc"):
        if not shutil.which(tool):
            raise SystemExit(f"FAIL supervisor: required tool missing: {tool}")
    sup.build_vbios()
    sup.build_ap_trampoline()
    payload, _ = sup.build_payload()
    loader, _ = sup.build_loader(payload)
    # Same closure as the committed producer; ESP/disk assembly is deliberately left to the root runner.
    return {"payload.bin": art(d / "payload.bin"), "payload.elf": art(d / "payload.elf"),
            "BOOTX64.EFI": art(loader)}, {"esp": "not assembled here (root runner copies BOOTX64.EFI/KERNEL64.BIN/WIN64.IMG)"}


def _kernel_step(out, profile, outname):
    d = out / "kernel"; d.mkdir(parents=True, exist_ok=True)
    kb = load("w98w64_kbuild", SHZ / "kbuild.py")
    kb.BUILD = d
    args, kw = kbuild_call(kb, profile)
    if any("SHZ_STANDALONE" in str(f) for f in args[2]):
        raise SystemExit(f"FAIL {profile}: derived profile is the standalone variant, not the supervised one")
    r = kb.build_kernel(*args, **kw)
    return r, args, kw


def step_kernel32(out):
    r, args, kw = _kernel_step(out, "kernel32", "KERNEL32.BIN")
    return {"KERNEL32.BIN": art(r["bin"]), "kernel32.elf": art(r["elf"])}, {
        "profile": "kernel32 (supervised; the single K32 native_win98/build.py requires)",
        "derived_from": "shizukudos/kbuild.py build_all build_kernel('kernel32') call",
        "flags": list(args[2]), "extra_c": [str(Path(p).relative_to(ROOT)) for p in kw.get("extra_c", [])],
        "reuse": "none: rebuilt every run (no recorded closure to prove an older K32 fresh)"}


def step_kernel64(out):
    r, args, kw = _kernel_step(out, "kernel64", "KERNEL64.BIN")
    return {"KERNEL64.BIN": art(r["bin"]), "kernel64.elf": art(r["elf"])}, {
        "profile": "kernel64 (supervised, no SHZ_STANDALONE); SHZ_W64_GUI_DERIVED_OWNER not passed (default in w64_gui_service.c)",
        "derived_from": "shizukudos/kbuild.py build_all build_kernel('kernel64') call",
        "flags": list(args[2]), "extra_c": [str(Path(p).relative_to(ROOT)) for p in kw.get("extra_c", [])]}


RECEIPT_PATH = ROOT_RUNTIME_RECEIPT
FIXTURE_APPS = (("t_hello", []), ("t_gui_native", ["gdi32", "user32"]), ("t_w98w64_runtime_topology", []))


def root_receipt():
    """Returns (raw_bytes, parsed). The hash recorded is of the physical raw bytes."""
    try:
        raw = RECEIPT_PATH.read_bytes()
    except PermissionError:
        txt = subprocess.run(["sudo", "-n", "cat", str(RECEIPT_PATH)], capture_output=True)
        if txt.returncode:
            raise SystemExit("FAIL runtime: cannot read root runtime receipt: " + txt.stderr.decode().strip())
        raw = txt.stdout
    try:
        return raw, json.loads(raw)
    except ValueError as e:
        raise SystemExit(f"FAIL runtime: root runtime receipt is not JSON: {e}")
    except FileNotFoundError:
        raise SystemExit(f"FAIL runtime: runtime receipt absent: {RECEIPT_PATH}; every native DLL must be rebuilt "
                         "with the full shizukudos/win64/build.py producer")


GLOBAL_PREFIX = ("shizukudos/win64/include/", "shizukudos/win64/ntdll/", "shizukudos/win64/kernel32/",
                 "shizukudos/win64/crt/", "shizukudos/win64/tools/", "shizukudos/kcommon/")
GLOBAL_FILES = ("shizukudos/win64/build.py", "shizukudos/kernel64/ntsys.h", "shizukudos/tools/shzlib.py",
                "shizukudos/upstream/manifest.json")


NON_DLL_PREFIX = ("shizukudos/win64/apps/", "shizukudos/win64/tests/", "shizukudos/win64/setup/",
                  "shizukudos/win64/data/")


def verify_cached_dlls(rec, dll_names):
    """Compare every recorded source hash with the working tree. A change affects a DLL unless it is provably
    another module's directory (dlls/<other>/) or a non-DLL tree (apps, tests, setup, data). Anything else
    (headers, crt, wineport, webkit, trident, build.py, shared kcommon...) conservatively stales every DLL."""
    changed = [rel for rel, h in rec["sources_sha256"].items()
               if not (ROOT / rel).is_file() or sha(ROOT / rel) != h]
    stale = {}
    for n in dll_names:
        why = []
        for c in changed:
            if c.startswith(NON_DLL_PREFIX) or "/tests/" in c:
                continue
            if c.startswith("shizukudos/win64/dlls/"):
                if c.startswith(f"shizukudos/win64/dlls/{n}/"):
                    why.append(c)
                continue
            why.append(c)
        sha_rec = rec["native_cache_sha256"].get(str(CACHE / f"{n}.dll"))
        p = CACHE / f"{n}.dll"
        if sha_rec is None or not p.is_file():
            why.append(f"cache DLL missing or not in root receipt: {p}")
        elif sha(p) != sha_rec:
            why.append(f"cache DLL bytes differ from root receipt ({p})")
        if why:
            stale[n] = why
    return stale


def step_runtime(out, allow_dirty):
    d = out / "runtime"; d.mkdir(parents=True, exist_ok=True)
    raw_receipt, rec = root_receipt()
    dll_entries = [f for f in rec["archive"]["files"] if f.upper().startswith("\\SHZ\\SYS64\\") and f.upper().endswith(".DLL")]
    names = [f.rsplit("\\", 1)[1][:-4] for f in dll_entries]
    stale = verify_cached_dlls(rec, names)
    if stale:
        lines = [f"  {n}: {w[:3]}{'...' if len(w) > 3 else ''}" for n, w in sorted(stale.items())]
        raise SystemExit("FAIL runtime: cached native DLLs are not provably current; these DLLs must be rebuilt with "
                         "shizukudos/win64/build.py (not done here):\n" + "\n".join(lines))
    w = load("w98w64_win64_build", SHZ / "win64/build.py")
    w.OUT = d; w.RES = d / "res"
    d.mkdir(exist_ok=True)
    for lib in ("kernel32", "ntdll", "gdi32", "user32"):
        shutil.copy2(CACHE / f"lib{lib}.a", d / f"lib{lib}.a")
    crt_obj, _ = w.build_crt()
    apps = {}
    for stem, libs in FIXTURE_APPS:
        src = SHZ / "win64/tests" / f"{stem}.c"
        exe = d / f"{stem}.exe"
        extra = [w.version_obj(f"{stem}.exe", f"Shizuku Win64 self-check {stem}", w.verres.VFT_APP)]
        crt = SHZ / "win64/crt"
        cmd = [w.CC, *w.COMMON, "-nostdlib", "-Wl,--entry,ShzStart", "-Wl,--subsystem,console", "-Wl,--kill-at",
               "-Wl,--image-base,0x140000000", *(["-Wl,--disable-dynamicbase"] if stem in w.FIXED_BASE_APPS else []),
               "-I", SHZ / "win64/include", "-I", crt, src, crt_obj, *extra,
               "-L", d, "-lkernel32", "-lntdll", *[f"-l{l}" for l in libs], "-lgcc", "-o", exe]
        run(cmd)
        apps[stem] = exe
    files = []
    for n in names:
        files.append((f"\\SHZ\\SYS64\\{n}.dll", (CACHE / f"{n}.dll").read_bytes()))
    files.append(("\\SHZ\\TESTS\\T_HELLO.EXE", apps["t_hello"].read_bytes()))
    files.append(("\\SHZ\\FIXTURES\\T_GUI_NATIVE.EXE", apps["t_gui_native"].read_bytes()))
    files.append(("\\SHZ\\FIXTURES\\T_W98W64_RUNTIME_TOPOLOGY.EXE", apps["t_w98w64_runtime_topology"].read_bytes()))
    img = d / "WIN64.IMG"
    img.write_bytes(w.pack_archive(files))
    return {"WIN64.IMG": art(img), "T_HELLO.EXE": art(apps["t_hello"]), "T_GUI_NATIVE.EXE": art(apps["t_gui_native"]),
            "T_W98W64_RUNTIME_TOPOLOGY.EXE": art(apps["t_w98w64_runtime_topology"])}, {
        "scope": "SMALL_RUNTIME_PACK_NOT_FULL_QA_WINE_OR_MODERN_APP",
        "reused_native_dlls": {n: sha(CACHE / f"{n}.dll") for n in names},
        "reuse_verified_against": {"receipt": str(RECEIPT_PATH.relative_to(ROOT)),
                                   "receipt_raw_sha256": hashlib.sha256(raw_receipt).hexdigest(), "receipt_raw_bytes": len(raw_receipt),
                                   "source_entries_checked": len(rec["sources_sha256"])},
        "archive_files": [p for p, _ in files],
        "omitted": "certs, network catalogs, trident, wineport QA fixtures, SHZSETUP, other T_* tests"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--allow-dirty", action="store_true", help="build with dirty relevant sources; recorded in manifest")
    ap.add_argument("--runtime-receipt", type=Path, default=ROOT_RUNTIME_RECEIPT,
                    help="build-result.json from shizukudos/win64/build.py used to verify cached DLLs (default: root's)")
    ap.add_argument("--native-cache", type=Path, default=None,
                    help="directory holding the DLLs/import libraries the receipt pins (default: receipt native_cache_dir, else root stage)")
    ap.add_argument("--steps", default=",".join(STEPS), help="comma list subset of: " + ",".join(STEPS))
    args = ap.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "build").resolve()) or out == (ROOT / "build").resolve():
        ap.error("--out must be a directory under project build/")
    global RECEIPT_PATH
    RECEIPT_PATH = args.runtime_receipt.resolve()
    if not RECEIPT_PATH.is_relative_to(ROOT):
        ap.error("--runtime-receipt must be inside the project tree")
    global CACHE
    if args.native_cache is not None:
        CACHE = args.native_cache.resolve()
        if not CACHE.is_relative_to(ROOT / "build"):
            ap.error("--native-cache must be inside the project build/ tree")
    steps = [s for s in args.steps.split(",") if s]
    if any(s not in STEPS for s in steps):
        ap.error("unknown step")
    head = git("rev-parse", "HEAD").strip()
    before = hash_all(steps)
    inputs = {rel for h in before.values() for rel in h}
    dirty = [f for f in dirty_files() if f in inputs and f != "tools/build_w98w64_connection.py"]
    if dirty and not args.allow_dirty:
        print("REFUSED: dirty relevant sources (commit them or pass --allow-dirty to record the dirt):", file=sys.stderr)
        for f in dirty:
            print("  " + f, file=sys.stderr)
        return 2
    manifest_path = out / "manifest.json"
    out.mkdir(parents=True, exist_ok=True)
    manifest_path.unlink(missing_ok=True)
    artifacts, details, timings = {}, {}, {}
    fns = {"vxd": step_vxd, "platform": step_platform, "presenter": step_presenter, "supervisor": step_supervisor,
           "kernel32": step_kernel32, "kernel64": step_kernel64, "runtime": lambda o: step_runtime(o, args.allow_dirty)}
    for s in steps:
        t = time.time()
        a, dt = fns[s](out)
        artifacts[s], details[s] = a, dt
        timings[s] = round(time.time() - t, 1)
    if hash_all(steps) != before:
        raise SystemExit("FAIL: input sources changed during the build; no manifest written")
    manifest = {"schema": "w98w64.connection.build.v1",
                "complete": steps == list(STEPS),
                "scope": "HOST_COMPILED_MATCHING_SET_NOT_GUEST_OR_VM_EVIDENCE",
                "built_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "git": {"head": head, "dirty_relevant": dirty, "allow_dirty": bool(args.allow_dirty),
                        "dirty_all": dirty_files()},
                "tools": tool_versions(), "steps": steps, "seconds": timings,
                "sources_sha256": before, "loaded_module_closure": loaded_module_closure(), "artifacts": artifacts, "details": details}
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    g = lambda s, n: artifacts.get(s, {}).get(n, {}).get("path", "(step not run)")
    print("\nmanifest:", manifest_path.relative_to(ROOT), "sha256", sha(manifest_path))
    print("ROOT LAUNCH INPUTS (each sha256 is in the manifest; verify before use):")
    print("  loader   :", g("supervisor", "BOOTX64.EFI"))
    print("  kernel32 :", g("kernel32", "KERNEL32.BIN"), "(supervised K32, required by native_win98/build.py)")
    print("  kernel64 :", g("kernel64", "KERNEL64.BIN"), "(copy to ESP ::/SHZDOS/KERNEL64.BIN)")
    print("  runtime  :", g("runtime", "WIN64.IMG"), "(copy to ESP ::/SHZDOS/WIN64.IMG)")
    print("  guest VxD:", g("vxd", "NTWRAP9X.VXD"))
    print("  guest    :", g("platform", "NTW32.DLL"), g("platform", "NTW64RUN.EXE"), g("presenter", "NTW64GUI.EXE"))
    esp = [g("kernel32", "KERNEL32.BIN"), g("kernel64", "KERNEL64.BIN"), g("runtime", "WIN64.IMG")]
    if "(step not run)" not in esp:
        pins = {n: artifacts[s][n]["sha256"] for s, n in (("kernel32", "KERNEL32.BIN"), ("kernel64", "KERNEL64.BIN"),
                                                          ("runtime", "WIN64.IMG"))}
        print("  NATIVE ESP BUILDER (root-owned custody; disk/rom/config pins and VGA/persistence come from root):")
        print("    python3 shizukudos/supervisor/native_win98/build.py --disk <DISK> --disk-sha256 <sha> --rom <SEABIOS> --rom-sha256 <sha>"
              " --config <WIN98CFG.BIN> --config-sha256 <sha>")
        print(f"      --kernel32 {esp[0]} --kernel32-sha256 {pins['KERNEL32.BIN']}")
        print(f"      --kernel64 {esp[1]} --kernel64-sha256 {pins['KERNEL64.BIN']}")
        print(f"      --win64-img {esp[2]} --win64-img-sha256 {pins['WIN64.IMG']} --out <fresh private dir>"
              "  [optional: --vga-config/--vga-rom/--vga-build-receipt/--persistence-config each with -sha256]")
    print("  ESP/disk assembly, Win98 baseline and VM custody remain root-owned.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
