#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build WebKit's JavaScriptCore shell (jsc.exe) for the ShizukuDOS Kernel64 Win64 runtime (docs/shizukudos10/WEBKIT.md).

Toolchain: the WebKit toolchain of webkit/deps/toolchain.py (clang 18 for x86_64-w64-mingw32, a mingw-w64 v13 sysroot
built for the UCRT, libc++/libc++abi/libunwind 18 as DLLs), shared with WebCore (agent W3). build.py runs it when its
output is missing.

Inputs
  build/upstream/webkit, build/upstream/icu   pinned upstream trees (shizukudos/upstream/manifest.json), fetched shallow
                                              (and sparse where the manifest says so) if absent; never edited except by
                                              the patches below
  webkit/patches/*.patch                      local changes to the WebKit tree, applied in name order after the touched
                                              files are restored to the pinned commit (so a rebuild starts clean)
  build/shizukudos/win64                      the Shizuku runtime (win64/build.py): every import of the result is
                                              checked against its DLLs' exports (webkit/importcheck.py)

Outputs (build/shizukudos/win64/webkit/)
  icu-host/, icu-win64/install/  ICU (manifest pin): host tools, then static Win64 libraries with the full data
  jsc-<config>/                  the CMake/Ninja tree (PORT=JSCOnly)
  out/                           jsc.exe, wkbatch.exe and the runtime DLLs they need (libc++.dll, libunwind.dll):
                                 what tests/run_k64_webkit.py copies to the guest's D:\\WK
  build-result.json              commands, versions, patch list, import check, licence table

Configurations (--config)
  cloop   M1: ENABLE_JIT=OFF, ENABLE_C_LOOP=ON, no WebAssembly, static JavaScriptCore (default)
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "tools"))
sys.path.insert(0, str(HERE))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, run, sha256_file  # noqa: E402
import importcheck  # noqa: E402
import licscan  # noqa: E402

W64OUT = BUILD / "win64"
OUT = W64OUT / "webkit"
UPSTREAM = REPO / "build" / "upstream"
MANIFEST = REPO / "shizukudos" / "upstream" / "manifest.json"
TC = BUILD / "webkit" / "toolchain"                    # deps/toolchain.py output
TRIPLE = "x86_64-w64-mingw32"
CC = TC / "bin" / f"{TRIPLE}-clang"
CXX = TC / "bin" / f"{TRIPLE}-clang++"
RUNTIME_DLLS = ["libc++.dll", "libunwind.dll"]         # in the sysroot's bin/
JOBS = max(1, int(os.environ.get("SHZ_WEBKIT_JOBS", str(os.cpu_count() or 2))))

CONFIGS = {
    "cloop": ["-DENABLE_JIT=OFF", "-DENABLE_C_LOOP=ON", "-DENABLE_WEBASSEMBLY=OFF", "-DENABLE_SAMPLING_PROFILER=OFF",
              "-DENABLE_STATIC_JSC=ON"],
}


# ---------------------------------------------------------------- upstream trees
def spec(name):
    return json.loads(MANIFEST.read_text())["upstreams"][name]


def git(tree, *args, check=True):
    r = subprocess.run(["git", "-C", str(tree), *args], capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(f"git {' '.join(args)} in {tree}: {r.stderr.strip()}")
    return r.stdout.strip()


def ensure_tree(name):
    """Shallow fetch of the pinned commit into build/upstream/<name> (sparse when the manifest lists sparse_paths, which
    are re-applied when they changed); a tree at another commit is fetched again. Verifies HEAD."""
    s = spec(name)
    dest = UPSTREAM / name
    sparse = s.get("sparse_paths")
    if (dest / ".git").exists() and git(dest, "rev-parse", "HEAD", check=False) != s["commit"]:
        shutil.rmtree(dest)
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        git(dest, "init", "-q")
        git(dest, "remote", "add", "origin", s["repository"])
        run(["git", "-C", dest, "fetch", "-q", "--depth", "1", *(["--filter=blob:none"] if sparse else []), "origin",
             s["commit"]], timeout=3600)
        if sparse:
            git(dest, "sparse-checkout", "set", "--no-cone", *sparse)
        git(dest, "checkout", "-q", "FETCH_HEAD")
    elif sparse and git(dest, "sparse-checkout", "list", check=False).splitlines() != sparse:
        git(dest, "sparse-checkout", "set", "--no-cone", *sparse)
    head = git(dest, "rev-parse", "HEAD")
    if head != s["commit"]:
        raise SystemExit(f"{name}: pinned {s['commit']} but {dest} is at {head}")
    return dest


def patch_targets(patch):
    return sorted({l[6:].split("\t")[0].strip() for l in patch.read_text(errors="replace").splitlines()
                   if l.startswith("+++ b/")})


def apply_patches(tree):
    """Restores every file a patch touches (and any file an earlier build patched) to the pinned commit, then applies
    webkit/patches/*.patch in name order. The manifest's `patches` list must name exactly these files."""
    patches = sorted((HERE / "patches").glob("*.patch"))
    listed = sorted(REPO / p for p in spec("webkit").get("patches", []))
    if listed != patches:
        raise SystemExit("manifest.json webkit.patches does not list exactly shizukudos/win64/webkit/patches/*.patch:\n"
                         f"  listed {[str(p.relative_to(REPO)) for p in listed]}\n"
                         f"  found  {[str(p.relative_to(REPO)) for p in patches]}")
    dirty = [l[3:] for l in git(tree, "status", "--porcelain", "--untracked-files=no").splitlines() if l]
    targets = sorted({t for p in patches for t in patch_targets(p)} | set(dirty))
    tracked = [t for t in targets if git(tree, "ls-files", "--", t)]
    if tracked:
        git(tree, "checkout", "HEAD", "--", *tracked)
    for t in targets:
        if t not in tracked and (tree / t).exists():
            (tree / t).unlink()                           # a file created by a patch
    for p in patches:
        r = subprocess.run(["git", "-C", str(tree), "apply", "--whitespace=nowarn", str(p)], capture_output=True, text=True)
        if r.returncode:
            raise SystemExit(f"{p.name} does not apply to the pinned WebKit tree:\n{r.stderr}")
    return [str(p.relative_to(REPO)) for p in patches]


# ---------------------------------------------------------------- toolchain and ICU
def ensure_toolchain():
    if not (CXX.exists() and (TC / "toolchain.cmake").exists() and all((TC / TRIPLE / "bin" / d).exists() for d in RUNTIME_DLLS)):
        run([sys.executable, HERE / "deps" / "toolchain.py"], timeout=3 * 3600)
    return json.loads((TC / "toolchain.json").read_text()) if (TC / "toolchain.json").exists() else {}


def build_icu(icu_tree, log):
    """Host build (data tools), then the static Win64 libraries with the full data archive. Cached by a stamp."""
    src = icu_tree / "icu4c" / "source"
    host, cross = OUT / "icu-host", OUT / "icu-win64"
    prefix = cross / "install"
    stamp = prefix / ".shz-stamp"
    key = json.dumps({"commit": spec("icu")["commit"], "toolchain": sha256_file(CXX), "v": 4})
    if stamp.exists() and stamp.read_text() == key:
        return prefix
    common = ["--disable-tests", "--disable-samples", "--disable-extras", "--disable-icuio", "--disable-layoutex"]
    hstamp = host / ".shz-commit"
    if not (host / "bin" / "icupkg").exists() or not hstamp.exists() or hstamp.read_text() != spec("icu")["commit"]:
        shutil.rmtree(host, ignore_errors=True)
        host.mkdir(parents=True)
        run([src / "configure", *common], cwd=host, timeout=600, capture=True)
        run(["make", f"-j{JOBS}"], cwd=host, timeout=3600, capture=True)
        hstamp.write_text(spec("icu")["commit"])
    shutil.rmtree(cross, ignore_errors=True)
    cross.mkdir(parents=True)
    env = dict(os.environ, CC=str(CC), CXX=str(CXX), AR="llvm-ar", RANLIB="llvm-ranlib", CFLAGS="-O2",
               CXXFLAGS="-O2 -std=c++17")
    cfg = [src / "configure", f"--host={TRIPLE}", f"--with-cross-build={host}", "--enable-static", "--disable-shared",
           "--with-data-packaging=static", "--disable-tools", f"--prefix={prefix}", *common]
    run(cfg, cwd=cross, env=env, timeout=600, capture=True)
    run(["make", f"-j{JOBS}"], cwd=cross, env=env, timeout=7200, capture=True)
    # `make install` copies the headers and libsicuuc/libsicuin; its data step installs the stub and then fails on
    # the absent bin/ directory, so the three static libraries are placed by hand under the names CMake's FindICU
    # looks for on Windows (icuuc, icuin, icudt).
    run(["make", "-C", "common", "install"], cwd=cross, env=env, capture=True)
    run(["make", "-C", "i18n", "install"], cwd=cross, env=env, capture=True)
    lib = prefix / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    for src_name, dst in (("libsicuuc.a", "libicuuc.a"), ("libsicuin.a", "libicuin.a"), ("sicudt.a", "libicudt.a")):
        shutil.copyfile(cross / "lib" / src_name, lib / dst)
    log["icu_configure"] = [str(x) for x in cfg]
    stamp.write_text(key)
    return prefix


# WebKit names some Windows libraries in mixed case (-lDbgHelp, -lWinmm); lld on Linux searches case-sensitively.
# DbgHelp: WTF calls it only in debug builds (wtf/win/DbgHelperWin.cpp) and the Shizuku runtime has no dbghelp.dll;
# the import check proves nothing is imported from it.
LIB_ALIASES = {"libDbgHelp.a": "libdbghelp.a", "libWinmm.a": "libwinmm.a"}


def lib_aliases():
    d = OUT / "libalias"
    d.mkdir(parents=True, exist_ok=True)
    for name, target in LIB_ALIASES.items():
        link = d / name
        if link.is_symlink() or link.exists():
            link.unlink()
        link.symlink_to(TC / TRIPLE / "lib" / target)
    return d


# ---------------------------------------------------------------- WebKit
def configure_jsc(tree, icu, config, log):
    bdir = OUT / f"jsc-{config}"
    cache = bdir / "CMakeCache.txt"
    if cache.exists() and str(CXX) not in cache.read_text(errors="replace"):
        shutil.rmtree(bdir)                                       # a tree configured with another compiler
    bdir.mkdir(parents=True, exist_ok=True)
    cmd = ["cmake", "-G", "Ninja", "-S", tree, "-B", bdir, f"-DCMAKE_TOOLCHAIN_FILE={HERE / 'toolchain-mingw-clang.cmake'}",
           f"-DSHZ_WEBKIT_TOOLCHAIN={TC / 'toolchain.cmake'}", f"-DSHZ_ICU_PREFIX={icu}", f"-DSHZ_LIBALIAS={lib_aliases()}",
           "-DCMAKE_BUILD_TYPE=Release", "-DPORT=JSCOnly", "-DDEVELOPER_MODE=OFF", "-DUSE_SYSTEM_UNIFDEF=ON",
           "-DENABLE_API_TESTS=OFF", "-DENABLE_REMOTE_INSPECTOR=OFF", "-DENABLE_TOOLS=OFF", f"-DICU_ROOT={icu}",
           "-DCMAKE_C_FLAGS=-DU_STATIC_IMPLEMENTATION", "-DCMAKE_CXX_FLAGS=-DU_STATIC_IMPLEMENTATION", *CONFIGS[config]]
    run(cmd, timeout=900)
    log["cmake"] = [str(x) for x in cmd]
    return bdir


def build_wkbatch():
    exe = OUT / "wkbatch.exe"
    cmd = [CC, "-O2", "-Wall", "-Werror", HERE / "tests" / "wkbatch.c", "-o", exe]
    run(cmd)
    return exe, cmd


def build_probes():
    """The toolchain experiments of WEBKIT.md, rebuilt from tests/probe_* with the WebKit toolchain: out-probes/."""
    pdir = OUT / "out-probes"
    pdir.mkdir(parents=True, exist_ok=True)
    tests = HERE / "tests"
    cmds = {
        "probe_libcxx": [CXX, "-O2", "-std=c++20", tests / "probe_cxx.cpp"],
        "probe_tls": [CC, "-O1", tests / "probe_tls.c"],
        "probe_seh": [CC, "-O1", "-fms-extensions", tests / "probe_seh.c"],
    }
    out = {}
    for name, cmd in cmds.items():
        exe = pdir / f"{name}.exe"
        run([*cmd, "-o", exe])
        out[name] = {"exe": str(exe), "sha256": sha256_file(exe), "command": [str(x) for x in cmd]}
    for d in RUNTIME_DLLS:
        shutil.copyfile(TC / TRIPLE / "bin" / d, pdir / d)
    report, _ = importcheck.check([v["exe"] for v in out.values()] + [str(pdir / d) for d in RUNTIME_DLLS])
    for name in out:
        out[name]["missing_imports"] = report[f"{name}.exe"]["missing"]
    shzlib.write_json(pdir / "probes.json", out)
    print(json.dumps({n: {"missing_imports": v["missing_imports"]} for n, v in out.items()}, indent=2))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", choices=sorted(CONFIGS), default="cloop")
    ap.add_argument("--target", default="jsc", help="ninja target (default jsc)")
    ap.add_argument("--probes", action="store_true", help="only build the toolchain probes (out-probes/)")
    args = ap.parse_args()
    for tool in ("clang", "clang++", "ld.lld", "llvm-ar", "cmake", "ninja", "ruby", "perl", "gperf", "unifdef"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    for f in ("kernel32.dll", "ucrtbase.dll", "ntdll.dll"):
        if not (W64OUT / f).exists():
            raise SystemExit(f"missing {W64OUT / f}: run shizukudos/win64/build.py first")
    OUT.mkdir(parents=True, exist_ok=True)
    tc = ensure_toolchain()
    if args.probes:
        build_probes()
        return
    log = {"built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "config": args.config}
    t0 = time.time()
    wk, icu_tree = ensure_tree("webkit"), ensure_tree("icu")
    log["patches"] = apply_patches(wk)
    icu = build_icu(icu_tree, log)
    bdir = configure_jsc(wk, icu, args.config, log)
    run(["ninja", "-C", bdir, f"-j{JOBS}", args.target], timeout=6 * 3600)
    dest = OUT / "out"
    dest.mkdir(exist_ok=True)
    for old in dest.glob("*"):
        old.unlink()
    for p in sorted(set(bdir.glob("bin/*.exe")) | set(bdir.glob("bin/*.dll"))):
        shutil.copyfile(p, dest / p.name)
    for d in RUNTIME_DLLS:
        shutil.copyfile(TC / TRIPLE / "bin" / d, dest / d)
    batch, batch_cmd = build_wkbatch()
    shutil.copyfile(batch, dest / batch.name)
    images = sorted(dest.glob("*.exe")) + sorted(dest.glob("*.dll"))
    report, bad = importcheck.check([str(p) for p in images])
    log.update({
        "seconds": round(time.time() - t0, 1),
        "toolchain": {"deps/toolchain.py": tc, "cmake": shzlib.tool_version("cmake"), "ninja": shzlib.tool_version("ninja")},
        "upstreams": {n: spec(n)["commit"] for n in ("webkit", "icu")},
        "outputs": {p.name: {"sha256": sha256_file(p), "bytes": p.stat().st_size} for p in images},
        "wkbatch": [str(x) for x in batch_cmd],
        "import_check": report,
        "licences": licscan.scan(wk),
    })
    shzlib.write_json(OUT / "build-result.json", log)
    print(json.dumps({"outputs": log["outputs"], "import_check": {k: v["missing"] or "all resolve" for k, v in report.items()}},
                     indent=2))
    if bad:
        raise SystemExit("imports the Shizuku runtime does not export (see build-result.json import_check)")


if __name__ == "__main__":
    main()
