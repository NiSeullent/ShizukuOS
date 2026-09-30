#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build WebKit's JavaScriptCore shell (jsc.exe) for the ShizukuDOS Kernel64 Win64 runtime (docs/shizukudos10/WEBKIT.md).

Inputs
  build/upstream/webkit, build/upstream/icu   pinned upstream trees (shizukudos/upstream/manifest.json), fetched shallow
                                              and sparse if absent; never edited except by the patches below
  webkit/patches/*.patch                      local changes to the WebKit tree, applied in name order after the touched
                                              files are restored to the pinned commit (so a rebuild starts clean)
  webkit/toolchain-mingw-clang.cmake          clang --target=x86_64-w64-windows-gnu (WEBKIT.md "Toolchain")
  webkit/compat/*.c                           link glue between mingw-w64 and the Shizuku runtime
  build/shizukudos/win64                      the Shizuku runtime (win64/build.py): its import libraries are searched
                                              first and every import of the result is checked against its DLLs' exports

Outputs (build/shizukudos/win64/webkit/)
  icu-host/, icu-win64/install/  ICU 78.3: host tools, then static Win64 libraries with the full data
  jsc-<config>/                  the CMake/Ninja tree (PORT=JSCOnly)
  out/jsc.exe, out/wkbatch.exe   what tests/run_k64_webkit.py copies to the guest's D:\\WK
  build-result.json              commands, versions, patch list, import check

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
TARGET = "x86_64-w64-windows-gnu"
UCRT_DEFS = ["-D_UCRT", "-D__MSVCRT_VERSION__=0xE00", "-D_WIN32_WINNT=0x0A00"]
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
    """Shallow, sparse fetch of the pinned commit into build/upstream/<name>; re-applies the manifest's sparse paths
    when they changed and verifies HEAD (as wineport/build.py does for its trees)."""
    s = spec(name)
    dest = UPSTREAM / name
    if not (dest / ".git").exists():
        dest.mkdir(parents=True, exist_ok=True)
        git(dest, "init", "-q")
        git(dest, "remote", "add", "origin", s["repository"])
        run(["git", "-C", dest, "fetch", "-q", "--depth", "1", "--filter=blob:none", "origin", s["commit"]], timeout=3600)
        git(dest, "sparse-checkout", "set", "--no-cone", *s["sparse_paths"])
        git(dest, "checkout", "-q", "FETCH_HEAD")
    elif git(dest, "sparse-checkout", "list", check=False).splitlines() != s["sparse_paths"]:
        git(dest, "sparse-checkout", "set", "--no-cone", *s["sparse_paths"])
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


# ---------------------------------------------------------------- ICU
def build_icu(icu_tree, log):
    """Host build (data tools), then the static Win64 libraries with the full data archive. Cached by a stamp."""
    src = icu_tree / "icu4c" / "source"
    host, cross = OUT / "icu-host", OUT / "icu-win64"
    prefix = cross / "install"
    stamp = prefix / ".shz-stamp"
    key = json.dumps({"commit": spec("icu")["commit"], "defs": UCRT_DEFS, "v": 2})
    if stamp.exists() and stamp.read_text() == key:
        return prefix
    common = ["--disable-tests", "--disable-samples", "--disable-extras", "--disable-icuio", "--disable-layoutex"]
    if not (host / "bin" / "icupkg").exists():
        host.mkdir(parents=True, exist_ok=True)
        run([src / "configure", *common], cwd=host, timeout=600, capture=True)
        run(["make", f"-j{JOBS}"], cwd=host, timeout=3600, capture=True)
    shutil.rmtree(cross, ignore_errors=True)
    cross.mkdir(parents=True)
    env = dict(os.environ, CC=f"clang --target={TARGET}", CXX=f"clang++ --target={TARGET}", AR="llvm-ar", RANLIB="llvm-ranlib",
               CPPFLAGS=" ".join(UCRT_DEFS), CFLAGS="-O2", CXXFLAGS="-O2 -std=c++17")
    cfg = [src / "configure", f"--host={TARGET.replace('windows-gnu', 'mingw32')}", f"--with-cross-build={host}",
           "--enable-static", "--disable-shared", "--with-data-packaging=static", "--disable-tools", f"--prefix={prefix}", *common]
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


# ---------------------------------------------------------------- the Shizuku link glue
def build_compat():
    obj = OUT / "shzwk_compat.o"
    run(["clang", f"--target={TARGET}", "-O2", "-Wall", "-Werror", *UCRT_DEFS, "-c", HERE / "compat" / "shzwk_compat.c",
         "-o", obj])
    return obj


# mingw-w64's UCRT import library, by path: besides the ucrtbase imports it carries the msvcrt-style entry points
# (__getmainargs, _onexit, __set_app_type, ...) that crt2.o and libmingw32 were compiled against. `-lucrtbase` would
# find the Shizuku libucrtbase.a first (plain dlltool imports, without those objects). A literal -lucrtbase still follows:
# without one, clang's MinGW driver appends -lmsvcrt.
MINGW_UCRT = "/usr/x86_64-w64-mingw32/lib/libucrtbase.a"


def shz_libs(*names):
    """Shizuku import libraries, by path, so they bind ahead of mingw-w64's same-named ones."""
    return [str(W64OUT / f"lib{n}.a") for n in names]


# ---------------------------------------------------------------- WebKit
def configure_jsc(tree, icu, config, compat, log):
    bdir = OUT / f"jsc-{config}"
    bdir.mkdir(parents=True, exist_ok=True)
    cflags = " ".join([*UCRT_DEFS, "-DU_STATIC_IMPLEMENTATION"])
    # Libraries appended to every link: the glue, the Shizuku ntdll (for crt2.o's __C_specific_handler) and
    # bcryptprimitives (ProcessPrng, used by the glue's rand_s), ICU's own Windows dependency (advapi32).
    extra = " ".join([str(compat), *shz_libs("ntdll", "bcryptprimitives", "advapi32")])
    cmd = ["cmake", "-G", "Ninja", "-S", tree, "-B", bdir, f"-DCMAKE_TOOLCHAIN_FILE={HERE / 'toolchain-mingw-clang.cmake'}",
           f"-DSHZ_WIN64_LIBDIR={W64OUT}", f"-DSHZ_ICU_PREFIX={icu}", "-DCMAKE_BUILD_TYPE=Release", "-DPORT=JSCOnly", "-DDEVELOPER_MODE=OFF",
           "-DUSE_SYSTEM_UNIFDEF=ON", "-DENABLE_API_TESTS=OFF", "-DENABLE_REMOTE_INSPECTOR=OFF", "-DENABLE_TOOLS=OFF",
           f"-DICU_ROOT={icu}", f"-DCMAKE_C_FLAGS={cflags}", f"-DCMAKE_CXX_FLAGS={cflags}",
           f"-DCMAKE_CXX_STANDARD_LIBRARIES={extra} {MINGW_UCRT} -lucrtbase", f"-DCMAKE_C_STANDARD_LIBRARIES={extra} {MINGW_UCRT} -lucrtbase",
           *CONFIGS[config]]
    run(cmd, timeout=900)
    log["cmake"] = [str(x) for x in cmd]
    return bdir


def build_wkbatch(compat):
    exe = OUT / "wkbatch.exe"
    cmd = ["clang", f"--target={TARGET}", "-O2", "-Wall", "-Werror", *UCRT_DEFS, "-fuse-ld=lld", "-static",
           HERE / "tests" / "wkbatch.c", compat, *shz_libs("ntdll", "bcryptprimitives"), MINGW_UCRT, "-lucrtbase", "-o", exe]
    run(cmd)
    return exe, cmd


def build_probes(compat):
    """The toolchain experiments of WEBKIT.md, rebuilt from tests/probe_*: out-probes/<name>.exe. Each is linked the way
    jsc.exe is (Shizuku ntdll/bcryptprimitives import libraries first, the glue, mingw-w64's UCRT import library)."""
    pdir = OUT / "out-probes"
    pdir.mkdir(parents=True, exist_ok=True)
    tests = HERE / "tests"
    link = [compat, *shz_libs("ntdll", "bcryptprimitives")]
    cmds = {
        "probe_clang": ["clang++", f"--target={TARGET}", *UCRT_DEFS, "-O2", "-std=c++20", "-fuse-ld=lld", "-static",
                        tests / "probe_cxx.cpp", *link, "-lucrtbase"],
        # GCC 13 itself: its driver would add -lmsvcrt, so the default libraries are spelled out with the UCRT instead
        "probe_gcc": ["x86_64-w64-mingw32-g++-win32", *UCRT_DEFS, "-O2", "-std=c++20", "-static", tests / "probe_cxx.cpp",
                      *link, "-nodefaultlibs", "-Wl,--start-group", "-lstdc++", "-lmingw32", "-lgcc", "-lgcc_eh", "-lmingwex",
                      "-lucrtbase", "-lkernel32", "-Wl,--end-group"],
        "probe_tls": ["clang", f"--target={TARGET}", *UCRT_DEFS, "-O1", "-fuse-ld=lld", tests / "probe_tls.c", *link, "-lucrtbase"],
        "probe_seh": ["clang", f"--target={TARGET}", *UCRT_DEFS, "-O1", "-fms-extensions", "-fuse-ld=lld", tests / "probe_seh.c",
                      *link, "-lucrtbase"],
    }
    out = {}
    for name, cmd in cmds.items():
        exe = pdir / f"{name}.exe"
        run([*cmd, "-o", exe])
        out[name] = {"exe": str(exe), "sha256": sha256_file(exe), "command": [str(x) for x in cmd]}
    report, _ = importcheck.check([v["exe"] for v in out.values()])
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
    for tool in ("clang", "clang++", "ld.lld", "llvm-ar", "cmake", "ninja", "ruby", "perl", "gperf", "unifdef",
                 "x86_64-w64-mingw32-g++-win32"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    for f in ("libkernel32.a", "libucrtbase.a", "libntdll.a", "ucrtbase.dll"):
        if not (W64OUT / f).exists():
            raise SystemExit(f"missing {W64OUT / f}: run shizukudos/win64/build.py first")
    OUT.mkdir(parents=True, exist_ok=True)
    if args.probes:
        build_probes(build_compat())
        return
    log = {"built_utc": shzlib.utc_now(), "git": shzlib.git_state(), "config": args.config}
    t0 = time.time()
    wk, icu_tree = ensure_tree("webkit"), ensure_tree("icu")
    log["patches"] = apply_patches(wk)
    icu = build_icu(icu_tree, log)
    compat = build_compat()
    bdir = configure_jsc(wk, icu, args.config, compat, log)
    run(["ninja", "-C", bdir, f"-j{JOBS}", args.target], timeout=4 * 3600)
    dest = OUT / "out"
    dest.mkdir(exist_ok=True)
    for old in dest.glob("*"):
        old.unlink()
    produced = sorted(set(bdir.glob("bin/*.exe")) | set(bdir.glob("bin/*.dll")))
    for p in produced:
        shutil.copyfile(p, dest / p.name)
    batch, batch_cmd = build_wkbatch(compat)
    shutil.copyfile(batch, dest / batch.name)
    images = sorted(dest.glob("*.exe")) + sorted(dest.glob("*.dll"))
    report, bad = importcheck.check([str(p) for p in images])
    log.update({
        "seconds": round(time.time() - t0, 1),
        "toolchain": {"clang": shzlib.tool_version("clang"), "libstdc++ (mingw-w64 GCC)": shzlib.tool_version("x86_64-w64-mingw32-g++-win32"),
                      "cmake": shzlib.tool_version("cmake"), "ninja": shzlib.tool_version("ninja")},
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
