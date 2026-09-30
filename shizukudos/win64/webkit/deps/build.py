#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the WebKit port's third-party dependencies for the Kernel64 Win64 runtime (agent W3).

Every dependency is a pinned upstream in shizukudos/upstream/manifest.json (fetched shallowly into build/upstream,
never committed); local changes are patches under deps/patches/<name>/. Each is built as DLLs with the W3 toolchain
(deps/toolchain.py: host clang 18 + mingw-w64 UCRT + libc++) and installed into one prefix:

  build/shizukudos/webkit/deps/{bin,include,lib}   DLLs, headers, import libraries, pkg-config and CMake files
  build/shizukudos/webkit/deps/deps.json           per dependency: pin, licence, DLLs (bytes, sha256), build seconds

The WebKit port (port/) finds everything there. Guest checks: deps/tests/t_dep_*.c(pp), built by --tests and run by
deps/run_deps_guest.py.

Usage: build.py [--only NAME[,NAME]] [--tests] [--clean]
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
sys.path.insert(0, str(HERE))
import toolchain as tc  # noqa: E402
from toolchain import BUILD, REPO, TRIPLE, run  # noqa: E402

PREFIX = BUILD / "webkit" / "deps"
WORK = REPO / "build" / "webkit-work" / "deps"
TESTS = HERE / "tests"
TOUT = BUILD / "webkit" / "deps-tests"
JOBS = str(os.cpu_count() or 2)


def env():
    e = dict(os.environ)
    e["PATH"] = f"{tc.TC / 'bin'}:{e['PATH']}"
    e["PKG_CONFIG_LIBDIR"] = str(PREFIX / "lib" / "pkgconfig")
    e["PKG_CONFIG_PATH"] = ""
    e.pop("PKG_CONFIG_SYSROOT_DIR", None)
    return e


def cmake_build(name, src, defs, subdir=""):
    b = WORK / f"build-{name}"
    if b.exists():
        shutil.rmtree(b)
    base = {"CMAKE_TOOLCHAIN_FILE": tc.TC / "toolchain.cmake", "CMAKE_BUILD_TYPE": "Release",
            "CMAKE_INSTALL_PREFIX": PREFIX, "CMAKE_PREFIX_PATH": PREFIX, "CMAKE_FIND_ROOT_PATH": f"{tc.SYSROOT};{PREFIX}",
            "BUILD_SHARED_LIBS": "ON", "CMAKE_INSTALL_LIBDIR": "lib", "CMAKE_INSTALL_BINDIR": "bin"}
    base.update(defs)
    run(["cmake", "-G", "Ninja", "-S", Path(src) / subdir, "-B", b, "-Wno-dev", *[f"-D{k}={v}" for k, v in base.items()]],
        env=env(), timeout=1800)
    run(["ninja", "-C", b, "-j", JOBS], env=env(), timeout=14400)
    run(["ninja", "-C", b, "install"], env=env(), timeout=1800)


def meson_cross():
    f = WORK / "meson-cross.txt"
    f.write_text(f"""[binaries]
c = '{tc.TC}/bin/{TRIPLE}-clang'
cpp = '{tc.TC}/bin/{TRIPLE}-clang++'
ar = '{shutil.which("llvm-ar")}'
strip = '{shutil.which("llvm-strip")}'
windres = '{shutil.which("x86_64-w64-mingw32-windres")}'
pkg-config = '{shutil.which("pkg-config")}'

[properties]
pkg_config_libdir = '{PREFIX}/lib/pkgconfig'

[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
""")
    return f


def meson_build(name, src, opts):
    b = WORK / f"build-{name}"
    if b.exists():
        shutil.rmtree(b)
    run(["meson", "setup", b, src, "--cross-file", meson_cross(), f"--prefix={PREFIX}", "--libdir=lib",
         "--buildtype=release", "-Ddefault_library=shared", *[f"-D{k}={v}" for k, v in opts.items()]],
        env=env(), timeout=1800)
    run(["ninja", "-C", b, "-j", JOBS], env=env(), timeout=14400)
    run(["ninja", "-C", b, "install"], env=env(), timeout=1800)


def autotools_build(name, src, args, extra_env=None, targets=("install",)):
    b = WORK / f"build-{name}"
    if b.exists():
        shutil.rmtree(b)
    b.mkdir(parents=True)
    e = env()
    e.update({"CC": f"{TRIPLE}-clang", "CXX": f"{TRIPLE}-clang++", "AR": "llvm-ar", "RANLIB": "llvm-ranlib",
              "NM": "llvm-nm", "STRIP": "llvm-strip", "WINDRES": "x86_64-w64-mingw32-windres",
              "RC": "x86_64-w64-mingw32-windres", **(extra_env or {})})
    run([Path(src) / "configure", *args], cwd=b, env=e, timeout=1800)
    run(["make", "-j" + JOBS], cwd=b, env=e, timeout=14400)
    for t in targets:
        run(["make", t], cwd=b, env=e, timeout=1800)
    return b


# ------------------------------------------------------------------------------------------------ the dependencies
def b_zlib(src):
    cmake_build("zlib", src, {"ZLIB_BUILD_EXAMPLES": "OFF", "INSTALL_PKGCONFIG_DIR": PREFIX / "lib" / "pkgconfig"})


def b_libpng(src):
    cmake_build("libpng", src, {"PNG_SHARED": "ON", "PNG_STATIC": "OFF", "PNG_TESTS": "OFF", "PNG_TOOLS": "OFF",
                                "PNG_FRAMEWORK": "OFF", "ZLIB_ROOT": PREFIX})


def b_libjpeg_turbo(src):
    cmake_build("libjpeg-turbo", src, {"ENABLE_SHARED": "ON", "ENABLE_STATIC": "OFF", "WITH_TURBOJPEG": "ON",
                                       "WITH_SIMD": "ON", "REQUIRE_SIMD": "ON",
                                       "CMAKE_ASM_NASM_COMPILER": shutil.which("nasm")})


def b_libwebp(src):
    cmake_build("libwebp", src, {f"WEBP_BUILD_{t}": "OFF" for t in (
        "ANIM_UTILS", "CWEBP", "DWEBP", "GIF2WEBP", "IMG2WEBP", "VWEBP", "WEBPINFO", "WEBPMUX", "EXTRAS")} |
        {"WEBP_BUILD_LIBWEBPMUX": "ON"})


def b_brotli(src):
    cmake_build("brotli", src, {"BROTLI_DISABLE_TESTS": "ON"})


def b_woff2(src):
    cmake_build("woff2", src, {"NOISY_LOGGING": "OFF", "CMAKE_SKIP_RPATH": "ON"})


def b_sqlite(src):
    host = WORK / "build-sqlite-host"
    if host.exists():
        shutil.rmtree(host)
    host.mkdir(parents=True)
    hostenv = dict(os.environ)
    run([Path(src) / "configure", "--disable-tcl"], cwd=host, env=hostenv, timeout=1800)
    run(["make", "sqlite3.c"], cwd=host, env=hostenv, timeout=1800)
    (PREFIX / "include").mkdir(parents=True, exist_ok=True)
    (PREFIX / "bin").mkdir(parents=True, exist_ok=True)
    (PREFIX / "lib" / "pkgconfig").mkdir(parents=True, exist_ok=True)
    for h in ("sqlite3.h", "sqlite3ext.h"):
        shutil.copy2(host / h if (host / h).exists() else Path(src) / "src" / h, PREFIX / "include" / h)
    defs = ["-DSQLITE_ENABLE_FTS3", "-DSQLITE_ENABLE_FTS3_PARENTHESIS", "-DSQLITE_ENABLE_RTREE",
            "-DSQLITE_ENABLE_COLUMN_METADATA", "-DSQLITE_THREADSAFE=1", "-DSQLITE_OMIT_LOAD_EXTENSION=0",
            "-DSQLITE_API=__declspec(dllexport)"]
    run([f"{TRIPLE}-clang", "-O2", "-shared", *defs, host / "sqlite3.c", "-o", PREFIX / "bin" / "libsqlite3-0.dll",
         f"-Wl,--out-implib,{PREFIX / 'lib' / 'libsqlite3.dll.a'}"], env=env(), timeout=1800)
    version = (host / "VERSION").read_text().strip() if (host / "VERSION").exists() else \
        (Path(src) / "VERSION").read_text().strip()
    (PREFIX / "lib" / "pkgconfig" / "sqlite3.pc").write_text(
        f"prefix={PREFIX}\nlibdir=${{prefix}}/lib\nincludedir=${{prefix}}/include\n\nName: SQLite\n"
        f"Description: SQL database engine\nVersion: {version}\nLibs: -L${{libdir}} -lsqlite3\nCflags: -I${{includedir}}\n")


def b_libxml2(src):
    cmake_build("libxml2", src, {f"LIBXML2_WITH_{o}": "OFF" for o in (
        "ICONV", "ICU", "LZMA", "ZLIB", "PYTHON", "TESTS", "PROGRAMS", "HTTP", "DEBUG", "MODULES")} |
        {"LIBXML2_WITH_THREADS": "ON"})


def b_libxslt(src):
    cmake_build("libxslt", src, {"LIBXSLT_WITH_PYTHON": "OFF", "LIBXSLT_WITH_TESTS": "OFF",
                                 "LIBXSLT_WITH_PROGRAMS": "OFF", "LIBXSLT_WITH_CRYPTO": "OFF",
                                 "LIBXSLT_WITH_PROFILER": "OFF"})


def b_icu(src):
    icusrc = Path(src) / "icu4c" / "source"
    host = WORK / "build-icu-host"
    if not (host / "bin" / "icupkg").exists():
        if host.exists():
            shutil.rmtree(host)
        host.mkdir(parents=True)
        hostenv = dict(os.environ)
        hostenv.update({"CC": "gcc", "CXX": "g++"})
        run([icusrc / "configure", "--disable-tests", "--disable-samples", "--disable-extras"], cwd=host,
            env=hostenv, timeout=1800)
        run(["make", "-j" + JOBS], cwd=host, env=hostenv, timeout=7200)
    autotools_build("icu", icusrc, [f"--host={TRIPLE}", f"--with-cross-build={host}", f"--prefix={PREFIX}",
                                    "--disable-tests", "--disable-samples", "--disable-extras", "--disable-tools",
                                    "--enable-shared", "--disable-static", "--with-data-packaging=library"])


def b_freetype(src):
    cmake_build("freetype", src, {"FT_DISABLE_HARFBUZZ": "ON", "FT_DISABLE_BZIP2": "ON", "FT_REQUIRE_ZLIB": "ON",
                                  "FT_REQUIRE_PNG": "ON", "FT_REQUIRE_BROTLI": "ON"})


def b_harfbuzz(src):
    meson_build("harfbuzz", src, {"icu": "enabled", "freetype": "enabled", "glib": "disabled", "gobject": "disabled",
                                  "cairo": "disabled", "chafa": "disabled", "tests": "disabled",
                                  "introspection": "disabled", "docs": "disabled", "utilities": "disabled",
                                  "gdi": "disabled", "directwrite": "disabled", "benchmark": "disabled",
                                  "subset": "disabled"})


def b_openssl(src):
    b = WORK / "build-openssl"
    if b.exists():
        shutil.rmtree(b)
    b.mkdir(parents=True)
    e = env()
    e.update({"CC": f"{TRIPLE}-clang", "CXX": f"{TRIPLE}-clang++", "AR": "llvm-ar", "RANLIB": "llvm-ranlib",
              "RC": "x86_64-w64-mingw32-windres", "WINDRES": "x86_64-w64-mingw32-windres"})
    run(["perl", Path(src) / "Configure", "mingw64", "shared", "no-tests", "no-docs", "no-apps", "no-module",
         "no-legacy", "no-engine", f"--prefix={PREFIX}", "--libdir=lib", f"--openssldir={PREFIX / 'ssl'}"],
        cwd=b, env=e, timeout=1800)
    run(["make", "-j" + JOBS, "build_sw"], cwd=b, env=e, timeout=14400)
    run(["make", "install_sw"], cwd=b, env=e, timeout=1800)


def b_curl(src):
    cmake_build("curl", src, {"CURL_USE_OPENSSL": "ON", "OPENSSL_ROOT_DIR": PREFIX, "CURL_ZLIB": "ON",
                              "CURL_BROTLI": "ON", "CURL_ZSTD": "OFF", "USE_NGHTTP2": "OFF", "USE_LIBIDN2": "OFF",
                              "CURL_USE_LIBPSL": "OFF", "CURL_USE_LIBSSH2": "OFF", "BUILD_CURL_EXE": "OFF",
                              "BUILD_TESTING": "OFF", "BUILD_STATIC_LIBS": "OFF", "CURL_DISABLE_LDAP": "ON",
                              "BUILD_LIBCURL_DOCS": "OFF", "BUILD_MISC_DOCS": "OFF", "ENABLE_CURL_MANUAL": "OFF",
                              "BUILD_EXAMPLES": "OFF", "CURL_WINDOWS_SSPI": "OFF", "USE_WIN32_IDN": "OFF"})


def b_libpsl(src):
    psl = tc.fetch("publicsuffix-list")
    meson_build("libpsl", src, {"runtime": "no", "builtin": "true", "psl_file": psl / "public_suffix_list.dat",
                                "tests": "false", "docs": "false"})


# name -> (builder, manifest upstream)
DEPS = {
    "zlib": (b_zlib, "zlib"),
    "libpng": (b_libpng, "libpng"),
    "libjpeg-turbo": (b_libjpeg_turbo, "libjpeg-turbo"),
    "libwebp": (b_libwebp, "libwebp"),
    "brotli": (b_brotli, "brotli"),
    "woff2": (b_woff2, "woff2"),
    "sqlite": (b_sqlite, "sqlite"),
    "libxml2": (b_libxml2, "libxml2"),
    "libxslt": (b_libxslt, "libxslt"),
    "icu": (b_icu, "icu"),
    "freetype": (b_freetype, "freetype-webkit"),
    "harfbuzz": (b_harfbuzz, "harfbuzz"),
    "openssl": (b_openssl, "openssl"),
    "curl": (b_curl, "curl"),
    "libpsl": (b_libpsl, "libpsl"),
}


def record(name, upstream, seconds, before):
    spec = tc.shzlib.load_manifest()["upstreams"][upstream]
    dlls = sorted(set((PREFIX / "bin").glob("*.dll")) - before)
    return {"upstream": upstream, "ref": spec["ref"], "commit": spec["commit"], "license": spec["license"],
            "build_seconds": round(seconds, 1),
            "dlls": {p.name: {"bytes": p.stat().st_size, "sha256": tc.shzlib.sha256_file(p)} for p in dlls}}


def build(only=None, clean=False):
    if not (tc.TC / "toolchain.cmake").exists():
        raise SystemExit("toolchain missing: run shizukudos/win64/webkit/deps/toolchain.py first")
    if clean and PREFIX.exists():
        shutil.rmtree(PREFIX)
    PREFIX.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    state_file = PREFIX / "deps.json"
    state = json.loads(state_file.read_text()) if state_file.exists() else {}
    for name, (fn, upstream) in DEPS.items():
        if only and name not in only:
            continue
        print(f"== {name}", flush=True)
        before = set((PREFIX / "bin").glob("*.dll")) if (PREFIX / "bin").exists() else set()
        for old in state.get(name, {}).get("dlls", {}):
            before.discard(PREFIX / "bin" / old)
        t0 = time.time()
        fn(tc.patched_source(upstream, WORK))
        state[name] = record(name, upstream, time.time() - t0, before)
        state_file.write_text(json.dumps(state, indent=1) + "\n")
    return state


def build_tests(only=None):
    """deps/tests/t_*.c and t_*.cpp -> build/shizukudos/webkit/deps-tests/*.exe (one import-checked EXE each)."""
    TOUT.mkdir(parents=True, exist_ok=True)
    libs = json.loads((TESTS / "tests.json").read_text())
    out = {}
    for src in sorted(TESTS.glob("t_*.c*")):
        name = src.stem
        if only and name not in only:
            continue
        drv = f"{TRIPLE}-clang++" if src.suffix == ".cpp" else f"{TRIPLE}-clang"
        std = ["-std=c++20"] if src.suffix == ".cpp" else ["-std=c11"]
        exe = TOUT / f"{name}.exe"
        cmd = [drv, "-O2", "-Wall", "-Wextra", "-Werror", *std, "-I", PREFIX / "include",
               *[f"-I{PREFIX / 'include' / d}" for d in libs.get(name, {}).get("include_dirs", [])],
               *libs.get(name, {}).get("defines", []), src, "-L", PREFIX / "lib",
               *[f"-l{l}" for l in libs.get(name, {}).get("libs", [])], "-o", exe]
        run(cmd, env=env(), timeout=600)
        out[name] = exe
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--only", help="comma-separated dependency names")
    ap.add_argument("--tests", action="store_true", help="only build the guest checks (deps/tests)")
    ap.add_argument("--clean", action="store_true")
    a = ap.parse_args()
    only = set(a.only.split(",")) if a.only else None
    if a.tests:
        print(json.dumps({k: str(v) for k, v in build_tests(only).items()}, indent=1))
    else:
        print(json.dumps(build(only, a.clean), indent=1))
