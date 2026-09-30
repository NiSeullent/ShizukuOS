#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the ShizukuDOS "Shizuku" WebKit port (agent W3; docs/shizukudos10/WEBKIT.md "WebCore and the Shizuku port").

Tree: the pinned WebKit checkout (build/upstream/webkit, agent W1's `webkit` pin and sparse paths). Every build starts
from the pinned files: W1's webkit/build.py apply_patches() restores and applies W1's patches, then this script restores
the files its own patches touch, applies port/patches/*.patch in name order and copies port/overlay/ over the tree
(new files only: the Options/Platform CMake files of PORT=Shizuku).

Toolchain and dependencies: the shared WebKit toolchain (deps/toolchain.py, through W1's CMake toolchain file), W1's
static ICU and the W3 static dependencies (deps/build_deps.py). WTF, JavaScriptCore, WebCore, Skia and every
dependency are linked statically into each program; libc++.dll and libunwind.dll ship next to it.

Output: build/shizukudos/win64/webkit/shizuku/ (CMake/Ninja tree; bin/*.exe) and port-build.json.

Usage: build_port.py [--target T[,T]] [--keep-going] [--configure-only] [--jobs N]
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
WEBKIT = HERE.parent
sys.path.insert(0, str(WEBKIT / "deps"))
import build_deps as deps  # noqa: E402
w1 = deps.w1
import shzlib  # noqa: E402
from shzlib import run  # noqa: E402

OUT = w1.OUT / "shizuku"
PATCHES = HERE / "patches"
OVERLAY = HERE / "overlay"

# Static libraries every image links after WebCore/JavaScriptCore (static deps are not transitive in CMake's finders).
DEP_LIBS = ["xslt", "exslt", "xml2", "sqlite3", "curl", "ssl", "crypto", "psl", "harfbuzz-icu", "harfbuzz", "freetype",
            "woff2dec", "woff2common", "brotlidec", "brotlicommon", "webpdemux", "webp", "sharpyuv", "jpeg", "png16", "z",
            "icuin", "icuuc", "icudt"]
SYS_LIBS = ["ws2_32", "crypt32", "bcrypt", "iphlpapi", "secur32", "user32", "gdi32", "shlwapi", "ole32", "oleaut32",
            "uuid", "winmm", "usp10", "advapi32", "shell32", "imm32", "version", "comctl32"]
PORT_DEFS = ["-DU_STATIC_IMPLEMENTATION", "-DLIBXML_STATIC", "-DLIBXSLT_STATIC", "-DLIBEXSLT_STATIC", "-DCURL_STATICLIB",
             "-DPSL_STATIC"]


def prepare_tree():
    tree = w1.ensure_tree("webkit")
    w1_patches = w1.apply_patches(tree)
    mine = sorted(PATCHES.glob("*.patch"))
    targets = sorted({t for p in mine for t in w1.patch_targets(p)})
    tracked = [t for t in targets if w1.git(tree, "ls-files", "--", t)]
    if tracked:
        w1.git(tree, "checkout", "HEAD", "--", *tracked)
    for p in mine:
        r = subprocess.run(["git", "-C", str(tree), "apply", "--whitespace=nowarn", str(p)], capture_output=True,
                           text=True)
        if r.returncode:
            raise SystemExit(f"{p.name} does not apply after W1's patches:\n{r.stderr}")
    overlay = []
    for f in sorted(OVERLAY.rglob("*")):
        if f.is_file():
            rel = f.relative_to(OVERLAY)
            if w1.git(tree, "ls-files", "--", str(rel)):
                raise SystemExit(f"overlay file {rel} exists upstream: carry it as a patch instead")
            (tree / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(f, tree / rel)
            overlay.append(str(rel))
    return tree, w1_patches, [str(p.relative_to(shzlib.REPO)) for p in mine], overlay


def configure(tree):
    deps.prepare()
    icu = deps.ICU_PREFIX
    OUT.mkdir(parents=True, exist_ok=True)
    flags = " ".join(PORT_DEFS)
    libs = " ".join([f"-L{deps.PREFIX / 'lib'}", f"-L{icu / 'lib'}", *[f"-l{l}" for l in DEP_LIBS + SYS_LIBS]])
    defs = {
        "CMAKE_TOOLCHAIN_FILE": deps.toolchain_file(), **deps.toolchain_env(),
        "CMAKE_BUILD_TYPE": "Release", "PORT": "Shizuku", "SHIZUKU_PORT_DIR": HERE, "DEVELOPER_MODE": "OFF",
        "CMAKE_PREFIX_PATH": f"{deps.PREFIX};{icu}", "ICU_ROOT": icu, "OPENSSL_ROOT_DIR": deps.PREFIX,
        "OPENSSL_USE_STATIC_LIBS": "ON", "ZLIB_LIBRARY": deps.PREFIX / "lib" / "libz.a",
        "ZLIB_INCLUDE_DIR": deps.PREFIX / "include", "CMAKE_C_FLAGS": flags, "CMAKE_CXX_FLAGS": flags,
        "CMAKE_C_STANDARD_LIBRARIES": libs, "CMAKE_CXX_STANDARD_LIBRARIES": libs,
    }
    cmd = ["cmake", "-G", "Ninja", "-S", tree, "-B", OUT, "-Wno-dev", *[f"-D{k}={v}" for k, v in defs.items()]]
    run(cmd, env=deps.env(), timeout=1800)
    return cmd


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", default="WebCore", help="ninja target(s), comma-separated (default WebCore)")
    ap.add_argument("--keep-going", action="store_true", help="ninja -k 0: collect every failing compile")
    ap.add_argument("--configure-only", action="store_true")
    ap.add_argument("--jobs", type=int, default=w1.JOBS)
    a = ap.parse_args()
    t0 = time.time()
    tree, w1_patches, mine, overlay = prepare_tree()
    cmd = configure(tree)
    log = {"utc": shzlib.utc_now(), "git": shzlib.git_state(), "webkit": w1.spec("webkit")["commit"],
           "w1_patches": w1_patches, "w3_patches": mine, "overlay": overlay, "cmake": [str(c) for c in cmd]}
    rc = 0
    if not a.configure_only:
        ninja = ["ninja", "-C", str(OUT), f"-j{a.jobs}", *(["-k", "0"] if a.keep_going else []), *a.target.split(",")]
        rc = subprocess.run(ninja, env=deps.env()).returncode
        log["ninja"] = ninja
        log["ninja_rc"] = rc
    log["seconds"] = round(time.time() - t0, 1)
    shzlib.write_json(OUT / "port-build.json", log)
    print(json.dumps({k: log[k] for k in ("webkit", "w3_patches", "overlay", "seconds") if k in log}, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main())
