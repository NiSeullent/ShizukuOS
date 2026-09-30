#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build ShizukuTrident Lite, the minimal HTML/CSS engine backend of the Trident layer: shzlite.dll (exporting
ShzEngineGetInterface, trident/engine.h) and its import library libshzlite.a.

Sources: core/*.c (portable C99: DOM, HTML parser, CSS, layout, events, forms, images), win/*.c (engine.h glue, GDI
painting, fonts, the view window, platform layer, DLL entry) and the vendored LodePNG (src/vendor/lodepng, zlib
licence). Compiled with x86_64-w64-mingw32-gcc -Wall -Wextra -Werror, freestanding, no C runtime (DllMain entry, the
process heap through kernel32); linked against the Shizuku import libraries in build/shizukudos/win64 (kernel32,
user32, gdi32), which this script only reads.

    build(out_dir) -> {"dll": Path, "implib": Path, "def": Path, "exports": [...], "objects": [...], "command": [...]}

Command line: python3 shizukudos/win64/trident/engine/build_engine.py --out DIR
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
WIN64_OUT = REPO / "build" / "shizukudos" / "win64"          # Shizuku import libraries (read only)
LODEPNG = REPO / "src" / "vendor" / "lodepng"
DEFAULT_OUT = REPO / "build" / "shizukudos" / "trident-engine"

CC = "x86_64-w64-mingw32-gcc"
DLLTOOL = "x86_64-w64-mingw32-dlltool"
NM = "x86_64-w64-mingw32-nm"
OBJCOPY = "x86_64-w64-mingw32-objcopy"
DLL_NAME = "shzlite.dll"
EXPORTS = ["ShzEngineGetInterface"]
IMAGE_BASE = 0x7FFA80000000          # between the wineport DLLs (0x7ff9...) and the Shizuku modules (0x7ffb...)
IMPORTS = ["kernel32", "user32", "gdi32"]

COMMON = ["-O2", "-g0", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
          "-fno-ident", "-fno-tree-loop-distribute-patterns", "-fno-strict-aliasing"]
CORE_FLAGS = ["-std=c99"]
WIN_FLAGS = ["-std=gnu99", "-DUNICODE", "-D_UNICODE"]       # not WIN32_LEAN_AND_MEAN: engine.h needs VARIANT
LODEPNG_FLAGS = ["-std=c99", "-DLODEPNG_NO_COMPILE_ALLOCATORS", "-DLODEPNG_NO_COMPILE_DISK", "-DLODEPNG_NO_COMPILE_CPP",
                 "-DLODEPNG_NO_COMPILE_ENCODER", "-DLODEPNG_NO_COMPILE_ERROR_TEXT"]


def _run(cmd):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(str(c) for c in cmd)}\n{r.stdout}{r.stderr}")
    return r


def sources():
    """(source, extra flags) for every translation unit of the DLL."""
    units = [(s, CORE_FLAGS + ["-I", HERE / "core", "-I", LODEPNG]) for s in sorted((HERE / "core").glob("*.c"))]
    units += [(s, WIN_FLAGS + ["-I", HERE / "win", "-I", HERE / "core", "-I", HERE.parent, "-I", LODEPNG])
              for s in sorted((HERE / "win").glob("*.c"))]
    units.append((LODEPNG / "lodepng.c", LODEPNG_FLAGS + ["-I", LODEPNG]))
    return units


def defined_globals(obj):
    """Global symbols an object defines (text/data/bss/rdata)."""
    r = _run([NM, "--defined-only", "-g", obj])
    return {line.split()[-1] for line in r.stdout.splitlines() if len(line.split()) == 3}


def resolve_stubs(objects, obj_dir):
    """The temporary L1/L2 stubs (core/stubs_*.c, win/stubs_*.c) are plain definitions in the DLL build (GNU ld for PE
    cannot resolve weak definitions across objects). Every stub that a real object also defines is made local in a
    copy of the stub object, so the real definition wins and implementing a function never breaks the link."""
    stubs = [o for o in objects if o.stem.startswith(("core_stubs_", "win_stubs_"))]
    real = set()
    for o in objects:
        if o not in stubs:
            real |= defined_globals(o)
    result, overridden = [], []
    for o in objects:
        if o not in stubs:
            result.append(o)
            continue
        dup = sorted(defined_globals(o) & real)
        if not dup:
            result.append(o)
            continue
        fixed = obj_dir / (o.stem + "_resolved.o")
        _run([OBJCOPY, *[f"--localize-symbol={d}" for d in dup], o, fixed])
        result.append(fixed)
        overridden += dup
    return result, overridden


def build(out_dir, image_base=IMAGE_BASE):
    """Compile and link shzlite.dll + libshzlite.a into out_dir; returns the paths and the export list."""
    for tool in (CC, DLLTOOL, NM, OBJCOPY):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    for lib in IMPORTS:
        if not (WIN64_OUT / f"lib{lib}.a").exists():
            raise SystemExit(f"missing {WIN64_OUT / f'lib{lib}.a'}: build the Shizuku runtime first (win64/build.py)")
    out = Path(out_dir)
    obj_dir = out / "obj"
    obj_dir.mkdir(parents=True, exist_ok=True)

    def compile_unit(unit):
        src, flags = unit
        tag = "vendor_" if src.parent == LODEPNG else ("win_" if src.parent.name == "win" else "core_")
        obj = obj_dir / f"{tag}{src.stem}.o"
        _run([CC, *COMMON, *flags, "-c", src, "-o", obj])
        return obj

    with ThreadPoolExecutor(max_workers=os.cpu_count() or 2) as pool:
        objects = list(pool.map(compile_unit, sources()))
    objects, overridden = resolve_stubs(objects, obj_dir)

    def_file = out / "shzlite.def"
    def_file.write_text("LIBRARY shzlite.dll\nEXPORTS\n" + "".join(f"  {e}\n" for e in EXPORTS))
    dll = out / DLL_NAME
    cmd = [CC, "-shared", "-nostdlib", "-Wl,--entry,DllMain", f"-Wl,--image-base,{image_base:#x}", "-Wl,--dynamicbase",
           "-Wl,--subsystem,windows", "-Wl,--kill-at", "-Wl,--no-insert-timestamp", *objects, def_file,
           "-L", WIN64_OUT, *[f"-l{lib}" for lib in IMPORTS], "-lgcc", "-o", dll]
    _run(cmd)
    implib = out / "libshzlite.a"
    _run([DLLTOOL, "-d", def_file, "-l", implib, "--kill-at"])
    return {"dll": dll, "implib": implib, "def": def_file, "exports": list(EXPORTS), "objects": objects,
            "imports": [f"{lib}.dll" for lib in IMPORTS], "stubs_overridden": overridden,
            "command": [str(c) for c in cmd]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=str(DEFAULT_OUT), help=f"output directory (default {DEFAULT_OUT})")
    args = ap.parse_args()
    res = build(Path(args.out))
    print(json.dumps({"dll": str(res["dll"]), "implib": str(res["implib"]), "exports": res["exports"],
                      "size": res["dll"].stat().st_size}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
