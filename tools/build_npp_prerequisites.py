#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the preserved KernelEx application providers on Linux, in isolation.

These are prerequisites for a separate native application trial. A successful
build is not an application result and does not install or patch any guest.
KernelEx and Microsoft Unicode installers are deliberately not redistributed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
PIN = "31cdfc3560fc116637ee8ed7be31b12f3aacf5d1"
ARCHIVE_SHA = "6f9823e41bf9f48442f5926fd59a0246d4a1865783c6feed01b082980ee8cbbf"
COMMON = ["-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
          "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-nostdlib",
          "-Wl,--gc-sections", "-Wl,--major-image-version,4",
          "-Wl,--minor-image-version,10", "-Wl,--disable-dynamicbase",
          "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
          "-Wl,--no-insert-timestamp", "-shared", "-Wl,--entry,_DllMain@12",
          "-Wl,--subsystem,windows:4.10"]


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def gate(path: Path, native: dict) -> dict:
    """Check real linked PE imports against the frozen OEM export inventory."""
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem,
            opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14C, 0x10B, 2, 4, 10):
            raise ValueError(f"{path.name}: incompatible image architecture/version")
        if not pe.is_dll() or opt.DllCharacteristics & 0x140:
            raise ValueError(f"{path.name}: incompatible DLL flags")
        if not opt.DATA_DIRECTORY[5].VirtualAddress or pe.FILE_HEADER.Characteristics & 1:
            raise ValueError(f"{path.name}: relocations required")
        if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 13, 14)):
            raise ValueError(f"{path.name}: unexpected TLS/delay/CLR")
        imports = {}
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            dll = descriptor.dll.decode("ascii").upper()
            names = []
            for entry in descriptor.imports:
                if entry.name is None:
                    raise ValueError(f"{path.name}: ordinal import {dll}!{entry.ordinal}")
                name = entry.name.decode("ascii")
                if name not in native.get(dll, set()):
                    raise ValueError(f"{path.name}: outside OEM export inventory {dll}!{name}")
                names.append(name)
            imports[dll] = sorted(names)
        exports = sorted(s.name.decode("ascii") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name)
        return {"bytes": path.stat().st_size, "sha256": digest(path), "imports": imports,
                "exports": exports, "oem_import_gate": "PASS", "native_load": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    inputs, out = args.inputs.resolve(), args.out.resolve()
    if out.exists():
        parser.error("output must be a new directory; retained builds are immutable")
    source = inputs / "sources" / ("KernelEx-" + PIN)
    archive = inputs / "KernelEx-31cdfc3560fc.tar.gz"
    if digest(archive) != ARCHIVE_SHA:
        parser.error("pinned upstream archive hash mismatch")
    # Require exact extracted source bytes, rather than trusting a directory name.
    import tarfile
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.isfile():
                local = inputs / "sources" / member.name
                stream = tar.extractfile(member)
                if stream is None or local.read_bytes() != stream.read():
                    parser.error("pinned extracted upstream source differs")
    cc, clang = shutil.which("i686-w64-mingw32-gcc"), shutil.which("clang")
    if not cc or not clang:
        parser.error("the existing MinGW GCC and Clang compilers are required")
    out.mkdir(parents=True)
    records, frozen = [], {}
    native_doc = json.loads((ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json").read_text())
    native = {name.upper(): set(names) for name, names in native_doc["dlls"].items()}

    def run(command: list[str]):
        with (out / "build.log").open("a") as log:
            log.write(json.dumps(command) + "\n"); log.flush()
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=log, timeout=180)
        records.append({"command": command, "exit_code": result.returncode})
        if result.returncode:
            raise RuntimeError(f"build step failed; see {out / 'build.log'}")

    def build(name: str, files: list[str], libs: list[str], extra: list[str] | None = None):
        paths = [ROOT / filename for filename in files] + [ROOT / "platform/freestanding/memory.c"]
        for path in paths: frozen[str(path.relative_to(ROOT))] = digest(path)
        objects, definitions = [], []
        for index, path in enumerate(paths):
            if path.suffix == ".def":
                definitions.append(str(path)); continue
            obj = out / f"{name}.{index}.o"; objects.append(str(obj))
            # The original providers were compiled with LLVM-MinGW. Clang's
            # FS intrinsic correctly models segment-relative Win9x fiber reads.
            run([clang, "--no-default-config", "--target=i686-w64-windows-gnu",
                 "--sysroot=/usr/i686-w64-mingw32/sys-root/mingw", "-std=c11", "-march=i486",
                 "-Os", "-Wall", "-Wextra", "-Werror", "-fno-builtin",
                 "-ffunction-sections", "-fdata-sections", *(extra or []),
                 "-c", str(path), "-o", str(obj)])
        run([cc, *COMMON, *(extra or []), "-o", str(out / name),
             *objects, *definitions, *("-l" + lib for lib in libs)])

    receipt = {"schema": "win98modern.npp-prerequisites.v1", "native_installed": False,
               "application_launched": False, "upstream_pin": PIN,
               "upstream_archive_sha256": ARCHIVE_SHA, "status": "FAIL"}
    try:
        ordered = re.findall(r"'([^']+\.c)'", (ROOT / "tools/m98wrap-sources.ps1").read_text())
        if not ordered or len(ordered) != len(set(ordered)):
            raise ValueError("invalid preserved wrapper source list")
        build("M98WRAP.DLL", ordered, ["kernel32"])
        build("M98SHELL.DLL", ["src/m98shell.c", "src/m98shell_openfolder.c"], ["shell32", "ole32", "kernel32"])
        build("M98AD2.DLL", ["src/m98advapi.c"], ["kernel32", "advapi32"])
        build("M98USR1.DLL", ["src/m98_clipboard.c", "src/m98user.c"], ["user32", "kernel32"])
        build("M98GDI3.DLL", ["src/m98_gdi_alpha.c", "src/m98gdi.c"], ["kernel32"])
        build("M98CTL3.DLL", ["src/m98_comctl_ordinals.c", "src/m98_icon_choice.c", "src/m98_icon_png.c",
                              "src/vendor/lodepng/lodepng.c", "src/m98ctl.c"], ["kernel32", "user32", "gdi32"],
              ["-DM98_WITH_PNG", "-DLODEPNG_NO_COMPILE_ENCODER", "-DLODEPNG_NO_COMPILE_DISK",
               "-DLODEPNG_NO_COMPILE_ANCILLARY_CHUNKS", "-DLODEPNG_NO_COMPILE_ERROR_TEXT",
               "-DLODEPNG_NO_COMPILE_ALLOCATORS", "-DLODEPNG_MAX_ALLOC=8388608"])
        for dll, source_base, libs in [("DBGHELP", "dbghelp", ["kernel32"]),
                                       ("DWMAPI", "dwmapi", []), ("BCRYPT", "bcrypt", ["kernel32"])]:
            build(dll + ".DLL", [f"src/{source_base}_shim.c", f"src/{source_base}_shim.def"], libs)
        ux = source / "auxiliary/uxtheme"
        replacements = {"CloseThemeData", "DrawThemeBackground", "DrawThemeParentBackground",
                        "EnableThemeDialogTexture", "GetThemeBackgroundContentRect", "GetThemeColor",
                        "GetThemeFont", "GetThemePartSize", "OpenThemeData", "SetWindowTheme", "GetThemeSysFont"}
        additions = {"BeginBufferedAnimation", "BufferedPaintRenderAnimation", "BufferedPaintStopAllAnimations",
                     "DrawThemeTextEx", "EndBufferedAnimation", "GetThemeTransitionDuration"}
        lines = (ux / "uxtheme.def").read_text().splitlines()
        lines[0] = lines[0].replace("BASE=0x7D030000", "BASE=2097348608")
        lines = [f"{line.strip()}=m98_{line.strip()}" if line.strip() in replacements else line for line in lines]
        lines.extend(f"{name}=m98_{name}" for name in sorted(additions))
        definition = out / "uxtheme-known.def"; definition.write_text("\n".join(lines) + "\n")
        objects = []
        for path, extra in [(ux / "uxtheme.c", ["-fasm-blocks"]), (ux / "metric.c", []),
                            (ROOT / "src/uxtheme_shim.c", ["-DDllMain=m98UxThemeUnusedDllMain"]),
                            (ROOT / "src/uxtheme_sysfont.c", [])]:
            obj = out / (path.stem + ".o"); objects.append(str(obj))
            frozen[str(path.relative_to(ROOT))] = digest(path)
            run([clang, "--no-default-config", "--target=i686-w64-windows-gnu",
                 "--sysroot=/usr/i686-w64-mingw32/sys-root/mingw", "-march=i486", "-std=gnu11", "-Os",
                 "-fno-builtin", "-ffunction-sections", "-fdata-sections", *extra, "-c", str(path), "-o", str(obj)])
        run([cc, *COMMON, "-o", str(out / "UXTHEME.DLL"), *objects, str(definition), "-lkernel32", "-luser32", "-lgdi32"])
        artifacts = {path.name: gate(path, native) for path in sorted(out.glob("*.DLL"))}
        if len(artifacts) != 10:
            raise ValueError("prerequisite set is incomplete")
        for name, before in frozen.items():
            if digest(ROOT / name) != before:
                raise ValueError(f"source changed during build: {name}")
        receipt.update(status="PASS", artifacts=artifacts)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, pefile.PEFormatError) as exc:
        receipt["error"] = str(exc)
    receipt.update(steps=records, sources=frozen)
    (out / "build-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({key: receipt[key] for key in ("status", "native_installed", "application_launched")}
                     | {"receipt": str(out / "build-result.json"), "error": receipt.get("error")}, indent=2))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
