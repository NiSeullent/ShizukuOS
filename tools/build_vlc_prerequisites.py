#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build new VLC providers in isolated outputs; never install or execute them."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[1]
PARTS = {"compat": ("M98VLC.DLL", "m98_vlc_compat", ["kernel32", "gdi32"]),
         "locale": ("M98LOC.DLL", "m98_vlc_locale", ["kernel32", "advapi32", "version"]),
         "process": ("M98CTX.DLL", "m98_vlc_process", ["kernel32"])}
# Explicit nonoverlapping bases avoid the MinGW linker deriving a different
# preferred address from each private output path. Native relocations remain.
IMAGE_BASES = {"compat": 0x68000000, "locale": 0x68100000, "process": 0x68200000}
PROBES = {"compat": ("VLCAPI.EXE", "tests/vlc_compat_probe.c", ["kernel32", "user32", "gdi32"]),
          "locale": ("VLCLOC.EXE", "tests/vlc_locale_probe.c", ["kernel32", "advapi32"]),
          "process": ("VLCCTX.EXE", "tests/vlc_process_probe.c", ["kernel32"])}
COMMON = ["-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
          "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-nostdlib",
          "-Wl,--gc-sections", "-Wl,--major-image-version,4", "-Wl,--minor-image-version,10",
          "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware",
          "-Wl,--no-insert-timestamp"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def artifact(path, native):
    with pefile.PE(str(path)) as pe:
        o = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem, o.MajorSubsystemVersion,
            o.MinorSubsystemVersion) != (0x14C, 0x10B, 2, 4, 10):
            raise ValueError("PE32 x86 GUI4.10 image required")
        if (o.MajorOperatingSystemVersion, o.MinorOperatingSystemVersion) != (4, 0):
            raise ValueError("native PE32 OS4.0 image required")
        if any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)) or o.DllCharacteristics & 0x140:
            raise ValueError("unexpected TLS/load-config/delay/CLR/ASLR/NX flags")
        imports = {}
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            dll = descriptor.dll.decode("ascii").upper()
            imports[dll] = []
            for symbol in descriptor.imports:
                if not symbol.name or symbol.name.decode("ascii") not in native.get(dll, ()):
                    raise ValueError("outside actual sameguest native export inventory")
                imports[dll].append(symbol.name.decode("ascii"))
        return {"path": str(path.resolve()), "bytes": path.stat().st_size, "sha256": digest(path), "imports": imports,
                "exports": [s.name.decode("ascii") for s in getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", ()) if s.name],
                "native_import_gate": "PASS", "native_execution": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parts", nargs="+", choices=tuple(PARTS), default=["compat", "locale", "process"])
    parser.add_argument("--native-exports", type=Path, required=True)
    parser.add_argument("--reuse-process-artifacts", type=Path,
                        help="Preserve exact process DLL/probe bytes from a source-bound prior build")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("new isolated repository build output required")
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc: parser.error("existing i686 MinGW compiler required")
    document = json.loads(args.native_exports.read_text())
    if document.get("status") != "PASS": parser.error("actual native export readback must pass")
    native = {}
    frozen = {"src/kex_abi.h": digest(ROOT / "src/kex_abi.h"),
              "platform/freestanding/memory.c": digest(ROOT / "platform/freestanding/memory.c"),
              "platform/freestanding/memory.h": digest(ROOT / "platform/freestanding/memory.h"),
              str(Path(__file__).relative_to(ROOT)): digest(Path(__file__))}
    for item in document["modules"]:
        path = Path(item["path"])
        if digest(path) != item["sha256"]: parser.error("native system input changed")
        native[item["module"].upper()] = {s["name"] for s in item["exports"] if s["name"]}
    for part in args.parts:
        stem = PARTS[part][1]
        for suffix in (".c", ".h", ".def"):
            path = ROOT / "src" / (stem + suffix)
            if not path.is_file(): parser.error("part sources not ready: " + str(path))
            frozen[str(path.relative_to(ROOT))] = digest(path)
        if part == "locale":
            for name in ("m98_vlc_locale_core.c", "m98_vlc_locale_core.h", "m98_vlc_geo.inc"):
                path = ROOT / "src" / name
                if not path.is_file(): parser.error("locale core not ready: " + str(path))
                frozen[str(path.relative_to(ROOT))] = digest(path)
        probe = ROOT / PROBES[part][1]
        if not probe.is_file(): parser.error("native probe not ready: " + str(probe))
        frozen[str(probe.relative_to(ROOT))] = digest(probe)
    if set(args.parts) == set(PARTS):
        frozen["tests/vlc_api_suite.c"] = digest(ROOT / "tests/vlc_api_suite.c")
    reused = None
    if args.reuse_process_artifacts:
        if "process" not in args.parts:
            parser.error("process reuse requires the process part")
        prior = args.reuse_process_artifacts.resolve(strict=True)
        if not prior.is_relative_to(ROOT / "build"):
            parser.error("isolated prior process build receipt required")
        old = json.loads(prior.read_text())
        if (old.get("schema") != "win98modern.vlc-prerequisite-build.v1" or old.get("status") != "PASS" or
                old.get("native_execution") is not False or old.get("application_success") is not False):
            parser.error("exact compile-only successful prior process receipt required")
        process_sources = ["src/kex_abi.h", "src/m98_vlc_process.c", "src/m98_vlc_process.h", "src/m98_vlc_process.def",
                           "tests/vlc_process_probe.c", "platform/freestanding/memory.c", "platform/freestanding/memory.h"]
        for name in process_sources:
            if (old.get("sources", {}).get(name) != frozen[name] or
                    digest(prior.parent / "frozen" / name) != frozen[name]):
                parser.error("current/frozen reused process source changed")
        if old.get("compiler", {}).get("sha256") != digest(Path(cc)):
            parser.error("reused process compiler identity changed")
        reused = {"producer": {"path": str(prior), "sha256": digest(prior)}, "artifacts": {},
                  "source_files": [{"path": str(prior.parent / "frozen" / name), "sha256": frozen[name]}
                                   for name in process_sources]}
        for name in ("M98CTX.DLL", "VLCCTX.EXE"):
            item = old.get("artifacts", {}).get(name, {})
            path = prior.parent / name
            if (Path(item.get("path", "")).resolve() != path or item.get("bytes") != path.stat().st_size or
                    item.get("sha256") != digest(path) or item.get("native_import_gate") != "PASS" or
                    item.get("native_execution") is not False):
                parser.error("exact reused process artifact changed")
            reused["artifacts"][name] = {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}
    out.mkdir(parents=True)
    for name in frozen:
        destination = out / "frozen" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
        if digest(destination) != frozen[name]:
            raise ValueError("source changed while freezing")
    receipt = {"schema": "win98modern.vlc-prerequisite-build.v1", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "status": "FAIL", "native_execution": False, "application_success": False,
               "compiler": {"path": cc, "sha256": digest(Path(cc)), "version": subprocess.check_output([cc, "--version"], text=True).splitlines()[0]},
               "native_exports": {"path": str(args.native_exports.resolve()), "sha256": digest(args.native_exports)},
               "sources": frozen, "reused_process": reused, "steps": [], "artifacts": {}}
    def run(command):
        with (out / "build.log").open("a") as log:
            log.write(json.dumps(command) + "\n"); log.flush()
            p = subprocess.run(command, cwd=ROOT, stdout=log, stderr=log, timeout=120)
        receipt["steps"].append({"command": command, "exit_code": p.returncode})
        if p.returncode: raise RuntimeError("compiler failed; see retained build.log")
    try:
        for part in args.parts:
            dll, stem, libraries = PARTS[part]
            if part == "process" and reused:
                shutil.copyfile(reused["artifacts"][dll]["path"], out / dll)
                if digest(out / dll) != reused["artifacts"][dll]["sha256"]:
                    raise ValueError("process DLL changed during copying")
                receipt["artifacts"][dll] = artifact(out / dll, native)
                continue
            sources = out / "frozen"
            extras = [str(sources / "src/m98_vlc_locale_core.c")] if part == "locale" else []
            # The root-owned locale implementation deliberately uses compact
            # guard statements; this single style warning is disabled only for
            # that part, with every other warning remaining fatal.
            part_flags = ["-Wno-misleading-indentation"] if part == "locale" else []
            run([cc, *COMMON, *part_flags, "-shared", "-Wl,--entry,_DllMain@12", "-Wl,--subsystem,windows:4.10",
                 f"-Wl,--image-base,0x{IMAGE_BASES[part]:x}",
                 "-o", str(out / dll), str(sources / "src" / (stem + ".c")),
                 str(sources / "src" / (stem + ".def")), str(sources / "platform/freestanding/memory.c"),
                 *extras, *("-l" + lib for lib in libraries)])
            receipt["artifacts"][dll] = artifact(out / dll, native)
            with pefile.PE(str(out / dll)) as image:
                if image.OPTIONAL_HEADER.ImageBase != IMAGE_BASES[part] or image.OPTIONAL_HEADER.SizeOfImage >= 0x100000:
                    raise ValueError("provider preferred-address ownership interval changed")
                receipt["artifacts"][dll]["preferred_image_base"] = IMAGE_BASES[part]
        for part in args.parts:
            executable, probe, libraries = PROBES[part]
            if part == "process" and reused:
                shutil.copyfile(reused["artifacts"][executable]["path"], out / executable)
                if digest(out / executable) != reused["artifacts"][executable]["sha256"]:
                    raise ValueError("process probe changed during copying")
                receipt["artifacts"][executable] = artifact(out / executable, native)
                continue
            part_flags = ["-Wno-misleading-indentation"] if part == "locale" else []
            run([cc, *COMMON, *part_flags, "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
                 "-o", str(out / executable), str(out / "frozen" / probe),
                 str(out / "frozen/platform/freestanding/memory.c"),
                 *("-l" + lib for lib in libraries)])
            receipt["artifacts"][executable] = artifact(out / executable, native)
        if set(args.parts) == set(PARTS):
            run([cc, *COMMON, "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
                 "-o", str(out / "VLCSUITE.EXE"), str(out / "frozen/tests/vlc_api_suite.c"),
                 str(out / "frozen/platform/freestanding/memory.c"), "-lkernel32"])
            receipt["artifacts"]["VLCSUITE.EXE"] = artifact(out / "VLCSUITE.EXE", native)
        for path, pin in frozen.items():
            if digest(ROOT / path) != pin: raise ValueError("source changed during build")
        if digest(args.native_exports) != receipt["native_exports"]["sha256"]: raise ValueError("native receipt changed during build")
        for item in document["modules"]:
            if digest(Path(item["path"])) != item["sha256"]:
                raise ValueError("native system input changed during build")
        if digest(Path(cc)) != receipt["compiler"]["sha256"]:
            raise ValueError("compiler changed during build")
        if reused:
            if digest(Path(reused["producer"]["path"])) != reused["producer"]["sha256"]:
                raise ValueError("reused process producer changed during build")
            for item in reused["artifacts"].values():
                if digest(Path(item["path"])) != item["sha256"]:
                    raise ValueError("reused process artifacts changed during build")
            for item in reused["source_files"]:
                if digest(Path(item["path"])) != item["sha256"]:
                    raise ValueError("reused process frozen source changed during build")
        receipt["status"] = "PASS"
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired, pefile.PEFormatError) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "artifacts": len(receipt["artifacts"]), "receipt": str(out / "result.json"), "error": receipt.get("error")}, indent=2))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
