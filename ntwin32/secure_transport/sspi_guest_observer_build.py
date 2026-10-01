#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the fixed SSPI child observer; no guest, staging or store changes.

Original project recipe: freeze its C source, bind the actual compiler header
closure and selected tools/archive, compile an i486 GUI PE32 without a CRT,
and compare its imports with the original Win98 SE OEM export inventory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import subprocess

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FLOOR = 20 * 1024 ** 3
ALLOWANCE = 8 * 1024 ** 2
SOURCE_NAMES = ("sspi_guest_observer.c", "sspi_guest_observer_host_test.py",
                "sspi_guest_observer_build.py", "sspi_guest_observer_HANDOFF.md")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def binding(path: Path) -> dict:
    path = path.resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(message)


def dependencies(data: str) -> set[Path]:
    require(":" in data, "Compiler dependency target is absent")
    words = shlex.split(data.split(":", 1)[1].replace("\\\n", " "))
    require(bool(words), "Compiler dependency list is empty")
    return {Path(word).resolve(strict=True) for word in words}


def model_receipt(path: Path, source_hashes: dict, sanitizer: str) -> dict:
    receipt = json.loads(path.read_bytes())
    require(receipt.get("schema") == "win98modern.sspi-observer-host-fault-model.v1"
            and receipt.get("status") == "PASS" and receipt.get("test_exit") == 0
            and receipt.get("checks") == 45 and len(set(receipt.get("cases", []))) == 45
            and receipt.get("sanitizer") == sanitizer
            and receipt.get("native_windows_executed") is False
            and receipt.get("native_sspi_verified") is False,
            "Require the corresponding 45-case actual-source host model PASS")
    for key, name in (("source", "sspi_guest_observer.c"),
                      ("test_driver", "sspi_guest_observer_host_test.py")):
        row = receipt[key]
        require(Path(row["path"]).resolve() == HERE / name
                and row["sha256"] == source_hashes[name]
                and digest(Path(row["path"])) == row["sha256"],
                "Host model does not bind the current source/driver")
    for row in receipt["files"]:
        artifact = Path(row["path"]).resolve(strict=True)
        require(artifact.is_relative_to(path.resolve().parent)
                and digest(artifact) == row["sha256"], "Host model artifact changed")
    return receipt


def audit(binary: Path, baseline: Path) -> dict:
    inventory = json.loads(baseline.read_bytes())["dlls"]
    pe = pefile.PE(str(binary), fast_load=False)
    imports, absent = {}, []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = entry.dll.decode("ascii").upper()
        names = [row.name.decode("ascii") if row.name else "#" + str(row.ordinal)
                 for row in entry.imports]
        imports[dll] = names
        absent += [{"dll": dll, "symbol": name} for name in names
                   if name not in inventory.get(dll, [])]
    forbidden = {str(index): {"rva": pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].VirtualAddress,
                             "bytes": pe.OPTIONAL_HEADER.DATA_DIRECTORY[index].Size}
                 for index in (9, 10, 13, 14)}
    relocs = sum(entry.type == 3 for block in getattr(pe, "DIRECTORY_ENTRY_BASERELOC", [])
                 for entry in block.entries)
    exports = len(getattr(getattr(pe, "DIRECTORY_ENTRY_EXPORT", None), "symbols", []))
    result = {"machine": pe.FILE_HEADER.Machine, "optional_magic": pe.OPTIONAL_HEADER.Magic,
              "dll": bool(pe.FILE_HEADER.Characteristics & 0x2000),
              "timestamp": pe.FILE_HEADER.TimeDateStamp, "subsystem": pe.OPTIONAL_HEADER.Subsystem,
              "os_version": [pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                             pe.OPTIONAL_HEADER.MinorOperatingSystemVersion],
              "subsystem_version": [pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                                    pe.OPTIONAL_HEADER.MinorSubsystemVersion],
              "entry_rva": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
              "imports": imports, "import_count": sum(map(len, imports.values())),
              "absent_from_oem_exports": absent, "forbidden_directories": forbidden,
              "highlow_relocations": relocs, "export_count": exports}
    result["static_gate_passed"] = (
        result["machine"] == 0x14c and result["optional_magic"] == 0x10b
        and not result["dll"] and result["timestamp"] == 0 and result["subsystem"] == 2
        and result["os_version"] == [4, 10] and result["subsystem_version"] == [4, 10]
        and result["entry_rva"] != 0 and set(imports) == {"KERNEL32.DLL"}
        and bool(imports["KERNEL32.DLL"]) and not absent and not exports and relocs > 0
        and not any(row["rva"] or row["bytes"] for row in forbidden.values()))
    pe.close()
    return result


def build(output: Path, normal: Path, ubsan: Path) -> dict:
    output = output.resolve()
    require(output.is_relative_to(ROOT / "build") and not output.exists(),
            "Choose a new private output directory below this worktree's build/")
    require(shutil.disk_usage(ROOT).free >= FLOOR + ALLOWANCE,
            "Preserve the 20 GiB reserve plus the bounded 8 MiB build allowance")
    source_hashes = {name: digest(HERE / name) for name in SOURCE_NAMES}
    models = []
    for path, sanitizer in ((normal, "none"), (ubsan, "ubsan")):
        models.append(model_receipt(path, source_hashes, sanitizer))
    baseline = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    compiler_name = shutil.which("i686-w64-mingw32-gcc")
    require(bool(compiler_name), "Installed x86 MinGW compiler is required")
    compiler = Path(compiler_name).resolve(strict=True)
    commands, retained = [], {Path(normal).resolve(), Path(ubsan).resolve(), baseline.resolve(), compiler}
    for model in models:
        retained.update(Path(row["path"]).resolve() for row in model["files"])
    output.mkdir(parents=True, mode=0o700)
    snapshots = output / "source"
    snapshots.mkdir()
    for name in SOURCE_NAMES:
        (snapshots / name).write_bytes((HERE / name).read_bytes())
    source = snapshots / "sspi_guest_observer.c"
    object_file, binary = output / "SSPWATCH.o", output / "SSPWATCH.EXE"
    dependency_file, link_map = output / "dependencies.d", output / "SSPWATCH.map"
    receipt = {"schema": "win98modern.sspi-native-observer.v1", "status": "FAIL",
               "source_sha256": source_hashes, "source": binding(HERE / source.name),
               "source_snapshot": binding(source), "compiler_argv": commands,
               "native_guest_verified": False, "native_sspi_verified": False,
               "os_provider_registered": False, "network_used": False,
               "scope": "Build/import checks and host observer model only"}

    def run(argv: list[str], label: str) -> str:
        commands.append({"label": label, "argv": argv})
        proc = subprocess.run(argv, capture_output=True, timeout=60)
        (output / (label + ".log")).write_bytes(proc.stdout + proc.stderr)
        require(proc.returncode == 0, "Failed " + label + "; inspect its retained log")
        return proc.stdout.decode("utf-8")

    try:
        kernel_archive = None
        for option, name in (("-print-prog-name=cc1", "cc1"),
                             ("-print-prog-name=collect2", "collect2"),
                             ("-print-prog-name=as", "as"), ("-print-prog-name=ld", "ld"),
                             ("-print-file-name=libkernel32.a", "kernel32")):
            selected = run([str(compiler), option], "select-" + name).strip()
            if not Path(selected).is_absolute():
                selected = shutil.which(selected) or selected
            selected_path = Path(selected).resolve(strict=True)
            require(selected_path.is_file(), "Selected native tool/archive is absent")
            retained.add(selected_path)
            if name == "kernel32":
                kernel_archive = selected_path
        run([str(compiler), "--version"], "compiler-version")
        flags = ["-std=c99", "-Wall", "-Wextra", "-Werror", "-Os", "-march=i486",
                 "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib",
                 "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400"]
        preliminary = run([str(compiler), *flags, "-M", "-MT", "SSPWATCH", str(source)],
                          "dependency-query")
        header_paths = dependencies(preliminary)
        retained.update(header_paths)
        retained.update((HERE / name).resolve() for name in SOURCE_NAMES)
        retained.add(Path(pefile.__file__).resolve())
        before = {str(path): binding(path) for path in retained}
        run([str(compiler), *flags, "-MD", "-MF", str(dependency_file), "-MT", "SSPWATCH",
             "-c", str(source), "-o", str(object_file)], "compile")
        require(dependencies(dependency_file.read_text()) == header_paths,
                "Actual compilation's header closure differs from the prequery")
        run([str(compiler), "-nostdlib",
             "-Wl,--entry,_mainCRTStartup,--subsystem,windows:4.10,--no-insert-timestamp",
             "-Wl,--major-os-version,4,--minor-os-version,10", "-Wl,-Map," + str(link_map),
             str(object_file), str(kernel_archive), "-o", str(binary)], "link")
        map_inputs = [row[5:].strip() for row in link_map.read_text().splitlines()
                      if row.startswith("LOAD ")]
        # GNU PE ld creates this in-memory relocation/export-section BFD; it
        # is not a disk binary input. No other synthetic name is accepted.
        require(map_inputs.count("dll stuff") == 1, "Expected GNU PE relocation filler is absent")
        loaded = {Path(row).resolve(strict=True) for row in map_inputs if row != "dll stuff"}
        require(loaded == {object_file.resolve(), kernel_archive},
                "Unexpected implicit binary input in the native link map")
        pe_audit = audit(binary, baseline)
        require(pe_audit["static_gate_passed"], "SSPWATCH native PE/import gate failed")
        require(before == {str(path): binding(path) for path in retained},
                "Compiler/header/source/model/baseline inputs changed during the build")
        require(source_hashes == {name: digest(HERE / name) for name in SOURCE_NAMES},
                "Observer source set changed during the build")
        for path, sanitizer in ((normal, "none"), (ubsan, "ubsan")):
            model_receipt(path, source_hashes, sanitizer)
        require(sum(path.stat().st_size for path in output.rglob("*") if path.is_file()) <= ALLOWANCE,
                "Observer build exceeded its 8 MiB bound")
        receipt.update(status="PASS", retained_inputs=list(before.values()),
                       link_map_synthetic_inputs=["dll stuff"],
                       header_count=len(header_paths), host_models=[binding(normal), binding(ubsan)],
                       binary={**binding(binary), "pe_audit": pe_audit},
                       artifacts=[binding(path) for path in output.rglob("*") if path.is_file()])
    except Exception as error:
        receipt["error"] = str(error)
        raise
    finally:
        (output / "observer-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return {"receipt": binding(output / "observer-result.json"), "binary": receipt["binary"],
            "native_guest_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--host-normal", type=Path, required=True)
    parser.add_argument("--host-ubsan", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.output, args.host_normal, args.host_ubsan)))


if __name__ == "__main__":
    main()
