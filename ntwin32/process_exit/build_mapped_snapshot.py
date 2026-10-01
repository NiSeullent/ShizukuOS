#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build own closed mapped-exit diagnostic; never boot or admit applications."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ORIGINAL_BUILD = ROOT / "build/process-exit-win98-guard-20261001T0112-v5"
ORIGINAL_PIN = "1115f7968e7ee96503146bddd654781c1f38094c4c595eb268706d32fad29387"
MANIFEST = ROOT / "build/process-exit-win98-guard-prepared-20261001T0114-v5/manifest.json"
MANIFEST_PIN = "729b3a6d9ca02dc7bed789a01a5c69a5ba0fe395309e1de1235948be162dca32"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent private build directory required")
    if shutil.disk_usage(ROOT).free < 17 * 1024 ** 3 + 512 * 1024 ** 2:
        parser.error("strict 17 GiB plus 512 MiB floor required")
    cc, host = shutil.which("i686-w64-mingw32-gcc"), shutil.which("clang")
    if not cc or not host:
        parser.error("existing native and MS-ABI/sanitizer compilers required")
    if sha(ORIGINAL_BUILD / "result.json") != ORIGINAL_PIN or sha(MANIFEST) != MANIFEST_PIN:
        parser.error("unchanged genuine v5 manager corpus required")
    old_inputs = json.loads(MANIFEST.read_text())["inputs"]
    owned_names = ("mapped_snapshot.h", "mapped_snapshot.c", "mapped_snapshot_test.c",
                   "mapped_fixture.h", "mapped_fixture.c", "mapped_fixture.def",
                   "mapped_native_probe.c", "mapped_native_suite.c", "build_mapped_snapshot.py")
    kernel_names = ("original_kernel.h", "original_kernel_win98_v3.c", "main_image.h", "main_image.c",
                    "win98_guard.h", "win98_guard.c", "win98_export.h", "win98_export.c")
    source_paths = [HERE / n for n in owned_names + kernel_names]
    source_paths += [ROOT / "ntwin32/native_loader" / n for n in
                     ("pe.c", "pe.h", "tls_runtime.c", "tls_runtime.h", "tls_compiler_fixture.c")]
    source_paths += [ROOT / "platform/freestanding" / n for n in ("memory.c", "memory.h")]
    inventory = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    source_paths.append(inventory)
    pins = {str(p.relative_to(ROOT)): sha(p) for p in source_paths}
    out.mkdir(parents=True)
    for p in source_paths:
        dest = out / "frozen" / p.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)
        if sha(dest) != pins[str(p.relative_to(ROOT))]:
            raise ValueError("source changed while freezing")
    source = out / "frozen/ntwin32/process_exit"
    native = out / "frozen/ntwin32/native_loader"
    memory = out / "frozen/platform/freestanding/memory.c"
    receipt = {"schema": "win98modern.own-mapped-exit-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources": pins,
               "compilers": [{"path": cc, "sha256": sha(cc)}, {"path": host, "sha256": sha(host)}],
               "steps": [], "native_executed": False, "application_success": False,
               "production_loader_integrated": False, "physical_worker_cessation_established": False,
               "original_manager_producer": {"path": str(ORIGINAL_BUILD / "result.json"), "sha256": ORIGINAL_PIN},
               "original_manager_manifest": {"path": str(MANIFEST), "sha256": MANIFEST_PIN}}
    flags = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
             "-Wno-misleading-indentation", "-fno-builtin", "-fno-tree-loop-distribute-patterns",
             "-fno-stack-protector", "-ffunction-sections", "-fdata-sections", "-nostdlib",
             "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp", "-Xlinker", "--stack", "-Xlinker", "2097152,4096"]
    def run(command, name):
        with (out / (name + ".log")).open("wb") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=log, timeout=120)
        receipt["steps"].append({"command": command, "exit_code": result.returncode,
                                 "log": {"path": str(out / (name + ".log")), "sha256": sha(out / (name + ".log"))}})
        if result.returncode:
            raise ValueError("bounded build/control failed: " + name)
    try:
        run([host, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
             str(source / "mapped_snapshot.c"), str(source / "mapped_snapshot_test.c"),
             "-o", str(out / "mapped-host")], "host-compile")
        run([str(out / "mapped-host")], "host-controls")
        host_log = (out / "host-controls.log").read_text()
        if not host_log.startswith("PASS ") or "native_executed=false" not in host_log or "runtime error" in host_log or "Sanitizer" in host_log:
            raise ValueError("actual sanitized pure ownership controls missing")
        receipt["host_controls"] = host_log.strip()
        run([host, "--no-default-config", "--target=i686-pc-windows-msvc", "-march=i486", "-O2", "-fno-stack-protector",
             "-c", str(native / "tls_compiler_fixture.c"), "-o", str(out / "compiler.obj")], "ms-tls-compile")
        run(flags + ["-shared", "-Wl,--entry,_DllMain@12", "-Wl,--undefined,__tls_used", "-Wl,--defsym,__tls_array=0x2c",
                     "-o", str(out / "MXFIX.DLL"), str(source / "mapped_fixture.c"), str(out / "compiler.obj"),
                     str(source / "mapped_fixture.def")], "own-fixture")
        run(flags + ["-Wl,--entry,_entry@0", "-o", str(out / "MXPROBE.EXE"),
                     str(source / "mapped_native_probe.c"), str(source / "mapped_snapshot.c"), str(native / "pe.c"),
                     str(native / "tls_runtime.c"), str(source / "original_kernel_win98_v3.c"),
                     str(source / "main_image.c"), str(source / "win98_guard.c"), str(source / "win98_export.c"),
                     str(memory), "-lkernel32", "-lgcc"], "native-probe")
        run(flags + ["-Wl,--entry,_entry@0", "-o", str(out / "MXSUIT.EXE"), str(source / "mapped_native_suite.c"),
                     str(memory), "-lkernel32"], "native-suite")
        available = json.loads((out / "frozen" / inventory.relative_to(ROOT)).read_text())["dlls"]
        available = {k.upper(): set(v) for k, v in available.items()}
        artifacts = []
        for name in ("MXFIX.DLL", "MXPROBE.EXE", "MXSUIT.EXE"):
            p = out / name
            with pefile.PE(str(p)) as pe:
                o = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem, o.MajorSubsystemVersion, o.MinorSubsystemVersion,
                    o.MajorOperatingSystemVersion, o.MinorOperatingSystemVersion) != (0x14c, 0x10b, 2, 4, 10, 4, 0):
                    raise ValueError("classic native GUI profile differs")
                if o.DllCharacteristics & 0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (10, 13, 14)) or pe.is_dll() != name.endswith(".DLL"):
                    raise ValueError("unexpected runtime/native profile")
                imports = {}
                for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
                    dll = module.dll.decode().upper(); imports[dll] = []
                    for entry in module.imports:
                        if not entry.name or entry.name.decode() not in available.get(dll, set()):
                            raise ValueError("outside actual OEM exports")
                        imports[dll].append(entry.name.decode())
                if set(imports) != (set() if name == "MXFIX.DLL" else {"KERNEL32.DLL"}):
                    raise ValueError("own mapped code must have zero native imports")
                item = {"path": str(p), "bytes": p.stat().st_size, "sha256": sha(p), "imports": imports,
                        "native_import_gate": "PASS", "native_executed": False}
                if name == "MXFIX.DLL":
                    exports = {e.name.decode() for e in pe.DIRECTORY_ENTRY_EXPORT.symbols if e.name}
                    if exports != {"MxBind", "MxWord"} or not o.DATA_DIRECTORY[9].VirtualAddress or o.DATA_DIRECTORY[9].Size != 24:
                        raise ValueError("actual own TLS/export ABI differs")
                    code = b"".join(s.get_data() for s in pe.sections if s.Characteristics & 0x20000000)
                    if code.count(b"\x64\x8b") != 2:
                        raise ValueError("actual compiler FS operands missing")
                    item["exports"] = sorted(exports)
                elif o.DATA_DIRECTORY[9].VirtualAddress:
                    raise ValueError("native EXE must have no static TLS")
            artifacts.append(item)
        for name in ("M98EXIT.DLL", "PXDEPA.DLL", "PXDEPB.DLL"):
            item = next(i for i in old_inputs if Path(i["source"]).name == name)
            if sha(item["source"]) != item["sha256"]:
                raise ValueError("unchanged actual v5 artifact changed")
            shutil.copyfile(item["source"], out / name)
            if (out / name).stat().st_size != item["bytes"] or sha(out / name) != item["sha256"]:
                raise ValueError("original manager copy changed")
            artifacts.append({"path": str(out / name), "bytes": item["bytes"], "sha256": item["sha256"],
                              "origin": "Byte-identical accepted genuine native v5 artifact; no rebuild", "native_executed_in_this_fixture": False})
        if any(sha(ROOT / n) != pin or sha(out / "frozen" / n) != pin for n, pin in pins.items()):
            raise ValueError("source changed during build")
        receipt.update(status="HOST_BUILD_PASS_NATIVE_PENDING", artifacts=artifacts)
    except (OSError, ValueError, pefile.PEFormatError, subprocess.TimeoutExpired) as error:
        receipt["error"] = str(error)
    p = out / "result.json";p.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [{"source": i["path"], "guest": "C:\\VXDLAB\\" + Path(i["path"]).name,
                                "bytes": i["bytes"], "sha256": i["sha256"]} for i in artifacts],
                    "outputs": ["C:\\VXDLAB\\" + n for n in ("MXMA.LOG", "MXWO.LOG", "MXNO.LOG", "MXDP.LOG", "MXSUIT.LOG")],
                    "backups": [], "source_receipts": [{"path": str(p), "sha256": sha(p)}],
                    "command": "C:\\VXDLAB\\MXSUIT.EXE",
                    "scope": "Own zero-import mapped TLS notifications plus actual missing-TLS and detached-owned-dependency refusal. No production graph/app admission or physical-worker cessation claim."}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "result": str(p), "sha256": sha(p), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
