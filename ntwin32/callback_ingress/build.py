#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze, sanitize-test and compile own callback ingress; never start a guest."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

import pefile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("new isolated build directory under this worktree required")
    compilers = {key: shutil.which(value) for key, value in
                 (("gcc", "gcc"), ("clang", "clang"), ("native", "i686-w64-mingw32-gcc"))}
    if not all(compilers.values()):
        parser.error("existing GCC, Clang and i686 MinGW compilers required")
    names = ("ingress.c", "ingress.h", "host_test.c", "fixture.c", "fixture.h",
             "fixture.def", "fixture_contract.h", "fixture_contract_test.c",
             "native_probe.c", "native_suite.c", "build.py", "README.md")
    sources = [HERE / n for n in names]
    sources += [ROOT / "ntwin32/native_loader" / n for n in
                ("tls_runtime.c", "tls_runtime.h", "pe.c", "pe.h", "tls_compiler_fixture.c")]
    sources += [ROOT / "platform/freestanding" / n for n in ("memory.c", "memory.h")]
    inventory = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    sources.append(inventory)
    pins = {str(p.relative_to(ROOT)): sha(p) for p in sources}
    out.mkdir(parents=True)
    receipt = {"schema": "win98modern.callback-ingress-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "sources": pins,
               "steps": [], "native_executed": False, "application_success": False,
               "production_loader_integrated": False, "production_provider_integrated": False,
               "compilers": {k: {"path": p, "sha256": sha(p)} for k, p in compilers.items()}}
    for p in sources:
        dest = out / "frozen" / p.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dest)
        if sha(dest) != pins[str(p.relative_to(ROOT))]:
            receipt["error"] = "source changed while freezing"
            (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
            return 1
    own = out / "frozen/ntwin32/callback_ingress"
    native = out / "frozen/ntwin32/native_loader"
    support = out / "frozen/platform/freestanding/memory.c"

    def run(command, name):
        log = out / (name + ".log")
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=stream,
                                    env=env, timeout=120)
        receipt["steps"].append({"name": name, "command": command, "exit_code": result.returncode,
                                 "log": {"path": str(log), "sha256": sha(log)}})
        if result.returncode:
            raise ValueError("build/control failed: " + name)

    cc = compilers["native"]
    flags = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
             "-Wno-misleading-indentation", "-fno-builtin", "-fno-tree-loop-distribute-patterns",
             "-fno-stack-protector", "-ffunction-sections", "-fdata-sections", "-nostdlib",
             "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"]
    try:
        host_results = {}
        for name in ("gcc", "clang"):
            host = out / (name + "-host")
            command = [compilers[name]] + (["--no-default-config"] if name == "clang" else [])
            sanitizer = (["-fsanitize=address,undefined"] if name == "clang" else
                         ["-fsanitize=undefined", "-fsanitize-undefined-trap-on-error"])
            command += ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"] + sanitizer + ["-fno-sanitize-recover=all",
                        "-fno-omit-frame-pointer", "-pthread", str(own / "ingress.c"),
                        str(own / "host_test.c"), str(native / "tls_runtime.c"), "-o", str(host)]
            run(command, name + "-host-compile")
            run([str(host)], name + "-host-controls")
            raw = (out / (name + "-host-controls.log")).read_text()
            match = re.fullmatch(r"PASS CHECKS=(\d+) REAL_PTHREAD_WORKERS=8 REUSED_CALLBACKS=8000\n"
                                 r"NATIVE_EXECUTED=0 APPLICATION_SUCCESS=0\n", raw)
            if not match or int(match[1]) < 100000:
                raise ValueError("complete sanitized real TLS/worker controls absent")
            host_results[name] = {"checks": int(match[1]), "real_pthread_workers": 8,
                                  "reused_callbacks": 8000, "sanitizer":
                                  "ASan/UBSan PASS" if name == "clang" else "UBSan trap PASS"}
        receipt["host_results"] = host_results
        run([compilers["clang"], "--no-default-config", "--target=i686-pc-windows-msvc",
             "-march=i486", "-O2", "-fno-stack-protector", "-c",
             str(native / "tls_compiler_fixture.c"), "-o", str(out / "compiler.obj")], "ms-tls-compile")
        run(flags + ["-shared", "-Wl,--entry,_DllMain@12", "-Wl,--undefined,__tls_used",
                     "-Wl,--defsym,__tls_array=0x2c", "-o", str(out / "CIFIX.DLL"),
                     str(own / "fixture.c"), str(out / "compiler.obj"), str(own / "fixture.def")], "native-fixture")
        run(flags + ["-Wl,--entry,_entry@0", "-o", str(out / "CIWRK.EXE"),
                     str(own / "native_probe.c"), str(own / "ingress.c"), str(native / "tls_runtime.c"),
                     str(native / "pe.c"), str(support), "-lkernel32", "-lgcc"], "native-probe")
        run(flags + ["-Wl,--entry,_entry@0", "-o", str(out / "CISUIT.EXE"),
                     str(own / "native_suite.c"), str(support), "-lkernel32", "-lgcc"], "native-suite")
        # Run the SAME native fixture admission predicate on the actual linked
        # DLL; export enumeration alone previously missed null .idata metadata.
        run([compilers["clang"], "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
             str(own / "fixture_contract_test.c"), str(native / "pe.c"),
             "-o", str(out / "fixture-contract-host")], "compiled-fixture-contract-compile")
        run([str(out / "fixture-contract-host"), str(out / "CIFIX.DLL")], "compiled-fixture-contract")
        contract = (out / "compiled-fixture-contract.log").read_text()
        matched = re.fullmatch(r"PASS COMPILED_FIXTURE_ZERO_IMPORT_PROTOCOL_CHECKS=(\d+) NATIVE_EXECUTED=0\n", contract)
        if not matched or int(matched[1]) < 16:
            raise ValueError("actual compiled fixture/native admission protocol controls absent")
        receipt["compiled_fixture_contract_checks"] = int(matched[1])
        available = json.loads((out / "frozen" / inventory.relative_to(ROOT)).read_text())["dlls"]
        artifacts = []
        for name in ("CIFIX.DLL", "CIWRK.EXE", "CISUIT.EXE"):
            p = out / name
            with pefile.PE(str(p)) as pe:
                o = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem, o.MajorSubsystemVersion,
                    o.MinorSubsystemVersion, o.MajorOperatingSystemVersion, o.MinorOperatingSystemVersion) != (0x14c, 0x10b, 2, 4, 10, 4, 0):
                    raise ValueError("i486/native GUI PE32 profile differs")
                if pe.is_dll() != name.endswith(".DLL") or o.DllCharacteristics & 0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (10, 13, 14)):
                    raise ValueError("unexpected native runtime features")
                imports = {}
                for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
                    dll = descriptor.dll.decode().upper()
                    imports[dll] = []
                    for entry in descriptor.imports:
                        if not entry.name or entry.name.decode() not in available.get(dll, ()):
                            raise ValueError("outside preserved actual OEM exports")
                        imports[dll].append(entry.name.decode())
                if set(imports) != (set() if name == "CIFIX.DLL" else {"KERNEL32.DLL"}):
                    raise ValueError("mapped fixture must have zero native imports")
                extra = {}
                if name == "CIFIX.DLL":
                    exports = sorted(s.name.decode() for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name)
                    if exports != ["CiBind", "CiWord"] or o.DATA_DIRECTORY[9].Size != 24 or not o.DATA_DIRECTORY[9].VirtualAddress:
                        raise ValueError("own compiler-TLS fixture profile differs")
                    code = b"".join(s.get_data() for s in pe.sections if s.Characteristics & 0x20000000)
                    if code.count(b"\x64\x8b") != 2:
                        raise ValueError("Microsoft-ABI compiler FS instructions absent")
                    extra = {"exports": exports, "real_ms_abi_tls": True}
                elif o.DATA_DIRECTORY[9].VirtualAddress:
                    raise ValueError("native observer must have no automatic TLS directory")
                artifacts.append({"path": str(p), "bytes": p.stat().st_size, "sha256": sha(p),
                                  "imports": imports, "oem_import_gate": "PASS", **extra})
        receipt["artifacts"] = artifacts
        if any(sha(ROOT / n) != pin or sha(out / "frozen" / n) != pin for n, pin in pins.items()):
            raise ValueError("source mutated during validation")
        total = sum(p.stat().st_size for p in out.rglob("*") if p.is_file())
        if total > 16 * 1024 * 1024:
            raise ValueError("isolated 16 MiB output allowance exceeded")
        receipt.update(status="HOST_BUILD_PASS_NATIVE_PENDING", output_bytes=total,
                       sources_unchanged_during_validation=True)
    except (OSError, ValueError, subprocess.TimeoutExpired, pefile.PEFormatError) as error:
        receipt["error"] = str(error)
    result = out / "result.json"
    result.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [{"source": a["path"], "guest": "C:\\VXDLAB\\" + Path(a["path"]).name,
                                "bytes": a["bytes"], "sha256": a["sha256"]} for a in receipt["artifacts"]],
                    "outputs": ["C:\\VXDLAB\\CIWRK.LOG", "C:\\VXDLAB\\CISUIT.LOG"], "backups": [],
                    "source_receipts": [{"path": str(result), "sha256": sha(result)}],
                    "command": "C:\\VXDLAB\\CISUIT.EXE",
                    "scope": "Own mapped compiler TLS on actual provider-like persistent workers. Native/app pending; no production provider/loader integration."}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "result": str(result),
                      "host_results": receipt.get("host_results"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
