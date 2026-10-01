#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze/build explicit mapped resource adapter; no staging or VM execution."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
READER = ROOT / "build/chromium-resources-validation-v3-20261001/result.json"
READER_SHA = "9553009dfb30df05862880f3ad6215fcf270cfa88f4c30dfcb07c611193608b3"
PARENTS = [
    (ROOT / "build/resource-adapter-validation-20261001T0659-v2/result.json",
     "283a50ccc1baf707550ef15d9fbdec8439fdd74bd05b44f9158c17e05a4fae0d"),
    (ROOT / "build/resource-adapter-validation-20261001T0659-v2/manifest.json",
     "c86bb6ddc03a3c9953ca760246a26dd0e1aa759a222eb2b4a67a2c91b5929a0d"),
    (ROOT / "build/resource-adapter-independent-review-20261001T0720-v2/review.json",
     "eb46bc510d150521f8c9a461debf89a83882817501a78a254fee5753f3fe80d4"),
]
ORIGINALS = [
    (ROOT / "build/latest-app-preflight-20260930/chromium-157.0.8080.0-1707946/chrome.exe",
     "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823", 54),
    (ROOT / "build/chromium-large-image-20260930T2336/chrome.dll",
     "f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158", 105),
]
READER_PINS = {
    "resources.c": "156f534e01bf2bf197196abac20ade010f7b7a25d6a845f4a696f0c23bcbaf6b",
    "resources.h": "4cbc299811e1edd5a33bf1e05155809a55acd9b2728665a453fa64af1a18ff0b",
    "../native_loader/pe.c": "4a7857bc90eed7d7b4d084ba866da657c21c5b1c1e34d7c2c3964231cce3b71a",
    "../native_loader/pe.h": "eade2d1be3395bd5a0fbe849921afebba713a78e471f60d759d1fe4afa70dd7b",
}


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent private build directory required")
    if shutil.disk_usage(ROOT).free < 17 * 1024**3 + 512 * 1024**2:
        parser.error("existing 17 GiB plus 512 MiB floor required")
    out.mkdir(parents=True)
    receipt = {"schema": "win98modern.mapped-resource-adapter.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "steps": [],
               "native_executed": False, "application_success": False,
               "chromium_entry_calls": 0, "production_loader_integrated": False,
               "runtime_admission_changed": False, "observer_own_os_exit_proven": False,
               "reader_receipt": {"path": str(READER), "sha256": READER_SHA}}

    def run(command, name, timeout=120):
        log = out / (name + ".log")
        with log.open("wb") as stream:
            result = subprocess.run(command, cwd=ROOT, stdout=stream, stderr=stream, timeout=timeout)
        receipt["steps"].append({"command": command, "exit_code": result.returncode,
                                  "log": {"path": str(log), "sha256": sha(log)}})
        if result.returncode:
            raise ValueError("bounded build/control failed: " + name)
        return log.read_text()

    try:
        if sha(READER) != READER_SHA:
            raise ValueError("reader receipt changed")
        receipt["parent_receipts"] = []
        for p, pin in PARENTS:
            if sha(p) != pin:
                raise ValueError("held v2 producer/manifest/review changed")
            target = out / "parents" / p.parent.name / p.name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, target)
            if sha(target) != pin:
                raise ValueError("parent changed while freezing")
            receipt["parent_receipts"].append({"path": str(p), "sha256": pin, "frozen": str(target)})
        for name, pin in READER_PINS.items():
            if sha(HERE / name) != pin:
                raise ValueError("held reader/parser changed: " + name)
        receipt["original_inputs"] = []
        for path, pin, leaves in ORIGINALS:
            if sha(path) != pin:
                raise ValueError("actual immutable Chromium input changed")
            receipt["original_inputs"].append({"path": str(path), "bytes": path.stat().st_size,
                                               "sha256": pin, "resources": leaves,
                                               "code_executed": False})
        own_names = ("win32_adapter.h", "win32_adapter.c", "adapter_host_test.c", "mapped_fixture.c",
                     "mapped_fixture.rc", "mapped_fixture.def", "native_resource_probe.c",
                     "native_resource_wait.c", "adapter_contracts.json", "ADAPTER_README.md", "build_adapter.py")
        paths = [HERE / n for n in own_names + ("resources.c", "resources.h")]
        paths += [ROOT / "ntwin32/native_loader" / n for n in ("pe.c", "pe.h", "native.c")]
        paths += [ROOT / "ntwin32/process_exit" / n for n in
                  ("original_kernel.h", "original_kernel_win98_v3.c", "main_image.h", "main_image.c",
                   "win98_guard.h", "win98_guard.c", "win98_export.h", "win98_export.c")]
        paths += [ROOT / "platform/freestanding" / n for n in ("memory.c", "memory.h")]
        paths += [ROOT / "shizukufs/v1/tools" / n for n in ("sha256.c", "sha256.h")]
        inventory = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
        paths += [inventory, READER, ROOT / "build/chromium-large-native-probe-20261001T0036-v2/manifest.json",
                  ROOT / "build/resource-adapter-primary-20261001/result.json"]
        contracts = json.loads((HERE / "adapter_contracts.json").read_text())
        for item in contracts["wine_primary_sources"]:
            p = ROOT / item["path"]
            if sha(p) != item["sha256"]:
                raise ValueError("pinned primary Wine source changed")
            paths.append(p)
        pins = {str(p.relative_to(ROOT)): sha(p) for p in paths}
        receipt["sources"] = pins
        for p in paths:
            target = out / "frozen" / p.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(p, target)
            if sha(target) != pins[str(p.relative_to(ROOT))]:
                raise ValueError("source changed while freezing")
        compilers = {}
        for name in ("gcc", "clang", "i686-w64-mingw32-gcc", "i686-w64-mingw32-windres"):
            p = shutil.which(name)
            if not p:
                raise ValueError("existing compiler missing: " + name)
            version = run([p, "--version"], "version-" + name).splitlines()[0]
            compilers[name] = p
            receipt.setdefault("compilers", []).append({"name": name, "path": p, "sha256": sha(p), "version": version})
        for name in ("gcc", "i686-w64-mingw32-gcc"):
            p = Path(run([compilers[name], "-print-prog-name=cc1"], "cc1-path-" + name).strip()).resolve()
            receipt["compilers"].append({"name": name + ":cc1", "path": str(p), "sha256": sha(p)})
        for flag in ("-print-prog-name=as", "-print-prog-name=ld", "-print-libgcc-file-name"):
            raw = run([compilers["i686-w64-mingw32-gcc"], flag], "native-component-" + flag.split("=")[-1].lstrip("-")).strip()
            p = Path(raw)
            if not p.is_file():
                located = shutil.which(raw)
                if not located:
                    raise ValueError("actual native toolchain component missing")
                p = Path(located)
            p = p.resolve()
            receipt["compilers"].append({"name": "i686-w64-mingw32-gcc:" + flag, "path": str(p), "sha256": sha(p)})
        for name in ("i686-w64-mingw32-objdump", "i686-w64-mingw32-nm"):
            p = shutil.which(name)
            if not p:
                raise ValueError("existing compiled ABI inspection tool missing")
            compilers[name] = p
            receipt["compilers"].append({"name": name, "path": p, "sha256": sha(p)})
        source = out / "frozen/ntwin32/resources"
        native = out / "frozen/ntwin32/native_loader"
        kernel = out / "frozen/ntwin32/process_exit"
        memory = out / "frozen/platform/freestanding/memory.c"
        crypto = out / "frozen/shizukufs/v1/tools"
        cc = compilers["i686-w64-mingw32-gcc"]
        flags = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror", "-Wno-misleading-indentation",
                 "-fno-builtin", "-fno-tree-loop-distribute-patterns", "-fno-stack-protector", "-ffunction-sections",
                 "-fdata-sections", "-nostdlib", "-Wl,--gc-sections", "-Wl,--subsystem,windows:4.10",
                 "-Wl,--major-os-version,4", "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase",
                 "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
                 "-Xlinker", "--stack", "-Xlinker", "2097152,4096"]
        run([compilers["i686-w64-mingw32-windres"], "-O", "coff", str(source / "mapped_fixture.rc"),
             str(out / "fixture-resources.o")], "fixture-resources")
        run(flags + ["-shared", "-Wl,--entry,0", str(source / "mapped_fixture.c"), str(source / "mapped_fixture.def"),
                     str(out / "fixture-resources.o"), "-o", str(out / "RRFIX.DLL")], "closed-fixture-build")
        (out / "resource_pins.h").write_text('#define RR_FIXTURE_BYTES %du\n#define RR_FIXTURE_SHA "%s"\n' %
                                             ((out / "RRFIX.DLL").stat().st_size, sha(out / "RRFIX.DLL")))
        core_sources = [str(source / n) for n in ("win32_adapter.c", "resources.c")] + [str(native / "pe.c")]
        host_sources = core_sources + [str(source / "mapped_fixture.c"), str(source / "adapter_host_test.c")]
        host_results = []
        for kind, compiler, extra in (("normal", compilers["gcc"], []),
                                      ("sanitized", compilers["clang"], ["--no-default-config", "-fsanitize=address,undefined",
                                       "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])):
            executable = out / ("adapter-host-" + kind)
            run([compiler] + extra + ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                 "-Wno-misleading-indentation"] + host_sources + ["-o", str(executable)], kind + "-compile")
            log = run([str(executable), str(out / "RRFIX.DLL")] + [str(i[0]) for i in ORIGINALS], kind + "-controls")
            match = re.search(r"RESULT PASS cases=(\d+) checks=(\d+) closed_native_pending=true application_success=false", log)
            if not match or "runtime error" in log or "Sanitizer" in log:
                raise ValueError("actual host ownership/malformed controls missing")
            host_results.append({"kind": kind, "cases": int(match[1]), "checks": int(match[2]), "sha256": sha(executable)})
        receipt["host_controls"] = host_results
        common = [str(kernel / n) for n in ("original_kernel_win98_v3.c", "main_image.c", "win98_guard.c", "win98_export.c")]
        common += [str(memory), str(crypto / "sha256.c")]
        includes = ["-I", str(out), "-I", str(crypto)]
        run(flags + includes + ["-Wl,--entry,_entry@0", str(source / "native_resource_probe.c")] +
            core_sources + common + ["-lkernel32", "-lgcc", "-o", str(out / "RRPROBE.EXE")], "native-probe-build")
        (out / "probe_pins.h").write_text('#define RR_PROBE_BYTES %du\n#define RR_PROBE_SHA "%s"\n' %
                                          ((out / "RRPROBE.EXE").stat().st_size, sha(out / "RRPROBE.EXE")))
        run(flags + includes + ["-Wl,--entry,_entry@0", str(source / "native_resource_wait.c")] +
            common + ["-lkernel32", "-lgcc", "-o", str(out / "RRWAIT.EXE")], "native-observer-build")
        receipt["generated_headers"] = {n: sha(out / n) for n in ("resource_pins.h", "probe_pins.h")}
        abi = run([compilers["i686-w64-mingw32-objdump"], "--disassemble=_ResourceFixtureRun@8", str(out / "RRFIX.DLL")], "compiled-fixture-stdcall")
        if "<_ResourceFixtureRun@8>:" not in abi or not re.search(r"ret\s+\$0x8", abi):
            raise ValueError("actual closed fixture stdcall return differs")
        symbols = run([compilers["i686-w64-mingw32-nm"], "-g", str(out / "RRPROBE.EXE")], "compiled-facade-ABI")
        expected = ("_nra_FindResourceExA@16", "_nra_FindResourceExW@16", "_nra_FindResourceA@12", "_nra_FindResourceW@12",
                    "_nra_LoadResource@8", "_nra_LockResource@4", "_nra_SizeofResource@8", "_nra_FreeResource@4")
        if any(symbol not in symbols for symbol in expected):
            raise ValueError("actual compiled resource facade argument ABI differs")
        receipt["compiled_ABI"] = {"fixture_stdcall_return_bytes": 8, "facade_symbols": list(expected)}
        receipt["native_last_error_controls"] = {"compiled_sentinels": 12, "observed_in_guest": False,
                                                "callback_contract": "preserve actual thread LastError on every return"}
        available = {k.upper(): set(v) for k, v in json.loads((out / "frozen" / inventory.relative_to(ROOT)).read_text())["dlls"].items()}
        artifacts = []
        for name in ("RRFIX.DLL", "RRPROBE.EXE", "RRWAIT.EXE"):
            path = out / name
            with pefile.PE(str(path)) as pe:
                o = pe.OPTIONAL_HEADER
                classic = (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem, o.MajorSubsystemVersion, o.MinorSubsystemVersion,
                           o.MajorOperatingSystemVersion, o.MinorOperatingSystemVersion)
                if classic != (0x14c, 0x10b, 2, 4, 10, 4, 0) or pe.is_dll() != name.endswith(".DLL"):
                    raise ValueError("classic i486 PE32 GUI profile differs")
                if pe.FILE_HEADER.TimeDateStamp or o.DllCharacteristics & 0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
                    raise ValueError("unexpected timestamp/TLS/load-config/delay/CLR/modern flags")
                imports = {}
                for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
                    dll = module.dll.decode().upper(); imports[dll] = []
                    for entry in module.imports:
                        if not entry.name or entry.name.decode() not in available.get(dll, set()):
                            raise ValueError("outside actual OEM exports")
                        imports[dll].append(entry.name.decode())
                if set(imports) != (set() if name.endswith(".DLL") else {"KERNEL32.DLL"}):
                    raise ValueError("resource fixture must have no OS imports; probes OEM Kernel32 only")
                exports = {e.name.decode() for e in getattr(pe, "DIRECTORY_ENTRY_EXPORT", ()).symbols if e.name} if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") else set()
                if name.endswith(".DLL") and (o.AddressOfEntryPoint or exports != {"ResourceFixtureRun"} or not o.DATA_DIRECTORY[2].VirtualAddress):
                    raise ValueError("own zero-entry resource/export ABI differs")
                if path.stat().st_size > 1024 * 1024:
                    raise ValueError("classic existing per-input budget exceeded")
                artifacts.append({"path": str(path), "bytes": path.stat().st_size, "sha256": sha(path), "imports": imports,
                                  "exports": sorted(exports), "classic_profile": list(classic), "entry_rva": o.AddressOfEntryPoint,
                                  "native_import_gate": "PASS", "native_executed": False})
        for p, pin, _ in ORIGINALS:
            if sha(p) != pin:
                raise ValueError("original input changed during build")
        if any(sha(ROOT / name) != pin or sha(out / "frozen" / name) != pin for name, pin in pins.items()):
            raise ValueError("source changed during build")
        if any(sha(i["path"]) != i["sha256"] for i in receipt["compilers"]):
            raise ValueError("compiler changed during build")
        if any(sha(p) != pin for p, pin in PARENTS):
            raise ValueError("held parent changed during build")
        receipt.update(status="HOST_BUILD_PASS_NATIVE_PENDING", artifacts=artifacts, sources_stable=True,
                       original_inputs_stable=True, original_resources_consumed=159,
                       original_runtime_admission="unchanged np_runtime_profile refusal")
    except (OSError, ValueError, subprocess.TimeoutExpired, pefile.PEFormatError) as error:
        receipt["error"] = str(error)
    result = out / "result.json"
    result.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [{"source": i["path"], "guest": "C:\\VXDLAB\\" + Path(i["path"]).name,
                                "bytes": i["bytes"], "sha256": i["sha256"]} for i in receipt["artifacts"]],
                    "outputs": ["C:\\VXDLAB\\RRPROBE.LOG", "C:\\VXDLAB\\RRWAIT.LOG"], "backups": [],
                    "source_receipts": [{"path": str(result), "sha256": sha(result)}],
                    "command": "C:\\VXDLAB\\RRWAIT.EXE",
                    "scope": "Own closed mapped resource consumer plus original OEM resource semantic comparison; no Chromium code/admission. Plan only, no guest staging performed."}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "result": str(result), "sha256": sha(result), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "HOST_BUILD_PASS_NATIVE_PENDING" else 1


if __name__ == "__main__":
    raise SystemExit(main())
