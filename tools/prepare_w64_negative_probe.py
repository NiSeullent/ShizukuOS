#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a fresh native Win98 W64_OPEN negative fixture; no VM or installation.

The proven production VxD is pinned and copied unchanged. New native programs
are GUI i486 PE32, no CRT or KernelEx, and only use OEM Kernel32 exports.
The guest owner chooses the execution profile and disposable VM separately.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import uuid

import pefile

ROOT = Path(__file__).resolve().parents[1]
BOOT = Path("/root/Win98-Modern-boot")
DRIVER = BOOT / "build/ntwrapper-production-native-gui-inputs-20260930T2357-v5/NTWRAP9X.VXD"
DRIVER_SHA = "44d7a537c1a547d3b735d98ebdf5756c132486605dc1a25e3f6f364b9547b9bf"
NATIVE_REVIEW = BOOT / "build/ntwrapper-production-native-gui-receipts-20260930T2358-v5/recovered-native-review.json"
NATIVE_REVIEW_SHA = "97021ba3bd5e56965511b64acd97c5d926c7ae8b871626f87496f948c3116b34"
PROFILE = BOOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
PROFILE_SHA = "3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d"
HEADER_PINS = {
    "ntwrapper/vxd/bridge.h": "a90418f9f354f5eb8f8bb8aac5697523d2a1c5111d553ab128380165c58087cd",
    "ntwrapper/include/ntwrapper.h": "902c72f956a01be2f6a8e3be74986ca13719375697c8e479b2242b88f14a93c3",
}
COMMON_IMPORTS = {"CloseHandle", "CreateFileA", "ExitProcess", "FlushFileBuffers", "GetLastError", "SetCurrentDirectoryA", "WriteFile"}
PROBE_IMPORTS = COMMON_IMPORTS | {"DeviceIoControl"}
OBSERVER_IMPORTS = COMMON_IMPORTS | {"CreateProcessA", "GetExitCodeProcess", "GetFileAttributesA", "ReadFile", "TerminateProcess", "WaitForSingleObject"}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def inspect(path, expected, oem):
    with pefile.PE(str(path)) as pe:
        opt = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem,
                opt.MajorOperatingSystemVersion, opt.MinorOperatingSystemVersion,
                opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10, 4, 10):
            raise ValueError("Native GUI i486 PE32 profile changed")
        if pe.FILE_HEADER.Characteristics & 0x2000 or opt.DllCharacteristics:
            raise ValueError("Unexpected DLL/modern PE flags")
        if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (0, 2, 9, 10, 13, 14)):
            raise ValueError("Unexpected export/resource/TLS/modern loader state")
        imports = {}
        for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
            dll = descriptor.dll.decode("ascii").upper()
            names = [item.name.decode("ascii") if item.name else "#" + str(item.ordinal) for item in descriptor.imports]
            if dll != "KERNEL32.DLL" or set(names) != expected or set(names) - set(oem[dll]):
                raise ValueError("Exact OEM Kernel32-only import gate failed")
            imports[dll] = names
        if set(imports) != {"KERNEL32.DLL"} or not pe.verify_checksum():
            raise ValueError("PE import/checksum invalid")
        return {"machine": "I386", "subsystem": "WINDOWS_GUI", "os_version": [4, 10],
                "subsystem_version": [4, 10], "entry_rva": opt.AddressOfEntryPoint,
                "image_bytes": opt.SizeOfImage, "imports": imports, "oem_gate": "PASS",
                "checksum_valid": True, "sha256": sha(path), "bytes": path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--nonce", default=None)
    parser.add_argument("--guest-directory", choices=("VXDLAB", "GOPLAB"), default="VXDLAB",
                        help="Bounded native guest directory accepted by the disposable Win98 runner")
    args = parser.parse_args()
    out = args.out.resolve()
    guest_directory = "C:\\" + args.guest_directory
    nonce = args.nonce or "cb43-w64-" + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", nonce): parser.error("Nonce must be 1..64 plain ASCII identifier characters")
    if out.exists() or not out.is_relative_to(ROOT / "build") or out == ROOT / "build":
        parser.error("A fresh isolated PRIVATE build directory is required")
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc: parser.error("Existing i486 Windows compiler is missing")
    for path, pin in ((DRIVER, DRIVER_SHA), (NATIVE_REVIEW, NATIVE_REVIEW_SHA), (PROFILE, PROFILE_SHA)):
        if sha(path) != pin: parser.error("Pinned native input changed: " + str(path))
    sources = [ROOT / "ntwrapper/vxd/w64_negative_probe.c",
               ROOT / "ntwrapper/vxd/w64_outer_observer.c", Path(__file__).resolve()]
    sources += [ROOT / name for name in HEADER_PINS]
    for name, pin in HEADER_PINS.items():
        if sha(ROOT / name) != pin: parser.error("Production ABI header differs: " + name)
    pins = {str(path): sha(path) for path in [*sources, DRIVER, NATIVE_REVIEW, PROFILE, Path(cc)]}
    oem = json.loads(PROFILE.read_text())["dlls"]
    out.mkdir(parents=True)
    for path in sources:
        target = out / "frozen" / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())
    driver_copy = out / "NTWRAP9X.VXD"
    shutil.copyfile(DRIVER, driver_copy)
    if sha(driver_copy) != DRIVER_SHA: raise ValueError("Copied production driver changed")
    source = out / "frozen/ntwrapper/vxd/w64_negative_probe.c"
    commands, profiles = [], {}
    flags = [cc, "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror", "-march=i486",
             "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-nostdlib",
             "-DW64_NEGATIVE_NONCE=" + json.dumps(nonce),
             "-DW64_NEGATIVE_DIRECTORY=" + json.dumps(guest_directory), "-Wl,--subsystem,windows:4.10",
             "-Wl,--major-os-version,4", "-Wl,--minor-os-version,10", "-Wl,--disable-dynamicbase",
             "-Wl,--disable-nxcompat", "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp",
             "-Wl,--entry,_mainCRTStartup"]
    result = {"schema": "win98modern.native-w64-negative-preparation.v1", "status": "FAIL",
              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "nonce": nonce,
              "guest_directory": guest_directory,
              "sources": pins, "commands": commands, "native_executed": False,
              "application_executed": False, "win64_bridge_executed": False,
              "scope": "New native GUI probe, actual-child-exit observer and fixed-target outer OS-exit observer; unchanged proven production VxD. Source/build only."}
    try:
        outer_source = out / "frozen/ntwrapper/vxd/w64_outer_observer.c"
        for name, observer, expected, input_source in (
                ("W64NEG.EXE", False, PROBE_IMPORTS, source),
                ("W64OBS.EXE", True, OBSERVER_IMPORTS, source),
                ("W64OUT.EXE", False, OBSERVER_IMPORTS, outer_source)):
            command = flags + (["-DW64_NEGATIVE_OBSERVER"] if observer else []) + [str(input_source), "-o", str(out / name), "-lkernel32"]
            commands.append(command)
            compiled = subprocess.run(command, cwd=out, capture_output=True, text=True, timeout=90)
            (out / (name + ".compile.log")).write_text(compiled.stdout + compiled.stderr)
            if compiled.returncode: raise ValueError("Native compiler failed: " + name)
            profiles[name] = inspect(out / name, expected, oem)
        for path, pin in pins.items():
            if sha(path) != pin: raise ValueError("Held input changed during preparation: " + path)
        inputs = [{"source": str(out / name), "guest": guest_directory + "\\" + name,
                   "bytes": (out / name).stat().st_size, "sha256": sha(out / name)}
                  for name in ("NTWRAP9X.VXD", "W64NEG.EXE", "W64OBS.EXE", "W64OUT.EXE")]
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                    "outputs": [guest_directory + "\\W64NEG.LOG", guest_directory + "\\W64OBS.LOG",
                                guest_directory + "\\W64OUT.LOG"],
                    "backups": [], "source_receipts": [{"path": str(NATIVE_REVIEW), "sha256": NATIVE_REVIEW_SHA}],
                    "commands": [guest_directory + "\\W64OUT.EXE"], "nonce": nonce,
                    "scope": "Negative absent-Supervisor boundary only. No native positive Win64 channel or app acceptance."}
        save(out / "guest-inputs.json", manifest)
        execution = {"status": "NOT_EXECUTED", "nonce": nonce, "guest_directory": guest_directory,
                     "native_executed": False,
                     "profile": "Guest owner must choose a fresh isolated Win98 clone, normal non-Shizuku CPU advertisement and its existing disk/RAM guards.",
                     "immutable_inputs": inputs, "manifest_sha256": sha(out / "guest-inputs.json"),
                     "required_evidence": ["Fresh nonce in all three actual disk-readback logs", "Two real QUERY/W64_OPEN_FALSE_ERROR50/QUERY/checked-close cycles",
                         "Actual W64NEG child OS exit0 in W64OBS and actual W64OBS OS exit0 in W64OUT; outermost own selected exit is not actual OS-exit evidence",
                         "Actual CPU/hypervisor signature unchanged and no positive channel/app claim", "Guest boot/checkpoint/input hashes and launch profile"],
                     "limits": ["No VM command was run or native/shared base changed", "CreateFile close proves close requests; not global VXD unmapping", "Failed-call returned-count/output changes are recorded without assuming VWIN32 normalization", "No Supervisor Win98 domain, offscreen raster or input bridge implementation is supplied"]}
        save(out / "execution-template.json", execution)
        result.update(status="HOST_BUILD_PASS_NATIVE_PENDING", profiles=profiles, inputs=inputs,
                      manifest=str(out / "guest-inputs.json"), manifest_sha256=sha(out / "guest-inputs.json"),
                      execution_template_sha256=sha(out / "execution-template.json"))
        save(out / "build-result.json", result)
    except Exception as error:
        result["error"] = str(error); save(out / "build-result.json", result); raise
    print(json.dumps({"status": result["status"], "nonce": nonce, "manifest": result["manifest"],
                      "manifest_sha256": result["manifest_sha256"], "build_result_sha256": sha(out / "build-result.json"),
                      "inputs": inputs}))


if __name__ == "__main__":
    main()
