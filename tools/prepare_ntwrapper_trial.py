#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze the reviewed production NTWrapper VxD and bounded native controls.

Existing driver/probe/template bytes remain immutable. No guest is launched,
driver installed, or configuration altered by this preparer.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pefile

ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_SHA = "44d7a537c1a547d3b735d98ebdf5756c132486605dc1a25e3f6f364b9547b9bf"
PROBE_SHA = "7f8abf3e15d2d7838d921e0aed1e9efb0efd9d7a2d243f968b7b5eca5f71ddb0"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path):
    return {"path": str(path.resolve()), "sha256": sha(path)}


def bounded_file(path, digest, root, limit=1024**2):
    path = Path(path)
    if not path.is_absolute():
        path = ROOT / path
    if path.is_symlink() or any(p.is_symlink() for p in path.parents):
        raise ValueError("symlink input refused")
    path = path.resolve(strict=True)
    if (not path.is_relative_to(root) or not path.is_file() or
            not 0 < path.stat().st_size <= limit or sha(path) != digest):
        raise ValueError("bounded input location/size/hash mismatch: " + str(path))
    return path


def prepare(manifest, manifest_sha, host, host_sha, out):
    manifest = bounded_file(manifest, manifest_sha, ROOT / "build")
    host = bounded_file(host, host_sha, ROOT / "build")
    built, checked = json.loads(manifest.read_text()), json.loads(host.read_text())
    if (built.get("status") != "HOST-BUILD-PASS" or built.get("format") != "LE" or
            built.get("object_flags") != [0x2065, 0x2063] or
            built.get("sha256") != CANDIDATE_SHA or built.get("bytes") != 18013 or
            built.get("guest_loaded") is not False or
            built.get("native_vmm_calls_verified") is not False or
            built.get("probe", {}).get("sha256") != PROBE_SHA or
            built["probe"].get("bytes") != 9327):
        raise ValueError("exact host-only production candidate required")
    if (checked.get("passed") is not True or checked.get("inputs_unchanged_during_test") is not True or
            checked.get("artifact_sha256") != CANDIDATE_SHA or checked.get("probe_sha256") != PROBE_SHA or
            checked.get("guest_loaded") is not False or checked.get("native_vmm_calls_verified") is not False or
            checked.get("win98_probe_executed") is not False):
        raise ValueError("exact passing host-only production receipt required")
    if checked["hashes"].get(str(manifest.relative_to(ROOT))) != manifest_sha:
        raise ValueError("host receipt does not bind this manifest")
    pins = {str(manifest): manifest_sha, str(host): host_sha}
    for name, digest in built["sources"].items():
        path = bounded_file(ROOT / name, digest, ROOT)
        pins[str(path)] = digest
        # ABI headers are held by the build manifest. The host receipt pins
        # that whole manifest, but its legacy direct-hash list omits them.
        if name in checked["hashes"] and checked["hashes"][name] != digest:
            raise ValueError("host/build source binding differs")
    for name, digest in checked["hashes"].items():
        path = bounded_file(ROOT / name, digest, ROOT, 8*1024**2)
        pins[str(path)] = digest
    if sha(host.parent / "host-tests.log") != checked["log_sha256"]:
        raise ValueError("host control log changed")
    candidate = bounded_file(manifest.parent / "NTWRAP9X.VXD", CANDIDATE_SHA, manifest.parent)
    probe = bounded_file(manifest.parent / "NTWQUERY.EXE", PROBE_SHA, manifest.parent)
    template = ROOT / "ntwrapper/vxd/dos_loader_diag.asm"
    source = ROOT / "remote/guest/ntwrapper_trial_watch.c"
    inventory = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
    for path in (template, source, inventory, Path(__file__)):
        pins[str(path)] = sha(path)
    cc, nasm = shutil.which("i686-w64-mingw32-gcc"), shutil.which("nasm")
    if not cc or not nasm:
        raise ValueError("existing MinGW and NASM required")
    compilers = {name: record(Path(path)) for name, path in (("cc", cc), ("nasm", nasm))}
    text = template.read_text(encoding="ascii")
    substitutions = {"C:\\NTWLAB\\NTWLDR.LOG": "C:\\VXDLAB\\NTWLDR.LOG",
                     "C:\\NTWLAB\\NTWRAP9X.VXD": "C:\\VXDLAB\\NTWRAP9X.VXD",
                     "PREFLIGHT=EXACT_9390_BYTES_AND_EOF": "PREFLIGHT=EXACT_18013_BYTES_AND_EOF"}
    for before, after in substitutions.items():
        if text.count(before) != 1:
            raise ValueError("exact diagnostic template replacement required")
        text = text.replace(before, after)
    out = Path(out)
    if not out.is_absolute():
        out = ROOT / out
    if out.is_symlink() or any(p.is_symlink() for p in out.parents):
        raise ValueError("symlink output refused")
    out = out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        raise ValueError("new isolated build output required")
    # All input and output gates precede any creation.
    out.mkdir(parents=True)
    frozen = out / "frozen"
    for name, digest in pins.items():
        path = Path(name)
        target = frozen / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if sha(target) != digest:
            raise ValueError("input changed during freezing")
    for path in (candidate, probe):
        shutil.copyfile(path, out / path.name)
    if sha(out / candidate.name) != CANDIDATE_SHA or sha(out / probe.name) != PROBE_SHA:
        raise ValueError("exact production destination VxD/probe binding failed")
    (out / "expected.vxd").write_bytes(candidate.read_bytes())
    (out / "expected.inc").write_text('%define EXPECTED_SIZE 18013\n%define EXPECTED_SHA256 "' + CANDIDATE_SHA + '"\n')
    (out / "NTWLDR.asm").write_text(text, encoding="ascii")
    flags = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
             "-fno-builtin", "-fno-tree-loop-distribute-patterns", "-fno-stack-protector", "-nostdlib",
             "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10", "-Wl,--major-os-version,4",
             "-Wl,--minor-os-version,0", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
             "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"]
    commands = [[nasm, "-f", "bin", "-Wall", "-Werror", "-I", str(out) + "/",
                 "-l", str(out / "NTWLDR.lst"), "-o", str(out / "NTWLDR.COM"), str(out / "NTWLDR.asm")],
                flags + ["-o", str(out / "NTWVSUIT.EXE"), str(frozen / source.relative_to(ROOT)), "-lkernel32"]]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, timeout=90)
        (out / f"compile-{index}.log").write_bytes(result.stdout + result.stderr)
        if result.returncode:
            raise ValueError("native control compilation failed; private log retained")
    com = (out / "NTWLDR.COM").read_bytes()
    if not 18013 < len(com) < 0xFE00 or com.count(candidate.read_bytes()) != 1:
        raise ValueError("bounded COM/embedded exact VxD multiplicity mismatch")
    available = json.loads(inventory.read_text())["dlls"]["KERNEL32.DLL"]
    with pefile.PE(str(out / "NTWVSUIT.EXE")) as pe:
        opt = pe.OPTIONAL_HEADER
        if ((pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion,
             opt.MinorSubsystemVersion) != (0x14C, 0x10B, 2, 4, 10) or opt.DllCharacteristics & 0x140 or
                any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9,10,13,14))):
            raise ValueError("classic native observer PE profile mismatch")
        imports = {}
        for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
            dll = descriptor.dll.decode("ascii").upper()
            symbols = []
            for imp in descriptor.imports:
                if not imp.name or dll != "KERNEL32.DLL" or imp.name.decode("ascii") not in available:
                    raise ValueError("observer import outside exact OEM Kernel32")
                symbols.append(imp.name.decode("ascii"))
            imports[dll] = sorted(symbols)
        if set(imports) != {"KERNEL32.DLL"}:
            raise ValueError("observer native imports missing")
    if any(sha(Path(path)) != digest for path, digest in pins.items()):
        raise ValueError("held source/artifact changed during preparation")
    inputs = [{"source": str(out/name), "guest": "C:\\VXDLAB\\"+name,
               "bytes": (out/name).stat().st_size, "sha256": sha(out/name)}
              for name in ("NTWRAP9X.VXD", "NTWQUERY.EXE", "NTWLDR.COM", "NTWVSUIT.EXE")]
    receipt = {"schema": "win98modern.production-vxd-native-preparation.v1", "status": "PREPARED",
               "producer": record(manifest), "host_producer": record(host), "pins": pins,
               "compilers": compilers, "commands": commands, "template_substitutions": substitutions,
               "observer_imports": imports, "inputs": inputs, "native_executed": False,
               "driver_changed": False, "query_changed": False, "application_executed": False,
               "scope": "Exact production VxD native load/unload and version/event/error query only; no WIN64 channel/app/graphics claim.",
               "acceptance": ["Fresh native V86 log verifies all18013 bytes+EOF, records actual CF/AX from load/unload and DOS exit0.",
                              "Fresh NTWQUERY.LOG verifies two real open/query/event/error/close cycles.",
                              "Fresh NTWOBS.LOG observes real query-child wait0/exit0; observer own OS exit is independent evidence.",
                              "Source disk/original licensed files and held input artifacts remain unchanged."],
               "effects": ["Four files staged only in the new private clone VXDLAB directory.",
                           "The controls dynamically load and request unload of this exact VxD; private query exercises native VMM page services.",
                           "Three fresh private reports; bounded30s child wait+5s guard cleanup; termination is a failed result.",
                           "No SYSTEM.INI/registry installation, Supervisor activation, MMIO, foreign VM or host/client change."]}
    prepared = out / "preparation.json"
    prepared.write_text(json.dumps(receipt, indent=2) + "\n")
    native_manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                       "outputs": ["C:\\VXDLAB\\NTWLDR.LOG", "C:\\VXDLAB\\NTWQUERY.LOG", "C:\\VXDLAB\\NTWOBS.LOG"],
                       "backups": [], "source_receipts": [record(manifest), record(host), record(prepared)],
                       "commands": ["C:\\VXDLAB\\NTWLDR.COM", "C:\\VXDLAB\\NTWVSUIT.EXE"], "scope": receipt["scope"]}
    path = out / "manifest.json"
    path.write_text(json.dumps(native_manifest, indent=2) + "\n")
    return {"status": "PREPARED", "manifest": str(path), "sha256": sha(path),
            "input_count": len(inputs), "input_bytes": sum(item["bytes"] for item in inputs), "native_executed": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-manifest", required=True, type=Path)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--host-receipt", required=True, type=Path)
    parser.add_argument("--host-sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.build_manifest, args.build_sha, args.host_receipt, args.host_sha, args.out), indent=2))


if __name__ == "__main__":
    main()
