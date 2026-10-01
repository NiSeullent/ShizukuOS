#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the original, freestanding x64 EFI application using an existing compiler."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parent
BUILD = ROOT / "build"


def check_pe(path):
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[:2] == b"MZ" and data[pe:pe + 4] == b"PE\0\0", "PE signature"
    machine, sections, timestamp = struct.unpack_from("<HHI", data, pe + 4)
    optional = pe + 24
    assert machine == 0x8664, "AMD64 machine"
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B, "PE32+ format"
    assert struct.unpack_from("<H", data, optional + 68)[0] == 10, "EFI application subsystem"
    imports, import_size = struct.unpack_from("<II", data, optional + 120)
    if imports:
        # GNU ld emits an empty import descriptor even with -nostdlib.
        section_table = optional + struct.unpack_from("<H", data, pe + 20)[0]
        for index in range(sections):
            entry = section_table + index * 40
            size, rva, raw_size, raw = struct.unpack_from("<IIII", data, entry + 8)
            if rva <= imports < rva + max(size, raw_size):
                offset = raw + imports - rva
                assert import_size >= 20 and data[offset:offset + 20] == bytes(20), "No imported DLLs"
                break
        else:
            raise AssertionError("Import directory is outside image sections")
    relocation = struct.unpack_from("<II", data, optional + 112 + 5 * 8)
    assert all(relocation), "Relocation table is required for firmware loading"
    assert timestamp == 0, "Deterministic PE timestamp"
    return {"machine": "AMD64", "subsystem": "EFI_APPLICATION", "imports": [],
            "relocations": True, "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--cc", default="x86_64-w64-mingw32-gcc")
    p.add_argument("--test-pci", action="store_true", help="Build QEMU-only mechanism-1 diagnostic")
    args = p.parse_args()
    compiler = shutil.which(args.cc)
    if not compiler:
        raise SystemExit(f"Existing compiler required: {args.cc}; nothing installed")
    if BUILD.is_symlink() and not BUILD.exists():
        BUILD.unlink()
    BUILD.mkdir(exist_ok=True)
    output = BUILD / ("BOOTX64-PCI-TEST.EFI" if args.test_pci else "BOOTX64.EFI")
    temporary = output.with_suffix(".EFI.tmp")
    receipt_name = "build-pci-result.json" if args.test_pci else "build-result.json"
    (BUILD / receipt_name).unlink(missing_ok=True)
    sources = [ROOT / name for name in ("main.c", "boot.c", "boot.h", "efi.h", "display.c", "display.h", "kernel_probe.c")]
    sources += [ROOT.parent.parent / name for name in ("ntwrapper/core.c", "ntwrapper/include/ntwrapper.h",
                                                        "ntwddm/src/ntwddm.c", "ntwddm/include/ntwddm.h")]
    if args.test_pci:
        sources += [ROOT / "pci_probe.c", ROOT.parent.parent / "drivers/pcie/src/ntw_pcie.c",
                    ROOT.parent.parent / "drivers/pcie/include/ntw_pcie.h"]
    def source_hashes():
        return {str(path.relative_to(ROOT.parent.parent)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sources}
    csm = ROOT.parent / "csmwrap"
    switch_obj = BUILD / "csmwrap-switch.obj"
    subprocess.run(["nasm", "-f", "win64", "-o", str(switch_obj), str(csm / "loader" / "switch.asm")],
                   check=True, timeout=30)
    csm_sources = [
        csm / "core" / "mode.c", csm / "core" / "checksum.c", csm / "core" / "kernel64.c",
        csm / "core" / "registry.c", csm / "handoff" / "fill.c", csm / "diagnostics" / "log.c",
        csm / "bios" / "dispatch.c", csm / "loader" / "uefi_collect.c",
        csm / "loader" / "entry16_bytes.c",
    ]
    sources += csm_sources
    before = source_hashes()
    command = [compiler, "-std=c11", "-Os", "-Wall", "-Wextra", "-Werror",
               "-ffreestanding", "-fno-builtin", "-fno-stack-protector", "-mno-red-zone",
               "-mno-stack-arg-probe", "-fno-ident", "-fno-asynchronous-unwind-tables",
               "-nostdlib", "-Wl,--subsystem,10", "-Wl,--entry,efi_main",
               "-Wl,--image-base,0x10000000", "-Wl,--enable-reloc-section",
               "-Wl,--no-insert-timestamp", "-Wl,--strip-all",
               "-I", str(ROOT.parent.parent / "ntwddm" / "include"),
               str(ROOT / "main.c"), str(ROOT / "boot.c"), str(ROOT / "display.c"),
               str(ROOT / "kernel_probe.c"), str(ROOT.parent.parent / "ntwrapper" / "core.c"),
               str(ROOT.parent.parent / "ntwddm" / "src" / "ntwddm.c"),
               *[str(path) for path in csm_sources], str(switch_obj),
               "-o", str(temporary)]
    if args.test_pci:
        command += ["-DSD_UEFI_TEST_PCI", "-I", str(ROOT.parent.parent / "drivers" / "pcie" / "include"),
                    str(ROOT / "pci_probe.c"), str(ROOT.parent.parent / "drivers" / "pcie" / "src" / "ntw_pcie.c")]
    subprocess.run(command, check=True, cwd=ROOT, timeout=60)
    receipt = check_pe(temporary)
    if source_hashes() != before:
        raise SystemExit("Sources changed during compilation; rebuild before testing")
    temporary.replace(output)
    receipt["sources_sha256"] = before
    receipt["compiler"] = subprocess.check_output([compiler, "--version"], text=True).splitlines()[0]
    receipt["command"] = command
    receipt["qemu_pci_diagnostic_only"] = args.test_pci
    (BUILD / receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
