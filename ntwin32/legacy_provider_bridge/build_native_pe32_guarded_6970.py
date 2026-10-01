#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build-only NTWPROV/NTWPRB PE32 and real MinGW SDK ABI proof.

No PE, provider, application or guest is executed. The frozen SSPI guard owns
the new 8 MiB output tree, captures and self-inclusive receipt above 20 GiB.
Observed sampling/RLIMIT_FSIZE is not a filesystem quota or full toolchain
attestation. Compiler/linker/version/objdump commands run only after admission.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "ntwin32/legacy_provider_bridge"
BASE_GUARD = HERE / "test_native_sspi_6970.py"
BASE_GUARD_SHA256 = "1b52856e537b298ea253d564754afefc35eb340bd7f7090fc1b30786bfa4f44e"
LIMIT = 8 * 1024 * 1024
RESERVE = 20 * 1024 * 1024 * 1024
CAPTURE_LIMIT = 256 * 1024
RECEIPT_LIMIT = 256 * 1024
PENDING = CAPTURE_LIMIT + RECEIPT_LIMIT + 64 * 1024
SOURCE_INPUT_LIMIT = 2 * 1024 * 1024
SOURCE_TOTAL_LIMIT = 16 * 1024 * 1024
HEADER_TOTAL_LIMIT = 32 * 1024 * 1024
TOOL_INPUT_LIMIT = 256 * 1024 * 1024
DEPENDENCY_LIMIT = 64 * 1024
DEPENDENCY_PATH_LIMIT = 256
COMMAND_TIMEOUT = 60
INVALID_RECEIPT_SCHEMA = "native-provider-pe32-build-invalid-receipt-v1"
SDK_FIXTURE_SHA256 = "714e1a3f42eb0241fa0a2f4df94ed0eb847743edd7ba58d8eef29d1e4386a0be"
SDK_FIXTURE_SIZE = 5015
FROZEN_INPUTS = {
    "ntwin32/legacy_provider_bridge/build.py":
        (4572, "4007b6daeca61ee580c9dbaa0cff45277a98b2d601f4030657a1310c2fb0ba1d"),
    "ntwin32/legacy_provider_bridge/native.c":
        (10295, "97a33c5292773ef949df251c7615eff259305b604f8d8d8d7f20b8039f98c301"),
    "ntwin32/legacy_provider_bridge/table.c":
        (3424, "c6fbe91b0ba24a68b2fcaef1f265b82071a738036ac331fdc6eb6f3986d5004d"),
    "ntwin32/legacy_provider_bridge/table.h":
        (538, "58fbf58f784fabcebc1a1821a3f1080fa65a432e08178b58d3b3e50ad68079a1"),
    "ntwin32/legacy_provider_bridge/probe.c":
        (3750, "63560ce5225069e3eae21fe77aae3480962b995ac40a394736f28e6ec41c2c41"),
    "ntwin32/legacy_provider_bridge/NTWPROV.def":
        (197, "bbc13ed2f636c04195232e3e409958e83a711419a7c7419ed59e7cb1fb9c0b50"),
    "ntwin32/legacy_provider_bridge/test_native_sspi_6970.py": (41247, BASE_GUARD_SHA256),
    "tools/build_npp_prerequisites.py":
        (10627, "aab253717ad653f0b0ccbea37ddc0f9bd9b474e51cade3ff1f13d63844f48d84"),
    "benchmarks/win98se-ko-oem-native-exports-v1.json":
        (1866608, "3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d"),
    "ntwin32/secure_transport/i486_gate.py":
        (8829, "85e976035c70478e9a2f021a37aa6925dd20ad85f089c7d06a18efadb7b9730f"),
    "ntwin32/secure_transport/i486_gate_test.py":
        (5194, "6e90e48f6f690efd29d2db7035478589bca4f140f3c28f05960c9bd0b5a4af69"),
}
# Exact original build.py C flags, separately compiling native/table TUs so
# each actual -MD/-MF includes all SDK headers. The object split is disclosed.
DLL_CFLAGS = ["-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
              "-fno-builtin", "-ffunction-sections", "-fdata-sections", "-nostdlib"]
PROBE_CFLAGS = ["-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
                "-fno-builtin", "-nostdlib"]
IMAGE_FLAGS = ["-Wl,--major-image-version,4", "-Wl,--minor-image-version,10",
               "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
               "-Wl,--disable-tsaware", "-Wl,--no-insert-timestamp"]
DLL_LDFLAGS = [*DLL_CFLAGS, "-shared", "-Wl,--gc-sections", "-Wl,--entry,_DllMain@12",
               "-Wl,--subsystem,windows:4.10", *IMAGE_FLAGS]
PROBE_LDFLAGS = [*PROBE_CFLAGS, "-Wl,--entry,_mainCRTStartup",
                 "-Wl,--subsystem,windows:4.10", *IMAGE_FLAGS]
I486_CONTROL_METHODS = (
    "test_legacy_string_aliases_and_x87",
    "test_newer_mnemonics_and_multibyte_nop_rejected",
    "test_exact_byte_address_coverage_and_symbol",
    "test_gap_tampered_bytes_and_missing_section",
)
COFF_FORMAT_REFERENCE = {
    "project": "GNU binutils / BFD",
    "release": "GNU binutils 2.42",
    "tag": "binutils-2_42",
    "commit": "c7f28aad0c99d1d2fec4e52ebfa3735d90ceb8e9",
    "file": "bfd/coffcode.h",
    "blob": "4170b630b4db39501e3509846c226d6745125f76",
    "url": "https://gnu.googlesource.com/binutils-gdb/+/c7f28aad0c99d1d2fec4e52ebfa3735d90ceb8e9/bfd/coffcode.h",
    "license_at_reference_revision": "GPL-3.0-or-later",
    "copied_upstream_source": False,
    "concept_only": "COFF section allocation size and file-content pointer are distinct; an uninitialized section may have nonzero size and zero raw-data pointer",
    "section_flag_reference": "https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#section-flags",
}

# Only four original in-memory unittest methods; the fifth filesystem/scan
# test is excluded because its scanner bypasses this launch's guarded run.
I486_CONTROL_CHILD = r'''
import hashlib, importlib.util, io, json, pathlib, sys, types, unittest
gate_path, gate_sha, test_path, test_sha = sys.argv[1:5]
methods = json.loads(sys.argv[5])
def pinned(path, digest):
    p = pathlib.Path(path)
    if not p.is_file() or not 0 < p.stat().st_size <= 2*1024*1024:
        raise RuntimeError("bounded control source required")
    raw = p.read_bytes()
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("frozen ISA control source changed")
    return raw
gate_before = pinned(gate_path, gate_sha)
test_before = pinned(test_path, test_sha)
original_spec = importlib.util.spec_from_file_location
loads = []
class BoundGateLoader:
    def create_module(self, spec):
        return None
    def exec_module(self, module):
        module.__file__ = gate_path
        exec(compile(gate_before, gate_path, "exec"), module.__dict__)
        loads.append(gate_sha)
def bound_gate_spec(name, location, *args, **kwargs):
    if name != "tested_i486_gate" or pathlib.Path(location).resolve() != pathlib.Path(gate_path).resolve():
        raise RuntimeError("unexpected original control module loading boundary")
    return importlib.util.spec_from_loader(name, BoundGateLoader(), origin=gate_path)
module = types.ModuleType("native_pe32_original_i486_controls")
module.__file__ = test_path
importlib.util.spec_from_file_location = bound_gate_spec
try:
    exec(compile(test_before, test_path, "exec"), module.__dict__)
finally:
    importlib.util.spec_from_file_location = original_spec
if loads != [gate_sha]:
    raise RuntimeError("original control gate boundary was not exact verified source")
suite = unittest.TestSuite(module.InstructionGateTests(name) for name in methods)
stream = io.StringIO()
result = unittest.TextTestRunner(stream=stream, verbosity=1).run(suite)
if pinned(gate_path, gate_sha) != gate_before or pinned(test_path, test_sha) != test_before:
    raise RuntimeError("frozen ISA sources changed during controls")
if result.testsRun != 4 or not result.wasSuccessful() or result.skipped:
    sys.stderr.write(stream.getvalue())
    sys.exit(1)
sys.stdout.write("I486_PYTHON_CONTROLS: 4 original methods passed\n")
'''


def bootstrap_bytes(path, maximum):
    """Read exactly one bounded regular inode before importing trusted guard."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
            raise RuntimeError("unbounded/nonregular verified module")
        raw = bytearray()
        started = time.monotonic()
        while True:
            block = os.read(fd, min(65536, maximum + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > maximum or time.monotonic() - started > COMMAND_TIMEOUT:
                raise RuntimeError("verified module byte/time limit exceeded")
        def fields(info):
            return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (fields(before) != fields(os.fstat(fd))
                or fields(before) != fields(path.stat(follow_symlinks=False))):
            raise RuntimeError("verified module changed during source read")
        return bytes(raw)
    finally:
        os.close(fd)


def import_verified(path, digest, name, *, guard=None):
    """Execute only the fully hashed helper bytes, never a mutable-path loader.

    This binds these helper source bytes. It does not attest their imported
    Python modules, Python runtime, or this runner's already-loaded code.
    """
    if guard is not None:
        guard.check()
    raw = bootstrap_bytes(path, SOURCE_INPUT_LIMIT)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise RuntimeError("frozen helper source hash mismatch")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.dont_write_bytecode = True
    exec(compile(raw, str(path), "exec"), module.__dict__)
    if bootstrap_bytes(path, SOURCE_INPUT_LIMIT) != raw:
        raise RuntimeError("frozen helper source changed during import")
    if guard is not None:
        guard.check()
    return module


def read_pinned(path, pin, base, *, maximum, guard=None):
    if base.hash_regular(path, maximum=maximum, guard=guard) != pin:
        raise RuntimeError("input changed before bounded byte read")
    raw = bootstrap_bytes(path, maximum)
    if hashlib.sha256(raw).hexdigest() != pin["sha256"]:
        raise RuntimeError("input changed during bounded byte read")
    if base.hash_regular(path, maximum=maximum, guard=guard) != pin:
        raise RuntimeError("input changed after bounded byte read")
    return raw


def source_snapshot(paths, base, guard=None, *, maximum_total=SOURCE_TOTAL_LIMIT):
    total = 0
    result = {}
    for path in sorted(set(paths)):
        record = base.hash_regular(path, maximum=SOURCE_INPUT_LIMIT, guard=guard)
        total += record["identity"][2]
        if total > maximum_total:
            raise RuntimeError("total bounded source/header input bytes exceeded")
        key = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
        result[key] = record
    return result


def compact_manifest(manifest):
    return {key: manifest[key] for key in ("manifest", "sha256", "identity")}


def coff_symbols(raw, pointer, count, sections, wanted):
    """Read bounded actual COFF symbols for DLL export/stdcall identities."""
    if not 0 < count <= 65536 or pointer < 20 or pointer + count * 18 + 4 > len(raw):
        raise RuntimeError("retained COFF symbol table absent/out of bounds")
    strings = pointer + count * 18
    string_size = struct.unpack_from("<I", raw, strings)[0]
    if not 4 <= string_size <= SOURCE_INPUT_LIMIT or strings + string_size > len(raw):
        raise RuntimeError("COFF string table out of bounds")
    result = {}
    index = 0
    while index < count:
        at = pointer + index * 18
        name_raw, value, section, kind, storage, auxiliaries = struct.unpack_from("<8sIhHBB", raw, at)
        if index + auxiliaries >= count:
            raise RuntimeError("COFF auxiliary records outside symbol table")
        if name_raw[:4] == b"\0" * 4:
            offset = struct.unpack_from("<I", name_raw, 4)[0]
            if not 4 <= offset < string_size:
                raise RuntimeError("COFF long symbol name offset out of bounds")
            end = raw.find(b"\0", strings + offset, min(strings + string_size, strings + offset + 257))
            if end < 0:
                raise RuntimeError("COFF long symbol name unterminated/unbounded")
            name = raw[strings + offset:end].decode("ascii", errors="strict")
        else:
            name = name_raw.split(b"\0", 1)[0].decode("ascii", errors="strict")
        if name in wanted:
            if (name in result or storage != 2 or not 1 <= section <= len(sections)
                    or not sections[section - 1].Characteristics & 0x20000000
                    or not value < sections[section - 1].Misc_VirtualSize):
                raise RuntimeError("stdcall COFF alias is not unique executable external symbol")
            result[name] = sections[section - 1].VirtualAddress + value
        index += 1 + auxiliaries
    if set(result) != set(wanted):
        raise RuntimeError("actual stdcall COFF export alias absent")
    return result


def coff_object_metadata(raw, observation=None):
    """Inspect bounded i386 COFF metadata, allowing flag-defined BSS storage.

    Independently implemented format predicates; no BFD source was copied.
    COFF_FORMAT_REFERENCE identifies the upstream concept/license/revision.
    SizeOfRawData is the object section allocation size; non-file-backed BSS
    is selected by flag 0x80, never by trusting a section name alone.
    """
    if observation is None:
        observation = {}
    observation.update(raw_file_bytes=len(raw), section_rows=[], section_table_complete=False)
    if len(raw) < 20:
        raise RuntimeError("compiled COFF object truncated")
    machine, count, timestamp, symbols, symbol_count, optional, flags = struct.unpack_from("<HHIIIHH", raw)
    observation["header"] = {"machine": machine, "section_count": count,
                              "symbol_table_offset": symbols, "symbol_count": symbol_count,
                              "optional_header_bytes": optional, "characteristics": flags}
    # Retain bounded actual fields BEFORE predicates can reject the object.
    # A malformed/truncated table leaves only the observed header, not invented rows.
    header_end = 20 + count * 40
    sections = []
    if 0 < count <= 96 and header_end <= len(raw):
        for index in range(count):
            section = struct.unpack_from("<8sIIIIIIHHI", raw, 20 + index * 40)
            sections.append(section)
            observation["section_rows"].append({
                "index": index, "name_raw_hex": section[0].hex(),
                "name_field": section[0].rstrip(b"\0").decode("ascii", errors="backslashreplace"),
                "size": section[3], "raw_data_offset": section[4],
                "relocation_offset": section[5], "relocation_count": section[7],
                "characteristics": section[9]})
        observation["section_table_complete"] = True
    if machine != 0x14C or not 0 < count <= 96 or optional != 0 or flags & 0x2002:
        raise RuntimeError("compiled object must be i386 COFF, not executable/DLL")
    if header_end > len(raw) or not symbols or symbols + symbol_count * 18 + 4 > len(raw):
        raise RuntimeError("compiled COFF headers/symbol table out of bounds")
    string_size = struct.unpack_from("<I", raw, symbols + symbol_count * 18)[0]
    if string_size < 4 or symbols + symbol_count * 18 + string_size > len(raw):
        raise RuntimeError("compiled COFF string table out of bounds")
    allocation = 0
    uninitialized = 0
    file_backed = 0
    for section in sections:
        size, at, relocation_at, relocations = section[3], section[4], section[5], section[7]
        characteristics = section[9]
        allocation += size
        if allocation > LIMIT:
            raise RuntimeError("compiled COFF summed section allocation exceeded 8 MiB")
        if characteristics & 0x80:
            if at != 0 or characteristics & (0x20 | 0x40 | 0x20000000):
                raise RuntimeError("compiled COFF uninitialized section has raw bytes or conflicting flags")
            uninitialized += size
        elif size and (at < header_end or at + size > len(raw)):
            raise RuntimeError("compiled COFF section bytes outside object")
        else:
            file_backed += size
        # Extended relocation-count encoding is not interpreted by this scope.
        if characteristics & 0x01000000:
            raise RuntimeError("compiled COFF extended relocation count unsupported")
        if relocations and (relocation_at < header_end or relocation_at + relocations * 10 > len(raw)):
            raise RuntimeError("compiled COFF relocation record bounds invalid")
    return {"format": "i386 COFF", "machine": machine, "section_count": count,
            "optional_header_bytes": optional, "symbol_count": symbol_count,
            "summed_section_allocation_bytes": allocation,
            "uninitialized_allocation_bytes": uninitialized, "file_backed_section_bytes": file_backed,
            "metadata_bounds_verified": True, "relocation_record_bounds_verified": True,
            "relocation_semantics_verified": False,
            "native_execution_verified": False}


def coff_object_controls(guard, reports):
    """Fixed synthetic format controls, executed only in the admitted runner.

    No compiler-produced object is reconstructed or claimed from these bytes.
    Memory-only 136-byte fixtures test the selected allocation/flag/raw/reloc
    predicates; they are not complete COFF/linker/relocation-semantic proof.
    """
    fixture = bytearray(136)
    struct.pack_into("<HHIIIHH", fixture, 0, 0x14C, 2, 0, 114, 1, 0, 0)
    struct.pack_into("<8sIIIIIIHHI", fixture, 20, b".text", 0, 0, 4, 100, 104, 0, 1, 0, 0x60000020)
    struct.pack_into("<8sIIIIIIHHI", fixture, 60, b".bss", 0, 0, 64, 0, 0, 0, 0, 0, 0xC0000080)
    fixture[100:104] = b"\xc3\0\0\0"
    struct.pack_into("<IIH", fixture, 104, 0, 0, 6)
    struct.pack_into("<8sIhHBB", fixture, 114, b"_stub", 0, 1, 0x20, 2, 0)
    struct.pack_into("<I", fixture, 132, 4)
    raw_error = "compiled COFF section bytes outside object"
    bss_error = "compiled COFF uninitialized section has raw bytes or conflicting flags"
    relocation_error = "compiled COFF relocation record bounds invalid"
    format_error = "compiled object must be i386 COFF, not executable/DLL"
    cases = (
        ("initialized-and-empty-bss", ((76, "<I", 0),), None),
        ("nonzero-uninitialized-allocation", (), None),
        ("flagged-uninitialized-renamed", ((60, "<8s", b".reserve"),), None),
        ("summed-allocation-at-8MiB", ((76, "<I", LIMIT - 4),), None),
        ("initialized-data-section", ((56, "<I", 0xC0000040),), None),
        ("initialized-null-raw-pointer", ((40, "<I", 0),), raw_error),
        ("initialized-header-overlap", ((40, "<I", 99),), raw_error),
        ("initialized-outside-file", ((40, "<I", 137),), raw_error),
        ("initialized-truncated-bytes", ((36, "<I", 137),), raw_error),
        ("bss-name-without-uninitialized-flag", ((96, "<I", 0xC0000000),), raw_error),
        ("uninitialized-has-code-flag", ((96, "<I", 0xC00000A0),), bss_error),
        ("uninitialized-has-initialized-flag", ((96, "<I", 0xC00000C0),), bss_error),
        ("uninitialized-executable", ((96, "<I", 0xE0000080),), bss_error),
        ("uninitialized-has-file-pointer", ((80, "<I", 100),), bss_error),
        ("summed-allocation-exceeds-8MiB", ((76, "<I", LIMIT),),
         "compiled COFF summed section allocation exceeded 8 MiB"),
        ("relocation-null-pointer", ((44, "<I", 0),), relocation_error),
        ("relocation-header-overlap", ((44, "<I", 99),), relocation_error),
        ("relocation-truncated", ((44, "<I", 127),), relocation_error),
        ("relocation-overflow-flag", ((56, "<I", 0x61000020),),
         "compiled COFF extended relocation count unsupported"),
        ("executable-file-characteristic", ((18, "<H", 2),), format_error),
        ("DLL-file-characteristic", ((18, "<H", 0x2000),), format_error),
        ("wrong-machine", ((0, "<H", 0x8664),), format_error),
    )
    for label, edits, expected_error in cases:
        guard.check()
        raw = bytearray(fixture)
        for at, format, value in edits:
            struct.pack_into(format, raw, at, value)
        observed = {}
        try:
            metadata = coff_object_metadata(bytes(raw), observed)
        except RuntimeError as error:
            if expected_error is None or str(error) != expected_error:
                raise RuntimeError("COFF synthetic control failed/unintended rejection: " + label) from error
            outcome = "PASS_REJECTION"
        else:
            if expected_error is not None:
                raise RuntimeError("malformed synthetic COFF control accepted: " + label)
            outcome = "PASS_ACCEPTANCE"
            if not metadata["metadata_bounds_verified"]:
                raise RuntimeError("COFF synthetic positive omitted its metadata validation")
        if not observed.get("section_table_complete") or len(observed["section_rows"]) != 2:
            raise RuntimeError("bounded synthetic COFF diagnostic rows missing")
        reports.append({"case": label, "result": outcome, "expected_rejection": expected_error,
                        "synthetic_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
        guard.check()
    return {"completed": len(reports), "positive_controls": 5, "negative_controls": 17,
            "compiler_produced_objects_reconstructed": False,
            "full_COFF_or_relocation_semantics_verified": False}


def structural_pe_gate(raw, document, pe_module, *, dll):
    """Scoped compiler-output structure/import/export checks, not loader proof."""
    if len(raw) < 64 or raw[:2] != b"MZ":
        raise RuntimeError("actual PE DOS header invalid")
    nt = struct.unpack_from("<I", raw, 0x3C)[0]
    if not 64 <= nt <= 65536 or nt + 24 > len(raw) or raw[nt:nt + 4] != b"PE\0\0":
        raise RuntimeError("actual PE NT header bounds invalid")
    with pe_module.PE(data=raw) as pe:
        header = pe.OPTIONAL_HEADER
        count = pe.FILE_HEADER.NumberOfSections
        table = nt + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
        if (pe.FILE_HEADER.Machine != 0x14C or header.Magic != 0x10B
                or pe.FILE_HEADER.SizeOfOptionalHeader != 224 or not 0 < count <= 96
                or count != len(pe.sections) or table + count * 40 > header.SizeOfHeaders
                or not table + count * 40 <= header.SizeOfHeaders <= len(raw)
                or not header.SizeOfHeaders <= header.SizeOfImage <= 16 * 1024 * 1024
                or header.NumberOfRvaAndSizes != 16 or len(header.DATA_DIRECTORY) != 16
                or not pe.FILE_HEADER.Characteristics & 2 or pe.is_dll() != dll):
            raise RuntimeError("bounded compiler PE32 headers/section table required")
        virtual = []
        mapped = []
        names = set()
        for section in pe.sections:
            name = section.Name.rstrip(b"\0").decode("ascii", errors="strict")
            span = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if (not name or name in names or section.VirtualAddress < header.SizeOfHeaders
                    or span > header.SizeOfImage - section.VirtualAddress
                    or section.VirtualAddress > header.SizeOfImage):
                raise RuntimeError("actual PE virtual section extent invalid")
            names.add(name)
            if span:
                start, end = section.VirtualAddress, section.VirtualAddress + span
                if any(start < previous_end and previous_start < end for previous_start, previous_end in virtual):
                    raise RuntimeError("overlapping actual virtual sections")
                virtual.append((start, end))
            if section.SizeOfRawData:
                start, end = section.PointerToRawData, section.PointerToRawData + section.SizeOfRawData
                if start < header.SizeOfHeaders or end > len(raw):
                    raise RuntimeError("actual PE raw section extent invalid")
                if any(start < previous_end and previous_start < end for previous_start, previous_end in mapped):
                    raise RuntimeError("overlapping actual raw sections")
                mapped.append((start, end))
        def offset(rva, size):
            if rva < header.SizeOfHeaders and size <= header.SizeOfHeaders - rva:
                return rva
            for section in pe.sections:
                delta = rva - section.VirtualAddress
                if 0 <= delta < section.SizeOfRawData and size <= section.SizeOfRawData - delta:
                    return section.PointerToRawData + delta
            raise RuntimeError("declared PE structure not fully file-backed")
        def string(rva):
            at = offset(rva, 1)
            for length in range(256):
                pos = offset(rva + length, 1)
                if pos != at + length:
                    raise RuntimeError("PE import/export string crosses raw span")
                if raw[pos] == 0:
                    if length == 0:
                        raise RuntimeError("empty PE import/export string")
                    return raw[at:pos].decode("ascii", errors="strict")
            raise RuntimeError("PE import/export string unterminated/unbounded")
        for index, directory in enumerate(header.DATA_DIRECTORY):
            rva, size = directory.VirtualAddress, directory.Size
            if bool(rva) != bool(size):
                raise RuntimeError("declared PE directory has partial address/size")
            if rva:
                if index == 4:
                    raise RuntimeError("unexpected certificate overlay outside build recipe")
                offset(rva, size)
        def executable(rva):
            return any(section.Characteristics & 0x20000000
                       and section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize
                       for section in pe.sections)
        if not executable(header.AddressOfEntryPoint):
            raise RuntimeError("PE entry point outside executable bytes")
        directory = header.DATA_DIRECTORY[1]
        if not directory.VirtualAddress or directory.Size < 40:
            raise RuntimeError("actual PE import directory absent/truncated")
        actual = {}
        parsed = getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
        descriptor_offsets = []
        terminated = False
        for index in range(min(directory.Size // 20, 128)):
            at = offset(directory.VirtualAddress + index * 20, 20)
            descriptor = struct.unpack_from("<IIIII", raw, at)
            if not any(descriptor):
                terminated = True
                break
            original, timestamp, forward_chain, name_rva, first = descriptor
            name = string(name_rva).upper()
            if name in actual or name not in document["dlls"] or not first:
                raise RuntimeError("PE import descriptor duplicate/outside named OEM policy")
            entries = []
            thunk = original or first
            thunk_terminated = False
            for number in range(512):
                value = struct.unpack_from("<I", raw, offset(thunk + number * 4, 4))[0]
                if not value:
                    thunk_terminated = True
                    break
                if value & 0x80000000:
                    raise RuntimeError("PE ordinal import rejected")
                offset(value, 2)       # actual hint word is file-backed
                function = string(value + 2)
                if function in entries or function not in document["dlls"][name]:
                    raise RuntimeError("PE named import duplicate/outside actual OEM inventory")
                offset(first + number * 4, 4)
                entries.append(function)
            if not thunk_terminated or not entries:
                raise RuntimeError("actual import thunks empty/unbounded/unterminated")
            actual[name] = entries
            descriptor_offsets.append(at)
        if not terminated or not actual or len(parsed) != len(descriptor_offsets):
            raise RuntimeError("declared actual import descriptors were not completely parsed")
        for descriptor, at in zip(parsed, descriptor_offsets):
            name = descriptor.dll.decode("ascii", errors="strict").upper()
            imported = [entry.name.decode("ascii", errors="strict") if entry.name else None
                        for entry in descriptor.imports]
            if descriptor.struct.get_file_offset() != at or imported != actual.get(name):
                raise RuntimeError("raw/parsed actual import descriptor mismatch")
        exports = {}
        if dll:
            export_directory = header.DATA_DIRECTORY[0]
            if not export_directory.VirtualAddress or export_directory.Size < 40:
                raise RuntimeError("actual bridge export directory absent/truncated")
            structure = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
            if structure is None or structure.struct.NumberOfFunctions != 3 or structure.struct.NumberOfNames != 3:
                raise RuntimeError("exact three named bridge export functions required")
            info = structure.struct
            offset(info.AddressOfFunctions, 12)
            offset(info.AddressOfNames, 12)
            offset(info.AddressOfNameOrdinals, 6)
            aliases = {"NtwOpenProviderDirectoryA": "_NtwOpenProviderDirectoryA@4",
                       "NtwFindProviderExportA": "_NtwFindProviderExportA@12",
                       "NtwCloseProviderDirectory": "_NtwCloseProviderDirectory@4"}
            symbols = coff_symbols(raw, pe.FILE_HEADER.PointerToSymbolTable,
                                   pe.FILE_HEADER.NumberOfSymbols, pe.sections, aliases.values())
            if len(structure.symbols) != 3:
                raise RuntimeError("parsed bridge export list incomplete")
            ordinals = set()
            for symbol in structure.symbols:
                name = symbol.name.decode("ascii", errors="strict") if symbol.name else None
                if (name not in aliases or name in exports or symbol.ordinal in ordinals
                        or symbol.forwarder is not None or not executable(symbol.address)
                        or symbol.address != symbols[aliases[name]]):
                    raise RuntimeError("bridge export not unique/nonforwarded/executable/stdcall identity")
                exports[name] = {"rva": symbol.address, "ordinal": symbol.ordinal,
                                 "stdcall_coff_symbol": aliases[name]}
                ordinals.add(symbol.ordinal)
        return {"header_section_raw_and_virtual_bounds_verified": True,
                "declared_named_import_descriptors_and_thunks_verified": True,
                "imports": actual, "bridge_export_stdcall_symbol_identities": exports,
                "bridge_export_identity_verified": dll,
                "full_relocation_block_validation_verified": False,
                "complete_PE_loader_acceptance_verified": False,
                "native_execution_verified": False}


def structural_negative_controls(raw, document, pe_module, guard, output, base):
    """Mutate only new owned copies, then require the intended guard failure.

    These bounded deterministic cases cover selected new PE predicates. They
    are not exhaustive malformed-PE, loader, relocation or decoder controls.
    """
    with pe_module.PE(data=raw) as pe:
        nt = struct.unpack_from("<I", raw, 0x3C)[0]
        optional = nt + 24
        section_table = optional + pe.FILE_HEADER.SizeOfOptionalHeader
        imports = list(pe.DIRECTORY_ENTRY_IMPORT)
        exports = list(pe.DIRECTORY_ENTRY_EXPORT.symbols)
        export = pe.DIRECTORY_ENTRY_EXPORT.struct
        first_import = imports[0].struct.get_file_offset()
        first_symbol = exports[0]
        names = {symbol.name.decode("ascii"): symbol for symbol in exports}
        name_symbol = names["NtwOpenProviderDirectoryA"]
        def mapped(rva):
            for section in pe.sections:
                delta = rva - section.VirtualAddress
                if 0 <= delta < section.SizeOfRawData:
                    return section.PointerToRawData + delta
            raise RuntimeError("negative control source address not file-backed")
        ordinal_index = first_symbol.ordinal - export.Base
        open_index = name_symbol.ordinal - export.Base
        nonexecuting = next(section for section in pe.sections
                            if not section.Characteristics & 0x20000000 and section.Misc_VirtualSize)
        cases = [
            ("nt-header-bounds", [(0x3C, "<I", len(raw))], "actual PE NT header bounds invalid"),
            ("section-raw-bounds", [(section_table + 20, "<I", len(raw))],
             "actual PE raw section extent invalid"),
            ("section-overlap", [(section_table + 40 + 12, "<I", pe.sections[0].VirtualAddress)],
             "overlapping actual virtual sections"),
            ("import-directory-unparsed", [(optional + 96 + 8, "<I", pe.OPTIONAL_HEADER.SizeOfImage - 1)],
             "declared PE structure not fully file-backed"),
            ("import-name-policy", [(first_import + 12, "<I", export.Name)],
             "PE import descriptor duplicate/outside named OEM policy"),
            ("export-count", [(export.get_file_offset() + 24, "<I", 2)],
             "exact three named bridge export functions required"),
            ("export-forwarder", [(mapped(export.AddressOfFunctions) + ordinal_index * 4,
                                   "<I", pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress)],
             "bridge export not unique/nonforwarded/executable/stdcall identity"),
            ("export-nonexecuting", [(mapped(export.AddressOfFunctions) + ordinal_index * 4,
                                      "<I", nonexecuting.VirtualAddress)],
             "bridge export not unique/nonforwarded/executable/stdcall identity"),
            ("export-stdcall-identity", [(mapped(export.AddressOfFunctions) + open_index * 4,
                                         "<I", name_symbol.address + 1)],
             "bridge export not unique/nonforwarded/executable/stdcall identity"),
        ]
    reports = []
    cases.append(("import-descriptor-duplicate", [],
                  "PE import descriptor duplicate/outside named OEM policy"))
    for label, edits, expected in cases:
        changed = bytearray(raw)
        for at, format, value in edits:
            struct.pack_into(format, changed, at, value)
        if label == "import-descriptor-duplicate":
            changed[first_import + 20:first_import + 40] = raw[first_import:first_import + 20]
        path = output / ("negative-" + label + ".dll")
        guard.write(path, bytes(changed))
        guard.check()
        pin = base.hash_regular(path, maximum=LIMIT, guard=guard)
        observed = read_pinned(path, pin, base, maximum=LIMIT, guard=guard)
        if observed != bytes(changed):
            raise RuntimeError("owned negative PE copy differs from exact mutation")
        try:
            structural_pe_gate(observed, document, pe_module, dll=True)
        except RuntimeError as error:
            if str(error) != expected:
                raise RuntimeError("PE negative control rejected for unintended predicate: " + label) from error
            reports.append({"case": label, "path": str(path), "bytes": len(changed),
                            "sha256": hashlib.sha256(changed).hexdigest(),
                            "identity": pin["identity"],
                            "expected_rejection": expected, "result": "PASS_REJECTION"})
        else:
            raise RuntimeError("malformed PE negative control incorrectly accepted: " + label)
        guard.check()
    return reports


def executable_sections(raw, pe_module):
    sections = {}
    with pe_module.PE(data=raw) as pe:
        if pe.FILE_HEADER.Machine != 0x14C or pe.OPTIONAL_HEADER.Magic != 0x10B:
            raise RuntimeError("i486 decode requires actual PE32 i386")
        if not 0 < len(pe.sections) <= 96:
            raise RuntimeError("bounded PE section count required")
        for section in pe.sections:
            if section.Characteristics & 0x20000000:
                name = section.Name.rstrip(b"\0").decode("ascii", errors="strict")
                size = section.Misc_VirtualSize
                if (not name or name in sections
                        or not 0 < size <= section.SizeOfRawData <= 4 * 1024 * 1024):
                    raise RuntimeError("executable PE section extent invalid")
                data = section.get_data()[:size]
                if len(data) != size:
                    raise RuntimeError("truncated actual executable section")
                sections[name] = {"address": pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress,
                                  "bytes": data}
    if not sections or sum(len(value["bytes"]) for value in sections.values()) > 4 * 1024 * 1024:
        raise RuntimeError("bounded nonempty executable sections required")
    return sections


def probe_gate(raw, document, pe_module):
    """Preserve build.py's probe PE32/OEM-import acceptance semantics."""
    imports = {}
    with pe_module.PE(data=raw) as pe:
        header = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, header.Magic, header.Subsystem,
                header.MajorSubsystemVersion, header.MinorSubsystemVersion) != (0x14C, 0x10B, 2, 4, 10):
            raise RuntimeError("probe PE ABI mismatch")
        if (pe.is_dll() or header.DllCharacteristics & 0x140
                or any(header.DATA_DIRECTORY[index].VirtualAddress for index in (9, 13, 14))):
            raise RuntimeError("probe unsupported runtime flags")
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            name = descriptor.dll.decode("ascii", errors="strict").upper()
            if name in imports:
                raise RuntimeError("duplicate probe import descriptor")
            imports[name] = []
            for entry in descriptor.imports:
                if entry.name is None:
                    raise RuntimeError("probe ordinal import outside named OEM policy")
                function = entry.name.decode("ascii", errors="strict")
                if function not in document["dlls"].get(name, []):
                    raise RuntimeError("probe import outside original OEM inventory")
                imports[name].append(function)
    if not imports:
        raise RuntimeError("probe named native OEM imports absent")
    return {"imports": imports, "oem_import_gate": "PASS", "native_load": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_root
    allowed = ROOT / "build/native-provider-pe32-6970"
    if not output.is_absolute() or output.parent != allowed or output.exists():
        raise SystemExit("output must be one NEW absolute direct child of build/native-provider-pe32-6970")
    base = import_verified(BASE_GUARD, BASE_GUARD_SHA256, "native_pe32_frozen_sspi_guard")
    if base.ROOT != ROOT or any(getattr(base, key) != globals()[key] for key in
                              ("LIMIT", "RESERVE", "CAPTURE_LIMIT", "RECEIPT_LIMIT", "PENDING",
                               "SOURCE_INPUT_LIMIT", "TOOL_INPUT_LIMIT", "DEPENDENCY_LIMIT",
                               "DEPENDENCY_PATH_LIMIT", "COMMAND_TIMEOUT")):
        raise SystemExit("frozen guard root/resource contract mismatch")
    base.INVALID_RECEIPT_SCHEMA = INVALID_RECEIPT_SCHEMA
    base.safe_components(output)
    if ROOT != ROOT.resolve():
        raise SystemExit("source root must be canonical")
    fixture = HERE / "sspi_sdk_abi_6970.c"
    expected = {**FROZEN_INPUTS,
                str(fixture.relative_to(ROOT)): (SDK_FIXTURE_SIZE, SDK_FIXTURE_SHA256)}
    closure = [ROOT / name for name in expected] + [Path(__file__).resolve()]
    before = source_snapshot(closure, base)
    for name, (size, digest) in expected.items():
        record = before[name]
        if record["identity"][2] != size or record["sha256"] != digest:
            raise SystemExit("frozen build/helper/SDK/OEM source pin mismatch: " + name)
    try:
        available = base.admission()
        available = base.admission()       # fresh full budget immediately before owned mkdir
    except RuntimeError as error:
        print(json.dumps({"result": "BLOCKED_NOT_RUN", "reason": str(error)}))
        return 3
    output.mkdir(parents=True, exist_ok=False)
    guard = base.Guard(output)
    receipt = {
        "schema": "native-provider-pe32-build-and-sdk-abi-v1", "result": "NOT_COMPLETED",
        "source_inputs": before, "output_root": str(output), "available_before_bytes": available,
        "reserve_bytes": RESERVE, "output_limit_bytes": LIMIT,
        "capture_limit_bytes_aggregate": CAPTURE_LIMIT, "receipt_limit_bytes": RECEIPT_LIMIT,
        "commands": [], "derived_guard_source_sha256": BASE_GUARD_SHA256,
        "reported_hosted_checkout_sha": os.environ.get("GITHUB_SHA"),
        "hosted_checkout_independently_verified_by_runner": False,
        "self_loaded_runner_binding_verified": False,
        "native_execution_verified": False, "actual_native_load_verified": False,
        "network_execution_verified": False,
        "windows98_integration_verified": False, "windows_acceptance_verified": False,
        "tls_execution_verified": False, "os_tls_provider_verified": False,
        "credential_execution_verified": False, "application_compatibility_verified": False,
        "os_registration_verified": False, "kernel64_backend_verified": False,
        "engine_link_verified": False, "guest_execution_verified": False,
        "provider_policy_changed": False, "sdk_abi_compile_verified": False,
        "pe32_artifacts_build_verified": False, "oem_import_gate_verified": False,
        "i486_full_executable_sections_decode_verified": False,
        "i486_executable_raw_padding_verified": False,
        "full_relocation_block_validation_verified": False,
        "complete_PE_loader_acceptance_verified": False,
        "original_i486_python_controls_verified": False,
        "original_i486_synthetic_PE_scan_control_verified": False,
        "structural_negative_controls_verified": False,
        "coff_object_structural_controls_verified": False,
        "independent_export_clause_coverage": False,
        "coff_format_reference": COFF_FORMAT_REFERENCE,
        "recipe": {"reference": "ntwin32/legacy_provider_bridge/build.py",
                   "reference_sha256": FROZEN_INPUTS["ntwin32/legacy_provider_bridge/build.py"][1],
                   "original_one_shot_compile_link_used": False,
                   "object_split_for_individual_actual_MD_manifests": True,
                   "original_C_linker_flags_def_and_kernel32_preserved": True,
                   "added_linker_trace_flag_without_link_semantics_change": "-Wl,-t",
                   "SDK_fixture_compile_only_no_link_or_execution": True},
        "guard_model": {"recursive_regular_file_logical_bytes": True,
                        "sample_interval_seconds": 0.05, "per_file_rlimit_fsize": True,
                        "aggregate_filesystem_quota": False,
                        "all_transient_create_unlink_peaks_observed": False,
                        "maximum_directories": 128, "maximum_files": 4096, "maximum_depth": 16,
                        "bounded_fail_receipt_authorizes_further_work": False},
        "provenance_limits": {"source_or_header_bytes_per_file": SOURCE_INPUT_LIMIT,
                              "source_input_total_bytes": SOURCE_TOTAL_LIMIT,
                              "unique_header_input_total_bytes": HEADER_TOTAL_LIMIT,
                              "direct_tool_or_linker_input_bytes_per_file": TOOL_INPUT_LIMIT,
                              "hash_seconds_per_input": COMMAND_TIMEOUT,
                              "dependency_manifest_bytes": DEPENDENCY_LIMIT,
                              "dependency_declared_path_count": DEPENDENCY_PATH_LIMIT,
                              "unique_header_path_count": DEPENDENCY_PATH_LIMIT,
                              "subprocess_seconds": COMMAND_TIMEOUT,
                              "actual_M_and_MD_include_closures_required": True,
                              "actual_M_and_MD_include_closures_hashed": False,
                              "direct_kernel32_linker_input_required": True,
                              "direct_kernel32_linker_input_hashed_before_after": False,
                              "actual_linker_trace_matches_direct_kernel32_input": False,
                              "compiler_backend_linker_dynamic_runtime_kernel_closure_verified": False,
                              "python_runtime_or_self_loaded_code_attestation_verified": False,
                              "imported_pefile_runtime_attestation_verified": False},
        "standard_header_closure": {}, "standard_header_inputs_before": {},
        "standard_header_inputs_after": {},
        "scope": "actual PE32 build, original OEM imports/exports and all linked executable-section i486 decode; compile-only production/installed-SDK static ABI assertions",
    }
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "TMPDIR": str(output), "TMP": str(output), "TEMP": str(output),
           "PYTHONDONTWRITEBYTECODE": "1", "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1"}
    admission = base.admission

    def run(argv, label):
        admission()
        guard.check(PENDING)
        if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
            raise RuntimeError("nonreaping owned process-group observation is unavailable")
        budget = LIMIT - guard.count() - PENDING
        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (budget, budget))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        start = time.monotonic()
        selector = selectors.DefaultSelector()
        try:
            child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, preexec_fn=child_limits)
        except BaseException:
            selector.close()
            raise
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        aborted = None
        group_kill = "NOT_REQUESTED"
        leader_exit_observed = False
        try:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while True:
                guard.check(PENDING)
                if time.monotonic() - start > COMMAND_TIMEOUT:
                    raise RuntimeError("bounded compiler/fixture subprocess timeout")
                # Keep an exited group leader waitable until its owned pipes
                # close or abort teardown completes. poll() would reap it and
                # release the PID/PGID before descendant termination.
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                leader_exit_observed = bool(observed and observed.si_pid == child.pid)
                if leader_exit_observed and not selector.get_map():
                    break
                for key, _ in selector.select(0.05):
                    block = os.read(key.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        if guard.capture_bytes + len(block) > CAPTURE_LIMIT:
                            raise RuntimeError("whole-run aggregate capture exceeded 256 KiB")
                        guard.capture_bytes += len(block)
                        chunks[key.data].extend(block)
            guard.check(PENDING)
            child.wait(timeout=5)
        except BaseException as error:
            aborted = str(error)[:2048]
            # The compiler driver may already have exited while one of its
            # owned descendants keeps the pipe or a temporary file open.
            # Teardown always targets this launch's process group, never a
            # peer PID and never merely the direct child's running state.
            try:
                os.killpg(child.pid, signal.SIGKILL)
                group_kill = "SIGKILL_SENT_TO_OWNED_GROUP"
            except ProcessLookupError:
                group_kill = "OWNED_GROUP_ALREADY_ABSENT"
            except OSError as kill_error:
                group_kill = "FAILED: " + str(kill_error)
            child.wait(timeout=5)
            if group_kill.startswith("FAILED:"):
                raise RuntimeError("owned process-group teardown failed") from error
            raise
        finally:
            selector.close()
            child.stdout.close()
            child.stderr.close()
            receipt["commands"].append({"label": label, "argv": [str(value) for value in argv],
                                        "returncode": child.returncode, "owned_pid": child.pid,
                                        "reaped": child.returncode is not None, "aborted": aborted,
                                        "owned_group_kill": group_kill,
                                        "nonreaping_leader_exit_observed": leader_exit_observed,
                                        "group_lifetime_observation": "waitid WNOWAIT until EOF/abort then wait",
                                        "elapsed_seconds": time.monotonic() - start,
                                        "rlimit_fsize_bytes": budget,
                                        "captured_bytes": sum(map(len, chunks.values())),
                                        "aggregate_captured_bytes": guard.capture_bytes,
                                        "captured_sha256": {name: hashlib.sha256(data).hexdigest()
                                                            for name, data in chunks.items()},
                                        "aborted_stderr_preview": bytes(chunks["stderr"][:2048]).decode(errors="replace")
                                        if aborted else None})
        guard.write(output / (label + ".stdout"), bytes(chunks["stdout"]))
        guard.write(output / (label + ".stderr"), bytes(chunks["stderr"]))
        return subprocess.CompletedProcess(argv, child.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]))

    def clean(argv, label):
        result = run(argv, label)
        if result.returncode or result.stdout or result.stderr:
            raise RuntimeError("build/dependency diagnostic or failed command: " + label)
        return result

    try:
        receipt["coff_object_control_cases"] = []
        receipt["coff_object_control_summary"] = coff_object_controls(
            guard, receipt["coff_object_control_cases"])
        tools = {}
        for label, name in (("compiler", "i686-w64-mingw32-gcc-win32"),
                            ("objdump", "i686-w64-mingw32-objdump")):
            found = shutil.which(name, path=env["PATH"])
            if not found:
                raise RuntimeError("installed compiler/objdump required")
            path = Path(found).resolve(strict=True)
            pin = base.hash_regular(path, maximum=TOOL_INPUT_LIMIT, guard=guard)
            version = run([str(path), "--version"], label + "-version")
            lines = version.stdout.decode("ascii", errors="strict").split("\n")
            if version.returncode or version.stderr or not lines[0]:
                raise RuntimeError("actual direct tool version query failed")
            tools[label] = {"path": str(path), **pin, "version": lines[0], "requested_tool": name}
        receipt["tools"] = tools
        python_path = Path(sys.executable).resolve(strict=True)
        python_pin = base.hash_regular(python_path, maximum=TOOL_INPUT_LIMIT, guard=guard)
        tools["python_control_driver"] = {"path": str(python_path), **python_pin,
                                           "version_queried": False,
                                           "full_Python_runtime_attestation_verified": False}
        cc = tools["compiler"]["path"]
        query = run([cc, "-print-file-name=libkernel32.a"], "kernel32-input-query")
        text = query.stdout.decode("ascii", errors="strict")
        if query.returncode or query.stderr or not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
            raise RuntimeError("actual direct kernel32 input query failed")
        queried = Path(text[:-1])
        if not queried.is_absolute() or queried.name != "libkernel32.a":
            raise RuntimeError("actual installed kernel32 import library path required")
        library = queried.resolve(strict=True)
        library_before = base.hash_regular(library, maximum=TOOL_INPUT_LIMIT, guard=guard)
        receipt["direct_kernel32_linker_input_before"] = {"path": str(library), **library_before}
        oem_path = ROOT / "benchmarks/win98se-ko-oem-native-exports-v1.json"
        document = json.loads(read_pinned(oem_path, before[str(oem_path.relative_to(ROOT))], base,
                                          maximum=SOURCE_INPUT_LIMIT, guard=guard))
        native_exports = {name.upper(): set(names) for name, names in document["dlls"].items()}
        prerequisite = import_verified(ROOT / "tools/build_npp_prerequisites.py",
                                       expected["tools/build_npp_prerequisites.py"][1],
                                       "native_pe32_frozen_oem_gate", guard=guard)
        i486 = import_verified(ROOT / "ntwin32/secure_transport/i486_gate.py",
                              expected["ntwin32/secure_transport/i486_gate.py"][1],
                              "native_pe32_frozen_i486_gate", guard=guard)
        parser_path = Path(i486.pefile.__file__).absolute()
        base.safe_components(parser_path)
        if parser_path != parser_path.resolve(strict=True) or parser_path.suffix != ".py":
            raise RuntimeError("actual imported parser must identify canonical regular Python source")
        parser_parent = parser_path.parent
        prep_name = os.environ.get("PMA_PROVIDER_PE32_PREP")
        if prep_name is not None:
            prep = Path(prep_name)
            prepared_pydeps = prep / "pydeps"
            base.safe_components(prepared_pydeps)
            if (not prep.is_absolute() or prep != prep.resolve(strict=True)
                    or parser_parent != prepared_pydeps
                    or prepared_pydeps != prepared_pydeps.resolve(strict=True)):
                raise RuntimeError("actual imported parser differs from exact isolated hosted pydeps")
        if len(str(parser_parent)) > 4096:
            raise RuntimeError("actual parser source directory path exceeded bound")
        parser_before = base.hash_regular(parser_path, maximum=SOURCE_INPUT_LIMIT, guard=guard)
        env["PYTHONPATH"] = str(parser_parent)
        receipt["direct_parser_source_before"] = {"path": str(parser_path), **parser_before,
                                                   "actual_module_parent": str(parser_parent),
                                                   "matches_prepared_pydeps": prep_name is not None,
                                                   "loaded_code_attestation_verified": False}
        receipt["control_child_pythonpath"] = str(parser_parent)
        controls = run([str(python_path), "-B", "-c", I486_CONTROL_CHILD,
                        str(ROOT / "ntwin32/secure_transport/i486_gate.py"),
                        expected["ntwin32/secure_transport/i486_gate.py"][1],
                        str(ROOT / "ntwin32/secure_transport/i486_gate_test.py"),
                        expected["ntwin32/secure_transport/i486_gate_test.py"][1],
                        json.dumps(I486_CONTROL_METHODS)], "i486-original-python-controls")
        if (controls.returncode or controls.stderr
                or controls.stdout != b"I486_PYTHON_CONTROLS: 4 original methods passed\n"):
            raise RuntimeError("original four bounded ISA controls failed")
        receipt["original_i486_controls"] = {"method_names": list(I486_CONTROL_METHODS),
                                              "completed_methods": 4,
                                              "original_fifth_method_deferred": True,
                                              "original_test_methods_and_literal_cases_unchanged": True,
                                              "test_and_gate_loaded_from_exact_hashed_source_buffers": True,
                                              "gate_loader_boundary_substituted": True,
                                              "path_loader_or_stale_pyc_fallback_used": False,
                                              "native_execution_verified": False}
        include_union = set()
        recipes = (("dll-native", HERE / "native.c", DLL_CFLAGS),
                   ("dll-table", HERE / "table.c", DLL_CFLAGS),
                   ("probe", HERE / "probe.c", PROBE_CFLAGS),
                   ("sdk-abi", fixture, DLL_CFLAGS))
        objects = {}
        receipt["compiled_objects"] = objects
        for label, source, flags in recipes:
            common = [cc, *flags]
            depfile = output / (label + ".includes")
            target = "native_pe32_proof"
            clean([*common, "-M", "-MT", target, "-MF", str(depfile), str(source)],
                  label + "-dependencies")
            included, manifest = base.dependencies(depfile, target)
            required = {source}
            if label in ("dll-native", "dll-table", "sdk-abi"):
                required.add(HERE / "table.h")
            if label == "sdk-abi":
                required.add(HERE / "native.c")
            if not required <= set(included):
                raise RuntimeError("production/SDK TU missing from actual include closure")
            unit_before = source_snapshot(included, base, guard, maximum_total=HEADER_TOTAL_LIMIT)
            for path in included:
                key = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
                previous = receipt["standard_header_inputs_before"].get(key)
                if previous is not None and previous != unit_before[key]:
                    raise RuntimeError("shared actual SDK/header input changed between TUs")
            include_union.update(included)
            if len(include_union) > DEPENDENCY_PATH_LIMIT:
                raise RuntimeError("unique actual SDK header closure exceeded path bound")
            receipt["standard_header_inputs_before"].update(unit_before)
            if sum(value["identity"][2] for value in receipt["standard_header_inputs_before"].values()) > HEADER_TOTAL_LIMIT:
                raise RuntimeError("unique actual SDK headers exceeded total byte bound")
            obj = output / (label + ".o")
            compile_depfile = output / (label + "-compile.includes")
            clean([*common, "-MD", "-MT", target, "-MF", str(compile_depfile),
                   "-c", str(source), "-o", str(obj)], label + "-compile")
            compiled_includes, compile_manifest = base.dependencies(compile_depfile, target)
            unit_after = source_snapshot(included, base, guard, maximum_total=HEADER_TOTAL_LIMIT)
            if compiled_includes != included or unit_after != unit_before:
                raise RuntimeError("actual -M/-MD SDK/source closure changed during compilation")
            receipt["standard_header_closure"][label] = {
                "discovery": compact_manifest(manifest), "compilation": compact_manifest(compile_manifest),
                "included_paths": list(unit_before), "included_path_count": len(included)}
            object_pin = base.hash_regular(obj, maximum=LIMIT, guard=guard)
            object_raw = read_pinned(obj, object_pin, base, maximum=LIMIT, guard=guard)
            # Install the actual immutable artifact pin and bounded diagnostic
            # sink before validation. A FAIL receipt retains this object/rows.
            record = {"path": str(obj), **object_pin,
                      "coff_observation": {"validation_result": "NOT_COMPLETED"}}
            objects[label] = record
            try:
                record["metadata"] = coff_object_metadata(object_raw, record["coff_observation"])
            except RuntimeError as error:
                record["coff_observation"].update(validation_result="FAIL", error=str(error)[:2048])
                raise
            record["coff_observation"]["validation_result"] = "PASS"
        dll = output / "NTWPROV.DLL"
        probe = output / "NTWPRB.EXE"
        for flags, paths, artifact, label in (
                (DLL_LDFLAGS, [objects["dll-native"]["path"], objects["dll-table"]["path"],
                               str(HERE / "NTWPROV.def")], dll, "dll-link"),
                (PROBE_LDFLAGS, [objects["probe"]["path"]], probe, "probe-link")):
            if base.hash_regular(library, maximum=TOOL_INPUT_LIMIT, guard=guard) != library_before:
                raise RuntimeError("direct kernel32 linker input changed before actual link")
            linked = run([cc, *flags, "-Wl,-t", "-o", str(artifact), *paths, "-lkernel32"], label)
            trace = linked.stdout.decode("ascii", errors="strict")
            if (linked.returncode or linked.stderr or not trace.endswith("\n")
                    or "\r" in trace or not trace[:-1]):
                raise RuntimeError("actual link trace failed/diagnosed/empty")
            traced = []
            permitted = {Path(path).resolve(strict=True) for path in paths} | {library}
            for line in trace.split("\n")[:-1]:
                candidate = Path(line)
                if not candidate.is_absolute():
                    candidate = ROOT / candidate
                resolved = candidate.resolve(strict=True)
                if resolved not in permitted:
                    raise RuntimeError("actual linker trace contains unbound direct input")
                traced.append(str(resolved))
            if str(library) not in traced:
                raise RuntimeError("actual linker trace did not select frozen kernel32 import library")
            receipt.setdefault("linker_trace", {})[label] = {
                "resolved_inputs": traced,
                "stdout_sha256": hashlib.sha256(linked.stdout).hexdigest(),
                "direct_kernel32_input_matches_query": True}
        artifacts = {}
        for artifact, label in ((dll, "dll"), (probe, "probe")):
            guard.check()
            pin = base.hash_regular(artifact, maximum=LIMIT, guard=guard)
            raw = read_pinned(artifact, pin, base, maximum=LIMIT, guard=guard)
            structure = structural_pe_gate(raw, document, i486.pefile, dll=label == "dll")
            if label == "dll":
                policy = prerequisite.gate(artifact, native_exports)
                if set(policy["exports"]) != {"NtwOpenProviderDirectoryA", "NtwFindProviderExportA",
                                             "NtwCloseProviderDirectory"}:
                    raise RuntimeError("native provider exact export ABI mismatch")
                if policy["bytes"] != len(raw) or policy["sha256"] != pin["sha256"]:
                    raise RuntimeError("OEM policy input differs from retained artifact")
            else:
                policy = probe_gate(raw, document, i486.pefile)
            sections = executable_sections(raw, i486.pefile)
            decoded = run([tools["objdump"]["path"], "-d", "-z", "--show-raw-insn",
                           "--insn-width=16", str(artifact)], label + "-objdump")
            if decoded.returncode or decoded.stderr or not decoded.stdout:
                raise RuntimeError("actual bounded objdump failed/diagnosed/empty")
            guard.check()
            decode = i486.inspect_decode(decoded.stdout.decode("ascii", errors="strict"), sections)
            guard.check()
            if decode["status"] != "PASS":
                receipt.setdefault("i486_failed_decode", {})[label] = decode
                raise RuntimeError("actual executable-section i486 instruction gate failed")
            if base.hash_regular(artifact, maximum=LIMIT, guard=guard) != pin:
                raise RuntimeError("linked artifact changed during OEM/i486 proof")
            artifacts[artifact.name] = {"path": str(artifact), **pin, "oem_policy": policy,
                                        "structural_policy": structure,
                                        "i486_decode": decode,
                                        "objdump_stdout_sha256": hashlib.sha256(decoded.stdout).hexdigest(),
                                        "native_load_verified": False}
            if label == "dll":
                receipt["structural_negative_controls"] = structural_negative_controls(
                    raw, document, i486.pefile, guard, output, base)
        receipt["artifacts"] = artifacts
        headers_after = source_snapshot(include_union, base, guard, maximum_total=HEADER_TOTAL_LIMIT)
        receipt["standard_header_inputs_after"] = headers_after
        if headers_after != receipt["standard_header_inputs_before"]:
            raise RuntimeError("actual SDK/project headers changed before final proof")
        after = source_snapshot(closure, base, guard)
        receipt["source_inputs_after"] = after
        if after != before:
            raise RuntimeError("frozen build/helper/SDK/OEM sources changed during proof")
        for info in tools.values():
            if base.hash_regular(Path(info["path"]), maximum=TOOL_INPUT_LIMIT, guard=guard) != {
                    "sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("actual direct compiler/objdump changed during proof")
        library_after = base.hash_regular(library, maximum=TOOL_INPUT_LIMIT, guard=guard)
        receipt["direct_kernel32_linker_input_after"] = {"path": str(library), **library_after}
        if library_after != library_before:
            raise RuntimeError("actual direct kernel32 linker input changed during proof")
        parser_after = base.hash_regular(parser_path, maximum=SOURCE_INPUT_LIMIT, guard=guard)
        receipt["direct_parser_source_after"] = {"path": str(parser_path), **parser_after}
        if parser_after != parser_before:
            raise RuntimeError("direct imported parser source changed during proof")
        for info in objects.values():
            if base.hash_regular(Path(info["path"]), maximum=LIMIT, guard=guard) != {
                    "sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("compiled object changed before final proof")
        for info in receipt["structural_negative_controls"]:
            if base.hash_regular(Path(info["path"]), maximum=LIMIT, guard=guard) != {
                    "sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("owned mutated PE negative copy changed before final proof")
        guard.check(RECEIPT_LIMIT)
        receipt["provenance_limits"]["actual_M_and_MD_include_closures_hashed"] = True
        receipt["provenance_limits"]["direct_kernel32_linker_input_hashed_before_after"] = True
        receipt["provenance_limits"]["actual_linker_trace_matches_direct_kernel32_input"] = True
        receipt.update(sdk_abi_compile_verified=True, pe32_artifacts_build_verified=True,
                       oem_import_gate_verified=True, i486_full_executable_sections_decode_verified=True,
                       original_i486_python_controls_verified=True,
                       structural_negative_controls_verified=True,
                       coff_object_structural_controls_verified=True,
                       result="PASS_BUILD_AND_SDK_ABI_ONLY")
    except BaseException as error:
        receipt.update(result="FAIL", error=str(error)[:2048])
        raise
    finally:
        try:
            base.write_receipt(output, receipt, guard)
        finally:
            guard.close()
    print(json.dumps({"result": receipt["result"], "receipt": str(output / "result.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
