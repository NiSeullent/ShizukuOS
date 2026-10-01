#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze a real KERNELBASE candidate beside the private Modern theme archive.

This supplies an explicit, privately sealed startup comparison. Static export
resolution, application startup, painting, and native Windows 98 are separate
evidence levels. No peer sources or existing archives are changed.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys

import pefile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("private_extension_theme", ROOT / "tools/required_theme_runtime.py")
theme = importlib.util.module_from_spec(spec)
spec.loader.exec_module(theme)
handoff = theme.handoff
inventory = theme.inventory
EXTENSION_PATH = "\\SHZ\\SYS64\\KERNELBASE.DLL"
FALSE_FLAGS = {**theme.FALSE_FLAGS, "modern_memory_semantics_verified": False}
ADAPTERS = frozenset(("VirtualAlloc2", "MapViewOfFile3", "UnmapViewOfFile2"))
IMPORTS = frozenset(("GetCurrentProcess", "GetProcessId", "GetLastError", "SetLastError", "GetSystemInfo",
                     "VirtualAllocEx", "MapViewOfFileEx", "UnmapViewOfFile", "VirtualQuery"))
BUILDER = "ntwddm/win64/memory_bridge/build.py"
MAX_SOURCE_BYTES = 2 * 1024**2
MAX_SOURCE_TOTAL = 16 * 1024**2
MAX_RECEIPT_BYTES = 16 * 1024**2
MAX_DLL_BYTES = 1024**2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sources():
    return {**theme.source_hashes(), "tools/required_theme_runtime.py": handoff.digest_file(ROOT / "tools/required_theme_runtime.py"),
            "tools/runtime_extension_overlay.py": handoff.digest_file(Path(__file__).resolve())}


def digest_bound(path, expected):
    require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected) is not None, "explicit receipt SHA256 required")
    require(handoff.digest_file(path) == expected, "receipt digest changed")


def bounded_regular(path, maximum):
    stream, before = inventory.open_regular(path)
    with stream:
        require(before.st_size <= maximum, "extension input exceeds its size bound")
        data = stream.read(before.st_size + 1)
        require(len(data) == before.st_size and inventory.file_identity(before) == inventory.file_identity(os.fstat(stream.fileno())),
                "extension input changed during read")
        return data


def bound_row(path, checksum, relative, maximum=MAX_SOURCE_BYTES):
    require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "invalid extension input SHA256")
    require(isinstance(path, Path) and path.is_absolute(), "absolute extension input path required")
    data = bounded_regular(path, maximum)
    require(theme.sha(data) == checksum, "extension compiler input changed")
    return {"source_path": str(path), "relative_path": relative, "sha256": checksum, "bytes": len(data), "data": data}


def actual_pe_gate(data):
    exports, ordinals = theme.pe_exports(data)
    require(set(row["ordinal"] for row in exports.values()) == set(ordinals), "unnamed extension exports are unsupported")
    require(ADAPTERS.issubset(exports), "missing modern memory adapters")
    require(all(exports[name]["forwarder"] is None for name in ADAPTERS), "memory adapters must have actual implementation RVAs")
    with pefile.PE(data=data) as pe:
        opt = pe.OPTIONAL_HEADER
        require(pe.is_dll() and pe.FILE_HEADER.Machine == 0x8664 and opt.Magic == 0x20B, "wrong extension ABI")
        require(pe.FILE_HEADER.TimeDateStamp == 0 and opt.AddressOfEntryPoint and opt.Subsystem == 2,
                "wrong extension timestamp, entry point or subsystem")
        require(opt.DATA_DIRECTORY[5].VirtualAddress and opt.DATA_DIRECTORY[5].Size, "extension relocations absent")
        for index in (9, 10, 13, 14):
            require(not opt.DATA_DIRECTORY[index].VirtualAddress and not opt.DATA_DIRECTORY[index].Size,
                    "unexpected extension TLS/load config/delay/managed directory")
        require(pe.DIRECTORY_ENTRY_EXPORT.name.decode("ascii").upper() == "KERNELBASE.DLL", "wrong extension DLL identity")
        for rva in (opt.AddressOfEntryPoint, *(exports[name]["rva"] for name in ADAPTERS)):
            section = pe.get_section_by_rva(rva)
            require(section is not None and section.Characteristics & 0x20000000 and pe.get_data(rva, 1),
                    "extension code RVA must have actual executable bytes")
        imports = {}
        for descriptor in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
            dll = descriptor.dll.decode("ascii").upper()
            require(dll == "KERNEL32.DLL" and dll not in imports, "unexpected/duplicate extension import module")
            require(all(item.name for item in descriptor.imports), "extension ordinal import unsupported")
            names = [item.name.decode("ascii") for item in descriptor.imports]
            require(len(names) == len(set(names)), "duplicate extension import name")
            imports[dll] = sorted(names)
        require(imports == {"KERNEL32.DLL": sorted(IMPORTS)}, "unexpected adapter imports")
    return {"status": "PASS", "machine": "AMD64", "format": "PE32+", "imports": imports, "exports": exports,
            "native_win98_loadable": False, "runtime_execution_verified": False}


def definition_bytes(exports):
    forwarded = {name: row["forwarder"] for name, row in exports.items() if name not in ADAPTERS}
    require(all(target is not None for target in forwarded.values()), "unexpected extension implementation export")
    require(all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,94}", name) for name in exports), "invalid extension definition name")
    return ("LIBRARY KERNELBASE\nEXPORTS\n" + "".join("    " + name + "=m98mb_" + name + "\n" for name in sorted(ADAPTERS))
            + "".join("    " + name + "=" + target + "\n" for name, target in sorted(forwarded.items()))).encode("ascii")


def extension_inputs(path: Path, expected: str):
    digest_bound(path, expected)
    receipt_data = bounded_regular(path, MAX_RECEIPT_BYTES)
    receipt = json.loads(receipt_data)
    require(isinstance(receipt, dict), "extension receipt must be an object")
    require(receipt.get("schema") == 1 and receipt.get("structural_build_status") == "PASS"
            and receipt.get("status") == "STATIC_CANDIDATE_READY_FOR_GUEST_TEST", "extension is not a structural candidate")
    root = Path(receipt.get("source_root", ""))
    require(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(), "canonical absolute extension source root required")
    hashes = receipt.get("source_hashes")
    required_sources = {"LICENSE", BUILDER, "ntwddm/win64/memory_bridge/bridge.c", "ntwddm/win64/memory_bridge/bridge.h"}
    require(isinstance(hashes, dict) and required_sources.issubset(hashes) and len(hashes) <= 64
            and all(isinstance(name, str) for name in hashes), "source recipe, implementation, header and license hashes required")
    subset = receipt.get("supported_subset")
    require(isinstance(subset, dict) and ADAPTERS | {"unsupported", "ownership"} <= subset.keys()
            and all(isinstance(value, str) and value and len(value) <= 8192 for value in subset.values()),
            "explicit supported subset, unsupported cases and ownership required")
    rows = []
    for name, checksum in sorted(hashes.items()):
        original = root / theme.safe_relative(name)
        require(original.resolve(strict=True).is_relative_to(root), "extension source escapes its source root")
        rows.append(bound_row(original, checksum, "extension-sources/" + name))
    require(sum(row["bytes"] for row in rows) <= MAX_SOURCE_TOTAL, "extension compiler source total exceeds bound")
    artifact = receipt.get("artifact", {})
    require(isinstance(artifact, dict), "extension artifact must be an object")
    original = Path(artifact.get("path", ""))
    require(original.is_absolute(), "absolute candidate DLL path required")
    data = bounded_regular(original, MAX_DLL_BYTES)
    require(len(data) == artifact.get("bytes") and theme.sha(data) == artifact.get("sha256"), "extension artifact changed")
    gate = actual_pe_gate(data)
    require(artifact.get("pe_gate") == gate, "extension receipt PE gate differs from actual DLL")
    generated = receipt.get("generated_definition")
    require(isinstance(generated, dict), "generated export definition must be bound")
    definition = bound_row(Path(generated.get("path", "")), generated.get("sha256"), "extension-compiler-inputs/kernelbase.def")
    require(definition["data"] == definition_bytes(gate["exports"]), "generated definition differs from actual exports")
    rows.append(definition)
    compiler_inputs = receipt.get("compiler_inputs")
    require(isinstance(compiler_inputs, list) and len(compiler_inputs) == 3
            and all(isinstance(row, dict) for row in compiler_inputs), "three exact frozen compiler inputs required")
    expected_inputs = {"bridge.c": hashes["ntwddm/win64/memory_bridge/bridge.c"],
                       "bridge.h": hashes["ntwddm/win64/memory_bridge/bridge.h"], "kernelbase.def": generated["sha256"]}
    seen = set()
    for row in compiler_inputs:
        p = Path(row.get("path", ""))
        require(p.name in expected_inputs and p.name not in seen and row.get("sha256") == expected_inputs[p.name],
                "compiler input differs from source or generated definition")
        seen.add(p.name)
        if p.name == "kernelbase.def":
            require(p == Path(generated["path"]), "compiler used a different generated definition")
        else:
            rows.append(bound_row(p, row["sha256"], "extension-compiler-inputs/" + p.name))
    coverage = receipt.get("forwarder_coverage", {})
    require(isinstance(coverage, dict) and coverage.get("targets") == {name: row["forwarder"] for name, row in gate["exports"].items()
                                                                    if row["forwarder"] is not None},
            "forwarder receipt differs from actual exports")
    rows.extend(({"source_path": str(path.resolve()), "relative_path": "extension-result.json", "sha256": expected,
                  "bytes": len(receipt_data), "data": receipt_data},
                 {"source_path": str(original), "relative_path": "KERNELBASE.DLL", "sha256": theme.sha(data),
                  "bytes": len(data), "data": data}))
    digest_bound(path, expected)
    return receipt, data, rows


def candidate_gate(files, candidate, receipt=None):
    require(not any(name.casefold() == EXTENSION_PATH.casefold() for name, _ in files), "base already has KERNELBASE")
    modules = theme.archive_modules(files + [(EXTENSION_PATH, candidate)])
    gate = actual_pe_gate(candidate)
    pe = inventory.PEInventory(candidate)
    imports = []
    for row in pe.imports():
        for name in row["symbols"]:
            imports.append({"module": row["module"], "symbol": name,
                            "resolution": theme.resolve_export(modules, row["module"], name)})
    exports, _ = theme.pe_exports(candidate)
    forwarders = []
    for name, row in exports.items():
        if row["forwarder"]:
            forwarders.append({"name": name, "resolution": theme.resolve_export(modules, "KERNELBASE.DLL", name)})
    base_modules = theme.archive_modules(files)
    owner = base_modules.get("KERNEL32.DLL")
    require(owner is not None, "actual archive Kernel32 owner required")
    expected_forwarders = {name: "KERNEL32." + name for name, row in owner["names"].items()
                           if row["forwarder"] is None and name not in ADAPTERS}
    actual_forwarders = {name: row["forwarder"] for name, row in exports.items() if name not in ADAPTERS}
    require(set(exports) == ADAPTERS | set(expected_forwarders) and actual_forwarders == expected_forwarders,
            "extension exports must forward every selected direct Kernel32 name exactly")
    require(all(owner["names"].get(name, {}).get("forwarder", "missing") is None for name in IMPORTS),
            "memory backing APIs must be real direct Kernel32 exports")
    actual_modules = {name: {"member": row["archive_path"], "sha256": row["sha256"],
                             "bytes": len(next(data for path, data in files if path == row["archive_path"])), "exports": row["names"]}
                      for name, row in base_modules.items()}
    if receipt is not None:
        source_archive = receipt.get("runtime_archive", {})
        require(isinstance(source_archive, dict) and source_archive.get("member_count") == len(files)
                and source_archive.get("dll_count") == len(base_modules) and source_archive.get("modules") == actual_modules,
                "extension build archive modules differ from actual selected archive")
    return {"status": "STATIC_NAMES_RESOLVED", "imports": imports, "forwarders": forwarders,
            "actual_archive_module_count": len(modules), "candidate_pe_gate": gate, "abi_semantics_verified": False}


def input_plan(base_path, base_sha, extension_path, extension_sha):
    digest_bound(base_path, base_sha)
    base = theme.verified_overlay(base_path)
    candidate, data, rows = extension_inputs(extension_path, extension_sha)
    baseline = bounded_regular(Path(base["archive"]["path"]), 128 * 1024**2)
    files = theme.parse_archive(baseline)
    gate = candidate_gate(files, data, candidate)
    archived = candidate.get("runtime_archive", {})
    require(archived.get("sha256") == theme.sha(baseline), "extension must bind these exact selected theme archive bytes")
    build_archive = bound_row(Path(archived.get("path", "")), archived["sha256"], "extension-build-WIN64.IMG", 128 * 1024**2)
    require(build_archive["data"] == baseline, "extension compiler archive differs from selected theme archive")
    reviewed = candidate.get("reviewed_consumer_sources", {})
    require(isinstance(reviewed, dict) and reviewed.get("originals_unchanged") is True
            and reviewed.get("binary_source_identity_verified") is False, "review must separate source inspection from binary identity")
    peer = Path(base["runtime_worktree"]).resolve(strict=True)
    require(Path(reviewed.get("root", "")).resolve(strict=True) == peer, "reviewed consumer must bind selected runtime peer")
    hashes = reviewed.get("hashes")
    require(isinstance(hashes, dict) and 1 <= len(hashes) <= 32 and all(isinstance(name, str) for name in hashes),
            "bounded reviewed consumer source hashes required")
    for name, checksum in sorted(hashes.items()):
        source = peer / theme.safe_relative(name)
        require(source.resolve(strict=True).is_relative_to(peer), "reviewed consumer source escapes selected peer")
        rows.append(bound_row(source, checksum, "extension-reviewed-consumer/" + name))
    require(sum(row["bytes"] for row in rows) <= MAX_SOURCE_TOTAL + MAX_RECEIPT_BYTES + MAX_DLL_BYTES,
            "extension source and metadata total exceeds bound")
    rows.append(build_archive)
    rows += [{"source_path": str(base_path.resolve()), "relative_path": "theme-overlay.json", "sha256": base_sha,
              "bytes": base_path.stat().st_size, "data": inventory.read_regular(base_path)},
             {"source_path": base["archive"]["path"], "relative_path": "theme-WIN64.IMG", "sha256": theme.sha(baseline),
              "bytes": len(baseline), "data": baseline}]
    require(len({row["relative_path"].casefold() for row in rows}) == len(rows), "frozen extension input alias/collision")
    digest_bound(base_path, base_sha)
    return base, candidate, data, baseline, files, gate, rows


def prepare(base_path, base_sha, extension_path, extension_sha, out):
    out = theme.owned_new_directory(out)
    before = sources()
    base, candidate, data, baseline, files, gate, rows = input_plan(base_path, base_sha, extension_path, extension_sha)
    derived = theme.pack_archive(files + [(EXTENSION_PATH, data)])
    require(theme.parse_archive(derived)[:-1] == files, "original archive member bytes/order changed")
    handoff.check_space(out.parent, len(derived) + sum(row["bytes"] for row in rows) + handoff.METADATA_MARGIN)
    theme.preserve_inputs(rows)
    out.mkdir()
    for row in rows:
        target = out / theme.safe_relative(row["relative_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        handoff.check_space(out, 0)
        with target.open("xb") as stream:
            stream.write(row["data"])
        target.chmod(0o400)
    archive = out / "WIN64.IMG"
    with archive.open("xb") as stream:
        stream.write(derived)
    archive.chmod(0o400)
    theme.preserve_inputs(rows, out)
    require(sources() == before, "consumer source changed during preparation")
    digest_bound(base_path, base_sha)
    result = {"schema": 1, "status": "PREPARED", "stage": "private-modern-memory-runtime-overlay", "source_hashes": before,
              "runtime_worktree": base["runtime_worktree"], "runtime_source_hashes": base["runtime_source_hashes"],
              "theme_overlay": {"path": str(base_path.resolve()), "sha256": base_sha},
              "extension_receipt": {"path": str(extension_path.resolve()), "sha256": extension_sha},
              "extension_receipt_sha256": extension_sha, "supported_subset": candidate.get("supported_subset"),
              "baseline": {"sha256": theme.sha(baseline), "members": theme.member_manifest(files)},
              "archive": {"path": str(archive), "sha256": theme.sha(derived), "bytes": len(derived),
                          "members": theme.member_manifest(files + [(EXTENSION_PATH, data)])},
              "frozen_inputs": [{key: value for key, value in row.items() if key != "data"} for row in rows],
              "actual_archive_gate": gate, "original_member_bytes_and_order_preserved": True,
              "original_inputs_preserved": True, "frozen_inputs_preserved": True,
              "reviewed_consumer_binary_source_identity_verified": False,
              "peer_sources_modified": False, "installation": "not_performed", "vm_started": False, **FALSE_FLAGS}
    handoff.write_json(out / "extension-overlay.json", result)
    return result


def verified(path):
    receipt = handoff.read_json(path)
    require(receipt.get("schema") == 1 and receipt.get("stage") == "private-modern-memory-runtime-overlay"
            and receipt.get("status") == "PREPARED" and receipt.get("source_hashes") == sources(), "overlay is not current/source-bound")
    directory = path.parent.resolve(strict=True)
    require(directory.is_relative_to(theme.OWN_BUILD.resolve(strict=True)), "overlay is outside owned build")
    archive = receipt["archive"]
    require(Path(archive["path"]).resolve(strict=True) == directory / "WIN64.IMG", "archive path changed")
    raw = inventory.read_regular(directory / "WIN64.IMG")
    require(theme.sha(raw) == archive["sha256"] and len(raw) == archive["bytes"], "archive bytes changed")
    files = theme.parse_archive(raw)
    baseline = inventory.read_regular(directory / "theme-WIN64.IMG")
    require(theme.sha(baseline) == receipt["baseline"]["sha256"]
            and theme.member_manifest(theme.parse_archive(baseline)) == receipt["baseline"]["members"]
            and files[:-1] == theme.parse_archive(baseline), "base member bytes/order changed")
    require(theme.member_manifest(files) == archive["members"] and files[-1][0] == EXTENSION_PATH, "extension manifest changed")
    base, candidate_receipt, candidate, planned_base, planned_files, gate, rows = input_plan(
        Path(receipt["theme_overlay"]["path"]), receipt["theme_overlay"]["sha256"],
        Path(receipt["extension_receipt"]["path"]), receipt["extension_receipt"]["sha256"])
    expected_rows = [{key: value for key, value in row.items() if key != "data"} for row in rows]
    require(receipt["frozen_inputs"] == expected_rows and receipt["extension_receipt_sha256"] == receipt["extension_receipt"]["sha256"],
            "frozen extension input lineage changed")
    theme.preserve_inputs(receipt["frozen_inputs"], directory)
    require(baseline == planned_base and files[:-1] == planned_files and files[-1][1] == candidate
            and gate == receipt["actual_archive_gate"], "actual extension import/forwarder graph changed")
    require(receipt["runtime_worktree"] == base["runtime_worktree"] and receipt["runtime_source_hashes"] == base["runtime_source_hashes"]
            and receipt["supported_subset"] == candidate_receipt["supported_subset"], "extension runtime or supported subset binding changed")
    return receipt


def run(path, image, out, qemu, accel, timeout, memory, firmware):
    out = theme.owned_new_directory(out)
    before = handoff.digest_file(path)
    receipt = verified(path)
    original = handoff.load_peer
    restored = []

    def loader(peer):
        productivity, hashes = original(peer)
        require(str(Path(peer).resolve()) == receipt["runtime_worktree"] and hashes == receipt["runtime_source_hashes"], "peer source binding changed")
        runner = productivity.runner
        require(not restored or restored[0][0] is runner, "unexpected runtime module")
        if not restored:
            restored.append((runner, runner.WIN64))
        runner.WIN64 = path.parent.resolve()
        return productivity, hashes

    image_data = handoff.read_json(image)
    image_hash = handoff.digest_file(image)
    require(image_data.get("app") == "signal" and image_data.get("runtime_worktree") == receipt["runtime_worktree"]
            and image_data.get("runtime_source_hashes") == receipt["runtime_source_hashes"], "Signal image must bind same runtime helper")
    handoff.load_peer = loader
    code = 1
    handoff_error = None
    try:
        code = handoff.run_image(image, out, qemu, accel, timeout, memory, firmware)
    except Exception as failure:
        handoff_error = str(failure)
        code = 2
    finally:
        handoff.load_peer = original
        for runner, win64 in restored:
            runner.WIN64 = win64
        if out.exists() and not out.is_symlink():
            preserved, error = False, None
            try:
                digest_bound(path, before)
                digest_bound(image, image_hash)
                verified(path)
                preserved = True
            except Exception as failure:
                error = str(failure)
            seal_path = out / "runtime-seal.json"
            matched = False
            try:
                seal = handoff.read_json(seal_path) if seal_path.exists() else {}
                row = seal.get("sealed_runtime_input_hashes", {}).get("win64_initrd", {})
                owned_archive = out / "runtime-inputs/WIN64.IMG"
                matched = (Path(row.get("path", "")).is_absolute() and Path(row["path"]) == owned_archive
                           and row.get("source_path") == receipt["archive"]["path"]
                           and row.get("sha256") == receipt["archive"]["sha256"]
                           and row.get("bytes") == receipt["archive"]["bytes"]
                           and owned_archive.stat().st_size == receipt["archive"]["bytes"]
                           and handoff.digest_file(owned_archive) == receipt["archive"]["sha256"])
            except (OSError, KeyError, ValueError, TypeError, AttributeError) as failure:
                error = error or str(failure)
            handoff.write_json(out / "extension-runtime-result.json", {"schema": 1, "status": "FAIL", "stage": "required-signal-memory-startup-diagnostic",
                "overlay_receipt": {"path": str(path.resolve()), "sha256": before},
                "required_app_image_receipt": {"path": str(image.resolve()), "sha256": image_hash},
                "overlay_sha256": before, "sealed_extension_runtime_input_verified": matched, "overlay_inputs_preserved": preserved,
                "supported_subset": receipt["supported_subset"], "handoff_error": handoff_error,
                "preservation_error": error, "handoff_return_code": code, "peer_sources_modified": False,
                "installation": "not_performed", **FALSE_FLAGS})
            if not matched or not preserved:
                code = 2
    if handoff_error and not out.exists():
        raise ValueError("handoff preflight failed: " + handoff_error)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    stages = parser.add_subparsers(dest="stage", required=True)
    p = stages.add_parser("prepare")
    for name in ("theme-overlay", "extension-receipt", "out"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("theme-overlay-sha256", "extension-receipt-sha256"):
        p.add_argument("--" + name, required=True)
    p = stages.add_parser("run")
    for name in ("overlay", "image-receipt", "out", "qemu"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    p.add_argument("--timeout", type=int, default=90)
    p.add_argument("--memory", type=int, default=4096)
    p.add_argument("--firmware-dir", type=Path, action="append", required=True)
    args = parser.parse_args()
    try:
        if args.stage == "prepare":
            r = prepare(args.theme_overlay, args.theme_overlay_sha256, args.extension_receipt, args.extension_receipt_sha256, args.out)
            print(json.dumps({"status": r["status"], "archive_sha256": r["archive"]["sha256"]}))
            return 0
        return run(args.overlay, args.image_receipt, args.out, args.qemu, args.accel, args.timeout, args.memory, args.firmware_dir)
    except (ValueError, OSError, KeyError, TypeError, AttributeError, UnicodeError, pefile.PEFormatError) as error:
        print("FAIL:", error, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
