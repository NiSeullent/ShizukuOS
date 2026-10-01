#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privately append the source-bound Modern UXTHEME candidate to Kernel64.

prepare validates the real SHZARC01 members and import/export graph, freezes
inputs and writes a new archive. run delegates to the unchanged required-app
handoff, which seals this derived archive before starting its diagnostic guest.
Neither stage modifies peer source, installs a system theme or proves an app
works. The standalone AMD64 runtime is distinct from native Windows 98.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
OWN_BUILD = ROOT / "build"
spec = importlib.util.spec_from_file_location("theme_required_handoff", ROOT / "tools/required_app_runtime_handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)
inventory = handoff.corpus.inventory
THEME_PATH = "\\SHZ\\SYS64\\UXTHEME.DLL"
MAX_MEMBERS = 4096
PACKER_PATH = "shizukudos/win64/build.py"
PROVIDER_BUILDER = "ntwddm/win64/theme_provider/build.py"
FALSE_FLAGS = {"app_functionality_verified": False, "windows98_execution_verified": False,
               "os_wide_theme_verified": False, "theme_painting_verified": False}


class ThemeRuntimeError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ThemeRuntimeError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_relative(name: str) -> Path:
    require(isinstance(name, str) and name and "\\" not in name and ":" not in name,
            "invalid source-relative path")
    path = Path(name)
    require(not path.is_absolute() and all(part not in ("", ".", "..") for part in name.split("/")),
            "invalid source-relative path")
    return path


def source_hashes() -> dict:
    paths = (Path(__file__).resolve(), ROOT / "tools/required_app_runtime_handoff.py",
             ROOT / "tools/signal_desktop_corpus.py", ROOT / "tools/modern_app_inventory.py")
    return {str(path.relative_to(ROOT)): handoff.digest_file(path) for path in paths}


def owned_new_directory(path: Path) -> Path:
    require(not path.exists() and not path.is_symlink(), "choose a new owned output directory")
    parent = path.parent.resolve(strict=True)
    require(parent.is_relative_to(OWN_BUILD.resolve(strict=True)), "output must be beneath this worktree's build directory")
    return parent / path.name


def archive_name(raw: bytes) -> str:
    require(len(raw) == 120 and b"\0" in raw, "archive name must be NUL-terminated")
    value, padding = raw.split(b"\0", 1)
    require(not any(padding), "nonzero archive name padding")
    try:
        name = value.decode("ascii")
    except UnicodeDecodeError as error:
        raise ThemeRuntimeError("archive name must be ASCII") from error
    require(name.startswith("\\") and not name.startswith("\\\\"), "archive path must have one root separator")
    parts = name[1:].split("\\")
    require(parts and all(part not in ("", ".", "..") and part[-1:] not in (".", " ")
                          and not any(ord(char) < 32 or char in '/:*?<>|"' for char in part) for part in parts),
            "unsafe archive path")
    return name


def parse_archive(raw: bytes) -> list[tuple[str, bytes]]:
    require(len(raw) >= 16 and raw[:8] == b"SHZARC01", "invalid SHZARC01 header")
    count, reserved = struct.unpack_from("<II", raw, 8)
    require(1 <= count <= MAX_MEMBERS and reserved == 0, "invalid archive member count/reserved word")
    header = 16 + count * 136
    require(header <= len(raw), "truncated archive directory")
    records, paths = [], {}
    for index in range(count):
        raw_name, offset, size = struct.unpack_from("<120sQQ", raw, 16 + index * 136)
        name = archive_name(raw_name)
        parts = name[1:].split("\\")
        for depth in range(1, len(parts) + 1):
            component = "\\" + "\\".join(parts[:depth])
            kind = "file" if depth == len(parts) else "directory"
            prior = paths.get(component.casefold())
            require(prior is None or (prior == (component, kind) and kind == "directory"),
                    "archive case alias, duplicate or file/directory collision")
            paths[component.casefold()] = (component, kind)
        require(offset >= header and offset % 16 == 0 and size <= len(raw) - offset,
                "archive extent is unaligned or out of bounds")
        records.append((name, offset, size))
    end = header
    for _, offset, size in sorted(records, key=lambda row: (row[1], row[2])):
        require(offset >= end, "overlapping archive payloads")
        require(not any(raw[end:offset]), "nonzero archive alignment padding")
        end = offset + size
    require(end == len(raw), "unaccounted archive trailing bytes")
    return [(name, raw[offset:offset + size]) for name, offset, size in records]


def pack_archive(files: list[tuple[str, bytes]]) -> bytes:
    """Exact peer pack_archive format; peer Python is read, never executed here."""
    header_size = 16 + 136 * len(files)
    blob, rows = bytearray(), bytearray()
    for name, data in files:
        encoded = name.encode("ascii")
        require(len(encoded) < 120, "archive name exceeds format limit")
        blob.extend(b"\0" * (-(header_size + len(blob)) % 16))
        rows.extend(encoded.ljust(120, b"\0") + struct.pack("<QQ", header_size + len(blob), len(data)))
        blob.extend(data)
    packed = b"SHZARC01" + struct.pack("<II", len(files), 0) + rows + blob
    require(parse_archive(packed) == files, "packed archive failed independent extent validation")
    return bytes(packed)


def member_manifest(files: list[tuple[str, bytes]]) -> list[dict]:
    return [{"name": name, "bytes": len(data), "sha256": sha(data)} for name, data in files]


def module_name(name: str) -> str:
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_\-]+(?:\.(?:[dD][lL][lL]|[eE][xX][eE]))?", name),
            "invalid import/forwarder module name")
    name = name.upper()
    return name if name.endswith((".DLL", ".EXE")) else name + ".DLL"


def pe_exports(data: bytes) -> tuple[dict, dict]:
    pe = inventory.PEInventory(data)
    require(pe.arch == "x64" and pe.magic == 0x20B, "runtime module must be AMD64 PE32+")
    header = pe.u32(0x3C)
    require(bool(pe.u16(header + 22) & 0x2000), "runtime module must be a DLL")
    rva, size = pe.directory(0)
    require(rva and size >= 40, "runtime module has no valid export directory")
    offset = pe.offset(rva, size)
    fields = pe.unpack("<IIHHIIIIIII", offset)
    _, _, _, _, _, base, functions, names, eat, name_table, ordinals = fields
    require(1 <= functions <= 65536 and names <= 65536 and base + functions <= 0x10000,
            "invalid export counts/ordinal range")
    eat_offset = pe.offset(eat, functions * 4)
    by_ordinal = {}
    for index in range(functions):
        target = pe.u32(eat_offset + index * 4)
        if not target:
            continue
        forwarder = None
        if rva <= target < rva + size:
            forwarder = pe.string(target)
            require(forwarder and target + len(forwarder) + 1 <= rva + size,
                    "forwarder exceeds export directory")
        else:
            pe.loaded_extent(target, 1)
        by_ordinal[base + index] = {"ordinal": base + index, "rva": target, "forwarder": forwarder}
    by_name = {}
    if names:
        names_offset, ordinal_offset = pe.offset(name_table, names * 4), pe.offset(ordinals, names * 2)
        for index in range(names):
            name = pe.string(pe.u32(names_offset + index * 4))
            ordinal_index = pe.u16(ordinal_offset + index * 2)
            require(name and name not in by_name and ordinal_index < functions and base + ordinal_index in by_ordinal,
                    "duplicate, empty or null named export")
            by_name[name] = by_ordinal[base + ordinal_index]
    return by_name, by_ordinal


def archive_modules(files: list[tuple[str, bytes]]) -> dict:
    result = {}
    for name, data in files:
        if name.upper().startswith("\\SHZ\\SYS64\\") and name.upper().endswith(".DLL"):
            require(name.count("\\") == 3, "nested SYS64 module is unsupported")
            key = module_name(name.rsplit("\\", 1)[1])
            require(key not in result, "ambiguous archive module basename")
            names, ordinals = pe_exports(data)
            result[key] = {"archive_path": name, "sha256": sha(data), "names": names, "ordinals": ordinals}
    require(result, "archive contains no actual SYS64 DLLs")
    return result


def resolve_export(modules: dict, dll: str, symbol: str, seen=()) -> list[dict]:
    dll = module_name(dll)
    require(isinstance(symbol, str) and symbol, "invalid imported symbol")
    key = (dll, symbol)
    require(key not in seen and len(seen) < 32, "cyclic or oversized export forwarder chain")
    module = modules.get(dll)
    require(module is not None, f"missing archive module {dll}")
    if symbol.startswith("#"):
        require(re.fullmatch(r"#[0-9]+", symbol) is not None and 0 <= int(symbol[1:]) <= 65535,
                "invalid imported ordinal")
        export = module["ordinals"].get(int(symbol[1:]))
    else:
        export = module["names"].get(symbol)
    require(export is not None, f"missing archive export {dll}!{symbol}")
    row = {"module": dll, "symbol": symbol, "ordinal": export["ordinal"],
           "archive_path": module["archive_path"], "module_sha256": module["sha256"],
           "forwarder": export["forwarder"]}
    if export["forwarder"]:
        require("." in export["forwarder"], "invalid export forwarder")
        target_dll, target_symbol = export["forwarder"].rsplit(".", 1)
        return [row] + resolve_export(modules, target_dll, target_symbol, seen + (key,))
    return [row]


def import_gate(provider: bytes, files: list[tuple[str, bytes]]) -> dict:
    pe = inventory.PEInventory(provider)
    names, ordinals = pe_exports(provider)
    modules = archive_modules(files)
    resolved = []
    for delayed in (False, True):
        for descriptor in pe.imports(delayed):
            for symbol in descriptor["symbols"]:
                resolved.append({"module": module_name(descriptor["module"]), "symbol": symbol,
                                 "delayed": delayed, "resolution": resolve_export(modules, descriptor["module"], symbol)})
    require(resolved, "provider has no imports to validate")
    return {"status": "STATIC_NAMES_RESOLVED", "resolved_imports": resolved,
            "module_count": len(modules), "provider_exports": {name: row["ordinal"] for name, row in names.items()},
            "provider_ordinals": sorted(ordinals), "abi_semantics_verified": False,
            "runtime_execution_verified": False}


def provider_inputs(receipt_path: Path, expected_sha: str) -> tuple[dict, bytes, list[dict]]:
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha or "") is not None, "explicit provider receipt SHA256 required")
    require(handoff.digest_file(receipt_path) == expected_sha, "provider receipt digest changed")
    receipt = handoff.read_json(receipt_path)
    require(receipt.get("schema") == 1 and receipt.get("status") == "STATIC_CANDIDATE_READY_FOR_GUEST_TEST"
            and receipt.get("structural_build_status") == "PASS", "provider is not a guest-test candidate")
    require(receipt.get("default_style") == {"selection": "modern", "value": 2, "application_local_only": True,
                                           "lazy_initialization": True, "dllmain_initialization": False,
                                           "public_api_called_during_initialization": False}, "explicit Modern app-local provider required")
    source_root = Path(receipt.get("source_root", ""))
    require(source_root.is_absolute(), "provider source root must be absolute")
    sources = receipt.get("source_hashes")
    require(isinstance(sources, dict) and PROVIDER_BUILDER in sources and "LICENSE" in sources,
            "provider recipe and license must be source-bound")
    frozen = []
    for name, checksum in sorted(sources.items()):
        path = source_root / safe_relative(name)
        require(isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum), "invalid provider source hash")
        data = inventory.read_regular(path)
        require(sha(data) == checksum, f"provider source changed: {name}")
        frozen.append({"source_path": str(path), "relative_path": "provider-sources/" + name,
                       "bytes": len(data), "sha256": checksum, "data": data})
    adapter = receipt.get("adapter_port", {})
    require(adapter.get("lazy_creation_replacements") == 1
            and adapter.get("creation_replacement") == "status = m98w_create_default(&desc, 2u, &engine);",
            "provider generated adapter does not bind the Modern initializer")
    generated = ((adapter.get("generated_path"), adapter.get("generated_sha256"), "provider-generated-adapter.c"),
                 (receipt.get("private_unicode_transport", {}).get("generated_font_path"),
                  receipt.get("private_unicode_transport", {}).get("generated_font_sha256"), "provider-generated-font.c"))
    for path_text, checksum, relative in generated:
        require(isinstance(path_text, str) and Path(path_text).is_absolute()
                and isinstance(checksum, str) and re.fullmatch(r"[0-9a-f]{64}", checksum),
                "provider generated compiler input lacks a bound path/digest")
        path = Path(path_text)
        data = inventory.read_regular(path)
        require(sha(data) == checksum, "provider generated compiler input changed")
        if relative == "provider-generated-adapter.c":
            require(data.count(adapter["creation_replacement"].encode("ascii")) == 1,
                    "generated provider adapter lacks its unique Modern creation anchor")
        frozen.append({"source_path": str(path), "relative_path": relative, "bytes": len(data), "sha256": checksum, "data": data})
    artifact = receipt.get("artifact", {})
    path = Path(artifact.get("path", ""))
    require(path.is_absolute(), "provider DLL path must be absolute")
    data = inventory.read_regular(path)
    require(len(data) == artifact.get("bytes") and sha(data) == artifact.get("sha256"), "provider DLL changed")
    gate = artifact.get("pe_gate", {})
    names, _ = pe_exports(data)
    pe = inventory.PEInventory(data)
    imports = {row["module"]: sorted(row["symbols"]) for row in pe.imports()}
    require(gate.get("status") == "PASS" and gate.get("machine") == "AMD64" and gate.get("format") == "PE32+"
            and gate.get("exports") == {name: row["ordinal"] for name, row in names.items()}
            and gate.get("imports") == imports and not pe.imports(True), "provider receipt PE gate differs from actual DLL")
    require(all(not row["forwarder"] for row in names.values()) and names.get("DrawThemeBackgroundEx", {}).get("ordinal") == 47,
            "provider ordinal 47 must name its actual DrawThemeBackgroundEx implementation")
    require(handoff.digest_file(receipt_path) == expected_sha, "provider receipt changed during validation")
    frozen.extend(({"source_path": str(receipt_path), "relative_path": "provider-result.json", "bytes": receipt_path.stat().st_size,
                    "sha256": expected_sha, "data": inventory.read_regular(receipt_path)},
                   {"source_path": str(path), "relative_path": "UXTHEME.DLL", "bytes": len(data), "sha256": sha(data), "data": data}))
    return receipt, data, frozen


def preserve_inputs(rows: list[dict], directory: Path | None = None) -> bool:
    for row in rows:
        require(handoff.digest_file(Path(row["source_path"])) == row["sha256"], "original overlay input changed")
        if directory is not None:
            path = directory / safe_relative(row["relative_path"])
            require(path.stat().st_size == row["bytes"] and handoff.digest_file(path) == row["sha256"], "frozen overlay input changed")
    return True


def prepare_overlay(base: Path, runtime_peer: Path, provider_receipt: Path, provider_sha: str, out: Path) -> dict:
    out = owned_new_directory(out)
    before_sources = source_hashes()
    runtime_peer = runtime_peer.resolve(strict=True)
    baseline = inventory.read_regular(base)
    files = parse_archive(baseline)
    require(not any(name.casefold() == THEME_PATH.casefold() for name, _ in files), "baseline already has UXTHEME; append-only consumer required")
    provider, candidate, inputs = provider_inputs(provider_receipt, provider_sha)
    gate = import_gate(candidate, files)
    packer = runtime_peer / PACKER_PATH
    packer_data = inventory.read_regular(packer)
    require(b"def pack_archive(files):" in packer_data and b'SHZARC01' in packer_data,
            "selected peer has no SHZARC01 packer recipe")
    productivity, peer_hashes = handoff.load_peer(runtime_peer)
    require(base.resolve(strict=True) == (productivity.runner.WIN64 / "WIN64.IMG").resolve(strict=True),
            "baseline must be selected peer runner's actual WIN64.IMG")
    derived_files = files + [(THEME_PATH, candidate)]
    derived = pack_archive(derived_files)
    require(parse_archive(derived)[:-1] == files, "baseline member bytes/order changed")
    inputs += [{"source_path": str(base.resolve()), "relative_path": "baseline-WIN64.IMG", "bytes": len(baseline),
                "sha256": sha(baseline), "data": baseline},
               {"source_path": str(packer.resolve()), "relative_path": "baseline-packer.py", "bytes": len(packer_data),
                "sha256": sha(packer_data), "data": packer_data}]
    # Include metadata and both immutable archives above the fixed 20 GiB reserve.
    required = len(derived) + sum(row["bytes"] for row in inputs) + handoff.METADATA_MARGIN
    handoff.check_space(out.parent, required)
    preserve_inputs(inputs)
    out.mkdir()
    for row in inputs:
        target = out / safe_relative(row["relative_path"])
        target.parent.mkdir(parents=True, exist_ok=True)
        handoff.check_space(out, 0)
        with target.open("xb") as stream:
            stream.write(row["data"])
        target.chmod(0o400)
    image = out / "WIN64.IMG"
    with image.open("xb") as stream:
        stream.write(derived)
    image.chmod(0o400)
    preserve_inputs(inputs, out)
    require(source_hashes() == before_sources, "consumer source changed during preparation")
    require({name: handoff.digest_file(runtime_peer / name) for name in handoff.PEER_FILES} == peer_hashes,
            "peer helper source changed during preparation")
    result = {"schema": 1, "stage": "private-kernel64-theme-overlay", "status": "PREPARED",
              "runtime_worktree": str(runtime_peer), "runtime_source_hashes": peer_hashes,
              "source_hashes": before_sources, "provider_receipt_sha256": provider_sha,
              "provider_default_style": provider["default_style"], "lineage": provider.get("lineage"),
              "baseline": {"source_path": str(base.resolve()), "sha256": sha(baseline), "bytes": len(baseline),
                           "members": member_manifest(files)},
              "archive": {"path": str(image), "sha256": sha(derived), "bytes": len(derived),
                          "members": member_manifest(derived_files)},
              "frozen_inputs": [{key: value for key, value in row.items() if key != "data"} for row in inputs],
              "actual_archive_import_gate": gate, "original_member_bytes_and_order_preserved": True,
              "original_inputs_preserved": True, "frozen_inputs_preserved": True,
              "peer_sources_modified": False, "installation": "not_performed", "vm_started": False, **FALSE_FLAGS}
    handoff.write_json(out / "theme-overlay.json", result)
    return result


def verified_overlay(receipt_path: Path) -> dict:
    receipt = handoff.read_json(receipt_path)
    require(receipt.get("schema") == 1 and receipt.get("stage") == "private-kernel64-theme-overlay"
            and receipt.get("status") == "PREPARED" and receipt.get("source_hashes") == source_hashes(),
            "overlay is not current and source-bound")
    directory = receipt_path.parent.resolve(strict=True)
    require(directory.is_relative_to(OWN_BUILD.resolve(strict=True)), "overlay must be in owned build directory")
    archive = receipt["archive"]
    require(Path(archive["path"]).resolve(strict=True) == directory / "WIN64.IMG", "overlay archive path changed")
    raw = inventory.read_regular(Path(archive["path"]))
    require(sha(raw) == archive["sha256"] and len(raw) == archive["bytes"], "derived archive changed")
    files = parse_archive(raw)
    require(member_manifest(files) == archive["members"] and files[-1][0] == THEME_PATH,
            "derived member manifest changed")
    baseline = inventory.read_regular(directory / "baseline-WIN64.IMG")
    baseline_files = parse_archive(baseline)
    require(sha(baseline) == receipt["baseline"]["sha256"] and member_manifest(baseline_files) == receipt["baseline"]["members"]
            and files[:-1] == baseline_files, "baseline member preservation failed")
    preserve_inputs(receipt["frozen_inputs"], directory)
    provider_inputs(directory / "provider-result.json", receipt["provider_receipt_sha256"])
    require(files[-1][1] == inventory.read_regular(directory / "UXTHEME.DLL"), "archived provider differs from frozen DLL")
    require(import_gate(files[-1][1], baseline_files) == receipt["actual_archive_import_gate"], "archive import coverage changed")
    return receipt


def run_overlay(overlay_path: Path, image_receipt: Path, out: Path, qemu: Path, accel: str,
                timeout: int, memory: int, firmware_directories: list[Path]) -> int:
    overlay_hash = handoff.digest_file(overlay_path)
    overlay = verified_overlay(overlay_path)
    out = owned_new_directory(out)
    image = handoff.read_json(image_receipt)
    require(image.get("app") in ("signal", "onlyoffice_x64") and image.get("runtime_worktree") == overlay["runtime_worktree"]
            and image.get("runtime_source_hashes") == overlay["runtime_source_hashes"],
            "required app image must use the same peer helper sources as the overlay")
    original_loader = handoff.load_peer
    changed_runners = []

    def overlay_loader(peer):
        productivity, hashes = original_loader(peer)
        require(str(Path(peer).resolve(strict=True)) == overlay["runtime_worktree"] and hashes == overlay["runtime_source_hashes"],
                "runtime peer source binding changed")
        runner = productivity.runner
        if not changed_runners:
            changed_runners.append((runner, runner.WIN64))
        require(changed_runners[0][0] is runner, "unexpected second runtime module")
        runner.WIN64 = overlay_path.parent.resolve(strict=True)
        return productivity, hashes

    handoff.load_peer = overlay_loader
    code, error = 1, None
    try:
        # Source/recipe/control/tree/image validation and sealed-copy guards are
        # entirely the original handoff implementation; its hashes stay honest.
        code = handoff.run_image(image_receipt, out, qemu, accel, timeout, memory, firmware_directories)
    except Exception as failure:
        error = str(failure)
        raise
    finally:
        handoff.load_peer = original_loader
        for runner, original_win64 in changed_runners:
            runner.WIN64 = original_win64
        if out.exists():
            preserved, preservation_error = False, None
            try:
                require(handoff.digest_file(overlay_path) == overlay_hash, "overlay receipt changed during run")
                verified_overlay(overlay_path)
                preserved = True
            except Exception as failure:
                preservation_error = str(failure)
            seal_path = out / "runtime-seal.json"
            sealed = handoff.read_json(seal_path) if seal_path.exists() else {}
            sealed_input = sealed.get("sealed_runtime_input_hashes", {}).get("win64_initrd", {})
            sealed_match = sealed_input.get("sha256") == overlay["archive"]["sha256"]
            if sealed_match:
                sealed_match = handoff.digest_file(Path(sealed_input["path"])) == overlay["archive"]["sha256"]
            record = {"schema": 1, "stage": "standalone-kernel64-required-app-theme-diagnostic", "status": "FAIL",
                      "theme_overlay_receipt": {"path": str(overlay_path.resolve()), "sha256": overlay_hash},
                      "required_app_image_receipt": {"path": str(image_receipt.resolve()), "sha256": handoff.digest_file(image_receipt)},
                      "derived_archive_sha256": overlay["archive"]["sha256"],
                      "provider_default_style": overlay["provider_default_style"],
                      "sealed_theme_runtime_input_verified": sealed_match, "overlay_inputs_preserved": preserved,
                      "preservation_error": preservation_error, "handoff_error": error,
                      "handoff_return_code": code, "original_handoff_source_checks_retained": True,
                      "peer_sources_modified": False, "installation": "not_performed", **FALSE_FLAGS}
            handoff.write_json(out / "theme-runtime-result.json", record)
    return code


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="stage", required=True)
    prepare = commands.add_parser("prepare")
    for name in ("base", "runtime-worktree", "provider-receipt", "out"):
        prepare.add_argument("--" + name, type=Path, required=True)
    prepare.add_argument("--provider-receipt-sha256", required=True)
    run = commands.add_parser("run")
    for name in ("overlay", "image-receipt", "out", "qemu"):
        run.add_argument("--" + name, type=Path, required=True)
    run.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    run.add_argument("--timeout", type=int, default=90)
    run.add_argument("--memory", type=int, default=2048)
    run.add_argument("--firmware-dir", type=Path, action="append", required=True)
    args = parser.parse_args(argv)
    try:
        if args.stage == "prepare":
            result = prepare_overlay(args.base, args.runtime_worktree, args.provider_receipt,
                                     args.provider_receipt_sha256, args.out)
            print(json.dumps({"status": result["status"], "receipt": str(args.out / "theme-overlay.json"),
                              "archive_sha256": result["archive"]["sha256"],
                              "resolved_imports": len(result["actual_archive_import_gate"]["resolved_imports"])}))
            return 0
        return run_overlay(args.overlay, args.image_receipt, args.out, args.qemu, args.accel,
                           args.timeout, args.memory, args.firmware_dir)
    except (ValueError, OSError, KeyError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
