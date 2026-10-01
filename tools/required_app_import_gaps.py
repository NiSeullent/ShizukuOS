"""Compare a static publisher inventory with actual runtime DLL export tables.

No application, installer, or DLL is executed. Export presence establishes a
binary symbol candidate only; it does not establish behavior or loader choice.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("modern_app_inventory", ROOT / "tools/modern_app_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
MAX_EXPORTS = 65536
MAX_DLLS = 512
MAX_NATIVE = 4096
MAX_IMPORTS = 200000
MAX_JSON = 32 * 1024**2
RUNTIME_SUFFIXES = {".dll", ".drv", ".cpl"}
HASH = re.compile(r"[0-9a-f]{64}\Z")
MODULE = re.compile(r"[A-Za-z0-9_.+@-]+\Z")


class GapError(ValueError):
    pass


def module_key(value: str) -> str:
    if not isinstance(value, str) or not value or not MODULE.fullmatch(value):
        raise GapError("unsafe or invalid imported module name")
    return value.casefold()


def forwarder_target(value: str) -> tuple[str, str]:
    """Split at the final dot, including explicit module.dll.#ordinal syntax."""
    if "." not in value:
        raise GapError("export forwarder has no module/symbol separator")
    module, symbol = value.rsplit(".", 1)
    module_key(module)
    if not symbol or (symbol.startswith("#") and (not re.fullmatch(r"#[0-9]{1,10}", symbol) or int(symbol[1:]) > 0xFFFFFFFF)):
        raise GapError("invalid export forwarder symbol")
    if any(ord(char) < 33 or ord(char) > 126 for char in symbol):
        raise GapError("invalid export forwarder symbol")
    if symbol.startswith("#"):
        symbol = "#" + str(int(symbol[1:]))
    return module if "." in module else module + ".dll", symbol


def exports(data: bytes) -> dict:
    """Bounded PE export parser; ordinal holes are not available symbols."""
    pe = inventory.PEInventory(data)
    rva, size = pe.directory(0)
    result = {"architecture": pe.arch, "format": "PE32" if pe.width == 4 else "PE32+",
              "names": {}, "ordinals": {}, "module_name": None}
    if not rva and not size:
        return result
    if not rva or size < 40 or rva + size > 0x100000000:
        raise inventory.PEError("invalid export directory extent")
    at = pe.offset(rva, size)
    fields = pe.unpack("<IIHHIIIIIII", at)
    _, _, _, _, name_rva, base, functions, names, eat, ent, eot = fields
    if functions > MAX_EXPORTS or names > MAX_EXPORTS or base + functions > 0x100000000:
        raise inventory.PEError("export table count/ordinal exceeds bound")
    result["module_name"] = pe.string(name_rva) if name_rva else None
    if functions:
        pe.offset(eat, functions * 4)
    if names:
        pe.offset(ent, names * 4)
        pe.offset(eot, names * 2)
    slots = []
    for index in range(functions):
        address = pe.u32(pe.offset(eat + index * 4, 4))
        if not address:
            slots.append(None)
            continue
        item = {"ordinal": base + index, "rva": address, "forwarder": None}
        if rva <= address < rva + size:
            value = pe.string(address)
            if address + len(value) + 1 > rva + size:
                raise inventory.PEError("forwarder string exceeds export directory")
            forwarder_target(value)
            item["forwarder"] = value
        else:
            pe.loaded_extent(address, 1)
        slots.append(item)
        result["ordinals"]["#" + str(base + index)] = item
    for index in range(names):
        name = pe.string(pe.u32(pe.offset(ent + index * 4, 4)))
        slot = pe.u16(pe.offset(eot + index * 2, 2))
        if not name or name in result["names"] or slot >= functions or slots[slot] is None:
            raise inventory.PEError("duplicate/empty export name or invalid export slot")
        result["names"][name] = slots[slot]
    return result


def snapshot(path: Path, maximum: int | None = None) -> tuple[bytes, tuple]:
    stream, before = inventory.open_regular(path)
    with stream:
        if maximum is not None and before.st_size > maximum:
            raise GapError("input exceeds diagnostic bound")
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or inventory.file_identity(os.fstat(stream.fileno())) != inventory.file_identity(before):
            raise GapError("input changed while being read")
    return data, inventory.file_identity(before)


def unchanged(path: Path, identity: tuple, digest: str) -> None:
    data, after = snapshot(path)
    if after != identity or hashlib.sha256(data).hexdigest() != digest:
        raise GapError("input changed during diagnostic: " + str(path))


def validate_inventory(receipt: dict) -> list[dict]:
    if not isinstance(receipt, dict) or receipt.get("schema") != 1 or receipt.get("status") != "PASS":
        raise GapError("expected successful schema 1 static publisher inventory")
    if receipt.get("installer_or_application_executed") is not False or receipt.get("app_functionality_verified") is not False:
        raise GapError("inventory is not an explicitly static receipt")
    artifact = receipt.get("artifact", {})
    if not isinstance(artifact, dict) or artifact.get("publisher_digest_verified") is not True or not HASH.fullmatch(str(artifact.get("sha256", ""))):
        raise GapError("inventory has no publisher integrity identity")
    native = receipt.get("native_files")
    if not isinstance(native, list) or not 1 <= len(native) <= MAX_NATIVE:
        raise GapError("native inventory count outside bound")
    paths, total = set(), 0
    for item in native:
        if not isinstance(item, dict):
            raise GapError("native inventory entry is not an object")
        path = item.get("path")
        if not isinstance(path, str) or "\\" in path or path.startswith("/") or any(part in ("", ".", "..") for part in path.split("/")):
            raise GapError("invalid inventoried native path")
        if path.casefold() in paths or not HASH.fullmatch(str(item.get("sha256", ""))):
            raise GapError("duplicate native path or missing native byte identity")
        paths.add(path.casefold())
        if item.get("format") not in ("PE32", "PE32+"):
            continue
        if (item.get("architecture"), item.get("format")) not in (("x64", "PE32+"), ("ia32", "PE32"), ("arm64", "PE32+")):
            raise GapError("inconsistent inventory architecture/format")
        for kind in ("direct_imports", "delay_imports"):
            rows = item.get(kind)
            if not isinstance(rows, list):
                raise GapError("missing import inventory")
            for row in rows:
                if not isinstance(row, dict):
                    raise GapError("invalid import descriptor")
                module_key(row.get("module"))
                symbols = row.get("symbols")
                if not isinstance(symbols, list):
                    raise GapError("invalid import symbol list")
                total += len(symbols)
                if total > MAX_IMPORTS:
                    raise GapError("import count exceeds diagnostic bound")
                for symbol in symbols:
                    if not isinstance(symbol, str) or not symbol or any(ord(c) < 33 or ord(c) > 126 for c in symbol):
                        raise GapError("invalid import symbol")
                    if symbol.startswith("#") and (not re.fullmatch(r"#(?:0|[1-9][0-9]{0,4})", symbol) or int(symbol[1:]) > 65535):
                        raise GapError("invalid ordinal import")
    return native


def load_runtime(directory: Path) -> tuple[dict, list[dict], list[tuple]]:
    if directory.is_symlink() or not directory.is_dir():
        raise GapError("runtime DLL directory must be a real directory")
    paths = sorted((p for p in directory.iterdir() if p.suffix.casefold() in RUNTIME_SUFFIXES), key=lambda p: p.name.casefold())
    if not 1 <= len(paths) <= MAX_DLLS:
        raise GapError("runtime DLL count outside bound")
    providers, rows, frozen = {}, [], []
    for path in paths:
        key = module_key(path.name)
        if key in providers:
            raise GapError("case-aliased runtime DLLs")
        data, identity = snapshot(path, 64 * 1024**2)
        digest = hashlib.sha256(data).hexdigest()
        row = {"path": str(path.absolute()), "module": path.name.upper(), "sha256": digest, "bytes": len(data)}
        try:
            provider = exports(data)
            row.update({"architecture": provider["architecture"], "format": provider["format"],
                        "named_exports": len(provider["names"]), "ordinal_exports": len(provider["ordinals"]),
                        "forwarded_exports": sum(item["forwarder"] is not None for item in provider["ordinals"].values()),
                        "export_table_inspected": True})
        except (inventory.PEError, GapError) as error:
            provider = {"error": str(error)}
            row.update({"export_table_inspected": False, "error": str(error)})
        provider["receipt"] = row
        providers[key] = provider
        rows.append(row)
        frozen.append((path, identity, digest))
    return providers, rows, frozen


def resolve(module: str, symbol: str, architecture: str, fmt: str, providers: dict,
            packaged: dict, chain: tuple = ()) -> dict:
    key = module_key(module)
    tag = (key, symbol)
    if tag in chain or len(chain) >= 32:
        return {"status": "forwarder_cycle_or_depth", "chain": [list(t) for t in (*chain, tag)]}
    if key.startswith(("api-ms-", "ext-ms-")):
        return {"status": "api_set_mapping_unverified", "runtime_exact_name_present": key in providers}
    if key in packaged:
        return {"status": "packaged_provider_exports_uninspected", "packaged_candidates": packaged[key],
                "runtime_exact_name_present": key in providers, "loader_search_order_verified": False}
    if key.endswith(".exe"):
        return {"status": "executable_host_alias_unverified", "runtime_exact_name_present": key in providers}
    provider = providers.get(key)
    if provider is None:
        return {"status": "runtime_module_absent_in_selected_directory"}
    if "error" in provider:
        return {"status": "runtime_export_table_uninspectable", "provider_sha256": provider["receipt"]["sha256"]}
    common = {"provider_sha256": provider["receipt"]["sha256"]}
    if provider["architecture"] != architecture or provider["format"] != fmt:
        return {"status": "runtime_architecture_mismatch", **common,
                "provider_architecture": provider["architecture"], "provider_format": provider["format"]}
    item = provider["ordinals" if symbol.startswith("#") else "names"].get(symbol)
    if item is None:
        return {"status": "runtime_export_absent", **common}
    if item["forwarder"] is not None:
        target_module, target_symbol = forwarder_target(item["forwarder"])
        target = resolve(target_module, target_symbol, architecture, fmt, providers, packaged, (*chain, tag))
        return {"status": "runtime_forwarder_candidate", **common, "ordinal": item["ordinal"],
                "forwarder": item["forwarder"], "target": target}
    return {"status": "runtime_export_candidate_present", **common, "ordinal": item["ordinal"]}


def diagnose(inventory_path: Path, runtime_dir: Path) -> dict:
    tool_paths = (Path(__file__), ROOT / "tools/modern_app_inventory.py")
    tool_frozen = []
    for path in tool_paths:
        data, info = snapshot(path)
        tool_frozen.append((path, info, hashlib.sha256(data).hexdigest()))
    source, identity = snapshot(inventory_path, MAX_JSON)
    digest = hashlib.sha256(source).hexdigest()
    receipt = json.loads(source)
    native = validate_inventory(receipt)
    providers, dlls, frozen = load_runtime(runtime_dir)
    packaged = {}
    for item in native:
        if item.get("format") in ("PE32", "PE32+") and item["path"].lower().endswith(".dll"):
            packaged.setdefault(PurePosixPath(item["path"]).name.casefold(), []).append({
                "path": item["path"], "sha256": item["sha256"], "architecture": item["architecture"], "format": item["format"]})
    rows, excluded = [], []
    for item in sorted(native, key=lambda i: i["path"].casefold()):
        if item.get("format") not in ("PE32", "PE32+"):
            excluded.append({"path": item["path"], "sha256": item["sha256"], "format": item.get("format"),
                             "reason": "non_windows_native_payload"})
            continue
        for kind in ("direct_imports", "delay_imports"):
            for descriptor in item[kind]:
                for symbol in descriptor["symbols"]:
                    resolution = resolve(descriptor["module"], symbol, item["architecture"], item["format"], providers, packaged)
                    terminal = resolution
                    while terminal["status"] == "runtime_forwarder_candidate":
                        terminal = terminal["target"]
                    rows.append({"importer": item["path"], "importer_sha256": item["sha256"],
                                 "architecture": item["architecture"], "format": item["format"],
                                 "kind": kind, "module": descriptor["module"].upper(), "symbol": symbol,
                                 **resolution, "terminal_status": terminal["status"]})
    rows.sort(key=lambda r: (r["importer"].casefold(), r["kind"], r["module"], r["symbol"]))
    # Re-read the byte identities after the whole comparison, including tools.
    tool_hashes = [{"path": str(p), "sha256": sha} for p, _, sha in tool_frozen]
    unchanged(inventory_path, identity, digest)
    for path, info, sha in frozen:
        unchanged(path, info, sha)
    for path, info, sha in tool_frozen:
        unchanged(path, info, sha)
    # Detect directory additions/removals after inspection, not just file edits.
    if sorted(p.name for p in runtime_dir.iterdir() if p.suffix.casefold() in RUNTIME_SUFFIXES) != sorted(Path(row["path"]).name for row in dlls):
        raise GapError("runtime DLL directory membership changed during diagnostic")
    counts = dict(sorted(Counter(row["status"] for row in rows).items()))
    gaps = {}
    for row in rows:
        if row["terminal_status"] in ("runtime_export_absent", "runtime_module_absent_in_selected_directory", "runtime_architecture_mismatch"):
            key = (row["module"], row["symbol"], row["terminal_status"])
            gaps.setdefault(key, set()).add(row["importer"])
    return {"schema": 1, "status": "DIAGNOSTIC", "evidence_level": "static-imports-and-binary-export-candidates",
            "app": receipt.get("app"), "source_inventory": {"path": str(inventory_path.absolute()), "sha256": digest,
                "publisher_artifact_sha256_claim": receipt["artifact"]["sha256"], "publisher_artifact_reverified": False},
            "runtime_directory": str(runtime_dir.absolute()), "runtime_dlls": dlls, "source_tools": tool_hashes,
            "imports": rows, "summary": {"imports": len(rows), "statuses": counts, "runtime_dlls": len(dlls),
                "terminal_statuses": dict(sorted(Counter(row["terminal_status"] for row in rows).items())),
                "runtime_export_table_errors": sum(not row["export_table_inspected"] for row in dlls)},
            "concrete_gaps_in_selected_runtime": [{"module": module, "symbol": symbol, "status": status,
                "importers": sorted(importers)} for (module, symbol, status), importers in sorted(gaps.items())],
            "excluded_non_windows_payloads": excluded,
            "limits": ["Export candidates do not establish API behavior or implementation completeness.",
                       "Package DLL bytes were not extracted; exports and loader search order remain unverified.",
                       "API set mapping and executable host aliases remain unverified.",
                       "Dynamic GetProcAddress imports, symbol semantics, initialization, and transitive runtime imports are not validated."],
            "runtime_execution_verified": False, "windows98_execution_verified": False,
            "standalone_kernel64_execution_verified": False, "app_functionality_verified": False,
            "installer_or_application_executed": False, "loader_resolution_verified": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--runtime-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new static diagnostic receipt")
    args = parser.parse_args(argv)
    try:
        report = diagnose(args.inventory, args.runtime_dir)
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except (OSError, ValueError, TypeError, KeyError) as error:
        parser.exit(1, "Static import diagnostic failed: " + str(error) + "\n")
    print(json.dumps({"status": report["status"], **report["summary"], "app_functionality_verified": False}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
