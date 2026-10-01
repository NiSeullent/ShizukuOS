"""Read real Office/Steam PE components without executing or modifying them.

Inventory includes PE32 and PE32+ ordinary and delay imports. It never converts
an address inventory or Kernel64 standalone result into native Win98 app proof.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from app_preflight import _SnapshotPE  # same immutable, file-backed bounds
from scan_imports import PEError

MAX_ENTRIES = 8192
MAX_COMPONENTS = 32
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024


def snapshot(path: Path, maximum: int = MAX_FILE) -> bytes:
    if path.is_symlink():
        raise ValueError(f"symlink input refused: {path}")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("input is not a bounded regular file")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    named = path.stat()
    metadata = lambda value: (value.st_dev, value.st_ino, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    if len(data) != before.st_size or metadata(before) != metadata(after) or metadata(after) != metadata(named):
        raise ValueError("input changed during inventory")
    return data


def delay_rows(view: _SnapshotPE) -> list[dict]:
    """Decode the validated delay INT with the actual PE's thunk width."""
    address, size = view.directory(13)
    if not address:
        return []
    start = view.rva(address)
    base = (view.u32(view.optional + 28) if view.thunk_width == 4
            else view.unpack("<Q", view.optional + 24)[0])
    result = []
    mask = 1 << (view.thunk_width * 8 - 1)
    fmt = "<I" if view.thunk_width == 4 else "<Q"
    for index in range(min(65536, size // 32)):
        fields = view.unpack("<IIIIIIII", start + index * 32)
        if not any(fields):
            return result
        attrs, name, _module, iat, names, _bound, _unload, _stamp = fields
        if not attrs & 1:
            name -= base
            iat -= base
            if names:
                names -= base
        dll = view.string(name).upper()
        table, end = view._span(names or iat, view.thunk_width)
        for entry in range(65536):
            offset = table + entry * view.thunk_width
            if offset + view.thunk_width > end:
                raise PEError("delay INT crosses its file-backed range")
            value = view.unpack(fmt, offset)[0]
            if not value:
                break
            symbol = f"#{value & 0xffff}" if value & mask else view.string(value + 2)
            result.append({"dll": dll, "symbol": symbol, "kind": "delay"})
        else:
            raise PEError("delay INT exceeds the bounded profile")
    raise PEError("delay import descriptors have no terminator")


def inspect(data: bytes, name: str) -> dict:
    view = _SnapshotPE(data)
    view.validate_imports()
    view.validate_delay_imports()
    rows = [{"dll": dll.upper(), "symbol": symbol, "kind": "load"}
            for dll, symbol in view.imports()]
    rows.extend(delay_rows(view))
    subsystem = view.u16(view.optional + 68)
    subsystem_version = [view.u16(view.optional + 48), view.u16(view.optional + 50)]
    blockers = []
    if view.machine != 0x14c or view.format != "PE32":
        blockers.append("stock Win98 loader requires x86 PE32")
    if subsystem not in (2, 3):
        blockers.append("not a stock Win98 GUI/console subsystem")
    if tuple(subsystem_version) > (4, 10):
        blockers.append("subsystem version exceeds stock Win98 4.10")
    if view.directory(14)[0]:
        blockers.append("CLR runtime required separately")
    return {
        "path": name, "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "pe": {"format": view.format, "machine": view.machine,
               "subsystem": subsystem, "subsystem_version": subsystem_version,
               "tls_present": bool(view.directory(9)[0]),
               "load_config_present": bool(view.directory(10)[0]),
               "clr_present": bool(view.directory(14)[0])},
        "ordinary_and_delay_inventory_complete": True,
        "imports": rows,
        "api_set_dlls": sorted({row["dll"] for row in rows
                                if row["dll"].lower().startswith(("api-ms-", "ext-ms-"))}),
        "stock_win98_structural_blockers": blockers,
        "requires_additional_64_bit_execution_path": view.machine == 0x8664 and view.format == "PE32+",
        "import_semantics_and_dependency_closure": "unverified",
        "runtime_compatibility": "unverified",
    }


def inventory(root: Path, wanted: set[str]) -> dict[str, list[Path]]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("application root must be a real directory")
    root = root.resolve()
    result = {name: [] for name in wanted}
    pending, visited = [root], 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                visited += 1
                if visited > MAX_ENTRIES:
                    raise ValueError("application inventory exceeds 8192 entries; supply a smaller actual deployment root")
                if entry.is_symlink():
                    raise ValueError(f"symlink in application deployment: {entry.path}")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False) and entry.name.lower() in result:
                    result[entry.name.lower()].append(Path(entry.path).relative_to(root))
    return result


def component_path(root: Path, relative: Path) -> Path:
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError("component must be a relative path inside the deployment")
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"symlink component refused: {current}")
    return current


def analyze(app: str, root: Path, explicit: dict[str, list[Path]] | None = None) -> dict:
    profiles = json.loads((HERE / "office_steam_profiles.json").read_text())
    profile = profiles[app]
    required = profile["required_component_names"]
    explicit = explicit or {}
    if set(explicit) - set(required):
        raise ValueError("unknown component role")
    found = inventory(root, {name.lower() for names in required.values() for name in names})
    root = root.resolve()
    selected, failures, total = {}, [], 0
    for role, names in required.items():
        candidates = explicit.get(role)
        if candidates is None:
            candidates = [path for name in names for path in found[name.lower()]]
            duplicates = [name for name in names if len(found[name.lower()]) > 1]
            if duplicates:
                failures.append({"role": role, "reason": "ambiguous component locations; use --component ROLE=relative/path",
                                 "names": duplicates})
                continue
        if not candidates:
            failures.append({"role": role, "reason": "actual required component absent", "names": names})
            continue
        selected[role] = []
        for relative in candidates:
            if relative.name.lower() not in {name.lower() for name in names}:
                raise ValueError(f"component does not match the real product's {role} role")
            if sum(len(values) for values in selected.values()) >= MAX_COMPONENTS:
                raise ValueError("too many selected application components")
            data = snapshot(component_path(root, relative), min(MAX_FILE, MAX_TOTAL - total))
            total += len(data)
            selected[role].append(inspect(data, relative.as_posix()))
    return {
        "schema": "win98modern.office-steam-preflight.v1",
        "application": app, "root": str(root),
        "profile_sha256": hashlib.sha256((HERE / "office_steam_profiles.json").read_bytes()).hexdigest(),
        "target_profile": profiles["native_target"],
        "scope": "selected original application components; full dependency closure is not inferred",
        "components": selected, "component_failures": failures,
        "input_bytes_inspected": total,
        "required_native_operations": profile["required_native_operations"],
        "application_payload_present": not failures,
        "original_files_modified": False,
        "guest_executed": False,
        "runtime_compatibility": "unverified",
        "native_application_passed": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True, choices=("libreoffice", "steam"))
    parser.add_argument("--root", required=True, type=Path, help="actual deployment tree, not an SDK sample")
    parser.add_argument("--component", action="append", default=[], metavar="ROLE=RELATIVE_PATH")
    args = parser.parse_args(argv)
    explicit = {}
    try:
        for entry in args.component:
            role, value = entry.split("=", 1)
            explicit.setdefault(role, []).append(Path(value))
        report = analyze(args.app, args.root, explicit)
    except (OSError, ValueError, KeyError, TypeError, PEError) as exc:
        print(f"office_steam_preflight: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2))
    return 0 if report["application_payload_present"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
