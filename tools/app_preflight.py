"""Read-only PE import and NTW32 preparation diagnostics; no application execution.

The input is read once. Inventory and hashing use that immutable snapshot, and
NTW32's real preparer runs only in memory. No transformed bytes are saved.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import html
import importlib.util
import json
import struct
import sys
from pathlib import Path

from measure_pe_coverage import delay_imports
from scan_imports import PEError, PEView


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "win98modern.app-preflight.v1"


def _load_preparer():
    spec = importlib.util.spec_from_file_location(
        "app_preflight_ntw_prepare", ROOT / "ntwin32/prepare.py"
    )
    if spec is None or spec.loader is None:
        raise PEError("cannot load the NTW32 preparer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _SnapshotPE(PEView):
    """Reuse PEView's inventory parser with file-backed bounds on every table.

    PEView's path constructor would reread the input and permits virtual tails.
    Initialize its parser fields directly from the snapshot instead, validating
    the optional header before probing directories or the section table.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self._file_ranges: list[tuple[int, int]] = []
        if len(data) < 64 or data[:2] != b"MZ":
            raise PEError("missing or truncated DOS header")
        self.pe = self.u32(0x3C)
        if self.pe < 64 or self.pe + 24 > len(data):
            raise PEError("PE/COFF header is outside the file")
        if data[self.pe:self.pe + 4] != b"PE\0\0":
            raise PEError("missing PE signature")
        self.machine = self.u16(self.pe + 4)
        count = self.u16(self.pe + 6)
        if not 1 <= count <= 96:
            raise PEError("invalid PE section count")
        self.optional = self.pe + 24
        optional_size = self.u16(self.pe + 20)
        optional_end = self.optional + optional_size
        if optional_size < 2 or optional_end > len(data):
            raise PEError("truncated optional header")
        magic = self.u16(self.optional)
        if magic == 0x10B:
            self.format, self.thunk_width, base = "PE32", 4, 96
        elif magic == 0x20B:
            self.format, self.thunk_width, base = "PE32+", 8, 112
        else:
            raise PEError(f"unsupported optional header magic {magic:#x}")
        if optional_size < base:
            raise PEError("optional header is shorter than its Windows fields")
        directory_count = self.u32(self.optional + base - 4)
        if directory_count > 16:
            raise PEError("unsupported data-directory count above 16")
        if base + directory_count * 8 > optional_size:
            raise PEError("data-directory count exceeds SizeOfOptionalHeader")
        table = optional_end
        self.headers = self.u32(self.optional + 60)
        if not table + count * 40 <= self.headers <= len(data):
            raise PEError("section table or SizeOfHeaders is outside the file")
        self._raw_sections: list[tuple[int, int, int, int]] = []
        self.sections = []
        for index in range(count):
            at = table + index * 40
            virtual_size, address, raw_size, raw = self.unpack("<IIII", at + 8)
            span = max(virtual_size, raw_size)
            if address < self.headers or address + span > 0x100000000:
                raise PEError("invalid virtual section range")
            if raw_size and (raw < self.headers or raw + raw_size > len(data)):
                raise PEError("raw section range is outside the file")
            for old_address, old_span, old_raw, old_size in self._raw_sections:
                if span and old_span and address < old_address + old_span and old_address < address + span:
                    raise PEError("overlapping virtual sections")
                if raw_size and old_size and raw < old_raw + old_size and old_raw < raw + raw_size:
                    raise PEError("overlapping raw sections")
            self._raw_sections.append((address, span, raw, raw_size))
            self.sections.append((address, span, raw))
        self._file_ranges = [(0, self.headers)] + [
            (raw, raw + size) for _address, _span, raw, size in self._raw_sections if size
        ]
        self.directories = []
        for index in range(directory_count):
            address, size = self.unpack("<II", self.optional + base + index * 8)
            if address or size:
                # GLOBALPTR carries an RVA and a specified zero size.
                if not address or (not size and index != 8):
                    raise PEError(f"incomplete data directory {index}")
                if index == 4:
                    # The certificate table is a file offset, never an RVA.
                    if address + size > len(data):
                        raise PEError("certificate directory is outside the file")
                else:
                    self._span(address, size or 1)
            self.directories.append((address, size))
        self.import_rva = self.directory(1)[0]

    def unpack(self, fmt: str, offset: int) -> tuple:
        size = struct.calcsize(fmt)
        if self._file_ranges and not any(
            start <= offset and offset + size <= end for start, end in self._file_ranges
        ):
            raise PEError("PE structure crosses a file-backed range")
        return super().unpack(fmt, offset)

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def _span(self, address: int, size: int = 1) -> tuple[int, int]:
        if address < 0 or size < 1 or address + size > 0x100000000:
            raise PEError("invalid RVA range")
        if address < self.headers and address + size <= self.headers:
            return address, self.headers
        for start, _span, raw, raw_size in self._raw_sections:
            if start <= address and address + size <= start + raw_size:
                offset = raw + address - start
                return offset, raw + raw_size
        raise PEError(f"RVA {address:#x} is outside a file-backed image range")

    def rva(self, address: int) -> int:
        return self._span(address)[0]

    def string(self, address: int) -> str:
        start, end = self._span(address)
        terminator = self.data.find(b"\0", start, min(end, start + 4096))
        if terminator < 0:
            raise PEError("unterminated PE string within its file-backed range")
        if terminator == start:
            raise PEError("empty PE import string")
        try:
            result = self.data[start:terminator].decode("ascii")
        except UnicodeDecodeError as exc:
            raise PEError("non-ASCII PE import string") from exc
        if any(ord(char) < 32 or ord(char) == 127 for char in result):
            raise PEError("control character in PE import string")
        return result

    def _dll_name(self, address: int) -> str:
        name = self.string(address)
        if any(char in name for char in "/\\:"):
            raise PEError("invalid import DLL name")
        return name

    def _validate_thunks(self, address: int, iat: int) -> None:
        if not address or not iat:
            raise PEError("missing import thunk or IAT")
        start, end = self._span(address, self.thunk_width)
        mask = 1 << (self.thunk_width * 8 - 1)
        fmt = "<I" if self.thunk_width == 4 else "<Q"
        for index in range(65536):
            offset = start + index * self.thunk_width
            if offset + self.thunk_width > end:
                raise PEError("unterminated thunk table within its file-backed range")
            value = self.unpack(fmt, offset)[0]
            if not value:
                self._span(iat, (index + 1) * self.thunk_width)
                return
            if value & mask:
                if value & ~(mask | 0xFFFF):
                    raise PEError("invalid ordinal import")
            else:
                self._span(value, 2)  # The hint precedes the import name.
                self.string(value + 2)
        raise PEError("unterminated or oversized thunk table")

    def validate_imports(self) -> None:
        address, size = self.directory(1)
        if not address:
            return
        if size < 20:
            raise PEError("import directory is shorter than one descriptor")
        start = self._span(address, size)[0]
        for index in range(min(4096, size // 20)):
            original, stamp, chain, name, first = self.unpack("<IIIII", start + index * 20)
            if not any((original, stamp, chain, name, first)):
                return
            if not name or not first:
                raise PEError("incomplete import descriptor")
            if stamp and not original:
                raise PEError("bound imports without an original lookup table")
            self._dll_name(name)
            self._validate_thunks(original or first, first)
        raise PEError("unterminated import descriptors within the declared directory")

    def validate_delay_imports(self) -> None:
        address, size = self.directory(13)
        if not address:
            return
        if size < 32:
            raise PEError("delay import directory is shorter than one descriptor")
        start = self._span(address, size)[0]
        image_base = (
            self.u32(self.optional + 28) if self.thunk_width == 4
            else self.unpack("<Q", self.optional + 24)[0]
        )
        for index in range(min(65536, size // 32)):
            fields = self.unpack("<IIIIIIII", start + index * 32)
            if not any(fields):
                return
            attrs, name, _module, iat, names, _bound, _unload, _stamp = fields
            if attrs not in (0, 1):
                raise PEError("unsupported delay import attributes")
            if attrs == 0:
                if name < image_base or iat < image_base or (names and names < image_base):
                    raise PEError("delay import VA precedes image base")
                name, iat = name - image_base, iat - image_base
                if names:
                    names -= image_base
            self._dll_name(name)
            self._validate_thunks(names or iat, iat)
        raise PEError("unterminated delay import descriptors within the declared directory")


def analyze(path: Path) -> dict:
    """Inspect a single immutable input snapshot without saving or running it."""
    path = Path(path)
    data = path.read_bytes()
    view = _SnapshotPE(data)
    view.validate_imports()
    view.validate_delay_imports()
    preparer = _load_preparer()
    try:
        plan = preparer.routes()
    except preparer.PEError as exc:
        raise PEError(f"invalid NTW32 routing configuration: {exc}") from exc
    supported = set(preparer.route_names(plan))
    rows = [
        {"dll": dll.upper(), "symbol": symbol, "kind": "load"}
        for dll, symbol in view.imports()
    ]
    notes = []
    complete = True
    if view.directory(13)[0]:
        if view.thunk_width == 4:
            rows.extend(
                {"dll": dll, "symbol": symbol, "kind": "delay"}
                for dll, symbol in delay_imports(view)
            )
        else:
            complete = False
            notes.append("PE32+ delay import inventory is incomplete: delay symbols are not listed.")
    for row in rows:
        row["ntw32_route_candidate"] = (
            row["kind"] == "load" and row["dll"] == plan["source_dll"]
            and row["symbol"] in supported
        )
    api_sets = sorted({
        row["dll"] for row in rows
        if row["dll"].lower().startswith(("api-ms-", "ext-ms-"))
    })
    if api_sets:
        notes.append("API-set imports have no NTW32 route; no API-set mapping is inferred.")
    version = [view.u16(view.optional + 48), view.u16(view.optional + 50)]
    subsystem = view.u16(view.optional + 68)
    clr = bool(view.directory(14)[0])
    blockers = []
    if view.machine != 0x14C or view.format != "PE32":
        blockers.append(
            f"stock 32-bit Windows 98 requires x86 PE32; got machine {view.machine:#x} {view.format}"
        )
    if subsystem not in (2, 3):
        blockers.append(f"subsystem {subsystem} is outside the stock Win98 GUI/console application path")
    if tuple(version) > (4, 10):
        blockers.append(f"subsystem version {version[0]}.{version[1]} exceeds stock Win98 4.10")
    if clr:
        blockers.append("CLR image requires a separate runtime; stock Win98 application path is blocked")
    try:
        transformed, _receipt = preparer.prepare(data)
        del transformed, _receipt
        preparation = {"preparation_status": "eligible", "reason": None}
    except preparer.PEError as exc:
        preparation = {"preparation_status": "rejected", "reason": str(exc)}
    return {
        "schema": SCHEMA,
        "input": {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)},
        "pe": {"machine": view.machine, "format": view.format, "subsystem": subsystem,
               "subsystem_version": version, "clr_present": clr,
               "certificate_table_present": bool(view.directory(4)[0]),
               "tls_present": bool(view.directory(9)[0]),
               "load_config_present": bool(view.directory(10)[0])},
        "imports": rows,
        "import_inventory_complete": complete,
        "import_inventory_notes": notes,
        "api_set_dlls": api_sets,
        "unresolved_by_ntw32": [row.copy() for row in rows if not row["ntw32_route_candidate"]],
        "paths": {"stock_win98": {"status": "blocked" if blockers else "unverified", "blockers": blockers},
                  "ntw32": preparation},
        "guest_executed": False,
        "runtime_compatibility": "unverified",
    }


def _cell(value) -> str:
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: dict) -> str:
    """Render the same diagnostic without promoting it to execution evidence."""
    pe = report["pe"]
    stock = report["paths"]["stock_win98"]
    ntw32 = report["paths"]["ntw32"]
    version = ".".join(str(value) for value in pe["subsystem_version"])
    lines = [
        "# Application preflight", "",
        f"Input: {_cell(report['input']['path'])}", "",
        f"SHA-256: {_cell(report['input']['sha256'])}", "",
        f"Size: {report['input']['size_bytes']} bytes. Machine: {pe['machine']:#x}; "
        f"format: {_cell(pe['format'])}; subsystem: {pe['subsystem']} ({version}).", "",
        f"Stock 32-bit Win98 path: **{stock['status']}**.", "",
    ]
    lines.extend(f"- {_cell(reason)}" for reason in stock["blockers"])
    if stock["blockers"]:
        lines.append("")
    lines.extend([
        f"NTW32 preparation: **{ntw32['preparation_status']}**.", "",
        f"Reason: {_cell(ntw32['reason'])}." if ntw32["reason"] else "The real preparer accepted the input in memory; transformed bytes were discarded.",
        "", "Guest executed: **false**. Runtime compatibility: **unverified**.", "",
        "This diagnostic does not assess the ShizukuDOS WIN64 subsystem path.", "",
        f"Static import inventory complete: **{str(report['import_inventory_complete']).lower()}**.", "",
    ])
    lines.extend(f"- {_cell(note)}" for note in report["import_inventory_notes"])
    if report["import_inventory_notes"]:
        lines.append("")
    lines.extend([
        "An import without an NTW32 route is unresolved by this provider. "
        "It is not proof of a missing DLL or API; native and bundled exports were not checked.",
        "", "| DLL | Symbol | Kind | NTW32 route candidate |", "| --- | --- | --- | --- |",
    ])
    for row in report["imports"]:
        lines.append("| " + " | ".join(_cell(row[key]) for key in
                     ("dll", "symbol", "kind", "ntw32_route_candidate")) + " |")
    if not report["imports"]:
        lines.append("| (none listed) | | | |")
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="PE file to inspect without executing or changing it")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    args = parser.parse_args(argv)
    try:
        report = analyze(args.input)
        output = render_markdown(report) if args.format == "markdown" else json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    except (OSError, PEError, ValueError) as exc:
        print(f"app_preflight: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
