"""Read-only architecture and loader-prerequisite inventory for modern apps.

This is evidence for porting, never a compatibility score or a guest pass.
No target executable, native addon, or installer is executed.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import struct
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE = 1024 * 1024 * 1024
MACHINES = {0x14C: ("ia32", 0x10B), 0x8664: ("x64", 0x20B),
            0xAA64: ("arm64", 0x20B)}


class PEError(ValueError):
    """A PE cannot be inventoried without guessing or ignoring metadata."""


def file_identity(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def open_regular(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise PEError("input is not a regular file")
        if info.st_size > MAX_FILE:
            raise PEError("input exceeds bounded inventory size")
        return os.fdopen(descriptor, "rb"), info
    except BaseException:
        os.close(descriptor)
        raise


def read_regular(path: Path) -> bytes:
    stream, before = open_regular(path)
    with stream:
        data = stream.read(before.st_size + 1)
        if len(data) != before.st_size or file_identity(os.fstat(stream.fileno())) != file_identity(before):
            raise PEError("input changed during bounded read")
        return data


def stream_digest(stream, expected_size: int) -> str:
    digest, total = hashlib.sha256(), 0
    while total <= expected_size:
        block = stream.read(min(1024 * 1024, expected_size + 1 - total))
        if not block:
            break
        digest.update(block)
        total += len(block)
    if total != expected_size:
        raise PEError("stream size changed or exceeds declared extent")
    return digest.hexdigest()


class PEInventory:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:2] != b"MZ":
            raise PEError("missing/truncated DOS header")
        pe = self.u32(0x3C)
        if self.span(pe, 24)[:4] != b"PE\0\0":
            raise PEError("missing PE signature")
        self.machine = self.u16(pe + 4)
        count, optional_size = self.u16(pe + 6), self.u16(pe + 20)
        if not 1 <= count <= 96:
            raise PEError("invalid section count")
        optional = pe + 24
        self.span(optional, optional_size)
        self.magic = self.u16(optional)
        if self.machine not in MACHINES or MACHINES[self.machine][1] != self.magic:
            raise PEError("unsupported or inconsistent machine/optional-header pair")
        self.arch = MACHINES[self.machine][0]
        self.width = 4 if self.magic == 0x10B else 8
        directory_offset = 96 if self.width == 4 else 112
        if optional_size < directory_offset:
            raise PEError("truncated optional header")
        self.image_base = (self.u32(optional + 28) if self.width == 4
                           else self.u64(optional + 24))
        self.headers_size = self.u32(optional + 60)
        self.image_size = self.u32(optional + 56)
        if self.headers_size > len(data):
            raise PEError("header extent exceeds file")
        if not self.image_size or self.headers_size > self.image_size:
            raise PEError("invalid loaded image extent")
        self.os_version = [self.u16(optional + 40), self.u16(optional + 42)]
        self.subsystem_version = [self.u16(optional + 48), self.u16(optional + 50)]
        self.subsystem = self.u16(optional + 68)
        self.characteristics = self.u16(optional + 70)
        directory_count = self.u32(optional + directory_offset - 4)
        if directory_count > (optional_size - directory_offset) // 8:
            raise PEError("data directories exceed optional header")
        self.directories = [self.unpack("<II", optional + directory_offset + i * 8)
                            for i in range(directory_count)]
        self.sections = []
        self.image_sections = []
        section_table = optional + optional_size
        self.span(section_table, count * 40)
        if section_table + count * 40 > self.headers_size:
            raise PEError("section table exceeds headers")
        for i in range(count):
            at = section_table + i * 40
            virtual, size, raw = self.u32(at + 12), self.u32(at + 16), self.u32(at + 20)
            loaded_size = max(self.u32(at + 8), size)
            self.span(raw, size)
            if virtual + size > 0x100000000:
                raise PEError("section RVA overflow")
            self.sections.append((virtual, size, raw))
            if virtual + loaded_size > self.image_size:
                raise PEError("section exceeds loaded image extent")
            self.image_sections.append((virtual, loaded_size))

    def span(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise PEError("PE structure exceeds file")
        return self.data[offset:offset + size]

    def unpack(self, fmt: str, offset: int) -> tuple:
        return struct.unpack(fmt, self.span(offset, struct.calcsize(fmt)))

    def u16(self, at: int) -> int:
        return self.unpack("<H", at)[0]

    def u32(self, at: int) -> int:
        return self.unpack("<I", at)[0]

    def u64(self, at: int) -> int:
        return self.unpack("<Q", at)[0]

    def offset(self, rva: int, size: int = 1) -> int:
        if rva < 0 or size < 1 or rva + size > 0x100000000:
            raise PEError("invalid RVA extent")
        if rva < self.headers_size and rva + size <= self.headers_size:
            return rva
        matches = [raw + rva - start for start, length, raw in self.sections
                   if start <= rva and rva + size <= start + length]
        if len(matches) != 1:
            raise PEError("RVA is unmapped, ambiguous, or virtual-only")
        self.span(matches[0], size)
        return matches[0]

    def string(self, rva: int) -> str:
        start = self.offset(rva)
        for length in range(8192):
            at = self.offset(rva + length)
            if at != start + length:
                raise PEError("string crosses discontiguous sections")
            if self.data[at] == 0:
                try:
                    return self.data[start:at].decode("ascii")
                except UnicodeDecodeError as exc:
                    raise PEError("non-ASCII import name") from exc
        raise PEError("unterminated or oversized import name")

    def loaded_extent(self, rva: int, size: int) -> None:
        """Validate an IAT destination, including legal zero-filled sections."""
        if not rva or size < 1 or rva + size > self.image_size:
            raise PEError("import address table exceeds loaded image")
        if rva < self.headers_size and rva + size <= self.headers_size:
            return
        matches = [start for start, length in self.image_sections
                   if start <= rva and rva + size <= start + length]
        if len(matches) != 1:
            raise PEError("import address table is unmapped or ambiguous")

    def directory(self, index: int) -> tuple[int, int]:
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def thunks(self, rva: int, va_names: bool = False) -> list[str]:
        if not rva:
            raise PEError("missing import lookup table")
        names = []
        mask = 1 << (self.width * 8 - 1)
        for index in range(65536):
            at = self.offset(rva + index * self.width, self.width)
            value = self.u32(at) if self.width == 4 else self.u64(at)
            if not value:
                return names
            if value & mask:
                if value & ~(mask | 0xFFFF):
                    raise PEError("invalid ordinal thunk")
                names.append("#" + str(value & 0xFFFF))
            else:
                name_rva = value - self.image_base if va_names else value
                self.offset(name_rva, 2)
                name = self.string(name_rva + 2)
                if not name:
                    raise PEError("empty import symbol")
                names.append(name)
        raise PEError("unterminated import lookup table")

    def imports(self, delayed: bool = False) -> list[dict]:
        rva, size = self.directory(13 if delayed else 1)
        if not rva and not size:
            return []
        width = 32 if delayed else 20
        if not rva or size < width:
            raise PEError("invalid import directory extent")
        self.offset(rva, size)
        result = []
        for index in range(min(size // width, 4096)):
            at = self.offset(rva + index * width, width)
            values = self.unpack("<8I" if delayed else "<5I", at)
            if not any(values):
                return result
            if delayed:
                attrs, name, _, iat, lookup, _, _, _ = values
                if attrs & ~1:
                    raise PEError("unknown delay import attributes")
                va_names = not bool(attrs & 1)
                convert = lambda value: value - self.image_base if va_names else value
                name, lookup, iat = convert(name), convert(lookup or iat), convert(iat)
            else:
                lookup, _, _, name, iat = values
                lookup = lookup or iat
                va_names = False
            module = self.string(name)
            if not module:
                raise PEError("empty imported module name")
            symbols = self.thunks(lookup, va_names)
            self.loaded_extent(iat, (len(symbols) + 1) * self.width)
            result.append({"module": module.upper(), "symbols": symbols})
        raise PEError("unterminated import descriptor directory")

    def report(self) -> dict:
        metadata = {}
        for index, label in ((9, "static_thread_local_storage"),
                             (10, "load_configuration"), (13, "delay_imports")):
            rva, size = self.directory(index)
            if rva or size:
                if not rva or not size:
                    raise PEError("incomplete " + label + " directory")
                self.offset(rva, size)
            metadata[label] = {"rva": rva, "bytes": size, "present": bool(rva)}
        return {
            "architecture": self.arch, "machine": f"0x{self.machine:04x}",
            "format": "PE32" if self.width == 4 else "PE32+",
            "declared_os_version": self.os_version,
            "declared_subsystem_version": self.subsystem_version,
            "subsystem": self.subsystem,
            "dll_characteristics": f"0x{self.characteristics:04x}",
            "loader_metadata": metadata,
            "direct_imports": self.imports(), "delay_imports": self.imports(True),
            "required_execution_path": {
                "ia32": "ported_x86_loader_and_runtime",
                "x64": "win64_runtime_or_current_source_x86_port",
                "arm64": "arm64_runtime_or_current_source_x86_port",
            }[self.arch],
            "guest_execution_verified": False, "app_functionality_verified": False,
        }


def foreign_addon(data: bytes) -> dict | None:
    """Keep packaged Unix addons visible without treating them as Windows PEs."""
    if data.startswith(b"\x7fELF"):
        if len(data) < 20 or data[4] not in (1, 2) or data[5] not in (1, 2):
            raise PEError("malformed ELF addon")
        minimum = 52 if data[4] == 1 else 64
        if len(data) < minimum:
            raise PEError("truncated ELF addon")
        machine = struct.unpack_from("<H" if data[5] == 1 else ">H", data, 18)[0]
        architecture = {3: "ia32", 40: "arm", 62: "x64", 183: "arm64",
                        243: "riscv", 258: "loongarch"}.get(machine, f"elf-{machine}")
        return {"format": "ELF", "architecture": architecture,
                "applicable_to_windows_runtime": False}
    magic = data[:4]
    if magic in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                 b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        if len(data) < 32:
            raise PEError("truncated Mach-O addon")
        endian = "<" if magic[0] in (0xCE, 0xCF) else ">"
        cpu = struct.unpack_from(endian + "I", data, 4)[0]
        architecture = {7: "ia32", 12: "arm", 0x1000007: "x64",
                        0x100000C: "arm64"}.get(cpu, f"mach-o-{cpu}")
        return {"format": "Mach-O", "architecture": architecture,
                "applicable_to_windows_runtime": False}
    return None


def inventory(root: Path, app_id: str, manifest: dict) -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("package root must be a directory")
    targets = [a for a in manifest["apps"] if a["id"] == app_id]
    if len(targets) != 1:
        raise ValueError("app must have exactly one manifest target")
    files, errors = [], []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            errors.append({"path": path.relative_to(root).as_posix(),
                           "error": "package symlink or omitted symlink subtree"})
            continue
        if path.suffix.lower() not in {".exe", ".dll", ".node"}:
            continue
        relative = path.relative_to(root).as_posix()
        try:
            if not path.resolve().is_relative_to(root):
                raise PEError("package symlink escapes or replaces a binary")
            data = read_regular(path)
            size = len(data)
            item = foreign_addon(data) if path.suffix.lower() == ".node" else None
            if item is None:
                item = PEInventory(data).report()
                item["applicable_to_windows_runtime"] = True
            item.update({"path": relative, "bytes": size,
                         "sha256": hashlib.sha256(data).hexdigest(),
                         "native_addon": path.suffix.lower() == ".node"})
            files.append(item)
        except (OSError, PEError) as exc:
            errors.append({"path": relative, "error": str(exc)})
    if not files and not errors:
        errors.append({"path": ".", "error": "no PE binaries or native addons found"})
    entry_name = targets[0].get("entry_point", "")
    entries = [item for item in files if item["path"].casefold() == entry_name.casefold()]
    entry = entries[0] if len(entries) == 1 else None
    if entry_name and entry is None:
        errors.append({"path": entry_name, "error": "expected entry point not inventoried"})
    return {"schema": 1, "app_id": app_id, "target": targets[0],
            "kind": "static_porting_inventory", "package_root": str(root),
            "files": files, "errors": errors,
            "architectures": sorted({item["architecture"] for item in files
                                      if item["applicable_to_windows_runtime"]}),
            "entry_point": entry,
            "target_identity_verified": False,
            "guest_execution_verified": False, "app_functionality_verified": False}


def verify_archive(report: dict, archive: Path) -> None:
    """Tie all app payloads and inventoried bytes to one pinned ZIP descriptor."""
    target = report["target"].get("first_probe", {})
    expected = target.get("publisher_sha256")
    if not expected or len(expected) != 64:
        raise ValueError("target has no publisher-pinned probe archive")
    if report["errors"]:
        raise ValueError("cannot verify a package with inventory errors")
    root = Path(report["package_root"])
    actual = {item["path"]: item for item in report["files"]}
    paths = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("package contains a symlink or omitted subtree")
        if path.is_file():
            paths.add(path.relative_to(root).as_posix())
        elif not path.is_dir():
            raise ValueError("package contains a special-file payload")
    seen, binaries = set(), set()
    archive_stream, before = open_regular(archive)
    with archive_stream:
        if stream_digest(archive_stream, before.st_size) != expected:
            raise ValueError("archive differs from publisher-pinned SHA-256")
        archive_stream.seek(0)
        with zipfile.ZipFile(archive_stream) as package:
            for member in package.infolist():
                if member.is_dir():
                    continue
                name = member.filename
                if name in seen or name not in paths or stat.S_ISLNK(member.external_attr >> 16):
                    raise ValueError("package payload paths differ from pinned archive")
                seen.add(name)
                path = root / name
                if not path.resolve().is_relative_to(root):
                    raise ValueError("archive member escapes package root")
                if member.file_size > MAX_FILE:
                    raise ValueError("archive member exceeds bounded inventory size")
                with package.open(member) as source:
                    member_digest = stream_digest(source, member.file_size)
                payload, info = open_regular(path)
                with payload:
                    if info.st_size != member.file_size or stream_digest(payload, info.st_size) != member_digest:
                        raise ValueError("application payload differs from pinned archive")
                    if file_identity(os.fstat(payload.fileno())) != file_identity(info):
                        raise ValueError("application payload changed during archive verification")
                if Path(name).suffix.lower() in {".exe", ".dll", ".node"}:
                    if name not in actual or actual[name]["bytes"] != member.file_size or actual[name]["sha256"] != member_digest:
                        raise ValueError("inventoried binary differs from pinned archive")
                    binaries.add(name)
        if file_identity(os.fstat(archive_stream.fileno())) != file_identity(before):
            raise ValueError("archive changed during verification")
    if seen != paths or binaries != set(actual):
        raise ValueError("package has missing or additional payloads")
    if report["entry_point"] is None:
        raise ValueError("publisher archive verification requires an entry point")
    if report["entry_point"]["architecture"] != target.get("architecture"):
        raise ValueError("entry point architecture differs from pinned probe")
    report["target_identity_verified"] = True
    report["archive_identity"] = {"sha256": expected, "source": target["url"],
                                  "publisher_digest_source": target["publisher_digest_source"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--manifest", type=Path,
                        default=ROOT / "benchmarks/modern-app-targets-v1.json")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--archive", type=Path,
                        help="verify all application payloads against publisher-pinned ZIP")
    args = parser.parse_args()
    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        report = inventory(args.root, args.app, manifest)
        if args.archive:
            verify_archive(report, args.archive)
        encoded = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(encoded, encoding="utf-8")
        else:
            print(encoded, end="")
        return int(bool(report["errors"]))
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print("FAIL: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
