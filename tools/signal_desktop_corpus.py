"""Inventory pinned Signal and ONLYOFFICE publisher packages without running them.

Local artifacts only: no downloader, installer execution, or guest support claim.
ZIP members are streamed. Signal's NSIS nested 7z is read by an explicitly selected
host 7-Zip executable, into one bounded temporary archive, never extract-all.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import selectors
import stat
import struct
import subprocess
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("modern_app_inventory", ROOT / "tools/modern_app_inventory.py")
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)

PINS = {
    "signal": {
        "version": "8.28.0", "architecture": "x64", "entry_point": "Signal.exe",
        "url": "https://updates.signal.org/desktop/signal-desktop-win-x64-8.28.0.exe",
        "bytes": 141981864, "algorithm": "sha512",
        "digest": "jCEuerFSe9HiVtES7y40Wk+VmrzI7VOCpuB61WRLeZRv3JJdn7KN15ZRnWMItFGE+35QyAOoIPPE4LlLBHvmgw==",
        "encoding": "base64", "metadata_url": "https://updates.signal.org/desktop/latest.yml",
        "release_url": "https://github.com/signalapp/Signal-Desktop/releases/tag/v8.28.0",
        "native_dependencies": {"@signalapp/libsignal-client": "0.100.0", "@signalapp/ringrtc": "2.71.0", "@signalapp/sqlcipher": "4.1.0"},
    },
    "onlyoffice": {
        "version": "9.4.0", "architecture": "ia32", "entry_point": "DesktopEditors.exe",
        "url": "https://github.com/ONLYOFFICE/DesktopEditors/releases/download/v9.4.0/DesktopEditors_x86.zip",
        "bytes": 582858718, "algorithm": "sha256",
        "digest": "5eba4b785c5366023de6deaba478da1d18624211561f0a8306da4ca9bd053e1a",
        "encoding": "hex", "metadata_url": "https://api.github.com/repos/ONLYOFFICE/DesktopEditors/releases/latest",
        "release_url": "https://github.com/ONLYOFFICE/DesktopEditors/releases/tag/v9.4.0",
    },
    "onlyoffice_x64": {
        "version": "9.4.0", "architecture": "x64", "entry_point": "DesktopEditors.exe",
        "url": "https://github.com/ONLYOFFICE/DesktopEditors/releases/download/v9.4.0/DesktopEditors_x64.zip",
        "bytes": 598575987, "algorithm": "sha256",
        "digest": "22ae48a7813954e5079bff1ea211c6583aba67f34f2d0dbcb2431d4a20e94dfc",
        "encoding": "hex", "metadata_url": "https://api.github.com/repos/ONLYOFFICE/DesktopEditors/releases/tags/v9.4.0",
        "release_url": "https://github.com/ONLYOFFICE/DesktopEditors/releases/tag/v9.4.0",
    },
}
PIN_CHECKED_UTC = "2026-10-01"
MAX_MEMBERS = 30000
MAX_EXPANDED = 4 * 1024**3
MAX_MEMBER = 512 * 1024**2
MAX_LISTING = 16 * 1024**2
MAX_ASAR_HEADER = 16 * 1024**2
MAX_PACKAGE_JSON = 1024**2
NATIVE_SUFFIXES = (".exe", ".dll", ".node")


class CorpusError(ValueError):
    pass


def safe_member(name: str) -> str:
    """Reject Windows aliases too, even though this tool never extracts paths."""
    name = name.replace("\\", "/")
    parts = name.split("/")
    if not name or name.startswith(("/", "@", "-")) or any(p in ("", ".", "..") for p in parts):
        raise CorpusError("absolute, empty, or traversing archive member")
    for part in parts:
        if any(ord(c) < 32 for c in part) or any(c in part for c in ':*?"<>|') or part.endswith((".", " ")):
            raise CorpusError("unsafe Windows archive member")
        if part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *("COM" + str(i) for i in range(1, 10)), *("LPT" + str(i) for i in range(1, 10))}:
            raise CorpusError("reserved Windows archive member")
    return name


def checked_entries(entries: list[dict]) -> list[dict]:
    if not entries or len(entries) > MAX_MEMBERS:
        raise CorpusError("archive member count outside bound")
    names, total, result = set(), 0, []
    for row in entries:
        name = safe_member(row["name"])
        folded = name.casefold()
        if folded in names or row.get("link"):
            raise CorpusError("duplicate, case-aliased, or linked archive member")
        names.add(folded)
        size = row["bytes"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_MEMBER:
            raise CorpusError("member exceeds bounded extent")
        total += size
        if total > MAX_EXPANDED:
            raise CorpusError("archive expansion exceeds bound")
        result.append({**row, "name": name})
    return result


def bounded_read(stream, expected: int) -> bytes:
    if not 0 <= expected <= MAX_MEMBER:
        raise CorpusError("read exceeds member bound")
    data = stream.read(expected + 1)
    if len(data) != expected:
        raise CorpusError("member differs from declared size")
    return data


def artifact_digest(stream, pin: dict) -> dict:
    before = os.fstat(stream.fileno())
    if not stat.S_ISREG(before.st_mode) or before.st_size != pin["bytes"]:
        raise CorpusError("artifact size/type differs from publisher pin")
    stream.seek(0)
    digest, sha256, total = hashlib.new(pin["algorithm"]), hashlib.sha256(), 0
    for block in iter(lambda: stream.read(1024**2), b""):
        total += len(block)
        if total > pin["bytes"]:
            raise CorpusError("artifact grew during verification")
        digest.update(block)
        sha256.update(block)
    value = base64.b64encode(digest.digest()).decode() if pin["encoding"] == "base64" else digest.hexdigest()
    if total != pin["bytes"] or value != pin["digest"] or inventory.file_identity(before) != inventory.file_identity(os.fstat(stream.fileno())):
        raise CorpusError("artifact changed or fails publisher digest")
    stream.seek(0)
    return {"bytes": total, "sha256": sha256.hexdigest(), "publisher_digest_verified": True}


def zip_entries(archive: zipfile.ZipFile) -> list[dict]:
    rows = []
    if len(archive.infolist()) > MAX_MEMBERS:
        raise CorpusError("ZIP member count exceeds bound")
    for info in archive.infolist():
        mode = info.external_attr >> 16
        if info.flag_bits & 1:
            raise CorpusError("encrypted ZIP member")
        linked = stat.S_ISLNK(mode) or bool(mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))
        if linked:
            raise CorpusError("linked or special ZIP member")
        if info.is_dir():
            safe_member(info.filename.rstrip("/"))
            continue
        rows.append({"name": info.filename, "bytes": info.file_size,
                     "archive_name": info.filename})
    return checked_entries(rows)


def seven_zip(command: list[str], maximum: int, timeout: int = 180) -> bytes:
    """Read bounded stdout/stderr and reap only our own extraction process."""
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector, buffers = selectors.DefaultSelector(), {"out": bytearray(), "err": bytearray()}
    for stream, label in ((child.stdout, "out"), (child.stderr, "err")):
        selector.register(stream, selectors.EVENT_READ, label)
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            if time.monotonic() >= deadline:
                raise CorpusError("host archive tool timeout")
            for key, _ in selector.select(min(0.25, max(0, deadline - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                target = buffers[key.data]
                if len(target) + len(data) > (maximum if key.data == "out" else 65536):
                    raise CorpusError("host archive output exceeds bound")
                target.extend(data)
        code = child.wait(timeout=max(0.01, deadline - time.monotonic()))
        if code != 0:
            raise CorpusError("host archive tool failed: " + buffers["err"].decode("utf-8", "replace")[:500])
        return bytes(buffers["out"])
    finally:
        selector.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        child.stdout.close()
        child.stderr.close()


def seven_entries(data: bytes, *, allow_unknown_installer_sizes: bool = False) -> list[dict]:
    text = data.decode("utf-8", "strict").replace("\r\n", "\n")
    if "\n----------\n" not in text:
        raise CorpusError("archive tool listing has no member boundary")
    rows, names = [], set()
    records = text.split("\n----------\n", 1)[1].strip().split("\n\n")
    if len(records) > MAX_MEMBERS:
        raise CorpusError("archive tool member count exceeds bound")
    for record in records:
        fields = {}
        for line in record.splitlines():
            if " = " not in line:
                raise CorpusError("malformed archive tool listing")
            key, value = line.split(" = ", 1)
            if key in fields:
                raise CorpusError("duplicate archive listing field")
            fields[key] = value
        name = fields.get("Path", "")
        normalized = safe_member(name)
        if normalized.casefold() in names:
            raise CorpusError("duplicate or case-aliased archive-tool member")
        names.add(normalized.casefold())
        linked = bool(fields.get("Symbolic Link") or fields.get("Hard Link")) or "l" in fields.get("Attributes", "").split(" ")[0]
        if linked:
            raise CorpusError("linked archive-tool member")
        if fields.get("Folder") == "+" or fields.get("Attributes", "").startswith("D"):
            continue
        # NSIS reports no expanded size for compressed installer helpers.
        # We never inspect or execute those helpers; the selected app archive
        # must still have an exact known extent before bounded extraction.
        if allow_unknown_installer_sizes and fields.get("Size") == "":
            continue
        try:
            size = int(fields["Size"])
        except (KeyError, ValueError) as error:
            raise CorpusError("missing archive member size") from error
        rows.append({"name": name, "bytes": size, "tool_name": name})
    return checked_entries(rows)


def asar_package(data: bytes) -> dict:
    """Decode only the packed root package.json, with Pickle/header bounds."""
    if len(data) < 16:
        raise CorpusError("truncated ASAR header")
    size_pickle, header_bytes, payload_bytes, json_bytes = struct.unpack_from("<4I", data)
    if size_pickle != 4 or header_bytes > MAX_ASAR_HEADER or header_bytes < 8 or payload_bytes + 4 != header_bytes or json_bytes > payload_bytes - 4:
        raise CorpusError("invalid ASAR Pickle/header extent")
    data_start = 8 + header_bytes
    if 16 + json_bytes > data_start or data_start > len(data):
        raise CorpusError("truncated ASAR JSON header")
    try:
        header = json.loads(data[16:16 + json_bytes])
        node = header["files"]["package.json"]
        if not isinstance(node, dict):
            raise CorpusError("ASAR package node is not an object")
        if node.get("unpacked") or "link" in node:
            raise CorpusError("root package.json is not a packed regular file")
        size, offset = node["size"], node["offset"]
        if isinstance(size, bool) or not isinstance(size, int) or not 0 < size <= MAX_PACKAGE_JSON or not isinstance(offset, str) or not re.fullmatch(r"0|[1-9][0-9]{0,15}", offset):
            raise CorpusError("invalid ASAR package extent")
        start = data_start + int(offset)
        if start + size > len(data):
            raise CorpusError("ASAR package extends beyond archive")
        package = json.loads(data[start:start + size])
        if not isinstance(package, dict):
            raise CorpusError("ASAR package is not an object")
        return package
    except (KeyError, TypeError, ValueError, UnicodeDecodeError) as error:
        raise CorpusError("invalid ASAR root package metadata") from error


def inspect_members(app: str, entries: list[dict], reader) -> dict:
    pin, native, package = PINS[app], [], None
    for entry in entries:
        name = entry["name"]
        if not name.lower().endswith(NATIVE_SUFFIXES) and not (app == "signal" and name.lower().endswith("/app.asar")):
            continue
        data = reader(entry)
        if len(data) != entry["bytes"]:
            raise CorpusError("member extraction differs from declared size")
        if app == "signal" and name.lower().endswith("/app.asar"):
            if package is not None:
                raise CorpusError("ambiguous packaged app.asar")
            package = asar_package(data)
            continue
        try:
            foreign = inventory.foreign_addon(data) if name.lower().endswith(".node") else None
            pe = ({**foreign, "guest_execution_verified": False, "app_functionality_verified": False}
                  if foreign else inventory.PEInventory(data).report())
        except inventory.PEError as error:
            raise CorpusError("invalid native member " + name + ": " + str(error)) from error
        native.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), **pe})
    mains = [row for row in native if row["path"].split("/")[-1].casefold() == pin["entry_point"].casefold()]
    if len(mains) != 1 or mains[0]["architecture"] != pin["architecture"]:
        raise CorpusError("missing/ambiguous publisher entry point or wrong architecture")
    if app == "signal":
        if not package or package.get("name") != "signal-desktop" or package.get("version") != pin["version"]:
            raise CorpusError("packaged Signal version does not match publisher pin")
        dependencies = package.get("dependencies", {})
        if not isinstance(dependencies, dict) or any(dependencies.get(name) != version for name, version in pin["native_dependencies"].items()):
            raise CorpusError("packaged Signal native dependency versions differ")
        if not any(row["path"].lower().endswith(".node") and row["format"] == "PE32+" and row["architecture"] == pin["architecture"] for row in native):
            raise CorpusError("Signal native addon payload absent")
    return {"entry_point": mains[0]["path"], "native_files": native,
            "packaged_app_version": package.get("version") if package else None,
            "native_dependency_versions": pin.get("native_dependencies") if package else None,
            "binary_version_resource_inspected": False,
            "declared_expanded_bytes": sum(row["bytes"] for row in entries), "archive_members": len(entries)}


def inspect_artifact(app: str, artifact: Path, seven: Path | None = None) -> dict:
    pin = PINS[app]
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(artifact, flags), "rb") as stream:
        before = inventory.file_identity(os.fstat(stream.fileno()))
        verified = artifact_digest(stream, pin)
        if app.startswith("onlyoffice"):
            with zipfile.ZipFile(stream) as archive:
                entries = zip_entries(archive)
                def reader(entry):
                    with archive.open(entry["archive_name"]) as member:
                        return bounded_read(member, entry["bytes"])
                report = inspect_members(app, entries, reader)
        else:
            if seven is None or not seven.is_absolute() or not seven.is_file():
                raise CorpusError("Signal needs an explicitly selected absolute host 7-Zip executable")
            seven = seven.resolve(strict=True)
            tool_digest = hashlib.sha256(inventory.read_regular(seven)).hexdigest()
            # An inherited descriptor prevents a path rename from substituting the input.
            # The host tool's descriptor is supplied by its own /proc parent path.
            source = f"/proc/{os.getpid()}/fd/{stream.fileno()}"
            entries = seven_entries(seven_zip([str(seven), "l", "-slt", "--", source], MAX_LISTING),
                                    allow_unknown_installer_sizes=True)
            nested = [row for row in entries if row["name"].casefold() == "$pluginsdir/app-64.7z"]
            if len(nested) != 1:
                raise CorpusError("Signal installer has no unique pinned x64 nested payload")
            payload = seven_zip([str(seven), "x", "-so", "--", source, nested[0]["tool_name"]], nested[0]["bytes"])
            if len(payload) != nested[0]["bytes"]:
                raise CorpusError("nested payload size mismatch")
            with tempfile.TemporaryDirectory(prefix="m98-signal-inventory-") as temporary:
                nested_path = Path(temporary) / "app-64.7z"
                nested_path.write_bytes(payload)
                del payload
                members = seven_entries(seven_zip([str(seven), "l", "-slt", "--", str(nested_path)], MAX_LISTING))
                def reader(entry):
                    return seven_zip([str(seven), "x", "-so", "--", str(nested_path), entry["tool_name"]], entry["bytes"])
                report = inspect_members(app, members, reader)
            if tool_digest != hashlib.sha256(inventory.read_regular(seven)).hexdigest():
                raise CorpusError("host archive tool changed during inventory")
            report["host_archive_tool"] = {"path": str(seven), "sha256": tool_digest}
        # Full second digest binds the bytes inventoried to the verified publisher file.
        after = artifact_digest(stream, pin)
        if verified != after or inventory.file_identity(os.fstat(stream.fileno())) != before:
            raise CorpusError("artifact changed during inventory")
    return {"schema": 1, "status": "PASS", "evidence_level": "publisher-integrity-and-static-loader-inventory",
            "app": app, "publisher_pin": pin, "pin_checked_utc": PIN_CHECKED_UTC,
            "artifact": {"path": str(artifact.resolve()), **verified}, **report,
            "windows98_execution_verified": False, "standalone_kernel64_execution_verified": False,
            "app_functionality_verified": False, "installer_or_application_executed": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=tuple(PINS), required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="new inventory receipt; existing files are never overwritten")
    parser.add_argument("--seven-zip", type=Path, help="absolute host extraction executable for Signal only")
    args = parser.parse_args(argv)
    if args.output.exists():
        parser.error("output already exists; choose a fresh receipt")
    try:
        receipt = inspect_artifact(args.app, args.artifact, args.seven_zip)
        # Exclusive creation also closes the exists()/open() race.
        with args.output.open("x", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except (CorpusError, OSError, zipfile.BadZipFile, UnicodeError) as error:
        parser.exit(1, "Corpus inventory failed: " + str(error) + "\n")
    print(json.dumps({"status": receipt["status"], "app": args.app, "native_files": len(receipt["native_files"]), "app_functionality_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
