#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare complete publisher packages for the existing standalone Kernel64 runner.

Three explicit stages: prepare extracts a pinned package into a new private tree;
image calls the existing productivity image builder; run starts its generic runner.
Nothing downloads, installs into Windows 98, changes peer source, or supplies a
synthetic success marker. Kernel64 accepts AMD64 PE32+ only. An x86 ONLYOFFICE
package is rejected before extraction. A startup diagnostic is never an app pass.
Run requires explicit firmware package directories and uses a sealed private -L
directory so relocating the QEMU executable cannot drop its PC/VGA boot data.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("required_app_corpus", ROOT / "tools/signal_desktop_corpus.py")
corpus = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus)
GIB = 1024**3
RESERVE = 20 * GIB
METADATA_MARGIN = 128 * 1024**2
RUN_WRITE_BUDGET = 256 * 1024**2
RUN_STDERR_BUDGET = 16 * 1024**2
RUN_POLL_SECONDS = 0.1
FIRMWARE_MAX_FILES = 64
FIRMWARE_MAX_BYTES = 32 * 1024**2
# The frozen peer scenario uses PC, standard VGA, and the multiboot ELF stub.
FIRMWARE_REQUIRED = frozenset(("bios-256k.bin", "vgabios-stdvga.bin", "kvmvapic.bin",
                               "multiboot.bin", "multiboot_dma.bin"))
FLAGS = {"windows98_execution_verified": False, "standalone_kernel64_execution_verified": False,
         "app_functionality_verified": False}
PEER_FILES = ("shizukudos/tests/run_k64_productivity.py", "shizukudos/tests/run_k64_electron.py",
              "shizukudos/tools/shzlib.py", "shizukudos/tools/qemu.py",
              "shizukudos/kernel64/autorun.c", "shizukudos/kernel64/ldr.c")


class HandoffError(ValueError):
    pass


def digest_file(path: Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise HandoffError("input is not a regular file")
        digest, total = hashlib.sha256(), 0
        for block in iter(lambda: stream.read(1024**2), b""):
            digest.update(block)
            total += len(block)
        if total != before.st_size or corpus.inventory.file_identity(before) != corpus.inventory.file_identity(os.fstat(stream.fileno())):
            raise HandoffError("input changed during hashing")
        return digest.hexdigest()


def read_json(path: Path) -> dict:
    try:
        result = json.loads(corpus.inventory.read_regular(path))
    except (ValueError, OSError) as error:
        raise HandoffError("cannot read bounded receipt") from error
    if not isinstance(result, dict):
        raise HandoffError("receipt must be an object")
    return result


def write_json(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def verify_inventory(app: str, receipt: dict) -> dict:
    pin = corpus.PINS.get(app)
    if pin is None or app not in ("signal", "onlyoffice", "onlyoffice_x64"):
        raise HandoffError("unknown pinned required application")
    if (receipt.get("schema") != 1 or receipt.get("status") != "PASS" or receipt.get("app") != app
            or receipt.get("publisher_pin") != pin or receipt.get("artifact", {}).get("publisher_digest_verified") is not True):
        raise HandoffError("inventory does not match the current publisher pin")
    if pin["architecture"] != "x64":
        raise HandoffError("standalone Kernel64 requires AMD64 PE32+; retain ia32 package for native porting separately")
    entry = corpus.safe_member(receipt.get("entry_point", ""))
    natives = receipt.get("native_files")
    if not isinstance(natives, list) or not natives:
        raise HandoffError("inventory has no native payload")
    mains = [row for row in natives if row.get("path") == entry]
    if len(mains) != 1 or mains[0].get("architecture") != "x64" or mains[0].get("format") != "PE32+":
        raise HandoffError("inventory entry is not a unique AMD64 PE32+ executable")
    for row in natives:
        corpus.safe_member(row.get("path", ""))
        if not isinstance(row.get("sha256"), str) or len(row["sha256"]) != 64:
            raise HandoffError("native member lacks its content digest")
    return pin


def validate_layout(entries: list[dict]) -> list[dict]:
    """Include every parent in Windows case-alias and file/directory checks."""
    entries = corpus.checked_entries(entries)
    paths = {}
    for row in entries:
        parts = row["name"].split("/")
        for i in range(1, len(parts) + 1):
            name = "/".join(parts[:i])
            kind = "file" if i == len(parts) else "directory"
            if len(parts[i - 1].encode("utf-16-le")) > 510:
                raise HandoffError("member component exceeds Windows/FAT name bound")
            previous = paths.get(name.casefold())
            if previous is not None and previous != (name, kind):
                raise HandoffError("Windows parent alias or file/directory collision")
            paths[name.casefold()] = (name, kind)
    return entries


def check_space(parent: Path, required: int, *, initial: bool = False) -> None:
    free = shutil.disk_usage(parent).free
    margin = METADATA_MARGIN if initial else 0
    if required < 0 or free < required + RESERVE + margin:
        raise HandoffError(f"disk reserve gate: free={free}, required={required}, reserve={RESERVE}, metadata_margin={margin}")


def extraction_budget(entries: list[dict], parent: Path) -> int:
    block = os.statvfs(parent).f_frsize or 4096
    parents = {""}
    for row in entries:
        parts = row["name"].split("/")
        parents.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return sum((row["bytes"] + block - 1) // block * block for row in entries) + len(parents) * block


def checked_package_entries(entries: list[dict], inventory: dict, parent: Path) -> list[dict]:
    entries = validate_layout(entries)
    if len(entries) != inventory["archive_members"] or sum(row["bytes"] for row in entries) != inventory["declared_expanded_bytes"]:
        raise HandoffError("complete archive listing differs from inventory")
    check_space(parent, extraction_budget(entries, parent), initial=True)
    return entries


def extract_zip(archive: zipfile.ZipFile, entries: list[dict], destination: Path) -> None:
    for row in validate_layout(entries):
        check_space(destination, 0)
        path = destination / row["name"]
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        with os.fdopen(os.open(path, flags, 0o600), "wb") as target, archive.open(row["archive_name"]) as source:
            remaining = row["bytes"]
            while remaining:
                block = source.read(min(1024**2, remaining))
                if not block:
                    raise HandoffError("ZIP member shorter than declared extent")
                check_space(destination, 0)
                target.write(block)
                remaining -= len(block)
            if source.read(1):
                raise HandoffError("ZIP member larger than declared extent")


def extract_signal(seven: Path, archive: Path, destination: Path) -> None:
    """Run one prevalidated extraction with a live reserve and bounded host log."""
    command = [str(seven), "x", "-y", "-aoa", "-o" + str(destination), "--", str(archive)]
    with tempfile.TemporaryFile(dir=destination.parent) as output:
        check_space(destination, 0)
        child = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 600
        try:
            while child.poll() is None:
                check_space(destination, 0)
                if os.fstat(output.fileno()).st_size > corpus.MAX_LISTING:
                    raise HandoffError("archive extraction host output exceeds bound")
                if time.monotonic() >= deadline:
                    raise HandoffError("archive extraction timeout")
                try:
                    child.wait(timeout=RUN_POLL_SECONDS)
                except subprocess.TimeoutExpired:
                    pass
            check_space(destination, 0)
            if child.returncode != 0 or os.fstat(output.fileno()).st_size > corpus.MAX_LISTING:
                raise HandoffError("archive extraction failed or exceeded host output bound")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()


def tree_manifest(tree: Path, entries: list[dict] | None = None) -> tuple[list[dict], str]:
    """Same complete-content fingerprint as peer productivity.tree_fingerprint."""
    root = tree.resolve(strict=True)
    rows, digest = [], hashlib.sha256()
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise HandoffError("tree contains a link or special file")
        if not stat.S_ISREG(info.st_mode):
            continue
        relative = path.relative_to(root).as_posix()
        encoded = relative.encode()
        digest.update(len(encoded).to_bytes(4, "little"))
        digest.update(encoded)
        digest.update(info.st_size.to_bytes(8, "little"))
        member_digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024**2), b""):
                digest.update(block)
                member_digest.update(block)
        if corpus.inventory.file_identity(info) != corpus.inventory.file_identity(path.lstat()):
            raise HandoffError("tree member changed during hashing")
        rows.append({"path": relative, "bytes": info.st_size, "sha256": member_digest.hexdigest()})
    validate_layout([{"name": row["path"], "bytes": row["bytes"]} for row in rows])
    if entries is not None:
        wanted = {row["name"]: row["bytes"] for row in entries}
        if {row["path"]: row["bytes"] for row in rows} != wanted:
            raise HandoffError("extracted tree is incomplete or has unexpected members")
    return rows, digest.hexdigest()


def source_hashes() -> dict:
    return {str(path.relative_to(ROOT)): digest_file(path) for path in
            (Path(__file__).resolve(), ROOT / "tools/signal_desktop_corpus.py", ROOT / "tools/modern_app_inventory.py")}


def prepare(app: str, artifact: Path, inventory_path: Path, tree: Path, receipt_path: Path, seven: Path | None = None) -> dict:
    inventory = read_json(inventory_path)
    pin = verify_inventory(app, inventory)  # architecture gate precedes any payload writes
    if tree.exists() or receipt_path.exists() or tree.is_symlink() or receipt_path.is_symlink():
        raise HandoffError("choose new tree and receipt paths")
    tree.parent.resolve(strict=True)
    receipt_path.parent.resolve(strict=True)
    required = inventory["declared_expanded_bytes"] + (pin["bytes"] if app == "signal" else 0)
    check_space(tree.parent, required, initial=True)
    sources = source_hashes()
    inventory_hash = digest_file(inventory_path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    temporary = Path(tempfile.mkdtemp(prefix=".required-app-", dir=tree.parent))
    moved = False
    try:
        with os.fdopen(os.open(artifact, flags), "rb") as stream:
            verified = corpus.artifact_digest(stream, pin)
            if verified != {key: inventory["artifact"][key] for key in ("bytes", "sha256", "publisher_digest_verified")}:
                raise HandoffError("inventory and source artifact differ")
            if app != "signal":
                with zipfile.ZipFile(stream) as archive:
                    entries = checked_package_entries(corpus.zip_entries(archive), inventory, tree.parent)
                    extract_zip(archive, entries, temporary)
                archive_tool = None
            else:
                if seven is None or not seven.is_absolute() or not seven.is_file():
                    raise HandoffError("Signal needs an explicit absolute host 7-Zip executable")
                tool_hash = digest_file(seven)
                if inventory.get("host_archive_tool") != {"path": str(seven.resolve()), "sha256": tool_hash}:
                    raise HandoffError("host archive tool differs from inventory")
                source = f"/proc/{os.getpid()}/fd/{stream.fileno()}"
                outer = corpus.seven_entries(corpus.seven_zip([str(seven), "l", "-slt", "--", source], corpus.MAX_LISTING), allow_unknown_installer_sizes=True)
                nested = [row for row in outer if row["name"].casefold() == "$pluginsdir/app-64.7z"]
                if len(nested) != 1:
                    raise HandoffError("Signal has no unique app-64.7z")
                payload = corpus.seven_zip([str(seven), "x", "-so", "--", source, nested[0]["tool_name"]], nested[0]["bytes"])
                if len(payload) != nested[0]["bytes"]:
                    raise HandoffError("nested payload extent mismatch")
                with tempfile.TemporaryDirectory(prefix=".signal-archive-", dir=tree.parent) as archive_dir:
                    nested_path = Path(archive_dir) / "app-64.7z"
                    nested_path.write_bytes(payload)
                    del payload
                    entries = checked_package_entries(corpus.seven_entries(corpus.seven_zip([str(seven), "l", "-slt", "--", str(nested_path)], corpus.MAX_LISTING)), inventory, tree.parent)
                    # One full extraction of the immutable, prevalidated solid archive;
                    # decompressing it per member would repeatedly scan ~500 MiB.
                    extract_signal(seven, nested_path, temporary)
                if digest_file(seven) != tool_hash:
                    raise HandoffError("host archive tool changed")
                archive_tool = {"path": str(seven.resolve()), "sha256": tool_hash}
            if len(entries) != inventory["archive_members"] or sum(row["bytes"] for row in entries) != inventory["declared_expanded_bytes"]:
                raise HandoffError("complete archive listing differs from inventory")
            members, fingerprint = tree_manifest(temporary, entries)
            mapped = {row["path"]: row for row in members}
            for native in inventory["native_files"]:
                if mapped.get(native["path"]) != {key: native[key] for key in ("path", "bytes", "sha256")}:
                    raise HandoffError("native member differs from the inspected package")
            entry_pe = corpus.inventory.PEInventory(corpus.inventory.read_regular(temporary / inventory["entry_point"])).report()
            if entry_pe["architecture"] != "x64" or entry_pe["format"] != "PE32+":
                raise HandoffError("extracted entry is not AMD64 PE32+")
            if corpus.artifact_digest(stream, pin) != verified or digest_file(inventory_path) != inventory_hash or source_hashes() != sources:
                raise HandoffError("source, inventory or artifact changed during preparation")
        temporary.rename(tree)
        moved = True
        check_space(tree.parent, 0)
        result = {"schema": 1, "status": "PREPARED", "stage": "complete-publisher-tree", "app": app,
                  "publisher_pin": pin, "artifact": {"path": str(artifact.resolve()), **verified},
                  "inventory": {"path": str(inventory_path.resolve()), "sha256": inventory_hash},
                  "tree": str(tree.resolve()), "entry_point": inventory["entry_point"], "members": members,
                  "tree_content_sha256": fingerprint, "source_hashes": sources, "host_archive_tool": archive_tool,
                  "payload_executed": False, **FLAGS}
        write_json(receipt_path, result)
        return result
    finally:
        if not moved:
            shutil.rmtree(temporary)


def verified_tree(receipt_path: Path) -> tuple[dict, Path, list[dict]]:
    receipt = read_json(receipt_path)
    if receipt.get("status") != "PREPARED" or receipt.get("stage") != "complete-publisher-tree":
        raise HandoffError("not a prepared package receipt")
    app, pin = receipt.get("app"), receipt.get("publisher_pin")
    if app not in corpus.PINS or pin != corpus.PINS[app] or pin["architecture"] != "x64":
        raise HandoffError("prepared package does not match current AMD64 pin")
    if receipt.get("source_hashes") != source_hashes():
        raise HandoffError("preparation source changed; make a new source-bound receipt")
    tree = Path(receipt["tree"])
    if tree.is_symlink():
        raise HandoffError("tree root is a symlink")
    members, fingerprint = tree_manifest(tree)
    if members != receipt.get("members") or fingerprint != receipt.get("tree_content_sha256"):
        raise HandoffError("prepared publisher tree changed")
    entry = corpus.safe_member(receipt["entry_point"])
    entry_pe = corpus.inventory.PEInventory(corpus.inventory.read_regular(tree / entry)).report()
    if entry_pe["architecture"] != "x64" or entry_pe["format"] != "PE32+":
        raise HandoffError("entry is not AMD64 PE32+")
    return receipt, tree, members


def load_peer(peer: Path):
    peer = peer.resolve(strict=True)
    hashes = {name: digest_file(peer / name) for name in PEER_FILES}
    tests = peer / "shizukudos/tests"
    sys.path.insert(0, str(tests))
    sys.path.insert(0, str(peer / "shizukudos/tools"))
    # Each CLI invocation selects one worktree; avoid cross-worktree module reuse.
    for name in ("run_k64_electron", "run_k64_productivity", "shzlib", "qemu"):
        loaded = sys.modules.get(name)
        if loaded is not None and not Path(loaded.__file__).resolve().is_relative_to(peer):
            raise HandoffError("runtime helper from a different worktree is already loaded")
    previous_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        import run_k64_productivity as productivity
    finally:
        sys.dont_write_bytecode = previous_bytecode
    if not Path(productivity.__file__).resolve().is_relative_to(peer):
        raise HandoffError("runtime helper resolved outside selected peer")
    if {name: digest_file(peer / name) for name in PEER_FILES} != hashes:
        raise HandoffError("peer helper source changed during import")
    return productivity, hashes


def seal_runtime_inputs(inputs: dict[str, Path], directory: Path) -> dict:
    """Copy only regular inputs into an owned directory before any guest starts."""
    records = {}
    directory.mkdir()
    filenames = {"boot_stub": "boot.elf", "kernel": "KERNEL64S.BIN", "win64_initrd": "WIN64.IMG", "qemu": "qemu"}
    for name, source in inputs.items():
        source = source.resolve(strict=True)
        target = directory / filenames[name]
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream, target.open("xb") as output:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise HandoffError("runtime input is not a regular file")
            digest = hashlib.sha256()
            total = 0
            for block in iter(lambda: stream.read(1024**2), b""):
                check_space(directory, 0)
                output.write(block)
                digest.update(block)
                total += len(block)
            if total != before.st_size or corpus.inventory.file_identity(before) != corpus.inventory.file_identity(os.fstat(stream.fileno())):
                raise HandoffError("runtime input changed while sealing")
        target.chmod(0o500 if name == "qemu" else 0o400)
        checksum = digest.hexdigest()
        if digest_file(source) != checksum or digest_file(target) != checksum:
            raise HandoffError("runtime input changed before sealed receipt")
        records[name] = {"source_path": str(source), "path": str(target.resolve()), "bytes": total, "sha256": checksum}
    return records


def firmware_manifest(directories: list[Path]) -> dict:
    """Inventory explicit package data roots without guessing host search paths."""
    if not directories or len(directories) > 8:
        raise HandoffError("one to eight explicit firmware directories required")
    roots, files, total = [], {}, 0
    for requested in directories:
        if not requested.is_absolute():
            raise HandoffError("firmware directory must be absolute")
        root = requested.resolve(strict=True)
        if not root.is_dir() or str(root) in roots:
            raise HandoffError("firmware directory is not a unique directory")
        roots.append(str(root))
        for entry in sorted(root.iterdir()):
            if entry.suffix.lower() not in (".bin", ".rom"):
                continue
            if entry.name in files:
                raise HandoffError("ambiguous firmware basename: " + entry.name)
            # Distribution data may link to a separate firmware package. Keep
            # both paths and the link text; copy the resolved regular object.
            link = os.readlink(entry) if entry.is_symlink() else None
            source = entry.resolve(strict=True)
            before = source.stat()
            if not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
                raise HandoffError("firmware input is not a nonempty regular file")
            total += before.st_size
            if len(files) + 1 > FIRMWARE_MAX_FILES or total > FIRMWARE_MAX_BYTES:
                raise HandoffError("firmware inventory exceeds bounded count or bytes")
            checksum = digest_file(source)
            if (entry.resolve(strict=True) != source
                    or (os.readlink(entry) if entry.is_symlink() else None) != link
                    or corpus.inventory.file_identity(source.stat()) != corpus.inventory.file_identity(before)):
                raise HandoffError("firmware input changed during inventory")
            files[entry.name] = {"source_entry": str(entry), "source_path": str(source),
                                 "source_symlink": link, "bytes": before.st_size, "sha256": checksum}
    if not FIRMWARE_REQUIRED.issubset(files):
        raise HandoffError("required PC/VGA/multiboot firmware missing: " + ", ".join(sorted(FIRMWARE_REQUIRED - files.keys())))
    return {"source_directories": roots, "files": files, "bytes": total}


def firmware_sources_preserved(manifest: dict) -> bool:
    try:
        for row in manifest["files"].values():
            entry, source = Path(row["source_entry"]), Path(row["source_path"])
            if (entry.resolve(strict=True) != source
                    or (os.readlink(entry) if entry.is_symlink() else None) != row["source_symlink"]
                    or source.stat().st_size != row["bytes"] or digest_file(source) != row["sha256"]):
                return False
    except (OSError, ValueError):
        return False
    return True


def seal_firmware(manifest: dict, directory: Path) -> dict:
    if not firmware_sources_preserved(manifest):
        raise HandoffError("firmware input changed before sealing")
    directory.mkdir()
    records = {}
    for name, row in manifest["files"].items():
        source, target = Path(row["source_path"]), directory / name
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        with os.fdopen(descriptor, "rb") as stream, target.open("xb") as output:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size != row["bytes"]:
                raise HandoffError("firmware input changed before copy")
            checksum, total = hashlib.sha256(), 0
            for block in iter(lambda: stream.read(1024**2), b""):
                check_space(directory, 0)
                output.write(block)
                checksum.update(block)
                total += len(block)
                if total > row["bytes"]:
                    raise HandoffError("firmware input grew during copy")
            if (total != row["bytes"] or checksum.hexdigest() != row["sha256"]
                    or corpus.inventory.file_identity(before) != corpus.inventory.file_identity(os.fstat(stream.fileno()))):
                raise HandoffError("firmware input changed during copy")
        target.chmod(0o400)
        if digest_file(target) != row["sha256"]:
            raise HandoffError("sealed firmware digest mismatch")
        records[name] = {**row, "path": str(target.resolve())}
    if not firmware_sources_preserved(manifest):
        raise HandoffError("firmware source changed before sealed receipt")
    return {"path": str(directory.resolve()), "source_directories": manifest["source_directories"],
            "files": records, "bytes": manifest["bytes"]}


def sealed_firmware_preserved(sealed: dict) -> bool:
    directory = Path(sealed["path"])
    try:
        if directory.is_symlink() or set(path.name for path in directory.iterdir()) != set(sealed["files"]):
            return False
        return all(Path(row["path"]).parent == directory and Path(row["path"]).stat().st_size == row["bytes"]
                   and digest_file(Path(row["path"])) == row["sha256"] for row in sealed["files"].values())
    except (OSError, ValueError):
        return False


class GuardedSubprocess:
    """Bound this runner's one QEMU child, including its unlinked snapshot file."""
    def __init__(self, qemu: Path, out: Path, firmware: dict):
        self.qemu, self.out = qemu.resolve(), out.resolve()
        self.firmware = firmware
        self.snapshot = self.out / "qemu-snapshot"
        self.snapshot.mkdir()
        self.output_path = self.out / "qemu-host-output.log"
        self.record = {"write_budget_bytes": RUN_WRITE_BUDGET, "stderr_budget_bytes": RUN_STDERR_BUDGET,
                       "reserve_bytes": RESERVE, "poll_seconds": RUN_POLL_SECONDS,
                       "snapshot_directory": str(self.snapshot), "peak_written_bytes": 0,
                       "minimum_free_bytes": None, "termination_reason": None}
        self.child = None
        self.output = None
        self.reader = None

    def __getattr__(self, name):
        return getattr(subprocess, name)

    def written_bytes(self, pid: int) -> tuple[int, int]:
        # snapshot=on normally unlinks the temporary qcow2 after opening it.
        # Read only this child's descriptors; directory walking would miss it.
        overlay = 0
        try:
            descriptors = list((Path("/proc") / str(pid) / "fd").iterdir())
        except FileNotFoundError:
            descriptors = []
        for fd in descriptors:
            try:
                location = os.readlink(fd)
                if location.startswith(str(self.snapshot) + "/"):
                    overlay += fd.stat().st_blocks * 512
            except (FileNotFoundError, ProcessLookupError):
                continue
        stderr = self.output_path.stat().st_size if self.output_path.exists() else 0
        serial = self.out / "serial.log"
        serial_bytes = serial.stat().st_size if serial.exists() else 0
        return overlay + stderr + serial_bytes, stderr

    def Popen(self, command, **kwargs):
        if self.child is not None or Path(command[0]).resolve() != self.qemu:
            raise HandoffError("runtime attempted an unowned or additional child")
        if any(arg.startswith("-L") or arg in ("-bios", "-option-rom", "-fw_cfg")
               or "romfile=" in arg for arg in command[1:]):
            raise HandoffError("runtime attempted to override sealed firmware")
        if not sealed_firmware_preserved(self.firmware):
            raise HandoffError("sealed firmware changed before guest launch")
        command = [command[0], "-L", self.firmware["path"], *command[1:]]
        self.record["actual_qemu_command"] = list(command)
        self.record["firmware_directory"] = self.firmware["path"]
        check_space(self.out, RUN_WRITE_BUDGET)
        self.output = self.output_path.open("xb")
        environment = dict(kwargs.pop("env", os.environ))
        environment["TMPDIR"] = str(self.snapshot)
        kwargs["env"], kwargs["stdout"], kwargs["stderr"] = environment, self.output, subprocess.STDOUT
        self.child = subprocess.Popen(command, **kwargs)
        owner = self

        class Child:
            @property
            def stdout(self):
                owner.output.flush()
                if owner.reader is None:
                    owner.reader = owner.output_path.open("rb")
                return owner.reader

            def kill(self):
                owner.child.kill()

            def wait(self, timeout=None):
                deadline = None if timeout is None else time.monotonic() + timeout
                while owner.child.poll() is None:
                    written, stderr = owner.written_bytes(owner.child.pid)
                    free = shutil.disk_usage(owner.out).free
                    owner.record["peak_written_bytes"] = max(owner.record["peak_written_bytes"], written)
                    minimum = owner.record["minimum_free_bytes"]
                    owner.record["minimum_free_bytes"] = free if minimum is None else min(minimum, free)
                    reason = ("disk reserve crossed" if free < RESERVE else "guest write budget crossed" if written > RUN_WRITE_BUDGET
                              else "host output budget crossed" if stderr > RUN_STDERR_BUDGET else None)
                    if reason:
                        owner.record["termination_reason"] = reason
                        owner.child.kill()
                        return owner.child.wait()
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise subprocess.TimeoutExpired(command, timeout)
                    try:
                        return owner.child.wait(timeout=min(RUN_POLL_SECONDS, remaining) if remaining is not None else RUN_POLL_SECONDS)
                    except subprocess.TimeoutExpired:
                        pass
                return owner.child.returncode

        return Child()

    def close(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()
            self.child.wait()
        if self.output is not None:
            self.output.close()
        if self.reader is not None:
            self.reader.close()


def runtime_spec(app: str, entry: str, timeout: int) -> tuple[dict, bytes]:
    if not 1 <= timeout <= 300:
        raise HandoffError("guest timeout outside diagnostic bound")
    volume = "signal" if app == "signal" else "onlyoffice"
    exe = corpus.safe_member(entry).replace("/", "\\")
    args = "--no-sandbox --disable-gpu --enable-logging=stderr --v=0 --no-first-run --user-data-dir=D:\\sigprofile" if app == "signal" else ""
    if any(char.isspace() for char in exe):
        raise HandoffError("current generic runner needs an entry without command-line whitespace")
    # Match the selected existing runner's control generation byte for byte.
    # The actual publisher entry is resolved relative to cwd, not by a shell.
    command = f"{exe} {args}"
    cwd = f"D:\\{volume}"
    image = cwd + "\\" + exe
    if len(command) > 511 or len(image) > 199 or len(cwd) > 159:
        raise HandoffError("autorun field exceeds current kernel bounds")
    control = f"image={image}\r\ncmdline={command}\r\ncwd={cwd}\r\ntimeout={timeout}\r\n".encode("ascii")
    return {"dir": volume, "exe": exe, "args": args, "expect": None}, control


def build_image(prepared_path: Path, peer: Path, image: Path, receipt_path: Path, guest_timeout: int) -> dict:
    peer = peer.resolve(strict=True)
    prepared, tree, members = verified_tree(prepared_path)
    if image.exists() or image.is_symlink() or receipt_path.exists() or Path(str(image) + ".json").exists():
        raise HandoffError("choose a fresh owned image and receipt")
    image.parent.resolve(strict=True)
    receipt_path.parent.resolve(strict=True)
    productivity, peer_hashes = load_peer(peer)
    spec, control = runtime_spec(prepared["app"], prepared["entry_point"], guest_timeout)
    total = sum(row["bytes"] for row in members)
    image_bytes = ((total * 11 // 10 >> 20) + 256) << 20
    check_space(image.parent, image_bytes)
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            raise HandoffError("image builder tool missing: " + tool)
    preparation_hash = digest_file(prepared_path)
    listing = productivity.build_product_image(image, tree, spec["dir"], productivity.runner.build_image)
    check_space(image.parent, 0)
    with tempfile.TemporaryDirectory(prefix=".required-control-", dir=image.parent) as control_dir:
        productivity.runner.put_file(image, control, "K64RUN.TXT", Path(control_dir))
    check_space(image.parent, 0)
    if digest_file(prepared_path) != preparation_hash or verified_tree(prepared_path)[0] != prepared:
        raise HandoffError("publisher preparation changed during image build")
    if {name: digest_file(peer / name) for name in PEER_FILES} != peer_hashes:
        raise HandoffError("peer runtime source changed during image build")
    result = {"schema": 1, "status": "PREPARED", "stage": "standalone-kernel64-image", "app": prepared["app"],
              "prepared_receipt": {"path": str(prepared_path.resolve()), "sha256": preparation_hash},
              "image": {"path": str(image.resolve()), "bytes": image.stat().st_size, "sha256": digest_file(image)},
              "image_builder_stamp_sha256": digest_file(Path(str(image) + ".json")),
              "runtime_worktree": str(peer.resolve()), "runtime_source_hashes": peer_hashes,
              "spec": spec, "control_base64": base64.b64encode(control).decode(), "guest_timeout": guest_timeout,
              "tree_files": len(listing), "source_hashes": source_hashes(), "network_attached": False,
              "payload_executed": False, **FLAGS}
    write_json(receipt_path, result)
    return result


def run_image(receipt_path: Path, out: Path, qemu: Path, accel: str, timeout: int, memory: int,
              firmware_directories: list[Path]) -> int:
    receipt = read_json(receipt_path)
    if receipt.get("status") != "PREPARED" or receipt.get("stage") != "standalone-kernel64-image" or receipt.get("source_hashes") != source_hashes():
        raise HandoffError("not a current source-bound Kernel64 image receipt")
    if out.exists() or out.is_symlink() or not qemu.is_absolute() or not qemu.is_file() or not 1 <= timeout <= 600 or not 512 <= memory <= 8192:
        raise HandoffError("new output, absolute QEMU, and bounded run limits required")
    prepared_path = Path(receipt["prepared_receipt"]["path"])
    if digest_file(prepared_path) != receipt["prepared_receipt"]["sha256"]:
        raise HandoffError("prepared receipt changed")
    prepared, tree, members = verified_tree(prepared_path)
    if receipt.get("app") != prepared["app"]:
        raise HandoffError("image receipt and prepared publisher target differ")
    image = Path(receipt["image"]["path"])
    if image.stat().st_size != receipt["image"]["bytes"] or digest_file(image) != receipt["image"]["sha256"]:
        raise HandoffError("prepared image changed")
    check_space(image.parent, 0)
    out.parent.resolve(strict=True)
    productivity, peer_hashes = load_peer(Path(receipt["runtime_worktree"]))
    if peer_hashes != receipt["runtime_source_hashes"]:
        raise HandoffError("peer runtime source changed; build a fresh image receipt")
    runner = productivity.runner
    runtime_inputs = {"boot_stub": runner.K64S / "boot.elf", "kernel": runner.K64S / "KERNEL64S.BIN",
                      "win64_initrd": runner.WIN64 / "WIN64.IMG", "qemu": qemu}
    firmware = firmware_manifest(firmware_directories)
    copy_bytes = sum(path.stat().st_size for path in runtime_inputs.values()) + firmware["bytes"] + FIRMWARE_MAX_FILES * 4096
    check_space(out.parent, copy_bytes + RUN_WRITE_BUDGET)
    input_hashes = {name: {"path": str(path.resolve()), "sha256": digest_file(path), "bytes": path.stat().st_size}
                    for name, path in runtime_inputs.items()}
    handoff_hash = digest_file(receipt_path)
    spec, control = runtime_spec(receipt["app"], prepared["entry_point"], receipt["guest_timeout"])
    if spec != receipt["spec"] or base64.b64encode(control).decode() != receipt["control_base64"]:
        raise HandoffError("runtime control differs from fixed diagnostic scenario")
    name = "required_" + receipt["app"]
    original = (runner.find_exe, runner.classify, runner.build_image, runner.put_file, sys.argv,
                runner.K64S, runner.WIN64, getattr(runner, "subprocess", subprocess))
    if name in runner.APPS:
        raise HandoffError("runtime application key already owned")
    out.mkdir()
    sealed_inputs = seal_runtime_inputs(runtime_inputs, out / "runtime-inputs")
    if any(row["sha256"] != input_hashes[key]["sha256"] for key, row in sealed_inputs.items()):
        raise HandoffError("runtime input changed before sealing")
    sealed_firmware = seal_firmware(firmware, out / "runtime-firmware")
    write_json(out / "runtime-seal.json", {"schema": 1, "stage": "sealed-standalone-runtime-inputs",
               "required_handoff_receipt_sha256": handoff_hash, "image_sha256": receipt["image"]["sha256"],
               "runtime_worktree": receipt["runtime_worktree"], "runtime_source_hashes": peer_hashes,
               "source_hashes": source_hashes(), "sealed_runtime_input_hashes": sealed_inputs,
               "sealed_firmware": sealed_firmware,
               "payload_executed": False, **FLAGS})
    guard = GuardedSubprocess(Path(sealed_inputs["qemu"]["path"]), out, sealed_firmware)
    runner.K64S = runner.WIN64 = out / "runtime-inputs"
    runner.subprocess = guard
    runner.APPS[name] = spec
    runner.find_exe = lambda selected_tree, selected_name: spec["exe"] if Path(selected_tree).resolve() == tree.resolve() and selected_name == spec["exe"] else None
    runner.classify = lambda serial, expect: productivity.classify_product(serial, expect, original[1])
    def sealed_builder(selected_image, selected_tree, volume, overlay=None):
        if Path(selected_image).resolve() != image.resolve() or Path(selected_tree).resolve() != tree.resolve() or volume != spec["dir"] or overlay:
            raise HandoffError("runner attempted a different image/tree/overlay")
        return [(row["path"], row["bytes"]) for row in members]
    def sealed_control(selected_image, data, filename, folder):
        if Path(selected_image).resolve() != image.resolve() or filename != "K64RUN.TXT" or data != control:
            raise HandoffError("runner attempted to change the sealed autorun control")
    runner.build_image, runner.put_file = sealed_builder, sealed_control
    sys.argv = [str(Path(runner.__file__)), "--app", name, "--tree", str(tree), "--image", str(image), "--out", str(out),
                "--qemu", sealed_inputs["qemu"]["path"], "--accel", accel, "--memory", str(memory), "--timeout", str(timeout),
                "--guest-timeout", str(receipt["guest_timeout"])]
    try:
        code = runner.main()
    finally:
        runner.find_exe, runner.classify, runner.build_image, runner.put_file, sys.argv, runner.K64S, runner.WIN64, runner.subprocess = original
        runner.APPS.pop(name, None)
        guard.close()
    result_path = out / "result.json"
    if result_path.exists():
        result = read_json(result_path)
        result.update({"product": receipt["app"], "product_version": prepared["publisher_pin"]["version"],
                       "evidence_level": "standalone-kernel64-packaged-startup-diagnostic",
                       "guest_os": "ShizukuDOS Kernel64 standalone", "app_functionality_verified": False,
                       "windows98_execution_verified": False, "network_attached": False,
                       "required_handoff_receipt_sha256": handoff_hash, "runtime_input_hashes": input_hashes,
                       "sealed_runtime_input_hashes": sealed_inputs,
                       "sealed_firmware": sealed_firmware,
                       "sealed_firmware_preserved": sealed_firmware_preserved(sealed_firmware),
                       "firmware_sources_preserved": firmware_sources_preserved(firmware),
                       "actual_qemu_command": guard.record.get("actual_qemu_command"),
                       "sealed_runtime_inputs_preserved": all(digest_file(Path(row["path"])) == row["sha256"] for row in sealed_inputs.values()),
                       "resource_guard": guard.record,
                       "runtime_inputs_preserved": all(digest_file(path) == input_hashes[name]["sha256"] for name, path in runtime_inputs.items()),
                       "runtime_sources_preserved": {name: digest_file(Path(receipt["runtime_worktree"]) / name) for name in PEER_FILES} == peer_hashes,
                       "handoff_receipt_preserved": digest_file(receipt_path) == handoff_hash,
                       "tree_preserved": tree_manifest(tree)[1] == prepared["tree_content_sha256"],
                       "image_preserved": digest_file(image) == receipt["image"]["sha256"]})
        # The runner has no product functionality marker for either real app.
        # Preserve its FAIL diagnostic even if process creation or clean exit occurred.
        result["status"] = "FAIL"
        runner.shzlib.write_json(result_path, result)
    return 2 if code == 2 else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    stages = parser.add_subparsers(dest="stage", required=True)
    prepare_parser = stages.add_parser("prepare", allow_abbrev=False)
    prepare_parser.add_argument("--app", choices=("signal", "onlyoffice", "onlyoffice_x64"), required=True)
    for option in ("artifact", "inventory", "tree", "receipt"):
        prepare_parser.add_argument("--" + option, type=Path, required=True)
    prepare_parser.add_argument("--seven-zip", type=Path)
    image_parser = stages.add_parser("image", allow_abbrev=False)
    for option in ("prepared", "runtime-worktree", "image", "receipt"):
        image_parser.add_argument("--" + option, type=Path, required=True)
    image_parser.add_argument("--guest-timeout", type=int, default=60)
    run_parser = stages.add_parser("run", allow_abbrev=False)
    for option in ("receipt", "out", "qemu"):
        run_parser.add_argument("--" + option, type=Path, required=True)
    run_parser.add_argument("--firmware-dir", type=Path, action="append", required=True,
                            help="explicit PC, VGA, and multiboot firmware package directory; repeat for split packages")
    run_parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    run_parser.add_argument("--timeout", type=int, default=90)
    run_parser.add_argument("--memory", type=int, default=4096)
    args = parser.parse_args(argv)
    try:
        if args.stage == "prepare":
            result = prepare(args.app, args.artifact, args.inventory, args.tree, args.receipt, args.seven_zip)
        elif args.stage == "image":
            result = build_image(args.prepared, args.runtime_worktree, args.image, args.receipt, args.guest_timeout)
        else:
            return run_image(args.receipt, args.out, args.qemu, args.accel, args.timeout, args.memory, args.firmware_dir)
    except (HandoffError, corpus.CorpusError, corpus.inventory.PEError, OSError, ValueError, KeyError, TypeError, RuntimeError, zipfile.BadZipFile) as error:
        parser.exit(2, "BLOCKED: " + str(error) + "\n")
    print(json.dumps({key: result[key] for key in ("status", "stage", "app", "app_functionality_verified")}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
