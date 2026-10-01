#!/usr/bin/env python3
"""Bind real thin-archive members and observed compiler inputs without building.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
The only write is a new JSON receipt under --work. No guest is launched.
An optional existing linked PE is a post-link observation, not retrospective
proof of the object bytes used by an earlier link.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys

FILE_LIMIT = 256 * 1024 ** 2
RECEIPT_LIMIT = 8 * 1024 ** 2
FLOOR = 20 * 1024 ** 3


def canonical(value) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_path(path: Path, work: Path, exists=True) -> Path:
    absolute = Path(os.path.abspath(path))
    if not absolute.is_relative_to(work):
        raise ValueError("path is outside the private work area: " + str(path))
    cursor = work
    for part in absolute.relative_to(work).parts:
        cursor /= part
        if cursor.is_symlink():
            raise ValueError("private paths must not traverse symlinks: " + str(cursor))
    resolved = absolute.resolve(strict=exists)
    if resolved != absolute or not resolved.is_relative_to(work):
        raise ValueError("private path resolution changed: " + str(path))
    return absolute


def file_pin(path: Path) -> tuple[dict, tuple]:
    declared = Path(os.path.abspath(path))
    resolved = declared.resolve(strict=True)
    fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= FILE_LIMIT:
            raise ValueError("pin input must be a bounded nonempty regular file: " + str(path))
        value = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 ** 2)
            if not block:
                break
            value.update(block)
        after = os.fstat(fd)
        named_after = resolved.stat(follow_symlinks=False)
    finally:
        os.close(fd)
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if (identity(before) != identity(after) or identity(named_after) != identity(after)
            or declared.resolve(strict=True) != resolved):
        raise ValueError("file changed while hashing: " + str(path))
    return {"path": str(declared), "resolved_path": str(resolved), "bytes": before.st_size,
            "sha256": value.hexdigest()}, identity(before)


def command(argv: list[str], cwd: Path | None = None, limit=64 * 1024 ** 2) -> str:
    result = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=120)
    if result.returncode or result.stderr or len(result.stdout) > limit:
        raise ValueError("read-only tool failed or exceeded its output budget: " + shlex.join(argv)
                         + ": " + result.stderr.decode("utf-8", errors="replace")[:512])
    return result.stdout.decode("utf-8", errors="strict")


def archive_members(work: Path, archive: Path, ar: str) -> tuple[list[dict], dict, dict]:
    """Small reusable guard seam; it never creates an archive or receipt."""
    archive = private_path(archive, work)
    initial, archive_state = file_pin(archive)
    with archive.open("rb") as stream:
        if stream.read(8) != b"!<thin>\n":
            raise ValueError("only genuine GNU thin archives are supported")
    # Absolute archive input makes GNU ar's printed external paths unambiguous.
    names_text = command([ar, "t", str(archive)])
    names = names_text.splitlines()
    if not names or not names_text.endswith("\n") or len(names) > 20000 or len(set(names)) != len(names):
        raise ValueError("empty, duplicate or incomplete archive member order")
    members, seen, identities, states = [], set(), set(), {}
    for index, name in enumerate(names):
        if not name or any(ord(character) < 32 for character in name):
            raise ValueError("invalid or ambiguous member name")
        member = Path(name) if Path(name).is_absolute() else archive.parent / name
        member = private_path(member, work)
        if member.suffix not in (".o", ".obj") or not member.is_file():
            raise ValueError("missing or unsupported external object member: " + name)
        pin, state = file_pin(member)
        inode = state[:2]
        if str(member) in seen or inode in identities:
            raise ValueError("duplicate resolved object or inode")
        seen.add(str(member))
        identities.add(inode)
        states[str(member)] = (pin, state)
        members.append({"index": index, "name": name, "path": str(member),
                        "bytes": pin["bytes"], "sha256": pin["sha256"]})
    # Read twice here, and again after compiler/source inspection in create().
    verify_members(work, archive, ar, members, initial, archive_state, states)
    return members, initial, {"archive_state": archive_state, "members": states}


def verify_members(work, archive, ar, members, initial, archive_state, states):
    if command([ar, "t", str(archive)]).splitlines() != [row["name"] for row in members]:
        raise ValueError("archive member order changed during inspection")
    for member in members:
        path = private_path(Path(member["path"]), work)
        if file_pin(path) != states[str(path)]:
            raise ValueError("external member changed during inspection: " + str(path))
    if file_pin(archive) != (initial, archive_state):
        raise ValueError("thin archive changed during inspection")


def create(work: Path, archive: Path, output: Path,
           linked_pe: Path | None = None, linked_receipt: Path | None = None,
           extra_objects: list[Path] | None = None) -> dict:
    if work.is_symlink():
        raise ValueError("work must be an existing private directory")
    work = work.resolve(strict=True)
    archive = private_path(archive, work)
    output = private_path(output, work, exists=False)
    if output.exists() or not output.parent.is_dir():
        raise ValueError("receipt parent must exist and output must be absent")
    if shutil.disk_usage(work).free < FLOOR + RECEIPT_LIMIT:
        raise ValueError("host free space is below the 20 GiB floor plus receipt budget")
    ar = shutil.which("i686-w64-mingw32-ar")
    ninja = shutil.which("ninja")
    if not ar or not ninja:
        raise ValueError("existing GNU MinGW ar and Ninja are required")
    members, archive_pin, state = archive_members(work, archive, ar)
    build = archive.parent.parent
    if archive.parent.name != "lib":
        raise ValueError("archive must belong to an existing CMake build lib directory")
    observed = {}

    def observe(path: Path) -> dict:
        key = str(Path(os.path.abspath(path)))
        if key not in observed:
            observed[key] = file_pin(path)
        return observed[key][0]

    inspector = observe(Path(__file__))
    extras = []
    selected_paths = {row["path"] for row in members}
    selected_inodes = {snapshot[1][:2] for snapshot in state["members"].values()}
    for path in extra_objects or []:
        path = private_path(path, work)
        if path.suffix not in (".o", ".obj") or str(path) in selected_paths:
            raise ValueError("duplicate or unsupported extra object input")
        selected_paths.add(str(path))
        pin = observe(path)
        inode = observed[str(path)][1][:2]
        if inode in selected_inodes:
            raise ValueError("duplicate extra object inode")
        selected_inodes.add(inode)
        extras.append({"index": len(members) + len(extras), "name": str(path),
                       "path": str(path), "sha256": pin["sha256"], "bytes": pin["bytes"]})
    selected_objects = members + extras
    config_names = ("CMakeCache.txt", "cmakeconfig.h", "compile_commands.json", "build.ninja")
    configs = {name: observe(private_path(build / name, work)) for name in config_names}
    cache = (build / "CMakeCache.txt").read_text()
    cache_values = {}
    for line in cache.splitlines():
        match = re.match(r"([^:#/][^:]*)\:[^=]+=(.*)$", line)
        if match:
            cache_values[match[1]] = match[2]
    if cache_values.get("PORT") != "JSCOnly" or cache_values.get("USE_THIN_ARCHIVES") != "ON":
        raise ValueError("a real configured JSCOnly thin-archive build is required")
    source = private_path(Path(cache_values["CMAKE_HOME_DIRECTORY"]), work)
    source_basis = observe(source / ".iewebkit-hydrated.json")
    # This progress receipt can change when an independent JSC step finishes;
    # it is context, excluded from the immutable compiler/member input set.
    core_receipt = file_pin(work / "core-build.json")[0]
    toolchain = observe(Path(cache_values["CMAKE_TOOLCHAIN_FILE"]))
    # Tie exact order to the configured archive command's object inputs.
    relative_archive = archive.relative_to(build).as_posix()
    graph = (build / "build.ninja").read_text().replace("$\n", "")
    lines = [line for line in graph.splitlines() if line.startswith("build " + relative_archive + ": ")]
    if len(lines) != 1:
        raise ValueError("archive target is absent or ambiguous in the configured graph")
    tokens = shlex.split(lines[0].split(": ", 1)[1])
    inputs = []
    for token in tokens[1:]:
        if token in ("|", "||", "|@"):
            break
        if "$" in token or Path(token).suffix not in (".o", ".obj"):
            raise ValueError("unsupported Ninja archive input syntax")
        inputs.append(str(private_path(build / token, work)))
    if inputs != [row["path"] for row in members]:
        raise ValueError("GNU ar order differs from the complete Ninja archive input order")
    entries = json.loads((build / "compile_commands.json").read_text())
    by_output = {}
    for entry in entries:
        directory = private_path(Path(entry["directory"]), work)
        argv = entry.get("arguments") or shlex.split(entry["command"])
        emitted = entry.get("output")
        if not emitted:
            if argv.count("-o") != 1:
                raise ValueError("compile command has no unambiguous object output")
            emitted = argv[argv.index("-o") + 1]
        target = Path(emitted) if Path(emitted).is_absolute() else directory / emitted
        target = str(private_path(target, work, exists=False))
        if target in by_output:
            raise ValueError("duplicate configured compile output")
        by_output[target] = (entry, argv, directory)
    compilers, compiled_sources = {}, []
    for member in selected_objects:
        if member["path"] not in by_output:
            raise ValueError("archive member has no configured compile command")
        entry, argv, directory = by_output[member["path"]]
        compiler = Path(argv[0]) if Path(argv[0]).is_absolute() else Path(shutil.which(argv[0]) or "")
        if not compiler.is_file():
            raise ValueError("configured compiler cannot be pinned")
        compilers[str(compiler)] = observe(compiler)
        source_file = Path(entry["file"])
        if not source_file.is_absolute():
            source_file = directory / source_file
        source_pin = observe(private_path(source_file, work))
        compiled_sources.append({"member_index": member["index"], "source": source_pin,
                                 "directory": str(directory), "argv_sha256": digest(canonical(argv))})
    # Recorded compiler dependencies bind real included source/header inputs,
    # including generated unified sources. No compiler or generator is run.
    dependency_text = command([ninja, "-C", str(build), "-t", "deps",
                               *[Path(row["path"]).relative_to(build).as_posix() for row in selected_objects]])
    expected_targets = selected_paths
    dependency_paths, observed_targets = set(), set()
    current = None
    for line in dependency_text.splitlines():
        if line.startswith("    "):
            if current is None:
                raise ValueError("Ninja dependency appeared without a validated target")
            name = line[4:]
            path = Path(name) if Path(name).is_absolute() else build / name
            dependency_paths.add(str(Path(os.path.abspath(path))))
        elif line:
            match = re.match(r"(.+): #deps ([0-9]+), deps mtime [0-9]+ \(VALID\)$", line)
            if not match or int(match[2]) == 0:
                raise ValueError("missing or stale recorded compiler dependencies")
            current = str(private_path(build / match[1], work))
            if current not in expected_targets or current in observed_targets:
                raise ValueError("duplicate or unexpected dependency target")
            observed_targets.add(current)
    if observed_targets != expected_targets:
        raise ValueError("incomplete dependency target coverage")
    if len(dependency_paths) > 20000:
        raise ValueError("compiler input inventory exceeds its budget")
    dependencies = [observe(Path(path)) for path in sorted(dependency_paths)]
    tools = {"ar": observe(Path(ar)), "ninja": observe(Path(ninja)), "compilers": compilers}
    linked = None
    if bool(linked_pe) != bool(linked_receipt):
        raise ValueError("provide both linked PE and its existing receipt")
    if linked_pe and linked_receipt:
        pe_pin = observe(private_path(linked_pe, work))
        receipt_pin = observe(private_path(linked_receipt, work))
        old = json.loads(linked_receipt.read_text())
        if (old.get("schema") != "iewebkit-real-wtf-linked-native-v1"
                or old["binary"]["sha256"] != pe_pin["sha256"]
                or old["configuration_sha256"] != configs["cmakeconfig.h"]["sha256"]
                or not any(row["path"] == str(archive) and row["sha256"] == archive_pin["sha256"]
                           for row in old["archives"])):
            raise ValueError("unchanged PE/old linked receipt/archive binding failed")
        linked = {"pe": pe_pin, "receipt": receipt_pin, "observation": "supplemental-post-link",
                  "original_link_member_bytes_verified": False}
    for key, before in observed.items():
        if file_pin(Path(key)) != before:
            raise ValueError("observed source/compiler/config input changed: " + key)
    verify_members(work, archive, ar, members, archive_pin, state["archive_state"], state["members"])
    receipt = {"schema": "iewebkit-thin-archive-members-v1", "work": str(work),
               "archive": archive_pin, "format": "GNU-thin", "member_count": len(members),
               "members": members, "member_inventory_sha256": digest(canonical(members)),
               "extra_objects": extras, "extra_object_inventory_sha256": digest(canonical(extras)),
               "aggregate_encoding": "UTF-8/ASCII JSON; ordered array; sorted object keys; compact separators",
               "ninja_order_verified": True, "before_after_unchanged": True,
               "configuration": configs, "source_basis": source_basis, "core_receipt": core_receipt,
               "mutable_context_paths": [str(work / "core-build.json")],
               "toolchain": toolchain, "tools": tools, "compiled_sources": compiled_sources,
               "compiler_dependency_count": len(dependencies), "compiler_dependencies": dependencies,
               "compiler_input_inventory_sha256": digest(canonical(dependencies)),
               "linked_observation": linked, "inspector": inspector,
               "source_or_build_modified": False, "fresh_compilation_verified": False,
               "guest_execution": "NOT-VERIFIED", "full_engine": False, "rendering_verified": False}
    raw = json.dumps(receipt, indent=2).encode() + b"\n"
    if len(raw) > RECEIPT_LIMIT or shutil.disk_usage(work).free < FLOOR + len(raw):
        raise ValueError("receipt exceeds its size/free-space budget")
    with output.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return {"receipt": str(output), "sha256": digest(raw), "bytes": len(raw),
            "members": len(members), "member_inventory_sha256": receipt["member_inventory_sha256"],
            "compiler_dependency_count": len(dependencies), "guest_execution": "NOT-VERIFIED"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--linked-pe", type=Path)
    parser.add_argument("--linked-receipt", type=Path)
    parser.add_argument("--extra-object", type=Path, action="append", default=[])
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create(args.work, args.archive, args.output, args.linked_pe, args.linked_receipt,
                                args.extra_object), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
