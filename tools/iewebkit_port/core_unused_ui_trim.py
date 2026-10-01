#!/usr/bin/env python3
"""Trim only byte-exact, unused private JSCOnly UI/documentation source caches.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
The complete compressed inventory and exact notices permit later restoration
from the retained original archive. No engine, compiler or guest is executed.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
FLOOR = 20 * 1024 ** 3
BUDGET = 2 * 1024 ** 2
ROOT = "webkitgtk-2.54.0"
ARCHIVE_SHA = "846fd19ccedbae1dbfe904f26dbf2d68a800a33a50caf2ad5222c8dcb3f25682"
CANDIDATES = ("Documentation", "Source/WebInspectorUI", "Source/WebKit")
EXPECTED = {
    "Documentation": "0f598345ebbeb60764f9cabbf82d3910254a2658371bac84ab1b78eb32cd1001",
    "Source/WebInspectorUI": "9ac8a582864a17c53e9be1adec6b9a452de25c8b343ebb233f28d29dc8002185",
    "Source/WebKit": "f8b5132b1aa09170d4670cd9eb8726a54e68a71f43c746a7917bcdc9c33342ff",
}
DUPLICATE = "Source/WebKit/Resources/gtk/gtk-theme.css"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def stream_sha(stream):
    value = hashlib.sha256()
    for data in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(data)
    return value.hexdigest()


def identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def file_pin(path):
    named = path.lstat()
    if not stat.S_ISREG(named.st_mode):
        raise ValueError("Preserve nonregular input: " + str(path))
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if identity(opened) != identity(named):
            raise ValueError("Input was replaced before inspection")
        digest = stream_sha(stream)
        after = os.fstat(stream.fileno())
    if identity(opened) != identity(after) or identity(path.lstat()) != identity(after):
        raise ValueError("Input changed or was atomically replaced during inspection")
    return {"path": str(path), "sha256": digest, "bytes": after.st_size}, identity(after)


def guard_space(work):
    if shutil.disk_usage(work).free < FLOOR + BUDGET:
        raise ValueError("Preserve the 20 GiB free-space floor plus the two MiB receipt budget")


def graph_inputs(work, source, build):
    cache = (build / "CMakeCache.txt").read_text()
    if ("PORT:STRING=JSCOnly" not in cache or "USE_SKIA:BOOL=OFF" not in cache
            or "CMAKE_HOME_DIRECTORY:INTERNAL=" + str(source) not in cache):
        raise ValueError("Require the actual private JSCOnly source/build graph")
    profile = json.loads((HERE / "core_profile.json").read_text())
    item = next(row for row in profile["files"]
                if row["path"] == "Source/cmake/OptionsJSCOnly.cmake")
    options = source / item["path"]
    if file_pin(options)[0]["sha256"] != item["after_sha256"]:
        raise ValueError("Effective JSCOnly source profile changed")
    text = options.read_text()
    if any("set(" + name + " OFF)" not in text for name in
           ("ENABLE_WEBCORE", "ENABLE_WEBKIT", "ENABLE_WEBINSPECTORUI")):
        raise ValueError("Require effective disabled renderer/UI targets")
    paths = [build / name for name in ("build.ninja", "compile_commands.json",
             "cmake_install.cmake", "CMakeFiles/rules.ninja", "CMakeCache.txt", "cmakeconfig.h")]
    paths += [options, source / "Source/CMakeLists.txt", HERE / "core_profile.json"]
    paths += sorted(HERE.glob("*pin.json"))
    paths += sorted((HERE / "patches").glob("*.patch"))
    pins = [file_pin(path)[0] for path in dict.fromkeys(paths)]
    for path in paths[:4]:
        if any(name in path.read_text() for name in CANDIDATES):
            raise ValueError("Preserve a cache referenced by the configured graph")
    for path in sorted(HERE.glob("*pin.json")):
        if any(name in path.read_text() for name in CANDIDATES):
            raise ValueError("Preserve a cache referenced by a source pin")
    for path in sorted((HERE / "patches").glob("*.patch")):
        targets = [line for line in path.read_text().splitlines()
                   if line.startswith(("--- ", "+++ "))]
        if any(any(name in line for name in CANDIDATES) for line in targets):
            raise ValueError("Preserve an actual source patch target")
    result = subprocess.run(["ninja", "-C", str(build), "-t", "deps"],
                            check=True, capture_output=True, text=True, timeout=60)
    if any(name in result.stdout for name in CANDIDATES):
        raise ValueError("Preserve a cache referenced by actual compiler dependencies")
    return {"pins": pins, "compiler_deps_sha256": sha(result.stdout.encode()),
            "compiler_deps_bytes": len(result.stdout.encode()),
            "candidate_reference_hits": [], "effective_profile": "JSCOnly",
            "cached_webkit_value": next(line for line in cache.splitlines()
                if line.startswith("ENABLE_WEBKIT:BOOL=")),
            "effective_webkit_and_inspector": "OFF by pinned normal CMake variables"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    work = args.work.resolve()
    source = work / ROOT
    build = work / "build-jsc-win9x"
    output = args.output.absolute()
    if (source.is_symlink() or not source.is_dir() or not (work / "core-build.json").is_file() or output.exists()
            or output.parent.exists() or not output.resolve().is_relative_to(work)
            or output.resolve().is_relative_to(source) or args.archive.resolve().is_relative_to(work)):
        raise ValueError("Require an owned source tree and a new private receipt directory")
    guard_space(work)
    helper_pin = file_pin(Path(__file__).resolve())[0]
    archive_pin, archive_state = file_pin(args.archive)
    if archive_pin["sha256"] != ARCHIVE_SHA:
        raise ValueError("Retained original archive does not match its exact pin")
    graph = graph_inputs(work, source, build)
    actual, states, directories = {}, {}, []
    before_allocated = 0
    for name in CANDIDATES:
        base = source / name
        if not base.is_dir() or base.is_symlink() or base.resolve() != base:
            raise ValueError("Preserve missing or linked cache root")
        paths = [base]
        for current, dirs, files in os.walk(base, followlinks=False):
            paths.extend(Path(current) / entry for entry in dirs + files)
        for path in paths:
            st = path.lstat()
            relative = path.relative_to(source).as_posix()
            before_allocated += st.st_blocks * 512
            if stat.S_ISDIR(st.st_mode):
                directories.append({"path": relative, "mode": st.st_mode & 0o777})
                states[relative] = identity(st)
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                raise ValueError("Preserve special, symlink or externally linked cache file")
            pin, state = file_pin(path)
            states[relative] = state
            actual[relative] = {"path": relative, "kind": "file", "bytes": pin["bytes"],
                                "sha256": pin["sha256"], "mode": st.st_mode & 0o777}
    seen, tar_directories, duplicates = {}, set(), []
    with tarfile.open(args.archive, mode="r|xz") as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            if not name.parts or name.parts[0] != ROOT or ".." in name.parts:
                continue
            relative = PurePosixPath(*name.parts[1:]).as_posix()
            if not any(relative == root or relative.startswith(root + "/") for root in CANDIDATES):
                continue
            if member.isdir():
                tar_directories.add(relative)
                continue
            row = actual.get(relative)
            if row is None or not member.isfile():
                raise ValueError("Private/archive source inventory type or path mismatch")
            # Independently consume and hash EACH tar entry, including both
            # upstream copies of the known gtk-theme.css packaging duplicate.
            digest = stream_sha(archive.extractfile(member))
            if (digest != row["sha256"] or member.size != row["bytes"]
                    or (member.mode & 0o777 & ~0o022) != row["mode"]):
                raise ValueError("Preserve modified cache bytes or normalized permissions")
            seen[relative] = seen.get(relative, 0) + 1
            row["archive_mode"] = member.mode & 0o777
            if relative == DUPLICATE:
                duplicates.append({"path": relative, "occurrence": seen[relative],
                                   "sha256": digest, "bytes": member.size,
                                   "archive_mode": member.mode & 0o777})
    if set(seen) != set(actual) or {name: count for name, count in seen.items() if count > 1} != {DUPLICATE: 2}:
        raise ValueError("Preserve extra/missing files or unreviewed duplicate archive entries")
    inventories = {name: sorted([row for path, row in actual.items()
                   if path.startswith(name + "/")], key=lambda row: row["path"]) for name in CANDIDATES}
    if {name: sha(canonical(rows)) for name, rows in inventories.items()} != EXPECTED:
        raise ValueError("Cache inventory differs from the independent exact audit")
    omitted = sorted(row["path"] for row in directories
                     if row["path"] not in CANDIDATES and row["path"] not in tar_directories)
    if len(omitted) != 330:
        raise ValueError("Unreviewed directory-header packaging change")
    inventory = {"files": sorted(actual.values(), key=lambda row: row["path"]),
                 "directories": sorted(directories, key=lambda row: row["path"]),
                 "omitted_descendant_directory_headers": omitted,
                 "duplicate_archive_entries_independently_verified": duplicates}
    compressed = gzip.compress(canonical(inventory), mtime=0)
    notices = [row for row in actual.values() if any(token in Path(row["path"]).name.upper()
               for token in ("LICENSE", "COPYING", "NOTICE"))]
    if len(compressed) + sum(row["bytes"] for row in notices) + 128 * 1024 > BUDGET:
        raise ValueError("Complete inventory/notice evidence exceeds the two MiB budget")
    if file_pin(args.archive) != (archive_pin, archive_state) or graph_inputs(work, source, build) != graph:
        raise ValueError("Archive or actual source/compiler graph changed during audit")
    guard_space(work)
    output.parent.mkdir(mode=0o700)
    inventory_path = output.parent / "inventory.json.gz"
    inventory_path.write_bytes(compressed)
    retained = []
    for row in notices:
        destination = output.parent / "notices" / row["path"]
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((source / row["path"]).read_bytes())
        pin = file_pin(destination)[0]
        if pin["sha256"] != row["sha256"]:
            raise ValueError("Exact license/notice retention changed")
        retained.append({"origin": row["path"], **pin})
    report = {"schema": "iewebkit-exact-unused-ui-source-cache-trim-v1", "helper": helper_pin,
              "work": str(work), "archive": archive_pin, "candidates": CANDIDATES,
              "inventory": {**file_pin(inventory_path)[0], "uncompressed_sha256": sha(canonical(inventory)),
                            "file_count": len(actual), "directory_count": len(directories),
                            "per_cache_file_inventory_sha256": EXPECTED,
                            "omitted_descendant_directory_headers": 330,
                            "known_duplicate_entries_independently_verified": duplicates},
              "graph": graph, "retained_notices": retained, "before_allocated_bytes": before_allocated,
              "floor_bytes": FLOOR, "evidence_budget_bytes": BUDGET, "deleted_roots": [],
              "applied": False, "full_engine_or_renderer": False,
              "restoration": "Reconstruct only these source subtrees from the exact retained archive; validate every inventory file, normalized mode and both duplicate entries before reuse."}
    def save():
        data = canonical(report) + b"\n"
        temporary = output.with_suffix(output.suffix + ".temporary")
        temporary.write_bytes(data)
        temporary.replace(output)
    save()
    try:
        evidence_bytes = output.parent.stat().st_blocks * 512 + sum(
            path.lstat().st_blocks * 512 for path in output.parent.rglob("*"))
        if evidence_bytes + 16 * 1024 > BUDGET:
            raise ValueError("Actual allocated evidence exceeds the two MiB budget")
        report["evidence_allocated_bytes_before_apply"] = evidence_bytes
        # Immediately before deleting, require the exact named file inodes,
        # bytes, permissions and graph again. No source bytes are changed.
        for relative, state in states.items():
            path = source / relative
            if relative in actual:
                pin, current = file_pin(path)
                if current != state or pin["sha256"] != actual[relative]["sha256"]:
                    raise ValueError("Cache file changed before deletion")
            elif identity(path.lstat()) != state:
                raise ValueError("Cache directory changed before deletion")
        if graph_inputs(work, source, build) != graph or file_pin(Path(__file__).resolve())[0] != helper_pin:
            raise ValueError("Compiler graph or helper changed before deletion")
        if file_pin(args.archive) != (archive_pin, archive_state):
            raise ValueError("Retained archive changed before deletion")
        guard_space(work)
        report["immediate_predelete_validation"] = "PASS"
        save()
        if args.apply:
            for name in CANDIDATES:
                shutil.rmtree(source / name)
                report["deleted_roots"].append(name)
                save()
            report["applied"] = True
            report["reclaimed_source_allocated_bytes"] = before_allocated
        report["final_host_free_bytes"] = shutil.disk_usage(work).free
        save()
    except BaseException as error:
        report["failure"] = str(error) or type(error).__name__
        save()
        raise
    print(json.dumps({"receipt": str(output), "sha256": file_pin(output)[0]["sha256"],
                      "applied": report["applied"], "reclaimed_source_allocated_bytes":
                      report.get("reclaimed_source_allocated_bytes", 0),
                      "final_host_free_bytes": report["final_host_free_bytes"]}))


if __name__ == "__main__":
    main()
