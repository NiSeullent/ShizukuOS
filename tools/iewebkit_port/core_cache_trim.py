#!/usr/bin/env python3
"""Remove only reconstructible unused private JSCOnly source caches.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
No engine object, installed dependency, canonical checkout or guest is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import tarfile


ARCHIVE_SHA = "846fd19ccedbae1dbfe904f26dbf2d68a800a33a50caf2ad5222c8dcb3f25682"
ROOT_NAME = "webkitgtk-2.54.0"
CANDIDATES = ("Source/ThirdParty/ANGLE", "Source/ThirdParty/skia", "Source/WebCore")
HERE = Path(__file__).resolve().parent


def digest_stream(stream):
    value = hashlib.sha256()
    for data in iter(lambda: stream.read(1024 * 1024), b""):
        value.update(data)
    return value.hexdigest()


def digest(path):
    with path.open("rb") as stream:
        return digest_stream(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    work = args.work.resolve()
    source = work / ROOT_NAME
    build = work / "build-jsc-win9x"
    if (not (work / "core-build.json").is_file() or source.is_symlink()
            or args.output.exists() or args.archive.resolve().is_relative_to(source)
            or not args.output.resolve().is_relative_to(work)
            or args.output.resolve().is_relative_to(source)
            or digest(args.archive) != ARCHIVE_SHA):
        raise ValueError("Require a private real-core worktree, new receipt and exact retained archive")
    cache = (build / "CMakeCache.txt").read_text()
    if "PORT:STRING=JSCOnly" not in cache or "USE_SKIA:BOOL=OFF" not in cache:
        raise ValueError("Only the JSCOnly profile without Skia permits these cache removals")
    config = (build / "cmakeconfig.h").read_text()
    profile = json.loads((HERE / "core_profile.json").read_text())
    options_item = next(item for item in profile["files"] if item["path"] == "Source/cmake/OptionsJSCOnly.cmake")
    if (digest(source / options_item["path"]) != options_item["after_sha256"]
            or "#define ENABLE_WEBGL 0" not in config or "#define USE_SKIA 0" not in config):
        raise ValueError("Require the pinned effective JSCOnly graph with WebGL and Skia disabled")
    dependency_texts = [(build / name).read_text() for name in
                        ("build.ninja", "compile_commands.json", "cmake_install.cmake")]
    dependencies = subprocess.run(["ninja", "-C", str(build), "-t", "deps"],
                                  check=True, capture_output=True, text=True).stdout
    dependency_texts.append(dependencies)
    for relative in CANDIDATES:
        if any(relative in text for text in dependency_texts):
            raise ValueError("Preserve a source cache referenced by the active build: " + relative)
        directory = source / relative
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError("Require the actual private cache directory: " + relative)
    actual = {}
    for relative in CANDIDATES:
        for path in (source / relative).rglob("*"):
            name = path.relative_to(source).as_posix()
            stat = path.lstat()
            if path.is_symlink():
                actual[name] = {"path": name, "kind": "symlink", "target": os.readlink(path), "mode": stat.st_mode & 0o777}
            elif path.is_file():
                if stat.st_nlink != 1:
                    raise ValueError("Preserve a source cache linked outside its owned location: " + name)
                actual[name] = {"path": name, "kind": "file", "sha256": digest(path),
                                "bytes": stat.st_size, "mode": stat.st_mode & 0o777}
            elif not path.is_dir():
                raise ValueError("Preserve unrecognized source cache file type: " + name)
    archived = set()
    with tarfile.open(args.archive, mode="r|xz") as archive:
        for member in archive:
            path = PurePosixPath(member.name)
            if not path.parts or path.parts[0] != ROOT_NAME or ".." in path.parts:
                continue
            relative = PurePosixPath(*path.parts[1:]).as_posix()
            if not any(relative == name or relative.startswith(name + "/") for name in CANDIDATES):
                continue
            if member.isdir():
                continue
            item = actual.get(relative)
            if item is None or relative in archived:
                raise ValueError("Private source differs from the retained archive inventory: " + relative)
            if member.isfile() and item["kind"] == "file":
                stream = archive.extractfile(member)
                if stream is None or digest_stream(stream) != item["sha256"] or member.size != item["bytes"]:
                    raise ValueError("Preserve modified source bytes: " + relative)
            elif member.issym() and item["kind"] == "symlink" and member.linkname == item["target"]:
                pass
            else:
                raise ValueError("Preserve source cache type/link mismatch: " + relative)
            # The archive has group-writable upstream metadata; the private
            # bootstrap hydrates it under the host's standard umask 022.
            expected_mode = member.mode & 0o777
            if member.isfile():
                expected_mode &= ~0o022
            if expected_mode != item["mode"]:
                raise ValueError("Preserve changed source permissions: " + relative)
            item["archive_mode"] = member.mode & 0o777
            archived.add(relative)
    if archived != set(actual):
        raise ValueError("Preserve private cache files absent from the original archive")
    # Retain byte-exact license notices outside the disposable cache.
    licenses = []
    receipt_dir = args.output.parent / (args.output.stem + "-licenses")
    if receipt_dir.exists():
        raise FileExistsError("Preserve existing retained license directory")
    receipt_dir.mkdir(parents=True)
    for name, item in actual.items():
        if item["kind"] == "file" and any(token in Path(name).name.upper() for token in ("LICENSE", "COPYING", "NOTICE")):
            target = receipt_dir / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((source / name).read_bytes())
            licenses.append({"origin": name, "retained": str(target), "sha256": digest(target)})
    before = sum((source / item["path"]).lstat().st_blocks * 512 for item in actual.values())
    report = {"schema": "iewebkit-archive-exact-unused-source-cache-trim-v1",
              "tool_sha256": digest(Path(__file__)),
              "archive": str(args.archive.resolve()), "archive_sha256": ARCHIVE_SHA,
              "source": str(source), "candidates": list(CANDIDATES), "all_file_bytes_and_link_targets_exact": True,
              "file_modes_match_archive_umask_022": True,
              "active_compiler_and_ninja_dependencies_absent": True,
              "profile": "Pinned JSCOnly sets normal CMake variables WebCore/WebGL OFF; effective generated WebGL and Skia flags are zero",
              "cached_webgl": next(line for line in cache.splitlines() if line.startswith("ENABLE_WEBGL:")),
              "inventory": list(actual.values()),
              "licenses_retained": licenses, "candidate_allocated_bytes": before,
              "applied": False, "restoration": "Extract only the listed source subtrees from the exact retained archive; validate this inventory before use"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    if args.apply:
        # Check the exact inventory again immediately before deleting owned caches.
        for name, item in actual.items():
            path = source / name
            if ((item["kind"] == "file" and (path.is_symlink() or digest(path) != item["sha256"]))
                    or (item["kind"] == "symlink" and os.readlink(path) != item["target"])):
                raise ValueError("Source cache changed after archive comparison; preserve it")
        for relative in CANDIDATES:
            shutil.rmtree(source / relative)
        report.update({"applied": True, "removed_allocated_bytes": before,
                       "host_free_bytes": shutil.disk_usage(work).free})
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"receipt": str(args.output), "sha256": digest(args.output),
                      "files": len(actual), "reclaimed_bytes": before if args.apply else 0,
                      "free_bytes": shutil.disk_usage(work).free}))


if __name__ == "__main__":
    main()
