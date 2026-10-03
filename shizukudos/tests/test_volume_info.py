#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute the production volume query and FAT/SFS callbacks on bounded host fixtures.

Extracts unchanged production functions/types; only handles, user copies, locks,
clock/heap and sfs_statfs are host adapters. No disk image, device or VM is used.
This is a component check, not native Windows98 or SFS guest acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def block(text, start, suffix=""):
    at = text.index(start)
    opening = text.index("{", at)
    depth = 0
    for end in range(opening, len(text)):
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
            if not depth:
                return text[at:end + 1] + suffix
    raise ValueError(start)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--source-root", type=Path, default=ROOT)
    ap.add_argument("--out", type=Path, default=ROOT / "build/shizukudos/volume-info-host")
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    paths = ["shizukudos/kernel64/" + name for name in
             ("fs.h", "disk.c", "sfs_mount.c", "sysk32.c", "fat32.h", "fs.c")]
    paths += ["shizukufs/v1/libsfs/sfs.h"]
    source = {p: (args.source_root / p).read_text() for p in paths}
    fs, disk, sfs, query = [source["shizukudos/kernel64/" + p]
                           for p in ("fs.h", "disk.c", "sfs_mount.c", "sysk32.c")]
    callback = "(*volume_info)" in fs
    pieces = ["typedef struct fsnode fsnode_t; typedef struct fsvol fsvol_t;",
              block(fs, "struct fsnode {", ";")]
    if callback:
        pieces.append(block(fs, "typedef struct fs_volume_info {", " fs_volume_info_t;"))
    pieces += [block(fs, "struct fsvol {", ";"),
               block(disk, "typedef struct {", " disk_vol_t;"),
               block(sfs, "typedef struct sfsk_vol {", " sfsk_vol;"),
               "static disk_vol_t dvol;",
               "int disk_volume_info(const fsnode_t *, uint32_t *, char [12], uint64_t *, uint64_t *, uint32_t *, int *);",
               block(disk, "int disk_volume_info("),
               block(query, "static int32_t put_result("),
               block(query, "static uint32_t put_utf16_ascii(")]
    if callback:
        pieces += [block(disk, "static int fat_volume_info(fsvol_t *fv, fs_volume_info_t *out)\n{"),
                   block(sfs, "static int vol_volume_info(")]
    pieces += [block(source["shizukudos/kernel64/fs.c"], "int utf8_to_utf16("),
               block(query, "static int32_t sys_query_volume(")]
    (out / "production.inc").write_text("\n\n".join(pieces) + "\n")
    # Copy the exact two dependency headers into the bounded compilation output.
    (out / "fat32.h").write_text(source[paths[4]])
    (out / "sfs.h").write_text(source[paths[-1]])
    test = Path(__file__).with_suffix(".c")
    before = {p: hashlib.sha256((args.source_root / p).read_bytes()).hexdigest() for p in paths}
    before[str(test)] = hashlib.sha256(test.read_bytes()).hexdigest()
    results = []
    for name, flags in (("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])):
        compiler = shutil.which(name)
        if not compiler:
            raise SystemExit("required host compiler missing: " + name)
        binary = out / name
        cmd = [compiler, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-Wno-unused-function", "-fno-strict-aliasing", *flags,
               "-DHAVE_VOLUME_CALLBACK=" + str(int(callback)), "-I", str(out), str(test), "-o", str(binary)]
        build = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        (out / (name + ".compile.log")).write_text(build.stdout + build.stderr)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30) if not build.returncode else None
        output = run.stdout + run.stderr if run else build.stdout + build.stderr
        (out / (name + ".log")).write_text(output)
        print(name + ": " + output, end="")
        results.append({"compiler": compiler, "compiler_sha256": hashlib.sha256(Path(compiler).read_bytes()).hexdigest(),
                        "command": cmd, "compile_exit": build.returncode, "exit": run.returncode if run else None})
    after = {p: hashlib.sha256((args.source_root / p).read_bytes()).hexdigest() for p in paths}
    after[str(test)] = hashlib.sha256(test.read_bytes()).hexdigest()
    good = before == after and all(r["compile_exit"] == 0 and r["exit"] == 0 for r in results)
    (out / "result.json").write_text(json.dumps({"status": "PASS_HOST_COMPONENT" if good else "FAIL",
        "sources": before, "sources_unchanged": before == after, "runs": results,
        "native_windows98_verified": False, "sfs_guest_volume_query_verified": False}, indent=2) + "\n")
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
