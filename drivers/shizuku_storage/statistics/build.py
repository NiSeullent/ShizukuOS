#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Build matched, opt-in 2KiB/16KiB statistics BIOS candidates; never run a VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BASE = REPO / "build/shizukudos/csm-gop-anchor"
SOURCE = BASE / "work/csmwrap/seabios"
HELD = REPO / "build/shizukudos/shizuku-storage-v86-16k-20261001T0806-v2"
FLOOR = 17 * 1024**3 + 512 * 1024**2
PINS = {
    BASE / "build-result.json": "7d8e36d4b7faaa7583ac8b14feb796599928b3814ae8fdfc98ce0a6eeb683ed3",
    BASE / "Csm16.bin": "039f38c9759add2b192aee7dd80172f975d1c7cbc801d71c37d15634ab653649",
    SOURCE / "src/block.c": "1249d451ba4846c98348b7bdfcb7e5d8b637b69867372e20f1e96ff3345cfd29",
    SOURCE / ".config": "bbd147c3ba50c7d7633cd638658b118b0a11582ab7bd8cce888afefe0418fcdc",
    SOURCE / ".version": "418b430b2d8b60ba887d4b5611880704c2ebc4734aa2c97c56535e2dc8ff2ff7",
    HELD / "frozen-release.json": "f2a33b3fff7fe878d174e10baaf85a162eb6784eb8aa38a76b6fee1ea683b301",
    HELD / "Csm16.bin": "16a03175c47e92c0ada3e71e76685043dc679d44d5839b18abf339bb3e6ee028",
    HERE.parent / "v86-bounce-16k.patch": "fadb141fd1e1bf5cee62c9f615045ccad611d58000b81238b62d5c8122f1f44e",
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def catalog(root):
    rows = []
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root)
        if any(x in rel.parts for x in ("out", ".git", "__pycache__")):
            continue
        if p.is_symlink():
            raise ValueError(f"Source symlink is not admitted: {p}")
        if p.is_file():
            rows.append({"path": str(rel), "bytes": p.stat().st_size, "sha256": sha(p)})
    return rows


def run(argv, cwd, env, log, timeout=600):
    with log.open("x") as stream:
        proc = subprocess.run(argv, cwd=cwd, env=env, stdout=stream,
                              stderr=subprocess.STDOUT, timeout=timeout, check=False)
    row = {"argv": [str(x) for x in argv], "cwd": str(cwd), "exit": proc.returncode,
           "log": str(log), "log_sha256": sha(log)}
    if proc.returncode:
        raise RuntimeError(f"Private command failed ({proc.returncode}): {log}")
    return row


def tools_snapshot():
    rows = []
    for name in ("gcc", "clang", "make", "patch", "ld", "as", "objcopy", "objdump", "nm", "python3"):
        p = Path(shutil.which(name)).resolve(strict=True)
        rows.append({"tool": name, "path": str(p), "bytes": p.stat().st_size, "sha256": sha(p)})
    for query in (("gcc", "-print-prog-name=cc1"), ("gcc", "-print-file-name=libgcc.a")):
        value = subprocess.check_output(query, text=True, timeout=20).strip()
        p = Path(value).resolve(strict=True)
        rows.append({"tool": " ".join(query), "path": str(p), "bytes": p.stat().st_size, "sha256": sha(p)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    allowed = (REPO / "build/shizukudos").resolve()
    if out.parent != allowed or not out.name.startswith("shizuku-storage-statistics-") or out.exists():
        parser.error("--out must be a fresh shizuku-storage-statistics-* under build/shizukudos")
    for p, expected in PINS.items():
        if sha(p) != expected:
            raise ValueError(f"Held input differs before writes: {p}")
    before = catalog(SOURCE)
    producers = catalog(HERE)
    held_sources = [{"path": str(HERE.parent / name), "sha256": sha(HERE.parent / name)}
                    for name in ("build.py", "test_storage.py", "v86-bounce-16k.patch", "README.md", "NOTICE")]
    tool_before = tools_snapshot()
    free_before = shutil.disk_usage(allowed).free
    source_bytes = sum(x["bytes"] for x in before)
    if free_before < FLOOR + 2 * source_bytes + 256 * 1024**2:
        raise RuntimeError("Unchanged free reserve plus bounded private pair budget not met")
    out.mkdir()
    result = {"schema": 1, "kind": "private-matched-seabios-transfer-statistics-pair",
              "status": "FAIL", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "native_execution": False, "native_statistics_lifetime_accepted": False,
              "speed_or_storage_acceleration_accepted": False, "default_modified": False,
              "source_bytes": source_bytes, "free_before": free_before,
              "immutable_sources": [{"path": str(p), "sha256": h} for p, h in PINS.items()],
              "held_parent_sources": held_sources, "producer_sources": producers,
              "pinned_source_catalog": before, "tools_before": tool_before, "profiles": {}}
    try:
        import prepare
        import test_statistics
        snapshot = out / "producer-source-snapshot"
        snapshot.mkdir()
        for x in producers:
            shutil.copy2(HERE / x["path"], snapshot / x["path"])
        env = dict(os.environ, LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="1785283200",
                   GIT_CEILING_DIRECTORIES=str(out), PYTHONDONTWRITEBYTECODE="1")
        for capacity in (2048, 16384):
            name = "2k" if capacity == 2048 else "16k"
            pdir = out / name
            pdir.mkdir()
            profile = {"requested_capacity": capacity, "commands": [], "artifacts": {}}
            result["profiles"][name] = profile
            tree = pdir / "seabios"
            shutil.copytree(SOURCE, tree, ignore=shutil.ignore_patterns("out", ".git", "__pycache__"))
            if catalog(tree) != before:
                raise RuntimeError("Private copy differs before deliberate changes")
            patch = HERE.parent / "v86-bounce-16k.patch"
            profile["commands"].append(run(["patch", "-p1", "--fuzz=0", "-i", str(patch)], tree, env, pdir / "patch.log"))
            corrected = (tree / "src/block.c").read_text()
            control = pdir / "corrected-control-block.c"
            control.write_text(corrected)
            profile["corrected_control_sha256"] = sha(control)
            prepare.write_private(tree, corrected, capacity)
            profile["host_tests"] = test_statistics.run_tests(tree, control, SOURCE / "src/block.c", pdir / "host-tests")
            profile["commands"].append(run(["make", "-j1", "EXTRAVERSION=-CSMWrap-3.1.2-25-g7f30b74", "all"], tree, env, pdir / "make.log"))
            for filename in ("Csm16.bin", "vgabios.bin"):
                src = tree / "out" / filename
                shutil.copy2(src, pdir / filename)
                profile["artifacts"][filename] = {"path": str(pdir / filename), "bytes": src.stat().st_size, "sha256": sha(src)}
            if sha(pdir / "vgabios.bin") != "4dc749ad92671d8264ed7f96903060218378e66d955336bf5c27ea998af2f210":
                raise RuntimeError("Paired observation must not change SeaVGABIOS")
            profile["source_catalog"] = catalog(tree)
            original = {x["path"]: x for x in before}
            changed = [x["path"] for x in profile["source_catalog"] if x != original.get(x["path"])]
            if changed != ["src/block.c", "src/shzstorage_profile.h", "src/shzstorage_statistics.h"]:
                raise RuntimeError(f"Unexpected source changes: {changed}")
            profile["commands"].append(run(["nm", "-n", "-S", str(tree / "out/rom.o")], tree, env, pdir / "symbols.txt"))
            rows = [l.split() for l in (pdir / "symbols.txt").read_text().splitlines() if l.endswith(" shz_storage_stats")]
            if len(rows) != 1 or len(rows[0]) != 4:
                raise RuntimeError("Compiled F-segment statistics symbol is not unique")
            address, size = int(rows[0][0], 16), int(rows[0][1], 16)
            if size != 224 or address % 16 or not 0xf0000 <= address <= 0x100000 - size:
                raise RuntimeError("Compiled statistics object is not fully aligned in BIOS F-segment")
            profile["statistics_abi"] = {"magic": "SHZSTAT1", "major": 1, "minor": 0,
                                         "bytes": 224, "physical_address": address, "alignment": 16,
                                         "sequence_offset": 16, "requested_capacity_offset": 20,
                                         "actual_capacity_offset": 24, "flags_offset": 28,
                                         "allocation": "linker-owned VARFSEG in reserved BIOS span",
                                         "reader": "equal even sequence/body/sequence; bound below2^31 requests; flag2 invalid; flag1 lowerbounds"}
        a = {x["path"]: x for x in result["profiles"]["2k"]["source_catalog"]}
        b = {x["path"]: x for x in result["profiles"]["16k"]["source_catalog"]}
        if a.keys() != b.keys() or [k for k in a if a[k] != b[k]] != ["src/shzstorage_profile.h"]:
            raise RuntimeError("Paired source difference must be only the requested capacity header")
        result["paired_source_only_capacity_header_differs"] = True
        result["status"] = "PASS-HOST-CONTROLS-AND-PAIRED-COMPILE-NATIVE-PENDING"
    except Exception as e:
        result["error"] = str(e)
    finally:
        result["source_tree_unchanged"] = catalog(SOURCE) == before
        result["held_pins_unchanged"] = all(sha(p) == h for p, h in PINS.items())
        result["held_parent_sources_unchanged"] = all(sha(x["path"]) == x["sha256"] for x in held_sources)
        result["producer_sources_unchanged"] = catalog(HERE) == producers
        result["tools_after"] = tools_snapshot()
        result["toolchain_unchanged"] = tool_before == result["tools_after"]
        result["free_after"] = shutil.disk_usage(out).free
        for flag in ("source_tree_unchanged", "held_pins_unchanged", "held_parent_sources_unchanged", "producer_sources_unchanged", "toolchain_unchanged"):
            if not result[flag]:
                result["status"] = "FAIL"
                result["error"] = "A held source, producer or tool changed during the build"
        (out / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "error": result.get("error"), "out": str(out)}))
    if result["status"] == "FAIL":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
