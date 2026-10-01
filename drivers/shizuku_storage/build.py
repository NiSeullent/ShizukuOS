#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
"""Build an isolated, optional SeaBIOS V86 disk-transfer candidate. No VM runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

REPO = Path(__file__).resolve().parents[2]
BASE = REPO / "build/shizukudos/csm-gop-anchor"
SOURCE = BASE / "work/csmwrap/seabios"
PINNED = {
    "build-result.json": "7d8e36d4b7faaa7583ac8b14feb796599928b3814ae8fdfc98ce0a6eeb683ed3",
    "Csm16.bin": "039f38c9759add2b192aee7dd80172f975d1c7cbc801d71c37d15634ab653649",
    "work/csmwrap/seabios/src/block.c": "1249d451ba4846c98348b7bdfcb7e5d8b637b69867372e20f1e96ff3345cfd29",
    "work/csmwrap/seabios/.config": "bbd147c3ba50c7d7633cd638658b118b0a11582ab7bd8cce888afefe0418fcdc",
    "work/csmwrap/seabios/.version": "418b430b2d8b60ba887d4b5611880704c2ebc4734aa2c97c56535e2dc8ff2ff7",
}
FLOOR = 17 * 1024**3 + 512 * 1024**2


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def files(root):
    result = []
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root)
        if "out" in rel.parts or ".git" in rel.parts or "__pycache__" in rel.parts:
            continue
        if path.is_symlink():
            raise ValueError(f"Source symlink is not admitted: {path}")
        if path.is_file():
            result.append({"path": str(rel), "bytes": path.stat().st_size, "sha256": sha(path)})
    return result


def execute(command, cwd, env, log, timeout=600):
    with log.open("x") as output:
        p = subprocess.run(command, cwd=cwd, env=env, stdout=output,
                           stderr=subprocess.STDOUT, timeout=timeout, check=False)
    if p.returncode:
        raise RuntimeError(f"Build command failed ({p.returncode}): {log}")
    return {"argv": [str(x) for x in command], "cwd": str(cwd),
            "exit_code": p.returncode, "log": str(log), "log_sha256": sha(log)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True, help="Fresh directory under build/shizukudos")
    parser.add_argument("--v86-bounce-16k", action="store_true", help="Apply the separate opt-in storage patch")
    args = parser.parse_args()
    out = args.out.resolve()
    allowed = (REPO / "build/shizukudos").resolve()
    if out.parent != allowed or not out.name.startswith("shizuku-storage-") or out.exists():
        parser.error("--out must be a new component directory under build/shizukudos")
    for rel, expected in PINNED.items():
        if sha(BASE / rel) != expected:
            raise ValueError(f"Pinned frozen input differs: {rel}")
    before = files(SOURCE)
    source_bytes = sum(x["bytes"] for x in before)
    free_before = shutil.disk_usage(allowed).free
    if free_before < FLOOR + source_bytes + 128 * 1024**2:
        raise RuntimeError("Build free space is below the unchanged reserve plus private build budget")
    out.mkdir()
    result = {"schema": 1, "kind": "isolated-seabios-v86-storage-build", "status": "FAIL",
              "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "feature_enabled": args.v86_bounce_16k, "default_modified": False,
              "native_execution": False, "storage_acceleration_accepted": False,
              "free_before": free_before, "source_bytes": source_bytes,
              "immutable_sources": [{"path": str(BASE / rel), "sha256": expected}
                                    for rel, expected in PINNED.items()],
              "producer_sources": [{"path": str(Path(__file__)), "sha256": sha(__file__)}],
              "pinned_source_files": before, "commands": [], "artifacts": {}}
    try:
        tree = out / "seabios"
        shutil.copytree(SOURCE, tree, ignore=shutil.ignore_patterns("out", ".git", "__pycache__"))
        if files(tree) != before:
            raise RuntimeError("Private source copy differs before patching")
        env = dict(os.environ, LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="1785283200",
                   GIT_CEILING_DIRECTORIES=str(out))
        patch = Path(__file__).with_name("v86-bounce-16k.patch")
        if args.v86_bounce_16k:
            result["producer_sources"].append({"path": str(patch), "sha256": sha(patch)})
            result["commands"].append(execute(["patch", "-p1", "--fuzz=0", "-i", str(patch)], tree, env, out / "patch.log"))
            import test_storage
            result["producer_sources"].append({"path": str(Path(test_storage.__file__)), "sha256": sha(test_storage.__file__)})
            result["host_tests"] = test_storage.run_tests(tree / "src/block.c", SOURCE / "src/block.c", out / "host-tests")
        # Build only SeaBIOS/SeaVGABIOS. This stage cannot replace an EFI or run a guest.
        command = ["make", "-j1", "EXTRAVERSION=-CSMWrap-3.1.2-25-g7f30b74", "all"]
        result["commands"].append(execute(command, tree, env, out / "make.log"))
        for name in ["Csm16.bin", "vgabios.bin"]:
            src = tree / "out" / name
            shutil.copy2(src, out / name)
            result["artifacts"][name] = {"path": str(out / name), "bytes": src.stat().st_size, "sha256": sha(src)}
        result["patched_source_files"] = files(tree)
        changed = [x["path"] for x, y in zip(before, result["patched_source_files"]) if x != y]
        if changed != (["src/block.c"] if args.v86_bounce_16k else []):
            raise RuntimeError(f"Unexpected source changes: {changed}")
        if not args.v86_bounce_16k:
            result["baseline_binary_exact_match"] = sha(out / "Csm16.bin") == PINNED["Csm16.bin"]
            if not result["baseline_binary_exact_match"]:
                raise RuntimeError("Unpatched baseline Csm16 differs from the frozen original")
        result["compiled_symbols"] = execute(["nm", "-n", str(tree / "out/rom.o")], tree, env, out / "symbols.txt")
        if args.v86_bounce_16k and "bounce_buf_size" not in (out / "symbols.txt").read_text():
            raise RuntimeError("Actual capacity symbol is absent from the compiled firmware")
        result["status"] = "PASS-HOST-COMPILE-NATIVE-PENDING" if args.v86_bounce_16k else "PASS-EXACT-BASELINE-COMPILE"
    except Exception as exc:
        result["error"] = str(exc)
    finally:
        result["source_tree_unchanged"] = files(SOURCE) == before
        result["pinned_inputs_unchanged"] = all(sha(BASE / rel) == expected for rel, expected in PINNED.items())
        result["producer_sources_unchanged"] = all(sha(x["path"]) == x["sha256"] for x in result["producer_sources"])
        result["free_after"] = shutil.disk_usage(out).free
        if not all(result[k] for k in ["source_tree_unchanged", "pinned_inputs_unchanged", "producer_sources_unchanged"]):
            result["status"] = "FAIL"
            result["error"] = "Source or producer changed during build"
        (out / "build-result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in ["status", "feature_enabled", "source_tree_unchanged", "pinned_inputs_unchanged"]}))
    if result["status"] == "FAIL":
        raise SystemExit(result.get("error", "Build failed"))


if __name__ == "__main__":
    main()
