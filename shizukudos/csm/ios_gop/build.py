#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the isolated IO.SYS/GOP compatibility profile from cached pinned sources.

This extends the existing CSMWrap builder without editing its source or outputs.
All build inputs are frozen before compilation, including the concurrently owned
GOP handover patch. It never fetches sources or changes the upstream checkout.
"""
import argparse
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
BUILD = REPO / "build" / "shizukudos"
BASE = HERE.parent / "build.py"
DEFAULT_OUT = BUILD / "csm-ios-gop-7acd"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(path, *args):
    result = subprocess.run(["git", "-C", str(path), *args], capture_output=True,
                            text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"Cached source check failed: {path}: {result.stderr.strip()}")
    return result.stdout.strip()


def check_cached_sources(source, spec):
    """Check every explicitly pinned gitlink without invoking git fetch/update."""
    if git(source, "rev-parse", "HEAD") != spec["commit"]:
        raise RuntimeError("Cached CSMWrap commit differs from the manifest")
    git(source, "diff", "--quiet", "HEAD", "--ignore-submodules=all")
    for name, item in spec["submodules"].items():
        link = git(source, "ls-tree", "HEAD", name).split()
        if len(link) < 3 or link[1:3] != ["commit", item["commit"]]:
            raise RuntimeError(f"Cached CSMWrap gitlink drift: {name}")
        sub = source / name
        if git(sub, "rev-parse", "HEAD") != item["commit"]:
            raise RuntimeError(f"Cached submodule commit drift: {name}")
        git(sub, "diff", "--quiet", "HEAD", "--ignore-submodules=all")


def archive_commit(source, commit, destination):
    """Copy immutable git objects; never compile untracked or concurrent edits."""
    result = subprocess.run(["git", "-C", str(source), "archive", "--format=tar", commit],
                            capture_output=True, timeout=60, check=True)
    destination.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:") as archive:
        archive.extractall(destination, filter="data")


def main():
    wrapper_bytes = Path(__file__).read_bytes()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--jobs", type=int, choices=range(1, 5), default=2)
    parser.add_argument("--direct-io-sys", action="store_true",
                        help="Also freeze and apply the cooperating IO.SYS entry port after the GOP patch")
    args = parser.parse_args()
    out = args.out.resolve()
    if out.parent != BUILD.resolve() or not out.name.startswith("csm-ios-gop-7acd"):
        parser.error("--out must be an isolated build/shizukudos/csm-ios-gop-7acd* directory")
    if out.exists():
        parser.error("--out already exists; select a new comparison directory")
    manifest_path = REPO / "shizukudos" / "upstream" / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    spec = json.loads(manifest_bytes)["upstreams"]["csmwrap"]
    upstream = REPO / "build" / "upstream" / "csmwrap"
    check_cached_sources(upstream, spec)
    geometry_patches = sorted((HERE / "patches").glob("*.patch"))
    if not geometry_patches:
        raise RuntimeError("IO.SYS GOP compatibility patch is missing")
    base_bytes = BASE.read_bytes()
    direct_patch = REPO / "shizukudos" / "iosys_uefi" / "patches" / "0001-direct-iosys.patch"
    direct_patches = [direct_patch] if args.direct_io_sys else []
    module = types.ModuleType("isolated_csm_builder")
    module.__file__ = str(BASE)
    exec(compile(base_bytes, str(BASE), "exec"), module.__dict__)
    inputs = out / "inputs"
    inputs.mkdir(parents=True)
    (inputs / "base-build.py").write_bytes(base_bytes)
    (inputs / "ios-build.py").write_bytes(wrapper_bytes)
    (inputs / "manifest.json").write_bytes(manifest_bytes)
    frozen, bindings = {}, []
    for number, original in enumerate([*module.PATCHES, module.FIRMWARE_GOP_PATCH,
                                       *geometry_patches, *direct_patches]):
        raw = original.read_bytes()
        target = inputs / f"{number:02d}-{original.name}"
        target.write_bytes(raw)
        frozen[original] = target
        bindings.append({"patch": str(original.relative_to(REPO)),
                         "snapshot": str(target.relative_to(REPO)),
                         "sha256": hashlib.sha256(raw).hexdigest()})
    module.PATCHES = [frozen[p] for p in module.PATCHES] + [frozen[p] for p in geometry_patches]
    module.FIRMWARE_GOP_PATCH = frozen[module.FIRMWARE_GOP_PATCH]
    # Use git objects rather than a filesystem copy: ignored/untracked generated
    # source and another session's in-flight edits never enter this build.
    def fresh_tree(selected_spec):
        tree = module.WORK / "csmwrap"
        archive_commit(upstream, selected_spec["commit"], tree)
        for name, item in selected_spec["submodules"].items():
            archive_commit(upstream / name, item["commit"], tree / name)
        (tree / "seabios" / ".version").write_text(selected_spec["seabios_version"] + "\n")
        return tree
    module.fresh_tree = fresh_tree
    module.shzlib.load_manifest = lambda: json.loads(manifest_bytes)
    # This peer patch consumes GOP declarations, so apply it after baseline
    # main has applied GOP and immediately before its single compilation call.
    original_run = module.run
    direct_applied = False
    def run_with_direct(command, **kwargs):
        nonlocal direct_applied
        if args.direct_io_sys and str(command[0]) == "make":
            if direct_applied:
                raise RuntimeError("The direct IO.SYS patch may be applied only once")
            original_run(["patch", "-p1", "--batch", "--forward", "-s", "-i",
                          frozen[direct_patch]], cwd=kwargs["cwd"])
            direct_applied = True
        return original_run(command, **kwargs)
    module.run = run_with_direct
    old_argv = sys.argv
    try:
        sys.argv = [str(BASE), "--jobs", str(args.jobs), "--out", str(out), "--firmware-gop"]
        module.main()
    finally:
        sys.argv = old_argv
    receipt_path = out / "build-result.json"
    receipt = json.loads(receipt_path.read_text())
    # Restore nominal patch names for the existing native runner's ABI check;
    # preserve the actual immutable snapshot name alongside each nominal name.
    by_hash = {item["sha256"]: item for item in bindings}
    receipt["patches"] = [by_hash[item["sha256"]] for item in receipt["patches"]]
    if args.direct_io_sys:
        if not direct_applied:
            raise RuntimeError("The direct IO.SYS patch was not compiled")
        receipt["patches"].append(next(item for item in bindings
                                      if item["patch"] == str(direct_patch.relative_to(REPO))))
    tree = out / "work" / "csmwrap"
    receipt["ios_gop"] = {
        "profile": "IO.SYS early BIOS text on a fixed firmware GOP framebuffer",
        "compiled_support": True,
        "native_windows_gui": "unverified; requires separate actual Windows 98 run",
        "direct_io_sys_entry": "peer opt-in IO.SYS entry port compiled" if args.direct_io_sys else
                               "owned by the cooperating IO.SYS bootstrap chat; not compiled in this comparison",
        "input_snapshot": str(inputs.relative_to(REPO)),
        "wrapper_sha256": hashlib.sha256(wrapper_bytes).hexdigest(),
        "base_build_sha256": hashlib.sha256(base_bytes).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "source_changed_during_build": [item["patch"] for item in bindings
            if digest(REPO / item["patch"]) != item["sha256"]],
        "patched_seavgabios_sources": {str(p.relative_to(tree)): digest(p)
            for p in sorted((tree / "seabios" / "vgasrc").glob("*"))
            if p.is_file() and p.name in ("cbvga.c", "vgabios.c", "shz_legacy_text_geometry.h")},
    }
    if args.direct_io_sys:
        receipt["iosys_uefi"] = {
            "compiled_support": True, "enabled_by_config": "iosys_boot=true", "default": False,
            "capsule_bytes": 2688, "capsule_path": "EFI/BOOT/IOSYS.BIN",
            "entry": "0070:0200", "original_resume": "0070:0208",
            "scope": "cooperating guarded memory entry port plus BIOS GOP mode03 compatibility",
            "native_windows_gui": "not-established",
            "patched_sources": {name: digest(tree / name) for name in
                ("src/iosys_uefi.c", "src/iosys_uefi.h", "src/iosys_entry.asm", "src/csmwrap.c")},
        }
    receipt["firmware_gop"]["build_script_sha256"] = hashlib.sha256(base_bytes).hexdigest()
    receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"Isolated IO.SYS/GOP profile: {receipt_path}")


if __name__ == "__main__":
    main()
