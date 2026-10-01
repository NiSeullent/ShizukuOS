#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Offline, isolated CSMWrap build with the opt-in Windows 98 IO.SYS entry port.

No download or shared firmware output is used. Microsoft IO.SYS is not needed
to build this firmware and is never embedded in the redistributable EFI image.
"""
import argparse
import importlib.util
import json
import shutil
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib


def load_builder():
    spec = importlib.util.spec_from_file_location("iosys_csm_build", HERE.parent / "csm/build.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified_cache(spec):
    source = shzlib.UPSTREAM_DIR / "csmwrap"
    pins = [(source, spec["commit"])] + [
        (source / name, sub["commit"]) for name, sub in spec["submodules"].items()]
    for directory, expected in pins:
        head = shzlib.run(["git", "-C", directory, "rev-parse", "HEAD"], capture=True).stdout.strip()
        if head != expected:
            raise RuntimeError(f"Offline cache pin mismatch: {directory}: {head} != {expected}")
        for args in (["diff", "--quiet"], ["diff", "--cached", "--quiet"]):
            if shzlib.run(["git", "-C", directory, *args], check=False).returncode:
                raise RuntimeError(f"Offline cache has modified tracked sources: {directory}")
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, choices=range(1, 5), default=1)
    parser.add_argument("--out", type=Path, default=shzlib.BUILD / "iosys-uefi-port/firmware")
    args = parser.parse_args()
    out = args.out.resolve()
    own_root = (shzlib.BUILD / "iosys-uefi-port").resolve()
    if out == own_root or not out.is_relative_to(own_root):
        parser.error("--out must be a child of build/shizukudos/iosys-uefi-port")
    spec = shzlib.load_manifest()["upstreams"]["csmwrap"]
    source = verified_cache(spec)
    patches = [HERE.parent / "csm/patches/0001-helper-id-with-disabled-lapic.patch",
               HERE.parent / "csm/patches/0002-force-firmware-gop.patch",
               HERE / "patches/0001-direct-iosys.patch"]
    for patch in patches:
        if not patch.is_file():
            raise RuntimeError(f"Required source patch missing: {patch}")
    out.mkdir(parents=True, exist_ok=True)
    work = out / ("work-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
    work.mkdir()
    tree = work / "csmwrap"
    shutil.copytree(source, tree, symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "bin-*", "obj-*", "edk2-ovmf"))
    for stale in ("src/bins", "seabios/out", "seabios/.config"):
        path = tree / stale
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    (tree / "seabios/.version").write_text(spec["seabios_version"] + "\n")
    baseline = load_builder()
    baseline.WORK = work
    env = baseline.build_env()
    embedding = baseline.prepare_binary_embedding(env)
    applied = []
    for patch in patches:
        shzlib.run(["patch", "-p1", "--fuzz=0", "--batch", "--forward", "-i", patch], cwd=tree, capture=True)
        applied.append({"patch": str(patch.relative_to(shzlib.REPO)),
                        "sha256": shzlib.sha256_file(patch)})
    integrated = (tree / "src/csmwrap.c").read_text()
    if not (integrated.index("Regs.X.AX = Legacy16PrepareToBoot;") <
            integrated.index("iosys_uefi_boot();") < integrated.index("Regs.X.AX = Legacy16Boot;")):
        raise RuntimeError("IO.SYS entry must follow SeaBIOS disk/interrupt initialization")
    cmd = ["make", f"-j{args.jobs}", "ARCH=x86_64", f"BUILD_VERSION={spec['build_version']}", "all"]
    proc = shzlib.run(cmd, cwd=tree, env=env, timeout=1200, capture=True, check=False)
    (out / "make.log").write_text(proc.stdout)
    if proc.returncode:
        raise RuntimeError(f"Firmware build failed; diagnostics: {out / 'make.log'}")
    artifacts = {}
    for name, relative in (("CSMWRAP.EFI", "bin-x86_64/csmwrap.efi"),
                           ("Csm16.bin", "seabios/out/Csm16.bin"),
                           ("vgabios.bin", "seabios/out/vgabios.bin")):
        built = tree / relative
        if not built.is_file() or (name.endswith(".EFI") and built.read_bytes()[:2] != b"MZ"):
            raise RuntimeError(f"Missing or invalid artifact: {built}")
        shutil.copy2(built, out / name)
        artifacts[name] = {"sha256": shzlib.sha256_file(built), "bytes": built.stat().st_size,
                           "origin": relative}
    receipt = {"profile": "actual-win98-iosys-uefi-entry-port", "built_utc": shzlib.utc_now(),
               "upstream": {"csmwrap": spec}, "git": shzlib.git_state(), "patches": applied,
               "binary_embedding": embedding, "build_tree": str(tree.relative_to(shzlib.REPO)),
               "commands": [" ".join(cmd)], "artifacts": artifacts,
               "source_sha256": shzlib.sha256_file(Path(__file__)),
               "firmware_gop": {"compiled_support": True,
                    "abi": {"magic": "SHZGOP1", "major": 1, "minor": 0,
                            "descriptor_bytes": 96, "coreboot_tag": 0x53485a47}},
               "iosys_uefi": {"compiled_support": True, "enabled_by_config": "iosys_boot=true",
                    "default": False, "capsule_bytes": 2688, "capsule_path": "EFI/BOOT/IOSYS.BIN",
                    "entry": "0070:0200", "original_resume": "0070:0208",
                    "scope": "guarded in-memory entry patch; SeaBIOS provides subsequent BIOS services",
                    "native_windows_gui": "not-established"}}
    shzlib.write_json(out / "build-result.json", receipt)
    print(json.dumps({"receipt": str(out / "build-result.json"), "artifacts": artifacts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
