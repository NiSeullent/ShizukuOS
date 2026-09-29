#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build CSMWrap (UEFI application wrapping a SeaBIOS CSM16 build) from the pinned tree.

This is an *external-code* profile: CSMWrap (LGPL-2.1) with its submodules, most
importantly SeaBIOS/SeaVGABIOS (LGPL-3.0), fetched at the commits pinned in
shizukudos/upstream/manifest.json. Nothing here is an original Shizuku
implementation; this script only builds it reproducibly.

On a UEFI class-3 machine CSMWrap recreates the PC BIOS environment (INT 10h/13h/
15h/16h/1Ah ..., BDA/EBDA, E820, MP/PIR tables) and legacy-boots the MBR of the
disk it was started from, which is what a DOS IO.SYS-class kernel needs.

Reproducibility: upstream derives its version string from `git describe`, which
changes whenever new tags appear (and would describe *this* repository in a
.git-free copy). The build runs in a .git-free copy with BUILD_VERSION fixed from
the manifest and a SeaBIOS `.version` file, so SeaBIOS's buildversion.py neither
calls git nor appends a build timestamp and host name.

Local patches: none. The pinned tree builds unmodified with gcc/nasm/xxd, and the two
reproducibility fixes above are make/`.version` inputs, not source changes. Any future
change goes to shizukudos/csm/patches/*.patch (applied with `patch -p1`, hashed in the receipt).

Outputs (build/shizukudos/csm/): CSMWRAP.EFI, Csm16.bin, vgabios.bin, build-result.json.
"""
import argparse
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

OUT = BUILD / "csm"
WORK = OUT / "work"
PATCHES = sorted((SHZ / "csm" / "patches").glob("*.patch"))
UPSTREAM = "csmwrap"
FIXED_EPOCH = "1785283200"  # same fixed stamp as fatimg.FIXED_EPOCH


def build_env():
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": FIXED_EPOCH,
                # a .git-free tree inside this repository must never see the repository's git state
                "GIT_CEILING_DIRECTORIES": str(WORK)})
    return env


def fresh_tree(spec):
    src = shzlib.ensure_upstream(UPSTREAM)
    dst = WORK / UPSTREAM
    if dst.exists():
        shutil.rmtree(dst)
    WORK.mkdir(parents=True, exist_ok=True)
    # Submodule checkouts contain a `.git` *file*; drop both kinds so no git metadata leaks into the build.
    shutil.copytree(src, dst, symlinks=True,
                    ignore=shutil.ignore_patterns(".git", "bin-*", "obj-*", "edk2-ovmf"))
    for stale in ("src/bins", "seabios/out", "seabios/.config"):
        p = dst / stale
        if p.is_dir():
            shutil.rmtree(p)
        elif p.exists():
            p.unlink()
    (dst / "seabios" / ".version").write_text(spec["seabios_version"] + "\n")
    return dst


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jobs", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    args = parser.parse_args()
    manifest = shzlib.load_manifest()
    spec = manifest["upstreams"][UPSTREAM]
    OUT.mkdir(parents=True, exist_ok=True)
    tree = fresh_tree(spec)
    env = build_env()
    applied = []
    for patch in PATCHES:
        run(["patch", "-p1", "-s", "-i", patch], cwd=tree)
        applied.append({"patch": str(patch.relative_to(REPO)), "sha256": sha256_file(patch)})
    # `all` is `make seabios` followed by `make bin-x86_64/csmwrap.efi`; both see the same fixed version.
    cmd = ["make", f"-j{args.jobs}", "ARCH=x86_64", f"BUILD_VERSION={spec['build_version']}", "all"]
    proc = run(cmd, cwd=tree, env=env, timeout=1200, capture=True)
    (OUT / "make.log").write_text(proc.stdout)
    efi = tree / "bin-x86_64" / "csmwrap.efi"
    csm16 = tree / "seabios" / "out" / "Csm16.bin"
    vgabios = tree / "seabios" / "out" / "vgabios.bin"
    for p in (efi, csm16, vgabios):
        if not p.exists():
            raise RuntimeError(f"CSMWrap build produced no {p.relative_to(tree)}")
    autoversion = (tree / "seabios" / "out" / "autoversion.h").read_text()
    seabios_version = next((l.split('"')[1] for l in autoversion.splitlines() if "BUILD_VERSION" in l), "")
    if seabios_version != f"{spec['seabios_version']}-CSMWrap-{spec['build_version']}":
        raise RuntimeError(f"SeaBIOS version string drifted: {seabios_version!r} (timestamp/hostname appended?)")
    if efi.read_bytes()[:2] != b"MZ":
        raise RuntimeError("csmwrap.efi is not a PE image")
    shutil.copy2(efi, OUT / "CSMWRAP.EFI")
    shutil.copy2(csm16, OUT / "Csm16.bin")
    shutil.copy2(vgabios, OUT / "vgabios.bin")
    receipt = {
        "profile": "csm-csmwrap (external code: CSMWrap LGPL-2.1 + SeaBIOS LGPL-3.0)",
        "built_utc": shzlib.utc_now(),
        "git": shzlib.git_state(),
        "upstream": {
            UPSTREAM: {"repository": spec["repository"], "commit": spec["commit"], "license": spec["license"],
                       "build_version": spec["build_version"], "seabios_version": seabios_version,
                       "submodules": {k: {"commit": v["commit"], "license": v["license"]}
                                      for k, v in spec["submodules"].items()}},
        },
        "patches": applied,
        "toolchain": {name: shzlib.tool_version(name, vargs) for name, vargs in
                      (("gcc", ("--version",)), ("ld", ("--version",)), ("nasm", ("-v",)), ("make", ("--version",)),
                       ("xxd", ("-v",)), ("python3", ("--version",)))},
        "build_tree": str(tree.relative_to(REPO)),
        "commands": [f"copy {spec['repository']}@{spec['commit']} (+submodules, without .git) -> "
                     f"{tree.relative_to(REPO)}",
                     f"echo {spec['seabios_version']} > seabios/.version",
                     " ".join(cmd)],
        "artifacts": {
            "CSMWRAP.EFI": {"sha256": sha256_file(efi), "bytes": efi.stat().st_size,
                            "origin": f"CSMWrap {spec['commit'][:12]} bin-x86_64/csmwrap.efi"},
            "Csm16.bin": {"sha256": sha256_file(csm16), "bytes": csm16.stat().st_size,
                          "origin": f"SeaBIOS (seabios-csmwrap {spec['submodules']['seabios']['commit'][:12]}) "
                                    "CONFIG_CSM build, embedded in CSMWRAP.EFI"},
            "vgabios.bin": {"sha256": sha256_file(vgabios), "bytes": vgabios.stat().st_size,
                            "origin": "SeaVGABIOS (CONFIG_VGA_COREBOOT), embedded in CSMWRAP.EFI"},
        },
    }
    shzlib.write_json(OUT / "build-result.json", receipt)
    print(json.dumps(receipt["artifacts"], indent=2))


if __name__ == "__main__":
    main()
