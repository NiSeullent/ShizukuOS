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

Local patches are carried under patches/. The helper-ID patch retains the BIOS proxy's
CPU identity after its LAPIC is hardware-disabled. The pinned tree builds with gcc/nasm and a binary-to-C
converter: xxd when installed, otherwise a build-local Python replacement for its two
`xxd -i` calls. The receipt identifies and hashes that replacement. The two reproducibility
fixes above are make/`.version` inputs, not source changes. Any future upstream change
goes to shizukudos/csm/patches/*.patch (applied with `patch -p1`, hashed in the receipt).

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

DEFAULT_OUT = BUILD / "csm"
OUT = DEFAULT_OUT
WORK = OUT / "work"
FIRMWARE_GOP_PATCH = SHZ / "csm" / "patches" / "0002-force-firmware-gop.patch"
PATCHES = sorted(p for p in (SHZ / "csm" / "patches").glob("*.patch") if p != FIRMWARE_GOP_PATCH)
UPSTREAM = "csmwrap"
FIXED_EPOCH = "1785283200"  # same fixed stamp as fatimg.FIXED_EPOCH
XXD_INCLUDE_FALLBACK = r'''#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Build-local replacement for the pinned CSMWrap tree's two `xxd -i` calls.
import sys
from pathlib import Path

if len(sys.argv) != 3 or sys.argv[1] != "-i" or sys.argv[2] not in ("Csm16.bin", "vgabios.bin"):
    raise SystemExit("CSMWrap xxd fallback supports only -i Csm16.bin or -i vgabios.bin")
data = Path(sys.argv[2]).read_bytes()
name = sys.argv[2].replace(".", "_")
print("unsigned char " + name + "[] = {")
for start in range(0, len(data), 12):
    row = data[start:start + 12]
    suffix = "," if start + len(row) < len(data) else ""
    print("  " + ", ".join("0x%02x" % byte for byte in row) + suffix)
print("};")
print("unsigned int " + name + "_len = " + str(len(data)) + ";")
'''


def build_env():
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "TZ": "UTC", "SOURCE_DATE_EPOCH": FIXED_EPOCH,
                # a .git-free tree inside this repository must never see the repository's git state
                "GIT_CEILING_DIRECTORIES": str(WORK)})
    return env


def prepare_binary_embedding(env):
    """Keep upstream unmodified without installing xxd or changing the host PATH."""
    xxd = shutil.which("xxd", path=env.get("PATH"))
    if xxd:
        return {"backend": "xxd", "path": xxd}
    tools = WORK / "host-tools"
    tools.mkdir(parents=True, exist_ok=True)
    helper = tools / "xxd"
    helper.write_text(XXD_INCLUDE_FALLBACK)
    helper.chmod(0o755)
    env["PATH"] = str(tools) + os.pathsep + env.get("PATH", os.defpath)
    return {"backend": "python3-xxd-i-fallback", "path": str(helper.relative_to(REPO)),
            "sha256": sha256_file(helper), "reason": "xxd absent from the build environment PATH"}


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
    global OUT, WORK
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--jobs", type=int, default=max(1, min(4, os.cpu_count() or 1)))
    parser.add_argument("--out", type=Path, default=OUT,
                        help="Separate build artifact directory under build/shizukudos for firmware comparisons")
    parser.add_argument("--firmware-gop", action="store_true",
                        help="Include the opt-in gop_only configuration and reserved framebuffer handover patch")
    args = parser.parse_args()
    OUT = args.out.resolve()
    if OUT == BUILD.resolve() or not OUT.is_relative_to(BUILD.resolve()):
        parser.error("--out must be a component directory under build/shizukudos")
    if args.firmware_gop and OUT == DEFAULT_OUT.resolve():
        parser.error("--firmware-gop requires a separate --out; the default CSM artifacts are preserved")
    WORK = OUT / "work"
    manifest = shzlib.load_manifest()
    spec = manifest["upstreams"][UPSTREAM]
    OUT.mkdir(parents=True, exist_ok=True)
    tree = fresh_tree(spec)
    env = build_env()
    binary_embedding = prepare_binary_embedding(env)
    applied = []
    selected_patches = PATCHES + ([FIRMWARE_GOP_PATCH] if args.firmware_gop else [])
    for patch in selected_patches:
        run(["patch", "-p1", "-s", "-i", patch], cwd=tree)
        applied.append({"patch": str(patch.relative_to(REPO)), "sha256": sha256_file(patch)})
    # `all` is `make seabios` followed by `make bin-x86_64/csmwrap.efi`; both see the same fixed version.
    cmd = ["make", f"-j{args.jobs}", "ARCH=x86_64", f"BUILD_VERSION={spec['build_version']}", "all"]
    proc = run(cmd, cwd=tree, env=env, timeout=1200, capture=True, check=False)
    (OUT / "make.log").write_text(proc.stdout)
    if proc.returncode:
        raise RuntimeError(f"CSMWrap make failed ({proc.returncode}); full diagnostics: {OUT / 'make.log'}")
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
        "binary_embedding": binary_embedding,
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
    if args.firmware_gop:
        receipt["firmware_gop"] = {
            "compiled_support": True,
            "abi": {"magic": "SHZGOP1", "major": 1, "minor": 0,
                    "descriptor_bytes": 96, "coreboot_tag": 0x53485a47},
            "persistent_locator": {"magic": "SHZLOC1", "major": 1, "minor": 0,
                                   "bytes": 48, "physical_scan_base": 0xf0000,
                                   "physical_scan_bytes": 0x10000, "alignment": 16,
                                   "allocator": "SeaBIOS Legacy16GetTableAddress AX=6 BX=1 CX=48 DX=16",
                                   "descriptor_binding": "self physical address and final SHZGOP1 checksum",
                                   "runtime_lifetime": "pending actual Windows VMM/reboot capture"},
            "enabled_by_config": "gop_only=true in csmwrap.ini next to CSMWRAP.EFI",
            "default": False,
            "handover": "SHZGOP1 ABI 1.0: 96-byte reserved descriptor, private CB tag 0x53485a47; additive SHZLOC1 ABI 1.0 allocator-backed F-segment anchor",
            "runtime_validation": "pending; build success does not establish a native Windows display driver",
            "build_script_sha256": sha256_file(Path(__file__)),
            "patched_sources": {name: sha256_file(tree / "src" / name) for name in
                                ("config.h", "config.c", "csmwrap.h", "csmwrap.c", "video.c", "coreboot.c", "shzgop.h")},
        }
    shzlib.write_json(OUT / "build-result.json", receipt)
    print(json.dumps(receipt["artifacts"], indent=2))


if __name__ == "__main__":
    main()
