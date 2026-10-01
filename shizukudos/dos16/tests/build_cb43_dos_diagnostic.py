#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Assemble an isolated DOS API diagnostic disk; never start a VM.

Requires supplied source-built WIN31SUPPORT kernel tree and FreeCOM binary,
Open Watcom on PATH with WATCOM set, NASM and mtools. Copies all inputs before
timestamp normalization; no shared build, boot configuration or source writes.
"""
import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO / "shizukudos/tools"))
import fatimg
from verify_cb43_dos_layout import verify


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kernel-tree", type=pathlib.Path, required=True)
    parser.add_argument("--freecom", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    tree, freecom, out = args.kernel_tree.resolve(), args.freecom.resolve(), args.output.resolve()
    if out == tree or tree in out.parents or out == freecom.parent:
        raise SystemExit("use an independent output folder")
    if shutil.disk_usage(out.parent).free <= 17 * 1024 ** 3:
        raise SystemExit("17 GiB disk reserve required")
    if not os.environ.get("WATCOM"):
        raise SystemExit("set WATCOM and put its binl64 on PATH")
    for tool in ("wcl", "nasm", "mformat", "mcopy", "mdir"):
        if not shutil.which(tool):
            raise SystemExit(f"missing real tool: {tool}")
    layout = verify(tree)
    out.mkdir(parents=True, exist_ok=False)
    inputs = out / "inputs"
    inputs.mkdir()
    for name, path in (("KERNEL.SYS", tree / "bin/kernel.sys"), ("COMMAND.COM", freecom),
                       ("fat16com.bin", tree / "boot/fat16com.bin")):
        shutil.copyfile(path, inputs / name)
    if digest(inputs / "KERNEL.SYS") != layout["kernel_sys_sha256"]:
        raise SystemExit("bin/kernel.sys differs from verified kernel/kernel.sys")
    commands = [
        ["wcl", "-zq", "-bt=dos", "-ms", "-os", "-wx", "-we", "-fe=CBDOSINT.EXE", "-fo=./",
         str(pathlib.Path(__file__).with_name("cb43_dos_internals.c"))],
        ["nasm", "-f", "bin", "-w+all", "-o", "SHZEXIT.COM", str(pathlib.Path(__file__).with_name("shzexit.asm"))],
        ["nasm", "-f", "bin", "-w+all", "-o", "mbr.bin", str(REPO / "shizukudos/dos16/mbr.asm")],
    ]
    for command in commands:
        result = subprocess.run(command, cwd=out, capture_output=True, text=True)
        with (out / "compile.log").open("a") as log:
            log.write(result.stdout + result.stderr)
        result.check_returncode()
    (out / "CONFIG.SYS").write_bytes(b"DOS=LOW\r\nFILES=30\r\nBUFFERS=20\r\nSHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n")
    (out / "AUTOEXEC.BAT").write_bytes(
        b"@ECHO OFF\r\nCBDOSINT.EXE\r\nIF ERRORLEVEL 1 GOTO BAD\r\n"
        b"TYPE CBDOSINT.TXT\r\nSHZEXIT.COM 0\r\nGOTO DONE\r\n:BAD\r\n"
        b"TYPE CBDOSINT.TXT\r\nSHZEXIT.COM 1\r\n:DONE\r\n")
    image = out / "cb43-dos-internals.img"
    spec = fatimg.make_hdd(image, out / "mbr.bin")
    fatimg.install_freedos_boot(spec, inputs / "fat16com.bin")
    payload = [(inputs / "KERNEL.SYS", "KERNEL.SYS"), (inputs / "COMMAND.COM", "COMMAND.COM")]
    payload += [(out / name, name) for name in ("CONFIG.SYS", "AUTOEXEC.BAT", "CBDOSINT.EXE", "SHZEXIT.COM")]
    fatimg.copy_in(spec, payload)
    for path, name in payload:
        if fatimg.read_bytes(spec, name) != path.read_bytes():
            raise SystemExit(f"image payload mismatch: {name}")
    manifest = {
        "schema": "shizukudos-cb43-dos-api-diagnostic-image-v1", "vm_started": False,
        "native_checks": "NOT RUN", "windows_boot": "NOT TESTED",
        "image": {"file": image.name, "sha256": digest(image), "bytes": image.stat().st_size},
        "payload": [{"file": name, "sha256": digest(path), "bytes": path.stat().st_size} for path, name in payload],
        "boot_template": {"sha256": digest(inputs / "fat16com.bin"), "bytes": 512},
        "source": [{"file": str(path.relative_to(REPO)), "sha256": digest(path)} for path in (
            pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name("cb43_dos_internals.c"),
            pathlib.Path(__file__).with_name("verify_cb43_dos_layout.py"),
            pathlib.Path(__file__).with_name("shzexit.asm"), REPO / "shizukudos/dos16/mbr.asm",
            REPO / "shizukudos/tools/fatimg.py", REPO / "shizukudos/tools/shzlib.py")],
        "compile_commands": [[str(value).replace(str(REPO) + "/", "<repo>/") for value in command] for command in commands],
        "image_construction": "fatimg.make_hdd(size_mib=32); install_freedos_boot; copy_in; read back every file",
        "kernel_layout": layout,
        "resource_budget": {"disk_image_MiB_max": 32, "guest_RAM_MiB": 128, "guest_CPUs": 1, "disk_reserve_GiB": 17, "suggested_time_limit_seconds": 120},
        "reviewed_guest_requirements": ["TCG only", "-nic none", "own serial file", "dedicated image only", "no Windows or Microsoft inputs", "no CSM or main builder"],
        "end_marker": "SHZ-EXIT:0 or SHZ-EXIT:1 on COM1; guest then halts",
        "limits": ["No VM was launched by this producer", "No synthetic Windows startup broadcast", "No Windows 98, Setup or native modern application success claim"],
    }
    (out / "image-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "image-listing.txt").write_text(fatimg.listing(spec))
    print(json.dumps({"manifest": str(out / "image-manifest.json"), "image_sha256": digest(image), "vm_started": False}))


if __name__ == "__main__":
    main()
