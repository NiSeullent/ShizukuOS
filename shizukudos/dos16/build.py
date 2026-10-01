#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
r"""Build the DOS16 runtime from pinned FreeDOS sources and assemble a boot image.

The current DOS-compatibility bootstrap uses FreeDOS/FreeCOM (GPL-2.0-or-later)
built from pinned source with Open Watcom and recorded local patches. ShizukuDOS
is the MS-DOS replacement for Windows 98; the current external-code bootstrap
does not yet complete that Windows 98 boot/GUI/kernel connection.

Outputs (all under build/shizukudos/dos16/): kernel.sys, command.com, test
programs, shizukudos-dos16-hd32.img, shizukudos-dos16-dual.img,
shizukudos-dos10.img and build-result.json.

shizukudos-dos10.img is the normal BIOS/UEFI-CSM compatibility-shell profile:
AUTOEXEC calls SHZSTART.BAT and returns to a permanent COMMAND.COM prompt.
Startup failure or SHZSAFE.TAG selects a recovery prompt. It never runs the
conformance programs or SHZEXIT automatically. The older two images remain
unchanged conformance profiles for the existing developer harnesses.

shizukudos-dos16-dual.img is the same MBR + FAT16 + FreeDOS disk with T_INTS (BIOS
interrupt coverage) added to AUTOEXEC.BAT and \EFI\BOOT\BOOTX64.EFI = CSMWrap
(external, LGPL-2.1; wraps SeaBIOS CSM16, LGPL-3.0; built by shizukudos/csm/build.py).
One image boots two ways: legacy BIOS -> MBR -> FreeDOS, and UEFI -> CSMWrap ->
SeaBIOS CSM16 -> the same MBR -> FreeDOS. hd32.img is left exactly as before.
"""
import argparse
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import fatimg  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

OUT = BUILD / "dos16"
WORK = OUT / "work"
TESTS = SHZ / "dos16" / "tests"
CSM = BUILD / "csm"
PATCHES = sorted((SHZ / "dos16" / "patches").glob("0*.patch"))
FREECOM_PATCHES = sorted((SHZ / "dos16" / "patches").glob("freecom-*.patch"))
USER = Path(__file__).resolve().parent / "user"
USER_FILES = ("CONFIG.SYS", "AUTOEXEC.BAT", "SHZSTART.BAT", "RECOVER.BAT", "README.TXT")

CONFIG_SYS = (
    "DOS=LOW\r\nFILES=30\r\nBUFFERS=20\r\nLASTDRIVE=Z\r\n"
    "SHELL=C:\\COMMAND.COM C:\\ /E:512 /P\r\n"
)
AUTOEXEC_BAT = (
    "@ECHO OFF\r\n"
    "SET PATH=C:\\\r\n"
    "ECHO ShizukuDOS 10.0-dev DOS16 conformance run\r\n"
    "T_MODE.COM\r\n"
    "T_BIOS.COM\r\n"
    "T_COM.COM\r\n"
    "T_EXE.EXE ARG1 ARG2\r\n"
    "IF ERRORLEVEL 43 GOTO EXEBAD\r\n"
    "IF ERRORLEVEL 42 GOTO EXEOK\r\n"
    ":EXEBAD\r\n"
    "ECHO T_EXE_EXITCODE FAIL>>RESULT.TXT\r\n"
    "GOTO DONE\r\n"
    ":EXEOK\r\n"
    "ECHO T_EXE_EXITCODE PASS>>RESULT.TXT\r\n"
    ":DONE\r\n"
    "ECHO DONE>>RESULT.TXT\r\n"
    "SHZEXIT.COM 0\r\n"
)
# The dual BIOS/UEFI image additionally runs T_INTS (writes INTS.TXT) right after T_BIOS.
AUTOEXEC_DUAL_BAT = AUTOEXEC_BAT.replace("T_BIOS.COM\r\n", "T_BIOS.COM\r\nT_INTS.COM\r\n")
# CSMWrap configuration next to BOOTX64.EFI: log to COM1 so the host harness sees the UEFI path.
CSMWRAP_INI = (
    "; ShizukuDOS dual image: CSMWrap debug log on COM1 (read by shizukudos/csm/test_qemu.py)\r\n"
    "serial=true\r\nserial_port=0x3f8\r\nserial_baud=115200\r\n"
)


def fresh_copy(name):
    src = shzlib.ensure_upstream(name)
    dst = WORK / name
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    return dst


def build_kernel(env):
    tree = fresh_copy("freedos-kernel")
    applied = []
    for patch in PATCHES:
        run(["patch", "-p1", "-s", "-i", patch], cwd=tree)
        applied.append({"patch": str(patch.relative_to(REPO)), "sha256": sha256_file(patch)})
    # Both halves are required: C interrupt hooks and their assembly data.
    config = "XNASM=nasm\nundefine XUPX\nALLCFLAGS=-DWIN31SUPPORT\nNASMFLAGS=-DWIN31SUPPORT\n"
    config_path = tree / "config.mak"
    config_path.write_text(config)
    make_config = {"text": config, "sha256": sha256_file(config_path),
                   "c_defines": ["WIN31SUPPORT"], "nasm_defines": ["WIN31SUPPORT"]}
    commands = []
    cmd = ["make", "all", "XCPU=386", "XFAT=32"]
    run(cmd, cwd=tree, env=env, timeout=600, capture=True)
    if sha256_file(config_path) != make_config["sha256"]:
        raise RuntimeError("FreeDOS compilation configuration changed during build")
    commands.append(" ".join(cmd))
    kernel = tree / "bin" / "kernel.sys"
    boot = tree / "boot" / "fat16com.bin"
    if not kernel.exists() or not boot.exists():
        raise RuntimeError("FreeDOS kernel build produced no kernel.sys / fat16com.bin")
    return {"tree": tree, "kernel": kernel, "boot_fat16": boot, "sys": tree / "bin" / "sys.com",
            "patches": applied, "commands": commands, "make_config": make_config}


def build_freecom(env):
    tree = fresh_copy("freedos-freecom")
    applied = []
    for patch in FREECOM_PATCHES:
        run(["patch", "-p1", "-s", "-i", patch], cwd=tree)
        applied.append({"patch": str(patch.relative_to(REPO)), "sha256": sha256_file(patch)})
    cmd = ["bash", "build.sh"]
    run(cmd, cwd=tree, env=env, timeout=600, capture=True)
    command_com = tree / "command.com"
    if not command_com.exists():
        raise RuntimeError("FreeCOM build produced no command.com")
    return {"tree": tree, "command": command_com, "commands": [" ".join(cmd)], "patches": applied}


def build_tests(env):
    programs = {}
    OUT.joinpath("tests").mkdir(parents=True, exist_ok=True)
    commands = []
    for name in ("t_mode", "t_bios", "t_ints", "t_com", "shzexit"):
        out = OUT / "tests" / f"{name}.com"
        cmd = ["nasm", "-f", "bin", "-w+all", "-o", out, TESTS / f"{name}.asm"]
        run(cmd, cwd=TESTS)
        commands.append(" ".join(str(x) for x in cmd))
        programs[name] = out
    exe = OUT / "tests" / "t_exe.exe"
    cmd = ["wcl", "-zq", "-bt=dos", "-ms", "-os", f"-fe={exe}", "-fo=" + str(OUT / "tests") + "/",
           TESTS / "t_exe.c"]
    run(cmd, cwd=OUT / "tests", env=env, capture=True)
    commands.append(" ".join(str(x) for x in cmd))
    programs["t_exe"] = exe
    return programs, commands


def assemble_image(kernel, freecom, tests, name="shizukudos-dos16-hd32.img", autoexec=AUTOEXEC_BAT,
                   autoexec_host="AUTOEXEC.BAT", extra_tests=()):
    image = OUT / name
    mbr = OUT / "mbr.bin"
    run(["nasm", "-f", "bin", "-w+all", "-o", mbr, SHZ / "dos16" / "mbr.asm"])
    spec = fatimg.make_hdd(image, mbr)
    fatimg.install_freedos_boot(spec, kernel["boot_fat16"])
    cfg = OUT / "CONFIG.SYS"
    auto = OUT / autoexec_host
    cfg.write_bytes(CONFIG_SYS.encode("ascii"))
    auto.write_bytes(autoexec.encode("ascii"))
    fatimg.copy_in(spec, [
        (kernel["kernel"], "KERNEL.SYS"),
        (freecom["command"], "COMMAND.COM"),
        (cfg, "CONFIG.SYS"),
        (auto, "AUTOEXEC.BAT"),
        (tests["t_mode"], "T_MODE.COM"),
        (tests["t_bios"], "T_BIOS.COM"),
        *[(tests[t], f"{t.upper()}.COM") for t in extra_tests],
        (tests["t_com"], "T_COM.COM"),
        (tests["t_exe"], "T_EXE.EXE"),
        (tests["shzexit"], "SHZEXIT.COM"),
    ])
    return image


def ensure_csmwrap():
    """CSMWRAP.EFI rebuilt when absent, changed, or built with different pinned patches."""
    spec = shzlib.load_manifest()["upstreams"]["csmwrap"]
    receipt = CSM / "build-result.json"
    efi = CSM / "CSMWRAP.EFI"
    current = False
    wanted_patches = [{"patch": name, "sha256": sha256_file(REPO / name)}
                      for name in spec.get("patches", [])]
    if efi.exists() and receipt.exists():
        got = json.loads(receipt.read_text())
        up = got.get("upstream", {}).get("csmwrap", {})
        current = (up.get("commit") == spec["commit"] and up.get("build_version") == spec["build_version"]
                   and got.get("patches", []) == wanted_patches
                   and got.get("artifacts", {}).get("CSMWRAP.EFI", {}).get("sha256") == sha256_file(efi))
    if not current:
        run([sys.executable, SHZ / "csm" / "build.py"], timeout=1800)
    return efi, json.loads(receipt.read_text())


def assemble_dual(kernel, freecom, tests, csm_efi):
    """hd32 content + T_INTS in AUTOEXEC + \\EFI\\BOOT\\BOOTX64.EFI (CSMWrap) + csmwrap.ini."""
    image = assemble_image(kernel, freecom, tests, name="shizukudos-dos16-dual.img",
                           autoexec=AUTOEXEC_DUAL_BAT, autoexec_host="AUTOEXEC-DUAL.BAT",
                           extra_tests=("t_ints",))
    boot_efi = OUT / "BOOTX64.EFI"
    shutil.copyfile(csm_efi, boot_efi)
    ini = OUT / "csmwrap.ini"
    ini.write_bytes(CSMWRAP_INI.encode("ascii"))
    spec = fatimg.partition_spec(image)
    fatimg.make_dirs(spec, ["EFI", "EFI/BOOT"])
    fatimg.copy_in(spec, [(boot_efi, "EFI/BOOT/BOOTX64.EFI"), (ini, "EFI/BOOT/csmwrap.ini")])
    return image


def user_text(path):
    """ASCII DOS text with one CRLF per line, without modifying source files."""
    return Path(path).read_text(encoding="ascii").replace("\r\n", "\n").replace("\n", "\r\n").encode("ascii")


def assemble_user(kernel, freecom, csm_efi):
    """Normal DOS10 shell, on one MBR/FAT16 image bootable by BIOS or UEFI-CSM.

    This is a compatibility bootstrap for the Windows 98 architecture, not a
    Windows 98 installation or proof of complete MS-DOS compatibility.
    """
    work = OUT / "user-boot"
    work.mkdir(parents=True, exist_ok=True)
    mbr, ready = work / "mbr.bin", work / "SHZREADY.COM"
    commands = [
        ["nasm", "-f", "bin", "-w+all", "-o", mbr, SHZ / "dos16" / "mbr.asm"],
        ["nasm", "-f", "bin", "-w+all", "-o", ready, USER / "ready.asm"],
    ]
    for command in commands:
        run(command)
    members = {"SHZREADY.COM": ready}
    for name, source in (("KERNEL.SYS", kernel["kernel"]), ("COMMAND.COM", freecom["command"])):
        target = work / name
        shutil.copyfile(source, target)
        members[name] = target
    for name in USER_FILES:
        target = work / name
        target.write_bytes(user_text(USER / name))
        members[name] = target
    config = members["CONFIG.SYS"].read_bytes()
    if b" /P\r\n" not in config or not members["AUTOEXEC.BAT"].stat().st_size:
        raise RuntimeError("Normal DOS profile requires a permanent shell and a real AUTOEXEC.BAT")
    boot = work / "BOOTX64.EFI"
    shutil.copyfile(csm_efi, boot)
    ini = work / "csmwrap.ini"
    ini.write_bytes(CSMWRAP_INI.encode("ascii"))
    members.update({"EFI/BOOT/BOOTX64.EFI": boot, "EFI/BOOT/csmwrap.ini": ini})
    image = OUT / "shizukudos-dos10.img"
    spec = fatimg.make_hdd(image, mbr)
    fatimg.install_freedos_boot(spec, kernel["boot_fat16"])
    # KERNEL.SYS stays first, as required by the boot-image construction contract.
    ordered = ["KERNEL.SYS", "COMMAND.COM", *[n for n in members if n not in ("KERNEL.SYS", "COMMAND.COM")]]
    fatimg.copy_in(spec, [(members[name], name) for name in ordered if "/" not in name])
    fatimg.make_dirs(spec, ["EFI", "EFI/BOOT"])
    fatimg.copy_in(spec, [(members[name], name) for name in ordered if "/" in name])
    for name, source in members.items():
        if fatimg.read_bytes(spec, name) != source.read_bytes():
            raise RuntimeError(f"Normal DOS image readback differs: {name}")
    inputs = [Path(__file__).resolve(), USER / "ready.asm", *(USER / n for n in USER_FILES)]
    pins = {str(p.relative_to(REPO)): sha256_file(p) for p in inputs}
    return image, {
        "profile": "dos10-user-compatibility-bootstrap", "product": "ShizukuOS 1.0.0",
        "kernel_origin": "pinned FreeDOS ke2046 + recorded local patches",
        "shell_origin": "pinned FreeCOM 04fc21a", "auto_start": "C:\\SHZSTART.BAT",
        "recovery": "startup absent/nonzero, SHZSAFE.TAG, RECOVER.BAT, retained F5/F8",
        "permanent_shell": True, "conformance_auto_run": False,
        "Windows98_native_boot_connection_complete": False,
        "sources_sha256": pins,
        "members": {n: {"bytes": p.stat().st_size, "sha256": sha256_file(p)} for n, p in members.items()},
        "commands": [" ".join(str(x) for x in cmd) for cmd in commands],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    env = shzlib.ow_env()
    snapshot, snapshot_pin = shzlib.open_watcom_snapshot()
    if not snapshot:
        raise RuntimeError("Open Watcom build has no recorded snapshot")
    kernel = build_kernel(env)
    freecom = build_freecom(env)
    tests, test_commands = build_tests(env)
    image = assemble_image(kernel, freecom, tests)
    csm_efi, csm_receipt = ensure_csmwrap()
    dual = assemble_dual(kernel, freecom, tests, csm_efi)
    user_image, user_receipt = assemble_user(kernel, freecom, csm_efi)
    manifest = shzlib.load_manifest()
    for name in ("kernel.sys",):
        shutil.copy2(kernel["kernel"], OUT / name)
    shutil.copy2(freecom["command"], OUT / "command.com")
    receipt = {
        "profile": "dos16-freedos",
        "built_utc": shzlib.utc_now(),
        "git": shzlib.git_state(),
        "upstream": {k: {"commit": v["commit"], "ref": v["ref"], "license": v["license"]}
                     for k, v in manifest["upstreams"].items()},
        "patches": kernel["patches"] + freecom["patches"],
        "kernel_make_config": kernel["make_config"],
        "user_boot": user_receipt,
        "toolchain": {
            "open-watcom": {"snapshot_sha256": snapshot,
                            "manifest_snapshot_sha256": snapshot_pin,
                            "matches_manifest": snapshot == snapshot_pin},
            "nasm": shzlib.tool_version("nasm", ("-v",)),
            "mtools": shzlib.tool_version("mformat", ("--version",)),
        },
        "commands": ["nasm -f bin dos16/mbr.asm"] + kernel["commands"] + freecom["commands"] + test_commands + user_receipt["commands"],
        "artifacts": {
            "kernel.sys": {"sha256": sha256_file(kernel["kernel"]),
                           "bytes": kernel["kernel"].stat().st_size,
                           "origin": "FreeDOS kernel ke2046 + shizukudos patches"},
            "command.com": {"sha256": sha256_file(freecom["command"]),
                            "bytes": freecom["command"].stat().st_size,
                            "origin": "FreeCOM 04fc21a (FDOS/freecom master)"},
            "hd32.img": {"sha256": sha256_file(image), "bytes": image.stat().st_size},
            "dual.img": {"sha256": sha256_file(dual), "bytes": dual.stat().st_size,
                         "origin": "hd32 content + T_INTS + EFI/BOOT/BOOTX64.EFI (CSMWrap, external LGPL-2.1 "
                                   "with SeaBIOS CSM16 LGPL-3.0) + EFI/BOOT/csmwrap.ini"},
            "dos10.img": {"sha256": sha256_file(user_image), "bytes": user_image.stat().st_size,
                          "origin": "normal automatic startup + permanent compatibility/recovery shell + UEFI CSMWrap"},
            "BOOTX64.EFI": {"sha256": sha256_file(csm_efi), "bytes": csm_efi.stat().st_size,
                            "origin": "shizukudos/csm/build.py (CSMWrap "
                                      f"{csm_receipt['upstream']['csmwrap']['commit'][:12]})"},
            **{f"{name}": {"sha256": sha256_file(path), "bytes": path.stat().st_size,
                            "origin": "original Shizuku test program"}
               for name, path in tests.items()},
        },
        "image_listing": fatimg.listing(fatimg.partition_spec(image)),
        "dual_image_listing": fatimg.listing(fatimg.partition_spec(dual)) +
                              fatimg.listing(fatimg.partition_spec(dual), "EFI/BOOT"),
        "user_image_listing": fatimg.listing(fatimg.partition_spec(user_image)) +
                              fatimg.listing(fatimg.partition_spec(user_image), "EFI/BOOT"),
    }
    if shzlib.open_watcom_snapshot() != (snapshot, snapshot_pin):
        raise RuntimeError("Open Watcom snapshot changed during build")
    shzlib.write_json(OUT / "build-result.json", receipt)
    print(json.dumps({k: receipt["artifacts"][k] for k in ("kernel.sys", "command.com", "hd32.img", "dual.img", "dos10.img")},
                     indent=2))


if __name__ == "__main__":
    main()
