#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot-manager test: one MBR disk that boots FreeDOS on legacy BIOS *and* on UEFI.

Disk layout (built here, never shipped): an MBR partition table with one active
FAT16 partition at LBA 63 holding
    KERNEL.SYS, COMMAND.COM, CONFIG.SYS, AUTOEXEC.BAT + conformance programs  (FreeDOS DOS16)
    \\EFI\\BOOT\\BOOTX64.EFI       the Shizuku Supervisor loader / boot manager
    \\EFI\\SHIZUKU\\CSMWRAP.EFI    CSMWrap (LGPL-2.1, wraps SeaBIOS CSM16) built from the pinned clone
    \\EFI\\SHIZUKU\\csmwrap.ini    CSMWrap's own config: serial debug on COM1 (evidence only)
    \\SHZDOS\\DISK.IMG             the Supervisor's RAM-disk input (+ guest kernels if built)
    \\EFI\\SHIZUKU\\BOOT.INI       per case (absent = built-in mode=auto)

Cases (QEMU TCG here; no case exercises Intel VMX, which this host cannot provide):
    auto            OVMF, Intel CPU model without VMX, no BOOT.INI: loader reports VMX unusable,
                    chain-loads CSMWrap, SeaBIOS legacy-boots the MBR, FreeDOS runs AUTOEXEC,
                    host verifies RESULT.TXT & co on the disk afterwards (dos16/verify.py)
    csm             OVMF, AMD CPU model, BOOT.INI mode=csm (CRLF, comments, mixed case): same run
    supervisor      BOOT.INI mode=supervisor without VMX: refuses, returns to firmware
    missing         mode=csm with csm_path to a file that does not exist: clear error, returns
    missing-default no BOOT.INI and \\EFI\\SHIZUKU\\CSMWRAP.EFI deleted: clear error, returns
    malformed-key   BOOT.INI with an unknown key: rejected as a whole, returns
    malformed-mode  BOOT.INI with an invalid mode value: rejected as a whole, returns
    not-an-image    csm_path points at a text file: LoadImage() error reported, returns
    one-cpu         -smp 1: CSMWrap's 2-processor requirement is checked before it can hang
    legacy          the same disk on SeaBIOS (i440fx, legacy BIOS): MBR -> FreeDOS -> verify
plus a host test of the BOOT.INI parser (shizukudos/supervisor/loader/bootini.c) under ASan/UBSan.
"Returned to firmware" is proven by OVMF's own BdsDxe line "failed to start Boot000N ...: <status>".
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[0] / "tools"))
sys.path.insert(0, str(HERE.parents[0] / "dos16"))
import fatimg  # noqa: E402
import qemu  # noqa: E402
import shzlib  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

OUT = BUILD / "bootmgr"
SUP = BUILD / "supervisor"
DOS16_IMAGE = BUILD / "dos16" / "shizukudos-dos16-hd32.img"
CSMWRAP_COMMIT = "7f30b740c352ee952eb596bf10ae263a8a5da4c7"
INTEL_NO_VMX = "qemu64,vendor=GenuineIntel"      # TCG cannot provide VMX at all; vendor chosen to hit the Intel path
AMD_CPU = "qemu64"                                # QEMU's default AuthenticAMD model
CSMWRAP_INI = b"; CSMWrap configuration (evidence only): mirror its log to COM1\r\nserial = true\r\nserial_port = 0x3f8\r\n"
MTOOLS_ENV = {**os.environ, "MTOOLS_SKIP_CHECK": "1", "TZ": "UTC"}

INI_CSM = (b"; Shizuku boot manager policy\r\n# comments and blank lines are allowed\r\n\r\n"
           b"  Mode = CSM  \r\ncsm_path = \\EFI\\SHIZUKU\\CSMWRAP.EFI\r\n")
INI_SUPERVISOR = b"mode = supervisor\n"
INI_MISSING = b"mode = csm\ncsm_path = \\EFI\\SHIZUKU\\NOPE.EFI\n"
INI_BAD_KEY = b"mode = auto\ntimeout = 5\n"
INI_BAD_MODE = b"mode = legacy\n"
INI_NOT_IMAGE = b"mode = auto\ncsm_path = \\EFI\\SHIZUKU\\csmwrap.ini\n"

DOS_RUN = "dos"            # expectation kinds
RETURN = "return"


def case_table():
    return [
        {"name": "auto", "ini": None, "cpu": INTEL_NO_VMX, "smp": 2, "expect": DOS_RUN,
         "serial": ["no \\EFI\\SHIZUKU\\BOOT.INI; built-in policy mode=auto",
                    "Supervisor profile not available: Intel VMX backend unusable: CPUID does not report VMX",
                    "CSM legacy boot (mode=auto, no usable virtualization backend)",
                    "CSM legacy boot: CSMWrap loaded"]},
        {"name": "csm", "ini": INI_CSM, "cpu": AMD_CPU, "smp": 2, "expect": DOS_RUN,
         "serial": ["\\EFI\\SHIZUKU\\BOOT.INI mode=csm, csm_path=\\EFI\\SHIZUKU\\CSMWRAP.EFI",
                    "CSM legacy boot (mode=csm)", "CSM legacy boot: CSMWrap loaded"],
         "absent": ["Supervisor profile not available", "VMX"]},
        {"name": "supervisor", "ini": INI_SUPERVISOR, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Unsupported",
         "serial": ["BOOT.INI mode=supervisor", "REFUSED: Intel VMX backend unusable: CPUID does not report VMX",
                    "Returning to firmware."]},
        {"name": "missing", "ini": INI_MISSING, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Not Found",
         "serial": ["REFUSED: CSM legacy boot image \\EFI\\SHIZUKU\\NOPE.EFI not found on the boot volume",
                    "Returning to firmware."]},
        {"name": "missing-default", "ini": None, "delete": ["::/EFI/SHIZUKU/CSMWRAP.EFI"], "cpu": INTEL_NO_VMX,
         "smp": 2, "expect": RETURN, "status": "Not Found",
         "serial": ["Supervisor profile not available: Intel VMX backend unusable",
                    "REFUSED: CSM legacy boot image \\EFI\\SHIZUKU\\CSMWRAP.EFI not found on the boot volume",
                    "Returning to firmware."]},
        {"name": "malformed-key", "ini": INI_BAD_KEY, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Invalid Parameter",
         "serial": ["REFUSED: \\EFI\\SHIZUKU\\BOOT.INI line 2: unknown key 'timeout' (allowed: mode, csm_path)",
                    "rejected as a whole; nothing was started. Returning to firmware."],
         "absent": ["Intel VMX", "CSM legacy boot"]},
        {"name": "malformed-mode", "ini": INI_BAD_MODE, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Invalid Parameter",
         "serial": ["REFUSED: \\EFI\\SHIZUKU\\BOOT.INI line 1: invalid mode 'legacy' "
                    "(expected auto, supervisor or csm)"],
         "absent": ["Intel VMX", "CSM legacy boot"]},
        {"name": "not-an-image", "ini": INI_NOT_IMAGE, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": None,
         "serial": ["REFUSED: firmware LoadImage() rejected \\EFI\\SHIZUKU\\csmwrap.ini",
                    "The file is not a loadable x64 UEFI application", "Returning to firmware."]},
        {"name": "one-cpu", "ini": None, "cpu": INTEL_NO_VMX, "smp": 1, "expect": RETURN, "status": "Unsupported",
         "serial": ["REFUSED: CSMWrap needs at least 2 enabled logical processors", "this machine reports 1",
                    "Returning to firmware."]},
        {"name": "legacy", "legacy": True, "expect": DOS_RUN, "serial": []},
    ]


# ------------------------------------------------------------------ inputs
def mtools(*args, check=True):
    return run([*args], env=MTOOLS_ENV, capture=True, check=check)


def csmwrap_image(args, record):
    """CSMWrap EFI image: explicit path, else the C1 product build, else `make` in a copy of the pinned clone."""
    if args.csmwrap:
        path = Path(args.csmwrap).resolve()
        record["csmwrap"] = {"source": "command line", "path": str(path)}
    elif (SHZ / "csm" / "build.py").exists():
        product = BUILD / "csm" / "CSMWRAP.EFI"
        if not product.exists():
            run([sys.executable, SHZ / "csm" / "build.py"], timeout=1800)
        path = product
        record["csmwrap"] = {"source": "shizukudos/csm/build.py", "path": str(path)}
    else:
        clone = shzlib.UPSTREAM_DIR / "csmwrap"
        head = subprocess.run(["git", "-C", str(clone), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        if head != CSMWRAP_COMMIT:
            raise SystemExit(f"build/upstream/csmwrap must be the pinned clone {CSMWRAP_COMMIT} (found {head or 'none'})")
        dirty = subprocess.run(["git", "-C", str(clone), "status", "--porcelain", "--ignore-submodules=none"],
                               capture_output=True, text=True).stdout.strip()
        subs = subprocess.run(["git", "-C", str(clone), "submodule", "status", "--recursive"],
                              capture_output=True, text=True).stdout.strip().splitlines()
        work = OUT / "csmwrap-src"
        path = work / "bin-x86_64" / "csmwrap.efi"
        stamp = OUT / "csmwrap-build.json"
        previous = json.loads(stamp.read_text()) if stamp.exists() else {}
        if not path.exists() or previous.get("commit") != head or previous.get("submodules") != subs:
            shutil.rmtree(work, ignore_errors=True)
            shutil.copytree(clone, work, symlinks=True, ignore=shutil.ignore_patterns("bin-*", "obj-*"))
            run(["make", "-C", work, f"-j{os.cpu_count() or 2}"], capture=True, timeout=1800)
            shzlib.write_json(stamp, {"commit": head, "submodules": subs, "sha256": sha256_file(path),
                                      "command": f"cp -a build/upstream/csmwrap {work.relative_to(REPO)} (minus bin-*/obj-*); "
                                                 f"make -C {work.relative_to(REPO)}",
                                      "utc": shzlib.utc_now()})
        record["csmwrap"] = {"source": "make in a copy of the pinned clone (shizukudos/csm/build.py absent in this tree)",
                             "path": str(path), "commit": head, "clone_dirty": bool(dirty), "submodules": subs,
                             "build": json.loads(stamp.read_text())}
    if not path.exists():
        raise SystemExit(f"CSMWrap image missing: {path}")
    data = path.read_bytes()
    pe = int.from_bytes(data[0x3c:0x40], "little")
    if data[:2] != b"MZ" or data[pe:pe + 4] != b"PE\0\0" or int.from_bytes(data[pe + 4:pe + 6], "little") != 0x8664:
        raise SystemExit(f"{path} is not an x64 PE image")
    record["csmwrap"].update({"sha256": sha256_file(path), "bytes": len(data), "license": "LGPL-2.1 (CSMWrap), "
                              "LGPL-3.0 (SeaBIOS CSM16 inside it); started as a separate image, not linked"})
    return path


def check_loader_fresh():
    loader = SUP / "BOOTX64.EFI"
    receipt = SUP / "build-result.json"
    if not (loader.exists() and receipt.exists()):
        raise SystemExit("Run shizukudos/supervisor/build.py first")
    built = json.loads(receipt.read_text())
    for name, digest in built["sources_sha256"].items():
        if sha256_file(REPO / name) != digest:
            raise SystemExit(f"Stale Supervisor build, source changed: {name}; rerun shizukudos/supervisor/build.py")
    if built["artifacts"]["BOOTX64.EFI"]["sha256"] != sha256_file(loader):
        raise SystemExit("BOOTX64.EFI does not match build-result.json")
    return loader


def build_disk(work, loader, csmwrap, record):
    """MBR + one active FAT16 partition with FreeDOS and the UEFI boot files."""
    if not DOS16_IMAGE.exists():
        raise SystemExit("Run shizukudos/dos16/build.py first (the FreeDOS system is an input)")
    src = fatimg.partition_spec(DOS16_IMAGE)
    names = [l.strip()[3:] for l in mtools("mdir", "-b", "-i", src, "::/").stdout.splitlines() if l.strip()]
    if "KERNEL.SYS" not in names:
        raise SystemExit(f"{DOS16_IMAGE} has no KERNEL.SYS in its root: {names}")
    names.remove("KERNEL.SYS")
    names.insert(0, "KERNEL.SYS")                   # same order the dos16 build uses: kernel first
    dos_files = work / "dos"
    dos_files.mkdir()
    for name in names:
        mtools("mcopy", "-n", "-m", "-i", src, f"::/{name}", dos_files / name)
    with open(DOS16_IMAGE, "rb") as fh:
        mbr = fh.read(512)
        fh.seek(fatimg.PART_START * 512)
        boot_template = fh.read(512)                # FreeDOS FAT16 boot code (fat16com) of the DOS16 image
    (work / "mbr.bin").write_bytes(mbr)
    (work / "fat16boot.bin").write_bytes(boot_template)
    shzdos = [(DOS16_IMAGE, "DISK.IMG")] + [(p, p.name) for p in (BUILD / "kernel32" / "KERNEL32.BIN",
                                                                BUILD / "kernel64" / "KERNEL64.BIN",
                                                                BUILD / "win64" / "WIN64.IMG") if p.exists()]
    payload = sum(p.stat().st_size for p in dos_files.iterdir()) + loader.stat().st_size + \
        csmwrap.stat().st_size + sum(p.stat().st_size for p, _ in shzdos)
    size_mib = max(64, -(-(payload * 5 // 4 + (8 << 20)) // (8 << 20)) * 8)
    if size_mib > 480:
        raise SystemExit(f"payload needs {size_mib} MiB; the CHS-addressable FAT16 layout stops at 504 MiB")
    disk = work / "bootmgr-disk.img"
    spec = fatimg.make_hdd(disk, work / "mbr.bin", size_mib=size_mib, label="SHIZUKU", serial=0x53485A42)
    fatimg.install_freedos_boot(spec, work / "fat16boot.bin")
    fatimg.copy_in(spec, [(dos_files / n, n) for n in names])
    mtools("mmd", "-i", spec, "::/EFI", "::/EFI/BOOT", "::/EFI/SHIZUKU", "::/SHZDOS")
    (work / "csmwrap.ini").write_bytes(CSMWRAP_INI)
    shutil.copyfile(loader, work / "BOOTX64.EFI")      # copy_in stamps file times: never touch the inputs
    shutil.copyfile(csmwrap, work / "CSMWRAP.EFI")
    fatimg.copy_in(spec, [(work / "BOOTX64.EFI", "EFI/BOOT/BOOTX64.EFI"), (work / "CSMWRAP.EFI", "EFI/SHIZUKU/CSMWRAP.EFI"),
                          (work / "csmwrap.ini", "EFI/SHIZUKU/csmwrap.ini")])
    for path, name in shzdos:
        mtools("mcopy", "-m", "-i", spec, path, f"::/SHZDOS/{name}")
    with open(disk, "rb") as fh:
        sector0 = fh.read(512)
        fh.seek(fatimg.PART_START * 512)
        vbr = fh.read(512)
    entry = sector0[446:462]
    record["disk"] = {
        "size_mib": size_mib, "sha256": sha256_file(disk),
        "mbr_partition_1": {"active": entry[0] == 0x80, "type": hex(entry[4]),
                            "start_lba": int.from_bytes(entry[8:12], "little"),
                            "sectors": int.from_bytes(entry[12:16], "little")},
        "vbr_fs_type": vbr[54:62].decode("ascii", "replace"),
        "listing": mtools("mdir", "-/", "-i", spec, "::/").stdout,
        "shzdos": [name for _, name in shzdos],
    }
    if not (entry[0] == 0x80 and entry[4] == 0x06 and vbr[54:59] == b"FAT16" and vbr[510:] == b"\x55\xaa"):
        raise SystemExit(f"disk layout is not MBR + active FAT16: {record['disk']}")
    return disk


# ------------------------------------------------------------------ parser host test
PARSER_DRIVER = r"""
#include <stdio.h>
#include <stdlib.h>
#include "bootini.h"
int main(int argc, char **argv)
{
    static char buf[1 << 16];
    bootini_policy_t p;
    char err[160];
    FILE *f = fopen(argv[1], "rb");
    size_t n;
    int line;
    if (argc != 2 || !f) return 2;
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    line = bootini_parse(buf, n, &p, err, sizeof err);
    if (line) printf("ERR %d %s\n", line, err);
    else printf("OK %s %s %d %d\n", bootini_mode_name(p.mode), p.csm_path, p.mode_set, p.csm_path_set);
    return 0;
}
"""

PARSER_CASES = [
    # (name, bytes, expected prefix of the driver output)
    ("empty file", b"", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0"),
    ("comments only", b"; a\n# b\n\n   \t\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0"),
    ("mode=auto", b"mode=auto", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0"),
    ("mode supervisor", b"mode = supervisor\n", "OK supervisor"),
    ("mode csm CRLF, case", b"MODE = Csm\r\n", "OK csm"),
    ("utf-8 bom", b"\xef\xbb\xbfmode = csm\n", "OK csm"),
    ("csm_path", b"csm_path = \\EFI\\CSM\\X.EFI\n", "OK auto \\EFI\\CSM\\X.EFI 0 1"),
    ("both keys", b"mode=csm\ncsm_path=\\A.EFI\n", "OK csm \\A.EFI 1 1"),
    ("tab separated", b"mode\t=\tcsm\t\n", "OK csm"),
    ("unknown key", b"mode = csm\ntimeout = 3\n", "ERR 2 unknown key 'timeout' (allowed: mode, csm_path)"),
    ("invalid mode", b"mode = legacy\n", "ERR 1 invalid mode 'legacy' (expected auto, supervisor or csm)"),
    ("inline comment", b"mode = csm ; x\n", "ERR 1 invalid mode 'csm ; x'"),
    ("duplicate mode", b"mode = csm\nmode = auto\n", "ERR 2 duplicate key 'mode'"),
    ("duplicate csm_path", b"csm_path=\\A.EFI\ncsm_path=\\B.EFI\n", "ERR 2 duplicate key 'csm_path'"),
    ("missing =", b"mode csm\n", "ERR 1 expected 'key = value', got 'mode csm'"),
    ("section header", b"[boot]\nmode=csm\n", "ERR 1 expected 'key = value', got '[boot]'"),
    ("empty key", b" = csm\n", "ERR 1 missing key before '='"),
    ("empty mode", b"mode =\n", "ERR 1 empty value for 'mode'"),
    ("empty path", b"csm_path = \n", "ERR 1 empty value for 'csm_path'"),
    ("relative path", b"csm_path = EFI\\X.EFI\n", "ERR 1 csm_path 'EFI\\X.EFI' must be absolute"),
    ("forward slash", b"csm_path = /EFI/X.EFI\n", "ERR 1 csm_path '/EFI/X.EFI' must be absolute"),
    ("slash inside", b"csm_path = \\EFI/X.EFI\n", "ERR 1 csm_path '\\EFI/X.EFI' uses '/'"),
    ("empty component", b"csm_path = \\EFI\\\\X.EFI\n", "ERR 1 csm_path '\\EFI\\\\X.EFI' contains an empty path component"),
    ("trailing backslash", b"csm_path = \\EFI\\\n", "ERR 1 csm_path '\\EFI\\' does not name a file"),
    ("root only", b"csm_path = \\\n", "ERR 1 csm_path '\\' does not name a file"),
    ("dot-dot", b"csm_path = \\EFI\\..\\X.EFI\n", "ERR 1 csm_path '\\EFI\\..\\X.EFI' contains a '.' or '..' component"),
    ("dot", b"csm_path = \\.\\X.EFI\n", "ERR 1 csm_path '\\.\\X.EFI' contains a '.' or '..' component"),
    ("dotfile ok", b"csm_path = \\EFI\\.X\\A.EFI\n", "OK auto \\EFI\\.X\\A.EFI 0 1"),
    ("wildcard", b"csm_path = \\EFI\\*.EFI\n", "ERR 1 csm_path '\\EFI\\*.EFI' contains a character that is not allowed"),
    ("drive letter", b"csm_path = \\C:X.EFI\n", "ERR 1 csm_path '\\C:X.EFI' contains a character"),
    ("path too long", b"csm_path = \\" + b"A" * 127 + b"\n", "ERR 1 csm_path '\\AAAA"),
    ("path 127 ok", b"csm_path = \\" + b"A" * 126 + b"\n", "OK auto \\" + "A" * 126),
    ("utf-16", "mode=csm\n".encode("utf-16"), "ERR 1 file is UTF-16"),
    ("non-ascii", "mode = csm\ncsm_path = \\EFI\\Ä.EFI\n".encode("utf-8"), "ERR 2 non-ASCII byte in line"),
    ("NUL byte", b"mode = csm\x00\n", "ERR 1 control character in line"),
    ("escape sequence", b"mode = \x1b[2Jcsm\n", "ERR 1 control character in line"),
    ("stray CR", b"mode = c\rsm\n", "ERR 1 control character in line"),
    ("long line", b"; " + b"x" * 300 + b"\n", "ERR 1 line is longer than 255 characters"),
    ("too large", b"; x\n" * 1025, "ERR 1 file is larger than 4096 bytes"),
    ("error on line 5", b"\n\n; c\nmode = csm\nfoo\n", "ERR 5 expected 'key = value', got 'foo'"),
    ("quoted value truncated", b"mode = " + b"z" * 60 + b"\n", "ERR 1 invalid mode '" + "z" * 40 + "...'"),
]


def parser_host_test(work):
    src = HERE / "loader"
    exe = work / "bootini_test"
    (work / "bootini_test.c").write_text(PARSER_DRIVER)
    cmd = ["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
           "-fno-sanitize-recover=all", "-I", src, work / "bootini_test.c", src / "bootini.c", "-o", exe]
    run(cmd, capture=True)
    checks = []
    for i, (name, data, expected) in enumerate(PARSER_CASES):
        f = work / f"ini{i}.txt"
        f.write_bytes(data)
        r = subprocess.run([str(exe), str(f)], capture_output=True, text=True, timeout=30)
        got = r.stdout.strip()
        ok = r.returncode == 0 and not r.stderr and got.startswith(expected)
        checks.append(verify._check(f"BOOT.INI parser: {name}", ok, got[:120] + (f" | {r.stderr[-200:]}" if r.stderr else "")))
    return checks, " ".join(str(x) for x in cmd)


# ------------------------------------------------------------------ QEMU runs
def ovmf_paths(args):
    code, variables = Path(args.firmware_code), Path(args.firmware_vars)
    if not code.exists() or not variables.exists():
        raise SystemExit(f"OVMF not found: {code} / {variables}")
    return code, variables


def run_case(case, base_disk, args, session):
    name = case["name"]
    run_dir = Path(tempfile.mkdtemp(prefix=f"{name}-", dir=session))
    disk = run_dir / "disk.img"
    shutil.copyfile(base_disk, disk)
    spec = fatimg.partition_spec(disk)
    if case.get("ini") is not None:
        (run_dir / "BOOT.INI").write_bytes(case["ini"])
        mtools("mcopy", "-o", "-i", spec, run_dir / "BOOT.INI", "::/EFI/SHIZUKU/BOOT.INI")
    for victim in case.get("delete", []):
        mtools("mdel", "-i", spec, victim)
    serial = run_dir / "serial.log"
    rec = {"case": name, "run_dir": str(run_dir), "boot_ini": case["ini"].decode("latin-1") if case.get("ini") else None}
    with tempfile.TemporaryDirectory(prefix="shz-bm-") as tmp:
        sock = Path(tmp) / "qmp.sock"
        if case.get("legacy"):
            command = [args.qemu, "-name", f"shz-bootmgr-{name}", "-machine", "pc", "-accel", "tcg", "-cpu", "qemu64",
                       "-m", "64", "-display", "none", "-monitor", "none", "-vga", "std", "-net", "none", "-no-reboot",
                       "-drive", f"file={disk},format=raw,if=ide,cache=writethrough", "-boot", "c",
                       "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off"]
            rec["firmware"] = "SeaBIOS (QEMU built-in legacy BIOS)"
        else:
            code, template = ovmf_paths(args)
            variables = run_dir / "OVMF_VARS.fd"
            shutil.copyfile(template, variables)
            command = [args.qemu, "-name", f"shz-bootmgr-{name}", "-machine", "q35", "-accel", "tcg",
                       "-cpu", case["cpu"], "-smp", str(case["smp"]), "-m", "256",
                       "-display", "none", "-monitor", "none", "-vga", "std", "-net", "none", "-no-reboot",
                       "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                       "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
                       "-drive", f"file={disk},format=raw,if=none,id=hd0,cache=writethrough",
                       "-device", "ide-hd,drive=hd0,bus=ide.0,bootindex=1",
                       "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off"]
            rec["firmware"] = f"OVMF {code.name}"
        rec["command"] = [str(c) for c in command]
        started = time.time()
        proc = qemu.launch(command, run_dir)
        qmp = None
        screen, regs, outcome = [], "", "timeout"
        try:
            qmp = qemu.QMP(sock, timeout=30)
            deadline = started + case.get("timeout", args.timeout)
            while time.time() < deadline and proc.poll() is None:
                text = serial.read_bytes() if serial.exists() else b""
                if b"SHZ-EXIT:" in text:
                    outcome = "dos-exit"
                    time.sleep(1.0)            # let the guest reach its final HLT
                    break
                if re.search(rb"BdsDxe: failed to start Boot[0-9A-F]{4}", text):
                    outcome = "firmware-returned"
                    time.sleep(1.0)
                    break
                if b"*** PANIC" in text or b"System halted" in text:
                    outcome = "csmwrap-panic"
                    break
                time.sleep(0.5)
            if proc.poll() is not None:
                outcome = f"qemu exited {proc.returncode}"
            else:
                regs = qemu.cpu_state(qmp)
                screen = qemu.decode_text_page(qemu.read_guest_memory(qmp, 0xB8000, 4000, run_dir / "b8000.bin"))
                (run_dir / "screen.txt").write_text("\n".join(screen) + "\n")
                qmp.call("quit")
        except Exception as exc:                  # keep what was collected
            rec["harness_error"] = repr(exc)
        finally:
            if qmp:
                qmp.close()
            try:
                proc.wait(timeout=20)
            except Exception:
                proc.kill()                        # only the QEMU this harness started
                proc.wait(timeout=20)
        rec["seconds"] = round(time.time() - started, 1)
        rec["outcome"] = outcome
    text = serial.read_text(errors="replace") if serial.exists() else ""
    checks = []
    for needle in case.get("serial", []):
        checks.append(verify._check(f"[{name}] serial shows: {needle}", needle in text))
    for needle in case.get("absent", []):
        checks.append(verify._check(f"[{name}] serial does not show: {needle}", needle not in text))
    if not case.get("legacy"):
        checks.append(verify._check(f"[{name}] Shizuku loader started from \\EFI\\BOOT\\BOOTX64.EFI",
                                    "ShizukuDOS 10.0-dev Supervisor loader (UEFI x64)" in text))
    if case["expect"] == DOS_RUN:
        checks.append(verify._check(f"[{name}] DOS reached SHZEXIT (COM1 marker)", outcome == "dos-exit", outcome))
        if not case.get("legacy"):
            checks.append(verify._check(f"[{name}] CSMWrap ran from \\EFI\\SHIZUKU and read its csmwrap.ini next to it",
                                        "serial = true" in text and "csm_bin_base:" in text))
            checks.append(verify._check(f"[{name}] CSMWrap chose this disk as the legacy boot device",
                                        "bootdev: BBS[0] Boot HDD" in text))
            checks.append(verify._check(f"[{name}] CSMWrap exited boot services and started SeaBIOS",
                                        "CALL16 " in text and "Reporting " in text))
        cr0 = re.search(r"CR0=([0-9a-fA-F]{8})", regs)
        checks.append(verify._check(f"[{name}] CPU 0 in real mode after the run (QMP info registers, CR0.PE=0)",
                                    bool(cr0) and not int(cr0.group(1), 16) & 1, cr0.group(0) if cr0 else "missing"))
        d_checks, result_txt = verify.verify_disk(disk)
        for c in d_checks:
            c["check"] = f"[{name}] disk after run: {c['check']}"
        checks += d_checks
        for c in verify.verify_screen(screen):
            c["check"] = f"[{name}] screen: {c['check']}"
            checks.append(c)
        rec["result_txt"] = result_txt
    else:
        m = re.search(r"BdsDxe: failed to start (Boot[0-9A-F]{4}) .*?: ([A-Za-z ]+)\r?$", text, re.M)
        want = case.get("status")
        checks.append(verify._check(f"[{name}] loader returned to firmware (OVMF BdsDxe reports the boot option failed)",
                                    outcome == "firmware-returned" and bool(m) and (want is None or m.group(2).strip() == want),
                                    m.group(0).strip() if m else outcome))
        checks.append(verify._check(f"[{name}] CSMWrap never took over the machine", "csm_bin_base:" not in text))
        checks.append(verify._check(f"[{name}] no DOS ran", "SHZ-EXIT:" not in text))
    rec["serial_tail"] = text[-4000:]
    rec["disk_after_sha256"] = sha256_file(disk)
    if not args.keep_disks:
        disk.unlink()
    return rec, checks


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or qemu.DEFAULT_QEMU)
    parser.add_argument("--firmware-code", default=qemu.DEFAULT_OVMF_CODE)
    parser.add_argument("--firmware-vars", default=qemu.DEFAULT_OVMF_VARS)
    parser.add_argument("--csmwrap", help="use this CSMWrap x64 EFI image instead of building one")
    parser.add_argument("--timeout", type=int, default=240, help="per-case limit in seconds")
    parser.add_argument("--case", action="append", help="run only these cases (repeatable)")
    parser.add_argument("--keep-disks", action="store_true")
    args = parser.parse_args()

    record = {"test": "shizukudos/supervisor/test_bootmgr.py", "utc": shzlib.utc_now(), "git": shzlib.git_state(),
              "accelerator": "tcg", "qemu": qemu.qemu_version(args.qemu),
              "host_dev_kvm": Path("/dev/kvm").exists(),
              "scope": "boot manager policy + CSMWrap legacy fallback; the Intel VMX Supervisor path is NOT exercised"}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "runs").mkdir(exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=OUT / "runs"))
    record["session_dir"] = str(session)
    loader = check_loader_fresh()
    record["loader"] = {"path": str(loader), "sha256": sha256_file(loader)}
    csmwrap = csmwrap_image(args, record)
    base = build_disk(session, loader, csmwrap, record)
    record["dos16_image_sha256"] = sha256_file(DOS16_IMAGE)

    checks = []
    p_checks, p_cmd = parser_host_test(session)
    record["parser_host_test"] = {"command": p_cmd, "cases": len(PARSER_CASES)}
    checks += p_checks
    cases = [c for c in case_table() if not args.case or c["name"] in args.case]
    record["cases"] = []
    for case in cases:
        rec, c = run_case(case, base, args, session)
        status = verify.overall(c)
        rec["status"] = status
        rec["checks"] = c
        record["cases"].append(rec)
        checks += c
        print(f"[{status}] case {case['name']}: {rec['outcome']} in {rec['seconds']} s")
        for x in c:
            if x["status"] != "PASS":
                print(f"    [{x['status']}] {x['check']}  {x['detail']}")
    base.unlink()
    status = verify.overall(checks)
    record["summary"] = {c["name"]: next(r["status"] for r in record["cases"] if r["case"] == c["name"]) for c in cases}
    record["summary"]["parser-host-test"] = verify.overall(p_checks)
    record["status"] = status
    record["checks"] = checks
    shzlib.write_json(session / "result.json", record)
    shzlib.write_json(OUT / "result.json", record)
    print(f"parser host test: {record['summary']['parser-host-test']} ({len(PARSER_CASES)} cases)")
    print(f"result: {OUT / 'result.json'} (session {session})")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
