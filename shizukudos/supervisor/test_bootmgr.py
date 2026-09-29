#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot-manager test: one MBR disk that boots FreeDOS on legacy BIOS *and* on UEFI, and Kernel64 directly on UEFI.

Disk layout (built here, never shipped): an MBR partition table with one active
FAT16 partition at LBA 63 holding
    KERNEL.SYS, COMMAND.COM, CONFIG.SYS, AUTOEXEC.BAT + conformance programs  (FreeDOS DOS16)
    \\EFI\\BOOT\\BOOTX64.EFI       the Shizuku Supervisor loader / boot manager
    \\EFI\\SHIZUKU\\CSMWRAP.EFI    CSMWrap (LGPL-2.1, wraps SeaBIOS CSM16) from shizukudos/csm/build.py
    \\EFI\\SHIZUKU\\csmwrap.ini    CSMWrap's own config: serial debug on COM1 (evidence only)
    \\SHZDOS\\DISK.IMG             the Supervisor's RAM-disk input (+ guest kernels if built)
    \\SHZDOS\\KERNEL64S.BIN        standalone Kernel64 (-DSHZ_STANDALONE) for mode=kernel64
    \\SHZDOS\\WIN64.IMG            its initial RAM image (ntdll, kernel32, DLLs, T_*.EXE)
    \\EFI\\SHIZUKU\\BOOT.INI, \\SHZDOS\\KERNEL64.INI   per case (absent = built-in mode=auto / no cmdline)

Cases (QEMU TCG here; no case exercises Intel VMX, which this host cannot provide):
    auto            OVMF, Intel CPU model without VMX, no BOOT.INI: loader reports VMX unusable,
                    chain-loads CSMWrap, SeaBIOS legacy-boots the MBR, FreeDOS runs AUTOEXEC,
                    host verifies RESULT.TXT & co on the disk afterwards (dos16/verify.py);
                    KERNEL64S.BIN is on the disk but auto_kernel64 defaults to no
    csm             OVMF, AMD CPU model, BOOT.INI mode=csm (CRLF, comments, mixed case): same run
    supervisor      BOOT.INI mode=supervisor without VMX: refuses, returns to firmware
    missing         mode=csm with csm_path to a file that does not exist: clear error, returns
    missing-default no BOOT.INI and \\EFI\\SHIZUKU\\CSMWRAP.EFI deleted: clear error, returns
    malformed-key   BOOT.INI with an unknown key: rejected as a whole, returns
    malformed-mode  BOOT.INI with an invalid mode value: rejected as a whole, returns
    not-an-image    csm_path points at a text file: LoadImage() error reported, returns
    one-cpu         -smp 1: CSMWrap's 2-processor requirement is checked before it can hang
    kernel64        mode=kernel64 + KERNEL64.INI cmdline, OVMF with S3 off: Kernel64 runs directly
                    (no Supervisor, no VMX) and must produce what tests/run_k64_standalone.py checks
                    (its parser/evaluator is reused) plus every T_*.EXE in WIN64.IMG exiting 0
    auto-kernel64   mode=auto + auto_kernel64=yes, no VMX, S3 off: the same Kernel64 run via auto
    auto-k64-fallback  auto_kernel64=yes, but \SHZDOS\KERNEL64S.BIN is the Supervisor-profile image: Kernel64
                    is refused before ExitBootServices and auto falls back to CSM -> FreeDOS verified
    kernel64-s3     mode=kernel64 with S3 on (QEMU's default): OVMF's EfiACPIMemoryNVS at 8 MiB becomes a
                    firmware hole (kernel64/standalone/memholes.h) fenced off in Kernel64's heap; Kernel64
                    runs and reports the same holes the loader handed over
    menu-timeout    mode=auto + menu_timeout=1: the boot manager menu is shown, no key arrives, the
                    policy (auto -> CSM -> FreeDOS verified) is followed
    kernel64-missing   mode=kernel64, KERNEL64S.BIN deleted: Not Found, returns
    kernel64-wrong-image   KERNEL64S.BIN replaced by the Supervisor-profile KERNEL64.BIN: refused, returns
    kernel64-bad-ini   KERNEL64.INI with an unknown key: rejected as a whole, returns
    legacy          the same disk on SeaBIOS (i440fx, legacy BIOS): MBR -> FreeDOS -> verify
plus a host test of the BOOT.INI / KERNEL64.INI parsers (shizukudos/supervisor/loader/bootini.c) under ASan/UBSan.
"Returned to firmware" is proven by OVMF's own BdsDxe line "failed to start Boot000N ...: <status>".
"S3 off" is `-global ICH9-LPC.disable_s3=1`: OVMF then no longer reserves its SEC/PEI scratch RAM at 8 MiB as
EfiACPIMemoryNVS, so RAM is contiguous from 1 MiB as on typical PC firmware. With S3 on that range is a firmware
hole that Kernel64 never writes (see kernel64-s3).
The menu's key selection (K = Kernel64 direct) is exercised by tools/test_shizuku_se_boot_matrix.py, which types on
COM1; this harness only logs COM1 to a file.
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
sys.path.insert(0, str(HERE.parents[0] / "tests"))
import fatimg  # noqa: E402
import qemu  # noqa: E402
import run_k64_standalone  # noqa: E402  (its serial parser and evaluator are reused unchanged)
import shzlib  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, REPO, SHZ, run, sha256_file  # noqa: E402

OUT = BUILD / "bootmgr"
SUP = BUILD / "supervisor"
DOS16_IMAGE = BUILD / "dos16" / "shizukudos-dos16-hd32.img"
K64S_IMAGE = BUILD / "kernel64s" / "KERNEL64S.BIN"
K64_SUPERVISOR_IMAGE = BUILD / "kernel64" / "KERNEL64.BIN"
WIN64_IMAGE = BUILD / "win64" / "WIN64.IMG"
WIN64_RECEIPT = BUILD / "win64" / "build-result.json"
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
INI_KERNEL64 = b"; boot the standalone Long Mode kernel directly\r\nmode = kernel64\r\n"
INI_AUTO_K64 = b"mode = auto\nauto_kernel64 = yes\n"
INI_MENU = b"mode = auto\r\nmenu_timeout = 1\r\n"
K64_CMDLINE = "shz.boot=uefi-direct console=com1 note=a;b#c"
K64_INI = f"; Kernel64 command line (\\SHZDOS\\KERNEL64.INI)\r\ncmdline = {K64_CMDLINE}\r\n".encode()
K64_INI_BAD = b"cmdline = x\nappend = y\n"

DOS_RUN = "dos"            # expectation kinds
K64_RUN = "k64"
RETURN = "return"


def case_table():
    k64_files = [(K64_INI, "::/SHZDOS/KERNEL64.INI")]
    return [
        {"name": "auto", "ini": None, "cpu": INTEL_NO_VMX, "smp": 2, "expect": DOS_RUN,
         "serial": ["no \\EFI\\SHIZUKU\\BOOT.INI; built-in policy mode=auto",
                    "Supervisor profile not available: Intel VMX backend unusable: CPUID does not report VMX",
                    "CSM legacy boot (mode=auto, no usable virtualization backend)",
                    "CSM legacy boot: CSMWrap loaded"],
         "absent": ["Kernel64 direct boot"]},
        {"name": "csm", "ini": INI_CSM, "cpu": AMD_CPU, "smp": 2, "expect": DOS_RUN,
         "serial": ["\\EFI\\SHIZUKU\\BOOT.INI mode=csm, csm_path=\\EFI\\SHIZUKU\\CSMWRAP.EFI",
                    "CSM legacy boot (mode=csm)", "CSM legacy boot: CSMWrap loaded"],
         "absent": ["Supervisor profile not available", "VMX", "Kernel64 direct boot"]},
        {"name": "supervisor", "ini": INI_SUPERVISOR, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Unsupported",
         "serial": ["BOOT.INI mode=supervisor", "REFUSED: Intel VMX backend unusable: CPUID does not report VMX",
                    "Returning to firmware."],
         "absent": ["Kernel64 direct boot", "CSM legacy boot"]},
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
         "serial": ["REFUSED: \\EFI\\SHIZUKU\\BOOT.INI line 2: unknown key 'timeout' "
                    "(allowed: mode, csm_path, auto_kernel64, menu_timeout)",
                    "rejected as a whole; nothing was started. Returning to firmware."],
         "absent": ["Intel VMX", "CSM legacy boot", "Kernel64 direct boot"]},
        {"name": "malformed-mode", "ini": INI_BAD_MODE, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": "Invalid Parameter",
         "serial": ["REFUSED: \\EFI\\SHIZUKU\\BOOT.INI line 1: invalid mode 'legacy' "
                    "(expected auto, supervisor, csm or kernel64)"],
         "absent": ["Intel VMX", "CSM legacy boot", "Kernel64 direct boot"]},
        {"name": "not-an-image", "ini": INI_NOT_IMAGE, "cpu": INTEL_NO_VMX, "smp": 2, "expect": RETURN,
         "status": None,
         "serial": ["REFUSED: firmware LoadImage() rejected \\EFI\\SHIZUKU\\csmwrap.ini",
                    "The file is not a loadable x64 UEFI application", "Returning to firmware."]},
        {"name": "one-cpu", "ini": None, "cpu": INTEL_NO_VMX, "smp": 1, "expect": RETURN, "status": "Unsupported",
         "serial": ["REFUSED: CSMWrap needs at least 2 enabled logical processors", "this machine reports 1",
                    "Returning to firmware."]},
        {"name": "kernel64", "ini": INI_KERNEL64, "files": k64_files, "cpu": INTEL_NO_VMX, "smp": 2, "s3": False,
         "expect": K64_RUN, "cmdline": K64_CMDLINE,
         "serial": ["\\EFI\\SHIZUKU\\BOOT.INI mode=kernel64", "Kernel64 direct boot (mode=kernel64)"],
         "absent": ["Supervisor profile not available", "CSM legacy boot", "Intel VMX backend"]},
        {"name": "auto-kernel64", "ini": INI_AUTO_K64, "cpu": INTEL_NO_VMX, "smp": 2, "s3": False,
         "expect": K64_RUN, "cmdline": "",
         "serial": ["BOOT.INI mode=auto, csm_path=\\EFI\\SHIZUKU\\CSMWRAP.EFI (default), auto_kernel64=yes",
                    "Supervisor profile not available: Intel VMX backend unusable: CPUID does not report VMX",
                    "Kernel64 direct boot (mode=auto, auto_kernel64=yes, no usable virtualization backend)"],
         "absent": ["CSM legacy boot", "Kernel64 0.1: command line"]},
        {"name": "auto-k64-fallback", "ini": INI_AUTO_K64, "delete": ["::/SHZDOS/KERNEL64S.BIN"],
         "copy": [(K64_SUPERVISOR_IMAGE, "::/SHZDOS/KERNEL64S.BIN")], "cpu": INTEL_NO_VMX, "smp": 2,
         "expect": DOS_RUN,
         "serial": ["Kernel64 direct boot (mode=auto, auto_kernel64=yes, no usable virtualization backend)",
                    "REFUSED: \\SHZDOS\\KERNEL64S.BIN is not the standalone (-DSHZ_STANDALONE) Kernel64 build",
                    "Kernel64 direct boot did not start (status 0x8000000000000001); falling back to the CSM legacy "
                    "BIOS profile.",
                    "CSM legacy boot (mode=auto, no usable virtualization backend)", "CSM legacy boot: CSMWrap loaded"],
         "absent": ["ExitBootServices done", "Kernel64 0.1"]},
        {"name": "kernel64-s3", "ini": INI_KERNEL64, "cpu": INTEL_NO_VMX, "smp": 2, "expect": K64_RUN,
         "cmdline": "", "holes": True,
         "serial": ["Kernel64 direct boot (mode=kernel64)",
                    "firmware hole 0x0000000000800000 size 0x0000000000008000 (occupied by EfiACPIMemoryNVS",
                    ": fenced off in Kernel64's heap"],
         "absent": ["Supervisor profile not available", "CSM legacy boot", "REFUSED: "]},
        {"name": "menu-timeout", "ini": INI_MENU, "cpu": INTEL_NO_VMX, "smp": 2, "expect": DOS_RUN,
         "serial": ["BOOT.INI mode=auto, csm_path=\\EFI\\SHIZUKU\\CSMWRAP.EFI (default), auto_kernel64=no, "
                    "menu_timeout=1",
                    "Shizuku boot manager menu: press a key within 1 seconds",
                    "  K           Kernel64 direct: the standalone Long Mode kernel, no Supervisor, no VMX",
                    "Boot manager menu: no key within 1 seconds; BOOT.INI mode=auto.",
                    "CSM legacy boot (mode=auto, no usable virtualization backend)", "CSM legacy boot: CSMWrap loaded"],
         "absent": ["Kernel64 direct boot", "Boot manager menu: key"]},
        {"name": "kernel64-missing", "ini": INI_KERNEL64, "delete": ["::/SHZDOS/KERNEL64S.BIN"], "cpu": INTEL_NO_VMX,
         "smp": 2, "s3": False, "expect": RETURN, "status": "Not Found",
         "serial": ["REFUSED: \\SHZDOS\\KERNEL64S.BIN not found on the boot volume",
                    "Nothing was started. Returning to firmware."],
         "absent": ["ExitBootServices done", "Kernel64 0.1", "CSM legacy boot"]},
        {"name": "kernel64-wrong-image", "ini": INI_KERNEL64, "delete": ["::/SHZDOS/KERNEL64S.BIN"],
         "copy": [(K64_SUPERVISOR_IMAGE, "::/SHZDOS/KERNEL64S.BIN")], "cpu": INTEL_NO_VMX, "smp": 2, "s3": False,
         "expect": RETURN, "status": "Load Error",
         "serial": ["REFUSED: \\SHZDOS\\KERNEL64S.BIN is not the standalone (-DSHZ_STANDALONE) Kernel64 build",
                    "Nothing was started. Returning to firmware."],
         "absent": ["ExitBootServices done", "Kernel64 0.1", "CSM legacy boot"]},
        {"name": "kernel64-bad-ini", "ini": INI_KERNEL64, "files": [(K64_INI_BAD, "::/SHZDOS/KERNEL64.INI")],
         "cpu": INTEL_NO_VMX, "smp": 2, "s3": False, "expect": RETURN, "status": "Invalid Parameter",
         "serial": ["REFUSED: \\SHZDOS\\KERNEL64.INI line 2: unknown key 'append' (allowed: cmdline)",
                    "The file is rejected as a whole. Nothing was started. Returning to firmware."],
         "absent": ["ExitBootServices done", "Kernel64 0.1", "CSM legacy boot"]},
        {"name": "legacy", "legacy": True, "expect": DOS_RUN, "serial": []},
    ]


# ------------------------------------------------------------------ inputs
def mtools(*args, check=True):
    return run([*args], env=MTOOLS_ENV, capture=True, check=check)


def csmwrap_image(args, record):
    """CSMWrap EFI image: explicit path, else the product of shizukudos/csm/build.py (built when absent)."""
    if args.csmwrap:
        path = Path(args.csmwrap).resolve()
        record["csmwrap"] = {"source": "command line", "path": str(path)}
    else:
        path = BUILD / "csm" / "CSMWRAP.EFI"
        receipt = BUILD / "csm" / "build-result.json"
        pin = shzlib.load_manifest()["upstreams"]["csmwrap"]["commit"]
        built = json.loads(receipt.read_text()) if receipt.exists() else {}
        if not path.exists() or built.get("upstream", {}).get("csmwrap", {}).get("commit") != pin:
            run([sys.executable, SHZ / "csm" / "build.py"], timeout=1800)
            built = json.loads(receipt.read_text())
        record["csmwrap"] = {"source": "shizukudos/csm/build.py", "path": str(path),
                             "upstream": built.get("upstream", {}).get("csmwrap"),
                             "receipt_sha256": built.get("artifacts", {}).get("CSMWRAP.EFI", {}).get("sha256")}
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


def check_kernel64_inputs(record):
    """KERNEL64S.BIN must be built from the current kernel sources; WIN64.IMG must match its receipt."""
    for path, hint in ((K64S_IMAGE, "shizukudos/kbuild.py"), (K64_SUPERVISOR_IMAGE, "shizukudos/kbuild.py"),
                       (WIN64_IMAGE, "shizukudos/win64/build.py"), (WIN64_RECEIPT, "shizukudos/win64/build.py")):
        if not path.exists():
            raise SystemExit(f"missing {path}: run {hint}")
    kr = json.loads((BUILD / "kernels-build-result.json").read_text())
    for name, digest in kr["sources_sha256"].items():
        if (REPO / name).exists() and sha256_file(REPO / name) != digest:
            raise SystemExit(f"Stale kernel build, source changed: {name}; rerun shizukudos/kbuild.py")
    if kr["kernels"]["kernel64-standalone"]["sha256"] != sha256_file(K64S_IMAGE):
        raise SystemExit("KERNEL64S.BIN does not match kernels-build-result.json")
    wr = json.loads(WIN64_RECEIPT.read_text())
    if wr["archive"]["sha256"] != sha256_file(WIN64_IMAGE):
        raise SystemExit("WIN64.IMG does not match shizukudos/win64 build-result.json")
    apps = sorted(f.rsplit("\\", 1)[1] for f in wr["archive"]["files"]
                  if re.fullmatch(r"\\SHZ\\TESTS\\T_[A-Z0-9_]+\.EXE", f))
    record["kernel64"] = {"KERNEL64S.BIN": sha256_file(K64S_IMAGE), "WIN64.IMG": sha256_file(WIN64_IMAGE),
                          "win64_test_programs": apps}
    return apps


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
                                                                K64_SUPERVISOR_IMAGE, K64S_IMAGE, WIN64_IMAGE)
                                            if p.exists()]
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
#include <string.h>
#include "bootini.h"
int main(int argc, char **argv)
{
    static char buf[1 << 16];
    bootini_policy_t p;
    char err[160], cmd[256];
    FILE *f;
    size_t n;
    int line;
    if (argc < 2 || !(f = fopen(argv[1], "rb"))) return 2;
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (argc == 4 && !strcmp(argv[2], "k64")) {             /* KERNEL64.INI with a cmdline buffer of argv[3] bytes */
        size_t cap = (size_t)atoi(argv[3]);
        char *heap = malloc(cap);                           /* exact size: ASan catches any overrun */
        if (!heap || cap > sizeof cmd) return 2;
        line = k64ini_parse(buf, n, heap, cap, err, sizeof err);
        if (line) printf("ERR %d %s\n", line, err);
        else printf("OK [%s]\n", heap);
        free(heap);
        return 0;
    }
    line = bootini_parse(buf, n, &p, err, sizeof err);
    if (line) printf("ERR %d %s\n", line, err);
    else printf("OK %s %s %d %d k64=%d %d menu=%d %d\n", bootini_mode_name(p.mode), p.csm_path, p.mode_set,
                p.csm_path_set, p.auto_kernel64, p.auto_kernel64_set, p.menu_timeout, p.menu_timeout_set);
    return 0;
}
"""

PARSER_CASES = [
    # (name, bytes, expected prefix of the driver output)
    ("empty file", b"", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 0"),
    ("comments only", b"; a\n# b\n\n   \t\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 0"),
    ("mode=auto", b"mode=auto", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0"),
    ("mode supervisor", b"mode = supervisor\n", "OK supervisor"),
    ("mode csm CRLF, case", b"MODE = Csm\r\n", "OK csm"),
    ("mode kernel64", b"mode = Kernel64\r\n", "OK kernel64 \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0 k64=0 0"),
    ("utf-8 bom", b"\xef\xbb\xbfmode = csm\n", "OK csm"),
    ("csm_path", b"csm_path = \\EFI\\CSM\\X.EFI\n", "OK auto \\EFI\\CSM\\X.EFI 0 1"),
    ("both keys", b"mode=csm\ncsm_path=\\A.EFI\n", "OK csm \\A.EFI 1 1"),
    ("tab separated", b"mode\t=\tcsm\t\n", "OK csm"),
    ("auto_kernel64 yes", b"mode = auto\nauto_kernel64 = YES\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0 k64=1 1"),
    ("auto_kernel64 no", b"auto_kernel64=no\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 1"),
    ("all three keys", b"mode=kernel64\ncsm_path=\\B.EFI\nauto_kernel64=yes\n", "OK kernel64 \\B.EFI 1 1 k64=1 1"),
    ("auto_kernel64 invalid", b"auto_kernel64 = true\n", "ERR 1 invalid auto_kernel64 'true' (expected yes or no)"),
    ("auto_kernel64 empty", b"auto_kernel64 =\n", "ERR 1 invalid auto_kernel64 '' (expected yes or no)"),
    ("auto_kernel64 1", b"auto_kernel64 = 1\n", "ERR 1 invalid auto_kernel64 '1'"),
    ("duplicate auto_kernel64", b"auto_kernel64 = no\nauto_kernel64 = yes\n", "ERR 2 duplicate key 'auto_kernel64'"),
    ("unknown key", b"mode = csm\ntimeout = 3\n",
     "ERR 2 unknown key 'timeout' (allowed: mode, csm_path, auto_kernel64, menu_timeout)"),
    ("defaults: no menu", b"mode = auto\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0 k64=0 0 menu=0 0"),
    ("menu_timeout", b"mode = auto\r\nMenu_Timeout = 5\r\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 1 0 k64=0 0 menu=5 1"),
    ("menu_timeout 0 (no menu)", b"menu_timeout=0\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 0 menu=0 1"),
    ("menu_timeout 30", b"menu_timeout = 30\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 0 menu=30 1"),
    ("menu_timeout 005", b"menu_timeout = 005\n", "OK auto \\EFI\\SHIZUKU\\CSMWRAP.EFI 0 0 k64=0 0 menu=5 1"),
    ("menu_timeout 31", b"menu_timeout = 31\n", "ERR 1 invalid menu_timeout '31' (expected whole seconds 0 to 30)"),
    ("menu_timeout 0005", b"menu_timeout = 0005\n", "ERR 1 invalid menu_timeout '0005'"),
    ("menu_timeout negative", b"menu_timeout = -1\n", "ERR 1 invalid menu_timeout '-1'"),
    ("menu_timeout fraction", b"menu_timeout = 1.5\n", "ERR 1 invalid menu_timeout '1.5'"),
    ("menu_timeout empty", b"menu_timeout =\n", "ERR 1 invalid menu_timeout ''"),
    ("menu_timeout word", b"menu_timeout = five\n", "ERR 1 invalid menu_timeout 'five'"),
    ("duplicate menu_timeout", b"menu_timeout = 1\nmenu_timeout = 2\n", "ERR 2 duplicate key 'menu_timeout'"),
    ("all four keys", b"mode=csm\ncsm_path=\\C.EFI\nauto_kernel64=no\nmenu_timeout=3\n",
     "OK csm \\C.EFI 1 1 k64=0 1 menu=3 1"),
    ("KERNEL64.INI key in BOOT.INI", b"cmdline = x\n", "ERR 1 unknown key 'cmdline'"),
    ("invalid mode", b"mode = legacy\n", "ERR 1 invalid mode 'legacy' (expected auto, supervisor, csm or kernel64)"),
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

# KERNEL64.INI: (name, bytes, cmdline buffer size, expected prefix)
K64INI_CASES = [
    ("cmdline", b"cmdline = console=com1 debug\n", 256, "OK [console=com1 debug]"),
    ("cmdline CRLF, key case, comments", b"; c\r\n# d\r\nCmdLine = a b\r\n", 256, "OK [a b]"),
    ("value keeps ; and # (no inline comments)", b"cmdline = a;b # c\n", 256, "OK [a;b # c]"),
    ("empty value", b"cmdline =\n", 256, "OK []"),
    ("key absent", b"; nothing\n", 256, "OK []"),
    ("empty file", b"", 256, "OK []"),
    ("unknown key", b"cmdline = x\nappend = y\n", 256, "ERR 2 unknown key 'append' (allowed: cmdline)"),
    ("BOOT.INI key", b"mode = kernel64\n", 256, "ERR 1 unknown key 'mode' (allowed: cmdline)"),
    ("duplicate", b"cmdline=a\ncmdline=b\n", 256, "ERR 2 duplicate key 'cmdline'"),
    ("control char", b"cmdline = a\x01b\n", 256, "ERR 1 control character in line"),
    ("non-ascii", "cmdline = Ä\n".encode("utf-8"), 256, "ERR 1 non-ASCII byte in line"),
    ("longest line fits", b"cmdline = " + b"x" * 245 + b"\n", 256, "OK [" + "x" * 245 + "]"),
    ("value exactly fills buffer", b"cmdline = abcdefg\n", 8, "OK [abcdefg]"),
    ("value one byte too long, never truncated", b"cmdline = abcdefgh\n", 8,
     "ERR 1 cmdline is too long for the boot information block"),
    ("missing =", b"cmdline\n", 256, "ERR 1 expected 'key = value', got 'cmdline'"),
]


def parser_host_test(work):
    src = HERE / "loader"
    exe = work / "bootini_test"
    (work / "bootini_test.c").write_text(PARSER_DRIVER)
    cmd = ["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
           "-fno-sanitize-recover=all", "-I", src, work / "bootini_test.c", src / "bootini.c", "-o", exe]
    run(cmd, capture=True)
    checks = []
    cases = [(f"BOOT.INI parser: {n}", d, [], e) for n, d, e in PARSER_CASES] + \
            [(f"KERNEL64.INI parser: {n}", d, ["k64", str(cap)], e) for n, d, cap, e in K64INI_CASES]
    for i, (name, data, extra, expected) in enumerate(cases):
        f = work / f"ini{i}.txt"
        f.write_bytes(data)
        r = subprocess.run([str(exe), str(f), *extra], capture_output=True, text=True, timeout=30)
        got = r.stdout.strip()
        ok = r.returncode == 0 and not r.stderr and got.startswith(expected)
        checks.append(verify._check(name, ok, got[:120] + (f" | {r.stderr[-200:]}" if r.stderr else "")))
    return checks, " ".join(str(x) for x in cmd), len(cases)


# ------------------------------------------------------------------ QEMU runs
def ovmf_paths(args):
    code, variables = Path(args.firmware_code), Path(args.firmware_vars)
    if not code.exists() or not variables.exists():
        raise SystemExit(f"OVMF not found: {code} / {variables}")
    return code, variables


def k64_checks(name, text, qemu_rc, case, apps):
    """Kernel64 evidence: run_k64_standalone.py's own checks, every test program, and the boot handoff."""
    ev, code = run_k64_standalone.parse(text)
    checks = []
    for c in run_k64_standalone.evaluate(text, ev, code, qemu_rc):
        checks.append(verify._check(f"[{name}] run_k64_standalone.py: {c['check']}", c["status"] == "PASS", c["detail"]))
    checks.append(verify._check(f"[{name}] Kernel64 asked QEMU to exit with status 0 (isa-debug-exit rc = 0<<1|1)",
                                code == 0 and qemu_rc == 1, f"SHZ-EXIT={code} qemu rc={qemu_rc}"))
    announced = re.search(r"^K64 win64: (\d+) self-checking app\(s\) besides T_HELLO\.EXE", text, re.M)
    ran = re.findall(r"^K64 win64 app: (\S+) exit=(-?\d+) faulted=(\d+)", text, re.M)
    expected = [a for a in apps if a != "T_HELLO.EXE"]
    bad = [f"{n} exit={e} faulted={f}" for n, e, f in ran if e != "0" or f != "0"]
    checks.append(verify._check(f"[{name}] every T_*.EXE in WIN64.IMG ran and exited 0 without a fault",
                                bool(announced) and int(announced.group(1)) == len(expected) and
                                sorted(n for n, _, _ in ran) == expected and not bad,
                                f"{len(ran)}/{len(expected)} ran" + (f"; {bad[:3]}" if bad else "") +
                                (f"; missing {sorted(set(expected) - {n for n, _, _ in ran})[:3]}"
                                 if set(expected) - {n for n, _, _ in ran} else "")))
    loader_ram = re.search(r"ExitBootServices done \(0x([0-9a-f]+) call\(s\)\); Kernel64 RAM \[0, 0x([0-9a-f]+)\)", text)
    kernel_ram = re.search(r"Kernel64 0\.1: Long Mode kernel starting, (\d+) MiB RAM", text)
    checks.append(verify._check(f"[{name}] loader exited boot services and Kernel64 saw the RAM size the loader "
                                "computed from the final UEFI memory map",
                                bool(loader_ram and kernel_ram) and int(loader_ram.group(2), 16) >> 20 ==
                                int(kernel_ram.group(1)) and int(kernel_ram.group(1)) >= 64,
                                f"loader {loader_ram.group(0) if loader_ram else 'missing'}; "
                                f"kernel {kernel_ram.group(1) + ' MiB' if kernel_ram else 'missing'}"))
    checks.append(verify._check(f"[{name}] Kernel64 read boot info ABI 1.1 (472 bytes) flagged UEFI-direct",
                                "Kernel64 0.1: boot info ABI 1.1, 472 bytes, started directly by the UEFI boot manager "
                                "(no Supervisor)" in text))
    if case.get("cmdline"):
        checks.append(verify._check(f"[{name}] KERNEL64.INI command line reached Kernel64 verbatim",
                                    f'Kernel64 0.1: command line "{case["cmdline"]}"' in text))
    else:
        checks.append(verify._check(f"[{name}] no KERNEL64.INI: empty command line", "Kernel64 0.1: command line" not in text))
    lg = re.search(r"GOP (\d+)x(\d+) (BGRX|RGBX) at 0x([0-9a-f]+)\.", text)
    kg = re.search(r"UEFI GOP framebuffer (\d+)x(\d+), pitch (\d+), (BGRX|RGBX), at ([0-9a-f]+) \((\d+) KiB\)", text)
    checks.append(verify._check(f"[{name}] GOP framebuffer handed over: Kernel64's k64_boot_framebuffer() reports the "
                                "mode the loader read from GOP",
                                bool(lg and kg) and lg.group(1, 2, 3) == kg.group(1, 2, 4) and
                                int(lg.group(4), 16) == int(kg.group(5), 16) and
                                int(kg.group(3)) >= 4 * int(kg.group(1)),
                                (kg.group(0) if kg else "kernel line missing") + " / " + (lg.group(0) if lg else "loader line missing")))
    lh = re.search(r"Kernel64 RAM \[0, 0x[0-9a-f]+\); 0x([0-9a-f]+) firmware hole\(s\) handed over at 0x6000", text)
    kh = re.search(r"K64: (\d+) firmware memory hole\(s\): (\d+) page\(s\) kept out of the page allocator, "
                   r"(\d+) KiB of the heap fenced off", text)
    handed = int(lh.group(1), 16) if lh else -1
    # Holes near the top of RAM (EfiRuntimeServicesData) exist with S3 off too; with S3 on the 8 MiB ACPI NVS must be
    # among them, fenced off in the heap (case "holes").
    checks.append(verify._check(f"[{name}] Kernel64 applied exactly the firmware holes the loader handed over "
                                "(kernel64/standalone/memholes.h at 0x6000)" +
                                (", including heap-window holes fenced off" if case.get("holes") else ""),
                                handed >= 0 and (int(kh.group(1)) if kh else 0) == handed and
                                (not case.get("holes") or (kh is not None and int(kh.group(3)) > 0)),
                                f"loader {handed}; kernel {kh.group(0) if kh else 'no hole line'}"))
    checks.append(verify._check(f"[{name}] CSMWrap never ran", "csm_bin_base:" not in text))
    return checks


def save_png(ppm):
    """PNG next to the PPM screendump when Pillow is installed; returns the path kept."""
    try:
        from PIL import Image
    except ImportError:
        return ppm
    png = ppm.with_suffix(".png")
    Image.open(ppm).save(png)
    return png


def run_case(case, base_disk, args, session, apps):
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
    for i, (data, dest) in enumerate(case.get("files", [])):
        (run_dir / f"file{i}").write_bytes(data)
        mtools("mcopy", "-o", "-i", spec, run_dir / f"file{i}", dest)
    for src, dest in case.get("copy", []):
        shutil.copyfile(src, run_dir / "copy.bin")
        mtools("mcopy", "-o", "-i", spec, run_dir / "copy.bin", dest)
    serial = run_dir / "serial.log"
    rec = {"case": name, "run_dir": str(run_dir), "boot_ini": case["ini"].decode("latin-1") if case.get("ini") else None,
           "extra_files": [dest for _, dest in case.get("files", [])] + [dest for _, dest in case.get("copy", [])],
           "deleted": case.get("delete", [])}
    qemu_rc = None
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
            variables = run_dir / "OVMF_VARS.fd"         # per-run copy: no case sees another's NVRAM
            shutil.copyfile(template, variables)
            command = [args.qemu, "-name", f"shz-bootmgr-{name}", "-machine", "q35", "-accel", "tcg",
                       "-cpu", case["cpu"], "-smp", str(case["smp"]), "-m", "256",
                       *(["-global", "ICH9-LPC.disable_s3=1"] if case.get("s3") is False else []),
                       "-display", "none", "-monitor", "none", "-vga", "std", "-net", "none", "-no-reboot",
                       "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
                       "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
                       "-drive", f"file={disk},format=raw,if=none,id=hd0,cache=writethrough",
                       "-device", "ide-hd,drive=hd0,bus=ide.0,bootindex=1",
                       # Kernel64 (standalone) ends the VM through isa-debug-exit, as under run_k64_standalone.py
                       *(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"] if case["expect"] == K64_RUN else []),
                       "-serial", f"file:{serial}", "-qmp", f"unix:{sock},server=on,wait=off"]
            rec["firmware"] = f"OVMF {code.name}" + (" (S3 disabled)" if case.get("s3") is False else "")
        rec["command"] = [str(c) for c in command]
        started = time.time()
        proc = qemu.launch(command, run_dir)
        qmp = None
        screen, regs, outcome = [], "", "timeout"
        shots, shot_at = [], 0
        try:
            qmp = qemu.QMP(sock, timeout=30)
            deadline = started + case.get("timeout", args.timeout)
            while time.time() < deadline and proc.poll() is None:
                text = serial.read_bytes() if serial.exists() else b""
                if case["expect"] == K64_RUN:
                    # every GUI scene the Win64 test programs show: pause, dump the real screen, resume
                    for m in re.finditer(rb"GUI-READY: (\S+)\r?\n", text[shot_at:]):
                        scene = m.group(1).decode(errors="replace")
                        ppm = run_dir / f"shot-{scene}.ppm"
                        try:
                            qmp.call("stop")
                            try:
                                qmp.call("screendump", {"filename": str(ppm)})
                            finally:
                                qmp.call("cont")
                            shots.append(save_png(ppm))
                        except Exception as exc:   # a missed picture is reported, never fatal to the boot case
                            rec.setdefault("screenshot_errors", []).append(f"{scene}: {exc!r}")
                    shot_at = text.rfind(b"\n") + 1           # only whole lines are consumed
                if b"SHZ-EXIT:" in text:
                    outcome = "k64-exit" if case["expect"] == K64_RUN else "dos-exit"
                    time.sleep(1.0)            # let the guest reach its final HLT / QEMU finish isa-debug-exit
                    break
                if re.search(rb"BdsDxe: failed to start Boot[0-9A-F]{4}", text):
                    outcome = "firmware-returned"
                    time.sleep(1.0)
                    break
                if b"*** PANIC" in text or b"System halted" in text or b"the machine is halted" in text:
                    outcome = "halted"
                    break
                time.sleep(0.5)
            if proc.poll() is not None:
                qemu_rc = proc.returncode
                final = serial.read_bytes() if serial.exists() else b""
                # Kernel64 prints SHZ-EXIT and ends QEMU at once, usually between two polls of this loop.
                outcome = "k64-exit" if case["expect"] == K64_RUN and b"SHZ-EXIT:" in final else f"qemu exited {qemu_rc}"
            elif case["expect"] == K64_RUN and outcome == "k64-exit":
                try:
                    qemu_rc = proc.wait(timeout=30)     # Kernel64 ends the VM itself through isa-debug-exit
                except subprocess.TimeoutExpired:
                    outcome = "k64-exit but QEMU did not exit"
            if proc.poll() is None:
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
        rec["screenshots"] = [str(x) for x in shots]
        rec["seconds"] = round(time.time() - started, 1)
        rec["outcome"] = outcome
        rec["qemu_rc"] = qemu_rc
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
    elif case["expect"] == K64_RUN:
        checks.append(verify._check(f"[{name}] Kernel64 reached SHZ-EXIT and QEMU exited", outcome == "k64-exit", outcome))
        checks += k64_checks(name, text, qemu_rc, case, apps)
        rec["k64_evidence"] = {str(k): hex(v) for k, v in sorted(run_k64_standalone.parse(text)[0].items())}
        rec["k64_boot_lines"] = [l for l in text.splitlines() if l.startswith(("Kernel64 direct boot", "Shizuku boot manager",
                                                                              "Kernel64 0.1:", "K64 win64 app:"))]
    else:
        m = re.search(r"BdsDxe: failed to start (Boot[0-9A-F]{4}) .*?: ([A-Za-z ]+)\r?$", text, re.M)
        want = case.get("status")
        checks.append(verify._check(f"[{name}] loader returned to firmware (OVMF BdsDxe reports the boot option failed)",
                                    outcome == "firmware-returned" and bool(m) and (want is None or m.group(2).strip() == want),
                                    m.group(0).strip() if m else outcome))
        checks.append(verify._check(f"[{name}] CSMWrap never took over the machine", "csm_bin_base:" not in text))
        checks.append(verify._check(f"[{name}] no DOS or Kernel64 ran", "SHZ-EXIT:" not in text))
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
    parser.add_argument("--csmwrap", help="use this CSMWrap x64 EFI image instead of shizukudos/csm/build.py's")
    parser.add_argument("--timeout", type=int, default=420, help="per-case limit in seconds")
    parser.add_argument("--case", action="append", help="run only these cases (repeatable)")
    parser.add_argument("--keep-disks", action="store_true")
    args = parser.parse_args()

    record = {"test": "shizukudos/supervisor/test_bootmgr.py", "utc": shzlib.utc_now(), "git": shzlib.git_state(),
              "accelerator": "tcg", "qemu": qemu.qemu_version(args.qemu),
              "host_dev_kvm": Path("/dev/kvm").exists(),
              "scope": "boot manager policy, CSMWrap legacy fallback and direct Kernel64 boot on OVMF; "
                       "the Intel VMX Supervisor path is NOT exercised"}
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "runs").mkdir(exist_ok=True)
    session = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=OUT / "runs"))
    record["session_dir"] = str(session)
    loader = check_loader_fresh()
    record["loader"] = {"path": str(loader), "sha256": sha256_file(loader)}
    apps = check_kernel64_inputs(record)
    csmwrap = csmwrap_image(args, record)
    base = build_disk(session, loader, csmwrap, record)
    record["dos16_image_sha256"] = sha256_file(DOS16_IMAGE)

    checks = []
    p_checks, p_cmd, p_count = parser_host_test(session)
    record["parser_host_test"] = {"command": p_cmd, "cases": p_count}
    checks += p_checks
    for c in p_checks:
        if c["status"] != "PASS":
            print(f"    [{c['status']}] {c['check']}  {c['detail']}")
    cases = [c for c in case_table() if not args.case or c["name"] in args.case]
    record["cases"] = []
    for case in cases:
        rec, c = run_case(case, base, args, session, apps)
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
    print(f"parser host test: {record['summary']['parser-host-test']} ({p_count} cases)")
    print(f"result: {OUT / 'result.json'} (session {session})")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
