#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise IO.SYS early boot contracts, then continue on a private Windows clone.

The authored MBR diagnostic has no DOS or replacement Windows kernel. The native
mode chains the retained Microsoft Windows boot sector and IO.SYS after guards.
Contract success alone does not establish Windows startup or a working desktop.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "shizukudos" / "tools"))
import fatimg
import qemu
import shzlib

BUILD = REPO / "build" / "shizukudos"
PREFIX = "run-ios-gop-7acd-"
MARKERS = ("IOGOP:S", "IOGOP:T", "IOGOP:D", "IOGOP:C")


def load_source(path):
    raw = path.read_bytes()
    module = types.ModuleType(path.stem + "_ios_owned")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module, raw


def verify_firmware(directory, require_ios=True):
    directory = directory.resolve(strict=True)
    receipt = json.loads((directory / "build-result.json").read_text())
    for name in ("CSMWRAP.EFI", "Csm16.bin", "vgabios.bin"):
        item = receipt["artifacts"][name]
        path = directory / name
        if path.stat().st_size != item["bytes"] or shzlib.sha256_file(path) != item["sha256"]:
            raise RuntimeError(f"Firmware artifact differs from its receipt: {name}")
    if receipt.get("firmware_gop", {}).get("compiled_support") is not True:
        raise RuntimeError("The selected firmware does not support forced GOP")
    if require_ios and receipt.get("ios_gop", {}).get("compiled_support") is not True:
        raise RuntimeError("The selected firmware lacks the early IO.SYS GOP profile")
    return receipt


def ordered_checks(serial):
    cursor, checks = 0, []
    for marker in MARKERS:
        offset = serial.find(marker, cursor)
        checks.append({"marker": marker, "status": "PASS" if offset >= 0 else "FAIL"})
        if offset >= 0:
            cursor = offset + len(marker)
    checks.append({"marker": "IOGOP:F absent", "status": "PASS" if "IOGOP:F" not in serial else "FAIL"})
    return checks


def resource_guard(destination):
    if shutil.disk_usage(destination).free < 8 * 1024 ** 3 + 256 * 1024 ** 2:
        raise RuntimeError("Insufficient free disk reserve for a private boot trial")
    memory = Path("/proc/meminfo").read_text()
    available = re.search(r"^MemAvailable:\s+(\d+)", memory, re.M)
    if not available or int(available.group(1)) < 1024 ** 2:
        raise RuntimeError("Less than 1 GiB available host memory")


def contract_run(args, probe, csm_dir, expected_failure=False):
    receipt = verify_firmware(csm_dir, require_ios=not expected_failure)
    run_dir = BUILD / ("csm-ios-gop-7acd-contract-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
                       + ("-control" if expected_failure else "-patched"))
    resource_guard(BUILD)
    run_dir.mkdir(mode=0o700)
    record = {"profile": "authored-early-io-sys-bios-contract", "utc": shzlib.utc_now(),
              "status": "FAIL", "native_windows": False, "expected_failure": expected_failure,
              "firmware_build_receipt_sha256": shzlib.sha256_file(csm_dir / "build-result.json"),
              "firmware": receipt["artifacts"], "probe_sha256": shzlib.sha256_file(probe),
              "scope": "real firmware BIOS text and EDD calls; no replacement OS or Windows GUI claim"}
    image = run_dir / "contract.raw"
    spec = fatimg.make_hdd(image, probe, label="IOGOPTEST")
    fatimg.make_dirs(spec, ["EFI", "EFI/BOOT"])
    ini = run_dir / "csmwrap.ini"
    ini.write_bytes(b"serial=true\r\nserial_port=0x3f8\r\nserial_baud=115200\r\ngop_only=true\r\n")
    for source, target in ((csm_dir / "CSMWRAP.EFI", "EFI/BOOT/BOOTX64.EFI"),
                           (ini, "EFI/BOOT/csmwrap.ini")):
        subprocess.run(["mcopy", "-o", "-i", spec, str(source), "::" + target],
                       env=fatimg._mtools_env(), check=True, timeout=60)
    variables = run_dir / "OVMF_VARS.fd"
    shutil.copyfile(args.firmware_vars, variables)
    serial = run_dir / "serial.log"
    with tempfile.TemporaryDirectory(prefix="iosgop7acd-") as temporary:
        socket = Path(temporary) / "qmp.sock"
        command = [args.qemu, "-name", "ios-gop-7acd-contract", "-machine", "q35,hpet=off",
                   "-accel", args.accel, "-cpu", "qemu64", "-smp", "2", "-m", "128",
                   "-nodefaults", "-nic", "none", "-display", "none", "-device", "VGA",
                   "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
                   "-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={args.firmware_code}",
                   "-drive", f"if=pflash,unit=1,format=raw,file={variables}",
                   "-drive", f"file={image},format=raw,if=none,id=contract",
                   "-device", "ide-hd,drive=contract,bus=ide.0,bootindex=1",
                   "-serial", f"file:{serial}", "-qmp", f"unix:{socket},server=on,wait=off", "-no-reboot"]
        record["command"] = command
        started = time.monotonic()
        child = qemu.launch(command, run_dir)
        monitor = None
        try:
            monitor = qemu.QMP(socket)
            while child.poll() is None and time.monotonic() - started < args.timeout:
                time.sleep(0.2)
            if child.poll() is None:
                record["timeout"] = True
                monitor.call("quit")
        finally:
            if monitor:
                monitor.close()
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=10)
        record["qemu_exit_code"] = child.returncode
        record["seconds"] = round(time.monotonic() - started, 3)
    serial_text = serial.read_text(errors="replace") if serial.exists() else ""
    checks = ordered_checks(serial_text)
    record["checks"] = checks
    firmware_ok = ("gop_only: forced firmware GOP + SeaVGABIOS; no VGA OpROM" in serial_text
                   and "Video Initialisation Succeed with OpROM" not in serial_text)
    record["forced_gop_no_vga_oprom"] = firmware_ok
    if expected_failure:
        accepted = (child.returncode == 35 and "IOGOP:S" in serial_text and "IOGOP:F" in serial_text
                    and "IOGOP:T" not in serial_text and "IOGOP:C" not in serial_text)
    else:
        accepted = child.returncode == 33 and all(c["status"] == "PASS" for c in checks)
    record["status"] = "PASS" if accepted and firmware_ok else "FAIL"
    record["serial_sha256"] = shzlib.sha256_file(serial) if serial.exists() else None
    shzlib.write_json(run_dir / "result.json", record)
    print(json.dumps({"result": str(run_dir / "result.json"), "status": record["status"],
                      "qemu_exit_code": child.returncode, "checks": checks}, indent=2))
    return record["status"] == "PASS"


def native_run(args, remainder, probe_module, wrapper_bytes):
    if not remainder:
        raise RuntimeError("Native mode needs --archive and --checkpoint-record arguments")
    if "--native-bios-control" in remainder or "--firmware-gop" in remainder or "--csm-dir" in remainder:
        raise RuntimeError("Native mode fixes the UEFI/GOP firmware profile itself")
    run_name = PREFIX + time.strftime("%Y%m%dT%H%M%S", time.gmtime())
    source = HERE.parent / "test_win98_uefi.py"
    native, source_bytes = load_source(source)
    # Freeze the loaded runner so its source receipt describes executed bytes.
    inputs = args.csm_dir / "inputs" / run_name
    inputs.mkdir()
    snapshot = inputs / "native-runner.py"
    snapshot.write_bytes(source_bytes)
    (inputs / "ios-runner.py").write_bytes(wrapper_bytes)
    native.__file__ = str(snapshot)
    probe = probe_module.build_probe(inputs / "probe", test_exit=False)
    injected = {}
    launch = native.qemu.launch

    def launch_with_probe(command, run_dir, *extra, **kwargs):
        disk = Path(run_dir) / "windows-uefi.raw"
        if Path(run_dir).name != run_name or not disk.is_file():
            raise RuntimeError("The probe may modify only this trial's new private Windows clone")
        with disk.open("r+b") as stream:
            before = stream.read(512)
            probe_module.validate_mbr(before, disk.stat().st_size // 512)
            patched = probe_module.apply_to_mbr(before, Path(probe).read_bytes())
            if patched[440:] != before[440:]:
                raise RuntimeError("Probe changed the Windows disk identity or partition table")
            (Path(run_dir) / "original-mbr.bin").write_bytes(before)
            stream.seek(0)
            stream.write(patched)
            stream.flush()
            os.fsync(stream.fileno())
        injected.update({"original_mbr_sha256": hashlib.sha256(before).hexdigest(),
                         "probe_mbr_sha256": hashlib.sha256(patched).hexdigest(),
                         "probe_sha256": shzlib.sha256_file(probe),
                         "disk_sha256_before_vm": shzlib.sha256_file(disk),
                         "preserved_disk_identity_and_partition_bytes": [440, 511],
                         "windows_vbr_and_io_sys": "unchanged; original VBR executes after probe guards"})
        return launch(command, run_dir, *extra, **kwargs)

    # The trial needs firmware, BDA and visible Windows behavior, not copies of
    # proprietary live instruction bytes.
    native.capture_cpu0_code = lambda *values: None
    native.qemu.launch = launch_with_probe
    old_argv = sys.argv
    try:
        sys.argv = [str(source), "--csm-dir", str(args.csm_dir), "--firmware-gop",
                    "--run-name", run_name, "--timeout", str(args.timeout),
                    "--accel", args.accel, "--qemu", args.qemu,
                    "--firmware-code", str(args.firmware_code),
                    "--firmware-vars", str(args.firmware_vars), *remainder]
        code = native.main()
    finally:
        native.qemu.launch = launch
        sys.argv = old_argv
    result_path = BUILD / "csm" / run_name / "result.json"
    result = json.loads(result_path.read_text())
    serial = Path(result.get("serial_log", result_path.parent / "serial.log"))
    checks = ordered_checks(serial.read_text(errors="replace") if serial.exists() else "")
    result["boot_path"] = "OVMF -> forced GOP CSMWrap -> guarded MBR probe -> original Windows VBR -> IO.SYS"
    result["io_sys_gop_early_boot"] = {"injection": injected, "checks": checks,
        "status": "PASS" if injected and all(c["status"] == "PASS" for c in checks) else "FAIL",
        "scope": "BIOS text/EDD and Windows VBR handoff; Windows startup and GUI require visual review",
        "runner_sha256": hashlib.sha256(wrapper_bytes).hexdigest(),
        "runner_snapshot": str(inputs / "ios-runner.py"),
        "baseline_runner_sha256": hashlib.sha256(source_bytes).hexdigest()}
    if injected:
        partition = result["partition"]
        partition["pre_probe_mbr_sha256"] = partition["mbr_sha256"]
        partition["mbr_sha256"] = injected["probe_mbr_sha256"]
        partition["uefi_disk_sha256_before_probe"] = partition["uefi_disk_sha256"]
        partition["uefi_disk_sha256"] = injected["disk_sha256_before_vm"]
    if injected and result.get("csmwrap_replacement"):
        result["csmwrap_replacement"]["legacy_boot_sectors_preserved"] = False
        result["csmwrap_replacement"]["windows_vbr_preserved"] = True
        result["csmwrap_replacement"]["mbr_code_change"] = "separately recorded owned probe; identity/partitions retained"
    if result["io_sys_gop_early_boot"]["status"] != "PASS":
        result["status"] = "FAIL"
        code = 1
    shzlib.write_json(result_path, result)
    print(f"Native Windows IO.SYS/GOP trial: {result_path}")
    return code


def main():
    wrapper_bytes = Path(__file__).read_bytes()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--csm-dir", type=Path, required=True)
    parser.add_argument("--negative-csm-dir", type=Path)
    parser.add_argument("--native-windows", action="store_true")
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--firmware-code", type=Path, default=Path(qemu.DEFAULT_OVMF_CODE))
    parser.add_argument("--firmware-vars", type=Path, default=Path(qemu.DEFAULT_OVMF_VARS))
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--timeout", type=int, default=60)
    args, remainder = parser.parse_known_args()
    if not 10 <= args.timeout <= 900 or (remainder and not args.native_windows):
        parser.error("Require a bounded 10..900 second trial; extra options are native-only")
    args.csm_dir = args.csm_dir.resolve(strict=True)
    verify_firmware(args.csm_dir)
    resource_guard(BUILD)
    probe_module, _ = load_source(HERE / "boot_probe" / "build.py")
    with open("/tmp/win98-modern-ios-gop-7acd.lock", "a") as lease:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.native_windows:
            return native_run(args, remainder, probe_module, wrapper_bytes)
        inputs = args.csm_dir / "inputs" / ("contract-" + time.strftime("%Y%m%dT%H%M%S", time.gmtime()))
        probe = probe_module.build_probe(inputs / "probe", test_exit=True)
        passed = contract_run(args, probe, args.csm_dir)
        if args.negative_csm_dir:
            passed = contract_run(args, probe, args.negative_csm_dir.resolve(strict=True), True) and passed
        return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
