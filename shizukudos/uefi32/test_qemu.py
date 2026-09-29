#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded KVM proof of the real UEFI-to-32-bit protected-mode kernel handoff.

Reuses this project's original uefi/test_qemu.py harness structure. All media,
logs, screenshots and memory snapshots belong only to this new build directory.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parent


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(2)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile("rwb", buffering=0)
        greeting = json.loads(self.stream.readline())
        if "QMP" not in greeting:
            raise RuntimeError("Missing QMP greeting")
        self.call("qmp_capabilities")

    def call(self, command, arguments=None):
        message = {"execute": command}
        if arguments is not None:
            message["arguments"] = arguments
        self.stream.write((json.dumps(message) + "\n").encode())
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP closed unexpectedly")
            response = json.loads(line)
            if "return" in response:
                return response["return"]
            if "error" in response:
                raise RuntimeError(f"QMP {command}: {response['error']}")

    def close(self):
        self.stream.close()
        self.socket.close()


def inspect_screen(path):
    data = path.read_bytes()
    magic, dimensions, maximum, pixels = data.split(b"\n", 3)
    if magic != b"P6" or maximum != b"255":
        raise RuntimeError("Unexpected QEMU screenshot encoding")
    width, height = map(int, dimensions.split())
    if width < 640 or height < 400 or len(pixels) != width * height * 3:
        return False, width, height
    # These colors are written only by the independent post-firmware paths.
    expected = {(10, 10): bytes.fromhex("101c30"),
                (50, 50): bytes.fromhex("20d080"),
                (130, 50): bytes.fromhex("ffb020"),
                (210, 50): bytes.fromhex("30d0e0")}
    ok = all(pixels[(y * width + x) * 3:(y * width + x) * 3 + 3] == color
             for (x, y), color in expected.items())
    return ok, width, height


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_handoff(qmp, directory):
    filename = directory / "handoff.bin"
    qmp.call("pmemsave", {"val": 0x0200F000, "size": 112, "filename": str(filename)})
    names = ("magic version size stage framebuffer framebuffer_bytes width height pitch_pixels pixel_format "
             "memory_map map_bytes descriptor_bytes descriptor_version region_base region_bytes payload_bytes stack_top "
             "cr0 cr4 efer cs ss esp core_pass graphics_pass mode_pass exit_attempted").split()
    values = dict(zip(names, struct.unpack("<28I", filename.read_bytes())))
    valid = (values["magic"] == 0x32334453 and values["version"] == 1 and values["size"] == 112 and
             values["stage"] == 5 and values["core_pass"] == values["graphics_pass"] == values["mode_pass"] == 1 and
             values["cr0"] & 1 and not values["cr0"] & 0x80000000 and not values["cr4"] & 0x21020 and
             not values["efer"] & 0x500 and values["cs"] == 0x10 and values["ss"] == 0x18 and
             0x021F0000 <= values["esp"] < 0x02200000 and values["exit_attempted"] == 1)
    return bool(valid), values


def inspect_registers(registers, handoff):
    observed = {}
    for name in ("EIP", "ESP", "CR0", "CR4", "EFER"):
        match = re.search(r"\b" + name + r"=([0-9a-fA-F]+)", registers)
        if not match:
            raise RuntimeError(f"QEMU did not report independent {name}")
        observed[name] = int(match.group(1), 16)
    valid = ("CS32" in registers and "CPL=0" in registers and "HLT=1" in registers and
             0x02010000 <= observed["EIP"] < 0x02100000 and
             0x021F0000 <= observed["ESP"] < 0x02200000 and
             observed["CR0"] == handoff["cr0"] and observed["CR4"] == handoff["cr4"] and
             observed["EFER"] == handoff["efer"])
    if not valid:
        raise RuntimeError("Independent QEMU CPU state disagrees with protected-mode handoff")
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="/usr/libexec/qemu-kvm")
    parser.add_argument("--firmware-code", default="/usr/share/edk2/ovmf/OVMF_CODE.fd")
    parser.add_argument("--firmware-vars", default="/usr/share/edk2/ovmf/OVMF_VARS.fd")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 45:
        parser.error("The disposable boot must be bounded to 1..45 seconds")
    build = ROOT / "build"
    artifact = build / "BOOTX64.EFI"
    manifest = build / "build-result.json"
    if not manifest.is_file():
        raise SystemExit("A successful current build receipt is required; run build.py first")
    built = json.loads(manifest.read_text())
    if built["efi"]["sha256"] != digest(artifact):
        raise SystemExit("EFI image differs from the successful build receipt")
    for name, expected in built.get("sources_sha256", {}).items():
        if digest(ROOT.parent.parent / name) != expected:
            raise SystemExit(f"Source changed after build: {name}; rebuild before boot testing")
    for filename in (artifact, Path(args.qemu), Path(args.firmware_code), Path(args.firmware_vars)):
        if not filename.is_file():
            raise SystemExit(f"Existing file required: {filename}; nothing downloaded")
    media_tools = {name: shutil.which(name) for name in ("mkfs.vfat", "mmd", "mcopy")}
    if not all(media_tools.values()):
        raise SystemExit("Existing mkfs.vfat and mtools required; nothing installed")
    testdir = Path(tempfile.mkdtemp(prefix="ovmf-", dir=build))
    esp = testdir / "esp"
    boot = esp / "EFI" / "BOOT"
    boot.mkdir(parents=True)
    shutil.copyfile(artifact, boot / "BOOTX64.EFI")
    disk = testdir / "esp.img"
    with disk.open("wb") as file:
        file.truncate(16 * 1024 * 1024)
    subprocess.run([media_tools["mkfs.vfat"], "-F", "16", str(disk)],
                   check=True, capture_output=True, timeout=10)
    subprocess.run([media_tools["mmd"], "-i", str(disk), "::/EFI", "::/EFI/BOOT"],
                   check=True, capture_output=True, timeout=10)
    subprocess.run([media_tools["mcopy"], "-i", str(disk), str(artifact), "::/EFI/BOOT/BOOTX64.EFI"],
                   check=True, capture_output=True, timeout=10)
    variables = testdir / "OVMF_VARS.fd"
    shutil.copyfile(args.firmware_vars, variables)
    monitor = testdir / "qmp.sock"
    screenshot = testdir / "handoff.ppm"
    command = [args.qemu, "-machine", "q35", "-accel", args.accel, "-cpu", "host" if args.accel == "kvm" else "max",
               "-m", "256M", "-smp", "1", "-nodefaults", "-nic", "none",
               "-display", "none", "-device", "VGA", "-no-reboot",
               "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={Path(args.firmware_code).resolve()}",
               "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
               "-drive", f"if=none,id=esp,format=raw,readonly=on,file={disk}",
               "-device", "virtio-blk-pci,drive=esp,bootindex=1",
               "-serial", f"file:{testdir / 'serial.log'}",
               "-qmp", f"unix:{monitor},server=on,wait=off"]
    receipt = {"artifact_sha256": digest(artifact), "command": command,
               "firmware_code_sha256": digest(Path(args.firmware_code)),
               "memory_mib": 256, "vcpus": 1, "network": "disabled", "pass": False}
    qmp = None
    process = None
    watchdog = None
    started = time.monotonic()
    try:
        with (testdir / "qemu.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            watchdog = threading.Timer(args.timeout, process.kill)
            watchdog.daemon = True
            watchdog.start()
            receipt["pid"] = process.pid
            deadline = started + args.timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited early: {(testdir / 'qemu.log').read_text()}")
                if monitor.exists():
                    qmp = QMP(monitor)
                    break
                time.sleep(0.1)
            if qmp is None:
                raise RuntimeError("QMP startup timed out")
            receipt["kvm"] = qmp.call("query-kvm")
            if args.accel == "kvm" and not receipt["kvm"].get("enabled"):
                raise RuntimeError("KVM was required but is not active")
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError("QEMU exited before post-firmware handoff")
                qmp.call("screendump", {"filename": str(screenshot)})
                ok, width, height = inspect_screen(screenshot)
                if ok:
                    ok, receipt["handoff"] = inspect_handoff(qmp, testdir)
                if ok:
                    receipt.update({"pass": True, "resolution": [width, height],
                                    "exit_boot_services": "actual protected-mode payload owns execution",
                                    "cpu_mode": "legacy 32-bit protected mode, CPL0, paging/PAE/LME/LMA off",
                                    "ntwddm": "NTWDDM_PM32_PASS: software fill/present/fence",
                                    "ntwrapper": "NTWRAPPER9X_PM32_PASS: event/lease core",
                                    "windows_98_boot": "not implemented or claimed",
                                    "screenshot_sha256": digest(screenshot)})
                    receipt["registers"] = qmp.call("human-monitor-command", {"command-line": "info registers"})
                    receipt["independent_registers"] = inspect_registers(receipt["registers"], receipt["handoff"])
                    (testdir / "registers.txt").write_text(receipt["registers"])
                    # Native PNG output is optional; the PPM is sufficient evidence.
                    try:
                        qmp.call("screendump", {"filename": str(testdir / "handoff.png"), "format": "png"})
                    except RuntimeError:
                        pass
                    break
                time.sleep(0.5)
            if not receipt["pass"]:
                _, receipt["handoff"] = inspect_handoff(qmp, testdir)
                receipt["registers"] = qmp.call("human-monitor-command", {"command-line": "info registers"})
                raise RuntimeError("No complete post-firmware proof screen before timeout")
    except Exception as error:
        receipt["pass"] = False
        receipt["error"] = str(error)
    finally:
        if qmp:
            qmp.close()
        if process:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            receipt["process_stopped"] = process.poll() is not None
            receipt["qemu_returncode"] = process.returncode
        if watchdog:
            watchdog.cancel()
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        receipt["evidence_directory"] = str(testdir)
        (testdir / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
        receipt_name = "qemu-result.json"
        (build / receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
    if not receipt["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
