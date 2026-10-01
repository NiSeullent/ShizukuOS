#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, network-disabled OVMF boot of the exact production EFI artifact.

No guest disk or existing VM is used. The only writable guest firmware file is
a private copy. QMP proves KVM and takes a live screenshot after the real
ExitBootServices path and independent graphics/kernel-core checks run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import re
import socket
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


def inspect_screen(path, test_pci=False):
    data = path.read_bytes()
    magic, dimensions, maximum, pixels = data.split(b"\n", 3)
    if magic != b"P6" or maximum != b"255":
        raise RuntimeError("Unexpected QEMU screenshot encoding")
    width, height = map(int, dimensions.split())
    if width < 320 or height < 200 or len(pixels) != width * height * 3:
        return False, width, height
    # These colors are written only by the independent post-firmware paths.
    expected = {(10, 10): bytes.fromhex("101c30"),
                (50, 50): bytes.fromhex("20d080"),
                (130, 50): bytes.fromhex("7040e0"),
                (210, 50): bytes.fromhex("ffb020"),
                (280, 50): bytes.fromhex("30d0e0")}
    if test_pci:
        if height < 368:
            return False, width, height
        expected[(50, 320)] = bytes.fromhex("f040b0")
    ok = all(pixels[(y * width + x) * 3:(y * width + x) * 3 + 3] == color
             for (x, y), color in expected.items())
    return ok, width, height


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="/usr/libexec/qemu-kvm")
    parser.add_argument("--firmware-code", default="/usr/share/edk2/ovmf/OVMF_CODE.fd")
    parser.add_argument("--firmware-vars", default="/usr/share/edk2/ovmf/OVMF_VARS.fd")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--test-pci", action="store_true", help="Attach disposable downstream xHCI for the explicit test build")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 45:
        parser.error("The disposable boot must be bounded to 1..45 seconds")
    build = ROOT / "build"
    artifact = build / ("BOOTX64-PCI-TEST.EFI" if args.test_pci else "BOOTX64.EFI")
    manifest = build / ("build-pci-result.json" if args.test_pci else "build-result.json")
    if not manifest.is_file():
        raise SystemExit("A successful current build receipt is required; run build.py first")
    built = json.loads(manifest.read_text())
    if built.get("sha256") != digest(artifact):
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
    command = [args.qemu, "-machine", "q35", "-accel", args.accel,
               "-m", "256M", "-smp", "1", "-nodefaults", "-nic", "none",
               "-display", "none", "-device", "VGA", "-no-reboot",
               "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={Path(args.firmware_code).resolve()}",
               "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
               "-drive", f"if=none,id=esp,format=raw,readonly=on,file={disk}",
               "-device", "virtio-blk-pci,drive=esp,bootindex=1",
               "-serial", f"file:{testdir / 'serial.log'}",
               "-qmp", f"unix:{monitor},server=on,wait=off"]
    if args.test_pci:
        command += ["-device", "pcie-root-port,id=rp1,chassis=1,slot=1,bus=pcie.0",
                    "-device", "qemu-xhci,bus=rp1",
                    "-debugcon", f"file:{testdir / 'pci-debug.log'}"]
    receipt = {"artifact_sha256": digest(artifact), "command": command,
               "test_harness_sha256": digest(Path(__file__)),
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
                ok, width, height = inspect_screen(screenshot, args.test_pci)
                if ok and args.test_pci:
                    ok = "NTWPCIE_BRIDGE_XHCI_PASS" in (testdir / "pci-debug.log").read_text()
                if ok:
                    selections = re.findall(
                        r"GOP selection: mode (\d+) (\d+)x(\d+) pitch (\d+) (BGRX|RGBX) "
                        r"queried (\d+) EDID=(preferred|unavailable) (selected|firmware-fallback)",
                        (testdir / "serial.log").read_text(errors="replace"))
                    if len(selections) != 1:
                        raise RuntimeError("No unique live GOP selection record in the firmware console log")
                    mode, sw, sh, pitch, layout, queried, edid, policy = selections[0]
                    if ((int(sw), int(sh)) != (width, height) or int(pitch) < width * 4 or
                            int(pitch) % 4 or int(pitch) * height > 64 * 1024 * 1024 or
                            int(queried) > 1024 or (int(queried) and int(mode) >= int(queried))):
                        raise RuntimeError("Live GOP selection violates budget/pitch or disagrees with the post-exit screen")
                    receipt.update({"pass": True, "resolution": [width, height],
                                    "gop_selection": {"mode": int(mode), "width": int(sw), "height": int(sh),
                                                      "pitch_bytes": int(pitch), "layout": layout,
                                                      "modes_queried": int(queried), "edid": edid, "policy": policy},
                                    "exit_boot_services": "post-exit framebuffer verified",
                                    "ntwddm": "software fill/present/fence verified",
                                    "ntwrapper": "NTWRAPPER9X_RING0_PASS",
                                    "windows_98_boot": "not implemented or claimed",
                                    "screenshot_sha256": digest(screenshot)})
                    if args.test_pci:
                        receipt["pcie"] = "downstream xHCI + bridge enumerated via 256-byte mechanism-1; no ECAM/DMA"
                        receipt["pci_debug_log"] = (testdir / "pci-debug.log").read_text()
                    # Native PNG output is optional; the PPM is sufficient evidence.
                    try:
                        qmp.call("screendump", {"filename": str(testdir / "handoff.png"), "format": "png"})
                    except RuntimeError:
                        pass
                    break
                time.sleep(0.5)
            if not receipt["pass"]:
                raise RuntimeError("No complete post-firmware proof screen before timeout")
    except Exception as error:
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
        receipt_name = "qemu-pci-result.json" if args.test_pci else "qemu-result.json"
        (build / receipt_name).write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))
    if not receipt["pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
