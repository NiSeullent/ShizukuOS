#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private, bounded Windows 98 installation lab; never operates existing VMs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build" / "win98-lab"
ISO = BUILD / "win98se-ko-oem.iso"
EXPECTED_ISO = "4c1b148bfd8aa9ffa702d6756ffa32064c49bb78c00d074225db5a0f302c0873"
DISK = BUILD / "install-disk.qcow2"
STATE = BUILD / "install-state.json"
QMP_PATH = BUILD / "install-qmp.sock"
PREFLIGHT = Path("/home/almalinux/workspace/zuku-platform/scripts/compat-vm/compat_vm.py")


class QMP:
    def __init__(self):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.socket.connect(str(QMP_PATH))
        self.stream = self.socket.makefile("rwb", buffering=0)
        if "QMP" not in json.loads(self.stream.readline()):
            raise RuntimeError("Missing QMP greeting")
        self.call("qmp_capabilities")

    def call(self, command, arguments=None):
        request = {"execute": command}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.write((json.dumps(request) + "\n").encode())
        while True:
            line = self.stream.readline()
            if not line:
                raise RuntimeError("QMP closed")
            reply = json.loads(line)
            if "return" in reply:
                return reply["return"]
            if "error" in reply:
                raise RuntimeError(str(reply["error"]))

    def close(self):
        self.stream.close()
        self.socket.close()


def digest(path):
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def write_state(state):
    temporary = STATE.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(state, indent=2) + "\n")
    temporary.replace(STATE)


def headroom():
    values = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(values["MemAvailable"].split()[0]) * 1024
    free = shutil.disk_usage(BUILD).free
    if available - (128 + 256) * 1024 * 1024 < 6 * 1024 ** 3:
        raise RuntimeError("Less than 6 GiB host RAM reserve after guest overhead")
    # Reserve the entire 2-GiB virtual disk even though qcow2 is sparse.
    if free - 2 * 1024 ** 3 < 20 * 1024 ** 3:
        raise RuntimeError("Less than 20 GiB host disk reserve after guest disk cap")
    return {"available_memory_bytes": available, "free_disk_bytes": free}


def preflight():
    if not ISO.is_file() or digest(ISO) != EXPECTED_ISO:
        raise RuntimeError("Authorized installation media missing or checksum mismatch")
    result = json.loads(subprocess.check_output([sys.executable, str(PREFLIGHT), "preflight"], text=True, timeout=30))
    if not result["ok"] or result["active_compat_vms"] or result["active_direct_compat_pids"]:
        raise RuntimeError("Compatibility lab must have no other active QA guest")
    result["local_headroom"] = headroom()
    return result


def assert_owned():
    state = json.loads(STATE.read_text())
    if state.get("owner") != "win98-modern-isolated-install-v1":
        raise RuntimeError("Unknown install-lab owner")
    pid = state.get("pid")
    command = Path(f"/proc/{pid}/cmdline")
    if not command.exists():
        raise RuntimeError("The owned guest is stopped")
    args = command.read_bytes().split(b"\0")
    if str(DISK).encode() not in b" ".join(args) or str(QMP_PATH).encode() not in b" ".join(args):
        raise RuntimeError("PID is not the owned disk/QMP process")
    return state


def supervise(seconds, resume):
    if not 60 <= seconds <= 1800:
        raise RuntimeError("Install supervisor must be bounded to 60..1800 seconds")
    os.umask(0o077)
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    if STATE.exists():
        prior = json.loads(STATE.read_text())
        if prior.get("pid") and Path(f"/proc/{prior['pid']}/cmdline").exists():
            raise RuntimeError("A prior lab process is still present; inspect it first")
    if DISK.exists() and not resume:
        raise RuntimeError("Existing installation preserved; explicitly --resume to boot it")
    if resume and not DISK.is_file():
        raise RuntimeError("No existing installation to resume")
    check = preflight()
    if not DISK.exists():
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(DISK), "2G"], check=True, timeout=15)
    QMP_PATH.unlink(missing_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    log_path = BUILD / f"qemu-{stamp}.log"
    command = ["/usr/libexec/qemu-kvm", "-name", "win98-modern-private-install",
               "-machine", "pc-i440fx-rhel10.0.0,acpi=off,hpet=off", "-accel", "kvm", "-cpu", "qemu64",
               "-smp", "1", "-m", "128M", "-nodefaults", "-nic", "none",
               "-display", "none", "-device", "VGA", "-rtc", "base=localtime",
               "-bios", "/usr/share/seabios/bios-256k.bin", "-boot", "order=d,menu=on",
               "-drive", f"file={DISK},if=ide,index=0,format=qcow2",
               "-drive", f"file={ISO},if=ide,index=2,media=cdrom,format=raw,readonly=on",
               "-qmp", f"unix:{QMP_PATH},server=on,wait=off"]
    state = {"owner": "win98-modern-isolated-install-v1", "iso_sha256": EXPECTED_ISO,
             "command": command, "disk": str(DISK), "disk_capacity_bytes": 2 * 1024 ** 3,
             "memory_mib": 128, "network": "none", "display": "QMP screenshots only; no VNC",
             "preflight": check, "windows_98_installed": False,
             "product_key": "No key provided or requested from external sources",
             "max_seconds": seconds, "started_utc": stamp}
    process = None
    timer = None
    started = time.monotonic()
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            state["pid"] = process.pid
            timer = threading.Timer(seconds, process.terminate)
            timer.daemon = True
            timer.start()
            write_state(state)
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU startup failed: {log_path.read_text()}")
                if QMP_PATH.exists():
                    break
                time.sleep(0.1)
            qmp = QMP()
            state["kvm"] = qmp.call("query-kvm")
            state["status"] = qmp.call("query-status")
            qmp.close()
            if not state["kvm"].get("enabled"):
                raise RuntimeError("KVM is required for this installation attempt")
            write_state(state)
            print(json.dumps({"pid": process.pid, "kvm": state["kvm"], "state": str(STATE),
                              "qmp": str(QMP_PATH), "log": str(log_path)}, indent=2), flush=True)
            while process.poll() is None and time.monotonic() - started < seconds + 3:
                time.sleep(0.25)
    finally:
        if timer:
            timer.cancel()
        if process:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            state["process_stopped"] = process.poll() is not None
            state["returncode"] = process.returncode
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_state(state)
        (BUILD / f"run-{stamp}.json").write_text(json.dumps(state, indent=2) + "\n")
        print(json.dumps({"process_stopped": state.get("process_stopped"), "elapsed_seconds": state["elapsed_seconds"]}), flush=True)


def action(args):
    assert_owned()
    qmp = QMP()
    try:
        if args.command == "status":
            print(json.dumps({"status": qmp.call("query-status"), "kvm": qmp.call("query-kvm")}, indent=2))
        elif args.command == "snapshot":
            if not re.fullmatch(r"[a-zA-Z0-9_-]{1,80}", args.name):
                raise RuntimeError("Invalid screenshot name")
            output = BUILD / (args.name + ".png")
            if output.exists():
                raise RuntimeError("Existing screenshot preserved; choose another name")
            qmp.call("screendump", {"filename": str(output), "format": "png"})
            print(output)
        elif args.command == "key":
            for key in args.keys:
                if not re.fullmatch(r"[a-z0-9_-]+", key):
                    raise RuntimeError("Use QEMU key names")
                qmp.call("human-monitor-command", {"command-line": "sendkey " + key + " 30"})
                time.sleep(0.15)
            print(f"Sent {len(args.keys)} key actions")
        elif args.command == "text":
            # For installer commands/labels. Never use this CLI to enter a key.
            if len(args.text) > 200 or re.fullmatch(r"(?:[A-Za-z0-9]{5}-){4}[A-Za-z0-9]{5}", args.text):
                raise RuntimeError("Product keys must not be passed as CLI arguments")
            symbols = {" ": "spc", ".": "dot", "/": "slash", "\\": "backslash", ":": "shift-semicolon",
                       "-": "minus", "_": "shift-minus", "=": "equal", "\n": "ret"}
            for char in args.text:
                if char.isascii() and char.isalnum():
                    key = ("shift-" if char.isupper() else "") + char.lower()
                elif char in symbols:
                    key = symbols[char]
                else:
                    raise RuntimeError("Unsupported command character")
                qmp.call("human-monitor-command", {"command-line": "sendkey " + key + " 30"})
                time.sleep(0.08)
            print(f"Sent {len(args.text)} command characters")
        elif args.command == "stop":
            qmp.call("quit")
            print("Requested termination of the owned installation guest")
    finally:
        qmp.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("--max-seconds", type=int, default=900)
    run.add_argument("--resume", action="store_true")
    sub.add_parser("status")
    snap = sub.add_parser("snapshot"); snap.add_argument("name")
    key = sub.add_parser("key"); key.add_argument("keys", nargs="+")
    text = sub.add_parser("text"); text.add_argument("text")
    sub.add_parser("stop")
    args = parser.parse_args()
    if args.command == "run":
        supervise(args.max_seconds, args.resume)
    else:
        action(args)


if __name__ == "__main__":
    main()
