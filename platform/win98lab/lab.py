#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private, bounded Windows 98 installation lab; never operates existing VMs."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
import storage

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "build" / "win98-lab"
ISO = BUILD / "win98se-ko-oem.iso"
EXPECTED_ISO = "4c1b148bfd8aa9ffa702d6756ffa32064c49bb78c00d074225db5a0f302c0873"
DISK = BUILD / "install-disk.qcow2"
STATE = BUILD / "install-state.json"
QMP_PATH = BUILD / "install-qmp.sock"
PREFLIGHT = Path("/home/almalinux/workspace/zuku-platform/scripts/compat-vm/compat_vm.py")


class QMP:
    def __init__(self, expected_pid=None):
        if expected_pid is None:
            expected_pid = assert_owned().get('pid')
        if not isinstance(expected_pid, int) or expected_pid <= 0:
            raise RuntimeError('Owned QEMU PID required before QMP connection')
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(5)
        self.socket.connect(str(QMP_PATH))
        peer_pid, peer_uid, _ = struct.unpack('3i', self.socket.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
        if peer_pid != expected_pid or peer_uid != os.getuid():
            self.socket.close()
            raise RuntimeError('QMP peer credentials do not match the owned QEMU process')
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
    storage.durable_json(STATE, state)


@contextmanager
def exclusive_lab_lock():
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(BUILD / 'lab.lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another owned installation run/persistence operation holds the lab lock') from None
        yield
    finally:
        os.close(fd)


def headroom(ram_copy=False):
    values = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(values["MemAvailable"].split()[0]) * 1024
    free = shutil.disk_usage(BUILD).free
    limits = storage.check_headroom(available, free, shutil.disk_usage('/dev/shm').free, ram_copy)
    return {"available_memory_bytes": available, "free_disk_bytes": free, **limits}


def preflight(ram_copy=False):
    if not ISO.is_file() or digest(ISO) != EXPECTED_ISO:
        raise RuntimeError("Authorized installation media missing or checksum mismatch")
    result = json.loads(subprocess.check_output([sys.executable, str(PREFLIGHT), "preflight"], text=True, timeout=30))
    if not result["ok"] or result["active_compat_vms"] or result["active_direct_compat_pids"]:
        raise RuntimeError("Compatibility lab must have no other active QA guest")
    result["local_headroom"] = headroom(ram_copy)
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
    active_disk = state.get('disk', str(DISK))
    if active_disk != str(DISK) and active_disk != state.get('ram_working_copy', {}).get('working_disk'):
        raise RuntimeError("Unknown working disk")
    expected_disk = f'file={active_disk},if=ide,index=0,format=qcow2'.encode()
    expected_qmp = f'unix:{QMP_PATH},server=on,wait=off'.encode()
    if expected_disk not in args or expected_qmp not in args:
        raise RuntimeError("PID is not the owned disk/QMP process")
    return state


def supervise(seconds, resume, ram_copy=False):
    if not 60 <= seconds <= 1800:
        raise RuntimeError("Install supervisor must be bounded to 60..1800 seconds")
    os.umask(0o077)
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    if storage.pending_journals(BUILD):
        raise RuntimeError('An unfinished RAM persistence journal requires recovery before another boot')
    if STATE.exists():
        prior = json.loads(STATE.read_text())
        if prior.get("pid") and Path(f"/proc/{prior['pid']}/cmdline").exists():
            raise RuntimeError("A prior lab process is still present; inspect it first")
        pending = prior.get('ram_working_copy', {})
        if pending and pending.get('status') != 'persisted':
            raise RuntimeError("A prior RAM working copy needs persistence/recovery before another boot")
    if ram_copy and not resume:
        raise RuntimeError("RAM working copies require an existing stopped disk and --resume")
    if DISK.exists() and not resume:
        raise RuntimeError("Existing installation preserved; explicitly --resume to boot it")
    if resume and not DISK.is_file():
        raise RuntimeError("No existing installation to resume")
    check = preflight(ram_copy)
    if not DISK.exists():
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(DISK), "2G"], check=True, timeout=15)
    QMP_PATH.unlink(missing_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    log_path = BUILD / f"qemu-{stamp}.log"
    ram_record = storage.prepare(DISK) if ram_copy else None
    active_disk = Path(ram_record['working_disk']) if ram_record else DISK
    command = ["/usr/libexec/qemu-kvm", "-name", "win98-modern-private-install",
               "-machine", "pc-i440fx-rhel10.0.0,acpi=off,hpet=off", "-accel", "kvm", "-cpu", "qemu64",
               "-smp", "1", "-m", "128M", "-nodefaults", "-nic", "none",
               "-display", "none", "-device", "VGA", "-rtc", "base=localtime",
               "-bios", "/usr/share/seabios/bios-256k.bin", "-boot", "order=d,menu=on",
               "-drive", f"file={active_disk},if=ide,index=0,format=qcow2",
               "-drive", f"file={ISO},if=ide,index=2,media=cdrom,format=raw,readonly=on",
               "-qmp", f"unix:{QMP_PATH},server=on,wait=off"]
    state = {"owner": "win98-modern-isolated-install-v1", "iso_sha256": EXPECTED_ISO,
             "command": command, "disk": str(active_disk), "disk_capacity_bytes": 2 * 1024 ** 3,
             "memory_mib": 128, "network": "none", "display": "QMP screenshots only; no VNC",
             "preflight": check, "windows_98_installed": False,
             "product_key": "No key provided or requested from external sources",
             "max_seconds": seconds, "started_utc": stamp}
    if ram_record:
        state['ram_working_copy'] = ram_record
        state['child_file_size_limit_bytes'] = storage.RAM_DISK_ALLOWANCE
    state['harness_sources_sha256'] = {name: digest(Path(__file__).parent / name)
                                      for name in ('lab.py', 'storage.py')}
    write_state(state)
    process = None
    timer = None
    started = time.monotonic()
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
                                       preexec_fn=storage.limit_child_files)
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
            qmp = QMP(process.pid)
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
        if ram_record and (process is None or process.poll() is not None):
            try:
                storage.persist(ram_record)
            except Exception as error:
                ram_record['status'] = 'persistence_required'
                ram_record['error'] = str(error)
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        write_state(state)
        (BUILD / f"run-{stamp}.json").write_text(json.dumps(state, indent=2) + "\n")
        report_completion(state)


def report_completion(state):
    summary = {'process_stopped': state.get('process_stopped'),
               'elapsed_seconds': state['elapsed_seconds']}
    ram = state.get('ram_working_copy')
    if ram:
        summary['persistence'] = {key: ram.get(key) for key in ('status', 'error')}
    print(json.dumps(summary), flush=True)
    if ram and ram.get('status') != 'persisted':
        raise RuntimeError('Guest stopped, but RAM persistence is incomplete; inspect the saved receipt and journal')


def action(args):
    owned = assert_owned()
    qmp = QMP(owned['pid'])
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
    run.add_argument("--ram-working-copy", action="store_true")
    sub.add_parser("persist-ram")
    sub.add_parser("status")
    snap = sub.add_parser("snapshot"); snap.add_argument("name")
    key = sub.add_parser("key"); key.add_argument("keys", nargs="+")
    text = sub.add_parser("text"); text.add_argument("text")
    sub.add_parser("stop")
    args = parser.parse_args()
    if args.command == "run":
        with exclusive_lab_lock():
            supervise(args.max_seconds, args.resume, args.ram_working_copy)
    elif args.command == 'persist-ram':
        with exclusive_lab_lock():
            retry_persistence()
    else:
        action(args)


def retry_persistence():
    state = (json.loads(STATE.read_text()) if STATE.exists() else
             {'owner': 'win98-modern-isolated-install-v1', 'pid': None})
    if state.get('owner') != 'win98-modern-isolated-install-v1':
        raise RuntimeError('Persistence requires a known owned guest')
    pid = state.get('pid')
    if pid is not None and (not isinstance(pid, int) or pid <= 0 or Path(f'/proc/{pid}/cmdline').exists()):
        raise RuntimeError('Recorded guest PID is still present or cannot be verified')
    # A supervisor crash can leave the last receipt marked running even after
    # its QEMU child stopped. PID absence, the lock and journal permit recovery.
    record = state.get('ram_working_copy')
    pending = storage.pending_journals(BUILD)
    if not record and not pending:
        # A first recovery may finish and remove RAM, then crash before creating
        # STATE. A sole completed journal still proves the published disk.
        pending = list(BUILD.glob('ram-copy-*.json'))
    if pending:
        if len(pending) != 1:
            raise RuntimeError('Multiple persistence journals need explicit review')
        record = json.loads(pending[0].read_text())
    if not record:
        raise RuntimeError('No RAM copy journal')
    if record.get('original_disk') != str(DISK):
        raise RuntimeError('Unexpected persistent disk target')
    storage.locations(record)
    assert_no_owned_processes(record)
    storage.persist(record)
    state['ram_working_copy'] = record
    state['process_stopped'] = True
    write_state(state)
    print('Verified RAM working copy persisted; original backup retained')


def assert_no_owned_processes(record, proc_root=Path('/proc')):
    disks = [f"file={record[key]},if=ide,index=0,format=qcow2".encode()
             for key in ('original_disk', 'working_disk')]
    # Covers a supervisor crash in the narrow Popen-to-state-write interval.
    # The common flock excludes another harness launch throughout this scan
    # and publication; qemu-img also refuses a disk locked by a running VM.
    for command in proc_root.glob('[0-9]*/cmdline'):
        try:
            argv = command.read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        except PermissionError:
            raise RuntimeError('Cannot verify process ownership; recovery refused') from None
        if b'win98-modern-private-install' in argv or any(disk in argv for disk in disks):
            raise RuntimeError('An owned installation process is still present; recovery refused')


if __name__ == "__main__":
    main()
