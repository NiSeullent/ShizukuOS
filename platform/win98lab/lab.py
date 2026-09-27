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
import packed
import base_archive
import trial

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


def harness_sources():
    return {name: digest(Path(__file__).parent / name)
            for name in ('lab.py', 'storage.py', 'packed.py', 'base_archive.py', 'trial.py')}


def assert_harness_sources(expected):
    if harness_sources() != expected:
        raise RuntimeError('Lab harness sources changed during the operation')


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


def storage_backend(record):
    mode = record.get('mode')
    if mode is None:
        return storage
    if mode == 'packed':
        return packed
    if mode == 'qa-trial':
        return trial
    raise RuntimeError('Unknown RAM persistence mode')


def pending_journals():
    return storage.pending_journals(BUILD) + packed.pending_journals(BUILD) + trial.pending_journals(BUILD)


def headroom(ram_copy=False, packed_checkpoint=False):
    values = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(values["MemAvailable"].split()[0]) * 1024
    free = shutil.disk_usage(BUILD).free
    tmpfs_free = shutil.disk_usage('/dev/shm').free
    limits = (packed.check_headroom(available, free, tmpfs_free) if packed_checkpoint else
              storage.check_headroom(available, free, tmpfs_free, ram_copy))
    return {"available_memory_bytes": available, "free_disk_bytes": free, **limits}


def preflight(ram_copy=False, packed_checkpoint=False):
    if not ISO.is_file() or digest(ISO) != EXPECTED_ISO:
        raise RuntimeError("Authorized installation media missing or checksum mismatch")
    result = json.loads(subprocess.check_output([sys.executable, str(PREFLIGHT), "preflight"], text=True, timeout=30))
    if not result["ok"] or result["active_compat_vms"] or result["active_direct_compat_pids"]:
        raise RuntimeError("Compatibility lab must have no other active QA guest")
    result["local_headroom"] = headroom(ram_copy, packed_checkpoint)
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
    if active_disk != str(DISK):
        storage_backend(state['ram_working_copy']).locations(state['ram_working_copy'])
    expected_disk = f'file={active_disk},if=ide,index=0,format=qcow2'.encode()
    expected_qmp = f'unix:{QMP_PATH},server=on,wait=off'.encode()
    if expected_disk not in args or expected_qmp not in args:
        raise RuntimeError("PID is not the owned disk/QMP process")
    return state


def supervise(seconds, resume, ram_copy=False, packed_checkpoint=False,
              ephemeral_qa=False, baseline_pointer_sha256=None):
    if not 60 <= seconds <= 1800:
        raise RuntimeError("Install supervisor must be bounded to 60..1800 seconds")
    if ephemeral_qa and (ram_copy or packed_checkpoint):
        raise RuntimeError('Ephemeral QA cannot be combined with persistent RAM modes')
    if ephemeral_qa:
        if not isinstance(baseline_pointer_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', baseline_pointer_sha256):
            raise RuntimeError('Ephemeral QA requires the exact reviewed baseline pointer SHA-256')
    elif baseline_pointer_sha256 is not None:
        raise RuntimeError('A baseline pointer hash requires --ephemeral-qa')
    os.umask(0o077)
    BUILD.mkdir(mode=0o700, parents=True, exist_ok=True)
    if pending_journals():
        raise RuntimeError('An unfinished RAM persistence journal requires recovery before another boot')
    if STATE.exists():
        prior = json.loads(STATE.read_text())
        if prior.get("pid") and Path(f"/proc/{prior['pid']}/cmdline").exists():
            raise RuntimeError("A prior lab process is still present; inspect it first")
        pending = prior.get('ram_working_copy', {})
        terminal = 'discarded' if pending.get('mode') == 'qa-trial' else 'persisted'
        if pending and pending.get('status') != terminal:
            raise RuntimeError("A prior RAM working copy needs persistence/recovery before another boot")
    ram_copy = ram_copy or packed_checkpoint or ephemeral_qa
    archived = base_archive.has_archive(DISK)
    if archived and not (packed_checkpoint or ephemeral_qa):
        raise RuntimeError('An archived base is present; raw access is refused, use --packed-checkpoint')
    if ram_copy and not resume:
        raise RuntimeError("RAM working copies require an existing stopped disk and --resume")
    if packed.has_checkpoint(DISK) and not (packed_checkpoint or ephemeral_qa):
        raise RuntimeError('A packed checkpoint is current; resume with --packed-checkpoint to avoid rollback')
    if (DISK.exists() or archived) and not resume:
        raise RuntimeError("Existing installation preserved; explicitly --resume to boot it")
    if resume and not DISK.is_file() and not archived:
        raise RuntimeError("No existing installation to resume")
    if archived and not ephemeral_qa:
        packed.current(DISK)
    check = preflight(ram_copy, packed_checkpoint or ephemeral_qa)
    sources = harness_sources()
    if not DISK.exists() and not archived:
        subprocess.run(["qemu-img", "create", "-f", "qcow2", str(DISK), "2G"], check=True, timeout=15)
    QMP_PATH.unlink(missing_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    log_path = BUILD / f"qemu-{stamp}.log"
    backend = trial if ephemeral_qa else packed if packed_checkpoint else storage
    ram_record = (trial.prepare(DISK, baseline_pointer_sha256) if ephemeral_qa else
                  backend.prepare(DISK) if ram_copy else None)
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
             "product_key": "Product-key handling is recorded only in private installation evidence; no key is stored here",
             "max_seconds": seconds, "started_utc": stamp}
    if ram_record:
        state['ram_working_copy'] = ram_record
        state['child_file_size_limit_bytes'] = storage.RAM_DISK_ALLOWANCE
    state['harness_sources_sha256'] = sources
    write_state(state)
    process = None
    timer = None
    started = time.monotonic()
    try:
        with log_path.open("wb") as log:
            assert_harness_sources(sources)
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
                if ephemeral_qa:
                    assert_harness_sources(sources)
                    trial.record_stopped(ram_record, guard=assert_no_owned_processes)
                    state['baseline_unchanged'] = True
                    state['persisted'] = False
                else:
                    backend.persist(ram_record)
            except Exception as error:
                if ephemeral_qa:
                    state['qa_stop_error'] = str(error)
                else:
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
    if ram and ram.get('mode') == 'qa-trial':
        summary['qa_trial'] = {'status': ram.get('status'), 'persisted': False,
                               'baseline_unchanged': state.get('baseline_unchanged', False),
                               'error': state.get('qa_stop_error')}
        print(json.dumps(summary), flush=True)
        if ram.get('status') != 'stopped_awaiting_evidence' or state.get('qa_stop_error'):
            raise RuntimeError('QA working copy retained; inspect its journal and explicitly recover it')
        return
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
    run.add_argument("--packed-checkpoint", action="store_true",
                     help="resume in RAM and persist byte-exact compressed checkpoints")
    run.add_argument('--ephemeral-qa', action='store_true',
                     help='restore a reviewed baseline; retain stopped RAM for evidence without disk writeback')
    run.add_argument('--baseline-pointer-sha256', help='exact reviewed current packed pointer file SHA-256')
    for name in ('qa-record-stopped', 'qa-seal-evidence', 'qa-discard'):
        command = sub.add_parser(name)
        command.add_argument('--journal', required=True, type=Path)
        if name == 'qa-seal-evidence':
            command.add_argument('--inputs', required=True, type=Path,
                                 help='bounded JSON map of evidence filenames to absolute source paths')
        if name == 'qa-discard':
            command.add_argument('--evidence-sha256', required=True,
                                 help='explicitly reviewed immutable evidence manifest SHA-256')
    sub.add_parser("persist-ram")
    archive = sub.add_parser('archive-base', help='verify an immutable base archive and explicitly retire its raw duplicate')
    archive.add_argument('--expected-packed-sha256', required=True,
                         help='SHA-256 of the reviewed current packed pointer file')
    sub.add_parser("status")
    snap = sub.add_parser("snapshot"); snap.add_argument("name")
    key = sub.add_parser("key"); key.add_argument("keys", nargs="+")
    text = sub.add_parser("text"); text.add_argument("text")
    sub.add_parser("stop")
    args = parser.parse_args()
    if args.command == "run":
        with exclusive_lab_lock():
            supervise(args.max_seconds, args.resume, args.ram_working_copy, args.packed_checkpoint,
                      args.ephemeral_qa, args.baseline_pointer_sha256)
    elif args.command.startswith('qa-'):
        qa_operation(args)
    elif args.command == 'persist-ram':
        with exclusive_lab_lock():
            retry_persistence()
    elif args.command == 'archive-base':
        archive_base(args.expected_packed_sha256)
    else:
        action(args)


def retry_persistence():
    if trial.pending_journals(BUILD):
        raise RuntimeError('Retained QA trial requires explicit QA recovery; it cannot be persisted')
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
    if record and record.get('mode') == 'qa-trial':
        raise RuntimeError('QA trials never write back; use explicit QA evidence/discard commands')
    pending = pending_journals()
    if not record and not pending:
        # A first recovery may finish and remove RAM, then crash before creating
        # STATE. A sole completed journal still proves the published disk.
        pending = list(BUILD.glob('ram-copy-*.json')) + list(BUILD.glob('packed-copy-*.json'))
    if pending:
        if len(pending) != 1:
            raise RuntimeError('Multiple persistence journals need explicit review')
        record = json.loads(pending[0].read_text())
    if not record:
        raise RuntimeError('No RAM copy journal')
    if record.get('original_disk') != str(DISK):
        raise RuntimeError('Unexpected persistent disk target')
    backend = storage_backend(record)
    if backend is storage and base_archive.has_archive(DISK):
        raise RuntimeError('An archived base is present; raw persistence is refused')
    if backend is storage and packed.has_checkpoint(DISK):
        raise RuntimeError('A packed checkpoint is current; raw persistence would roll back the installation')
    backend.locations(record)
    assert_no_owned_processes(record)
    backend.persist(record)
    state['ram_working_copy'] = record
    state['process_stopped'] = True
    write_state(state)
    print('Verified RAM working copy persisted; previous disk checkpoints retained')


def qa_operation(args):
    """Explicit stopped-only evidence/recovery; never write back a QA image."""
    with exclusive_lab_lock():
        sources = harness_sources()
        journal = args.journal
        if journal.parent != BUILD:
            raise RuntimeError('QA journal must belong to this private installation lab')
        record = trial.load_record(journal)
        if record['original_disk'] != str(DISK):
            raise RuntimeError('QA journal targets a different installation')

        def guard(value):
            assert_harness_sources(sources)
            if storage.pending_journals(BUILD) or packed.pending_journals(BUILD):
                raise RuntimeError('Unfinished persistent copy blocks QA recovery')
            pending = trial.pending_journals(BUILD)
            if any(path != journal for path in pending):
                raise RuntimeError('Another QA journal requires recovery first')
            if STATE.exists():
                state = json.loads(STATE.read_text())
                if state.get('owner') != 'win98-modern-isolated-install-v1':
                    raise RuntimeError('Unknown installation state owner')
                pid = state.get('pid')
                if pid is not None and (type(pid) is not int or pid <= 0 or Path(f'/proc/{pid}').exists()):
                    raise RuntimeError('Recorded installation PID is still present or cannot be verified')
            assert_no_owned_processes(value)

        guard(record)
        if args.command == 'qa-record-stopped':
            trial.record_stopped(record, guard=guard)
        elif args.command == 'qa-seal-evidence':
            evidence, _ = trial._json(args.inputs)
            trial.seal(record, evidence, guard=guard)
        elif args.command == 'qa-discard':
            trial.discard(record, args.evidence_sha256, guard=guard)
        else:
            raise RuntimeError('Unknown QA operation')
        guard(record)
        if STATE.exists():
            state = json.loads(STATE.read_text())
            if state.get('ram_working_copy', {}).get('token') == record['token']:
                state['ram_working_copy'] = record
                state['process_stopped'] = True
                state['baseline_unchanged'] = True
                state['persisted'] = False
                state.pop('qa_stop_error', None)
                write_state(state)
        print(json.dumps({'qa_trial': record['token'], 'status': record['status'],
                          'baseline_unchanged': True, 'persisted': False,
                          'evidence_sha256': record.get('evidence_sha256')}, indent=2))


def archive_base(expected_packed_sha256):
    """Explicit, stopped-only base retirement; never starts a guest or creates a disk."""
    if not isinstance(expected_packed_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_packed_sha256):
        raise RuntimeError('A valid reviewed packed pointer SHA-256 is required')
    with exclusive_lab_lock():
        sources = harness_sources()

        def guard(stage=None):
            assert_harness_sources(sources)
            if trial.pending_journals(BUILD):
                raise RuntimeError('Retained QA trial blocks base archival')
            if storage.pending_journals(BUILD):
                raise RuntimeError('Unfinished raw RAM journals must be recovered before base archival')
            pending = packed.pending_journals(BUILD)
            if len(pending) > 1:
                raise RuntimeError('Multiple packed journals require explicit recovery review')
            state = json.loads(STATE.read_text()) if STATE.exists() else {}
            if state and state.get('owner') != 'win98-modern-isolated-install-v1':
                raise RuntimeError('Base archival requires known installation ownership')
            pid = state.get('pid')
            if pid is not None and (type(pid) is not int or pid <= 0 or Path(f'/proc/{pid}/cmdline').exists()):
                raise RuntimeError('Recorded guest PID is still present or cannot be verified')
            record = state.get('ram_working_copy')
            if pending:
                saved, _ = packed._json(pending[0])
                if record and any(record.get(key) != saved.get(key)
                                  for key in ('mode', 'original_disk', 'working_disk', 'directory')):
                    raise RuntimeError('Pending packed journal differs from the installation state')
                record = saved
            if record:
                if record.get('original_disk') != str(DISK):
                    raise RuntimeError('RAM state belongs to a different installation')
                backend = storage_backend(record)
                backend.locations(record)
                if backend is storage and record.get('status') != 'persisted':
                    raise RuntimeError('Raw RAM state is not durably persisted')
                if backend is packed and record.get('status') != 'persisted':
                    packed._generation(record, packed._target(record) if record.get('candidate') else None)
            assert_no_owned_processes(record or {'original_disk': str(DISK), 'working_disk': str(DISK)})
            pointer, checksum = packed._load_pointer(DISK)
            if pointer is None or checksum != expected_packed_sha256:
                raise RuntimeError('Current packed pointer differs from the reviewed candidate')

        guard()
        packed.current(DISK)
        value = base_archive.create(DISK, checkpoint=guard)
        guard()
        result = base_archive.retire_raw(DISK, checkpoint=guard)
        guard()
        receipt = {'schema': 'ntw.lab.base-archive-operation.v1', 'status': result['status'],
                   'original_disk': str(DISK), 'base': value,
                   'packed_pointer_sha256': expected_packed_sha256,
                   'harness_sources_sha256': sources, 'processes_absent': True}
        storage.durable_json(BUILD / 'archive-base-result.json', receipt)
        print(json.dumps(receipt, indent=2))
        return receipt


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
