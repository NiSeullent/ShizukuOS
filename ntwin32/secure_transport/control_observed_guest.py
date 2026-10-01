#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Control only the pinned TLS observer in an already owned canonical CSM run.

Adapted from tools/iewebkit_wtf_control.py's GUI request/ACK protocol. This
controller never starts or kills a VM, opens a live disk, or accepts TLS success.
The canonical runner alone handles its finish request. A reviewer must inspect
the supplied screenshot before each stage. Stopped-disk verification determines
the protocol and exact post-CRT child exit results separately.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

BOOT = Path('/root/Win98-Modern-boot')
RUNS = BOOT / 'build/shizukudos/csm'
MANIFEST = BOOT / 'build/secure-transport-7707/tls-observed-v5-crt/guest-files.json'
MANIFEST_SHA = '1097b2e9b239fc83f5a85c7731360cf0d544156638ca97b87c706238c82c2213'
NONCE = 'tls7707-20261001-crt-b483d962'
COMMAND = r'C:\GOPLAB\TLSWATCH.EXE --nonce ' + NONCE
INPUTS = {'C:\\GOPLAB\\' + name for name in (
    'TLS13PRB.EXE', 'SRV.PEM', 'SRV.KEY', 'CA.PEM', 'BADCA.PEM',
    'EXP.PEM', 'EXP.KEY', 'TLSWATCH.EXE')}
OUTPUTS = [r'C:\GOPLAB\TLS13.LOG', r'C:\GOPLAB\TLSOBS.LOG']
QEMU = Path('/usr/libexec/qemu-kvm')
ACK_STATUS = 'sent; application effect requires screenshot/readback verification'
MAX_JSON = 256 * 1024
MAX_IMAGE = 16 * 1024**2
OBSERVE_SECONDS = 105
BOOT_STATUS = 'BOOT_CONTROLS_ACKNOWLEDGED; NEXT_SCREEN_REVIEW_REQUIRED'
DESKTOP_STATUS = 'CONTROLS_ACKNOWLEDGED; STOPPED_TLS_EVIDENCE_NOT_REVIEWED'


def bounded_bytes(path: Path, limit: int) -> bytes:
    """Reject symlinks, foreign/multiply-linked files and unbounded reads."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or not 0 < info.st_size <= limit):
            raise ValueError('Expected a bounded privately owned regular file: ' + str(path))
        data = bytearray()
        while len(data) <= limit:
            part = os.read(fd, min(65536, limit + 1 - len(data)))
            if not part:
                break
            data.extend(part)
        after = os.fstat(fd)
        if (len(data) != info.st_size or len(data) > limit
                or (info.st_ino, info.st_dev, info.st_mtime_ns, info.st_size)
                != (after.st_ino, after.st_dev, after.st_mtime_ns, after.st_size)):
            raise ValueError('Bounded evidence changed during read')
        return bytes(data)
    finally:
        os.close(fd)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_json(path: Path) -> dict:
    value = json.loads(bounded_bytes(path, MAX_JSON))
    if not isinstance(value, dict):
        raise ValueError('Expected a JSON object')
    return value


def validate_manifest(path: Path, sha: str) -> dict:
    if path != MANIFEST or path.resolve(strict=True) != path or sha != MANIFEST_SHA:
        raise ValueError('Only the frozen observed-v5-crt manifest and digest are permitted')
    raw = bounded_bytes(path, MAX_JSON)
    if digest(raw) != sha:
        raise ValueError('Pinned TLS observer manifest changed')
    obj = json.loads(raw)
    rows = obj.get('inputs', [])
    if (obj.get('schema') != 1 or obj.get('kind') != 'isolated-guest-file-inputs'
            or obj.get('nonce') != NONCE or obj.get('command') != COMMAND
            or not isinstance(rows, list) or len(rows) != 8
            or any(not isinstance(row, dict) for row in rows)
            or {row.get('guest') for row in rows} != INPUTS
            or obj.get('outputs') != OUTPUTS or obj.get('backups') != []
            or obj.get('post_crt_exit_required') is not True
            or obj.get('network_required') is not False
            or obj.get('guest_execution') != 'NOT-VERIFIED'):
        raise ValueError('Expected the exact eight-input offline TLS observer fixture')
    # Every typed character must be supported by canonical CSM type_ascii.
    if any(not (c.isascii() and c.isalnum()) and c not in ' .\\:-/' for c in COMMAND):
        raise ValueError('Command contains a character unsupported by the canonical keyboard driver')
    for row in rows:
        source = Path(row['source'])
        if (source.parent != path.parent or source.resolve(strict=True) != source
                or source.name != row['guest'].rsplit('\\', 1)[1]
                or type(row.get('bytes')) is not int or not 0 < row['bytes'] <= 1024**2):
            raise ValueError('Pinned fixture source path or size differs')
        data = bounded_bytes(source, 1024**2)
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('Frozen TLS observer input changed')
    for row in obj.get('source_receipts', []):
        source = Path(row['path'])
        if source.parent != path.parent or source.resolve(strict=True) != source:
            raise ValueError('Source receipt belongs to another fixture')
        if digest(bounded_bytes(source, 1024**2)) != row['sha256']:
            raise ValueError('Frozen TLS observer source receipt changed')
    return obj


def validate_plan(run: Path, manifest: dict, path: Path, sha: str) -> str:
    plan_path = run / 'guest-files-plan.json'
    raw = bounded_bytes(plan_path, MAX_JSON)
    plan = json.loads(raw)
    rows = plan.get('inputs', [])
    if (plan.get('manifest') != str(path) or plan.get('manifest_sha256') != sha
            or plan.get('outputs') != OUTPUTS
            or plan.get('output_baseline') != 'all absent before private injection'
            or plan.get('backups') != [] or plan.get('installed_gop_replacement') != []
            or not isinstance(rows, list) or len(rows) != 8
            or any(not isinstance(row, dict) for row in rows)
            or {row.get('guest') for row in rows} != INPUTS):
        raise ValueError('Canonical injection plan differs or lacks fresh output absence')
    planned = {row['guest']: row for row in rows}
    for row in manifest['inputs']:
        got = planned[row['guest']]
        if (got.get('source') != row['source'] or got.get('bytes') != row['bytes']
                or got.get('sha256') != row['sha256']
                or got.get('private_copy_sha256') != row['sha256']):
            raise ValueError('Injected TLS fixture differs from the frozen input')
        private = run / ('prepared-guest-' + row['guest'].rsplit('\\', 1)[1])
        data = bounded_bytes(private, 1024**2)
        if len(data) != row['bytes'] or digest(data) != row['sha256']:
            raise ValueError('Stopped prelaunch input readback copy differs')
    return digest(raw)


def validate_run(run: Path) -> None:
    if (run.resolve(strict=True) != run or run.parent != RUNS
            or not re.fullmatch(r'run-win98-gop-tls-observed-v5-7707-20261001T[0-9]{4}(?:-[a-z0-9-]+)?', run.name)
            or run.stat().st_uid != os.geteuid()):
        raise ValueError('Expected this root-owned canonical TLS CSM trial directory')
    for name in ('windows-uefi.raw', 'OVMF_VARS.fd'):
        path = run / name
        info = path.lstat()
        if (path.resolve(strict=True) != path or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid() or info.st_nlink != 1):
            raise ValueError('Private disk/VARS identity is not independently owned')


def owned_qemu_args(argv: list[str], run: Path) -> bool:
    if len(argv) != 33 or argv[0] != str(QEMU):
        return False
    # The runner uses a separate disposable QMP directory, not run/qmp.sock.
    qmp = argv[31]
    if not re.fullmatch(r'unix:/tmp/shz-win98-uefi-[A-Za-z0-9_-]+/qmp\.sock,server=on,wait=off', qmp):
        return False
    expected = [
        str(QEMU), '-name', 'shz-disposable-win98-uefi',
        '-machine', 'q35,hpet=off', '-accel', 'kvm', '-cpu', 'qemu64',
        '-smp', '2', '-m', '128', '-nodefaults', '-nic', 'none',
        '-display', 'none', '-device', 'VGA',
        '-drive', 'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
        '-drive', f'if=pflash,unit=1,format=raw,file={run}/OVMF_VARS.fd',
        '-drive', f'file={run}/windows-uefi.raw,format=raw,if=none,id=win98',
        '-device', 'ide-hd,drive=win98,bus=ide.0,bootindex=1',
        '-serial', f'file:{run}/serial.log', '-qmp', qmp, '-no-reboot',
    ]
    return argv == expected


def process_token(pid: int, run: Path) -> str:
    if type(pid) is not int or pid < 2:
        raise ValueError('Expected a live owned QEMU PID')
    proc = Path('/proc') / str(pid)
    if proc.stat().st_uid != os.geteuid() or (proc / 'exe').resolve(strict=True) != QEMU.resolve(strict=True):
        raise ValueError('QEMU owner or executable is different')
    argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    if not owned_qemu_args(argv, run):
        raise ValueError('QEMU argv differs from this exact private no-NIC canonical trial')
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    if len(fields) <= 19 or fields[0] in {'Z', 'X'} or not fields[19].isdigit():
        raise ValueError('Owned QEMU has already exited or lacks a stable start identity')
    validate_run(run)
    return fields[19]


def screenshot(path: Path, run: Path) -> str:
    if (path.parent != run or path.resolve(strict=True) != path
            or not re.fullmatch(r'screen-[0-9]{3}\.png', path.name)):
        raise ValueError('Screenshot belongs to a different trial')
    data = bounded_bytes(path, MAX_IMAGE)
    if not data.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Expected the reviewed bounded native PNG screenshot')
    return digest(data)


def acknowledged_request(run: Path, request: dict) -> dict | None:
    control, receipt = run / 'gui-control.json', run / 'gui-control-receipt.json'
    if read_json(control) != request:
        raise ValueError('Another controller changed the exact pending request')
    if not receipt.exists():
        return None
    got = read_json(receipt)
    value = got.get('sequence')
    if type(value) is not int or value < 1 or value > request['sequence']:
        raise ValueError('Foreign or invalid GUI receipt sequence')
    if value != request['sequence']:
        return None
    if (got.get('name') != request['name']
            or got.get('keys') != request.get('keys', [])
            or got.get('typed') != request.get('text')
            or got.get('status') != ACK_STATUS or got.get('error') is not None):
        raise ValueError('ACK does not match the exact submitted request')
    path = Path(got.get('screenshot', ''))
    got['review_driver_screenshot_sha256'] = screenshot(path, run)
    if request.get('framebuffer_capture'):
        physical = path.with_name(path.stem + '-physical-framebuffer.bin')
        got['review_driver_physical_capture_sha256'] = digest(bounded_bytes(physical, MAX_IMAGE))
    return got


def atomic_json(path: Path, value: dict) -> None:
    raw = (json.dumps(value, indent=2) + '\n').encode()
    if len(raw) > MAX_JSON:
        raise ValueError('Control receipt exceeds its bounded size')
    temporary = path.with_name(path.name + '.tls7707-control.tmp')
    with temporary.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temporary, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        temporary.unlink(missing_ok=True)


def existing_queue(run: Path, record: dict) -> tuple[int, dict | None]:
    """Only an acknowledged boot stage of this controller may be resumed."""
    control, receipt = run / 'gui-control.json', run / 'gui-control-receipt.json'
    boot_record = run / 'tls-control-boot-warning.json'
    if not control.exists() and not receipt.exists() and not boot_record.exists():
        return 0, None
    if (record['reviewed_stage'] != 'desktop' or not control.exists()
            or not receipt.exists() or not boot_record.exists()):
        raise ValueError('Pending, foreign or repeated GUI stage already exists')
    prior = read_json(boot_record)
    for key in ('manifest', 'manifest_sha256', 'nonce', 'guest_plan_sha256',
                'control_source_sha256', 'qemu_pid', 'qemu_start_ticks'):
        if prior.get(key) != record.get(key):
            raise ValueError('Prior boot controls belong to a different fixture/process')
    actions = prior.get('actions', [])
    if prior.get('status') != BOOT_STATUS or len(actions) != 2:
        raise ValueError('Prior boot controls were incomplete')
    expected = [
        dict(sequence=1, name='tls7707-reviewed-boot-warning-enter', keys=[['ret']]),
        dict(sequence=2, name='tls7707-boot-warning-result-capture', framebuffer_capture=True),
    ]
    if [a.get('request') for a in actions] != expected:
        raise ValueError('Prior boot control requests differ')
    last = actions[-1]
    got = acknowledged_request(run, last['request'])
    if got is None or got != last.get('ack'):
        raise ValueError('Boot GUI request is pending or its exact ACK/image changed')
    return 2, last['request']


def drive(args, run: Path, record: dict, out: Path, token: str,
          sequence: int, previous: dict | None) -> int:
    with out.open('x') as stream:
        json.dump(record, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    deadline = time.monotonic() + (120 if args.stage == 'boot-warning' else 240)
    expected_current = previous

    def live() -> None:
        if time.monotonic() > deadline or process_token(args.qemu_pid, run) != token:
            raise ValueError('Owned guest ended, PID was reused or control deadline expired')
        control = run / 'gui-control.json'
        if expected_current is None:
            if control.exists() or (run / 'gui-control-receipt.json').exists():
                raise ValueError('Foreign GUI queue appeared')
        elif read_json(control) != expected_current:
            raise ValueError('Another controller changed the GUI request')

    def pause(seconds: float) -> None:
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            live()
            time.sleep(min(.2, max(0, until - time.monotonic())))

    def send(name: str, **values) -> None:
        nonlocal sequence, expected_current
        live()
        if expected_current is not None and acknowledged_request(run, expected_current) is None:
            raise ValueError('An existing GUI request is still pending')
        sequence += 1
        request = dict(sequence=sequence, name=name, **values)
        record['pending_request'] = request
        atomic_json(out, record)
        atomic_json(run / 'gui-control.json', request)
        expected_current = request
        until = time.monotonic() + 30
        while True:
            got = acknowledged_request(run, request)
            if got is not None:
                # A finish ACK may outlive QEMU; the owning runner stops it.
                if not request.get('finish'):
                    live()
                record['actions'].append(dict(request=request, ack=got))
                record.pop('pending_request')
                atomic_json(out, record)
                print(json.dumps({'sequence': sequence, 'action': name,
                                  'screenshot': got['screenshot'], 'tls_pass': False}), flush=True)
                return
            if time.monotonic() > until:
                raise ValueError('Canonical runner did not acknowledge this exact request')
            pause(.2)

    try:
        if args.stage == 'boot-warning':
            send('tls7707-reviewed-boot-warning-enter', keys=[['ret']])
            pause(45)
            send('tls7707-boot-warning-result-capture', framebuffer_capture=True)
            record['status'] = BOOT_STATUS
        else:
            send('tls7707-open-run-for-observer', keys=[['esc'], ['meta_l', 'r']])
            pause(2)
            send('tls7707-launch-pinned-observer', keys=[['ctrl', 'a']], text=COMMAND, enter=True)
            record['observer_wait_seconds'] = OBSERVE_SECONDS
            atomic_json(out, record)
            # Child deadline90s + guard reaping5s; give the observer105s before
            # asking the runner to stop. No live filesystem inspection occurs.
            for elapsed in range(0, OBSERVE_SECONDS, 15):
                pause(min(15, OBSERVE_SECONDS - elapsed))
                print(json.dumps({'stage': 'observer-wait', 'seconds': elapsed + 15,
                                  'tls_pass': False}), flush=True)
            send('tls7707-capture-and-finish-owned-trial', framebuffer_capture=True, finish=True)
            record['runner_finish_requested'] = True
            record['status'] = DESKTOP_STATUS
        return 0
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        record['status'], record['error'] = 'CONTROL_INTERRUPTED', str(error)
        return 1
    finally:
        atomic_json(out, record)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--qemu-pid', type=int, required=True)
    parser.add_argument('--reviewed-image', type=Path, required=True)
    parser.add_argument('--stage', choices=['boot-warning', 'desktop'], required=True,
                        help='Guest stage personally reviewed in the supplied image')
    args = parser.parse_args()
    run = args.run.absolute()
    validate_run(run)
    image = args.reviewed_image.absolute()
    image_sha = screenshot(image, run)
    manifest = validate_manifest(args.manifest.absolute(), args.manifest_sha256)
    plan_sha = validate_plan(run, manifest, MANIFEST, MANIFEST_SHA)
    token = process_token(args.qemu_pid, run)
    record = dict(schema='win98modern.tls-observed-owned-control.v1', status='RUNNING',
                  reviewed_stage=args.stage, reviewed_image=str(image), reviewed_image_sha256=image_sha,
                  manifest=str(MANIFEST), manifest_sha256=MANIFEST_SHA, nonce=NONCE,
                  command=COMMAND, guest_plan_sha256=plan_sha,
                  control_source_sha256=digest(Path(__file__).read_bytes()),
                  qemu_pid=args.qemu_pid, qemu_start_ticks=token, actions=[],
                  tls_pass=False, application_pass=False, process_exit_verified=False,
                  scope='Exact control ACKs only; stopped native protocol/child-exit evidence must be verified separately')
    out = run / ('tls-control-' + args.stage + '.json')
    lock_fd = os.open(run / 'tls-control-driver.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1):
            raise ValueError('TLS control lock is not independently owned')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if out.exists():
            raise ValueError('Preserve existing control evidence; do not rerun a stage')
        sequence, previous = existing_queue(run, record)
        if process_token(args.qemu_pid, run) != token:
            raise ValueError('QEMU start identity changed before the control lock')
        return drive(args, run, record, out, token, sequence, previous)


if __name__ == '__main__':
    raise SystemExit(main())
