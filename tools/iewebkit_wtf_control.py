#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Submit a bounded WTF observer trial to an already owned native guest.

This never starts or kills a process, reads a live disk, or accepts application
success. A human first reviews the supplied guest screenshot. The existing
native runner retains process ownership, timeout and allocation guards. Final
acceptance belongs to iewebkit_verify_wtf.py using stopped-disk evidence.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import time

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / 'build/shizukudos/iosys-uefi-port/runs'
QEMU = Path('/usr/libexec/qemu-kvm')
OBSERVER = r'C:\GOPLAB\WTFWAIT.EXE'
INPUTS = {r'C:\GOPLAB\WTFNAT.EXE', OBSERVER}
OUTPUTS = {r'C:\GOPLAB\WTFNAT.LOG', r'C:\GOPLAB\WTFEXIT.LOG'}
MAX_JSON = 256 * 1024


def read_json(path: Path) -> dict:
    raw = path.read_bytes()
    if len(raw) > MAX_JSON:
        raise ValueError('JSON evidence exceeds the bounded read limit')
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError('Expected a JSON object')
    return obj


def validate_manifest(path: Path, digest: str) -> tuple[dict, str]:
    raw = path.read_bytes()
    if len(raw) > MAX_JSON or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError('Frozen manifest hash or size mismatch')
    obj = json.loads(raw)
    nonce = obj.get('nonce')
    command = obj.get('command')
    if (not isinstance(nonce, str) or not re.fullmatch(r'83bd-wtf-[0-9a-f]{32}', nonce)
            or command != OBSERVER + ' ' + nonce):
        raise ValueError('Only the exact fresh WTFWAIT command is permitted')
    rows = obj.get('inputs', [])
    expected_outputs = [r'C:\GOPLAB\WTFNAT.LOG', r'C:\GOPLAB\WTFEXIT.LOG']
    diagnostic = obj.get('diagnostic_scope')
    if diagnostic is not None:
        if not isinstance(diagnostic, dict) or diagnostic.get('closed_checkpoint_handles') is not True:
            raise ValueError('Expected exact closed-checkpoint diagnostic scope')
        expected_outputs.insert(1, r'C:\GOPLAB\WTFABRT.LOG')
    if (len(rows) != 2 or {row.get('guest') for row in rows} != INPUTS
            or obj.get('outputs') != expected_outputs
            or obj.get('post_crt_exit_required') is not True
            or obj.get('requires_nic_absent') is not True
            or obj.get('requires_absent_guest_paths') is not True):
        raise ValueError('Expected exact fresh observer inputs and selected outputs')
    if obj.get('backups', []):
        raise ValueError('Guest backup mutation is outside this trial')
    validate_input_sources(path, obj)
    return obj, command


def validate_input_sources(manifest_path: Path, manifest: dict) -> None:
    """Fail before expensive boot preparation if a frozen PE escapes its package."""
    parent = manifest_path.resolve(strict=True).parent
    total = 0
    for row in manifest['inputs']:
        if (type(row.get('bytes')) is not int or not 0 < row['bytes'] <= 64 * 1024**2
                or not isinstance(row.get('source'), str)
                or not isinstance(row.get('sha256'), str)
                or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
            raise ValueError('Expected exact bounded frozen input identity')
        source = Path(row['source']).resolve(strict=True)
        total += row['bytes']
        if (not source.is_relative_to(parent) or not source.is_file()
                or source.stat().st_size != row['bytes'] or total > 64 * 1024**2):
            raise ValueError('Frozen input path or size differs from its manifest package')
        digest = hashlib.sha256()
        with source.open('rb') as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != row['sha256']:
            raise ValueError('Frozen input hash differs from its manifest package')


def owned_qemu_args(argv: list[str], run: Path) -> bool:
    if not argv or Path(argv[0]).name not in {'qemu-kvm', 'qemu-system-x86_64'}:
        return False
    if any(word in {'-net', '-netdev'} for word in argv):
        return False
    if any(word in {'-hda', '-hdb', '-hdc', '-hdd', '-fda', '-fdb', '-cdrom',
                    '-blockdev', '-readconfig', '-kernel', '-initrd', '-bios',
                    '-incoming', '-loadvm', '-boot'} for word in argv):
        return False
    nics = [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == '-nic']
    if nics != ['none'] or argv[-1] in {'-nic', '-device', '-drive'}:
        return False
    devices = [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == '-device']
    if sorted(devices) != ['VGA', 'ide-hd,drive=win98,bus=ide.0,bootindex=1']:
        return False
    drives = [argv[i + 1] for i, word in enumerate(argv[:-1]) if word == '-drive']
    expected = [
        'if=pflash,unit=0,format=raw,readonly=on,file=/usr/share/edk2/ovmf/OVMF_CODE.fd',
        f'if=pflash,unit=1,format=raw,file={run}/OVMF_VARS.fd',
        f'file={run}/windows-uefi.raw,format=raw,if=none,id=win98',
    ]
    return sorted(drives) == sorted(expected)


def process_token(pid: int, run: Path) -> str:
    proc = Path('/proc') / str(pid)
    if proc.stat().st_uid != os.geteuid() or (proc / 'exe').resolve() != QEMU.resolve():
        raise ValueError('QEMU owner or executable differs from the owned trial')
    argv = (proc / 'cmdline').read_bytes().rstrip(b'\0').decode().split('\0')
    if not owned_qemu_args(argv, run):
        raise ValueError('QEMU does not use this exact private disk with no NIC')
    # comm may contain spaces or parentheses; field 22 starts after the last ).
    fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
    if fields[0] == 'Z':
        raise ValueError('Owned QEMU has already exited')
    return fields[19]


def queue_sequence(run: Path) -> int:
    control, receipt = run / 'gui-control.json', run / 'gui-control-receipt.json'
    if not control.exists() and not receipt.exists():
        return 0
    if not control.exists() or not receipt.exists():
        raise ValueError('An unacknowledged GUI request is already pending')
    a, b = read_json(control), read_json(receipt)
    value = b.get('sequence')
    if (type(value) is not int or value < 1 or type(a.get('sequence')) is not int
            or a.get('sequence') != value
            or b.get('status') != 'sent; application effect requires screenshot/readback verification'):
        raise ValueError('Existing GUI queue has not completed successfully')
    return value


def atomic_json(path: Path, value: dict) -> None:
    raw = (json.dumps(value, indent=2) + '\n').encode()
    if len(raw) > MAX_JSON:
        raise ValueError('Control evidence exceeded its byte budget')
    temp = path.with_name(path.name + '.wtf-control.tmp')
    with temp.open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def acknowledged_request(run: Path, request: dict) -> dict | None:
    receipt = run / 'gui-control-receipt.json'
    if not receipt.exists():
        return None
    got = read_json(receipt)
    if got.get('sequence') != request['sequence']:
        return None
    if (type(got.get('sequence')) is not int
            or read_json(run / 'gui-control.json') != request
            or got.get('name') != request['name']
            or got.get('keys') != request.get('keys', [])
            or got.get('typed') != request.get('text')
            or got.get('status') != 'sent; application effect requires screenshot/readback verification'):
        raise ValueError('Acknowledgement does not belong to the exact submitted request')
    path = Path(got.get('screenshot', '')).resolve(strict=True)
    if path.parent != run or not re.fullmatch(r'screen-[0-9]{3}\.png', path.name):
        raise ValueError('Control screenshot belongs to a different run')
    data = path.read_bytes()
    if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) > 16 * 1024**2:
        raise ValueError('Control screenshot is not a bounded native PNG')
    got['review_driver_screenshot_sha256'] = hashlib.sha256(data).hexdigest()
    if request.get('framebuffer_capture'):
        physical = path.with_name(path.stem + '-physical-framebuffer.bin')
        if not 0 < physical.stat().st_size <= 16 * 1024**2:
            raise ValueError('Requested physical framebuffer capture is missing or oversized')
        got['review_driver_physical_capture_sha256'] = hashlib.sha256(physical.read_bytes()).hexdigest()
    return got


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--run', required=True, type=Path)
    ap.add_argument('--manifest', required=True, type=Path)
    ap.add_argument('--manifest-sha256', required=True)
    ap.add_argument('--qemu-pid', required=True, type=int)
    ap.add_argument('--reviewed-image', required=True, type=Path)
    ap.add_argument('--stage', choices=['boot-warning', 'welcome', 'desktop', 'run-dialog', 'diagnostic'], required=True,
                    help='Guest stage personally reviewed in the supplied screenshot')
    ap.add_argument('--action', choices=['capture', 'dismiss-runtime-dialog', 'finish'],
                    help='One separately reviewed diagnostic action; requires --stage diagnostic')
    ap.add_argument('--launch-only', action='store_true',
                    help='Compatibility option; desktop launch always returns for visual review')
    args = ap.parse_args()
    if (args.stage == 'diagnostic') != (args.action is not None):
        ap.error('A diagnostic stage requires one explicit action; other stages cannot use --action')
    run = args.run.resolve(strict=True)
    if (run.parent != RUNS or not re.fullmatch(r'win98-iosys-gop-wtf-[a-z0-9-]+-83bd-[a-z0-9]+', run.name)
            or args.qemu_pid < 2):
        raise ValueError('Expected one root-owned WTF trial directory and PID')
    image = args.reviewed_image.resolve(strict=True)
    if image.parent != run or not re.fullmatch(r'screen-[0-9]{3}\.png', image.name):
        raise ValueError('Reviewed screenshot must belong to this exact guest')
    image_bytes = image.read_bytes()
    if len(image_bytes) > 16 * 1024**2 or not image_bytes.startswith(b'\x89PNG\r\n\x1a\n'):
        raise ValueError('Expected a bounded native PNG screenshot')
    manifest, command = validate_manifest(args.manifest.resolve(strict=True), args.manifest_sha256)
    plan_path = run / 'guest-files-plan.json'
    plan = read_json(plan_path)
    if (plan.get('manifest') != str(args.manifest.resolve())
            or plan.get('manifest_sha256') != args.manifest_sha256
            or plan.get('outputs') != manifest['outputs']):
        raise ValueError('Requested manifest differs from the actual injected plan')
    planned = {row['guest']: row for row in plan.get('inputs', [])}
    if len(plan.get('inputs', [])) != 2 or set(planned) != INPUTS:
        raise ValueError('Native guest inputs differ from the requested fixture')
    for row in manifest['inputs']:
        got = planned[row['guest']]
        if (got.get('sha256') != row['sha256']
                or got.get('private_copy_sha256') != row['sha256']
                or got.get('bytes') != row['bytes']):
            raise ValueError('Injected PE does not match its frozen source')
    token = process_token(args.qemu_pid, run)
    sequence = queue_sequence(run)
    out = run / f'wtf-control-driver-{sequence + 1:03d}.json'
    record = dict(schema='win98modern.wtf-owned-control.v1', status='RUNNING',
                  reviewed_stage=args.stage, reviewed_image=str(image),
                  reviewed_image_sha256=hashlib.sha256(image_bytes).hexdigest(),
                  manifest=str(args.manifest.resolve()), manifest_sha256=args.manifest_sha256,
                  guest_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
                  control_source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  qemu_pid=args.qemu_pid, qemu_start_ticks=token, actions=[],
                  application_pass=False,
                  scope='Control acknowledgements only; stopped native logs and process exit determine acceptance')
    lock_fd = os.open(run / 'wtf-control-driver.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'r+b') as lock:
        info = os.fstat(lock.fileno())
        if info.st_uid != os.geteuid() or info.st_nlink != 1:
            raise ValueError('Controller lock is not privately owned')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return drive(args, run, command, record, out, token, sequence)


def drive(args, run: Path, command: str, record: dict, out: Path,
          token: str, sequence: int) -> int:
    with out.open('x') as stream:
        json.dump(record, stream, indent=2)
    deadline = time.monotonic() + 240

    def live() -> None:
        if time.monotonic() > deadline or process_token(args.qemu_pid, run) != token:
            raise ValueError('Owned trial ended or exceeded the control deadline')

    def pause(seconds: float) -> None:
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            live()
            time.sleep(min(.2, max(0, until - time.monotonic())))

    def send(name: str, **request) -> None:
        nonlocal sequence
        live()
        if queue_sequence(run) != sequence:
            raise ValueError('Another controller changed the GUI queue')
        sequence += 1
        submitted = dict(sequence=sequence, name=name, **request)
        atomic_json(run / 'gui-control.json', submitted)
        until = time.monotonic() + 30
        while True:
            got = acknowledged_request(run, submitted)
            if got is not None:
                record['actions'].append(got)
                atomic_json(out, record)
                print(json.dumps({'sequence': sequence, 'action': name}), flush=True)
                return
            if time.monotonic() > until:
                raise ValueError('Native runner did not acknowledge the request')
            pause(.2)

    try:
        if args.stage == 'boot-warning':
            send('ack-reviewed-boot-warning', keys=[['ret']])
            record['status'] = 'WARNING_ACKNOWLEDGED; REVIEW_DESKTOP_BEFORE_LAUNCH'
            return 0
        if args.stage == 'welcome':
            send('close-reviewed-baseline-welcome', keys=[['alt', 'f4']])
            record['status'] = 'WELCOME_CLOSED; REVIEW_DESKTOP_BEFORE_LAUNCH'
            return 0
        if args.stage == 'diagnostic':
            if args.action == 'dismiss-runtime-dialog':
                send('dismiss-reviewed-owned-runtime-dialog', keys=[['ret']])
            else:
                request = dict(framebuffer_capture=True)
                if args.action == 'finish':
                    request['finish'] = True
                send(args.action + '-reviewed-owned-wtf-trial', **request)
            record['status'] = 'DIAGNOSTIC_CONTROL_ACKNOWLEDGED; STOPPED_EVIDENCE_REQUIRED'
            return 0
        if args.stage == 'desktop':
            send('open-run-for-wtf-observer', keys=[['meta_l', 'r']])
            record['status'] = 'RUN_REQUESTED; REVIEW_RUN_DIALOG_BEFORE_LAUNCH'
            return 0
        send('launch-exact-frozen-wtf-observer', keys=[['ctrl', 'a']], text=command, enter=True)
        record['status'] = 'LAUNCH_ACKNOWLEDGED; REVIEW_NATIVE_OUTCOME_BEFORE_FINISH'
        return 0
    except (OSError, ValueError) as error:
        record['status'], record['error'] = 'CONTROL_INTERRUPTED', str(error)
        return 1
    finally:
        atomic_json(out, record)


if __name__ == '__main__':
    raise SystemExit(main())
