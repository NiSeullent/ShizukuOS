"""Finish only this root-owned VM after its actual observer deadline and margin."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import time

RUN = Path('/root/Win98-Modern-boot/build/shizukudos/csm/run-win98-gop-tls13-i486-5abe-native-v1')
OUT = Path('/root/Win98-Modern-theme-tls-5abe/build/tls13-i486-native-launch-v1')
IMAGE = str(RUN / 'windows-uefi.raw')
deadline = time.monotonic() + 2400
identity = None
launch_receipt_raw = None
launch_receipt_monotonic = None

def own_identity():
    matches = []
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            if not (proc / 'comm').read_text().strip().startswith('qemu'):
                continue
            targets = set()
            for fd in (proc / 'fd').iterdir():
                try:
                    targets.add(os.readlink(fd))
                except (FileNotFoundError, PermissionError, ProcessLookupError):
                    pass
            if IMAGE in targets:
                fields = (proc / 'stat').read_text().rsplit(')', 1)[1].split()
                matches.append((int(proc.name), int(fields[19])))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    if len(matches) > 1:
        raise RuntimeError('Ambiguous own image descriptors')
    return matches[0] if matches else None

def write_once(path, value):
    with path.open('x') as stream:
        stream.write(json.dumps(value, indent=2) + '\n')

while time.monotonic() < deadline:
    observed = own_identity()
    if identity is None and observed is not None:
        identity = observed
        write_once(OUT / 'watcher-owned-vm.json', dict(
            actual_pid=identity[0], actual_start_ticks=identity[1],
            actual_open_image=IMAGE, native_component_acceptance=False,
            source_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()))
    if identity is not None and observed != identity:
        raise RuntimeError('Own VM stopped or identity changed before finish')
    receipt = RUN / 'gui-control-receipt.json'
    if identity is not None and receipt.exists():
        raw = receipt.read_bytes()
        data = json.loads(raw)
        if (data.get('sequence') == 4 and
                data.get('typed') == 'C:\\GOPLAB\\T13RUN.EXE' and
                data.get('status') == 'sent; application effect requires screenshot/readback verification'):
            if launch_receipt_raw is None:
                if own_identity() != identity:
                    raise RuntimeError('Own identity drift before launch-receipt preservation')
                with (OUT / 'actual-observer-launch-receipt.json').open('xb') as stream:
                    stream.write(raw)
                launch_receipt_raw = raw
                launch_receipt_monotonic = time.monotonic()
            elif launch_receipt_raw != raw:
                raise RuntimeError('Actual observer launch receipt generation changed')
            sent = datetime.datetime.fromisoformat(data['utc'].replace('Z', '+00:00'))
            now = datetime.datetime.now(datetime.timezone.utc)
            elapsed = (now - sent).total_seconds()
            elapsed_monotonic = time.monotonic() - launch_receipt_monotonic
            if elapsed_monotonic >= 140:
                control = RUN / 'gui-control.json'
                current = json.loads(control.read_bytes())
                if current.get('sequence') != 4 or current.get('text') != data['typed']:
                    raise RuntimeError('Own control changed before guarded finish')
                if own_identity() != identity or receipt.read_bytes() != raw:
                    raise RuntimeError('Own process or observer receipt changed')
                action = dict(sequence=5, name='finish owned corrected TLS v1 after actual observer deadline and margin', finish=True)
                tmp = RUN / 'gui-control.5abe-finish.tmp'
                with tmp.open('x') as stream:
                    stream.write(json.dumps(action) + '\n')
                os.replace(tmp, control)
                write_once(OUT / 'finish-request.json', dict(
                    utc=now.isoformat(), actual_pid=identity[0], actual_start_ticks=identity[1],
                    actual_open_image=IMAGE, actual_observer_launch_receipt_sha256=hashlib.sha256(raw).hexdigest(),
                    saved_actual_observer_launch_receipt=str(OUT / 'actual-observer-launch-receipt.json'),
                    wall_clock_elapsed_since_action_utc_seconds=elapsed,
                    monotonic_elapsed_since_completed_launch_receipt_observation_seconds=elapsed_monotonic,
                    required_observer_ms=120000, required_reap_ms=5000, extra_margin_ms=15000,
                    action=action, native_component_acceptance=False, peer_control=False))
                print(json.dumps(dict(status='OWNED_FINISH_REQUEST_SENT', elapsed_monotonic_seconds=elapsed_monotonic)), flush=True)
                break
    time.sleep(1)
else:
    raise RuntimeError('Owned finish watcher bound reached without a valid launched observer')
