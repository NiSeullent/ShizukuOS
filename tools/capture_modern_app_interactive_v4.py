#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Observe a publisher app and accept bounded, explicitly reviewed keys.

Uses the fixed application commands and content-verified package-image builder
from run_k64_productivity. This observation never constitutes an application
functionality pass or an installed Windows98 pass. No host service or guest
credential is configured. Disk writes remain in QEMU's temporary snapshot.
Only root-reviewed screenshot-bound requests may send one allowlisted key.
Screenshots prove captured bytes, not an unchanged live framebuffer or usable
Discord/Steam. No text, credentials, arbitrary QMP or automatic UI choices.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PINS = {
    'tools/capture_modern_app.py': 'e0a8ded19d526274eee96a5b710ed9bf3155ce93b4511122999d961e2cb84194',
    'shizukudos/tests/run_k64_steam.py': '1f2866c220a3c923e9775a0056a32498e126ae773af4ddcde1c4856185b22b2b',
    'shizukudos/tests/run_k64_productivity.py': '7e18c6e52005ef3784ded4551379708e8a0b1686801e82751fd22da50dfba275',
    'shizukudos/tests/run_k64_electron.py': '7364c1788807abb55bce86a95e1fd63af8a3ef07420e1caf625e025928d6be2a',
    'shizukudos/tools/qemu.py': 'aac9c9aed1e975eac1e1a7f7952818ba3804149c55675e2748e27120d72a2bb4',
    'shizukudos/tools/shzlib.py': 'bcbe177f38f327989b7815d55eaa3046bd8b5e8255753edf072bdf4f0bdb2329'}
# Validate the unchanged provider sources before importing their code.
for source_name, source_sha in SOURCE_PINS.items():
    with (ROOT/source_name).open('rb') as source_stream:
        if hashlib.file_digest(source_stream, 'sha256').hexdigest() != source_sha:
            raise RuntimeError('Frozen publisher capture provider changed: ' + source_name)
sys.path.insert(0, str(ROOT/'shizukudos/tests'))
import run_k64_steam as steam
productivity = steam.runner
runner = productivity.runner


class QMP:
    def __init__(self, path, owner_pid):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        try:
            self.socket.connect(str(path))
            self.peer_pid, _, _ = struct.unpack('3i', self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if self.peer_pid != owner_pid:
                raise ValueError('QMP peer is not the retained owned QEMU process')
            self.stream = self.socket.makefile('rwb')
            greeting_raw = self.stream.readline(65537)
            if len(greeting_raw) > 65536: raise ValueError('QMP greeting exceeds bound')
            greeting = json.loads(greeting_raw)
            if 'QMP' not in greeting:
                raise ValueError('missing QMP greeting')
            self.greeting = greeting
            self.sequence = 0
            self.command('qmp_capabilities')
        except BaseException:
            if hasattr(self, 'stream'):
                try: self.stream.close()
                except OSError: pass
            self.socket.close()
            raise

    def command(self, name, arguments=None):
        self.sequence += 1
        message = {'execute': name, 'id': self.sequence}
        if arguments is not None:
            message['arguments'] = arguments
        self.stream.write((json.dumps(message)+'\n').encode())
        self.stream.flush()
        deadline = time.monotonic()+3
        while True:
            remaining = deadline-time.monotonic()
            if remaining <= 0: raise TimeoutError('QMP response deadline expired')
            self.socket.settimeout(remaining)
            line = self.stream.readline(65537)
            if len(line) > 65536: raise ValueError('QMP response exceeds bound')
            if not line:
                raise ConnectionError('QMP connection ended')
            response = json.loads(line)
            if response.get('id') == self.sequence:
                if 'error' in response:
                    raise RuntimeError(json.dumps(response['error']))
                return response['return']

    def close(self):
        try: self.stream.close()
        finally: self.socket.close()


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


QCODES = ('tab', 'ret', 'spc', 'esc', 'up', 'down', 'left', 'right')
CONTROL_SCHEMA = 'win98modern.publisher-reviewed-key.v1'


def atomic_json(path, data, new=False, temporary_directory=None):
    fd, name = tempfile.mkstemp(prefix='.interactive-', dir=temporary_directory or path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        if new:
            os.link(name, path)
        else:
            os.replace(name, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(parent)
        finally: os.close(parent)
    finally:
        Path(name).unlink(missing_ok=True)


def read_regular_bytes(path, maximum):
    if not path.is_absolute() or path.parent != path.parent.resolve(strict=True):
        raise ValueError('Evidence path is not canonical')
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 1 <= before.st_size <= maximum:
            raise ValueError('Evidence is not a bounded regular file')
        raw = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd); current = os.stat(path, follow_symlinks=False)
        key = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if len(raw) != before.st_size or key(before) != key(after) or key(after) != key(current):
            raise ValueError('Evidence inode/bytes changed while reading')
        return raw
    finally:
        os.close(fd)


def strict_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ValueError('Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def verify_png(raw):
    from PIL import Image
    try:
        with Image.open(io.BytesIO(raw)) as picture:
            width, height = picture.size
            if picture.format != 'PNG' or not 1 <= width <= 8192 or not 1 <= height <= 8192 or width*height > 33554432:
                raise ValueError('Producer PNG dimensions/format exceed bounds')
            picture.verify()
        with Image.open(io.BytesIO(raw)) as picture:
            picture.load()
        return [width, height]
    except Exception as error:
        raise ValueError('Producer PNG could not be fully verified/decoded: '+str(error)) from error


def guest_identity(pid):
    root = Path('/proc')/str(pid)
    def proc_stat():
        raw = (root/'stat').read_text(); close = raw.rfind(')'); fields = raw[close+2:].split()
        if close < 0 or int(raw[:raw.find(' ')]) != pid or fields[0] == 'Z':
            raise ValueError('Owned guest is absent or exited')
        return int(fields[19]), int(fields[1]), int(fields[3])
    before = proc_stat(); executable = (root/'exe').stat()
    argv = [v.decode('utf-8', errors='surrogateescape') for v in (root/'cmdline').read_bytes().split(b'\0') if v]
    if before != proc_stat(): raise ValueError('Guest PID/start identity changed during read')
    return {'pid': pid, 'start': before[0], 'ppid': before[1], 'session': before[2], 'argv': argv,
            'exe_device': executable.st_dev, 'exe_inode': executable.st_ino}


def capture_owned_guest(proc, command):
    fd = os.pidfd_open(proc.pid, 0)
    try:
        first, second = guest_identity(proc.pid), guest_identity(proc.pid)
        exe = Path(command[0]).stat()
        if (proc.poll() is not None or first != second or first['argv'] != command or first['ppid'] != os.getpid()
                or first['session'] != proc.pid or (first['exe_device'], first['exe_inode']) != (exe.st_dev, exe.st_ino)):
            checks = {'child_running': proc.poll() is None, 'two_identity_reads_equal': first == second,
                      'argv_equal': first['argv'] == command, 'ppid_equal': first['ppid'] == os.getpid(),
                      'session_equal': first['session'] == proc.pid,
                      'executable_equal': (first['exe_device'], first['exe_inode']) == (exe.st_dev, exe.st_ino)}
            # Explain a rejected owned launch without weakening its exact gate.
            raise ValueError('Actual child differs from owned QEMU command: '+json.dumps(checks, sort_keys=True))
        return {'identity': first, 'pidfd': fd}
    except BaseException:
        os.close(fd); raise


def require_owned_guest(proc, owned, qmp=None):
    if proc.poll() is not None: raise ValueError('Owned guest exited before GUI operation')
    first, second = guest_identity(proc.pid), guest_identity(proc.pid)
    if first != owned['identity'] or second != first or (qmp is not None and qmp.peer_pid != proc.pid):
        raise ValueError('Owned guest/QMP identity changed before GUI operation')
    return first


class ReviewedControls:
    def __init__(self, out, app, proc, owned, nonce, clock=time.monotonic, pause=time.sleep):
        self.out, self.app, self.proc, self.owned, self.nonce = out, app, proc, owned, nonce
        self.clock, self.pause = clock, pause
        self.started = clock(); self.sequence = 0; self.reviewed_number = 0
        self.receipt_sha = None; self.disabled = False; self.pending = False
        self.requests = {}; self.captures = []; self.receipts = []; self.errors = []
        (out/'controls').mkdir(mode=0o700); (out/'control-receipts').mkdir(mode=0o700)
        self.save()

    def save(self):
        atomic_json(self.out/'interactive-state.json', {'schema': 'win98modern.publisher-interactive-state.v1',
            'app': self.app, 'run_nonce': self.nonce, 'owned_qemu': self.owned['identity'],
            'control_status': 'DISABLED' if self.disabled else 'PENDING' if self.pending else 'READY',
            'last_sequence': self.sequence, 'last_reviewed_capture_number': self.reviewed_number,
            'last_control_receipt_sha256': self.receipt_sha, 'captures': self.captures,
            'control_receipts': self.receipts, 'control_errors': self.errors,
            'allowed_qcodes': list(QCODES), 'max_sequences': 32, 'hold_time_ms': 80,
            'app_functionality_verified': False, 'windows98_execution_verified': False})

    def capture(self, qmp, origin='periodic'):
        require_owned_guest(self.proc, self.owned, qmp)
        number = len(self.captures) + 1
        if number > 784: raise ValueError('Capture count exceeded fixed bound')
        path = self.out/f'screen-{number:04d}.png'
        if path.exists() or path.is_symlink(): raise ValueError('Capture filename already exists')
        status = qmp.command('query-status')
        qmp.command('screendump', {'filename': str(path), 'format': 'png'})
        raw = read_regular_bytes(path, 32*1024*1024)
        if raw[:8] != b'\x89PNG\r\n\x1a\n': raise ValueError('Actual producer did not return PNG bytes')
        dimensions = verify_png(raw)
        value = {'number': number, 'seconds': round(self.clock()-self.started, 3), 'path': str(path),
            'basename': path.name, 'sha256': hashlib.sha256(raw).hexdigest(), 'generation': self.sequence,
            'origin': origin, 'vm_status': status, 'dimensions': dimensions, 'png_fully_decoded': True}
        self.captures.append(value); self.save()
        print('Real guest screen:', path, flush=True)
        return value

    def validate(self, request):
        keys = {'schema', 'sequence', 'app', 'run_nonce', 'owned_qemu_pid', 'owned_qemu_start',
                'reviewed_capture', 'reviewed_capture_sha256', 'prior_control_receipt_sha256', 'qcode'}
        if not isinstance(request, dict) or set(request) != keys:
            raise ValueError('Control object differs from the exact schema')
        sequence = request['sequence']
        if (type(sequence) is not int or not 1 <= sequence <= 32 or sequence != self.sequence + 1
                or request['schema'] != CONTROL_SCHEMA or request['app'] != self.app or request['run_nonce'] != self.nonce
                or type(request['owned_qemu_pid']) is not int or request['owned_qemu_pid'] != self.owned['identity']['pid']
                or type(request['owned_qemu_start']) is not int or request['owned_qemu_start'] != self.owned['identity']['start']
                or request['qcode'] not in QCODES or type(request['qcode']) is not str):
            raise ValueError('Control sequence/app/nonce/owned PID/key differs')
        name, digest = request['reviewed_capture'], request['reviewed_capture_sha256']
        if type(name) is not str or not re.fullmatch(r'screen-[0-9]{4}\.png', name) or type(digest) is not str or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise ValueError('Control lacks an exact actual capture basename/hash')
        if request['prior_control_receipt_sha256'] != self.receipt_sha:
            raise ValueError('Control prior receipt linkage differs')
        capture = next((c for c in self.captures if c['basename'] == name), None)
        if (capture is None or capture['generation'] != self.sequence or capture['number'] <= self.reviewed_number
                or capture['sha256'] != digest):
            raise ValueError('Capture was not produced in the current action generation')
        if self.sequence:
            prior = read_regular_bytes(self.out/'control-receipts'/f'{self.sequence:04d}.json', 65536)
            if hashlib.sha256(prior).hexdigest() != self.receipt_sha:
                raise ValueError('Actual completed prior control receipt changed')
        raw = read_regular_bytes(self.out/name, 32*1024*1024)
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError('Reviewed actual capture bytes changed')
        return capture

    def poll(self, qmp):
        if self.disabled or self.pending: return
        path = None; receipt = None; attempted = False
        try:
            directory = self.out/'controls'
            if directory.is_symlink() or directory.resolve(strict=True) != directory: raise ValueError('Control directory changed')
            entries = list(directory.iterdir())
            if len(entries) > 32: raise ValueError('Too many control files')
            numbers = {}
            for entry in entries:
                if not re.fullmatch(r'(?:000[1-9]|00[12][0-9]|003[0-2])\.json', entry.name): raise ValueError('Unexpected control filename')
                number = int(entry.stem); numbers[number] = entry
                if number <= self.sequence:
                    raw = read_regular_bytes(entry, 8192)
                    if hashlib.sha256(raw).hexdigest() != self.requests.get(number): raise ValueError('Consumed control request changed/replayed')
            if not numbers or max(numbers) <= self.sequence: return
            number = self.sequence + 1
            if number not in numbers: raise ValueError('Control sequence has a gap')
            path = numbers[number]; raw = read_regular_bytes(path, 8192); request = strict_json(raw)
            capture = self.validate(request)
            require_owned_guest(self.proc, self.owned, qmp)
            self.pending = True; self.sequence = number; self.reviewed_number = capture['number']
            self.requests[number] = hashlib.sha256(raw).hexdigest()
            action = {'execute': 'send-key', 'arguments': {'keys': [{'type': 'qcode', 'data': request['qcode']}], 'hold-time': 80}}
            receipt = {'schema': 'win98modern.publisher-reviewed-key-receipt.v1', 'sequence': number,
                'status': 'ACCEPTED_PENDING_NOT_SENT', 'request': request, 'request_sha256': self.requests[number],
                'reviewed_capture': capture, 'owned_qemu': self.owned['identity'], 'qmp_peer_pid': qmp.peer_pid,
                'action': action, 'app_functionality_verified': False}
            receipt_path = self.out/'control-receipts'/f'{number:04d}.json'
            atomic_json(receipt_path, receipt, new=True); self.save()
            receipt['before_live_capture'] = self.capture(qmp, 'before-control')
            # A changed reviewed image or process must still stop before dispatch.
            if hashlib.sha256(read_regular_bytes(self.out/request['reviewed_capture'], 32*1024*1024)).hexdigest() != request['reviewed_capture_sha256']:
                raise ValueError('Reviewed actual capture changed before dispatch')
            require_owned_guest(self.proc, self.owned, qmp)
            receipt['status'] = 'DISPATCH_ATTEMPTED_NO_RETRY'; atomic_json(receipt_path, receipt)
            attempted = True
            receipt['qmp_reply'] = qmp.command(action['execute'], action['arguments'])
            receipt['status'] = 'KEY_ACKNOWLEDGED_CAPTURE_PENDING'; atomic_json(receipt_path, receipt)
            self.pause(.12)
            receipt['after_capture'] = self.capture(qmp, 'after-control')
            receipt['status'] = 'KEY_ACKNOWLEDGED_AND_CAPTURED'; atomic_json(receipt_path, receipt)
            self.receipt_sha = sha256(receipt_path); self.receipts.append({'sequence': number, 'path': str(receipt_path), 'sha256': self.receipt_sha})
            self.pending = False; self.save()
        except (OSError, RuntimeError, ValueError, TypeError) as error:
            self.disabled = True; self.pending = False
            if receipt is not None:
                receipt['status'] = 'INDETERMINATE_AFTER_DISPATCH_NO_RETRY' if attempted else 'REJECTED_BEFORE_DISPATCH_NO_RETRY'
                receipt['error'] = str(error)
                atomic_json(self.out/'control-receipts'/f'{self.sequence:04d}.json', receipt)
            self.errors.append({'path': str(path) if path else None, 'error': str(error), 'dispatch_attempted': attempted})
            self.save()


def submit_control(out, sequence, qcode, reviewed):
    if out != out.resolve(strict=True) or out.is_symlink() or not out.is_relative_to((ROOT/'build/modern-apps').resolve(strict=True)):
        raise ValueError('Control output is not the canonical PRIVATE observation')
    state = strict_json(read_regular_bytes(out/'interactive-state.json', 1024*1024))
    if state.get('schema') != 'win98modern.publisher-interactive-state.v1' or state.get('control_status') != 'READY':
        raise ValueError('Observation is not ready for a reviewed control')
    if type(sequence) is not int or not 1 <= sequence <= 32 or sequence != state['last_sequence'] + 1 or qcode not in QCODES:
        raise ValueError('Sequence/key is outside the ready control scope')
    if reviewed.parent != out or reviewed != reviewed.absolute(): raise ValueError('Reviewed screenshot must be in this exact run')
    capture = next((c for c in state['captures'] if c['basename'] == reviewed.name), None)
    digest = hashlib.sha256(read_regular_bytes(reviewed, 32*1024*1024)).hexdigest()
    if not capture or capture['generation'] != state['last_sequence'] or capture['number'] <= state['last_reviewed_capture_number'] or capture['sha256'] != digest:
        raise ValueError('Selected actual screenshot is stale or changed')
    directory = out/'controls'
    if directory.is_symlink() or directory.resolve(strict=True) != directory: raise ValueError('Control directory changed')
    request = {'schema': CONTROL_SCHEMA, 'sequence': sequence, 'app': state['app'], 'run_nonce': state['run_nonce'],
        'owned_qemu_pid': state['owned_qemu']['pid'], 'owned_qemu_start': state['owned_qemu']['start'],
        'reviewed_capture': reviewed.name, 'reviewed_capture_sha256': digest,
        'prior_control_receipt_sha256': state['last_control_receipt_sha256'], 'qcode': qcode}
    atomic_json(directory/f'{sequence:04d}.json', request, new=True, temporary_directory=out)
    print('Reviewed control queued; dispatch requires the owned live guest:', sequence, flush=True)


def validate_durations(seconds, guest_timeout, capture_every):
    if (any(type(n) is not int for n in (seconds, guest_timeout, capture_every))
            or not 10 <= seconds <= 3600 or not 5 <= guest_timeout < seconds or not 5 <= capture_every <= 120):
        raise ValueError('Observation duration or capture interval is out of bounds')


def public_root_bootstrap(runtime_directory):
    """Require the exact copied OS trust payload recorded by its own builder."""
    receipt_path = runtime_directory/'receipt.json'
    receipt_bytes = receipt_path.read_bytes()
    proof = json.loads(receipt_bytes)
    archive = runtime_directory/'WIN64.IMG'
    raw = archive.read_bytes()
    archive_sha256 = hashlib.sha256(raw).hexdigest()
    if proof.get('status') != 'NATIVE_BUILD_PASS_GUEST_PENDING' or proof.get('host_trust_modified') is not False or \
       proof.get('tls_verification_disabled') is not False or archive_sha256 != proof['archive_sha256']:
        raise ValueError('exact isolated public trust runtime receipt required')
    if len(raw) < 16 or raw[:8] != b'SHZARC01':
        raise ValueError('invalid public trust archive')
    count = struct.unpack_from('<I', raw, 8)[0]
    header = 16+count*136
    if header > len(raw):
        raise ValueError('truncated public trust archive')
    files, spans = {}, []
    for index in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16+index*136)
        name = name.split(b'\0', 1)[0].decode('ascii').casefold()
        if name in files or offset < header or offset+size > len(raw):
            raise ValueError('invalid public trust archive entry')
        files[name] = raw[offset:offset+size]
        spans.append((offset, offset+size))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError('overlapping public trust archive')
    expected = {'\\shz\\tests\\t_runtime_roots.exe', '\\shz\\certs\\roots.bin',
                *('\\shz\\certs\\server'+str(i)+'.cer' for i in range(3))}
    additions = {name.casefold(): digest for name, digest in proof['additions'].items()}
    if set(additions) != expected or any(hashlib.sha256(files.get(name, b'')).hexdigest() != digest
                                         for name, digest in additions.items()):
        raise ValueError('public trust payload differs from its receipt')
    return {'receipt': str(receipt_path), 'receipt_sha256': hashlib.sha256(receipt_bytes).hexdigest(),
            'archive_sha256': archive_sha256,
            'public_anchor_count': proof['public_anchor_count'], 'payload_sha256': additions,
            'tls_verification_disabled': False, 'host_trust_modified': False}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--app', choices=('legcord', 'steam'), required=True)
    ap.add_argument('--tree', type=Path, required=True)
    ap.add_argument('--image', type=Path, required=True)
    ap.add_argument('--runtime', type=Path, required=True)
    ap.add_argument('--kernel', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--network', choices=('offline', 'user'), default='offline')
    ap.add_argument('--seconds', type=int, default=110)
    ap.add_argument('--guest-timeout', type=int, default=90)
    ap.add_argument('--capture-every', type=int, default=15)
    ap.add_argument('--public-root-bootstrap', action='store_true',
                    help='initialize isolated OS trust from its exact receipt before unchanged Steam')
    args = ap.parse_args()
    validate_durations(args.seconds, args.guest_timeout, args.capture_every)
    trust = None
    if args.public_root_bootstrap:
        if args.app != 'steam' or args.network != 'user':
            raise SystemExit('public-root bootstrap requires the real Steam network scenario')
        trust = public_root_bootstrap(args.runtime.resolve(strict=True))
    out = args.out.resolve()
    if not out.is_relative_to((ROOT/'build/modern-apps').resolve(strict=True)):
        raise SystemExit('output must be a fresh PRIVATE build/modern-apps directory')
    out.mkdir(parents=True, exist_ok=False, mode=0o700)
    global ACTIVE_OUT
    ACTIVE_OUT = out
    product = productivity.PRODUCTS[args.app]
    if '--no-sandbox' not in product['args'].split():
        raise SystemExit('fixed publisher command must contain mandatory --no-sandbox')
    exe, host_exe = productivity.find_product_exe(args.tree, product['candidates'])
    if not exe or productivity.pe_machine(host_exe) != 0x8664:
        raise SystemExit('actual publisher AMD64 executable is required')
    tree_hash = productivity.tree_fingerprint(args.tree)
    image = args.image.resolve()
    productivity.build_product_image(image, args.tree, product['dir'], runner.build_image)
    startup_image = f"D:\\{product['dir']}\\{exe}"
    startup_command = f"{exe} {product['args']}"
    if trust:
        startup_image = 'C:\\SHZ\\TESTS\\T_RUNTIME_ROOTS.EXE'
        startup_command = 'T_RUNTIME_ROOTS.EXE --steam'
    control = (f"image={startup_image}\r\ncmdline={startup_command}\r\n"
               f"cwd=D:\\{product['dir']}\r\ntimeout={args.guest_timeout}\r\n").encode()
    if len(f"{exe} {product['args']}") > 511:
        raise SystemExit('fixed command exceeds native autorun limit')
    runner.put_file(image, control, 'K64RUN.TXT', out)
    kernel = args.kernel.resolve()/'KERNEL64S.BIN'
    stub = args.kernel.resolve()/'boot.elf'
    runtime = args.runtime.resolve()/'WIN64.IMG'
    inputs = {str(path): sha256(path) for path in (kernel, stub, runtime, host_exe, image)}
    for name, expected in SOURCE_PINS.items():
        if sha256(ROOT/name) != expected: raise ValueError('Frozen source provider drift before launch')
        inputs[str(ROOT/name)] = expected
    for path in (Path(__file__).resolve(), Path(runner.qemu.DEFAULT_QEMU).resolve()):
        inputs[str(path)] = sha256(path)
    if trust:
        if inputs[str(runtime)] != trust['archive_sha256'] or sha256(trust['receipt']) != trust['receipt_sha256']:
            raise SystemExit('validated public trust inputs changed before guest launch')
        inputs[trust['receipt']] = trust['receipt_sha256']
    serial = out/'serial.log'
    qmp = None
    captures = []
    failures = []
    elapsed = 0
    controls = None
    owned = None
    with tempfile.TemporaryDirectory(prefix='shz-qmp-') as directory:
        endpoint = Path(directory)/'qmp.sock'
        command = [runner.qemu.DEFAULT_QEMU, '-machine', 'pc', '-accel', 'kvm', '-cpu', 'max', '-m', '3072',
                   '-nodefaults', '-display', 'none', '-vga', 'std', '-kernel', str(stub),
                   '-initrd', f'{kernel},{runtime}', '-append',
                   'shz.noapps shz.autorun=D:\\K64RUN.TXT shz.k32trace shz.exctrace shz.systrace',
                   '-serial', f'file:{serial}', '-qmp', f'unix:{endpoint},server=on,wait=off',
                   '-device', 'isa-debug-exit,iobase=0xf4,iosize=0x04', '-no-reboot',
                   '-device', 'ahci,id=ahci0', '-drive', f'if=none,id=d0,file={image},format=raw,snapshot=on',
                   '-device', 'ide-hd,drive=d0,bus=ahci0.0']
        if args.network == 'user':
            command += ['-netdev', 'user,id=n0,net=10.0.2.0/24,host=10.0.2.2,dhcpstart=10.0.2.15,dns=10.0.2.3',
                        '-device', 'rtl8139,netdev=n0,mac=52:54:00:cb:43:08']
        start = time.monotonic()
        with (out/'qemu.log').open('wb') as log:
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
            next_capture = 5
            try:
                owned = capture_owned_guest(proc, command)
                controls = ReviewedControls(out, args.app, proc, owned, secrets.token_hex(16))
                while proc.poll() is None:
                    elapsed = time.monotonic()-start
                    if elapsed >= args.seconds: break
                    if qmp is None and endpoint.exists():
                        require_owned_guest(proc, owned)
                        qmp = QMP(endpoint, proc.pid)
                    if qmp and elapsed >= next_capture:
                        try:
                            controls.capture(qmp)
                        except (OSError, RuntimeError, ValueError) as error:
                            failures.append({'seconds': round(elapsed, 2), 'error': str(error)})
                            controls.disabled = True; controls.save()
                            break
                        next_capture += args.capture_every
                    if qmp: controls.poll(qmp)
                    time.sleep(0.1)
            except (OSError, RuntimeError, ValueError) as error:
                failures.append({'seconds': round(time.monotonic()-start, 2), 'error': str(error)})
            finally:
                try:
                    if proc.poll() is None:
                        if owned is None: owned = capture_owned_guest(proc, command)
                        require_owned_guest(proc, owned)
                        try: signal.pidfd_send_signal(owned['pidfd'], signal.SIGKILL, None, 0)
                        except ProcessLookupError: pass
                    proc.wait(timeout=10)
                except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
                    if proc.poll() is None:
                        failures.append({'seconds': round(time.monotonic()-start, 2), 'owned_stop_error': str(error)})
                if qmp:
                    try: qmp.close()
                    except OSError as error: failures.append({'qmp_close_error': str(error)})
                if owned is not None: os.close(owned['pidfd'])
                if controls:
                    controls.disabled = True; controls.save()
                    captures = controls.captures
        returncode = proc.returncode
    unchanged = all(sha256(Path(path)) == value for path, value in inputs.items())
    unchanged = unchanged and productivity.tree_fingerprint(args.tree) == tree_hash
    text = serial.read_text(errors='replace') if serial.exists() else ''
    proof = {'evidence_level': 'actual-publisher-standalone-display-observation',
             'app': args.app, 'scenario': product['scenario'], 'publisher': product['publisher'],
             'app_functionality_verified': False, 'windows98_execution_verified': False,
             'guest_os': 'ShizukuDOS Kernel64 standalone', 'network_profile': args.network,
             'isolated_public_root_bootstrap': trust, 'actual_startup_image': startup_image,
             'actual_startup_command': startup_command,
             'network_enabled': args.network == 'user', 'command': command,
             'seconds': round(time.monotonic()-start, 2), 'qemu_returncode': returncode,
             'inputs': inputs, 'inputs_unchanged': unchanged, 'tree_sha256': tree_hash,
             'captures': captures, 'capture_errors': failures,
             'controls': controls.receipts if controls else [], 'control_errors': controls.errors if controls else [],
             'owned_qemu': owned['identity'] if owned else None,
             'control_scope': 'Root-reviewed current-generation capture bytes, one qcode, 80ms, sequences1..32. Captured bytes do not prove unchanged live UI.',
             'product_classification': productivity.classify_product(text, product['expect'], runner.classify)}
    atomic_json(out/'observation.json', proof)
    print('Observation recorded; app functionality remains unverified:', out/'observation.json', flush=True)
    return 0 if unchanged and captures and not failures and not (controls and controls.errors) else 1


ACTIVE_OUT = None


def entrypoint():
    if '--control' in sys.argv[1:]:
        ap = argparse.ArgumentParser(description='Queue one explicitly reviewed key; no VM/QMP access')
        ap.add_argument('--out', type=Path, required=True)
        ap.add_argument('--control', type=int, required=True)
        ap.add_argument('--qcode', choices=QCODES, required=True)
        ap.add_argument('--reviewed-capture', type=Path, required=True)
        args = ap.parse_args()
        submit_control(args.out.absolute(), args.control, args.qcode, args.reviewed_capture.absolute())
        return 0
    return main()


if __name__ == '__main__':
    try:
        raise SystemExit(entrypoint())
    except (OSError, RuntimeError, ValueError) as error:
        if ACTIVE_OUT is not None:
            atomic_json(ACTIVE_OUT/'observation-failure.json', {'status': 'FAIL', 'error': str(error),
                'app_functionality_verified': False, 'windows98_execution_verified': False})
        print('Interactive observation failed:', error, file=sys.stderr)
        raise SystemExit(1)
