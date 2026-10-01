#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Capture real publisher-app guest displays, optionally with QEMU user NAT.

Uses the fixed application commands and content-verified package-image builder
from run_k64_productivity. This observation never constitutes an application
functionality pass or an installed Windows98 pass. No host service or guest
credential is configured. Disk writes remain in QEMU's temporary snapshot.
QMP command reference: https://www.qemu.org/docs/master/interop/qemu-qmp-ref.html
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'shizukudos/tests'))
import run_k64_steam as steam
productivity = steam.runner
runner = productivity.runner


class QMP:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(3)
        try:
            self.socket.connect(str(path))
            self.stream = self.socket.makefile('rwb')
            greeting = json.loads(self.stream.readline())
            if 'QMP' not in greeting:
                raise ValueError('missing QMP greeting')
            self.sequence = 0
            self.command('qmp_capabilities')
        except BaseException:
            self.socket.close()
            raise

    def command(self, name, arguments=None):
        self.sequence += 1
        message = {'execute': name, 'id': self.sequence}
        if arguments is not None:
            message['arguments'] = arguments
        self.stream.write((json.dumps(message)+'\n').encode())
        self.stream.flush()
        while True:
            line = self.stream.readline()
            if not line:
                raise ConnectionError('QMP connection ended')
            response = json.loads(line)
            if response.get('id') == self.sequence:
                if 'error' in response:
                    raise RuntimeError(json.dumps(response['error']))
                return response['return']

    def close(self):
        self.stream.close()
        self.socket.close()


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


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
    if args.app != 'steam' or not args.public_root_bootstrap or args.network != 'user':
        raise SystemExit('verified preinstalled Steam diagnostic requires real public trust and user network')
    corpus=Path('/root/Win98-Modern-codex-20260930/build/steam-assessment-01a0f3d0cb43')
    corpus_pins={str(p):sha256(p) for p in [corpus/'receipt.json',corpus/'files.json',corpus/'steam_client_win64.manifest']}
    verified=json.loads((corpus/'receipt.json').read_text())
    if verified['client_version']!='1788652215' or not verified['downloaded'] or sha256(corpus/'steam_client_win64.manifest')!=verified['manifest_sha256']:
        raise SystemExit('real saved publisher corpus receipt mismatch')
    rows=json.loads((corpus/'files.json').read_text())
    if len(rows)!=5624 or args.tree.resolve()!= (corpus/'client').resolve():raise SystemExit('exact verified publisher tree required')
    for row in rows:
        relative=Path(row['path']);target=args.tree/relative
        if relative.is_absolute() or '..' in relative.parts or not target.resolve().is_relative_to(args.tree.resolve()) or target.stat().st_size!=row['bytes'] or sha256(target)!=row['sha256']:
            raise SystemExit('publisher extraction content differs from verified package receipt')
    if set(str(p.relative_to(args.tree)).replace(chr(92),'/') for p in args.tree.rglob('*') if p.is_file())!=set(row['path'] for row in rows):raise SystemExit('publisher tree has unverified extra files')
    print('Verified all5624 actual publisher corpus files before preinstalled diagnostic',flush=True)
    if not 10 <= args.seconds <= 600 or not 5 <= args.guest_timeout < args.seconds or not 5 <= args.capture_every <= 120:
        raise SystemExit('observation duration or capture interval is out of bounds')
    trust = None
    if args.public_root_bootstrap:
        if args.app != 'steam' or args.network != 'user':
            raise SystemExit('public-root bootstrap requires the real Steam network scenario')
        trust = public_root_bootstrap(args.runtime.resolve(strict=True))
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise SystemExit('use a fresh observation output directory')
    product = productivity.PRODUCTS[args.app]
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
        startup_command = 'T_RUNTIME_ROOTS.EXE --steam-preinstalled'
    control = (f"image={startup_image}\r\ncmdline={startup_command}\r\n"
               f"cwd=D:\\{product['dir']}\r\ntimeout={args.guest_timeout}\r\n").encode()
    if len(f"{exe} {product['args']}") > 511:
        raise SystemExit('fixed command exceeds native autorun limit')
    runner.put_file(image, control, 'K64RUN.TXT', out)
    kernel = args.kernel.resolve()/'KERNEL64S.BIN'
    stub = args.kernel.resolve()/'boot.elf'
    runtime = args.runtime.resolve()/'WIN64.IMG'
    inputs = {str(path): sha256(path) for path in (kernel, stub, runtime, host_exe, image)}
    if trust:
        if inputs[str(runtime)] != trust['archive_sha256'] or sha256(trust['receipt']) != trust['receipt_sha256']:
            raise SystemExit('validated public trust inputs changed before guest launch')
        inputs[trust['receipt']] = trust['receipt_sha256']
    serial = out/'serial.log'
    qmp = None
    captures = []
    failures = []
    elapsed = 0
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
            proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            next_capture = 5
            try:
                while proc.poll() is None and elapsed < args.seconds:
                    elapsed = time.monotonic()-start
                    if qmp is None and endpoint.exists():
                        qmp = QMP(endpoint)
                    if qmp and elapsed >= next_capture:
                        filename = out/f'screen-{int(elapsed):03d}.png'
                        try:
                            status = qmp.command('query-status')
                            qmp.command('screendump', {'filename': str(filename), 'format': 'png'})
                            captures.append({'seconds': round(elapsed, 2), 'path': str(filename),
                                             'sha256': sha256(filename), 'vm_status': status})
                            print('Real guest screen:', filename, flush=True)
                        except (OSError, RuntimeError, ValueError) as error:
                            failures.append({'seconds': round(elapsed, 2), 'error': str(error)})
                        next_capture += args.capture_every
                    time.sleep(0.1)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                if qmp:
                    qmp.close()
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
             'product_classification': productivity.classify_product(text, product['expect'], runner.classify),
             'diagnostic_scenario': 'verified-publisher-corpus-skip-initial-bootstrap',
             'saved_publisher_receipt_pins': corpus_pins, 'verified_corpus_file_count':len(rows),
             'saved_publisher_receipts_unchanged': all(sha256(Path(k))==v for k,v in corpus_pins.items()),
             'normal_updater_functionality_verified':False}
    (out/'observation.json').write_text(json.dumps(proof, indent=2)+'\n')
    print('Observation recorded; app functionality remains unverified:', out/'observation.json', flush=True)
    return 0 if unchanged and captures and not failures else 1


if __name__ == '__main__':
    raise SystemExit(main())
