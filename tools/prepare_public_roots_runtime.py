#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a copied guest runtime with genuine public OS trust inputs and probe.

Reads a previously captured and hashed public CA bundle/server chain. It never
changes host trust, publisher binaries, ordinary Wine caches or TLS policy.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import ssl
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--capture', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build') or out == ROOT/'build':
        parser.error('a fresh owned build output is required')
    capture = args.capture.resolve(strict=True)
    capture_receipt_bytes = (capture/'receipt.json').read_bytes()
    captured = json.loads(capture_receipt_bytes)
    pem = (capture/'host-public-ca-bundle.pem').read_bytes()
    if hashlib.sha256(pem).hexdigest() != captured['bundle_sha256'] or captured['returncode'] != 0:
        parser.error('public source bundle or successful host chain evidence changed')
    blocks = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', pem, re.S)
    certs = [ssl.PEM_cert_to_DER_cert(block.decode('ascii')) for block in blocks]
    actual = [{'index': i, 'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
              for i, data in enumerate(certs)]
    if not 1 <= len(certs) <= 512 or actual != captured['anchors'] or any(not 1 <= len(c) <= 65536 for c in certs):
        parser.error('bounded exact public certificate identities changed')
    bundle = b'SHZCA001'+struct.pack('<II', 1, len(certs))
    bundle += b''.join(struct.pack('<I', len(data))+data for data in certs)
    base = args.base.resolve(strict=True)
    raw = base.read_bytes()
    host_log = capture/'host-chain-public.log'
    log_bytes = host_log.read_bytes()
    server_pems = re.findall(rb'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', log_bytes, re.S)
    server_der = [ssl.PEM_cert_to_DER_cert(block.decode('ascii')) for block in server_pems]
    server_inputs = [capture/f'server-{i}.der' for i in range(3)]
    server_bytes = [path.read_bytes() for path in server_inputs]
    if captured['server_certificates'] != 3 or len(server_der) != 3 or server_bytes != server_der or \
       any(not 1 <= len(data) <= 65536 for data in server_bytes):
        parser.error('exact public chain bytes must match the successful saved host TLS capture')
    if len(raw) < 16 or raw[:8] != b'SHZARC01': parser.error('invalid runtime')
    count = struct.unpack_from('<I', raw, 8)[0]
    header = 16+count*136
    if header > len(raw): parser.error('truncated runtime header')
    files, spans = {}, []
    for i in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16+i*136)
        name = name.split(b'\0', 1)[0].decode('ascii')
        if name.casefold() in files or offset < header or offset+size > len(raw): parser.error('invalid runtime entry')
        files[name.casefold()] = (name, raw[offset:offset+size]); spans.append((offset, offset+size))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])): parser.error('overlapping runtime entries')
    spec = importlib.util.spec_from_file_location('public_roots_builder', ROOT/'shizukudos/win64/build.py')
    builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
    for name in ('kernel32', 'ntdll', 'crypt32'):
        if (builder.OUT/(name+'.dll')).read_bytes() != files['\\shz\\sys64\\'+name+'.dll'][1]:
            parser.error('cached actual provider differs from supplied runtime: '+name)
    source = ROOT/'shizukudos/win64/tests/t_runtime_roots.c'
    inputs = [Path(__file__).resolve(), source, ROOT/'shizukudos/win64/build.py',
              Path(builder.verres.__file__), Path(builder.shzlib.__file__), base,
              capture/'receipt.json', capture/'host-public-ca-bundle.pem', host_log]
    inputs += sorted((builder.W64/'include').glob('*.h'))
    inputs += sorted((builder.W64/'crt').glob('*.[ch]'))
    inputs += [builder.W64/'tests/k32test.h']
    inputs += [builder.OUT/('lib'+name+'.a') for name in ('kernel32', 'ntdll', 'crypt32')]
    inputs += server_inputs
    pins = {str(path.resolve()): sha(path) for path in inputs}
    # Bind receipts to the bytes actually consumed, then check source identity.
    snapshots = {str(base): raw, str(host_log): log_bytes,
                 str(capture/'receipt.json'): capture_receipt_bytes,
                 str(capture/'host-public-ca-bundle.pem'): pem}
    snapshots.update({str(path): data for path, data in zip(server_inputs, server_bytes)})
    for path, data in snapshots.items():
        if pins[path] != hashlib.sha256(data).hexdigest():
            parser.error('public trust input changed while taking its byte snapshot')
    out.mkdir(parents=True)
    exe = out/'t_runtime_roots.exe'
    crt = builder.W64/'crt'
    command = [builder.CC, *builder.COMMON, '-nostdlib', '-Wl,--entry,ShzStart', '-Wl,--subsystem,console',
               '-Wl,--kill-at', '-Wl,--image-base,0x140000000', '-I', builder.W64/'include', '-I', crt,
               source, crt/'shzcrt.c', builder.version_obj('t_runtime_roots.exe', 'Public OS trust initialization', builder.verres.VFT_APP),
               '-L', builder.OUT, '-lcrypt32', '-lkernel32', '-lntdll', '-lgcc', '-o', exe]
    result = subprocess.run([str(x) for x in command], capture_output=True, text=True, timeout=120)
    (out/'compile.log').write_text(result.stdout+result.stderr)
    proof = {'status': 'NATIVE_BUILD_FAIL', 'command': [str(x) for x in command], 'inputs': pins,
             'native_windows98_verified': False, 'app_functionality_verified': False,
             'tls_verification_disabled': False, 'host_trust_modified': False,
             'host_capture_chain_matches_der': True,
             'public_anchor_count': len(certs), 'anchor_identities': actual}
    if result.returncode:
        (out/'receipt.json').write_text(json.dumps(proof, indent=2)+'\n')
        raise SystemExit('Native public trust initializer failed; see compile.log')
    changes = {'\\SHZ\\TESTS\\T_RUNTIME_ROOTS.EXE': exe.read_bytes(), '\\SHZ\\CERTS\\ROOTS.BIN': bundle}
    changes.update({'\\SHZ\\CERTS\\SERVER'+str(i)+'.CER': data for i, data in enumerate(server_bytes)})
    if any(sha(Path(path)) != pin for path, pin in pins.items()): raise SystemExit('trust build inputs changed')
    for name, data in changes.items():
        if name.casefold() in files: raise SystemExit('trust input already exists in base runtime')
        files[name.casefold()] = (name, data)
    image = out/'WIN64.IMG'; image.write_bytes(builder.pack_archive(sorted(files.values())))
    proof.update(status='NATIVE_BUILD_PASS_GUEST_PENDING', archive_sha256=sha(image),
                 unchanged_payload_count=count, additions={name: hashlib.sha256(data).hexdigest() for name, data in changes.items()})
    (out/'receipt.json').write_text(json.dumps(proof, indent=2)+'\n')
    print('Copied public trust runtime prepared:', image, '; actual guest validation pending')


if __name__ == '__main__':
    main()
