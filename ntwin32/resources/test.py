#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze/test the read-only Chromium PE32 resource prerequisite on the host.

Writes only the new --out directory. Compiles local C sources and reads existing
pinned originals. No targets, VM, downloads, services, install or client changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = ROOT / 'build/chromium-large-native-probe-20261001T0036-v2/manifest.json'
PROFILE = ROOT / 'tools/modern_apps/chromium_port_profile.json'
EXE_DIGEST = '7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823'
DLL_DIGEST = 'f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158'


def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def oracle(path):
    """Independent host struct reader; compare every original leaf and payload."""
    b = path.read_bytes()
    u16 = lambda at: struct.unpack_from('<H', b, at)[0]
    u32 = lambda at: struct.unpack_from('<I', b, at)[0]
    pe = u32(60)
    o = pe + 24
    sections = [struct.unpack_from('<IIII', b, o + u16(pe + 20) + 40 * i + 8)
                for i in range(u16(pe + 6))]

    def raw(at, n):
        if at <= u32(o + 60) and n <= u32(o + 60) - at:
            return at
        for _, va, rs, rp in sections:
            if at >= va and at - va <= rs and n <= rs - (at - va):
                return rp + at - va
        raise ValueError('oracle raw bounds')

    rva, size = struct.unpack_from('<II', b, o + 112)
    root = raw(rva, size)
    leaves = []
    regions = []

    def walk(at, keys):
        nn, ni = struct.unpack_from('<HH', b, root + at + 12)
        regions.append((at, 16 + (nn + ni) * 8))
        for i in range(nn + ni):
            k, target = struct.unpack_from('<II', b, root + at + 16 + i * 8)
            if k & 0x80000000:
                offset = k & 0x7fffffff
                count = u16(root + offset)
                regions.append((offset, 2 + count * 2))
                key = {'utf16le_hex': b[root + offset + 2:root + offset + 2 + count * 2].hex(),
                       'units': count}
            else:
                key = {'id': k}
            if target & 0x80000000:
                walk(target & 0x7fffffff, keys + [key])
            else:
                regions.append((target, 16))
                rv, count, cp, reserved = struct.unpack_from('<IIII', b, root + target)
                assert reserved == 0
                offset = raw(rv, count)
                leaves.append({'entry_offset': target, 'data_rva': rv, 'bytes': count,
                    'codepage': cp, 'language': key['id'], 'type': keys[0], 'name': keys[1],
                    'payload_sha256': hashlib.sha256(b[offset:offset + count]).hexdigest()})
    walk(0, [])
    return {'directory_rva': rva, 'directory_bytes': size,
            'regions': len(regions), 'leaves': leaves}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve()
    if out.exists():
        ap.error('use a fresh output directory; failed evidence is never overwritten')
    out.mkdir(parents=True)
    receipt = {'schema': 1, 'status': 'FAIL', 'host_only': True,
        'native_executed': False, 'target_entry_calls': 0, 'tls_callback_calls': 0,
        'application_success': False, 'module_registration': False,
        'runtime_admission_changed': False, 'language_policy': 'exact-only',
        'commands': [], 'sources': [], 'compilers': [], 'inputs': [], 'failures': []}
    sources = [HERE / n for n in ('resources.c', 'resources.h', 'host_test.c', 'test.py')]
    if (HERE / 'README.md').exists():
        sources.append(HERE / 'README.md')
    sources += [HERE.parent / 'native_loader/pe.c', HERE.parent / 'native_loader/pe.h']
    try:
        for source in sources:
            rel = source.relative_to(ROOT)
            frozen = out / 'frozen' / rel
            frozen.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, frozen)
            receipt['sources'].append({'path': str(source), 'frozen': str(frozen),
                                      'sha256': sha(source)})
        manifest = json.loads(MANIFEST.read_text())
        profile = json.loads(PROFILE.read_text())
        core = next(i for i in manifest['inputs'] if i['source'].lower().endswith('/chrome.dll'))
        assert core['sha256'] == DLL_DIGEST
        # The current pinned profile identifies the actual preflight corpus.
        entry = next(i for i in profile['existing_preflights'] if i['path'].endswith('chrome.exe.preflight.json'))
        exe = ROOT / entry['path'].removesuffix('.preflight.json')
        paths = [exe, Path(core['source'])]
        for meta in (MANIFEST, PROFILE):
            frozen = out / 'metadata' / meta.name
            frozen.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(meta, frozen)
            receipt.setdefault('input_metadata', []).append({'path': str(meta),
                'frozen': str(frozen), 'sha256': sha(meta)})
        for path, digest in zip(paths, (EXE_DIGEST, DLL_DIGEST)):
            assert sha(path) == digest, f'exact original input mismatch: {path}'
            item = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': digest,
                    'executed': False, 'host_mapping': 'PROT_READ|MAP_PRIVATE', 'oracle': oracle(path)}
            receipt['inputs'].append(item)

        def run(label, command, env=None):
            record = {'label': label, 'command': command}
            receipt['commands'].append(record)
            result = subprocess.run(command, capture_output=True, text=True,
                timeout=120, env=env)
            log = out / f'{label}.log'
            log.write_text(result.stdout + result.stderr)
            record.update({'exit_code': result.returncode, 'log': str(log), 'log_sha256': sha(log)})
            if result.returncode:
                raise RuntimeError(f'{label} failed with exit {result.returncode}; frozen log {log}')
            return result.stdout

        compilers = {name: str(Path(shutil.which(name) or name).resolve()) for name in
                     ('gcc', 'clang', 'i686-w64-mingw32-gcc')}
        for name, path in compilers.items():
            compiler = {'name': name, 'path': path, 'sha256': sha(path),
                'version': subprocess.check_output([path, '--version'], text=True).splitlines()[0]}
            if name.endswith('gcc'):
                backend = Path(subprocess.check_output([path, '-print-prog-name=cc1'], text=True).strip()).resolve()
                compiler['backend'] = {'path': str(backend), 'sha256': sha(backend)}
            receipt['compilers'].append(compiler)
        frozen = out / 'frozen/ntwin32'
        common = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation']
        cfiles = [str(frozen / 'resources/resources.c'), str(frozen / 'resources/host_test.c'),
                  str(frozen / 'native_loader/pe.c')]
        outputs = {}
        for mode in ('normal', 'asan-ubsan'):
            binary = out / f'resources-{mode}'
            compiler = compilers['gcc' if mode == 'normal' else 'clang']
            flags = [] if mode == 'normal' else [
                '-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
            run(f'build-{mode}', [compiler, *common, *flags, *cfiles, '-o', str(binary)])
            env = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
            text = run(f'tests-{mode}', [str(binary), *map(str, paths)], env)
            observed = [[] for _ in paths]
            for line in text.splitlines():
                if line.startswith('LEAF '):
                    input_index, index, offset, rv, n, cp, language = map(int, line.split()[1:])
                    assert index == len(observed[input_index])
                    observed[input_index].append((offset, rv, n, cp, language))
            for i, item in enumerate(receipt['inputs']):
                expected = [(x['entry_offset'], x['data_rva'], x['bytes'], x['codepage'], x['language'])
                            for x in item['oracle']['leaves']]
                assert observed[i] == expected, f'{mode} independent oracle disagreement'
            match = re.search(r'RESULT PASS cases=(\d+) checks=(\d+)', text)
            assert match, 'missing completed suite receipt'
            outputs[mode] = {'path': str(binary), 'sha256': sha(binary),
                'cases': int(match[1]), 'checks': int(match[2]), 'independent_oracle': 'PASS'}
        obj = out / 'resources-i486.o'
        run('build-i486', [compilers['i686-w64-mingw32-gcc'], '-std=c11', '-O2',
            '-march=i486', '-mtune=i486', '-mno-sse', '-mno-mmx', '-ffreestanding',
            '-fno-builtin', '-fno-stack-protector', '-fno-tree-loop-distribute-patterns',
            '-Wall', '-Wextra', '-Werror', '-c', str(frozen / 'resources/resources.c'), '-o', str(obj)])
        symbols = run('i486-symbols', ['i686-w64-mingw32-nm', '-u', str(obj)])
        undefined = [line.split()[-1] for line in symbols.splitlines() if line.strip()]
        assert set(undefined) <= {'_np_raw', '_np_u16', '_np_u32'}, undefined
        disassembly = run('i486-disassembly', ['i686-w64-mingw32-objdump', '-d', str(obj)])
        assert 'file format pe-i386' in disassembly
        assert not re.search(r'\b(cmov\w*|xmm\d+|ymm\d+|zmm\d+|cpuid|rdtsc)\b', disassembly)
        receipt['outputs'] = outputs
        receipt['i486'] = {'path': str(obj), 'sha256': sha(obj), 'format': 'pe-i386',
                           'undefined_symbols': undefined, 'compiled_only': True}
        receipt['status'] = 'PASS'
    except Exception as exc:
        receipt['failures'].append(f'{type(exc).__name__}: {exc}')
    finally:
        for item in receipt['sources']:
            item['sha256_after'] = sha(item['path'])
            item['unchanged'] = item['sha256'] == item['sha256_after']
        for item in receipt['inputs']:
            item['sha256_after'] = sha(item['path'])
            item['unchanged'] = item['sha256'] == item['sha256_after']
        if not all(i['unchanged'] for i in receipt['sources'] + receipt['inputs']):
            receipt['status'] = 'FAIL'
            receipt['failures'].append('source or original input changed during validation')
        target = out / 'result.json'
        target.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'status': receipt['status'], 'receipt': str(target),
                          'failures': receipt['failures'], 'application_success': False}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
