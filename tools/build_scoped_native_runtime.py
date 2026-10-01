#!/usr/bin/env python3
"""Compile selected native DLLs/tests into a fresh copy of a frozen runtime."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import pefile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack(raw):
    assert raw[:8] == b'SHZARC01'
    count = struct.unpack_from('<I', raw, 8)[0]
    header = 16 + count * 136
    assert header <= len(raw)
    files, spans = {}, []
    for i in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16 + i * 136)
        name = name.split(b'\0', 1)[0].decode('ascii')
        assert name not in files and offset >= header and offset + size <= len(raw)
        files[name] = raw[offset:offset + size]
        spans.append((offset, offset + size))
    spans.sort()
    assert all(a[1] <= b[0] for a, b in zip(spans, spans[1:]))
    return files


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--module', action='append', default=[])
    p.add_argument('--test', action='append', default=[])
    args = p.parse_args()
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'build') and not out.exists()
    spec = importlib.util.spec_from_file_location('scoped_builder', ROOT / 'shizukudos/win64/build.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    configs = {n: (d, c) for n, d, c in b.discover_modules()}
    assert len(set(args.module)) == len(args.module) and set(args.module) <= configs.keys()
    assert all('/' not in n and n.startswith('t_') and (b.W64 / 'tests' / (n + '.c')).is_file() for n in args.test)
    raw = args.base.read_bytes()
    files = unpack(raw)
    sources = {Path(__file__), ROOT / 'shizukudos/win64/build.py', Path(b.verres.__file__), Path(b.shzlib.__file__)}
    sources.update(b.W64.joinpath('include').glob('*.h'))
    sources.update(b.W64.joinpath('crt').glob('*.[ch]'))
    sources.update(b.W64.joinpath('tests').glob('*.h'))
    libraries = list(b.OUT.glob('lib*.a'))
    sources.update(libraries)
    for n in args.module:
        sources.update(p for p in configs[n][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for n in args.test:
        sources.add(b.W64 / 'tests' / (n + '.c'))
        rc = b.W64 / 'tests' / (n + '.rc')
        if rc.exists(): sources.add(rc)
    before = {str(p): sha(p) for p in sources}
    out.mkdir()
    b.OUT = out / 'native'
    b.OUT.mkdir()
    b.RES = b.OUT / 'res'
    for lib in libraries: shutil.copyfile(lib, b.OUT / lib.name)
    commands, changed = {}, {}
    pending = set(args.module)
    while pending:
        ready = sorted(n for n in pending if not set(configs[n][1].get('libs', ())) & pending)
        assert ready, 'cyclic selected module dependency'
        for n in ready:
            directory, config = configs[n]
            src = sorted(directory.glob('*.c'))
            guest = '\\SHZ\\SYS64\\' + n + '.dll'
            old = pefile.PE(data=files[guest], fast_load=True)
            base = old.OPTIONAL_HEADER.ImageBase
            old.close()
            definition = b.OUT / (n + '.def')
            b.write_def(definition, n + '.dll', b.scan_exports(src, 'DLLAPI'), config.get('forwarders', ()), config.get('ordinals'))
            import re
            entry = 'DllMain' if any(re.search(r'\bDllMain\s*\(', x.read_text()) for x in src) else '0'
            target = b.OUT / (n + '.dll')
            command = [b.CC, *b.COMMON, '-DBUILDING_' + n.upper(), '-shared', '-nostdlib', '-Wl,--entry,' + entry,
                       f'-Wl,--image-base,{base:#x}', '-Wl,--dynamicbase', '-Wl,--subsystem,console', '-Wl,--kill-at',
                       '-I', b.W64 / 'include', '-I', directory, *src, definition,
                       b.version_obj(n + '.dll', config.get('description', n + '.dll')), '-L', b.OUT,
                       *['-l' + lib for lib in ['kernel32', 'ntdll', *config.get('libs', ())]], '-lgcc', '-o', target]
            b.run(command)
            b.run([b.DLLTOOL, '-d', definition, '-l', b.OUT / ('lib' + n + '.a'), '--kill-at'])
            b.run([b.DLLTOOL, '-d', definition, '-y', b.OUT / ('lib' + n + '_delay.a'), '--kill-at'])
            commands[n] = list(map(str, command))
            changed[guest] = target.read_bytes()
            pending.remove(n)
    for n in args.test:
        source, target = b.W64 / 'tests' / (n + '.c'), b.OUT / (n + '.exe')
        crt = b.W64 / 'crt'
        command = [b.CC, *b.COMMON, '-nostdlib', '-Wl,--entry,ShzStart', '-Wl,--subsystem,console', '-Wl,--kill-at',
                   '-Wl,--image-base,0x140000000', '-I', b.W64 / 'include', '-I', crt, source, crt / 'shzcrt.c',
                   b.version_obj(n + '.exe', 'Shizuku Win64 self-check ' + n, b.verres.VFT_APP,
                                 extra_rc=source.with_suffix('.rc') if source.with_suffix('.rc').exists() else None),
                   '-L', b.OUT, *['-l' + lib for lib in sorted(configs)], '-lkernel32', '-lntdll', '-lgcc', '-o', target]
        b.run(command)
        commands[n] = list(map(str, command))
        changed['\\SHZ\\TESTS\\' + n.upper() + '.EXE'] = target.read_bytes()
    inventory_after = set(sources)
    inventory_after.update(b.W64.joinpath('include').glob('*.h'))
    inventory_after.update(b.W64.joinpath('crt').glob('*.[ch]'))
    inventory_after.update(b.W64.joinpath('tests').glob('*.h'))
    for n in args.module:
        inventory_after.update(p for p in configs[n][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    assert inventory_after == sources, 'source inventory changed during compilation'
    assert args.base.read_bytes() == raw and {str(p): sha(p) for p in sources} == before, 'consumed input drift'
    files.update(changed)
    images = {Path(name.replace('\\', '/')).name.casefold(): pefile.PE(data=data)
              for name, data in files.items() if name.casefold().endswith(('.dll', '.exe'))}
    ranges = sorted((im.OPTIONAL_HEADER.ImageBase, im.OPTIONAL_HEADER.ImageBase + im.OPTIONAL_HEADER.SizeOfImage, name)
                    for name, im in images.items() if name.endswith('.dll'))
    assert all(a[1] <= c[0] for a, c in zip(ranges, ranges[1:])), 'preferred DLL range overlap'
    imported = 0
    for guest in changed:
        im = images[Path(guest.replace('\\', '/')).name.casefold()]
        for desc in getattr(im, 'DIRECTORY_ENTRY_IMPORT', ()):
            provider = images[desc.dll.decode().casefold()]
            exports = getattr(provider, 'DIRECTORY_ENTRY_EXPORT').symbols
            names, ordinals = {e.name for e in exports}, {e.ordinal for e in exports}
            for imp in desc.imports:
                assert imp.name in names if imp.name else imp.ordinal in ordinals, (guest, desc.dll, imp.name, imp.ordinal)
                imported += 1
    for im in images.values(): im.close()
    packed = b.pack_archive(sorted(files.items()))
    (out / 'WIN64.IMG').write_bytes(packed)
    proof = {'status': 'PASS', 'mode': 'ordinary-native-scoped-build-and-immutable-runtime-merge', 'sources': before,
             'commands': commands, 'base': str(args.base.resolve()), 'base_sha256': hashlib.sha256(raw).hexdigest(),
             'replaced_or_added': {n: hashlib.sha256(v).hexdigest() for n, v in changed.items()},
             'unchanged_payload_count': len(files) - len(changed), 'actual_changed_import_names_found': imported,
             'preferred_dll_ranges_no_overlap': True, 'archive_sha256': hashlib.sha256(packed).hexdigest(),
             'guest_executed': False, 'app_functionality_verified': False}
    (out / 'receipt.json').write_text(json.dumps(proof, indent=2) + '\n')
    print('Scoped native runtime PASS:', len(changed), 'changes;', imported, 'actual imports resolved', flush=True)


if __name__ == '__main__':
    main()
