#!/usr/bin/env python3
"""Compile a selected ordinary native subset into a fresh frozen-runtime copy.

PE verification parses export/import directories only. --ntdll rebuilds the
ordinary core helper at the base archive preferred address and pins generated
syscall stubs. Host/static success does not claim guest or app functionality.
"""
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



INTERFACE_DIRECTORIES = (pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
                         pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'])


def interface_pe(data):
    image = pefile.PE(data=data, fast_load=True)
    try:
        image.parse_data_directories(directories=INTERFACE_DIRECTORIES)
        return image
    except BaseException:
        image.close()
        raise


def load_builder():
    spec = importlib.util.spec_from_file_location('frozen_subset_builder', ROOT / 'shizukudos/win64/build.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    return builder


def ntdll_sources(builder):
    return {builder.NTSYS, *(p for p in (builder.W64 / 'ntdll').rglob('*')
                           if p.is_file() and '__pycache__' not in p.parts)}


def build_ntdll_pinned(builder, base_payload):
    old = pefile.PE(data=base_payload, fast_load=True)
    try:
        preferred = old.OPTIONAL_HEADER.ImageBase
    finally:
        old.close()
    original_base, original_generator = builder.NTDLL_BASE, builder.gen_stubs
    generated = {}
    def generate_and_pin():
        names = original_generator()
        generated[builder.OUT / 'nt_stubs.S'] = sha(builder.OUT / 'nt_stubs.S')
        return names
    builder.NTDLL_BASE = f'{preferred:#x}'
    builder.gen_stubs = generate_and_pin
    try:
        target, command, names = builder.build_ntdll()
        assert generated and all(sha(path) == pin for path, pin in generated.items()), 'generated NTDLL stub drift'
        return target, command, {str(path): pin for path, pin in generated.items()}, preferred
    finally:
        builder.NTDLL_BASE, builder.gen_stubs = original_base, original_generator


def explicit_module_bases(values, selected, configs, files):
    bases = {}
    for value in values:
        name, separator, address = value.partition('=')
        assert separator and name in selected and name in configs and name not in bases, 'invalid/duplicate new-module base'
        assert '\\SHZ\\SYS64\\' + name + '.dll' not in files, 'existing preferred module base cannot be overridden'
        number = int(address, 0)
        assert 0x10000 <= number < 0x800000000000 and number % 0x10000 == 0, 'new module base must be valid aligned user address'
        bases[name] = number
    absent = {name for name in selected if '\\SHZ\\SYS64\\' + name + '.dll' not in files}
    assert absent == bases.keys(), 'every absent selected module requires explicit preferred address'
    return bases


def kernel32_sources(builder):
    return {p for p in (builder.W64 / 'kernel32').rglob('*') if p.is_file() and '__pycache__' not in p.parts}


def build_kernel32_pinned(builder, payload, ntdll_payload):
    old = pefile.PE(data=payload, fast_load=True)
    try:
        preferred = old.OPTIONAL_HEADER.ImageBase
    finally:
        old.close()
    nt = interface_pe(ntdll_payload)
    try:
        names = [symbol.name.decode('ascii') for symbol in nt.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name]
    finally:
        nt.close()
    previous = builder.K32_BASE
    builder.K32_BASE = f'{preferred:#x}'
    try:
        target, command, _ = builder.build_kernel32(names)
        return target, command, preferred
    finally:
        builder.K32_BASE = previous


def build_base_ntdll_importlib(builder, payload):
    """Link against the actual frozen NTDLL rather than an older cached list."""
    image = interface_pe(payload)
    try:
        exports = {symbol.name.decode('ascii'): symbol.ordinal
                   for symbol in image.DIRECTORY_ENTRY_EXPORT.symbols if symbol.name}
        assert exports and all(1 <= ordinal <= 65535 for ordinal in exports.values())
    finally:
        image.close()
    definition = builder.OUT / 'base-ntdll-imports.def'
    builder.write_def(definition, 'ntdll.dll', sorted(exports), ordinals=exports)
    library = builder.OUT / 'libntdll.a'
    builder.run([builder.DLLTOOL, '-d', definition, '-l', library, '--kill-at'])
    return {str(definition): sha(definition), str(library): sha(library)}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--base', type=Path, required=True)
    p.add_argument('--out', type=Path, required=True)
    p.add_argument('--module', action='append', default=[])
    p.add_argument('--test', action='append', default=[])
    p.add_argument('--test-lib', action='append', default=[], help='Explicit cached import library for selected tests, e.g. crypt32')
    p.add_argument('--ntdll', action='store_true', help='Rebuild the ordinary NTDLL core at the frozen base address')
    p.add_argument('--kernel32', action='store_true', help='Rebuild the ordinary Kernel32 core preserving its base and actual NTDLL forwarders')
    p.add_argument('--module-base', action='append', default=[], help='Explicit preferred address for a new selected module only, name=0xADDRESS')
    p.add_argument('--compile-timeout', type=int, default=300, help='Bounded per-command native compilation budget, 300..1200 seconds')
    args = p.parse_args()
    assert 300 <= args.compile_timeout <= 1200, 'compile timeout must remain bounded'
    out = args.out.resolve()
    assert out.is_relative_to(ROOT / 'build') and not out.exists()
    b = load_builder()
    ordinary_run = b.run
    def bounded_native_run(command, **kwargs):
        kwargs.setdefault('timeout', args.compile_timeout)
        return ordinary_run(command, **kwargs)
    b.run = bounded_native_run
    configs = {n: (d, c) for n, d, c in b.discover_modules()}
    assert len(set(args.module)) == len(args.module) and set(args.module) <= configs.keys()
    assert all('/' not in n and n.startswith('t_') and (b.W64 / 'tests' / (n + '.c')).is_file() for n in args.test)
    raw = args.base.read_bytes()
    files = unpack(raw)
    module_bases = explicit_module_bases(args.module_base, args.module, configs, files)
    sources = {Path(__file__), ROOT / 'shizukudos/win64/build.py', Path(b.verres.__file__), Path(b.shzlib.__file__)}
    sources.update(b.W64.joinpath('include').glob('*.h'))
    sources.update(b.W64.joinpath('crt').glob('*.[ch]'))
    sources.update(b.W64.joinpath('tests').glob('*.h'))
    libraries = list(b.OUT.glob('lib*.a'))
    cached_names = {lib.name[3:-2] for lib in libraries}
    assert len(set(args.test_lib)) == len(args.test_lib) and all(
        name.isascii() and name.replace('_', '').isalnum() and (name in cached_names or name in args.module)
        for name in args.test_lib), 'test libraries must name existing cached lib*.a files'
    sources.update(libraries)
    for n in args.module:
        sources.update(p for p in configs[n][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for n in args.test:
        sources.add(b.W64 / 'tests' / (n + '.c'))
        rc = b.W64 / 'tests' / (n + '.rc')
        if rc.exists(): sources.add(rc)
    if args.ntdll: sources.update(ntdll_sources(b))
    if args.kernel32: sources.update(kernel32_sources(b))
    before = {str(p): sha(p) for p in sources}
    out.mkdir()
    b.OUT = out / 'native'
    b.OUT.mkdir()
    b.RES = b.OUT / 'res'
    for lib in libraries: shutil.copyfile(lib, b.OUT / lib.name)
    commands, changed = {}, {}
    generated_sources, ntdll_base = {}, None
    if args.ntdll:
        guest = '\\SHZ\\SYS64\\ntdll.dll'
        target, command, generated_sources, ntdll_base = build_ntdll_pinned(b, files[guest])
        commands['ntdll'] = list(map(str, command))
        changed[guest] = target.read_bytes()
    kernel32_base = None
    if args.kernel32 and not args.ntdll:
        generated_sources.update(build_base_ntdll_importlib(b, files['\\SHZ\\SYS64\\ntdll.dll']))
    if args.kernel32:
        guest = '\\SHZ\\SYS64\\kernel32.dll'
        target, command, kernel32_base = build_kernel32_pinned(b, files[guest], changed.get('\\SHZ\\SYS64\\ntdll.dll', files['\\SHZ\\SYS64\\ntdll.dll']))
        commands['kernel32'] = list(map(str, command))
        changed[guest] = target.read_bytes()
    pending = set(args.module)
    while pending:
        ready = sorted(n for n in pending if not set(configs[n][1].get('libs', ())) & pending)
        assert ready, 'cyclic selected module dependency'
        for n in ready:
            directory, config = configs[n]
            src = sorted(directory.glob('*.c'))
            guest = '\\SHZ\\SYS64\\' + n + '.dll'
            if n in module_bases:
                base = module_bases[n]
            else:
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
                   '-L', b.OUT, *['-l' + lib for lib in sorted(configs)], *['-l' + lib for lib in args.test_lib],
                   '-lkernel32', '-lntdll', '-lgcc', '-o', target]
        b.run(command)
        commands[n] = list(map(str, command))
        changed['\\SHZ\\TESTS\\' + n.upper() + '.EXE'] = target.read_bytes()
    inventory_after = set(sources)
    inventory_after.update(b.W64.joinpath('include').glob('*.h'))
    inventory_after.update(b.W64.joinpath('crt').glob('*.[ch]'))
    inventory_after.update(b.W64.joinpath('tests').glob('*.h'))
    for n in args.module:
        inventory_after.update(p for p in configs[n][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    if args.ntdll: inventory_after.update(ntdll_sources(b))
    if args.kernel32: inventory_after.update(kernel32_sources(b))
    assert inventory_after == sources, 'source inventory changed during compilation'
    assert args.base.read_bytes() == raw and {str(p): sha(p) for p in sources} == before, 'consumed input drift'
    files.update(changed)
    assert all(sha(Path(path)) == value for path, value in generated_sources.items()), 'generated NTDLL stub drift'
    images = {Path(name.replace('\\', '/')).name.casefold(): interface_pe(data)
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
    proof = {'status': 'PASS', 'mode': 'ordinary-native-frozen-subset-build-and-immutable-runtime-merge', 'sources': before,
             'commands': commands, 'base': str(args.base.resolve()), 'base_sha256': hashlib.sha256(raw).hexdigest(),
             'replaced_or_added': {n: hashlib.sha256(v).hexdigest() for n, v in changed.items()},
             'unchanged_payload_count': len(files) - len(changed), 'actual_changed_import_names_found': imported,
             'preferred_dll_ranges_no_overlap': True, 'archive_sha256': hashlib.sha256(packed).hexdigest(),
             'pe_interface_directories_only': list(INTERFACE_DIRECTORIES), 'pefile_version': pefile.__version__,
             'generated_sources': generated_sources, 'rebuilt_ntdll': args.ntdll, 'ntdll_preferred_base': ntdll_base,
             'explicit_test_libraries': args.test_lib, 'explicit_new_module_bases': module_bases,
             'rebuilt_kernel32': args.kernel32, 'kernel32_preferred_base': kernel32_base,
             'compile_timeout_seconds': args.compile_timeout,
             'guest_executed': False, 'app_functionality_verified': False}
    (out / 'receipt.json').write_text(json.dumps(proof, indent=2) + '\n')
    print('Frozen native subset PASS:', len(changed), 'changes;', imported, 'actual imports resolved', flush=True)


if __name__ == '__main__':
    main()
