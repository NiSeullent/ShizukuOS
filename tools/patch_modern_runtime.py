#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Rebuild kernel32 and selected guest tests in a copied runtime archive.

Reuses the project's compiler flags and version-resource writer. All other
archive payloads stay byte-identical. This is an incremental experiment, not a
replacement for the ordinary full builder or a complete guest test run.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[1]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--test', action='append', default=[])
    parser.add_argument('--module', action='append', default=[])
    args = parser.parse_args()
    if args.base.resolve() == (args.out/'WIN64.IMG').resolve():
        raise SystemExit('output must not overwrite the base archive')
    args.out.mkdir(parents=True, exist_ok=True)
    raw = args.base.read_bytes()
    if raw[:8] != b'SHZARC01':
        raise SystemExit('invalid base archive')
    count = struct.unpack_from('<I', raw, 8)[0]
    header = 16 + count * 136
    if header > len(raw):
        raise SystemExit('truncated base archive')
    files = {}
    for i in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16 + i * 136)
        name = name.split(b'\0', 1)[0].decode('ascii')
        if name in files or offset < header or offset + size > len(raw):
            raise SystemExit('invalid or duplicate base archive entry')
        files[name] = raw[offset:offset + size]
    spec = importlib.util.spec_from_file_location('modern_builder', ROOT/'shizukudos/win64/build.py')
    b = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(b)
    if not b.OUT.resolve().is_relative_to(ROOT/'build'):
        raise SystemExit('builder output is outside this worktree')
    if (b.OUT/'ntdll.dll').read_bytes() != files.get('\\SHZ\\SYS64\\ntdll.dll'):
        raise SystemExit('cached ntdll does not match the base archive')
    ntd = pefile.PE(str(b.OUT/'ntdll.dll'), fast_load=False)
    names = [e.name.decode('ascii') for e in ntd.DIRECTORY_ENTRY_EXPORT.symbols if e.name]
    ntd.close()
    sources = [Path(__file__).resolve(), ROOT/'shizukudos/win64/build.py',
               Path(b.verres.__file__), Path(b.shzlib.__file__),
               *b.W64.joinpath('kernel32').glob('*.[ch]'),
               *b.W64.joinpath('include').glob('*.h'), *b.W64.joinpath('crt').glob('*.[ch]')]
    sources.extend(b.W64.joinpath('tests').glob('*.h'))
    configs = {name: (directory, config) for name,directory,config in b.discover_modules()}
    selected = set(args.module)
    if len(selected) != len(args.module) or not selected.issubset(configs):
        raise SystemExit('module must uniquely name a discovered source module')
    generated_libraries = {'libkernel32.a', 'libkernel32_delay.a'}
    generated_libraries.update(f'lib{name}{suffix}.a' for name in selected for suffix in ('', '_delay'))
    sources.extend(p for p in b.OUT.glob('lib*.a') if p.name not in generated_libraries)
    for name in selected:
        sources.extend(p for p in configs[name][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    for name in args.test:
        if '/' in name or not name.startswith('t_') or not (b.W64/'tests'/f'{name}.c').is_file():
            raise SystemExit('test must name an existing t_*.c source')
        sources.append(b.W64/'tests'/f'{name}.c')
        resource = b.W64/'tests'/f'{name}.rc'
        if resource.exists(): sources.append(resource)
    def source_inventory():
        # Detect additions/removals too: a new translation unit added during
        # the kernel32 build must not enter a later module build unrecorded.
        current = [Path(__file__).resolve(), ROOT/'shizukudos/win64/build.py',
                   Path(b.verres.__file__), Path(b.shzlib.__file__),
                   *b.W64.joinpath('kernel32').glob('*.[ch]'),
                   *b.W64.joinpath('include').glob('*.h'), *b.W64.joinpath('crt').glob('*.[ch]'),
                   *b.W64.joinpath('tests').glob('*.h')]
        current.extend(p for p in b.OUT.glob('lib*.a') if p.name not in generated_libraries)
        for name in selected:
            current.extend(p for p in configs[name][0].rglob('*') if p.is_file() and '__pycache__' not in p.parts)
        for name in args.test:
            current.append(b.W64/'tests'/f'{name}.c')
            resource = b.W64/'tests'/f'{name}.rc'
            if resource.exists(): current.append(resource)
        return {str(p.relative_to(ROOT)) for p in current}

    initial_inventory = source_inventory()
    hashes = {str(p.relative_to(ROOT)): digest(p) for p in sources}
    if set(hashes) != initial_inventory:
        raise SystemExit('source inventory changed while recording inputs')
    changed = {}
    dll, cmd, _ = b.build_kernel32(names)
    changed['\\SHZ\\SYS64\\kernel32.dll'] = dll.read_bytes()
    commands = {'kernel32': [str(x) for x in cmd]}
    preferred = {}
    for guest,payload in files.items():
        if guest.casefold().endswith('.dll'):
            image = pefile.PE(data=payload, fast_load=True)
            preferred[guest.casefold()] = image.OPTIONAL_HEADER.ImageBase
            image.close()
    next_base = (max(preferred.values()) // b.DLL_STRIDE + 1) * b.DLL_STRIDE
    pending = set(selected)
    while pending:
        ready = sorted(name for name in pending if not (set(configs[name][1].get('libs', [])) & pending))
        if not ready: raise SystemExit('cyclic selected module dependencies')
        for name in ready:
            directory,config = configs[name]
            src = sorted(directory.glob('*.c'))
            exports = b.scan_exports(src, 'DLLAPI')
            definition = b.OUT/f'{name}.def'
            b.write_def(definition, f'{name}.dll', exports, config.get('forwarders', []), config.get('ordinals'))
            has_main = any(__import__('re').search(r'\bDllMain\s*\(', p.read_text()) for p in src)
            guest = f'\\SHZ\\SYS64\\{name}.dll'
            base = preferred.get(guest.casefold(), next_base)
            if guest.casefold() not in preferred: next_base += b.DLL_STRIDE
            module_dll = b.OUT/f'{name}.dll'
            command = [b.CC, *b.COMMON, '-DBUILDING_'+name.upper(), '-shared', '-nostdlib',
                       '-Wl,--entry,'+('DllMain' if has_main else '0'), f'-Wl,--image-base,{base:#x}',
                       '-Wl,--dynamicbase', '-Wl,--subsystem,console', '-Wl,--kill-at', '-I', b.W64/'include',
                       '-I', directory, *src, definition, b.version_obj(f'{name}.dll',config.get('description',f'{name}.dll')),
                       '-L',b.OUT,*[f'-l{x}' for x in ['kernel32','ntdll',*config.get('libs',[])]],'-lgcc','-o',module_dll]
            b.run(command)
            b.run([b.DLLTOOL,'-d',definition,'-l',b.OUT/f'lib{name}.a','--kill-at'])
            b.run([b.DLLTOOL,'-d',definition,'-y',b.OUT/f'lib{name}_delay.a','--kill-at'])
            changed[guest] = module_dll.read_bytes()
            commands[name] = [str(x) for x in command]
            pending.remove(name)
    libs = sorted(x[0] for x in b.discover_modules())
    for name in args.test:
        source = b.W64/'tests'/f'{name}.c'
        exe = b.OUT/f'{name}.exe'
        crt = b.W64/'crt'
        command = [b.CC, *b.COMMON, '-nostdlib', '-Wl,--entry,ShzStart', '-Wl,--subsystem,console',
                   '-Wl,--kill-at', '-Wl,--image-base,0x140000000', '-I', b.W64/'include', '-I', crt,
                   source, crt/'shzcrt.c', b.version_obj(f'{name}.exe', f'Shizuku Win64 self-check {name}', b.verres.VFT_APP,
                   extra_rc=source.with_suffix('.rc') if source.with_suffix('.rc').exists() else None),
                   '-L', b.OUT, *[f'-l{x}' for x in libs], '-lkernel32', '-lntdll', '-lgcc', '-o', exe]
        b.run(command)
        changed[f'\\SHZ\\TESTS\\{name.upper()}.EXE'] = exe.read_bytes()
        commands[name] = [str(x) for x in command]
    if source_inventory() != initial_inventory or {x[0] for x in b.discover_modules()} != set(configs):
        raise SystemExit('source or module inventory changed during incremental experiment')
    changed_inputs = [p for p, sha in hashes.items() if digest(ROOT/p) != sha]
    if changed_inputs or digest(args.base) != hashlib.sha256(raw).hexdigest():
        raise SystemExit('build inputs changed during incremental experiment')
    files.update(changed)
    image = args.out/'WIN64.IMG'
    image.write_bytes(b.pack_archive(sorted(files.items())))
    proof = {'mode': 'incremental-kernel32-and-guest-tests', 'builder_output': str(b.OUT.resolve()),
             'base_archive': str(args.base.resolve()),
             'base_sha256': hashlib.sha256(raw).hexdigest(), 'archive_sha256': digest(image),
             'replaced_or_added': {p: hashlib.sha256(v).hexdigest() for p,v in changed.items()},
             'unchanged_payload_count': len(files)-len(changed), 'sources':hashes, 'commands':commands}
    (args.out/'receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    print('Incremental runtime built:',image)


if __name__ == '__main__':
    main()
