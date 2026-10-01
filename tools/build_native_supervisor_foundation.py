#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build ordinary native Kernel64/Supervisor in an owned frozen source snapshot.

No standalone stub, shared build output, download, firmware setting or VM is used.
The genuine T_HELLO fixture is retained from the explicitly pinned runtime archive.
This foundation is not a Windows 98 boot or positive W64 bridge result.
"""
import sys
sys.dont_write_bytecode = True
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import pefile

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'shizukudos/kbuild.py').is_file())
HELLO_SHA = '1bdfb6fd531f99ff5db9a6244692cd55927acb76e8d4ae496a710610e5946378'
DOS_SHA = 'aa40e4f0dd81fb6d611aa4425c69782214f59cf78de75e716a9f41407446e0e2'
INPUT_LIMIT = 64 << 20


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verified_input(path, expected, limit=INPUT_LIMIT):
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path or len(expected) != 64:
        raise ValueError('canonical absolute pinned input required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= limit:
            raise ValueError('bounded nonempty regular input required')
        chunks, left = [], before.st_size
        while left:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                raise ValueError('short input')
            chunks.append(chunk)
            left -= len(chunk)
        raw = b''.join(chunks)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.stat()):
            raise ValueError('input changed during read')
        if digest(raw) != expected:
            raise ValueError('input SHA mismatch')
        return raw
    finally:
        os.close(fd)


def unpack(raw):
    if raw[:8] != b'SHZARC01' or len(raw) < 16:
        raise ValueError('invalid archive')
    count, reserved = struct.unpack_from('<II', raw, 8)
    header = 16 + count * 136
    if reserved or not 1 <= count <= 1024 or header > len(raw):
        raise ValueError('invalid archive extent')
    files, spans = {}, []
    for i in range(count):
        name, offset, size = struct.unpack_from('<120sQQ', raw, 16 + i * 136)
        end = name.find(b'\0')
        if end <= 0 or any(name[end:]):
            raise ValueError('noncanonical archive name')
        name = name[:end].decode('ascii')
        if name in files or not name.startswith('\\SHZ\\') or size <= 0 or offset < header or offset + size > len(raw):
            raise ValueError('invalid archive file extent')
        files[name] = raw[offset:offset + size]
        spans.append((offset, offset + size))
    spans.sort()
    if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
        raise ValueError('overlapping archive files')
    return files


def tiny_runtime(raw):
    files = unpack(raw)
    names = ('\\SHZ\\SYS64\\ntdll.dll', '\\SHZ\\SYS64\\kernel32.dll', '\\SHZ\\TESTS\\T_HELLO.EXE')
    selected = {name: files[name] for name in names}
    if digest(selected[names[2]]) != HELLO_SHA:
        raise ValueError('genuine T_HELLO fixture pin mismatch')
    images = {}
    try:
        for name, data in selected.items():
            p = pefile.PE(data=data, fast_load=True)
            images[Path(name.replace('\\','/')).name.lower()] = p
            if p.FILE_HEADER.Machine != 0x8664 or p.OPTIONAL_HEADER.Magic != 0x20b:
                raise ValueError('AMD64 PE32+ required')
            p.parse_data_directories(directories=[0, 1, 13])
        exports = {name: {s.name if s.name else s.ordinal: s for s in getattr(p, 'DIRECTORY_ENTRY_EXPORT', ()).symbols}
                   for name, p in images.items() if hasattr(p, 'DIRECTORY_ENTRY_EXPORT')}
        def resolve(dll, symbol, visited=frozenset()):
            key = (dll, symbol)
            if key in visited or dll not in exports:
                raise ValueError('invalid import forwarding closure')
            candidates = exports[dll]
            entry = candidates.get(symbol)
            if entry is None and isinstance(symbol, int):
                entry = next((s for s in candidates.values() if s.ordinal == symbol), None)
            if entry is None or not entry.address:
                raise ValueError('unresolved actual import')
            if entry.forwarder:
                target, name = entry.forwarder.rsplit(b'.', 1)
                resolve(target.decode('ascii').lower()+'.dll', int(name[1:]) if name.startswith(b'#') else name, visited | {key})
        checked = 0
        for p in images.values():
            for attribute in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for library in getattr(p, attribute, []):
                    for item in library.imports:
                        resolve(library.dll.decode('ascii').lower(), item.name if item.name else item.ordinal)
                        checked += 1
        return sorted(selected.items()), checked
    finally:
        for p in images.values():
            p.close()


def source_files():
    paths = [ROOT/'shizukudos/kbuild.py', ROOT/'shizukudos/tools/shzlib.py',
             ROOT/'shizukudos/win64/pe_parse.c', ROOT/'shizukudos/win64/pe_parse.h']
    for name in ('shizukudos/kernel64', 'shizukudos/kcommon', 'shizukudos/abi',
                 'shizukudos/supervisor', 'shizukudos/uefi', 'shizukudos/win64/include', 'shizukufs/v1/libsfs'):
        paths += [p for p in (ROOT/name).rglob('*') if p.is_file() and p.suffix in ('.c', '.h', '.asm', '.ld', '.py')
                  and '__pycache__' not in p.parts]
    return sorted(set(paths))


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--runtime', type=Path, required=True)
    ap.add_argument('--runtime-sha256', required=True)
    ap.add_argument('--dos-disk', type=Path, required=True)
    ap.add_argument('--ovmf-vars', type=Path, default=Path('/usr/share/OVMF/OVMF_VARS.fd').resolve())
    ap.add_argument('--validate-only', action='store_true')
    args = ap.parse_args()
    out = args.out
    if not out.is_absolute() or out.resolve() != out or not out.is_relative_to(ROOT/'build/modern-apps') or out.exists():
        ap.error('fresh canonical owned output below worktree build/modern-apps required')
    runtime = verified_input(args.runtime, args.runtime_sha256)
    disk = verified_input(args.dos_disk, DOS_SHA)
    var_hash = digest(args.ovmf_vars.read_bytes())
    var_data = verified_input(args.ovmf_vars, var_hash, 4 << 20)
    tiny, import_count = tiny_runtime(runtime)
    inputs = {str(args.runtime): args.runtime_sha256, str(args.dos_disk): DOS_SHA, str(args.ovmf_vars): var_hash}
    paths = source_files()
    raw_sources = {str(p.relative_to(ROOT)): p.read_bytes() for p in paths}
    pins = {p: digest(data) for p, data in raw_sources.items()}
    if args.validate_only:
        print(json.dumps({'status':'VALIDATED_NO_BUILD_OR_VM','sources':len(pins),'runtime_imports':import_count,'inputs':inputs}))
        return
    if shutil.disk_usage(out.parent).free < 17 << 30:
        ap.error('17 GiB free disk floor required')
    out.mkdir()
    proof = {'status':'BUILDING','producer_sha256':digest(Path(__file__).read_bytes()),
             'sources_sha256':pins,'inputs':inputs,'VM_executed':False,'Windows98_positive_verified':False}
    try:
        source = out/'source'
        for name, data in raw_sources.items():
            p = source/name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        sys.path.insert(0, str(source/'shizukudos/tools'))
        # Each imported ordinary builder resolves REPO/SHZ/BUILD inside this snapshot.
        sys.modules.pop('shzlib', None)
        kbuild = load(source/'shizukudos/kbuild.py', 'native_foundation_kbuild')
        extra = [kbuild.SHZ/'win64/pe_parse.c', *sorted((source/'shizukufs/v1/libsfs').glob('*.c'))]
        kernel = kbuild.build_kernel('kernel64', 'kernel64', kbuild.K64_FLAGS,
                                    'elf64', 'elf_x86_64', 'KERNEL64.BIN', extra_c=extra)
        assert all('-DSHZ_STANDALONE' not in [str(x) for x in c] for c in kernel['commands'])
        build = source/'build/shizukudos'
        (build/'win64').mkdir(parents=True)
        # Use the documented ordinary archive format; byte-for-byte retained providers and fixture.
        header = 16 + 136*len(tiny)
        entries, payload = [], bytearray()
        for name, data in tiny:
            while (header+len(payload)) % 16: payload.append(0)
            entries.append((name, header+len(payload), len(data)))
            payload += data
        packed = bytearray(b'SHZARC01'+struct.pack('<II',len(tiny),0))
        for name, offset, size in entries:
            packed += struct.pack('<120sQQ',name.encode('ascii'),offset,size)
        packed += payload
        (build/'win64/WIN64.IMG').write_bytes(packed)
        supervisor = load(source/'shizukudos/supervisor/build.py', 'native_foundation_supervisor')
        supervisor.OUT.mkdir(parents=True)
        supervisor.build_vbios()
        payload, payload_commands = supervisor.build_payload()
        loader, loader_command = supervisor.build_loader(payload)
        owned_disk = out/'dos-input.img'
        owned_disk.write_bytes(disk)
        esp = supervisor.build_esp(loader, owned_disk)
        env = {'MTOOLS_SKIP_CHECK':'1','PATH':'/usr/bin:/bin'}
        supervisor.run(['mmd','-i',esp,'::/EFI/SHIZUKU'],env=env)
        policy = out/'BOOT.INI'
        policy.write_bytes(b'mode=supervisor\n')
        supervisor.run(['mcopy','-i',esp,policy,'::/EFI/SHIZUKU/BOOT.INI'],env=env)
        fsck = subprocess.run(['fsck.vfat','-n',str(esp)],capture_output=True,text=True,timeout=30)
        (out/'esp-fsck.log').write_text(fsck.stdout+fsck.stderr)
        if fsck.returncode: raise RuntimeError('owned ESP filesystem verification failed')
        # Firmware variables are a separate owned writable file; source template stays immutable.
        (out/'OVMF_VARS.fd').write_bytes(var_data)
        if any(digest((ROOT/name).read_bytes()) != pin for name,pin in pins.items()):
            raise RuntimeError('source drift during foundation build')
        verified_input(args.runtime,args.runtime_sha256)
        verified_input(args.dos_disk,DOS_SHA)
        verified_input(args.ovmf_vars, var_hash, 4 << 20)
        proof.update(status='PASS_NATIVE_FOUNDATION_BUILD_NOT_RUN',runtime_imports=import_count,
                     commands={'kernel':[[str(x) for x in c] for c in kernel['commands']],
                               'payload':[[str(x) for x in c] for c in payload_commands],
                               'loader':[str(x) for x in loader_command]},
                     selected_runtime={name:digest(data) for name,data in tiny},
                     artifacts={str(p.relative_to(out)):digest(p.read_bytes()) for p in
                                (kernel['bin'],loader,supervisor.OUT/'payload.bin',esp,build/'win64/WIN64.IMG',out/'OVMF_VARS.fd')},
                     standalone_compiled=False,source_before_after_match=True,shared_build_output_written=False,
                     expected_actual_gate='Real VMX/EPT native K64, T_HELLO twice actual exit7/evidence19–21/self-test failures0; no Win98 peer yet.')
    except BaseException as exc:
        proof.update(status='FAIL_BUILD_PRESERVED',error=f'{type(exc).__name__}: {exc}')
        raise
    finally:
        (out/'foundation-build-receipt.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(json.dumps({'status':proof['status'],'kernel_sha256':kernel['sha256'],'receipt':str(out/'foundation-build-receipt.json')}))


if __name__ == '__main__':
    main()
