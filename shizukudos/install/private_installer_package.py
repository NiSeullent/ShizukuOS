#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Private build-owned installer archive, never a runtime authority issuer.

The only production entry builds through independently anchored admission.
A saved JSON receipt cannot mint custody. Original target WIN64/SIM inputs
remain leased and unchanged. This produces inputs, not an ISO or boot proof.
"""
from argparse import Namespace
from contextlib import ExitStack
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import struct

import native_release_admission as admission

MIB = 1 << 20
LOAD_MAX = 64 * MIB
RAM_MAX = 256 * MIB
INITRD_PA = 32 * MIB
PAGE = 4096
CHUNK = 1 << 20
MANIFEST = '\\SHZ\\SETUP\\NATIVE\\MANIFEST.JSON'
SIM = '\\SHZ\\SETUP\\NATIVE\\ESP.SIM'
SETUP = '\\SHZ\\SETUP\\SHZSETUP.EXE'
HELLO = '\\SHZ\\TESTS\\T_HELLO.EXE'



def need(value, message):
    if not value:
        raise ValueError(message)


def align(value, unit=16):
    return (value + unit - 1) // unit * unit


def archive_table(read, size):
    """Read bounded SHZARC01 tables; preserve packer's case, reject aliases."""
    header = read(0, 16)
    need(len(header) == 16 and header[:8] == b'SHZARC01', 'archive magic differs')
    count, reserved = struct.unpack('<II', header[8:])
    floor = 16 + 136 * count
    need(reserved == 0 and 0 < count <= 4096 and floor <= size, 'archive header bounds')
    table = read(16, 136 * count)
    rows, seen, ranges = [], set(), []
    for index in range(count):
        raw = table[136*index:136*(index+1)]
        field = raw[:120]
        end = field.find(b'\0')
        need(0 < end < 120 and not any(field[end:]), 'archive path termination')
        try:
            path = field[:end].decode('ascii')
        except UnicodeDecodeError as error:
            raise ValueError('archive path ASCII required') from error
        canonical = path.replace('/', '\\').upper()
        parts = canonical.split('\\')
        need(canonical.startswith('\\') and len(parts) > 1 and
             all(part not in ('', '.', '..') and ':' not in part for part in parts[1:]) and
             all(32 < ord(char) < 127 for char in canonical), 'archive path grammar')
        need(canonical not in seen, 'archive path alias')
        seen.add(canonical)
        offset, length = struct.unpack('<QQ', raw[120:])
        need(floor <= offset <= size and offset % 16 == 0 and length <= size-offset,
             'archive member extent')
        if length:
            ranges.append((offset, offset+length))
        rows.append((path, offset, length))
    ranges.sort()
    need(all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])),
         'archive member overlap')
    return rows


def plan(custody):
    runtime = custody.pin('runtime')
    rows = archive_table(lambda offset, size: custody.read('runtime', offset, size), runtime['bytes'])
    names = {path.replace('/', '\\').upper() for path, _, _ in rows}
    need(SETUP in names and HELLO in names and '\\SHZ\\SYS64\\NTDLL.DLL' in names and
         '\\SHZ\\SYS64\\KERNEL32.DLL' in names, 'actual installer runtime members absent')
    need(not any(name.startswith('\\SHZ\\SETUP\\NATIVE\\') or name.endswith('\\INSTALL.IMG')
                 for name in names), 'recursive/private installer base forbidden')
    manifest, sim = custody.pin('manifest'), custody.pin('sim')
    need(0 < manifest['bytes'] <= 4*MIB and 0 < sim['bytes'] <= admission.MAX_ENCODED,
         'sealed source capability exceeded')
    members = [(path, 'runtime', offset, length) for path, offset, length in rows]
    members += [(MANIFEST, 'manifest', 0, manifest['bytes']), (SIM, 'sim', 0, sim['bytes'])]
    need(len(members) <= 4096, 'installer archive member count exceeded')
    at = 16 + 136*len(members)
    layout = []
    for path, role, source_offset, length in members:
        at = align(at)
        layout.append((path, role, source_offset, at, length))
        at += length
    snapshots = align(manifest['bytes'], PAGE) + align(sim['bytes'], PAGE)
    # Loader/initrd ends at 32MiB+archive. Reserve a further 32MiB for PMM
    # allocations/OS pages; kernel+12MiB heap are below the initrd. This is a
    # packaging headroom guard, not proof that a firmware memory map is usable.
    metadata = (16 + 136*len(members) +
                ((manifest['bytes']+PAGE-1)//PAGE + (sim['bytes']+PAGE-1)//PAGE)*8)
    need(metadata <= 8*MIB, 'snapshot metadata exceeds bounded heap headroom')
    minimum = align(INITRD_PA + at, PAGE) + snapshots + 32*MIB
    need(at <= LOAD_MAX, 'installer archive exceeds actual 64MiB loader/media limit')
    need(minimum <= RAM_MAX, 'installer archive and sealed snapshots exceed loader RAM budget')
    custody.check()
    return layout, {'archive_bytes': at, 'sealed_snapshot_bytes': snapshots, 'snapshot_and_origin_metadata_bytes': metadata,
                    'fixed_kernel_heap_bytes': 12*MIB, 'OS_PMM_headroom_bytes': 32*MIB,
                    'minimum_contiguous_ram_bytes_with_headroom': minimum,
                    'loader_ram_limit_bytes': RAM_MAX, 'loader_archive_limit_bytes': LOAD_MAX,
                    'firmware_memory_map_verified': False}


def write_all(fd, raw):
    while raw:
        written = os.write(fd, raw)
        need(written > 0, 'short private output write')
        raw = raw[written:]


def _copy_archive(custody, output):
    """Internal streaming primitive; admission is checked by finalize()."""
    layout, budget = plan(custody)  # Fail before creating files on size/grammar.
    output = Path(output)
    need(output.is_absolute() and output.resolve() == output and not output.exists() and
         output.parent.is_dir() and not any((p/'.git').exists() for p in output.parents),
         'fresh canonical private output outside Git required')
    custody.finish()
    output.mkdir(mode=0o700)
    owned = (output.stat().st_dev, output.stat().st_ino)
    def guard():
        state = output.stat()
        need((state.st_dev, state.st_ino) == owned and state.st_uid == os.getuid() and
             stat.S_IMODE(state.st_mode) == 0o700 and not output.is_symlink(),
             'private package directory custody changed')
    custody.guard(guard)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        guard()
        state = os.fstat(directory)
        need((state.st_dev, state.st_ino) == owned, 'private writer directory differs')
        fd = os.open('INSTALL.IMG', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW |
                     os.O_CLOEXEC, 0o600, dir_fd=directory)
        try:
            header = b'SHZARC01' + struct.pack('<II', len(layout), 0)
            for path, _, _, at, size in layout:
                raw = path.encode('ascii')
                header += raw.ljust(120, b'\0') + struct.pack('<QQ', at, size)
            write_all(fd, header)
            for _, role, offset, at, size in layout:
                custody.check()
                write_all(fd, b'\0'*(at-os.lseek(fd, 0, os.SEEK_CUR)))
                copied = hashlib.sha256()
                for delta in range(0, size, CHUNK):
                    raw = custody.read(role, offset+delta, min(CHUNK, size-delta))
                    copied.update(raw)
                    write_all(fd, raw)
                if role != 'runtime':
                    need(copied.hexdigest() == custody.pin(role)['sha256'], 'sealed input copy SHA differs')
            os.fsync(fd)
            state = os.fstat(fd)
            need(state.st_size == budget['archive_bytes'], 'private archive written extent differs')
            readback = archive_table(lambda off, size: os.pread(fd, size, off), state.st_size)
            need(readback == [(path, at, size) for path, _, _, at, size in layout],
                 'private archive node table readback differs')
            for (_, role, offset, at, size) in layout:
                for delta in range(0, size, CHUNK):
                    amount = min(CHUNK, size-delta)
                    need(os.pread(fd, amount, at+delta) == custody.read(role, offset+delta, amount),
                         'private archive member full readback differs')
            sha = hashlib.sha256()
            for off in range(0, state.st_size, CHUNK):
                custody.check()
                sha.update(os.pread(fd, min(CHUNK, state.st_size-off), off))
            row = {'path': str(output/'INSTALL.IMG'), 'bytes': state.st_size, 'sha256': sha.hexdigest()}
            # identity has the same tuple definition as the actual ingester.
            identity = (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns)
        finally:
            os.close(fd)
        os.fsync(directory)
    finally:
        os.close(directory)
    custody.retain_output(row, identity)
    custody.finish()
    return {'schema': 'PRIVATE_INSTALLER_INPUTS_PACKAGED_NOT_BOOTED',
            'private': True, 'public_artifact': False, 'archive': row, 'memory_budget': budget,
            'native_paths': [MANIFEST, SIM], 'target_runtime_unchanged': custody.pin('runtime'),
            'Windows98_boot_verified': False, 'installation_verified': False,
            'ISO_generated': False, 'boot_profile': 'direct-native-installer-gui',
            'required_iso_archive_path': 'SHZ/SETUP/INSTALL.IMG'}


def finalize(release, build, results):
    custody = release.get('custody') if type(release) is dict else None
    need(type(custody) is admission.BuildCustody and custody._active,
         'actual generator-owned live build custody required; receipt JSON is not authority')
    custody.check()
    need(release['manifest'] == custody.pin('manifest') and release['sim'] == custody.pin('sim'),
         'compiled release source differs from package source')
    result = _copy_archive(custody, Path(build)/'private-installer')
    result['installer_kernel'] = dict(results['kernel64-standalone'])
    # Require the exact K64S/stub bytes produced in this held compiler run.
    for name, expected, filename in (('kernel', result['installer_kernel']['sha256'], 'KERNEL64S.BIN'),
                                     ('stub', result['installer_kernel']['stub_sha256'], 'boot.elf')):
        path = Path(build)/'kernel64s'/filename
        with path.open('rb') as stream:
            state = os.fstat(stream.fileno())
            sha = hashlib.file_digest(stream, 'sha256').hexdigest()
        need(sha == expected, 'actual private installer '+name+' differs')
        row = {'path': str(path), 'bytes': state.st_size, 'sha256': sha}
        identity = (state.st_dev, state.st_ino, state.st_size, state.st_mtime_ns, state.st_ctime_ns)
        custody.retain_output(row, identity)
        result['installer_'+name+'_pin'] = row
    custody.finish()
    return result


def build_private_installer(manifest, output):
    """Usable build API. No caller supplied approval or pre-generated receipt."""
    need(admission.policy.NATIVE_SOURCE_MAP_SHA is not None and
         admission.policy.NATIVE_ARTIFACTS is not None,
         'independently approved native producer anchors absent; packaging refused')
    source = Path(__file__).resolve().parents[1]/'kbuild.py'
    spec = importlib.util.spec_from_file_location('private_installer_kbuild', source)
    kbuild = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(kbuild)
    with ExitStack() as stack:
        kbuild.build_all(Namespace(out=Path(output), native_release_manifest=Path(manifest)),
                         stack, private_finalize=finalize)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--native-release-manifest', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build_private_installer(args.native_release_manifest, args.out)


if __name__ == '__main__':
    main()
