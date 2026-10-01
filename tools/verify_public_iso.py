#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent read-only public ISO/source gate. No VM or completion claim."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import subprocess
import tarfile


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def safe_name(name):
    p = PurePosixPath(name)
    if p.is_absolute() or not p.parts or '..' in p.parts or '\\' in name or '\0' in name:
        raise ValueError('Unsafe archive/member path')
    return p


def source_members(raw):
    rows = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:*') as archive:
        for member in archive:
            p = safe_name(member.name)
            if member.isdir():
                continue
            if not member.isfile() or member.size > 16 * (1 << 20):
                raise ValueError('Source archive contains a link/special/oversized member')
            if any(part in ('build', '.git', '__pycache__', '.playwright-cli') for part in p.parts) or any(
                    p.parts[i:i + 2] in (('vm', 'media'), ('vm', 'disks'), ('vm', 'screenshots'))
                    for i in range(len(p.parts) - 1)):
                raise ValueError('Source archive contains a generated/private directory')
            relative = '/'.join(p.parts[1:])
            if not relative or relative in rows:
                raise ValueError('Source archive duplicate or unrooted file')
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError('Unreadable source member')
            data = stream.read()
            if len(data) != member.size:
                raise ValueError('Short source member')
            rows[relative] = {'sha256': digest(data), 'bytes': len(data)}
    if not rows:
        raise ValueError('Empty source archive')
    return rows


def public_inventory(names):
    for name in names:
        p = safe_name(name)
        upper = tuple(x.upper() for x in p.parts)
        if 'WIN98' in upper or p.suffix.lower() in ('.cab', '.qcow2', '.vmdk', '.vdi', '.key'):
            raise ValueError('Private Windows media/publisher/VM member in public ISO')
        if p.name.upper() in ('IO.SYS', 'MSDOS.SYS', 'WIN.COM', 'WIN386.SWP', 'VMM32.VXD',
                              'KERNEL386.EXE', 'SETUPX.DLL', 'STEAM.EXE', 'CHROME.EXE',
                              'FIREFOX.EXE', 'LEGCORD.EXE', 'SOFFICE.EXE', 'SOFFICE.BIN'):
            raise ValueError('Licensed OS/publisher binary in public ISO')


def physical_catalog(iso):
    size = iso.stat().st_size
    with iso.open('rb') as stream:
        head = stream.read(64 * 2048)
        if len(head) < 18 * 2048 or head[510:512] != b'\x55\xaa':
            raise ValueError('Missing hybrid MBR signature')
        if head[512:520] != b'EFI PART':
            raise ValueError('Missing hybrid GPT header')
        pvd = head[16 * 2048:17 * 2048]
        if pvd[:7] != b'\x01CD001\x01':
            raise ValueError('Missing ISO9660 primary descriptor')
        sectors = struct.unpack_from('<I', pvd, 80)[0]
        if sectors * 2048 != size:
            raise ValueError('ISO volume length differs from actual bytes')
        catalog_lba = None
        for sector in range(16, 64):
            block = head[sector * 2048:(sector + 1) * 2048]
            if block[:7] == b'\x00CD001\x01' and block[7:39].rstrip(b'\0 ') == b'EL TORITO SPECIFICATION':
                catalog_lba = struct.unpack_from('<I', block, 71)[0]
                break
        if catalog_lba is None or not 0 < catalog_lba < sectors:
            raise ValueError('Missing bounded El Torito catalog')
        stream.seek(catalog_lba * 2048)
        catalog = stream.read(2048)
    if len(catalog) != 2048 or catalog[0] != 1 or catalog[30:32] != b'\x55\xaa' or sum(struct.unpack('<16H', catalog[:32])) & 0xffff:
        raise ValueError('Invalid El Torito validation checksum')
    if catalog[32] != 0x88 or catalog[33] != 0 or not 0 < struct.unpack_from('<I', catalog, 40)[0] < sectors:
        raise ValueError('Missing bootable no-emulation BIOS entry')
    efi = None
    cursor = 64
    while cursor + 64 <= len(catalog) and catalog[cursor] in (0x90, 0x91):
        count = struct.unpack_from('<H', catalog, cursor + 2)[0]
        if not count or cursor + 32 + count * 32 > len(catalog):
            raise ValueError('Invalid catalog section length')
        if catalog[cursor + 1] == 0xef:
            entry = catalog[cursor + 32:cursor + 64]
            if entry[0] != 0x88 or entry[1] != 0 or not 0 < struct.unpack_from('<I', entry, 8)[0] < sectors:
                raise ValueError('Missing bootable no-emulation UEFI entry')
            efi = struct.unpack_from('<I', entry, 8)[0]
        cursor += 32 + count * 32
    if efi is None:
        raise ValueError('Missing UEFI catalog section')
    return {'catalog_lba': catalog_lba, 'uefi_image_lba': efi, 'volume_sectors': sectors}


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=180).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--iso', type=Path, required=True)
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    iso, source_root, out = args.iso.resolve(strict=True), args.source_root.resolve(strict=True), args.out.resolve()
    if out.exists() or not re.fullmatch(r'[0-9a-f]{40}', args.source_commit):
        parser.error('Fresh owned output and exact source commit required')
    if command(['git', '-C', str(source_root), 'rev-parse', 'HEAD']).strip() != args.source_commit:
        parser.error('Source checkout is not the declared final commit')
    if command(['git', '-C', str(source_root), 'status', '--porcelain', '--untracked-files=no']).strip():
        parser.error('Tracked source has uncommitted changes')
    proof = json.loads(args.receipt.read_text())
    if proof.get('private') is not False or proof.get('boot_profile') != 'desktop' or not proof.get('setup', {}).get('present'):
        parser.error('Public desktop ISO with actual carried installer required')
    before = file_digest(iso)
    if proof.get('sha256') != before or proof.get('bytes') != iso.stat().st_size:
        parser.error('Final ISO bytes differ from builder receipt')
    if proof.get('git', {}).get('revision') != args.source_commit or proof.get('git', {}).get('dirty') is not False:
        parser.error('Builder did not bind a clean final source commit')
    if shutil.disk_usage(out.parent).free < 17 * (1 << 30) + iso.stat().st_size:
        parser.error('17GiB reserve plus independent readback budget unavailable')
    catalog = physical_catalog(iso)
    listing = command(['xorriso', '-indev', str(iso), '-find', '/', '-type', 'f'])
    names = [shlex.split(line)[0].removeprefix('/') for line in listing.splitlines() if line.startswith("'/")]
    if len(set(names)) != len(names):
        raise ValueError('Duplicate ISO inventory')
    public_inventory(names)
    required = {'SHZ/K64/BOOT.ELF', 'SHZ/K64/KERNEL64S.BIN', 'SHZ/K64/WIN64.IMG',
                'SHZ/SETUP/INSTALL.IMG', 'SHZ/SETUP/MANIFEST.JSON',
                'ShizukuDOS10/efiboot.img', 'ShizukuDOS10/GPL-NOTICE.TXT',
                'ShizukuDOS10/SOURCE/shizukudos-source.tar.gz',
                'ShizukuDOS10/SOURCE/upstream-manifest.json',
                'ShizukuDOS10/LICENSES/Shizuku-LICENSE-GPL-2.0.txt'}
    if not required <= set(names):
        raise ValueError('Missing desktop/installer/source/license payload')
    out.mkdir(parents=True)
    picked = ['ShizukuDOS10/SOURCE/shizukudos-source.tar.gz',
              'ShizukuDOS10/receipts/kernels-build-result.json',
              'ShizukuDOS10/receipts/win64-build-result.json',
              'SHZ/K64/KERNEL64S.BIN', 'SHZ/K64/WIN64.IMG', 'SHZ/SETUP/MANIFEST.JSON']
    extract = ['xorriso', '-osirrox', 'on', '-indev', str(iso)]
    for name in picked:
        if name not in names:
            raise ValueError('Missing source-bound kernel/runtime receipt')
        extract += ['-extract', '/' + name, str(out / Path(name).name)]
    command(extract)
    sources = source_members((out / 'shizukudos-source.tar.gz').read_bytes())
    minimum = {'LICENSE', 'platform/build.py', 'ntwrapper/core.c', 'ntwrapper/vxd/build.py',
               'ntwin32/runtime.c', 'ntwin32/prepare.py', 'ntwddm/src/ntwddm.c',
               'ntwddm/win98/build.py', 'shizukudos/kbuild.py', 'shizukudos/win64/build.py',
               'shizukudos/supervisor/build.py', 'shizukudos/install/mkpayload.py',
               'tools/build_shizuku_se_iso.py', 'tools/shizuku_se_media.py'}
    if not minimum <= sources.keys():
        raise ValueError('Corresponding source lacks a carried GPL component producer')
    tracked = set(command(['git', '-C', str(source_root), 'ls-files', '--recurse-submodules', '-z']).split('\0'))
    if not sources.keys() <= tracked:
        raise ValueError('Carried source includes files absent from the committed source snapshot')
    for name, record in sources.items():
        path = source_root / name
        if not path.is_file() or file_digest(path) != record['sha256']:
            raise ValueError('Carried project source differs from final source: ' + name)
    kernels = json.loads((out / 'kernels-build-result.json').read_text())
    runtime = json.loads((out / 'win64-build-result.json').read_text())
    consumed = {}
    for receipt in (kernels, runtime):
        pins = receipt.get('sources_sha256')
        if not isinstance(pins, dict) or not pins:
            raise ValueError('Fresh source-pinned build receipt required')
        for name, pin in pins.items():
            if name not in sources or sources[name]['sha256'] != pin:
                raise ValueError('A consumed source is absent or differs: ' + name)
            consumed[name] = pin
    if file_digest(out / 'KERNEL64S.BIN') != kernels['kernels']['kernel64-standalone']['sha256']:
        raise ValueError('Carried kernel differs from fresh build receipt')
    if file_digest(out / 'WIN64.IMG') != runtime['archive']['sha256']:
        raise ValueError('Carried runtime differs from fresh build receipt')
    if file_digest(iso) != before:
        raise ValueError('Final ISO changed during independent readback')
    result = {'status': 'PASS_STATIC_PUBLIC_ISO_FINAL_SOURCE_BOUND', 'iso': str(iso),
              'bytes': iso.stat().st_size, 'sha256': before, 'source_commit': args.source_commit,
              'catalog': catalog, 'payload_files': len(names), 'project_source_files': len(sources),
              'actual_consumed_source_pins': len(consumed), 'desktop': True, 'installer_carried': True,
              'Windows98_media_or_publisher_binary_in_inventory': False,
              'VM_executed': False, 'boot_verified': False, 'modern_app_complete': False,
              'verifier_sha256': file_digest(Path(__file__))}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
