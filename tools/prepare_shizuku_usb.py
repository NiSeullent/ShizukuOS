#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare ordinary USB file folders, never format/write a device or install Windows.

ShizukuDOS replaces MS-DOS for Windows 98; Kernel32/Kernel64/Supervisor serve
that Windows 98 integration. The current desktop is a component test profile.

public: copy a separately source-verified public desktop ISO and its EFI files.
add-win98: create a separate private copy carrying the user's own untouched ISO.
private-command: print the existing builder command; do not execute it.
private-iso: explicitly run that builder with your own validated media.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shlex
import shutil
import stat
import struct
import subprocess
import tempfile
import zipfile

FAT32_MAX = (1 << 32) - 1
MANIFEST = 'SHIZUKU-USB.json'
ISO_GATE = 'PASS_STATIC_PUBLIC_ISO_FINAL_SOURCE_BOUND'
MS_FILES = {'IO.SYS', 'MSDOS.SYS', 'COMMAND.COM'}
REQUIRED_PUBLIC = {
    'NOMSBASE.TXT', 'ShizukuDOS10/efiboot.img',
    'ShizukuDOS10/GPL-NOTICE.TXT',
    'ShizukuDOS10/SOURCE/shizukudos-source.tar.gz',
    'ShizukuDOS10/SOURCE/upstream-manifest.json',
    'ShizukuDOS10/LICENSES/Shizuku-LICENSE-GPL-2.0.txt',
    'SHZ/SETUP/INSTALL.IMG', 'SHZ/SETUP/MANIFEST.JSON',
    'SHZ/K64/BOOT.ELF', 'SHZ/K64/KERNEL64S.BIN', 'SHZ/K64/WIN64.IMG',
}
REQUIRED_EFI = {'EFI/BOOT/BOOTX64.EFI', 'EFI/SHIZUKU/BOOT.INI',
                'SHZDOS/KERNEL64.INI', 'SHZDOS/KERNEL64.BIN', 'SHZDOS/WIN64.IMG'}


def plain_path(value):
    path = Path(value).expanduser().absolute()
    for part in (path, *path.parents):
        if part.is_symlink():
            raise ValueError('Symbolic-link paths are not accepted')
    if path == Path('/dev') or any(p == Path('/dev') for p in path.parents):
        raise ValueError('Device paths are not accepted')
    canonical = path.resolve(strict=False)
    if any(canonical == root or root in canonical.parents for root in map(Path, ('/dev', '/proc', '/sys'))):
        raise ValueError('Device and kernel virtual-filesystem paths are not accepted')
    return canonical


def regular_file(value):
    path = plain_path(value)
    if not stat.S_ISREG(path.stat().st_mode):
        raise ValueError('An ordinary file is required; devices are refused')
    return path


def fresh_path(value):
    path = plain_path(value)
    if path.exists() or not path.parent.is_dir():
        raise ValueError('Output must be new, with an existing ordinary parent directory')
    return path


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def record(path):
    regular_file(path)
    size = path.stat().st_size
    if size > FAT32_MAX:
        raise ValueError('A carried file exceeds the FAT32 4 GiB minus 1 byte limit')
    return {'bytes': size, 'sha256': file_hash(path)}


def member_name(name):
    path = PurePosixPath(name)
    if (path.is_absolute() or not path.parts or '..' in path.parts or '\\' in name
            or any(ord(c) < 32 for c in name) or any(c in name for c in ':<>"|?*')
            or any(len(p.encode('utf-16le')) > 510 for p in path.parts)
            or any(p.endswith(('.', ' ')) for p in path.parts)):
        raise ValueError('Unsafe or FAT-incompatible member name')
    return path.as_posix()


def public_names(names):
    folded = set()
    for name in names:
        name = member_name(name)
        key = name.casefold()
        if key in folded:
            raise ValueError('Duplicate or case-colliding USB member')
        folded.add(key)
        path = PurePosixPath(name)
        parts = {p.upper() for p in path.parts}
        if (parts & {'WIN98', 'PRIVATE'} or path.suffix.lower() in
                {'.cab', '.iso', '.qcow2', '.vmdk', '.vdi', '.key'} or
                path.name.upper() in MS_FILES | {
                    'MSBASE.TXT', 'WIN98-MEDIA.JSON', 'PERSONAL-MEDIA.TXT',
                    'WIN.COM', 'WIN386.SWP', 'VMM32.VXD',
                    'KERNEL386.EXE', 'SETUPX.DLL', 'CHROME.EXE', 'STEAM.EXE',
                    'FIREFOX.EXE', 'LEGCORD.EXE', 'SOFFICE.EXE', 'SOFFICE.BIN'}):
            raise ValueError('Private media or publisher executable in public files')


def command(args, file_limit=None):
    limit = None if file_limit is None else lambda: resource.setrlimit(
        resource.RLIMIT_FSIZE, (file_limit, file_limit))
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, preexec_fn=limit)
    if result.returncode:
        raise ValueError(f'{Path(args[0]).name} failed: {result.stderr[-1500:]}')
    return result.stdout


def iso_files(iso):
    listing = command(['xorriso', '-indev', str(iso), '-find', '/', '-type', 'f'])
    names = []
    for line in listing.splitlines():
        if not line.startswith("'/"):
            continue
        fields = shlex.split(line)
        if len(fields) != 1:
            raise ValueError('Unexpected ISO member listing')
        names.append(member_name(fields[0].removeprefix('/')))
    if not names or len(names) > 8192 or len(set(names)) != len(names):
        raise ValueError('Empty or duplicate ISO file inventory')
    return sorted(names)


def extract(iso, names, destination, file_limit=None):
    limit = min(FAT32_MAX, iso.stat().st_size) if file_limit is None else file_limit
    for start in range(0, len(names), 50):
        args = ['xorriso', '-osirrox', 'on:auto_chmod_on', '-indev', str(iso)]
        for name in names[start:start + 50]:
            target = destination / member_name(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            args += ['-extract', '/' + name, str(target)]
        command(args, file_limit=limit)
    for name in names:
        regular_file(destination / name)


def json_read(path):
    path = regular_file(path)
    if path.stat().st_size > 16 << 20:
        raise ValueError('Metadata exceeds its 16 MiB limit')
    return json.loads(path.read_text(encoding='utf-8'))


def json_write(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + '\n', encoding='utf-8')


@contextmanager
def fresh_directory(output):
    output = fresh_path(output)
    stage = Path(tempfile.mkdtemp(prefix='.' + output.name + '-prepare-', dir=output.parent))
    try:
        yield stage
        if output.exists():
            raise ValueError('Output appeared while preparing; refusing overwrite')
        stage.rename(output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def folder_records(folder):
    rows = {}
    for path in sorted(folder.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symbolic link in USB files')
        if path.is_dir():
            continue
        name = member_name(path.relative_to(folder).as_posix())
        if name != MANIFEST:
            rows[name] = record(path)
    return rows


def verify_bundle(folder):
    folder = plain_path(folder)
    if not folder.is_dir():
        raise ValueError('An ordinary prepared public folder is required')
    receipt = json_read(folder / MANIFEST)
    if receipt.get('private') is not False or receipt.get('kind') != 'shizuku-public-usb-files-v1':
        raise ValueError('An unmodified public USB files bundle is required')
    actual = folder_records(folder)
    public_names(actual)
    if actual != receipt.get('files') or not REQUIRED_PUBLIC | REQUIRED_EFI <= actual.keys():
        raise ValueError('Public bundle differs from its complete file manifest')
    return folder, receipt


def prepare_public(args):
    iso = regular_file(args.iso)
    proof, gate = json_read(args.receipt), json_read(args.verification)
    receipt_pin = file_hash(regular_file(args.receipt))
    gate_pin = file_hash(regular_file(args.verification))
    pin = {'bytes': iso.stat().st_size, 'sha256': file_hash(iso)}
    revision = proof.get('git', {}).get('revision')
    if (proof.get('private') is not False or proof.get('boot_profile') != 'desktop'
            or proof.get('setup', {}).get('present') is not True
            or proof.get('git', {}).get('dirty') is not False
            or not isinstance(revision, str) or not re.fullmatch(r'[0-9a-f]{40}', revision)
            or any(proof.get(k) != v or gate.get(k) != v for k, v in pin.items())
            or gate.get('status') != ISO_GATE or gate.get('source_commit') != revision
            or gate.get('Windows98_media_or_publisher_binary_in_inventory') is not False):
        raise ValueError('Matching public desktop builder receipt and final-source ISO verification required')
    names = iso_files(iso)
    public_names(names)
    if not REQUIRED_PUBLIC <= set(names):
        raise ValueError('ISO lacks public installer, matching source or licenses')
    efi = proof.get('efi_members')
    if not isinstance(efi, dict) or not REQUIRED_EFI <= efi.keys():
        raise ValueError('Desktop EFI member receipt is missing')
    public_names(efi)
    if any(not (n.startswith('EFI/') or n.startswith('SHZDOS/')) for n in efi):
        raise ValueError('Unexpected EFI root member')
    if any(not isinstance(r, dict) or set(r) != {'bytes', 'sha256'}
           or not isinstance(r['bytes'], int) or not 0 <= r['bytes'] <= FAT32_MAX
           or not isinstance(r['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', r['sha256'])
           for r in efi.values()):
        raise ValueError('Malformed or oversized EFI member receipt')
    additions = {'START-KO.txt', 'START-EN.txt', 'STUFF/README.txt'}
    # ISO/EFI duplicate names are accepted only when their complete bytes agree.
    public_names(set(names) | set(efi) | additions)
    if (additions | {MANIFEST}) & set(names):
        raise ValueError('Help file collides with an ISO member')
    if 'HASHES.TXT' not in names:
        raise ValueError('ISO lacks the full builder payload hash manifest')
    if shutil.disk_usage(fresh_path(args.output).parent).free < pin['bytes'] * (6 if args.zip else 3) + (256 << 20):
        raise ValueError('Insufficient space for bounded public ISO and EFI readback')
    if args.zip:
        fresh_path(args.zip)
    with fresh_directory(args.output) as stage:
        extract(iso, ['HASHES.TXT'], stage, file_limit=1 << 20)
        payload = {}
        for line in (stage / 'HASHES.TXT').read_text(encoding='ascii').splitlines()[1:]:
            fields = line.split(None, 2)
            if len(fields) != 3 or not re.fullmatch(r'[0-9a-f]{64}', fields[0]):
                raise ValueError('Malformed public ISO payload hash manifest')
            sha, size, name = fields
            name = member_name(name)
            size = int(size)
            if name in payload or size < 0 or size > FAT32_MAX:
                raise ValueError('Duplicate or oversized public payload member')
            payload[name] = {'sha256': sha, 'bytes': size}
        if set(payload) != set(names) - {'HASHES.TXT'}:
            raise ValueError('ISO inventory is not closed by the complete builder payload manifest')
        if sum(r['bytes'] for r in payload.values()) + sum(r['bytes'] for r in efi.values()) > pin['bytes'] * 3:
            raise ValueError('Public extraction exceeds its input-relative byte budget')
        for start in range(0, len(payload), 50):
            batch = sorted(payload)[start:start + 50]
            extract(iso, batch, stage, file_limit=max(1, max(payload[n]['bytes'] for n in batch)))
            for name in batch:
                if record(stage / name) != payload[name]:
                    raise ValueError('Carried ISO file differs from its byte/SHA manifest')
        image = stage / 'ShizukuDOS10/efiboot.img'
        with tempfile.TemporaryDirectory(prefix='.shizuku-efi-', dir=stage.parent) as tmp:
            for name, expected in sorted(efi.items()):
                target = Path(tmp) / member_name(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                command(['mcopy', '-i', str(image), '::/' + name, str(target)], file_limit=max(1, expected['bytes']))
                if record(target) != expected:
                    raise ValueError('EFI image differs from builder member receipt')
                carried = stage / name
                if carried.exists():
                    if record(carried) != expected:
                        raise ValueError('ISO and EFI image disagree on a USB-root file')
                else:
                    carried.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(target, carried)
        if (stage / 'SHZDOS/KERNEL64.INI').read_bytes().strip() != b'cmdline = shz.desktop':
            raise ValueError('EFI payload does not select the desktop profile')
        (stage / 'START-KO.txt').write_text(
            'Windows 98 Shizuku Modern Edition — USB 파일 묶음\n\n'
            '이미 준비된 FAT32 USB 루트로 모든 파일과 폴더를 복사하세요.\n'
            'x64 UEFI에서 Secure Boot를 끄고 USB의 EFI/BOOT/BOOTX64.EFI로 부팅합니다.\n'
            '목표는 ShizukuDOS가 MS-DOS를 대체하고 Windows 98을 부팅·확장하는 것입니다.\n'
            'Kernel32/64와 Supervisor도 Windows 98을 위한 구성요소입니다.\n'
            '현재 경로는 그 구성요소의 데스크톱 검증 프로필이며 Win98 설치기는 아닙니다.\n'
            '이 파일 복사만으로 BIOS USB가 부팅 가능해지지는 않습니다.\n'
            '개인 소유 WIN98.ISO는 개인용 USB 루트에 그대로 추가할 수 있습니다.\n'
            'ISO를 그 위치에 넣어도 Win98 설치가 시작되거나 완료되지 않습니다.\n'
            'Shizuku 설치 메뉴는 대상 디스크에 쓰므로 실제 설치 전 대상을 확인하세요.\n'
            '원본 DOS 매체 경로는 임시이며 대체 부팅·Windows 98 Setup 연결은 추가 구현 중입니다.\n'
            '실제 USB 부팅도 별도 검증 대상입니다.\n'
            '원본 Win98 UEFI/GOP·8개 최신 앱·가속·전체 드라이버는 계속 개발 중입니다.\n'
            '공개 소스: https://github.com/NiSeullent/Win98-Modern\n', encoding='utf-8')
        (stage / 'START-EN.txt').write_text(
            'Windows 98 Shizuku Modern Edition — USB files\n\n'
            'Copy every file/folder to the root of an already prepared FAT32 USB.\n'
            'Use x64 UEFI, Secure Boot off, and EFI/BOOT/BOOTX64.EFI.\n'
            'ShizukuDOS is intended to replace MS-DOS and boot/extend Windows 98.\n'
            'Kernel32, Kernel64 and Supervisor all serve that Windows 98 goal.\n'
            'This currently boots a component desktop test profile, not Windows 98 Setup.\n'
            'File copying alone does not install a BIOS USB bootloader.\n'
            'Your own WIN98.ISO may be carried unchanged at your personal USB root.\n'
            'Carrying it does not start or complete Windows 98 installation.\n'
            'Original DOS media is temporary; replacement boot/Win98 Setup integration is in development.\n'
            'Physical USB boot is a separate, unverified requirement.\n'
            'The Shizuku installer writes its selected disk; check that target.\n'
            'Native Win98 UEFI/GOP, eight modern apps, acceleration and complete\n'
            'drivers remain active goals. See project source/status for evidence.\n'
            'Source: https://github.com/NiSeullent/Win98-Modern\n', encoding='utf-8')
        (stage / 'STUFF').mkdir(exist_ok=True)
        (stage / 'STUFF/README.txt').write_text(
            'Existing payload paths are retained for the boot loaders.\n'
            'DRIVERS/: carried driver packages (availability is not a compatibility claim).\n'
            'SHZ/SETUP/: Shizuku component-profile installer. SHZSE/: legacy probe overlay.\n'
            'ShizukuDOS10/: boot components, build receipts, SOURCE/ and LICENSES/.\n'
            'Keep source/license folders with public redistributions.\n', encoding='utf-8')
        if file_hash(iso) != pin['sha256'] or iso.stat().st_size != pin['bytes']:
            raise ValueError('Input ISO changed during preparation')
        if (file_hash(regular_file(args.receipt)) != receipt_pin
                or file_hash(regular_file(args.verification)) != gate_pin):
            raise ValueError('Input receipt changed during preparation')
        result = {'kind': 'shizuku-public-usb-files-v1', 'private': False,
                  'input_iso': pin, 'source_commit': revision,
                  'builder_receipt_sha256': receipt_pin,
                  'source_verification_sha256': gate_pin,
                  'preparation_tool_sha256': file_hash(Path(__file__)),
                  'architecture_goal': {
                      'primary_os': 'Windows 98', 'MS_DOS_replacement': 'ShizukuDOS',
                      'Windows98_components': ['Kernel32', 'Kernel64', 'Supervisor'],
                      'current_desktop_scope': 'Windows98 component-validation profile',
                      'replacement_Windows98_boot_connection_complete': False},
                  'boot_profile': 'desktop', 'USB_boot_verified': False,
                  'Windows98_setup_boot_supported': False, 'Windows98_installed': False,
                  'modern_apps_complete': False, 'files': folder_records(stage)}
        json_write(stage / MANIFEST, result)
    if args.zip:
        archive = fresh_path(args.zip)
        try:
            with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as out:
                for path in sorted(Path(args.output).rglob('*')):
                    if path.is_file():
                        out.write(path, path.relative_to(args.output).as_posix())
        except BaseException:
            archive.unlink(missing_ok=True)
            raise
        print(json.dumps({'zip': str(archive), **record(archive)}))
    print(json.dumps({'output': str(Path(args.output).absolute()), 'files': len(result['files']),
                      'private': False, 'USB_boot_verified': False}))


def iso_identity(iso):
    with iso.open('rb') as stream:
        for sector in range(16, 256):
            stream.seek(sector * 2048)
            data = stream.read(2048)
            if len(data) != 2048 or data[1:6] != b'CD001' or data[6] != 1:
                break
            if data[0] == 1:
                little = struct.unpack_from('<I', data, 80)[0]
                big = struct.unpack_from('>I', data, 84)[0]
                if little != big or little * 2048 > iso.stat().st_size:
                    raise ValueError('Invalid ISO9660 volume length')
                fields = {'system_id': (8, 32), 'volume_id': (40, 32),
                          'publisher_id': (318, 128), 'application_id': (574, 128)}
                return {**{k: data[p:p + n].decode('ascii', errors='replace').strip()
                           for k, (p, n) in fields.items()}, 'volume_sectors': little,
                        'edition': 'not determined; labels are not an authenticity check'}
    raise ValueError('No valid ISO9660 primary descriptor')


def cabinet_members(path):
    # CFFILE names precede compressed payload; bounded metadata read suffices.
    with path.open('rb') as stream:
        data = stream.read(8 << 20)
    if len(data) < 36 or data[:4] != b'MSCF':
        return set()
    count = struct.unpack_from('<H', data, 28)[0]
    cursor = struct.unpack_from('<I', data, 16)[0]
    names = set()
    for _ in range(count):
        if cursor + 16 >= len(data):
            break
        end = data.find(b'\0', cursor + 16)
        if end < 0:
            break
        names.add(data[cursor + 16:end].decode('cp437').replace('\\', '/').rsplit('/', 1)[-1].upper())
        cursor = end + 1
    return names


def inspect_own_iso(iso, work):
    identity = iso_identity(iso)
    names = iso_files(iso)
    found = {Path(name).name.upper(): 'loose file' for name in names
             if Path(name).name.upper() in MS_FILES}
    cabs = [n for n in names if PurePosixPath(n).suffix.lower() == '.cab'
            and PurePosixPath(n).parent.name.upper() == 'WIN98']
    if not cabs:
        raise ValueError('No WIN98 cabinet folder; this is not accepted as Win98 source media')
    for name in cabs:
        if MS_FILES <= found.keys():
            break
        extract(iso, [name], work)
        for required in cabinet_members(work / name) & MS_FILES:
            found[required] = 'inside a WIN98 cabinet'
    if not MS_FILES <= found.keys():
        raise ValueError('Windows 98 source is missing IO.SYS, MSDOS.SYS or COMMAND.COM')
    return {'iso9660': identity, 'files': len(names), 'WIN98_cabinets': len(cabs),
            'required_files': found,
            'setup_exe_present': any(PurePosixPath(n).name.upper() == 'SETUP.EXE' for n in names),
            'cabinet_check': 'CFFILE names only; decompression/authenticity not verified',
            'original_DOS_media_scope': 'temporary existing-media path; ShizukuDOS replacement boot connection incomplete',
            'Windows98_version_verified': False,
            'installation_supported_by_preparer': False}


def add_win98(args):
    source, public = verify_bundle(args.bundle)
    iso = regular_file(args.win98_iso)
    source_pin = record(iso)
    need = sum(r['bytes'] for r in public['files'].values()) + 2 * source_pin['bytes'] + (256 << 20)
    if shutil.disk_usage(fresh_path(args.output).parent).free < need:
        raise ValueError('Insufficient space for private bundle and bounded media inspection')
    with tempfile.TemporaryDirectory(prefix='.private-win98-inspect-', dir=fresh_path(args.output).parent) as tmp:
        media = inspect_own_iso(iso, Path(tmp))
    if record(iso) != source_pin:
        raise ValueError('Windows ISO changed during validation')
    with fresh_directory(args.output) as stage:
        for name in public['files']:
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)
            if record(target) != public['files'][name]:
                raise ValueError('Public bundle changed during copy')
        carried = stage / 'WIN98.ISO'
        shutil.copyfile(iso, carried)
        if record(carried) != source_pin or record(iso) != source_pin:
            raise ValueError('Windows ISO changed or private copy differs')
        media.update(source_pin)
        media['kind'] = 'user-supplied-Windows98-ISO'
        media['redistribute'] = False
        json_write(stage / 'WIN98-MEDIA.json', media)
        (stage / 'PERSONAL-MEDIA.txt').write_text(
            'PRIVATE / 개인용: your own Windows media; do not publish this folder.\n'
            'WIN98.ISO is untouched. This is a carried file, not an installed OS.\n'
            '파일을 복사해도 Windows 98 설치가 시작되거나 완료되지 않습니다.\n', encoding='utf-8')
        result = {**public, 'kind': 'shizuku-private-usb-files-v1', 'private': True,
                  'public_bundle_manifest_sha256': file_hash(source / MANIFEST),
                  'Windows98_source': media, 'files': folder_records(stage)}
        json_write(stage / MANIFEST, result)
    print(json.dumps({'output': str(Path(args.output).absolute()), 'private': True,
                      'Windows98_iso_sha256': source_pin['sha256'], 'Windows98_installed': False}))


def private_command(args):
    repo = plain_path(args.repo)
    regular_file(repo / 'tools/build_shizuku_se_iso.py')
    iso = regular_file(args.win98_iso)
    output = fresh_path(args.output)
    if output.suffix.lower() != '.iso' or not output.name.lower().endswith('-private.iso'):
        raise ValueError('Private output must end in -private.iso')
    if output.is_relative_to(repo):
        raise ValueError('Keep the personal integrated image outside the public source checkout')
    argv = ['python3', str(repo / 'tools/build_shizuku_se_iso.py'), '--desktop',
            '--win98-media', str(iso), '--output', str(output), '--skip-qemu']
    if args.reuse_builds:
        argv.append('--reuse-builds')
    if args.action == 'private-command':
        print(shlex.join(argv))
        print('# Command only: not executed. Windows98 component profile + media overlay; replacement Setup boot connection incomplete.')
        return
    source_pin = record(iso)
    with tempfile.TemporaryDirectory(prefix='.private-win98-inspect-', dir=output.parent) as tmp:
        media = inspect_own_iso(iso, Path(tmp))
    if record(iso) != source_pin:
        raise ValueError('Windows ISO changed during validation')
    sidecar = fresh_path(output.with_suffix('.media.json'))
    print('Preparing PRIVATE Windows98 ShizukuDOS component media with your own Windows source overlay.', flush=True)
    print('This can build/download components into the source checkout build/; no VM or device write.', flush=True)
    subprocess.run(argv, check=True, cwd=repo)
    receipt = json_read(output.with_suffix('.json'))
    if (record(iso) != source_pin or receipt.get('private') is not True
            or receipt.get('sha256') != file_hash(regular_file(output))
            or receipt.get('bytes') != output.stat().st_size):
        raise ValueError('Private image or original media differs after build')
    json_write(sidecar, {'private': True, 'input_iso': source_pin, 'media': media,
                         'output_iso': {'bytes': output.stat().st_size, 'sha256': file_hash(output)},
                         'Windows98_installed': False, 'Windows98_setup_boot_supported': False})


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    public = sub.add_parser('public', help='Prepare public files from an independently verified public desktop ISO')
    public.add_argument('--iso', type=Path, required=True)
    public.add_argument('--receipt', type=Path, required=True)
    public.add_argument('--verification', type=Path, required=True)
    public.add_argument('--output', type=Path, required=True)
    public.add_argument('--zip', type=Path)
    public.set_defaults(function=prepare_public)
    private = sub.add_parser('add-win98', help='New PRIVATE local copy with your own validated ISO; never publish it')
    private.add_argument('--bundle', type=Path, required=True)
    private.add_argument('--win98-iso', type=Path, required=True)
    private.add_argument('--output', type=Path, required=True)
    private.set_defaults(function=add_win98)
    for action, help_text in (
            ('private-command', 'Print, never execute, the existing private ISO builder command'),
            ('private-iso', 'Explicitly build a PRIVATE integrated source-overlay ISO; not Windows Setup')):
        command_parser = sub.add_parser(action, help=help_text)
        command_parser.add_argument('--repo', type=Path, required=True)
        command_parser.add_argument('--win98-iso', type=Path, required=True)
        command_parser.add_argument('--output', type=Path, required=True)
        command_parser.add_argument('--reuse-builds', action='store_true')
        command_parser.set_defaults(function=private_command)
    args = parser.parse_args(argv)
    try:
        args.function(args)
    except (ValueError, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        parser.exit(2, f'error: {exc}\n')


if __name__ == '__main__':
    main()
