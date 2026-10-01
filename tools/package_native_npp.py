#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Package hash-bound, native-tested NPP compatibility components and sources.

Reads preserved acceptance/build receipts; never compiles, installs or launches.
All inputs are validated before writing an absent output directory.
"""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PREREQ = 'build/app-prerequisites-20260930/providers-freestanding'
ENV = 'build/shizukudos/native-environment-20260930-v3'
READBACK = 'build/native-npp-controls/prerequisite-proof-20260930T1653'
PROOFS = {
    READBACK + '/result.json': '56d2c888800753960c1dc1e7d89e8cbdfb9a6e6bf95df88e6e94c31b44b50015',
    'build/shizukudos/csm/run-win98-gop-latest-npp-environment-v3-20260930T1748/native-gop-latest-npp-review.json': '4969701e15e2170caa6927bdb9cd2c40a34367d3666d7487caa00f8170e1bfa5',
    'build/shizukudos/csm/run-win98-gop-latest-npp-cold-v3-20260930T1807/native-gop-latest-npp-cold-keyboard-review.json': 'e945062ad535c5e2b61f7ee39be91c308d1103b29ff3d44d0f5b2e3455d40175',
    'build/shizukudos/csm/run-win98-gop-native-environment-v3-20260930T1734/native-environment-v3-review.json': '546d8dcb5ed60b3fe7c1b89113bc6500a75f98f592ae2da23dde4144ecc31cc9',
}
BUILD_PINS = {
    PREREQ + '/build-result.json': 'b56b1c89dada0f3392672d59ad7dfabddb0db58028554c9921b69d99b3a2a28f',
    ENV + '/build-result.json': 'ae263a45a34d586a9e7db737f0c6855bf66dc7dd0772eb040cbaa29baec131c5',
    'build/native-file-dialog/build-result.json': '3d42187d3cb00ffdb1f47fe2a55cc05de6e6b59cff631c8935402fb4d2baa479',
}
ARCHIVE = 'build/app-prerequisites-20260930/KernelEx-31cdfc3560fc.tar.gz'
ARCHIVE_SHA = '6f9823e41bf9f48442f5926fd59a0246d4a1865783c6feed01b082980ee8cbbf'
FORBIDDEN = {'NPP.EXE', 'KERNEL32.DLL', 'USER32.DLL', 'GDI32.DLL', 'UNICOWS.DLL'}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def member_name(name):
    path = PurePosixPath(name)
    if (not name or '\\' in name or path.is_absolute() or
            any(p in ('.', '..') for p in path.parts) or path.as_posix() != name or
            path.name.upper() in FORBIDDEN or path.suffix.lower() in ('.img', '.qcow2', '.iso', '.vhd')):
        raise ValueError('Excluded or noncanonical package member: ' + name)
    return name


def read(root, name, expected=None):
    path = root / name
    if path.is_symlink() or not path.resolve(strict=True).is_relative_to(root.resolve()):
        raise ValueError('Input must be a regular workspace file')
    raw = path.read_bytes()
    if len(raw) > 8 * 1024 * 1024 or (expected is not None and sha(raw) != expected):
        raise ValueError('Input hash or size differs: ' + name)
    return raw


def assemble(root=ROOT):
    members = {}; evidence = []

    def add(name, raw):
        member_name(name)
        if name in members and members[name] != raw:
            raise ValueError('Conflicting member: ' + name)
        members[name] = raw

    proofs = {}
    for name, pin in PROOFS.items():
        document = json.loads(read(root, name, pin))
        if any(check['status'] != 'PASS' for check in document['checks']):
            raise ValueError('Native acceptance check failed')
        proofs[name] = document
        evidence.append({'receipt': Path(name).name, 'sha256': pin,
                         'status': document['status'], 'check_count': len(document['checks'])})
        if 'raw_result' in document:
            raw = json.loads(read(root, Path(document['raw_result']).relative_to(ROOT).as_posix(), document['raw_result_sha256']))
            if raw['status'] != 'NEEDS-VISUAL-REVIEW' or document['raw_receipt_mutated']:
                raise ValueError('Original runner receipt must remain unchanged')
            for record in document['native_logs']:
                read(root, Path(record['path']).relative_to(ROOT).as_posix(), record['sha256'])
            binding = document['provider_receipt']
            audit = json.loads(read(root, Path(binding['path']).relative_to(ROOT).as_posix(), binding['sha256']))
            for record in audit['files']:
                content = read(root, Path(record['path']).relative_to(ROOT).as_posix(), record['sha256'])
                if record['status'] != 'PASS' or len(content) != record['bytes'] or record['sha256'] != record['expected_sha256']:
                    raise ValueError('Accepted native prerequisite changed')
    builds = {name: json.loads(read(root, name, pin)) for name, pin in BUILD_PINS.items()}
    providers = builds[PREREQ + '/build-result.json']
    environment = builds[ENV + '/build-result.json']
    if providers['status'] != 'PASS' or environment['status'] != 'PASS':
        raise ValueError('Accepted build required')
    actual = {Path(row['host']).name: row for row in proofs[READBACK + '/result.json']['readback']}
    binary_records = []
    for name, record in providers['artifacts'].items():
        guest_name = 'UXTNEW.DLL' if name == 'UXTHEME.DLL' else name
        row = actual[guest_name]
        raw = read(root, PREREQ + '/' + name, record['sha256'])
        if len(raw) != record['bytes'] or row['sha256'] != sha(raw) or row['returncode'] != 0:
            raise ValueError('Native provider readback differs')
        if read(root, READBACK + '/readback/' + guest_name, sha(raw)) != raw:
            raise ValueError('Readback content differs')
        destination = 'native/' + ('app-local/' if name in ('BCRYPT.DLL', 'DWMAPI.DLL', 'DBGHELP.DLL') else 'KernelEx/') + guest_name
        add(destination, raw); binary_records.append(destination)
    com_pin = '9c63aeca6d403ffaee5f70c572c18dcebf17b85b81d253cfdb68008419c4d47a'
    com = builds['build/native-file-dialog/build-result.json']
    if com['artifacts']['M98FDLG.DLL']['sha256'] != com_pin or actual['M98FDLG.DLL']['sha256'] != com_pin:
        raise ValueError('Native COM acceptance binding differs')
    com_binary = read(root, 'build/native-file-dialog/M98FDLG.DLL', com_pin)
    read(root, READBACK + '/readback/M98FDLG.DLL', com_pin)
    add('native/FDLG/M98FDLG.DLL', com_binary); binary_records.append('native/FDLG/M98FDLG.DLL')
    for record in environment['artifacts']:
        name = Path(record['path']).name
        if name not in ('NTWPENV.EXE', 'ENVFIX.EXE'):
            raise ValueError('Unexpected native environment executable')
        raw = read(root, ENV + '/' + name, record['sha256'])
        if len(raw) != record['bytes']:
            raise ValueError('Native environment size differs')
        destination = 'native/VXDLAB/' + name
        add(destination, raw); binary_records.append(destination)
    if len(binary_records) != 13:
        raise ValueError('Expected twelve runtime files and one fixture')
    source_pins = providers['sources'] | environment['sources'] | com['sources_sha256']
    for name, pin in source_pins.items():
        raw = read(root, name, pin)
        if not name.startswith('build/'):
            add('source/' + name, raw)
    # Complete local headers and vendor source; omit unrelated in-progress VLC port.
    for path in sorted((root / 'src').rglob('*')):
        if path.is_file() and path.suffix in ('.h', '.c', '.def') and not path.name.startswith('m98_vlc'):
            add('source/' + path.relative_to(root).as_posix(), read(root, path.relative_to(root).as_posix()))
    for name, pin in environment['frozen_sources'].items():
        add('source/ntwin32/native_environment/' + name, read(root, ENV + '/source/' + name, pin))
    for name in ('LICENSE', 'THIRD_PARTY.md', 'licenses/Wine-LGPL-2.1.txt',
                 'src/vendor/lodepng/LICENSE', 'platform/freestanding/memory.h',
                 'tools/build_npp_prerequisites.py', 'tools/m98wrap-sources.ps1',
                 'tools/prepare_npp_core.py', 'remote/guest/npp_app_mode.c',
                 'remote/guest/known_dll_switch.c', 'docs/NATIVE_NPP_INSTALL.md',
                 'tools/package_native_npp.py'):
        add('source/' + name, read(root, name))
    for name in ('COPYING.RUNTIME', 'COPYING3'):
        add('licenses/GCC-' + name, Path('/usr/share/licenses/mingw32-gcc', name).read_bytes())
    for name in ('COPYING', 'DISCLAIMER', 'DISCLAIMER.PD'):
        add('licenses/MinGW-' + name, Path('/usr/share/licenses/mingw32-headers', name).read_bytes())
    add('LICENSE', read(root, 'LICENSE'))
    add('README.md', read(root, 'docs/NATIVE_NPP_INSTALL.md'))
    archive = read(root, ARCHIVE, ARCHIVE_SHA)
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        for item in tar.getmembers():
            if item.issym() or item.islnk() or item.isdev() or item.name.startswith('/') or '..' in PurePosixPath(item.name).parts:
                raise ValueError('Unexpected upstream source archive member')
    add('upstream/KernelEx-31cdfc3560fc.tar.gz', archive)
    plan = json.loads(read(root, 'build/app-prerequisites-20260930/npp-core-plan/plan-installed-stock-v2.json', 'e1827b3ad1b0910fdf60e9617113973b261b91dfbdb3db044794b7f76635b621'))
    public_plan = {key: plan[key] for key in ('schema', 'kind', 'profile', 'libraries', 'names', 'ordinals')}
    add('config/npp-routes.json', encode(public_plan))
    add('config/CORE.EXAMPLE.INI', read(root, READBACK + '/readback/CORE.CUR', '022289408799526d71661d2c9367b84030de5aadeb7fa5681466655b5acf30ec'))
    spec = importlib.util.spec_from_file_location('npp_package_core_merge', root / 'tools/prepare_npp_core.py')
    merger = importlib.util.module_from_spec(spec); spec.loader.exec_module(merger)
    original = read(root, READBACK + '/readback/CORE.BAK', 'f9cff1953e6295c0a4310091818faab779e29c60e69c5797dfc8079e1fbb59d9')
    if merger.merge(original, public_plan)[0] != members['config/CORE.EXAMPLE.INI']:
        raise ValueError('Packaged route plan does not reproduce the native accepted configuration')
    recipes = {'providers': [step['command'] for step in providers['steps']],
               'environment': environment['commands'], 'file_dialog': com.get('commands', []),
               'note': 'Build-only commands; paths refer to source layout and private build inputs. Generated profiles.h is included. Compiler byte reproducibility is not claimed.'}
    add('BUILD-RECIPES.json', encode(json.loads(json.dumps(recipes).replace(str(root.resolve()), '$SOURCE_ROOT'))))
    add('EVIDENCE.json', encode({'schema': 1, 'acceptance_receipts': evidence,
                               'genuine_windows98_gop': True, 'requires_field_interpreter': True,
                               'unassisted_npp_exit_verified': False, 'fresh_zip_install_verified': False,
                               'other_modern_apps_verified': False, 'gpu_3d_verified': False,
                               'windows_clean_shutdown_verified': False,
                               'shortcut_correction_and_prior_document_restoration': True}))
    manifest = {'schema': 1, 'package': 'Shizuku latest Notepad++ compatibility preview',
                'runtime_binaries': 12, 'diagnostic_fixtures': 1,
                'members': {name: {'bytes': len(raw), 'sha256': sha(raw)} for name, raw in sorted(members.items())}}
    add('MANIFEST.json', encode(manifest))
    if len(members) > 160 or sum(map(len, members.values())) > 8 * 1024 * 1024:
        raise ValueError('Unexpected package size')
    return members


def zip_bytes(members):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, raw in sorted(members.items()):
            member_name(name)
            info = zipfile.ZipInfo(name, (2026, 9, 30, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3; info.external_attr = 0o100644 << 16
            archive.writestr(info, raw, compresslevel=9)
    return output.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(); out = args.out.resolve()
    if not out.is_relative_to(ROOT / 'build') or out.exists():
        parser.error('Use a new workspace build directory')
    members = assemble(); payload = zip_bytes(members)
    if payload != zip_bytes(members):
        raise ValueError('ZIP assembly is not deterministic')
    out.mkdir(parents=True)
    archive = out / 'SHZNPP.zip'; archive.write_bytes(payload)
    (out / 'SHZNPP.zip.sha256').write_text(sha(payload) + '  SHZNPP.zip\n')
    receipt = {'status': 'PASS', 'zip_sha256': sha(payload), 'bytes': len(payload),
               'member_count': len(members), 'runtime_binaries': 12, 'diagnostic_fixtures': 1,
               'deterministic_zip_assembly': True, 'compiler_reproducibility_claimed': False,
               'fresh_zip_install_verified': False, 'guest_mutated': False,
               'manifest_sha256': sha(members['MANIFEST.json'])}
    (out / 'result.json').write_bytes(encode(receipt)); print(json.dumps(receipt))


if __name__ == '__main__':
    main()
