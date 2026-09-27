#!/usr/bin/env python3
"""Package only independent project code/artifacts; no OS media or firmware.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

class Inputs:
    """Bind validation and archive bytes to the same observed input versions."""
    def __init__(self):
        self.observed = {}

    def read(self, path):
        data = path.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if self.observed.setdefault(path, actual) != actual:
            raise RuntimeError(f'Input changed during packaging: {path}')
        return data

    def digest(self, path):
        return hashlib.sha256(self.read(path)).hexdigest()

    def json(self, path):
        return json.loads(self.read(path))

    def verify_unchanged(self):
        for path, expected in self.observed.items():
            if digest(path) != expected:
                raise RuntimeError(f'Input changed before package publication: {path}')

def main():
    inputs = Inputs()
    digest = inputs.digest
    read_json = inputs.json
    build = ROOT/'build/platform'
    manifest_path = build/'manifest.json'
    manifest = read_json(manifest_path)
    tests = read_json(build/'host-tests.json')
    if tests['build_manifest_sha256'] != digest(manifest_path):
        raise RuntimeError('Host test receipt belongs to a different build')
    for name, expected in {**manifest['sources_sha256'], **tests['test_sources_sha256']}.items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'Source changed since validation: {name}')
    for name, info in manifest['artifacts'].items():
        if digest(build/name) != info['sha256']:
            raise RuntimeError(f'Artifact changed since validation: {name}')
    files = {}
    for folder in ('ntwrapper','ntwin32','ntwddm','drivers/pcie','shizukudos/uefi',
                   'shizukudos/uefi32','platform'):
        for path in (ROOT/folder).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(ROOT)
            if any(part in ('build','__pycache__') for part in relative.parts):
                continue
            files[str(relative)] = path
    for name in ('LICENSE','THIRD_PARTY.md','docs/INDEPENDENT_PLATFORM_CHECKPOINT.md',
                 'docs/NATIVE_PLATFORM_CHECKPOINT.md'):
        files[name] = ROOT/name
    for name in ('NTW32.DLL','NTWPROBE.EXE','ntwrapper9x.a','ntwrapper9x.o',
                 'manifest.json','host-tests.json','prepare-report.json'):
        files['build/platform/'+name] = build/name
    uefi = ROOT/'shizukudos/uefi/build'
    receipt_path = uefi/'qemu-result.json'
    receipt = read_json(receipt_path)
    if not receipt['pass'] or not receipt['process_stopped'] or receipt['artifact_sha256'] != digest(uefi/'BOOTX64.EFI'):
        raise RuntimeError('Current EFI image lacks matching stopped-guest proof')
    uefi_build = read_json(uefi/'build-result.json')
    if uefi_build['sha256'] != receipt['artifact_sha256']:
        raise RuntimeError('EFI build receipt and tested artifact differ')
    for name, expected in uefi_build['sources_sha256'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'EFI source changed since build: {name}')
    for name in ('BOOTX64.EFI','build-result.json','qemu-result.json'):
        files['shizukudos/uefi/build/'+name] = uefi/name
    screenshot = Path(receipt['evidence_directory'])/'handoff.ppm'
    if digest(screenshot) != receipt['screenshot_sha256']:
        raise RuntimeError('Screenshot changed since guest validation')
    files['evidence/uefi-handoff.ppm'] = screenshot
    files['evidence/uefi-handoff.png'] = Path(receipt['evidence_directory'])/'handoff.png'
    # Preserve the first checkpoint archive; this checkpoint adds independently
    # built LE/VxD, actual PE32 execution and legacy protected-mode handoff.
    abi = ROOT/'platform/abi32/build/results.json'
    abi_receipt = read_json(abi)
    if abi_receipt['dll_sha256'] != digest(build/'NTW32.DLL') or len(abi_receipt['variants']) != 2:
        raise RuntimeError('Actual PE32 execution receipt does not match this DLL')
    if abi_receipt['packer_tests']['status'] != 'PASS':
        raise RuntimeError('ABI packer validation did not pass')
    for name, expected in abi_receipt['sources_sha256'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'ABI harness changed since validation: {name}')
    files['platform/abi32/build/results.json'] = abi
    for variant in abi_receipt['variants']:
        if not variant['stdout'].startswith('PASS NTW32 actual PE32 ABI:'):
            raise RuntimeError('PE32 variant did not pass')
    vxd = ROOT/'ntwrapper/vxd/build'
    vxd_manifest = read_json(vxd/'manifest.json')
    if digest(vxd/'NTWRAP9X.VXD') != vxd_manifest['sha256']:
        raise RuntimeError('VxD artifact changed since build')
    for name, expected in vxd_manifest['sources'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'VxD source changed since build: {name}')
    vxd_tests = read_json(vxd/'host-tests.json')
    if (not vxd_tests['passed'] or not vxd_tests['inputs_unchanged_during_test'] or
        vxd_tests['artifact_sha256'] != vxd_manifest['sha256'] or
        vxd_tests['probe_sha256'] != vxd_manifest['probe']['sha256'] or
        digest(vxd/'NTWQUERY.EXE') != vxd_manifest['probe']['sha256'] or
        digest(vxd/'host-tests.log') != vxd_tests['log_sha256']):
        raise RuntimeError('VxD/probe artifacts lack matching successful host validation')
    for name, expected in vxd_tests['hashes'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'VxD input changed since host validation: {name}')
    for name in ('NTWRAP9X.VXD','NTWRAP9X.elf','manifest.json','host-tests.json',
                 'host-tests.log','NTWQUERY.EXE'):
        files['ntwrapper/vxd/build/'+name] = vxd/name
    pm = ROOT/'shizukudos/uefi32/build'
    pm_build = read_json(pm/'build-result.json')
    pm_guest = read_json(pm/'qemu-result.json')
    if (not pm_guest['pass'] or not pm_guest['process_stopped'] or
        pm_guest['artifact_sha256'] != digest(pm/'BOOTX64.EFI') or
        pm_build['efi']['sha256'] != pm_guest['artifact_sha256']):
        raise RuntimeError('32-bit handoff lacks matching stopped-guest proof')
    for name, expected in pm_build['sources_sha256'].items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'32-bit handoff source changed since build: {name}')
    for name, key in (('payload.bin','payload'),('transition.bin','transition')):
        if digest(pm/name) != pm_build[key]['sha256']:
            raise RuntimeError(f'32-bit handoff payload changed: {name}')
    for name in ('BOOTX64.EFI','payload.bin','transition.bin','build-result.json',
                 'qemu-result.json','host-tests.log'):
        files['shizukudos/uefi32/build/'+name] = pm/name
    pm_evidence = Path(pm_guest['evidence_directory'])
    if digest(pm_evidence/'handoff.ppm') != pm_guest['screenshot_sha256']:
        raise RuntimeError('32-bit handoff screenshot changed since validation')
    for name in ('handoff.ppm','handoff.png','registers.txt','handoff.bin'):
        files['evidence/uefi32-'+name] = pm_evidence/name
    output = ROOT/'build/windows98-shizuku-second-edition-native-checkpoint.zip'
    temporary = output.with_suffix('.zip.tmp')
    members = {name:inputs.read(path) for name,path in sorted(files.items())}
    index = {name:hashlib.sha256(data).hexdigest() for name,data in members.items()}
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as archive:
        def add(name, data):
            entry=zipfile.ZipInfo(name, (2026,9,27,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED
            entry.external_attr=0o100644 << 16
            archive.writestr(entry,data)
        for name,data in members.items():
            add(name,data)
        add('FILES-SHA256.json',json.dumps(index,indent=2)+'\n')
        add('README.txt',"Windows 98 Shizuku's Second Edition — native platform checkpoint\n"
            "Read platform/README.md and docs/NATIVE_PLATFORM_CHECKPOINT.md.\n"
            "Not a complete operating system or installation package.\n"
            "See checkpoint for precise Windows 98 VxD/app validation status.\n"
            "Modern vendor drivers, complete DOS and UEFI-to-Win98 boot remain unfinished.\n"
            "Contains only independently authored source/binaries and development evidence.\n"
            "No Windows media, keys, firmware binaries or third-party implementations.\n")
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Package CRC verification failed')
        for name, expected in index.items():
            if hashlib.sha256(archive.read(name)).hexdigest() != expected:
                raise RuntimeError(f'Package member failed manifest validation: {name}')
    inputs.verify_unchanged()
    temporary.replace(output)
    output.with_suffix('.zip.sha256').write_text(digest(output)+'  '+output.name+'\n')
    print(json.dumps({'path':str(output),'sha256':digest(output),'files':len(files)+2,
                      'bytes':output.stat().st_size},indent=2))

if __name__ == '__main__':
    main()
