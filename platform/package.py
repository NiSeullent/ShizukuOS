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

def main():
    build = ROOT/'build/platform'
    manifest_path = build/'manifest.json'
    manifest = json.loads(manifest_path.read_text())
    tests = json.loads((build/'host-tests.json').read_text())
    if tests['build_manifest_sha256'] != digest(manifest_path):
        raise RuntimeError('Host test receipt belongs to a different build')
    for name, expected in {**manifest['sources_sha256'], **tests['test_sources_sha256']}.items():
        if digest(ROOT/name) != expected:
            raise RuntimeError(f'Source changed since validation: {name}')
    for name, info in manifest['artifacts'].items():
        if digest(build/name) != info['sha256']:
            raise RuntimeError(f'Artifact changed since validation: {name}')
    files = {}
    for folder in ('ntwrapper','ntwin32','ntwddm','drivers/pcie','shizukudos/uefi','platform'):
        for path in (ROOT/folder).rglob('*'):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(ROOT)
            if any(part in ('build','__pycache__') for part in relative.parts):
                continue
            files[str(relative)] = path
    for name in ('LICENSE','THIRD_PARTY.md','docs/INDEPENDENT_PLATFORM_CHECKPOINT.md'):
        files[name] = ROOT/name
    for name in ('NTW32.DLL','NTWPROBE.EXE','ntwrapper9x.a','ntwrapper9x.o',
                 'manifest.json','host-tests.json','prepare-report.json'):
        files['build/platform/'+name] = build/name
    uefi = ROOT/'shizukudos/uefi/build'
    receipt_path = uefi/'qemu-result.json'
    receipt = json.loads(receipt_path.read_text())
    if not receipt['pass'] or not receipt['process_stopped'] or receipt['artifact_sha256'] != digest(uefi/'BOOTX64.EFI'):
        raise RuntimeError('Current EFI image lacks matching stopped-guest proof')
    uefi_build = json.loads((uefi/'build-result.json').read_text())
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
    output = ROOT/'build/windows98-shizuku-second-edition-foundation.zip'
    temporary = output.with_suffix('.zip.tmp')
    index = {name:digest(path) for name,path in sorted(files.items())}
    with zipfile.ZipFile(temporary,'w',zipfile.ZIP_DEFLATED) as archive:
        def add(name, data):
            entry=zipfile.ZipInfo(name, (2026,9,27,0,0,0))
            entry.compress_type=zipfile.ZIP_DEFLATED
            entry.external_attr=0o100644 << 16
            archive.writestr(entry,data)
        for name,path in sorted(files.items()):
            add(name,path.read_bytes())
        add('FILES-SHA256.json',json.dumps(index,indent=2)+'\n')
        add('README.txt',"Windows 98 Shizuku's Second Edition — independent foundation checkpoint\n"
            "Read platform/README.md and docs/INDEPENDENT_PLATFORM_CHECKPOINT.md.\n"
            "Not a complete operating system or installation package.\n"
            "Windows 98 VxD/app execution, modern vendor drivers and full DOS are not yet verified.\n"
            "Contains only independently authored source/binaries and development evidence.\n"
            "No Windows media, keys, firmware binaries or third-party implementations.\n")
    with zipfile.ZipFile(temporary) as archive:
        if archive.testzip() is not None:
            raise RuntimeError('Package CRC verification failed')
    temporary.replace(output)
    output.with_suffix('.zip.sha256').write_text(digest(output)+'  '+output.name+'\n')
    print(json.dumps({'path':str(output),'sha256':digest(output),'files':len(files)+2,
                      'bytes':output.stat().st_size},indent=2))

if __name__ == '__main__':
    main()
