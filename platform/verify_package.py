#!/usr/bin/env python3
"""Extract own source package, rebuild and compare exact bytes in an isolated dir.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import io
import json
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = 'windows98-shizuku-second-edition-usb-configuration-checkpoint.zip'
REBUILD_COMMANDS = (
    ('python3','platform/build.py'), ('python3','platform/test.py'),
    ('python3','platform/abi32/build.py'), ('python3','ntwrapper/vxd/build.py'),
    ('python3','shizukudos/uefi/build.py'), ('python3','shizukudos/uefi32/build.py'),
    ('python3','drivers/ahci_native/test.py'), ('python3','shizukudos/uefi_ahci/build.py'),
    ('python3','shizukudos/uefi_ahci/test.py'), ('python3','drivers/xhci_native/test.py'),
    ('python3','shizukudos/uefi_xhci/build.py'), ('python3','shizukudos/uefi_xhci/test.py'),
    ('python3','platform/freestanding/test.py'), ('python3','ntwddm/win98/test.py'),
    ('python3','ntwddm/win98/build.py'), ('python3','drivers/usb_native/test.py'),
    ('python3','drivers/xhci_usb/test.py'), ('python3','shizukudos/uefi_usb/build.py'),
    ('python3','shizukudos/uefi_usb/test.py'), ('python3','shizukudos/uefi_usb_config/build.py'),
    ('python3','shizukudos/uefi_usb_config/test.py'))
REBUILT_ARTIFACTS = (
    'build/platform/NTW32.DLL','build/platform/NTWPROBE.EXE',
    'build/platform/ntwrapper9x.a','shizukudos/uefi/build/BOOTX64.EFI',
    'shizukudos/uefi32/build/BOOTX64.EFI','shizukudos/uefi32/build/payload.bin',
    'shizukudos/uefi32/build/transition.bin',
    'ntwrapper/vxd/build/NTWRAP9X.VXD','ntwrapper/vxd/build/NTWQUERY.EXE',
    'shizukudos/uefi_ahci/build/BOOTX64.EFI','shizukudos/uefi_ahci/build/payload.bin',
    'shizukudos/uefi_ahci/build/transition.bin',
    'shizukudos/uefi_xhci/build/BOOTX64.EFI','shizukudos/uefi_xhci/build/payload.bin',
    'shizukudos/uefi_xhci/build/transition.bin','ntwddm/win98/build/NTWGPROB.EXE',
    'shizukudos/uefi_usb/build/BOOTX64.EFI','shizukudos/uefi_usb/build/payload.bin',
    'shizukudos/uefi_usb/build/transition.bin','shizukudos/uefi_usb_config/build/BOOTX64.EFI',
    'shizukudos/uefi_usb_config/build/payload.bin','shizukudos/uefi_usb_config/build/transition.bin')
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    package = ROOT/'build'/PACKAGE_NAME
    receipt_path = ROOT/'build/platform/package-rebuild.json'
    receipt_path.unlink(missing_ok=True)
    package_bytes = package.read_bytes()
    package_sha256 = hashlib.sha256(package_bytes).hexdigest()
    folder=Path(tempfile.mkdtemp(prefix='package-check-',dir=ROOT/'build'))
    with zipfile.ZipFile(io.BytesIO(package_bytes)) as archive:
        for entry in archive.infolist():
            destination = (folder/entry.filename).resolve()
            if not destination.is_relative_to(folder) or entry.file_size > 16*1024*1024:
                raise RuntimeError('Invalid source-package member')
        archive.extractall(folder)
    index=json.loads((folder/'FILES-SHA256.json').read_text())
    for name, expected in index.items():
        path=(folder/name).resolve()
        if not path.is_relative_to(folder) or digest(path) != expected:
            raise RuntimeError(f'Extracted file failed manifest validation: {name}')
    for command in REBUILD_COMMANDS:
        proc=subprocess.run(command,cwd=folder,capture_output=True,text=True,timeout=90)
        (folder/('rebuild-'+command[1].replace('/','-')+'.log')).write_text(proc.stdout+proc.stderr)
        if proc.returncode:
            raise RuntimeError(f'Package rebuild failed: {command}; logs in {folder}')
    compared={}
    for name in REBUILT_ARTIFACTS:
        actual=digest(folder/name)
        if actual != index[name]:
            raise RuntimeError(f'Rebuilt bytes differ: {name} {index[name]} {actual}')
        compared[name]=actual
    if digest(package) != package_sha256:
        raise RuntimeError('Source package changed during rebuild; no receipt published')
    receipt={'source_package_sha256':package_sha256,'extracted_to':str(folder),
             'rebuild_identical':compared,'host_tests':'pass', 'guest_reexecuted':False,
             'rebuild_commands':[list(command) for command in REBUILD_COMMANDS]}
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))
if __name__ == '__main__':
    main()
