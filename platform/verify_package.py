#!/usr/bin/env python3
"""Extract own source package, rebuild and compare exact bytes in an isolated dir.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    package = ROOT/'build/windows98-shizuku-second-edition-foundation.zip'
    receipt_path = ROOT/'build/platform/package-rebuild.json'
    receipt_path.unlink(missing_ok=True)
    folder=Path(tempfile.mkdtemp(prefix='package-check-',dir=ROOT/'build'))
    with zipfile.ZipFile(package) as archive:
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
    for command in (['python3','platform/build.py'], ['python3','platform/test.py'],
                    ['python3','shizukudos/uefi/build.py']):
        proc=subprocess.run(command,cwd=folder,capture_output=True,text=True,timeout=90)
        (folder/('rebuild-'+command[1].replace('/','-')+'.log')).write_text(proc.stdout+proc.stderr)
        if proc.returncode:
            raise RuntimeError(f'Package rebuild failed: {command}; logs in {folder}')
    compared={}
    for name in ('build/platform/NTW32.DLL','build/platform/NTWPROBE.EXE',
                 'build/platform/ntwrapper9x.a','shizukudos/uefi/build/BOOTX64.EFI'):
        actual=digest(folder/name)
        if actual != index[name]:
            raise RuntimeError(f'Rebuilt bytes differ: {name} {index[name]} {actual}')
        compared[name]=actual
    receipt={'source_package_sha256':digest(package),'extracted_to':str(folder),
             'rebuild_identical':compared,'host_tests':'pass'}
    receipt_path.write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt,indent=2))
if __name__ == '__main__':
    main()
