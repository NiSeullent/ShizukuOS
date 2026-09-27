#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Make a private read-only CD of original probes/providers, never OS media."""
import argparse
import hashlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT/'build/win98-lab'

def sha(data):
    return hashlib.sha256(data).hexdigest()

def build_media(include_graphics=False):
    platform = ROOT/'build/platform'
    vxd = ROOT/'ntwrapper/vxd/build'
    manifests = {platform/'manifest.json': None, vxd/'manifest.json': None}
    graphics = ROOT/'ntwddm/win98/build'
    if include_graphics:
        manifests[graphics/'build-result.json'] = None
    for path in manifests:
        manifests[path] = path.read_bytes()
    app = json.loads(manifests[platform/'manifest.json'])
    kernel = json.loads(manifests[vxd/'manifest.json'])
    sources = {name:platform/name for name in ('NTW32.DLL','NTWPROBE.EXE')}
    sources.update({name:vxd/name for name in ('NTWRAP9X.VXD','NTWQUERY.EXE')})
    expected = {name:app['artifacts'][name]['sha256'] for name in ('NTW32.DLL','NTWPROBE.EXE')}
    expected.update({'NTWRAP9X.VXD':kernel['sha256'],'NTWQUERY.EXE':kernel['probe']['sha256']})
    if include_graphics:
        graphic_build = json.loads(manifests[graphics/'build-result.json'])
        if not graphic_build['passed'] or graphic_build['artifact'] != 'NTWGPROB.EXE':
            raise RuntimeError('Graphics probe has no successful audited build receipt')
        sources['NTWGPROB.EXE'] = graphics/'NTWGPROB.EXE'
        expected['NTWGPROB.EXE'] = graphic_build['sha256']
    payload = {name:path.read_bytes() for name,path in sources.items()}
    for name,data in payload.items():
        if sha(data) != expected[name]:
            raise RuntimeError('Probe differs from its build manifest: '+name)
    payload['README.TXT'] = (
        "Windows 98 Shizuku's Second Edition - original native probes\r\n"
        "Use a disposable, installed Windows 98 snapshot without KernelEx.\r\n"
        "Copy all binaries to C:\\NTWLAB and run from that directory:\r\n"
        "  NTWPROBE.EXE  (writes NTWPROBE.LOG)\r\n"
        "  NTWQUERY.EXE  (loads NTWRAP9X.VXD and writes NTWQUERY.LOG)\r\n" +
        ("  NTWGPROB.EXE (5-second GDI window, writes NTWGPROB.LOG)\r\n"
         "Capture the graphics window while visible; check WIN98_IDENTIFIED=1.\r\n"
         if include_graphics else "") +
        "Record each exit code and complete log, then stop the guest.\r\n"
        "Do not count this CD build as native Windows execution evidence.\r\n"
        "Contains no Windows installation files, firmware or product key.\r\n"
    ).encode('ascii')
    payload['HASHES.TXT'] = ''.join(h+'  '+n+'\r\n' for n,h in sorted(expected.items())).encode('ascii')
    with tempfile.TemporaryDirectory(prefix='probe-media-',dir=BUILD) as temporary:
        temporary = Path(temporary)
        source = temporary/'source'; source.mkdir()
        for name,data in payload.items(): (source/name).write_bytes(data)
        image = temporary/'probes.iso'
        command = ['xorriso','-as','mkisofs','-quiet','-iso-level','1',
                   '-V','NTWLAB','-o',str(image),str(source)]
        subprocess.run(command,check=True,capture_output=True,timeout=30)
        extracted = temporary/'extracted'
        subprocess.run(['xorriso','-osirrox','on','-indev',str(image),
                        '-extract','/',str(extracted)],check=True,capture_output=True,timeout=30)
        observed = {p.name:p.read_bytes() for p in extracted.iterdir() if p.is_file()}
        if observed != payload:
            raise RuntimeError('ISO extraction changed names, bytes or file inventory')
        for name,path in sources.items():
            if path.read_bytes() != payload[name]:
                raise RuntimeError('Probe changed during media construction: '+name)
        for path,data in manifests.items():
            if path.read_bytes() != data:
                raise RuntimeError('Build manifest changed during media construction')
        output = BUILD/'ntw-native-probes.iso'
        image_bytes = image.read_bytes()
        result = {'sha256':sha(image_bytes),'path':str(output),
                  'bytes':len(image_bytes),'contents_sha256':{n:sha(b) for n,b in payload.items()},
                  'source_manifests_sha256':{str(p.relative_to(ROOT)):sha(b) for p,b in manifests.items()},
                  'guest_executed':False,'media':'original project probes only; no Windows files'}
        receipt = BUILD/'probe-media.json'
        staged_receipt = temporary/'receipt.json'
        staged_receipt.write_text(json.dumps(result,indent=2)+'\n')
        # A failed publication may leave an image without a receipt, never a
        # receipt for a different image. Cooperating writers hold the same lock.
        receipt.unlink(missing_ok=True)
        image.replace(output)
        if output.read_bytes() != image_bytes:
            raise RuntimeError('Published probe image changed before receipt publication')
        staged_receipt.replace(receipt)
        if output.read_bytes() != image_bytes:
            receipt.unlink(missing_ok=True)
            raise RuntimeError('Published probe image changed during receipt publication')
    print(json.dumps(result,indent=2))

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--graphics', action='store_true',
                        help='Include the separately built original native GDI probe')
    args = parser.parse_args()
    os.umask(0o077)
    BUILD.mkdir(parents=True, exist_ok=True)
    with (BUILD/'probe-media.lock').open('a') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another original probe CD build is running') from error
        build_media(args.graphics)

if __name__=='__main__':main()
