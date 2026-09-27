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

def build_media(include_graphics=False, include_runner=False, include_batch=False):
    include_runner = include_runner or include_batch
    include_graphics = include_graphics or include_runner
    platform = ROOT/'build/platform'
    vxd = ROOT/'ntwrapper/vxd/build'
    manifests = {platform/'manifest.json': None, vxd/'manifest.json': None}
    graphics = ROOT/'ntwddm/win98/build'
    runner = ROOT/'platform/win98lab/build/native_runner'
    runner_sources = {}
    if include_graphics:
        manifests[graphics/'build-result.json'] = None
    if include_runner:
        manifests[runner/'build-result.json'] = None
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
    if include_runner:
        runner_build = json.loads(manifests[runner/'build-result.json'])
        if (runner_build.get('schema') != 'ntw.native_runner.build.v1' or
                runner_build.get('passed') is not True or runner_build.get('artifact') != 'NTWRUN.EXE' or
                runner_build.get('crt_linked') is not False or runner_build.get('kernelex_linked') is not False):
            raise RuntimeError('Native runner has no successful original build/import receipt')
        if set(runner_build.get('sources_sha256', {})) != {
                'platform/win98lab/native_runner.c', 'platform/win98lab/build_native.py', 'ntwin32/prepare.py'}:
            raise RuntimeError('Native runner build source receipt is incomplete')
        for name, expected_source in runner_build['sources_sha256'].items():
            path = ROOT/name
            if Path(name).is_absolute() or not path.resolve().is_relative_to(ROOT.resolve()):
                raise RuntimeError('Invalid native runner source path: '+name)
            source_bytes = path.read_bytes()
            if sha(source_bytes) != expected_source:
                raise RuntimeError('Native runner source changed after its build: '+name)
            runner_sources[path] = source_bytes
        sources['NTWRUN.EXE'] = runner/'NTWRUN.EXE'
        expected['NTWRUN.EXE'] = runner_build['sha256']
    payload = {name:path.read_bytes() for name,path in sources.items()}
    for name,data in payload.items():
        if sha(data) != expected[name]:
            raise RuntimeError('Probe differs from its build manifest: '+name)
    payload['README.TXT'] = (
        "Windows 98 Shizuku's Second Edition - original native probes\r\n"
        "Use a disposable, installed Windows 98 snapshot without KernelEx.\r\n"
        "Copy all binaries to fresh C:\\NTWLAB and run from that directory.\r\n" +
        ("Run NTWRUN.EXE once to capture Windows identity and actual process exits.\r\n"
         "It launches all three probes in order and refuses existing probe logs.\r\n"
         "Retain NTWRUN.LOG plus all probe logs; capture the visible GDI window.\r\n"
         "The following names describe its children; do not run them first.\r\n"
         if include_runner else "Run the following probes and collect each result:\r\n") +
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
    if include_batch:
        batch_source = ROOT/'platform/win98lab/run_native.bat'
        batch_bytes = batch_source.read_bytes()
        # COMMAND.COM consumes the original ASCII script with DOS line ends.
        batch = batch_bytes.decode('ascii').replace('\r\n', '\n').replace('\n', '\r\n').encode('ascii')
        runner_sources[batch_source] = batch_bytes
        payload['RUNTEST.BAT'] = batch
        payload['HASHES.TXT'] += (sha(batch)+'  RUNTEST.BAT\r\n').encode('ascii')
        payload['README.TXT'] += (
            'Run RUNTEST.BAT from fresh C:\\NTWLAB to record runner exit0..3.\r\n'
            'The batch records NTWEXIT.TXT and GUESTVER.TXT; retain both.\r\n'
            'An unexpected exit is not a successful validation.\r\n'
        ).encode('ascii')
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
        for path,data in {**manifests, **runner_sources}.items():
            if path.read_bytes() != data:
                raise RuntimeError('Build manifest changed during media construction')
        output = BUILD/('ntw-native-probes-runner-batch.iso' if include_batch else
                       'ntw-native-probes-runner.iso' if include_runner else 'ntw-native-probes.iso')
        image_bytes = image.read_bytes()
        result = {'sha256':sha(image_bytes),'path':str(output),
                  'bytes':len(image_bytes),'contents_sha256':{n:sha(b) for n,b in payload.items()},
                  'source_manifests_sha256':{str(p.relative_to(ROOT)):sha(b) for p,b in manifests.items()},
                  'runner_sources_sha256':{str(p.relative_to(ROOT)):sha(b) for p,b in runner_sources.items()},
                  'guest_executed':False,'media':'original project probes only; no Windows files'}
        receipt = BUILD/('probe-media-runner-batch.json' if include_batch else
                        'probe-media-runner.json' if include_runner else 'probe-media.json')
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
    parser.add_argument('--runner', action='store_true',
                        help='Include the original bounded runner and graphics in a separate CD')
    parser.add_argument('--batch', action='store_true',
                        help='Include the runner plus a COMMAND.COM exit-code script in a separate CD')
    args = parser.parse_args()
    os.umask(0o077)
    BUILD.mkdir(parents=True, exist_ok=True)
    with (BUILD/'probe-media.lock').open('a') as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError('Another original probe CD build is running') from error
        build_media(args.graphics, args.runner, args.batch)

if __name__=='__main__':main()
