#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host controls only: modeled producer admission is never production proof."""
import fcntl
from contextlib import contextmanager, ExitStack, redirect_stdout
from argparse import Namespace
import importlib.util
import json
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'shizukudos/install'))
import native_release_admission as release


class AdmissionTests(unittest.TestCase):
    def test_absent_independent_anchors_refuse_before_open(self):
        with self.assertRaisesRegex(ValueError, 'anchors absent'):
            with release.admit_for_build('/definitely/absent.json', '/definitely/out'):
                self.fail('no authority exists')

    def test_no_runtime_receipt_can_extend_policy(self):
        with self.assertRaisesRegex(ValueError, 'anchor differs'):
            release.anchored({'bytes': 1, 'sha256': 'a'*64}, release.policy.DOS_RECEIPT, 'DOS')
        with self.assertRaisesRegex(ValueError, 'anchor differs'):
            release.anchored({'bytes': 1, 'sha256': 'a'*64}, None, 'DOS')

    def test_private_original_requires_independent_custody(self):
        with self.assertRaisesRegex(ValueError, 'installed-source custody absent'):
            release.policy.verify_private_source_custody({'approval': True, 'sha256': 'a'*64}, None)

    def test_stale_ingestion_epoch(self):
        with patch.object(release.policy, 'INGEST_SHA', 'a'*64):
            with self.assertRaisesRegex(ValueError, 'epoch changed'):
                release.load_ingester()

    def test_bounds_use_encoded_not_expanded_size(self):
        row = {'bytes': 100, 'sha256': 'a'*64}
        encoded = {'bytes': release.MAX_ENCODED, 'sha256': 'b'*64}
        self.assertIn(str(release.MAX_ENCODED).encode(), release.render_record(row, encoded, 'c'*64))
        encoded['bytes'] += 1
        with self.assertRaisesRegex(ValueError, 'capability'):
            release.render_record(row, encoded, 'c'*64)

    def test_real_leases_and_sim_readback_with_host_only_modeled_producer(self):
        ingest = release.load_ingester()
        with tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-release-host-') as temp:
            base = Path(temp)
            def put(name, raw):
                p = base/name; p.write_bytes(raw)
                return {'path': str(p), 'bytes': len(raw), 'sha256': release.digest(raw)}
            def obj(name, value):
                return put(name, (json.dumps(value, indent=2)+'\n').encode())
            # Tiny modeled producer, actual saved-byte leases and independent
            # SIM decoder. No Windows content, no production policy mutation.
            raw = b'X'*4096
            esp = put('model-esp', raw)
            sim_raw = struct.pack('<8sIIIIQ', b'SHZSIMG1', 4096, 0, 1, 0, len(raw))
            sim_raw += bytes.fromhex(esp['sha256']) + struct.pack('<QII', 0, 1, 0) + raw
            sim = put('model-sim', sim_raw)
            dos = obj('dos', {'toolchain': {'open-watcom': {'snapshot_sha256': release.policy.WATCOM_SHA}}})
            payload = put('model-dos', b'DOS fixture')
            profile = obj('profile', {'payloads': [{'guest': n, 'file': payload} for n in release.policy.DOS_ARTIFACTS]})
            component = put('model-component', b'not a kernel')
            mapping = {'model-source': 'a'*64}
            native = obj('native', {'sources_sha256': mapping,
                         'input_pins': {'KERNEL32.BIN': component, 'KERNEL64.BIN': component},
                         'members': {'EFI/BOOT/BOOTX64.EFI': component}})
            request = obj('request', {'dos_build_receipt': dos, 'constructor_profile': profile,
                                      'native_build_receipt': native})
            lineage = {'model_only_not_Windows': True}
            manifest = obj('manifest', release.manifest_expected(ingest, request, lineage, sim))
            def modeled_lineage(req, held):
                return held.add(esp), lineage
            ap = (component['bytes'], component['sha256'])
            with patch.object(release, 'load_ingester', return_value=ingest), \
                 patch.object(ingest, 'validate_lineage', side_effect=modeled_lineage), \
                 patch.object(release.policy, 'verify_private_source_custody', return_value={'HOST_ONLY': 'modeled custody'}), \
                 patch.object(release.policy, 'DOS_RECEIPT', (dos['bytes'], dos['sha256'])), \
                 patch.object(release.policy, 'DOS_ARTIFACTS', {n: (payload['bytes'], payload['sha256']) for n in release.policy.DOS_ARTIFACTS}), \
                 patch.object(release.policy, 'NATIVE_SOURCE_MAP_SHA', release.digest(release.canonical(mapping))), \
                 patch.object(release.policy, 'NATIVE_ARTIFACTS', {n: ap for n in ('KERNEL32.BIN','KERNEL64.BIN','BOOTX64.EFI')}):
                with release.admit_for_build(manifest['path'], base/'generated') as result:
                    generated = result['source']
                    self.assertEqual(generated.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(generated.parent.stat().st_mode & 0o777, 0o700)
                    leases = []
                    for name in os.listdir('/proc/self/fd'):
                        try:
                            fd = int(name)
                            if os.fstat(fd).st_ino == generated.stat().st_ino:
                                leases.append(fcntl.fcntl(fd, fcntl.F_GETLEASE))
                        except OSError:
                            pass
                    self.assertIn(fcntl.F_RDLCK, leases)
                    self.assertEqual(release.digest(generated.read_bytes()), result['record']['sha256'])
                with generated.open('rb') as stream:
                    self.assertEqual(fcntl.fcntl(stream.fileno(), fcntl.F_GETLEASE), fcntl.F_UNLCK)
                changed = release.manifest_expected(ingest, request, lineage, sim)
                changed['Windows98_boot_verified'] = True
                bad = obj('forged-manifest', changed)
                with self.assertRaisesRegex(ValueError, 'reconstructed'):
                    with release.admit_for_build(bad['path'], base/'refused'):
                        self.fail('forged attestation accepted')
                self.assertFalse((base/'refused').exists())
                corrupt = bytearray(sim_raw); corrupt[-1] ^= 1
                forged_sim = put('forged-sim', bytes(corrupt))
                bad = obj('forged-sim-manifest', release.manifest_expected(ingest, request, lineage, forged_sim))
                with self.assertRaisesRegex(ValueError, 'expanded ESP SHA'):
                    with release.admit_for_build(bad['path'], base/'refused-sim'):
                        self.fail('corrupt expansion accepted')
                with self.assertRaisesRegex(ValueError, 'lease broken'):
                    with release.admit_for_build(manifest['path'], base/'lease-break') as result:
                        with self.assertRaises(BlockingIOError):
                            os.close(os.open(result['source'], os.O_WRONLY | os.O_NONBLOCK))

    def test_actual_kbuild_only_installer_receives_generated_record(self):
        spec = importlib.util.spec_from_file_location('release_actual_kbuild', ROOT/'shizukudos/kbuild.py')
        build = importlib.util.module_from_spec(spec); spec.loader.exec_module(build)
        with tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-release-build-') as temp:
            base = Path(temp); selected = {}; closed = []
            @contextmanager
            def modeled_admission(manifest, out, pins):
                # Explicit host-only model of the independent producer. The real
                # kbuild selector/flags/source and receipt ordering run unchanged.
                self.assertTrue(any(row['path'].endswith('kbuild.py') for row in pins))
                self.assertTrue(any('cc1' in row['path'] for row in pins))
                out.mkdir(); source = out/'native_release_admitted.c'; source.write_text('/* model only */')
                yield {'source': source, 'private': True, 'public_artifact': False}
                closed.append(True)
            def modeled_compile(name, directory, flags, *rest, extra_c=()):
                selected[name] = (flags, extra_c)
                elf = base/(name+'.elf'); raw = bytearray(20)
                raw[4] = 1 if name=='kernel32' else 2
                raw[18:20] = b'\x03\x00' if name=='kernel32' else b'\x3e\x00'
                elf.write_bytes(raw)
                return {'elf': elf, 'bytes': 20, 'sha256': 'a'*64, 'elf_sha256': 'b'*64, 'commands': []}
            def save_receipt(path, result):
                self.assertEqual(closed, [True], 'successful receipt precedes mandatory custody close')
                self.assertTrue(result['private']);self.assertFalse(result['public_artifact'])
                self.assertIn('gcc-cc1', result['tools_sha256'])
                self.assertIn('shizukudos/install/native_release_policy.py', result['sources_sha256'])
            with patch.object(release, 'admit_for_build', side_effect=modeled_admission), \
                 patch.object(build, 'build_kernel', side_effect=modeled_compile), \
                 patch.object(build, 'build_standalone_stub', return_value={'sha256': 'c'*64}), \
                 patch.object(build.shzlib, 'write_json', side_effect=save_receipt):
                with ExitStack() as stack, redirect_stdout(io.StringIO()):
                    build.build_all(Namespace(out=base/'private-build', native_release_manifest=base/'model'), stack)
            for name, (flags, sources) in selected.items():
                active = name=='kernel64s'
                self.assertEqual('-DSHZ_NATIVE_INSTALLER_RELEASE' in flags, active)
                self.assertEqual(any(p.name=='native_release_admitted.c' for p in sources), active)

    def test_actual_consumer_abi_and_default_refusal(self):
        header = ROOT/'shizukudos/kernel64'
        row = {'bytes': 100, 'sha256': 'a'*64}
        sim = {'bytes': 200, 'sha256': 'b'*64}
        with tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-release-c-') as temp:
            base = Path(temp)
            record = base/'record.c'; record.write_bytes(release.render_record(row, sim, 'c'*64))
            test = base/'test.c'
            test.write_text('''#include "setup_native_release.h"
#include <assert.h>
#include <string.h>
int main(void) {
 archive_source_info_t p[2];memset(p,0,sizeof(p));
 p[0].bytes=100;p[1].bytes=200;
 memset(p[0].sha256,0xaa,32);memset(p[1].sha256,0xbb,32);
#if defined(SHZ_NATIVE_INSTALLER_RELEASE) && !defined(HOST_INVALID_RECORD)
 assert(setup_native_release_available());assert(!setup_native_release_pair(p));
 assert(!setup_native_release_source(p,0));assert(setup_native_release_source(p,1));
 assert(setup_native_release_source(p,2));assert(setup_native_release_source(0,0));
 p[0].sha256[0]^=1;assert(setup_native_release_pair(p));p[0].sha256[0]^=1;
 p[1].bytes++;assert(setup_native_release_pair(p));
#else
 assert(!setup_native_release_available());assert(setup_native_release_pair(p));
#endif
 assert(setup_native_release_pair(0));return 0;
}
''')
            for compiler in ('gcc', 'clang'):
                for active in (False, True):
                    cmd = [compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-I', str(header),
                           str(test), str(header/'setup_native_release.c'), '-o', str(base/'test')]
                    if active:
                        cmd += ['-DSHZ_STANDALONE', '-DSHZ_NATIVE_INSTALLER_RELEASE', str(record)]
                    subprocess.run(cmd, check=True)
                    subprocess.run([str(base/'test')], check=True)
                valid = release.render_record(row, sim, 'c'*64)
                for forged in (valid.replace(b'0x31524e53u', b'0x31524e52u'),
                               valid.replace(b'1u,128u,0u', b'2u,128u,0u'),
                               valid.replace(b'1u,128u,0u', b'1u,128u,1u'),
                               valid.replace(b'100ull,200ull', b'0ull,200ull'),
                               valid.replace(b'100ull,200ull', b'100ull,268435457ull')):
                    record.write_bytes(forged)
                    subprocess.run([compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                                    '-DSHZ_STANDALONE', '-DSHZ_NATIVE_INSTALLER_RELEASE', '-DHOST_INVALID_RECORD',
                                    '-I', str(header), str(test), str(header/'setup_native_release.c'),
                                    str(record), '-o', str(base/'forged')], check=True, capture_output=True)
                    subprocess.run([str(base/'forged')], check=True)
                record.write_bytes(valid)
                result = subprocess.run([compiler, '-std=gnu11', '-DSHZ_NATIVE_INSTALLER_RELEASE',
                                         '-I', str(header), '-c', str(header/'setup_native_release.c'),
                                         '-o', str(base/'bad.o')], capture_output=True)
                self.assertNotEqual(result.returncode, 0, 'release macro cannot enter normal target kernel')


if __name__ == '__main__':
    unittest.main()
