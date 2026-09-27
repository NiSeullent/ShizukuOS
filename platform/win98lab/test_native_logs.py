#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""SYNTHETIC log fixtures only: these tests provide NO native execution evidence.

All fixture strings are independently assembled from the documented probe
contracts, not emitted by a guest or by the parser. Filesystem tests use private
temporary files only; no VM, installation media, native binary or real log runs.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('ntw_verify_native_logs', HERE / 'verify_native_logs.py')
v = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(v)

# Explicit synthetic success-shaped transcript. This is NOT a recorded pass.
RUNNER = '''NTWRUN_VERSION=1
DIRECTORY=C:\\NTWLAB
OS_PLATFORM=1
OS_MAJOR=4
OS_MINOR=10
OS_BUILD_RAW=67766446
OS_BUILD_LOW=2222
WIN98_IDENTIFIED=1
PREFLIGHT=PASS
BEGIN=NTWPROBE.EXE
PROCESS_CREATED=1
WAIT_RESULT=0
EXIT_CODE=0
CLOSE_THREAD=PASS
CLOSE_PROCESS=PASS
END=NTWPROBE.EXE
BEGIN=NTWQUERY.EXE
PROCESS_CREATED=1
WAIT_RESULT=0
EXIT_CODE=0
CLOSE_THREAD=PASS
CLOSE_PROCESS=PASS
END=NTWQUERY.EXE
BEGIN=NTWGPROB.EXE
PROCESS_CREATED=1
WAIT_RESULT=0
EXIT_CODE=0
CLOSE_THREAD=PASS
CLOSE_PROCESS=PASS
END=NTWGPROB.EXE
RESULT=PASS
'''
VXD = '''START NTWrapper9x native VxD query ABI 0x00000001
BEGIN load cycle 0x00000001
PASS dynamic load/open 0x00000001
PASS version/core initialization/event selftest 0x00000001
PASS unknown/short/input request errors 0x00000003
PASS close/unload request 0x00000001
BEGIN load cycle 0x00000002
PASS dynamic load/open 0x00000002
PASS version/core initialization/event selftest 0x00000001
PASS unknown/short/input request errors 0x00000003
PASS close/unload request 0x00000002
PASS: NTWrapper9x native VxD probe 0x00000000
'''
GDI = '''NTWDDMWrapper9x native GDI probe v1
SCOPE=app-owned software DIB; no WDDM/D3D/GPU claim
OS_PLATFORM=1
OS_MAJOR=4
OS_MINOR=10
OS_BUILD=67766446
WIN98_IDENTIFIED=1
DISPLAY_BITSPIXEL=16
DISPLAY_PLANES=1
PIXEL_CONTRACT_CHECKS=128014
PIXEL_CONTRACTS=PASS
FENCE_SCOPE=CPU copy only
SUCCESSFUL_PAINTS=20
CLEANUP=PASS
RESULT=PASS
'''


def fixture():
    text = {'NTWRUN.LOG': RUNNER, 'NTWPROBE.LOG': 'PASS: NTWin32Wrapper9x static imports\n',
            'NTWQUERY.LOG': VXD, 'NTWGPROB.LOG': GDI}
    return {name: value.replace('\n', '\r\n').encode('ascii') for name, value in text.items()}


class SyntheticNativeLogTests(unittest.TestCase):
    def rejected(self, logs, exit_code=0):
        with self.assertRaises(v.NativeLogError):
            v.verify_logs(logs, exit_code)

    def test_complete_synthetic_claim_is_never_native_verification(self):
        logs = fixture()
        result = v.verify_logs(logs, 0)
        self.assertEqual(result['schema'], 'ntw.native_logs.v1')
        self.assertIs(result['guest_reported_pass'], True)
        self.assertIs(result['complete_success'], True)
        self.assertIs(result['native_execution_verified'], False)
        self.assertIs(result['provenance_required'], True)
        self.assertEqual(result['assessment_scope'], 'guest-reported log consistency only')
        self.assertIsNone(result['incomplete_reason'])
        self.assertEqual(result['os'], {'platform': 1, 'major': 4, 'minor': 10,
                                       'build_raw': 0x040a08ae, 'build_low': 2222})
        self.assertEqual(result['gdi']['pixel_contract_checks'], 128014)
        self.assertEqual(result['gdi']['successful_paints'], 20)
        self.assertEqual(result['child_exit_codes'], {'NTWPROBE.EXE': 0, 'NTWQUERY.EXE': 0, 'NTWGPROB.EXE': 0})
        self.assertEqual(len(result['independent_evidence_required']), 4)
        self.assertEqual(result['logs'], {name: {'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                                          for name, data in logs.items()})
        self.assertEqual(logs, fixture())

    def test_missing_or_nonzero_supervisor_exit_never_completes(self):
        for code in (None, 1, 2, 3, 259, 65536, 0x80000005, 0xffffffff):
            with self.subTest(code=code):
                result = v.verify_logs(fixture(), code)
                self.assertIs(result['guest_reported_pass'], True)
                self.assertIs(result['complete_success'], False)
                self.assertIs(result['native_execution_verified'], False)
                self.assertEqual(result['runner_exit_code'], code)
                self.assertTrue(result['incomplete_reason'])
        self.assertIn('final log-close failure', v.verify_logs(fixture())['incomplete_reason'])

    def test_invalid_exit_argument_types_and_range(self):
        for code in (-1, 0x100000000, True, False, '0', b'0', 0.0, [], object()):
            with self.subTest(code=repr(code)):
                self.rejected(fixture(), code)

    def test_exact_inventory_and_immutable_bytes_required(self):
        logs = fixture()
        for name in logs:
            altered = dict(logs)
            del altered[name]
            self.rejected(altered)
            for bad in (None, '', logs[name].decode(), bytearray(logs[name]), memoryview(logs[name]), 123):
                altered = dict(logs)
                altered[name] = bad
                self.rejected(altered)
        self.rejected({**logs, 'OTHER.LOG': b'PASS\r\n'})
        self.rejected(None)
        self.rejected(list(logs.items()))

    def test_every_byte_truncation_rejected(self):
        baseline = fixture()
        count = 0
        for name, data in baseline.items():
            for cut in range(len(data)):
                self.rejected({**baseline, name: data[:cut]})
                count += 1
        self.assertEqual(count, 1444)

    def test_every_byte_high_bit_mutation_rejected(self):
        baseline = fixture()
        for name, data in baseline.items():
            for offset in range(len(data)):
                mutated = data[:offset] + bytes((data[offset] ^ 0x80,)) + data[offset + 1:]
                self.rejected({**baseline, name: mutated})

    def test_exact_crlf_printable_ascii_and_no_padding(self):
        logs = fixture()
        for name, data in logs.items():
            for bad in (data.replace(b'\r\n', b'\n'), data.replace(b'\r\n', b'\r'),
                        b'\xef\xbb\xbf' + data, data + b'\r\n', data + b'\0', data + b'\x1a',
                        b' ' + data, data[:-2] + b' \r\n', b'\t' + data[1:],
                        data.replace(b'PASS', b'PA\x00SS', 1), b'X' * 4097 + b'\r\n'):
                self.rejected({**logs, name: bad})

    def test_each_line_removal_duplication_and_reordering(self):
        logs = fixture()
        for name, data in logs.items():
            lines = data.splitlines(keepends=True)
            for index in range(len(lines)):
                removed = lines[:index] + lines[index + 1:]
                doubled = lines[:index] + [lines[index]] + lines[index:]
                self.rejected({**logs, name: b''.join(removed)})
                self.rejected({**logs, name: b''.join(doubled)})
                changed = lines[:]
                changed[index] = b'?' + changed[index][1:]
                self.rejected({**logs, name: b''.join(changed)})
            for index in range(len(lines) - 1):
                swapped = lines[:]
                swapped[index], swapped[index + 1] = swapped[index + 1], swapped[index]
                self.rejected({**logs, name: b''.join(swapped)})

    def test_child_failure_timeout_or_missing_cleanup_cannot_mix_with_pass(self):
        logs = fixture()
        for before, after in ((b'PROCESS_CREATED=1', b'PROCESS_CREATED=0'),
                              (b'WAIT_RESULT=0', b'WAIT_RESULT=258'),
                              (b'WAIT_RESULT=0', b'WAIT_RESULT=4294967295'),
                              (b'EXIT_CODE=0', b'EXIT_CODE=1'),
                              (b'EXIT_CODE=0', b'EXIT_CODE=4294967295'),
                              (b'CLOSE_THREAD=PASS', b'CLOSE_THREAD=FAIL'),
                              (b'CLOSE_PROCESS=PASS', b'CLOSE_PROCESS=FAIL'),
                              (b'PREFLIGHT=PASS', b'EXISTING_LOG=NTWPROBE.LOG'),
                              (b'RESULT=PASS', b'RESULT=FAIL')):
            for occurrence in (1, 2, 3):
                self.rejected({**logs, 'NTWRUN.LOG': logs['NTWRUN.LOG'].replace(before, after, occurrence)})
        for name, data in logs.items():
            self.rejected({**logs, name: data + b'FAIL_STAGE=injected\r\n'})

    def test_exact_vxd_two_cycles_and_abi(self):
        logs = fixture()
        data = logs['NTWQUERY.LOG']
        for old, new in ((b'ABI 0x00000001', b'ABI 0x00000002'),
                         (b'BEGIN load cycle 0x00000002', b'BEGIN load cycle 0x00000001'),
                         (b'request errors 0x00000003', b'request errors 0x00000002'),
                         (b'selftest 0x00000001', b'selftest 0x00000000'),
                         (b'probe 0x00000000', b'probe 0x00000001')):
            self.rejected({**logs, 'NTWQUERY.LOG': data.replace(old, new, 1)})

    def test_os_identity_raw_low_and_cross_log_match(self):
        logs = fixture()
        for name in ('NTWRUN.LOG', 'NTWGPROB.LOG'):
            for old, new in ((b'OS_PLATFORM=1', b'OS_PLATFORM=2'), (b'OS_MAJOR=4', b'OS_MAJOR=10'),
                             (b'OS_MINOR=10', b'OS_MINOR=90'), (b'WIN98_IDENTIFIED=1', b'WIN98_IDENTIFIED=0')):
                self.rejected({**logs, name: logs[name].replace(old, new)})
        self.rejected({**logs, 'NTWRUN.LOG': logs['NTWRUN.LOG'].replace(b'OS_BUILD_LOW=2222', b'OS_BUILD_LOW=1998')})
        self.rejected({**logs, 'NTWGPROB.LOG': logs['NTWGPROB.LOG'].replace(b'OS_BUILD=67766446', b'OS_BUILD=2222')})
        self.rejected({**logs, 'NTWGPROB.LOG': logs['NTWGPROB.LOG'].replace(b'OS_BUILD=67766446', b'OS_BUILD=67766222')})

    def test_dword_boundaries_are_canonical_and_do_not_truncate(self):
        for value in (0, 2222, 65535, 65536, 0x80000000, 0xffffffff):
            logs = fixture()
            logs['NTWRUN.LOG'] = logs['NTWRUN.LOG'].replace(b'OS_BUILD_RAW=67766446', ('OS_BUILD_RAW=' + str(value)).encode())
            logs['NTWRUN.LOG'] = logs['NTWRUN.LOG'].replace(b'OS_BUILD_LOW=2222', ('OS_BUILD_LOW=' + str(value & 65535)).encode())
            logs['NTWGPROB.LOG'] = logs['NTWGPROB.LOG'].replace(b'OS_BUILD=67766446', ('OS_BUILD=' + str(value)).encode())
            result = v.verify_logs(logs, 0)
            self.assertEqual(result['os']['build_raw'], value)
            self.assertIs(result['native_execution_verified'], False)
        for value in (b'-1', b'+1', b'01', b' 1', b'1 ', b'0x1', b'1.0', b'1e2',
                      b'4294967296', b'99999999999', b''):
            logs = fixture()
            for name, field, old in (('NTWRUN.LOG', b'OS_BUILD_RAW=', b'67766446'),
                                     ('NTWRUN.LOG', b'OS_BUILD_LOW=', b'2222'),
                                     ('NTWGPROB.LOG', b'SUCCESSFUL_PAINTS=', b'20'),
                                     ('NTWGPROB.LOG', b'DISPLAY_BITSPIXEL=', b'16')):
                self.rejected({**logs, name: logs[name].replace(field + old, field + value)})

    def test_gdi_counts_paints_scope_and_cleanup(self):
        logs = fixture()
        for old, new in ((b'PIXEL_CONTRACT_CHECKS=128014', b'PIXEL_CONTRACT_CHECKS=128013'),
                         (b'SUCCESSFUL_PAINTS=20', b'SUCCESSFUL_PAINTS=0'),
                         (b'PIXEL_CONTRACTS=PASS', b'PIXEL_CONTRACTS=FAIL'),
                         (b'CLEANUP=PASS', b'CLEANUP=FAIL'), (b'RESULT=PASS', b'RESULT=FAIL'),
                         (b'FENCE_SCOPE=CPU copy only', b'FENCE_SCOPE=GPU complete')):
            self.rejected({**logs, 'NTWGPROB.LOG': logs['NTWGPROB.LOG'].replace(old, new)})
        for count in (1, 0xffffffff):
            altered = {**logs, 'NTWGPROB.LOG': logs['NTWGPROB.LOG'].replace(b'SUCCESSFUL_PAINTS=20', ('SUCCESSFUL_PAINTS=' + str(count)).encode())}
            self.assertEqual(v.verify_logs(altered, 0)['gdi']['successful_paints'], count)

    def test_mapping_values_are_captured_once_for_hash_binding(self):
        class Once(dict):
            def __getitem__(self, key):
                self.reads[key] = self.reads.get(key, 0) + 1
                if self.reads[key] != 1:
                    raise AssertionError('parser reread a mutable mapping value')
                return super().__getitem__(key)
        source = Once(fixture())
        source.reads = {}
        result = v.verify_logs(source, 0)
        self.assertEqual(source.reads, {name: 1 for name in fixture()})
        self.assertEqual(result['logs']['NTWRUN.LOG']['sha256'], hashlib.sha256(fixture()['NTWRUN.LOG']).hexdigest())

    def test_bounded_reader_and_cli_only_consume_synthetic_temp_files(self):
        with tempfile.TemporaryDirectory(prefix='ntw-synthetic-logs-') as directory:
            root = Path(directory)
            for name, data in fixture().items():
                (root / name).write_bytes(data)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            self.assertEqual(v.read_logs(root), fixture())
            for arguments, expected in (([directory], 2), ([directory, '--runner-exit-code', '0'], 0),
                                        ([directory, '--runner-exit-code', '4294967295'], 2)):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(v.main(arguments), expected)
                result = json.loads(output.getvalue())
                self.assertIs(result['native_execution_verified'], False)
                self.assertIs(result['complete_success'], expected == 0)
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            bad = root / 'NTWPROBE.LOG'
            bad.write_bytes(b'FAIL\r\n')
            errors = io.StringIO()
            with contextlib.redirect_stderr(errors):
                self.assertEqual(v.main([directory, '--runner-exit-code', '0']), 1)
            self.assertIn('Native logs rejected:', errors.getvalue())

    def test_reader_rejects_missing_oversized_links_and_special_files(self):
        with tempfile.TemporaryDirectory(prefix='ntw-synthetic-logs-') as directory:
            root = Path(directory)
            for name, data in fixture().items():
                (root / name).write_bytes(data)
            target = root / 'NTWRUN.LOG'
            for size in (0, 4097):
                target.write_bytes(b'X' * size)
                with self.assertRaises(v.NativeLogError):
                    v.read_logs(root)
            target.unlink()
            with self.assertRaises(v.NativeLogError):
                v.read_logs(root)
            target.symlink_to(root / 'NTWQUERY.LOG')
            with self.assertRaises(v.NativeLogError):
                v.read_logs(root)
            target.unlink()
            os.mkfifo(target)
            with self.assertRaises(v.NativeLogError):
                v.read_logs(root)
            target.unlink()
            target.mkdir()
            with self.assertRaises(v.NativeLogError):
                v.read_logs(root)


if __name__ == '__main__':
    print('SYNTHETIC fixtures only; native execution remains unverified.', flush=True)
    unittest.main(verbosity=2)
