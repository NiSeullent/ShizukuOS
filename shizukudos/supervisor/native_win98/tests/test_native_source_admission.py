# SPDX-License-Identifier: GPL-2.0-only
"""Actual leased source loading; private recipe and VM admission are not exercised."""
import argparse
import fcntl
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


parser = argparse.ArgumentParser()
parser.add_argument('--source', type=Path,
                    default=Path(__file__).resolve().parent.parent / 'task_custody.py')
args, remaining = parser.parse_known_args()
definition = importlib.util.spec_from_file_location('source_admission_guardian', args.source)
guardian = importlib.util.module_from_spec(definition)
definition.loader.exec_module(guardian)
NATIVE = 'shizukudos/supervisor/native_win98/native_epoch_host.py'


class SourceAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-admission-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.source = args.source.read_bytes()
        self.rpc_source = Path(guardian.rpc.__file__).read_bytes()
        self.sources = {}
        for relative in guardian.SOURCES:
            raw = self.source if relative == guardian.SOURCES[-2] else (
                self.rpc_source if relative == guardian.SOURCES[-3] else b'VALUE = 7\n')
            self.sources[relative] = self.write_source(relative, raw)
        self.native = self.write_source(NATIVE, b'VALUE = "held native source"\n')
        self.marker = mock.patch.object(guardian, '__executed_sha256__',
                                       hashlib.sha256(self.source).hexdigest(), create=True)
        self.marker.start()
        self.addCleanup(self.marker.stop)
        self.rpc_marker = mock.patch.object(guardian.rpc, '__executed_sha256__',
                                           hashlib.sha256(self.rpc_source).hexdigest(), create=True)
        self.rpc_marker.start()
        self.addCleanup(self.rpc_marker.stop)
        self.union = guardian.LeaseUnion()
        self.addCleanup(self.union.close)

    def write_source(self, relative, raw):
        path = self.repo / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        path.chmod(0o600)
        return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}

    def admit(self, sources=None):
        return guardian.admit_runtime_sources(self.repo,
                                               self.sources if sources is None else sources,
                                               self.union)

    def test_legacy_complete_closure_retains_actual_read_leases(self):
        self.admit()
        self.assertEqual(set(self.union.rows), {row['path'] for row in self.sources.values()})
        for row in self.union.rows.values():
            self.assertEqual(fcntl.fcntl(row['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
            self.assertTrue(row['full_SHA_admitted'])

    def test_declared_native_source_is_admitted_without_changing_legacy_roles(self):
        sources = {**self.sources, NATIVE: self.native}
        self.admit(sources)
        self.assertIn(self.native['path'], self.union.rows)
        self.assertEqual(guardian.SOURCES[-3].rsplit('/', 1)[1], 'custody_rpc.py')
        self.assertEqual(guardian.SOURCES[-2].rsplit('/', 1)[1], 'task_custody.py')
        self.assertEqual(guardian.SOURCES[-1].rsplit('/', 1)[1], 'disk_lineage.py')

    def test_native_source_cannot_replace_an_original_required_source(self):
        sources = {**self.sources, NATIVE: self.native}
        del sources[guardian.SOURCES[0]]
        with self.assertRaises(ValueError):
            self.admit(sources)
        self.assertEqual(self.union.rows, {})

    def test_unknown_extra_source_is_refused_before_any_lease(self):
        with self.assertRaises(ValueError):
            self.admit({**self.sources, 'extra.py': self.native})
        self.assertEqual(self.union.rows, {})

    def test_native_source_path_must_match_the_declared_repository_role(self):
        wrong = self.write_source('other.py', b'VALUE = 9\n')
        with self.assertRaises(ValueError):
            self.admit({**self.sources, NATIVE: wrong})
        self.assertNotIn(wrong['path'], self.union.rows)

    def test_native_source_full_hash_mismatch_is_refused(self):
        wrong = {**self.native, 'sha256': '1' * 64}
        with self.assertRaises(ValueError):
            self.admit({**self.sources, NATIVE: wrong})
        self.assertNotIn(wrong['path'], self.union.rows)

    def test_independently_executed_guardian_marker_must_match(self):
        with mock.patch.object(guardian, '__executed_sha256__', '1' * 64):
            with self.assertRaises(ValueError):
                self.admit()

    def test_independently_executed_rpc_marker_must_match(self):
        with mock.patch.object(guardian.rpc, '__executed_sha256__', '1' * 64):
            with self.assertRaises(ValueError):
                self.admit()

    def test_held_module_execution_has_exact_source_hash_marker(self):
        self.union.add(self.native)
        module = guardian.admitted_module('held_native_probe', self.native, self.union)
        self.assertEqual(module.VALUE, 'held native source')
        self.assertEqual(module.__executed_sha256__, self.native['sha256'])

    def test_import_refusal_after_execution_does_not_return_the_module(self):
        self.union.add(self.native)
        with mock.patch.object(self.union, 'check',
                               side_effect=[None, RuntimeError('cancelled during import')]):
            with self.assertRaisesRegex(RuntimeError, 'cancelled during import'):
                guardian.admitted_module('cancelled_probe', self.native, self.union)


if __name__ == '__main__':
    unittest.main(argv=[sys.argv[0], *remaining])
