# SPDX-License-Identifier: GPL-2.0-only
"""Adversarial host controls: these synthetic logs are never native evidence."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('readonly_native_review', ROOT / 'tools/verify_chromium_readonly_native.py')
reviewer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reviewer)

# Independent transcript of the held C producers. Native structure fields are
# hex DWORDs except their explicit text flags. These are HOST TESTS ONLY.
STRUCTURE = b'''SCOPE=ORIGINAL_CHROMIUM_NATIVE_READONLY_STRUCTURE_ONLY
TARGET_ENTRY_CALLS=0
TARGET_IMPORTS_RESOLVED=0
TARGET_TLS_CALLBACK_CALLS=0
APPLICATION_FUNCTIONALITY_VERIFIED=0
NATIVE_OS_PLATFORM=00000001
NATIVE_OS_MAJOR=00000004
NATIVE_OS_MINOR=0000000A
NATIVE_OS_BUILD=000008AE
ACTUAL_FILE_SHA256=f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158
ACTUAL_FILE_BYTES=10E16600
READONLY_NATIVE_VIEW=10000000
DEFAULT_FILE_CAP=02000000
DEFAULT_IMAGE_CAP=04000000
DEFAULT_REFUSAL=FILE_SIZE
DECLARED_IMAGE_BYTES=10FC4000
EXACT_LOGICAL_BUDGET=21DDA600
IMPORT_RECORDS_CHECKED=00000515
DEFAULT_RELOCATION_REFUSED=RELOC_LIMIT
HIGHLOW_ENTRIES_CHECKED=00472C3D
TLS_STRUCTURE_PRESENT=00000001
TLS_CALLBACKS_NOT_INVOKED=00000006
EXECUTION_PROFILE_STILL_REFUSED=1
RUNTIME_PROFILE_STILL_REFUSED=1
STATUS=NATIVE_READONLY_STRUCTURE_PASS
SELECTED_EXIT_CODE=00000000
'''.replace(b'\n', b'\r\n')
WAIT = b'''FRESH_REPORT_ERROR=00000002
ACTUAL_CHILD_PID=00001234
ACTUAL_WAIT_RESULT=00000000
ACTUAL_WAIT_ERROR=00000000
ACTUAL_CHILD_OS_EXIT=00000000
OBSERVER_SELECTED_RESULT=00000000
'''.replace(b'\n', b'\r\n')
OUTER = b'''OUTER_ENTRY_REACHED=00000001
CHROMIUM_TARGET_ENTRY_CALLS=00000000
CHROMIUM_APPLICATION_ACCEPTED=00000000
ACTUAL_ORIGINAL_WIN98_GUARD=00000001
ORIGINAL_KERNEL_RESOLVER=00000001
HELPER_ACTUAL_BYTES=000022F7
HELPER_EXACT_SHA_AND_BYTES=00000001
ACTUAL_HELPER_PID=00005678
HELPER_PROCESS_CREATED=00000001
ACTUAL_HELPER_WAIT=00000000
ACTUAL_HELPER_WAIT_ERROR=00000000
ACTUAL_HELPER_OS_EXIT=00000000
INNER_OBSERVER_LOG_READABLE=00000001
INNER_STRUCTURE_LOG_READABLE=00000001
OUTER_SELECTED_RESULT=00000000
OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=00000001
'''.replace(b'\n', b'\r\n')


class NativeLogReview(unittest.TestCase):
    def setUp(self):
        # Each negative control starts with a valid positive transcript, so an
        # unrelated fixture mistake cannot make rejection checks falsely pass.
        self.assertFalse(reviewer.review_log_chain(STRUCTURE, WAIT, OUTER)['application_success'])

    def review(self, structure=STRUCTURE, wait=WAIT, outer=OUTER):
        return reviewer.review_log_chain(structure, wait, outer)

    def refused(self, index, raw):
        logs = [STRUCTURE, WAIT, OUTER]
        logs[index] = raw
        with self.assertRaises(reviewer.EvidenceError):
            reviewer.review_log_chain(*logs)

    def test_complete_chain_preserves_all_acceptance_limits(self):
        result = self.review()
        self.assertEqual(result['reported_structure_child_pid'], 0x1234)
        self.assertEqual(result['reported_inner_observer_pid'], 0x5678)
        self.assertEqual(result['relocations_checked'], 4664381)
        self.assertFalse(result['application_success'])
        self.assertFalse(result['outer_observer_own_os_exit_proven'])
        self.assertFalse(result['native_evidence_independently_accepted'])

    def test_direct_original_resolver_without_resident_kernel_ex(self):
        result = self.review(outer=OUTER.replace(b'ORIGINAL_KERNEL_RESOLVER=00000001', b'ORIGINAL_KERNEL_RESOLVER=00000000'))
        self.assertEqual(result['original_kernel_resolver'], 0)

    def test_missing_duplicate_truncated_or_overlong_transcripts(self):
        for index, raw in enumerate((STRUCTURE, WAIT, OUTER)):
            for bad in (b'', raw[:-2], raw.split(b'\r\n', 1)[1], raw + raw.split(b'\r\n', 1)[0] + b'\r\n',
                        raw.replace(b'\r\n', b'\n'), raw + b'A=' + b'0' * 16384 + b'\r\n'):
                with self.subTest(index=index, size=len(bad)):
                    self.refused(index, bad)

    def test_unknown_guard_or_error_even_with_selected_zero(self):
        for index in range(3):
            for extra in (b'GUARD_TERMINATE=00000001\r\n', b'UNMAP_ERROR=00000005\r\n',
                          b'HOST_TEST_ONLY_SYNTHETIC_MARKER=1\r\n'):
                with self.subTest(index=index, extra=extra):
                    self.refused(index, (STRUCTURE, WAIT, OUTER)[index] + extra)

    def test_original_platform_counts_hash_and_gate_must_match(self):
        mutations = [
            (b'NATIVE_OS_PLATFORM=00000001', b'NATIVE_OS_PLATFORM=00000002'),
            (b'NATIVE_OS_BUILD=000008AE', b'NATIVE_OS_BUILD=000008AF'),
            (b'ACTUAL_FILE_SHA256=f8dec', b'ACTUAL_FILE_SHA256=f9dec'),
            (b'IMPORT_RECORDS_CHECKED=00000515', b'IMPORT_RECORDS_CHECKED=00000514'),
            (b'HIGHLOW_ENTRIES_CHECKED=00472C3D', b'HIGHLOW_ENTRIES_CHECKED=00472C3C'),
            (b'TLS_CALLBACKS_NOT_INVOKED=00000006', b'TLS_CALLBACKS_NOT_INVOKED=00000000'),
            (b'TARGET_ENTRY_CALLS=0', b'TARGET_ENTRY_CALLS=1'),
            (b'APPLICATION_FUNCTIONALITY_VERIFIED=0', b'APPLICATION_FUNCTIONALITY_VERIFIED=1'),
            (b'DEFAULT_FILE_CAP=02000000', b'DEFAULT_FILE_CAP=20000000'),
            (b'RUNTIME_PROFILE_STILL_REFUSED=1', b'RUNTIME_PROFILE_STILL_REFUSED=0'),
            (b'READONLY_NATIVE_VIEW=10000000', b'READONLY_NATIVE_VIEW=FFFFFFFF'),
        ]
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, STRUCTURE)
                self.refused(0, STRUCTURE.replace(before, after))

    def test_real_wait_and_exit_are_required_from_both_parents(self):
        for index, raw, wait_key, exit_key in ((1, WAIT, b'ACTUAL_WAIT_RESULT', b'ACTUAL_CHILD_OS_EXIT'),
                                              (2, OUTER, b'ACTUAL_HELPER_WAIT', b'ACTUAL_HELPER_OS_EXIT')):
            for key, value in ((wait_key, b'00000102'), (exit_key, b'00000103'),
                               (exit_key, b'00000003')):
                with self.subTest(index=index, key=key, value=value):
                    self.refused(index, raw.replace(key + b'=00000000', key + b'=' + value))

    def test_distinct_pids_and_exact_outer_provenance_fields(self):
        for value in (b'00000000', b'00001234', b'0000abcd', b'FFFFFFFFF'):
            self.refused(2, OUTER.replace(b'ACTUAL_HELPER_PID=00005678', b'ACTUAL_HELPER_PID=' + value))
        for before, after in (
            (b'ACTUAL_ORIGINAL_WIN98_GUARD=00000001', b'ACTUAL_ORIGINAL_WIN98_GUARD=00000000'),
            (b'ORIGINAL_KERNEL_RESOLVER=00000001', b'ORIGINAL_KERNEL_RESOLVER=00000002'),
            (b'INNER_STRUCTURE_LOG_READABLE=00000001', b'INNER_STRUCTURE_LOG_READABLE=00000000'),
            (b'OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=00000001', b'OUTER_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=00000000'),
        ):
            self.refused(2, OUTER.replace(before, after))

    def test_host_composition_fixture_cannot_become_native_proof(self):
        fixture = ROOT / 'build/chromium-observer-composition-fat-20261001T0700-v3/positive-real-original-three'
        with self.assertRaises((reviewer.EvidenceError, OSError)):
            reviewer.verify_run(fixture)

    def test_interrupted_native_run_cannot_become_native_proof(self):
        fixture = ROOT / 'build/shizukudos/csm/run-win98-gop-chromium-ro-large-20261001T0337'
        with self.assertRaises((reviewer.EvidenceError, OSError)):
            reviewer.verify_run(fixture)


if __name__ == '__main__':
    unittest.main()
