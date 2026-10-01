"""Memory-only parser controls; synthetic reports establish no native result."""
import unittest

import review_native as review


FIXTURE = b"inert own fixture bytes"


def probe():
    rows = ["SCOPE=OWN_MAPPED_TLS_PROVIDER_WORKER_INGRESS", "APPLICATION_SUCCESS=0",
            "PRODUCTION_PROVIDER_INTEGRATED=0", "ORIGINAL_FIXTURE_BYTES=%08X" % len(FIXTURE),
            "ORIGINAL_FIXTURE_FNV1A=%08X" % review.fnv(FIXTURE)]
    for label, count in review.EXPECTED.items():
        rows.extend(["PASS=" + label] * count)
    rows += ["CHECKS=%08X" % sum(review.EXPECTED.values()), "FAILURES=00000000", "STATUS=PASS",
             "OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1"]
    return ("\r\n".join(rows) + "\r\n").encode("ascii")


def suite():
    return ("SCOPE=OWN_MAPPED_PROVIDER_INGRESS_OBSERVER\r\nAPPLICATION_SUCCESS=0\r\n"
            "ACTUAL_CHILD_PID=0000002A\r\nACTUAL_WAIT=00000000\r\nACTUAL_CHILD_OS_EXIT=00000000\r\n"
            "STATUS=SCOPED_NATIVE_INGRESS_PASS\r\nSUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1\r\n").encode("ascii")


class ReviewControls(unittest.TestCase):
    def test_valid_probe_stays_scoped(self):
        result = review.parse_probe(probe(), FIXTURE)
        self.assertEqual(result["worker_os_exit_zero_count"], 2)
        self.assertEqual(result["mapped_ms_abi_tls_calls"], 256)
        self.assertFalse(result["real_provider_integrated"])

    def test_missing_or_wrong_semantic_assertion(self):
        for altered in (probe().replace(b"PASS=MAIN_TLS_DETACHED\r\n", b""),
                        probe().replace(b"PASS=ACTUAL_PROVIDER_THREAD_EXIT_ZERO", b"PASS=OTHER_RESULT", 1)):
            with self.assertRaises(ValueError):
                review.parse_probe(altered, FIXTURE)

    def test_inconsistent_count(self):
        with self.assertRaises(ValueError):
            review.parse_probe(probe().replace(b"CHECKS=0000003F", b"CHECKS=0000003E"), FIXTURE)

    def test_failure_row_cannot_hide_behind_zero_aggregate(self):
        with self.assertRaises(ValueError):
            review.parse_probe(probe() + b"FAIL=UNEXPECTED\r\n", FIXTURE)

    def test_duplicate_status(self):
        with self.assertRaises(ValueError):
            review.parse_probe(probe() + b"STATUS=PASS\r\n", FIXTURE)

    def test_scope_promotion_refused(self):
        with self.assertRaises(ValueError):
            review.parse_probe(probe().replace(b"PRODUCTION_PROVIDER_INTEGRATED=0", b"PRODUCTION_PROVIDER_INTEGRATED=1"), FIXTURE)

    def test_same_size_fixture_replacement(self):
        with self.assertRaises(ValueError):
            review.parse_probe(probe(), b"X" + FIXTURE[1:])

    def test_complete_ascii_crlf(self):
        for malformed in (probe()[:-1], probe().replace(b"\r\n", b"\n"), probe() + b"\x00\r\n", probe() + b"\xff\r\n"):
            with self.assertRaises((ValueError, UnicodeError)):
                review.parse_probe(malformed, FIXTURE)

    def test_valid_observer_does_not_claim_its_own_exit(self):
        result = review.parse_suite(suite())
        self.assertEqual(result["actual_probe_os_exit"], 0)
        self.assertIsNone(result["suite_own_os_exit"])
        self.assertFalse(result["suite_own_os_exit_verified"])

    def test_real_nonzero_exit_or_timeout(self):
        for altered in (suite().replace(b"ACTUAL_CHILD_OS_EXIT=00000000", b"ACTUAL_CHILD_OS_EXIT=00000103"),
                        suite().replace(b"ACTUAL_WAIT=00000000", b"ACTUAL_WAIT=00000102"),
                        suite() + b"GUARD_TERMINATED=00000001\r\n"):
            with self.assertRaises(ValueError):
                review.parse_suite(altered)

    def test_missing_or_duplicate_actual_pid(self):
        for altered in (suite().replace(b"ACTUAL_CHILD_PID=0000002A\r\n", b""), suite() + b"ACTUAL_CHILD_PID=0000002B\r\n"):
            with self.assertRaises(ValueError):
                review.parse_suite(altered)

    def test_unobserved_outer_exit_stays_explicit(self):
        with self.assertRaises(ValueError):
            review.parse_suite(suite().replace(b"SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=1", b"SUITE_OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=0"))


if __name__ == "__main__":
    unittest.main()
