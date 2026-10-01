#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Negative controls for the guest's intentionally nonzero observation diagnostic."""
import unittest

import run_k64_standalone as runner

PARENT = "[win64 T_AUTORUN_OBSERVE.EXE pid 68] K64 observation fixture: actual parent pid 68 exits 7 after real child pid 76 acquired its process handle\n"
REAPED = "K64 win64 diagnostic: T_AUTORUN_OBSERVE.EXE pid=68 exit=7 faulted=0 reaped=0\n"
CHILD = "[win64 T_AUTORUN_OBSERVE.EXE pid 76] K64 observation fixture: real child pid 76 survived actual parent pid 68 exit 7 after delayed scheduling\n"


class ObservationDiagnosticTests(unittest.TestCase):
    def status(self, serial):
        return runner.observation_diagnostic(serial)["status"]

    def test_matching_real_identities_and_order(self):
        self.assertEqual(self.status(PARENT + REAPED + "other real app output\n" + CHILD), "PASS")

    def test_parent_exit_seven_alone_is_insufficient(self):
        for text in (REAPED, PARENT + REAPED, PARENT + CHILD, REAPED + CHILD, ""):
            with self.subTest(text=text):
                self.assertEqual(self.status(text), "FAIL")

    def test_false_exit_fault_and_wait_results(self):
        for wrong in ("exit=0", "exit=1", "faulted=1", "reaped=-1"):
            original = "exit=7" if wrong.startswith("exit") else "faulted=0" if wrong.startswith("faulted") else "reaped=0"
            with self.subTest(wrong=wrong):
                self.assertEqual(self.status(PARENT + REAPED.replace(original, wrong) + CHILD), "FAIL")

    def test_foreign_zero_or_self_process_identity(self):
        variants = (
            PARENT.replace("pid 68]", "pid 72]") + REAPED + CHILD,
            PARENT + REAPED.replace("pid=68", "pid=72") + CHILD,
            PARENT + REAPED + CHILD.replace("pid 76]", "pid 80]"),
            PARENT + REAPED + CHILD.replace("parent pid 68", "parent pid 72"),
            (PARENT + REAPED + CHILD).replace("68", "0"),
            (PARENT + REAPED + CHILD).replace("76", "68"),
        )
        for text in variants:
            with self.subTest(text=text):
                self.assertEqual(self.status(text), "FAIL")

    def test_no_duplicates_or_reversed_lifecycle(self):
        for text in (CHILD + PARENT + REAPED, REAPED + PARENT + CHILD,
                     PARENT + PARENT + REAPED + CHILD, PARENT + REAPED + CHILD + CHILD):
            with self.subTest(text=text):
                self.assertEqual(self.status(text), "FAIL")

    def test_diagnostic_must_not_be_reported_as_an_ordinary_app(self):
        for code in (0, 7):
            serial = PARENT + REAPED + CHILD + f"K64 win64 app: T_AUTORUN_OBSERVE.EXE exit={code} faulted=0\n"
            self.assertEqual(self.status(serial), "FAIL")


if __name__ == "__main__":
    unittest.main()
