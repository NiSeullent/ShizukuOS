# SPDX-License-Identifier: GPL-2.0-only
"""Guarded wait boundaries and real pipe readiness; no VM or device authority."""
import errno
import importlib.util
import os
from pathlib import Path
import time
import unittest
from unittest import mock


HELPER = Path(__file__).resolve().parents[1] / "native_epoch_guard_pump.py"


class GuardedSelectTests(unittest.TestCase):
    def pump(self):
        self.assertTrue(HELPER.is_file(), "the guarded one-slice wait helper is missing")
        spec = importlib.util.spec_from_file_location("native_epoch_guard_pump_test", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_one_slice_caps_wait_and_checks_guard_before_returning_readiness(self):
        pump = self.pump()
        events = []
        ready = ([7], [8], [])

        def clock():
            events.append("clock")
            return 100_000_000

        def wait(readers, writers, errors, timeout):
            events.append("select")
            self.assertEqual((readers, writers, errors), ([7], [8], []))
            self.assertEqual(timeout, .025)
            return ready

        with mock.patch.object(pump.time, "monotonic_ns", side_effect=clock), \
                mock.patch.object(pump, "_poll_select", side_effect=wait) as selected:
            result = pump.checked_select([7], [8], 1_000_000_000,
                                         lambda: events.append("guard"))
        self.assertIs(result, ready)
        self.assertEqual(selected.call_count, 1)
        self.assertEqual(events, ["guard", "clock", "select", "guard", "clock"])

    def test_near_deadline_reduces_the_requested_slice(self):
        pump = self.pump()
        with mock.patch.object(pump.time, "monotonic_ns", side_effect=[100_000_000, 101_000_000]), \
                mock.patch.object(pump, "_poll_select", return_value=([], [], [])) as selected:
            self.assertEqual(pump.checked_select([], [], 105_000_000, lambda: None), ([], [], []))
        selected.assert_called_once_with([], [], [], .005)

    def test_repeated_caller_steps_keep_the_same_original_deadline(self):
        pump = self.pump()
        with mock.patch.object(pump.time, "monotonic_ns", side_effect=[100_000_000, 101_000_000,
                                                                    195_000_000, 196_000_000]), \
                mock.patch.object(pump, "_poll_select", return_value=([], [], [])) as selected:
            for _ in range(2):
                self.assertEqual(pump.checked_select([], [], 200_000_000, lambda: None), ([], [], []))
        self.assertEqual(selected.call_args_list, [mock.call([], [], [], .025),
                                                  mock.call([], [], [], .005)])

    def test_expired_deadline_does_not_select(self):
        pump = self.pump()
        guards = []
        with mock.patch.object(pump.time, "monotonic_ns", return_value=100), \
                mock.patch.object(pump, "_poll_select") as selected:
            with self.assertRaises(TimeoutError):
                pump.checked_select([], [], 100, lambda: guards.append(1))
        self.assertEqual(guards, [1])
        selected.assert_not_called()

    def test_initial_guard_cannot_consume_the_deadline_and_still_wait(self):
        pump = self.pump()
        now = [100]

        def guard():
            now[0] = 200

        with mock.patch.object(pump.time, "monotonic_ns", side_effect=lambda: now[0]), \
                mock.patch.object(pump, "_poll_select") as selected:
            with self.assertRaises(TimeoutError):
                pump.checked_select([], [], 200, guard)
        selected.assert_not_called()

    def test_deadline_reached_during_wait_refuses_even_ready_descriptors(self):
        pump = self.pump()
        guards = []
        with mock.patch.object(pump.time, "monotonic_ns", side_effect=[100, 200]), \
                mock.patch.object(pump, "_poll_select", return_value=([7], [], [])) as selected:
            with self.assertRaises(TimeoutError):
                pump.checked_select([7], [], 200, lambda: guards.append(1))
        self.assertEqual(guards, [1, 1])
        selected.assert_called_once_with([7], [], [], .0000001)

    def test_initial_guard_refusal_prevents_select(self):
        pump = self.pump()
        refusal = RuntimeError("owner cancelled")

        def guard():
            raise refusal

        with mock.patch.object(pump, "_poll_select") as selected:
            with self.assertRaises(RuntimeError) as observed:
                pump.checked_select([], [], time.monotonic_ns() + 1_000_000_000, guard)
        self.assertIs(observed.exception, refusal)
        selected.assert_not_called()

    def test_select_error_still_checks_the_post_guard(self):
        pump = self.pump()
        failure = OSError(errno.EBADF, "selected descriptor is invalid")
        guards = []
        with mock.patch.object(pump, "_poll_select", side_effect=failure) as selected:
            with self.assertRaises(OSError) as observed:
                pump.checked_select([], [], time.monotonic_ns() + 1_000_000_000,
                                    lambda: guards.append(1))
        self.assertIs(observed.exception, failure)
        self.assertEqual(guards, [1, 1])
        self.assertEqual(selected.call_count, 1)

    def test_first_select_error_remains_primary_when_post_guard_also_fails(self):
        pump = self.pump()
        first = OSError(errno.EBADF, "first select failure")
        later = RuntimeError("postguard lease broke")
        calls = []

        def guard():
            calls.append(1)
            if len(calls) == 2:
                raise later

        with mock.patch.object(pump, "_poll_select", side_effect=first):
            with self.assertRaises(OSError) as observed:
                pump.checked_select([], [], time.monotonic_ns() + 1_000_000_000, guard)
        self.assertIs(observed.exception, first)
        self.assertIs(observed.exception.__cause__, later)
        self.assertTrue(observed.exception.__suppress_context__)
        self.assertEqual(calls, [1, 1])

    def test_invalid_deadline_or_missing_owner_guard_is_refused_before_wait(self):
        pump = self.pump()
        with mock.patch.object(pump, "_poll_select") as selected:
            for value in (True, 100.0, None):
                with self.subTest(deadline=value), self.assertRaises(TypeError):
                    pump.checked_select([], [], value, lambda: None)
            with self.assertRaises(TypeError):
                pump.checked_select([], [], time.monotonic_ns() + 1_000_000_000, None)
        selected.assert_not_called()

    def test_real_pipe_readiness_leaves_the_byte_and_descriptors_with_the_caller(self):
        pump = self.pump()
        reader, writer = os.pipe()
        guards = []
        try:
            os.write(writer, b"x")
            self.assertEqual(pump.checked_select([reader], [], time.monotonic_ns() + 1_000_000_000,
                                                 lambda: guards.append(1)), ([reader], [], []))
            self.assertEqual(guards, [1, 1])
            os.fstat(reader)
            os.fstat(writer)
            self.assertEqual(os.read(reader, 1), b"x")
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_ready_pipe_is_not_consumed_when_post_guard_refuses(self):
        pump = self.pump()
        reader, writer = os.pipe()
        calls = []
        refusal = RuntimeError("owner resource floor consumed")

        def guard():
            calls.append(1)
            if len(calls) == 2:
                raise refusal

        try:
            os.write(writer, b"y")
            with self.assertRaises(RuntimeError) as observed:
                pump.checked_select([reader], [], time.monotonic_ns() + 1_000_000_000, guard)
            self.assertIs(observed.exception, refusal)
            self.assertEqual(calls, [1, 1])
            self.assertEqual(os.read(reader, 1), b"y")
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_writable_pipe_does_not_receive_a_hidden_write(self):
        pump = self.pump()
        reader, writer = os.pipe()
        try:
            os.set_blocking(reader, False)
            self.assertEqual(pump.checked_select([], [writer], time.monotonic_ns() + 1_000_000_000,
                                                 lambda: None), ([], [writer], []))
            with self.assertRaises(BlockingIOError):
                os.read(reader, 1)
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_closed_descriptor_error_keeps_post_guard_refusal_as_cause(self):
        pump = self.pump()
        reader, writer = os.pipe()
        os.close(reader)
        calls = []
        refusal = RuntimeError("owner cancellation after select")

        def guard():
            calls.append(1)
            if len(calls) == 2:
                raise refusal

        try:
            with self.assertRaises(OSError) as observed:
                pump.checked_select([reader], [], time.monotonic_ns() + 1_000_000_000, guard)
            self.assertEqual(observed.exception.errno, errno.EBADF)
            self.assertIs(observed.exception.__cause__, refusal)
            self.assertEqual(calls, [1, 1])
        finally:
            os.close(writer)


if __name__ == "__main__":
    unittest.main()
