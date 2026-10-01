#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual owned pipe children: no sockets, VM or foreign-process control."""
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from build_tls13_i486 import read_owned_port


class Startup(unittest.TestCase):
    def child_case(self, source, *, expected=None, error=None, timeout=0.5):
        child = subprocess.Popen([sys.executable, "-B", "-u", "-c", source],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        fd = child.stdout.fileno()
        original_blocking = os.get_blocking(fd)
        started = time.monotonic()
        try:
            if error is None:
                self.assertEqual(read_owned_port(child.stdout, timeout), expected)
            else:
                with self.assertRaisesRegex(RuntimeError, error):
                    read_owned_port(child.stdout, timeout)
            self.assertEqual(os.get_blocking(fd), original_blocking)
            self.assertLess(time.monotonic() - started, timeout + 1.0)
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=1)
            child.stdout.close()
            child.stderr.close()
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_complete_low_high_ports(self):
        for port in (1, 65535):
            with self.subTest(port=port):
                self.child_case("import os; os.write(1, b'PORT=%d\\n')" % port,
                                expected=("PORT=%d\n" % port).encode())

    def test_fragmented_complete(self):
        self.child_case("import os,time; os.write(1,b'PO'); time.sleep(.03); "
                        "os.write(1,b'RT=12345'); time.sleep(.03); os.write(1,b'\\n')",
                        expected=b"PORT=12345\n")

    def test_following_endpoint_log_stays_unconsumed(self):
        child = subprocess.Popen([sys.executable, "-B", "-u", "-c",
                                  "import os; os.write(1,b'PORT=19\\nENDPOINT\\n')"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertEqual(read_owned_port(child.stdout, 0.5), b"PORT=19\n")
            rest, err = child.communicate(timeout=1)
            self.assertEqual(rest, b"ENDPOINT\n")
            self.assertEqual(err, b"")
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=1)
            child.stdout.close()
            child.stderr.close()

    def test_partial_stalled(self):
        self.child_case("import os,time; os.write(1,b'PORT=12'); time.sleep(10)",
                        error="startup deadline", timeout=0.2)

    def test_no_bytes_stalled(self):
        self.child_case("import time; time.sleep(10)", error="startup deadline", timeout=0.2)

    def test_eof_empty_and_partial(self):
        for data in (b"", b"PORT=123"):
            with self.subTest(data=data):
                self.child_case("import os; os.write(1,%r)" % data, error="startup EOF")

    def test_oversized_with_and_without_newline(self):
        for newline in (b"", b"\n"):
            with self.subTest(newline=newline):
                self.child_case("import os,time; os.write(1,%r); time.sleep(10)" %
                                (b"PORT=" + b"1" * 60 + newline), error="exceeds 64 bytes")

    def test_malformed_and_out_of_range(self):
        for line in (b"PORT=0\n", b"PORT=65536\n", b"PORT=-1\n", b"PORT=1\r\n",
                     b"OTHER=1\n", b"PORT=\n", b"PORT=1 trailing\n"):
            with self.subTest(line=line):
                self.child_case("import os; os.write(1,%r)" % line, error="isolated LTS loopback port")

    def test_slow_writer_does_not_restart_absolute_deadline(self):
        self.child_case("import os,time; "
                        "[(os.write(1,bytes([c])),time.sleep(.08)) for c in b'PORT=12345\\n']",
                        error="startup deadline", timeout=0.25)

    def test_invalid_deadline_rejected(self):
        for timeout in (0, -1, 5.1, True, float("inf"), float("nan")):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(RuntimeError, "bounded owned server startup timeout"):
                    read_owned_port(None, timeout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
