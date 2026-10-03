"""HOST-ONLY COM2 framing regressions for the production HostGrant transport.

Real production methods (HostGrant.transfer/_receive_ready, checked_select,
validate_ready) over a real AF_UNIX socketpair. The QEMU/QMP/listener/ESP
device checks (HostGrant.check) are NOT exercised here: the constructor is
bypassed and check() is replaced by a no-op on the instance; the outer owner
guard is a real callable that is invoked and counted. Nothing here proves a
guest READY, a firmware console on COM2 or any VM behaviour.
"""
import hashlib
import importlib.util
from pathlib import Path
import socket
import struct
import sys
import time
import types
import unittest
from unittest.mock import patch

NATIVE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_epoch_host_b12', NATIVE / 'native_epoch_host.py')
host = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = host
spec.loader.exec_module(host)

NONCE = bytes(range(0x40, 0x60))
READY = host.frame(4, 48, 0) + NONCE
# Shape of OVMF TerminalDxe (PC-ANSI) console text; a model, not captured bytes.
ANSI = b'\x1b[0m\x1b[37m\x1b[40m\x1b[2J\x1b[01;01H\x1b[0m\x1b[37m\x1b[40m' + b'BdsDxe: loading Boot0001 "UEFI Misc Device" from PciRoot(0x0)/Pci(0x3,0x0)\r\n'


class SegmentedPeer:
    """Real socket; recv returns at most `segment` bytes per call."""
    def __init__(self, sock, segment):
        self.sock, self.segment = sock, segment
    def fileno(self): return self.sock.fileno()
    def recv(self, n): return self.sock.recv(min(n, self.segment))
    def send(self, data): return self.sock.send(data)


def tolerant(test):
    """Pin the pre-READY text bound to its production default (16384 since
    batch 13, justified by root's actual R4 COM2 capture; see b13 tests)."""
    return patch.object(host, 'PRE_READY_TEXT_BOUND', host.COM2_PREAMBLE_MAX)(test)


def strict(test):
    """Explicit strict mode (bound 0): any byte before READY refuses."""
    return patch.object(host, 'PRE_READY_TEXT_BOUND', 0)(test)


class Transport(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.guards = 0

    def tearDown(self):
        self.a.close(); self.b.close()

    def grant(self, segment=1 << 20, deadline_s=5.0, guard=None):
        g = object.__new__(host.HostGrant)
        g.attempt = types.SimpleNamespace(nonce=NONCE, original_deadline_ns=time.monotonic_ns() + int(deadline_s * 1e9))
        g.peer = SegmentedPeer(self.a, segment)
        def counting():
            self.guards += 1
            if guard: guard(self.guards)
        g.guard = counting
        g.check = lambda: None  # host-only: device/QMP checks bypassed (see module doc)
        g.exchange_stop_ns = g.original_exchange_stop_ns = None
        g.transport_calls = 0; g.grant_bytes_written = 0; g.ready_preamble = g.transport_failure = None
        return g

    def failure(self, g, call, kind, error=host.EpochTransportError):
        with self.assertRaises(error) as caught: call()
        d = caught.exception.transport_diagnostics
        self.assertEqual(d['kind'], kind); self.assertIs(g.transport_failure, d)
        self.assertEqual(d['schema'], host.COM2_FAILURE_SCHEMA)
        self.assertLessEqual(len(d['frame_head_hex']), 32); self.assertLessEqual(len(d['surplus_head_hex']), 64)
        self.assertLessEqual(len(d['segment_lengths']), host.COM2_DIAG_SEGMENTS)
        self.assertLessEqual(len(d['message']), 256)
        return d

    def test_ready_split_one_byte_at_a_time(self):
        self.b.sendall(READY); g = self.grant(segment=1)
        ready = g._receive_ready(); host.validate_ready(ready, NONCE)
        self.assertEqual(ready, READY); self.assertEqual(g.ready_preamble['bytes'], 0)
        self.assertGreaterEqual(self.guards, 48 * 2)

    @tolerant
    def test_ansi_preamble_coalesced_with_ready(self):
        self.b.sendall(ANSI + READY); g = self.grant()
        self.assertEqual(g._receive_ready(), READY)
        self.assertEqual(g.ready_preamble['bytes'], len(ANSI))
        self.assertEqual(g.ready_preamble['sha256'], hashlib.sha256(ANSI).hexdigest())

    @tolerant
    def test_ansi_preamble_then_ready_one_byte_segments(self):
        self.b.sendall(ANSI + READY); g = self.grant(segment=1)
        self.assertEqual(g._receive_ready(), READY); self.assertEqual(g.ready_preamble['bytes'], len(ANSI))

    @tolerant
    def test_preamble_that_mimics_partial_marker_then_ready(self):
        noise = ANSI + b'WDE1 text' + b'\r\n'
        self.b.sendall(noise + READY); g = self.grant(segment=7)
        self.assertEqual(g._receive_ready(), READY); self.assertEqual(g.ready_preamble['bytes'], len(noise))

    def test_surplus_after_ready_is_error(self):
        self.b.sendall(READY + b'A'); g = self.grant()
        d = self.failure(g, g._receive_ready, 'surplus')
        self.assertEqual(d['surplus_head_hex'], '41'); self.assertEqual(d['frame_head_hex'], READY[:16].hex())

    @tolerant
    def test_eof_before_ready_reports_partial(self):
        self.b.sendall(ANSI + READY[:20]); self.b.close(); g = self.grant(segment=5)
        d = self.failure(g, g._receive_ready, 'eof')
        self.assertEqual(d['frame_head_hex'], READY[:16].hex()); self.assertEqual(d['pre_ready_console']['bytes'], len(ANSI))
        self.assertEqual(d['phase'], 'READY')

    def test_eof_immediately(self):
        self.b.close(); g = self.grant()
        d = self.failure(g, g._receive_ready, 'eof'); self.assertEqual(d['phase_stream_bytes'], 0)

    @tolerant
    def test_foreign_nonce_ready_refused(self):
        self.b.sendall(ANSI + host.frame(4, 48, 0) + bytes(32)); g = self.grant()
        d = self.failure(g, g._receive_ready, 'foreign-ready')
        self.assertTrue(d['frame_head_hex'].startswith(READY[4:8].hex()))

    def test_malformed_ready_header_refused(self):
        bad = struct.pack('<IHHII', 0x31454457, 2, 4, 48, 0) + NONCE
        self.b.sendall(bad); g = self.grant()
        self.failure(g, g._receive_ready, 'preamble-byte')

    @tolerant
    def test_binary_garbage_before_ready_refused(self):
        self.b.sendall(b'ok\x00\xff' + READY); g = self.grant()
        d = self.failure(g, g._receive_ready, 'preamble-byte')
        self.assertEqual(d['pre_ready_console']['head_hex'], b'ok'.hex()); self.assertTrue(d['frame_head_hex'].startswith('00ff'))

    @tolerant
    def test_oversize_preamble_refused(self):
        self.b.sendall(b'A' * (host.COM2_PREAMBLE_MAX + 1)); g = self.grant()
        self.failure(g, g._receive_ready, 'preamble-bound')

    @tolerant
    def test_deadline_expiry_keeps_timeout_type_with_diagnostics(self):
        self.b.sendall(ANSI); g = self.grant(deadline_s=0.08)
        d = self.failure(g, g._receive_ready, 'timeout', TimeoutError)
        self.assertEqual(d['pre_ready_console']['bytes'], len(ANSI)); self.assertGreaterEqual(d['elapsed_ms'], 1)

    def test_owner_guard_refusal_keeps_type_and_attaches(self):
        def refuse(n):
            if n == 3: raise ValueError('outer owner revoked')
        g = self.grant(guard=refuse)
        d = self.failure(g, g._receive_ready, 'refused', ValueError)
        self.assertEqual(d['error_class'], 'ValueError'); self.assertIn('outer owner revoked', d['message'])

    def test_report_split_and_surplus_and_eof(self):
        report = b'R' * 256
        self.b.sendall(report); g = self.grant(segment=3)
        self.assertEqual(g.transfer(None, 256), report)
        self.b.sendall(report + b'S'); g = self.grant()
        d = self.failure(g, lambda: g.transfer(None, 256), 'surplus')
        self.assertEqual((d['phase'], d['surplus_bytes'], d['frame_bytes_transferred']), ('REPORT', 1, 0))
        self.b.sendall(report[:100]); self.b.close(); g = self.grant()
        d = self.failure(g, lambda: g.transfer(None, 256), 'eof')
        self.assertEqual(d['frame_bytes_transferred'], 100)

    @strict
    def test_strict_any_pre_ready_byte_refused_with_capture(self):
        self.assertEqual(host.PRE_READY_TEXT_BOUND, 0)
        self.b.sendall(ANSI + READY); g = self.grant()
        d = self.failure(g, g._receive_ready, 'preamble-byte')
        pre = d['pre_ready_console']
        self.assertGreater(pre['bytes'], 0); self.assertEqual(pre['head_hex'], ANSI[:pre['bytes']][:32].hex())
        self.assertEqual(pre['sha256'], hashlib.sha256(ANSI[:pre['bytes']]).hexdigest()); self.assertIn('elapsed_ms', d)
        self.assertIsNone(g.ready_preamble)

    @strict
    def test_strict_foreign_ready_hides_nonce_bytes(self):
        self.b.sendall(host.frame(4, 48, 0) + bytes(range(1, 33))); g = self.grant()
        d = self.failure(g, g._receive_ready, 'foreign-ready')
        self.assertEqual(len(d['pre_ready_console']['head_hex']), 32); self.assertEqual(d['pre_ready_console']['tail_hex'], '')

    def test_strict_transfer_does_not_skip_preamble(self):
        # transfer() keeps exact-frame semantics; only READY has a sync marker.
        self.b.sendall(ANSI + READY); g = self.grant()
        self.failure(g, lambda: g.transfer(None, 48), 'surplus')

    def test_send_challenge_exact_bytes_then_closed_peer(self):
        challenge = host.frame(1, 48, 0) + NONCE; g = self.grant()
        self.assertEqual(g.transfer(challenge, 48, True), b'\0' * 48)
        self.assertEqual(self.b.recv(100), challenge)
        self.b.close(); g = self.grant()
        with self.assertRaises(OSError) as caught: g.transfer(host.frame(3, 272, 2) + bytes(256), 272, True)
        self.assertEqual(caught.exception.transport_diagnostics['phase'], 'GRANT')

    def test_finite_shared_budget(self):
        g = self.grant(); g.transport_calls = host.COM2_MAX_CALLS
        with self.assertRaises(ValueError) as caught: g._receive_ready()
        self.assertIn('finite shared COM2 transfer budget', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
