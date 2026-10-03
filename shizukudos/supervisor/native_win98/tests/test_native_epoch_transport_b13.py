"""HOST-ONLY regressions for the bounded pre-READY COM2 terminal sync, fed with
the bytes root ACTUALLY captured on COM2 in the B9 R4 VM run.

What is REAL here: the 49 bytes in CAPTURED_R4 are verbatim from root's
receipt .codex/context/root-b9r4-actual-com2-bytes.json (error_detail
chunk_prefix; recv was capped at extent+1 = 49, so this is a truncated prefix
of OVMF's TerminalDxe initialisation: ESC[2J ESC[001;001H ESC[=3h ...).
Production methods HostGrant._receive_ready/transfer, checked_select and
validate_ready run over a real AF_UNIX socketpair.

What is MODELED: every READY frame and nonce below is synthetic, the peer is a
socketpair (not QEMU's COM2 chardev), the HostGrant constructor and its
QEMU/QMP/listener/ESP/device checks (HostGrant.check) are bypassed, and the
outer owner guard is a counting callable. Nothing here proves that the real
guest sends a READY, nor any CHALLENGE/REPORT/GRANT exchange or Windows 98 boot.
"""
import hashlib
import importlib.util
from pathlib import Path
import socket
import sys
import time
import types
import unittest

NATIVE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('native_epoch_host_b13', NATIVE / 'native_epoch_host.py')
host = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = host
spec.loader.exec_module(host)

# REAL: verbatim root R4 capture (only the 49 bytes that were actually read).
CAPTURED_R4 = bytes.fromhex('1b5b324a1b5b3030313b303031481b5b3d33681b5b324a1b5b3030313b303031481b5b'
                            '324a1b5b3030313b303031481b5b')
# MODELED: synthetic live nonce (high-bit bytes so it cannot be terminal text).
NONCE = hashlib.sha256(b'b13 modeled live nonce').digest()
READY = host.frame(4, 48, 0) + NONCE


class SegmentedPeer:
    def __init__(self, sock, segment): self.sock, self.segment = sock, segment
    def fileno(self): return self.sock.fileno()
    def recv(self, n): return self.sock.recv(min(n, self.segment))
    def send(self, data): return self.sock.send(data)


def hex_fields(d):
    for key, value in d.items():
        if isinstance(value, dict): yield from hex_fields(value)
        elif key.endswith('_hex'): yield key, bytes.fromhex(value)


class CapturedPreamble(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair(); self.guards = 0

    def tearDown(self):
        self.a.close(); self.b.close()

    def grant(self, segment=1 << 20, deadline_s=5.0, nonce=NONCE):
        g = object.__new__(host.HostGrant)
        g.attempt = types.SimpleNamespace(nonce=nonce, original_deadline_ns=time.monotonic_ns() + int(deadline_s * 1e9))
        g.peer = SegmentedPeer(self.a, segment)
        def counting(): self.guards += 1
        g.guard = counting
        g.check = lambda: None  # MODELED: device/QMP/listener checks bypassed
        g.exchange_stop_ns = g.original_exchange_stop_ns = None
        g.transport_calls = 0; g.grant_bytes_written = 0; g.ready_preamble = g.transport_failure = None
        return g

    def failure(self, g, call, kind, error=host.EpochTransportError, nonces=(NONCE,)):
        with self.assertRaises(error) as caught: call()
        d = caught.exception.transport_diagnostics
        self.assertEqual(d['kind'], kind); self.assertIs(g.transport_failure, d)
        self.assertLessEqual(len(d['frame_head_hex']), 2 * host.COM2_FRAME_HEADER_HEX)
        self.assertNoNonce(d, nonces)
        return d

    def assertNoNonce(self, d, nonces):
        for key, raw in hex_fields(d):
            for nonce in nonces:
                for i in range(len(nonce) - 2):
                    self.assertNotIn(nonce[i:i + 3], raw, '%s leaks nonce bytes' % key)

    def test_capture_is_exact_49_bytes(self):
        self.assertEqual(len(CAPTURED_R4), 49)
        self.assertTrue(CAPTURED_R4.startswith(b'\x1b[2J\x1b[001;001H\x1b[=3h'))

    def test_production_default_is_finite_nonzero(self):
        self.assertEqual(host.PRE_READY_TEXT_BOUND, host.COM2_PREAMBLE_MAX)
        self.assertTrue(0 < host.PRE_READY_TEXT_BOUND <= 16384)

    def test_captured_prefix_then_live_ready_accepted_by_default(self):
        for segment in (1 << 20, 16, 1):  # coalesced, UART-FIFO-sized, single bytes
            with self.subTest(segment=segment):
                self.tearDown(); self.setUp()
                try:
                    self.b.sendall(CAPTURED_R4 + READY); g = self.grant(segment=segment)
                    ready = g._receive_ready(); host.validate_ready(ready, NONCE)
                    self.assertEqual(ready, READY)
                    summary = g.ready_preamble  # recorded, discarded uninterpreted
                    self.assertEqual(summary, {'bytes': 49, 'sha256': hashlib.sha256(CAPTURED_R4).hexdigest(),
                                               'head_hex': CAPTURED_R4[:32].hex(), 'tail_hex': CAPTURED_R4[-32:].hex()})
                    self.assertIsNone(g.transport_failure); self.assertGreater(self.guards, 0)
                finally:
                    self.tearDown()

    def test_captured_prefix_without_ready_eof(self):
        self.b.sendall(CAPTURED_R4); self.b.close(); g = self.grant(segment=16)
        d = self.failure(g, g._receive_ready, 'eof')
        self.assertEqual(d['phase'], 'READY')
        self.assertEqual(d['pre_ready_console']['bytes'], 49)
        self.assertEqual(d['pre_ready_console']['sha256'], hashlib.sha256(CAPTURED_R4).hexdigest())
        self.assertEqual(d['pre_ready_console']['head_hex'], CAPTURED_R4[:32].hex())

    def test_captured_prefix_without_ready_timeout(self):
        self.b.sendall(CAPTURED_R4); g = self.grant(deadline_s=0.08)
        d = self.failure(g, g._receive_ready, 'timeout', TimeoutError)
        self.assertEqual(d['pre_ready_console']['bytes'], 49); self.assertEqual(d['error_class'], 'TimeoutError')

    def test_captured_prefix_ready_plus_one_byte_is_surplus(self):
        self.b.sendall(CAPTURED_R4 + READY + b'\r'); g = self.grant()
        d = self.failure(g, g._receive_ready, 'surplus')
        self.assertEqual((d['surplus_bytes'], d['surplus_head_hex']), (1, '0d'))
        self.assertEqual(d['frame_head_hex'], READY[:16].hex()); self.assertIsNone(g.ready_preamble)

    def test_captured_prefix_then_foreign_ready_refused(self):
        foreign = hashlib.sha256(b'b13 modeled foreign nonce').digest()
        self.b.sendall(CAPTURED_R4 + host.frame(4, 48, 0) + foreign); g = self.grant(segment=16)
        d = self.failure(g, g._receive_ready, 'foreign-ready', nonces=(NONCE, foreign))
        self.assertEqual(d['pre_ready_console']['head_hex'], CAPTURED_R4[:32].hex())
        self.assertIsNone(g.ready_preamble)

    def test_captured_prefix_with_high_bit_byte_refused(self):
        for bad in (b'\xc4', b'\xe2\x94\x80', b'\x00'):  # PC-ANSI box, UTF-8 box, NUL
            with self.subTest(bad=bad.hex()):
                self.tearDown(); self.setUp()
                try:
                    self.b.sendall(CAPTURED_R4[:20] + bad + CAPTURED_R4[20:] + READY); g = self.grant()
                    d = self.failure(g, g._receive_ready, 'preamble-byte')
                    self.assertEqual(d['pre_ready_console']['bytes'], 20)
                    self.assertTrue(d['frame_head_hex'].startswith(bad[:1].hex())); self.assertIsNone(g.ready_preamble)
                finally:
                    self.tearDown()

    def test_malformed_header_with_current_nonce_redacted(self):
        bad = host.frame(4, 48, 0)[:4] + b'\x02\x00' + host.frame(4, 48, 0)[6:] + NONCE  # version 2
        self.b.sendall(CAPTURED_R4 + bad); g = self.grant(segment=16)
        d = self.failure(g, g._receive_ready, 'preamble-byte')
        self.assertEqual(d['pre_ready_console']['bytes'], 53)  # capture + 'WDE1'

    def test_strict_frame_surplus_chunk_redacted(self):
        # last_chunk_head_hex used to carry nonce bytes of a coalesced frame.
        report = host.frame(2, 256, 0) + NONCE + bytes(range(1, 209))
        self.b.sendall(report + b'X'); g = self.grant()
        d = self.failure(g, lambda: g.transfer(None, 256), 'surplus')
        self.assertEqual(d['last_chunk_head_hex'], report[:16].hex())

    def test_capture_against_strict_mode_still_refuses(self):
        old = host.PRE_READY_TEXT_BOUND; host.PRE_READY_TEXT_BOUND = 0
        try:
            self.b.sendall(CAPTURED_R4 + READY); g = self.grant()
            d = self.failure(g, g._receive_ready, 'preamble-byte')
            self.assertEqual(d['pre_ready_console']['bytes'], 49)
        finally:
            host.PRE_READY_TEXT_BOUND = old


if __name__ == '__main__':
    unittest.main()
