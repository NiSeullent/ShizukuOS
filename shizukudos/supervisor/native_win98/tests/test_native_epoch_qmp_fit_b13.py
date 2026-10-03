"""HOST-ONLY regressions for fitting each epoch QMP request into the immutable
exchange stop (root B9 R5 failure: 'existing QMP5s request bound does not fit
exchange reserve' raised by SoleQMP.call at the end of the first observation).

What is REAL here: the production pure helper qmp_request_deadline_ns, the
production SoleQMP.call body, the production OwnedQMP class loaded from the
current owned_capture.py source (its own 5 s per-request cap and poll loop),
an AF_UNIX QMP-shaped peer in a separate Python process (SO_PEERCRED is its
real PID), and the production HostGrant.exchange ordering for the double
observation and the GRANT.

What is MODELED: the peer is a Python fixture, never QEMU; SoleQMP's
constructor and its owner/source/process check() are bypassed (check is a
deadline-only invariant probe); the Attempt, listener, COM2 transport and
observations in the exchange-order test are stand-ins. Nothing here proves
QEMU timing, guest TSC behaviour while paused, a live GRANT or Windows boot.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

NATIVE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module); return module


host = load('native_epoch_host_qmp_fit_b13', NATIVE / 'native_epoch_host.py')
capture = load('owned_capture_qmp_fit_b13', NATIVE / 'owned_capture.py')
MS = 1_000_000
S = 1_000_000_000

PEER = ('import socket,json,sys,time;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(1);'
        'delay=float(sys.argv[2]);c,_=s.accept();f=c.makefile("rwb",buffering=0);'
        'f.write(b\'{"QMP":{"version":{}}}\\n\');n=0\n'
        'for line in f:\n'
        ' r=json.loads(line);n+=1\n'
        ' if n>1: time.sleep(delay)\n'
        ' f.write((json.dumps({"id":r["id"],"return":{"running":False,"status":"paused"}})+"\\n").encode())\n')


class PureRequestBound(unittest.TestCase):
    now = 1_000 * S

    def bound(self, remaining_ns, post_grant=False, original=None):
        return host.qmp_request_deadline_ns(self.now, original or self.now + 60 * S, self.now + remaining_ns, post_grant)

    def test_large_reserve_keeps_existing_cap(self):
        self.assertEqual(self.bound(10 * S), self.now + host.QMP_REQUEST_CAP_NS)

    def test_medium_reserve_shrinks_request(self):
        # R5 situation: under 5 s left. Old code refused; now it fits.
        self.assertEqual(self.bound(4 * S), self.now + 4 * S - host.QMP_GRANT_RESERVE_NS)
        self.assertEqual(self.bound(4 * S, True), self.now + 4 * S)

    def test_tiny_and_zero_reserve_refused(self):
        for remaining in (host.QMP_GRANT_RESERVE_NS + host.QMP_MIN_REQUEST_NS - 1, host.QMP_GRANT_RESERVE_NS, 0, -S):
            with self.subTest(remaining=remaining), self.assertRaisesRegex(ValueError, 'below minimum useful QMP request bound'):
                self.bound(remaining)
        with self.assertRaises(ValueError): self.bound(host.QMP_MIN_REQUEST_NS - 1, True)
        self.assertEqual(self.bound(host.QMP_MIN_REQUEST_NS, True), self.now + host.QMP_MIN_REQUEST_NS)

    def test_never_later_than_original_or_exchange(self):
        for remaining in (300 * MS, 900 * MS, 3 * S, 7 * S, 20 * S):
            for post in (False, True):
                for original in (self.now + 2 * S, self.now + 60 * S):
                    try: stop = self.bound(remaining, post, original)
                    except ValueError: continue
                    self.assertLessEqual(stop, min(original, self.now + remaining, self.now + host.QMP_REQUEST_CAP_NS))

    def test_shape_refused(self):
        for args in ((1.5, 2 * S, 3 * S, False), (0, 2 * S, 3 * S, 1), (0, None, 3 * S, False)):
            with self.subTest(args=args), self.assertRaises(ValueError): host.qmp_request_deadline_ns(*args)


class RealOwnedQMPFit(unittest.TestCase):
    def run_sole(self, delay, remaining_ns, post_grant=False, command='query-status'):
        tmp = tempfile.TemporaryDirectory(); path = Path(tmp.name) / 'qmp.sock'
        child = subprocess.Popen([sys.executable, '-B', '-c', PEER, str(path), str(delay)])
        monitor = None
        try:
            original_s = time.monotonic() + 30
            monitor = capture.OwnedQMP(path, child.pid, original_s)
            sole = host.SoleQMP.__new__(host.SoleQMP)
            original_ns = int(original_s * 1e9)
            stop = time.monotonic_ns() + remaining_ns
            sole.attempt = types.SimpleNamespace(original_deadline_ns=original_ns, exchange_stop_ns=stop, original_exchange_stop_ns=stop)
            sole.monitor, sole.deadline = monitor, monitor.deadline
            sole.calls = sole.total_bytes = sole.qmp_elapsed_ns = 0; sole.transcripts = []
            sole.ecam_reads = frozenset(); sole.tightened = None; sole.post_grant = post_grant
            seen = []
            def check():
                # Deadline-only invariant probe (production check() bypassed).
                tightened = sole.tightened
                self.assertTrue(tightened is None or tightened <= sole.deadline)
                self.assertEqual(monitor.deadline, sole.deadline if tightened is None else tightened)
                seen.append(monitor.deadline)
            sole.check = check
            monitor.pump = lambda: seen.append(('pump', monitor.deadline))
            started = time.monotonic_ns(); error = None
            try: sole.call(command)
            except BaseException as e: error = e
            elapsed = time.monotonic_ns() - started
            self.assertIs(monitor.deadline, sole.deadline, 'monitor deadline restored exactly')
            self.assertIsNone(sole.tightened)
            self.assertEqual((sole.attempt.exchange_stop_ns, sole.attempt.original_exchange_stop_ns), (stop, stop), 'no renewal')
            return sole, monitor, error, elapsed, seen, stop
        finally:
            if monitor is not None: monitor.close()
            child.kill(); child.wait(timeout=5); tmp.cleanup()

    def test_medium_reserve_request_succeeds_with_shrunk_bound(self):
        sole, monitor, error, elapsed, seen, stop = self.run_sole(0.0, 3 * S)
        self.assertIsNone(error)
        row = sole.transcripts[0]
        self.assertLessEqual(row['request_bound_ms'], 2500); self.assertGreaterEqual(row['request_bound_ms'], 2000)
        pumped = [d for tag, d in (x for x in seen if type(x) is tuple)]
        self.assertTrue(pumped and all(d <= (stop - host.QMP_GRANT_RESERVE_NS) / 1e9 + 1e-6 for d in pumped), 'narrowed deadline in force during I/O')

    def test_large_reserve_keeps_5s_cap(self):
        sole, *_ = self.run_sole(0.0, 9 * S)
        self.assertEqual(sole.transcripts[0]['request_bound_ms'], 5000)

    def test_slow_reply_times_out_at_shrunk_bound_not_5s(self):
        # Reply delay 2 s; only ~0.4 s usable: the real OwnedQMP loop must
        # raise its own deadline TimeoutError near the narrowed stop.
        sole, monitor, error, elapsed, seen, stop = self.run_sole(2.0, host.QMP_GRANT_RESERVE_NS + 400 * MS)
        self.assertIsInstance(error, TimeoutError)
        self.assertLess(elapsed, 1_200 * MS); self.assertEqual(sole.transcripts, [])
        self.assertEqual(sole.calls, 1)

    def test_tiny_reserve_refused_before_any_request(self):
        sole, monitor, error, elapsed, seen, stop = self.run_sole(0.0, host.QMP_GRANT_RESERVE_NS + 100 * MS)
        self.assertIsInstance(error, ValueError)
        self.assertIn('below minimum useful QMP request bound', str(error))
        self.assertEqual(monitor.request, 1, 'only qmp_capabilities was ever sent')

    def test_post_grant_releases_only_grant_reserve(self):
        sole, *_ , stop = self.run_sole(0.0, host.QMP_GRANT_RESERVE_NS, post_grant=True)
        self.assertLessEqual(sole.transcripts[0]['request_bound_ms'], host.QMP_GRANT_RESERVE_NS // MS)

    def test_zero_reserve_refused(self):
        sole, monitor, error, *_ = self.run_sole(0.0, 0)
        self.assertIsInstance(error, ValueError); self.assertEqual(monitor.request, 1)


class ExchangeOrder(unittest.TestCase):
    """Production HostGrant.exchange with modeled transport/observations."""
    def run_exchange(self, second):
        grant = host.HostGrant.__new__(host.HostGrant)
        now = time.monotonic_ns()
        grant.attempt = types.SimpleNamespace(consumed=False, original_deadline_ns=now + 60 * S, exchange_stop_ns=None,
                                              original_exchange_stop_ns=None, nonce=b'n' * 32, expected=None,
                                              policy=b'p' * 256, policy_identity=(1, 2, 256))
        grant.binding = types.SimpleNamespace(check=lambda: {'pid': 1}, process=types.SimpleNamespace(pid=1))
        grant.listener = types.SimpleNamespace(accept=lambda *a, **k: object())
        events = []
        class QMP:
            post_grant = False; transcripts = []
            def call(self, command, arguments=None): events.append(('qmp', command, self.post_grant))
            def paused(self): events.append(('paused', self.post_grant))
        grant.qmp = QMP(); grant.peer = None; grant.ready_preamble = None
        grant.exchange_stop_ns = grant.original_exchange_stop_ns = None
        grant.transport_calls = grant.grant_bytes_written = 0
        grant._guarded_check = lambda: None; grant._receive_ready = lambda: b'r'
        def transfer(data, extent, send=False):
            events.append(('transfer', extent, send))
            if send and extent == 272: grant.grant_bytes_written = 272
            return b'R' * 256 if not send else None
        grant.transfer = transfer
        observed = iter([{'epoch': 1}, second])
        grant.observe = lambda report: (events.append(('observe',)), next(observed))[1]
        with mock.patch.object(host, 'validate_ready'), mock.patch.object(host, 'validate_report', return_value=[]), \
             mock.patch.object(host, 'grant', return_value=b'G' * 272), mock.patch.object(host, 'frame', return_value=b'F' * 16):
            try: return grant.exchange(), events, grant
            except ValueError as error: return error, events, grant

    def test_both_observations_compared_before_grant(self):
        error, events, grant = self.run_exchange({'epoch': 2})
        self.assertIsInstance(error, ValueError); self.assertIn('epoch changed', str(error))
        self.assertEqual(events.count(('observe',)), 2)
        self.assertNotIn(('transfer', 272, True), events); self.assertFalse(grant.qmp.post_grant)
        self.assertEqual(grant.failure_after_grant_bytes, 0)

    def test_post_grant_flag_only_after_complete_grant(self):
        receipt, events, grant = self.run_exchange({'epoch': 1})
        self.assertTrue(receipt['host_grant_transmitted'])
        at = events.index(('transfer', 272, True))
        self.assertTrue(all(e[-1] is False for e in events[:at] if e[0] in ('qmp', 'paused')))
        self.assertEqual(events[at + 1], ('paused', True))
        self.assertEqual(grant.exchange_stop_ns, grant.original_exchange_stop_ns)
        self.assertEqual(grant.attempt.exchange_stop_ns, grant.exchange_stop_ns)


if __name__ == '__main__':
    unittest.main()
