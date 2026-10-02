"""Real Linux child/socket/parser transport; QEMU hardware/recipe remain modeled.

The Python peer is never QEMU. HostGrant's QEMU constructor is deliberately
bypassed, while its exchange, guard, one-reader adapter and handoff are real.
"""
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_native_epoch_host as baseline

host = baseline.host
NATIVE = Path(__file__).resolve().parents[1]
CHILDREN = []

# An owned, single-threaded, finite peer implements literal hardware fields.
# Its QMP replies intentionally leave an unfinished event in the parser. The
# next request completes that event, exercising the real existing parser.
PEER = r'''
import hashlib,json,select,socket,sys,time
qpath,cpath,nonce_hex,report_hex,pci_json,esp_path=sys.argv[1:]
qserver=socket.socket(socket.AF_UNIX);qserver.bind(qpath);qserver.listen(1)
com=socket.socket(socket.AF_UNIX);com.connect(cpath)
nonce=bytes.fromhex(nonce_hex);report=bytearray.fromhex(report_hex)
com.sendall(bytes.fromhex('57444531010004003000000000000000')+nonce)
q,_=qserver.accept();q.sendall(b'{"QMP":{"version":{}}}\n')
qb=bytearray();cb=bytearray();phase=0;tail=False;running=False
stop=time.monotonic()+25
flat=('FlatView #0\n AS "memory", root: system\n Root memory region: system\n'
      '  0000000000000000-000000007fffffff (prio 0, ram): pc.ram\n'
      '  00000000b0000000-00000000bfffffff (prio 1, i/o): pcie-mmcfg\n\n')
row={'node-name':'owned','drv':'raw','ro':False,'encrypted':False,
     'file':esp_path,'cache':{'writeback':True,'direct':False,'no-flush':False},
     'image':{'filename':esp_path,'format':'raw','virtual-size':2304<<20}}
while time.monotonic()<stop:
    ready,_,_=select.select([q,com],[],[],min(.1,stop-time.monotonic()))
    for stream in ready:
        data=stream.recv(65536)
        if not data:sys.exit(0)
        if stream is com:
            cb.extend(data)
            if phase==0 and len(cb)>=48:
                challenge=bytes(cb[:48]);del cb[:48]
                report[16:48]=challenge[16:48];com.sendall(report);phase=1
            if phase==1 and len(cb)>=272:
                grant=bytes(cb[:272]);del cb[:272];phase=2
                sys.stdout.write(hashlib.sha256(grant).hexdigest());sys.stdout.flush()
            continue
        qb.extend(data)
        while b'\n' in qb:
            line,_,rest=qb.partition(b'\n');qb=bytearray(rest)
            r=json.loads(line);cmd=r['execute'];args=r.get('arguments',{})
            v={}
            if cmd=='query-status':v={'running':running,'status':'running' if running else 'paused'}
            elif cmd=='stop':running=False
            elif cmd=='cont':running=True
            elif cmd=='query-pci':v=json.loads(pci_json)
            elif cmd=='query-block':v=[{'device':'esp','locked':False,'inserted':row}]
            elif cmd=='query-named-block-nodes':v=[row]
            elif cmd=='human-monitor-command':
                text=args['command-line']
                if text=='info mtree -f':v=flat
                else:
                    address=int(text.split()[-1],16);bdf=(address-0xb0000000)//4096
                    import struct
                    words=struct.unpack_from('<10I',report,160 if bdf==16 else 208)
                    v='\n'.join('%016x: '%(address+i*4)+' '.join('0x%08x'%x for x in words[i:i+4]) for i in (0,4,8))+'\n'
            payload=(b'}\n' if tail else b'')+(json.dumps({'id':r['id'],'return':v})+'\n').encode()
            # All status replies leave the same real partial event tail.
            tail=cmd=='query-status'
            if tail:payload+=b'{"event":"HANDOFF_TAIL"'
            q.sendall(payload)
'''


class Handoff(unittest.TestCase):
    setUp = baseline.LinuxOwnership.setUp
    source = baseline.LinuxOwnership.source
    existing_source = baseline.LinuxOwnership.existing_source
    binding = baseline.LinuxOwnership.binding

    def tearDown(self):
        # Resources/children must be reaped before the baseline tempdir and
        # its admitted source leases are released.
        self.doCleanups()
        baseline.LinuxOwnership.tearDown(self)

    def context(self):
        number = getattr(self, '_context_number', 0) + 1
        self._context_number = number
        frames = baseline.Frames(); frames.setUp()
        vga, rom, disk, bars = baseline.configs()
        deadline = time.monotonic() + 20
        attempt = host.Attempt(self.source('vga-%d' % number, vga), self.source('rom-%d' % number, rom),
                               self.source('disk-%d' % number, disk), bars, int(deadline * 1e9))
        listener = host.PrivateListener(self.path / ('e%d.sock' % number))
        qpath = self.path / ('q%d.sock' % number)
        source = self.existing_source(NATIVE / 'owned_capture.py')
        namespace = {'__file__': str(source.path), '__name__': '_handoff_transport'}
        exec(compile(source.check(), str(source.path), 'exec'), namespace)
        class ESPModel:
            path = Path('/modeled/esp.img')
            binding = (77, 88)
            def check(self): pass
            def observe_backend(self, binding):
                return {'modeled_backend_open_inode': [77, 88], 'not_runtime_authority': True}
        esp = ESPModel()
        argv = [sys.executable, '-B', '-c', PEER, str(qpath),
                str(listener.path), attempt.nonce.hex(), frames.report().hex(),
                json.dumps(frames.pci()), str(esp.path)]
        child = subprocess.Popen(argv, pass_fds=(attempt.policy_fd,), stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
        CHILDREN.append({'case': self.id(), 'pid': child.pid, 'pgid': os.getpgid(child.pid),
                         'sid': os.getsid(child.pid), 'reaped': False})
        binding = monitor = exchange = None
        try:
            binding = self.binding(child, argv)
            monitor = namespace['OwnedQMP'](qpath, child.pid, deadline)
            exchange = host.HostGrant.__new__(host.HostGrant)
            exchange.guard = lambda: None
            exchange.attempt, exchange.binding = attempt, binding
            exchange.listener, exchange.esp = listener, esp
            exchange.qmp = host.SoleQMP(binding, monitor, attempt, source)
            exchange.peer = None
            exchange.exchange_stop_ns = exchange.original_exchange_stop_ns = None
            exchange.transport_calls = exchange.grant_bytes_written = 0
            attempt.owner = listener.owner = binding
            self.addCleanup(self.cleanup_context, child, binding, monitor, exchange,
                            listener, attempt)
            return exchange, monitor, source, child
        except BaseException:
            self.cleanup_context(child, binding, monitor, exchange, listener, attempt)
            raise

    def cleanup_context(self, child, binding, monitor, exchange, listener, attempt):
        try:
            try: os.kill(child.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            if binding is not None:
                poll = select.poll(); poll.register(binding.pidfd, select.POLLIN)
                self.assertTrue(poll.poll(2000), 'owned fixture failed finite cleanup')
                record = binding.reap_owned()
                self.assertEqual(record['pid'], child.pid)
                self.assertEqual(record['code'], os.CLD_KILLED)
                self.assertEqual(record['status'], signal.SIGKILL)
                binding.assert_reaped()
                row = next(row for row in CHILDREN if row['pid'] == child.pid)
                row.update(reaped=True, typed_waitid=dict(record), returncode=child.returncode,
                           pidfd_reaped_state_verified=True)
                if exchange is not None: exchange.close_after_reap()
                else: listener.close(); attempt.close()
                os.close(binding.pidfd)
            else:
                child.wait(timeout=2); listener.close(); attempt.close()
        finally:
            if monitor is not None: monitor.close()
            child.stdout.close(); child.stderr.close()

    def complete(self):
        exchange, monitor, source, child = self.context()
        record = exchange.exchange()
        self.assertEqual(exchange.grant_bytes_written, 272)
        self.assertTrue(select.select([child.stdout], [], [], 1)[0])
        self.assertEqual(child.stdout.read(64).decode(), record['grant_sha256'])
        self.assertFalse(record['VM_Windows_boot_verified'])
        return exchange, monitor, source

    def assert_custody(self, exchange):
        with self.assertRaises(ValueError): exchange.close_after_reap()
        self.assertTrue(exchange.listener.path.exists())
        self.assertEqual(os.fstat(exchange.attempt.policy_fd).st_size, 256)
        self.assertIs(exchange.qmp.monitor._native_epoch_claim, exchange.qmp.claim)

    def test_success_returns_same_live_parser_and_retires_old_adapters(self):
        exchange, monitor, source = self.complete()
        self.assertTrue(callable(getattr(exchange, 'handoff_monitor', None)),
                        'successful epoch requires an explicit monitor handoff')
        sole = exchange.qmp; old_buffer = monitor.buffer
        original_deadlines = (monitor.deadline, sole.deadline,
                              exchange.attempt.original_deadline_ns,
                              exchange.exchange_stop_ns, exchange.original_exchange_stop_ns)
        snapshots = []
        def final_guard():
            snapshots.append((monitor.buffer, bytes(monitor.buffer), monitor.request, monitor.socket))
        exchange.guard = final_guard
        handed = exchange.handoff_monitor()
        self.assertIs(handed, monitor)
        self.assertIsNot(monitor.buffer, old_buffer, 'real QMP parsing must be allowed to replace its buffer')
        latest = snapshots[-1]
        self.assertIs(monitor.buffer, latest[0]); self.assertEqual(bytes(monitor.buffer), latest[1])
        self.assertEqual(monitor.request, latest[2]); self.assertIs(monitor.socket, latest[3])
        self.assertEqual(bytes(monitor.buffer), b'{"event":"HANDOFF_TAIL"')
        self.assertEqual((monitor.deadline, sole.deadline, exchange.attempt.original_deadline_ns,
                          exchange.exchange_stop_ns, exchange.original_exchange_stop_ns), original_deadlines)
        self.assert_custody(exchange)
        for operation in (sole.check, lambda: sole.call('query-status'), exchange.check,
                          exchange.exchange, exchange.handoff_monitor):
            with self.assertRaises(ValueError): operation()
        with self.assertRaises(ValueError):
            host.SoleQMP(exchange.binding, monitor, exchange.attempt, source)
        # The caller explicitly owns its postphase checks and original budget.
        exchange.binding.check()
        self.assertLess(time.monotonic(), monitor.deadline)
        monitor.call('cont')
        self.assertEqual(monitor.call('query-status'), {'running': True, 'status': 'running'})

    def test_before_exchange_handoff_is_terminal_and_keeps_custody(self):
        exchange, monitor, _, _ = self.context()
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)
        with self.assertRaises(ValueError): exchange.exchange()
        with self.assertRaises(ValueError): exchange.handoff_monitor()

    def test_partial_grant_failure_cannot_release_monitor(self):
        exchange, monitor, _, _ = self.context()
        transfer = exchange.transfer
        def partial(data, extent, send=False):
            if send and extent == 272:
                transfer(data[:31], 31, True)
                exchange.grant_bytes_written += 31
                raise ValueError('deliberate transport fault after actual 31 bytes')
            return transfer(data, extent, send)
        exchange.transfer = partial
        with self.assertRaises(ValueError): exchange.exchange()
        self.assertEqual(exchange.failure_after_grant_bytes, 31)
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_full_grant_then_guard_failure_cannot_release_monitor(self):
        exchange, monitor, _, _ = self.context()
        def fail_late():
            if exchange.grant_bytes_written == 272:
                raise ValueError('deliberate owner refusal after actual full GRANT')
        exchange.guard = fail_late
        with self.assertRaises(ValueError): exchange.exchange()
        self.assertEqual(exchange.failure_after_grant_bytes, 272)
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_early_exchange_failure_cannot_release_monitor(self):
        exchange, monitor, _, _ = self.context()
        def early_refusal(): raise ValueError('owner refusal before connecting peer')
        exchange.guard = early_refusal
        with self.assertRaises(ValueError): exchange.exchange()
        self.assertEqual(exchange.failure_after_grant_bytes, 0)
        exchange.guard = lambda: None
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_receipt_construction_failure_is_not_completed_exchange(self):
        exchange, monitor, _, _ = self.context()
        original = exchange.binding.check
        late = 0
        def fail_receipt():
            nonlocal late
            if exchange.grant_bytes_written == 272 and sys._getframe(1).f_code is host.HostGrant.exchange.__code__:
                late += 1
                # Only the actual exchange receipt's direct binding check
                # fails; all checks through the adapter/owner stay real.
                raise ValueError('deliberate receipt binding refusal')
            return original()
        exchange.binding.check = fail_receipt
        with self.assertRaises(ValueError): exchange.exchange()
        self.assertEqual(late, 1)
        self.assertEqual(exchange.failure_after_grant_bytes, 272)
        exchange.binding.check = original
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_paused_refusal_after_success_keeps_monitor_claimed(self):
        exchange, monitor, _ = self.complete()
        monitor.call('cont')  # Actual peer state changes, hardware still modeled.
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)
        monitor.call('stop')
        with self.assertRaises(ValueError): exchange.handoff_monitor()

    def test_original_deadline_expiry_cannot_be_renewed_for_handoff(self):
        exchange, monitor, _ = self.complete()
        deadlines = (monitor.deadline, exchange.attempt.original_deadline_ns, exchange.exchange_stop_ns)
        with patch.object(host.time, 'monotonic_ns', return_value=exchange.attempt.original_deadline_ns):
            with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assertEqual((monitor.deadline, exchange.attempt.original_deadline_ns, exchange.exchange_stop_ns), deadlines)
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_guard_refusal_is_terminal_even_after_guard_recovers(self):
        exchange, monitor, _ = self.complete()
        def refused(): raise RuntimeError('actual callback refusal fixture')
        exchange.guard = refused
        with self.assertRaises(RuntimeError): exchange.handoff_monitor()
        exchange.guard = lambda: None
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        with self.assertRaises(ValueError): exchange.check()
        self.assert_custody(exchange)

    def test_source_drift_prevents_handoff(self):
        exchange, monitor, source = self.complete()
        import fcntl
        fcntl.fcntl(source.fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assert_custody(exchange)

    def test_same_class_monitor_replacement_cannot_inherit_claim(self):
        exchange, monitor, _ = self.complete()
        replacement = type(monitor).__new__(type(monitor))
        replacement.__dict__.update(monitor.__dict__)
        exchange.qmp.monitor = replacement
        try:
            with self.assertRaises(ValueError): exchange.handoff_monitor()
        finally: exchange.qmp.monitor = monitor
        self.assert_custody(exchange)

    def test_socket_replacement_cannot_release_second_reader(self):
        exchange, monitor, _ = self.complete()
        pair = socket.socketpair(); original = monitor.socket
        monitor.socket = pair[0]
        try:
            with self.assertRaises(ValueError): exchange.handoff_monitor()
        finally:
            monitor.socket = original; pair[0].close(); pair[1].close()
        self.assert_custody(exchange)

    def test_final_guard_adapter_replacement_cannot_leave_old_reader_active(self):
        exchange, monitor, _ = self.complete()
        original = exchange.qmp; calls = 0
        def substitute_adapter():
            nonlocal calls
            calls += 1
            if calls == 2:
                replacement = host.SoleQMP.__new__(host.SoleQMP)
                replacement.__dict__.update(original.__dict__)
                exchange.qmp = replacement
        exchange.guard = substitute_adapter
        try:
            with self.assertRaises(ValueError): exchange.handoff_monitor()
            self.assertFalse(getattr(original, 'retired', False))
        finally: exchange.qmp = original
        self.assert_custody(exchange)

    def test_final_guard_parser_drift_refuses_without_rebuilding_parser(self):
        for drift in ('buffer-replacement', 'buffer-content', 'request'):
            with self.subTest(drift=drift):
                exchange, monitor, _ = self.complete()
                calls = 0
                def mutate_final():
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        if drift == 'buffer-replacement': monitor.buffer = bytearray(monitor.buffer)
                        elif drift == 'buffer-content': monitor.buffer.extend(b'X')
                        else: monitor.request += 1
                exchange.guard = mutate_final
                with self.assertRaises(ValueError): exchange.handoff_monitor()
                exchange.guard = lambda: None
                with self.assertRaises(ValueError): exchange.handoff_monitor()
                self.assert_custody(exchange)
                self.doCleanups()

    def test_original_exchange_deadline_and_reserve_remain_enforced(self):
        exchange, monitor, _ = self.complete()
        original = exchange.exchange_stop_ns
        with patch.object(host.time, 'monotonic_ns', return_value=original-4_000_000_000):
            with self.assertRaises(ValueError): exchange.handoff_monitor()
        self.assertEqual(exchange.exchange_stop_ns, original)
        self.assertEqual(exchange.attempt.exchange_stop_ns, original)
        self.assert_custody(exchange)


if __name__ == '__main__':
    program = unittest.main(exit=False)
    if 'HANDOFF_AUDIT_PATH' in os.environ:
        raw = (json.dumps({'schema': 'root6970.modeled-hardware-real-transport-children.v1',
                           'children': CHILDREN, 'all_created_children_typed_reaped':
                           bool(CHILDREN) and all(row['reaped'] for row in CHILDREN),
                           'QEMU_executed': False, 'Win98_boot_verified': False},
                          sort_keys=True, separators=(',', ':')) + '\n').encode()
        assert len(raw) <= 16384
        with open(os.environ['HANDOFF_AUDIT_PATH'], 'xb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
