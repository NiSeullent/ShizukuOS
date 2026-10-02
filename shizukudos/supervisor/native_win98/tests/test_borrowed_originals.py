# SPDX-License-Identifier: GPL-2.0-only
"""Real tiny Linux leases, credentials and SCM_RIGHTS; no guest or media."""
import array
from contextlib import ExitStack
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


rpc = load('borrow_controls_rpc', HERE / 'custody_rpc.py')
guardian = load('borrow_controls_guardian', HERE / 'task_custody.py')
controller = load('borrow_controls_controller', HERE / 'run_vm.py')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


class BorrowedOriginalControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / 'original'
        self.source.write_bytes(bytes(range(256)) * 32)
        self.row = pin(self.source)
        self.union = guardian.LeaseUnion()
        self.entry = self.union.add(self.row)
        self.owner = types.SimpleNamespace(union=self.union)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.server = guardian.Server(rpc.Channel(left, os.getpid()), self.owner, {}, self.root)
        self.client = rpc.Client(right.detach(), os.getpid())
        self.errors = []
        self.thread = None

    def serve(self):
        def work():
            while True:
                try:
                    self.server.once(.2)
                except socket.timeout:
                    continue
                except EOFError:
                    return
                except BaseException as error:
                    self.errors.append(error)
                    return
        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.client.close()
        if self.thread is not None:
            self.thread.join(2)
            self.assertFalse(self.thread.is_alive(), 'owned RPC responder did not return')
        self.server.channel.socket.close()
        try:
            self.union.close()
        except ValueError:
            # Negative controls deliberately make final guardian closure fail.
            self.assertTrue(self.union.closed)
        self.temporary.cleanup()

    def test_real_original_RPC_returns_only_prehashed_held_descriptor(self):
        result, rights = self.server.dispatch({'id': 1, 'op': 'original', 'params': {'pin': self.row}}, [])
        self.assertEqual(rights, [self.entry['fd']])
        self.assertEqual(result['pin'], self.row)
        self.assertEqual(result['identity'], list(guardian.identity(os.fstat(rights[0]))))
        self.assertTrue(result['guardian_full_SHA_admitted'])
        self.assertEqual(fcntl.fcntl(rights[0], fcntl.F_GETLEASE), fcntl.F_RDLCK)

    def test_actual_client_rights_keep_guardian_lease_owner_and_read_bytes(self):
        self.serve()
        before_owner = fcntl.fcntl(self.entry['fd'], fcntl.F_GETOWN)
        with self.client.borrow_original(self.row) as original:
            self.assertNotEqual(original.fd, self.entry['fd'])
            self.assertEqual(os.pread(original.fd, self.row['bytes'], 0), self.source.read_bytes())
            original.check()
            self.assertEqual(fcntl.fcntl(original.fd, fcntl.F_GETOWN), before_owner)
            self.assertEqual(fcntl.fcntl(original.fd, fcntl.F_GETLEASE), fcntl.F_RDLCK)
        self.assertEqual(fcntl.fcntl(self.entry['fd'], fcntl.F_GETLEASE), fcntl.F_RDLCK)
        self.assertEqual(fcntl.fcntl(self.entry['fd'], fcntl.F_GETOWN), before_owner)
        self.assertFalse(self.errors)

    def test_actual_owned_child_borrows_without_stealing_guardian_lease(self):
        parent=os.getpid();pid=os.fork()
        if pid==0:
            try:
                self.server.channel.socket.close();os.close(self.entry['fd'])
                with self.client.borrow_original(self.row) as original:
                    assert os.pread(original.fd,self.row['bytes'],0)==bytes(range(256))*32
                    assert fcntl.fcntl(original.fd,fcntl.F_GETOWN)==parent
                    original.check()
                self.client.close();os._exit(0)
            except BaseException:
                os._exit(2)
        self.client.close();self.server.channel.peer_pid=pid
        stop=time.monotonic()+10
        try:
            while True:
                self.assertLess(time.monotonic(),stop,'actual child RPC exceeded finite control deadline')
                try:self.server.once(1)
                except EOFError:break
        finally:
            _,status=os.waitpid(pid,0)
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
        self.assertEqual(fcntl.fcntl(self.entry['fd'],fcntl.F_GETOWN),parent)
        self.assertEqual(fcntl.fcntl(self.entry['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)

    def test_unknown_conflicting_duplicate_and_output_pins_refuse(self):
        original = {'id': 1, 'op': 'original', 'params': {'pin': self.row}}
        self.server.dispatch(original, [])
        with self.assertRaises(ValueError):
            self.server.dispatch({**original, 'id': 2}, [])
        other = self.root / 'owned-output'
        other.write_bytes(self.source.read_bytes())
        self.union.add(pin(other))  # Added after the original snapshot.
        with self.assertRaises(ValueError):
            self.server.dispatch({'id': 3, 'op': 'original', 'params': {'pin': pin(other)}}, [])
        with self.assertRaises(ValueError):
            self.server.dispatch({'id': 4, 'op': 'original', 'params': {'pin': {**self.row, 'sha256': '1'*64}}}, [])
        self.assertEqual(set(self.union.rows), {str(self.source), str(other)})

    def test_unadmitted_full_SHA_entry_and_request_rights_refuse(self):
        self.entry['full_SHA_admitted'] = False
        with self.assertRaises(ValueError):
            self.server.dispatch({'id': 1, 'op': 'original', 'params': {'pin': self.row}}, [])
        self.entry['full_SHA_admitted'] = True
        with self.assertRaises(ValueError):
            self.server.dispatch({'id': 2, 'op': 'original', 'params': {'pin': self.row}}, [self.entry['fd']])

    def test_actual_late_same_bytes_inode_replacement_refuses_checkpoint(self):
        self.serve()
        with self.assertRaises((ValueError, RuntimeError)):
            with self.client.borrow_original(self.row) as original:
                replacement = self.root / 'new-inode'
                replacement.write_bytes(self.source.read_bytes())
                replacement.replace(self.source)
                original.check()
        with self.assertRaises(ValueError):
            self.union.check()

    def test_actual_same_inode_ancestor_symlink_alias_refuses(self):
        directory = self.root / 'tree'
        directory.mkdir()
        source = directory / 'input'
        source.write_bytes(b'ancestor control')
        row = pin(source)
        self.union.add(row)
        self.server = guardian.Server(self.server.channel, self.owner, {}, self.root)
        saved = self.root / 'saved-tree'
        directory.rename(saved)
        directory.symlink_to(saved, target_is_directory=True)
        try:
            with self.assertRaises(ValueError):
                self.server.dispatch({'id': 1, 'op': 'original', 'params': {'pin': row}}, [])
        finally:
            directory.unlink()
            saved.rename(directory)

    def response(self, rights, transform=lambda row: row):
        def work():
            request, incoming = self.server.channel.receive()
            for fd in incoming:
                os.close(fd)
            answer = {'pin': self.row, 'identity': list(self.entry['identity']),
                      'guardian_pid': os.getpid(), 'guardian_full_SHA_admitted': True}
            self.server.channel.send({'id': request['id'], 'ok': True, 'result': transform(answer)}, rights)
        self.thread = threading.Thread(target=work, daemon=True)
        self.thread.start()

    def test_actual_foreign_same_bytes_descriptor_and_surplus_rights_refuse(self):
        foreign = self.root / 'foreign'
        foreign.write_bytes(self.source.read_bytes())
        foreign_entry = self.union.add(pin(foreign))
        self.response([foreign_entry['fd']])
        with self.assertRaises(ValueError):
            self.client.borrow_original(self.row)

    def test_actual_surplus_response_rights_are_closed(self):
        before = len(os.listdir('/proc/self/fd'))
        self.response([self.entry['fd'], self.entry['fd']])
        with self.assertRaises(ValueError):
            self.client.borrow_original(self.row)
        self.thread.join(2)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_malformed_full_SHA_identity_and_guardian_owner_refuse(self):
        self.response([self.entry['fd']], lambda row: {**row, 'guardian_full_SHA_admitted': False})
        with self.assertRaises(ValueError):
            self.client.borrow_original(self.row)

    def test_foreign_guardian_lease_owner_response_refuses(self):
        self.response([self.entry['fd']], lambda row: {**row, 'guardian_pid': os.getpid()+1})
        with self.assertRaises(ValueError):
            self.client.borrow_original(self.row)

    def test_malformed_five_field_identity_refuses_before_read(self):
        self.response([self.entry['fd']], lambda row: {**row, 'identity': list(self.entry['identity'])[:-1]})
        with self.assertRaises(ValueError):
            self.client.borrow_original(self.row)

    def test_controller_content_and_final_audit_use_same_FD_provenance(self):
        self.serve()
        reads=[]
        real_sha=controller.sha
        def counted_sha(path):
            reads.append(str(path));return real_sha(path)
        with mock.patch.object(controller,'sha',counted_sha),ExitStack() as stack:
            originals=controller.GuardianOriginalInputs(self.client,stack)
            self.assertEqual(originals.read(self.row,16384),self.source.read_bytes())
            self.assertTrue(originals.audit(self.row))
            proof=originals.evidence()
            self.assertEqual(proof[0]['identity'],list(self.entry['identity']))
            self.assertTrue(proof[0]['guardian_initial_full_SHA_admitted'])
            self.assertFalse(proof[0]['controller_independent_full_SHA_readback'])
            self.assertEqual(reads,[],'controller performed an independent original full read')
        self.assertEqual(fcntl.fcntl(self.entry['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)

    def test_actual_kernel_foreign_PID_credentials_refuse(self):
        pid = os.fork()
        if pid == 0:
            try:
                self.server.channel.send({'id': 1, 'ok': True, 'result': {}})
                os._exit(0)
            except BaseException:
                os._exit(2)
        try:
            with self.assertRaises(ValueError):
                self.client.channel.receive()
        finally:
            _, status = os.waitpid(pid, 0)
            self.assertEqual(os.waitstatus_to_exitcode(status), 0)

    def test_real_lease_break_latch_refuses_future_transfer(self):
        pid = os.fork()
        if pid == 0:
            try:
                os.open(self.source, os.O_WRONLY | os.O_NONBLOCK)
            except BlockingIOError:
                os._exit(0)
            except BaseException:
                os._exit(2)
            os._exit(3)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assertTrue(self.union.broken)
        with self.assertRaises(ValueError):
            self.server.dispatch({'id': 1, 'op': 'original', 'params': {'pin': self.row}}, [])

    def controller_receipt_lifetime(self, close_failure=False):
        # Run the existing real CLI fixture with its modeled QEMU/capture, but
        # replace its original-input custody with real leases and SCM_RIGHTS.
        legacy = load('borrow_lifetime_fixture', HERE / 'tests/test_controller_main.py')
        fixture = legacy.MainControls('test_optional_preparation_pins_are_verified_when_present')
        self.addCleanup(fixture.doCleanups)
        value = legacy.m
        actual_run = value.run_plan
        actual_atomic = legacy.u.atomic_json
        published = []
        duplicates = []

        def source_args(args, parser, custody, stack):
            plan = json.loads(args.plan.read_bytes())
            built = json.loads(Path(plan['input_pins']['build_receipt']['path']).read_bytes())
            header = Path(plan['input_pins']['build_receipt']['path']).parent / 'source' / value.RUNTIME_ORIGINALS[-1]
            source_paths = {name: args.repo / name for name in value.HELPERS}
            source_paths.update({value.RUNTIME_ORIGINALS[4]: Path(value.__file__),
                                 value.RUNTIME_ORIGINALS[5]: HERE / 'owned_capture.py',
                                 value.RUNTIME_ORIGINALS[6]: header})
            sources = {name: pin(path) for name, path in source_paths.items()}
            for row in [pin(args.plan), *sources.values(), *plan['input_pins'].values(), *built['input_pins'].values()]:
                self.union.add(row)
            self.owner.record = {'custody_admitted': True, 'owned_child_reaped': True, 'leases_released': False}
            self.server = guardian.Server(self.server.channel, self.owner, {}, self.root)
            args.plan_bytes = args.plan.stat().st_size
            args.runtime_source_pins_json = json.dumps(sources)
            self.serve()
            return actual_run(args, parser, custody, stack)

        actual_borrow = self.client.borrow_original
        def borrow(row):
            entry = actual_borrow(row)
            duplicates.append(entry)
            if close_failure and len(duplicates) == 1:
                original_close = entry.close
                def failed_close():
                    original_close()
                    raise OSError('owned duplicate close control')
                entry.close = failed_close
            return entry

        def atomic(path, record):
            if path.name == 'native-result.json':
                # The actual received descriptors must still be open at fsync
                # publication, after the modeled owned target has been reaped.
                self.assertTrue(record['owned_child_reaped'])
                self.assertTrue(duplicates)
                for entry in duplicates:
                    self.assertFalse(entry.closed, 'borrowed FD closed before controller receipt')
                    self.assertEqual(os.fstat(entry.fd).st_ino, entry.identity[1])
                    self.assertEqual(fcntl.fcntl(entry.fd, fcntl.F_GETLEASE), fcntl.F_RDLCK)
                published.append(record.copy())
            return actual_atomic(path, record)

        self.client.load = lambda name, path: value.load(name, path)
        self.client.admit_frozen = lambda *args: None
        self.client.layout = lambda *args: 5368
        self.client.admit_qmp = lambda *args: None
        def modeled_spawn(command, writers):
            child = value.subprocess.Popen(command)
            child.args = command
            self.client.launch_requested = True
            return child
        self.client.spawn = modeled_spawn
        with mock.patch.object(value, 'get_custody', return_value=self.client), \
             mock.patch.object(value, 'run_plan', source_args), \
             mock.patch.object(self.client, 'borrow_original', borrow), \
             mock.patch.object(legacy.u, 'atomic_json', atomic):
            result, error, record, state, out = fixture.fixture('preparation_pins_match')
        self.assertEqual(len(published), 1, 'receipt was never published with all original FDs held')
        self.assertTrue(all(entry.closed for entry in duplicates))
        self.assertFalse(self.client.originals)
        self.assertFalse(self.union.closed)
        self.union.check()
        self.assertFalse(self.errors)
        self.assertTrue(record['guardian_late_full_SHA_closure_pending'])
        self.assertFalse(record['leases_released_after_reap'])
        self.assertTrue(record['controller_original_FDs_held_at_receipt_publication'])
        self.assertTrue(record['controller_original_FD_closure_pending_at_receipt'])
        if close_failure:
            self.assertIsInstance(error, OSError, 'duplicate close failure did not fail controller return')
            self.assertIsNone(result)
        else:
            self.assertIsNone(error)
            self.assertEqual(result, 0)

    def test_real_borrowed_FDs_remain_held_through_controller_receipt_publication(self):
        self.controller_receipt_lifetime()

    def test_actual_duplicate_close_failure_prevents_successful_controller_return(self):
        self.controller_receipt_lifetime(close_failure=True)


if __name__ == '__main__':
    unittest.main()
