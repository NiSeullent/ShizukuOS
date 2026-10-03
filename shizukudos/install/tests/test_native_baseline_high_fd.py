# SPDX-License-Identifier: GPL-2.0-only
"""Actual high-number Linux FDs/IPC/readleases; no VM or Windows execution."""
from contextlib import contextmanager
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import resource
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[3]

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module

provider=load('high_fd_provider',ROOT/'shizukudos/install/native_baseline_provider.py')
control=provider.control
custody=load('high_fd_custody',ROOT/'shizukudos/install/native_baseline_custody.py')
lineage_fixture=load('high_fd_lineage_fixture',Path(__file__).with_name('test_native_baseline_lineage.py'))

@contextmanager
def high_fds():
    # Keep the actual allocation sequence high; do not substitute mocked FDs or
    # duplicate a low-number pidfd. Limits and every owned filler remain local.
    if resource.getrlimit(resource.RLIMIT_NOFILE)[0]<4096:
        raise RuntimeError('actual test process needs an existing >=4096 FD limit')
    held=[]
    try:
        while not held or held[-1]<=2048:
            held.append(os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC))
            if len(held)>4096:raise RuntimeError('bounded FD fixture exceeded')
        yield
    finally:
        for fd in reversed(held):os.close(fd)

class HighFDControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(dir='/var/tmp',prefix='shz-high-fd-')
        self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.source=self.root/'source';self.source.write_bytes(b'owned Linux fixture, not Windows\n')
        self.source.chmod(0o400);self.pin=provider.replacement.local_pin(self.source)

    def test_actual_alive_zombie_reaped_high_pidfd(self):
        for module in (control,custody):
            with self.subTest(module=module.__name__),high_fds():
                child=subprocess.Popen(['/usr/bin/sleep','60'])
                fd=os.pidfd_open(child.pid);original=module.pidfd_identity(fd)
                self.assertGreater(fd,2048)
                try:
                    self.assertFalse(module.pidfd_ready(fd,original))
                    signal.pidfd_send_signal(fd,signal.SIGTERM)
                    status=os.waitid(os.P_PIDFD,fd,os.WEXITED|os.WNOWAIT)
                    self.assertEqual(status.si_pid,child.pid)
                    raw=Path('/proc',str(child.pid),'stat').read_bytes()
                    self.assertEqual(raw[raw.rfind(b')')+2:].split()[0],b'Z')
                    self.assertTrue(module.pidfd_ready(fd,original))
                    child.wait(timeout=5)
                    self.assertTrue(module.pidfd_ready(fd,original))
                    poller=select.poll();poller.register(fd,select.POLLIN|select.POLLHUP)
                    self.assertTrue(poller.poll(0)[0][1]&select.POLLHUP)
                    self.assertEqual(module.pidfd_identity(fd),original)
                finally:
                    if child.poll() is None:child.kill();child.wait()
                    os.close(fd)

    def test_closed_nonpidfd_and_foreign_reused_high_fd_refused(self):
        for module in (control,custody):
            with self.subTest(module=module.__name__),high_fds():
                child=subprocess.Popen(['/usr/bin/sleep','60'])
                other=subprocess.Popen(['/usr/bin/sleep','60'])
                fd=os.pidfd_open(child.pid);original=module.pidfd_identity(fd)
                self.assertGreater(fd,2048);os.close(fd)
                try:
                    with self.assertRaises(OSError):module.pidfd_ready(fd,original)
                    reused=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
                    self.assertEqual(reused,fd)
                    try:
                        with self.assertRaisesRegex(ValueError,'actual original pidfd'):
                            module.pidfd_ready(reused,original)
                    finally:os.close(reused)
                    foreign=os.pidfd_open(other.pid);self.assertEqual(foreign,fd)
                    try:
                        with self.assertRaisesRegex(ValueError,'identity changed'):
                            module.pidfd_ready(foreign,original)
                    finally:os.close(foreign)
                finally:
                    for process in (child,other):
                        if process.poll() is None:process.kill()
                        process.wait()

    def test_poll_error_events_do_not_mean_actual_child_death(self):
        # Real retained high pidfds and identity checks; only the kernel error
        # event is injected, to prove it cannot be reclassified as a dead child.
        for module in (control,custody):
            with self.subTest(module=module.__name__),high_fds():
                fd=os.pidfd_open(os.getpid());original=module.pidfd_identity(fd)
                try:
                    for error in (select.POLLERR,select.POLLNVAL):
                        class BrokenPoll:
                            def register(self,number,flags):self.number=number
                            def poll(self,timeout):return [(self.number,error)]
                        with patch.object(module.select,'poll',return_value=BrokenPoll()):
                            with self.assertRaisesRegex(ValueError,'poll failed'):
                                module.pidfd_ready(fd,original)
                    self.assertFalse(module.pidfd_ready(fd,original))
                finally:os.close(fd)

    def test_actual_high_socket_packet_and_eof(self):
        with high_fds():
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            self.assertGreater(left.fileno(),2048);self.assertGreater(right.fileno(),2048)
            try:
                checks=[];provider.send(right,{'actual':'packet'})
                self.assertEqual(provider.receive(left,time.monotonic()+1,lambda:checks.append(1)),{'actual':'packet'})
                self.assertGreaterEqual(len(checks),3)
                right.close()
                with self.assertRaisesRegex(ValueError,'complete bounded custody packet'):
                    provider.receive(left,time.monotonic()+1)
            finally:left.close();right.close()

    def test_actual_high_socket_absolute_timeout_and_closed_fd(self):
        with high_fds():
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            try:
                started=time.monotonic()
                with self.assertRaisesRegex(ValueError,'deadline expired'):
                    provider.receive(left,started+.02)
                elapsed=time.monotonic()-started
                self.assertGreaterEqual(elapsed,.02);self.assertLess(elapsed,1)
                left.close()
                with self.assertRaises((OSError,ValueError)):
                    provider.receive(left,time.monotonic()+1)
            finally:left.close();right.close()

    def test_actual_high_socket_postwait_cancel_keeps_packet_unread(self):
        with high_fds():
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            calls=[0]
            def guard():
                calls[0]+=1
                if calls[0]==2:raise RuntimeError('actual owner cancelled after wait')
            try:
                provider.send(right,{'queued':True})
                with self.assertRaisesRegex(RuntimeError,'cancelled'):
                    provider.receive(left,time.monotonic()+1,guard)
                self.assertEqual(json.loads(left.recv(65536)),{'queued':True})
            finally:left.close();right.close()

    def test_actual_high_socket_postguard_expiry_keeps_packet_unread(self):
        with high_fds():
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            calls=[0]
            def guard():
                calls[0]+=1
                if calls[0]==2:time.sleep(.03)
            try:
                provider.send(right,{'queued':True})
                with self.assertRaisesRegex(ValueError,'deadline expired'):
                    provider.receive(left,time.monotonic()+.02,guard)
                self.assertEqual(json.loads(left.recv(65536)),{'queued':True})
            finally:left.close();right.close()

    def test_actual_high_socket_truncated_packet_refused(self):
        with high_fds():
            left,right=socket.socketpair(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            try:
                right.send(b'x'*(provider.MAX_PACKET+1))
                with self.assertRaisesRegex(ValueError,'complete bounded custody packet'):
                    provider.receive(left,time.monotonic()+1)
            finally:left.close();right.close()

    def test_actual_high_provider_finish_keeps_borrowed_leases_until_exit(self):
        ingest=provider.load(ROOT/'shizukudos/install/native_payload_ingest.py','high_provider_ingest')
        with high_fds():
            with ingest.Union() as union:
                union.add(self.pin);handler=signal.getsignal(signal.SIGIO)
                with provider.Client(self.pin,self.root/'service',borrowed_launcher=union) as client:
                    self.assertGreater(client.pidfd,2048);self.assertGreater(client.peer.fileno(),2048)
                    client.wait_ready();client.query();client.finish();pidfd=client.pidfd
                    self.assertEqual(client.child.returncode,0)
                    self.assertTrue(control.pidfd_ready(pidfd,client.pidfd_identity))
                    self.assertIs(signal.getsignal(signal.SIGIO),handler)
                with self.assertRaises(OSError):os.fstat(pidfd)
                inputs=[e['fd'] for e in union.entries.values()]
                for fd in inputs:self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
                union.finish()
            for fd in inputs:
                with self.assertRaises(OSError):os.fstat(fd)
            self.assertEqual(self.source.read_bytes(),b'owned Linux fixture, not Windows\n')

    def test_actual_high_provider_death_reaps_before_borrowed_release(self):
        ingest=provider.load(ROOT/'shizukudos/install/native_payload_ingest.py','high_failed_provider_ingest')
        with high_fds():
            with ingest.Union() as union:
                source=union.add(self.pin)
                with provider.Client(self.pin,self.root/'service',borrowed_launcher=union) as client:
                    client.wait_ready();self.assertGreater(client.pidfd,2048)
                    signal.pidfd_send_signal(client.pidfd,signal.SIGKILL);client.child.wait(timeout=5)
                    with self.assertRaisesRegex(ValueError,'service exited'):client.query()
                    self.assertEqual(fcntl.fcntl(source['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)
                    pidfd=client.pidfd
                self.assertIsNotNone(client.child.returncode)
                with self.assertRaises(OSError):os.fstat(pidfd)
                self.assertEqual(fcntl.fcntl(source['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)
                union.finish()

    def test_actual_high_lineage_owner_stays_source_only(self):
        case=lineage_fixture.LinuxControls();case.setUp();self.addCleanup(case.doCleanups)
        with high_fds(),lineage_fixture.ingest.Union() as union:
            with case.owner(union) as owner:
                self.assertGreater(owner._pidfd,2048);owner.check()
                with self.assertRaisesRegex(ValueError,'SOURCE_CUSTODY_ONLY'):
                    owner.verify(case.source,union.entries[Path(case.source['path'])])
                fd=owner._pidfd
            with self.assertRaises(OSError):os.fstat(fd)
            union.finish()

    def test_actual_high_lineage_identity_fault_closes_original_pidfd(self):
        case=lineage_fixture.LinuxControls();case.setUp();self.addCleanup(case.doCleanups)
        opened=[];open_pidfd=os.pidfd_open
        def capture(*args):
            fd=open_pidfd(*args);opened.append(fd);return fd
        with high_fds(),lineage_fixture.ingest.Union() as union:
            with patch.object(os,'pidfd_open',side_effect=capture),patch.object(
                    lineage_fixture.m.provider.control,'pidfd_identity',side_effect=OSError('injected identity read failure')):
                with self.assertRaisesRegex(OSError,'identity read failure'):case.owner(union)
            self.assertEqual(len(opened),1);self.assertGreater(opened[0],2048)
            with self.assertRaises(OSError):os.fstat(opened[0])
            union.finish()

    def test_actual_high_owned_observation_reap_and_final_leases(self):
        # The observation record is modeled; Linux child, high pidfd and leased
        # source/clone readbacks are real. No Windows identity is asserted.
        clone=self.root/'clone';clone.write_bytes(self.source.read_bytes())
        pin=provider.replacement.local_pin(clone)
        with high_fds():
            child=subprocess.Popen(['/usr/bin/true']);fd=os.pidfd_open(child.pid)
            child.wait(timeout=5);self.assertGreater(fd,2048)
            try:
                with provider.replacement.leased_inputs([self.pin,pin]) as held:
                    def guard(*_):
                        for entry in held.values():entry['checkpoint']()
                    observer=control.OwnedObservation(control._OBSERVATION_KEY,guard,held,self.pin,
                        held[pin['path']]['fd'],pin,fd,child,{})
                    observer.check();observer.finish();observer._active=False
                    for entry in held.values():
                        self.assertEqual(fcntl.fcntl(entry['fd'],fcntl.F_GETLEASE),fcntl.F_RDLCK)
            finally:os.close(fd)

class DelegatedHighFDControls(unittest.TestCase):
    setUp=HighFDControls.setUp
    @unittest.skipUnless(os.environ.get('SHZ_BASELINE_TEST_UNIT'),'actual delegated Linux owner required')
    def test_high_source_owner_identity_fault_closes_and_restores_handlers(self):
        previous={n:signal.getsignal(n) for n in (signal.SIGIO,signal.SIGTERM,signal.SIGINT,signal.SIGHUP)}
        opened=[];open_pidfd=os.pidfd_open
        def capture(*args):
            fd=open_pidfd(*args);opened.append(fd);return fd
        with high_fds():
            with patch.object(os,'pidfd_open',side_effect=capture),patch.object(
                    custody,'pidfd_identity',side_effect=OSError('injected identity read failure')):
                with self.assertRaisesRegex(OSError,'identity read failure'):
                    custody.BaselineSourceOwner(os.environ['SHZ_BASELINE_TEST_UNIT'],self.pin)
            self.assertEqual(len(opened),1);self.assertGreater(opened[0],2048)
            with self.assertRaises(OSError):os.fstat(opened[0])
            for n,handler in previous.items():self.assertIs(signal.getsignal(n),handler)

    @unittest.skipUnless(os.environ.get('SHZ_BASELINE_TEST_UNIT'),'actual delegated Linux owner required')
    def test_high_source_launch_identity_fault_reaps_before_lease_release(self):
        with high_fds(),custody.BaselineSourceOwner(os.environ['SHZ_BASELINE_TEST_UNIT'],self.pin) as owner:
            owner.clone(self.root/'clone');capture=custody.pidfd_identity
            def fail_child(fd):
                if fd!=owner.owner_pidfd:raise OSError('injected child identity failure')
                return capture(fd)
            with patch.object(custody,'pidfd_identity',side_effect=fail_child):
                with self.assertRaisesRegex(OSError,'child identity failure'):
                    owner.launch_control(['/usr/bin/sleep','60'],provider.replacement.local_pin(Path('/usr/bin/sleep')),5)
            self.assertGreater(owner.child_pidfd,2048);self.assertIsNotNone(owner.process.returncode)
            self.assertFalse(owner.descendants())
            self.assertEqual(fcntl.fcntl(owner.source_fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)

    @unittest.skipUnless(os.environ.get('SHZ_BASELINE_TEST_UNIT'),'actual delegated Linux owner required')
    def test_high_source_owner_clone_and_actual_reap(self):
        with high_fds(),custody.BaselineSourceOwner(os.environ['SHZ_BASELINE_TEST_UNIT'],self.pin) as owner:
            self.assertGreater(owner.owner_pidfd,2048);owner.check()
            owner.clone(self.root/'clone')
            owner.launch_control(['/usr/bin/true'],provider.replacement.local_pin(Path('/usr/bin/true')),5)
            self.assertGreater(owner.child_pidfd,2048)
            self.assertIsNotNone(owner.process.returncode);self.assertFalse(owner.descendants())
            self.assertEqual(fcntl.fcntl(owner.source_fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
            self.assertEqual(owner.callback(owner.nonce,lambda cap:cap.grade),custody.SOURCE_CUSTODY_ONLY)

    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'actual delegated Linux owner required')
    def test_high_cleanup_member_actually_exits_after_pidfd_open(self):
        with high_fds():
            group=provider.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
            child=subprocess.Popen(['/usr/bin/sleep','60'],preexec_fn=group.enter_child)
            fd=os.pidfd_open(child.pid);original=provider.actual_group;seen=[]
            def exiting(pid='self'):
                if pid==child.pid:
                    child.kill();child.wait(timeout=5)
                return original(pid)
            capture_identity=provider.control.pidfd_identity
            def capture(number):seen.append(number);return capture_identity(number)
            try:
                with patch.object(provider,'actual_group',side_effect=exiting),patch.object(provider.control,'pidfd_identity',side_effect=capture):
                    group.signal_members(signal.SIGTERM,set())
                self.assertTrue(seen);self.assertTrue(all(number>2048 for number in seen))
                self.assertIsNotNone(child.returncode);self.assertFalse(group.members())
            finally:group.cleanup(child,fd);os.close(fd);group.remove()

    @unittest.skipUnless(os.environ.get('SHZ_PROVIDER_TEST_UNIT'),'actual delegated Linux owner required')
    def test_high_cleanup_live_missing_proc_path_still_refused(self):
        with high_fds():
            group=provider.OwnedKeeperGroup(os.environ['SHZ_PROVIDER_TEST_UNIT'])
            child=subprocess.Popen(['/usr/bin/sleep','60'],preexec_fn=group.enter_child)
            fd=os.pidfd_open(child.pid);original=provider.actual_group
            def missing(pid='self'):
                if pid==child.pid:raise FileNotFoundError('modeled inaccessible proc of actual live child')
                return original(pid)
            try:
                with patch.object(provider,'actual_group',side_effect=missing):
                    with self.assertRaisesRegex(ValueError,'live owned cleanup'):
                        group.signal_members(signal.SIGTERM,set())
                self.assertIsNone(child.poll())
            finally:group.cleanup(child,fd);os.close(fd);group.remove()

if __name__=='__main__':
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(HighFDControls)
    for name in unittest.defaultTestLoader.getTestCaseNames(DelegatedHighFDControls):
        if name.startswith('test_high_'):suite.addTest(DelegatedHighFDControls(name))
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
