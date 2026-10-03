# SPDX-License-Identifier: GPL-2.0-only
"""Actual Linux RDLK/FICLONE/pidfd/owned child controls. No Windows/VM proof.

Run in an independent Delegate=yes unit with Baseline owner MainPID and no
RuntimeMax (mandatory retained cleanup). Set SHZ_BASELINE_TEST_UNIT to its name.
"""
import fcntl
import hashlib
import importlib.util
import os
from pathlib import Path
import pickle
import signal
import subprocess
import tempfile
import unittest

path = Path(__file__).resolve().parents[1] / 'native_baseline_custody.py'
spec = importlib.util.spec_from_file_location('baseline_source', path)
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)

def pin(file):
    raw=file.read_bytes()
    return {'path':str(file),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}

class LinuxControls(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='baseline-custody-',dir='/var/tmp')
        self.base=Path(self.tmp.name);self.base.chmod(0o700)
        self.source=self.base/'original';self.source.write_bytes(b'actual held source\0'*128);self.source.chmod(0o400)
        self.unit=os.environ['SHZ_BASELINE_TEST_UNIT']

    def tearDown(self):self.tmp.cleanup()

    def owner(self):return p.BaselineSourceOwner(self.unit,pin(self.source))
    def launch(self,owner):
        owner.clone(self.base/'clone');owner.launch_control(['/usr/bin/true'],pin(Path('/usr/bin/true')),5)

    def test_actual_lease_clone_pidfd_callback_and_no_windows_grade(self):
        with self.owner() as owner:
            self.assertEqual(fcntl.fcntl(owner.source_fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
            self.launch(owner)
            self.assertEqual((self.base/'clone').read_bytes(),self.source.read_bytes())
            self.assertNotEqual((self.base/'clone').stat().st_ino,self.source.stat().st_ino)
            captured=[]
            def callback(cap):
                self.assertEqual(cap.grade,p.SOURCE_CUSTODY_ONLY)
                cap.match_held_source({'fd':owner.source_fd,'pin':owner.pin,'identity':owner.source_identity})
                with self.assertRaises(ValueError):cap.verify_windows_identity()
                with self.assertRaises(TypeError):pickle.dumps(cap)
                captured.append(cap);return 'source callback ran'
            self.assertEqual(owner.callback(owner.nonce,callback),'source callback ran')
            with self.assertRaises(ValueError):owner.callback(owner.nonce,callback)
            with self.assertRaises(ValueError):captured[0].check()
        with self.assertRaises(ValueError):owner.check()

    def test_original_mode_and_fake_pin_refuse(self):
        self.source.chmod(0o600)
        with self.assertRaises(ValueError):self.owner()
        self.source.chmod(0o400)
        row=pin(self.source);row['sha256']='a'*64
        with self.assertRaises(ValueError):p.BaselineSourceOwner(self.unit,row)

    def test_hardlink_and_symlink_refuse(self):
        os.link(self.source,self.base/'hard')
        with self.assertRaises(ValueError):self.owner()
        (self.base/'hard').unlink();(self.base/'link').symlink_to(self.source)
        with self.assertRaises(ValueError):p.BaselineSourceOwner(self.unit,pin(self.base/'link'))

    def test_original_namespace_drift_invalidates_live_custody(self):
        owner=self.owner()
        self.source.rename(self.base/'moved');self.source.write_bytes(b'changed');self.source.chmod(0o400)
        with self.assertRaises(ValueError):owner.check()
        with self.assertRaises(ValueError):owner.close()
        self.assertEqual(owner.phase,'CLOSED')

    def test_fresh_clone_and_bad_timeout_before_launch(self):
        with self.owner() as owner:
            (self.base/'exists').write_bytes(b'keep')
            with self.assertRaises(ValueError):owner.clone(self.base/'exists')
            owner.clone(self.base/'clone')
            for timeout in (0,-1,601,float('nan'),True):
                with self.assertRaises(ValueError):owner.launch_control(['/usr/bin/true'],pin(Path('/usr/bin/true')),timeout)
            self.assertIsNone(owner.process)

    def test_wrong_nonce_and_caller_fake_capability_refuse(self):
        with self.owner() as owner:
            self.launch(owner)
            with self.assertRaises(ValueError):owner.callback(bytes(32),lambda cap:None)
            with self.assertRaises(ValueError):p.SourceCapability(None,owner,owner.nonce)
            def callback(cap):
                with self.assertRaises(ValueError):cap.match_held_source({'fd':owner.source_fd,'pin':dict(owner.pin,sha256='f'*64),'identity':owner.source_identity})
            owner.callback(owner.nonce,callback)

    def test_nonzero_actual_child_exit_never_admitted(self):
        with self.owner() as owner:
            owner.clone(self.base/'clone')
            with self.assertRaises(ValueError):owner.launch_control(['/usr/bin/false'],pin(Path('/usr/bin/false')),5)
            with self.assertRaises(ValueError):owner.callback(owner.nonce,lambda cap:None)
            self.assertFalse(owner.descendants())

    def test_forked_caller_owner_binding_refuses(self):
        with self.owner() as owner:
            child=os.fork()
            if not child:
                try:owner.check()
                except ValueError:os._exit(0)
                os._exit(1)
            _,status=os.waitpid(child,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)

    def test_changed_handler_refuses_without_silent_replacement(self):
        owner=self.owner();signal.signal(signal.SIGIO,signal.SIG_IGN)
        with self.assertRaises(ValueError):owner.check()
        with self.assertRaises(ValueError):owner.close()
        signal.signal(signal.SIGIO,owner.previous[signal.SIGIO])

    def test_callback_exception_revokes_capability(self):
        with self.owner() as owner:
            self.launch(owner);held=[]
            def callback(cap):held.append(cap);raise RuntimeError('modeled compiler failure')
            with self.assertRaises(RuntimeError):owner.callback(owner.nonce,callback)
            with self.assertRaises(ValueError):held[0].check()

    def test_actual_late_writer_sigio_refuses_and_preserves_original(self):
        owner=self.owner();owner.clone(self.base/'clone')
        original=self.source.read_bytes()
        argv=[str(Path('/usr/bin/python3').resolve()),'-c','import sys;open(sys.argv[1], "wb").write(b"forbidden")',str(self.source)]
        with self.assertRaises(Exception):owner.launch_control(argv,pin(Path('/usr/bin/python3').resolve()),.1)
        self.assertTrue(owner.broken)
        self.assertFalse(owner.descendants())
        self.assertEqual(self.source.read_bytes(),original)
        with self.assertRaises(ValueError):owner.close()

    def test_actual_owner_cancellation_retains_until_cleanup(self):
        owner=self.owner();os.kill(os.getpid(),signal.SIGTERM)
        self.assertTrue(owner.cancelled)
        with self.assertRaises(ValueError):owner.check()
        self.assertEqual(fcntl.fcntl(owner.source_fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
        with self.assertRaises(ValueError):owner.close()
        self.assertEqual(owner.phase,'CLOSED')

    def test_actual_child_timeout_cleans_own_group_before_release(self):
        with self.owner() as owner:
            owner.clone(self.base/'clone')
            with self.assertRaises(Exception):owner.launch_control(['/usr/bin/sleep','60'],pin(Path('/usr/bin/sleep')), .05)
            self.assertFalse(owner.descendants())
            with self.assertRaises(ValueError):owner.callback(owner.nonce,lambda cap:None)

    def test_actual_orphan_child_is_reaped_before_callback(self):
        with self.owner() as owner:
            owner.clone(self.base/'clone')
            executable=Path('/usr/bin/python3').resolve()
            argv=[str(executable),'-c','import subprocess;subprocess.Popen(["/usr/bin/sleep","60"])']
            owner.launch_control(argv,pin(executable),5)
            self.assertFalse(owner.descendants())
            self.assertEqual(owner.callback(owner.nonce,lambda cap:cap.grade),p.SOURCE_CUSTODY_ONLY)

    def test_clone_replacement_refuses_before_freeze(self):
        with self.owner() as owner:
            owner.clone(self.base/'clone')
            (self.base/'clone').rename(self.base/'other')
            (self.base/'clone').write_bytes(b'changed clone')
            with self.assertRaises(ValueError):owner.launch_control(['/usr/bin/true'],pin(Path('/usr/bin/true')),5)
            with self.assertRaises(ValueError):owner.callback(owner.nonce,lambda cap:None)

    def test_callback_pending_child_refuses_after_actual_cleanup(self):
        with self.owner() as owner:
            self.launch(owner);children=[]
            def callback(cap):
                cap.check();children.append(subprocess.Popen(['/usr/bin/sleep','60']));return 'not admission'
            with self.assertRaises(ValueError):owner.callback(owner.nonce,callback)
            children[0].wait(timeout=5);self.assertFalse(owner.descendants())

if __name__=='__main__':unittest.main(verbosity=2)
