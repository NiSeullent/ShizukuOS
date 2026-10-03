# SPDX-License-Identifier: GPL-2.0-only
"""Descriptor budget and typed source Git tree controls; no producer approval."""
import os
import hashlib
import fcntl
import resource
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import private_installer_iso as iso

class SourceClosure(unittest.TestCase):
 def test_actual_tree_distinguishes_gitlink_from_regular_source(self):
  revision=iso._git(iso.ROOT,'rev-parse','HEAD').decode().strip()
  blobs,links=iso._tree_entries(iso.ROOT,revision)
  self.assertIn('shizukudos/install/private_installer_iso.py',blobs)
  self.assertEqual(links['third_party/KernelEx'],'31cdfc3560fc116637ee8ed7be31b12f3aacf5d1')
  self.assertNotIn('third_party/KernelEx',blobs)
 def test_fd_budget_raise_and_restore_on_failure_is_process_local(self):
  changes=[]
  with patch.object(iso,'_tree_entries',return_value=({'file':'a'},{})),patch.object(iso,'_git',return_value=b'a'*40),patch.object(iso.resource,'getrlimit',return_value=(1024,65536)),patch.object(iso.resource,'setrlimit',side_effect=lambda kind,limit:changes.append((kind,limit))):
   with self.assertRaisesRegex(RuntimeError,'host modeled failure'):
    with iso._fd_budget() as budget:
     self.assertGreater(budget['required'],1024)
     raise RuntimeError('host modeled failure')
  self.assertEqual(changes[-1],(resource.RLIMIT_NOFILE,(1024,65536)))
  self.assertLessEqual(changes[0][1][0],65536)
 def test_hard_limit_refuses_before_any_change(self):
  with patch.object(iso,'_tree_entries',return_value=({'file':'a'},{})),patch.object(iso,'_git',return_value=b'a'*40),patch.object(iso.resource,'getrlimit',return_value=(1024,1024)),patch.object(iso.resource,'setrlimit') as change:
   with self.assertRaisesRegex(ValueError,'hard descriptor limit'):
    with iso._fd_budget():self.fail('descriptor retention impossible')
   change.assert_not_called()
 def test_unsupported_tree_type_refused(self):
  with patch.object(iso,'_git',return_value=b'120000 blob '+b'a'*40+b'\tlink\0'):
   with self.assertRaisesRegex(ValueError,'unsupported committed source type'):
    iso._tree_entries('/unused','a'*40)
 def test_real_empty_metadata_lease_kept_then_closed_on_cancel(self):
  from test_private_installer_package import PackagingTests
  with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
   root=Path(tmp);stack,held,custody,_,_=PackagingTests().model(root)
   path=root/'committed-metadata';path.write_bytes(b'')
   with stack:
    metadata=iso._CommittedMetadataLeases(custody)
    with self.assertRaisesRegex(RuntimeError,'cancel'):
     with metadata:
      metadata.add(path,hashlib.sha256(b'').hexdigest())
      fd=metadata.entries[0]['fd']
      self.assertEqual(fcntl.fcntl(fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
      custody.check()
      self.assertNotIn(path,held.entries)
      raise RuntimeError('cancel')
    self.assertTrue(metadata.closed)
    with self.assertRaises(OSError):os.fstat(fd)
    custody.check()
 def test_empty_metadata_refuses_native_size_and_digest_substitution(self):
  from test_private_installer_package import PackagingTests
  with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
   root=Path(tmp);stack,_,custody,_,_=PackagingTests().model(root)
   path=root/'nonempty';path.write_bytes(b'not metadata')
   with stack,iso._CommittedMetadataLeases(custody) as metadata:
    with self.assertRaisesRegex(ValueError,'exact empty'):
     metadata.add(path,hashlib.sha256(path.read_bytes()).hexdigest())
    with self.assertRaisesRegex(ValueError,'independent empty'):
     metadata.add(path,hashlib.sha256(b'').hexdigest())
    self.assertEqual(metadata.entries,[])
 def test_all_metadata_descriptors_close_when_cleanup_one_unlock_fails(self):
  from test_private_installer_package import PackagingTests
  with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
   root=Path(tmp);stack,_,custody,_,_=PackagingTests().model(root)
   with stack:
    metadata=iso._CommittedMetadataLeases(custody)
    for name in ('a','b'):
     path=root/name;path.write_bytes(b'');metadata.add(path,hashlib.sha256(b'').hexdigest())
    fds=[e['fd'] for e in metadata.entries];original=iso.fcntl.fcntl
    def fail_once(fd,op,*args):
     if fd==fds[1] and op==fcntl.F_SETLEASE and args==(fcntl.F_UNLCK,):raise OSError('modeled unlock failure')
     return original(fd,op,*args)
    with patch.object(iso.fcntl,'fcntl',side_effect=fail_once):
     with self.assertRaisesRegex(OSError,'modeled unlock'):
      metadata.__exit__(None,None,None)
    self.assertTrue(metadata.closed)
    for fd in fds:
     with self.assertRaises(OSError):os.fstat(fd)
if __name__=='__main__':unittest.main(verbosity=2)
