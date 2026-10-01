# SPDX-License-Identifier: GPL-2.0-or-later
import hashlib
import os
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

P=Path(__file__).resolve().parents[1]/'run_original_dos_control.py'
spec=importlib.util.spec_from_file_location('original_control_reflink_test',P)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class ReflinkControl(unittest.TestCase):
    def test_actual_cow_clone_preserves_source_after_target_writes(self):
        with tempfile.TemporaryDirectory(dir=P.parents[1]/'build') as temporary:
            root=Path(temporary)
            source=root/'source.raw'; target=root/'clone.raw'
            data=b'OWNED SOURCE'+b'\0'*(1024*1024)
            source.write_bytes(data)
            digest=hashlib.sha256(data).hexdigest()
            result=module.copy_new_reflink(source,target,digest)
            self.assertEqual(result['sha256'],digest)
            self.assertTrue(result['target_readback_verified'])
            self.assertNotEqual(source.stat().st_ino,target.stat().st_ino)
            with target.open('r+b') as stream: stream.write(b'LOCAL CHANGE')
            self.assertEqual(source.read_bytes(),data)
            self.assertNotEqual(target.read_bytes(),data)

    def test_wrong_pin_or_existing_destination_never_publishes(self):
        with tempfile.TemporaryDirectory(dir=P.parents[1]/'build') as temporary:
            root=Path(temporary); source=root/'source'; target=root/'target'
            source.write_bytes(b'original')
            with self.assertRaises(ValueError): module.copy_new_reflink(source,target,'a'*64)
            self.assertFalse(target.exists())
            target.write_bytes(b'retained')
            with self.assertRaises(FileExistsError): module.copy_new_reflink(source,target,hashlib.sha256(b'original').hexdigest())
            self.assertEqual(target.read_bytes(),b'retained')
            self.assertEqual(source.read_bytes(),b'original')
            self.assertEqual(sorted(p.name for p in root.iterdir()),['source','target'])

    def test_real_existing_writer_refuses_a_source_read_lease(self):
        with tempfile.TemporaryDirectory(dir=P.parents[1]/'build') as temporary:
            root=Path(temporary); source=root/'source'; target=root/'target'
            source.write_bytes(b'original')
            writer=os.open(source,os.O_WRONLY|os.O_NONBLOCK)
            try:
                with self.assertRaises((OSError,RuntimeError)):
                    module.copy_new_reflink(source,target,hashlib.sha256(b'original').hexdigest())
            finally:os.close(writer)
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(),b'original')

    def test_real_lease_break_is_rejected_before_publication(self):
        with tempfile.TemporaryDirectory(dir=P.parents[1]/'build') as temporary:
            root=Path(temporary); source=root/'source'; target=root/'target'
            source.write_bytes(b'original')
            real=module.fcntl.ioctl
            def request_writer(fd,op,arg):
                try:
                    writer=os.open(source,os.O_WRONLY|os.O_NONBLOCK)
                except BlockingIOError: writer=None
                if writer is not None:
                    os.close(writer)
                    self.fail('writer acquired the read-leased source')
                return real(fd,op,arg)
            with patch.object(module.fcntl,'ioctl',request_writer):
                with self.assertRaises(RuntimeError):
                    module.copy_new_reflink(source,target,hashlib.sha256(b'original').hexdigest())
            self.assertFalse(target.exists())
            self.assertEqual(source.read_bytes(),b'original')
            self.assertEqual([p.name for p in root.iterdir()],['source'])

    def test_ioctl_failure_preserves_original_without_dense_fallback(self):
        with tempfile.TemporaryDirectory(dir=P.parents[1]/'build') as temporary:
            root=Path(temporary); source=root/'source'; target=root/'target'
            source.write_bytes(b'original')
            with patch.object(module.fcntl,'ioctl',side_effect=OSError('no reflink')):
                with self.assertRaises(OSError): module.copy_new_reflink(source,target,hashlib.sha256(b'original').hexdigest())
            self.assertEqual(source.read_bytes(),b'original')
            self.assertFalse(target.exists())
            self.assertEqual([p.name for p in root.iterdir()],['source'])

if __name__=='__main__': unittest.main()
