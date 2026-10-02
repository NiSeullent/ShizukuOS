#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual sparse/COW/FAT streaming controls, never an OS or VM proof."""
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('native_io_optimized',HERE.parent/'build.py')
B=importlib.util.module_from_spec(spec);spec.loader.exec_module(B)

class OptimizedIO(unittest.TestCase):
    def setUp(self):
        self.folder=tempfile.TemporaryDirectory(prefix='shz-native-io-',dir=os.environ.get('SHZ_NATIVE_INPUT_TEST_ROOT',HERE.parents[3]/'build'))
        self.root=Path(self.folder.name)
        self.source=self.root/'sparse-source'
        with self.source.open('xb') as stream:
            stream.write(b'first-marker');stream.seek(8*1024*1024-17);stream.write(b'last-marker-exact!')
        self.pin=B.file_sha(self.source);self.size=self.source.stat().st_size
        if os.environ.get('SHZ_NATIVE_INPUT_TEST_ROOT'):
            real_space=B.space
            def fixture_space(path,remaining=0):
                # Explicit tiny fixture capacity model; actual host/RAM floors
                # remain observed and production reserve arithmetic is real.
                if isinstance(B.shutil.disk_usage,mock.Mock):return real_space(path,remaining)
                stats=os.statvfs(self.root);free=stats.f_bavail*stats.f_frsize
                mem=int(next(row.split()[1] for row in Path('/proc/meminfo').read_text().splitlines() if row.startswith('MemAvailable:')))*1024
                assert free>=(6<<30)+(160<<20) and mem>=(6<<30)+(160<<20)
                assert self.root==Path(path).parent or self.root in Path(path).parents
                usage=shutil._ntuple_diskusage(free+B.RESERVE,0,free+B.RESERVE)
                with mock.patch.object(B.shutil,'disk_usage',return_value=usage):real_space(path,remaining)
            capacity=mock.patch.object(B,'space',fixture_space);capacity.start();self.addCleanup(capacity.stop)
            spec=importlib.util.spec_from_file_location('io_fixture_capacity',HERE/'test_input_lease_lifetime.py')
            helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
            child_capacity=mock.patch.object(B,'command',helper.fixture_worker_capacity_command(B.command))
            child_capacity.start();self.addCleanup(child_capacity.stop)
    def tearDown(self):self.folder.cleanup()
    def copy(self,**kwargs):
        target=self.root/'copy'
        with B.read_leased(self.source,self.pin,self.size) as (fd,check):
            result=B.copy_fd(fd,check,target,self.pin,self.size,**kwargs)
        return target,result
    def test_zero_fallback_is_sparse_exact_and_source_stable(self):
        target,result=self.copy()
        self.assertEqual(B.file_sha(target),self.pin)
        self.assertEqual(B.file_sha(self.source),self.pin)
        self.assertLess(target.stat().st_blocks*512,64*1024)
        self.assertTrue(result['target_readback_verified'])
        self.assertEqual(result['method'],'streaming-sparse-zero-runs')
    def test_actual_reflink_then_target_write_does_not_change_original(self):
        target,result=self.copy(prefer_reflink=True)
        self.assertIn(result['method'],('leased-FICLONE-COW','streaming-sparse-zero-runs'))
        self.assertNotEqual(target.stat().st_ino,self.source.stat().st_ino)
        with target.open('r+b') as stream:stream.write(b'OWNED CHANGE')
        self.assertEqual(B.file_sha(self.source),self.pin)
        self.assertNotEqual(B.file_sha(target),self.pin)
    def test_unsupported_reflink_falls_back_sparse_from_the_same_leased_fd(self):
        real=B.fcntl.ioctl
        def unsupported(fd,op,arg):
            if op==0x40049409:raise OSError(errno.EOPNOTSUPP,'controlled unsupported clone')
            return real(fd,op,arg)
        with mock.patch.object(B.fcntl,'ioctl',unsupported):target,result=self.copy(prefer_reflink=True)
        self.assertEqual(result['method'],'streaming-sparse-zero-runs')
        self.assertEqual(result['reflink_fallback_errno'],errno.EOPNOTSUPP)
        self.assertEqual(B.file_sha(target),self.pin)
        self.assertLess(target.stat().st_blocks*512,64*1024)
    def test_reflink_eio_is_not_hidden_by_fallback(self):
        with mock.patch.object(B.fcntl,'ioctl',side_effect=OSError(errno.EIO,'controlled I/O error')):
            with self.assertRaises(OSError):self.copy(prefer_reflink=True)
        self.assertEqual(B.file_sha(self.source),self.pin)
        self.assertEqual((self.root/'copy').stat().st_size,0)
    def test_measured_budget_preserves_17gib_without_blanket_7gib(self):
        inputs={'DISK.IMG':{'path':self.source,'bytes':self.size}}
        budget=B.preparation_budget(inputs)
        self.assertEqual(budget,(B.ESP_MIB<<20)+self.source.stat().st_blocks*512+(128<<20))
        self.assertLess(budget,3<<30)
        self.assertEqual(B.RESERVE,17<<30)
        usage=shutil._ntuple_diskusage(30<<30,10<<30,20<<30)
        with mock.patch.object(B.shutil,'disk_usage',return_value=usage):B.space(self.root/'out',budget)
        with mock.patch.object(B.shutil,'disk_usage',return_value=usage):
            with self.assertRaises(RuntimeError):B.space(self.root/'out',7<<30)
    @unittest.skipUnless(all(shutil.which(p) for p in ('mkfs.vfat','mmd','mcopy','mtype')),'mtools absent')
    def test_actual_fat_readback_stream_no_dense_temporary(self):
        out=self.root/'fat';out.mkdir()
        loader=self.root/'loader';loader.write_bytes(b'owned non-executable loader fixture')
        receipt={'commands':[]}
        with mock.patch.object(B,'ESP_MIB',64):
            esp,members=B.assemble(out,{'DISK.IMG':self.source},loader,receipt)
        self.assertEqual(members['SHZDOS/DISK.IMG']['sha256'],self.pin)
        self.assertFalse((out/'readback-owned.tmp').exists())
        self.assertTrue(any(c[0]=='mtype' for c in receipt['commands']))
        with self.assertRaisesRegex(ValueError,'ESP byte readback mismatch'):
            B.verify_esp_member(esp,'SHZDOS/DISK.IMG','0'*64,self.size,receipt)
        with self.assertRaises((ValueError,RuntimeError)):
            B.verify_esp_member(esp,'SHZDOS/ABSENT','0'*64,1,receipt)
        self.assertEqual(B.file_sha(self.source),self.pin)

if __name__=='__main__':unittest.main(verbosity=2)
