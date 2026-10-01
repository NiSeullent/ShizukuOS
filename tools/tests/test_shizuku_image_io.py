#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual sparse image and immutable same-content ISO alias controls; no VM."""
import hashlib
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'shizuku_image_io.py'
spec = importlib.util.spec_from_file_location('shizuku_image_io', MODULE) if MODULE.exists() else None
io = importlib.util.module_from_spec(spec) if spec else None
if spec:spec.loader.exec_module(io)

class ImageIO(unittest.TestCase):
    def setUp(self):
        if io is None and self._testMethodName!='test_helper_exists':self.skipTest('production helper not implemented')
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
    def tearDown(self):
        if hasattr(self,'tmp'):self.tmp.cleanup()
    def test_helper_exists(self):
        self.assertTrue(MODULE.is_file(),'production sparse/duplicate helper is missing')
    def payload(self):
        data=bytearray(8*1024*1024+513)
        data[:512]=bytes(range(256))*2
        data[1024*1024+27:1024*1024+64]=b'Q'*37
        data[-513:]=b'T'*513
        return bytes(data)
    def test_sparse_copy_exact_size_hash_and_real_allocation(self):
        source=self.root/'source.img';target=self.root/'clone.img';data=self.payload();source.write_bytes(data)
        result=io.copy_new_sparse(source,target,expected_sha256=hashlib.sha256(data).hexdigest())
        self.assertEqual(target.read_bytes(),data);self.assertEqual(result['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(result['bytes'],len(data));self.assertLess(result['written_bytes'],20*1024)
        self.assertLess(target.stat().st_blocks*512,source.stat().st_blocks*512//20)
        self.assertEqual(source.read_bytes(),data)
    def test_range_copy_and_unaligned_tail(self):
        source=self.root/'source';target=self.root/'part';source.write_bytes(b'prefix'+self.payload()+b'suffix')
        result=io.copy_new_sparse(source,target,source_offset=6,length=len(self.payload()))
        self.assertEqual(target.read_bytes(),self.payload());self.assertEqual(result['bytes'],len(self.payload()))
    def test_wrong_pin_no_target(self):
        source=self.root/'source';target=self.root/'target';source.write_bytes(self.payload())
        with self.assertRaises(ValueError):io.copy_new_sparse(source,target,expected_sha256='0'*64)
        self.assertFalse(target.exists());self.assertEqual(list(self.root.glob('.*.tmp')),[])
    def test_existing_target_and_symlink_refused(self):
        source=self.root/'source';target=self.root/'target';source.write_bytes(b'new');target.write_bytes(b'old')
        with self.assertRaises(FileExistsError):io.copy_new_sparse(source,target)
        self.assertEqual(target.read_bytes(),b'old');target.unlink();target.symlink_to(source)
        with self.assertRaises(FileExistsError):io.copy_new_sparse(source,target)
        alias=self.root/'alias';alias.symlink_to(source)
        with self.assertRaises(OSError):io.copy_new_sparse(alias,self.root/'new')
    def test_range_bound_and_nonregular_source(self):
        source=self.root/'source';source.write_bytes(b'abcd')
        for offset,length in [(-1,2),(0,-1),(3,2),(6,0),(True,1),(0,False)]:
            with self.assertRaises(ValueError):io.copy_new_sparse(source,self.root/'new',source_offset=offset,length=length)
        fifo=self.root/'fifo';os.mkfifo(fifo)
        with self.assertRaises(ValueError):io.copy_new_sparse(fifo,self.root/'new')
    def test_short_writes_complete_and_zero_write_failure_cleanup(self):
        source=self.root/'source';source.write_bytes(self.payload());real_write=os.pwrite
        with patch.object(io.os,'pwrite',side_effect=lambda fd,data,offset:real_write(fd,data[:47],offset)):
            io.copy_new_sparse(source,self.root/'complete')
        self.assertEqual((self.root/'complete').read_bytes(),self.payload())
        with patch.object(io.os,'pwrite',return_value=0):
            with self.assertRaises(OSError):io.copy_new_sparse(source,self.root/'failed')
        self.assertFalse((self.root/'failed').exists());self.assertEqual(list(self.root.glob('.*.tmp')),[])
    def test_source_change_detected_before_destination_publication(self):
        source=self.root/'source';source.write_bytes(self.payload());real_pread=os.pread;once=[False]
        def mutate(fd,size,offset):
            data=real_pread(fd,size,offset)
            if not once[0]:
                once[0]=True
                with source.open('ab')as file:file.write(b'changed')
            return data
        with patch.object(io.os,'pread',side_effect=mutate):
            with self.assertRaises(RuntimeError):io.copy_new_sparse(source,self.root/'failed')
        self.assertFalse((self.root/'failed').exists())
    def test_partial_overlay_preserves_prefix_suffix_and_overwrites_stale_zeros(self):
        data=self.payload();source=self.root/'source';source.write_bytes(data)
        target=self.root/'owned.img.partial';target.write_bytes(b'prefix'+b'Z'*len(data)+b'suffix')
        result=io.overlay_sparse_partial(source,target,destination_offset=6,length=len(data))
        self.assertEqual(target.read_bytes(),b'prefix'+data+b'suffix');self.assertEqual(result['sha256'],hashlib.sha256(data).hexdigest())
        unsafe=self.root/'actual.img';unsafe.write_bytes(b'old')
        with self.assertRaises(ValueError):io.overlay_sparse_partial(source,unsafe)
        self.assertEqual(unsafe.read_bytes(),b'old')
    def test_fresh_sparse_partial_skips_zero_writes_and_keeps_layout(self):
        source=self.root/'source';data=self.payload();source.write_bytes(data);target=self.root/'disk.img.partial'
        with target.open('wb')as file:file.truncate(len(data)+1048576)
        io.overlay_sparse_partial(source,target,destination_offset=1048576)
        self.assertEqual(target.read_bytes(),bytes(1048576)+data)
        self.assertLess(target.stat().st_blocks*512,32*1024)
    def test_empty_and_whole_zero_copies_preserve_sizes(self):
        for size in (0,4095,4096,1048576):
            source=self.root/('source'+str(size));source.write_bytes(bytes(size))
            target=self.root/('target'+str(size));result=io.copy_new_sparse(source,target)
            self.assertEqual(target.read_bytes(),bytes(size));self.assertEqual(result['written_bytes'],0)
    def test_flush_readback_and_link_failures_leave_no_canonical_copy(self):
        source=self.root/'source';source.write_bytes(self.payload())
        for name in ('flush','readback','link'):
            target=self.root/name
            if name=='flush':
                operation=patch.object(io.os,'fsync',side_effect=OSError('injected fsync failure'))
            elif name=='readback':
                real_pwrite=os.pwrite
                def corrupt(fd,data,offset):
                    bad=bytearray(data);bad[0]^=1;return real_pwrite(fd,bad,offset)
                operation=patch.object(io.os,'pwrite',side_effect=corrupt)
            else:operation=patch.object(io.os,'link',side_effect=OSError('injected publication failure'))
            with operation:
                with self.assertRaises((OSError,RuntimeError)):io.copy_new_sparse(source,target)
            self.assertFalse(target.exists());self.assertEqual(list(self.root.glob('.*.tmp')),[])
    def test_concurrent_destination_creation_preserves_other_owner(self):
        source=self.root/'source';source.write_bytes(b'copy');target=self.root/'target';real_link=os.link
        def concurrent(src,dst,**kwargs):
            target.write_bytes(b'other publisher');return real_link(src,dst,**kwargs)
        with patch.object(io.os,'link',side_effect=concurrent):
            with self.assertRaises(FileExistsError):io.copy_new_sparse(source,target)
        self.assertEqual(target.read_bytes(),b'other publisher');self.assertEqual(list(self.root.glob('.*.tmp')),[])
    def test_bad_overlay_pin_has_no_writes_and_bounds_are_checked(self):
        source=self.root/'source';source.write_bytes(b'source');target=self.root/'owned.partial';target.write_bytes(b'previous target')
        with self.assertRaises(ValueError):io.overlay_sparse_partial(source,target,expected_sha256='0'*64)
        self.assertEqual(target.read_bytes(),b'previous target')
        with self.assertRaises(ValueError):io.overlay_sparse_partial(source,target,destination_offset=12)
        self.assertEqual(target.read_bytes(),b'previous target')
    def test_manifest_validation_precedes_any_alias_and_timestamp_mismatch_is_retained(self):
        stage=self.root/'stage';stage.mkdir()
        for name in ('a','b','z'):(stage/name).write_bytes(b'same')
        for name in ('a','b'):os.utime(stage/name,ns=(1,1))
        digest=hashlib.sha256(b'same').hexdigest();manifest={n:{'sha256':digest,'bytes':4}for n in ('a','b','z')}
        before=(stage/'b').stat().st_ino;manifest['z']['sha256']='0'*64
        with self.assertRaises(ValueError):io.deduplicate_stage(stage,manifest)
        self.assertEqual((stage/'b').stat().st_ino,before)
        manifest['z']['sha256']=digest;self.assertEqual(io.deduplicate_stage(stage,{'a':manifest['a'],'z':manifest['z']})['aliases'],0)
        with self.assertRaises(ValueError):io.deduplicate_stage(stage,{'a':{'sha256':digest,'bytes':True}})
    def test_pinned_stage_aliases_preserve_two_paths_and_bytes(self):
        data=b'exact runtime image'*400;stage=self.root/'stage';stage.mkdir()
        for name in ['win64.img','SHZ/K64/WIN64.IMG','different']:
            p=stage/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data if name!='different'else b'other');os.utime(p,ns=(1785283200000000000,1785283200000000000))
        manifest={name:{'sha256':hashlib.sha256((stage/name).read_bytes()).hexdigest(),'bytes':(stage/name).stat().st_size} for name in ['win64.img','SHZ/K64/WIN64.IMG','different']}
        result=io.deduplicate_stage(stage,manifest)
        self.assertEqual(result['aliases'],1);self.assertEqual((stage/'win64.img').stat().st_ino,(stage/'SHZ/K64/WIN64.IMG').stat().st_ino)
        for name,item in manifest.items():self.assertEqual(hashlib.sha256((stage/name).read_bytes()).hexdigest(),item['sha256'])
    def test_stage_bad_pin_path_symlink_mode_mismatch_are_refused_or_retained(self):
        stage=self.root/'stage';stage.mkdir();(stage/'a').write_bytes(b'same');(stage/'b').write_bytes(b'same')
        os.utime(stage/'a',ns=(1785283200000000000,1785283200000000000));os.utime(stage/'b',ns=(1785283200000000000,1785283200000000000))
        digest=hashlib.sha256(b'same').hexdigest();manifest={'a':{'sha256':digest,'bytes':4},'b':{'sha256':digest,'bytes':4}}
        with self.assertRaises(ValueError):io.deduplicate_stage(stage,{'../outside':manifest['a']})
        with self.assertRaises(ValueError):io.deduplicate_stage(stage,{'a':{'sha256':'0'*64,'bytes':4}})
        (stage/'s').symlink_to(stage/'a')
        with self.assertRaises(OSError):io.deduplicate_stage(stage,{'s':manifest['a']})
        (stage/'b').chmod(0o644 if (stage/'a').stat().st_mode & 0o777 == 0o600 else 0o600);self.assertEqual(io.deduplicate_stage(stage,manifest)['aliases'],0)
    @unittest.skipUnless(shutil.which('xorriso'),'xorriso required for actual ISO extent control')
    def test_actual_iso_two_paths_share_extent_and_extract_identical(self):
        stage=self.root/'stage';stage.mkdir();data=self.payload()[:1048576]
        for name in ('a.img','b.img'):
            (stage/name).write_bytes(data);os.utime(stage/name,ns=(1785283200000000000,1785283200000000000))
        digest=hashlib.sha256(data).hexdigest();io.deduplicate_stage(stage,{n:{'sha256':digest,'bytes':len(data)}for n in ('a.img','b.img')})
        image=self.root/'test.iso';subprocess.run(['xorriso','-as','mkisofs','--hardlinks','-R','-J','-o',str(image),str(stage)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        report=subprocess.check_output(['xorriso','-indev',str(image),'-find','/','-type','f','-exec','report_lba','--'],text=True,stderr=subprocess.DEVNULL,timeout=30)
        rows=[r for r in report.splitlines()if "'/a.img'"in r or "'/b.img'"in r]
        self.assertEqual(len(rows),2);self.assertEqual(rows[0].split(',')[1:4],rows[1].split(',')[1:4])
        extract=self.root/'extracted';subprocess.run(['xorriso','-osirrox','on','-indev',str(image),'-extract','/',str(extract)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=30)
        self.assertEqual((extract/'a.img').read_bytes(),data);self.assertEqual((extract/'b.img').read_bytes(),data)
        self.assertLess(image.stat().st_size,len(data)*2)

if __name__=='__main__':unittest.main()
