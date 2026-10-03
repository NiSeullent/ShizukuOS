#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Synthetic disks and real source/template/lease controls, never OS boot proof."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / 'prepare_replacement.py'
spec = importlib.util.spec_from_file_location('replacement_prepare', TOOL) if TOOL.exists() else None
prep = importlib.util.module_from_spec(spec) if spec else None
if spec:
    spec.loader.exec_module(prep)
UPSTREAM = Path('/root/Win98-Modern-main-integration-20261001/build/shizukudos/dos16/work/freedos-kernel')


def geometry_fixture(kind):
    mbr, vbr = bytearray(512), bytearray(512)
    mbr[510:] = vbr[510:] = b'\x55\xaa'
    start = 32
    clusters = {12: 2000, 16: 5000, 32: 66000}[kind]
    fat_sectors = {12: 6, 16: 20, 32: 516}[kind]
    reserved, roots = (32, 0) if kind == 32 else (1, 512)
    total = reserved + 2 * fat_sectors + roots * 32 // 512 + clusters
    entry = 446
    mbr[entry] = 0x80
    mbr[entry + 4] = {12: 1, 16: 6, 32: 0x0c}[kind]
    struct.pack_into('<II', mbr, entry + 8, start, total)
    vbr[:3] = b'\xeb\x58\x90' if kind == 32 else b'\xeb\x3c\x90'
    vbr[3:11] = b'MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', vbr, 11, 512, 1, reserved, 2, roots,
                     total if total < 65536 else 0, 0xf8, 0 if kind == 32 else fat_sectors,
                     63, 255, start, total if total >= 65536 else 0)
    if kind == 32:
        struct.pack_into('<IHHIHH', vbr, 36, fat_sectors, 0, 0, 2, 1, 6)
        vbr[64] = 0x80
    else:
        vbr[36] = 0x80
    return bytes(mbr), bytes(vbr), (start + total) * 512


class ReplacementGeometry(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(prep, 'source-specific private replacement constructor is missing')

    def test_three_valid_fat_geometries_and_preserved_sys_bpb_ranges(self):
        for kind, filename, end, load in ((12, 'fat12com.bin', 62, 0x5c),
                                        (16, 'fat16com.bin', 62, 0x5c),
                                        (32, 'fat32lba.bin', 90, 0x78)):
            with self.subTest(fat=kind):
                mbr, vbr, size = geometry_fixture(kind)
                geometry = prep.inspect_geometry(mbr, vbr, size)
                self.assertEqual(geometry['fat_bits'], kind)
                boot = prep.compose_boot(vbr, (UPSTREAM / 'boot' / filename).read_bytes(), filename[:-4], geometry)
                preserved = bytearray(vbr[11:end]); preserved[(64 if kind == 32 else 36)-11] = 0x80
                self.assertEqual(boot[11:end], bytes(preserved))
                self.assertEqual(boot[3:11], b'FRDOS5.1')
                self.assertEqual(struct.unpack_from('<H', boot, load)[0], 0x60)
                self.assertEqual(boot[0x1f1:0x1fc], b'KERNEL  SYS')

    def test_partition_overlap_multiple_active_and_bpb_extent_are_refused(self):
        mbr, vbr, size = geometry_fixture(16)
        changed = bytearray(mbr); changed[462:478] = mbr[446:462]
        with self.assertRaises(ValueError): prep.inspect_geometry(changed, vbr, size)
        changed = bytearray(vbr); struct.pack_into('<I', changed, 28, 33)
        with self.assertRaises(ValueError): prep.inspect_geometry(mbr, changed, size)
        changed = bytearray(vbr); changed[13] = 3
        with self.assertRaises(ValueError): prep.inspect_geometry(mbr, changed, size)
        with self.assertRaises(ValueError): prep.inspect_geometry(mbr, vbr, size - 512)

    def test_fat32_backup_fsinfo_and_fat_capacity_are_bounded(self):
        mbr, vbr, size = geometry_fixture(32)
        for offset, value in ((50, 32), (50, 1), (48, 32), (42, 1), (40, 0x81)):
            changed = bytearray(vbr); struct.pack_into('<H', changed, offset, value)
            with self.subTest(offset=offset, value=value):
                with self.assertRaises(ValueError): prep.inspect_geometry(mbr, changed, size)
        changed = bytearray(vbr); struct.pack_into('<I', changed, 36, 1)
        with self.assertRaises(ValueError): prep.inspect_geometry(mbr, changed, size)

    def test_wrong_source_specific_template_or_magic_never_synthesizes_success(self):
        mbr, vbr, size = geometry_fixture(32)
        geometry = prep.inspect_geometry(mbr, vbr, size)
        template = (UPSTREAM / 'boot/fat32lba.bin').read_bytes()
        with self.assertRaises(ValueError): prep.compose_boot(vbr, template, 'fat16com', geometry)
        changed = bytearray(template); changed[0x82] ^= 1
        with self.assertRaises(ValueError): prep.compose_boot(vbr, changed, 'fat32lba', geometry)


class ReplacementCopy(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(prep, 'private disk copy guards missing')
        self.tmp = tempfile.TemporaryDirectory(prefix='shz-replacement-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source.raw'
        self.source.write_bytes(b'ORIGINAL PRIVATE SYNTHETIC DISK' + bytes(8192))
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.pin = {'path': str(self.source), 'bytes': self.source.stat().st_size, 'sha256': self.digest}

    def test_explicit_full_copy_is_independent_and_read_back(self):
        target = self.root / 'new.raw'
        with prep.leased_inputs([self.pin]) as sources, patch.object(prep, 'available_bytes', return_value=1 << 40):
            result = prep.copy_disk(sources[str(self.source)], target, 'full', self.source.stat().st_size, 1 << 20)
        self.assertEqual(target.read_bytes(), self.source.read_bytes())
        self.assertEqual(result['method'], 'explicit-full-copy')
        self.assertTrue(result['destination_readback_verified'])
        target.write_bytes(b'CHANGED OWNED COPY')
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(), self.digest)

    def test_wrong_pin_existing_output_and_insufficient_budget_make_no_copy(self):
        target = self.root / 'new.raw'
        with self.assertRaises(ValueError):
            with prep.leased_inputs([dict(self.pin, sha256='a'*64)]): pass
        self.assertFalse(target.exists())
        with prep.leased_inputs([self.pin]) as sources:
            with self.assertRaises(ValueError): prep.copy_disk(sources[str(self.source)], target, 'full', 1, 1 << 20)
        self.assertFalse(target.exists())
        target.write_bytes(b'EXISTING')
        with prep.leased_inputs([self.pin]) as sources:
            with self.assertRaises(FileExistsError): prep.copy_disk(sources[str(self.source)], target, 'full', 1 << 20, 1 << 20)
        self.assertEqual(target.read_bytes(), b'EXISTING')

    def test_existing_writer_or_lease_break_rejects_source(self):
        writer = os.open(self.source, os.O_WRONLY | os.O_NONBLOCK)
        try:
            with self.assertRaises(OSError):
                with prep.leased_inputs([self.pin]): pass
        finally: os.close(writer)
        with self.assertRaises(RuntimeError):
            with prep.leased_inputs([self.pin]) as sources:
                with self.assertRaises(BlockingIOError): os.open(self.source, os.O_WRONLY | os.O_NONBLOCK)
                sources[str(self.source)]['checkpoint']()

    def test_reflink_failure_has_no_full_copy_fallback(self):
        target = self.root / 'new.raw'
        with prep.leased_inputs([self.pin]) as sources, patch.object(prep, 'available_bytes', return_value=1 << 40), patch.object(prep.fcntl, 'ioctl', side_effect=OSError('unsupported')):
            with self.assertRaises(OSError): prep.copy_disk(sources[str(self.source)], target, 'reflink', 0, 1 << 20)
        self.assertFalse(target.exists())

    def test_copy_floor_and_capture_reserve_are_not_relaxed_for_small_inputs(self):
        target=self.root/'new.raw'
        with prep.leased_inputs([self.pin]) as sources,patch.object(prep,'available_bytes',return_value=18253611008+1048576):
            with self.assertRaises(RuntimeError):prep.copy_disk(sources[str(self.source)],target,'full',1<<20,1<<20)
        self.assertFalse(target.exists())

    def test_command_argument_paths_cannot_smuggle_mtools_image_syntax(self):
        for path in ('/tmp/file@@512', '/tmp/::bad', '/tmp/a\nb'):
            with self.subTest(path=path):
                with self.assertRaises(ValueError): prep.safe_path(path)


class ReplacementSparseCopy(unittest.TestCase):
    """Real tiny files/syscalls; injected capacity never admits a production job."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='shz-sparse-copy-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source, self.target = self.root/'source.raw', self.root/'new.raw'

    def pin(self, data):
        self.source.write_bytes(data)
        return {'path':str(self.source), 'bytes':len(data), 'sha256':hashlib.sha256(data).hexdigest()}

    def test_leading_interior_trailing_zero_chunks_omit_writes_but_read_every_byte(self):
        chunk = 1 << 20
        data = bytes(chunk) + b'A' + bytes(chunk-2) + b'B' + bytes(chunk) + b'C' + bytes(chunk-2) + b'D' + bytes(chunk+17)
        pin = self.pin(data)
        real_read, real_write = os.pread, os.write
        reads, written = [], []
        with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40):
            source = sources[str(self.source)]
            def observed_read(fd, count, at):
                block = real_read(fd, count, at)
                if fd == source['fd']: reads.append((at,len(block)))
                return block
            def observed_write(fd, block):
                n = real_write(fd, block); written.append(n); return n
            with patch.object(prep.os,'pread',observed_read), patch.object(prep.os,'write',observed_write):
                result = prep.copy_disk(source,self.target,'full',len(data),1 << 20)
        self.assertEqual(self.target.read_bytes(),data)
        self.assertEqual(reads,[(0,chunk),(chunk,chunk),(2*chunk,chunk),(3*chunk,chunk),(4*chunk,chunk),(5*chunk,17)])
        self.assertEqual(sum(written),2*chunk)
        self.assertEqual(result['data_bytes_written'],2*chunk)
        self.assertEqual(result['zero_bytes_omitted'],3*chunk+17)
        self.assertEqual(result['source_bytes_read'],5*chunk+17)
        self.assertNotEqual(self.target.stat().st_ino,self.source.stat().st_ino)

    def test_all_zero_input_has_exact_extent_hash_and_no_data_writes(self):
        data = bytes((2 << 20)+19); pin = self.pin(data)
        real_write, real_truncate, real_sync = os.write, os.ftruncate, os.fsync
        writes, events = [], []
        def observed_write(fd, block):
            n = real_write(fd,block); writes.append(n); return n
        def observed_truncate(fd, size):
            real_truncate(fd,size); events.append(('truncate',os.fstat(fd).st_size))
        def observed_sync(fd):
            events.append(('sync',os.fstat(fd).st_size)); return real_sync(fd)
        with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40), \
             patch.object(prep.os,'write',observed_write), patch.object(prep.os,'ftruncate',observed_truncate), \
             patch.object(prep.os,'fsync',observed_sync):
            result = prep.copy_disk(sources[str(self.source)],self.target,'full',len(data),1 << 20)
        self.assertEqual(self.target.stat().st_size,len(data))
        self.assertEqual(hashlib.sha256(self.target.read_bytes()).hexdigest(),pin['sha256'])
        self.assertEqual(sum(writes),0)
        self.assertEqual(events,[('truncate',len(data)),('sync',len(data))])
        self.assertEqual(result['data_bytes_written'],0)
        self.assertEqual(result['zero_bytes_omitted'],len(data))

    def test_nonzero_bytes_across_short_read_boundaries_survive_short_writes(self):
        # Nonzero offsets 63,64,191 put bytes on either side of 64-byte reads.
        data = bytes(63)+b'A'+b'B'+bytes(126)+b'C'+bytes(321); pin = self.pin(data)
        real_read, real_write = os.pread, os.write
        with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40):
            source = sources[str(self.source)]
            def short_read(fd, count, at):
                return real_read(fd,min(count,64) if fd == source['fd'] else count,at)
            def short_write(fd, block): return real_write(fd,block[:7])
            with patch.object(prep.os,'pread',short_read), patch.object(prep.os,'write',short_write):
                result = prep.copy_disk(source,self.target,'full',len(data),1 << 20)
        self.assertEqual(self.target.read_bytes(),data)
        self.assertEqual(result.get('source_bytes_read'),513)
        self.assertEqual(result.get('data_bytes_written'),192)
        self.assertEqual(result.get('zero_bytes_omitted'),321)

    def test_failed_or_wrong_seek_and_failed_or_ignored_truncate_leave_no_copy(self):
        pin = self.pin(bytes((1 << 20)+7)); real_seek = os.lseek
        def wrong_seek(fd, offset, whence): return real_seek(fd,offset,whence)-1
        controls = (('lseek',OSError('seek unavailable')),('lseek',wrong_seek),
                    ('ftruncate',OSError('truncate unavailable')),('ftruncate',lambda *_: None))
        for number, (call, behavior) in enumerate(controls):
            target = self.root/('failed-'+str(number)+'.raw')
            with self.subTest(call=call,behavior=str(behavior)):
                with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40), \
                     patch.object(prep.os,call,side_effect=behavior):
                    with self.assertRaises((OSError,ValueError)):
                        prep.copy_disk(sources[str(self.source)],target,'full',pin['bytes'],1 << 20)
                self.assertFalse(target.exists())

    def test_premature_source_end_and_zero_destination_write_leave_no_copy(self):
        pin = self.pin(b'A'+bytes((1 << 20)+7)); real_read, real_write = os.pread, os.write
        for failure in ('read','write'):
            with self.subTest(failure=failure), prep.leased_inputs([pin]) as sources, \
                 patch.object(prep,'available_bytes',return_value=1 << 40):
                source = sources[str(self.source)]
                def ended_read(fd, count, at):
                    return b'' if fd == source['fd'] and at else real_read(fd,count,at)
                with patch.object(prep.os,'pread',ended_read if failure == 'read' else real_read), \
                     patch.object(prep.os,'write',side_effect=(lambda *_: 0) if failure == 'write' else real_write):
                    with self.assertRaises(ValueError):
                        prep.copy_disk(source,self.target,'full',pin['bytes'],1 << 20)
            self.assertFalse(self.target.exists())

    def test_actual_lease_break_at_zero_skip_or_truncate_never_accepts_copy(self):
        pin = self.pin(bytes((1 << 20)+7))
        for call in ('lseek','ftruncate'):
            target = self.root/(call+'.raw')
            real = getattr(os,call)
            def concurrent_writer(*args):
                result = real(*args)
                with self.assertRaises(BlockingIOError): os.open(self.source,os.O_WRONLY|os.O_NONBLOCK)
                return result
            with self.subTest(call=call):
                with self.assertRaises(RuntimeError):
                    with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40), \
                         patch.object(prep.os,call,concurrent_writer):
                        prep.copy_disk(sources[str(self.source)],target,'full',pin['bytes'],1 << 20)
                self.assertFalse(target.exists())

    def test_all_zero_source_still_requires_complete_logical_budget(self):
        pin = self.pin(bytes((2 << 20)+19))
        with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',return_value=1 << 40):
            with self.assertRaises(ValueError):
                prep.copy_disk(sources[str(self.source)],self.target,'full',pin['bytes']-1,1 << 20)
        self.assertFalse(self.target.exists())

    def test_capacity_loss_after_zero_chunk_read_rejects_and_removes_copy(self):
        pin = self.pin(bytes((1 << 20)+7)); free = iter((1 << 40,prep.FLOOR))
        with prep.leased_inputs([pin]) as sources, patch.object(prep,'available_bytes',side_effect=lambda _: next(free)):
            with self.assertRaises(RuntimeError):
                prep.copy_disk(sources[str(self.source)],self.target,'full',pin['bytes'],1 << 20)
        self.assertFalse(self.target.exists())

    def test_failed_truncate_in_real_tiny_fat_preparation_never_publishes_receipt(self):
        fixture = ReplacementPrepare('test_validate_only_has_no_owned_disk_or_acceptance_claim')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        out = fixture.root/'failed-owned'
        with patch.object(prep.os,'ftruncate',side_effect=OSError('truncate unavailable')):
            with self.assertRaises(OSError): fixture.prepare(out)
        self.assertFalse((out/'preparation.json').exists())
        self.assertFalse((out/'replacement.img').exists())


class PrivateOutputPlacement(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='shz-private-output-',dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root/'new-output'

    def test_large_output_requires_explicit_private_scope_outside_default_lane(self):
        with self.assertRaises(ValueError): prep.large_output_scope(self.out,2 << 30)
        scope = prep.large_output_scope(self.out,2 << 30,self.root)
        self.assertEqual(scope['kind'],'explicit-owned-private-root')
        prep.check_output_scope(scope)
        self.assertFalse(self.out.exists())

    def test_public_permissions_symlink_and_outside_root_are_refused(self):
        self.root.chmod(0o755)
        with self.assertRaises(ValueError): prep.large_output_scope(self.out,2 << 30,self.root)
        self.root.chmod(0o700)
        for out in (self.root,self.root.parent/'outside'):
            with self.assertRaises(ValueError): prep.large_output_scope(out,2 << 30,self.root)
        alias = self.root/'alias'; alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaises(ValueError): prep.large_output_scope(self.out,2 << 30,alias)
        with self.assertRaises(ValueError): prep.large_output_scope(self.out,2 << 30,Path('/srv/m98'))

    def test_root_replacement_and_permission_drift_invalidate_observation(self):
        scope = prep.large_output_scope(self.out,2 << 30,self.root)
        self.root.chmod(0o710)
        with self.assertRaises(ValueError): prep.check_output_scope(scope)
        self.root.chmod(0o700)
        saved=self.root/'saved'; owned=self.root/'owned'; owned.mkdir(mode=0o700)
        scope=prep.large_output_scope(owned/'new',2 << 30,owned)
        owned.rename(saved); owned.mkdir(mode=0o700)
        with self.assertRaises(ValueError): prep.check_output_scope(scope)

    def test_private_scope_does_not_bypass_real_capacity_guard(self):
        prep.large_output_scope(self.out,2 << 30,self.root)
        with patch.object(prep,'available_bytes',return_value=prep.FLOOR):
            with self.assertRaises(RuntimeError): prep.capacity(self.root,16 << 20,128 << 20)
        with patch.object(prep.os,'geteuid',return_value=os.geteuid()+1):
            with self.assertRaises(ValueError): prep.large_output_scope(self.out,2 << 30,self.root)


class ReplacementInventory(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(prep)
        # /tmp is itself a Git checkout on this shared host. Keep private
        # synthetic output outside that visible checkout rather than bypassing
        # the same source-output guard used by production.
        self.tmp = tempfile.TemporaryDirectory(prefix='shz-replacement-fat-', dir='/var/tmp')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.disk = self.root / 'source.img'
        with self.disk.open('wb') as handle: handle.truncate((32+2048)*512)
        subprocess.run(['mkfs.fat', '-F', '12', '-s', '1', '-h', '32', '--offset=32', str(self.disk), '1024'], check=True, capture_output=True)
        mbr = bytearray(512); mbr[510:] = b'\x55\xaa'; mbr[446] = 0x80; mbr[450] = 1
        struct.pack_into('<II', mbr, 454, 32, 2048)
        with self.disk.open('r+b') as handle: handle.write(mbr)
        self.original = self.root / 'original.txt'; self.original.write_bytes(b'unchanged synthetic Windows file\n')
        subprocess.run(['mcopy', '-i', str(self.disk)+'@@16384', str(self.original), '::WIN.COM'], check=True, capture_output=True)

    def inventory(self, path):
        with path.open('rb') as handle:
            handle.seek(16384); vbr = handle.read(512); handle.seek(0); mbr = handle.read(512)
            geometry = prep.inspect_geometry(mbr, vbr, path.stat().st_size)
            return prep.inventory(handle.fileno(), geometry)

    def test_real_fat_file_hash_and_metadata_survive_unrelated_root_copy(self):
        before = self.inventory(self.disk)
        self.assertEqual(before['WIN.COM']['sha256'], hashlib.sha256(self.original.read_bytes()).hexdigest())
        new = self.root / 'new.bin'; new.write_bytes(b'new source fixture')
        subprocess.run(['mcopy', '-i', str(self.disk)+'@@16384', str(new), '::KERNEL.SYS'], check=True, capture_output=True)
        after = self.inventory(self.disk)
        self.assertEqual(before['WIN.COM'], after['WIN.COM'])
        self.assertEqual(after['KERNEL.SYS']['bytes'], 18)

    def test_fat_cycle_is_refused_instead_of_hashing_truncated_file(self):
        with self.disk.open('r+b') as handle:
            handle.seek(16384); vbr = handle.read(512)
            geometry = prep.inspect_geometry(self.disk.read_bytes()[:512], vbr, self.disk.stat().st_size)
            root_at = (32+geometry['reserved']+geometry['fats']*geometry['fat_sectors'])*512
            handle.seek(root_at); row = handle.read(32); cluster = struct.unpack_from('<H', row, 26)[0]
            offset = cluster+cluster//2
            for n in range(geometry['fats']):
                at = (32+geometry['reserved']+n*geometry['fat_sectors'])*512+offset
                handle.seek(at); pair = struct.unpack('<H', handle.read(2))[0]
                pair = ((pair&15)|(cluster<<4)) if cluster&1 else ((pair&0xf000)|cluster)
                handle.seek(at); handle.write(struct.pack('<H', pair))
        with self.assertRaises(ValueError): self.inventory(self.disk)

    def invalid_eoc_entry(self, directory):
        with self.disk.open('r+b') as handle:
            mbr = handle.read(512); handle.seek(16384); vbr = handle.read(512)
            geometry = prep.inspect_geometry(mbr, vbr, self.disk.stat().st_size)
            root_at = (geometry['start_lba']+geometry['reserved']+
                       geometry['fats']*geometry['fat_sectors'])*512
            row = bytearray(32); row[:11] = b'BADENTRY   '
            row[11] = 16 if directory else 32
            struct.pack_into('<H', row, 26, 0xff8)
            handle.seek(root_at); handle.write(row)
        with self.assertRaises(ValueError): self.inventory(self.disk)
        if not directory:
            # A legitimate empty file has no cluster chain; keep that case.
            struct.pack_into('<H', row, 26, 0)
            with self.disk.open('r+b') as handle:
                handle.seek(root_at); handle.write(row)
            self.assertEqual(self.inventory(self.disk)['BADENTRY']['bytes'], 0)

    def test_eoc_start_is_not_an_empty_directory(self):
        self.invalid_eoc_entry(True)

    def test_eoc_start_is_not_a_valid_zero_length_file(self):
        self.invalid_eoc_entry(False)


class ReplacementPrepare(ReplacementInventory):
    def setUp(self):
        super().setUp()
        self.source_root = self.root / 'build-source'; self.source_root.mkdir()
        (self.source_root / 'build.py').write_text('# synthetic build source fixture\n')
        self.kernel = self.root / 'kernel.sys'; self.kernel.write_bytes(b'synthetic source-build kernel fixture')
        self.command = self.root / 'command.com'; self.command.write_bytes(b'synthetic source-build shell fixture')
        def pin(path):
            return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        self.pin = pin
        receipt = {'profile':'dos16-freedos','upstream':{
            'freedos-kernel':{'commit':'5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3'},
            'freedos-freecom':{'commit':'04fc21a9f6792abe9048598e8f2d048b4f6cd0e5'}},
            'artifacts':{'kernel.sys':{k:v for k,v in pin(self.kernel).items() if k!='path'},
                         'command.com':{k:v for k,v in pin(self.command).items() if k!='path'}},
            'user_boot':{'sources_sha256':{'build.py':pin(self.source_root/'build.py')['sha256']}},'patches':[]}
        self.receipt = self.root / 'build-result.json'; self.receipt.write_text(json.dumps(receipt))
        self.profile = {'schema':'shizukuos.private-replacement-profile.v1','disk':pin(self.disk),
            'boot_template':{'kind':'fat12com','file':pin(UPSTREAM/'boot/fat12com.bin')},
            'freedos_source':str(UPSTREAM),'build_receipt':pin(self.receipt),
            'build_source_root':str(self.source_root),
            'payloads':[{'guest':'KERNEL.SYS','file':pin(self.kernel)},{'guest':'COMMAND.COM','file':pin(self.command)}]}
        self.profile_path = self.root / 'profile.json'

    def prepare(self, out, validate_only=False):
        self.profile_path.write_text(json.dumps(self.profile))
        with patch.object(prep, 'available_bytes', return_value=1 << 40):
            return prep.prepare(self.profile_path,self.pin(self.profile_path)['sha256'],out,'full',self.disk.stat().st_size,1<<20,validate_only=validate_only)

    def test_actual_small_private_construction_preserves_original_member_and_boot_sector(self):
        before = self.disk.read_bytes()
        out = self.root / 'owned'
        result = self.prepare(out)
        self.assertEqual(result['status'],'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED')
        self.assertFalse(result['Windows98_boot_verified']); self.assertFalse(result['public_artifact'])
        self.assertEqual(self.disk.read_bytes(),before)
        self.assertEqual((out/'original-vbr.bin').read_bytes(),before[16384:16896])
        after = self.inventory(out/'replacement.img')
        self.assertEqual(after['WIN.COM']['sha256'],hashlib.sha256(self.original.read_bytes()).hexdigest())
        self.assertEqual(after['KERNEL.SYS']['sha256'],self.pin(self.kernel)['sha256'])
        with self.assertRaises(FileExistsError): self.prepare(out)

    def gop_cohort(self):
        for name in sorted(prep.GOP_ROOT - {'KERNEL.SYS','COMMAND.COM'}):
            path = self.root/name;path.write_bytes(name.encode())
            self.profile['payloads'].append({'guest':name,'file':self.pin(path)})
        target = next(p['file'] for p in self.profile['payloads'] if p['guest']=='SHZGOP.VXD')
        for name in sorted(prep.GOP_NESTED):
            if name == 'SHZGOP/SHZGOP.VXD':pin = target
            else:
                path = self.root/('nested-'+Path(name).name)
                path.write_bytes(b'N'*32 if name.endswith('GPEPOCH.NON') else name.encode());pin = self.pin(path)
            self.profile['payloads'].append({'guest':name,'file':pin})

    def test_real_borrowed_guardian_union_keeps_original_leases_and_handler(self):
        import fcntl, signal
        tool = Path(__file__).resolve().parents[2]/'supervisor/native_win98/task_custody.py'
        definition=importlib.util.spec_from_file_location('borrowed_constructor_custody',tool)
        custody=importlib.util.module_from_spec(definition);definition.loader.exec_module(custody)
        union=custody.LeaseUnion();handler=signal.getsignal(signal.SIGIO)
        entries=prep.LeaseRegistry()
        def add(rows):
            for row in rows:entries[row['path']]={**union.add(row),'checkpoint':union.check}
        entries.add_inputs=add
        try:
            self.gop_cohort();self.profile_path.write_text(json.dumps(self.profile))
            profile_pin=self.pin(self.profile_path);add([profile_pin,self.profile['disk']]);original_fd=entries[str(self.disk)]['fd']
            with patch.object(prep,'available_bytes',return_value=1<<40):
                result=prep.prepare(self.profile_path,profile_pin['sha256'],self.root/'borrowed',
                      'full',self.disk.stat().st_size,1<<20,borrowed_inputs=entries)
            self.assertEqual(result['status'],'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED')
            self.assertEqual(entries[str(self.disk)]['fd'],original_fd)
            self.assertEqual(fcntl.fcntl(original_fd,fcntl.F_GETLEASE),fcntl.F_RDLCK)
            self.assertEqual(signal.getsignal(signal.SIGIO),handler)
            union.check();self.assertFalse(union.closed)
        finally:union.close()

    def test_real_nested_gop_clone_readback_preserves_all_original_bytes(self):
        self.gop_cohort();original = self.disk.read_bytes();out = self.root/'nested'
        result = self.prepare(out);after = self.inventory(out/'replacement.img')
        self.assertEqual(self.disk.read_bytes(),original)
        self.assertTrue(after['SHZGOP']['directory'])
        for member in self.profile['payloads']:
            self.assertEqual(after[member['guest']]['sha256'],member['file']['sha256'])
        self.assertEqual(after['WIN.COM'],self.inventory(self.disk)['WIN.COM'])
        self.assertFalse(result['VM_executed'])

    def test_real_nested_existing_nonce_backup_and_unrelated_file_preserved(self):
        self.gop_cohort();self.original.write_bytes(b'old nonce32B'+b'X'*21)
        subprocess.run(['mmd','-i',str(self.disk)+'@@16384','::SHZGOP'],check=True,capture_output=True)
        subprocess.run(['mcopy','-i',str(self.disk)+'@@16384',str(self.original),'::SHZGOP/GPEPOCH.NON'],check=True,capture_output=True)
        subprocess.run(['mcopy','-i',str(self.disk)+'@@16384',str(self.original),'::SHZGOP/KEEP.TXT'],check=True,capture_output=True)
        self.profile['disk'] = self.pin(self.disk);before = self.inventory(self.disk);out = self.root/'existing-nested'
        self.prepare(out);after = self.inventory(out/'replacement.img')
        self.assertEqual(after['SHZGOP/KEEP.TXT'],before['SHZGOP/KEEP.TXT'])
        self.assertEqual((out/'original-files/SHZGOP/GPEPOCH.NON').read_bytes(),self.original.read_bytes())
        self.assertEqual(self.pin(self.disk),self.profile['disk'])

    def test_actual_payload_tool_append_refuses_final_extent_and_prepared_receipt(self):
        out = self.root/'appended-output'; calls = []
        original = prep.run_tool
        def tool(name, args, commands, cwd=None):
            original(name, args, commands, cwd=cwd)
            if name == 'mcopy':
                target = Path(str(args[args.index('-i')+1]).split('@@',1)[0])
                with target.open('ab') as handle: handle.write(b'!')
                calls.append(target)
        with patch.object(prep, 'run_tool', tool):
            with self.assertRaisesRegex(ValueError, 'disk extent differs'):
                self.prepare(out)
        self.assertEqual(len(calls), 2)
        self.assertEqual((out/'replacement.img').stat().st_size, self.disk.stat().st_size+2)
        self.assertFalse((out/'preparation.json').exists())

    def test_source_build_artifact_and_source_drift_refused_before_output(self):
        out = self.root / 'owned'
        self.kernel.write_bytes(b'changed unreviewed kernel')
        self.profile['payloads'][0]['file'] = self.pin(self.kernel)
        with self.assertRaises(ValueError): self.prepare(out)
        self.assertFalse(out.exists())

    def test_recorded_build_source_requires_literal_nonzero_sha(self):
        out=self.root/'owned'
        original=json.loads(self.receipt.read_text())
        for field in ('source','patch'):
            for bad in (None,'0'*64,'unreviewed',[],True):
                receipt=json.loads(json.dumps(original))
                if field=='source':receipt['user_boot']['sources_sha256']['build.py']=bad
                else:receipt['patches']=[{'patch':'build.py','sha256':bad}]
                self.receipt.write_text(json.dumps(receipt))
                self.profile['build_receipt']=self.pin(self.receipt)
                with self.subTest(field=field,bad=bad):
                    with self.assertRaises(ValueError):self.prepare(out)
                    self.assertFalse(out.exists())

    def test_existing_command_backup_and_long_filename_metadata_are_retained(self):
        original=self.root/'prior-command.bin';original.write_bytes(b'private synthetic prior command')
        for name in ('COMMAND.COM','Original long Windows name.txt'):
            subprocess.run(['mcopy','-i',str(self.disk)+'@@16384',str(original),'::'+name],check=True,capture_output=True)
        self.profile['disk']=self.pin(self.disk)
        before=self.inventory(self.disk)
        out=self.root/'owned'
        self.prepare(out)
        self.assertEqual((out/'original-files/COMMAND.COM').read_bytes(),original.read_bytes())
        after=self.inventory(out/'replacement.img')
        for name,row in before.items():
            if name!='COMMAND.COM':self.assertEqual(after[name],row)

    def test_actual_build_source_writer_refused_before_owned_output(self):
        out = self.root/'owned'
        writer = os.open(self.source_root/'build.py',os.O_WRONLY|os.O_NONBLOCK)
        try:
            with self.assertRaises(OSError): self.prepare(out)
        finally: os.close(writer)
        self.assertFalse(out.exists())

    def test_lease_break_during_final_inventory_never_leaves_prepared_receipt(self):
        out=self.root/'owned'
        original=Path.write_text
        def concurrent_writer(path,*args,**kwargs):
            result=original(path,*args,**kwargs)
            if path.name=='original-inventory.json':
                try: writer=os.open(self.disk,os.O_WRONLY|os.O_NONBLOCK)
                except BlockingIOError: writer=None
                if writer is not None:
                    os.close(writer);self.fail('writer acquired read-leased disk')
            return result
        with patch.object(Path,'write_text',concurrent_writer):
            with self.assertRaises(RuntimeError):self.prepare(out)
        self.assertFalse((out/'preparation.json').exists())

    def test_validate_only_has_no_owned_disk_or_acceptance_claim(self):
        out = self.root / 'owned'
        result = self.prepare(out,validate_only=True)
        self.assertEqual(result['status'],'INPUTS_VALIDATED_REPLACEMENT_NOT_PREPARED')
        self.assertFalse(out.exists())

    def test_duplicate_payload_and_original_windows_binary_overwrite_refused(self):
        out=self.root/'owned'
        original=list(self.profile['payloads'])
        for bad in (original+[original[0]],[dict(original[0],guest='IO.SYS'),original[1]],
                    [dict(original[0],guest='WINDOWS/KERNEL.SYS'),original[1]]):
            self.profile['payloads']=bad
            with self.assertRaises(ValueError):self.prepare(out)
            self.assertFalse(out.exists())

    def test_private_outputs_cannot_be_created_in_visible_git_source(self):
        repo=self.root/'checkout';repo.mkdir()
        subprocess.run(['git','init','-q',str(repo)],check=True,capture_output=True)
        out=repo/'visible-private'
        with self.assertRaises(ValueError):self.prepare(out)
        self.assertFalse(out.exists())

    def test_git_build_output_requires_actual_ignore_rule(self):
        repo=self.root/'checkout';repo.mkdir()
        subprocess.run(['git','init','-q',str(repo)],check=True,capture_output=True)
        (repo/'build').mkdir()
        out=repo/'build/private'
        with self.assertRaises(ValueError):self.prepare(out)
        self.assertFalse(out.exists())
        (repo/'.gitignore').write_text('/build/\n')
        result=self.prepare(out)
        self.assertEqual(result['status'],'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED')


class ReplacementFat32(unittest.TestCase):
    def test_real_fat32_private_copy_installs_both_boot_sectors_and_preserves_files(self):
        fixture = ReplacementPrepare('test_validate_only_has_no_owned_disk_or_acceptance_claim')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with fixture.disk.open('wb') as handle: handle.truncate((32+81920)*512)
        subprocess.run(['mkfs.fat','-F','32','-s','1','-h','32','--offset=32',str(fixture.disk),'40960'],check=True,capture_output=True)
        mbr=bytearray(512); mbr[510:]=b'\x55\xaa';mbr[446]=0x80;mbr[450]=0x0c
        struct.pack_into('<II',mbr,454,32,81920)
        with fixture.disk.open('r+b') as handle:handle.write(mbr)
        subprocess.run(['mcopy','-i',str(fixture.disk)+'@@16384',str(fixture.original),'::WIN.COM'],check=True,capture_output=True)
        fixture.profile['disk']=fixture.pin(fixture.disk)
        fixture.profile['boot_template']={'kind':'fat32lba','file':fixture.pin(UPSTREAM/'boot/fat32lba.bin')}
        before=fixture.inventory(fixture.disk)
        out=fixture.root/'fat32-owned'
        result=fixture.prepare(out)
        self.assertEqual(result['geometry']['fat_bits'],32)
        self.assertEqual(result['status'],'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED')
        after=fixture.inventory(out/'replacement.img')
        self.assertEqual(before['WIN.COM'],after['WIN.COM'])
        with (out/'replacement.img').open('rb') as handle:
            handle.seek(16384);primary=handle.read(512)
            handle.seek((32+6)*512);backup=handle.read(512)
        self.assertEqual(primary,backup)
        self.assertEqual((out/'original-backup-vbr.bin').stat().st_size,512)


if __name__ == '__main__':
    unittest.main()
