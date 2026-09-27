#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Independent synthetic tests for private compressed VM checkpoints.

No VM, installed OS, production checkpoint or external media is opened. One
test creates a sparse empty qcow2 and an internal snapshot with qemu-img; all
other cases use tiny byte fixtures and mock only host capacity/qcow validation.
"""
import copy
from contextlib import contextmanager
import hashlib
import json
import lzma
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import packed as p


def sha(data):
    return hashlib.sha256(data).hexdigest()


class SimulatedCrash(RuntimeError):
    pass


def fail_at(wanted):
    def checkpoint(stage):
        if stage == wanted:
            raise SimulatedCrash('interrupted at '+stage)
    return checkpoint


class TemporaryCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='win98-packed-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        space = patch.object(p.shutil, 'disk_usage', return_value=
            shutil._ntuple_diskusage(100*p.s.GIB, 0, 100*p.s.GIB))
        space.start()
        self.addCleanup(space.stop)
        memory = patch.object(p, 'available_memory', return_value=20*p.s.GIB)
        memory.start()
        self.addCleanup(memory.stop)
        # Only remove private allocations whose durable journal belongs to this
        # test's TemporaryDirectory; never enumerate other lab working copies.
        self.addCleanup(self.clean_ram)

    def clean_ram(self):
        for path in self.root.rglob('packed-copy-*.json'):
            record = json.loads(path.read_text())
            directory = Path(record['directory'])
            if (directory.parent == Path('/dev/shm') and
                directory.name.startswith('win98-modern-private-packed-') and
                not directory.is_symlink()):
                shutil.rmtree(directory, ignore_errors=True)

    def write(self, name, data):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def free_space(self, free):
        return patch.object(p.shutil, 'disk_usage', return_value=
            shutil._ntuple_diskusage(100*p.s.GIB, 0, free))


class Codecs(TemporaryCase):
    def setUp(self):
        super().setUp()
        self.raw_bytes = bytes(65537)+bytes(range(256))*73+bytes(4097)+b'last byte\xff'
        self.raw = self.write('source.qcow2', self.raw_bytes)
        self.archive = self.root/'checkpoint.xz'

    def assert_preserved(self):
        self.assertEqual(self.raw.read_bytes(), self.raw_bytes)

    def test_measure_encode_decode_preserves_exact_bytes_hashes_and_private_mode(self):
        measured = p.encode(self.raw)
        self.assertFalse(self.archive.exists())
        encoded = p.encode(self.raw, self.archive)
        self.assertEqual(encoded, measured)
        self.assertEqual(encoded['raw_sha256'], sha(self.raw_bytes))
        self.assertEqual(encoded['raw_bytes'], len(self.raw_bytes))
        self.assertEqual(encoded['archive_sha256'], sha(self.archive.read_bytes()))
        self.assertEqual(encoded['archive_bytes'], self.archive.stat().st_size)
        self.assertEqual(self.archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(lzma.decompress(self.archive.read_bytes()), self.raw_bytes)
        self.assertEqual(p.decode(self.archive, expected=encoded), encoded)
        output = self.root/'restored.qcow2'
        self.assertEqual(p.decode(self.archive, output, expected=encoded), encoded)
        self.assertEqual(output.read_bytes(), self.raw_bytes)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assert_preserved()

    def test_existing_destinations_survive_encode_and_decode(self):
        metadata = p.encode(self.raw, self.archive)
        output = self.write('foreign.qcow2', b'foreign destination')
        for operation in (lambda:p.encode(self.raw, output),
                          lambda:p.decode(self.archive, output, expected=metadata)):
            with self.assertRaises((FileExistsError,RuntimeError)):
                operation()
            self.assertEqual(output.read_bytes(), b'foreign destination')
        self.assert_preserved()

    def test_corruption_truncation_concatenation_and_trailing_bytes_are_rejected(self):
        p.encode(self.raw, self.archive)
        data = self.archive.read_bytes()
        corrupt = bytearray(data)
        corrupt[len(corrupt)//2] ^= 0x40
        variants = [b'', data[:1], data[:12], data[:-1], data[:-12], bytes(corrupt),
                    data+b'trailing', data+data, data+lzma.compress(b''), data+bytes(4)]
        output = self.root/'failed.qcow2'
        for index, bad in enumerate(variants):
            source = self.write('corrupt.xz', bad)
            with self.subTest(index=index), self.assertRaises((RuntimeError,lzma.LZMAError)):
                p.decode(source, output)
            self.assertFalse(output.exists())
            self.assertEqual(source.read_bytes(), bad)
        self.assert_preserved()

    def test_metadata_mismatches_never_leave_a_restored_output(self):
        metadata = p.encode(self.raw, self.archive)
        archive_bytes = self.archive.read_bytes()
        output = self.root/'failed.qcow2'
        for key,value in (('raw_sha256',sha(b'other')),('archive_sha256',sha(b'other')),
                          ('raw_bytes',len(self.raw_bytes)-1),('archive_bytes',1)):
            wrong = {**metadata,key:value}
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                p.decode(self.archive, output, expected=wrong)
            self.assertFalse(output.exists())
            self.assertEqual(self.archive.read_bytes(),archive_bytes)
        self.assert_preserved()

    def test_raw_expansion_and_archive_caps_have_exact_boundaries(self):
        with patch.object(p,'RAW_CAP',len(self.raw_bytes)):
            metadata = p.encode(self.raw,self.archive)
            self.assertEqual(p.decode(self.archive),metadata)
        with patch.object(p,'RAW_CAP',len(self.raw_bytes)-1):
            with self.assertRaises(RuntimeError):p.encode(self.raw,self.root/'too-large.xz')
            with self.assertRaises(RuntimeError):p.decode(self.archive,self.root/'too-large.raw')
        self.assertFalse((self.root/'too-large.xz').exists())
        self.assertFalse((self.root/'too-large.raw').exists())
        with patch.object(p,'ARCHIVE_CAP',metadata['archive_bytes']):
            self.assertEqual(p.decode(self.archive),metadata)
        with patch.object(p,'ARCHIVE_CAP',metadata['archive_bytes']-1):
            with self.assertRaises(RuntimeError):p.decode(self.archive,self.root/'archive-cap.raw')
            with self.assertRaises(RuntimeError):p.encode(self.raw,self.root/'archive-cap.xz')
        self.assertFalse((self.root/'archive-cap.raw').exists())
        self.assertFalse((self.root/'archive-cap.xz').exists())
        self.assert_preserved()

    def test_decoder_memory_limit_rejects_large_dictionary_with_tiny_output(self):
        data = lzma.compress(b'tiny data',format=lzma.FORMAT_XZ,check=lzma.CHECK_CRC64,
            filters=[{'id':lzma.FILTER_LZMA2,'dict_size':8*1024*1024}])
        source = self.write('large-dictionary.xz',data)
        with patch.object(p,'DECODER_MEMORY',1024*1024):
            with self.assertRaises((RuntimeError,lzma.LZMAError)):
                p.decode(source,self.root/'limited.raw')
        self.assertFalse((self.root/'limited.raw').exists())
        self.assertEqual(source.read_bytes(),data)

    def test_only_nonempty_crc64_xz_is_accepted(self):
        variants = [lzma.compress(b'raw',check=lzma.CHECK_NONE),
                    lzma.compress(b'raw',check=lzma.CHECK_CRC32),
                    lzma.compress(b'raw',format=lzma.FORMAT_ALONE),
                    lzma.compress(b''), b'uncompressed data']
        for index,data in enumerate(variants):
            path = self.write('unsupported-codec.xz',data)
            output = self.root/'unsupported.raw'
            with self.subTest(index=index),self.assertRaises(RuntimeError):p.decode(path,output)
            self.assertFalse(output.exists())
            self.assertEqual(path.read_bytes(),data)
        empty = self.write('empty.raw',b'')
        with self.assertRaises(RuntimeError):p.encode(empty,self.root/'empty.xz')
        self.assertFalse((self.root/'empty.xz').exists())

    def test_high_ratio_decompression_drains_bounded_chunks_and_stops_at_cap(self):
        for length in (16384,16385):
            source = self.write('high-ratio.xz',lzma.compress(bytes(length)))
            output = self.root/'expanded.raw'
            with patch.object(p,'CHUNK',4096),patch.object(p,'RAW_CAP',16384):
                if length == 16384:
                    result = p.decode(source,output)
                    self.assertEqual(result['raw_bytes'],16384)
                    self.assertEqual(output.read_bytes(),bytes(16384))
                    output.unlink()
                else:
                    with self.assertRaises(RuntimeError):p.decode(source,output)
                    self.assertFalse(output.exists())

    def test_encode_reserve_failure_preserves_source_and_removes_only_own_partial(self):
        with self.free_space(9):
            with self.assertRaises(RuntimeError):p.encode(self.raw,self.archive,reserve=10)
        self.assertFalse(self.archive.exists())
        self.assert_preserved()

    def test_source_growth_is_rejected_during_encode(self):
        # Grow after the initial extent check, leaving the
        # streaming bound to reject bytes absent from the original stat result.
        original_input = p._input
        @contextmanager
        def grow(path,cap):
            with original_input(path,cap) as stream:
                if Path(path) == self.raw:
                    with self.raw.open('ab') as out:out.write(b'growth')
                yield stream
        with patch.object(p,'RAW_CAP',len(self.raw_bytes)),patch.object(p,'_input',grow):
            with self.assertRaises(RuntimeError):p.encode(self.raw,self.archive)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.raw.read_bytes(),self.raw_bytes+b'growth')

    def test_input_mutation_during_compression_cannot_publish_a_mixed_checkpoint(self):
        actual_write = p._Output.write
        replacement = b'changed original byte content'
        changed = False
        def mutate_source(output,data):
            nonlocal changed
            actual_write(output,data)
            if not changed:
                changed = True
                self.raw.write_bytes(replacement)
        with patch.object(p._Output,'write',mutate_source):
            with self.assertRaises(RuntimeError):p.encode(self.raw,self.archive)
        self.assertTrue(changed)
        self.assertFalse(self.archive.exists())
        self.assertEqual(self.raw.read_bytes(),replacement)

    def test_failed_output_fsync_removes_partial_and_keeps_source(self):
        with patch.object(p.os,'fsync',side_effect=OSError('synthetic fsync failure')):
            with self.assertRaises(OSError):p.encode(self.raw,self.archive)
        self.assertFalse(self.archive.exists())
        self.assert_preserved()


class Transactions(TemporaryCase):
    def setUp(self):
        super().setUp()
        qcow = patch.object(p.s, 'check_qcow')
        qcow.start()
        self.addCleanup(qcow.stop)
        self.old = b'original fixture\0'*333
        self.new = bytes(range(256))*177+bytes(65536)+b'new final byte\xff'
        self.original = self.write('install-disk.qcow2', self.old)

    def prepare(self, original=None):
        return p.prepare(original or self.original)

    def working(self, record):
        return Path(record['working_disk'])

    def generation(self, data, original=None):
        record = self.prepare(original)
        self.working(record).write_bytes(data)
        return p.persist(record)

    def test_initial_publish_preserves_raw_source_and_verifies_current_archive(self):
        record = self.prepare()
        self.assertEqual(self.working(record).read_bytes(), self.old)
        self.assertEqual(Path(record['directory']).stat().st_mode & 0o777, 0o700)
        self.assertFalse(p.has_checkpoint(self.original))
        self.working(record).write_bytes(self.new)
        final = p.persist(record)
        self.assertEqual(final['status'],'persisted')
        self.assertEqual(self.original.read_bytes(),self.old)
        self.assertFalse(Path(record['directory']).exists())
        self.assertTrue(p.has_checkpoint(self.original))
        pointer = p.current(self.original)
        self.assertEqual(pointer['raw_sha256'],sha(self.new))
        self.assertEqual(pointer['raw_bytes'],len(self.new))
        self.assertEqual(lzma.decompress(Path(pointer['archive']).read_bytes()),self.new)
        self.assertEqual(p.pending_journals(self.root),[])

    def test_next_prepare_uses_current_compressed_generation_and_retains_history(self):
        first = self.generation(self.new)
        old_pointer = p.pointer_path(self.original).read_bytes()
        first_archive = Path(p.current(self.original)['archive'])
        archive_bytes = first_archive.read_bytes()
        record = self.prepare()
        self.assertEqual(self.working(record).read_bytes(),self.new)
        self.assertEqual(record['source_pointer_sha256'],sha(old_pointer))
        self.working(record).write_bytes(b'next generation')
        p.persist(record)
        self.assertEqual(first_archive.read_bytes(),archive_bytes)
        self.assertEqual(self.original.read_bytes(),self.old)
        self.assertEqual(p.current(self.original)['raw_sha256'],sha(b'next generation'))
        self.assertNotEqual(p.pointer_path(self.original).read_bytes(),old_pointer)
        # A completed stale transaction cannot roll the current pointer back.
        latest = p.pointer_path(self.original).read_bytes()
        with self.assertRaises(RuntimeError):p.persist(first)
        self.assertEqual(p.pointer_path(self.original).read_bytes(),latest)

    def test_initial_and_growth_headroom_are_measured_before_publication(self):
        required = p.ROOT_RESERVE+p.WRITE_MARGIN+p.allocation_bound(p.encode(self.original)['archive_bytes'])
        with self.free_space(required-1),patch.object(p.tempfile,'mkdtemp') as allocate:
            with self.assertRaises(RuntimeError):self.prepare()
        allocate.assert_not_called()
        self.assertEqual(list(self.root.glob('packed-copy-*.json')),[])
        with self.free_space(required):
            record = self.prepare()
        # A deterministic incompressible fixture makes growth require another
        # block, independently of the tiny initial compressed allocation.
        grown = b''.join(hashlib.sha256(str(index).encode()).digest() for index in range(4000))
        self.working(record).write_bytes(grown)
        needed = p.ROOT_RESERVE+p.WRITE_MARGIN+p.allocation_bound(p.encode(self.working(record))['archive_bytes'])
        self.assertGreater(needed,required)
        with self.free_space(needed-1):
            with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        self.assertFalse(p.pointer_path(self.original).exists())
        self.assertEqual(self.working(record).read_bytes(),grown)
        self.assertEqual(self.original.read_bytes(),self.old)
        with self.free_space(needed):p.persist(copy.deepcopy(record))
        self.assertEqual(p.current(self.original)['raw_sha256'],sha(grown))

    def test_every_publication_boundary_recovers_from_preoperation_record(self):
        stages = ('persistence_started','archive_verified','archive_published',
                  'pointer_published','persisted_journal','ram_unlinked','ram_removed')
        for stage in stages:
            with self.subTest(stage=stage):
                original = self.write(stage+'/install-disk.qcow2',self.old)
                initial = self.prepare(original)
                self.working(initial).write_bytes(self.new)
                with self.assertRaises(SimulatedCrash):
                    p.persist(copy.deepcopy(initial),fail_at(stage))
                if stage in ('persistence_started','archive_verified','archive_published'):
                    self.assertFalse(p.pointer_path(original).exists())
                else:
                    self.assertEqual(p.current(original)['raw_sha256'],sha(self.new))
                result = p.persist(copy.deepcopy(initial))
                again = p.persist(copy.deepcopy(initial))
                self.assertEqual(result['status'],'persisted')
                self.assertEqual(again['status'],'persisted')
                self.assertEqual(original.read_bytes(),self.old)
                self.assertEqual(p.current(original)['raw_sha256'],sha(self.new))
                self.assertFalse(Path(initial['directory']).exists())
                self.assertEqual(p.pending_journals(original.parent),[])

    def test_pointer_replacement_is_atomic_after_complete_archive_validation(self):
        self.generation(self.old)
        pointer = p.pointer_path(self.original)
        old_pointer = pointer.read_bytes()
        record = self.prepare()
        self.working(record).write_bytes(self.new)
        original_replace = os.replace
        seen = []
        def interrupt_pointer_replace(source,destination):
            if Path(destination) == pointer:
                self.assertEqual(pointer.read_bytes(),old_pointer)
                candidate = json.loads(Path(source).read_text())
                self.assertEqual(lzma.decompress(Path(candidate['archive']).read_bytes()),self.new)
                self.assertEqual(candidate['raw_sha256'],sha(self.new))
                seen.append(candidate)
                raise SimulatedCrash('before pointer atomic replace')
            return original_replace(source,destination)
        with patch.object(p.s.os,'replace',side_effect=interrupt_pointer_replace):
            with self.assertRaises(SimulatedCrash):p.persist(copy.deepcopy(record))
        self.assertEqual(len(seen),1)
        self.assertEqual(pointer.read_bytes(),old_pointer)
        self.assertEqual(self.working(record).read_bytes(),self.new)
        p.persist(copy.deepcopy(record))
        self.assertEqual(json.loads(pointer.read_text()),seen[0])
        self.assertEqual(self.original.read_bytes(),self.old)

    def test_prepare_interruption_is_discoverable_and_missing_working_copy_recovers(self):
        with self.assertRaises(SimulatedCrash):self.prepare_checkpoint('prepared_journal')
        journals = p.pending_journals(self.root)
        self.assertEqual(len(journals),1)
        record = json.loads(journals[0].read_text())
        self.assertFalse(self.working(record).exists())
        p.persist(record)
        self.assertEqual(p.current(self.original)['raw_sha256'],sha(self.old))
        self.assertEqual(self.original.read_bytes(),self.old)

    def test_missing_empty_ram_directory_is_recreated_only_from_its_durable_journal(self):
        with self.assertRaises(SimulatedCrash):self.prepare_checkpoint('prepared_journal')
        record = json.loads(p.pending_journals(self.root)[0].read_text())
        Path(record['directory']).rmdir()
        p.persist(copy.deepcopy(record))
        self.assertEqual(p.current(self.original)['raw_sha256'],sha(self.old))
        self.assertEqual(self.original.read_bytes(),self.old)
        self.assertFalse(Path(record['directory']).exists())

    def prepare_checkpoint(self, stage):
        return p.prepare(self.original,fail_at(stage))

    def test_partial_prepare_is_never_overwritten_or_published(self):
        with self.assertRaises(SimulatedCrash):self.prepare_checkpoint('prepared_journal')
        record = json.loads(p.pending_journals(self.root)[0].read_text())
        self.working(record).write_bytes(b'partial or foreign working file')
        with self.assertRaises(RuntimeError):p.persist(record)
        self.assertEqual(self.working(record).read_bytes(),b'partial or foreign working file')
        self.assertEqual(self.original.read_bytes(),self.old)
        self.assertFalse(p.pointer_path(self.original).exists())

    def test_working_copy_active_prepare_crash_recovers_from_its_journal(self):
        with self.assertRaises(SimulatedCrash):self.prepare_checkpoint('working_copy_active')
        journals = p.pending_journals(self.root)
        self.assertEqual(len(journals),1)
        record = json.loads(journals[0].read_text())
        self.assertEqual(record['status'],'working_copy_active')
        self.assertEqual(self.working(record).read_bytes(),self.old)
        p.persist(copy.deepcopy(record))
        self.assertEqual(p.current(self.original)['raw_sha256'],sha(self.old))

    def test_changed_working_after_candidate_freeze_is_retained_and_not_published(self):
        record = self.prepare()
        self.working(record).write_bytes(self.new)
        with self.assertRaises(SimulatedCrash):
            p.persist(copy.deepcopy(record),fail_at('archive_verified'))
        self.working(record).write_bytes(b'changed after compressed candidate')
        with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        self.assertFalse(p.pointer_path(self.original).exists())
        self.assertEqual(self.working(record).read_bytes(),b'changed after compressed candidate')
        self.assertEqual(self.original.read_bytes(),self.old)

    def test_foreign_archive_and_journal_never_overwrite_outputs(self):
        record = self.prepare()
        self.working(record).write_bytes(self.new)
        working,original,directory,journal,temporary,archive = p.locations(record)
        archive.write_bytes(b'foreign immutable generation')
        with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        self.assertEqual(archive.read_bytes(),b'foreign immutable generation')
        self.assertEqual(working.read_bytes(),self.new)
        self.assertEqual(original.read_bytes(),self.old)
        self.assertFalse(p.pointer_path(original).exists())
        saved = json.loads(journal.read_text())
        saved['original_sha256'] = sha(b'foreign original')
        journal.write_text(json.dumps(saved))
        with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        self.assertEqual(archive.read_bytes(),b'foreign immutable generation')

    def test_unverified_preexisting_temporary_is_retained_on_refusal(self):
        record = self.prepare()
        self.working(record).write_bytes(self.new)
        temporary = p.locations(record)[4]
        temporary.write_bytes(b'partial or foreign archive temporary')
        with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        self.assertEqual(temporary.read_bytes(),b'partial or foreign archive temporary')
        self.assertEqual(self.working(record).read_bytes(),self.new)
        self.assertEqual(self.original.read_bytes(),self.old)
        self.assertFalse(p.pointer_path(self.original).exists())

    def test_original_changed_during_active_copy_is_not_silently_replaced(self):
        record = self.prepare()
        self.original.write_bytes(b'changed outside checkpoint')
        with self.assertRaises(RuntimeError):p.persist(record)
        self.assertEqual(self.original.read_bytes(),b'changed outside checkpoint')
        self.assertEqual(self.working(record).read_bytes(),self.old)
        self.assertFalse(p.pointer_path(self.original).exists())

    def test_corrupt_current_archive_and_foreign_pointer_are_rejected(self):
        self.generation(self.new)
        pointer_path = p.pointer_path(self.original)
        pointer_bytes = pointer_path.read_bytes()
        pointer = json.loads(pointer_bytes)
        archive = Path(pointer['archive'])
        original_archive = archive.read_bytes()
        archive.write_bytes(original_archive[:-1])
        with self.assertRaises(RuntimeError):p.current(self.original)
        with self.assertRaises(RuntimeError):self.prepare()
        self.assertEqual(pointer_path.read_bytes(),pointer_bytes)
        archive.write_bytes(original_archive)
        for key,value in (('original_disk',str(self.root/'foreign.qcow2')),
                          ('generation','foreign'),('archive',str(self.root/'foreign.xz'))):
            with self.subTest(key=key):
                pointer_path.write_text(json.dumps({**pointer,key:value}))
                with self.assertRaises(RuntimeError):p.current(self.original)
                self.assertEqual(archive.read_bytes(),original_archive)
        pointer_path.write_bytes(pointer_bytes)

    def test_symlink_archive_and_ram_ownership_are_rejected(self):
        record = self.prepare()
        working,original,directory,journal,temporary,archive = p.locations(record)
        foreign = self.write('foreign.xz',b'preserve me')
        archive.symlink_to(foreign)
        with self.assertRaises((RuntimeError,OSError)):p.persist(copy.deepcopy(record))
        self.assertEqual(foreign.read_bytes(),b'preserve me')
        archive.unlink()
        directory.chmod(0o755)
        with self.assertRaises(RuntimeError):p.persist(copy.deepcopy(record))
        directory.chmod(0o700)
        self.assertEqual(working.read_bytes(),self.old)


class Headroom(unittest.TestCase):
    def test_rounded_allocation_bounds(self):
        for size,expected in ((0,0),(1,4096),(4096,4096),(4097,8192)):
            self.assertEqual(p.allocation_bound(size),expected)

    def test_full_memory_disk_tmpfs_reserves_at_exact_boundary_and_one_byte_short(self):
        ram = 6*p.s.GIB+p.s.GUEST_ALLOWANCE+p.RAW_CAP+p.CODEC_ALLOWANCE
        root = p.ROOT_RESERVE+p.WRITE_MARGIN
        p.check_headroom(ram,root,p.RAW_CAP)
        for values in ((ram-1,root,p.RAW_CAP),(ram,root-1,p.RAW_CAP),(ram,root,p.RAW_CAP-1)):
            with self.subTest(values=values),self.assertRaises(RuntimeError):p.check_headroom(*values)


class RealQcow(TemporaryCase):
    @unittest.skipUnless(shutil.which('qemu-img'),'qemu-img is required for the tiny snapshot fixture')
    def test_empty_qcow_internal_snapshot_survives_exact_packed_roundtrip(self):
        original = self.root/'install-disk.qcow2'
        def qemu(*arguments):
            return subprocess.run(['qemu-img',*arguments],check=True,capture_output=True,text=True,timeout=30)
        qemu('create','-f','qcow2',str(original),str(p.s.DISK_CAP))
        qemu('snapshot','-c','synthetic-internal-checkpoint',str(original))
        before = original.read_bytes()
        self.assertLess(len(before),2*1024*1024)
        info = json.loads(qemu('info','--output=json',str(original)).stdout)
        self.assertEqual([item['name'] for item in info['snapshots']],['synthetic-internal-checkpoint'])
        record = p.prepare(original)
        self.assertEqual(Path(record['working_disk']).read_bytes(),before)
        p.persist(record)
        self.assertEqual(original.read_bytes(),before)
        restored = p.prepare(original)
        working = Path(restored['working_disk'])
        self.assertEqual(working.read_bytes(),before)
        restored_info = json.loads(qemu('info','--output=json',str(working)).stdout)
        self.assertEqual(restored_info['snapshots'],info['snapshots'])
        qemu('check','-q',str(working))
        p.persist(restored)


if __name__ == '__main__':
    unittest.main()
