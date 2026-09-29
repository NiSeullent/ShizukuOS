#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic immutable-base tests. No VM, installed OS, or real media access.

Only temporary files are changed. One optional qemu-img case uses a newly
created empty 2GiB virtual qcow2 and an internal snapshot. Capacity mocks keep
the same production thresholds while avoiding dependence on this host's load.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import base_archive as b
import packed as p


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Interrupted(RuntimeError):
    pass


def fail_at(name):
    def checkpoint(stage):
        if stage == name:
            raise Interrupted(stage)
    return checkpoint


class BaseArchive(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='win98-base-archive-test-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.ram = self.root/'private-ram'
        self.ram.mkdir(mode=0o700)
        self.original = self.root/'install-disk.qcow2'
        self.data = bytes(8193)+bytes(range(256))*129+b'original base tail'
        self.original.write_bytes(self.data)
        self.qcow = patch.object(b.s,'check_qcow')
        self.qcow.start()
        self.addCleanup(self.qcow.stop)
        for patcher in (patch.object(b,'RAM_ROOT',self.ram),
                        patch.object(p,'available_memory',return_value=20*p.s.GIB),
                        patch.object(p.shutil,'disk_usage',return_value=
                                     shutil._ntuple_diskusage(100*p.s.GIB,0,100*p.s.GIB))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.make_history('first')

    def make_history(self, token):
        source = self.original.parent/('current-source-'+token)
        source.write_bytes(self.data+b'newer packed generation '+token.encode())
        archive = self.original.parent/('install-packed-'+token+'.qcow2.xz')
        metadata = p.encode(source,archive)
        pointer = {'version':1,'format':'xz','codec':p.CODEC,'generation':token,
                   'archive':str(archive),'original_disk':str(self.original),
                   'original_sha256':sha(self.data),'parent_pointer_sha256':None,**metadata}
        b.s.durable_json(p.pointer_path(self.original),pointer)
        return pointer

    def record(self):
        return json.loads(b.journal_path(self.original).read_text())

    def assert_identity(self):
        self.assertEqual(b.verify(self.original,sha(self.data)),
                         {'raw_sha256':sha(self.data),'raw_bytes':len(self.data)})

    def assert_no_raw_removal(self):
        self.assertTrue(self.original.is_file())
        self.assertEqual(self.original.read_bytes(),self.data)

    def pending_raw(self):
        token = self.root.name
        directory = Path('/dev/shm')/('win98-modern-private-install-'+token)
        record = {'directory':str(directory),'working_disk':str(directory/'install-disk.qcow2'),
                  'original_disk':str(self.original),'status':'working_copy_active'}
        path = self.root/('ram-copy-'+token+'.json')
        b.s.durable_json(path,record)
        return path

    def test_create_preserves_raw_and_packed_history_then_explicit_retire_is_exact(self):
        history = p.pointer_path(self.original).read_bytes()
        old_archives = {path:path.read_bytes() for path in self.root.glob('install-packed-*.xz')}
        value = b.create(self.original)
        self.assert_no_raw_removal()
        self.assert_identity()
        self.assertEqual(value,b.create(self.original))
        self.assertEqual(self.record()['status'],'pointer_published')
        result = b.retire_raw(self.original)
        self.assertEqual(result['status'],'raw_retired')
        self.assertFalse(self.original.exists())
        self.assert_identity()
        self.assertEqual(b.retire_raw(self.original),result)
        restored = self.root/'independent-restoration'
        p.decode(value['archive'],restored,expected=value)
        self.assertEqual(restored.read_bytes(),self.data)
        self.assertEqual(p.pointer_path(self.original).read_bytes(),history)
        for path,data in old_archives.items():
            self.assertEqual(path.read_bytes(),data)
        self.assertEqual(list(self.ram.iterdir()),[])

    def test_every_durable_create_boundary_retries_without_replacing_raw(self):
        for stage in ('journal_created','archive_verified','archive_published','pointer_published'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(dir=self.root) as directory:
                original = Path(directory)/'install-disk.qcow2'
                original.write_bytes(self.data)
                source = self.original
                self.original = original
                try:
                    self.make_history('fixture')
                    with self.assertRaises(Interrupted):
                        b.create(original,fail_at(stage))
                    identity = b._raw(original)[1]
                    value = b.create(original)
                    self.assertEqual(b._raw(original)[1],identity)
                    self.assertEqual(b.verify(original),{'raw_sha256':sha(self.data),'raw_bytes':len(self.data)})
                    self.assertEqual(self.record()['status'],'pointer_published')
                    self.assertEqual(p.decode(value['archive'])['raw_sha256'],sha(self.data))
                finally:
                    self.original = source

    def test_every_durable_retirement_boundary_retries(self):
        for stage in ('retirement_started','raw_unlinked','raw_retired'):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(dir=self.root) as directory:
                original = Path(directory)/'install-disk.qcow2'
                original.write_bytes(self.data)
                source = self.original
                self.original = original
                try:
                    self.make_history('retire')
                    b.create(original)
                    with self.assertRaises(Interrupted):
                        b.retire_raw(original,fail_at(stage))
                    self.assertEqual(original.exists(),stage=='retirement_started')
                    self.assertEqual(b.retire_raw(original)['status'],'raw_retired')
                    self.assert_identity()
                finally:
                    self.original = source

    def test_retired_base_identity_survives_newer_packed_generation(self):
        b.create(self.original)
        b.retire_raw(self.original)
        prior = b.journal_path(self.original).read_bytes()
        self.make_history('later')
        self.assert_identity()
        self.assertEqual(b.retire_raw(self.original)['status'],'raw_retired')
        self.assertEqual(b.journal_path(self.original).read_bytes(),prior)

    def test_any_pointer_presence_refuses_raw_even_corrupt_or_dangling(self):
        path = b.pointer_path(self.original)
        self.assertFalse(b.has_archive(self.original))
        path.write_text('not JSON')
        self.assertTrue(b.has_archive(self.original))
        with self.assertRaises(RuntimeError):b.verify(self.original)
        with self.assertRaises(RuntimeError):b.create(self.original)
        path.unlink()
        path.symlink_to(self.root/'absent')
        self.assertTrue(b.has_archive(self.original))
        with self.assertRaises(RuntimeError):b.verify(self.original)
        self.assert_no_raw_removal()

    def test_matching_verified_packed_history_is_mandatory(self):
        path = p.pointer_path(self.original)
        before = path.read_bytes()
        for mode in ('absent','hash','path','archive'):
            with self.subTest(mode=mode):
                value = json.loads(before)
                if mode=='absent':path.unlink()
                else:
                    value[{'hash':'original_sha256','path':'original_disk','archive':'archive'}[mode]] = (
                        sha(b'foreign') if mode=='hash' else str(self.root/'foreign'))
                    path.write_text(json.dumps(value))
                with self.assertRaises(RuntimeError):b.create(self.original)
                self.assertFalse(b.journal_path(self.original).exists())
                self.assert_no_raw_removal()
                path.write_bytes(before)

    def test_corrupt_current_archive_blocks_retirement(self):
        b.create(self.original)
        value = json.loads(p.pointer_path(self.original).read_text())
        archive = Path(value['archive'])
        before = archive.read_bytes()
        archive.write_bytes(before[:-1])
        with self.assertRaises(RuntimeError):b.retire_raw(self.original)
        self.assert_no_raw_removal()
        self.assertEqual(archive.read_bytes(),before[:-1])

    def test_pending_raw_journal_blocks_retirement_before_and_after_hook(self):
        b.create(self.original)
        path = self.pending_raw()
        with self.assertRaisesRegex(RuntimeError,'Pending raw'):b.retire_raw(self.original)
        self.assert_no_raw_removal()
        path.unlink()
        def inject(stage):
            if stage=='retirement_started':self.pending_raw()
        with self.assertRaisesRegex(RuntimeError,'Pending raw'):b.retire_raw(self.original,inject)
        self.assert_no_raw_removal()

    def test_source_hardlinks_are_refused_without_deleting_any_name(self):
        alias = self.root/'alias'
        os.link(self.original,alias)
        with self.assertRaisesRegex(RuntimeError,'hardlinks'):b.create(self.original)
        self.assertEqual(alias.read_bytes(),self.data)
        alias.unlink()
        b.create(self.original)
        os.link(self.original,alias)
        with self.assertRaisesRegex(RuntimeError,'hardlinks'):b.retire_raw(self.original)
        self.assertEqual(alias.read_bytes(),self.data)
        self.assert_no_raw_removal()

    def test_archive_foreign_hardlink_is_refused(self):
        value = b.create(self.original)
        alias = self.root/'archive-alias'
        os.link(value['archive'],alias)
        with self.assertRaisesRegex(RuntimeError,'hardlinks'):b.retire_raw(self.original)
        self.assertTrue(alias.exists())
        self.assert_no_raw_removal()

    def test_same_bytes_same_path_replacement_never_authorizes_unlink(self):
        b.create(self.original)
        old = self.root/'preserved-real-original'
        def replace(stage):
            if stage=='retirement_started':
                self.original.rename(old)
                self.original.write_bytes(self.data)
        with self.assertRaisesRegex(RuntimeError,'identity or bytes changed'):
            b.retire_raw(self.original,replace)
        self.assert_no_raw_removal()
        self.assertEqual(old.read_bytes(),self.data)

    def test_source_mutation_before_publication_keeps_all_versions(self):
        changed = self.data+b'foreign update'
        def mutate(stage):
            if stage=='archive_verified':self.original.write_bytes(changed)
        with self.assertRaisesRegex(RuntimeError,'identity or bytes changed'):
            b.create(self.original,mutate)
        self.assertEqual(self.original.read_bytes(),changed)
        self.assertFalse(b.has_archive(self.original))
        self.assertTrue(list(self.root.glob('.install-base-*.part')))

    def test_same_bytes_source_replacement_before_publication_is_rejected(self):
        old = self.root/'preserved-base'
        def replace(stage):
            if stage=='archive_verified':
                self.original.rename(old)
                self.original.write_bytes(self.data)
        with self.assertRaisesRegex(RuntimeError,'identity or bytes changed'):
            b.create(self.original,replace)
        self.assert_no_raw_removal()
        self.assertEqual(old.read_bytes(),self.data)
        self.assertFalse(b.has_archive(self.original))

    def test_stale_packed_generation_during_create_or_retire_is_refused(self):
        def advance(stage):
            if stage=='archive_verified':self.make_history('newer')
        with self.assertRaisesRegex(RuntimeError,'generation changed'):
            b.create(self.original,advance)
        self.assert_no_raw_removal()
        self.assertFalse(b.has_archive(self.original))

    def test_stale_packed_generation_at_retirement_preserves_raw(self):
        b.create(self.original)
        def advance(stage):
            if stage=='retirement_started':self.make_history('newer')
        with self.assertRaisesRegex(RuntimeError,'generation changed'):
            b.retire_raw(self.original,advance)
        self.assert_no_raw_removal()

    def test_unknown_partial_is_preserved_and_refused(self):
        with self.assertRaises(Interrupted):b.create(self.original,fail_at('journal_created'))
        archive = Path(self.record()['pointer']['archive'])
        temporary = archive.with_name('.'+archive.name+'.part')
        temporary.write_bytes(b'unknown interrupted/foreign bytes')
        with self.assertRaises(RuntimeError):b.create(self.original)
        self.assertEqual(temporary.read_bytes(),b'unknown interrupted/foreign bytes')
        self.assert_no_raw_removal()
        self.assertFalse(b.has_archive(self.original))

    def test_linked_archive_crash_is_recoverable_only_for_owned_alias(self):
        with self.assertRaises(Interrupted):b.create(self.original,fail_at('archive_verified'))
        archive = Path(self.record()['pointer']['archive'])
        temporary = archive.with_name('.'+archive.name+'.part')
        os.link(temporary,archive)  # crash after link, before staging unlink
        value = b.create(self.original)
        self.assertEqual(Path(value['archive']).stat().st_nlink,1)
        self.assertFalse(temporary.exists())
        self.assert_identity()

    def test_pointer_published_before_journal_update_recovers(self):
        with self.assertRaises(Interrupted):b.create(self.original,fail_at('archive_published'))
        record = self.record()
        b._publish_json(b.pointer_path(self.original),record['pointer'])
        self.assertEqual(b.create(self.original),record['pointer'])
        self.assertEqual(self.record()['status'],'pointer_published')
        self.assert_no_raw_removal()

    def test_atomic_json_rename_interruption_keeps_one_link_and_recovers(self):
        actual = b._rename_new
        for which in ('journal','pointer'):
            with self.subTest(which=which), tempfile.TemporaryDirectory(dir=self.root) as directory:
                previous = self.original
                self.original = Path(directory)/'install-disk.qcow2'
                self.original.write_bytes(self.data)
                try:
                    self.make_history('atomic')
                    target = b.journal_path(self.original) if which=='journal' else b.pointer_path(self.original)
                    def interrupted(source,destination):
                        actual(source,destination)
                        if destination==target:
                            raise Interrupted('after actual atomic no-replace rename')
                    with patch.object(b,'_rename_new',side_effect=interrupted):
                        with self.assertRaises(Interrupted):b.create(self.original)
                    self.assertEqual(target.stat().st_nlink,1)
                    b.create(self.original)
                    self.assert_identity()
                    self.assert_no_raw_removal()
                finally:self.original = previous

    def test_foreign_pointer_or_journal_at_publication_is_never_overwritten(self):
        for target in ('pointer','journal'):
            with self.subTest(target=target), tempfile.TemporaryDirectory(dir=self.root) as directory:
                original = Path(directory)/'install-disk.qcow2'
                original.write_bytes(self.data)
                prior = self.original
                self.original = original
                try:
                    self.make_history('foreign-'+target)
                    path = b.pointer_path(original) if target=='pointer' else b.journal_path(original)
                    def replace(stage):
                        if stage=='archive_published':path.write_bytes(b'foreign metadata')
                    with self.assertRaises((RuntimeError,FileExistsError)):
                        b.create(original,replace)
                    self.assertEqual(path.read_bytes(),b'foreign metadata')
                    if target=='journal':self.assertFalse(b.has_archive(original))
                    self.assert_no_raw_removal()
                finally:self.original = prior

    def test_changed_retirement_journal_never_authorizes_raw_removal(self):
        b.create(self.original)
        journal = b.journal_path(self.original)
        def replace(stage):
            if stage=='retirement_started':journal.write_bytes(b'foreign retirement record')
        with self.assertRaisesRegex(RuntimeError,'record'):
            b.retire_raw(self.original,replace)
        self.assertEqual(journal.read_bytes(),b'foreign retirement record')
        self.assert_no_raw_removal()

    def test_restore_cleanup_retains_unexpected_children(self):
        def validator(path):
            path = Path(path)
            if path.parent.parent==self.ram:
                (path.parent/'foreign-child').write_bytes(b'preserve unexpected content')
        with patch.object(b.s,'check_qcow',side_effect=validator):
            with self.assertRaises(OSError):b.create(self.original)
        children = list(self.ram.glob('*/foreign-child'))
        self.assertEqual(len(children),1)
        self.assertEqual(children[0].read_bytes(),b'preserve unexpected content')
        self.assert_no_raw_removal()

    def test_archive_corruption_truncation_and_trailing_bytes_fail_closed(self):
        value = b.create(self.original)
        archive = Path(value['archive'])
        before = archive.read_bytes()
        for corrupt in (before[:-1],before+b'x',before[:20]+bytes((before[20]^1,))+before[21:]):
            with self.subTest(length=len(corrupt)):
                archive.write_bytes(corrupt)
                with self.assertRaises(RuntimeError):b.verify(self.original)
                with self.assertRaises(RuntimeError):b.retire_raw(self.original)
                self.assertEqual(archive.read_bytes(),corrupt)
                self.assert_no_raw_removal()
                archive.write_bytes(before)

    def test_wrong_expected_base_hash_and_current_raw_change_are_rejected(self):
        b.create(self.original)
        with self.assertRaisesRegex(RuntimeError,'expected original'):b.verify(self.original,sha(b'other'))
        self.original.write_bytes(self.data+b'new write')
        with self.assertRaisesRegex(RuntimeError,'Present original'):b.verify(self.original)
        self.assertTrue(self.original.exists())

    def test_symlinked_archive_source_or_parent_is_rejected(self):
        value = b.create(self.original)
        archive = Path(value['archive'])
        before = archive.read_bytes()
        foreign = self.root/'foreign-archive'
        archive.rename(foreign)
        archive.symlink_to(foreign)
        with self.assertRaisesRegex(RuntimeError,'Symlinked'):b.verify(self.original)
        self.assertEqual(foreign.read_bytes(),before)
        alias = self.root/'alias-parent'
        alias.symlink_to(self.root,target_is_directory=True)
        with self.assertRaisesRegex(RuntimeError,'symlinked'):b.create(alias/'install-disk.qcow2')
        self.assert_no_raw_removal()

    def test_oversized_raw_and_archive_are_refused_without_allocation(self):
        with patch.object(p,'RAW_CAP',len(self.data)-1):
            with self.assertRaisesRegex(RuntimeError,'bounded'):b.create(self.original)
        value = b.create(self.original)
        with patch.object(p,'ARCHIVE_CAP',Path(value['archive']).stat().st_size-1):
            with self.assertRaises(RuntimeError):b.verify(self.original)
        self.assert_no_raw_removal()

    def test_initial_and_exact_candidate_disk_headroom_boundaries(self):
        metadata = p.encode(self.original)
        minimum = p.ROOT_RESERVE+p.WRITE_MARGIN
        for free in (minimum-1,minimum+p.allocation_bound(metadata['archive_bytes'])-1):
            with self.subTest(free=free), patch.object(p.shutil,'disk_usage',return_value=
                    shutil._ntuple_diskusage(100*p.s.GIB,0,free)):
                with self.assertRaises(RuntimeError):b.create(self.original)
                self.assert_no_raw_removal()
                self.assertFalse(b.has_archive(self.original))
        with patch.object(p.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(
                100*p.s.GIB,0,minimum+p.allocation_bound(metadata['archive_bytes']))):
            b.create(self.original)
        self.assert_identity()

    def test_ram_and_codec_reserves_are_not_reduced(self):
        required = 6*p.s.GIB+p.s.GUEST_ALLOWANCE+p.RAW_CAP+p.CODEC_ALLOWANCE
        with patch.object(p,'available_memory',return_value=required-1):
            with self.assertRaisesRegex(RuntimeError,'RAM reserve'):b.create(self.original)
        self.assertFalse(b.journal_path(self.original).exists())
        b.create(self.original)
        with patch.object(p,'available_memory',return_value=6*p.s.GIB+p.CODEC_ALLOWANCE-1):
            with self.assertRaisesRegex(RuntimeError,'RAM reserve'):b.retire_raw(self.original)
        self.assert_no_raw_removal()

    def test_source_race_during_capture_is_detected(self):
        with self.assertRaisesRegex(RuntimeError,'identity changed'):
            with b._input(self.original,p.RAW_CAP) as (stream,_):
                self.assertEqual(stream.read(),self.data)
                self.original.rename(self.root/'original-retained')
                self.original.write_bytes(self.data)
        self.assert_no_raw_removal()

    def test_duplicate_or_foreign_metadata_never_falls_back(self):
        value = b.create(self.original)
        path = b.pointer_path(self.original)
        before = path.read_bytes()
        path.write_bytes(before.rstrip()[:-1]+b',"version":1}')
        self.assertTrue(b.has_archive(self.original))
        with self.assertRaisesRegex(RuntimeError,'Duplicate'):b.verify(self.original)
        path.write_bytes(before)
        value['archive'] = str(self.root/'outside-generation')
        path.write_text(json.dumps(value))
        with self.assertRaisesRegex(RuntimeError,'Foreign or malformed'):b.retire_raw(self.original)
        self.assert_no_raw_removal()

    def test_reappearing_raw_after_retirement_is_preserved_and_refused(self):
        b.create(self.original)
        b.retire_raw(self.original)
        self.original.write_bytes(self.data)
        with self.assertRaisesRegex(RuntimeError,'reappeared'):b.retire_raw(self.original)
        self.assert_no_raw_removal()

    @unittest.skipUnless(shutil.which('qemu-img'),'qemu-img unavailable; no installation attempted')
    def test_empty_qcow2_internal_snapshot_roundtrips_byte_exactly(self):
        self.qcow.stop()
        self.original.unlink()
        subprocess.run(['qemu-img','create','-q','-f','qcow2',str(self.original),'2G'],check=True,
                       capture_output=True,timeout=30)
        subprocess.run(['qemu-img','snapshot','-c','synthetic-base-snapshot',str(self.original)],check=True,
                       capture_output=True,timeout=30)
        self.data = self.original.read_bytes()
        self.make_history('qcow')
        value = b.create(self.original)
        b.retire_raw(self.original)
        restored = self.root/'restored-real.qcow2'
        p.decode(value['archive'],restored,expected=value)
        self.assertEqual(restored.read_bytes(),self.data)
        result = json.loads(subprocess.check_output(['qemu-img','info','--output=json',str(restored)],
                                                    text=True,timeout=30))
        self.assertEqual([item['name'] for item in result['snapshots']],['synthetic-base-snapshot'])
        b.s.check_qcow(restored)


if __name__ == '__main__':
    unittest.main()
