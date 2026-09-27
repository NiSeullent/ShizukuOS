#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic disposable QA tests: no VM, private checkpoint or OS media access."""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import trial as t


def sha(data):return hashlib.sha256(data).hexdigest()


class Crash(RuntimeError):pass


def fail_at(wanted):
    def checkpoint(stage):
        if stage==wanted:raise Crash(stage)
    return checkpoint


class Trial(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory(prefix='win98-trial-test-',dir='/dev/shm')
        self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.ram=self.root/'ram';self.ram.mkdir()
        self.disk=self.root/'install-disk.qcow2';self.disk.write_bytes(b'preserved base\0'*101)
        self.source=self.root/'baseline-source';self.data=b'checkpoint bytes\0'*1024+bytes(range(256))
        self.source.write_bytes(self.data)
        self.archive=self.root/'install-packed-fixture.qcow2.xz'
        metadata=t.p.encode(self.source,self.archive)
        pointer={'version':1,'format':'xz','codec':t.p.CODEC,'generation':'fixture',
                 'archive':str(self.archive),'original_disk':str(self.disk),
                 'original_sha256':sha(self.disk.read_bytes()),'parent_pointer_sha256':None,**metadata}
        self.pointer=t.p.pointer_path(self.disk);self.pointer.write_text(json.dumps(pointer)+'\n')
        self.pointer_bytes=self.pointer.read_bytes();self.pointer_sha=sha(self.pointer_bytes)
        self.archive_bytes=self.archive.read_bytes();self.original_bytes=self.disk.read_bytes()
        for mock in (patch.object(t,'RAM_ROOT',self.ram),
                     patch.object(t.p,'available_memory',return_value=20*t.s.GIB),
                     patch.object(t.p.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100*t.s.GIB,0,100*t.s.GIB)),
                     patch.object(t.s,'check_qcow')):
            mock.start();self.addCleanup(mock.stop)
        self.guard_calls=0

    def guard(self,record):
        self.guard_calls+=1
        self.assertEqual(record['mode'],'qa-trial')

    def prepare(self,checkpoint=lambda stage:None):
        return t.prepare(self.disk,self.pointer_sha,checkpoint)

    def files(self):
        log=self.root/'collected.log';log.write_bytes(b'PASS\r\nEXIT=0\r\n')
        image=self.root/'screen.bin';image.write_bytes(bytes(range(256))*4)
        return {'log.txt':log,'screen.bin':image}

    def stopped(self):
        record=self.prepare();working=t.locations(record)[0]
        working.write_bytes(self.data+b' guest change')
        return t.record_stopped(record,guard=self.guard)

    def sealed(self):
        return t.seal(self.stopped(),self.files(),guard=self.guard)

    def journal(self):
        paths=list(self.root.glob('qa-trial-*.json'));self.assertEqual(len(paths),1)
        return paths[0]

    def unchanged(self):
        self.assertEqual(self.pointer.read_bytes(),self.pointer_bytes)
        self.assertEqual(self.archive.read_bytes(),self.archive_bytes)
        self.assertEqual(self.disk.read_bytes(),self.original_bytes)

    def rejected(self,call):
        with self.assertRaises((RuntimeError,OSError,ValueError,TypeError)):call()

    def space(self,free):
        return patch.object(t.p.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100*t.s.GIB,0,free))

    def test_complete_lifecycle_exact_bytes_no_encode_no_pointer_write(self):
        with patch.object(t.p,'encode',side_effect=AssertionError('trial must not encode')):
            record=self.prepare();working,_,ram,journal,evidence=t.locations(record)
            self.assertEqual(working.read_bytes(),self.data)
            self.assertEqual(working.stat().st_mode&0o777,0o600)
            self.assertEqual(ram.stat().st_mode&0o777,0o700)
            working.write_bytes(self.data+b'new guest bytes')
            t.record_stopped(record,guard=self.guard)
            paths=self.files();t.seal(record,paths,guard=self.guard)
            for name,source in paths.items():self.assertEqual((evidence/name).read_bytes(),source.read_bytes())
            reviewed=sha((evidence/'manifest.json').read_bytes())
            self.assertEqual(record['evidence_sha256'],reviewed)
            self.assertTrue(working.exists())
            t.discard(record,reviewed,guard=self.guard)
            self.assertFalse(ram.exists());self.assertTrue(evidence.exists());self.assertTrue(journal.exists())
            self.assertEqual(t.pending_journals(self.root),[])
            t.discard(record,reviewed,guard=self.guard)
        self.assertGreater(self.guard_calls,8);self.unchanged()

    def test_explicit_guard_required_and_refusal_preserves_working(self):
        record=self.prepare();working=t.locations(record)[0]
        for call in (lambda:t.record_stopped(record),lambda:t.record_stopped(record,guard=None),
                     lambda:t.record_stopped(record,guard=lambda record:False)):
            self.rejected(call)
        t.record_stopped(record,guard=self.guard)
        self.rejected(lambda:t.seal(record,self.files()))
        self.rejected(lambda:t.seal(record,self.files(),guard=None))
        t.seal(record,self.files(),guard=self.guard)
        self.rejected(lambda:t.discard(record,record['evidence_sha256']))
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=lambda record:False))
        self.assertTrue(working.exists());self.unchanged()

    def test_reviewed_pointer_required_missing_and_wrong_never_allocate(self):
        with patch.object(t.tempfile,'mkdtemp') as create:
            for value in (None,'','0'*64,self.pointer_sha.upper()):
                self.rejected(lambda:t.prepare(self.disk,value))
            self.pointer.unlink();self.rejected(self.prepare)
            create.assert_not_called()
        self.assertEqual(list(self.root.glob('qa-trial-*')),[])

    def test_baseline_archive_corruption_and_original_change_refuse_prepare(self):
        self.archive.write_bytes(self.archive_bytes+b'junk');self.rejected(self.prepare)
        self.archive.write_bytes(self.archive_bytes);self.disk.write_bytes(b'foreign base');self.rejected(self.prepare)
        self.assertEqual(list(self.ram.iterdir()),[])

    def test_pending_raw_packed_or_trial_blocks_prepare(self):
        for owner in (t.s,t.p):
            with patch.object(owner,'pending_journals',return_value=[self.root/'pending']):self.rejected(self.prepare)
        record=self.prepare();self.rejected(self.prepare)
        self.assertEqual(t.pending_journals(self.root),[t.locations(record)[3]])

    def test_prepare_memory_tmpfs_root_boundaries(self):
        required=6*t.s.GIB+384*t.s.MIB+t.p.RAW_CAP+t.p.CODEC_ALLOWANCE
        with patch.object(t.p,'available_memory',return_value=required-1):self.rejected(self.prepare)
        with self.space(t.s.ROOT_RESERVE+t.s.WRITE_MARGIN-1):self.rejected(self.prepare)
        def usage(path):
            return shutil._ntuple_diskusage(100*t.s.GIB,0,t.p.RAW_CAP-1 if Path(path)==self.ram else 100*t.s.GIB)
        with patch.object(t.p.shutil,'disk_usage',side_effect=usage):self.rejected(self.prepare)
        with patch.object(t.p,'available_memory',return_value=required):
            record=self.prepare();self.assertEqual(record['status'],'ready')

    def test_headroom_rechecked_after_archive_measurement(self):
        with patch.object(t.p,'available_memory',side_effect=[20*t.s.GIB,0]),patch.object(t.tempfile,'mkdtemp') as create:
            self.rejected(self.prepare);create.assert_not_called()

    def test_source_race_during_measurement_refuses_before_allocation(self):
        decode=t.p.decode
        def changed(*args,**kwargs):
            result=decode(*args,**kwargs);self.pointer.write_bytes(self.pointer_bytes);return result
        with patch.object(t.p,'decode',side_effect=changed),patch.object(t.tempfile,'mkdtemp') as create:
            self.rejected(self.prepare);create.assert_not_called()

    def test_preparing_crash_retains_pending_absent_image_without_claiming_stopped(self):
        self.rejected(lambda:self.prepare(fail_at('prepared_journal')))
        record=t.load_record(self.journal());self.assertEqual(record['status'],'preparing')
        self.assertFalse(t.locations(record)[0].exists())
        self.rejected(lambda:t.record_stopped(record,guard=self.guard))
        self.assertEqual(t.pending_journals(self.root),[self.journal()]);self.unchanged()

    def test_complete_restore_before_ready_is_recoverable(self):
        self.rejected(lambda:self.prepare(fail_at('working_restored')))
        record=t.load_record(self.journal());self.assertEqual(record['status'],'preparing')
        t.record_stopped(record,guard=self.guard)
        self.assertEqual(record['status'],'stopped_awaiting_evidence')
        self.assertEqual(t.locations(record)[0].read_bytes(),self.data)

    def test_incomplete_preparing_image_is_preserved(self):
        self.rejected(lambda:self.prepare(fail_at('prepared_journal')))
        record=t.load_record(self.journal());working=t.locations(record)[0];working.write_bytes(b'partial')
        self.rejected(lambda:t.record_stopped(record,guard=self.guard))
        self.assertEqual(working.read_bytes(),b'partial')

    def test_ready_and_stopped_receipt_crashes_reload_durable_state(self):
        self.rejected(lambda:self.prepare(fail_at('ready')))
        record=t.load_record(self.journal());self.assertEqual(record['status'],'ready')
        stale=copy.deepcopy(record)
        self.rejected(lambda:t.record_stopped(record,guard=self.guard,checkpoint=fail_at('stopped_recorded')))
        t.record_stopped(stale,guard=self.guard)
        self.assertEqual(stale['status'],'stopped_awaiting_evidence')

    def test_stopped_image_mutation_during_hash_boundary_refuses_receipt(self):
        record=self.prepare();working=t.locations(record)[0]
        def change(stage):
            if stage=='stopped_image_hashed':working.write_bytes(b'changed')
        self.rejected(lambda:t.record_stopped(record,guard=self.guard,checkpoint=change))
        self.assertEqual(t.load_record(self.journal())['status'],'ready')
        self.assertEqual(working.read_bytes(),b'changed')

    def test_stopped_file_hardlink_and_symlink_refused(self):
        record=self.prepare();working=t.locations(record)[0]
        alias=self.root/'alias';os.link(working,alias)
        self.rejected(lambda:t.record_stopped(record,guard=self.guard));alias.unlink()
        working.unlink();working.symlink_to(self.source)
        self.rejected(lambda:t.record_stopped(record,guard=self.guard));self.assertTrue(working.is_symlink())

    def test_seal_requires_stopped_and_discard_requires_seal(self):
        record=self.prepare();self.rejected(lambda:t.seal(record,self.files(),guard=self.guard))
        self.rejected(lambda:t.discard(record,'0'*64,guard=self.guard))
        self.assertTrue(t.locations(record)[0].exists())

    def test_evidence_empty_names_path_aliases_and_file_count_rejected(self):
        record=self.stopped();paths=self.files();source=next(iter(paths.values()))
        for entries in ({},{'../bad':source},{'manifest.json':source},{1:source},
                        {str(i):source for i in range(33)}, {'disk':t.locations(record)[0]},
                        {'pointer':self.pointer},{'archive':self.archive}):
            with self.subTest(entries=list(entries)[:3]):self.rejected(lambda:t.seal(record,entries,guard=self.guard))
        self.assertEqual(t.load_record(self.journal())['status'],'stopped_awaiting_evidence')

    def test_evidence_symlink_and_hardlink_rejected(self):
        record=self.stopped();source=self.root/'external';source.write_bytes(b'log')
        alias=self.root/'alias';alias.symlink_to(source)
        self.rejected(lambda:t.seal(record,{'log':alias},guard=self.guard));alias.unlink()
        os.link(source,alias);self.rejected(lambda:t.seal(record,{'log':source},guard=self.guard))
        self.assertEqual(source.read_bytes(),b'log')

    def test_evidence_aggregate_byte_boundary(self):
        record=self.stopped();one=self.root/'one';two=self.root/'two'
        one.write_bytes(bytes(t.EVIDENCE_CAP));two.write_bytes(b'x')
        self.rejected(lambda:t.seal(record,{'one':one,'two':two},guard=self.guard))
        t.seal(record,{'one':one},guard=self.guard)
        self.assertEqual((t.locations(record)[4]/'one').stat().st_size,t.EVIDENCE_CAP)

    def test_sealing_crashes_recover_from_original_caller_record(self):
        for stage in ('sealing_recorded','evidence_copied','evidence_manifest_published','evidence_saved'):
            with self.subTest(stage=stage):
                # Each durable journal owns a separate synthetic original directory.
                case=Trial('test_complete_lifecycle_exact_bytes_no_encode_no_pointer_write');case.setUp()
                try:
                    record=case.stopped();stale=copy.deepcopy(record);paths=case.files()
                    case.rejected(lambda:t.seal(record,paths,guard=case.guard,checkpoint=fail_at(stage)))
                    t.seal(stale,paths,guard=case.guard)
                    self.assertEqual(stale['status'],'evidence_saved');case.unchanged()
                finally:case.doCleanups()

    def test_external_evidence_race_retained_without_success_receipt(self):
        record=self.stopped();paths=self.files()
        def change(stage):
            if stage=='evidence_copied':paths['log.txt'].write_bytes(b'changed')
        self.rejected(lambda:t.seal(record,paths,guard=self.guard,checkpoint=change))
        self.assertEqual(t.load_record(self.journal())['status'],'sealing')
        self.assertTrue(t.locations(record)[0].exists())
        self.rejected(lambda:t.seal(record,paths,guard=self.guard))

    def test_unknown_partial_or_extra_evidence_is_never_overwritten(self):
        record=self.stopped();paths=self.files();directory=t.locations(record)[4]
        target=directory/'log.txt';target.write_bytes(b'foreign partial')
        self.rejected(lambda:t.seal(record,paths,guard=self.guard))
        self.assertEqual(target.read_bytes(),b'foreign partial')
        extra=directory/'unknown';extra.write_bytes(b'unknown')
        self.rejected(lambda:t.seal(record,paths,guard=self.guard));self.assertEqual(extra.read_bytes(),b'unknown')

    def test_wrong_review_hash_refuses_discard(self):
        record=self.sealed();working=t.locations(record)[0]
        for value in ('0'*64,'',None):self.rejected(lambda:t.discard(record,value,guard=self.guard))
        self.assertTrue(working.exists());self.unchanged()

    def test_stopped_image_changed_after_seal_refuses_discard(self):
        record=self.sealed();working=t.locations(record)[0];working.write_bytes(b'later guest modification')
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertEqual(working.read_bytes(),b'later guest modification')

    def test_evidence_mutation_prevents_discard(self):
        record=self.sealed();working,_,_,_,directory=t.locations(record)
        (directory/'log.txt').write_bytes(b'altered')
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertTrue(working.exists())

    def test_pointer_and_archive_identical_byte_replacements_are_refused(self):
        record=self.sealed();working=t.locations(record)[0]
        for path,data in ((self.pointer,self.pointer_bytes),(self.archive,self.archive_bytes)):
            with self.subTest(path=path.name):
                # Rewriting alone changes the pinned mtime/ctime even for identical bytes.
                path.write_bytes(data)
                self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
                self.assertTrue(working.exists())

    def test_unknown_ram_child_blocks_discard_without_deleting_image(self):
        record=self.sealed();working,_,ram,_,_=t.locations(record)
        child=ram/'foreign';child.write_bytes(b'preserve')
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertTrue(working.exists());self.assertEqual(child.read_bytes(),b'preserve')

    def test_discard_crashes_replay_without_new_authorization_hash(self):
        for stage in ('discarding_recorded','ram_unlinked','ram_removed','discarded_recorded'):
            with self.subTest(stage=stage):
                case=Trial('test_complete_lifecycle_exact_bytes_no_encode_no_pointer_write');case.setUp()
                try:
                    record=case.sealed();stale=copy.deepcopy(record);reviewed=record['evidence_sha256']
                    case.rejected(lambda:t.discard(record,reviewed,guard=case.guard,checkpoint=fail_at(stage)))
                    t.discard(stale,reviewed,guard=case.guard)
                    self.assertEqual(stale['status'],'discarded');self.assertFalse(t.locations(stale)[2].exists())
                    case.unchanged()
                finally:case.doCleanups()

    def test_replaced_ram_directory_after_unlink_is_not_removed(self):
        record=self.sealed();reviewed=record['evidence_sha256'];ram=t.locations(record)[2]
        self.rejected(lambda:t.discard(record,reviewed,guard=self.guard,checkpoint=fail_at('ram_unlinked')))
        old=ram.with_name(ram.name+'-retained');ram.rename(old);ram.mkdir(mode=0o700)
        self.rejected(lambda:t.discard(record,reviewed,guard=self.guard))
        self.assertTrue(ram.exists());self.assertTrue(old.exists())

    def test_guard_replaces_working_immediately_before_unlink(self):
        record=self.sealed();working=t.locations(record)[0];count=0
        def guard(value):
            nonlocal count
            count+=1
            if count==3:
                replacement=working.with_name('replacement');replacement.write_bytes(working.read_bytes());os.replace(replacement,working)
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=guard))
        self.assertEqual(count,3);self.assertTrue(working.exists())

    def test_guard_injects_foreign_child_immediately_before_unlink(self):
        record=self.sealed();working,_,ram,_,_=t.locations(record);count=0
        def guard(value):
            nonlocal count
            count+=1
            if count==3:(ram/'foreign').write_bytes(b'keep')
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=guard))
        self.assertTrue(working.exists());self.assertEqual((ram/'foreign').read_bytes(),b'keep')

    def test_journal_mutation_before_unlink_preserves_image(self):
        record=self.sealed();working=t.locations(record)[0]
        def change(stage):
            if stage=='discarding_recorded':
                path=self.journal();path.write_bytes(path.read_bytes()+b' ')
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard,checkpoint=change))
        self.assertTrue(working.exists())

    def test_evidence_directory_replacement_refused(self):
        record=self.sealed();directory=t.locations(record)[4]
        directory.rename(directory.with_name(directory.name+'-keep'));directory.mkdir(mode=0o700)
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertTrue(Path(record['working_disk']).exists())

    def test_foreign_or_mutated_record_ownership_refused(self):
        record=self.prepare()
        for key,value in (('working_disk',str(self.source)),('token','../other'),('version',True),
                          ('directory_identity',{}),('changes_are_disposable',False)):
            bad=copy.deepcopy(record);bad[key]=value
            self.rejected(lambda:t.record_stopped(bad,guard=self.guard))
        self.assertTrue(t.locations(record)[0].exists())

    def test_json_exact_bound_and_normal_reserve_before_publication(self):
        value={'a':['x'*20]*2500}
        self.assertLess(len(json.dumps(value).encode()),t.RECORD_CAP)
        self.assertGreater(len((json.dumps(value,indent=2)+'\n').encode()),t.RECORD_CAP)
        target=self.root/'too-big.json';self.rejected(lambda:t._publish(target,value));self.assertFalse(target.exists())
        data={'small':'value'};needed=t.s.ROOT_RESERVE+t.s.WRITE_MARGIN+t.p.allocation_bound(len(t._encoded(data)))
        with self.space(needed-1):self.rejected(lambda:t._publish(target,data))
        self.assertFalse(target.exists())
        with self.space(needed):t._publish(target,data)
        self.assertEqual(json.loads(target.read_bytes()),data)

    def test_json_dynamic_reserve_refuses_write_and_preserves_old_record(self):
        target=self.root/'record.json';t._publish(target,{'before':1});previous=t._file(target,t.RECORD_CAP)
        values=iter([100*t.s.GIB,t.s.ROOT_RESERVE+t.s.WRITE_MARGIN-1])
        with patch.object(t.p.shutil,'disk_usage',side_effect=lambda path:shutil._ntuple_diskusage(100*t.s.GIB,0,next(values))):
            self.rejected(lambda:t._publish(target,{'after':2},previous))
        self.assertEqual(t._file(target,t.RECORD_CAP),previous)
        self.assertEqual(list(self.root.glob('.record.json.tmp-*')),[])

    def test_initial_publication_never_overwrites_foreign_record(self):
        target=self.root/'existing.json';target.write_bytes(b'foreign')
        self.rejected(lambda:t._publish(target,{'new':1}))
        self.assertEqual(target.read_bytes(),b'foreign')

    def test_archived_base_verified_once_then_byte_identity_pinned(self):
        archive=self.root/'install-base-abcdef0123456789abcdef0123456789.qcow2.xz'
        metadata=t.p.encode(self.disk,archive)
        pointer={'schema':t.b.SCHEMA,'version':1,'format':'xz','codec':t.p.CODEC,
                 'generation':'abcdef0123456789abcdef0123456789','original_disk':str(self.disk),'archive':str(archive),**metadata}
        t.b.pointer_path(self.disk).write_text(json.dumps(pointer)+'\n');self.disk.unlink()
        verify=t.p.base_identity
        with patch.object(t.p,'base_identity',wraps=verify) as checked:
            record=self.prepare();t.record_stopped(record,guard=self.guard)
            t.seal(record,self.files(),guard=self.guard)
            self.assertEqual(checked.call_count,1)
        archive.write_bytes(archive.read_bytes())
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertTrue(t.locations(record)[0].exists());self.assertFalse(self.disk.exists())

    def test_reappearing_raw_base_after_archive_only_capture_blocks_discard(self):
        archive=self.root/'install-base-abcdef0123456789abcdef0123456789.qcow2.xz';metadata=t.p.encode(self.disk,archive)
        pointer={'schema':t.b.SCHEMA,'version':1,'format':'xz','codec':t.p.CODEC,
                 'generation':'abcdef0123456789abcdef0123456789','original_disk':str(self.disk),'archive':str(archive),**metadata}
        t.b.pointer_path(self.disk).write_text(json.dumps(pointer)+'\n');self.disk.unlink()
        record=self.sealed();self.disk.write_bytes(self.original_bytes)
        self.rejected(lambda:t.discard(record,record['evidence_sha256'],guard=self.guard))
        self.assertTrue(t.locations(record)[0].exists())

    def test_json_actual_crash_after_exclusive_rename_reloads_single_link(self):
        target=self.root/'published.json';rename=t.b._rename_new
        def crash(source,destination):
            rename(source,destination);raise Crash('after atomic rename')
        with patch.object(t.b,'_rename_new',side_effect=crash):self.rejected(lambda:t._publish(target,{'value':3}))
        self.assertEqual(t._json(target)[0],{'value':3});self.assertEqual(target.stat().st_nlink,1)
        self.rejected(lambda:t._publish(target,{'value':4}))
        self.assertEqual(t._json(target)[0],{'value':3})

    def test_journal_actual_crash_after_atomic_replace_reloads_new_state(self):
        record=self.prepare();replace=os.replace
        def crash(source,destination):
            replace(source,destination);raise Crash('after replace')
        with patch.object(t.os,'replace',side_effect=crash):
            self.rejected(lambda:t.record_stopped(record,guard=self.guard))
        self.assertEqual(t.load_record(self.journal())['status'],'stopped_awaiting_evidence')
        t.record_stopped(record,guard=self.guard)

    def test_journal_duplicate_key_and_nonfinite_rejected(self):
        for data in (b'{"version":1,"version":1}',b'{"value":NaN}'):
            target=self.root/'bad.json';target.write_bytes(data);self.rejected(lambda:t._json(target))


if __name__=='__main__':unittest.main()
