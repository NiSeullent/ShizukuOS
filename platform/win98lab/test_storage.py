#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host guard and atomic-persistence tests; never starts a VM."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import storage as s

BUILD = Path(__file__).resolve().parents[2] / 'build/win98-lab'


class Guards(unittest.TestCase):
    def test_file_limit_is_child_only(self):
        import resource
        before=resource.getrlimit(resource.RLIMIT_FSIZE)
        child=subprocess.check_output([sys.executable,'-c',
            'import resource,json;print(json.dumps(resource.getrlimit(resource.RLIMIT_FSIZE)))'],
            preexec_fn=s.limit_child_files,text=True)
        self.assertEqual(json.loads(child),[s.RAM_DISK_ALLOWANCE]*2)
        self.assertEqual(resource.getrlimit(resource.RLIMIT_FSIZE),before)

    def test_default_exact_boundary(self):
        s.check_headroom(6*s.GIB+s.GUEST_ALLOWANCE,s.ROOT_RESERVE+s.RAM_DISK_ALLOWANCE,0,False)

    def test_default_short_disk(self):
        with self.assertRaises(RuntimeError):
            s.check_headroom(12*s.GIB,s.ROOT_RESERVE+s.RAM_DISK_ALLOWANCE-1,0,False)

    def test_ram_exact_boundaries(self):
        s.check_headroom(6*s.GIB+s.GUEST_ALLOWANCE+s.RAM_DISK_ALLOWANCE,
                         s.ROOT_RESERVE+s.WRITE_MARGIN,s.RAM_DISK_ALLOWANCE,True)

    def test_ram_short_memory(self):
        with self.assertRaises(RuntimeError):
            s.check_headroom(6*s.GIB+s.GUEST_ALLOWANCE+s.RAM_DISK_ALLOWANCE-1,
                             22*s.GIB,4*s.GIB,True)

    def test_ram_short_tmpfs(self):
        with self.assertRaises(RuntimeError):
            s.check_headroom(12*s.GIB,22*s.GIB,s.RAM_DISK_ALLOWANCE-1,True)

    def test_ram_preserves_root_reserve(self):
        with self.assertRaises(RuntimeError):
            s.check_headroom(12*s.GIB,s.ROOT_RESERVE+s.WRITE_MARGIN-1,4*s.GIB,True)


class Files(unittest.TestCase):
    def setUp(self):
        BUILD.mkdir(parents=True,exist_ok=True)
        self.root=Path(tempfile.mkdtemp(prefix='storage-test-',dir=BUILD))
        self.ram=Path(tempfile.mkdtemp(prefix='win98-modern-private-install-',dir='/dev/shm'))
        self.ram.chmod(0o700)
        self.original=self.root/'install-disk.qcow2';self.original.write_bytes(b'original')
        self.working=self.ram/'install-disk.qcow2';self.working.write_bytes(b'changed data')
        self.record={'directory':str(self.ram),'working_disk':str(self.working),
                     'original_disk':str(self.original),'original_sha256':s.digest(self.original)}
        # Host CI disk sizes vary. Synthetic persistence fixtures use explicit
        # ample space; dedicated low-space tests override this production call.
        self.space=patch.object(s.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(100*s.GIB,0,100*s.GIB))
        self.space.start()

    def tearDown(self):
        self.space.stop()
        shutil.rmtree(self.root)
        if self.ram.exists():shutil.rmtree(self.ram)

    def test_sparse_copy_preserves_all_bytes_and_mode(self):
        self.working.write_bytes(bytes(s.MIB)+b'x'+bytes(2*s.MIB))
        dest=self.root/'sparse'
        s.sparse_copy(self.working,dest)
        self.assertEqual(s.digest(dest),s.digest(self.working))
        self.assertEqual(dest.stat().st_mode&0o777,0o600)
        self.assertLess(dest.stat().st_blocks*512,dest.stat().st_size)

    def test_existing_destination_never_deleted(self):
        with self.assertRaises(FileExistsError):s.sparse_copy(self.working,self.original)
        self.assertEqual(self.original.read_bytes(),b'original')

    def test_copy_reserve_failure_removes_only_temporary(self):
        dest=self.root/'partial'
        with patch.object(s.shutil,'disk_usage',return_value=shutil._ntuple_diskusage(10,9,1)):
            with self.assertRaises(RuntimeError):s.sparse_copy(self.working,dest,reserve=10)
        self.assertFalse(dest.exists());self.assertEqual(self.working.read_bytes(),b'changed data')

    def test_success_retains_original_backup_and_removes_ram_copy(self):
        with patch.object(s,'check_qcow'):
            result=s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'changed data')
        self.assertEqual(Path(result['original_backup']).read_bytes(),b'original')
        self.assertEqual(result['persisted_sha256'],s.digest(self.original))
        self.assertFalse(self.ram.exists());self.assertEqual(result['status'],'persisted')

    def test_changed_original_preserved(self):
        self.original.write_bytes(b'new original')
        with patch.object(s,'check_qcow'):
            with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'new original');self.assertTrue(self.working.exists())

    def test_insufficient_writeback_space_retains_both_copies(self):
        with patch.object(s,'check_qcow'),patch.object(s.shutil,'disk_usage',
                return_value=shutil._ntuple_diskusage(30*s.GIB,10*s.GIB,20*s.GIB)):
            with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'original');self.assertTrue(self.working.exists())

    def test_corrupt_working_copy_is_not_published(self):
        with patch.object(s,'check_qcow',side_effect=RuntimeError('corrupt qcow')):
            with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'original');self.assertTrue(self.working.exists())

    def test_nonprivate_ram_directory_rejected(self):
        self.ram.chmod(0o755)
        with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'original')

    def test_oversize_sparse_extent_refused_before_copy(self):
        with self.working.open('r+b') as out:out.truncate(s.RAM_DISK_ALLOWANCE+1)
        with self.assertRaises(RuntimeError):s.sparse_copy(self.working,self.root/'too-large')
        self.assertFalse((self.root/'too-large').exists())

    def test_growth_during_copy_is_bounded(self):
        self.working.write_bytes(b'x'*(2*s.MIB))
        with patch.object(s,'check_extent'),patch.object(s,'RAM_DISK_ALLOWANCE',s.MIB):
            with self.assertRaises(RuntimeError):s.sparse_copy(self.working,self.root/'growing')
        self.assertFalse((self.root/'growing').exists())

    def test_foreign_backup_refused(self):
        backup=s.locations(self.record)[5];backup.write_bytes(b'foreign')
        with patch.object(s,'check_qcow'):
            with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(backup.read_bytes(),b'foreign');self.assertTrue(self.working.exists())

    def test_partial_preparation_is_not_published(self):
        self.record['status']='preparing'
        with patch.object(s,'check_qcow'):
            with self.assertRaises(RuntimeError):s.persist(self.record)
        self.assertEqual(self.original.read_bytes(),b'original');self.assertTrue(self.working.exists())

    def test_recovery_before_pid_or_global_state_publication(self):
        import lab
        self.record['status']='working_copy_active'
        s.durable_json(s.locations(self.record)[3],self.record)
        # No STATE and no PID: the sole durable journal plus absent owned
        # processes is sufficient. A repeat uses the now-durable global state.
        with patch.object(lab,'BUILD',self.root),patch.object(lab,'STATE',self.root/'state.json'),\
             patch.object(lab,'DISK',self.original),patch.object(lab,'assert_no_owned_processes'),\
             patch.object(s,'check_qcow'):
            lab.retry_persistence()
            lab.retry_persistence()
        self.assertEqual(self.original.read_bytes(),b'changed data')
        self.assertFalse(self.ram.exists())

    def test_live_process_refuses_manual_persistence(self):
        import lab
        self.record['status']='working_copy_active'
        s.durable_json(s.locations(self.record)[3],self.record)
        with patch.object(lab,'BUILD',self.root),patch.object(lab,'STATE',self.root/'state.json'),\
             patch.object(lab,'DISK',self.original),\
             patch.object(lab,'assert_no_owned_processes',side_effect=RuntimeError('running')):
            with self.assertRaises(RuntimeError):lab.retry_persistence()
        self.assertEqual(self.original.read_bytes(),b'original');self.assertTrue(self.working.exists())

    def test_journal_discovery_after_cleanup_interruption_without_state(self):
        import lab
        real_persist=s.persist
        for stage in ('persisted_journal','ram_unlinked','ram_removed'):
            with self.subTest(stage=stage):
                root=self.root/stage;root.mkdir()
                folder=Path(tempfile.mkdtemp(prefix='win98-modern-private-install-',dir='/dev/shm'))
                original=root/'install-disk.qcow2';original.write_bytes(b'old')
                working=folder/'install-disk.qcow2';working.write_bytes(b'new')
                record={'directory':str(folder),'working_disk':str(working),'original_disk':str(original),
                        'original_sha256':s.digest(original),'status':'working_copy_active'}
                s.durable_json(s.locations(record)[3],record)
                def fail(at):
                    if at==stage:raise RuntimeError('simulated crash')
                try:
                    with patch.object(lab,'BUILD',root),patch.object(lab,'STATE',root/'state.json'),\
                         patch.object(lab,'DISK',original),patch.object(lab,'assert_no_owned_processes'),\
                         patch.object(s,'check_qcow'):
                        with patch.object(s,'persist',side_effect=lambda rec:real_persist(rec,fail)):
                            with self.assertRaises(RuntimeError):lab.retry_persistence()
                        self.assertFalse((root/'state.json').exists())
                        lab.retry_persistence()
                    self.assertEqual(original.read_bytes(),b'new');self.assertFalse(folder.exists())
                finally:
                    if folder.exists():shutil.rmtree(folder)

    def test_retry_after_each_persistence_boundary(self):
        # Each failpoint receives a fresh original/RAM pair. The retry receives
        # only the pre-operation record, simulating a crash before state write.
        stages=('copy_verified','backup_linked','backup_verified','replaced','published',
                'persisted_journal','ram_unlinked','ram_removed')
        for stage in stages:
            with self.subTest(stage=stage):
                folder=Path(tempfile.mkdtemp(prefix='win98-modern-private-install-',dir='/dev/shm'))
                original=self.root/('original-'+stage);original.write_bytes(b'old')
                working=folder/'install-disk.qcow2';working.write_bytes(b'new')
                initial={'directory':str(folder),'working_disk':str(working),
                         'original_disk':str(original),'original_sha256':s.digest(original)}
                def stop_at(at):
                    if at==stage:raise RuntimeError('simulated interruption '+at)
                with patch.object(s,'check_qcow'):
                    with self.assertRaises(RuntimeError):s.persist(dict(initial),stop_at)
                    final=s.persist(dict(initial))
                    # Repeating a completed operation is also harmless.
                    again=s.persist(dict(initial))
                self.assertEqual(original.read_bytes(),b'new')
                self.assertEqual(Path(final['original_backup']).read_bytes(),b'old')
                self.assertEqual(again['status'],'persisted');self.assertFalse(folder.exists())


class Coordination(unittest.TestCase):
    def setUp(self):
        BUILD.mkdir(parents=True,exist_ok=True)
        self.root=Path(tempfile.mkdtemp(prefix='coordination-test-',dir=BUILD))

    def tearDown(self):shutil.rmtree(self.root)

    def test_incomplete_persistence_reports_error_and_fails(self):
        import lab
        state={'process_stopped':True,'elapsed_seconds':1,
               'ram_working_copy':{'status':'persistence_required','error':'insufficient space'}}
        with patch('builtins.print') as printed:
            with self.assertRaises(RuntimeError):lab.report_completion(state)
        self.assertEqual(json.loads(printed.call_args.args[0])['persistence'],state['ram_working_copy'])

    def test_persisted_completion_reports_durable_success(self):
        import lab
        state={'process_stopped':True,'elapsed_seconds':1,'ram_working_copy':{'status':'persisted'}}
        with patch('builtins.print') as printed:lab.report_completion(state)
        self.assertEqual(json.loads(printed.call_args.args[0])['persistence']['status'],'persisted')

    def test_second_process_cannot_acquire_supervisor_lock(self):
        import lab
        with patch.object(lab,'BUILD',self.root),lab.exclusive_lab_lock():
            code="import fcntl,os,sys;f=os.open(sys.argv[1],os.O_RDWR);fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)"
            result=subprocess.run([sys.executable,'-c',code,str(self.root/'lab.lock')],capture_output=True)
            self.assertNotEqual(result.returncode,0)
        with patch.object(lab,'BUILD',self.root),lab.exclusive_lab_lock():pass

    def test_wrong_qmp_peer_is_rejected_before_protocol(self):
        import lab,os,socket
        # Linux AF_UNIX limits the full socket path; CI checkout paths vary.
        directory=Path(tempfile.mkdtemp(prefix='win98-qmp-test-',dir='/dev/shm'))
        path=directory/'qmp.sock';server=socket.socket(socket.AF_UNIX)
        try:
            server.bind(str(path));server.listen(1)
            with patch.object(lab,'QMP_PATH',path):
                with self.assertRaisesRegex(RuntimeError,'peer credentials'):
                    lab.QMP(os.getpid()+999999)
        finally:server.close();shutil.rmtree(directory)

    def test_renamed_qemu_using_owned_disk_is_still_refused(self):
        import lab
        process=self.root/'123';process.mkdir()
        record={'original_disk':'/owned/original','working_disk':'/owned/ram'}
        (process/'cmdline').write_bytes(b'qemu\0-name\0changed-name\0-drive\0file=/owned/ram,if=ide,index=0,format=qcow2\0')
        with self.assertRaises(RuntimeError):lab.assert_no_owned_processes(record,self.root)


if __name__=='__main__':unittest.main()
