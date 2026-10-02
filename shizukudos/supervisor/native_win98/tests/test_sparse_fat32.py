#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Small real FAT32 packaging controls; no Windows/media/VM acceptance.

Fixtures model filesystem capacity only: production's 17 GiB policy stays
unchanged. Actual tmpfs/host headroom and this lane's allocation remain bounded.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import time
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('sparse_fixture_builder', HERE.parent/'build.py')
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)


class ActualSparseAssembly(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ['SHZ_SPARSE_FAT32_TEST_ROOT'])
        available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines()
                             if line.startswith('MemAvailable:'))) * 1024
        self.assertGreaterEqual(available, (6 << 30) + (160 << 20))
        self.assertGreaterEqual(shutil.disk_usage(parent).free, (6 << 30) + (160 << 20))
        self.folder = tempfile.TemporaryDirectory(prefix='actual-fat-', dir=parent)
        self.root = Path(self.folder.name)
        self.source = self.root/'source.img'
        with self.source.open('xb') as stream:
            stream.truncate(3 << 20)
            for at, value in ((4095, b'A'), (1 << 20, b'B'), ((3 << 20)-1, b'C')):
                stream.seek(at); stream.write(value)
        self.pin = B.file_sha(self.source)
        self.loader = self.root/'fixture-loader'
        self.loader.write_bytes(b'actual non-executable EFI fixture\r\n')

    def tearDown(self):
        allocated = sum(p.stat().st_blocks * 512 for p in self.root.rglob('*') if p.is_file())
        self.assertLessEqual(allocated, 64 << 20)
        self.folder.cleanup()

    def assemble(self, esp_mib=40):
        out = self.root/'out'; out.mkdir()
        receipt = {'commands': []}
        # Only the tiny host fixture models production capacity. All actual
        # file bytes, Linux leases, FAT writes, mtools and hashes remain real.
        capacity = shutil._ntuple_diskusage(64 << 30, 0, 64 << 30)
        real_command = B.command
        def fixture_capacity(argv, receipt, **kwargs):
            argv = list(map(str, argv))
            if len(argv) > 3 and argv[1:3] == ['-B', '-c']:
                argv[3] = "import shutil\nshutil.disk_usage=lambda p:shutil._ntuple_diskusage(64<<30,0,64<<30)\n" + argv[3]
            return real_command(argv, receipt, **kwargs)
        with mock.patch.object(B, 'ESP_MIB', esp_mib), mock.patch.object(B.shutil, 'disk_usage', return_value=capacity), mock.patch.object(B, 'command', side_effect=fixture_capacity):
            esp, members = B.assemble(out, {'DISK.IMG': self.source}, self.loader, receipt)
        return esp, members, receipt

    def test_actual_zero_member_does_not_allocate_its_full_logical_extent(self):
        esp, members, receipt = self.assemble()
        self.assertEqual(members['SHZDOS/DISK.IMG']['sha256'], self.pin)
        self.assertEqual(B.file_sha(self.source), self.pin)
        self.assertLess(esp.stat().st_blocks * 512, 1 << 20,
                        'whole-zero source chunks must not be densely written into the ESP')
        worker = receipt['disk_insertion']['result']
        self.assertGreater(worker['member']['zero_bytes_omitted'], (3 << 20)-16384)
        self.assertFalse(any(c[0] == 'mcopy' and c[-1] == '::/SHZDOS/DISK.IMG' for c in receipt['commands']))

    def test_actual_boot_members_remain_byte_identical(self):
        esp, members, receipt = self.assemble()
        B.verify_esp_member(esp, 'EFI/BOOT/BOOTX64.EFI', B.file_sha(self.loader), self.loader.stat().st_size, receipt)
        policy = esp.parent/'BOOT.INI'
        B.verify_esp_member(esp, 'EFI/SHIZUKU/BOOT.INI', B.file_sha(policy), policy.stat().st_size, receipt)
        self.assertFalse(any(p.name.startswith('readback') for p in esp.parent.iterdir()))

    def test_frozen_runtime_guard_import_needs_no_packer_sibling(self):
        path = self.root/'frozen-build.py'; path.write_bytes((HERE.parent/'build.py').read_bytes())
        spec = importlib.util.spec_from_file_location('standalone_frozen_guards', path)
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        self.assertEqual(module.config_bytes(), B.config_bytes())

    def test_production_2304_mib_esp_has_exact_fat_extent_and_real_member(self):
        # Default mkfs.fat CHS rounds this actual logical size down by 18
        # sectors. Exercise the ordinary assembler and strict packer at the
        # production extent with tiny real data, under the same physical cap.
        esp, members, receipt = self.assemble(2304)
        with esp.open('rb') as stream:
            boot = stream.read(512)
            backup_sector = struct.unpack_from('<H', boot, 50)[0]
            stream.seek(backup_sector * 512)
            backup = stream.read(512)
        self.assertEqual(esp.stat().st_size, 2304 << 20)
        self.assertEqual(struct.unpack_from('<I', boot, 32)[0], esp.stat().st_size // 512)
        self.assertEqual(backup, boot)
        self.assertEqual(members['SHZDOS/DISK.IMG']['sha256'], self.pin)
        self.assertTrue(receipt['disk_insertion']['independent_mtype_verified'])
        self.assertTrue(receipt['disk_insertion']['result']['fat']['mirrors_verified'])
        self.assertEqual(receipt['disk_insertion']['result']['esp']['sha256'], B.file_sha(esp))
        self.assertLess(esp.stat().st_blocks * 512, 64 << 20)


class WorkerControls(ActualSparseAssembly):
    def setUp(self):
        super().setUp()
        spec = importlib.util.spec_from_file_location('actual_sparse_worker', HERE.parent/'sparse_fat32.py')
        self.P = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.P)
        self.esp = self.root/'worker-esp'
        with self.esp.open('xb') as stream: stream.truncate(40 << 20)
        subprocess.run(['mkfs.vfat','-F','32','-n','SHZWIN98','-i','53485739',str(self.esp)], check=True, stdout=subprocess.DEVNULL, timeout=30)
        subprocess.run(['mmd','-i',str(self.esp),'::/SHZDOS'], check=True, stdout=subprocess.DEVNULL, timeout=30)
        self.result = self.root/'worker-result.json'
        self.request = self.root/'worker-request.json'

    def make_request(self):
        helper = (HERE.parent/'sparse_fat32.py').read_bytes()
        req = {'schema':'shizukuos.sparse-fat32-request.v1','member':'SHZDOS/DISK.IMG',
               'source':{'path':str(self.source),'bytes':self.source.stat().st_size,'sha256':B.file_sha(self.source),'identity':list(B.stable(self.source.stat()))},
               'esp':{'path':str(self.esp),'bytes':self.esp.stat().st_size,'identity':list(B.stable(self.esp.stat()))},
               'producer':{'sha256':hashlib.sha256(helper).hexdigest(),'bytes':len(helper)},'result':str(self.result)}
        raw=(json.dumps(req)+'\n').encode(); self.request.write_bytes(raw)
        return req,hashlib.sha256(raw).hexdigest()

    def run_worker(self):
        req, request_sha = self.make_request()
        capacity = shutil._ntuple_diskusage(64 << 30, 0, 64 << 30)
        with mock.patch.object(self.P.shutil, 'disk_usage', return_value=capacity):
            return self.P.prepare(self.request,request_sha,self.result,req['producer']['sha256'],req['producer']['bytes'])

    def fat_layout(self):
        with self.esp.open('rb') as stream: boot=stream.read(512)
        reserved=struct.unpack_from('<H',boot,14)[0]; fatsectors=struct.unpack_from('<I',boot,36)[0]
        return boot,reserved,fatsectors

    def edit(self, at, data):
        with self.esp.open('r+b') as stream: stream.seek(at); stream.write(data)

    def test_all_zero_and_odd_tail_are_actual_exact_mtype_bytes(self):
        for payload in (bytes(8193), b'A'+bytes(4095)+b'B'+bytes(8191)+b'C'):
            with self.subTest(bytes=len(payload)):
                # Each insertion requires a distinct fresh ESP/result.
                if self.result.exists():
                    self.result.unlink()
                    subprocess.run(['mkfs.vfat','-F','32',str(self.esp)],check=True,stdout=subprocess.DEVNULL,timeout=30)
                    subprocess.run(['mmd','-i',str(self.esp),'::/SHZDOS'],check=True,timeout=30)
                self.source.write_bytes(payload)
                result=self.run_worker()
                raw=subprocess.check_output(['mtype','-i',str(self.esp),'::/SHZDOS/DISK.IMG'],timeout=30)
                self.assertEqual(raw,payload)
                self.assertEqual(result['member']['zero_bytes_omitted']+result['member']['data_bytes_written'],len(payload))
                self.assertEqual(result['esp']['sha256'],B.file_sha(self.esp))

    def test_short_actual_reads_and_writes_complete_exact_bytes(self):
        real_read,real_write=self.P.os.pread,self.P.os.pwrite
        def short_read(fd,count,at):return real_read(fd,min(count,701),at)
        def short_write(fd,data,at):return real_write(fd,data[:613],at)
        with mock.patch.object(self.P.os,'pread',side_effect=short_read),mock.patch.object(self.P.os,'pwrite',side_effect=short_write):result=self.run_worker()
        B.verify_esp_member(self.esp,'SHZDOS/DISK.IMG',self.pin,3<<20,{'commands':[]})
        self.assertEqual(result['source']['streamed_sha256'],self.pin)

    def test_zero_write_and_eio_never_publish_result(self):
        for failure in (0,OSError(5,'controlled EIO')):
            with self.subTest(failure=str(failure)):
                with mock.patch.object(self.P.os,'pwrite',side_effect=failure if isinstance(failure,BaseException) else lambda *_:0):
                    with self.assertRaises((OSError,ValueError)):self.run_worker()
                self.assertFalse(self.result.exists())

    def test_bad_bpb_backup_and_fsinfo_refuse_before_data_writes(self):
        original=self.esp.read_bytes(); boot,reserved,fats=self.fat_layout()
        backup=struct.unpack_from('<H',boot,50)[0]; info=struct.unpack_from('<H',boot,48)[0]
        for at,data in ((11,b'\x00\x04'),(backup*512+3,b'BAD'),(info*512,b'BAD!'),((backup+info)*512+484,b'BAD!')):
            with self.subTest(at=at):
                self.esp.write_bytes(original);self.edit(at,data)
                before=B.file_sha(self.esp)
                with self.assertRaises(ValueError):self.run_worker()
                self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_nonmirrored_flags_and_fat_mismatch_refuse(self):
        boot,reserved,fats=self.fat_layout(); backup=struct.unpack_from('<H',boot,50)[0]
        self.edit(40,b'\x80\x00');self.edit(backup*512+40,b'\x80\x00')
        with self.assertRaisesRegex(ValueError,'mirrored'):self.run_worker()
        self.edit(40,b'\x00\x00');self.edit(backup*512+40,b'\x00\x00')
        self.edit((reserved+fats)*512+20,b'\x01')
        with self.assertRaisesRegex(ValueError,'mirrored FAT'):self.run_worker()
        self.assertFalse(self.result.exists())

    def test_duplicate_output_refuses_before_esp_changes(self):
        self.result.write_bytes(b'previous unaccepted owned result')
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'fresh owned result'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before)
        self.assertEqual(self.result.read_bytes(),b'previous unaccepted owned result')

    def test_reserved_high_fat_bits_and_both_fsinfos_are_preserved(self):
        boot,reserved,fats=self.fat_layout()
        with self.esp.open('rb') as stream:stream.seek(reserved*512);fat=stream.read(fats*512)
        number=next(n for n in range(2,len(fat)//4) if not struct.unpack_from('<I',fat,n*4)[0]&0xfffffff)
        for copy in range(2):self.edit((reserved+copy*fats)*512+number*4,struct.pack('<I',0xa0000000))
        result=self.run_worker()
        with self.esp.open('rb') as stream:
            for copy in range(2):
                stream.seek((reserved+copy*fats)*512+number*4)
                self.assertEqual(struct.unpack('<I',stream.read(4))[0]&0xf0000000,0xa0000000)
            info=struct.unpack_from('<H',boot,48)[0];backup=struct.unpack_from('<H',boot,50)[0]
            for sector in (info,backup+info):
                stream.seek(sector*512+488);free,next_free=struct.unpack('<II',stream.read(8))
                self.assertEqual(free,result['fat']['free_clusters_after']);self.assertEqual(next_free,result['fat']['next_free'])

    def test_capacity_and_deadline_reject_without_result(self):
        req, request_sha=self.make_request()
        with self.assertRaisesRegex(ValueError,'17GiB'):self.P.prepare(self.request,request_sha,self.result,req['producer']['sha256'],req['producer']['bytes'])
        with mock.patch.object(self.P,'TIMEOUT',0):
            with self.assertRaises(TimeoutError):self.run_worker()
        self.assertFalse(self.result.exists())

    def test_fsync_failure_rejects_result(self):
        with mock.patch.object(self.P.os,'fsync',side_effect=OSError(5,'controlled fsync EIO')):
            with self.assertRaises(OSError):self.run_worker()
        self.assertFalse(self.result.exists())

    def test_source_close_failure_never_publishes(self):
        real_close=self.P.os.close; failed=[False];source_inode=self.source.stat().st_ino
        def close_once(fd):
            selected=os.fstat(fd).st_ino == source_inode and not failed[0]
            real_close(fd)
            if selected:failed[0]=True;raise OSError(5,'controlled source close failure after actual close')
        with mock.patch.object(self.P.os,'close',side_effect=close_once):
            with self.assertRaises(OSError):self.run_worker()
        self.assertTrue(failed[0]);self.assertFalse(self.result.exists())
        # The changed output is deliberately not reusable after any failure.

    def test_source_lease_unlock_failure_never_publishes(self):
        real=self.P.fcntl.fcntl;failed=[False];source_inode=self.source.stat().st_ino
        def unlock_once(fd,op,arg=None):
            selected=op == self.P.fcntl.F_SETLEASE and arg == self.P.fcntl.F_UNLCK and os.fstat(fd).st_ino == source_inode and not failed[0]
            value=real(fd,op,arg) if arg is not None else real(fd,op)
            if selected:failed[0]=True;raise OSError(5,'controlled source unlock failure after actual unlock')
            return value
        with mock.patch.object(self.P.fcntl,'fcntl',side_effect=unlock_once):
            with self.assertRaises(OSError):self.run_worker()
        self.assertTrue(failed[0]);self.assertFalse(self.result.exists())

    def test_duplicate_request_key_refuses_before_payload_write(self):
        req,request_sha=self.make_request()
        raw=self.request.read_bytes().rstrip()[:-1]+b',"member":"SHZDOS/DISK.IMG"}\n'
        self.request.write_bytes(raw);request_sha=hashlib.sha256(raw).hexdigest()
        before=B.file_sha(self.esp)
        capacity=shutil._ntuple_diskusage(64<<30,0,64<<30)
        with mock.patch.object(self.P.shutil,'disk_usage',return_value=capacity):
            with self.assertRaises(ValueError):self.P.prepare(self.request,request_sha,self.result,req['producer']['sha256'],req['producer']['bytes'])
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_existing_source_writer_or_esp_reader_refuses_actual_lease(self):
        for path,flags in ((self.source,os.O_WRONLY),(self.esp,os.O_RDONLY)):
            fd=os.open(path,flags)
            try:
                with self.assertRaises(OSError):self.run_worker()
            finally:os.close(fd)
            self.assertFalse(self.result.exists())

    def test_actual_source_lease_break_refuses_result_and_source_stays_same(self):
        real_read=self.P.os.pread;writer=[None];triggered=[False]
        def trigger(fd,count,at):
            if os.fstat(fd).st_ino == self.source.stat().st_ino and not triggered[0]:
                triggered[0]=True
                writer[0]=subprocess.Popen([os.sys.executable,'-c','import os,sys;fd=os.open(sys.argv[1],os.O_WRONLY);os.close(fd)',str(self.source)])
                time.sleep(0.05)
            return real_read(fd,count,at)
        try:
            with mock.patch.object(self.P.os,'pread',side_effect=trigger):
                with self.assertRaises(ValueError):self.run_worker()
        finally:
            if writer[0] is not None:
                if writer[0].poll() is None:writer[0].kill()
                writer[0].wait(timeout=2)
        self.assertTrue(triggered[0]);self.assertFalse(self.result.exists());self.assertEqual(B.file_sha(self.source),self.pin)

    def test_source_pin_and_unexpected_eof_refuse_before_writes(self):
        req,request_sha=self.make_request();req['source']['sha256']='0'*64
        raw=json.dumps(req).encode();self.request.write_bytes(raw)
        before=B.file_sha(self.esp)
        capacity=shutil._ntuple_diskusage(64<<30,0,64<<30)
        with mock.patch.object(self.P.shutil,'disk_usage',return_value=capacity):
            with self.assertRaisesRegex(ValueError,'source SHA'):self.P.prepare(self.request,hashlib.sha256(raw).hexdigest(),self.result,req['producer']['sha256'],req['producer']['bytes'])
        real_read=self.P.os.pread
        def eof(fd,count,at):return b'' if os.fstat(fd).st_ino == self.source.stat().st_ino else real_read(fd,count,at)
        with mock.patch.object(self.P.os,'pread',side_effect=eof):
            with self.assertRaisesRegex(ValueError,'EOF'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_contiguous_zero_regions_have_bounded_real_source_reads(self):
        self.source.write_bytes(bytes(3<<20));inode=self.source.stat().st_ino
        real_read=self.P.os.pread;calls=[0]
        def counted(fd,count,at):
            if os.fstat(fd).st_ino == inode:calls[0]+=1
            return real_read(fd,count,at)
        with mock.patch.object(self.P.os,'pread',side_effect=counted):result=self.run_worker()
        self.assertEqual(result['member']['zero_bytes_omitted'],3<<20)
        self.assertLess(calls[0],64,'contiguous zero data must not cause a source syscall per FAT cluster')

    def test_duplicate_disk_refuses_before_payload(self):
        subprocess.run(['mcopy','-i',str(self.esp),str(self.loader),'::/SHZDOS/DISK.IMG'],check=True,timeout=30)
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'already exists'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before)

    def test_full_short_directory_preserves_its_last_terminator(self):
        boot,reserved,fats=self.fat_layout();root=struct.unpack_from('<I',boot,44)[0]
        root_at=(reserved+2*fats+(root-2)*boot[13])*512
        with self.esp.open('rb') as stream:stream.seek(root_at);rows=stream.read(boot[13]*512)
        shzdos=next(rows[i:i+32] for i in range(0,len(rows),32) if rows[i:i+11] == b'SHZDOS     ')
        cluster=struct.unpack_from('<H',shzdos,26)[0]|struct.unpack_from('<H',shzdos,20)[0]<<16
        at=(reserved+2*fats+(cluster-2)*boot[13])*512
        for number in range(2,boot[13]*16-1):
            row=bytearray(32);row[:11]=(f'F{number:07d}'.encode()+b'BIN');row[11]=0x20
            self.edit(at+number*32,row)
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'spare zero entry'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_insufficient_free_clusters_preserve_existing_members(self):
        for number in range(13):
            subprocess.run(['mcopy','-i',str(self.esp),str(self.source),f'::/FILL{number:02d}.BIN'],check=True,timeout=30)
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'capacity insufficient'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_cyclic_root_chain_refuses_before_payload(self):
        boot,reserved,fats=self.fat_layout();root=struct.unpack_from('<I',boot,44)[0]
        for copy in range(2):self.edit((reserved+copy*fats)*512+root*4,struct.pack('<I',root))
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'cyclic'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_skipped_source_zero_requires_actual_destination_zero(self):
        self.source.write_bytes(bytes(3<<20))  # Every actually skipped range is zero.
        boot,reserved,fats=self.fat_layout()
        with self.esp.open('rb') as stream:stream.seek(reserved*512);fat=stream.read(fats*512)
        free=next(n for n in range(2,len(fat)//4) if not struct.unpack_from('<I',fat,n*4)[0]&0xfffffff)
        at=(reserved+2*fats+(free-2)*boot[13])*512
        self.edit(at,b'POISON')
        before=B.file_sha(self.esp)
        with self.assertRaisesRegex(ValueError,'not zero'):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def test_child_timeout_is_actual_reaped_and_no_insertion_result(self):
        out=self.root/'timeout';out.mkdir();before=B.file_sha(self.source)
        capacity=shutil._ntuple_diskusage(64<<30,0,64<<30);real_command=B.command
        def delayed(argv,receipt,**kwargs):
            argv=list(map(str,argv))
            if len(argv)>3 and argv[1:3]==['-B','-c']:
                self.assertEqual(kwargs['timeout'],120)
                argv[3]='import time\ntime.sleep(1)\n'+argv[3]
                kwargs['timeout']=0.02  # Exact test boundary, production remains120.
            return real_command(argv,receipt,**kwargs)
        with mock.patch.object(B,'ESP_MIB',40),mock.patch.object(B.shutil,'disk_usage',return_value=capacity),mock.patch.object(B,'command',side_effect=delayed):
            with self.assertRaises(subprocess.TimeoutExpired):B.assemble(out,{'DISK.IMG':self.source},self.loader,{'commands':[]})
        self.assertFalse((out/'disk-insertion.json').exists());self.assertEqual(B.file_sha(self.source),before)

    def test_source_name_shell_metacharacters_stays_literal_argv(self):
        old=self.source;self.source=self.root/'source $(touch SENTINEL).img';old.rename(self.source)
        esp,members,receipt=self.assemble()
        self.assertEqual(members['SHZDOS/DISK.IMG']['sha256'],self.pin)
        self.assertFalse((self.root/'SENTINEL').exists())

    def test_held_helper_bytes_execute_when_declared_path_is_replaced(self):
        helper_folder=self.root/'helper';helper_folder.mkdir()
        helper=helper_folder/'sparse_fat32.py';helper.write_bytes((HERE.parent/'sparse_fat32.py').read_bytes())
        out=self.root/'changed-helper';out.mkdir();capacity=shutil._ntuple_diskusage(64<<30,0,64<<30)
        real_command=B.command;changed=[False]
        def replace_path(argv,receipt,**kwargs):
            argv=list(map(str,argv))
            if len(argv)>3 and argv[1:3]==['-B','-c']:
                changed[0]=True;helper.rename(helper_folder/'held-old-source')
                helper.write_bytes(b"raise RuntimeError('mutable helper path was executed')\n")
                argv[3]='import shutil\nshutil.disk_usage=lambda p:shutil._ntuple_diskusage(64<<30,0,64<<30)\n'+argv[3]
            return real_command(argv,receipt,**kwargs)
        with mock.patch.object(B,'HERE',helper_folder),mock.patch.object(B,'ESP_MIB',40),mock.patch.object(B.shutil,'disk_usage',return_value=capacity),mock.patch.object(B,'command',side_effect=replace_path):
            with self.assertRaisesRegex(RuntimeError,'identity changed'):B.assemble(out,{'DISK.IMG':self.source},self.loader,{'commands':[]})
        self.assertTrue(changed[0])
        # The immutable held bytes actually inserted the member; source drift
        # still prevents parent acceptance. Path execution would fail earlier.
        B.verify_esp_member(out/'esp-win98.img','SHZDOS/DISK.IMG',self.pin,3<<20,{'commands':[]})

    def tamper_after_worker(self, esp_metadata=False):
        real_command=B.command
        def changed(argv,receipt,**kwargs):
            returned=real_command(argv,receipt,**kwargs)
            argv=list(map(str,argv))
            if '--result' in argv:
                path=Path(argv[argv.index('--result')+1]);body=json.loads(path.read_text())
                if esp_metadata:
                    esp=Path(body['esp']['path'])
                    with esp.open('r+b') as stream:stream.seek(1024);stream.write(b'CHANGED UNUSED RESERVED SECTOR')
                    body['esp']['identity']=list(B.stable(esp.stat()));body['esp']['sha256']=B.file_sha(esp)
                else:
                    body['member']['zero_bytes_omitted']+=1;body['member']['data_bytes_written']-=1
                    body['fat']['free_clusters_before']+=1;body['fat']['free_clusters_after']+=1
                path.write_text(json.dumps(body,indent=2)+'\n')
            return returned
        with mock.patch.object(B,'command',side_effect=changed):
            with self.assertRaises(ValueError):self.assemble()

    def test_post_return_accounting_tamper_cannot_self_pin(self):
        self.tamper_after_worker()

    def test_post_return_esp_metadata_and_result_rebind_cannot_self_pin(self):
        self.tamper_after_worker(True)

    def test_actual_first_terminator_cannot_be_bypassed(self):
        boot,reserved,fats=self.fat_layout();root=struct.unpack_from('<I',boot,44)[0]
        root_at=(reserved+2*fats+(root-2)*boot[13])*512
        with self.esp.open('rb') as stream:stream.seek(root_at);rows=stream.read(boot[13]*512)
        row=next(rows[i:i+32] for i in range(0,len(rows),32) if rows[i:i+11] == b'SHZDOS     ')
        cluster=struct.unpack_from('<H',row,26)[0]|struct.unpack_from('<H',row,20)[0]<<16
        at=(reserved+2*fats+(cluster-2)*boot[13])*512
        poison=bytearray(32);poison[:11]=b'HIDDEN  BIN';poison[11]=0x20
        self.edit(at+96,poison)  # Actual first terminator remains at64.
        before=B.file_sha(self.esp)
        with self.assertRaises(ValueError):self.run_worker()
        self.assertEqual(B.file_sha(self.esp),before);self.assertFalse(self.result.exists())

    def faulty_return(self, kind):
        real_command=B.command;aliases=[];clock_patch=[None];original_clock=time.monotonic
        def altered(argv,receipt,**kwargs):
            argv=list(map(str,argv))
            worker='--return-fd' in argv
            if worker and kind in ('empty','short','extra','flood'):
                ret=int(argv[-1])
                prefix='import os\n'
                if kind == 'short':prefix+=f'os.write({ret},b"{{")\n'
                if kind in ('extra','flood'):prefix+=f'os.write({ret},b"X"*{1 if kind == "extra" else 513})\n'
                if kind in ('empty','short'):prefix+='raise SystemExit(0)\n'
                argv[3]=prefix+argv[3]
            answer=real_command(argv,receipt,**kwargs)
            if worker and kind == 'unclosed':
                aliases.append(os.dup(int(argv[-1])))
                clock_patch[0]=mock.patch.object(B.time,'monotonic',side_effect=lambda:original_clock()+119.99)
                clock_patch[0].start()
            return answer
        try:
            with mock.patch.object(B,'command',side_effect=altered):
                with self.assertRaises((ValueError,TimeoutError)):self.assemble()
        finally:
            if clock_patch[0] is not None:clock_patch[0].stop()
            for fd in aliases:os.close(fd)

    def test_empty_worker_return_refuses(self):self.faulty_return('empty')
    def test_short_worker_return_refuses(self):self.faulty_return('short')
    def test_extra_worker_return_refuses(self):self.faulty_return('extra')
    def test_flood_worker_return_refuses(self):self.faulty_return('flood')
    def test_unclosed_return_writer_uses_original_remaining_deadline(self):self.faulty_return('unclosed')


if __name__ == '__main__':
    unittest.main(verbosity=2)
