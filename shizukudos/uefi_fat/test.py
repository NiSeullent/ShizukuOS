#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-only synthetic evidence, FAT reader, clock and AHCI-adapter tests.

Creates only build/ products and private temporary original images. Never
starts a VM, opens a device or accesses any Windows installation media.
"""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

import fixture
import verify as v

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'
HOST_SOURCES = tuple('shizukudos/uefi_fat/'+name for name in (
    'fixture.py','verify.py','test.py','test_qemu.py','layout.h','budget.c','budget.h','bridge.c','bridge.h')) + (
    'shizukudos/uefi_ahci/clock.c','shizukudos/uefi_ahci/layout.h',
    'shizukudos/uefi32/layout.h','drivers/ahci_native/ahci.h',
    'drivers/fat_native/fat.c','drivers/fat_native/fat.h')


def synthetic_evidence(disk):
    """Fabricated host fixture, never evidence of native or virtual execution."""
    address, payload_end, payload_bytes = 0x02020000, 0x020d0000, 32768
    last = fixture.cluster_lba(fixture.FILE_CHAIN[-1])
    p = dict.fromkeys(v.PROOF_NAMES,0)
    p.update(magic=0x54414653,size=256,version=1,stage=3,calibrated=1,ticks_per_us=2400,
             start_tsc=1000000,clock_last_tsc=1000000000,file_start_us=100,file_end_us=100000,
             pci_bdf=0xfa,abar=0x81000000,pci_original=7,pci_restored=7,sectors_low=131072,
             sector_bytes=512,dma_address=address,dma_bytes=4096,allocations=1,releases=1,
             sector_reads=1050,last_lba_low=last,destination=v.OUTPUT_ADDRESS,capacity=v.OUTPUT_BYTES,
             guard_before=v.GUARD_BEFORE,guard_after=v.GUARD_AFTER,guard_bytes=4096,guards_pass=7)
    proof = bytearray(256)
    struct.pack_into('<8I4Q28I',proof,0,*(p[key] for key in v.PROOF_NAMES))
    struct.pack_into('<4IQ14I',proof,176,80,1,0,131195,2048,129024,129024,1,126944,9,1000,1024,2,0,1,3,257,1050,0)
    dma = bytearray(4096)
    struct.pack_into('<8I',dma,0,0x10005,512,address+1280,0,0,0,0,0)
    dma[1088],dma[1090] = 0x34,0x50
    dma[1280:1283],dma[1287],dma[1292] = b'\x27\x80\x25',0x40,1
    dma[1284:1287],dma[1288:1291] = last.to_bytes(6,'little')[:3],last.to_bytes(6,'little')[3:]
    struct.pack_into('<4I',dma,1408,address+2048,0,0,511)
    dma[2048:2560] = disk[last*512:(last+1)*512]
    output = fixture.content()+b'\xa5'*(v.OUTPUT_BYTES-fixture.FILE_BYTES)
    mmio = bytearray(4096)
    for offset,value in ((0,0xc0141f05),(4,0x80000000),(12,0x3f),(16,0x10000),
                         (0x118,6),(0x120,0x50),(0x124,0x101),(0x128,0x113)):
        struct.pack_into('<I',mmio,offset,value)
    handoff = struct.pack('<28I',0x32334453,1,112,5,0x80000000,640*480*4,640,480,640,1,
                          0x02004000,48,48,1,0x02000000,0x200000,payload_bytes,0x02200000,
                          0x33,0x608,0x800,0x10,0x18,0x021ffff0,1,1,1,1)
    memory_map = struct.pack('<IIQQQQQ',1,0,0x02000000,0,512,0,0)
    registers = 'EIP=02010080 ESP=021ffff0 CR0=00000033 CR4=00000608 EFER=00000800 CS32 CPL=0 HLT=1'
    return {'proof_bytes':bytes(proof),'dma_bytes':bytes(dma),'output_bytes':output,
            'before_bytes':b'\xa5'*4096,'after_bytes':b'\xa5'*4096,'mmio_bytes':bytes(mmio),
            'expected_dma_address':address,'disk_bytes':disk,'handoff_bytes':handoff,
            'memory_map_bytes':memory_map,'registers_text':registers,
            'payload_bytes':payload_bytes,'payload_end':payload_end}


class EvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='synthetic-fat-',dir=BUILD)
        cls.path = Path(cls.directory.name)/'original.img'
        cls.receipt = fixture.create(cls.path)
        cls.disk = v.read_regular(cls.path,fixture.DISK_BYTES)
        cls.evidence = synthetic_evidence(cls.disk)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def reject(self, key, data):
        args = dict(self.evidence)
        args[key] = data
        with self.assertRaises(v.EvidenceError):
            v.verify_evidence(**args)

    def test_fixture_independent_decode(self):
        decoded = v.decode_disk(self.disk)
        self.assertEqual(decoded['file'],fixture.content())
        self.assertEqual(decoded['disk_sha256'],self.receipt['disk_sha256'])
        self.assertEqual(decoded['root_chain'],[9,71,15])
        self.assertEqual(len(decoded['file_chain']),257)
        self.assertEqual(self.path.stat().st_size,67108864)
        self.assertLess(self.path.stat().st_blocks*512,2*1024**2)

    def test_synthetic_complete_not_execution(self):
        result = v.verify_evidence(**self.evidence)
        self.assertEqual(result['file_bytes'],131195)
        self.assertEqual(result['windows_98_driver'],'not_tested')
        self.assertIs(result['file_execution'],False)

    def test_exclusive_creation_preserves_existing(self):
        with self.assertRaises(FileExistsError):
            fixture.create(self.path)
        self.assertEqual(v.digest(v.read_regular(self.path,fixture.DISK_BYTES)),self.receipt['disk_sha256'])

    def test_every_proof_success_field(self):
        # Calibrations/times/diagnostics vary legitimately; mutate required ABI,
        # ownership, geometry and status fields into definitely invalid values.
        offsets = list(range(0,20,4))+[24,64,68,76]+list(range(80,152,4))+list(range(152,256,4))
        for offset in offsets:
            with self.subTest(offset=offset):
                data = bytearray(self.evidence['proof_bytes'])
                struct.pack_into('<I',data,offset,v.u32(data,offset)^0x80000000)
                self.reject('proof_bytes',data)

    def test_clock_constraints(self):
        for offset,fmt,value in ((20,'I',9),(20,'I',100001),(28,'I',64),(32,'Q',0),
                                 (40,'Q',1),(40,'Q',100000000),(56,'Q',100),(56,'Q',5000100)):
            data = bytearray(self.evidence['proof_bytes'])
            struct.pack_into('<'+fmt,data,offset,value)
            self.reject('proof_bytes',data)

    def test_truncation_and_extra_bytes(self):
        for key in ('proof_bytes','dma_bytes','output_bytes','before_bytes','after_bytes','mmio_bytes','handoff_bytes'):
            for data in (b'',self.evidence[key][:-1],self.evidence[key]+b'\0'):
                with self.subTest(key=key,length=len(data)):
                    self.reject(key,data)

    def test_file_guard_tail_mutations(self):
        for key,offsets in (('output_bytes',(0,512,131194,131195,524287)),
                            ('before_bytes',(0,4095)),('after_bytes',(0,4095))):
            for offset in offsets:
                data = bytearray(self.evidence[key]);data[offset]^=1
                self.reject(key,data)

    def test_dma_command_lifetime_and_content(self):
        for offset in (0,4,8,12,32,1023,1088,1090,1280,1282,1284,1287,1292,1408,1412,1420,
                       1536,2047,2048,2559,2560,4095):
            data = bytearray(self.evidence['dma_bytes']);data[offset]^=1
            self.reject('dma_bytes',data)

    def test_mmio_detach_and_errors(self):
        for offset,value in ((4,0),(4,0x80000001),(4,0x80000002),(12,0),(16,0),
                             (0x100,0x2020000),(0x104,1),(0x108,0x2020400),(0x10c,1),
                             (0x110,0x40000000),(0x114,1),(0x118,1),(0x118,16),(0x118,0x4000),
                             (0x118,0x8000),(0x120,1),(0x124,0xeb140101),(0x128,0),(0x130,1),
                             (0x134,1),(0x138,1)):
            data = bytearray(self.evidence['mmio_bytes']);struct.pack_into('<I',data,offset,value)
            self.reject('mmio_bytes',data)

    def test_geometry_mirror_chain_and_data_mutations(self):
        offsets = [510,446,450,454,462,2048*512+11,2048*512+36,2048*512+44,
                   (2048+32)*512+9*4,(2048+32+1024)*512+1000*4,
                   fixture.cluster_lba(71)*512+160,
                   fixture.cluster_lba(fixture.FILE_CHAIN[100])*512+7,100*512+123]
        for offset in offsets:
            data = bytearray(self.disk);data[offset]^=1
            with self.subTest(offset=offset),self.assertRaises(v.EvidenceError):
                v.decode_disk(data)
        for length in (0,fixture.DISK_BYTES-1,fixture.DISK_BYTES+1):
            with self.assertRaises(v.EvidenceError):
                v.decode_disk(self.disk[:length] if length <= fixture.DISK_BYTES else self.disk+b'\0')

    def test_map_and_registers(self):
        for offset,value in ((0,7),(8,0x2010000),(24,511),(32,1<<63)):
            data = bytearray(self.evidence['memory_map_bytes'])
            struct.pack_into('<Q' if offset in (8,24,32) else '<I',data,offset,value)
            self.reject('memory_map_bytes',data)
        self.reject('memory_map_bytes',self.evidence['memory_map_bytes'][:-1])
        for source,target in (('CPL=0','CPL=3'),('CS32','CS64'),('HLT=1','HLT=0'),
                              ('CR0=00000033','CR0=80000033'),('EIP=02010080','EIP=02100000'),
                              ('ESP=021ffff0','ESP=02180000')):
            self.reject('registers_text',self.evidence['registers_text'].replace(source,target))
        self.reject('registers_text',self.evidence['registers_text']+' EIP=02010080')

    def test_safe_regular_capture(self):
        directory = Path(self.directory.name)
        link = directory/'link';link.symlink_to(self.path)
        for path,limit in ((link,fixture.DISK_BYTES),(self.path,512),(directory,1024)):
            with self.assertRaises((v.EvidenceError,OSError)):
                v.read_regular(path,limit)
        fifo = directory/'fifo';os.mkfifo(fifo)
        with self.assertRaises(v.EvidenceError):
            v.read_regular(fifo,32)
        parent = directory/'parent';parent.symlink_to(directory,target_is_directory=True)
        with self.assertRaises(v.EvidenceError):
            v.read_regular(parent/'original.img',fixture.DISK_BYTES)

    def test_json_duplicate_and_nonfinite(self):
        for data in (b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":Infinity}',b'[]',b'{}x',b'\xff'):
            with self.assertRaises(v.EvidenceError):
                v.parse_json(data)

    def test_pci_inventory(self):
        controller = {'bus':0,'slot':31,'function':2,'id':{'vendor':0x8086,'device':0x2922},
                      'class_info':{'class':0x106},'regions':[{'bar':5,'type':'memory','size':4096,
                      'mem_type_64':False,'prefetch':False,'address':0x81000000}]}
        proof = v.decode_proof(self.evidence['proof_bytes'])
        inventory = [{'bus':0,'devices':[controller]}]
        self.assertEqual(v.verify_pci(inventory,proof)['bdf'],0xfa)
        for key,value in (('size',8192),('address',0x81001000),('mem_type_64',True),('type','io')):
            altered = copy.deepcopy(inventory);altered[0]['devices'][0]['regions'][0][key]=value
            with self.assertRaises(v.EvidenceError):v.verify_pci(altered,proof)
        with self.assertRaises(v.EvidenceError):v.verify_pci([{'bus':0,'devices':[controller,controller]}],proof)

    def test_guest_command_is_exact(self):
        import test_qemu as harness
        directory = Path(self.directory.name)
        command = harness.command_for(directory)
        self.assertEqual(harness.verify_command(command,directory),'/usr/share/edk2/ovmf/OVMF_CODE.fd')
        for suffix in (',readonly=off',',file=/other','\n'):
            altered = command[:];altered[22] += suffix
            with self.assertRaises(v.EvidenceError):harness.verify_command(altered,directory)
        for old,new in (('256M','512M'),('kvm','tcg'),('none','user'),
                        ('ide-hd,drive=sata,bus=ide.0','usb-storage,drive=sata')):
            altered = [new if item == old else item for item in command]
            with self.assertRaises(v.EvidenceError):harness.verify_command(altered,directory)
        with self.assertRaises(v.EvidenceError):harness.verify_command(command+['-usb'],directory)
        altered = command[:];altered[30]=altered[30].replace('readonly=off','readonly=on')
        with self.assertRaises(v.EvidenceError):harness.verify_command(altered,directory)
        with self.assertRaises(v.EvidenceError):harness.command_for(directory/'bad,name')

    def test_cleanup_preserves_initiating_failure(self):
        import test_qemu as harness
        result = {'pass':True}
        harness.record_failure(result,RuntimeError('initial command mismatch'),'execution')
        harness.record_failure(result,RuntimeError('unclean shutdown'),'cleanup')
        self.assertIs(result['pass'],False)
        self.assertEqual(result['error'],'initial command mismatch')
        self.assertEqual(result['errors'],[
            {'stage':'execution','message':'initial command mismatch'},
            {'stage':'cleanup','message':'unclean shutdown'}])
        result = {'pass':True}
        harness.record_failure(result,RuntimeError('bad saved capture'),'saved_evidence')
        self.assertEqual(result['error'],'bad saved capture')
        self.assertIs(result['pass'],False)

    def test_source_receipt_sets(self):
        import test_qemu as harness
        self.assertEqual(set(HOST_SOURCES),harness.HOST_SOURCES)
        source = {'a.c':'a'*64,'b.h':'b'*64}
        self.assertEqual(harness.hashes(source,source,'prefix/'),{'prefix/'+key:value for key,value in source.items()})
        for wrong in ({'a.c':'a'*64},{**source,'unexpected.c':'c'*64},{'a.c':True,'b.h':'b'*64}):
            with self.assertRaises(v.EvidenceError):harness.hashes(wrong,source)

    def test_qmp_block_ownership(self):
        import test_qemu as harness
        directory = Path(self.directory.name);firmware='/firmware.fd'
        specs = [(firmware,True),(str(directory/'OVMF_VARS.fd'),False),
                 (str(directory/'esp.img'),True),(str(directory/'synthetic-fat.img'),False)]
        blocks = [{'inserted':{'file':name,'ro':ro,'drv':'raw'}} for name,ro in specs]
        harness.verify_blocks(blocks,directory,firmware)
        for index in (0,2,3):
            changed = copy.deepcopy(blocks);changed[index]['inserted']['ro']=not changed[index]['inserted']['ro']
            with self.assertRaises(v.EvidenceError):harness.verify_blocks(changed,directory,firmware)
        for changed in (blocks[:-1],blocks+[blocks[0]],blocks[:3]+[blocks[0]]):
            with self.assertRaises(v.EvidenceError):harness.verify_blocks(changed,directory,firmware)

    def test_compatibility_guest_names(self):
        import test_qemu as harness
        for executable in ('/usr/libexec/qemu-kvm','/usr/bin/qemu-system-x86_64',
                           '/usr/bin/qemu-system-i386','/usr/bin/kvm'):
            for name in ('win98-modern-private-install','win98-modern-private-resume',
                         'zuku-compat-win98','zuku-compat-me','ntw-fat-fixture',
                         'ntw-ahci-fixture','ntw-xhci-fixture-usbconfig','ntw-uefi32'):
                for encoded in (name,'guest='+name+',debug-threads=on'):
                    command = (executable+'\0-name\0'+encoded+'\0').encode()
                    with self.subTest(executable=executable,name=encoded):
                        self.assertTrue(harness.compatibility_guest(command))
            for name in ('vm-zuku','win11-dev','unrelated-domain'):
                for encoded in (name,'guest='+name+',debug-threads=on'):
                    self.assertFalse(harness.compatibility_guest((executable+'\0-name\0'+encoded+'\0').encode()))
        self.assertTrue(harness.compatibility_guest(b'qemu-kvm\0-name=guest=ntw-fat-fixture\0'))

    def test_compatibility_unnamed_owned_media(self):
        import test_qemu as harness
        for folder in ('uefi','uefi32','uefi_ahci','uefi_xhci','uefi_usb','uefi_usb_config','uefi_fat'):
            image = str(ROOT/'shizukudos'/folder/'build/fixture/esp.img')
            for argument in ('file='+image+',format=raw',image,
                             '{"driver":"file","filename":"'+image+'"}'):
                self.assertTrue(harness.compatibility_guest(('qemu-kvm\0-drive\0'+argument+'\0').encode()))
        other = str(ROOT/'shizukudos-archive/production.img')
        self.assertFalse(harness.compatibility_guest(('qemu-kvm\0-drive\0file='+other+'\0').encode()))
        self.assertFalse(harness.compatibility_guest(b'qemu-kvm\0-drive\0file=/var/lib/libvirt/images/vm-zuku.qcow2\0'))

    def test_compatibility_executable_not_shell_text(self):
        import test_qemu as harness
        for executable in ('/bin/bash','python3','qemu-img','qemu-nbd','my-qemu-kvm-wrapper',
                           'qemu-system-x86_64-debug.txt'):
            command = (executable+'\0-c\0qemu-kvm -name ntw-fat-fixture\0-name\0ntw-fat-fixture\0').encode()
            self.assertFalse(harness.compatibility_guest(command))
        self.assertFalse(harness.compatibility_guest(b''))

    def test_process_scan_scopes_and_vanished(self):
        import test_qemu as harness
        with tempfile.TemporaryDirectory(prefix='fake-proc-',dir=BUILD) as directory:
            proc = Path(directory)
            for pid,command in ((100,b'qemu-kvm\0-name\0vm-zuku\0'),
                                (101,b'qemu-system-x86_64\0-name\0guest=win11-dev\0'),
                                (102,b'bash\0-c\0qemu-kvm -name ntw-fat-fixture\0'),(103,b'')):
                (proc/str(pid)).mkdir();(proc/str(pid)/'cmdline').write_bytes(command)
            (proc/'104').mkdir()  # cmdline vanished before opening it
            (proc/'self').mkdir()  # only numeric process directories are inspected
            harness.check_compatibility_lane(proc)
            (proc/'101/cmdline').write_bytes(b'qemu-system-x86_64\0-name\0ntw-fat-fixture\0')
            with self.assertRaisesRegex(RuntimeError,'compatibility QA'):
                harness.check_compatibility_lane(proc)
            (proc/'101/cmdline').write_bytes(b'qemu-system-x86_64\0-name\0win11-dev\0')
            def gone(path):
                if path.parent.name == '104':raise ProcessLookupError('synthetic vanished process')
                return path.read_bytes()
            harness.check_compatibility_lane(proc,read_cmdline=gone)

    def test_process_scan_unreadable_fails_closed(self):
        import test_qemu as harness
        with tempfile.TemporaryDirectory(prefix='fake-proc-',dir=BUILD) as directory:
            proc = Path(directory);(proc/'100').mkdir()
            for error in (PermissionError('synthetic denied'),OSError('synthetic I/O error')):
                def unreadable(path):
                    raise error
                with self.assertRaisesRegex(RuntimeError,'Cannot inspect process 100'):
                    harness.check_compatibility_lane(proc,read_cmdline=unreadable)
            for value in ('not bytes',b'x'*(1024**2+1)):
                with self.assertRaisesRegex(RuntimeError,'Invalid process command'):
                    harness.check_compatibility_lane(proc,read_cmdline=lambda path:value)
            with self.assertRaisesRegex(RuntimeError,'Cannot inspect process directory'):
                harness.check_compatibility_lane(proc/'missing-proc')

    def test_headroom_reserves_full_fixture_and_capture_allowance(self):
        import test_qemu as harness
        memory = (6*1024+512)*1024**2
        disk = 20*1024**3+128*1024**2
        with mock.patch.object(harness,'check_compatibility_lane') as lane:
            for available,free,passes in ((memory,disk,True),(memory-1024,disk,False),(memory,disk-1,False)):
                with mock.patch.object(Path,'read_text',return_value='MemAvailable: '+str(available//1024)+' kB\n'), \
                     mock.patch.object(harness.shutil,'disk_usage',return_value=type('Usage',(),{'free':free})()):
                    if passes:harness.headroom()
                    else:
                        with self.assertRaises(RuntimeError):harness.headroom()
            self.assertEqual(lane.call_count,3)


HOST_C = r'''
/* Original generated host glue; synthetic disk and bounded stub only. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bridge.h"
static unsigned checks, reads, calls;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"line %d\n",__LINE__); exit(1); } } while (0)
static unsigned char *image;
static struct ntwf_workspace workspace;
static unsigned char output[524288];
static struct ntwf_file_info info;
static uint64_t ticks, step;
static int stub_result;
static uint64_t stub_lba;
static uint64_t tick(void *unused) { (void)unused; uint64_t now=ticks; ticks+=step; return now; }
int ahci_read_sector(struct ahci_device *device,uint64_t lba,void *out,size_t bytes) {
    CHECK(device!=NULL && out!=NULL && bytes==512);++calls;stub_lba=lba;memset(out,0x42,512);return stub_result;
}
static int now(void *unused,uint64_t *out) { (void)unused;*out=ticks++;return 0; }
static int read_sector(void *unused,uint64_t lba,uint8_t out[512],uint32_t remaining) {
    (void)unused;CHECK(lba<131072 && remaining>0 && remaining<=5000000);++reads;
    memcpy(out,image+(size_t)lba*512,512);return 0;
}
static void bridge_cases(void) {
    struct ahci_device disk={0}; SDFAT_PROOF proof={0}; uint8_t sector[512];
    struct sdfat_binding b={&disk,&proof,{100,100,0,10,0,0},tick,NULL};
    ticks=110;step=10;calls=0;stub_result=0;
    CHECK(sdfat_read_sector(&b,UINT64_C(0x100000123),sector,1199999)!=0);
    CHECK(calls==0 && proof.read_refusals==1 && proof.sector_reads==0);
    CHECK(sdfat_read_sector(&b,UINT64_C(0x100000123),sector,1200000)==0);
    CHECK(calls==1 && proof.sector_reads==1 && stub_lba==UINT64_C(0x100000123));
    CHECK(proof.last_lba_high==1 && proof.last_lba_low==0x123 && sector[0]==0x42);
    stub_result=AHCI_IO;CHECK(sdfat_read_sector(&b,3,sector,1200000)!=0);
    CHECK(proof.read_result==(uint32_t)AHCI_IO);stub_result=0;
    ticks=b.clock.last_tsc-1;CHECK(sdfat_read_sector(&b,4,sector,1200000)!=0);
    CHECK(calls==2 && proof.clock_fault==SDFAT_CLOCK_BACKWARDS);
    uint64_t previous=b.clock.last_us;CHECK(sdfat_ahci_now(&b)==previous);
    b.clock=(struct sdfat_clock){100,100,0,10,0,0};ticks=110;step=12000000;
    CHECK(sdfat_read_sector(&b,5,sector,1200000)!=0 && proof.read_overruns==1);
    b.clock=(struct sdfat_clock){100,100,0,10,0,0};ticks=110;step=11999990;
    CHECK(sdfat_read_sector(&b,6,sector,1200000)==0);
    b.clock=(struct sdfat_clock){100,100,0,10,62,0};ticks=100;step=0;
    CHECK(sdfat_read_sector(&b,7,sector,1200000)!=0 && proof.clock_fault==SDFAT_CLOCK_STALLED);
    CHECK(proof.read_result==0); /* successful ATA call never masks failed post-clock */
    b.clock=(struct sdfat_clock){100,100,0,10,0,0};ticks=UINT64_MAX;step=1;
    CHECK(sdfat_read_sector(&b,8,sector,1200000)!=0 && proof.clock_fault==SDFAT_CLOCK_BACKWARDS);
    CHECK(sdfat_read_sector(NULL,0,sector,1200000)!=0);
    CHECK(sdfat_read_sector(&b,0,NULL,1200000)!=0);
}
static void clock_cases(void) {
    uint64_t value, expected, state=UINT64_C(0x8736412154329911);
    struct sdfat_clock clock={10,10,0,10,0,0};
    for(unsigned i=0;i<63;++i)CHECK(sdfat_clock_sample(&clock,10,&value)==0 && value==0);
    value=0xfeed;CHECK(sdfat_clock_sample(&clock,10,&value)!=0 && value==0xfeed);
    CHECK(clock.fault==SDFAT_CLOCK_STALLED && sdfat_clock_sample(&clock,1000,&value)!=0);
    for(unsigned i=0;i<10000;++i) {
        state^=state<<13;state^=state>>7;state^=state<<17;
        uint32_t divisor=10+(uint32_t)(state%99991);
        clock=(struct sdfat_clock){0,0,0,divisor,0,0};expected=state/divisor;
        CHECK(sdfat_clock_sample(&clock,state,&value)==0 && value==expected);
    }
    clock=(struct sdfat_clock){10,10,0,9,0,0};value=55;
    CHECK(sdfat_clock_sample(&clock,20,&value)!=0 && value==55 && clock.fault==SDFAT_CLOCK_INVALID);
    clock=(struct sdfat_clock){10,10,0,100001,0,0};CHECK(sdfat_clock_sample(&clock,20,&value)!=0);
    clock=(struct sdfat_clock){10,9,0,10,0,0};CHECK(sdfat_clock_sample(&clock,20,&value)!=0);
    CHECK(sdfat_clock_sample(NULL,20,&value)!=0 && sdfat_clock_sample(&clock,20,NULL)!=0);
    clock=(struct sdfat_clock){10,10,0,10,0,0};
    CHECK(sdfat_clock_sample(&clock,11,&value)==0 && value==0 && clock.stagnant==0);
}
int main(int argc,char **argv) {
    CHECK(argc==2);FILE *file=fopen(argv[1],"rb");CHECK(file!=NULL);
    image=malloc(67108864);CHECK(image!=NULL);CHECK(fread(image,1,67108864,file)==67108864);CHECK(fclose(file)==0);
    struct ntwf_io io={sizeof(io),NTWF_ABI_VERSION,512,0,131072,NULL,read_sector,now};
    struct ntwf_request request={sizeof(request),NTWF_ABI_VERSION,0,8192,5000000,0,
        {'N','T','W','B','O','O','T',' ','B','I','N'},0};
    memset(output,0xa5,sizeof(output));memset(&info,0x7e,sizeof(info));ticks=0;reads=0;
    CHECK(ntwf_read_root83(&io,&request,&workspace,output,sizeof(output),&info)==NTWF_OK);
    CHECK(info.file_bytes==131195 && info.root_cluster==9 && info.root_clusters==3 && info.file_clusters==257);
    CHECK(info.partition_lba==2048 && info.cluster_count==126944 && info.sector_reads==reads);
    for(size_t i=0;i<sizeof(output);++i) {
        uint8_t expected=i<131195?(uint8_t)(((i*29+(i/251)*7+83)^((i>>8)&255))&255):0xa5;
        CHECK(output[i]==expected);
    }
    struct ntwf_file_info saved=info;
    image[(2048+32+1024)*512+9*4]^=1;
    CHECK(ntwf_read_root83(&io,&request,&workspace,output,sizeof(output),&info)==NTWF_CORRUPT);
    CHECK(memcmp(&info,&saved,sizeof(info))==0);image[(2048+32+1024)*512+9*4]^=1;
    CHECK(ntwf_read_root83(&io,&request,&workspace,output,131194,&info)==NTWF_LIMIT);
    CHECK(memcmp(&info,&saved,sizeof(info))==0);
    for(size_t i=0;i<sizeof(output);++i) {
        uint8_t expected=i<131195?(uint8_t)(((i*29+(i/251)*7+83)^((i>>8)&255))&255):0xa5;
        CHECK(output[i]==expected);
    }
    clock_cases();bridge_cases();free(image);
    printf("{\"status\":\"PASS\",\"checks\":%u,\"synthetic_sector_reads\":%u,\"bridge_calls\":%u}\n",checks,reads,calls);
    return 0;
}
'''


def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD/'host-tests.json'
    receipt.unlink(missing_ok=True)
    before = {name:v.digest(v.read_regular(ROOT/name,8*1024**2)) for name in HOST_SOURCES}
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(EvidenceTests)
    tested = unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    log = BUILD/'host-tests.log';log.write_text(stream.getvalue())
    if not tested.wasSuccessful():
        raise RuntimeError(stream.getvalue())
    variants = {}
    with tempfile.TemporaryDirectory(prefix='synthetic-host-',dir=BUILD) as directory:
        image = Path(directory)/'original.img';fixture.create(image)
        source = BUILD/'host_glue.c';source.write_text(HOST_C)
        for name,compiler,extra in (('gcc','gcc',[]),('clang','clang',[]),
                ('asan_ubsan','clang',['-fsanitize=address,undefined','-fno-sanitize-recover=all','-fno-omit-frame-pointer'])):
            executable = BUILD/('test-'+name)
            command = [compiler,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wpedantic',*extra,
                       '-I',str(HERE),str(source),str(HERE/'budget.c'),str(HERE/'bridge.c'),
                       str(HERE.parent/'uefi_ahci/clock.c'),str(ROOT/'drivers/fat_native/fat.c'),'-o',str(executable)]
            compiled = subprocess.run(command,capture_output=True,text=True,timeout=60)
            if compiled.returncode:
                raise RuntimeError('Host compile failed: '+compiled.stdout+compiled.stderr)
            result = subprocess.run([executable,image],capture_output=True,text=True,timeout=60,check=True)
            if result.stderr:
                raise RuntimeError('Unexpected sanitizer/host diagnostics: '+result.stderr)
            counts = v.parse_json(result.stdout)
            if counts.get('status') != 'PASS' or counts.get('checks',0) < 1000000 or counts.get('bridge_calls') != 6:
                raise RuntimeError('Incomplete host bridge/fixture test: '+result.stdout)
            variant_log = BUILD/(name+'.log')
            variant_log.write_text(' '.join(command)+'\n'+compiled.stdout+compiled.stderr+result.stdout)
            variants[name] = {'passed':True,**counts,'log_sha256':v.digest(variant_log.read_bytes())}
    if any(v.digest(v.read_regular(ROOT/name,8*1024**2)) != expected for name,expected in before.items()):
        raise RuntimeError('FAT integration host inputs changed while testing')
    receipt.write_text(json.dumps({'schema':'shizukudos.uefi_fat.host.v1','passed':True,
        'sources_sha256':before,'evidence_tests':tested.testsRun,'variants':variants,
        'log_sha256':v.digest(log.read_bytes()),'fixture_kind':'synthetic original bytes only',
        'guest_executed':False,'native_windows':False},indent=2)+'\n')
    print(stream.getvalue(),end='')
    print(json.dumps(variants,indent=2))


if __name__ == '__main__':
    main()
