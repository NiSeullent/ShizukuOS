# SPDX-License-Identifier: GPL-2.0-only
"""Real sealed policies/read leases and tiny modeled producer files; no guest."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO=Path(__file__).resolve().parents[4]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
    sys.modules[name]=module;spec.loader.exec_module(module);return module
r=load('nonce_replacement',REPO/'shizukudos/win98_boot/prepare_replacement.py')
epoch=load('nonce_epoch',REPO/'shizukudos/supervisor/native_win98/native_epoch_host.py')
stage=load('nonce_staging',REPO/'shizukudos/supervisor/native_win98/gop_nonce_staging.py')

class NonceStaging(unittest.TestCase):
    def setUp(self):
        (REPO/'build').mkdir(exist_ok=True)
        self.temp=tempfile.TemporaryDirectory(dir=REPO/'build');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
    def file(self,name,raw):
        p=self.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw);p.chmod(0o600)
        return r.local_pin(p)
    def json(self,name,obj):return self.file(name,json.dumps(obj).encode())
    def test_invalid_preparation_intent_refuses_before_loading_or_writing(self):
        intent={'schema':'shizukuos.native-custody-gop-intent.v1','repo':str(REPO),'sources':{},'limits':{},'timeout':20,
                'gop':{'live_stage':{},'firstload_build':{}},'cohort_producers':{'gop_stage':[{}]*3,'caller_stage':[{}]*5,'nonce_stage':[{}]*3},
                'launch_profile':{},'producers':[{},{}],
                'native_inputs':{n:{} for n in ('SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG')},
                'optional_native_inputs':{n:{} for n in ('VGACFG.BIN','VGAROM.BIN','W98PERS.BIN')},
                'optional_native_provenance':{'vga-build-receipt':{}},'raw_bars':{'1':[0]*6,'2':[0]*6},
                'firmware':{n:{} for n in ('firmware_code','firmware_vars','qemu')},'private_root':str(self.root),'assembly_scratch':None}
        cust=mock.Mock();cust.admitted_module.side_effect=AssertionError('invalid input reached source execution')
        cases=[('timeout',True),('timeout',901),('raw_bars',{'1':[True]*6,'2':[0]*6}),
               ('raw_bars',{'1':[0]*5,'2':[0]*6}),('cohort_producers',{}),('producers',[]),
               ('optional_native_provenance',{}),('assembly_scratch',True)]
        for field,value in cases:
            altered=copy.deepcopy(intent);altered[field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):
                stage.prepare_intent(cust,altered,mock.Mock(),{},lambda:None)
        cust.admitted_module.assert_not_called()
        self.assertEqual(list(self.root.iterdir()),[])

    def inputs(self):
        rom=b'R'*65536;vga=struct.pack('<6I2Q',0x41475657,1,136,1,16,0,0xe0000000,16<<20)
        vga+=hashlib.sha256(rom).digest()+b's'*32+b'c'*32
        return self.file('vga.bin',vga),self.file('rom.bin',rom)
    def attempt(self,held,pins):
        return epoch.Attempt(*(epoch.PinnedFD(held[p['path']]['fd'],p) for p in pins),None,
              {1:(0xe0000008,0,0,0,0,0)},time.monotonic_ns()+60_000_000_000)
    def fixture(self):
        def executable(magic):
            raw=bytearray(80);raw[:2]=b'MZ';struct.pack_into('<I',raw,60,64);raw[64:66]=magic;return bytes(raw)
        self.profile={'schema':'shizukuos.private-replacement-profile.v1','disk':self.file('original.img',b'O'*1024),
          'boot_template':{},'freedos_source':'/unused','build_receipt':{},'build_source_root':'/unused',
          'payloads':[{'guest':n,'file':self.file('roots/'+n,executable(b'LE') if n=='SHZGOP.VXD' else n.encode())}
                      for n in sorted(stage.BASE)]}
        profile_pin=self.json('profile.json',self.profile)
        gop_pin=self.json('gop-stage.json',{'gop_receipt':{'sha256':'1'*64},'live_provider_identity_sha256':'2'*64})
        producer=[self.file('producer/'+str(i),b'source') for i in range(5)]
        live={'schema':'shizukuos.private-live-gop-stage.v1','status':'PRIVATE_CALLER_REQUEST_STAGED_NOT_EXECUTED',
          'constructor_profile':profile_pin,'source_gop_profile':gop_pin,'producer_inputs':producer,
          'live_provider_identity_sha256':'2'*64,'guardian_epoch_query_opcode':'0x4f11',
          'guardian_epoch_query_bytes':160,'guardian_epoch_HCALL':14}
        for n in ('public_artifact','VM_executed','default_GOP_registered','GPU_active','Windows98_boot_verified','Supervisor_epoch_verified'):live[n]=False
        sources={}
        for name in stage.FIRSTLOAD_SOURCES:
            raw=(REPO/name).read_bytes();sources[name]=hashlib.sha256(raw).hexdigest()
            self.file('first/source/'+name,raw)
        provider=hashlib.sha256()
        for name in sorted(sources):
            raw=(REPO/name).read_bytes();provider.update(name.encode()+b'\0'+len(raw).to_bytes(8,'little')+raw)
        target=next(p['file'] for p in self.profile['payloads'] if p['guest']=='SHZGOP.VXD')
        guard_raw=executable(b'LE')+provider.digest()
        artifacts={'SHZGUARD.VXD':self.file('first/SHZGUARD.VXD',guard_raw),
                   'GOPLOAD.EXE':self.file('first/GOPLOAD.EXE',executable(b'PE')+guard_raw+Path(target['path']).read_bytes()+provider.digest())}
        first={'status':'PASS_SOURCE_BUILD_NOT_EXECUTED','sources_sha256':sources,
          'tools':{n:{k:v for k,v in self.file('tools/'+n,b'tool').items() if k!='bytes'}
                   for n in ('nasm','clang','ld','i686-w64-mingw32-gcc')},
          'artifacts':{n:{k:v for k,v in p.items() if k!='path'} for n,p in artifacts.items()},
          'provider_identity_sha256':provider.hexdigest(),'gop_receipt_sha256':'1'*64,'gop_provider_identity_sha256':'2'*64,'gop_vxd_sha256':target['sha256'],
          'guest_executed':False,'default_changed':False,'mode_changed':False,'gpu_active_verified':False}
        return self.json('live.json',live),self.json('first/build-result.json',first)
    def test_real_sealed_attempt_nonce_staged_once_before_exec(self):
        pins=self.inputs();live,first=self.fixture()
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            try:
                with mock.patch.object(r,'capacity'):
                    result=stage.stage(attempt,epoch,r,held,live,first,REPO,self.root/'out',lambda:None,1<<20)
                self.assertEqual((self.root/'out/GPEPOCH.NON').read_bytes(),attempt.nonce)
                self.assertEqual(result['nonce_sha256'],hashlib.sha256(attempt.policy[16:48]).hexdigest())
                derived=json.loads((self.root/'out/replacement-profile.json').read_bytes())
                self.assertEqual(r.payload_names(derived['payloads']),r.GOP_ROOT|r.GOP_NESTED)
                self.assertFalse(result['HostGrant_transmitted']);self.assertFalse(result['VM_executed'])
                with self.assertRaises(ValueError):attempt.reserve_staging()
            finally:attempt.close()
    def test_saved_json_or_other_class_not_live_attempt(self):
        with self.assertRaises(ValueError):stage.stage({'nonce':b'N'*32},epoch,r,{}, {},{},self.root,self.root/'out',lambda:None,1<<20)
        self.assertFalse((self.root/'out').exists())
    def test_attempt_fork_identity_and_mutable_nonce_refused(self):
        pins=self.inputs()
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            try:
                with mock.patch.object(epoch.os,'getpid',return_value=os.getpid()+1):
                    with self.assertRaises(ValueError):attempt.reserve_staging()
                attempt.nonce=b'X'*32
                with self.assertRaises(ValueError):attempt.reserve_staging()
            finally:attempt.close()
    def test_cancel_after_write_revokes_constructor_receipts(self):
        pins=self.inputs();live,first=self.fixture()
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            def guard():
                if (self.root/'out/GPEPOCH.NON').exists():raise RuntimeError('canceled')
            try:
                with mock.patch.object(r,'capacity'),self.assertRaises(RuntimeError):
                    stage.stage(attempt,epoch,r,held,live,first,REPO,self.root/'out',guard,1<<20)
                self.assertFalse((self.root/'out/replacement-profile.json').exists())
                self.assertFalse((self.root/'out/stage-result.json').exists())
                with self.assertRaises(ValueError):attempt.reserve_staging()
            finally:attempt.close()
    def test_attempt_already_child_bound_cannot_stage_clone(self):
        pins=self.inputs()
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            try:
                attempt.owner=object()
                with self.assertRaises(ValueError):attempt.reserve_staging()
            finally:attempt.owner=None;attempt.close()
    def test_captured_firstload_source_drift_refused_before_write(self):
        pins=self.inputs();live,first=self.fixture()
        source=self.root/'first/source/drivers/shizuku_gop/first_load/guard.c'
        source.write_bytes(source.read_bytes()+b'changed')
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            try:
                with self.assertRaises(ValueError):stage.stage(attempt,epoch,r,held,live,first,REPO,self.root/'out',lambda:None,1<<20)
                self.assertFalse((self.root/'out').exists())
            finally:attempt.close()

    def test_wrong_provider_receipt_refused_before_writes(self):
        pins=self.inputs();live,first=self.fixture();obj=json.loads(Path(first['path']).read_bytes())
        obj['gop_provider_identity_sha256']='3'*64;first=self.json('first/build-result.json',obj)
        with r.leased_inputs(pins) as held:
            attempt=self.attempt(held,pins)
            try:
                with self.assertRaises(ValueError):stage.stage(attempt,epoch,r,held,live,first,REPO,self.root/'out',lambda:None,1<<20)
                self.assertFalse((self.root/'out').exists())
            finally:attempt.close()

class NestedContract(unittest.TestCase):
    def setUp(self):
        self.pin={'path':'/tmp/source','bytes':32,'sha256':'a'*64}
        self.payloads=[{'guest':n,'file':dict(self.pin)} for n in sorted(r.GOP_ROOT|r.GOP_NESTED)]
    def test_no_partial_or_arbitrary_nested_cohort(self):
        for bad in ('SHZGOP/OTHER.EXE','WINDOWS/SYSTEM.DAT','SHZGOP/../USER.DAT','SHZGOP\\GPEPOCH.NON','shzgop/GPEPOCH.NON'):
            rows=copy.deepcopy(self.payloads);rows[-1]['guest']=bad
            with self.subTest(bad=bad),self.assertRaises(ValueError):r.payload_names(rows)
        with self.assertRaises(ValueError):r.payload_names(self.payloads[:-1])
        rows=copy.deepcopy(self.payloads);next(x for x in rows if x['guest']=='SHZGOP/GPEPOCH.NON')['file']['bytes']=33
        with self.assertRaises(ValueError):r.payload_names(rows)
    def inventory(self):
        before={'WINDOWS/WIN.COM':{'bytes':8,'sha256':'b'*64},'SHZGOP':{'directory':True,'metadata_sha256':'old'},
                'SHZGOP/PRESERVE.TXT':{'bytes':10,'sha256':'c'*64}}
        after=copy.deepcopy(before);after['SHZGOP']['metadata_sha256']='updated'
        after.update({p['guest']:{'bytes':p['file']['bytes'],'sha256':p['file']['sha256']} for p in self.payloads})
        return before,after
    def test_readback_keeps_existing_folder_members(self):
        before,after=self.inventory();r.verify_payload_inventory(before,after,self.payloads)
        after['SHZGOP/PRESERVE.TXT']['sha256']='d'*64
        with self.assertRaises(ValueError):r.verify_payload_inventory(before,after,self.payloads)
    def test_extra_file_and_file_directory_collision_refused(self):
        before,after=self.inventory();after['SHZGOP/UNKNOWN.EXE']={}
        with self.assertRaises(ValueError):r.verify_payload_inventory(before,after,self.payloads)
        before,after=self.inventory();before['SHZGOP']={'bytes':3}
        with self.assertRaises(ValueError):r.verify_payload_inventory(before,after,self.payloads)

if __name__=='__main__':unittest.main()
