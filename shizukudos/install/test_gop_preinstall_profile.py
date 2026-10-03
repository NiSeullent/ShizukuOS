# SPDX-License-Identifier: GPL-2.0-or-later
"""GOP staging admission: host byte tests, not Windows/device acceptance."""
import copy
import hashlib
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import patch
import contextlib
import tempfile

spec=importlib.util.spec_from_file_location('gop_profile',Path(__file__).with_name('gop_preinstall_profile.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class Admission(unittest.TestCase):
    def setUp(self):
        self.raw={}
        for name,sig in [('SHZGOP.DRV',b'NE'),('SHZGOP.VXD',b'LE')]:
            b=bytearray(70);b[:2]=b'MZ';struct.pack_into('<I',b,60,64);b[64:66]=sig
            self.raw[name]=bytes(b)
        self.raw['SHZGOP.INF']=b'Class=DISPLAY\r\nHKR,DEFAULT,drv,,SHZGOP.DRV\r\nHKR,DEFAULT,minivdd,,SHZGOP.VXD\r\n'
        self.art={n:{'path':'/private/'+n,'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()} for n,b in self.raw.items()}
        self.profile={'schema':'shizukuos.private-replacement-profile.v1','disk':{'path':'/private/disk'},
            'boot_template':{},'freedos_source':{},'build_receipt':{},'build_source_root':'/source',
            'payloads':[{'guest':n,'file':{'path':'/private/'+n,'bytes':1,'sha256':'a'*64}} for n in sorted(m.BASE)]}
        self.launch={'schema':'shizukuos.private-win98-launch-profile.v1','status':'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED',
            'source_disk':self.profile['disk'],'observed_windows_path':'C:\\WINDOWS','boot_policy':'shz.foundation=win98',
            **{n:False for n in ('public_artifact','Windows98_boot_verified','native_apps_verified','VM_executed')}}
        self.receipt={'schema':1,'status':'HOST-BUILD-PASS','live_provider_identity_sha256':'d'*64,'live_query_opcode':'0x4f10','guardian_epoch_query_opcode':'0x4f11','guardian_epoch_query_bytes':160,'guardian_epoch_HCALL':14,'artifacts':{n:{'bytes':p['bytes'],'sha256':p['sha256']} for n,p in self.art.items()},
            'original_inputs':{'SHZGOP.INF':self.art['SHZGOP.INF']['sha256']}}
    def compose(self,read=None):
        return m.compose_profile(self.launch,self.profile,self.receipt,self.art,read or (lambda p:self.raw[Path(p['path']).name]))
    def rejects(self):
        with self.assertRaises((ValueError,RuntimeError)):self.compose()
    def test_preserves_original_startup_and_does_not_mutate(self):
        before=copy.deepcopy((self.launch,self.profile,self.receipt,self.art))
        result=self.compose();self.assertEqual(result['payloads'][:5],self.profile['payloads'])
        self.assertEqual(len(result['payloads']),8);self.assertEqual(before,(self.launch,self.profile,self.receipt,self.art))
        self.assertNotIn('default_GOP_registered',result)
    def test_missing_live_provider_cannot_be_staged_for_default_installation(self):
        self.receipt.pop('live_provider_identity_sha256');self.rejects()
    def test_unrecognized_query_abi_rejected(self):
        self.receipt['live_query_opcode']='0x110b';self.rejects()
    def test_old_or_invalid_epoch_producer_refused(self):
        for key,value in (('guardian_epoch_query_opcode','0x4f10'),('guardian_epoch_query_bytes',159),('guardian_epoch_HCALL',9)):
            old=self.receipt[key];self.receipt[key]=value;self.rejects();self.receipt[key]=old
        self.receipt.pop('guardian_epoch_query_opcode');self.rejects()
    def test_wrong_source_disk(self):
        self.launch['source_disk']={'path':'/other'};self.rejects()
    def test_no_invented_boot_or_native_acceptance(self):
        for key in ('public_artifact','Windows98_boot_verified','native_apps_verified','VM_executed'):
            self.launch[key]=True;self.rejects();self.launch[key]=False
    def test_missing_baseline_payload(self):
        self.profile['payloads'].pop();self.rejects()
    def test_native_signature_required_after_valid_sha(self):
        self.raw['SHZGOP.VXD']=self.raw['SHZGOP.DRV'];p=self.art['SHZGOP.VXD']
        p['sha256']=hashlib.sha256(self.raw['SHZGOP.VXD']).hexdigest()
        self.receipt['artifacts']['SHZGOP.VXD']['sha256']=p['sha256'];self.rejects()
    def test_actual_bytes_must_match(self):
        self.raw['SHZGOP.DRV']+=b'!';self.rejects()
    def test_callback_cannot_change_source_snapshot(self):
        def read(p):
            self.art['SHZGOP.VXD']['sha256']='b'*64
            return self.raw[Path(p['path']).name]
        result=self.compose(read);self.assertNotEqual(result['payloads'][-2]['file']['sha256'],'b'*64)
    def test_callback_cannot_rewrite_its_pin_to_admit_different_bytes(self):
        def read(pin):
            raw=self.raw[Path(pin['path']).name]
            if pin['path'].endswith('.DRV'):
                raw=raw[:-1]+b'!'
                pin['sha256']=hashlib.sha256(raw).hexdigest()
            return raw
        with self.assertRaises((ValueError,RuntimeError)):self.compose(read)
    def test_duplicate_device_registration_rejected_even_with_valid_sha(self):
        raw=self.raw['SHZGOP.INF']+b'Class=DISPLAY\r\n';self.raw['SHZGOP.INF']=raw
        pin=self.art['SHZGOP.INF'];pin.update(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
        self.receipt['artifacts']['SHZGOP.INF']={'bytes':pin['bytes'],'sha256':pin['sha256']}
        self.receipt['original_inputs']['SHZGOP.INF']=pin['sha256'];self.rejects()
    def test_existing_eight_payload_profile_cannot_be_used_as_original(self):
        self.profile=self.compose();self.rejects()
    def test_relative_and_nested_windows_directory_rejected(self):
        for path in ('WINDOWS','C:\\WINDOWS\\SYSTEM'):
            self.launch['observed_windows_path']=path;self.rejects()

class OutputCustody(unittest.TestCase):
    @contextlib.contextmanager
    def broken(self,rows):
        yield {}
        raise RuntimeError('late lease break')
    def test_late_break_revokes_owned_consumer_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);st=out.stat();owned=[(st.st_dev,st.st_ino)]
            for name in ('replacement-profile.json','gop-preinstall-profile.json'):(out/name).write_text('owned')
            with patch.object(m.replacement,'leased_inputs',self.broken):
                with self.assertRaises(RuntimeError):
                    with m.guarded_inputs([],out,owned):pass
            self.assertFalse((out/'replacement-profile.json').exists())
    def test_creation_collision_does_not_remove_someone_elses_profiles(self):
        with tempfile.TemporaryDirectory() as temp:
            out=Path(temp);file=out/'replacement-profile.json';file.write_text('other producer')
            with patch.object(m.replacement,'leased_inputs',self.broken):
                with self.assertRaises(RuntimeError):
                    with m.guarded_inputs([],out,[]):pass
            self.assertEqual(file.read_text(),'other producer')
    def test_replaced_output_directory_is_not_our_output(self):
        with tempfile.TemporaryDirectory() as temp:
            base=Path(temp);out=base/'ours';out.mkdir();st=out.stat();owned=[(st.st_dev,st.st_ino)]
            out.rename(base/'saved');out.mkdir();file=out/'replacement-profile.json';file.write_text('other producer')
            with patch.object(m.replacement,'leased_inputs',self.broken):
                with self.assertRaises(RuntimeError):
                    with m.guarded_inputs([],out,owned):pass
            self.assertEqual(file.read_text(),'other producer')

if __name__=='__main__':unittest.main()
