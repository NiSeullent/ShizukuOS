# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic receipt snapshots; no media, source producer, disk or VM is run."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest

spec=importlib.util.spec_from_file_location('disk_lineage',Path(__file__).resolve().parents[1]/'disk_lineage.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def pin(name,size=32,digest='a'*64):
    return {'path':'/private-fixture/'+name,'bytes':size,'sha256':digest}


class LineageTests(unittest.TestCase):
    def setUp(self):
        self.disk=pin('replacement.img',2<<30,'b'*64)
        original=pin('original.raw',2<<30,'c'*64)
        self.producers=[pin('win98_source_profile.py',123,'d'*64),pin('prepare_replacement.py',234,'e'*64)]
        self.profile={'schema':'shizukuos.private-replacement-profile.v1','disk':original,
            'boot_template':{'kind':'fat16','file':pin('boot.bin',512)},'freedos_source':'/private-fixture/upstream',
            'build_receipt':pin('dos-build.json',345),'build_source_root':'/private-fixture/dos-source',
            'payloads':[{'guest':name,'file':pin(name,6100 if name=='HIMEMX.EXE' else 128)}
                        for name in ('KERNEL.SYS','COMMAND.COM','HIMEMX.EXE','CONFIG.SYS','AUTOEXEC.BAT')]}
        self.prepared={'schema':'shizukuos.private-replacement-preparation.v1',
            'status':'PREPARED_PRIVATE_REPLACEMENT_NOT_BOOTED','private_source_disk':True,'source_unchanged':True,
            'public_artifact':False,'Windows98_boot_verified':False,'MSDOS_replacement_under_Windows98':False,
            'native_apps_verified':False,'VM_executed':False,'source_disk':original,'destination':self.disk,
            'profile_sha256':'pending','build_receipt_sha256':self.profile['build_receipt']['sha256'],
            'template':{'kind':'fat16','sha256':self.profile['boot_template']['file']['sha256'],
                        'kernel_name':'KERNEL.SYS','load_segment':96,'actual_BIOS_DL_capture':True},
            'copy':{'method':'explicit-full-copy','bytes':2<<30,'sha256':original['sha256'],
                    'destination_readback_verified':True,'source_lease_preserved':True},
            'original_vbr_sha256':'1'*64,'replacement_vbr_sha256':'2'*64,
            'original_inventory_sha256':'3'*64,'existing_members':12,'unchanged_original_members':10}
        self.launch={'schema':'shizukuos.private-win98-launch-profile.v1',
            'status':'PRIVATE_WIN98_LAUNCH_PROFILE_PREPARED_NOT_BOOTED','public_artifact':False,
            'Windows98_boot_verified':False,'installed_Windows98_version_verified':False,
            'MSDOS_replacement_under_Windows98':False,'native_apps_verified':False,'VM_executed':False,
            'drive_mapping_verified':False,'native_bootability_verified':False,'boot_policy':'shz.foundation=win98',
            'observed_windows_path':'C:\\WINDOWS','source_disk':original,'constructor_profile':'pending',
            'producer_inputs':self.producers,
            'observed_members':{'WINDOWS/'+name:{'bytes':12,'sha256':'a'*64,'metadata_sha256':'4'*64,'cluster':2}
                               for name in ('WIN.COM','SYSTEM.INI','SYSTEM/VMM32.VXD','IFSHLP.SYS')}}

    def inputs(self):
        records=copy.deepcopy([self.profile,self.launch,self.prepared])
        profile_raw=json.dumps(records[0]).encode()
        profile_pin=pin('replacement-profile.json',len(profile_raw),hashlib.sha256(profile_raw).hexdigest())
        records[1]['constructor_profile']=profile_pin
        records[2]['profile_sha256']=profile_pin['sha256']
        raw=[profile_raw,*(json.dumps(row).encode() for row in records[1:])]
        pins=[profile_pin,*(pin(name,len(data),hashlib.sha256(data).hexdigest()) for name,data in
                           zip(('source-profile.json','preparation.json'),raw[1:]))]
        return raw,pins

    def call(self,raw=None,pins=None,disk=None,producers=None):
        if raw is None:raw,pins=self.inputs()
        return m.admit(raw,pins,self.disk if disk is None else disk,
                       self.producers if producers is None else producers)

    def test_complete_chain_preserves_unverified_runtime_and_returns_no_original_label(self):
        result=self.call()
        self.assertEqual(result['disk_origin'],'source-built-private-replacement-prepared-not-booted')
        self.assertEqual(result['replacement_disk'],self.disk)
        self.assertEqual(result['boot_policy'],'shz.foundation=win98')
        for name in ('Windows98_boot_verified','MSDOS_replacement_under_Windows98','native_apps_verified','VM_executed'):
            self.assertIs(result[name],False)

    def test_refuses_generic_pass_and_missing_preparation(self):
        for key,value in (('status','PASS'),('schema','other'),('source_unchanged',False)):
            with self.subTest(key=key):
                old=self.prepared[key];self.prepared[key]=value
                with self.assertRaises(ValueError):self.call()
                self.prepared[key]=old

    def test_every_false_runtime_flag_is_exact_false_not_missing_numeric_or_true(self):
        for row in (self.launch,self.prepared):
            fields=[name for name,value in row.items() if value is False]
            for name in fields:
                for value in (True,0,None):
                    with self.subTest(name=name,value=value):
                        row[name]=value
                        with self.assertRaises(ValueError):self.call()
                        row[name]=False

    def test_original_disk_or_unbound_prepared_destination_is_refused(self):
        for disk in (self.profile['disk'],dict(self.disk,sha256='f'*64),dict(self.disk,bytes=1),dict(self.disk,path='/private-fixture/other.raw')):
            with self.subTest(disk=disk),self.assertRaises(ValueError):self.call(disk=disk)

    def test_raw_pin_mutations_and_truncation_are_refused(self):
        raw,pins=self.inputs()
        for at in range(3):
            for changed in (raw[at]+b' ',raw[at][:-1]):
                data=list(raw);data[at]=changed
                with self.subTest(at=at),self.assertRaises(ValueError):self.call(data,pins)
            altered=copy.deepcopy(pins);altered[at]['sha256']='0'*64
            with self.assertRaises(ValueError):self.call(raw,altered)

    def test_duplicate_json_fields_refused_even_when_explicit_hash_matches(self):
        raw,pins=self.inputs()
        raw[1]=b'{"schema":"wrong","schema":"shizukuos.private-win98-launch-profile.v1"}'
        pins[1]=pin('source-profile.json',len(raw[1]),hashlib.sha256(raw[1]).hexdigest())
        with self.assertRaises(ValueError):self.call(raw,pins)

    def test_manifest_geometry_and_noncanonical_paths_are_refused(self):
        raw,pins=self.inputs()
        for path in ('relative/file','/private-fixture/../secret','/proc/123/file','/private-fixture//file'):
            altered=copy.deepcopy(pins);altered[0]['path']=path
            with self.subTest(path=path),self.assertRaises(ValueError):self.call(raw,altered)
        for size in (True,0,17<<20):
            altered=copy.deepcopy(pins);altered[1]['bytes']=size
            with self.subTest(size=size),self.assertRaises(ValueError):self.call(raw,altered)

    def test_source_pin_crosslinks_and_bound_profile_sha_are_required(self):
        for row,key,value in ((self.prepared,'source_disk',pin('other.raw',2<<30)),
                              (self.launch,'source_disk',pin('other.raw',2<<30)),
                              (self.prepared,'build_receipt_sha256','f'*64)):
            old=row[key];row[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call()
            row[key]=old
        raw,pins=self.inputs();row=json.loads(raw[2]);row['profile_sha256']='f'*64
        raw[2]=json.dumps(row).encode();pins[2]=pin('preparation.json',len(raw[2]),hashlib.sha256(raw[2]).hexdigest())
        with self.assertRaises(ValueError):self.call(raw,pins)

    def test_exact_launch_payload_set_and_unique_guests_are_required(self):
        original=copy.deepcopy(self.profile['payloads'])
        for members in (original[:-1],original+[original[0]],original+[{'guest':'EVIL.SYS','file':pin('EVIL.SYS')}],
                        [dict(row,guest=row['guest'].lower()) for row in original]):
            self.profile['payloads']=members
            with self.subTest(members=members),self.assertRaises(ValueError):self.call()
        self.profile['payloads']=original

    def test_launch_policy_path_observed_windows_members_and_producer_pins_are_required(self):
        for key,value in (('boot_policy','shz.foundation=other'),('observed_windows_path','C:\\OTHER'),
                          ('observed_members',{}),('producer_inputs',self.producers[:1])):
            old=self.launch[key];self.launch[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call()
            self.launch[key]=old
        with self.assertRaises(ValueError):self.call(producers=[dict(row,sha256='f'*64) for row in self.producers])

    def test_constructor_boot_template_copy_coverage_and_original_inventory_are_required(self):
        for target,key,value in ((self.prepared['template'],'kernel_name','IO.SYS'),
                (self.prepared['template'],'load_segment',True),(self.prepared['template'],'actual_BIOS_DL_capture',False),
                (self.prepared['copy'],'destination_readback_verified',False),
                (self.prepared['copy'],'source_lease_preserved',False),
                (self.prepared['copy'],'sha256','f'*64),(self.prepared,'existing_members',0),
                (self.prepared,'unchanged_original_members',13),
                (self.prepared,'replacement_vbr_sha256',self.prepared['original_vbr_sha256'])):
            old=target[key];target[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.call()
            target[key]=old

    def test_returned_record_is_independent_and_untrusted_unknown_profile_keys_are_refused(self):
        raw,pins=self.inputs();result=self.call(raw,pins);pins[0]['path']='changed'
        self.assertEqual(result['constructor_profile']['path'],'/private-fixture/replacement-profile.json')
        self.profile['unexpected']='injected'
        with self.assertRaises(ValueError):self.call()

    def test_only_actual_regular_file_inventory_shape_is_admitted(self):
        original=copy.deepcopy(self.launch['observed_members']['WINDOWS/WIN.COM'])
        for row in ({'directory':True,'metadata_sha256':'4'*64},
                    *(dict(original,directory=value) for value in (True,False,0,1,'file')),
                    dict(original,cluster=True),dict(original,cluster=0),dict(original,bytes=True),
                    {key:value for key,value in original.items() if key!='metadata_sha256'},
                    dict(original,metadata_sha256='0'*64)):
            self.launch['observed_members']['WINDOWS/WIN.COM']=row
            with self.subTest(row=row),self.assertRaises(ValueError):self.call()
        self.launch['observed_members']['WINDOWS/WIN.COM']=original

    def test_extra_producer_observations_keep_exact_file_shape_without_new_path_allowlist(self):
        row=copy.deepcopy(self.launch['observed_members']['WINDOWS/WIN.COM'])
        self.launch['observed_members']['OTHER/COUNTRY.SYS']=row
        self.assertEqual(self.call()['disk_origin'],'source-built-private-replacement-prepared-not-booted')
        self.launch['observed_members']['OTHER/COUNTRY.SYS']=dict(row,directory=True)
        with self.assertRaises(ValueError):self.call()


if __name__=='__main__':unittest.main(verbosity=2)
