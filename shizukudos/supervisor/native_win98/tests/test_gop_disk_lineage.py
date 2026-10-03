# SPDX-License-Identifier: GPL-2.0-only
"""Modeled producer snapshots; no live Attempt, grant, disk or guest claims."""
import copy
import hashlib
import json
import unittest
import test_disk_lineage as base
m,pin = base.m,base.pin

class GOPLineage(unittest.TestCase):
    def setUp(self):
        fixture=base.LineageTests();fixture.setUp();self.fixture=fixture
        raw,pins=fixture.inputs();baseline=json.loads(raw[0]);self.launchpin=pins[1]
        self.context={'records':{},'producer_pins':{},'live_policy':{'policy_sha256':'8'*64,'nonce_sha256':'9'*64,'original_host_deadline_ns':123456789}}
        def record(name,obj):
            data=json.dumps(obj).encode();p=pin(name+'.json',len(data),hashlib.sha256(data).hexdigest())
            self.context['records'][name]={'raw':data,'pin':p};return p
        record('baseline_profile',baseline);self.context['records']['baseline_profile']['pin']=pins[0]
        gp=copy.deepcopy(baseline)
        gp['payloads'] += [{'guest':n,'file':pin(n)} for n in ('SHZGOP.DRV','SHZGOP.VXD','SHZGOP.INF')]
        gppin=record('gop_profile',gp)
        gopproducers=[pin(n) for n in ('gop_preinstall_profile.py','win98_source_profile.py','prepare_replacement.py')]
        callerproducers=[pin('caller/'+n) for n in ('prepare.py','gop_preinstall_profile.py','win98_source_profile.py','prepare_replacement.py','build.py')]
        nonceproducers=[pin('nonce/'+n) for n in ('gop_nonce_staging.py','native_epoch_host.py','prepare_replacement.py')]
        self.context['producer_pins']={'gop_stage':gopproducers,'caller_stage':callerproducers,'nonce_stage':nonceproducers}
        common={'public_artifact':False,'VM_executed':False,'default_GOP_registered':False,'Windows98_boot_verified':False,
                'Supervisor_epoch_verified':False,'guardian_epoch_query_opcode':'0x4f11','guardian_epoch_query_bytes':160,'guardian_epoch_HCALL':14}
        gop={**common,'schema':'shizukuos.private-gop-preinstall-profile.v1','status':'PRIVATE_GOP_PAYLOADS_PREPARED_NOT_INSTALLED',
             'constructor_profile':gppin,'launch_profile':pins[1],'producer_inputs':gopproducers,
             'staged_payloads':{p['guest']:p['file'] for p in gp['payloads'] if p['guest'].startswith('SHZGOP.')},
             'live_provider_identity_sha256':'7'*64,'gop_receipt':pin('gop-build.json')}
        goppin=record('gop_stage',gop)
        cp=copy.deepcopy(gp);cp['payloads'] += [{'guest':n,'file':pin(n)} for n in ('GOPINST.EXE','GPREQ.INI')]
        cppin=record('caller_profile',cp)
        caller={**common,'schema':'shizukuos.private-live-gop-stage.v1','status':'PRIVATE_CALLER_REQUEST_STAGED_NOT_EXECUTED',
                'source_gop_profile':goppin,'constructor_profile':cppin,'producer_inputs':callerproducers,
                'utility_payloads':cp['payloads'][-2:],'live_provider_identity_sha256':'7'*64}
        callerpin=record('caller_stage',caller)
        self.profile=copy.deepcopy(cp)
        staged={'SHZGUARD.VXD':pin('SHZGUARD.VXD'),'GOPLOAD.EXE':pin('GOPLOAD.EXE')}
        noncepin=pin('GPEPOCH.NON',32,'9'*64)
        self.profile['payloads'] += [{'guest':'SHZGOP/'+n,'file':p} for n,p in staged.items()]
        self.profile['payloads'] += [{'guest':'SHZGOP/SHZGOP.VXD','file':gop['staged_payloads']['SHZGOP.VXD']},
                                    {'guest':'SHZGOP/GPEPOCH.NON','file':noncepin}]
        self.profile_raw=json.dumps(self.profile).encode();self.profile_pin=pin('final-profile.json',len(self.profile_raw),hashlib.sha256(self.profile_raw).hexdigest())
        first={'status':'PASS_SOURCE_BUILD_NOT_EXECUTED','guest_executed':False,'default_changed':False,
               'mode_changed':False,'gpu_active_verified':False,'gop_provider_identity_sha256':'7'*64,
               'gop_vxd_sha256':gop['staged_payloads']['SHZGOP.VXD']['sha256'],'gop_receipt_sha256':gop['gop_receipt']['sha256'],
               'artifacts':{n:{'bytes':p['bytes'],'sha256':p['sha256']} for n,p in staged.items()}}
        firstpin=record('firstload_build',first)
        nonce={'schema':'shizukuos.private-gop-nonce-stage.v1','status':'PROSPECTIVE_CURRENT_ATTEMPT_STAGED_NOT_GRANTED',
               'same_process_staging':True,'source_live_stage':callerpin,'source_firstload_build':firstpin,'source_constructor_profile':cppin,
               'constructor_profile':self.profile_pin,'nonce_payload':noncepin,'staged_firstload_payloads':staged,
               'producer_inputs':nonceproducers,**self.context['live_policy'],
               'public_artifact':False,'VM_executed':False,'default_GOP_registered':False,'Windows98_boot_verified':False,'HostGrant_transmitted':False}
        record('nonce_stage',nonce)
        prepared=json.loads(raw[2]);prepared['profile_sha256']=self.profile_pin['sha256']
        pre_raw=json.dumps(prepared).encode();pre_pin=pin('prepared-final.json',len(pre_raw),hashlib.sha256(pre_raw).hexdigest())
        self.raw=[self.profile_raw,raw[1],pre_raw];self.pins=[self.profile_pin,pins[1],pre_pin]
    def call(self):return m.admit(self.raw,self.pins,self.fixture.disk,self.fixture.producers,gop_cohort=self.context)
    def mutate(self,name,fn):
        row=self.context['records'][name];obj=json.loads(row['raw']);fn(obj);raw=json.dumps(obj).encode()
        row['raw']=raw;row['pin']=dict(row['pin'],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
    def test_exact_full_chain_remains_prospective_without_runtime_authority(self):
        proof=self.call();self.assertIn('gop_cohort',proof)
        for key in ('HostGrant_transmitted','Windows98_boot_verified','default_GOP_registered'):
            self.assertIs(proof['gop_cohort'][key],False)
        self.assertEqual(proof['launch_receipt'],self.launchpin)
    def test_default_admission_still_rejects14_without_explicit_context(self):
        with self.assertRaises(ValueError):m.admit(self.raw,self.pins,self.fixture.disk,self.fixture.producers)
    def test_other_live_policy_nonce_or_deadline_refused(self):
        for key,bad in (('policy_sha256','f'*64),('nonce_sha256','e'*64),('original_host_deadline_ns',123456790)):
            old=self.context['live_policy'][key];self.context['live_policy'][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):self.call()
            self.context['live_policy'][key]=old
    def test_missing_or_unknown_receipt_chain_refused(self):
        for name in m.COHORT_RECORDS:
            row=self.context['records'].pop(name)
            with self.subTest(name=name),self.assertRaises(ValueError):self.call()
            self.context['records'][name]=row
        self.context['records']['extra']=self.context['records']['nonce_stage']
        with self.assertRaises(ValueError):self.call()
    def test_preexisting_nonce_receipt_cannot_claim_grant(self):
        self.mutate('nonce_stage',lambda n:n.update(HostGrant_transmitted=True))
        with self.assertRaises(ValueError):self.call()
    def test_display_target_or_partial_profile_cohort_refused(self):
        for bad in ('SHZGOP/OTHER.VXD','WINDOWS/SYSTEM.DAT'):
            profile=copy.deepcopy(self.profile);profile['payloads'][-1]['guest']=bad
            raw=json.dumps(profile).encode();pins=copy.deepcopy(self.pins);pins[0]=dict(pins[0],bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
            with self.subTest(bad=bad),self.assertRaises(ValueError):m.admit([raw,*self.raw[1:]],pins,self.fixture.disk,self.fixture.producers,gop_cohort=self.context)
    def test_arbitrary_staging_producer_hash_is_not_independently_approved(self):
        self.context['producer_pins']['nonce_stage'][0]['sha256']='f'*64
        with self.assertRaises(ValueError):self.call()
    def test_preserved_startup_payload_and_launch_source_cannot_change(self):
        self.mutate('baseline_profile',lambda p:p['payloads'][0]['file'].update(sha256='f'*64))
        with self.assertRaises(ValueError):self.call()

if __name__=='__main__':unittest.main()
