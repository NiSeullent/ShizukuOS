# SPDX-License-Identifier: GPL-2.0-only
"""Exercise controller collection logic with tiny inputs and modeled QEMU/VMCS.

The legacy no-custody collection branch is modeled explicitly. The real CLI
requires guardian admission, tested separately below and by lifecycle controls.

These host controls never run QEMU, original media or a Windows guest.
"""
from contextlib import contextmanager
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('controller_under_test', HERE/'run_vm.py')
m = importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
spec = importlib.util.spec_from_file_location('capture_under_test', HERE/'owned_capture.py')
u = importlib.util.module_from_spec(spec);spec.loader.exec_module(u)


class MainControls(unittest.TestCase):
    def test_real_cli_refuses_missing_guardian_before_launch(self):
        argv = ['run_vm.py', '--repo', '/unused', '--plan', '/unused/plan.json',
                '--plan-sha256', '0'*64, '--runtime-sources-sha256', '0'*64]
        with patch.object(sys, 'argv', argv), patch.object(m.subprocess, 'Popen') as launch:
            with self.assertRaisesRegex(ValueError, 'independently admitted task guardian'):
                m.main()
            launch.assert_not_called()

    def fixture(self, mode):
        temporary = tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        base=Path(temporary.name);repo=base/'repo';out=base/'vm';out.mkdir()
        relative=('shizukudos/supervisor/native_win98/build.py','shizukudos/supervisor/native_win98/prepare_vm.py','shizukudos/tools/qemu.py','shizukudos/tools/shzinfo.py')
        for name in relative:
            p=repo/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('owned host fixture\n')
        source=base/'builder';header=source/'source/shizukudos/supervisor/include/shz_info.h';header.parent.mkdir(parents=True);header.write_text('owned header fixture\n')
        sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
        def make(name, data=b'owned fixture'):
            p=base/name;p.write_bytes(data);return {'path':str(p),'sha256':sha(p),'bytes':len(data)}
        inputs={key:make(key) for key in ('esp','firmware_code','firmware_vars','qemu')}
        originals={key:make(key) for key in ('DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG')}
        built={'private':True,'VM_executed':False,'artifact':dict(inputs['esp']),'status':'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN','source_before_after_match':True,'originals_before_after_match':True,'sources_sha256':{'shizukudos/supervisor/include/shz_info.h':sha(header)},'input_pins':originals}
        receipt=source/'result.json';receipt.write_text(json.dumps(built));inputs['build_receipt']={'path':str(receipt),'sha256':sha(receipt),'bytes':receipt.stat().st_size}
        for key,name in [('esp','esp.img'),('firmware_code','OVMF_CODE.fd'),('firmware_vars','OVMF_VARS.fd')]:
            (out/name).write_bytes(Path(inputs[key]['path']).read_bytes())
        recipe=['modeled-owned-qemu','-serial','file:'+str(out/'serial.log')]
        plan={'status':'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN','private':True,'VM_executed':False,'source_bound_ESP':True,'originals_before_after_match':True,'qemu_argv':recipe,'input_pins':inputs}
        if mode in ('preparation_pins_match','preparation_pins_mismatch'):
            plan['preparation_runtime_helpers_sha256']=m.helper_identity(repo)[1]
            if mode=='preparation_pins_mismatch':plan['preparation_runtime_helpers_sha256'][relative[0]]='0'*64
        planpath=out/'vm-plan.json';planpath.write_text(json.dumps(plan))
        clock=[0.0];instance={};original_load=m.load
        class Child:
            pid=43210;returncode=None
            def __init__(self,*args,**kwargs):instance['child']=self;self.terminated=False;self.killed=False
            def poll(self):return self.returncode
            def wait(self,timeout):
                if mode=='kill_wait_failure':raise subprocess.TimeoutExpired('modeled-owned-qemu',timeout)
                if self.returncode is None:raise subprocess.TimeoutExpired('modeled-owned-qemu',timeout)
                return self.returncode
            def terminate(self):self.terminated=True;self.returncode=-15
            def kill(self):self.killed=True;self.returncode=-9
        class Monitor:
            def __init__(self,*args,**kwargs):self.deadline=9999
            def call(self,name,arguments=None):
                if name=='query-blockstats':
                    if mode=='bad_final_write_sample' and clock[0]>=20:return []
                    return [{'device':'esp','stats':{'wr_bytes':0}}]
                if name=='stop':
                    if mode=='pause_failure':raise OSError('modeled pause error')
                    return {}
                if name=='query-status':return {'running':True,'status':'running'}
                if name=='pmemsave':Path(arguments['filename']).write_bytes(b'\0'*(1 if mode=='memory_size_error' else 8192));return {}
                if name=='screendump':
                    if mode=='capture_error':raise OSError('modeled capture request error')
                    Path(arguments['filename']).write_bytes(b'\x89PNG\r\n\x1a\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>II',1,1)+b'\0'*9);return {}
                if name=='quit':
                    if mode in ('quit_failure','kill_wait_failure'):raise OSError('modeled quit failure')
                    if mode=='firmware_drift':Path(inputs['firmware_code']['path']).write_bytes(b'drift')
                    if mode=='config_drift':Path(originals['WIN98CFG.BIN']['path']).write_bytes(b'drift')
                    if mode=='source_esp_drift':Path(inputs['esp']['path']).write_bytes(b'drift')
                    if mode.startswith('original_drift:'):Path(originals[mode.split(':')[1]]['path']).write_bytes(b'drift')
                    if mode.startswith('plan_drift:'):Path(inputs[mode.split(':')[1]]['path']).write_bytes(b'drift')
                    if mode=='plan_file_missing':planpath.unlink()
                    if mode=='header_missing':header.unlink()
                    if mode=='runtime_snapshot_missing':(out/'runtime-source'/relative[0]).unlink()
                    instance['child'].returncode=0;return {}
                raise AssertionError(name)
            def hmp(self,name):return 'modeled owned CPU\n'
            def close(self):pass
        class Info:
            magic=11;version=3;size=5368
            @classmethod
            def parse(cls,raw):assert len(raw)==8192;return cls()
            def to_dict(self):return {'loader_flags':1,'boot_path':1,'guest_ram_size':128<<20,'disk_size':2<<30,'stage':5,'stage_name':'LAUNCHED','domains':{'WIN98':{'state':4,'exits':10,'error':'modeled domain failed'}}}
        @contextmanager
        def read_leased(path,pin,size,maximum=None):
            assert sha(path)==pin
            def checkpoint():
                if mode=='lease_break' and clock[0]>=20:raise RuntimeError('modeled lease break')
            yield (0,checkpoint)
        guards=types.SimpleNamespace(pinned_hash=lambda path,pin,*a: self.assertEqual(sha(path),pin),read_leased=read_leased)
        mods={'native_run_guards':guards,'native_run_preparation':types.SimpleNamespace(recipe=lambda *args:recipe),'native_run_qmp':types.SimpleNamespace(QMP=Monitor),'native_run_info':types.SimpleNamespace(REGION_BASE=64<<20,INFO_BYTES=8192,MAGIC=11,Info=Info,selfcheck=lambda path:5368),'native_run_capture':u}
        def loader(name,path):
            instance.setdefault('imported_helpers',[]).append(name)
            return mods[name] if name in mods else original_load(name,path)
        free=m.RESERVE+(64<<20) if mode=='budget_short' else m.RESERVE+(2<<30)
        argv=['run_vm.py','--repo',str(repo),'--plan',str(planpath),'--plan-sha256',sha(planpath),'--timeout','20','--runtime-sources-sha256',('0'*64 if mode=='helper_pin_mismatch' else m.helper_identity(repo)[0])]
        def atomic(path,value):
            if mode=='receipt_failure' and path.name=='native-result.json':raise OSError('modeled final receipt failure')
            return original_atomic(path,value)
        original_atomic=u.atomic_json
        original_write=Path.write_text
        def write(path,*args,**kwargs):
            if mode=='receipt_failure' and path.name=='native-result.json':raise OSError('modeled final receipt failure')
            return original_write(path,*args,**kwargs)
        with patch.object(m,'get_custody',return_value=None),patch.object(m,'load',loader),patch.object(sys,'argv',argv),patch.object(m.subprocess,'Popen',Child),patch.object(m.time,'monotonic',lambda:clock[0]),patch.object(m.time,'sleep',lambda n:clock.__setitem__(0,clock[0]+n)),patch.object(m.shutil,'disk_usage',lambda path:types.SimpleNamespace(free=(m.RESERVE-1 if mode=='reserve_consumed' and clock[0]>=1 else free))),patch.object(u,'available_memory_bytes',lambda:(5<<30 if mode=='memory_short' else 1<<30 if mode=='memory_consumed' and clock[0]>=1 else 8<<30)),patch.object(u,'OwnedQMP',Monitor),patch.object(u,'atomic_json',atomic),patch.object(Path,'write_text',write):
            try:result=m.main();failure=None
            except BaseException as error:result=None;failure=error
        p=out/'native-result.json';record=json.loads(p.read_text()) if p.exists() else None
        return result,failure,record,instance,out

    def test_original_firmware_config_and_source_esp_drift_veto_collection(self):
        for mode in ('firmware_drift','config_drift','source_esp_drift'):
            with self.subTest(mode=mode):
                result,error,record,_,_=self.fixture(mode)
                self.assertIsNone(error);self.assertEqual(result,1)
                self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')

    def test_host_memory_admission_and_runtime_margin(self):
        result,error,record,state,_=self.fixture('memory_short')
        self.assertIsInstance(error,SystemExit);self.assertEqual(error.code,2)
        self.assertNotIn('child',state);self.assertIsNone(record)
        result,error,record,_,_=self.fixture('memory_consumed')
        self.assertIsNone(error);self.assertEqual(result,1);self.assertFalse(record['collection_verified'])

    def test_wrong_helper_and_preparation_source_pins_rejected_before_import(self):
        for mode in ('helper_pin_mismatch','preparation_pins_mismatch'):
            with self.subTest(mode=mode):
                result,error,record,state,out=self.fixture(mode)
                self.assertIsInstance(error,SystemExit);self.assertEqual(error.code,2)
                self.assertNotIn('imported_helpers',state);self.assertNotIn('child',state)
                self.assertIsNone(record);self.assertFalse((out/'runtime-source').exists())

    def test_optional_preparation_pins_are_verified_when_present(self):
        result,error,record,_,_=self.fixture('preparation_pins_match')
        self.assertIsNone(error);self.assertEqual(result,0)
        self.assertTrue(record['preparation_helper_source_pins_verified'])

    def test_retained_reserve_consumption_is_a_failed_collection(self):
        result,error,record,_,_=self.fixture('reserve_consumed')
        self.assertIsNone(error);self.assertEqual(result,1);self.assertFalse(record['collection_verified'])
        self.assertLess(record['free_bytes_after'],m.RESERVE)

    def test_every_original_and_plan_input_is_an_independent_final_veto(self):
        for group,keys in [('original',('DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG')),('plan',('esp','firmware_code','firmware_vars','qemu','build_receipt'))]:
            for key in keys:
                with self.subTest(group=group,key=key):
                    result,error,record,_,_=self.fixture(group+'_drift:'+key)
                    self.assertIsNone(error);self.assertEqual(result,1)
                    self.assertFalse(record['collection_verified']);self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')

    def test_missing_plan_header_snapshot_and_lease_break_preserve_failed_receipt(self):
        for mode in ('plan_file_missing','header_missing','runtime_snapshot_missing','lease_break'):
            with self.subTest(mode=mode):
                result,error,record,_,_=self.fixture(mode)
                self.assertIsNone(error);self.assertEqual(result,1);self.assertFalse(record['collection_verified'])
                self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')

    def test_qmp_capture_error_bad_memory_and_failed_pause_are_not_valid_collection(self):
        for mode in ('capture_error','memory_size_error','pause_failure'):
            with self.subTest(mode=mode):
                result,error,record,_,_=self.fixture(mode)
                self.assertIsNone(error);self.assertEqual(result,1);self.assertFalse(record['collection_verified'])
                self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')

    def test_forced_termination_is_a_failed_collection_with_canonical_receipt(self):
        result,error,record,state,_=self.fixture('quit_failure')
        self.assertIsNone(error);self.assertEqual(result,1)
        self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')
        self.assertTrue(state['child'].terminated)

    def test_kill_wait_failure_still_persists_a_failed_receipt(self):
        result,error,record,_,_=self.fixture('kill_wait_failure')
        self.assertIsNone(error);self.assertEqual(result,1)
        self.assertEqual(record['status'],'NATIVE_CAPTURE_HARNESS_FAILED')
        self.assertFalse(record['owned_child_reaped'])
        self.assertTrue(record['unresolved_owned_child']);self.assertFalse(record['leases_released_after_reap'])

    def test_final_receipt_error_never_returns_collection_success(self):
        result,error,record,_,out=self.fixture('receipt_failure')
        self.assertIsNone(error);self.assertEqual(result,1);self.assertIsNone(record)
        self.assertEqual(list(out.glob('*.tmp')),[])

    def test_failed_last_write_sample_vetoes_collection(self):
        result,error,record,_,_=self.fixture('bad_final_write_sample')
        self.assertIsNone(error);self.assertEqual(result,1)
        self.assertFalse(record['write_budget_verified'])

    def test_full_capture_budget_is_required_before_launch(self):
        result,error,record,state,_=self.fixture('budget_short')
        self.assertIsInstance(error,SystemExit);self.assertEqual(error.code,2)
        self.assertNotIn('child',state);self.assertIsNone(record)

    def test_domain_failure_capture_does_not_claim_windows_or_replacement_success(self):
        result,error,record,_,_=self.fixture('normal')
        self.assertIsNone(error);self.assertEqual(result,0)
        self.assertEqual(record['status'],'NATIVE_WINDOWS98_DOMAIN_FAILED')
        self.assertTrue(record['collection_verified'])
        for key in ('Windows98_GUI_verified','native_Windows98_complete','ShizukuDOS_replaces_MS_DOS_validated','all_modern_apps_validated'):
            self.assertIs(record[key],False)

if __name__=='__main__':unittest.main()
