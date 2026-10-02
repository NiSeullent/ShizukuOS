# SPDX-License-Identifier: GPL-2.0-only
"""Execute the real CLI body with tiny owned inputs and modeled QEMU/VMCS.

These host controls never run QEMU, original media or a Windows guest.
"""
from contextlib import contextmanager, redirect_stderr
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import shutil
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
        if mode.startswith('checkpoint_'):
            manifest=base/'checkpoint-reservation.json'
            pins={name:sha(repo/name) for name in relative}
            pins.update({m.CONTROLLER:sha(HERE/'run_vm.py'),m.OWNED_QMP:sha(HERE/'owned_capture.py'),
                         m.INFO_HEADER:sha(header)})
            for name in m.CHECKPOINT_HELPERS:pins[name]=sha(HERE/Path(name).name)
            value={'schema':'shizuku.checkpoint-controller-reservation.v1','private':True,'approved':True,
                   'scope':'private_ram_checkpoint_only','sources_sha256':pins,'checkpoint_output':str(base/'checkpoint'),
                   'budget':{'path':str(base/'budget.json'),'sha256':'0'*64,'bytes':1},
                   'compiler':{'path':str(base/'compiler'),'sha256':'0'*64,'bytes':1}}
            if mode=='checkpoint_unapproved':value['approved']=False
            if mode=='checkpoint_closure_missing':value['sources_sha256'].pop(m.CHECKPOINT_HELPERS[1])
            manifest.write_text(json.dumps(value));manifest.chmod(0o600)
            argv+=['--checkpoint-reservation',str(manifest)]
            if mode!='checkpoint_missing_sha':
                argv+=['--checkpoint-reservation-sha256','0'*64 if mode=='checkpoint_pin_mismatch' else sha(manifest)]
            out.chmod(0o700)
        def atomic(path,value):
            if mode=='receipt_failure' and path.name=='native-result.json':raise OSError('modeled final receipt failure')
            return original_atomic(path,value)
        original_atomic=u.atomic_json
        original_write=Path.write_text
        def write(path,*args,**kwargs):
            if mode=='receipt_failure' and path.name=='native-result.json':raise OSError('modeled final receipt failure')
            return original_write(path,*args,**kwargs)
        stderr=io.StringIO()
        with redirect_stderr(stderr),patch.object(m,'load',loader),patch.object(sys,'argv',argv),patch.object(m.subprocess,'Popen',Child),patch.object(m.time,'monotonic',lambda:clock[0]),patch.object(m.time,'sleep',lambda n:clock.__setitem__(0,clock[0]+n)),patch.object(m.shutil,'disk_usage',lambda path:types.SimpleNamespace(free=(m.RESERVE-1 if mode=='reserve_consumed' and clock[0]>=1 else free))),patch.object(u,'available_memory_bytes',lambda:(5<<30 if mode=='memory_short' else 1<<30 if mode=='memory_consumed' and clock[0]>=1 else 8<<30)),patch.object(u,'OwnedQMP',Monitor),patch.object(u,'atomic_json',atomic),patch.object(Path,'write_text',write):
            try:result=m.main();failure=None
            except BaseException as error:result=None;failure=error
        instance['stderr']=stderr.getvalue()
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

    def test_checkpoint_optin_requires_paired_pin_approval_and_complete_sources(self):
        for mode,expected in (('checkpoint_missing_sha','paired checkpoint reservation'),
                              ('checkpoint_pin_mismatch','checkpoint reservation SHA'),
                              ('checkpoint_unapproved','approved private controller reservation'),
                              ('checkpoint_closure_missing','complete explicit checkpoint runtime source closure')):
            with self.subTest(mode=mode):
                result,error,record,state,out=self.fixture(mode)
                self.assertIsInstance(error,SystemExit);self.assertEqual(error.code,2)
                self.assertIn(expected,state['stderr'])
                self.assertNotIn('child',state);self.assertNotIn('imported_helpers',state)
                self.assertFalse((out/'runtime-source').exists())

    def test_default_control_does_not_import_or_enable_checkpoint(self):
        result,error,record,state,_=self.fixture('normal')
        self.assertIsNone(error);self.assertEqual(result,0)
        self.assertEqual(record['capture_total_limit_bytes'],256<<20)
        self.assertEqual(record['preflight_capture_budget_bytes'],1<<30)
        self.assertNotIn('checkpoint_requested',record)
        self.assertFalse(any('checkpoint' in name for name in state['imported_helpers']))

MODEL_QMP='''import json,socket,sys
path,mode=sys.argv[1:3]
config=json.load(open(sys.argv[3]))
flat='FlatView #1\\n AS "memory", root: system\\n Root memory region: system\\n  0000000000000000-000000000009ffff (prio 0, ram): pc.ram\\n  00000000000a0000-00000000000fffff (prio 1, rom): pc.bios\\n  0000000000100000-000000007fffffff (prio 0, ram): pc.ram @0000000000100000\\n  0000000080000000-00000000ffffffff (prio 0, i/o): pci-hole\\n  0000000100000000-000000017fffffff (prio 0, ram): pc.ram @0000000080000000\\n\\n'
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as server:
 server.bind(path);server.listen(1);conn,_=server.accept()
 with conn,conn.makefile('rb') as stream:
  conn.sendall(b'{"QMP":{}}\\n');state='running'
  for line in stream:
   request=json.loads(line);name=request['execute'];args=request.get('arguments',{});answer={}
   if name=='query-blockstats':answer=[{'device':'esp','stats':{'wr_bytes':0}}]
   elif name=='query-status':answer={'running':state=='running','status':state}
   elif name=='query-version':answer={'qemu':{'major':10,'minor':1,'micro':0},'package':'EXPLICIT HOST MODEL'}
   elif name=='query-memory-size-summary':answer={'base-memory':4294967296,'plugged-memory':0}
   elif name=='human-monitor-command':answer=flat if args['command-line']=='info mtree -f' else 'EXPLICIT HOST MODEL CPU\\n'
   elif name=='stop':state='running' if mode=='paused_false' else 'paused'
   elif name=='pmemsave':
    if args['size']>8192:raise RuntimeError('model forbids any actual disk/chunk capture')
    data=(bytes.fromhex(config['info']) if state=='paused' and 'info' in config else b'\\0'*args['size']) if args['val']==67108864 else bytes.fromhex(config['map']) if 'map' in config and args['val']==536870912 else b'D'*args['size'] if 'info' in config else b'\\0'*args['size']
    with open(args['filename'],'wb') as destination:destination.write(data)
   elif name=='screendump':
    import struct
    with open(args['filename'],'wb') as image:image.write(b'\\x89PNG\\r\\n\\x1a\\n'+struct.pack('>I',13)+b'IHDR'+struct.pack('>II',1,1)+b'\\0'*9)
   elif name not in ('qmp_capabilities','quit'):raise RuntimeError('unexpected modeled command')
   conn.sendall((json.dumps({'id':request['id'],'return':answer})+'\\n').encode())
   if name=='quit' or (name=='stop' and mode=='exit_after_stop'):break
'''


class CheckpointEntryControls(unittest.TestCase):
    """Actual controller + actual pidfd/peer/leases/C proof; QMP/RAM/space modeled."""
    def fixture(self,mode):
        temporary=tempfile.TemporaryDirectory(prefix='cwire-');self.addCleanup(temporary.cleanup)
        base=Path(temporary.name);repo=base/'repo';out=base/'vm';out.mkdir(mode=0o700)
        real_repo=HERE.parents[2]
        for name in m.HELPERS+m.CHECKPOINT_HELPERS:
            path=repo/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes((real_repo/name).read_bytes())
        builder=base/'builder';header=builder/'source'/m.INFO_HEADER;header.parent.mkdir(parents=True)
        header.write_bytes((real_repo/m.INFO_HEADER).read_bytes())
        digest=lambda path:hashlib.sha256(Path(path).read_bytes()).hexdigest()
        pin=lambda path:{'path':str(path),'sha256':digest(path),'bytes':path.stat().st_size}
        inputs={};originals={}
        for key in ('esp','firmware_code','firmware_vars'):
            path=base/key;path.write_bytes(b'EXPLICIT HOST MODEL INPUT');inputs[key]=pin(path)
        inputs['qemu']=pin(Path(sys.executable).resolve())
        for key in ('DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'):
            path=base/key;path.write_bytes(b'EXPLICIT HOST MODEL ORIGINAL');originals[key]=pin(path)
        built={'status':'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN','private':True,'VM_executed':False,
               'source_before_after_match':True,'originals_before_after_match':True,'artifact':dict(inputs['esp']),
               'sources_sha256':{m.INFO_HEADER:digest(header)},'input_pins':originals}
        result=builder/'result.json';result.write_text(json.dumps(built));inputs['build_receipt']=pin(result)
        for key,name in (('esp','esp.img'),('firmware_code','OVMF_CODE.fd'),('firmware_vars','OVMF_VARS.fd')):
            (out/name).write_bytes(Path(inputs[key]['path']).read_bytes())
        program=base/'provider.py';program.write_text(MODEL_QMP);program.chmod(0o600)
        config={}
        if mode in ('small_producer','output_tamper_after_quit','final_deadline_expired',
                    'layout_return_tamper','observation_return_tamper','checkpoint_return_tamper'):
            actual_info=m.load('entry_fixture_info',real_repo/'shizukudos/tools/shzinfo.py')
            value=actual_info.Info();value.magic=actual_info.MAGIC;value.version=3;value.size=__import__('ctypes').sizeof(value)
            value.loader_flags=1;value.boot_path=1;value.disk_base=4<<20;value.disk_size=8192
            value.guest_ram_base=128<<20;value.guest_ram_size=128<<20;value.region_base=64<<20;value.region_size=16<<20
            value.k32_ram_base=256<<20;value.k32_ram_size=32<<20;value.k64_ram_base=320<<20;value.k64_ram_size=64<<20
            value.ipc_base=384<<20;value.ipc_size=4<<20;value.memmap_base=512<<20;value.memmap_bytes=40;value.memmap_desc_size=40
            value.stage=5;value.hv_instance_id=1;value.cap_bits=1<<16
            value.domains[5].kind=3;value.domains[5].generation=1;value.domains[5].state=2
            value.blobs[0].name=b'SEABIOS.BIN';value.blobs[0].base=768<<20;value.blobs[0].size=256<<10
            config={'info':(bytes(value)+b'\0'*(8192-__import__('ctypes').sizeof(value))).hex(),
                    'map':struct.pack('<IIQQQQ',2,0,4<<20,0,2,0).hex()}
        configuration=base/'provider.json';configuration.write_text(json.dumps(config));configuration.chmod(0o600)
        recipe=[str(Path(sys.executable).resolve()),'-I','-B',str(program),str(out/'qmp.sock'),mode,str(configuration),
                '-machine','q35','-serial','file:'+str(out/'serial.log')]
        plan={'status':'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN','private':True,'VM_executed':False,
              'source_bound_ESP':True,'originals_before_after_match':True,'qemu_argv':recipe,'input_pins':inputs}
        planpath=out/'plan.json';planpath.write_text(json.dumps(plan));planpath.chmod(0o600)
        nas=base/'nas';nas.mkdir(mode=0o700);(nas/'fada').mkdir(mode=0o700)
        lane=nas/'fada/replacement';lane.mkdir(mode=0o700)
        budget={'schema':'shizuku.private-checkpoint-budget.v1','private':True,'approved':mode!='budget_unapproved',
                'scope':'private_ram_checkpoint_only','approved_lane':str(lane),'disk_bytes':2<<30,
                'capture_bytes':16<<20,'total_bytes':(2<<30)+(16<<20),'retained_free_bytes':17<<30,'timeout_seconds':1}
        if config:budget.update(disk_bytes=8192,total_bytes=8192+(16<<20))
        budgetpath=base/'budget.json';budgetpath.write_text(json.dumps(budget));budgetpath.chmod(0o600)
        sources={name:digest(repo/name) for name in m.HELPERS+m.CHECKPOINT_HELPERS}
        sources.update({m.CONTROLLER:digest(HERE/'run_vm.py'),m.OWNED_QMP:digest(HERE/'owned_capture.py'),m.INFO_HEADER:digest(header)})
        manifest={'schema':'shizuku.checkpoint-controller-reservation.v1','private':True,'approved':True,
                  'scope':'private_ram_checkpoint_only','sources_sha256':sources,'budget':pin(budgetpath),
                  'compiler':pin(Path(shutil.which('gcc')).resolve()),'checkpoint_output':str(lane/'capture')}
        reservation=base/'reservation.json';reservation.write_text(json.dumps(manifest));reservation.chmod(0o600)
        argv=['run_vm.py','--repo',str(repo),'--plan',str(planpath),'--plan-sha256',digest(planpath),
              '--runtime-sources-sha256',m.helper_identity(repo)[0],'--timeout','25' if mode=='deadline_short' else '26',
              '--checkpoint-reservation',str(reservation),'--checkpoint-reservation-sha256',digest(reservation)]
        clock=[0.0];state={'evaluated_import_leases':[]};original_load=m.CheckpointMode.load_held
        original_capture=m.CheckpointMode.capture;original_audit=m.CheckpointMode.audit_held;real_sleep=m.time.sleep;pipe=[]
        def loader(owner,name,path):
            module=original_load(owner,name,path)
            state['evaluated_import_leases'].append(fcntl.fcntl(owner.raw[str(Path(path).resolve())]['fd'],fcntl.F_GETLEASE))
            if name=='native_run_preparation':module.recipe=lambda *args:recipe
            if name=='native_run_capture':
                module.available_memory_bytes=lambda:8<<30
                if mode=='close_writers_failure':
                    close=module.BoundedLogs.close_writers
                    def failed(logs):
                        close(logs);raise OSError('modeled close_writers failure after actual Popen')
                    module.BoundedLogs.close_writers=failed
                pump=module.BoundedLogs.pump
                def advance(logs,timeout=0,check=True):
                    clock[0]+=timeout;pump(logs,timeout=0,check=check)
                module.BoundedLogs.pump=advance
                call=module.OwnedQMP.call
                def qmp(monitor,name,arguments=None):
                    if name=='quit' and 'mode' in state:
                        owner=state['mode']
                        if owner.output is not None and (owner.output/'checkpoint.raw').exists():
                            state['output_read_leases_at_quit']=[fcntl.fcntl(owner.source(owner.output/file).fd,fcntl.F_GETLEASE) for file in ('checkpoint.raw','checkpoint.json')]
                            if mode=='output_tamper_after_quit':
                                raw=owner.output/'checkpoint.raw';raw.rename(owner.output/'raw.displaced');raw.write_bytes(b'corrupt')
                    return call(monitor,name,arguments)
                module.OwnedQMP.call=qmp
                state['capture_module']=module
            if name=='native_run_checkpoint':
                module.NAS_WORKSPACE=nas
                if config:module.DISK_BYTES=8192;module.CHUNK_BYTES=4096
                if mode=='checkpoint_return_tamper':
                    produce=module.capture_private_checkpoint
                    def swapped(*args):
                        expected=produce(*args);path=owner.output/'checkpoint.json'
                        changed=json.loads(path.read_bytes());changed['post_return_note']='altered canonical bytes'
                        path.write_text(json.dumps(changed,sort_keys=True,indent=2)+'\n')
                        return expected
                    module.capture_private_checkpoint=swapped
            if name=='native_run_checkpoint_adapter':
                if mode=='layout_return_tamper':
                    prove=module.prove_layout
                    def swapped(*args):
                        expected=prove(*args);path=args[-1];changed=json.loads(path.read_bytes())
                        changed['commands'][1]['stdout_sha256']='1'*64
                        path.write_text(json.dumps(changed,sort_keys=True,indent=2)+'\n')
                        return expected
                    module.prove_layout=swapped
                if mode=='observation_return_tamper':
                    observe=module.OwnedRuntime.write_observation
                    def swapped(runtime,path,*args,**kwargs):
                        expected=observe(runtime,path,*args,**kwargs);changed=json.loads(path.read_bytes())
                        changed['post_return_note']='altered canonical bytes'
                        path.write_text(json.dumps(changed,sort_keys=True,indent=2)+'\n')
                        return expected
                    module.OwnedRuntime.write_observation=swapped
            return module
        def capture(owner,*args):
            state['mode']=owner
            if mode=='source_lease_break':
                source=owner.source(owner.out/'runtime-source'/m.CHECKPOINT_HELPERS[1])
                fcntl.fcntl(source.fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
            return original_capture(owner,*args)
        def audit(owner,deadline):
            if mode=='final_deadline_expired':clock[0]=deadline+1
            if mode=='unhandled_after_reap':raise RuntimeError('modeled unhandled finalization after actual child reap')
            return original_audit(owner,deadline)
        def sleep(value):
            # Keep the 20s observation fast while giving the actual child a turn
            # during OwnedQMP connection and subprocess.wait cleanup polling.
            clock[0]+=value;real_sleep(min(value,.005))
        def space(path):
            free=m.RESERVE+(4<<30)
            if mode=='budget_capacity' and Path(path)==lane:free=budget['retained_free_bytes']+budget['total_bytes']-1
            return types.SimpleNamespace(free=free)
        with patch.object(sys,'argv',argv),patch.object(m.CheckpointMode,'load_held',loader),patch.object(m.CheckpointMode,'capture',capture),patch.object(m.CheckpointMode,'audit_held',audit),patch.object(m.time,'monotonic',lambda:clock[0]),patch.object(m.time,'sleep',sleep),patch.object(m.shutil,'disk_usage',space):
            with __import__('contextlib').ExitStack() as overrides:
                if mode=='pidfd_bad':
                    reader,writer=os.pipe();pipe.append(writer);overrides.enter_context(patch.object(m.os,'pidfd_open',lambda pid:reader))
                if mode=='compiler_admission':
                    overrides.enter_context(patch.object(m,'checkpoint_compile_admission',side_effect=RuntimeError('modeled compiler admission refusal')))
                result=m.main()
        for fd in pipe:os.close(fd)
        record=json.loads((out/'native-result.json').read_text())
        return result,record,state,out,lane

    def assert_refusal(self,result,record):
        self.assertEqual(result,1);self.assertFalse(record['collection_verified'])
        self.assertTrue(record['checkpoint_requested']);self.assertFalse(record['checkpoint_capture_verified'])
        self.assertTrue(record['receipt_persisted'])
        for name in ('Windows98_GUI_verified','native_Windows98_complete','ShizukuDOS_replaces_MS_DOS_validated','all_modern_apps_validated','VMM_boot_verified','Windows98_boot_verified','cold_boot_persistence_verified','live_storage_flush_verified'):
            self.assertIn(name,record,record)
            self.assertIs(record[name],False)
        self.assertIs(record['checkpoint_runtime_readiness']['actual_optional_controller_admitted'],False)
        self.assertIs(record['checkpoint_runtime_readiness']['external_unreaped_child_custody_verified'],False)

    def test_real_entry_refuses_unapproved_capacity_short_deadline_and_compiler_admission(self):
        for mode in ('budget_unapproved','budget_capacity','deadline_short','compiler_admission'):
            with self.subTest(mode=mode):
                result,record,state,out,lane=self.fixture(mode);self.assert_refusal(result,record)
                self.assertFalse(record['VM_executed']);self.assertFalse((lane/'capture').exists())
                self.assertTrue(state['evaluated_import_leases'])
                self.assertEqual(set(state['evaluated_import_leases']),{fcntl.F_RDLCK})

    def test_real_entry_refuses_wrong_pidfd_lease_break_pause_and_owned_exit(self):
        for mode in ('pidfd_bad','source_lease_break','paused_false','exit_after_stop'):
            with self.subTest(mode=mode):
                result,record,state,out,lane=self.fixture(mode);self.assert_refusal(result,record)
                self.assertTrue(record['VM_executed']);self.assertTrue(record['owned_child_reaped'])
                self.assertFalse((lane/'capture/checkpoint.json').exists())
                self.assertTrue(record['original_disk_unchanged'])

    def test_real_entry_reaches_actual_frozen_producer_then_rejects_modeled_zero_info(self):
        result,record,state,out,lane=self.fixture('normal');self.assert_refusal(result,record)
        self.assertTrue(record['owned_child_reaped']);self.assertTrue(record['quit_acknowledged'])
        self.assertFalse(record['forced_cleanup']);self.assertTrue(record['final_pause_acknowledged'])
        self.assertTrue((out/'checkpoint-layout.json').exists());self.assertTrue((out/'checkpoint-ram.json').exists())
        self.assertEqual((lane/'capture/info-before.bin').stat().st_size,8192)
        self.assertFalse((lane/'capture/checkpoint.raw').exists());self.assertFalse((lane/'capture/checkpoint.json').exists())
        self.assertEqual(state['mode'].runtime.monitor.deadline,state['mode'].runtime.deadline)

    def test_small_full_producer_model_holds_output_leases_and_provenance_through_reap(self):
        result,record,state,out,lane=self.fixture('small_producer')
        self.assertEqual(result,0,record);self.assertTrue(record['collection_verified'])
        self.assertTrue(record['checkpoint_capture_verified']);self.assertTrue(record['owned_child_reaped'])
        self.assertEqual(state['output_read_leases_at_quit'],[fcntl.F_RDLCK,fcntl.F_RDLCK])
        self.assertTrue(record['checkpoint_held_input_sha_verified_after_reap'])
        self.assertTrue(record['checkpoint_outputs_read_leased_through_reap'])
        self.assertIs(record['checkpoint_runtime_readiness']['actual_optional_controller_admitted'],False)
        self.assertEqual((lane/'capture/checkpoint.raw').read_bytes(),b'D'*8192)
        self.assertEqual(state['mode'].runtime.monitor.deadline,state['mode'].runtime.deadline)
        for name in ('Windows98_boot_verified','VMM_boot_verified','cold_boot_persistence_verified','live_storage_flush_verified'):
            self.assertIs(record[name],False)

    def test_small_producer_output_swap_at_quit_vetoes_controller_acceptance(self):
        result,record,state,out,lane=self.fixture('output_tamper_after_quit')
        self.assert_refusal(result,record)
        self.assertTrue(record['owned_child_reaped']);self.assertFalse(record['checkpoint_held_input_sha_verified_after_reap'])
        self.assertFalse(record['checkpoint_outputs_read_leased_through_reap'])

    def test_small_producer_expired_original_deadline_vetoes_final_sha_acceptance(self):
        result,record,state,out,lane=self.fixture('final_deadline_expired')
        self.assert_refusal(result,record)
        self.assertTrue(record['quit_acknowledged']);self.assertTrue(record['owned_child_reaped'])
        self.assertFalse(record['checkpoint_held_input_sha_verified_after_reap'])
        self.assertFalse(record['checkpoint_outputs_read_leased_through_reap'])
        self.assertEqual(state['mode'].runtime.monitor.deadline,state['mode'].runtime.deadline)

    def test_all_post_return_proof_serialization_swaps_veto_real_entry_acceptance(self):
        for mode in ('layout_return_tamper','observation_return_tamper','checkpoint_return_tamper'):
            with self.subTest(mode=mode):
                result,record,state,out,lane=self.fixture(mode)
                self.assert_refusal(result,record)
                self.assertIn('returned producer serialization',str(record['harness_errors']))

    def test_unhandled_finalization_preserves_actual_launch_and_reap_in_failed_fallback(self):
        result,record,state,out,lane=self.fixture('unhandled_after_reap')
        self.assert_refusal(result,record)
        self.assertTrue(record['VM_executed']);self.assertTrue(record['owned_child_reaped'])
        self.assertTrue(record['quit_acknowledged']);self.assertFalse(record['forced_cleanup'])
        self.assertNotIn('prelaunch',record['scope'])
        self.assertIn('modeled unhandled finalization',str(record['harness_errors']))

    def test_close_writers_failure_preserves_actual_launch_pid_and_reap(self):
        result,record,state,out,lane=self.fixture('close_writers_failure')
        self.assert_refusal(result,record)
        self.assertTrue(record['VM_executed']);self.assertGreater(record['owned_pid'],0)
        self.assertTrue(record['owned_child_reaped']);self.assertTrue(record['forced_cleanup'])
        self.assertFalse(record['unresolved_owned_child'])
        self.assertIn('modeled close_writers failure',str(record['harness_errors']))


class CheckpointBoundaryControls(unittest.TestCase):
    def test_failed_fallback_preserves_modeled_unresolved_child_and_cleanup_truth(self):
        with tempfile.TemporaryDirectory(prefix='cwire-fallback-') as temporary:
            mode=m.CheckpointMode.__new__(m.CheckpointMode);mode.out=Path(temporary);mode.manifest_pin='1'*64
            mode.record={'scope':'modeled launched attempt with unresolved child','VM_executed':True,
                         'owned_pid':123,'owned_child_reaped':False,'unresolved_owned_child':True,
                         'leases_released_after_reap':False,'forced_cleanup':True,'quit_acknowledged':False,
                         'cleanup_errors':[{'operation':'kill_wait','type':'TimeoutExpired'}],
                         'collection_verified':True,'checkpoint_capture_verified':True}
            mode.preflight_failure(RuntimeError('modeled unhandled cleanup finalization'))
            record=json.loads((mode.out/'native-result.json').read_bytes())
            for key in ('VM_executed','owned_pid','owned_child_reaped','unresolved_owned_child','leases_released_after_reap','forced_cleanup','quit_acknowledged','cleanup_errors'):
                self.assertEqual(record[key],mode.record[key])
            self.assertFalse(record['collection_verified']);self.assertFalse(record['checkpoint_capture_verified'])
            self.assertIs(record['checkpoint_runtime_readiness']['actual_optional_controller_admitted'],False)

    def test_finite_ancestor_memory_and_pids_limits_veto_layout_compiler(self):
        read=Path.read_text;exists=Path.exists
        base=Path('/sys/fs/cgroup');leaf=base/'modeled-parent/modeled-leaf';parent=leaf.parent
        for exhausted in ('memory','pids'):
            values={}
            for directory in (leaf,parent):
                values.update({directory/name:value for name,value in {'memory.current':'0','memory.high':str(1<<30),
                    'memory.max':str(1280<<20),'pids.current':'0','pids.max':'64'}.items()})
            values[parent/('memory.current' if exhausted=='memory' else 'pids.current')]=str((1<<30)-(128<<20)) if exhausted=='memory' else '63'
            values[Path('/proc/self/cgroup')]='0::/modeled-parent/modeled-leaf\n'
            values[Path('/proc/meminfo')]='MemAvailable: 8388608 kB\n'
            def modeled(path,*args,**kwargs):return values[path] if path in values else read(path,*args,**kwargs)
            def present(path):return path in values if path.is_relative_to(base) else exists(path)
            with self.subTest(exhausted=exhausted),patch.object(Path,'read_text',modeled),patch.object(Path,'exists',present):
                with self.assertRaisesRegex(RuntimeError,'ancestor.*admission'):
                    m.checkpoint_compile_admission()

    def test_failed_preflight_fsync_does_not_unlink_a_replaced_foreign_receipt(self):
        with tempfile.TemporaryDirectory(prefix='cwire-publish-') as temporary:
            mode=m.CheckpointMode.__new__(m.CheckpointMode);mode.out=Path(temporary);mode.manifest_pin='1'*64;mode.record=None
            path=mode.out/'native-result.json';foreign=b'foreign replacement receipt\n';real_fsync=os.fsync;count=[0]
            def failed(fd):
                count[0]+=1
                if count[0]==1:
                    path.unlink();path.write_bytes(foreign);raise OSError('modeled receipt fsync failure')
                return real_fsync(fd)
            with patch.object(m.os,'fsync',failed):
                with self.assertRaisesRegex(OSError,'modeled receipt fsync failure'):
                    mode.preflight_failure(RuntimeError('prelaunch model refusal'))
            self.assertTrue(path.exists());self.assertEqual(path.read_bytes(),foreign)


if __name__=='__main__':unittest.main()
