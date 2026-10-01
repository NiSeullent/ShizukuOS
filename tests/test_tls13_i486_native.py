#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test-only synthetic protocol/frame controls, never a native PASS receipt."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
import verify_tls13_i486_native as v


def native_fixture(**changes):
    rows={n:'PASS' for n in v.CHECKS}
    rows.update(NONCE=v.NONCE,CLIENT_SHA256='a'*64,SERVER_SHA256='b'*64,
        SCOPE='Native DLL interoperability; offline queues; no OS networking',
        CLIENT_PATH=v.PREFIX+'M98TLS13.DLL',SERVER_PATH=v.PREFIX+'M98TLS.DLL',UNIX_TIME='1790812800',
        POSITIVE_CLIENT_STATUS='0',POSITIVE_SERVER_STATUS='0',POSITIVE_CLIENT_ESTABLISHED='1',
        POSITIVE_CLIENT_BACKEND_ERROR='0',POSITIVE_SERVER_BACKEND_ERROR='0',POSITIVE_CLIENT_VERIFY_FLAGS='0',
        POSITIVE_SERVER_VERIFY_FLAGS='4294967295',POSITIVE_SERVER_VERSION='TLSv1.3',
        CLIENT_CERTIFICATE_AUTHENTICATION='not-requested',CHECKS='24',FAILURES='0',FINAL='PASS',REQUESTED_EXIT='0')
    rows.update(changes)
    return ''.join(k+'='+rows[k]+'\r\n' for k in v.NATIVE_ORDER).encode()


def observer_fixture(**changes):
    rows=dict(scope='actual-win98-tls-owned-child-supervisor',nonce=v.NONCE,WIN98_IDENTIFIED='1')
    rows.update({'os.major':'4','os.minor':'10','os.build-low':'2222','os.platform':'1',
        'child.path':v.PREFIX+'TLSDLL.EXE','child.stdout':v.PREFIX+'TLSOUT.LOG','child.created':'1',
        'child.create-error':'0','child.pid':'4294877739','child.wait':'0','child.exit-query':'1','child.exit-query-error':'0',
        'child.exit-code':'0','child.stdout-flushed':'1','child.handles-closed':'1','child.success':'1',
        'supervisor.requested-exit-code':'0'})
    rows.update(changes)
    return ''.join(k+'='+rows[k]+'\r\n' for k in v.OBSERVER_ORDER).encode()


class NativeProtocolControls(unittest.TestCase):
    def parse(self,raw): return v.native_protocol(raw,v.NONCE,'a'*64,'b'*64)
    def test_nominal_parser_only_no_execution_claim(self):
        r=self.parse(native_fixture());self.assertEqual(r['checks'],24)
        self.assertEqual(r['server_reported_peer_verify_flags'],0xffffffff)
        self.assertNotIn('native_dll_memory_interop_verified',r)
    def test_every_one_of24_failure_controls(self):
        for n in v.CHECKS:
            with self.subTest(check=n),self.assertRaises(ValueError):self.parse(native_fixture(**{n:'FAIL'}))
    def test_every_check_omission(self):
        for n in v.CHECKS:
            raw=native_fixture().replace((n+'=PASS\r\n').encode(),b'')
            with self.subTest(check=n),self.assertRaises(ValueError):self.parse(raw)
    def test_duplicate_check(self):
        with self.assertRaises(ValueError):self.parse(native_fixture()+b'WIN98_IDENTIFIED=PASS\r\n')
    def test_full_protocol_order_and_diagnostic_placement(self):
        rows=native_fixture().splitlines(keepends=True);rows[5],rows[6]=rows[6],rows[5]
        with self.assertRaises(ValueError):self.parse(b''.join(rows))
    def test_nonce_and_both_dll_generation_controls(self):
        for n in ('NONCE','CLIENT_SHA256','SERVER_SHA256'):
            with self.subTest(field=n),self.assertRaises(ValueError):self.parse(native_fixture(**{n:'old'}))
    def test_positive_crypto_metadata_and_tls_version(self):
        for n in v.DIAGNOSTICS:
            if n=='POSITIVE_SERVER_VERIFY_FLAGS':continue
            with self.subTest(field=n),self.assertRaises(ValueError):self.parse(native_fixture(**{n:'failed'}))
    def test_server_flags_are_informational_not_mutual_authentication(self):
        for value in ('0','128','4294967295'):
            self.assertEqual(self.parse(native_fixture(POSITIVE_SERVER_VERIFY_FLAGS=value))['server_reported_peer_verify_flags'],int(value))
    def test_flags_full_dword_bound_and_canonical_spelling(self):
        for value in ('4294967296','-1','01','0x80','True',''):
            with self.subTest(value=value),self.assertRaises(ValueError):self.parse(native_fixture(POSITIVE_SERVER_VERIFY_FLAGS=value))
    def test_native_utc_exact_boundaries(self):
        for value in ('1577836800','2051222399'):self.parse(native_fixture(UNIX_TIME=value))
        for value in ('1577836799','2051222400','-1','01','1790812800.0'):
            with self.subTest(value=value),self.assertRaises(ValueError):self.parse(native_fixture(UNIX_TIME=value))
    def test_catalog_totals_and_requested_exit(self):
        for field in ('CHECKS','FAILURES','FINAL','REQUESTED_EXIT'):
            with self.subTest(field=field),self.assertRaises(ValueError):self.parse(native_fixture(**{field:'1'}))
    def test_unknown_or_fabricated_os_fields(self):
        with self.assertRaises(ValueError):self.parse(native_fixture()+b'ACP=949\r\n')
    def test_partial_crlf_ascii_and_oversize(self):
        for raw in (b'',native_fixture()[:-1],native_fixture().replace(b'\r\n',b'\n'),b'x='+b'a'*65536+b'\r\n',b'x=\xff\r\n'):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):self.parse(raw)
    def test_embedded_control_or_blank_line(self):
        for raw in (b'A=\x00\r\n',b'A=ok\r\n\r\n',b'A=ok\nB=bad\r\n'):
            with self.assertRaises(ValueError):v.log_pairs(raw)


class ObserverControls(unittest.TestCase):
    def test_nominal_full_dword_pid_only_parser(self):
        self.assertEqual(v.observer_protocol(observer_fixture(),v.NONCE),4294877739)
    def test_every_success_field_failure(self):
        for field in v.OBSERVER_ORDER:
            if field=='child.pid':continue
            with self.subTest(field=field),self.assertRaises(ValueError):
                v.observer_protocol(observer_fixture(**{field:'wrong'}),v.NONCE)
    def test_actual_child_exit_is_not_requested_supervisor_exit(self):
        with self.assertRaises(ValueError):v.observer_protocol(observer_fixture(**{'child.exit-code':'1'}),v.NONCE)
        self.assertIs(v.FALSE_SCOPE['actual_supervisor_exit_verified'],False)
    def test_missing_close_or_flush_and_actual_wait(self):
        for field in ('child.handles-closed','child.stdout-flushed','child.wait','child.exit-query'):
            raw=observer_fixture().replace((field+'='+v.log_pairs(observer_fixture())[field]+'\r\n').encode(),b'')
            with self.subTest(field=field),self.assertRaises(ValueError):v.observer_protocol(raw,v.NONCE)
    def test_pid_bound(self):
        for n in ('0','4294967296','-1','01'):
            with self.assertRaises(ValueError):v.observer_protocol(observer_fixture(**{'child.pid':n}),v.NONCE)
    def test_observer_order_duplicate_and_extra_acp(self):
        rows=observer_fixture().splitlines(keepends=True);rows[0],rows[1]=rows[1],rows[0]
        for raw in (b''.join(rows),observer_fixture()+b'nonce=duplicate\r\n',observer_fixture()+b'os.acp=949\r\n'):
            with self.assertRaises(ValueError):v.observer_protocol(raw,v.NONCE)


class ReadControls(unittest.TestCase):
    def test_duplicate_nested_nonfinite_and_nonobject_json(self):
        for raw in (b'{"a":0,"a":1}',b'{"a":{"b":0,"b":1}}',b'{"a":NaN}',b'[]'):
            with self.assertRaises(ValueError):v.object_json(raw)
    def test_bool_integer_equal_does_not_alias(self):
        for a,b in ((True,1),(False,0),({'memory':True},{'memory':128}),({'schema':True},{'schema':1})):
            self.assertFalse(v.equal(a,b))
    def test_bounded_real_file_symlink_parent_and_fifo(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'abc');self.assertEqual(v.raw_file(p,3)[0],b'abc')
            with self.assertRaises(ValueError):v.raw_file(p,2)
            q=Path(d)/'link';q.symlink_to(p)
            with self.assertRaises(ValueError):v.raw_file(q)
            os.mkfifo(Path(d)/'fifo')
            with self.assertRaises(ValueError):v.raw_file(Path(d)/'fifo')
            (Path(d)/'directory').mkdir();(Path(d)/'directory/file').write_bytes(b'x');(Path(d)/'alias').symlink_to('directory')
            with self.assertRaises(ValueError):v.raw_file(Path(d)/'alias/file')
    def test_same_name_path_replacement_is_detected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'file';p.write_bytes(b'first');ledger=v.Ledger();ledger.take(p)
            p.unlink();p.write_bytes(b'later')
            with self.assertRaises(ValueError):ledger.final_rehash()
    def test_every_consumed_category_drift_during_second_slow_stage_check(self):
        for kind in ('run','harness','native-log','prepared-input','source','receipt','test-log','stage-proof'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                p=Path(d)/kind;p.write_bytes(b'first');ledger=v.Ledger();ledger.take(p,group=0 if kind=='stage-proof' else 2)
                def second():p.write_bytes(b'later');return {'passed':True}
                with patch.object(v,'topology',side_effect=AssertionError('must reject before topology')):
                    with self.assertRaisesRegex(ValueError,'final consumed file drift'):
                        v.final_gate(ledger,{'passed':True},second,{})
    def test_second_stage_generation_drift_before_ledger(self):
        ledger=v.Ledger()
        with patch.object(ledger,'final_rehash',side_effect=AssertionError('must not accept')):
            with self.assertRaisesRegex(ValueError,'stage generation drift'):
                v.final_gate(ledger,{'passed':True},lambda:{'passed':False},{})
    def test_native_change_during_final_topology_walk(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'native';p.write_bytes(b'first');ledger=v.Ledger();ledger.take(p,group=2)
            with patch.object(v,'topology',side_effect=lambda _:p.write_bytes(b'later')):
                with self.assertRaisesRegex(ValueError,'last source/native/run file drift'):
                    v.final_gate(ledger,{'passed':True},lambda:{'passed':True},{})
    def test_source_change_during_final_topology_walk(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'source';p.write_bytes(b'first');ledger=v.Ledger();ledger.take(p,group=1)
            with patch.object(v,'topology',side_effect=lambda _:p.write_bytes(b'later')):
                with self.assertRaisesRegex(ValueError,'last source/native/run file drift'):
                    v.final_gate(ledger,{'passed':True},lambda:{'passed':True},{})
    def test_bulk_stage_change_during_final_topology_walk(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'stage';p.write_bytes(b'first');ledger=v.Ledger();ledger.take(p,group=0)
            with patch.object(v,'topology',side_effect=lambda _:p.write_bytes(b'later')):
                with self.assertRaisesRegex(ValueError,'file drift during final ledger'):
                    v.final_gate(ledger,{'passed':True},lambda:{'passed':True},{})
    def test_wrong_fixed_helper_before_execution(self):
        with patch.object(v,'Ledger',side_effect=AssertionError('no dependency execution')):
            with self.assertRaises(ValueError):v.load_helper(None,'0'*64)
    def test_actual_catalogue_and_fixed_original_sources(self):
        ledger=v.Ledger();v.catalogue(ledger);self.assertEqual(len(v.CHECKS),24)
        for p,h in v.DEPENDENCIES.items():self.assertEqual(v.sha(v.raw_file(p)[0]),h)


class FrameControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.base=Path(self.temp.name)
        self.runs=self.base/'runs';self.runs.mkdir();self.run=self.runs/'run-win98-gop-tls13-i486-5abe-native-v1';self.run.mkdir()
        self.stage=self.base/'stage';self.stage.mkdir();self.addCleanup(patch.stopall)
        patch.object(v,'RUNS',self.runs).start();patch.object(v,'STAGE',self.stage).start()
        cold=self.runs/'cold';cold.mkdir();(cold/'result.json').write_bytes(b'{}')
        self.manifest=dict(inputs=[],outputs=[v.PREFIX+n for n in sorted(v.OUTPUTS)])
        for name in sorted(v.INPUTS):
            data=('test-only synthetic '+name).encode();h=v.sha(data)
            self.manifest['inputs'].append(dict(source=str(self.stage/name),guest=v.PREFIX+name,bytes=len(data),sha256=h))
            (self.run/('prepared-guest-'+name)).write_bytes(data)
        f=dict(manifest=str(self.stage/'guest-files.json'),manifest_sha256='c'*64,inputs=[{**r,'private_copy_sha256':r['sha256']} for r in self.manifest['inputs']],
               outputs=self.manifest['outputs'],backups=[],installed_gop_replacement=[],system_driver_file_readback=[],
               output_baseline='all absent before private injection',native_installed_and_rendered='not-established',immutable_sources_unchanged=True)
        f['immutable_sources']={str(self.stage/'guest-files.json'):'c'*64,str(self.stage/'stage-authority.json'):'d'*64,
                                **{r['source']:r['sha256'] for r in self.manifest['inputs']}}
        plan={k:x for k,x in f.items() if k not in ('system_driver_file_readback','immutable_sources_unchanged')}
        (self.run/'guest-files-plan.json').write_text(json.dumps(plan))
        f['readback']=[]
        for name,data in (('TLSOUT.LOG',b''),('TLSDLL.LOG',native_fixture()),('T13RUN.LOG',observer_fixture())):
            p=self.run/('guest-output-'+name);p.write_bytes(data)
            f['readback'].append(dict(guest=v.PREFIX+name,path=str(p),sha256=v.sha(data),bytes=len(data),status='captured',freshness='new-in-owned-run'))
        (self.run/'runner-source.py').write_bytes(v.raw_file(v.BOOT/'shizukudos/csm/test_win98_uefi.py')[0]);(self.run/'qemu.stderr').write_bytes(b'')
        (self.run/'serial.log').write_bytes(b'gop_only = true\ngop_only: forced firmware GOP + SeaVGABIOS; no VGA OpROM\nSHZGOP1 handover=0\n')
        hardware=dict(run_name=self.run.name,network='none',machine='q35',accel='kvm',memory=128,smp=2,reserve_gib=20,timeout=600,capture_interval=5,
           manual_gui=True,manual_purpose='diagnostic',firmware_gop=True,replace_csmwrap=True,native_bios_control=False,diagnostic_boot=False,
           replace_installed_gop=False,large_chromium_inputs=False,application_manifest=None,native_trial_manifest=None,
           guest_files_manifest=str(self.stage/'guest-files.json'),guest_files_manifest_sha='c'*64,resume_owned_run=str(cold),
           archive=next(iter(v.MEDIA)),checkpoint_record=list(v.MEDIA)[1])
        self.record=dict(profile='actual-win98-uefi-csmwrap',status='NEEDS-VISUAL-REVIEW',originals_unchanged=True,prepared_source_unchanged=True,
             qemu_exit_code=0,manual_finish_requested=True,guest_status={'running':True},hardware=hardware,firmware_gop_opt_in=True,immutable_sources=dict(v.MEDIA),
             source_snapshot=str(self.run/'runner-source.py'),source_sha256=v.HARNESS_SHA,guest_files=f,serial_log=str(self.run/'serial.log'),
             prepared_reuse=dict(method='verified private sparse post-run disk copy; cold hardware, new VARS, no CPU/RAM state',source_run=str(cold),
                 source_receipt_sha256=v.sha(b'{}'),source_disk_sha256='e'*64,source_allocated_bytes=4096,requires_efi_replacement=False),
             gui_interaction=dict(all_actions_completed=True,actions=[dict(sequence=1,typed=v.PREFIX+'T13RUN.EXE',status='sent; application effect requires screenshot/readback verification')]),
             firmware_gop_checks=[dict(check=n,status='PASS') for n in ('explicit GOP configuration parsed','firmware GOP retained through SeaVGABIOS',
                 'reserved native framebuffer handover emitted','legacy VGA OpROM path absent')])
    def parse(self):return v.run_frame(self.record,self.run,self.manifest,'c'*64,'d'*64,v.Ledger())
    def test_nominal_frame_is_only_synthetic_parser_control(self):
        inputs,logs=self.parse();self.assertEqual(len(inputs),8);self.assertEqual(set(logs),v.OUTPUTS)
    def test_failed_partial_stale_or_unpreserved_run(self):
        for key,value in (('status','FAIL'),('qemu_exit_code',1),('qemu_exit_code',False),('manual_finish_requested',False),
                          ('originals_unchanged',False),('prepared_source_unchanged',False),('runtime_failure','actual failure')):
            old=copy.deepcopy(self.record)
            self.record[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.parse()
            self.record=old
    def test_every_hardware_value_bool_float_and_wrong_profile(self):
        for key,value in (('memory',True),('memory',128.0),('smp',1),('reserve_gib',19),('network','user'),('accel','tcg'),
                          ('machine','pc'),('manual_gui',1),('firmware_gop',False),('manual_purpose','gui-proof')):
            old=self.record['hardware'][key];self.record['hardware'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.parse()
            self.record['hardware'][key]=old
    def test_duplicate_missing_prepared_or_input_identity(self):
        rows=self.record['guest_files']['inputs'];old=copy.deepcopy(rows)
        rows[1]=copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):self.parse()
        self.record['guest_files']['inputs']=old;(self.run/'prepared-guest-TLSDLL.EXE').unlink()
        with self.assertRaises(OSError):self.parse()
    def test_prepared_late_bytes_and_symlink_escape(self):
        p=self.run/'prepared-guest-TLSDLL.EXE';p.write_bytes(b'wrong')
        with self.assertRaises(ValueError):self.parse()
        p.unlink();p.symlink_to('/etc/passwd')
        with self.assertRaises(ValueError):self.parse()
    def test_immutable_stage_authority_or_output_order_changed(self):
        f=self.record['guest_files'];f['immutable_sources'][str(self.stage/'stage-authority.json')]='0'*64
        with self.assertRaises(ValueError):self.parse()
        f['immutable_sources'][str(self.stage/'stage-authority.json')]='d'*64;f['outputs']=list(reversed(f['outputs']))
        with self.assertRaises(ValueError):self.parse()
    def test_output_basename_outside_path_stale_partial_and_duplicate(self):
        rows=self.record['guest_files']['readback'];original=copy.deepcopy(rows)
        for field,value in (('path',str(self.run/'other.TLSDLL.LOG')),('path','/etc/passwd'),('freshness','inherited'),
                            ('status','FAIL'),('bytes',True),('sha256','0'*64)):
            rows[0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.parse()
            rows[:]=copy.deepcopy(original)
        rows[1]=copy.deepcopy(rows[0])
        with self.assertRaises(ValueError):self.parse()
    def test_nonempty_child_stdout_rejected(self):
        p=self.run/'guest-output-TLSOUT.LOG';p.write_bytes(b'failure')
        row=next(r for r in self.record['guest_files']['readback'] if r['guest']==v.PREFIX+'TLSOUT.LOG');row.update(sha256=v.sha(b'failure'),bytes=7)
        with self.assertRaises(ValueError):self.parse()
    def test_wrong_harness_copy_or_source_snapshot(self):
        self.record['source_snapshot']=str(self.run/'subdir/runner-source.py')
        with self.assertRaises(ValueError):self.parse()
        self.record['source_snapshot']=str(self.run/'runner-source.py');(self.run/'runner-source.py').write_bytes(b'wrong')
        with self.assertRaises(ValueError):self.parse()
    def test_real_fatal_serial_gop_and_stale_plan(self):
        (self.run/'qemu.stderr').write_bytes(b'KVM internal error')
        with self.assertRaises(ValueError):self.parse()
        (self.run/'qemu.stderr').write_bytes(b'');(self.run/'serial.log').write_bytes(b'not GOP')
        with self.assertRaises(ValueError):self.parse()
    def test_empty_or_noncontiguous_manual_actions_and_wrong_command(self):
        action=self.record['gui_interaction']['actions'][0];action['sequence']=True
        with self.assertRaises(ValueError):self.parse()
        action['sequence']=1;action['typed']=v.PREFIX+'WRONG.EXE'
        with self.assertRaises(ValueError):self.parse()
    def test_private_preparation_plan_changed(self):
        (self.run/'guest-files-plan.json').write_bytes(b'{}')
        with self.assertRaises(ValueError):self.parse()


class AuthorityControls(unittest.TestCase):
    """Synthetic host-control metadata only; no native verification is called."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.base=self.root/'build/tls13-i486-native-verifier-v1';self.base.mkdir(parents=True)
        self.addCleanup(patch.stopall);original_root=v.ROOT
        sources={}
        for name in v.SOURCES:
            raw=v.raw_file(original_root/name)[0];sources[name]=v.sha(raw)
            for p in (self.root/name,self.base/'source'/name):p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
        actual=Path(sys.executable).resolve();raw=v.raw_file(actual)[0];(self.base/'python-interpreter.bin').write_bytes(raw)
        import ast
        tree=ast.parse(v.raw_file(original_root/v.SOURCES[1])[0])
        count=sum(isinstance(m,ast.FunctionDef) and m.name.startswith('test_') for c in tree.body if isinstance(c,ast.ClassDef) for m in c.body)
        steps=[]
        for mode in ('normal','optimized'):
            raw=('test-only synthetic host verdict\nRan '+str(count)+' tests in 0.1s\n\nOK\n').encode();p=self.base/(mode+'.log');p.write_bytes(raw)
            steps.append(dict(mode=mode,command=[str(actual),'-B']+(['-O'] if mode=='optimized' else [])+['tests/test_tls13_i486_native.py'],returncode=0,log=str(p),sha256=v.sha(raw)))
        inputs=[]
        for n,(p,h) in enumerate(v.DEPENDENCIES.items()):
            raw=v.raw_file(p)[0];f=self.base/'inputs'/(str(n)+'.bin');f.parent.mkdir(parents=True,exist_ok=True);f.write_bytes(raw)
            inputs.append(dict(source=str(p),frozen=str(f),sha256=h,bytes=len(raw)))
        self.record=dict(schema=1,kind='tls13-i486-native-verifier-host-controls',passed=True,synthetic_tests_only=True,native_guest_verified=False,
            source_sha256=sources,methods_each=count,steps=steps,inputs=inputs,
            python_interpreter=dict(path=str(actual),sha256=v.sha(v.raw_file(actual)[0]),bytes=actual.stat().st_size,frozen=str(self.base/'python-interpreter.bin')),
            **v.FALSE_SCOPE)
        self.path=self.base/'result.json';patch.object(v,'ROOT',self.root).start()
    def parse(self):
        raw=(json.dumps(self.record)+'\n').encode();self.path.write_bytes(raw)
        return v.tested_authority(v.Ledger(),self.path,v.sha(raw))
    def test_nominal_synthetic_host_authority_has_no_native_claim(self):
        self.assertEqual(set(self.parse()),set(v.SOURCES));self.assertIs(self.record['native_guest_verified'],False)
    def test_duplicate_and_wrong_caller_authority_pin(self):
        self.parse()
        with self.assertRaises(ValueError):v.tested_authority(v.Ledger(),self.path,'0'*64)
        raw=b'{"schema":1,"schema":1}';self.path.write_bytes(raw)
        with self.assertRaises(ValueError):v.tested_authority(v.Ledger(),self.path,v.sha(raw))
    def test_boolean_schema_count_native_and_scope(self):
        for field,value in (('schema',True),('methods_each',True),('native_guest_verified',True),('vm_operations',0),('system_tls_verified',True)):
            old=self.record[field];self.record[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.parse()
            self.record[field]=old
    def test_missing_or_extra_source_closure(self):
        source=self.record['source_sha256'];old=source.pop(v.SOURCES[0])
        with self.assertRaises(ValueError):self.parse()
        source[v.SOURCES[0]]=old;source['../outside']='0'*64
        with self.assertRaises(ValueError):self.parse()
    def test_current_or_frozen_tested_source_tamper(self):
        for p in (self.root/v.SOURCES[0],self.base/'source'/v.SOURCES[0]):
            old=p.read_bytes();p.write_bytes(b'wrong')
            with self.subTest(path=str(p)),self.assertRaises(ValueError):self.parse()
            p.write_bytes(old)
    def test_dependency_outside_path_and_snapshot_name(self):
        row=self.record['inputs'][0];old=copy.deepcopy(row);row['source']='/etc/passwd'
        with self.assertRaises(ValueError):self.parse()
        row.update(old);row['frozen']=str(self.base/'other.bin')
        with self.assertRaises(ValueError):self.parse()
    def test_dependency_missing_tampered_or_boolean_size(self):
        row=self.record['inputs'][0];old=row['bytes'];row['bytes']=True
        with self.assertRaises(ValueError):self.parse()
        row['bytes']=old;Path(row['frozen']).write_bytes(b'wrong')
        with self.assertRaises(ValueError):self.parse()
    def test_interpreter_wrong_or_missing_frozen_binary(self):
        py=self.record['python_interpreter'];old=py['sha256'];py['sha256']='0'*64
        with self.assertRaises(ValueError):self.parse()
        py['sha256']=old;Path(py['frozen']).unlink()
        with self.assertRaises(OSError):self.parse()
    def test_actual_control_commands_and_bounded_verdict(self):
        row=self.record['steps'][1];row['command'].remove('-O')
        with self.assertRaises(ValueError):self.parse()
        row['command'].insert(2,'-O');row['returncode']=False
        with self.assertRaises(ValueError):self.parse()
        row['returncode']=0;raw=b'Ran 1 tests in 0.1s\n\nOK (skipped=1)\n';Path(row['log']).write_bytes(raw);row['sha256']=v.sha(raw)
        with self.assertRaises(ValueError):self.parse()
    def test_host_authority_mutation_after_its_initial_parse(self):
        self.parse();raw=self.path.read_bytes();ledger=v.Ledger();v.tested_authority(ledger,self.path,v.sha(raw))
        self.path.write_bytes(raw+b' ')
        with self.assertRaises(ValueError):ledger.final_rehash()


if __name__=='__main__':unittest.main(verbosity=2)
