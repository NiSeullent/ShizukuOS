#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one bounded owned native Windows98 VM plan; preserve failures as evidence.

L0 KVM hosts L1 OVMF/Supervisor, which must itself create the L2 Windows98 VMCS.
The explicitly selected private disk has unverified DOS/Windows execution.
QEMU exit or VMCS launch never proves the Windows98 foundation.
"""
import argparse
from contextlib import ExitStack
import ctypes
import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import time

RESERVE=17<<30
WRITE_BUDGET=256<<20


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for data in iter(lambda:stream.read(1<<20),b''):h.update(data)
    return h.hexdigest()


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


HELPERS=('shizukudos/supervisor/native_win98/build.py',
         'shizukudos/supervisor/native_win98/prepare_vm.py',
         'shizukudos/tools/qemu.py','shizukudos/tools/shzinfo.py')
RUNTIME_ORIGINALS=(*HELPERS,'shizukudos/supervisor/native_win98/run_vm.py',
                   'shizukudos/supervisor/native_win98/owned_capture.py','shizukudos/supervisor/include/shz_info.h')


def unique_fields(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('duplicate original metadata field')
        result[key]=value
    return result


class GuardianOriginalInputs:
    """Controller custody of actual duplicate FDs, never independent SHA proof."""
    def __init__(self,custody,stack):self.custody,self.stack,self.rows=custody,stack,{}
    def admit(self,item):
        key=item['path']
        if key in self.rows:
            if self.rows[key].pin!=item:raise ValueError('conflicting original pins')
            return self.rows[key]
        entry=self.stack.enter_context(self.custody.borrow_original(item));self.rows[key]=entry;return entry
    def check(self):self.custody.check_originals()
    def read(self,item,maximum):
        if type(item['bytes']) is not int or not 0<item['bytes']<=maximum:raise ValueError('bounded original metadata/source')
        entry=self.admit(item);data=bytearray()
        while len(data)<item['bytes']:
            self.check();block=os.pread(entry.fd,min(1<<20,item['bytes']-len(data)),len(data))
            if not block:raise ValueError('short borrowed original read')
            data.extend(block)
        self.check()
        if os.pread(entry.fd,1,item['bytes']):raise ValueError('borrowed original grew')
        return bytes(data)
    def json(self,item,maximum=16<<20):
        return json.loads(self.read(item,maximum),object_pairs_hook=unique_fields,
                          parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite original metadata')))
    def audit(self,item):
        entry=self.rows.get(item['path'])
        if entry is None or entry.pin!=item:raise ValueError('original was not admitted before final audit')
        self.check();return True
    def evidence(self):
        self.check()
        return [{'pin':entry.pin,'identity':list(entry.identity),'guardian_pid':entry.guardian_pid,
                 'guardian_initial_full_SHA_admitted':True,'controller_independent_full_SHA_readback':False}
                for entry in self.rows.values()]


def helper_identity(repo):
    """Explicit caller pin, distinct from the historical ESP producer sources."""
    for name in HELPERS:
        if not 0<(repo/name).stat().st_size<=1<<20:raise ValueError('bounded nonempty runtime helper source required')
    pins={name:sha(repo/name) for name in HELPERS}
    return hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest(),pins


def cleanup_owned(child,monitor,record,pump=lambda:None):
    """Every lifecycle failure is retained; only our own Popen is signalled."""
    record.update(quit_acknowledged=False,forced_cleanup=False,owned_child_reaped=False,cleanup_errors=[])
    if child is None:return
    def error(operation,failure):
        record['cleanup_errors'].append({'operation':operation,'type':type(failure).__name__})
    def wait_owned(timeout):
        stop=time.monotonic()+timeout
        while True:
            pump()
            remaining=stop-time.monotonic()
            if remaining<=0:raise subprocess.TimeoutExpired('owned QEMU',timeout)
            try:return child.wait(timeout=min(.1,remaining))
            except subprocess.TimeoutExpired:
                # Continue draining pipes while the owned process shuts down.
                time.sleep(min(.02,max(0,stop-time.monotonic())))
    try:
        if child.poll() is None:
            try:
                if monitor is None:raise RuntimeError('owned QMP was unavailable for quit')
                monitor.deadline=time.monotonic()+5
                monitor.call('quit');record['quit_acknowledged']=True
            except (Exception,KeyboardInterrupt) as failure:error('quit',failure)
        else:record['natural_exit_observed']=True
        try:wait_owned(5);record['owned_child_reaped']=True
        except (Exception,KeyboardInterrupt) as failure:
            error('wait',failure);record['forced_cleanup']=True
            try:child.terminate()
            except (Exception,KeyboardInterrupt) as failure:error('terminate',failure)
            try:wait_owned(3);record['owned_child_reaped']=True
            except (Exception,KeyboardInterrupt) as failure:
                error('terminate_wait',failure)
                try:child.kill()
                except (Exception,KeyboardInterrupt) as failure:error('kill',failure)
                try:wait_owned(3);record['owned_child_reaped']=True
                except (Exception,KeyboardInterrupt) as failure:error('kill_wait',failure)
    except (Exception,KeyboardInterrupt) as failure:error('poll',failure)
    finally:
        if monitor is not None:
            try:monitor.close()
            except (Exception,KeyboardInterrupt) as failure:error('monitor_close',failure)


def esp_write_bytes(stats,last):
    if not isinstance(stats,list):raise ValueError('blockstats must be a list')
    matches=[s for s in stats if isinstance(s,dict) and s.get('device')=='esp']
    if len(matches)!=1:raise ValueError('exactly one owned ESP backend is required')
    s=matches[0].get('stats');value=s.get('wr_bytes') if isinstance(s,dict) else None
    if type(value) is not int or value<0:raise ValueError('ESP write counter must be nonnegative integer')
    if value<last:raise RuntimeError('ESP write counter reset')
    if value>WRITE_BUDGET:raise RuntimeError('ESP sampled write budget exceeded')
    return value


def evidence_status(info):
    if info is None:return 'NATIVE_INFO_UNAVAILABLE'
    if info.get('loader_flags')!=1 or info.get('boot_path')!=1 or info.get('guest_ram_size')!=128<<20 or info.get('disk_size')!=2<<30:
        raise ValueError('native info does not match explicit UEFI 128 MiB/2 GiB geometry')
    domain=info.get('domains',{}).get('WIN98')
    if domain and domain.get('state')==4:return 'NATIVE_WINDOWS98_DOMAIN_FAILED'
    if info.get('stage')==0xdead:return 'SUPERVISOR_FAILED'
    if domain and domain.get('exits',0)>0:return 'NATIVE_VMCS_RUNNING_WINDOWS_BOOT_UNVERIFIED'
    if domain:return 'NATIVE_DOMAIN_CREATED_CPU_EXECUTION_UNVERIFIED'
    return 'NATIVE_DOMAIN_NOT_CREATED'


def timeout_valid(value):
    return type(value) is int and 20<=value<=900


def get_custody(fd):
    if fd is None:raise ValueError("run this CLI through the independently admitted task guardian")
    module=sys.modules.get("native_custody_rpc")
    if module is None:raise ValueError("guardian held-byte bootstrap required")
    return module.Client(fd,os.getppid())


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--runtime-sources-sha256',required=True,
                        help='SHA256 of the sorted four-helper SHA map; see helper_identity()')
    parser.add_argument('--timeout',type=int,default=300)
    parser.add_argument('--custody-fd',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--plan-bytes',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--runtime-source-pins-json',help=argparse.SUPPRESS)
    parser.add_argument('--pci-preparation-json',help=argparse.SUPPRESS)
    args=parser.parse_args()
    custody=get_custody(args.custody_fd)
    leases=ExitStack()
    try:return run_plan(args,parser,custody,leases)
    finally:
        try:leases.close()
        finally:
            if custody is not None:custody.close()


def run_plan(args,parser,custody,leases):
    borrowed=GuardianOriginalInputs(custody,leases) if custody is not None else None
    pci_raw=getattr(args,'pci_preparation_json',None)
    pci_selection=None; pci_adapter=None; pci_expected=None
    if pci_raw is not None:
        if borrowed is None or type(pci_raw) is not str or len(pci_raw.encode())>16384:
            raise ValueError('PCI preparation requires bounded guardian-selected retained originals')
        pci_selection=json.loads(pci_raw,object_pairs_hook=unique_fields)
        if type(pci_selection) is not dict:raise ValueError('explicit PCI selection object required')
    runtime_names=RUNTIME_ORIGINALS+ (('tools/native_pci_preparation.py',) if pci_selection is not None else ())
    if not timeout_valid(args.timeout):parser.error('timeout must be 20..900 seconds')
    plan_size=args.plan_bytes if borrowed is not None else args.plan.stat().st_size
    if type(plan_size) is not int or not 0<plan_size<=16<<20:parser.error('private plan must be nonempty and at most 16 MiB')
    plan_pin={'path':str(args.plan),'sha256':args.plan_sha256,'bytes':plan_size}
    if borrowed is None:
        if sha(args.plan)!=args.plan_sha256:parser.error('explicit private VM plan SHA mismatch')
        identity,helper_pins=helper_identity(args.repo);plan=json.loads(args.plan.read_text())
    else:
        plan=borrowed.json(plan_pin)
        raw=args.runtime_source_pins_json
        if type(raw) is not str or len(raw.encode())>16384:raise ValueError('bounded exact runtime original pin map required')
        runtime_pins=json.loads(raw,object_pairs_hook=unique_fields)
        if type(runtime_pins) is not dict or set(runtime_pins)!=set(runtime_names):raise ValueError('exact runtime original pins including selected adapter required')
        for item in runtime_pins.values():
            if type(item) is not dict or set(item)!={'path','bytes','sha256'} or type(item['bytes']) is not int or not 0<item['bytes']<=1<<20 or type(item['sha256']) is not str:
                raise ValueError('bounded typed runtime original source pin')
        helper_pins={name:runtime_pins[name]['sha256'] for name in HELPERS}
        identity=hashlib.sha256(json.dumps(helper_pins,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        if identity!=args.runtime_sources_sha256:parser.error('explicit runtime helper identity differs')
        for name in runtime_names:
            item=runtime_pins[name]
            expected=(Path(__file__) if name.endswith('/run_vm.py') else Path(__file__).with_name('owned_capture.py')) if name in RUNTIME_ORIGINALS[4:6] else args.repo/name
            if name==RUNTIME_ORIGINALS[-1]:expected=Path(plan['input_pins']['build_receipt']['path']).parent/'source'/name
            if item['path']!=str(expected):raise ValueError('runtime source origin differs from exact guardian selection')
            borrowed.admit(item)
    if identity!=args.runtime_sources_sha256:parser.error('explicit runtime helper identity differs')
    preparation_pins=plan.get('preparation_runtime_helpers_sha256')
    if preparation_pins is not None and preparation_pins!=helper_pins:
        parser.error('preparation helper pins differ from the explicitly supplied runtime helpers')
    if plan.get('status')!='PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN' or plan.get('private') is not True or plan.get('VM_executed') is not False or not plan.get('source_bound_ESP') or not plan.get('originals_before_after_match'):
        parser.error('fresh source-bound no-execution native plan is required')
    out=args.plan.resolve().parent
    if (out/'native-result.json').exists():parser.error('this owned plan has already been run')
    frozen=out/'runtime-source';frozen.mkdir(mode=0o700)
    paths={name:args.repo/name for name in HELPERS}
    paths.update({'shizukudos/supervisor/native_win98/run_vm.py':Path(__file__),
                  'shizukudos/supervisor/native_win98/owned_capture.py':Path(__file__).with_name('owned_capture.py')})
    if pci_selection is not None:paths['tools/native_pci_preparation.py']=args.repo/'tools/native_pci_preparation.py'
    source_pins={};source_sizes={}
    for relative,source in paths.items():
        if borrowed is None:
            if source.stat().st_size>1<<20:parser.error('one runtime source exceeded 1 MiB')
            raw=source.read_bytes()
        else:raw=borrowed.read(runtime_pins[relative],1<<20)
        target=frozen/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(raw)
        if custody is not None:custody.admit_frozen(target,relative)
        source_pins[relative]=sha(target)
        source_sizes[relative]=target.stat().st_size
        if relative in helper_pins and source_pins[relative]!=helper_pins[relative]:
            parser.error('runtime helper changed while freezing')
    native=frozen/'shizukudos/supervisor/native_win98'
    loader=custody.load if custody is not None else load
    capture=loader('native_run_capture',native/'owned_capture.py')
    guards=loader('native_run_guards',native/'build.py')
    preparation=loader('native_run_preparation',native/'prepare_vm.py')
    info_helper=loader('native_run_info',frozen/'shizukudos/tools/shzinfo.py')
    if pci_selection is not None:
        pci_adapter=loader('native_run_pci_preparation',frozen/'tools/native_pci_preparation.py')
        pci_expected=pci_adapter.admit_selection(pci_selection,plan,borrowed.read)
        borrowed.check()
    build_pin=plan['input_pins']['build_receipt']
    if borrowed is None:
        guards.pinned_hash(Path(build_pin['path']),build_pin['sha256'],build_pin['bytes'],16<<20)
        built=json.loads(Path(build_pin['path']).read_text())
    else:built=borrowed.json(build_pin)
    if built.get('status')!='PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN' or built.get('private') is not True or built.get('VM_executed') is not False or not built.get('source_before_after_match') or not built.get('originals_before_after_match'):
        raise ValueError('native builder receipt failed its source/identity gates')
    if set(built.get('input_pins',{}))!={'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'}:
        raise ValueError('all six original native builder input pins are required')
    if set(plan.get('input_pins',{}))!={'esp','build_receipt','firmware_code','firmware_vars','qemu'}:
        raise ValueError('all five private VM preparation input pins are required')
    esp_pin=plan['input_pins']['esp']
    if built.get('artifact',{}).get('sha256')!=esp_pin['sha256'] or built.get('artifact',{}).get('bytes')!=esp_pin['bytes']:
        raise ValueError('ESP differs from the pinned source-bound builder artifact')
    header_name='shizukudos/supervisor/include/shz_info.h'
    header=Path(build_pin['path']).parent/'source'/header_name
    if borrowed is None:
        if sha(header)!=built['sources_sha256'][header_name]:raise ValueError('evidence header differs from source-bound builder')
        raw=header.read_bytes()
    else:
        hrow=runtime_pins[header_name]
        if hrow['path']!=str(header) or hrow['sha256']!=built['sources_sha256'][header_name]:raise ValueError('exact retained evidence header differs')
        raw=borrowed.read(hrow,1<<20)
    target=frozen/header_name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(raw)
    if custody is not None:custody.admit_frozen(target,header_name)
    source_pins[header_name]=sha(target)
    source_sizes[header_name]=target.stat().st_size
    layout_bytes=(custody.layout(info_helper,target) if custody is not None else info_helper.selfcheck(frozen))
    qemu=Path(plan['input_pins']['qemu']['path'])
    recipe=preparation.recipe(qemu,out)
    if recipe!=plan['qemu_argv']:raise ValueError('VM argv differs from the exact source recipe')
    for key,name in [('esp','esp.img'),('firmware_code','OVMF_CODE.fd'),('firmware_vars','OVMF_VARS.fd')]:
        item=plan['input_pins'][key];guards.pinned_hash(out/name,item['sha256'],item['bytes'],max(item['bytes'],4<<20))
        owned=(out/name).stat()
        original=borrowed.admit(item).identity[:2] if borrowed is not None else (lambda s:(s.st_dev,s.st_ino))(Path(item['path']).stat())
        if (owned.st_dev,owned.st_ino)==original:raise ValueError('VM input must have a distinct owned inode')
    if borrowed is None:guards.pinned_hash(qemu,plan['input_pins']['qemu']['sha256'],plan['input_pins']['qemu']['bytes'],64<<20)
    else:
        if not 0<plan['input_pins']['qemu']['bytes']<=64<<20:raise ValueError('bounded QEMU original')
        borrowed.admit(plan['input_pins']['qemu'])
    if shutil.disk_usage(out).free<RESERVE+capture.PREFLIGHT_BUDGET:
        parser.error('17 GiB reserve plus the 1 GiB bounded capture budget required')
    if capture.available_memory_bytes()<capture.MEMORY_ADMISSION:
        parser.error('6 GiB MemAvailable required for the owned 4 GiB VM and host margin')
    record={'status':'NATIVE_CAPTURE_PREPARING','scope':'L1 UEFI Supervisor -> L2 Windows98 domain using the explicitly selected private disk; DOS and Windows execution unverified',
            'requested_timeout_seconds':args.timeout,'cleanup_wait_budget_seconds':16,
            'plan_sha256':args.plan_sha256,'builder_receipt_sha256':build_pin['sha256'],
            'runtime_helpers_identity_sha256':identity,'preparation_helper_source_pins_verified':preparation_pins is not None,
            'source_pins':source_pins,'C_Python_evidence_layout_bytes':layout_bytes,'firmware_bytes':4<<20,'L1_memory_bytes':4<<30,'L2_memory_bytes':128<<20,
            'VM_executed':False,'SMP_verified':False,'ISO_verified':False,'Windows98_GUI_verified':False,'native_Windows98_complete':False,'ShizukuDOS_replaces_MS_DOS_validated':False,'all_modern_apps_validated':False,
            'sampled_ESP_write_budget_bytes':WRITE_BUDGET,'write_budget_verified':False,'captures':[],
            'retained_free_space_bytes':RESERVE,'preflight_capture_budget_bytes':capture.PREFLIGHT_BUDGET,
            'log_limit_per_stream_bytes':capture.LOG_LIMIT,'capture_total_limit_bytes':capture.CAPTURE_LIMIT,
            'host_memory_admission_bytes':capture.MEMORY_ADMISSION,'host_memory_floor_bytes':capture.MEMORY_FLOOR,
            'collection_verified':False,'receipt_persisted':False,'lease_integrity_verified':False}
    checkpoints=[];child=monitor=logs=None;start=time.monotonic()
    record.update(original_integrity_method=('GUARDIAN_INITIAL_FULL_SHA_AND_CONTINUOUS_SHARED_READ_LEASE_IDENTITY' if borrowed is not None else 'CONTROLLER_INDEPENDENT_FULL_SHA_AND_READ_LEASE'),
                  controller_independent_original_full_SHA_readback=borrowed is None,
                  guardian_late_full_SHA_closure_pending=borrowed is not None,guardian_PID1_final_join_required=borrowed is not None)
    last_info=None;last_writes=0;failure_seen=None;cleaning=False
    def pump():
        if logs is not None:logs.pump(check=not cleaning)
        if not cleaning:
            for checkpoint in checkpoints:checkpoint()
            if shutil.disk_usage(out).free<RESERVE:raise RuntimeError('17 GiB retained reserve consumed')
            if capture.available_memory_bytes()<capture.MEMORY_FLOOR:raise RuntimeError('2 GiB host memory margin consumed')
            capture.capture_bytes(out)
    def fail(operation,error):
        record['status']='NATIVE_CAPTURE_HARNESS_FAILED'
        record.setdefault('harness_errors',[]).append({'operation':operation,'type':type(error).__name__,'error':str(error)})
    try:
        # Lease each original identity once. Never lease the writable VM ESP/VARS.
        leased={}
        items=list(built['input_pins'].values())+list(plan['input_pins'].values())
        items += [{'path':str(args.plan),'sha256':args.plan_sha256,'bytes':plan_size},
                  {'path':str(header),'sha256':source_pins[header_name],'bytes':source_sizes[header_name]}]
        items += [{'path':str(paths[name]),'sha256':pin,'bytes':source_sizes[name]} for name,pin in source_pins.items() if name in paths]
        for item in items:
            path=Path(item['path']) if borrowed is not None else Path(item['path']).resolve();key=str(path)
            pin=(item['sha256'],item['bytes'])
            if key in leased:
                if leased[key]!=pin:raise ValueError('conflicting pins for one original input')
                continue
            if borrowed is None:
                _,checkpoint=leases.enter_context(guards.read_leased(path,pin[0],pin[1],maximum=max(pin[1],4<<20)));checkpoints.append(checkpoint)
            else:borrowed.admit(item)
            leased[key]=pin
        if borrowed is not None:checkpoints.append(borrowed.check)
        logs=capture.BoundedLogs(out)
        command=list(recipe)
        serial=command.index('-serial')+1
        if command[serial]!=f'file:{out / "serial.log"}':raise ValueError('exact serial recipe required')
        command[serial]=f'file:/proc/self/fd/{logs.writers["serial.log"]}'
        command += ['-debugcon',f'file:/proc/self/fd/{logs.writers["e9.log"]}','-global','isa-debugcon.iobase=0xe9']
        capture.atomic_json(out/'native-command.json',command);record['command_sha256']=sha(out/'native-command.json')
        child=(custody.spawn(command,logs.writers) if custody is not None else
               subprocess.Popen(command,cwd=out,stdout=subprocess.DEVNULL,stderr=logs.writers['native-qemu.stderr'],
                                pass_fds=(logs.writers['serial.log'],logs.writers['e9.log'])))
        # The real guardian spawn ACK (or modeled host Popen) is the boundary.
        record['owned_pid']=child.pid;record['VM_executed']=True;start=time.monotonic()
        if custody is not None:
            capture.atomic_json(out/'native-command.json',child.args);record['command_sha256']=sha(out/'native-command.json')
        logs.close_writers()
        print(json.dumps({'stage':'native-owned-VM-started','pid':child.pid}),flush=True)
        monitor=capture.OwnedQMP(out/'qmp.sock',child.pid,start+args.timeout,pump=pump)
        if custody is not None:custody.admit_qmp(monitor)
        next_capture=10
        while child.poll() is None and time.monotonic()-start<args.timeout:
            elapsed=time.monotonic()-start;pump()
            last_writes=esp_write_bytes(monitor.call('query-blockstats'),last_writes)
            if elapsed>=next_capture:
                stem='native-%03d'%len(record['captures']);sample={'seconds':round(elapsed,3)}
                registers=monitor.hmp('info registers')
                if not isinstance(registers,str) or len(registers.encode())>256<<10:raise ValueError('bounded CPU register text required')
                cpu=out/(stem+'-cpu.txt');cpu.write_text(registers);sample['cpu_sha256']=sha(cpu)
                image=out/(stem+'.png');monitor.call('screendump',{'filename':str(image),'format':'png'})
                sample['PNG_geometry']=capture.check_png(image);sample['PNG_sha256']=sha(image)
                memory=out/(stem+'-info.bin');monitor.call('pmemsave',{'val':info_helper.REGION_BASE,'size':info_helper.INFO_BYTES,'filename':str(memory)})
                if memory.stat().st_size!=info_helper.INFO_BYTES:raise ValueError('evidence memory capture has incorrect size')
                raw=memory.read_bytes();sample['info_sha256']=sha(memory)
                info=info_helper.Info.parse(raw)
                if info.magic==info_helper.MAGIC and info.version==3 and info.size==layout_bytes:
                    last_info=info.to_dict();sample['native_status']=evidence_status(last_info)
                    capture.atomic_json(out/(stem+'-info.json'),last_info)
                    sample['stage']=last_info['stage_name'];sample['WIN98_domain']=last_info['domains'].get('WIN98')
                    if sample['native_status'] in ('NATIVE_WINDOWS98_DOMAIN_FAILED','SUPERVISOR_FAILED') and failure_seen is None:failure_seen=elapsed
                else:sample['native_status']='NATIVE_INFO_UNAVAILABLE'
                sample['QEMU_status']=monitor.call('query-status');sample['sampled_ESP_write_bytes']=last_writes
                record['captures'].append(sample);record['last_info']=last_info
                capture.capture_bytes(out);capture.atomic_json(out/'native-progress.json',record)
                print(json.dumps({'stage':'native-capture','seconds':sample['seconds'],'status':sample['native_status']}),flush=True)
                next_capture=elapsed+20
            if failure_seen is not None and elapsed-failure_seen>=20:break
            logs.pump(timeout=min(1,max(0,start+args.timeout-time.monotonic())))
        # Observation deadline is distinct from the bounded final sample/cleanup.
        monitor.deadline=time.monotonic()+5
        monitor.call('stop');record['final_pause_acknowledged']=True
        last_writes=esp_write_bytes(monitor.call('query-blockstats'),last_writes)
        record['write_budget_verified']=True;record['status']=evidence_status(last_info)
        if pci_expected is not None:
            def pci_guard():
                pump();borrowed.check()
                if custody.ordinary('live-check') is not True:raise ValueError('guardian live/QMP identity refused')
                peer=struct.unpack('3i',monitor.socket.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                if peer[:2]!=(child.pid,os.getuid()):raise ValueError('current QMP peer differs from guardian child')
            record['pci_preparation']=pci_adapter.current_qmp_observation(pci_expected,monitor,pci_guard)
    except (Exception,KeyboardInterrupt) as error:fail('capture',error)
    finally:
        cleaning=True;cleanup_owned(child,monitor,record,pump=pump)
        if logs is not None:
            try:
                # Drain queued pipe bytes after reap, including the last messages.
                for _ in range(4):logs.pump(check=False)
                record['log_bytes']=dict(logs.counts);record['log_dropped_bytes']=dict(logs.dropped)
                if any(logs.dropped.values()):fail('logs',RuntimeError('owned log byte bound exceeded'))
            except (Exception,KeyboardInterrupt) as error:fail('log_drain',error)
            try:logs.close()
            except (Exception,KeyboardInterrupt) as error:fail('log_close',error)
        record['elapsed_seconds']=round(time.monotonic()-start,3);record['qemu_exit_code']=child.returncode if child else None
        record['QEMU0_is_not_Windows_success']=True;record['sampled_ESP_write_bytes']=last_writes;record['last_info']=last_info
        try:
            for checkpoint in checkpoints:checkpoint()
            record['lease_integrity_verified']=bool(checkpoints)
        except (Exception,KeyboardInterrupt) as error:fail('lease_checkpoint',error)
        def audit(item):
            try:return borrowed.audit(item) if borrowed is not None else sha(item['path'])==item['sha256'] and Path(item['path']).stat().st_size==item['bytes']
            except (Exception,KeyboardInterrupt) as error:fail('final_input',error);return False
        record['originals_unchanged']={key:audit(item) for key,item in built['input_pins'].items()}
        record['plan_originals_unchanged']={key:audit(item) for key,item in plan['input_pins'].items()}
        record['plan_file_unchanged']=audit({'path':str(args.plan),'sha256':args.plan_sha256,'bytes':plan_size})
        source_items={name:{'path':str(path),'sha256':source_pins[name],'bytes':source_sizes[name]} for name,path in paths.items()}
        source_items[header_name]={'path':str(header),'sha256':source_pins[header_name],'bytes':source_sizes[header_name]}
        record['runtime_source_origins_unchanged']={name:audit(item) for name,item in source_items.items()}
        record['private_source_ESP_unchanged']=record['plan_originals_unchanged'].get('esp',False)
        record['original_disk_unchanged']=record['originals_unchanged'].get('DISK.IMG',False)
        try:
            record['runtime_source_snapshots_unchanged']=all(sha(frozen/name)==pin for name,pin in source_pins.items())
            record['runtime_helper_originals_unchanged']=all(borrowed.audit(runtime_pins[name]) for name in HELPERS) if borrowed is not None else all(sha(args.repo/name)==pin for name,pin in helper_pins.items())
            record['owned_ESP_sha256_after']=sha(out/'esp.img')
            record['owned_VARS_sha256_after']=sha(out/'OVMF_VARS.fd')
            if borrowed is None:record['original_disk_sha256_after']=sha(built['input_pins']['DISK.IMG']['path'])
            else:
                record['original_disk_guardian_admitted_SHA256']=built['input_pins']['DISK.IMG']['sha256']
                record['guardian_original_FD_admissions']=borrowed.evidence()
            record['free_bytes_after']=shutil.disk_usage(out).free
            record['host_memory_available_after_bytes']=capture.available_memory_bytes()
            record['capture_bytes_after']=capture.capture_bytes(out)
            record['artifacts']={p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in out.iterdir() if p.is_file() and p.suffix in ('.log','.png','.bin','.txt','.stderr','.fd') and p.name!='esp.img'}
        except (Exception,KeyboardInterrupt) as error:fail('final_artifacts',error)
        record['leases_released_after_reap']=bool(record.get('owned_child_reaped')) if borrowed is None else False
        record['controller_original_FD_closure_pending_at_receipt']=borrowed is not None
        record['controller_original_FDs_held_at_receipt_publication']=False
        record['unresolved_owned_child']=child is not None and not record.get('owned_child_reaped',False)
        if borrowed is None:
            try:leases.close()
            except (Exception,KeyboardInterrupt) as error:record['lease_integrity_verified']=False;fail('lease_release',error)
        record['VM_launch_may_have_occurred']=bool(custody is not None and custody.launch_requested and not record['VM_executed'])
        external_verified=False
        if custody is not None:
            try:
                record['external_custody']=custody.ordinary('status')
                external_verified=(record['external_custody'].get('custody_admitted') is True and record['external_custody'].get('owned_child_reaped') is True)
            except (Exception,KeyboardInterrupt) as error:fail('external_custody',error)
        verified=((custody is None or external_verified) and record['VM_executed'] and record['write_budget_verified'] and record.get('owned_child_reaped')
                  and not record.get('forced_cleanup') and not record.get('cleanup_errors') and record.get('qemu_exit_code')==0
                  and (record.get('quit_acknowledged') or record.get('natural_exit_observed'))
                  and record['lease_integrity_verified'] and record['original_disk_unchanged']
                  and bool(record['originals_unchanged']) and all(record['originals_unchanged'].values())
                  and bool(record['plan_originals_unchanged']) and all(record['plan_originals_unchanged'].values())
                  and record['plan_file_unchanged'] and all(record['runtime_source_origins_unchanged'].values())
                  and record['private_source_ESP_unchanged'] and record.get('runtime_source_snapshots_unchanged')
                  and record.get('runtime_helper_originals_unchanged') and record.get('free_bytes_after',0)>=RESERVE
                  and record.get('host_memory_available_after_bytes',0)>=capture.MEMORY_FLOOR
                  and record['status']!='NATIVE_CAPTURE_HARNESS_FAILED')
        record['collection_verified']=bool(verified)
        if not verified:record['status']='NATIVE_CAPTURE_HARNESS_FAILED'
        try:
            if borrowed is not None:
                # Main closes these duplicates after receipt publication. A
                # close/check failure must still fail the actual CLI return.
                borrowed.check()
                record['controller_original_FDs_held_at_receipt_publication']=True
            record['receipt_persisted']=True
            receipt_bytes=len((json.dumps(record,indent=2)+'\n').encode())
            if receipt_bytes>capture.SINGLE_CAPTURE_LIMIT or capture.capture_bytes(out)+receipt_bytes>capture.CAPTURE_LIMIT:
                raise RuntimeError('final receipt exceeds the remaining bounded capture budget')
            capture.atomic_json(out/'native-result.json',record)
        except (Exception,KeyboardInterrupt) as error:
            record['receipt_persisted']=False;record['collection_verified']=False;fail('receipt',error)
        print(json.dumps({'stage':'native-complete','status':record['status'],'collection_verified':record['collection_verified'],
                          'receipt_persisted':record['receipt_persisted'],'original_disk_unchanged':record['original_disk_unchanged']}),flush=True)
    return 0 if record['collection_verified'] and record['receipt_persisted'] else 1

if __name__=='__main__':raise SystemExit(main())
