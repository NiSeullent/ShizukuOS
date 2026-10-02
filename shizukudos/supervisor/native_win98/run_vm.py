#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one bounded owned native Windows98 VM plan; preserve failures as evidence.

L0 KVM hosts L1 OVMF/Supervisor, which must itself create the L2 Windows98 VMCS.
Its installed disk still starts original Microsoft DOS. Never count component,
QEMU exit, VMCS launch or original DOS success as ShizukuDOS replacement.
"""
import argparse
from contextlib import ExitStack, contextmanager
import ctypes
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
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
CHECKPOINT_HELPERS=('shizukudos/supervisor/native_win98/private_checkpoint.py',
                    'shizukudos/supervisor/native_win98/private_checkpoint_adapter.py')
CONTROLLER='shizukudos/supervisor/native_win98/run_vm.py'
OWNED_QMP='shizukudos/supervisor/native_win98/owned_capture.py'
INFO_HEADER='shizukudos/supervisor/include/shz_info.h'
CHECKPOINT_READINESS={'schema':'shizuku.checkpoint-controller-readiness.v1',
                     'actual_optional_controller_admitted':False,
                     'external_unreaped_child_custody_verified':False,
                     'blocking_requirement':'external custody must retain exact process/pidfd/leases across unresolved-child and CLI exit'}


def _private_json(path,maximum=1<<20):
    path=Path(path)
    if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):
        raise ValueError('canonical absolute private input required')
    item=path.stat()
    if (not stat.S_ISREG(item.st_mode) or item.st_uid!=os.getuid() or item.st_mode&0o777!=0o600 or
            not 0<item.st_size<=maximum):raise ValueError('bounded owned mode0600 private input required')
    def pairs(items):
        result={}
        for key,value in items:
            if key in result:raise ValueError('duplicate private input key')
            result[key]=value
        return result
    payload=path.read_bytes()
    if len(payload)!=item.st_size:raise ValueError('private input extent changed')
    return path.resolve(),payload,json.loads(payload,object_pairs_hook=pairs)


@contextmanager
def _bootstrap_lease(path,pin,size):
    """Read-lease only the source that supplies subsequent reviewed lease helpers."""
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    previous=signal.getsignal(signal.SIGIO);broken=[False];leased=False
    def stable(item):return item.st_dev,item.st_ino,item.st_size,item.st_mtime_ns,item.st_ctime_ns
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size!=size or not 0<size<=1<<20:
            raise ValueError('bounded bootstrap source required')
        def notified(signum,frame):
            broken[0]=True
            if callable(previous):previous(signum,frame)
        signal.signal(signal.SIGIO,notified);fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid())
        fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK);leased=True
        def check():
            if (broken[0] or stable(os.fstat(fd))!=stable(before) or stable(path.stat())!=stable(before) or
                    fcntl.fcntl(fd,fcntl.F_GETLEASE)!=fcntl.F_RDLCK):raise RuntimeError('bootstrap source lease changed')
        check()
        payload=os.pread(fd,size+1,0)
        if len(payload)!=size or hashlib.sha256(payload).hexdigest()!=pin:raise ValueError('bootstrap source SHA differs')
        check();yield fd,check;check()
    finally:
        try:
            if leased:fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
        finally:
            os.close(fd);signal.signal(signal.SIGIO,previous)


def checkpoint_compile_admission():
    """Read current host/cgroup bounds; reserve only the small prelaunch C proof."""
    text=Path('/proc/meminfo').read_text()
    entries=[line.split() for line in text.splitlines() if line.startswith('MemAvailable:')]
    if len(entries)!=1 or len(entries[0])!=3 or entries[0][2]!='kB':raise ValueError('bounded host memory report required')
    available=int(entries[0][1])<<10
    base=Path('/sys/fs/cgroup')
    lines=Path('/proc/self/cgroup').read_text().splitlines()
    unified=[line[3:] for line in lines if line.startswith('0::/')]
    if len(unified)!=1 or '..' in Path(unified[0]).parts:raise ValueError('actual unified cgroup required')
    group=base/unified[0].lstrip('/')
    reserve=256<<20;retained=128<<20
    observations=[]
    for current in (group,*group.parents):
        if not current.is_relative_to(base):break
        values={name:(current/name).read_text().strip() if (current/name).exists() else 'absent'
                for name in ('memory.current','memory.high','memory.max','pids.current','pids.max')}
        if current==group and 'absent' in values.values():raise RuntimeError('actual leaf compiler admission counters required')
        for name,value in values.items():
            if (value=='max' and name.endswith('.current') or
                    value not in ('max','absent') and not re.fullmatch('[0-9]+',value)):
                raise ValueError('bounded numeric compiler admission counters required')
        limits=[int(values[name]) for name in ('memory.high','memory.max') if values[name] not in ('max','absent')]
        if (limits and (values['memory.current'] in ('max','absent') or min(limits)-int(values['memory.current'])<reserve+retained) or
                values['pids.max'] not in ('max','absent') and
                (values['pids.current'] in ('max','absent') or int(values['pids.max'])-int(values['pids.current'])<16)):
            raise RuntimeError('finite ancestor layout-compiler admission unavailable')
        observations.append({'path':str(current),'values':values})
    if available<(2<<30)+reserve:
        raise RuntimeError('fresh small layout-compiler host/cgroup admission unavailable')
    return {'scope':'small_prelaunch_layout_compiler_only','cgroup':str(group),'values':observations[0]['values'],
            'cgroup_and_ancestors':observations,
            'host_MemAvailable':available,'reserved_bytes':reserve,'retained_cgroup_bytes':retained}


class CheckpointMode:
    """Optional owned-controller integration; never manufactures owner approval."""
    def __init__(self,args):
        self.leases=ExitStack();self.raw={};self.guards=None;self.closed=False;self.pidfd=None
        self.runtime=None;self.binding=None;self.output=None;self.record=None
        path,payload,record=_private_json(args.checkpoint_reservation)
        if (not re.fullmatch('[0-9a-f]{64}',args.checkpoint_reservation_sha256) or
                hashlib.sha256(payload).hexdigest()!=args.checkpoint_reservation_sha256):
            raise ValueError('explicit checkpoint reservation SHA differs')
        names={'schema','private','approved','scope','budget','compiler','sources_sha256','checkpoint_output'}
        if (not isinstance(record,dict) or set(record)!=names or record['schema']!='shizuku.checkpoint-controller-reservation.v1' or
                record['private'] is not True or record['approved'] is not True or record['scope']!='private_ram_checkpoint_only'):
            raise ValueError('explicit approved private controller reservation required')
        expected=set(HELPERS+CHECKPOINT_HELPERS+(CONTROLLER,OWNED_QMP,INFO_HEADER))
        pins=record['sources_sha256']
        if not isinstance(pins,dict) or set(pins)!=expected or any(not isinstance(pin,str) or not re.fullmatch('[0-9a-f]{64}',pin) for pin in pins.values()):
            raise ValueError('complete explicit checkpoint runtime source closure required')
        for name in ('budget','compiler'):
            item=record[name]
            if (not isinstance(item,dict) or set(item)!={'path','sha256','bytes'} or not isinstance(item['path'],str) or
                    not isinstance(item['sha256'],str) or not re.fullmatch('[0-9a-f]{64}',item['sha256']) or
                    type(item['bytes']) is not int or not 0<item['bytes']<=(1<<20 if name=='budget' else 64<<20)):
                raise ValueError('bounded exact budget/compiler source pin required')
        self.manifest=record;self.manifest_path=path;self.manifest_pin=args.checkpoint_reservation_sha256
        self.manifest_bytes=len(payload);self.pins=pins
        self.out=args.plan.resolve().parent
        owned=self.out.stat()
        if (any(p.is_symlink() for p in (self.out,*self.out.parents)) or owned.st_uid!=os.getuid() or
                owned.st_mode&0o777!=0o700):raise ValueError('owned private controller output required')
        if (self.out/'native-result.json').exists():raise ValueError('owned controller result already exists')

    def held(self,path,pin,size,bootstrap=False):
        path=Path(path)
        if not path.is_absolute() or any(p.is_symlink() for p in (path,*path.parents)):
            raise ValueError('canonical held input required')
        path=path.resolve();key=str(path)
        if key in self.raw:
            item=self.raw[key]
            if (item['sha256'],item['bytes'])!=(pin,size):raise ValueError('conflicting held input pins')
            return item
        manager=_bootstrap_lease(path,pin,size) if bootstrap else self.guards.read_leased(path,pin,size,maximum=max(size,4<<20))
        fd,check=self.leases.enter_context(manager)
        item={'name':'owned_source_%03d'%len(self.raw),'path':path,'fd':fd,'sha256':pin,'bytes':size,'checkpoint':check}
        self.raw[key]=item;return item

    def check(self):
        for item in self.raw.values():item['checkpoint']()

    def hold_record(self,path,record,maximum):
        """Bind the canonical proof to the exact record returned by its producer."""
        if not isinstance(record,dict):raise RuntimeError('returned producer serialization object required')
        payload=(json.dumps(record,sort_keys=True,indent=2)+'\n').encode()
        if not 0<len(payload)<=maximum:raise RuntimeError('bounded returned producer serialization required')
        try:
            item=self.held(path,hashlib.sha256(payload).hexdigest(),len(payload));item['checkpoint']()
            if os.pread(item['fd'],len(payload)+1,0)!=payload:raise RuntimeError('canonical bytes differ')
            item['checkpoint']();return item
        except (Exception,KeyboardInterrupt) as error:
            raise RuntimeError('canonical proof differs from returned producer serialization') from error

    def audit_held(self,deadline):
        """Independently hash the actual leased descriptors before final release."""
        results={}
        for item in self.raw.values():
            try:
                item['checkpoint']()
                before=os.fstat(item['fd']);path=item['path'].stat()
                identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns)
                if (not stat.S_ISREG(before.st_mode) or before.st_size!=item['bytes'] or
                        identity(path)!=identity(before)):raise RuntimeError('held descriptor identity or extent changed')
                digest=hashlib.sha256();offset=0
                while offset<item['bytes']:
                    if deadline is not None and time.monotonic()>=deadline:
                        raise RuntimeError('original absolute checkpoint finalization deadline expired')
                    data=os.pread(item['fd'],min(1<<20,item['bytes']-offset),offset)
                    if not data:raise RuntimeError('held descriptor short read')
                    digest.update(data);offset+=len(data)
                    item['checkpoint']()
                if (os.pread(item['fd'],1,offset) or digest.hexdigest()!=item['sha256'] or
                        identity(os.fstat(item['fd']))!=identity(before) or identity(item['path'].stat())!=identity(before)):
                    raise RuntimeError('held descriptor full SHA or extent differs')
                item['checkpoint']();results[item['name']]=True
            except (Exception,KeyboardInterrupt):results[item['name']]=False
        return results

    def load_held(self,name,path):
        path=Path(path).resolve();item=self.raw[str(path)];self.check()
        payload=os.pread(item['fd'],item['bytes']+1,0)
        if len(payload)!=item['bytes'] or hashlib.sha256(payload).hexdigest()!=item['sha256']:
            raise RuntimeError('evaluated held module source differs')
        spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        try:exec(compile(payload,str(path),'exec'),module.__dict__)
        except BaseException:sys.modules.pop(name,None);raise
        self.check();return module

    def imports(self,frozen,paths,source_pins,source_sizes):
        for name in paths:
            if source_pins[name]!=self.pins[name]:raise ValueError('explicit checkpoint runtime source SHA differs')
        bootstrap=frozen/HELPERS[0]
        self.held(bootstrap,source_pins[HELPERS[0]],source_sizes[HELPERS[0]],bootstrap=True)
        self.guards=self.load_held('native_run_guards',bootstrap)
        for name,path in paths.items():
            self.held(path,source_pins[name],source_sizes[name]);self.held(frozen/name,source_pins[name],source_sizes[name])
        self.held(self.manifest_path,self.manifest_pin,self.manifest_bytes)
        for name in ('budget','compiler'):
            item=self.manifest[name]
            if name=='budget':_private_json(Path(item['path']))
            self.held(Path(item['path']),item['sha256'],item['bytes'])
        native=frozen/'shizukudos/supervisor/native_win98'
        self.checkpoint=self.load_held('native_run_checkpoint',native/'private_checkpoint.py')
        self.adapter=self.load_held('native_run_checkpoint_adapter',native/'private_checkpoint_adapter.py')
        return (self.load_held('native_run_capture',native/'owned_capture.py'),self.guards,
                self.load_held('native_run_preparation',native/'prepare_vm.py'),
                self.load_held('native_run_info',frozen/'shizukudos/tools/shzinfo.py'))

    def sources(self):return tuple(self.checkpoint.ReadLease(**item) for item in self.raw.values())
    def source(self,path):return self.checkpoint.ReadLease(**self.raw[str(Path(path).resolve())])

    def prepare(self,args,frozen,header,pin,info,record):
        if pin!=self.pins[INFO_HEADER]:raise ValueError('explicit checkpoint header source SHA differs')
        size=header.stat().st_size
        self.held(header,pin,size);self.held(frozen/INFO_HEADER,pin,size)
        budget=self.source(self.manifest['budget']['path'])
        self.reservation=self.adapter.read_budget(self.checkpoint,budget)
        self.output=self.checkpoint._canonical(self.manifest['checkpoint_output'])
        lane=self.checkpoint._canonical(self.reservation.approved_lane)
        if (lane not in self.output.parents or self.output.exists() or not self.output.parent.is_dir() or
                not lane.is_dir()):raise ValueError('exact fresh checkpoint output in approved lane required')
        for directory in (lane,self.output.parent):
            item=directory.stat()
            if item.st_uid!=os.getuid() or item.st_mode&0o777!=0o700:raise ValueError('owned private approved checkpoint lane required')
        if args.timeout<self.reservation.timeout_seconds+25:
            raise ValueError('original timeout must retain20s observation plus capture reservation and5s finalization')
        self.observation_seconds=args.timeout-self.reservation.timeout_seconds-5
        if shutil.disk_usage(lane).free<self.reservation.retained_free_bytes+self.reservation.total_bytes:
            raise RuntimeError('full separately approved checkpoint budget plus17GiB reserve unavailable')
        record['checkpoint_compile_admission']=checkpoint_compile_admission()
        expected=self.adapter.prove_layout(self.checkpoint,info,self.source(frozen/INFO_HEADER),
                                  self.source(frozen/'shizukudos/tools/shzinfo.py'),
                                  self.source(self.manifest['compiler']['path']),self.out/'checkpoint-layout.json')
        proof=self.out/'checkpoint-layout.json';layout=self.hold_record(proof,expected,self.adapter.MAX_PROOF_BYTES)
        record.update(checkpoint_requested=True,checkpoint_reservation_sha256=self.manifest_pin,
                      checkpoint_budget_sha256=budget.sha256,checkpoint_output=str(self.output),
                      checkpoint_capture_timeout_seconds=self.reservation.timeout_seconds,
                      checkpoint_observation_seconds=self.observation_seconds,
                      checkpoint_layout_proof_sha256=layout['sha256'],checkpoint_capture_verified=False)

    def capture(self,child,monitor,frozen,info,record):
        self.pidfd=os.pidfd_open(child.pid)
        paths={'controller':Path(__file__),'qemu':Path(self.qemu),'owned_qmp':frozen/OWNED_QMP,
               'checkpoint_helper':frozen/CHECKPOINT_HELPERS[0],'checkpoint_adapter':frozen/CHECKPOINT_HELPERS[1]}
        roles={role:self.source(path).name for role,path in paths.items()}
        self.runtime=self.adapter.OwnedRuntime(child,self.pidfd,monitor,self.checkpoint,self.capture_module,self.sources(),roles)
        self.runtime.assert_owned();monitor.call('stop');self.runtime.assert_owned()
        record['final_pause_acknowledged']=True
        status=monitor.call('query-status');self.runtime.assert_owned()
        if not isinstance(status,dict) or status.get('running') is not False or status.get('status')!='paused':
            raise RuntimeError('actual owned paused checkpoint required')
        if monitor.deadline-time.monotonic()<self.reservation.timeout_seconds:
            raise RuntimeError('existing absolute deadline cannot meet the approved checkpoint interval')
        observation=self.out/'checkpoint-ram.json';expected=self.runtime.write_observation(observation)
        self.hold_record(observation,expected,self.adapter.MAX_PROOF_BYTES)
        references={'controller':roles['controller'],'qemu':roles['qemu'],'checkpoint_helper':roles['checkpoint_helper'],
                    'ram_observation':self.source(observation).name,'info_header':self.source(frozen/INFO_HEADER).name,
                    'info_parser':self.source(frozen/'shizukudos/tools/shzinfo.py').name,
                    'layout_receipt':self.source(self.out/'checkpoint-layout.json').name,
                    'budget':self.source(self.manifest['budget']['path']).name}
        self.binding=self.runtime.bind(info,self.sources(),references)
        record['checkpoint_binding']=self.binding.proof
        receipt=self.checkpoint.capture_private_checkpoint(self.binding.adapter,self.binding.reservation,self.output)
        self.runtime.assert_owned()
        if (not isinstance(receipt,dict) or receipt.get('schema')!='shizuku.private-ram-checkpoint.v1' or
                receipt.get('private') is not True or receipt.get('source_before_after_match') is not True or
                receipt.get('current_info_before_after_match') is not True or receipt.get('owner')!=self.runtime.owner or
                receipt.get('disk',{}).get('bytes')!=self.checkpoint.DISK_BYTES or
                receipt.get('disk',{}).get('independent_readback_verified') is not True):
            raise RuntimeError('exact producer checkpoint receipt required')
        raw=self.output/'checkpoint.raw';self.held(raw,receipt['disk']['sha256'],self.checkpoint.DISK_BYTES)
        proof=self.output/'checkpoint.json';proof_pin=self.hold_record(proof,receipt,self.checkpoint.MAX_RECEIPT_BYTES)['sha256']
        self.runtime.assert_owned();self.check()
        record['checkpoint_capture_verified']=True
        record['checkpoint_output_read_leases_acquired']=True
        record['checkpoint_receipt_sha256']=proof_pin
        record['checkpoint_receipt']=receipt

    def close(self):
        self.closed=True
        try:self.leases.close()
        finally:
            if self.pidfd is not None:os.close(self.pidfd);self.pidfd=None

    def preflight_failure(self,error):
        if (self.out/'native-result.json').exists():return
        record={'status':'NATIVE_CAPTURE_HARNESS_FAILED','scope':'optional checkpoint prelaunch refusal',
                'checkpoint_requested':True,'checkpoint_capture_verified':False,'checkpoint_reservation_sha256':self.manifest_pin,
                'VM_executed':False,'Windows98_GUI_verified':False,'native_Windows98_complete':False,
                'ShizukuDOS_replaces_MS_DOS_validated':False,'all_modern_apps_validated':False,
                'VMM_boot_verified':False,'Windows98_boot_verified':False,
                'cold_boot_persistence_verified':False,'live_storage_flush_verified':False,
                'checkpoint_held_input_sha_verified_after_reap':False,
                'checkpoint_runtime_readiness':dict(CHECKPOINT_READINESS),
                'collection_verified':False,'receipt_persisted':True,'owned_child_reaped':False,
                'harness_errors':[]}
        if self.record is not None:
            record.update(self.record)
            if record.get('VM_executed') is True:record['scope']='optional checkpoint failed runtime finalization after owned launch'
        record.update(status='NATIVE_CAPTURE_HARNESS_FAILED',collection_verified=False,
                      checkpoint_capture_verified=False,receipt_persisted=True,
                      checkpoint_runtime_readiness=dict(CHECKPOINT_READINESS))
        record['harness_errors']=list(record.get('harness_errors',[]))+[
            {'operation':'checkpoint_preflight' if self.record is None else 'checkpoint_unhandled_finalization',
             'type':type(error).__name__,'error':str(error)}]
        payload=(json.dumps(record,indent=2)+'\n').encode()
        directory=os.open(self.out,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        identity=None
        try:
            parent=os.fstat(directory);named=self.out.stat(follow_symlinks=False)
            if ((parent.st_dev,parent.st_ino)!=(named.st_dev,named.st_ino) or parent.st_uid!=os.getuid() or
                    parent.st_mode&0o777!=0o700):raise RuntimeError('owned private failed-receipt parent changed')
            fd=os.open('native-result.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            with os.fdopen(fd,'wb') as stream:
                created=os.fstat(stream.fileno());identity=(created.st_dev,created.st_ino)
                stream.write(payload);stream.flush();os.fsync(stream.fileno())
            os.fsync(directory)
        except BaseException:
            try:
                named=os.stat('native-result.json',dir_fd=directory,follow_symlinks=False)
                if identity is not None and (named.st_dev,named.st_ino)==identity:
                    os.unlink('native-result.json',dir_fd=directory);os.fsync(directory)
            except OSError:pass
            raise
        finally:os.close(directory)


def helper_identity(repo):
    """Explicit caller pin, distinct from the historical ESP producer sources."""
    for name in HELPERS:
        if not 0<(repo/name).stat().st_size<=1<<20:raise ValueError('bounded nonempty runtime helper source required')
    pins={name:sha(repo/name) for name in HELPERS}
    return hashlib.sha256(json.dumps(pins,sort_keys=True,separators=(',',':')).encode()).hexdigest(),pins


def cleanup_owned(child,monitor,record,pump=lambda:None,preserve_deadline=False):
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
                if not preserve_deadline:monitor.deadline=time.monotonic()+5
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


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--repo',type=Path,required=True)
    parser.add_argument('--runtime-sources-sha256',required=True,
                        help='SHA256 of the sorted four-helper SHA map; see helper_identity()')
    parser.add_argument('--timeout',type=int,default=300)
    parser.add_argument('--checkpoint-reservation',type=Path,
                        help='explicit opt-in owner-approved private controller reservation JSON')
    parser.add_argument('--checkpoint-reservation-sha256',help='exact SHA256 of the approved reservation input')
    args=parser.parse_args()
    if (args.checkpoint_reservation is None)!=(args.checkpoint_reservation_sha256 is None):
        parser.error('paired checkpoint reservation and SHA256 arguments required')
    mode=None
    if args.checkpoint_reservation is not None:
        try:mode=CheckpointMode(args)
        except (Exception,KeyboardInterrupt) as error:parser.error(str(error))
    try:return run(args,parser,mode)
    except (Exception,KeyboardInterrupt,SystemExit) as error:
        if mode is None:raise
        mode.preflight_failure(error)
        return 1
    finally:
        if mode is not None and not mode.closed:mode.close()


def run(args,parser,mode=None):
    if not timeout_valid(args.timeout):parser.error('timeout must be 20..900 seconds')
    plan_size=args.plan.stat().st_size
    if not 0<plan_size<=16<<20:parser.error('private plan must be nonempty and at most 16 MiB')
    if sha(args.plan)!=args.plan_sha256:parser.error('explicit private VM plan SHA mismatch')
    identity,helper_pins=helper_identity(args.repo)
    if identity!=args.runtime_sources_sha256:parser.error('explicit runtime helper identity differs')
    plan=json.loads(args.plan.read_text())
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
    if mode is not None:paths.update({name:args.repo/name for name in CHECKPOINT_HELPERS})
    source_pins={};source_sizes={}
    for relative,source in paths.items():
        if source.stat().st_size>1<<20:parser.error('one runtime source exceeded 1 MiB')
        target=frozen/relative;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(source.read_bytes());source_pins[relative]=sha(target)
        source_sizes[relative]=target.stat().st_size
        if relative in helper_pins and source_pins[relative]!=helper_pins[relative]:
            parser.error('runtime helper changed while freezing')
    native=frozen/'shizukudos/supervisor/native_win98'
    if mode is None:
        capture=load('native_run_capture',native/'owned_capture.py')
        guards=load('native_run_guards',native/'build.py')
        preparation=load('native_run_preparation',native/'prepare_vm.py')
        info_helper=load('native_run_info',frozen/'shizukudos/tools/shzinfo.py')
    else:
        capture,guards,preparation,info_helper=mode.imports(frozen,paths,source_pins,source_sizes)
        mode.capture_module=capture
    build_pin=plan['input_pins']['build_receipt']
    guards.pinned_hash(Path(build_pin['path']),build_pin['sha256'],build_pin['bytes'],16<<20)
    built=json.loads(Path(build_pin['path']).read_text())
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
    if sha(header)!=built['sources_sha256'][header_name]:raise ValueError('evidence header differs from source-bound builder')
    target=frozen/header_name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(header.read_bytes());source_pins[header_name]=sha(target)
    source_sizes[header_name]=target.stat().st_size
    layout_bytes=info_helper.selfcheck(frozen) if mode is None else ctypes.sizeof(info_helper.Info)
    qemu=Path(plan['input_pins']['qemu']['path'])
    if mode is not None:mode.qemu=qemu
    recipe=preparation.recipe(qemu,out)
    if recipe!=plan['qemu_argv']:raise ValueError('VM argv differs from the exact source recipe')
    for key,name in [('esp','esp.img'),('firmware_code','OVMF_CODE.fd'),('firmware_vars','OVMF_VARS.fd')]:
        item=plan['input_pins'][key];guards.pinned_hash(out/name,item['sha256'],item['bytes'],max(item['bytes'],4<<20))
        owned=(out/name).stat();original=Path(item['path']).stat()
        if (owned.st_dev,owned.st_ino)==(original.st_dev,original.st_ino):raise ValueError('VM input must have a distinct owned inode')
    guards.pinned_hash(qemu,plan['input_pins']['qemu']['sha256'],plan['input_pins']['qemu']['bytes'],64<<20)
    if shutil.disk_usage(out).free<RESERVE+capture.PREFLIGHT_BUDGET:
        parser.error('17 GiB reserve plus the 1 GiB bounded capture budget required')
    if capture.available_memory_bytes()<capture.MEMORY_ADMISSION:
        parser.error('6 GiB MemAvailable required for the owned 4 GiB VM and host margin')
    record={'status':'NATIVE_CAPTURE_PREPARING','scope':'L1 UEFI Supervisor -> actual L2 original-MS-DOS installed Windows98 control; ShizukuDOS replacement incomplete',
            'requested_timeout_seconds':args.timeout,'cleanup_wait_budget_seconds':16,
            'plan_sha256':args.plan_sha256,'builder_receipt_sha256':build_pin['sha256'],
            'runtime_helpers_identity_sha256':identity,'preparation_helper_source_pins_verified':preparation_pins is not None,
            'source_pins':source_pins,'C_Python_evidence_layout_bytes':layout_bytes,'firmware_bytes':4<<20,'L1_memory_bytes':4<<30,'L2_memory_bytes':128<<20,
            'VM_executed':False,'Windows98_GUI_verified':False,'native_Windows98_complete':False,'ShizukuDOS_replaces_MS_DOS_validated':False,'all_modern_apps_validated':False,
            'sampled_ESP_write_budget_bytes':WRITE_BUDGET,'write_budget_verified':False,'captures':[],
            'retained_free_space_bytes':RESERVE,'preflight_capture_budget_bytes':capture.PREFLIGHT_BUDGET,
            'log_limit_per_stream_bytes':capture.LOG_LIMIT,'capture_total_limit_bytes':capture.CAPTURE_LIMIT,
            'host_memory_admission_bytes':capture.MEMORY_ADMISSION,'host_memory_floor_bytes':capture.MEMORY_FLOOR,
            'collection_verified':False,'receipt_persisted':False,'lease_integrity_verified':False}
    if mode is not None:
        record.update(checkpoint_requested=True,checkpoint_capture_verified=False,
                      checkpoint_outputs_read_leased_through_reap=False,
                      checkpoint_runtime_readiness=dict(CHECKPOINT_READINESS),
                      checkpoint_reservation_sha256=mode.manifest_pin,
                      VMM_boot_verified=False,Windows98_boot_verified=False,
                      cold_boot_persistence_verified=False,live_storage_flush_verified=False)
        mode.record=record
    leases=ExitStack() if mode is None else mode.leases
    checkpoints=[] if mode is None else [item['checkpoint'] for item in mode.raw.values()]
    child=monitor=logs=None;start=time.monotonic()
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
        if mode is not None:record['checkpoint_capture_verified']=False
        record.setdefault('harness_errors',[]).append({'operation':operation,'type':type(error).__name__,'error':str(error)})
    try:
        # Lease each original identity once. Never lease the writable VM ESP/VARS.
        leased={}
        items=list(built['input_pins'].values())+list(plan['input_pins'].values())
        items += [{'path':str(args.plan),'sha256':args.plan_sha256,'bytes':plan_size},
                  {'path':str(header),'sha256':source_pins[header_name],'bytes':source_sizes[header_name]}]
        items += [{'path':str(paths[name]),'sha256':pin,'bytes':source_sizes[name]} for name,pin in source_pins.items() if name in paths]
        for item in items:
            path=Path(item['path']).resolve();key=str(path)
            pin=(item['sha256'],item['bytes'])
            if key in leased:
                if leased[key]!=pin:raise ValueError('conflicting pins for one original input')
                continue
            if mode is None:
                _,checkpoint=leases.enter_context(guards.read_leased(path,pin[0],pin[1],maximum=max(pin[1],4<<20)))
            else:
                item=mode.held(path,pin[0],pin[1]);checkpoint=item['checkpoint']
            leased[key]=pin;checkpoints.append(checkpoint)
        if mode is not None:
            mode.prepare(args,frozen,header,source_pins[header_name],info_helper,record)
            checkpoints[:]=[item['checkpoint'] for item in mode.raw.values()]
        logs=capture.BoundedLogs(out)
        command=list(recipe)
        serial=command.index('-serial')+1
        if command[serial]!=f'file:{out / "serial.log"}':raise ValueError('exact serial recipe required')
        command[serial]=f'file:/proc/self/fd/{logs.writers["serial.log"]}'
        command += ['-debugcon',f'file:/proc/self/fd/{logs.writers["e9.log"]}','-global','isa-debugcon.iobase=0xe9']
        capture.atomic_json(out/'native-command.json',command);record['command_sha256']=sha(out/'native-command.json')
        child=subprocess.Popen(command,cwd=out,stdout=subprocess.DEVNULL,stderr=logs.writers['native-qemu.stderr'],
                               pass_fds=(logs.writers['serial.log'],logs.writers['e9.log']))
        if mode is not None:
            record['owned_pid']=child.pid;record['VM_executed']=True
        logs.close_writers();start=time.monotonic()
        record['owned_pid']=child.pid;record['VM_executed']=True
        print(json.dumps({'stage':'native-owned-VM-started','pid':child.pid}),flush=True)
        monitor=capture.OwnedQMP(out/'qmp.sock',child.pid,start+args.timeout,pump=pump)
        next_capture=10
        observation_seconds=args.timeout if mode is None else mode.observation_seconds
        while child.poll() is None and time.monotonic()-start<observation_seconds:
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
            logs.pump(timeout=min(1,max(0,start+observation_seconds-time.monotonic())))
        # Observation deadline is distinct from the bounded final sample/cleanup.
        if mode is None:
            monitor.deadline=time.monotonic()+5
            monitor.call('stop');record['final_pause_acknowledged']=True
        else:
            mode.capture(child,monitor,frozen,info_helper,record)
            checkpoints[:]=[item['checkpoint'] for item in mode.raw.values()]
        last_writes=esp_write_bytes(monitor.call('query-blockstats'),last_writes)
        record['write_budget_verified']=True;record['status']=evidence_status(last_info)
    except (Exception,KeyboardInterrupt) as error:fail('capture',error)
    finally:
        cleaning=True;cleanup_owned(child,monitor,record,pump=pump,preserve_deadline=mode is not None)
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
            try:return sha(item['path'])==item['sha256'] and Path(item['path']).stat().st_size==item['bytes']
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
            record['runtime_helper_originals_unchanged']=all(sha(args.repo/name)==pin for name,pin in helper_pins.items())
            record['owned_ESP_sha256_after']=sha(out/'esp.img')
            record['original_disk_sha256_after']=sha(built['input_pins']['DISK.IMG']['path'])
            record['free_bytes_after']=shutil.disk_usage(out).free
            record['host_memory_available_after_bytes']=capture.available_memory_bytes()
            record['capture_bytes_after']=capture.capture_bytes(out)
            record['artifacts']={p.name:{'bytes':p.stat().st_size,'sha256':sha(p)} for p in out.iterdir() if p.is_file() and p.suffix in ('.log','.png','.bin','.txt','.stderr','.fd') and p.name!='esp.img'}
        except (Exception,KeyboardInterrupt) as error:fail('final_artifacts',error)
        record['leases_released_after_reap']=bool(record.get('owned_child_reaped'))
        record['unresolved_owned_child']=child is not None and not record.get('owned_child_reaped',False)
        if mode is not None:
            held=mode.audit_held(monitor.deadline if monitor is not None else None)
            record['checkpoint_held_descriptor_SHA_after_reap']=held
            record['checkpoint_held_input_sha_verified_after_reap']=bool(record.get('owned_child_reaped') and held and all(held.values()))
            record['checkpoint_outputs_read_leased_through_reap']=bool(record.get('checkpoint_output_read_leases_acquired') and
                                                                       record['checkpoint_held_input_sha_verified_after_reap'])
            if not record['checkpoint_held_input_sha_verified_after_reap']:
                fail('checkpoint_final_held_inputs',RuntimeError('owned reap and every held descriptor full SHA/extent/lease required'))
        try:
            if mode is None:leases.close()
            else:mode.close()
        except (Exception,KeyboardInterrupt) as error:record['lease_integrity_verified']=False;fail('lease_release',error)
        verified=(record['VM_executed'] and record['write_budget_verified'] and record.get('owned_child_reaped')
                  and not record.get('forced_cleanup') and not record.get('cleanup_errors') and record.get('qemu_exit_code')==0
                  and (record.get('quit_acknowledged') or record.get('natural_exit_observed'))
                  and record['lease_integrity_verified'] and record['original_disk_unchanged']
                  and bool(record['originals_unchanged']) and all(record['originals_unchanged'].values())
                  and bool(record['plan_originals_unchanged']) and all(record['plan_originals_unchanged'].values())
                  and record['plan_file_unchanged'] and all(record['runtime_source_origins_unchanged'].values())
                  and record['private_source_ESP_unchanged'] and record.get('runtime_source_snapshots_unchanged')
                  and record.get('runtime_helper_originals_unchanged') and record.get('free_bytes_after',0)>=RESERVE
                  and record.get('host_memory_available_after_bytes',0)>=capture.MEMORY_FLOOR
                  and (mode is None or (record.get('checkpoint_capture_verified') is True and
                                        record.get('checkpoint_held_input_sha_verified_after_reap') is True))
                  and record['status']!='NATIVE_CAPTURE_HARNESS_FAILED')
        record['collection_verified']=bool(verified)
        if not verified:
            record['status']='NATIVE_CAPTURE_HARNESS_FAILED'
            if mode is not None:record['checkpoint_capture_verified']=False
        try:
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
