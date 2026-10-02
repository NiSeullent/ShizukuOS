#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded physical AP VMX component QA; immutable ESP plus small QCOW overlays."""
if '__shz_driver_capture__' not in globals():
    from pathlib import Path as _EntryPath
    import hashlib as _EntryHash
    _entry_path=_EntryPath(__file__).resolve();_entry_bytes=_entry_path.read_bytes()
    _entry_capture={'path':str(_entry_path),'sha256':_EntryHash.sha256(_entry_bytes).hexdigest()}
    exec(compile(_entry_bytes,str(_entry_path),'exec'),{'__name__':__name__,'__file__':str(_entry_path),'__shz_driver_capture__':_entry_capture})
    raise SystemExit(0)
import argparse
import ctypes as C
import fcntl
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import time
import tempfile
import types
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parents[0]/"tools"))
def fresh(name,path,data):
    module=types.ModuleType(name); module.__file__=str(path); sys.modules[name]=module
    module.__shz_loaded_sha256__=hashlib.sha256(data).hexdigest()
    exec(compile(data,str(path),'exec'),module.__dict__)
    return module
module_paths={'ap_provenance':HERE/'ap_provenance.py','qemu':HERE.parents[0]/'tools/qemu.py',
              'shzinfo':HERE.parents[0]/'tools/shzinfo.py','shzlib':HERE.parents[0]/'tools/shzlib.py'}
module_bytes={name:path.read_bytes() for name,path in module_paths.items()}
loaded_modules={name:fresh(name,module_paths[name],data) for name,data in module_bytes.items()}
LOADED_SHA={str(module_paths[name]):m.__shz_loaded_sha256__ for name,m in loaded_modules.items()}
LOADED_SHA[__shz_driver_capture__['path']]=__shz_driver_capture__['sha256']
provenance=loaded_modules['ap_provenance'];qemu=loaded_modules['qemu'];shzinfo=loaded_modules['shzinfo'];shzlib=loaded_modules['shzlib']
OUT=shzlib.BUILD/"supervisor"
DRIVER_SHA=__shz_driver_capture__['sha256']
RUNTIME_SHA={str(Path(__file__).relative_to(shzlib.REPO)):DRIVER_SHA}
fixture=HERE/'native_win98/tests/test_gop_auto_host.py'
RUNTIME_SHA[str(fixture.relative_to(shzlib.REPO))]=hashlib.sha256(fixture.read_bytes()).hexdigest()
u32,u64=C.c_uint32,C.c_uint64
class Topology(C.Structure):
    _fields_=[("rsdp",u64),("madt",u64),("lapic",u64),("count",u32),("bsp",u32),("pcat",u32),
              ("ids",u32*32),("uids",u32*32)]
class Record(C.Structure):
    _fields_=[(n,u32) for n in ("state","error","apic","reserved")]+[(n,u64) for n in
        ("cr3","stack","gdt","idt","tss","cr0","cr4","efer","hash","work")]
class Boot(C.Structure):
    _fields_=[("magic",u64)]+[(n,u32) for n in ("version","bytes","requested","flags")]+[
        ("low",u64),("pages",u64),("topology",Topology),("sealed",u32),("release",u32),("bsp_hash",u64),("cpus",Record*32)]

def run(cmd):
    return guard_commands.run([str(x) for x in cmd],check=True,capture_output=True,text=True).stdout

def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def closure(receipt):
    assert all(digest(p)==h for p,h in LOADED_SHA.items()),'loaded helper bytes changed'
    for path,expected in receipt["sources_sha256"].items():
        if path in RUNTIME_SHA:
            expected=RUNTIME_SHA[path]  # separately pinned noncompiled successors
        assert digest(shzlib.REPO/path)==expected, f"source changed: {path}"
    for name,item in receipt["artifacts"].items():
        assert digest(OUT/name)==item["sha256"], f"artifact changed: {name}"
    for path,expected in receipt.get('compiler_dependency_sha256',{}).items():
        assert digest(path)==expected, f"compiled dependency changed: {path}"
    for path,expected in receipt.get('build_tools_sha256',{}).items():
        assert digest(path)==expected, f"compiled tool changed: {path}"

def layout_check():
    shzinfo.selfcheck(shzlib.REPO)
    source=OUT/"ap-layout.c"
    source.write_text('#include <stdio.h>\n#include <stddef.h>\n#include "'+str(HERE/'include/ap_boot.h')+
                      '"\nint main(void){printf("%zu %zu %zu %zu\\n",sizeof(shz_ap_boot_t),offsetof(shz_ap_boot_t,cpu),sizeof(shz_ap_record_t),sizeof(shz_smp_topology_t));}\n')
    run(["gcc",source,"-o",OUT/"ap-layout"])
    assert run([OUT/"ap-layout"]).strip()==f"{C.sizeof(Boot)} {Boot.cpus.offset} {C.sizeof(Record)} {C.sizeof(Topology)}"

def first_cluster(esp,name):
    output=run(["mshowfat","-i",esp,name])
    found=re.search(r'<(\d+)(?:-\d+)?>',output)
    assert found,output
    return int(found.group(1))

def config_patch(esp,mode,count,out,overlay):
    with esp.open('rb') as f: b=f.read(512)
    sector=struct.unpack_from('<H',b,11)[0]; spc=b[13]
    data=(struct.unpack_from('<H',b,14)[0]+b[16]*struct.unpack_from('<I',b,36)[0])*sector
    policy_offset=data+(first_cluster(esp,'::/EFI/SHIZUKU/BOOT.INI')-2)*spc*sector
    with esp.open('rb') as f: f.seek(policy_offset); policy=bytearray(f.read(sector))
    assert policy.startswith(b'mode=supervisor\n') or policy[:7]==b'[boot]\n'
    # This base is retained from a failed QA preparation. The accepted parser
    # uses flat key=value policy. Preserve base bytes and fix only this overlay.
    if policy[:7]==b'[boot]\n': policy[:7]=b'      \n'
    policy_file=out/'policy-sector.bin'; policy_file.write_bytes(policy)
    run(['qemu-io','-f','qcow2','-c',f'write -s {policy_file} {policy_offset} {len(policy)}',overlay])
    if mode=='up':
        offset=data+(first_cluster(esp,'::/SHZDOS')-2)*spc*sector
        with esp.open('rb') as f: f.seek(offset); page=bytearray(f.read(spc*sector))
        entry=next(i for i in range(0,len(page),32) if page[i:i+11]==b'APCFG   BIN')
        page[entry]=0xe5
    else:
        offset=data+(first_cluster(esp,'::/SHZDOS/APCFG.BIN')-2)*spc*sector
        with esp.open('rb') as f: f.seek(offset); page=bytearray(f.read(sector))
        assert struct.unpack_from('<IIII',page,0)==(0x31435041,1,4,0)
        struct.pack_into('<I',page,8,count)
        if mode=='malformed': struct.pack_into('<I',page,12,1)
    patch=out/'config-sector.bin'; patch.write_bytes(page)
    run(['qemu-io','-f','qcow2','-c',f'write -s {patch} {offset} {len(page)}',overlay])
    return {'offset':offset,'bytes':len(page),'sha256':digest(patch),
            'flat_policy':{'offset':policy_offset,'bytes':len(policy),'sha256':digest(policy_file)}}

def memory_guard():
    available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M).group(1))*1024
    assert available>=4*(1<<30)+(512<<20), '4 GiB host reserve plus configured guest RAM required'
    group=Path('/sys/fs/cgroup')/Path('/proc/self/cgroup').read_text().split('::',1)[1].strip().lstrip('/')
    margins=[]
    while str(group).startswith('/sys/fs/cgroup'):
        if (group/'memory.max').exists():
            limit=(group/'memory.max').read_text().strip()
            current=int((group/'memory.current').read_text())
            if limit!='max':
                margin=int(limit)-current
                assert margin>=768<<20, 'configured 512 MiB guest plus 256 MiB cgroup margin required'
                margins.append({'path':str(group),'limit':int(limit),'current':current,'headroom':margin})
        if group==Path('/sys/fs/cgroup'): break
        group=group.parent
    return {'MemAvailable':available,'configured_guest_bytes':512<<20,'host_reserve_bytes':4<<30,'cgroup':margins}

def process_admission():
    baseline_path=shzlib.BUILD/'supervisor-ap/guest-baseline-r5.json'
    assert digest(baseline_path)=='94da486c4fef2589d5ccbed25518f6958c9bceb7fd1a715c316bc60869c2a1a1','historical process identity changed'
    baseline=json.loads(baseline_path.read_bytes());boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    known={item['pid']:item for item in baseline['known']};excluded=[];peers=[]
    for process in Path('/proc').iterdir():
        if not process.name.isdigit():continue
        try:
            argv=(process/'cmdline').read_bytes();name=Path(argv.split(b'\0')[0].decode()).name
            if name!='qemu-kvm' and not name.startswith('qemu-system-'):continue
            item={'pid':int(process.name),'argv_sha256':hashlib.sha256(argv).hexdigest(),
                  'start_ticks':int((process/'stat').read_text().rsplit(')',1)[1].split()[19]),
                  'executable':str((process/'exe').resolve()),'boot_id':boot_id}
        except (FileNotFoundError,ProcessLookupError,PermissionError):continue
        historical=known.get(item['pid'])
        if historical and all(item[k]==historical[k] for k in item):excluded.append(item)
        else:peers.append(item)
    return {'baseline_sha256':digest(baseline_path),'exact_historical_exclusions':excluded,'actual_guest_peers':peers}

def guest_admission():
    processes=process_admission()
    assert not processes['actual_guest_peers'],'peer actual guest active; no new launch'
    return {'processes':processes,'resources':memory_guard()}

def expected_hash(receipt):
    h=14695981039346656037
    disk=Path(receipt['historical_input']['disk'])
    assert digest(disk)==receipt['historical_input']['sha256']
    with disk.open('rb') as f: data=f.read(4096)
    assert len(data)==4096
    for r in range(512):
        for b in data: h=((h^b)*1099511628211)&((1<<64)-1)
        h=((h^(r&255))*1099511628211)&((1<<64)-1)
    return h

def main():
    global guard_commands
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--cpus',type=int,choices=(1,2,4),default=2)
    p.add_argument('--requested',type=int,default=None)
    p.add_argument('--mode',choices=('ap','up','novmx','refuse','malformed'),default='ap')
    p.add_argument('--timeout',type=int,default=30)
    p.add_argument('--label',default='final')
    p.add_argument('--build-label',default='final')
    args=p.parse_args()
    requested=args.requested if args.requested is not None else args.cpus
    assert 1<=requested<=32 and 1<=args.timeout<=60
    assert re.fullmatch('[a-z0-9_-]+',args.label)
    out=OUT/f'ap-run-{args.mode}-{args.cpus}-{requested}-{args.label}'
    assert not out.exists(),f'evidence already exists: {out}'
    assert args.build_label.isalnum()
    receipt_path=OUT/f'ap-build-result-{args.build_label}.json'
    receipt=json.loads(receipt_path.read_text())
    closure(receipt);admission=guest_admission();guard=admission['resources']
    out.mkdir()
    # Pin QEMU, Python and firmware before layout/config tools or launch.
    tool_before={x:digest(x) for x in (qemu.DEFAULT_QEMU,sys.executable)}
    firmware_before={x:digest(x) for x in (qemu.DEFAULT_OVMF_CODE,qemu.DEFAULT_OVMF_VARS)}
    guard_commands=provenance.CommandGuard(out/'command-inputs')
    shzinfo.subprocess=types.SimpleNamespace(run=guard_commands.run)
    shzlib.write_json(out/'preparation-intent.json',{'loaded_exact_bytes_sha256':LOADED_SHA,
        'driver_capture':__shz_driver_capture__,'tool_sha256':tool_before,'firmware_sha256':firmware_before,
        'resource_guard':guard,'process_admission':admission['processes'],'build_receipt_sha256':digest(receipt_path)})
    layout_check()
    # The sealed component base is never modified by QA or QEMU.
    esp=OUT/f'ap-component-base-{args.build_label}.img'; overlay=out/'esp.qcow2'
    run(['qemu-img','create','-f','qcow2','-F','raw','-b',esp.resolve(),overlay])
    patch=config_patch(esp,args.mode,requested,out,overlay)
    variables=out/'OVMF_VARS.fd'; shutil.copyfile(qemu.DEFAULT_OVMF_VARS,variables)
    serial=out/'serial.log'; socket_dir=Path(tempfile.mkdtemp(prefix='shz-ap-qmp-')); sock=socket_dir/'qmp.sock'
    cpu='host,-vmx' if args.mode=='novmx' else 'host,+vmx'
    command=[qemu.DEFAULT_QEMU,'-name','shz-supervisor-ap-component','-machine','q35','-accel','kvm','-cpu',cpu,
        '-m','512M','-smp',str(args.cpus),'-nodefaults','-nic','none','-display','none','-device','VGA','-no-reboot',
        '-drive',f'if=pflash,format=raw,unit=0,readonly=on,file={qemu.DEFAULT_OVMF_CODE}',
        '-drive',f'if=pflash,format=raw,unit=1,file={variables}',
        '-drive',f'if=none,id=esp,format=qcow2,file={overlay}', '-device','virtio-blk-pci,drive=esp,bootindex=1',
        '-serial',f'file:{serial}','-qmp',f'unix:{sock},server=on,wait=off']
    record={'command':command,'resource_guard':guard,'config_patch':patch,'build_receipt_sha256':digest(receipt_path),
        'runtime_driver_sha256':DRIVER_SHA,
        'loaded_exact_bytes_sha256':LOADED_SHA,'driver_capture':__shz_driver_capture__,
        'noncompiled_source_successors':RUNTIME_SHA,
        'source_pre':receipt['sources_sha256'],'tool_sha256':{**tool_before,**guard_commands.tool_pins},
        'commands_pre_post':guard_commands.events,
        'firmware_sha256':firmware_before,'mode':args.mode,
        'claims':'physical AP VMX initialization and bounded integrity work; historical DOS-only component'}
    lock=OUT/'ap-guest.lock'
    with lock.open('w') as lease:
        fcntl.flock(lease,fcntl.LOCK_EX|fcntl.LOCK_NB)
        guard_commands.verify();closure(receipt)
        assert all(digest(p)==h for p,h in tool_before.items())
        assert all(digest(p)==h for p,h in firmware_before.items())
        # Admission is in the same control flow as Popen and repeats after
        # preparation: a failed predicate cannot continue through a shell.
        record['launch_admission']=guest_admission()
        proc=qemu.launch(command,out); qmp=None; info=None; boot=None; checks=[]
        record['owned_child_pid']=proc.pid
        print(json.dumps({'launched_pid':proc.pid,'configured_MiB':512,'cpus':args.cpus,'deadline_seconds':args.timeout}),flush=True)
        try:
            qmp=qemu.QMP(sock,timeout=15)
            deadline=time.monotonic()+args.timeout
            while time.monotonic()<deadline:
                time.sleep(.1)
                if proc.poll() is not None: break
                text=serial.read_text(errors='replace') if serial.exists() else ''
                if args.mode in ('novmx','refuse','malformed') and 'REFUSED:' in text: break
                raw=qemu.read_guest_memory(qmp,shzinfo.REGION_BASE,8192,out/'info.bin')
                info=shzinfo.Info.parse(raw)
                if info.magic==shzinfo.MAGIC and (info.stage==0xdead or 'session complete' in text): break
            text=serial.read_text(errors='replace') if serial.exists() else ''
            record['serial']=text
            if info and info.magic==shzinfo.MAGIC:
                record['info']=info.to_dict()
                if info.reserved_in[0]:
                    raw=qemu.read_guest_memory(qmp,info.reserved_in[0],4096,out/'ap.bin')
                    boot=Boot.from_buffer_copy(raw)
                    record['ap']={'magic':boot.magic,'version':boot.version,'bytes':boot.bytes,'requested':boot.requested,
                        'sealed':boot.sealed,'release':boot.release,'low':boot.low,'pages':boot.pages,'hash':boot.bsp_hash,
                        'cpu':[{n:int(getattr(r,n)) for n,_ in Record._fields_} for r in boot.cpus[:requested]]}
            samples=[]
            for c in range(args.cpus):
                registers=qmp.call('human-monitor-command',{'command-line':'info registers','cpu-index':c})
                samples.append({'cpu':c,'registers':registers})
            record['registers']=samples
            record['qmp_cpus']=qmp.call('query-cpus-fast')
            if args.mode in ('novmx','refuse','malformed'):
                checks=[('firmware refusal', 'REFUSED:' in text),('no Supervisor entry','Supervisor (UEFI x64 profile) entered' not in text),
                        ('no AP startup', 'SHZ-AP: sealed' not in text)]
            elif args.mode=='up':
                checks=[('UP default logged','SHZ-AP: UP default' in text),('no retained AP config',info is not None and not info.reserved_in[0]),
                        ('BSP DOS conformance exit',info is not None and info.stage==6 and info.guest_exit_code==0)]
            else:
                expected=expected_hash(receipt)
                checks=[('exact requested physical CPUs',boot is not None and boot.requested==requested and boot.topology.count==args.cpus),
                        ('resource layout/sealed',boot is not None and boot.magic==0x31504150555a4853 and boot.version==1 and boot.bytes==C.sizeof(Boot) and boot.sealed==1),
                        ('retained low pages',boot is not None and boot.pages==requested-1 and boot.low>=0x1000 and boot.low+boot.pages*4096<=0x100000),
                        ('independent expected work hash',boot is not None and boot.bsp_hash==expected),
                        ('BSP DOS conformance exit',info is not None and info.stage==6 and info.guest_exit_code==0)]
                if boot:
                    for c in range(1,requested):
                        r=boot.cpus[c]; regs=samples[c]['registers']
                        actual_cr3=re.search(r'CR3=([0-9a-fA-F]+)',regs)
                        gdtr=re.search(r'GDT=\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',regs)
                        idtr=re.search(r'IDT=\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',regs)
                        tr=re.search(r'TR\s*=([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',regs)
                        rsp=re.search(r'RSP=([0-9a-fA-F]+)',regs)
                        checks += [(f'AP{c} real VMX/work terminal',r.state==5 and r.error==0 and r.hash==expected and r.work==2097152),
                                   (f'AP{c} VMX/long mode architectural state',r.cr4&0x2020==0x2020 and not r.cr4&0x20080 and r.efer&0x500==0x500 and r.cr0&0x80010001==0x80010001),
                                   (f'AP{c} independent QMP CR3',actual_cr3 is not None and int(actual_cr3.group(1),16)==r.cr3),
                                   (f'AP{c} independent live GDT/IDT/TSS',gdtr is not None and idtr is not None and tr is not None and
                                    tuple(int(x,16) for x in gdtr.groups())==(r.gdt,63) and tuple(int(x,16) for x in idtr.groups())==(r.idt,4095) and
                                    tuple(int(x,16) for x in tr.groups())==(24,r.tss,103) and 'TSS64-busy' in regs),
                                   (f'AP{c} independent private stack',rsp is not None and r.stack-65536<=int(rsp.group(1),16)<r.stack),
                                   (f'AP{c} private tables/stack',r.cr3!=info.host_cr3 and r.gdt and r.idt and r.tss and r.stack and len({boot.cpus[j].cr3 for j in range(1,requested)})==requested-1)]
            qmp.call('quit')
        except BaseException as e: record['harness_error']=repr(e)
        finally:
            if qmp: qmp.close()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=10)
            record['owned_child_reaped']=proc.returncode is not None
            record['exit_code']=proc.returncode
            shutil.rmtree(socket_dir)
    closure(receipt)
    record['source_artifacts_post_unchanged']=True
    guard_commands.verify()
    record['preparation_commands_verified']=True
    record['tool_post_unchanged']=all(guard_commands.stable(x,h) for x,h in record['tool_sha256'].items())
    record['retained_temporary_tool_inputs']=guard_commands.retained_paths
    checks += [('owned guest reaped',record['owned_child_reaped']),('source/artifact closure',True),('tool stability',record['tool_post_unchanged'])]
    record['checks']=[{'name':n,'pass':bool(v)} for n,v in checks]
    record['pass']=bool(checks) and all(v for _,v in checks) and 'harness_error' not in record
    shzlib.write_json(out/'result.json',record)
    print(json.dumps({'pass':record['pass'],'checks':len(checks),'failed':[n for n,v in checks if not v], 'harness_error':record.get('harness_error'),'out':str(out)}))
    raise SystemExit(0 if record['pass'] else 1)

if __name__=='__main__': main()
