#!/usr/bin/env python3
"""Source-only observer checks; VMCS evidence below is explicitly synthetic."""
import argparse
import ast
import ctypes
import hashlib
import errno
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path('/root/Win98-Modern-apps-cb43')
OWN = ROOT/'build/modern-apps/native-foundation-source-v1'
SOURCE = OWN/'candidate/shizukudos/supervisor/native_win98/run_candidate.py'
before = hashlib.sha256(SOURCE.read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location('own_native_win98_observer', SOURCE)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
base, producer = m.helpers()
sys.path.insert(0, str(base.HELPERS/'shizukudos/tools'))
import shzinfo

names = []
def check(name, ok):
    assert ok, name
    names.append(name)

def rejected(name, call):
    try:
        call()
    except (RuntimeError, ValueError, SystemExit):
        names.append(name)
        return
    raise AssertionError(name)

shzinfo.selfcheck(producer.COMPILE/'source')
check('actual C header and ctypes evidence layout match', True)

def factory():
    info = shzinfo.Info()
    info.magic, info.version, info.size = shzinfo.MAGIC, 3, ctypes.sizeof(shzinfo.Info)
    info.cap_bits = sum(1 << shzinfo.CAP_BITS[n] for n in ['LONG_MODE','VMX','VMX_ENABLED','EPT','UNRESTRICTED','BACKEND_VMX'])
    for i in range(3):info.cpu_vendor[i] = int.from_bytes(b'GenuineIntel'[4*i:4*i+4], 'little')
    info.stage, info.loader_flags = 5, 1
    info.guest_ram_size, info.disk_size, info.guest_ram_base, info.disk_base = 128 << 20, 2 << 30, 0x10000000, 0x50000000
    win98, native = info.domains[5], info.domains[4]
    win98.kind, win98.generation, win98.state, win98.exits, win98.run_slices = 3, 1, 2, 100, 30
    native.state, native.exit_code, native.last_efer, native.last_cr4, native.last_cs, native.last_rip, native.last_cr3, native.exits = 2, 0, 0xd01, 0x20, 8, 0xffffffff80001000, 0x60000, 100
    native.evidence[30] = 7 | 1 << 33 | 1 << 34
    for i,v in {0:0x80010001,1:0x60000,2:20,3:20000,4:10000,5:16,6:0x2a002a,7:0xc0000096,8:0xc0000005,9:0xc0000005,24:1 | 2 << 16}.items():native.evidence[i]=v
    native.evidence[19], native.evidence[20], native.evidence[21], native.evidence[23] = 0x140000000, 1, 2, 3
    return info

serial = ('SeaBIOS (version synthetic-host-model)\nBooting from Hard Disk...\n'
          'SHZ: IPC channel 2: KERNEL64 <-> WIN98 at gpa e0200000\n'
          'K64 subsys64: serving WIN64 subsystem requests from domain 5 on channel 2\n'
          'K64 test PASS: Win64 console app runs to exit code 7 twice without a fault\n'
          +2*'hello from Win64 PE32+: argc=2 argv1=first\n')
check('explicit synthetic complete construction/native checks pass', all(r['passed'] for r in m.checks(factory(), serial)))
for field, value in [('magic',0),('version',2),('size',8),('cap_bits',0),('loader_flags',0),('guest_ram_size',64 << 20),('disk_size',1 << 30),('status',1),('stage',0xdead)]:
    info = factory();setattr(info,field,value)
    check('reject bad actual contract '+field, not all(r['passed'] for r in m.checks(info, serial)))
for field, value in [('kind',0),('generation',0),('state',4),('exits',0),('run_slices',0)]:
    info = factory();setattr(info.domains[5],field,value)
    check('reject fake/unexecuted Win98 field '+field, not all(r['passed'] for r in m.checks(info, serial)))
info = factory();info.domains[5].error = b'actual failure'
check('reject Win98 domain error', not all(r['passed'] for r in m.checks(info, serial)))
for index, value in [(0,0),(1,0),(2,0),(3,0),(4,0),(5,0),(6,0),(7,0),(8,0),(9,0),(24,0),(30,7 | 1 << 32 | 1 << 33 | 1 << 34),(19,0x400000),(20,0),(21,0),(22,1),(23,0)]:
    info = factory();info.domains[4].evidence[index] = value
    check('reject missing native guest evidence '+str(index), not all(r['passed'] for r in m.checks(info, serial)))
for missing in ['SeaBIOS (version','Booting from Hard Disk','hello from Win64 PE32+: argc=2 argv1=first','SHZ: IPC channel 2: KERNEL64 <-> WIN98','K64 subsys64: serving WIN64 subsystem requests from domain 5 on channel 2','K64 test PASS: Win64 console app runs to exit code 7 twice without a fault']:
    check('reject absent real console marker '+missing, not all(r['passed'] for r in m.checks(factory(), serial.replace(missing,''))))
info = factory();info.domains[4].state=3;info.domains[4].evidence[29]=0x4b363421
check('terminated native kernel cannot stand in for resident real endpoint',not all(r['passed'] for r in m.checks(info,serial)))
check('explicit actual selftest failure rejects construction',not all(r['passed'] for r in m.checks(factory(),serial+'K64 test FAIL: actual failed body\n')))

with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=21 << 30)), patch.object(m.Path,'read_text',return_value='MemAvailable: 10485760 kB\n'):
    check('actual clone and guest resource budget accepts sufficient space', m.resources(ROOT/'build/modern-apps/uncreated-model', True)['disk_free_bytes'] == 21 << 30)
with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=(17 << 30)+(32 << 20))), patch.object(m.Path,'read_text',return_value='MemAvailable: 10485760 kB\n'):
    rejected('clone refuses reserve loss before any VM',lambda:m.resources(ROOT/'build/modern-apps/uncreated-model', True))
with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=17 << 30)), patch.object(m.Path,'read_text',return_value='MemAvailable: 10485760 kB\n'):
    rejected('runtime floor includes capture margin',lambda:m.resources(ROOT/'build/modern-apps/uncreated-model'))
with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=21 << 30)), patch.object(m.Path,'read_text',return_value='MemAvailable: 8388608 kB\n'):
    rejected('4096MiB guest preserves4GiB reserve plus margin',lambda:m.resources(ROOT/'build/modern-apps/uncreated-model'))
with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=18 << 30)), patch.object(m.Path,'read_text',return_value='MemAvailable: 6291456 kB\n'):
    rejected('prelaunch budgets actual guest in addition to reserve',lambda:m.resources(ROOT/'build/modern-apps/uncreated-model'))
    check('live VM does not double-count already allocated guest',m.resources(ROOT/'build/modern-apps/uncreated-model',live=True)['required_available_RAM_bytes']==(4 << 30)+(512 << 20))
with patch.object(m.shutil,'disk_usage',return_value=SimpleNamespace(free=18 << 30)), patch.object(m.Path,'read_text',return_value='MemAvailable: 4194304 kB\n'):
    rejected('live VM still protects actual4GiB reserve plus margin',lambda:m.resources(ROOT/'build/modern-apps/uncreated-model',live=True))

with tempfile.TemporaryDirectory(prefix='native-win98-reflink-host-',dir=ROOT/'build/modern-apps') as tmp:
    src,dst = Path(tmp)/'source',Path(tmp)/'owned'
    content = bytes((i*73+19)&255 for i in range(32768))
    src.write_bytes(content);digest=hashlib.sha256(content).hexdigest()
    m.reflink_clone(base,producer,src,dst,digest,len(content))
    check('actual FICLONE copies whole bytes to distinct inode',src.stat().st_ino!=dst.stat().st_ino and dst.read_bytes()==content)
    with dst.open('r+b') as stream:stream.seek(123);stream.write(b'owned-COW-write')
    check('actual owned clone write preserves original source bytes',src.read_bytes()==content and dst.read_bytes()!=content)
    with src.open('r+b') as stream:stream.seek(4098);stream.write(b'source-own-fixture-write')
    check('actual source fixture write preserves previous clone COW bytes',dst.read_bytes()[4098:4122]==content[4098:4122])
    src.write_bytes(content)
    with patch.object(m.fcntl,'ioctl',side_effect=OSError(errno.EOPNOTSUPP,'explicit unsupported clone fixture')):
        try:
            m.reflink_clone(base,producer,src,Path(tmp)/'failed-owned',digest,len(content))
        except OSError as error:
            check('unsupported FICLONE has no fullcopy fallback',error.errno==errno.EOPNOTSUPP)
        else:
            raise AssertionError('unsupported FICLONE must fail')
    check('unsupported reflink leaves original bytes unchanged',src.read_bytes()==content)
    check('unsupported reflink retains zero-byte owned failure file',(Path(tmp)/'failed-owned').stat().st_size==0)

for timeout in ['59','901']:
    with patch.object(sys,'argv',['observer','--out',str(ROOT/'build/modern-apps/uncreated-timeout-model'),'--timeout',timeout]):
        rejected('production CLI rejects timeout '+timeout,m.main)

with tempfile.TemporaryDirectory(prefix='native-win98-observer-host-',dir=ROOT/'build/modern-apps') as tmp:
    out = Path(tmp)/'failed-preparation';calls=[]
    with patch.object(sys,'argv',['observer','--out',str(out),'--execute']), patch.object(m,'inputs',side_effect=ValueError('explicit host pin failure')), patch.object(m.subprocess,'Popen',side_effect=lambda *a,**k:calls.append(1)):
        rejected('actual production preparation failure exits nonzero',m.main)
    result = json.loads((out/'result.json').read_text())
    check('production preparation FAIL is persisted',result['status']=='FAIL' and not result['VM_executed'])
    check('production preparation failure launches no VM',not calls and result['owned_QEMU_stopped'])
    check('false Win98/app/channel success is never reported',not any(result[k] for k in ['Windows98_boot_verified','Windows98_desktop_verified','native_W64_positive_verified','target_apps_verified']))

tree = ast.parse(SOURCE.read_text())
calls = [n for n in ast.walk(tree) if isinstance(n,ast.Call) and isinstance(n.func,ast.Attribute) and n.func.attr=='call']
commands = {n.args[0].value for n in calls if n.args and isinstance(n.args[0],ast.Constant)}
check('owned observer accepts only fixed screen/stop/quit direct QMP',commands=={'screendump','stop','quit'})
check('observer has no GUI text or keyboard protocol',not any(n for n in ast.walk(tree) if isinstance(n,ast.Constant) and isinstance(n.value,str) and n.value in ['send-key','human-monitor-command','qcode']))
pins = m.inputs(base)
check('all actual compiled/source/artifact/firmware inputs validate',len(pins)>490)
check('source remains exact before and after all checks',hashlib.sha256(SOURCE.read_bytes()).hexdigest()==before)
result = {'status':'PASS_SOURCE_ONLY_HOST_NO_VM','checks':len(names),'names':names,'observer_sha256':before,'actual_input_pins':len(pins),'VM_executed':False,'synthetic_info_contract_tests':True}
(OWN/'win98-observer-host-result-v3.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
