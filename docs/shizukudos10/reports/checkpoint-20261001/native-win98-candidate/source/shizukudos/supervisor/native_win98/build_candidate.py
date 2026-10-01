#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a fresh owned opt-in SeaBIOS/Win98 ESP; no VM or existing build writes.

Uses the real current native K64 already root-tested, the frozen new ordinary
Supervisor payload/EFI, and an exact read-leased copy of the installed cold disk.
The result is a boot candidate, never evidence that Windows 98 or apps booted.
"""
import sys
sys.dont_write_bytecode=True
import argparse,contextlib,fcntl,hashlib,importlib.util,json,os,shutil,signal,stat,struct,subprocess
from pathlib import Path
ROOT=next(p for p in Path(__file__).resolve().parents if (p/'shizukudos/kbuild.py').is_file())
BASE=ROOT/'build/modern-apps/native-foundation-current-build-v2'
COMPILE=ROOT/'build/modern-apps/native-foundation-source-v1/win98-compile-v1'
BASE_SHA='b65ce5dda18fae3d08f934f1ffdac14bbfb64b07e086296a55e9dd838491aad3'
COMPILE_SHA='51afab793e996623b3119dec7067605c2a242391a9f2492755bdc6b3baebe5c7'
COLD=Path('/path/to/your/private-installed-win98.raw')
COLD_SHA='518d18d5e286cb0eb63065d8d896d0d3ee743289f220fb62083f6176b5925db7'
ROM=Path('/usr/share/seabios/bios-256k.bin')
ROM_SHA='9280e87aa94f281b33086df8cf1ad0a0221a9b78e7afe5a7585bc7d3d0234aef'

def stable(s):return s.st_dev,s.st_ino,s.st_size,s.st_mtime_ns,s.st_ctime_ns

def pinned_hash(path,expected):
    if not path.is_absolute() or path.resolve()!=path:raise ValueError('canonical pinned file required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not before.st_size:raise ValueError('nonempty regular input required')
        digest=hashlib.sha256()
        while block:=os.read(fd,1<<20):digest.update(block)
        if stable(before)!=stable(os.fstat(fd)) or stable(before)!=stable(path.stat()) or digest.hexdigest()!=expected:raise ValueError('input SHA/identity drift')
        return before.st_size
    finally:os.close(fd)

def file_sha(path):
    if path.resolve()!=path:raise ValueError('canonical owned artifact required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):raise ValueError('regular artifact required')
        digest=hashlib.sha256()
        while block:=os.read(fd,1<<20):digest.update(block)
        if stable(before)!=stable(os.fstat(fd)) or stable(before)!=stable(path.stat()):raise ValueError('artifact changed during hash')
        return digest.hexdigest()
    finally:os.close(fd)

def input_pins():
    receipts={BASE/'foundation-build-receipt.json':BASE_SHA,COMPILE/'result.json':COMPILE_SHA}
    for p,h in receipts.items():pinned_hash(p,h)
    base=json.loads((BASE/'foundation-build-receipt.json').read_text());compiled=json.loads((COMPILE/'result.json').read_text())
    if base['status']!='PASS_NATIVE_FOUNDATION_BUILD_NOT_RUN' or compiled['status']!='PASS_ORDINARY_NATIVE_PAYLOAD_EFI_BUILD_NOT_RUN':raise ValueError('genuine ordinary build receipts required')
    pins=dict(receipts)
    for name,digest in base['sources_sha256'].items():pins[BASE/'source'/name]=digest
    for name,digest in base['artifacts'].items():pins[BASE/name]=digest
    for name,digest in compiled['source_pins'].items():pins[COMPILE/'source'/name]=digest
    for name,digest in compiled['artifacts'].items():pins[COMPILE/name]=digest
    pins[ROM]=ROM_SHA
    for p,h in pins.items():pinned_hash(p,h)
    if ROM.stat().st_size!=256<<10:raise ValueError('exact genuine256KiB ROM required')
    return pins

@contextlib.contextmanager
def read_leased(path,expected,size):
    if path.resolve()!=path:raise ValueError('canonical cold source required')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);previous=signal.getsignal(signal.SIGIO);broken=[False];lease=False
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size!=size:raise ValueError('cold disk geometry mismatch')
        signal.signal(signal.SIGIO,lambda *_:broken.__setitem__(0,True))
        fcntl.fcntl(fd,fcntl.F_SETOWN,os.getpid());fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_RDLCK);lease=True
        def checkpoint():
            if broken[0] or stable(before)!=stable(os.fstat(fd)) or stable(before)!=stable(path.stat()) or fcntl.fcntl(fd,fcntl.F_GETLEASE)!=fcntl.F_RDLCK:raise RuntimeError('cold source lease/identity changed')
        checkpoint();digest=hashlib.sha256()
        while block:=os.read(fd,1<<20):checkpoint();digest.update(block)
        checkpoint()
        if digest.hexdigest()!=expected:raise ValueError('cold source SHA mismatch')
        os.lseek(fd,0,os.SEEK_SET);yield fd,checkpoint
        checkpoint()
    finally:
        if lease:fcntl.fcntl(fd,fcntl.F_SETLEASE,fcntl.F_UNLCK)
        os.close(fd);signal.signal(signal.SIGIO,previous)

def copy_fd(fd,checkpoint,destination,expected,size):
    digest=hashlib.sha256();written=0
    with destination.open('xb') as stream:
        while block:=os.read(fd,1<<20):
            checkpoint();space(destination,margin=1<<20);stream.write(block);digest.update(block);written+=len(block)
        stream.flush();os.fsync(stream.fileno())
    checkpoint()
    if written!=size or digest.hexdigest()!=expected:raise ValueError('owned cold copy SHA/extent mismatch')
    pinned_hash(destination,expected)

def space(out,initial=False,margin=0):
    required=(17<<30)+((7<<30) if initial else margin)
    if shutil.disk_usage(out.parent).free<required:raise RuntimeError('17GiB floor plus7GiB initial owned copy/ESP/readback budget required')

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);ap.add_argument('--build',action='store_true');a=ap.parse_args();out=a.out
    if not out.is_absolute() or out.resolve()!=out or not out.is_relative_to(ROOT/'build/modern-apps') or out.exists():ap.error('fresh canonical output under owned build/modern-apps required')
    pins=input_pins()
    if not a.build:
        with read_leased(COLD,COLD_SHA,2<<30):pass
        print(json.dumps({'status':'VALIDATED_NO_BUILD_OR_VM','source_pins':len(pins),'cold_source_sha256':COLD_SHA}));return
    space(out,True);out.mkdir();result={'status':'FAIL_BUILD_PRESERVED','VM_executed':False,'Windows98_boot_verified':False,'native_W64_positive_verified':False,'input_pins':{str(p):h for p,h in pins.items()},'cold_source_sha256':COLD_SHA,'commands':[]}
    try:
        with read_leased(COLD,COLD_SHA,2<<30) as (fd,checkpoint):
            disk=out/'disk-owned.img';copy_fd(fd,checkpoint,disk,COLD_SHA,2<<30)
            runtime=out/'runtime';(runtime/'kernel64').mkdir(parents=True);(runtime/'win64').mkdir()
            for name,relative in [('KERNEL64.BIN','kernel64'),('WIN64.IMG','win64')]:
                source=BASE/'source/build/shizukudos'/relative/name;shutil.copyfile(source,runtime/relative/name)
            variables=out/'OVMF_VARS.fd';shutil.copyfile(BASE/'OVMF_VARS.fd',variables)
            sys.path.insert(0,str(COMPILE/'source/shizukudos/tools'));sys.modules.pop('shzlib',None)
            spec=importlib.util.spec_from_file_location('owned_win98_esp',COMPILE/'source/shizukudos/supervisor/build.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
            b.OUT=out/'esp-build';b.OUT.mkdir();b.BUILD=runtime;b.ESP_MIB=2304
            def run(command,**kwargs):
                checkpoint();space(out,margin=2<<30);actual=[str(x) for x in command];result['commands'].append(actual)
                kwargs.pop('timeout',None);r=subprocess.run(actual,cwd=out,check=True,timeout=900,**({'capture_output':True,'text':True} if kwargs.pop('capture',False) else {}),**kwargs)
                checkpoint();space(out);return r
            b.run=run
            loader=COMPILE/'source/build/shizukudos/supervisor/BOOTX64.EFI';esp=b.build_esp(loader,disk)
            run(['mmd','-i',esp,'::/EFI/SHIZUKU'],env={'MTOOLS_SKIP_CHECK':'1','PATH':'/usr/bin:/bin'})
            policy=out/'BOOT.INI';policy.write_bytes(b'mode=supervisor\n')
            config=out/'WIN98CFG.BIN';config.write_bytes(struct.pack('<4I',0x38395753,1,128,0))
            bios=out/'SEABIOS.BIN';shutil.copyfile(ROM,bios)
            for source,target in [(policy,'::/EFI/SHIZUKU/BOOT.INI'),(config,'::/SHZDOS/WIN98CFG.BIN'),(bios,'::/SHZDOS/SEABIOS.BIN')]:run(['mcopy','-i',esp,source,target],env={'MTOOLS_SKIP_CHECK':'1','PATH':'/usr/bin:/bin'})
            fsck=run(['fsck.vfat','-n',esp],capture=True);(out/'esp-fsck.log').write_text(fsck.stdout+fsck.stderr)
            # Every payload on the owned ESP is read back in full; pathname alone is no proof.
            checks=[]
            for target,source in [('::/SHZDOS/DISK.IMG',disk),('::/SHZDOS/SEABIOS.BIN',bios),('::/SHZDOS/WIN98CFG.BIN',config),('::/SHZDOS/KERNEL64.BIN',runtime/'kernel64/KERNEL64.BIN'),('::/SHZDOS/WIN64.IMG',runtime/'win64/WIN64.IMG'),('::/EFI/BOOT/BOOTX64.EFI',loader)]:
                extracted=out/('readback-'+source.name);run(['mcopy','-i',esp,target,extracted],env={'MTOOLS_SKIP_CHECK':'1','PATH':'/usr/bin:/bin'})
                expected=file_sha(source) if source!=disk else COLD_SHA
                pinned_hash(extracted,expected);checks.append({'ESP_path':target,'SHA':expected,'whole_bytes_verified':True})
            checkpoint()
        if input_pins()!=pins:raise RuntimeError('frozen compile/foundation/ROM source drift')
        pinned_hash(COLD,COLD_SHA)
        result.update(status='PASS_OWNED_WIN98_BOOT_CANDIDATE_NOT_RUN',readbacks=checks,artifacts={str(p.relative_to(out)):file_sha(p) for p in [esp,variables,config,bios]},cold_source_unchanged=True,source_before_after_match=True,expected_next_gate='root-owned4096MiB actual L1/VMX genuine SeaBIOS boot on isolated installed2GiB Win98 disk; not yet GUI/channel/app verified')
    except BaseException as exc:result['error']=f'{type(exc).__name__}: {exc}';raise
    finally:(out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'receipt':str(out/'result.json')}))
if __name__=='__main__':main()
