#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run only real T_DISK.EXE on a fresh owned 320 MiB FAT32/AHCI disk.

The root task owns actual execution. This records standalone Kernel64 disk
contracts, not Windows 98 execution or app functionality. Inputs stay immutable;
the newly created FAT32 image is writable and all failure artifacts are kept.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import time
import traceback
import zlib

ROOT=Path(__file__).resolve().parents[1]
TESTS=ROOT/'shizukudos/tests'
sys.path.insert(0,str(TESTS))
import run_k64_disk as disk
import run_k64_contract as contract
import run_k64_standalone as standalone

SIZE_MIB=320
FLOOR=17*1024**3
TESTPATH='\\SHZ\\TESTS\\T_DISK.EXE'
DELETE_CHECKS=('delete actual FAT file','deleted FAT file is absent','second FAT deletion reports file not found')


def sha(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for part in iter(lambda:f.read(1024**2),b''):h.update(part)
    return h.hexdigest()


def unpack(raw):
    if len(raw)<16 or raw[:8]!=b'SHZARC01':raise ValueError('invalid runtime archive')
    count=struct.unpack_from('<I',raw,8)[0];header=16+count*136
    if header>len(raw):raise ValueError('truncated runtime archive')
    files={};spans=[]
    for i in range(count):
        name,off,size=struct.unpack_from('<120sQQ',raw,16+i*136)
        name=name.split(bytes(1),1)[0].decode('ascii')
        if name in files or off<header or off+size>len(raw):raise ValueError('invalid archive entry')
        files[name]=raw[off:off+size];spans.append((off,off+size))
    spans.sort()
    if any(a[1]>b[0] for a,b in zip(spans,spans[1:])):raise ValueError('overlapping archive entries')
    return files


def make_manifest():
    return {'TESTS/hello.txt':b'hello from the FAT32 volume\r\n','TESTS/empty.txt':b'',
            'TESTS/pattern_1m.bin':disk.pattern(11,(1<<20)+17),
            'TESTS/A Long Mixed-Case File Name.dat':disk.pattern(12,4096*3+5),
            'TESTS/big_4m.bin':disk.pattern(13,(4<<20)+13),
            'TESTS/Sub Directory/nested file.txt':b'nested content on D:\r\n',**disk.WRITE_ORIG}


def aliases_from_mdir(text):
    # mdir appends an LFN only for entries that really have an LFN. The kernel
    # likewise exposes an alternate name only for such entries, not plain 8.3.
    aliases={}
    for line in text.splitlines():
        m=re.match(r'^(\S+)\s+(\S{1,3})?\s+(?:<DIR>|\d+)\s+\S+\s+\S+\s+(.+)$',line)
        if m:
            name=m[3].strip()
            if name not in {'.','..'}:aliases[name]=m[1]+('.'+m[2] if m[2] else '')
    return aliases


def actual_contract(serial,timed_out,qemu_rc):
    start=re.search(r'^K64 autorun: starting .*T_DISK\.EXE.*$',serial,re.M)
    scope=serial[start.start():] if start else ''
    # proc_wait returns 0 on successful teardown/reaping, -1 on lookup failure.
    # The early live-thread diagnostic is a distinct parenthesized result and
    # cannot satisfy this full line. Reaped is a return code, not a boolean.
    m=re.search(r'^K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d) reaped=(-?\d+) after (\d+) ms$',scope,re.M)
    app=scope[:m.start()] if m else scope
    summaries=list(re.finditer(r'(?:^|\] )t_disk: (\d+) checks, (\d+) failed$',app,re.M))
    failures=[line for line in app.splitlines() if re.search(r'(?:^|\] )FAIL:|(?:^|\] )FAIL |K64: process .* killed',line)]
    failures.extend(line for line in serial.splitlines() if 'K64 test FAIL' in line or 'K64 subsys64 FAIL' in line)
    delete_ok=all(re.search(r'(?:^|\] )PASS: '+re.escape(name)+r'$',app,re.M) for name in DELETE_CHECKS)
    ev,exit_code=standalone.parse(serial)
    ok=bool(start and m and m[1]=='exited' and int(m[2],16)==0 and m[3]=='0' and m[4]=='0'
            and len(summaries)==1 and int(summaries[0][1])>0 and summaries[0][2]=='0' and delete_ok
            and not failures and 'SKIP:' not in app and exit_code==0 and not timed_out and qemu_rc is not None and qemu_rc>=0)
    return {'check':'actual T_DISK checked, normal exit 0/fault 0, deletion assertions and no SKIP/FAIL',
            'status':'PASS' if ok else 'FAIL','detail':{'autorun':m[0] if m else None,
            'summary':summaries[0][0] if len(summaries)==1 else None,'deletion_checks_present':delete_ok,
            'failures':failures,'timed_out':timed_out,'qemu_returncode':qemu_rc,'kernel_exit':exit_code}},app,ev


def disk_checks(serial,ev,manifest,listing,sector0_crc):
    check=standalone.check;c=[]
    files={n[6:]:v for n,v in manifest.items() if n.startswith('TESTS/') and '/' not in n[6:]}
    children={**files,'Sub Directory':None}
    got_dir={m[1]:(int(m[2]),int(m[3],16),int(m[4],16)) for m in re.finditer(
        r'^\[win64 T_DISK\.EXE pid \d+\] DISK-DIR (.+?) (\d+) ([0-9a-f]+) ([0-9a-f]{16})$',serial,re.M) if m[1] not in {'.','..'}}
    got_crc={m[1]:(int(m[2]),int(m[3],16)) for m in re.finditer(
        r'^\[win64 T_DISK\.EXE pid \d+\] DISK-CRC (.+?) (\d+) ([0-9a-f]+)$',serial,re.M)}
    got_range={m[1].rsplit('\\',1)[-1]:(int(m[2]),int(m[3]),int(m[4],16)) for m in re.finditer(
        r'^\[win64 T_DISK\.EXE pid \d+\] DISK-RANGE (.+?) (\d+) (\d+) ([0-9a-f]+)$',serial,re.M)}
    c.append(check('TESTS children exclude hierarchy entries and match exact packed children',set(got_dir)==set(children),str(sorted(got_dir))))
    bad=[]
    for name,data in children.items():
        g=got_dir.get(name)
        if g is None:bad.append(name+' missing');continue
        if data is None:
            if not g[1]&0x10:bad.append(name+' not directory')
        elif g[0]!=len(data) or g[1]&0x10 or g[2]!=disk.FIXED_FILETIME:bad.append(name+' metadata mismatch')
    c.append(check('file sizes/attributes/fixed timestamps match',not bad,'; '.join(bad)))
    wanted_crc={n:(len(v),zlib.crc32(v)&0xffffffff) for n,v in files.items()}
    wanted_range={n:(max(len(v)//2-1234,1),min(3000,len(v)-max(len(v)//2-1234,1)),
                    zlib.crc32(v[max(len(v)//2-1234,1):max(len(v)//2-1234,1)+3000])&0xffffffff)
                  for n,v in files.items() if len(v)>8192}
    c.append(check('all sequential CRC and unaligned range reads match source bytes',got_crc==wanted_crc and got_range==wanted_range,str({'crc':got_crc,'range':got_range})))
    nested=manifest['TESTS/Sub Directory/nested file.txt'];m=re.search(r'DISK-NESTED (\d+) ([0-9a-f]+)',serial)
    c.append(check('nested LFN read matches source bytes',bool(m) and (int(m[1]),int(m[2],16))==(len(nested),zlib.crc32(nested)&0xffffffff),m[0] if m else 'missing'))
    xor=0
    for v in files.values():xor^=zlib.crc32(v)&0xffffffff
    summary=re.search(r'DISK-SUMMARY (\d+) (\d+) ([0-9a-f]+)',serial)
    c.append(check('content counts/CRC evidence match exactly',ev.get(18)==(len(files)<<32)|xor and bool(summary)
        and (int(summary[1]),int(summary[2]),int(summary[3],16))==(len(children),len(files),xor),str(ev.get(18))))
    aliases=aliases_from_mdir(listing);queries={}
    for m in re.finditer(r'^\[win64 T_DISK\.EXE pid \d+\] DISK-QUERY (\d+) (\S+) (.*)\|(.*)$',serial,re.M):
        if m[3] not in {'.','..'}:queries.setdefault((int(m[1]),m[2]),[]).append((m[3],m[4].upper()))
    want={(12,'*.bin'):sorted((n,'') for n in files if n.endswith('.bin')),
          (1,'A*.DAT'):[('A Long Mixed-Case File Name.dat','')],
          (3,'*'):sorted((n,aliases.get(n,'').upper()) for n in children)}
    got={k:sorted(v) for k,v in queries.items()}
    c.append(check('directory query classes/patterns and LFN aliases match mtools',got==want and len(aliases)>=2,str({'guest':got,'host':want})))
    mount=re.search(r'K64 disk: D: = (\S+), FAT32 "(\w*)" id ([0-9a-f]+), (\d+) clusters of (\d+) bytes',serial)
    c.append(check('real D FAT32 mount has SHZDISK label and 4096-byte clusters',bool(mount) and mount[2]=='SHZDISK' and mount[5]=='4096',mount[0] if mount else 'missing mount'))
    c.append(check('AHCI sector-zero CRC and extent match owned 320MiB image',ev.get(13)==((SIZE_MIB*1024**2//512)<<32)|sector0_crc,str(ev.get(13))))
    return c


class HostCommands:
    def __init__(self,out):self.out=out;self.records=[]
    def run(self,cmd,env=None):
        index=len(self.records);name=f'host-command-{index:03d}'
        record={'command':list(map(str,cmd)),'returncode':None,'stdout':name+'.stdout','stderr':name+'.stderr'}
        self.records.append(record)
        environment=dict(os.environ if env is None else env);environment['LC_ALL']='C'
        try:result=subprocess.run(record['command'],env=environment,capture_output=True,timeout=300)
        except BaseException as error:
            record['error']=f'{type(error).__name__}: {error}'
            (self.out/(name+'.stderr')).write_text(record['error'])
            (self.out/(name+'.stdout')).write_bytes(getattr(error,'stdout',None) or b'')
            raise
        (self.out/(name+'.stdout')).write_bytes(result.stdout);(self.out/(name+'.stderr')).write_bytes(result.stderr)
        record['returncode']=result.returncode
        return result


def write_checks(serial,image,out,host):
    c=[];check=standalone.check;want=disk.expected_writes()
    got={m[1].removeprefix('D:\\').replace('\\','/'):(int(m[2]),int(m[3],16)) for m in re.finditer(
        r'^\[win64 T_DISK\.EXE pid \d+\] DISK-WRITE (.+?) (\d+) ([0-9a-f]+)$',serial,re.M)}
    c.append(check('guest readback CRC/size for all four existing write contracts',got=={n:(len(v),zlib.crc32(v)&0xffffffff) for n,v in want.items()},str(got)))
    r=host.run(['fsck.fat','-n','-v',image]);text=(r.stdout+r.stderr).decode(errors='replace');(out/'fsck-after.txt').write_text(text)
    problems=[line for line in text.splitlines() if not line.startswith('Checking') and any(k in line.lower() for k in
        ('wrong','lost','invalid','differ','bad ','orphan','reclaim','unused','free cluster summary','has no','starts with','contains'))]
    c.append(check('real fsck -n reports a clean written FAT32 image',r.returncode==0 and not problems,str({'rc':r.returncode,'problems':problems})))
    bad=[]
    for i,(name,data) in enumerate(want.items()):
        target=out/f'readback-{i}.bin';r=host.run(['mcopy','-n','-i',image,'::'+name,target],env=disk.mtools_env())
        if r.returncode or not target.exists() or target.read_bytes()!=data:bad.append(name)
    c.append(check('real mcopy bytes equal each complete guest-written file',not bad,str(bad)))
    r=host.run(['mdir','-i',image,'::OUT'],env=disk.mtools_env());listing=r.stdout.decode(errors='replace');(out/'mdir-out.txt').write_text(listing)
    c.append(check('written LFN names and generated alias remain present',r.returncode==0 and 'Guest Written File.bin' in listing
        and 'GUESTW~1 BIN' in ' '.join(listing.split()) and 'Sub Dir' in listing,listing))
    missing=out/'deleted-readback.bin';r=host.run(['mcopy','-n','-i',image,'::OUT/delete.tmp',missing],env=disk.mtools_env())
    listed_delete=bool(re.search(r'^delete\s+tmp\s+',listing,re.I|re.M))
    c.append(check('deleted fixture absent in actual OUT listing and mcopy reports not found',not listed_delete and not missing.exists()
        and r.returncode!=0 and 'not found' in (r.stdout+r.stderr).decode(errors='replace').lower(),str(r.returncode)))
    pattern=(r'K64 disk: flush (\S+): rc (-?\d+); (\S+): (\d+) sectors read, (\d+) written, (\d+) cache flush'
        r'\(es\); D: (\d+) write\(s\), (\d+) create\(s\), (\d+) delete\(s\), (\d+) rename\(s\), (\d+) sector writes, (\d+) free clusters')
    flushes=list(re.finditer(pattern,serial));last=flushes[-1] if flushes else None
    c.append(check('actual WRITE DMA/FLUSH counters use current delete/rename log layout',bool(last) and last[2]=='0'
        and int(last[5])>600 and int(last[6])>=2 and int(last[7])>=5 and (int(last[8]),int(last[9])) in {(4,0),(5,1)}
        and last[10]=='0',last[0] if last else 'missing latest flush'))
    return c


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runtime',type=Path,required=True);ap.add_argument('--kernel',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True);ap.add_argument('--timeout',type=int,default=240)
    ap.add_argument('--guest-timeout',type=int,default=180);ap.add_argument('--memory',default='512')
    ap.add_argument('--accel',choices=('kvm','tcg'),default='kvm');args=ap.parse_args()
    out=args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT/'build') or args.out.resolve()!=args.out or ',' in str(out):raise SystemExit('fresh canonical owned output below build required')
    runtime=args.runtime/'WIN64.IMG';kernel=args.kernel/'KERNEL64S.BIN';stub=args.kernel/'boot.elf'
    for path in (runtime,kernel,stub):
        if not path.is_file():raise SystemExit('missing immutable input '+str(path))
    spec=importlib.util.spec_from_file_location('fat32_contract_builder',ROOT/'shizukudos/win64/build.py');builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    sources={Path(__file__).resolve(),Path(disk.__file__),Path(contract.__file__),Path(standalone.__file__),
        Path(contract.qemu.__file__),Path(contract.shzlib.__file__),Path(builder.__file__),Path(builder.verres.__file__),
        Path(disk.k64_lazy_dll.__file__),runtime,kernel,stub}
    before={str(path):sha(path) for path in sources};raw=runtime.read_bytes();entries=unpack(raw)
    if TESTPATH not in entries:raise SystemExit('T_DISK.EXE absent from frozen archive')
    entries['\\SHZ\\CONTRACT.TXT']=(f'image=C:{TESTPATH}\r\ncmdline=T_DISK.EXE\r\ncwd=C:\\SHZ\\TESTS\r\ntimeout={args.guest_timeout}\r\n').encode()
    packed=builder.pack_archive(sorted(entries.items()))
    free=os.statvfs(ROOT)
    if free.f_bavail*free.f_frsize<FLOOR+SIZE_MIB*1024**2+len(packed)+8*1024**2:raise SystemExit('17 GiB reserve plus fresh image/archive required')
    out.mkdir();host=HostCommands(out);proof={'status':'RUNNING','evidence_level':'standalone-kernel64-fat32-native-contract',
        'guest_os':'ShizukuDOS Kernel64 standalone','windows98_execution_verified':False,'app_functionality_verified':False,
        'test':'T_DISK.EXE','test_sha256':hashlib.sha256(entries[TESTPATH]).hexdigest(),'inputs_sha256_before':before,
        'owned_writable_disk':str(out/'disk.img'),'disk_size_mib':SIZE_MIB,'cluster_bytes':4096,'checks':[],'actual_guest_executed':False}
    started=time.monotonic();image=out/'disk.img';serial_path=out/'serial.log'
    try:
        manifest=make_manifest();src=out/'src';src.mkdir();files=[]
        for i,(name,data) in enumerate(manifest.items()):
            path=src/f'{i:02d}.bin';path.write_bytes(data);files.append((path,name))
        (out/'manifest.json').write_text(json.dumps({name:{'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'crc32':f'{zlib.crc32(data)&0xffffffff:08x}'} for name,data in manifest.items()},indent=2)+'\n')
        original_run=disk.run
        def logged_prepare(cmd,env=None,capture=False):
            result=host.run(cmd,env)
            if result.returncode:raise RuntimeError('disk preparation command failed; complete output preserved')
            return result
        disk.run=logged_prepare
        try:disk.make_image(image,SIZE_MIB,8,files,['TESTS','TESTS/Sub Directory','WRITE'])
        finally:disk.run=original_run
        r=host.run(['fsck.fat','-n',image]);(out/'fsck-before.txt').write_bytes(r.stdout+r.stderr)
        if r.returncode:raise RuntimeError('fresh FAT32 baseline fsck failed')
        proof['image_sha256_before_boot']=sha(image)
        with image.open('rb') as f:sector_crc=zlib.crc32(f.read(512))&0xffffffff
        archive=out/'CONTRACT.IMG';archive.write_bytes(packed);archive_before=sha(archive)
        free=os.statvfs(ROOT)
        if free.f_bavail*free.f_frsize<FLOOR+8*1024**2:raise RuntimeError('17 GiB reserve unavailable immediately before guest launch')
        cmd=[contract.qemu.DEFAULT_QEMU,'-machine','pc','-accel',args.accel,'-cpu','max','-m',args.memory,
            '-nodefaults','-display','none','-vga','std','-kernel',str(stub),'-initrd',f'{kernel},{archive}',
            '-append','shz.noapps shz.autorun=C:\\SHZ\\CONTRACT.TXT shz.k32trace shz.exctrace',
            '-serial',f'file:{serial_path}','-device','isa-debug-exit,iobase=0xf4,iosize=0x04','-no-reboot',
            '-device','ahci,id=ahci0','-drive',f'if=none,id=d0,file={image},format=raw','-device','ide-hd,drive=d0,bus=ahci0.0']
        proof.update(command=cmd,guest_command_attempted=True);timed_out=False
        try:
            result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=args.timeout);output=result.stdout;rc=result.returncode
        except subprocess.TimeoutExpired as error:timed_out=True;output=error.stdout or b'';rc=None
        (out/'qemu.log').write_bytes(output);serial=serial_path.read_text(errors='replace') if serial_path.exists() else ''
        actual,app,ev=actual_contract(serial,timed_out,rc)
        proof.update(qemu_returncode=rc,timed_out=timed_out,actual_guest_executed=bool(re.search(
            r'^\[win64 T_DISK\.EXE pid \d+\]',serial,re.M)),
            contract_archive_sha256_before=archive_before,contract_archive_sha256_after=sha(archive))
        r=host.run(['mdir','-i',image,'::TESTS'],env=disk.mtools_env());listing=r.stdout.decode(errors='replace');(out/'mdir-tests.txt').write_text(listing)
        proof['checks']=[actual,standalone.check('mtools TESTS listing succeeds',r.returncode==0,str(r.returncode))]
        proof['checks']+=disk_checks(serial,ev,manifest,listing,sector_crc)+write_checks(serial,image,out,host)
        proof['checks'].append(standalone.check('owned contract archive unchanged while QEMU consumed it',sha(archive)==archive_before))
        proof['status']='PASS' if all(c['status']=='PASS' for c in proof['checks']) else 'FAIL'
    except BaseException as error:
        proof.update(status='FAIL',error=f'{type(error).__name__}: {error}');(out/'failure.txt').write_text(traceback.format_exc())
    finally:
        after={}
        for path in sources:
            try:after[str(path)]=sha(path)
            except OSError as error:after[str(path)]='ERROR:'+str(error)
        proof.update(inputs_sha256_after=after,inputs_unchanged=after==before,host_commands=host.records,seconds=round(time.monotonic()-started,2))
        if after!=before:proof['status']='FAIL';proof['input_drift']=True
        if image.exists():proof['image_sha256_after_guest']=sha(image)
        proof['preserved_artifacts']=[{'path':str(p.relative_to(out)),'bytes':p.stat().st_size,'sha256':sha(p)} for p in out.rglob('*') if p.is_file() and p.name!='result.json']
        (out/'result.json').write_text(json.dumps(proof,indent=2)+'\n')
    print(proof['status'],'T_DISK.EXE standalone FAT32 contract')
    return 0 if proof['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
