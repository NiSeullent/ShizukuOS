#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run one real self-checking guest executable from a copied Kernel64 archive.

Records a contract test only. No Windows 98 VM, application package or network
is involved. The input archive and source disk images stay unchanged.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent/'tools'))
import qemu
import shzlib


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--runtime', type=Path, required=True)
    ap.add_argument('--kernel', type=Path, default=shzlib.BUILD/'kernel64s')
    ap.add_argument('--test', required=True)
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--timeout', type=int, default=100)
    ap.add_argument('--guest-timeout', type=int, default=60)
    ap.add_argument('--accel', choices=('kvm','tcg'), default='kvm')
    args=ap.parse_args()
    if not re.fullmatch(r'T_[A-Z0-9_]+\.EXE', args.test):
        raise SystemExit('test must name T_*.EXE')
    args.out.mkdir(parents=True,exist_ok=True)
    source=args.runtime/'WIN64.IMG'
    raw=source.read_bytes()
    if raw[:8]!=b'SHZARC01':raise SystemExit('invalid runtime')
    count=struct.unpack_from('<I',raw,8)[0]
    header=16+count*136
    if header>len(raw):raise SystemExit('truncated runtime')
    entries={}
    for i in range(count):
        name,off,size=struct.unpack_from('<120sQQ',raw,16+i*136)
        name=name.split(b'\0',1)[0].decode('ascii')
        if name in entries or off<header or off+size>len(raw):raise SystemExit('invalid archive entry')
        entries[name]=raw[off:off+size]
    testpath='\\SHZ\\TESTS\\'+args.test
    if testpath not in entries:raise SystemExit('guest test absent from runtime')
    control=(f'image=C:{testpath}\r\ncmdline={args.test}\r\ncwd=C:\\SHZ\\TESTS\r\ntimeout={args.guest_timeout}\r\n').encode()
    entries['\\SHZ\\CONTRACT.TXT']=control
    spec=importlib.util.spec_from_file_location('contract_builder',HERE.parent/'win64/build.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    archive=args.out/'CONTRACT.IMG'
    archive.write_bytes(builder.pack_archive(sorted(entries.items())))
    serial=args.out/'serial.log'
    serial.unlink(missing_ok=True)
    stub=args.kernel/'boot.elf';kernel=args.kernel/'KERNEL64S.BIN'
    kernel_hash=shzlib.sha256_file(kernel)
    cmd=[qemu.DEFAULT_QEMU,'-machine','pc','-accel',args.accel,'-cpu','max','-m','3072',
         '-nodefaults','-display','none','-vga','std','-kernel',str(stub),'-initrd',f'{kernel},{archive}',
         '-append','shz.noapps shz.autorun=C:\\SHZ\\CONTRACT.TXT shz.k32trace shz.exctrace',
         '-serial',f'file:{serial}','-device','isa-debug-exit,iobase=0xf4,iosize=0x04','-no-reboot']
    start=time.monotonic();timed_out=False
    try:
        result=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=args.timeout)
        output=result.stdout.decode(errors='replace');returncode=result.returncode
    except subprocess.TimeoutExpired as error:
        timed_out=True;returncode=None;output=(error.stdout or b'').decode(errors='replace')
    text=serial.read_text(errors='replace') if serial.exists() else ''
    after=text[text.find('K64 autorun: starting'):] if 'K64 autorun: starting' in text else ''
    match=re.search(r'K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d)',after)
    app_text=after[:match.start()] if match else after
    failures=[line for line in app_text.splitlines() if re.search(r'(?:^|\] )FAIL:|(?:^|\] )FAIL |K64: process .* killed',line)]
    failures.extend(line for line in text.splitlines() if 'K64 test FAIL' in line or 'K64 subsys64 FAIL' in line)
    checks=[line for line in app_text.splitlines() if re.search(r'(?:^|\] )PASS:|(?:^|\] )PASS ',line)]
    summary_count = 0
    for summary in re.finditer(r'SHZ-([A-Z0-9_]+)-CHECKS (\d+) checked (\d+) failed', app_text):
        if int(summary[3]): failures.append(summary[0])
        elif int(summary[2]) > 0 and f'SHZ-{summary[1]}-PASS' in app_text:
            checks.append(summary[0])
            summary_count += int(summary[2])
    unchanged=shzlib.sha256_file(source)==hashlib.sha256(raw).hexdigest() and shzlib.sha256_file(kernel)==kernel_hash
    ok=bool(not timed_out and match and match[1]=='exited' and int(match[2],16)==0 and match[3]=='0' and checks and not failures and 'SHZ-EXIT:0' in text and unchanged)
    proof={'status':'PASS' if ok else 'FAIL','evidence_level':'standalone-kernel64-api-contract','guest_os':'ShizukuDOS Kernel64 standalone',
           'windows98_execution_verified':False,'app_functionality_verified':False,'test':args.test,'test_sha256':hashlib.sha256(entries[testpath]).hexdigest(),
           'runtime_sha256':hashlib.sha256(raw).hexdigest(),'kernel_sha256':kernel_hash,'inputs_unchanged':unchanged,
           'autorun_result':match[0] if match else None,'checks':checks,'summary_check_count':summary_count,
           'failures':failures,'seconds':round(time.monotonic()-start,2),
           'timed_out':timed_out,'qemu_returncode':returncode,'command':cmd,'qemu_output':output}
    shzlib.write_json(args.out/'result.json',proof)
    print(proof['status'],args.test,len(checks),'checks',proof['autorun_result'])
    return 0 if ok else 1


if __name__=='__main__':raise SystemExit(main())
