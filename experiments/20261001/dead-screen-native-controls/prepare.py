#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare NEW unbooted private control disks. Never launch QEMU or change defaults."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

sys.dont_write_bytecode=True
import runner
HERE=Path(__file__).resolve().parent
ROOT=runner.ROOT
NATIVE=ROOT/'build/dead-screen-candidate-20261001T1120-v5'
NATIVE_RESULT_SHA='43dc3ffb6efea940326b2dc758cfe07eb9176fc49b486ee16db9104ab518a3dd'
NATIVE_MANIFEST_SHA='38716fcf05a72bf2ad527e895747c547529697457b90c4d36d756898227ba167'
TOKENS={case:'shz.dead-screen-'+case+'-control' for case in runner.CASES}
EPOCH=1785283200


def pin(p):
    p=Path(p).resolve(strict=True)
    return {'path':str(p),'bytes':p.stat().st_size,'sha256':runner.digest(p)}


def elf_symbols(path):
    data=path.read_bytes()
    if data[:6]!=b'\x7fELF\x02\x01' or struct.unpack_from('<H',data,18)[0]!=62:
        raise ValueError('actual little-endian ELF64 x86_64 candidate required')
    shoff=struct.unpack_from('<Q',data,40)[0];shsize,shnum=struct.unpack_from('<HH',data,58)
    if shsize!=64 or not 0<shnum<100 or shoff+shnum*64>len(data): raise ValueError('ELF section bounds')
    sections=[struct.unpack_from('<IIQQQQIIQQ',data,shoff+i*64) for i in range(shnum)]
    found={};owner=None;global_symbols={}
    for s in sections:
        if s[1]!=2: continue
        if s[9]!=24 or s[5]%24 or s[4]+s[5]>len(data) or s[6]>=shnum: raise ValueError('ELF symbol bounds')
        table=sections[s[6]];names=data[table[4]:table[4]+table[5]]
        for off in range(s[4],s[4]+s[5],24):
            name,info,_,index,value,size=struct.unpack_from('<IBBHQQ',data,off)
            if name>=len(names): raise ValueError('ELF name bounds')
            end=names.find(b'\0',name)
            if end<0: raise ValueError('ELF unterminated name')
            text=names[name:end].decode('ascii')
            typ=info&15
            if typ==4: owner=text
            if index and value:
                if typ==1 and info>>4==0 and owner=='native.c' and text in ('state','framebuffer','force_text','fallback_depth','initialised','keyboard_ready','timer_ready','serial_ready'):
                    if text in found: raise ValueError('ambiguous source-owned native symbol')
                    found[text]={'virtual':value,'physical':value-0xffffffff80000000,'bytes':size,'STT_FILE_owner':owner}
                if info>>4 in (1,2): global_symbols[text]=(value,size,index)
    expected={'state':1352,'framebuffer':40,'force_text':4,'fallback_depth':4,'initialised':4,'keyboard_ready':4,'timer_ready':4,'serial_ready':4}
    if {k:v['bytes'] for k,v in found.items()}!=expected: raise ValueError('compiled native symbol sizes/ownership differ')
    for v in found.values():
        if not 0x100000<=v['physical'] or v['physical']+v['bytes']>0x300000: raise ValueError('compiled BSS symbol out of retained kernel image')
    value,size,index=global_symbols['ds_native_control'];section=sections[index]
    off=section[4]+value-section[3];code=data[off:off+size]
    positions=[i for i in range(len(code)-1) if code[i:i+2]==b'\x0f\x0b']
    if len(positions)!=1: raise ValueError('closed deliberate control UD2 must be unique')
    # Bind the pinned control's real panic E8 call to the linked kpanic target.
    panic_call=value+0x89
    encoded=code[0x89:0x8e]
    if len(encoded)!=5 or encoded[0]!=0xe8 or panic_call+5+struct.unpack_from('<i',encoded,1)[0]!=global_symbols['kpanic'][0]:
        raise ValueError('held deliberate panic call/return instruction differs')
    return found,value+positions[0],global_symbols['__bss_end'][0],panic_call+5,{'call_ip':panic_call,'instruction_hex':encoded.hex(),'target_ip':global_symbols['kpanic'][0]}


def chs(lba):
    cyl,rem=divmod(lba,16*63);head,sec=divmod(rem,63);cyl=min(cyl,1023)
    return bytes([head,sec+1|((cyl>>2)&0xc0),cyl&255])


def main():
    if sys.argv[1:]: raise ValueError('closed preparation takes no alternate paths or options')
    planpath=HERE/'plan.json'
    if planpath.exists() or (HERE/'prepared').exists(): raise ValueError('preserve existing preparation; require a new version')
    logs=[];hold={};sources={};toolruntime={};report={'status':'FAIL','native_started':False,'app_success':False,'win98_vmm_acceptance':False}
    env={**os.environ,'TZ':'UTC','SOURCE_DATE_EPOCH':str(EPOCH),'MTOOLS_SKIP_CHECK':'1'}
    def run(argv,label,timeout=30):
        p=subprocess.run([str(a) for a in argv],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,cwd=ROOT,timeout=timeout)
        path=HERE/(f'{len(logs):03d}-'+label+'.log');path.write_bytes(p.stdout)
        logs.append({**pin(path),'command':[str(a) for a in argv],'exit_code':p.returncode})
        if p.returncode: raise ValueError(label+' failed: '+p.stdout.decode(errors='replace')[-2000:])
        return p.stdout
    def keep(p):
        x=pin(p);hold[x['path']]=x;return x
    try:
        if runner.digest(NATIVE/'result.json')!=NATIVE_RESULT_SHA or runner.digest(NATIVE/'manifest.json')!=NATIVE_MANIFEST_SHA:
            raise ValueError('exact held native V5 producer required')
        native=runner.read_json(NATIVE/'result.json');manifest=runner.read_json(NATIVE/'manifest.json')
        if native['status']!='PASS' or native['native_execution'] or native['candidate']['bss_end']!='0xffffffff802656c8': raise ValueError('held source-only candidate scope differs')
        for p in (NATIVE/'result.json',NATIVE/'manifest.json'): keep(p)
        for version in ('v1','v2','v3','v4'):
            base=ROOT/('build/dead-screen-native-control-plan-20261001-'+version)
            for name in ('result.json','plan.json','runner.py'):keep(base/name)
        actual_failure={name:keep(ROOT/'build'/rel) for name,rel in {
            'result':'dead-screen-native-run-20261001-v4/result.json',
            'panic_result':'dead-screen-native-run-20261001-v4/panic/result.json',
            'raw104':'dead-screen-native-run-20261001-v4/panic/104-first-latch-state.bin',
            'analysis':'dead-screen-native-failure-analysis-20261001-v4/review.json'}.items()}
        if actual_failure['raw104']['sha256']!='b3057c89fdf5556b29ee9785656ce46b85e8796af7026b563cf6c40cc1a709a6' or actual_failure['result']['sha256']!='f69e348c91f7b1583337173e4d5c86a75da0644b2220e981dc6f3cc49e1c6fed':
            raise ValueError('held actual V4 failure changed')
        for group in ('tools','tool_runtime'):
            for item in manifest[group].values():runner.verify(item);keep(item['path'])
        for rel,item in manifest['sources'].items():
            runner.verify(item);keep(item['path'])
            frozen=NATIVE/'frozen'/rel
            if not frozen.exists() or runner.digest(frozen)!=item['sha256']: raise ValueError('frozen native source differs: '+rel)
            keep(frozen)
        for name in ('elf','bin'):runner.verify(native['candidate'][name]);keep(native['candidate'][name]['path'])
        if runner.digest(ROOT/'build/shizukudos/kernel64s/KERNEL64S.BIN')!=native['existing_default_binary']['sha256']:
            raise ValueError('ordinary default kernel changed')
        keep(ROOT/'build/shizukudos/kernel64s/KERNEL64S.BIN')
        inherited=['shizukudos/tests/run_k64_gop.py','shizukudos/tools/fatimg.py','shizukudos/tools/qemu.py',
                   'shizukudos/supervisor/loader/loader.c','shizukudos/supervisor/loader/bootini.c','shizukudos/supervisor/loader/bootini.h',
                   'shizukudos/kernel64/link.ld','shizukudos/kernel64/k64.h','platform/win98lab/lab.py','platform/win98lab/storage.py',
                   'build/native-boot-concurrency-guard-20261001T0650-v2/qemu_guard.py',
                   'build/native-boot-concurrency-guard-20261001T0650-v2/result.json']
        for rel in inherited:keep(ROOT/rel)
        # Close actual original loader/runtime provenance without changing either artifact.
        receipts={}
        for rel in ('build/shizukudos/supervisor/build-result.json','build/shizukudos/win64/build-result.json'):
            rp=ROOT/rel;receipts[rel]=keep(rp);j=runner.read_json(rp)
            for source,sha in j['sources_sha256'].items():
                path=ROOT/source
                if runner.digest(path)!=sha: raise ValueError('original loader/runtime source changed: '+source)
                keep(path)
        loader=ROOT/'build/shizukudos/supervisor/BOOTX64.EFI';archive=ROOT/'build/shizukudos/win64/WIN64.IMG'
        lj=runner.read_json(ROOT/'build/shizukudos/supervisor/build-result.json')
        for name,path in [('BOOTX64.EFI',loader),('WIN64.IMG (input)',archive)]:
            a=lj['artifacts'][name]
            if runner.digest(path)!=a['sha256'] or path.stat().st_size!=a['bytes']: raise ValueError('original loader/runtime artifact differs')
            keep(path)
        tools={}
        for name,p in {'qemu':'/usr/libexec/qemu-kvm','gcc':'/usr/bin/gcc','nm':'/usr/bin/nm','readelf':'/usr/bin/readelf','ldd':'/usr/bin/ldd',
                       'mcopy':'/usr/bin/mcopy','mformat':'/usr/bin/mformat','mmd':'/usr/bin/mmd','python3':sys.executable}.items():
            tools[name]=keep(Path(p).resolve());run([p,'--version'],name+'-version')
            if name=='ldd': continue
            r=subprocess.run(['/usr/bin/ldd',tools[name]['path']],capture_output=True,timeout=15)
            path=HERE/(name+'-ldd.log');path.write_bytes(r.stdout+r.stderr)
            logs.append({**pin(path),'exit_code':r.returncode,'command':['/usr/bin/ldd',tools[name]['path']]})
            if r.returncode: raise ValueError('actual host runtime discovery failed '+name)
            for lib in re.findall(rb'(/[\w./+_-]+)',r.stdout):
                q=Path(lib.decode())
                if q.is_file():toolruntime[str(q.resolve())]=keep(q.resolve())
        fwcode=keep('/usr/share/edk2/ovmf/OVMF_CODE.fd');fwvars=keep('/usr/share/edk2/ovmf/OVMF_VARS.fd')
        if fwcode['sha256']!='090b9b1872b725cd698d41d9d8987ad3d08ffbe6ea5dab28b973ad7f7b846498' or fwvars['sha256']!='5d2ac383371b408398accee7ec27c8c09ea5b74a0de0ceea6513388b15be5d1e': raise ValueError('unchanged original firmware pins differ')
        status=runner.host_status()
        if status['filesystem_free']<runner.FLOOR+runner.RUN_HEADROOM: raise ValueError('preparation disk floor/headroom unavailable')
        prepared=HERE/'prepared';prepared.mkdir()
        romdir=prepared/'roms';romdir.mkdir()
        rom_sources=[Path('/usr/share/seavgabios/vgabios-stdvga.bin'),Path('/usr/share/seabios/bios-256k.bin')]
        rom_sources+=sorted(Path('/usr/share/qemu-kvm').glob('*.bin'))
        for path in rom_sources:
            keep(path);d=romdir/path.name
            if d.exists(): raise ValueError('ambiguous private ROM basename')
            shutil.copyfile(path,d);keep(d)
        (prepared/'OVMF_CODE.fd').write_bytes(Path(fwcode['path']).read_bytes());firmware_code=keep(prepared/'OVMF_CODE.fd')
        for p in sorted(HERE.iterdir()):
            if p.suffix in ('.py','.c','.md'):
                sources[p.name]=keep(p)
                d=prepared/'source'/p.name;d.parent.mkdir(exist_ok=True);shutil.copyfile(p,d);keep(d)
        run(['/usr/bin/gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',ROOT/'shizukudos/dead_screen',HERE/'abi.c','-o',prepared/'abi'],'actual-held-header-abi')
        abi=json.loads(run([prepared/'abi'],'abi-observation'))
        (prepared/'abi.json').write_text(json.dumps(abi,indent=2)+'\n');keep(prepared/'abi.json');keep(prepared/'abi')
        run(['/usr/bin/gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',ROOT/'shizukudos/dead_screen',
             HERE/'reference.c',ROOT/'shizukudos/dead_screen/dead_screen.c',ROOT/'shizukudos/dead_screen/render.c','-o',prepared/'reference'],'held-core-transport-reference')
        reference=keep(prepared/'reference')
        compiler_headers={}
        for src in [HERE/'abi.c',HERE/'reference.c',ROOT/'shizukudos/dead_screen/dead_screen.c',ROOT/'shizukudos/dead_screen/render.c']:
            dep=run(['/usr/bin/gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',ROOT/'shizukudos/dead_screen','-M',src],src.stem+'-actual-header-dependencies')
            for token in dep.decode().replace('\\\n',' ').split(':',1)[1].split():
                p=Path(token)
                if p.exists():compiler_headers[str(p.resolve())]=keep(p)
        (prepared/'compiler-inputs.json').write_text(json.dumps(compiler_headers,indent=2)+'\n');keep(prepared/'compiler-inputs.json')
        symbols,ud,bss,panic_return,panic_call=elf_symbols(Path(native['candidate']['elf']['path']))
        if symbols['state']['bytes']!=abi['state_size'] or symbols['framebuffer']['bytes']!=abi['surface_size'] or bss-0xffffffff80000000>=0x300000: raise ValueError('actual linked ABI/BSS limit differs')
        run(['/usr/bin/readelf','-Ws',native['candidate']['elf']['path']],'held-linked-symbols')
        cases={}
        for number,case in enumerate(runner.CASES):
            work=prepared/case;work.mkdir()
            for path,name in [(loader,'BOOTX64.EFI'),(Path(native['candidate']['bin']['path']),'KERNEL64S.BIN'),(archive,'WIN64.IMG'),(Path(fwvars['path']),'OVMF_VARS.fd')]:
                shutil.copyfile(path,work/name)
            (work/'BOOT.INI').write_bytes(b'; private standalone own-kernel control; not Win98\r\nmode = kernel64\r\n')
            (work/'KERNEL64.INI').write_bytes(('cmdline = '+TOKENS[case]+'\r\n').encode())
            image=work/'disk.img';total=(64*1024**2//(16*63*512))*(16*63);start=63;sectors=total-start
            mbr=bytearray(512);mbr[510:512]=b'\x55\xaa';mbr[446:462]=b'\x80'+chs(start)+b'\x06'+chs(total-1)+struct.pack('<II',start,sectors)
            with image.open('xb') as f:f.truncate(total*512);f.write(mbr)
            spec=str(image)+'@@32256'
            run(['/usr/bin/mformat','-i',spec,'-h','16','-s','63','-T',sectors,'-H',start,'-v','SHZDEAD','-N',f'{0x53445330+number:08x}','::'],case+'-format')
            for name in ['EFI','EFI/BOOT','EFI/SHIZUKU','SHZDOS']:run(['/usr/bin/mmd','-i',spec,'::'+name],case+'-mkdir')
            mappings={'BOOTX64.EFI':'EFI/BOOT/BOOTX64.EFI','BOOT.INI':'EFI/SHIZUKU/BOOT.INI',
                      'KERNEL64S.BIN':'SHZDOS/KERNEL64S.BIN','WIN64.IMG':'SHZDOS/WIN64.IMG','KERNEL64.INI':'SHZDOS/KERNEL64.INI'}
            members={}
            for host,guest in mappings.items():
                p=work/host;os.utime(p,(EPOCH,EPOCH));run(['/usr/bin/mcopy','-m','-i',spec,p,'::'+guest],case+'-copy')
                r=subprocess.run(['/usr/bin/mcopy','-n','-i',spec,'::'+guest,'-'],capture_output=True,env=env,timeout=30)
                if r.returncode or r.stdout!=p.read_bytes(): raise ValueError('unbooted private FAT whole-member readback differs')
                members[guest]={'bytes':len(r.stdout),'sha256':hashlib.sha256(r.stdout).hexdigest()}
            cases[case]={'token':TOKENS[case],'disk.img':keep(image),'OVMF_VARS.fd':keep(work/'OVMF_VARS.fd'),'FAT_members':members}
            for name in mappings:keep(work/name)
        # Meaningful malformed/ownership/QMP controls only; never use real QEMU.
        run([sys.executable,HERE/'selftest.py',prepared/'abi.json',reference['path'],actual_failure['raw104']['path']],'runner-host-controls')
        lane=HERE/'dead-screen-lane.lock'
        with lane.open('xb') as f:f.write(b'Private standalone Dead Screen Kernel64 lane; no Win98 disk or external lock.\n')
        lane_stat=lane.stat();lane_identity={**pin(lane),'device':lane_stat.st_dev,'inode':lane_stat.st_ino,'owner_uid':lane_stat.st_uid}
        # The exclusively locked lane must not also be shared-locked as an input.
        if len(hold)+64>1024:raise ValueError('unchanged descriptor budget exceeded')
        for item in hold.values():runner.verify(item)
        report.update(status='PREPARED_HELD_NO_NATIVE_EXECUTION',scope=runner.SCOPE,utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            candidate_sha256=native['candidate']['bin']['sha256'],candidate_elf=native['candidate']['elf'],native_producer=pin(NATIVE/'result.json'),
            candidate_bss_end=hex(bss),kernel_virtual_start=0xffffffff80100000,kernel_virtual_end=bss,control_ud_ip=ud,
            control_panic_return_ip=panic_return,control_panic_call=panic_call,actual_V4_failure=actual_failure,
            symbols=symbols,abi=abi,tools=tools,tool_runtime=toolruntime,compiler_inputs=compiler_headers,original_producers=receipts,
            runner=pin(HERE/'runner.py'),reference=reference,firmware_code=firmware_code,rom_directory=str(romdir),
            cases=cases,hold_files=list(hold.values()),sources=sources,logs=logs,
            actual_preparation_host_status=status,actual_final_free_bytes=shutil.disk_usage(HERE).free,
            parent_review_and_external_release_required=True,own_native_locks=[str(p) for p in runner.LOCKS],native_lane_identity=lane_identity,
            timeout_seconds_each=180,maximum_sequential_children=3,maximum_screenshot_attempts_per_control=120,
            unchanged_defaults=True,trace_scope='actual first owned Kernel64 record only; no unwind/Win98/VMM acceptance; live CPU differs from saved fault')
        planpath.write_text(json.dumps(report,indent=2)+'\n')
    except Exception as exc:report['failure']=repr(exc)
    (HERE/'result.json').write_text(json.dumps({'status':report['status'],'native_started':False,'app_success':False,
        'plan':pin(planpath) if planpath.exists() else None,'failure':report.get('failure'),'logs':logs},indent=2)+'\n')
    print(json.dumps({'status':report['status'],'result':pin(HERE/'result.json'),'plan':pin(planpath) if planpath.exists() else None,'failure':report.get('failure')}))
    return 0 if report['status']=='PREPARED_HELD_NO_NATIVE_EXECUTION' else 1

if __name__=='__main__':raise SystemExit(main())
