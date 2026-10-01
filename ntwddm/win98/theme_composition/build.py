#!/usr/bin/env python3
"""Build a disjoint composition probe with exact frozen provider/observer bytes."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
OWN=['composition.h','composition.c','winmock.h','composition_test.c','foreground.h','foreground_test.c','probe.c','verify.py','test_verify.py','test_build.py','build.py','README.md']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(ok,msg):
    if not ok:raise RuntimeError(msg)

def validate_static_receipt(receipt):
    """Prelaunch static contract; supplies no process exit or guest evidence."""
    require(isinstance(receipt,dict),'Receipt must be an object')
    require(type(receipt.get('schema')) is int and receipt['schema']==1,'Receipt schema')
    require(receipt.get('status')=='PASS','Receipt static build gates must pass')
    require(receipt.get('native_win98')=='not_tested','Receipt must describe static evidence only')
    require(receipt.get('native_visibility_verified',False) is False,'Static receipt cannot establish native visibility')
    artifacts=receipt.get('artifacts');require(isinstance(artifacts,dict),'Artifact mapping')
    for name in ['M98THEME.DLL','NTTHGUI.EXE','NTTHRUN.EXE']:
        entry=artifacts.get(name);require(isinstance(entry,dict),'Missing artifact '+name)
        gate=entry.get('pe98_gate');require(isinstance(gate,dict) and gate.get('status')=='PASS','Native gate '+name)
        require(gate.get('runtime_execution_verified') is False,'PE gate must be static '+name)
        path=entry.get('path');require(isinstance(path,str) and Path(path).is_absolute(),'Absolute artifact path '+name)
        digest=entry.get('sha256');require(isinstance(digest,str) and re.fullmatch('[0-9a-f]{64}',digest),'Artifact digest '+name)
        size=entry.get('bytes');require(type(size) is int and size>0,'Artifact size '+name)
        file=Path(path);require(file.is_file() and file.stat().st_size==size and sha(file)==digest,'Frozen artifact bytes '+name)

def main():
    ap=argparse.ArgumentParser(allow_abbrev=False);ap.add_argument('--frozen-theme-stage',type=Path,required=True);a=ap.parse_args()
    old=a.frozen_theme_stage.resolve(strict=True);receipt=json.loads((old/'build-result.json').read_text())
    validate_static_receipt(receipt)
    require(receipt['status']=='PASS' and Path(receipt['source_root'])==ROOT,'Frozen passing theme source required')
    for n,h in receipt['source_hashes'].items():require(sha(ROOT/n)==h,'Old theme source differs: '+n)
    require(sha(old/'NTTHGUI.EXE')==receipt['artifacts']['NTTHGUI.EXE']['sha256'],'Frozen lineage probe bytes differ')
    out=HERE/'build'/(datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ-')+secrets.token_hex(4));out.mkdir(parents=True)
    sources=dict(receipt['source_hashes']);sources.update({str((HERE/n).relative_to(ROOT)):sha(HERE/n) for n in OWN})
    commands=[]
    def run(argv,env=None):
        p=subprocess.run([str(x) for x in argv],cwd=ROOT,capture_output=True,text=True,timeout=120,env=env)
        commands.append({'argv':[str(x) for x in argv],'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr})
        (out/'commands.json').write_text(json.dumps(commands,indent=2)+'\n');require(p.returncode==0,p.stdout+p.stderr);return p.stdout.strip()
    compilers={}
    for n in ['clang','i686-w64-mingw32-gcc']:
        p=Path(shutil.which(n)).resolve(strict=True);compilers[n]={'path':str(p),'sha256':sha(p),'version':run([p,'--version']).splitlines()[0]}
    host={}
    for kind,flags in [('host',[]),('sanitizer',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        exe=out/('composition-'+kind)
        run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-DCOMPOSITION_HOST_TEST',*flags,HERE/'composition.c',HERE/'composition_test.c','-o',exe])
        env=dict(os.environ,ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',UBSAN_OPTIONS='halt_on_error=1');host[kind]=run([exe],env)
        require(re.fullmatch(r'PASS: [1-9][0-9]* composition pixel, text-mask, transfer and ownership assertions',host[kind]),'Unrecognized assertions')
        foreground=out/('foreground-'+kind)
        run(['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror',*flags,HERE/'foreground_test.c','-o',foreground])
        host['foreground_'+kind]=run([foreground],env)
        require(re.fullmatch(r'PASS: [1-9][0-9]* foreground ownership, refusal and independent handle assertions',host['foreground_'+kind]),'Unrecognized foreground assertions')
    run(['python3','-B','-m','unittest','discover','-s',HERE,'-p','test_*.py','-v'])
    host['python_tests']={'returncode':commands[-1]['returncode'],'stdout':commands[-1]['stdout'],'stderr':commands[-1]['stderr']}
    native=['i686-w64-mingw32-gcc','-std=c11','-Os','-Wall','-Wextra','-Werror','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-msoft-float','-fno-builtin','-fno-stack-protector','-mno-stack-arg-probe','-nostdlib','-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10','-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware','-Wl,--no-insert-timestamp','-Wl,--entry,_mainCRTStartup']
    gui=out/'NTTHGUI.EXE';run(native+[HERE/'probe.c',HERE/'composition.c',ROOT/'platform/freestanding/memory.c','-lkernel32','-luser32','-lgdi32','-o',gui])
    spec=importlib.util.spec_from_file_location('composition_existing_gate',ROOT/'ntwddm/win98/theme_probe/build.py');gate=importlib.util.module_from_spec(spec);spec.loader.exec_module(gate)
    pe_gate=gate.gate(gui,False)
    asm=run(['i686-w64-mingw32-objdump','-d',gui]);(out/'native-disassembly.txt').write_text(asm+'\n')
    require(re.search(r'\b(?:xmm\d+|ymm\d+|zmm\d+|mm[0-7]|cmov[a-z]+|fcomi[a-z]*|syscall|sysenter)\b',asm,re.I) is None,'Non-i486 instruction in diagnostic')
    artifacts=dict(receipt['artifacts']);artifacts['NTTHGUI.EXE']={'path':str(gui),'sha256':sha(gui),'bytes':gui.stat().st_size,'pe98_gate':pe_gate}
    for n in ['M98THEME.DLL','NTTHRUN.EXE']:
        require(sha(old/n)==receipt['artifacts'][n]['sha256'],'Frozen provider/observer differs');shutil.copyfile(old/n,out/n)
        artifacts[n]={**receipt['artifacts'][n],'path':str(out/n)}
    lineage={'original_probe_source_sha256':sha(ROOT/'ntwddm/win98/theme_probe/probe.c'),'original_probe_binary_sha256':sha(old/'NTTHGUI.EXE'),'frozen_original_receipt':str(old/'build-result.json'),'frozen_original_receipt_sha256':sha(old/'build-result.json'),'provider_and_observer':'exact frozen copies; no source/build change'}
    result={**receipt,'source_hashes':sources,'artifacts':artifacts,'run_dir':str(out),'composition_lineage':lineage,'composition_host_results':host,'composition_compilers':compilers,'native_win98':'not_tested','native_visibility_verified':False,'composition_only':True,'i486_disassembly_gate':'PASS','static_receipt_gate':'PASS'}
    require(all(sha(ROOT/n)==h for n,h in sources.items()),'Source changed during composition build')
    validate_static_receipt(result)
    (out/'build-result.json').write_text(json.dumps(result,indent=2)+'\n')
    (out/'THNONCE.TXT').write_text(secrets.token_hex(16))
    manifest={'schema':1,'kind':'isolated-guest-file-inputs','inputs':[{'source':str(out/n),'guest':'C:'+chr(92)+'VXDLAB'+chr(92)+n,'bytes':(out/n).stat().st_size,'sha256':sha(out/n)} for n in ['M98THEME.DLL','NTTHGUI.EXE','NTTHRUN.EXE','THNONCE.TXT']],'outputs':[],'native_execution':'NOT-PERFORMED; startup preparation will choose a fresh runtime nonce'}
    (out/'guest-files.json').write_text(json.dumps(manifest,indent=2)+'\n')
    for p in out.iterdir():p.chmod(0o444)
    out.chmod(0o555)
    print(json.dumps({'status':'PASS-BUILD-GATES','frozen_theme_stage':str(out),'receipt':str(out/'build-result.json'),'receipt_sha256':sha(out/'build-result.json'),'gui_sha256':sha(gui),'host':host,'native_execution':'NOT-PERFORMED'},indent=2))
if __name__=='__main__':main()
