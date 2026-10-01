#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run actual portable C decoder/model/hash/PE controls with sanitizers."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();out=args.out.resolve()
    if out.exists():ap.error('use fresh host output')
    cc=shutil.which('clang')
    if not cc:ap.error('existing Clang needed')
    inputs={str((HERE/name).relative_to(ROOT)):sha(HERE/name) for name in ('environment.h','environment.c','host_test.c','test.py')}
    npp=ROOT/'build/app-prerequisites-20260930/latest-npp-inputs/app/NPP.EXE';nppsha=sha(npp)
    if nppsha!='986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5':ap.error('untouched official input mismatch')
    out.mkdir(parents=True);exe=out/'host-test'
    command=[cc,'--no-default-config','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-fno-omit-frame-pointer','-I',str(HERE),str(HERE/'environment.c'),str(HERE/'host_test.c'),'-o',str(exe)]
    compile_result=subprocess.run(command,capture_output=True,text=True,timeout=120);(out/'compile.log').write_text(compile_result.stdout+compile_result.stderr);compile_result.check_returncode()
    run=subprocess.run([str(exe),str(npp)],capture_output=True,text=True,timeout=120);(out/'host.log').write_text(run.stdout+run.stderr);run.check_returncode()
    if any(sha(ROOT/name)!=digest for name,digest in inputs.items()) or sha(npp)!=nppsha:raise ValueError('source/input changed during checks')
    receipt={'status':'PASS','native_executed':False,'sources':inputs,'compiler':{'path':cc,'sha256':sha(Path(cc))},'command':command,'sanitizers':['address','undefined'],'actual_c_result':run.stdout,'official_npp':{'path':str(npp),'bytes':npp.stat().st_size,'sha256':nppsha},'scope':'bounded C field decoder/model/negative gates; no native DR or application acceptance'}
    (out/'host-result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'status':'PASS','receipt':str(out/'host-result.json'),'checks':run.stdout}))
if __name__=='__main__':main()
