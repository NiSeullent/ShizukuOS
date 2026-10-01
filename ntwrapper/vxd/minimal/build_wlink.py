#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a separate control-only fixture with the actual Open Watcom LE writer."""
from pathlib import Path
import hashlib
import json
import subprocess
import sys
from validate_watcom import decode

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
sys.path.insert(0,str(ROOT/'shizukudos/tools'))
import shzlib
FIXLINK_COMMIT='a2a74447daea3197255f3a4fb5cfb0c5a453dcc8'

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    env=shzlib.ow_env()
    tools=ROOT/'build/fixlink-reference'
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=tools,text=True).strip()!=FIXLINK_COMMIT:
        raise ValueError('fixlink source is not the pinned MIT commit')
    if subprocess.check_output(['git','status','--porcelain'],cwd=tools):
        raise ValueError('fixlink source cache changed')
    sources=[Path(__file__),HERE/'control_wlink.asm',HERE/'validate_watcom.py',tools/'fixlink.c']
    before={str(p):digest(p) for p in sources}
    out=HERE/'build/watcom-le';out.mkdir(parents=True,exist_ok=True)
    response=out/'driver.lnk'
    response.write_text('system win_vxd dynamic\noption map=driver.map\noption nodefaultlibs\n'
        'name NTWMIN9X.VXD\nfile control.obj\nsegment _TEXT PRELOAD NONDISCARDABLE\nexport VXD_DDB.1\n')
    commands=[['nasm','-f','obj','-o','control.obj',str(HERE/'control_wlink.asm')],
        ['wlink','@driver.lnk'],['gcc','-std=c99','-include','strings.h','-Dstricmp=strcasecmp',
         str(tools/'fixlink.c'),'-o','fixlink'],['./fixlink','-vxd32','NTWMIN9X.VXD']]
    logs=[]
    before_fix=None
    for i,command in enumerate(commands):
        result=subprocess.run(command,cwd=out,env=env,text=True,capture_output=True,check=True)
        logs.append(dict(command=command,stdout=result.stdout,stderr=result.stderr,exit=result.returncode))
        if i==1: before_fix=(out/'NTWMIN9X.VXD').read_bytes();(out/'before-fixlink.vxd').write_bytes(before_fix)
    image=(out/'NTWMIN9X.VXD').read_bytes();decoded=decode(image)
    # fixlink must change only the object's base and executable flag.
    changes=[i for i,(a,b) in enumerate(zip(before_fix,image)) if a!=b]
    if len(before_fix)!=len(image) or not changes or any(i not in range(0x148,0x150) for i in changes):
        raise ValueError('unexpected fixlink changes to the native toolchain output')
    if before!={str(p):digest(p) for p in sources}: raise ValueError('build source changed')
    fixture={'path':'build/watcom-le/NTWMIN9X.VXD','bytes':len(image),
        'sha256':digest(out/'NTWMIN9X.VXD'),'guest_loaded':False,'toolchain':'Open Watcom wlink + MIT fixlink',
        'ddb_first':True}
    receipt={'schema':1,'scope':'isolated toolchain control-only LE/DDB fixture',
        'files':{'watcom-le':fixture},'sources_sha256':before,'commands':logs,
        'fixlink_commit':FIXLINK_COMMIT,'fixlink_changes':changes,'decoded':decoded,
        'open_watcom_snapshot':shzlib.open_watcom_snapshot(),
        'tools':{name:digest(Path(env['WATCOM'])/'binl64'/name) for name in ('wlink',)},
        'native_loader_test':'not_run','production_driver_modified':False}
    (out/'build-result.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(fixture,indent=2))

if __name__=='__main__':main()
