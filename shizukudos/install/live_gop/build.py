#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the Win16 class caller using exact private SDK and pinned Watcom bytes.

Output includes private Microsoft headers and MUST remain outside the repository.
The caller refuses installation unless the real current-boot VxD probe passes.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import struct
import subprocess
import tarfile

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[2]
SNAPSHOT='4fdc24c04a02e31ffedae1690fc2c6d53fcb01464f92692adf6b17a7e890af3f'
SDK={'thunks.h':'eb53c8f1d8a1055feba0424cac7f4c7b1e828c8b1fdf461b231ec87e65552ff9',
     'windows.h':'2578d377949f1b46909ee300572acb4c0f9e5010032a4bb215a93688844d9b9a',
     'setupx.h':'aef84421a79596dcf6c7aaa90af03466e73a1a36bf83ae953138a9252421e815',
     'prsht.h':'e829f4c657e9ad3ec259b8ea8786a22064b1f1a9976ec6b090cc01d7ee4418a5'}
def digest(raw):return hashlib.sha256(raw).hexdigest()
def write(path,raw,executable=False):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    with path.open('xb') as file:file.write(raw)
    path.chmod(0o700 if executable else 0o600)
    if path.read_bytes()!=raw:raise ValueError('captured input readback differs')
def build(archive,watcom,sdk,out):
    archive,watcom,sdk,out=[p.resolve(strict=p!=out) for p in (archive,watcom,sdk,out)]
    if out.exists() or not out.parent.is_dir() or out==REPO or REPO in out.parents:
        raise ValueError('fresh PRIVATE output outside public source required')
    raw=archive.read_bytes()
    if digest(raw)!=SNAPSHOT:raise ValueError('exact historical Watcom snapshot required')
    headers={n:(sdk/n).read_bytes() for n in SDK}
    if any(digest(headers[n])!=SDK[n] for n in SDK):raise ValueError('original private Win98 SDK header identity differs')
    inputs={str(p.relative_to(REPO)):p.read_bytes() for p in
            [HERE/'gopinst.c',HERE/'native_gop_gate.c',HERE/'native_gop_gate.h',
             REPO/'drivers/shizuku_gop/gop_contract.h',REPO/'drivers/shizuku_gop/gop_live_contract.h',
             REPO/'shizukudos/accounts/sha256.c',REPO/'shizukudos/accounts/sha256.h',Path(__file__).resolve()]}
    captured={}
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:xz') as tar:
        for member in tar:
            name=PurePosixPath(member.name)
            if member.isdir():continue
            if '..' in name.parts or name.is_absolute():raise ValueError('unsafe compiler archive path')
            key=str(name)
            selected=key.startswith(('h/','lib286/')) or key in ('binl64/wcc','binl64/wlink','binl64/wlink.lnk')
            if not selected:continue
            if not member.isfile() or member.size>64<<20 or key in captured:raise ValueError('invalid compiler closure member')
            data=tar.extractfile(member).read()
            if (watcom/key).read_bytes()!=data:raise ValueError('cached compiler closure differs from pinned snapshot: '+key)
            captured[key]=data
    required={'binl64/wcc','binl64/wlink','binl64/wlink.lnk','lib286/win/windows.lib','lib286/win/clibl.lib'}
    if not required.issubset(captured):raise ValueError('incomplete compiler/link closure')
    out.mkdir(mode=0o700)
    for name,data in captured.items():write(out/'ow'/name,data,name in ('binl64/wcc','binl64/wlink'))
    for name,data in headers.items():write(out/'sdk'/name,data)
    for name,data in inputs.items():write(out/'source'/name,data)
    ow=out/'ow';env=dict(os.environ,WATCOM=str(ow),INCLUDE=str(out/'sdk')+':'+str(ow/'h'))
    commands=[]
    for source in ('shizukudos/install/live_gop/gopinst.c','shizukudos/install/live_gop/native_gop_gate.c','shizukudos/accounts/sha256.c'):
        cmd=[str(ow/'binl64/wcc'),'-bt=windows','-ml','-zq',
             '-i='+str(out/'source/shizukudos/accounts'),'-i='+str(out/'source/drivers/shizuku_gop'),
             '-fo='+str(out/(Path(source).stem+'.obj')),str(out/'source'/source)]
        subprocess.run(cmd,cwd=out,env=env,check=True);commands.append(cmd)
    cmd=[str(ow/'binl64/wlink'),'@'+str(ow/'binl64/wlink.lnk'),'system','windows','option','quiet',
         'name',str(out/'GOPINST.EXE'),'file',','.join(str(out/(n+'.obj')) for n in ('gopinst','native_gop_gate','sha256')),
         'option','map='+str(out/'GOPINST.MAP')]
    subprocess.run(cmd,cwd=out,env=env,check=True);commands.append(cmd)
    exe=(out/'GOPINST.EXE').read_bytes(); offset=struct.unpack_from('<I',exe,60)[0]
    if exe[:2]!=b'MZ' or exe[offset:offset+2]!=b'NE':raise ValueError('real Win16 NE executable required')
    receipt={'schema':'shizukuos.private-win16-gop-installer-build.v1','status':'HOST_COMPILE_LINK_PASS_NOT_EXECUTED',
        'Watcom_snapshot_sha256':SNAPSHOT,'sdk_header_sha256':SDK,
        'captured_compiler_closure':{n:digest(b) for n,b in captured.items()},
        'captured_public_sources':{n:digest(b) for n,b in inputs.items()},'commands':commands,
        'artifact':{'path':str(out/'GOPINST.EXE'),'bytes':len(exe),'sha256':digest(exe)},
        'VM_executed':False,'default_GOP_registered':False,'GPU_active':False,'cold_boot_verified':False,
        'native_current_boot_probe':'REAL_READONLY_QUERY_REQUIRED_NOT_GUEST_EXECUTED',
        'Supervisor_epoch_in_descriptor_ABI':False,
        'guardian_epoch_query_opcode':'0x4f11','guardian_epoch_query_bytes':160,'guardian_epoch_HCALL':14,
        'independent_current_guardian_nonce_required':r'C:\SHZGOP\GPEPOCH.NON',
        'Supervisor_epoch_verified':False,
        'private_SDK_headers_in_output':True,'public_artifact':False}
    write(out/'build-result.json',(json.dumps(receipt,indent=2)+'\n').encode())
    return receipt
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--watcom-archive',type=Path,required=True);p.add_argument('--watcom-root',type=Path,required=True)
    p.add_argument('--private-sdk',type=Path,required=True);p.add_argument('--private-out',type=Path,required=True)
    a=p.parse_args();r=build(a.watcom_archive,a.watcom_root,a.private_sdk,a.private_out)
    print(json.dumps({'status':r['status'],'artifact':r['artifact'],'default_GOP_registered':False}))
