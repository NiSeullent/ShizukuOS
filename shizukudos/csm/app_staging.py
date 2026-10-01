#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded fresh NPPLAB/VLCLAB staging; no installation or execution."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

HASH=re.compile(r'[0-9a-f]{64}')
COMPONENT=re.compile(r'[A-Za-z0-9_.+\-]{1,64}')
RESERVED={'CON','PRN','AUX','NUL'}|{f'{p}{n}' for p in ('COM','LPT') for n in range(1,10)}
PREFIXES=frozenset(('NPPLAB','VLCLAB'))

def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()

def unique_object(pairs):
    result={}
    for key,value in pairs:
        if key in result:raise ValueError('Duplicate JSON object key: '+key)
        result[key]=value
    return result

def staging_prefix(value):
    if not isinstance(value,str) or value not in PREFIXES:raise ValueError('Only NPPLAB or VLCLAB staging prefixes allowed')
    return value

def guest_path(value,prefix='NPPLAB'):
    prefix=staging_prefix(prefix)
    if not isinstance(value,str) or len(value)>240:raise ValueError('Guest path type/length')
    parts=value.split('\\')
    if not 3<=len(parts)<=8 or parts[:2]!=['C:',prefix]:raise ValueError('Only canonical files under the selected staging prefix allowed')
    for part in parts[2:]:
        if not COMPONENT.fullmatch(part) or part in ('.','..') or part.endswith('.') or part.split('.')[0].upper() in RESERVED:
            raise ValueError('Invalid/reserved guest path component')
    return value

def frozen_file(item,field,roots):
    if not isinstance(item,dict) or not isinstance(item.get(field),str) or not HASH.fullmatch(str(item.get('sha256',''))):raise ValueError('Frozen source declaration')
    path=Path(item[field]).resolve(strict=True)
    if not path.is_file() or not any(path.is_relative_to(root) for root in roots):raise ValueError('Frozen source escaped allowed root')
    if sha(path)!=item['sha256']:raise ValueError('Frozen source hash mismatch')
    return path

def validate(manifest,expected_sha,repo_root):
    root=Path(repo_root).resolve(strict=True);manifest=Path(manifest).resolve(strict=True)
    allowed=(root/'build',root/'benchmarks')
    if not HASH.fullmatch(str(expected_sha)) or not any(manifest.is_relative_to(p) for p in allowed) or manifest.stat().st_size>256*1024 or sha(manifest)!=expected_sha:raise ValueError('Manifest location/size/hash')
    data=json.loads(manifest.read_text(encoding='utf-8'),object_pairs_hook=unique_object)
    if not isinstance(data,dict) or type(data.get('schema')) is not int or data.get('schema')!=1 or data.get('kind')!='isolated-native-application-inputs':raise ValueError('Application manifest schema/kind')
    prefix=staging_prefix(data.get('staging_prefix','NPPLAB'))
    inputs=data.get('inputs');outputs=data.get('outputs',[]);receipts=data.get('source_receipts')
    if not isinstance(inputs,list) or not 1<=len(inputs)<=512 or not isinstance(outputs,list) or len(outputs)>16 or not isinstance(receipts,list) or not 1<=len(receipts)<=64:raise ValueError('Bounded input/output/receipt counts')
    immutable={str(manifest):expected_sha,str(Path(__file__).resolve()):sha(Path(__file__).resolve())};total=0;selected=[];paths={}
    for item in inputs:
        if not isinstance(item,dict):raise ValueError('Input declaration')
        guest=guest_path(item.get('guest'),prefix);key=guest.upper()
        if key in paths:raise ValueError('Case-colliding guest files')
        size=item.get('bytes')
        if type(size) is not int or not 0<size<=32*1024**2:raise ValueError('Input file size bound')
        total+=size
        if total>128*1024**2:raise ValueError('Total input size bound')
        path=frozen_file(item,'source',(manifest.parent,))
        if path.stat().st_size!=size:raise ValueError('Input source size mismatch')
        paths[key]='input';immutable[str(path)]=item['sha256'];selected.append(dict(item,source=str(path),guest=guest))
    output_paths=[];limits={}
    for output in outputs:
        guest=guest_path(output if isinstance(output,str) else output.get('guest') if isinstance(output,dict) else None,prefix)
        size=4*1024**2 if isinstance(output,str) else output.get('max_bytes')
        if type(size) is not int or not 0<size<=4*1024**2:raise ValueError('Output size bound')
        key=guest.upper()
        if key in paths:raise ValueError('Output collision with input or other output')
        paths[key]='output';output_paths.append(guest);limits[guest]=size
    for key in paths:
        parts=key.split('\\')
        if any('\\'.join(parts[:n]) in paths for n in range(3,len(parts))):raise ValueError('File/directory prefix collision')
    for receipt in receipts:
        path=frozen_file(receipt,'path',allowed);immutable[str(path)]=receipt['sha256']
    archive=data.get('upstream_archive');path=frozen_file(archive,'path',allowed);immutable[str(path)]=archive['sha256']
    return {'repo_root':str(root),'manifest':str(manifest),'manifest_sha256':expected_sha,'staging_prefix':prefix,'inputs':selected,'outputs':output_paths,
            'output_limits':limits,'total_input_bytes':total,'immutable_sources':immutable,
            'scope':f'fresh {prefix} file staging only; no guest installer, registry, system files or executable launch',
            'application_launched':False,'native_application_success':'not-established'}

def boot_sectors(disk,start):
    with disk.open('rb') as stream:
        mbr=stream.read(512);stream.seek(start*512);boot=stream.read(512)
    if len(mbr)!=512 or len(boot)!=512:raise ValueError('Truncated disk boot sectors')
    return mbr,boot

def directory_absent(spec,prefix='NPPLAB'):
    prefix=staging_prefix(prefix)
    root=subprocess.run(['mdir','-i',spec,'::'],capture_output=True,text=True,timeout=30)
    if root.returncode:raise ValueError('Private FAT root unreadable')
    probe=subprocess.run(['mdir','-i',spec,'::'+prefix],capture_output=True,text=True,timeout=30)
    if not probe.returncode:raise ValueError(prefix+' already present')
    if 'not found' not in (probe.stdout+probe.stderr).lower():raise ValueError(prefix+' absence not established')
    return {'guest_root':'C:\\'+prefix,'status':'absent'}

def stage(disk,run_dir,partition,plan,run_command):
    # Complete every manifest/source check before touching the disk or outputs.
    checked=validate(plan['manifest'],plan['manifest_sha256'],plan['repo_root'])
    if checked!=plan:raise ValueError('Validated application plan changed before stage')
    plan=checked;root=Path(plan['repo_root']).resolve(strict=True)
    run=Path(run_dir).resolve(strict=True);disk=Path(disk).resolve(strict=True);owned=root/'build/shizukudos/csm'
    if run.parent!=owned or not re.fullmatch(r'run-[A-Za-z0-9_.\-]+',run.name) or disk!=run/'windows-uefi.raw' or not disk.is_file() or disk.stat().st_nlink!=1:raise ValueError('Only exact new owned disposable run disk allowed')
    if any((run/name).exists() for name in ('result.json','qemu.stderr','app-stage-readback','app-stage-result.json')):raise ValueError('Active/completed/staged run rejected')
    start=partition.get('start_lba')
    if type(start) is not int or start<=0 or start>disk.stat().st_size//512-1:raise ValueError('Partition start bound')
    before=boot_sectors(disk,start)
    if any(hashlib.sha256(raw).hexdigest()!=partition.get(field) for raw,field in zip(before,('mbr_sha256','boot_sector_sha256'))):raise ValueError('Frozen partition boot hash mismatch')
    prefix=plan['staging_prefix'];spec=f'{disk}@@{start*512}';directory_absent(spec,prefix)
    # No overwrite option is used; a partial failed stage must be discarded.
    readback=run/'app-stage-readback';readback.mkdir();directories={'::'+prefix:'::'+prefix}
    for item in plan['inputs']:
        parts=item['guest'].split('\\')[1:-1]
        for n in range(1,len(parts)+1):
            directory='::'+'/'.join(parts[:n]);directories.setdefault(directory.upper(),directory)
    for directory in sorted(directories.values(),key=lambda p:(p.count('/'),p.upper())):run_command(['mmd','-i',spec,directory])
    copied=[]
    for n,item in enumerate(plan['inputs']):
        target='::'+item['guest'][3:].replace('\\','/');local=readback/f'{n:03d}-{item["guest"].split(chr(92))[-1]}'
        run_command(['mcopy','-i',spec,item['source'],target]);run_command(['mcopy','-i',spec,target,str(local)])
        if not local.is_file() or local.stat().st_size!=item['bytes'] or sha(local)!=item['sha256']:raise ValueError('Exact guest LFN/source readback mismatch')
        copied.append(dict(item,readback=str(local),readback_sha256=sha(local)))
    if boot_sectors(disk,start)!=before:raise ValueError('Application staging changed legacy boot sectors')
    for path,digest in plan['immutable_sources'].items():
        if sha(Path(path))!=digest:raise ValueError('Immutable source changed during stage')
    plan.update(inputs=copied,status='STAGED-READBACK-VERIFIED',output_baseline=f'fresh {prefix} tree absent before stage',
                boot_sectors_unchanged=True,disk=str(disk),partition_start_lba=start)
    (run/'app-stage-result.json').write_text(json.dumps(plan,indent=2)+'\n')
    return plan

def main():
    parser=argparse.ArgumentParser(description='Read-only frozen application manifest validation')
    parser.add_argument('--manifest',type=Path,required=True);parser.add_argument('--sha256',required=True);parser.add_argument('--repo-root',type=Path,required=True)
    args=parser.parse_args();plan=validate(args.manifest,args.sha256,args.repo_root)
    print(json.dumps({'status':'VALIDATED-ONLY','inputs':len(plan['inputs']),'bytes':plan['total_input_bytes'],'guest_writes':False}))

if __name__=='__main__':main()
