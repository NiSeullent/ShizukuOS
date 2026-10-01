#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual tiny FAT LFN readback plus rejection-before-mutation controls."""
import copy
import argparse
import hashlib
import importlib.util
import json
import subprocess
import struct
import shutil
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2];HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('app_staging',HERE/'app_staging.py');helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
run=args.out.resolve()
if run.exists():raise SystemExit('Use a fresh test output; existing receipt preserved')
run.mkdir(parents=True);inputs=run/'fixtures';inputs.mkdir();disk=run/'windows-uefi.raw'
with disk.open('wb') as stream:stream.truncate(2*1024*1024)
with disk.open('r+b') as stream:stream.seek(510);stream.write(b'\x55\xaa')
# Deterministic standard 1.44MiB FAT12 volume in an owned raw fixture. This is
# data construction only; the malformed mformat attempt remains preserved.
boot=bytearray(512);boot[:11]=b'\xeb\x3c\x90SHZTEST '
struct.pack_into('<HBHBHHBHHHII',boot,11,512,1,1,2,224,2880,0xf0,9,18,2,1,0)
boot[510:]=b'\x55\xaa'
with disk.open('r+b') as stream:
    stream.seek(512);stream.write(boot)
    for sector in (2,11):stream.seek(sector*512);stream.write(b'\xf0\xff\xff')
before=helper.boot_sectors(disk,1)
partition={'start_lba':1,'mbr_sha256':hashlib.sha256(before[0]).hexdigest(),'boot_sector_sha256':hashlib.sha256(before[1]).hexdigest()}
receipt=inputs/'source.json';receipt.write_text('{"scope":"host-only tiny FAT fixture"}\n')
archive=inputs/'source.zip';archive.write_bytes(b'own-host-fixture-no-native-evidence')
source=inputs/'sample.dat';source.write_bytes(bytes(range(256))*3)
base={'schema':1,'kind':'isolated-native-application-inputs','inputs':[
 {'source':str(source),'guest':'C:\\NPPLAB\\APP\\long.model.filename.xml','bytes':source.stat().st_size,'sha256':helper.sha(source)}],
 'outputs':['C:\\NPPLAB\\APP\\Fresh.output.log'],'source_receipts':[{'path':str(receipt),'sha256':helper.sha(receipt)}],
 'upstream_archive':{'path':str(archive),'sha256':helper.sha(archive)}}
manifest=inputs/'manifest.json';records=[];original=helper.sha(disk)
def select(data):manifest.write_text(json.dumps(data));return helper.sha(manifest)
def reject(label,data=None,raw=None):
    if raw is None:digest=select(data)
    else:manifest.write_text(raw);digest=helper.sha(manifest)
    calls=[]
    try:
        plan=helper.validate(manifest,digest,ROOT)
        helper.stage(disk,run,partition,plan,lambda argv:calls.append(argv))
    except (ValueError,FileNotFoundError):pass
    else:raise AssertionError(label)
    assert not calls and helper.sha(disk)==original and not (run/'app-stage-readback').exists(),label
    records.append({'case':label,'rejected_before_mutation':True})
for guest in ['C:\\WINDOWS\\SYSTEM.INI','C:\\NPPLAB\\..\\escape.txt','C:\\NPPLAB\\APP\\CON.txt','C:\\NPPLAB\\APP\\LPT1','C:\\NPPLAB\\APP\\trailing.','C:\\NPPLAB\\APP\\sp ace.txt','C:\\NPPLAB\\APP\\ümlaut.txt','C:\\\\NPPLAB\\APP\\file.txt','C:\\NPPLAB\\a\\b\\c\\d\\e\\f\\file.txt','C:\\NPPLAB\\'+('x'*65)]:
    data=copy.deepcopy(base);data['inputs'][0]['guest']=guest;reject('guest '+guest,data)
for field,value in [('schema',True),('inputs',[]),('outputs',['C:\\NPPLAB\\APP\\long.model.filename.xml']),('outputs',['C:\\NPPLAB\\APP\\F.log','C:\\NPPLAB\\APP\\f.LOG'])]:
    data=copy.deepcopy(base);data[field]=value;reject('manifest '+field+str(value),data)
for key,value in [('bytes',True),('bytes',32*1024**2+1),('bytes',1),('sha256','0'*64)]:
    data=copy.deepcopy(base);data['inputs'][0][key]=value;reject('input '+key+str(value),data)
data=copy.deepcopy(base);data['inputs'].append(dict(data['inputs'][0],guest='C:\\NPPLAB\\APP\\LONG.MODEL.FILENAME.XML'));reject('case duplicate inputs',data)
data=copy.deepcopy(base);data['inputs'].append(dict(data['inputs'][0],guest='C:\\NPPLAB\\APP\\long.model.filename.xml\\child.txt'));reject('file directory prefix collision',data)
outside=run/'outside.dat';outside.write_bytes(source.read_bytes());data=copy.deepcopy(base);data['inputs'][0]['source']=str(outside);reject('input outside manifest parent',data)
link=inputs/'link.dat';link.symlink_to(outside);data=copy.deepcopy(base);data['inputs'][0]['source']=str(link);reject('symlink source escape',data)
data=copy.deepcopy(base);data['source_receipts'][0]['sha256']='0'*64;reject('receipt hash mismatch',data)
data=copy.deepcopy(base);data['upstream_archive']['sha256']='0'*64;reject('archive hash mismatch',data)
data=copy.deepcopy(base);data['outputs']=[{'guest':'C:\\NPPLAB\\APP\\fresh.txt','max_bytes':4*1024**2+1}];reject('output bound',data)
reject('duplicate JSON key',raw='{"schema":1,"schema":1}')
reject('JSON over 256KiB',raw=' '* (256*1024+1))
for prefix in ['WINDOWS','VLCLAB\\..','C:\\VLCLAB','vlclab','NPPLAB ',None,True]:
    data=copy.deepcopy(base);data['staging_prefix']=prefix;reject('unallowlisted prefix '+str(prefix),data)
data=copy.deepcopy(base);data['inputs'][0]['guest']='C:\\VLCLAB\\APP\\sample.dat';reject('VLCLAB requires explicit prefix',data)
data=copy.deepcopy(base);data['staging_prefix']='VLCLAB';reject('selected prefix input mismatch',data)
for guest in ['C:\\VLCLAB\\..\\escape.txt','C:\\VLCLAB\\APP\\CON.txt','C:\\VLCLAB\\APP\\trailing.']:
    data=copy.deepcopy(base);data['staging_prefix']='VLCLAB';data['inputs'][0]['guest']=guest
    data['outputs']=['C:\\VLCLAB\\APP\\Fresh.output.log'];reject('VLCLAB path '+guest,data)
data=copy.deepcopy(base);data['staging_prefix']='VLCLAB';data['inputs'][0]['guest']='C:\\VLCLAB\\APP\\sample.dat';reject('mixed prefix output',data)
digest=select(base);(run/'qemu.stderr').write_text('host active-run sentinel')
reject('active run sentinel',base);(run/'qemu.stderr').unlink()
digest=select(base)
def command(argv):return subprocess.run([str(x) for x in argv],check=True,capture_output=True,text=True,timeout=30).stdout
result=helper.stage(disk,run,partition,helper.validate(manifest,digest,ROOT),command)
assert result['status']=='STAGED-READBACK-VERIFIED' and helper.boot_sectors(disk,1)==before
assert Path(result['inputs'][0]['readback']).read_bytes()==source.read_bytes()
records.append({'case':'actual FAT LFN exact source/readback','status':'PASS','native_executed':False})
after=helper.sha(disk)
try:helper.stage(disk,run,partition,helper.validate(manifest,digest,ROOT),command)
except ValueError:pass
else:raise AssertionError('second stage accepted')
assert helper.sha(disk)==after
records.append({'case':'second stage rejected unchanged','status':'PASS'})
# Independently check the immutable source FAT tree, then stage VLCLAB into a
# new disk copy that retains the existing NPPLAB LFN and its exact data.
source_spec=str(disk)+'@@512'
assert helper.directory_absent(source_spec,'VLCLAB')['status']=='absent'
try:helper.directory_absent(source_spec,'NPPLAB')
except ValueError:pass
else:raise AssertionError('existing source prefix accepted')
assert helper.sha(disk)==after
records.append({'case':'source prefix absence/presence checked read-only','status':'PASS'})
vlc_run=run.with_name(run.name+'-vlclab')
if vlc_run.exists():raise AssertionError('fresh VLCLAB fixture required')
vlc_run.mkdir();vlc_disk=vlc_run/'windows-uefi.raw';shutil.copyfile(disk,vlc_disk)
vlc_data=copy.deepcopy(base);vlc_data['staging_prefix']='VLCLAB'
for item in vlc_data['inputs']:item['guest']=item['guest'].replace('C:\\NPPLAB\\','C:\\VLCLAB\\')
vlc_data['outputs']=[name.replace('C:\\NPPLAB\\','C:\\VLCLAB\\') for name in vlc_data['outputs']]
vlc_digest=select(vlc_data);vlc_plan=helper.validate(manifest,vlc_digest,ROOT)
vlc_spec=str(vlc_disk)+'@@512';command(['mmd','-i',vlc_spec,'::VLCLAB']);occupied=helper.sha(vlc_disk);calls=[]
try:helper.stage(vlc_disk,vlc_run,partition,vlc_plan,lambda argv:calls.append(argv))
except ValueError:pass
else:raise AssertionError('existing selected VLCLAB accepted')
assert not calls and helper.sha(vlc_disk)==occupied and not (vlc_run/'app-stage-readback').exists()
records.append({'case':'existing VLCLAB rejected before mutation despite preserved NPPLAB','status':'PASS'})
command(['mrd','-i',vlc_spec,'::VLCLAB'])
vlc_result=helper.stage(vlc_disk,vlc_run,partition,vlc_plan,command)
assert vlc_result['staging_prefix']=='VLCLAB' and helper.boot_sectors(vlc_disk,1)==before
assert Path(vlc_result['inputs'][0]['readback']).read_bytes()==source.read_bytes()
retained=vlc_run/'preserved-NPPLAB.readback';command(['mcopy','-i',vlc_spec,'::NPPLAB/APP/long.model.filename.xml',retained])
assert retained.read_bytes()==source.read_bytes() and helper.sha(disk)==after
records.append({'case':'actual fresh VLCLAB FAT LFN stage preserves existing NPPLAB and source bytes','status':'PASS','native_executed':False})
document={'status':'PASS','cases':records,'native_executed':False,'helper_sha256':helper.sha(HERE/'app_staging.py'),'test_sha256':helper.sha(Path(__file__)),
          'scope':'host tiny FAT fixture only; original application and Win98 disks untouched'}
(run/'host-test-result.json').write_text(json.dumps(document,indent=2)+'\n')
print(json.dumps({'status':'PASS','cases':len(records),'receipt':str(run/'host-test-result.json')}))
