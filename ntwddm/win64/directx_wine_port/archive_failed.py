#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Losslessly compact ONLY the owned failed-v1 duplicate Wine source closure.

Receipt/logs remain untouched. Every source/license byte, path and file mode is
verified in the archive and the newer immutable owned closure before removal.
"""
import gzip,hashlib,json,shutil,stat,tarfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def require(x,s):
 if not x:raise RuntimeError(s)
def main():
 old=HERE/'build/wine-graphics-object-v1';new=HERE/'build/wine-graphics-object-v2';source=old/'wine';archive=old/'source-tree.tar.gz';manifest=old/'source-archive-manifest.json'
 require(source.is_dir() and not source.is_symlink() and not archive.exists() and not manifest.exists(),'exact owned failed duplicate only')
 original=json.loads((old/'result.json').read_text());latest=json.loads((new/'result.json').read_text());require(original['status']=='INCOMPLETE' and original['error'].startswith('[Errno 2]'),'exact recorded first temporary-file race')
 receipt_hash=digest(old/'result.json');expected={name:row['sha256'] for name,row in original['original'].items()};expected.update({name:row['sha256'] for name,row in original['generated_headers'].items()});rows={}
 def guard():
  total=0
  for p in (HERE/'build').rglob('*'):
   try:
    if p.is_file() and not p.is_symlink():total+=p.stat().st_size
   except FileNotFoundError:pass
  require(total<=256*1024**2 and shutil.disk_usage(old).free>=20*1024**3,'exact aggregate budget and disk reserve')
 for p in sorted(source.rglob('*')):
  require(not p.is_symlink(),'no symlinks in source closure')
  if not p.is_file():continue
  name=str(p.relative_to(old));h=digest(p);rel=str(p.relative_to(source));q=new/'wine'/rel
  require(expected.get(rel)==h and q.is_file() and not q.is_symlink() and digest(q)==h,'all source/license originals duplicated exactly in newer closure')
  rows[name]={'sha256':h,'bytes':p.stat().st_size,'mode':stat.S_IMODE(p.stat().st_mode)}
 require(len(rows)==len(expected),'complete failed source/license/header closure')
 guard()
 with archive.open('wb') as raw:
  with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0,compresslevel=6) as gz:
   with tarfile.open(fileobj=gz,mode='w|') as tar:
    for i,(name,row) in enumerate(rows.items()):
     p=old/name;require(digest(p)==row['sha256'],'source changed while archiving');info=tarfile.TarInfo(name);info.size=row['bytes'];info.mode=row['mode'];info.mtime=0
     with p.open('rb') as f:tar.addfile(info,f)
     if i%25==0:guard()
 restored={}
 with tarfile.open(archive,'r:gz') as tar:
  for member in tar:
   require(member.isfile() and member.name in rows and member.name not in restored,'regular unique complete archived source paths')
   data=tar.extractfile(member).read();row=rows[member.name];require(len(data)==row['bytes'] and member.mode==row['mode'] and hashlib.sha256(data).hexdigest()==row['sha256'],'independent full archive readback bytes and file mode')
   restored[member.name]=True
 require(len(restored)==len(rows) and digest(old/'result.json')==receipt_hash,'complete byte reconstruction and original receipt preservation')
 guard();record={'schema':1,'status':'LOSSLESS_ARCHIVE_VERIFIED','original_failure_receipt_sha256':receipt_hash,'archive':{'path':str(archive),'sha256':digest(archive),'bytes':archive.stat().st_size,'format':'gzip-compressed POSIX tar, regular members only'},'archiver_sha256':digest(Path(__file__).resolve()),'newer_source_receipt':{'path':str(new/'result.json'),'sha256':digest(new/'result.json')},'files':rows,'reconstruction':'All archived wine/... regular paths, modes and exact bytes were independently read back and checked. Extract only into a fresh owned directory; verify each SHA against this ledger before using. Original receipt/logs remain beside archive.','original_bytes':sum(row['bytes'] for row in rows.values()),'source_licenses_preserved':True,'duplicate_source_directory_removed':False}
 manifest.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');guard()
 # Removal occurs only after complete independent readback and a durable ledger.
 shutil.rmtree(source);record['duplicate_source_directory_removed']=True;manifest.write_text(json.dumps(record,sort_keys=True,indent=2)+'\n');archive.chmod(0o400);manifest.chmod(0o400);guard();print(json.dumps({'status':record['status'],'files':len(rows),'original_bytes':record['original_bytes'],'archive_bytes':record['archive']['bytes'],'manifest_sha256':digest(manifest)}))
if __name__=='__main__':main()
