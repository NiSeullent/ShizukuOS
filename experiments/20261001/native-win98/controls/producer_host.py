#!/usr/bin/env python3
import sys
sys.dont_write_bytecode=True
from pathlib import Path
import hashlib,importlib.util,json,os,tempfile,fcntl
from unittest.mock import patch
BASE=Path(__file__).resolve().parent
p=BASE/'candidate/shizukudos/supervisor/native_win98/build_candidate.py'
spec=importlib.util.spec_from_file_location('win98producer',p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
passed=[]
def check(name,v):
 if not v:raise AssertionError(name)
 passed.append(name)
def rejects(name,fn):
 try:fn()
 except (ValueError,RuntimeError,OSError):passed.append(name);return
 raise AssertionError(name+' unexpectedly accepted')
with tempfile.TemporaryDirectory(prefix='win98producer-host-',dir=m.ROOT/'build/modern-apps') as d:
 d=Path(d);source=d/'source';raw=b'real owned test bytes'*100;source.write_bytes(raw);digest=hashlib.sha256(raw).hexdigest()
 check('regular stable exact pin',m.pinned_hash(source,digest)==len(raw));check('streaming artifact hash',m.file_sha(source)==digest)
 rejects('bad input pin',lambda:m.pinned_hash(source,'0'*64));alias=d/'alias';alias.symlink_to(source);rejects('alias source rejected',lambda:m.pinned_hash(alias,digest));fifo=d/'fifo';os.mkfifo(fifo);rejects('FIFO rejected without blocking',lambda:m.pinned_hash(fifo,digest))
 with m.read_leased(source,digest,len(raw)) as (fd,checkpoint):
  check('actual shared read lease established',fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK)
  target=d/'owned-copy';m.copy_fd(fd,checkpoint,target,digest,len(raw));check('actual owned full copy and distinct inode',target.read_bytes()==raw and target.stat().st_ino!=source.stat().st_ino)
 check('original source preserved',source.read_bytes()==raw)
 def bad_geometry():
  with m.read_leased(source,digest,len(raw)+1):pass
 rejects('wrong source geometry',bad_geometry)
 def bad_sha():
  with m.read_leased(source,'0'*64,len(raw)):pass
 rejects('wrong leased source SHA',bad_sha)
 writer=os.open(source,os.O_WRONLY|os.O_NONBLOCK)
 try:
  def existing_writer():
   with m.read_leased(source,digest,len(raw)):pass
  rejects('actual existing writer refuses lease before copy',existing_writer)
 finally:os.close(writer)
 def real_break():
  with m.read_leased(source,digest,len(raw)) as (fd,checkpoint):
   # Actual incompatible open asks kernel to break the real lease; no write succeeds.
   try:foreign=os.open(source,os.O_WRONLY|os.O_NONBLOCK)
   except BlockingIOError:foreign=None
   if foreign is not None:os.close(foreign);raise AssertionError('writer acquired leased source')
   checkpoint()
 rejects('actual SIGIO/lease-break checkpoint rejects',real_break)
 check('actual lease-break leaves input bytes unchanged',source.read_bytes()==raw)
 def post_read_break():
  with m.read_leased(source,digest,len(raw)) as (fd,checkpoint):
   realread=m.os.read;once=[False]
   def postread(fd2,n):
    block=realread(fd2,n)
    if block and not once[0]:
     once[0]=True
     try:other=os.open(source,os.O_WRONLY|os.O_NONBLOCK)
     except BlockingIOError:other=None
     if other is not None:os.close(other);raise AssertionError('writer acquired lease')
    return block
   with patch.object(m.os,'read',side_effect=postread):
    try:m.copy_fd(fd,checkpoint,d/'partial',digest,len(raw))
    finally:check('post-read break performs no owned data write',not (d/'partial').read_bytes())
 rejects('actual post-read source lease break blocks owned copy',post_read_break)
 check('cold source final bytes remain exact',source.read_bytes()==raw)
 pins=m.input_pins();check('actual frozen build/source/ROM pins validate',len(pins)==461)
result={'status':'PASS_SOURCE_ONLY_REAL_LEASE_AND_COPY_HOST','checks':len(passed),'names':passed,'producer_sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'actual_pins':len(pins),'VM_executed':False}
(BASE/'producer-host-result.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
