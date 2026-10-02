"""Actual C native installer storage controls, with fresh regular files only.

Prior DOS3/native producer admission, physical whole roles and pure peer
relocation are explicit host models. Actual Linux leases, namespace identity,
source/expanded/target SHA, FAT members, writes, flush and GPT readback are real.
No production-2304MiB timing, guest provider, Windows or VM acceptance follows.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import re
import shutil
import signal
import struct
import subprocess
import time
import unittest

ROOT=Path(__file__).resolve().parents[3]
SETUP=ROOT/'shizukudos/win64/setup'
LANE=Path(os.environ['TMPDIR'])
HOST=LANE/'native-install-host'
CORE=('install.c','native_install.c','sfsw.c','gpt.c','fat32fmt.c','textparse.c')
IMAGE_BYTES=34<<20
TARGET_BYTES=40<<20
POLICY=b'mode=supervisor\r\nmenu_timeout=0\r\n'
PATCHES=('0001-shizukudos-branding.patch','0002-reproducible-build-date.patch',
 '0003-cb43-win98-dos-internals.patch','0003-dosmgr-honest-contract.patch',
 '0004-win-startup-chain.patch','freecom-0001-reproducible-build-stamp.patch')
MEMBERS={'EFI/BOOT/BOOTX64.EFI':b'MODELED SOURCE-BUILT EFI',
 'EFI/SHIZUKU/BOOT.INI':POLICY,'SHZDOS/KERNEL32.BIN':b'MODELED K32 FOUNDATION',
 'SHZDOS/KERNEL64.BIN':b'MODELED K64 BACKEND','SHZDOS/WIN64.IMG':b'MODELED PROVIDER ARCHIVE',
 'SHZDOS/DISK.IMG':b'MODELED PRIVATE DOS3 WINDOWS DISK',
 'SHZDOS/SEABIOS.BIN':b'MODELED FIRMWARE'.ljust(256<<10,b'\0'),
 'SHZDOS/WIN98CFG.BIN':struct.pack('<IIII',0x38395753,1,128,0)}


def digest(path):
 h=hashlib.sha256()
 with path.open('rb') as f:
  for b in iter(lambda:f.read(1<<20),b''):h.update(b)
 return h.hexdigest()
def sha(b):return hashlib.sha256(b).hexdigest()
def pin(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':digest(p)}
def sparse_copy(source,target):
 with source.open('rb') as src,target.open('xb') as dst:
  while b:=src.read(65536):
   if any(b):dst.write(b)
   else:dst.seek(len(b),1)
  dst.truncate(source.stat().st_size);dst.flush();os.fsync(dst.fileno())
 assert digest(source)==digest(target)
def model_pin(name):return {'path':'MODEL/'+name,'bytes':17,'sha256':sha(('MODELED '+name).encode())}
def name83(name):
 a,_,b=name.partition('.');return a.encode().ljust(8,b' ')+b.encode().ljust(3,b' ')
def fat_image(path,members=MEMBERS):
 total=IMAGE_BYTES//512;reserved=32;fat_sectors=1
 while True:
  clusters=total-reserved-2*fat_sectors;needed=((clusters+2)*4+511)//512
  if needed<=fat_sectors:break
  fat_sectors=needed
 assert clusters>=65525
 dirs={'':2,'EFI':3,'EFI/BOOT':4,'EFI/SHIZUKU':5,'SHZDOS':6};nextc=7
 fat=bytearray(fat_sectors*512);struct.pack_into('<II',fat,0,0x0ffffff8,0x0fffffff)
 entries={n:[] for n in dirs};payloads=[];offsets={}
 for n,c in dirs.items():
  struct.pack_into('<I',fat,c*4,0x0fffffff)
  if n:
   parent,_,base=n.rpartition('/');row=bytearray(32);row[:11]=name83(base);row[11]=16
   struct.pack_into('<H',row,26,c);entries[parent].append(row)
 first=reserved+2*fat_sectors
 for n,b in members.items():
  count=(len(b)+511)//512;c=nextc;nextc+=count
  for i in range(count):struct.pack_into('<I',fat,(c+i)*4,0x0fffffff if i+1==count else c+i+1)
  parent,_,base=n.rpartition('/');row=bytearray(32);row[:11]=name83(base);row[11]=32
  struct.pack_into('<H',row,20,c>>16);struct.pack_into('<H',row,26,c&65535);struct.pack_into('<I',row,28,len(b));entries[parent].append(row)
  offsets[n]=(first+c-2)*512;payloads.append((offsets[n],b))
 v=bytearray(512);v[:11]=b'\xeb\x58\x90SHZTEST '
 struct.pack_into('<H',v,11,512);v[13]=1;struct.pack_into('<H',v,14,reserved);v[16]=2;v[21]=0xf8
 struct.pack_into('<I',v,32,total);struct.pack_into('<I',v,36,fat_sectors);struct.pack_into('<I',v,44,2)
 struct.pack_into('<HH',v,48,2,9);v[64]=128;v[66]=0x29;v[82:90]=b'FAT32   ';v[510:]=b'\x55\xaa'
 f=bytearray(512);struct.pack_into('<I',f,0,0x41615252);struct.pack_into('<I',f,484,0x61417272)
 struct.pack_into('<II',f,488,clusters-nextc+2,nextc);struct.pack_into('<I',f,508,0xaa550000)
 g=bytearray(f);struct.pack_into('<II',g,488,0xffffffff,0xffffffff) # valid unequal FSInfo pair
 with path.open('xb') as out:
  out.truncate(IMAGE_BYTES)
  for sector,b in ((0,v),(9,v),(2,f),(11,g),(reserved,fat),(reserved+fat_sectors,fat)):
   out.seek(sector*512);out.write(b)
  for n,c in dirs.items():out.seek((first+c-2)*512);out.write(b''.join(entries[n])+bytes(32))
  for off,b in payloads:out.seek(off);out.write(b)
  out.flush();os.fsync(out.fileno())
 return offsets

def sim_encode(image,path):
 rows=[];chunks=[];block=0;start=None;raw=bytearray()
 with image.open('rb') as f:
  while b:=f.read(4096):
   assert len(b)==4096
   if any(b):
    if start is None:start=block
    raw.extend(b)
   elif start is not None:
    rows.append((start,len(raw)//4096));chunks.append(bytes(raw));start=None;raw.clear()
   block+=1
 if start is not None:rows.append((start,len(raw)//4096));chunks.append(bytes(raw))
 h=bytearray(64);h[:8]=b'SHZSIMG1';struct.pack_into('<I',h,8,4096);struct.pack_into('<I',h,16,len(rows))
 struct.pack_into('<Q',h,24,image.stat().st_size);h[32:]=bytes.fromhex(digest(image))
 path.write_bytes(h+b''.join(struct.pack('<QII',a,n,0) for a,n in rows)+b''.join(chunks))
 return rows

def manifest_for(image,sim,members=MEMBERS):
 lineage={n:model_pin(n) for n in ('source_profile','constructor_profile','replacement_receipt','dos_build_receipt','native_build_receipt','original_source_disk')}
 lineage.update(replacement_disk={'path':'MODEL/private-disk','bytes':len(members['SHZDOS/DISK.IMG']),'sha256':sha(members['SHZDOS/DISK.IMG'])},
  native_esp=pin(image),native_members={n:{'bytes':len(b),'sha256':sha(b)} for n,b in members.items()},
  observed_windows_path='C:\\WINDOWS',boot_policy='shz.foundation=win98',DOS3_patch_pins={n:sha(('MODEL '+n).encode()) for n in PATCHES})
 m={'schema':'shizukuos.private-native-install-payload.v1','status':'PRIVATE_NATIVE_ESP_INPUT_EXPORTED_NOT_INSTALLED',
 'private':True,'public_artifact':False,'redistribution':'PROHIBITED_PRIVATE_LICENSED_INPUT','boot_profile':'native-win98',
 'source_request':model_pin('request'),'lineage':lineage,'esp_sim':pin(sim),'ESP_geometry':'LBA0_SUPERFLOPPY_UNCHANGED_NOT_PARTITION_REBASED','first_lba':0,
 'input_linux_read_leases':True,'inputs_before_after_full_SHA_match':True,'independent_expanded_ESP_readback':True,'compiler_tool_closure_verified':False}
 for n in ('VM_executed','Windows98_boot_verified','installer_executed','installer_target_written','coldboot_persistence_verified','MSDOS_replacement_under_Windows98','native_apps_verified','SMP_acceptance','ISO_built'):m[n]=False
 return m

def owned(argv,timeout=30):
    p=subprocess.Popen([str(a) for a in argv],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    end=time.monotonic()+timeout;out=bytearray()
    import selectors
    sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
    try:
        while sel.get_map():
            if time.monotonic()>end:raise TimeoutError('owned host command deadline')
            for key,_ in sel.select(min(.05,max(0,end-time.monotonic()))):
                b=os.read(key.fd,65536)
                if not b:sel.unregister(key.fd)
                else:
                    out.extend(b)
                    if len(out)>1<<20:raise RuntimeError('owned host command output cap')
        rc=p.wait(timeout=max(.01,end-time.monotonic()))
        return rc,out.decode(errors='replace')
    finally:
        if p.poll() is None:
            os.killpg(p.pid,signal.SIGKILL);p.wait(timeout=5)
        sel.close();p.stdout.close()
        # An actual owned session must be empty after its reaped leader.
        for entry in Path('/proc').iterdir():
            if not entry.name.isdigit():continue
            try:
                s=(entry/'stat').read_text();tail=s[s.rfind(')')+2:].split()
                if int(tail[3])==p.pid:raise RuntimeError('unresolved owned session descendant')
            except (FileNotFoundError,ProcessLookupError):pass



class NativeInstallerHost(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  compiler=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  flags=['-std=c99','-O2','-g','-Wall','-Wextra','-fno-omit-frame-pointer']
  if 'clang' in compiler:flags+=['-fsanitize=address,undefined']
  argv=[compiler,*flags,'-I',SETUP,'-o',HOST,ROOT/'shizukudos/install/tests/native_install_host.c',*(SETUP/n for n in CORE)]
  rc,out=owned(argv,45);print(json.dumps({'command':[str(a) for a in argv],'exit':rc,'output':out}),flush=True)
  if rc:raise RuntimeError(out)
  cls.base=LANE/'native-fixture-base';cls.base.mkdir(mode=0o700);cls.image=cls.base/'original.img'
  cls.offsets=fat_image(cls.image);cls.sim=cls.base/'ESP.SIM';sim_encode(cls.image,cls.sim)
  cls.manifest=manifest_for(cls.image,cls.sim);cls.original=digest(cls.image)

 def run_case(self,fault='normal',change=None,sim_change=None,members=None,success=False,postwrite=False):
  d=LANE/self._testMethodName;d.mkdir(mode=0o700)
  inputs=d/'inputs';inputs.mkdir(mode=0o700);targets=d/'targets';targets.mkdir(mode=0o700)
  sim=inputs/'ESP.SIM';shutil.copyfile(self.sim,sim);m=copy.deepcopy(self.manifest)
  image=self.image;owned_image=None
  if members is not None:
   owned_image=inputs/'modified.img';fat_image(owned_image,members);image=owned_image;sim.unlink();sim_encode(image,sim);m=manifest_for(image,sim,members)
  if sim_change:sim_change(sim)
  m['esp_sim']=pin(sim)
  if change:change(m)
  manifest=inputs/'manifest.json';manifest.write_text(json.dumps(m,separators=(',',':')))
  if fault=='duplicate_json':manifest.write_text(manifest.read_text()[:-1]+',"private":true}')
  for p in (sim,manifest):os.chmod(p,0o600)
  disks=[]
  for i in range(2):
   p=targets/f'target{i}.img'
   with p.open('xb') as f:f.truncate(TARGET_BYTES);f.write(b'ORIGINAL'.ljust(512,b'A'));f.seek(TARGET_BYTES-512);f.write(b'Z'*512);f.flush();os.fsync(f.fileno())
   disks.append(p)
  if fault in ('source_alias','target_alias'):
   p=manifest if fault=='source_alias' else disks[0];sparse_copy(p,Path(str(p)+'.alias'))
  before=[digest(p) for p in disks];source_before=[digest(manifest),digest(sim),digest(image)]
  old=os.environ.get('MODEL_ADMITTED_MANIFEST_SHA256');os.environ['MODEL_ADMITTED_MANIFEST_SHA256']=digest(manifest)
  started=time.monotonic()
  try:rc,out=owned([HOST,manifest,sim,*disks,fault],35)
  finally:
   if old is None:os.environ.pop('MODEL_ADMITTED_MANIFEST_SHA256',None)
   else:os.environ['MODEL_ADMITTED_MANIFEST_SHA256']=old
  after=[digest(p) for p in disks];source_after=[digest(manifest),digest(sim),digest(image)]
  match=re.search(r'HOST_RESULT (.*)',out);self.assertIsNotNone(match,out)
  values={a:int(b) for a,b in re.findall(r'(\w+)=(\d+)',match[1])}
  row={'test':self.id(),'fault':fault,'exit':rc,'elapsed':time.monotonic()-started,'output':out,'before':before,'after':after,'sources_before':source_before,'sources_after':source_after,'actual_regular_FD_SHA_IO':True,'prior_producer_device_roles_and_peer_adapter_modeled':True}
  print(json.dumps(row),flush=True)
  try:
   self.assertEqual(values['ok'],int(success),out);self.assertEqual(rc,0 if success else 1,out)
   self.assertEqual(values['opened'],values['closed'],out);self.assertEqual(values['claimed'],0,out)
   self.assertEqual(values['windows'],0);self.assertEqual(values['vm'],0)
   self.assertEqual(before[1],after[1],'unselected actual target changed')
   if not success and not postwrite:self.assertEqual(values['writes'],0,out);self.assertEqual(before,after)
   if success:
    self.assertEqual(values['readback'],1);self.assertEqual(values['gpt'],1);self.verify_target(disks[0],image)
   if fault not in ('source_alias','source_ancestor'):self.assertEqual(source_before,source_after)
  finally:
   # Consume only this test's owned output after its actual process closed.
   # The receipt above retains all byte hashes/failure evidence, not media.
   if inputs.is_symlink():inputs.unlink();shutil.rmtree(str(inputs)+'.moved')
   if targets.is_symlink():targets.unlink();shutil.rmtree(str(targets)+'.moved')
   shutil.rmtree(d)

 def verify_target(self,target,image):
  import zlib
  with target.open('rb') as t,image.open('rb') as src:
   mbr=t.read(512);self.assertEqual(mbr[510:],b'\x55\xaa');self.assertEqual(mbr[450],0xee)
   primary=t.read(512);self.assertEqual(primary[:8],b'EFI PART');hs=struct.unpack_from('<I',primary,12)[0]
   expected=struct.unpack_from('<I',primary,16)[0];check=bytearray(primary[:hs]);check[16:20]=bytes(4);self.assertEqual(zlib.crc32(check),expected)
   t.seek(1024);entries=t.read(16384);self.assertEqual(zlib.crc32(entries),struct.unpack_from('<I',primary,88)[0])
   self.assertEqual(entries[:16],bytes.fromhex('28732ac11ff8d211ba4b00a0c93ec93b'))
   first,last,attrs=struct.unpack_from('<QQQ',entries,32);self.assertEqual((first,last,attrs),(2048,2048+IMAGE_BYTES//512-1,0));self.assertEqual(entries[128:],bytes(len(entries)-128))
   t.seek(TARGET_BYTES-512);backup=t.read(512);self.assertEqual(backup[:8],b'EFI PART');self.assertEqual(struct.unpack_from('<Q',backup,32)[0],1)
   t.seek(TARGET_BYTES-33*512);self.assertEqual(t.read(16384),entries)
   t.seek(first*512);off=0;expected_sha=hashlib.sha256();actual_sha=hashlib.sha256()
   while b:=src.read(65536):
    expected=bytearray(b)
    for pos in (28,9*512+28):
     if off<=pos<off+len(b):struct.pack_into('<I',expected,pos-off,first)
    actual=t.read(len(b));self.assertEqual(actual,expected,'non-overlay target byte differs');expected_sha.update(expected);actual_sha.update(actual);off+=len(b)
   self.assertEqual(expected_sha.digest(),actual_sha.digest())

 def test_actual_fat_gpt_native_roundtrip_and_unequal_fsinfo(self):self.run_case(success=True)
 def test_real_short_read_write_loops(self):self.run_case('short_io',success=True)
 def test_malformed_simg_refuses_before_first_target_write(self):self.run_case(sim_change=lambda p:p.write_bytes(b'SHZSIMG1'+bytes(56)))
 def test_ambiguous_serial_target_refuses_before_first_target_write(self):self.run_case('duplicate')
 def test_case_alias_target_refused(self):self.run_case('case_alias')
 def test_no_native_provider_refuses_without_open(self):self.run_case('missing_ops')
 def test_bad_exact_confirmation_refused(self):self.run_case('bad_confirm')
 def test_unknown_boot_whole_refused(self):self.run_case('unknown_boot_whole')
 def test_current_os_whole_refused(self):self.run_case('current_os_whole')
 def test_source_backing_whole_refused(self):self.run_case('source_whole')
 def test_missing_prior_source_admission_refused(self):self.run_case('missing_source_authority')
 def test_exclusive_claim_refused(self):self.run_case('claim_denied')
 def test_stale_generation_refused(self):self.run_case('stale_generation')
 def test_incomplete_enumeration_refused(self):self.run_case('enumeration_fail')
 def test_partition_target_refused(self):self.run_case('partition')
 def test_readonly_target_refused(self):self.run_case('readonly')
 def test_4k_target_refused(self):self.run_case('sector4k')
 def test_target_capacity_refused(self):self.run_case('small_target')
 def test_normalized_guid_collision_refused(self):self.run_case('random_alias')
 def test_arbitrary_byte_relocation_refused(self):self.run_case('bad_overlay')
 def test_relocation_input_mutation_refused(self):self.run_case('changed_snapshot')
 def test_actual_source_same_byte_path_substitution_refused(self):self.run_case('source_alias')
 def test_actual_source_same_inode_ancestor_alias_refused(self):self.run_case('source_ancestor')
 def test_actual_target_same_byte_path_substitution_refused(self):self.run_case('target_alias')
 def test_actual_target_same_inode_ancestor_alias_refused(self):self.run_case('target_ancestor')
 def test_actual_source_writer_break_refused(self):self.run_case('lease_break')
 def test_source_eio_refused(self):self.run_case('source_eio')
 def test_source_short_eof_refused(self):self.run_case('source_eof')
 def test_checked_sha_update_failure_refused(self):self.run_case('sha_update')
 def test_checked_sha_finalize_failure_refused(self):self.run_case('sha_end')
 def test_duplicate_manifest_key_refused(self):self.run_case('duplicate_json')
 def test_false_runtime_acceptance_refused(self):self.run_case(change=lambda m:m.update(Windows98_boot_verified=True))
 def test_bpb_unbounded_reserved_backup_refused(self):
  def corrupt(p):
   b=bytearray(p.read_bytes());n=struct.unpack_from('<I',b,16)[0];offset=64+16*n;struct.pack_into('<H',b,offset+50,32);p.write_bytes(b)
  self.run_case(sim_change=corrupt)
 def test_rebound_desktop_boot_policy_refused(self):
  members=dict(MEMBERS);members['EFI/SHIZUKU/BOOT.INI']=b'mode=kernel64\r\nmenu_timeout=0\r\n'.ljust(len(POLICY),b' ')
  self.run_case(members=members)
 def test_postwrite_plan_mutation_never_accepted(self):self.run_case('late_plan',postwrite=True)
 def test_zero_write_never_accepted(self):self.run_case('write_zero',postwrite=True)
 def test_flush_failure_never_accepted(self):self.run_case('flush_fail',postwrite=True)
 def test_actual_readback_corruption_never_accepted(self):self.run_case('readback_corrupt',postwrite=True)
 def test_readback_eio_never_accepted(self):self.run_case('readback_eio',postwrite=True)
 def test_mandatory_source_close_failure_never_accepted(self):self.run_case('source_close',postwrite=True)
 def test_mandatory_claim_release_failure_never_accepted(self):self.run_case('release_fail',postwrite=True)

if __name__=='__main__':unittest.main(verbosity=2)
