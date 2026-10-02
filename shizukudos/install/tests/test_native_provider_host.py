"""Real provider/core/relocator host controls, no private media or VM.

Uses existing synthetic FAT32 source builder and independently verifies every
installed byte plus GPT CRCs. Physical device role admission is modeled; Linux
file identities, read/write leases, SHA, actual storage I/O and flush are real.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[3]
SETUP=ROOT/'shizukudos/win64/setup'
# The reused fixture module requires a caller-owned lane; create only a fresh
# uniquely named temporary directory, restoring the environment after import.
_TEMP=tempfile.TemporaryDirectory(prefix='shz-native-provider-')
_old=os.environ.get('TMPDIR')
os.environ['TMPDIR']=_TEMP.name
try:
 spec=importlib.util.spec_from_file_location('provider_fixture',Path(__file__).with_name('test_native_install_host_fada.py'))
 fixture=importlib.util.module_from_spec(spec);spec.loader.exec_module(fixture)
finally:
 if _old is None:os.environ.pop('TMPDIR',None)
 else:os.environ['TMPDIR']=_old

class ProviderHost(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  compiler=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
  flags=['-std=c99','-O2','-g','-Wall','-Wextra','-fno-omit-frame-pointer']
  if 'clang' in compiler:flags+=['-fsanitize=address,undefined']
  args=[compiler,*flags,'-I',SETUP,'-o',fixture.HOST,Path(__file__).with_name('native_provider_host.c'),
        *(SETUP/n for n in fixture.CORE),'%s/native_provider.c'%SETUP,'%s/native_fat32_relocate.c'%SETUP]
  rc,out=fixture.owned(args,45);print(json.dumps({'compile':[str(a) for a in args],'exit':rc,'output':out}),flush=True)
  if rc:raise RuntimeError(out)
  cls.base=fixture.LANE/'native-fixture-base';cls.base.mkdir(mode=0o700);cls.image=cls.base/'original.img'
  cls.offsets=fixture.fat_image(cls.image);cls.sim=cls.base/'ESP.SIM';fixture.sim_encode(cls.image,cls.sim)
  cls.manifest=fixture.manifest_for(cls.image,cls.sim);cls.original=fixture.digest(cls.image)
 @classmethod
 def tearDownClass(cls):_TEMP.cleanup()
 run_case=fixture.NativeInstallerHost.run_case
 verify_target=fixture.NativeInstallerHost.verify_target
 def test_roundtrip_actual_pure_relocator_and_unequal_fsinfo(self):self.run_case(success=True)
 def test_short_io(self):self.run_case('short_io',success=True)
 def test_source_authority_missing(self):self.run_case('missing_source_authority')
 def test_boot_whole_unknown(self):self.run_case('unknown_boot_whole')
 def test_source_whole_excluded(self):self.run_case('source_whole')
 def test_current_system_whole_excluded(self):self.run_case('current_os_whole')
 def test_claim_denied(self):self.run_case('claim_denied')
 def test_partial_claim_failure_consumed(self):self.run_case('partial_claim_fail')
 def test_stale_generation(self):self.run_case('stale_generation')
 def test_backend_generation_changes_before_io(self):self.run_case('backend_generation')
 def test_duplicate_serial(self):self.run_case('duplicate')
 def test_bad_confirmation(self):self.run_case('bad_confirm')
 def test_sha_update_refuses(self):self.run_case('sha_update')
 def test_readback_corruption(self):self.run_case('readback_corrupt',postwrite=True)
 def test_flush_failure(self):self.run_case('flush_fail',postwrite=True)
 def test_source_close_failure(self):self.run_case('source_close',postwrite=True)
 def test_claim_release_failure(self):self.run_case('release_fail',postwrite=True)
 def test_bad_source_geometry_before_write(self):
  def corrupt(p):
   with p.open('r+b') as f:f.seek(0);f.write(b'BADIMAGE')
  self.run_case(sim_change=corrupt)

if __name__=='__main__':unittest.main(verbosity=2)
