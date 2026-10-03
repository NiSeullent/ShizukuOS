# SPDX-License-Identifier: GPL-2.0-only
"""Actual small leased-file/profile/EFI compiler controls; no Windows admission."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import test_private_installer_package as model
import native_capacity_profile as capacity
import native_release_admission as admission
import private_installer_package as package
ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'tools'))
import shizuku_se_media as media

class Profile(unittest.TestCase):
 def fixture(self,root):return model.PackagingTests().model(root)
 def test_small_actual_copy_and_closed_or_changed_profile(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,_,custody,_,_=self.fixture(root)
   with stack:
    profile=capacity.from_admitted_custody(custody)
    self.assertEqual((profile.source_bytes,profile.archive_bytes,profile.ram_bytes),(256<<20,64<<20,256<<20))
    package._copy_archive(custody,root/'archive',profile)
    self.assertIsNotNone(profile._archive_pin)
    profile.ram_bytes+=2<<20
    with self.assertRaisesRegex(ValueError,'profile changed'):profile.flags()
    profile.ram_bytes-=2<<20
    custody._active=False
    with self.assertRaisesRegex(ValueError,'closed'):profile.record()
 def test_modeled_preliminary_measured_extent_budget_without_large_files(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,_,custody,_,_=self.fixture(root)
   with stack:
    original=custody.pin
    def extent(role):
     row=original(role)
     if role=='sim':row['bytes']=273587088
     return row
    with patch.object(custody,'pin',side_effect=extent):
     profile=capacity.from_admitted_custody(custody)
     self.assertEqual(profile.source_bytes,261<<20)
     self.assertGreater(profile.archive_bytes,64<<20)
     self.assertGreater(profile.ram_bytes,512<<20)
     self.assertLessEqual(profile.ram_bytes,1<<30)
     self.assertFalse(profile.record()['firmware_memory_map_verified'])
     # This deliberately modeled metadata never copies/allocates a large source.
 def test_unbounded_or_caller_dict_profile_refused(self):
  with self.assertRaisesRegex(ValueError,'generator-held'):capacity.CapacityProfile(object(),{})
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   stack,_,custody,_,_=self.fixture(Path(temp))
   with stack:
    original=custody.pin
    def excessive(role):
     row=original(role)
     if role=='sim':row['bytes']=(512<<20)+1
     return row
    with patch.object(custody,'pin',side_effect=excessive),self.assertRaises(ValueError):
     capacity.from_admitted_custody(custody)
    def fits_protocol_but_not_mapping(role):
     row=original(role)
     if role=='sim':row['bytes']=500<<20
     return row
    with patch.object(custody,'pin',side_effect=fits_protocol_but_not_mapping),self.assertRaisesRegex(ValueError,'1GiB'):
     capacity.from_admitted_custody(custody)
 def test_private_loader_directory_refused_before_writes(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,_,custody,_,_=self.fixture(root)
   with stack:
    profile=capacity.from_admitted_custody(custody)
    spec=importlib.util.spec_from_file_location('capacity_bad_output',ROOT/'shizukudos/supervisor/build.py')
    supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
    supervisor.OUT=root/'unsafe';supervisor.OUT.mkdir(mode=0o755);supervisor.OUT.chmod(0o755)
    with self.assertRaisesRegex(ValueError,'custody'):
     supervisor.build_loader(b'host fixture',profile)
    self.assertEqual(list(supervisor.OUT.iterdir()),[])
 def test_actual_private_loader_compile_and_efi_media_profile_match(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,_,custody,_,_=self.fixture(root)
   with stack:
    profile=capacity.from_admitted_custody(custody)
    result=package._copy_archive(custody,root/'archive',profile)
    spec=importlib.util.spec_from_file_location('capacity_supervisor_build',ROOT/'shizukudos/supervisor/build.py')
    supervisor=importlib.util.module_from_spec(spec);spec.loader.exec_module(supervisor)
    supervisor.OUT=root/'efi';supervisor.OUT.mkdir(mode=0o700)
    # Actual PE32+ EFI compiler and real loader source, unused embedded payload
    # is an explicitly synthetic host blob, not a Supervisor producer proof.
    supervisor.build_ap_trampoline()
    loader,command=supervisor.build_loader(b'host fixture unused payload',profile)
    self.assertIn(profile.marker(),loader.read_bytes())
    self.assertTrue(any(arg=='-DSHZ_PRIVATE_NATIVE_EFI_LOAD' for arg in command))
    csm=root/'csm';csm.write_bytes(b'host fixture')
    load=media.Input('loader',loader,'host private compiler fixture')
    wrap=media.Input('csm',csm,'host fixture')
    setup={'SHZ/SETUP/INSTALL.IMG':Path(result['archive']['path']).read_bytes()}
    members=media.efi_members(load,wrap,{},'install',setup,0,profile)
    self.assertEqual(members['SHZ/SETUP/INSTALL.IMG'],setup['SHZ/SETUP/INSTALL.IMG'])
    self.assertIn(b'menu_timeout = 0',members['EFI/SHIZUKU/BOOT.INI'])
    with self.assertRaisesRegex(ValueError,'direct interactive'):
     media.efi_members(load,wrap,{},'install',setup,5,profile)
    with self.assertRaisesRegex(ValueError,'differs'):
     media.efi_members(load,wrap,{},'install',{'SHZ/SETUP/INSTALL.IMG':b'changed'},0,profile)
    ordinary=root/'ordinary';ordinary.write_bytes(b'host missing private profile marker')
    with self.assertRaisesRegex(ValueError,'exact measured'):
     media.efi_members(media.Input('ordinary',ordinary,'host'),wrap,{},'install',setup,0,profile)
 def test_compiled_header_guard_and_source_consumer_epoch(self):
  header=ROOT/'shizukudos/kernel64'
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);source=root/'profile.c'
   source.write_text('#include "setup_native_abi.h"\nint main(void){return sizeof(shz_native_call_v1)!=440 || SHZ_NATIVE_KERNEL_SOURCE_MAX!=(256ull<<20);}\n')
   for cc in ('gcc','clang'):
    command=[cc,'-std=c11','-Wall','-Wextra','-Werror','-I',str(header),str(source),'-o',str(root/'control')]
    subprocess.run(command,check=True,capture_output=True);subprocess.run([str(root/'control')],check=True)
    for flags in (['-DSHZ_PRIVATE_NATIVE_SOURCE_BYTES=273678336ull'],
                  ['-DSHZ_PRIVATE_NATIVE_SOURCE_BYTES=273678336ull','-DSHZ_PRIVATE_NATIVE_ARCHIVE_BYTES=301989888ull','-DSHZ_PRIVATE_NATIVE_RAM_BYTES=648019968ull'],
                  ['-DSHZ_PRIVATE_NATIVE_EFI_LOAD','-DSHZ_PRIVATE_NATIVE_SOURCE_BYTES=536870913ull','-DSHZ_PRIVATE_NATIVE_ARCHIVE_BYTES=301989888ull','-DSHZ_PRIVATE_NATIVE_RAM_BYTES=648019968ull'],
                  ['-DSHZ_PRIVATE_NATIVE_EFI_LOAD','-DSHZ_PRIVATE_NATIVE_SOURCE_BYTES=273678336ull','-DSHZ_PRIVATE_NATIVE_ARCHIVE_BYTES=301989888ull','-DSHZ_PRIVATE_NATIVE_RAM_BYTES=1075838976ull']):
     rejected=subprocess.run(command+flags,capture_output=True)
     self.assertNotEqual(rejected.returncode,0)
if __name__=='__main__':unittest.main(verbosity=2)
