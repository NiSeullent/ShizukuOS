# SPDX-License-Identifier: GPL-2.0-only
"""Actual xorriso/FAT readback of explicit tiny host model; no Windows approval."""
from pathlib import Path
import hashlib
import json
import tempfile
import unittest
from unittest.mock import patch
import test_private_installer_package as fixture
import native_capacity_profile as capacity
import private_installer_package as package
import private_installer_iso as private

CACHE=Path('/root/Win98-Modern-orphan-recovery-8cf7-20261002/build/upstream')

class PrivateISO(unittest.TestCase):
 def model(self,root):return fixture.PackagingTests().model(root)
 def test_production_absence_never_creates_output(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   out=Path(temp)/'absent'
   with self.assertRaisesRegex(ValueError,'anchors absent'):
    private.build_private_iso('/absent',out,'/absent')
   self.assertFalse(out.exists())
 def test_configured_native_without_source_bios_refuses_before_output(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   out=Path(temp)/'absent'
   with patch.object(private.admission.policy,'NATIVE_SOURCE_MAP_SHA','a'*64),patch.object(private.admission.policy,'NATIVE_ARTIFACTS',{}):
    with self.assertRaisesRegex(ValueError,'source-built native system BIOS closure absent'):
     private.build_private_iso('/absent',out,'/absent','/untrusted-receipt')
   self.assertFalse(out.exists())
 def test_bios_source_receipt_and_maps_have_independent_exact_anchors(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,held,custody,_,_=self.model(root)
   with stack:
    def put(name,raw):
     path=root/name;path.write_bytes(raw);return private._row(custody,path)
    artifact=put('bios',b'host modeled source-built BIOS')
    source=put('source.c',b'host source')
    tool=put('tool',b'host tool')
    archive=put('source.tar.gz',b'host modeled source archive')
    licence=put('COPYING',b'host licence')
    manifest=json.loads((private.ROOT/'shizukudos/upstream/manifest.json').read_text())
    commit=manifest['upstreams']['csmwrap']['submodules']['seabios']['commit']
    receipt={'schema':'shizukuos.actual-source-built-system-bios.v1','status':'ACTUAL_SOURCE_BOUND_SYSTEM_BIOS_BUILT_NOT_RUN','artifact':artifact,'source_root':str(root),'source_commit':commit,'sources_sha256':{source['path']:source['sha256']},
             'tools_sha256':{'cc':{'path':tool['path'],'sha256':tool['sha256']}},'source_archive':archive,'license_files':[licence]}
    producer=put('receipt.json',json.dumps(receipt).encode())
    anchor={'artifact':(artifact['bytes'],artifact['sha256']),'receipt':(producer['bytes'],producer['sha256']),
            'source_archive':(archive['bytes'],archive['sha256']),'source_commit':commit,
            'source_map_sha256':private.admission.digest(private.admission.canonical(receipt['sources_sha256'])),
            'tool_map_sha256':private.admission.digest(private.admission.canonical(receipt['tools_sha256']))}
    native=put('native.json',json.dumps({'input_pins':{'SEABIOS.BIN':artifact}}).encode())
    request=put('request.json',json.dumps({'native_build_receipt':native}).encode())
    saved=put('saved.json',json.dumps({'source_request':request}).encode())
    custody._roles['manifest']=saved
    with patch.object(private.admission.policy,'NATIVE_SYSTEM_BIOS_SOURCE',anchor,create=True):
     members=private._bios_sources(custody,producer['path'],manifest)
     self.assertEqual(members['SOURCE/native-system-bios/source.tar.gz'],b'host modeled source archive')
     anchor['tool_map_sha256']='0'*64
     with self.assertRaisesRegex(ValueError,'source/tool maps differ'):
      private._bios_sources(custody,producer['path'],manifest)
     anchor['receipt']=(producer['bytes'],'0'*64)
     with self.assertRaisesRegex(ValueError,'anchor differs'):
      private._bios_sources(custody,producer['path'],manifest)
 def test_receipt_dict_and_public_csm_omission_refused(self):
  with self.assertRaisesRegex(ValueError,'same live'):
   private._assemble({},object(),{}, {},{}, {},'/absent')
  with self.assertRaisesRegex(ValueError,'CSM omission'):
   private.media.efi_members(object(),None,{},'install',{},0)
 def test_budget_requires_actual_disk_and_ram_headroom(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   stack,_,custody,_,_=self.model(Path(temp))
   with stack:
    profile=capacity.from_admitted_custody(custody)
    with self.assertRaisesRegex(ValueError,'17GiB'):private._budget(profile,100,private.RESERVE,1<<40)
    with self.assertRaisesRegex(ValueError,'memory'):private._budget(profile,100,1<<40,0)
    self.assertFalse(private._budget(profile,100,1<<40,1<<40)['expanded_ESP_copied'])
 def test_pinned_packages_reject_wrong_manifest_hash(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   stack,_,custody,_,_=self.model(Path(temp))
   with stack:
    spec=json.loads((private.ROOT/'shizukudos/upstream/manifest.json').read_text())['upstreams']['syslinux']
    spec['packages']['isolinux']['sha256']='0'*64
    with self.assertRaisesRegex(ValueError,'public input differs'):private._syslinux(custody,CACHE,spec)
 def test_actual_iso_and_embedded_fat_all_member_readback_same_fds(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,held,custody,_,_=self.model(root)
   with stack:
    profile=capacity.from_admitted_custody(custody)
    packaged=package._copy_archive(custody,root/'archive',profile)
    # All stand-ins are explicit host-only bytes, not kernel release authority.
    for role,raw in (('kernel',b'host synthetic kernel'),('stub',b'host synthetic Multiboot stub')):
     path=root/role;path.write_bytes(raw)
     packaged['installer_'+role+'_pin']=private._retain(custody,path)
    supervisor=private._load('iso_host_actual_loader',private.ROOT/'shizukudos/supervisor/build.py')
    supervisor.OUT=private._directory(custody,root/'efi');supervisor.build_ap_trampoline()
    loader,command=supervisor.build_loader(b'host unused payload',profile)
    loader_row=private._row(custody,loader)
    spec=json.loads((private.ROOT/'shizukudos/upstream/manifest.json').read_text())['upstreams']['syslinux']
    files,compliance=private._syslinux(custody,CACHE,spec)
    original={role:held.entries[Path(custody.pin(role)['path'])]['fd'] for role in ('manifest','sim','runtime')}
    result=private._assemble(custody,profile,packaged,loader_row,files,compliance,root/'iso')
    self.assertTrue(result['ISO_generated']);self.assertFalse(result['Windows98_boot_verified'])
    self.assertFalse(result['VM_executed']);self.assertFalse(result['CSM_fallback_included'])
    self.assertEqual({role:held.entries[Path(custody.pin(role)['path'])]['fd'] for role in original},original)
    self.assertEqual((root/'iso').stat().st_mode&0o777,0o700)
    self.assertEqual(Path(result['ISO']['path']).stat().st_mode&0o777,0o400)
    report=Path(result['layout_report']).read_text()
    self.assertIn('byte-identical',report);self.assertIn('UEFI',report)
    cfg=(root/'iso/stage/isolinux/isolinux.cfg').read_text()
    self.assertIn('DEFAULT setup',cfg);self.assertNotIn('UI menu',cfg)
    self.assertNotIn('CSMWRAP.EFI',report)
    custody.finish()
 def test_changed_archive_refused_before_iso_output(self):
  with tempfile.TemporaryDirectory(dir='/var/tmp') as temp:
   root=Path(temp);stack,_,custody,_,_=self.model(root)
   with stack:
    profile=capacity.from_admitted_custody(custody)
    packaged=package._copy_archive(custody,root/'archive',profile)
    packaged['archive']=dict(packaged['archive']);packaged['archive']['sha256']='0'*64
    # Validation must precede the expensive FAT/ISO writer.
    with self.assertRaisesRegex(ValueError,'archive differs'):
     private._assemble(custody,profile,packaged,{'bytes':1}, {},{},root/'iso')
if __name__=='__main__':unittest.main(verbosity=2)
