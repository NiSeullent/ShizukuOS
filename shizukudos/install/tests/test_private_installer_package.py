#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host model only; production release/Windows approval remains absent."""
import ast
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT/'shizukudos/install'))
import native_release_admission as admission
import private_installer_package as package

# Extract the actual packer without executing unrelated build initialization.
tree = ast.parse((ROOT/'shizukudos/win64/build.py').read_text())
function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == 'pack_archive')
namespace = {'struct': struct}
exec(compile(ast.Module(body=[function], type_ignores=[]), 'actual-pack-archive', 'exec'), namespace)
pack = namespace['pack_archive']

class PackagingTests(unittest.TestCase):
    def model(self, root, extra=()):
        files = [(package.SETUP, b'host setup model'), (package.HELLO, b'host hello model'),
                 ('\\SHZ\\SYS64\\ntdll.dll', b'host DLL model'),
                 ('\\SHZ\\SYS64\\kernel32.dll', b'host DLL model'), *extra]
        data = {'runtime': pack(files), 'manifest': b'host modeled manifest', 'sim': b'host modeled SIM'}
        ingest = admission.load_ingester()
        stack = ExitStack()
        held = stack.enter_context(ingest.Union())
        rows = {}
        for role, raw in data.items():
            path = root/role;path.write_bytes(raw)
            rows[role] = {'path': str(path), 'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
            held.add(rows[role])
        custody = admission.BuildCustody(admission._CUSTODY_KEY, ingest, held, rows)
        return stack, held, custody, data, files

    def test_actual_packer_exact_roundtrip_and_held_sources(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            root=Path(tmp)
            stack, held, custody, data, files=self.model(root)
            with stack:
                fds={role: held.entries[Path(custody.pin(role)['path'])]['fd'] for role in data}
                result=package._copy_archive(custody,root/'new')
                expected=pack(files+[(package.MANIFEST,data['manifest']),(package.SIM,data['sim'])])
                self.assertEqual((root/'new/INSTALL.IMG').read_bytes(),expected)
                self.assertEqual(result['archive']['sha256'],hashlib.sha256(expected).hexdigest())
                for role, raw in data.items():
                    self.assertEqual((root/role).read_bytes(),raw)
                    self.assertEqual(held.entries[root/role]['fd'],fds[role])
                self.assertEqual((root/'new').stat().st_mode&0o777,0o700)
                self.assertEqual((root/'new/INSTALL.IMG').stat().st_mode&0o777,0o600)
                self.assertFalse(result['ISO_generated'])
                self.assertFalse(result['Windows98_boot_verified'])
                held.finish()

    def test_actual_kernel_parser_namespace_and_snapshot_of_packaged_nodes(self):
        import subprocess
        cc=os.environ.get('NATIVE_HOST_COMPILER','/usr/bin/gcc')
        kernel=ROOT/'shizukudos/kernel64'
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            root=Path(tmp)
            stack, _, custody, data, _=self.model(root)
            with stack:
                package._copy_archive(custody,root/'new')
                flags=['-D_POSIX_C_SOURCE=200809L','-std=c11','-O2','-g','-Wall','-Wextra','-Werror','-pthread']
                if 'clang' in cc:flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
                binary=root/'kernel-node-readback'
                sources=[ROOT/'shizukudos/install/tests/test_private_installer_archive.c']
                sources += [kernel/name for name in ['archive_source.c','boot_storage.c','blk_authority.c','blk.c','blk_part.c','fs.c']]
                sources += [ROOT/'shizukudos/accounts/sha256.c']
                command=[cc,*flags,'-include',str(kernel/'host/blk_authority_host_shim.h'),
                         *map(str,sources),'-o',str(binary)]
                built=subprocess.run(command,capture_output=True,text=True,timeout=30)
                self.assertEqual(built.returncode,0,built.stderr)
                ran=subprocess.run([str(binary),str(root/'new/INSTALL.IMG')],capture_output=True,text=True,timeout=20)
                self.assertEqual(ran.returncode,0,ran.stdout+ran.stderr)
                for index,role in enumerate(('manifest','sim')):
                    self.assertIn('role=%d bytes=%d sha256=%s'%(index,len(data[role]),
                                  hashlib.sha256(data[role]).hexdigest()),ran.stdout)
                self.assertIn('failures=0 actual_parser_namespace_snapshot=1',ran.stdout)

    def test_receipt_dict_is_not_live_generator_authority(self):
        with self.assertRaisesRegex(ValueError,'generator-owned'):
            package.finalize({'custody': {'approved': True}}, '/nonexistent', {})
        with self.assertRaisesRegex(ValueError,'generator-owned'):
            admission.BuildCustody(object(), None, None, {})

    def test_closed_custody_refuses_even_when_model_fds_remain_live(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            stack, held, custody, _, _=self.model(Path(tmp))
            with stack:
                custody._active=False
                with self.assertRaisesRegex(ValueError,'closed'):
                    package.plan(custody)

    def test_loader_cap_before_output_directory(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            root=Path(tmp)
            stack, _, custody, _, _=self.model(root)
            with stack:
                original=custody.pin
                def changed(role):
                    row=original(role)
                    if role=='sim': row['bytes']=package.LOAD_MAX
                    return row
                with patch.object(custody,'pin',side_effect=changed):
                    with self.assertRaisesRegex(ValueError,'64MiB'):
                        package._copy_archive(custody,root/'new')
                self.assertFalse((root/'new').exists())

    def test_recursive_archive_and_missing_runtime_before_output(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            root=Path(tmp)
            stack, _, custody, _, _=self.model(root,[(package.SIM,b'not accepted')])
            with stack:
                with self.assertRaisesRegex(ValueError,'recursive'):
                    package._copy_archive(custody,root/'new')
                self.assertFalse((root/'new').exists())

    def test_broken_input_union_does_not_create_package(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            root=Path(tmp)
            stack, held, custody, _, _=self.model(root)
            held.broken=True
            try:
                with self.assertRaisesRegex(ValueError,'lease broken'):
                    package._copy_archive(custody,root/'new')
                self.assertFalse((root/'new').exists())
            finally:
                held.broken=False
                stack.close()

    def test_malformed_table_alias_overlap_extent_and_header(self):
        raw=pack([('\\A', b'first'), ('\\B', b'second')])
        def verify(value):return package.archive_table(lambda at,n:value[at:at+n],len(value))
        for offset,replacement in [(12,struct.pack('<I',1)),(8,struct.pack('<I',4097)),
                                    (152,b'\\a\0'+bytes(117)),(136,struct.pack('<Q',16)),
                                    (144,struct.pack('<Q',1<<60))]:
            changed=bytearray(raw);changed[offset:offset+len(replacement)]=replacement
            with self.subTest(offset=offset),self.assertRaises(ValueError):verify(changed)
        changed=bytearray(raw)
        changed[272:280]=changed[136:144]
        with self.assertRaisesRegex(ValueError,'overlap'):verify(changed)
        changed=bytearray(raw);changed[16:136]=b'\\A'+bytes([65])*118
        with self.assertRaisesRegex(ValueError,'termination'):verify(changed)

    def test_actual_kbuild_finalize_before_close_and_receipt(self):
        from argparse import Namespace
        from contextlib import contextmanager, redirect_stdout
        import io
        import importlib.util
        spec=importlib.util.spec_from_file_location('test_finalize_kbuild',ROOT/'shizukudos/kbuild.py')
        kbuild=importlib.util.module_from_spec(spec);spec.loader.exec_module(kbuild)
        for close_error in (False, True):
            with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
                root=Path(tmp)
                model_stack, held, custody, _, _=self.model(root)
                events=[]
                @contextmanager
                def modeled_admit(manifest,out,pins):
                    # Host-only authority model: production policy stays None.
                    source=root/'host-source.c';source.write_text('/* host fixture */')
                    try:
                        yield {'source':source,'custody':custody,'manifest':custody.pin('manifest'),
                               'sim':custody.pin('sim')}
                        custody.finish()
                    finally:
                        custody._active=False
                        model_stack.close()
                        events.append('closed')
                    if close_error:raise ValueError('modeled mandatory close failed')
                def compile_model(name,directory,flags,*args,extra_c=()):
                    dest=kbuild.BUILD/name;dest.mkdir()
                    raw=bytearray(20);raw[4]=1 if name=='kernel32' else 2
                    raw[18:20]=b'\x03\x00' if name=='kernel32' else b'\x3e\x00'
                    elf=dest/'fixture.elf';elf.write_bytes(raw)
                    sha=hashlib.sha256(raw).hexdigest()
                    if name=='kernel64s':(dest/'KERNEL64S.BIN').write_bytes(raw)
                    self.assertEqual('-DSHZ_NATIVE_INSTALLER_RELEASE' in flags,name=='kernel64s')
                    return {'elf':elf,'bytes':len(raw),'sha256':sha,'elf_sha256':sha,'commands':[]}
                def stub_model(k32=False):
                    dest=kbuild.BUILD/('kernel32s' if k32 else 'kernel64s')
                    (dest/'boot.elf').write_bytes(b'host stub model')
                    return {'sha256':hashlib.sha256(b'host stub model').hexdigest()}
                def receipt(path,value):
                    self.assertEqual(events,['closed'])
                    self.assertNotIn('custody',value['native_release'])
                    self.assertFalse(value['private_installer']['ISO_generated'])
                    events.append('receipt')
                with patch.object(admission,'admit_for_build',side_effect=modeled_admit), \
                     patch.object(kbuild,'build_kernel',side_effect=compile_model), \
                     patch.object(kbuild,'build_standalone_stub',side_effect=stub_model), \
                     patch.object(kbuild.shzlib,'write_json',side_effect=receipt):
                    with ExitStack() as stack, redirect_stdout(io.StringIO()):
                        if close_error:
                            with self.assertRaisesRegex(ValueError,'mandatory close'):
                                kbuild.build_all(Namespace(out=root/'build',native_release_manifest=root/'model'),
                                                 stack,private_finalize=package.finalize)
                            self.assertEqual(events,['closed'])
                        else:
                            kbuild.build_all(Namespace(out=root/'build',native_release_manifest=root/'model'),
                                             stack,private_finalize=package.finalize)
                            self.assertEqual(events,['closed','receipt'])
                self.assertFalse(custody._active)

    def test_production_absence_creates_no_package(self):
        with tempfile.TemporaryDirectory(dir='/var/tmp') as tmp:
            out=Path(tmp)/'new'
            with self.assertRaisesRegex(ValueError,'anchors absent'):
                package.build_private_installer('/not/a/manifest',out)
            self.assertFalse(out.exists())

    def test_packaging_tool_is_in_actual_kernel_source_receipt(self):
        import importlib.util
        spec=importlib.util.spec_from_file_location('test_package_kbuild',ROOT/'shizukudos/kbuild.py')
        kbuild=importlib.util.module_from_spec(spec);spec.loader.exec_module(kbuild)
        source=kbuild.source_hashes()
        self.assertEqual(source['shizukudos/install/private_installer_package.py'],
                         hashlib.sha256((ROOT/'shizukudos/install/private_installer_package.py').read_bytes()).hexdigest())
        from argparse import Namespace
        with ExitStack() as stack,self.assertRaisesRegex(ValueError,'independent release'):
            kbuild.build_all(Namespace(native_release_manifest=None),stack,private_finalize=lambda *args: {})

if __name__=='__main__':unittest.main()
