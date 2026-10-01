"""Original VxD container, fixup, native dispatch ABI and mock VMM tests.
SPDX-License-Identifier: GPL-2.0-only
"""
import importlib.util
import hashlib
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
BUILD = Path(os.environ.get('NTWV_HOST_TEST_OUT',str(HERE/'build'))).resolve()
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
writer=module('le')
reader=module('inspect_le')


class SourceStabilityTests(unittest.TestCase):
    """Run the real receipt driver against isolated source copies and dummy
    artifacts. These fixtures test attribution, not VxD execution or acceptance.
    No project source/header is mutated by the fixtures."""
    def prepare_fixture(self, root, changed=None, nested=False):
        vxd=root/'ntwrapper/vxd'
        shutil.copytree(HERE,vxd,ignore=shutil.ignore_patterns('build','__pycache__','tests'))
        (vxd/'tests').mkdir()
        for path in (HERE/'tests').iterdir():
            if path.suffix in ('.c','.asm'):
                shutil.copy2(path,vxd/'tests'/path.name)
        shutil.copy2(HERE.parent/'core.c',root/'ntwrapper/core.c')
        shutil.copytree(HERE.parent/'include',root/'ntwrapper/include')
        abi=root/'shizukudos/abi'
        shutil.copytree(HERE.parents[1]/'shizukudos/abi',abi,
                        ignore=shutil.ignore_patterns('build','__pycache__'))
        if nested:
            (abi/'receipt_dependency.h').write_text('/* initial dependency fixture */\n')
            ipc=abi/'shz_ipc.h'
            ipc.write_text('#include "receipt_dependency.h"\n'+ipc.read_text())
        mutation='' if changed is None else (
            f"        target=root/{changed!r}\n"
            "        target.write_bytes(target.read_bytes()+b'\\n/* persistent fixture mutation */\\n')\n")
        (vxd/'tests/test_receipt_fixture.py').write_text(
            'from pathlib import Path\nimport unittest\n'
            'class ReceiptFixture(unittest.TestCase):\n'
            '    def test_fixture(self):\n'
            '        root=Path(__file__).resolve().parents[3]\n'+mutation+
            '        self.assertTrue(root.is_dir())\n')
        out=root/'build/vxd-fixture'
        out.mkdir(parents=True)
        for name in ('NTWRAP9X.VXD','NTWRAP9X.elf','NTWQUERY.EXE'):
            (out/name).write_bytes(('receipt fixture: '+name).encode())
        # Use native-target preprocessing flags and a manifest source set. This
        # fixture emits no native/guest binary and runs no compiled C test.
        sources={str(path.relative_to(root)):hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in root.rglob('*') if path.is_file() and 'build' not in path.relative_to(root).parts
                 and path.name!='receipt_dependency.h'}
        manifest={'sources':sources,'compiler_flags':['--target=i386-unknown-none-elf','-march=i486',
                  '-std=c11','-ffreestanding','-mno-sse','-mno-mmx','-msoft-float'],
                  'sha256':hashlib.sha256((out/'NTWRAP9X.VXD').read_bytes()).hexdigest(),
                  'probe':{'sha256':hashlib.sha256((out/'NTWQUERY.EXE').read_bytes()).hexdigest()}}
        (out/'manifest.json').write_text(json.dumps(manifest))
        return vxd,out

    def run_fixture(self, root, vxd, out):
        result=subprocess.run([sys.executable,'-B',str(vxd/'test.py'),'--out',str(out)],
                              cwd=root,capture_output=True,text=True,timeout=30)
        self.assertTrue((out/'host-tests.json').is_file(),result.stdout+result.stderr)
        return result,json.loads((out/'host-tests.json').read_text())

    def test_receipt_external_header_control_and_persistent_mutations(self):
        for changed in (None,'shizukudos/abi/shz_ipc.h','shizukudos/abi/shz_abi.h'):
            with self.subTest(changed=changed),tempfile.TemporaryDirectory(prefix='ntwv receipt ') as folder:
                root=Path(folder)
                vxd,out=self.prepare_fixture(root,changed)
                original={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in
                          ('shizukudos/abi/shz_ipc.h','shizukudos/abi/shz_abi.h')}
                result,report=self.run_fixture(root,vxd,out)
                self.assertEqual(result.returncode,0 if changed is None else 1,result.stdout+result.stderr)
                self.assertEqual(report['passed'],changed is None)
                self.assertEqual(report['inputs_unchanged_during_test'],changed is None)
                for name,digest in original.items():
                    self.assertEqual(report['hashes'].get(name),digest)
                if changed:
                    self.assertIn(changed,report['changed_inputs'])

    def test_receipt_discovers_nested_project_include_and_rejects_its_drift(self):
        changed='shizukudos/abi/receipt_dependency.h'
        with tempfile.TemporaryDirectory(prefix='ntwv-receipt-nested-') as folder:
            root=Path(folder)
            vxd,out=self.prepare_fixture(root,changed,nested=True)
            original=hashlib.sha256((root/changed).read_bytes()).hexdigest()
            result,report=self.run_fixture(root,vxd,out)
            self.assertEqual(result.returncode,1,result.stdout+result.stderr)
            self.assertFalse(report['passed'])
            self.assertEqual(report['hashes'].get(changed),original)
            self.assertIn(changed,report['changed_inputs'])
            self.assertIn(changed,report['project_dependencies']['native_i486'])
            self.assertIn(changed,report['project_dependencies']['host_w64_asan_ubsan'])

    def test_receipt_preserves_previous_receipt_and_log_before_run(self):
        with tempfile.TemporaryDirectory(prefix='ntwv-receipt-history-') as folder:
            root=Path(folder)
            vxd,out=self.prepare_fixture(root)
            previous=b'{"historical_receipt": true}\n'
            log=b'historical receipt fixture log\n'
            (out/'host-tests.json').write_bytes(previous)
            (out/'host-tests.log').write_bytes(log)
            result,report=self.run_fixture(root,vxd,out)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            self.assertIn('previous_receipt_directory',report)
            history=root/report['previous_receipt_directory']
            self.assertEqual((history/'host-tests.json').read_bytes(),previous)
            self.assertEqual((history/'host-tests.log').read_bytes(),log)

class VxDTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.elf=(BUILD/'NTWRAP9X.elf').read_bytes()
        cls.vxd=(BUILD/'NTWRAP9X.VXD').read_bytes()
        cls.input=writer.read_elf(cls.elf)

    def test_actual_artifact_and_reproducibility(self):
        self.assertEqual(writer.package(self.elf)[0],self.vxd)
        image=reader.inspect(self.vxd)
        self.assertEqual(len(image['objects']),2)
        self.assertGreater(len(image['fixups']),20)
        self.assertEqual(self.vxd[0x40:0x45],b'\xb8\x01\x4c\xcd\x21')
        self.assertEqual(self.input['objects'][1]['data'][:24],image['objects'][1]['memory'][:24])

    def test_real_relocations_at_independent_load_bases(self):
        for bases in ((0xc1000000,0xc3000000),(0x100000,0x400000),(0xff000000,0xfd000000)):
            image=reader.relocate(self.vxd,bases)
            for rel in self.input['relocations']:
                value=struct.unpack_from('<I',image['objects'][rel['object']-1]['memory'],rel['offset'])[0]
                expected=bases[rel['target']-1]+rel['target_offset']
                if rel['relative']:expected=(expected-bases[rel['object']-1]-rel['offset']-4)&0xffffffff
                self.assertEqual(value,expected)
            control=struct.unpack_from('<I',image['objects'][1]['memory'],24)[0]
            self.assertEqual(control,bases[0]+self.input['symbols']['ntwv_control']-self.input['objects'][0]['va'])

    def test_cross_page_fixups_are_emitted_for_both_pages(self):
        objects=[{'size':8192},{'size':16}]
        for offset in (4093,4094,4095):
            relocation={'object':1,'offset':offset,'target':2,'target_offset':4,'relative':False}
            page,records,count=writer.fixup_pages(objects,[relocation])
            self.assertEqual(count,3)
            self.assertEqual(struct.unpack('<4I',page),(0,9,18,18))
            self.assertEqual(struct.unpack_from('<h',records,2)[0],offset)
            self.assertEqual(struct.unpack_from('<h',records,11)[0],offset-4096)
            self.assertEqual(records[0],7)

    def test_reject_unsupported_elf(self):
        for at,value in ((4,2),(5,2),(16,1),(18,62)):
            data=bytearray(self.elf);data[at]=value
            with self.assertRaises(writer.FormatError):writer.package(bytes(data))
        for length in (0,16,51,len(self.elf)-1):
            with self.assertRaises(writer.FormatError):writer.package(self.elf[:length])
        data=bytearray(self.elf)
        shoff=struct.unpack_from('<I',data,32)[0];count=struct.unpack_from('<H',data,48)[0]
        for i in range(count):
            at=shoff+i*40
            if struct.unpack_from('<I',data,at+4)[0]==9:
                record=struct.unpack_from('<I',data,at+16)[0]
                data[record+4]=255
                break
        with self.assertRaisesRegex(writer.FormatError,'relocation type'):writer.package(bytes(data))

    def test_reject_damaged_le(self):
        base=0x80
        cases=[(0,0),(base,0),(base+0x10,1),(base+0x29,0),(base+0x44,255),(base+0xc2,0)]
        for at,value in cases:
            data=bytearray(self.vxd);data[at]=value
            with self.assertRaises(reader.LEError):reader.inspect(data)
        record=base+struct.unpack_from('<I',self.vxd,base+0x6c)[0]
        for at,value in ((record,3),(record+1,0),(record+4,0),(record+8,255)):
            data=bytearray(self.vxd);data[at]=value
            with self.assertRaises(reader.LEError):reader.inspect(data)
        for length in (0,64,128,256,len(self.vxd)-1):
            with self.assertRaises(reader.LEError):reader.inspect(self.vxd[:length])
        with self.assertRaises(reader.LEError):reader.relocate(self.vxd,(0xc0000000,0xc0000000))

    def test_exact_object_flags_reject_resident_missing_shared_and_permissions(self):
        base=struct.unpack_from('<I',self.vxd,60)[0]
        table=base+struct.unpack_from('<I',self.vxd,base+64)[0]
        for obj,expected in enumerate((0x2065,0x2063)):
            at=table+obj*24+8
            self.assertEqual(struct.unpack_from('<I',self.vxd,at)[0],expected)
            candidates={expected^(1<<bit) for bit in range(32)}
            candidates.update((0x2245,0x2243,0x2265,0x2263,0x2045,0x2043,
                               0x2063 if obj==0 else 0x2065))
            candidates.discard(expected)
            for flags in candidates:
                with self.subTest(object=obj,flags=hex(flags)):
                    data=bytearray(self.vxd);struct.pack_into('<I',data,at,flags)
                    with self.assertRaisesRegex(reader.LEError,'object permissions'):
                        reader.inspect(data)

    def test_bounded_elf_and_le_mutations_raise_only_format_errors(self):
        rng=random.Random(98)
        for original,parser,error in ((self.elf,writer.read_elf,writer.FormatError),(self.vxd,reader.inspect,reader.LEError)):
            for _ in range(500):
                data=bytearray(original);where=rng.randrange(len(data));data[where]^=rng.randrange(1,256)
                try:parser(data)
                except error:pass

    def test_native_vmm_import_constants_and_no_undefined_symbols(self):
        code=self.input['objects'][0]['data']
        for number in (0x10061,0x10063,0x10064,0x10067,0x1006c):
            self.assertEqual(code.count(b'\xcd\x20'+struct.pack('<I',number)),1)
        self.assertIn(b'\x9c\x60\xfc',code) # preserve flags/GPRs and clear DF
        self.assertEqual(code.count(b'\x0f\x01\xc1'),1) # exactly one VMCALL: the guarded hypercall thunk
        self.assertEqual(code.count(b'\x0f\xa2'),1) # exactly one CPUID: the hypervisor signature probe
        symbols=subprocess.check_output(['nm','-u',str(BUILD/'NTWRAP9X.elf')],text=True)
        self.assertEqual(symbols.strip(),'')

    def test_guest_probe_pe_contract(self):
        data=(BUILD/'NTWQUERY.EXE').read_bytes()
        pe=struct.unpack_from('<I',data,0x3c)[0]
        self.assertEqual(data[pe:pe+4],b'PE\0\0')
        self.assertEqual(struct.unpack_from('<H',data,pe+4)[0],0x14c)
        self.assertEqual(struct.unpack_from('<I',data,pe+8)[0],0)
        optional=pe+24
        self.assertEqual(struct.unpack_from('<H',data,optional)[0],0x10b)
        self.assertEqual(struct.unpack_from('<2H',data,optional+40),(4,10))
        self.assertEqual(struct.unpack_from('<2H',data,optional+48),(4,10))
        self.assertEqual(struct.unpack_from('<H',data,optional+68)[0],3)
        self.assertEqual(struct.unpack_from('<H',data,optional+70)[0]&0x8140,0)
        dump=subprocess.check_output(['i686-w64-mingw32-objdump','-p',str(BUILD/'NTWQUERY.EXE')],text=True)
        imports=[line.strip() for line in dump.splitlines() if 'DLL Name:' in line]
        self.assertEqual(imports,['DLL Name: KERNEL32.dll'])
        self.assertIn('DeviceIoControl',dump)
        self.assertIn(b'\\\\.\\NTWRAP9X.VXD\0',data)

    def test_native_control_dispatch_abi_in_i386_user_harness(self):
        subprocess.run(['nasm','-f','elf32',str(HERE/'tests/control_harness.asm'),'-o',str(BUILD/'control_harness.o')],check=True)
        subprocess.run(['ld','-m','elf_i386','-o',str(BUILD/'control_harness'),str(BUILD/'control.o'),str(BUILD/'control_harness.o')],check=True)
        result=subprocess.run([str(BUILD/'control_harness')])
        self.assertEqual(result.returncode,0)

    def test_page_failure_cleanup_and_lifecycle_under_sanitizers(self):
        command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wpedantic','-Wconversion','-Wshadow',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer',str(HERE/'bridge.c'),str(HERE.parent/'core.c'),
                 str(HERE/'tests/test_bridge.c'),'-o',str(BUILD/'test_bridge')]
        subprocess.run(command,check=True)
        result=subprocess.run([str(BUILD/'test_bridge')],check=True,capture_output=True,text=True)
        self.assertIn('every VMM-call failure unwound',result.stdout)
        print(result.stdout.strip())

    def test_win64_bridge_dioc_against_kernel64_wire_library_under_sanitizers(self):
        command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wpedantic','-Wshadow',
                 '-fsanitize=address,undefined','-fno-omit-frame-pointer',str(HERE/'bridge.c'),str(HERE.parent/'core.c'),
                 str(HERE/'tests/test_w64vxd.c'),'-o',str(BUILD/'test_w64vxd')]
        subprocess.run(command,check=True)
        result=subprocess.run([str(BUILD/'test_w64vxd')],check=True,capture_output=True,text=True)
        self.assertIn('PASS: VxD WIN64 bridge',result.stdout)
        print(result.stdout.strip())
        for case in ('reentrant', 'layout', 'epoch', 'live-layout', 'duplicate',
                     'responses', 'corrupt-head', 'corrupt-ring'):
            with self.subTest(case=case):
                result=subprocess.run([str(BUILD/'test_w64vxd'),case],check=True,
                                      capture_output=True,text=True,timeout=10)
                self.assertIn('PASS: VxD WIN64 regression '+case,result.stdout)
                print(result.stdout.strip())

    def test_parallel_win64_admission_under_sanitizers(self):
        for suffix,sanitizer in (('asan','address,undefined'),('tsan','thread')):
            with self.subTest(sanitizer=sanitizer):
                binary=BUILD/('test_w64_admission_'+suffix)
                command=['clang','-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wpedantic','-Wshadow',
                         '-fsanitize='+sanitizer,'-fno-omit-frame-pointer','-pthread',
                         str(HERE/'bridge.c'),str(HERE.parent/'core.c'),str(HERE/'tests/test_w64_admission.c'),
                         '-o',str(binary)]
                subprocess.run(command,check=True)
                result=subprocess.run([str(binary)],check=True,capture_output=True,text=True,timeout=10)
                self.assertIn('PASS: VxD parallel admission',result.stdout)
                self.assertIn('PASS: VxD shutdown-versus-entry 128 externally initialized rounds',result.stdout)
                print(suffix+': '+result.stdout.strip())

if __name__=='__main__':unittest.main()
