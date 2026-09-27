"""Original VxD container, fixup, native dispatch ABI and mock VMM tests.
SPDX-License-Identifier: GPL-2.0-only
"""
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import unittest

HERE = Path(__file__).resolve().parents[1]
BUILD = HERE/'build'
def module(name):
    spec=importlib.util.spec_from_file_location(name,HERE/(name+'.py'))
    result=importlib.util.module_from_spec(spec);spec.loader.exec_module(result);return result
writer=module('le')
reader=module('inspect_le')

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

    def test_bounded_elf_and_le_mutations_raise_only_format_errors(self):
        rng=random.Random(98)
        for original,parser,error in ((self.elf,writer.read_elf,writer.FormatError),(self.vxd,reader.inspect,reader.LEError)):
            for _ in range(500):
                data=bytearray(original);where=rng.randrange(len(data));data[where]^=rng.randrange(1,256)
                try:parser(data)
                except error:pass

    def test_native_vmm_import_constants_and_no_undefined_symbols(self):
        code=self.input['objects'][0]['data']
        for number in (0x10061,0x10063,0x10064,0x10067):
            self.assertEqual(code.count(b'\xcd\x20'+struct.pack('<I',number)),1)
        self.assertIn(b'\x9c\x60\xfc',code) # preserve flags/GPRs and clear DF
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

if __name__=='__main__':unittest.main()
