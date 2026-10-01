# SPDX-License-Identifier: GPL-2.0-or-later
"""Execute the real NASM TSR hook in a bounded host-only CPU emulator.

Requires optional test dependency unicorn==2.1.4. No BIOS, DOS, Windows binary,
VM, disk image or network is executed. A tiny original IRET fixture stands in
for the next interrupt handler, changing return registers/FLAGS deliberately.
"""
import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE, UC_HOOK_INSN
    from unicorn import x86_const as xc
except ImportError:
    raise unittest.SkipTest('optional host CPU controls require unicorn==2.1.4')

BASE=Path(__file__).resolve().parents[1]
ASM=BASE/'trace/dosvmm_trace.asm'
REG_NAMES=('EAX','EBX','ECX','EDX','ESI','EDI','EBP','DS','ES')
REG_IDS=tuple(getattr(xc,'UC_X86_REG_'+name) for name in REG_NAMES)
INPUT=(0x12341607,0x23450015,0x34560001,0x4567001f,0x56781357,0x67892468,0x789a3579,0x6100,0x6200)
OUTPUT=(0xa123b97c,0xb2340000,0xc3450001,0xd456a2ab,0xe567abcd,0xf678bcde,0x897acdef,0x7100,0x7200)

class TraceMachine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='shz-vmm-cpu-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.tree=Path(cls.temp.name)
        cls.com=cls.tree/'DOSVMM.COM'
        subprocess.run(['nasm','-f','bin','-w+all','-Werror','-o',str(cls.com),str(ASM)],check=True,capture_output=True)
        cls.blob=cls.com.read_bytes()
        fixture=cls.tree/'symbols.asm'
        fixture.write_text(ASM.read_text()+'\nfixture_symbols: dw handler,old2f,next_id,resident_end,install\n')
        fixture_com=fixture.with_suffix('.com')
        subprocess.run(['nasm','-f','bin','-w+all','-Werror','-o',str(fixture_com),str(fixture)],check=True,capture_output=True)
        fixture_bytes=fixture_com.read_bytes()
        if fixture_bytes[:-10]!=cls.blob:
            raise ValueError('symbol fixture changed production TSR bytes')
        cls.handler,cls.old2f,cls.counter,_,_=struct.unpack('<5H',fixture_bytes[-10:])
        spec=importlib.util.spec_from_file_location('trace_parser_cpu',BASE/'trace/parse_trace.py')
        cls.parser=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.parser)

    def execute(self, original_flags, returned_flags, *, selected=True, budget_full=False, mutate=True):
        mu=Uc(UC_ARCH_X86,UC_MODE_16)
        mu.mem_map(0,1024*1024)
        cs,old_cs,caller_cs,ss=0x2000,0x3000,0x4000,0x5000
        sp=0xff00
        mu.mem_write((cs<<4)+0x100,self.blob)
        mu.mem_write((cs<<4)+self.old2f,struct.pack('<HH',0x100,old_cs))
        if budget_full:
            mu.mem_write((cs<<4)+self.counter,struct.pack('<H',4096))
        next_source='bits 16\norg 0x100\npush bp\nmov bp,sp\nmov word [ss:bp+6],%d\npop bp\n' % returned_flags
        values=OUTPUT if mutate else INPUT
        if not selected:
            values=(values[0]&0xffff0000|0x1234,*values[1:])
        next_source+='mov ax,%d\nmov ds,ax\nmov ax,%d\nmov es,ax\n' % values[-2:]
        for name,value in zip(REG_NAMES[:7],values[:7]):
            next_source+='mov %s,0x%x\n' % (name.lower(),value)
        next_source+='iret\n'
        fixture=self.tree/'next.asm'
        fixture.write_text(next_source)
        next_com=fixture.with_suffix('.com')
        subprocess.run(['nasm','-f','bin','-w+all','-Werror','-o',str(next_com),str(fixture)],check=True,capture_output=True)
        mu.mem_write((old_cs<<4)+0x100,next_com.read_bytes())
        mu.mem_write((caller_cs<<4)+0x100,b'\x90')
        mu.mem_write((ss<<4)+sp,struct.pack('<HHH',0x100,caller_cs,original_flags))
        inputs=INPUT if selected else (INPUT[0]&0xffff0000|0x1234,*INPUT[1:])
        for reg,value in zip(REG_IDS,inputs):
            mu.reg_write(reg,value)
        mu.reg_write(xc.UC_X86_REG_CS,cs)
        mu.reg_write(xc.UC_X86_REG_SS,ss)
        mu.reg_write(xc.UC_X86_REG_ESP,0xabcd0000|sp)
        mu.reg_write(xc.UC_X86_REG_EFLAGS,original_flags & ~0x300)
        trace=bytearray()
        reached=[]
        def output(cpu,port,size,value,_):
            self.assertEqual((port,size),(0xe9,1))
            trace.append(value)
        def code(cpu,address,size,_):
            if address==(old_cs<<4)+0x100:
                observed=tuple(cpu.reg_read(reg) for reg in REG_IDS)
                self.assertEqual(observed,inputs,'old handler input registers changed')
                current_sp=cpu.reg_read(xc.UC_X86_REG_SP)
                chain_flags=struct.unpack('<H',cpu.mem_read((ss<<4)+current_sp+4,2))[0]
                self.assertEqual(chain_flags,original_flags,'old handler lost caller interrupt-frame FLAGS')
            if address==(caller_cs<<4)+0x100:
                reached.append(True)
                cpu.emu_stop()
        mu.hook_add(UC_HOOK_CODE,code)
        mu.hook_add(UC_HOOK_INSN,output,None,1,0,xc.UC_X86_INS_OUT)
        mu.emu_start((cs<<4)+self.handler,1024*1024,timeout=200000,count=20000)
        self.assertTrue(reached,'bounded CPU execution never returned to the caller')
        self.assertEqual(tuple(mu.reg_read(reg) for reg in REG_IDS),values,'returned registers changed')
        self.assertEqual(mu.reg_read(xc.UC_X86_REG_ESP),0xabcd0000|((sp+6)&0xffff),'caller stack pointer changed')
        self.assertEqual(mu.reg_read(xc.UC_X86_REG_EFLAGS)&0xffff,returned_flags,'returned FLAGS changed')
        self.assertEqual(mu.reg_read(xc.UC_X86_REG_SS),ss)
        self.assertEqual(mu.reg_read(xc.UC_X86_REG_CS),caller_cs)
        if selected and not budget_full:
            result=self.parser.parse(bytes(trace),'windows98-original-control')
            self.assertEqual(result['completed_calls'],1)
            self.assertFalse(result['native_Windows98_complete'])
            lines=bytes(trace).splitlines()
            entry=[int(x,16) for x in lines[0].split()[2:]]
            returned=[int(x,16) for x in lines[1].split()[2:]]
            self.assertEqual(entry[-1],original_flags)
            self.assertEqual(returned[-1],returned_flags)
            self.assertEqual(entry[1:],[inputs[0]&0xffff,inputs[1]&0xffff,inputs[2]&0xffff,inputs[3]&0xffff,inputs[7],inputs[4]&0xffff,inputs[8],inputs[5]&0xffff,inputs[6]&0xffff,original_flags])
            self.assertEqual(returned[1:],[values[0]&0xffff,values[1]&0xffff,values[2]&0xffff,values[3]&0xffff,values[7],values[4]&0xffff,values[8],values[5]&0xffff,values[6]&0xffff,returned_flags])
        else:
            self.assertEqual(trace,b'')

    def test_selected_chain_preserves_original_and_changed_return_flags(self):
        for original in (0x0002,0x0202,0x0243,0x0603,0x0e93):
            for returned in (original,original^0x0201,original^0x0400):
                with self.subTest(original=original,returned=returned):
                    self.execute(original,returned)

    def test_no_change_old_handler_and_unselected_budget_paths(self):
        for flags in (0x0002,0x0203,0x0643):
            with self.subTest(flags=flags):
                self.execute(flags,flags,mutate=False)
                self.execute(flags,flags,selected=False)
                self.execute(flags,flags,budget_full=True)

if __name__=='__main__':
    unittest.main()
