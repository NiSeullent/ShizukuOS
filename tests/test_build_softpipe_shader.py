# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('softpipe_builder',Path(__file__).resolve().parents[1]/'tools/build_softpipe_shader.py')
builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
gate=builder.instruction_gate()
class InstructionGate(unittest.TestCase):
 def test_exact_complete_section(self):
  row=gate.decode('Disassembly of section .text:\n401000: 90 nop\n401001: c3 ret', {'.text':{'address':0x401000,'data':b'\x90\xc3'}})
  self.assertEqual(row['instructions_decoded'],2)
  self.assertEqual(row['executable_sections']['.text']['decoded_bytes'],2)
 def test_cross_newline_control(self):
  for op in ('mfence','vzeroupper','ud2','cpuid','fcomip %st(1),%st','lock cmpxchg8b (%eax)','emms','mystery'):
   with self.subTest(op=op),self.assertRaises(ValueError):gate.decode('401000: 90 nop\n401001: 90 '+op)
 def test_missing_modified_extra_bytes_reject(self):
  for text in ('Disassembly of section .text:\n401000: 90 nop','Disassembly of section .text:\n401000: 90 nop\n401002: c3 ret','Disassembly of section .text:\n401000: 90 nop\n401001: 90 nop','Disassembly of section .text:\n401000: 90 nop\n401001: c3 ret\n401002: 90 nop'):
   with self.subTest(text=text),self.assertRaises(ValueError):gate.decode(text,{'.text':{'address':0x401000,'data':b'\x90\xc3'}})
 def test_both_executable_sections_required(self):
  with self.assertRaises(ValueError):gate.decode('Disassembly of section .text:\n401000: c3 ret', {'.text':{'address':0x401000,'data':b'\xc3'},'.other':{'address':0x402000,'data':b'\xc3'}})
 def test_empty_and_foreign_section_reject(self):
  with self.assertRaises(ValueError):gate.decode('')
  with self.assertRaises(ValueError):gate.decode('Disassembly of section .other:\n401000: c3 ret',{'.text':{'address':0x401000,'data':b'\xc3'}})
if __name__=='__main__':unittest.main()
