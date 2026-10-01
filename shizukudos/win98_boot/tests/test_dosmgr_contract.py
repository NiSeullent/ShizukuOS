# SPDX-License-Identifier: GPL-2.0-or-later
"""Compile the actual patched DOSMGR cases, never a second implementation.

SHZ_FREEDOS_SOURCE selects an already pinned public FreeDOS checkout. Tests copy
one source file to a temporary directory; they never mutate that checkout.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
PATCH = ROOT / 'shizukudos/dos16/patches/0003-dosmgr-honest-contract.patch'
PIN = '0793e3bb94c558b6fdeb335f9e15577486b4b6ae53e987c89c095909fb363727'

class DosmgrContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(os.environ.get('SHZ_FREEDOS_SOURCE', ROOT / 'build/upstream/freedos-kernel'))
        original = (source / 'kernel/inthndlr.c').read_bytes()
        if hashlib.sha256(original).hexdigest() != PIN:
            raise ValueError('FreeDOS inthndlr.c does not match the pinned ke2046 source')
        cls.temp = tempfile.TemporaryDirectory(prefix='shz-dosmgr-contract-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.tree = Path(cls.temp.name)
        (cls.tree / 'kernel').mkdir()
        (cls.tree / 'kernel/inthndlr.c').write_bytes(original)
        if PATCH.exists():
            subprocess.run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(PATCH)],
                           cwd=cls.tree, check=True, capture_output=True)
        patched = (cls.tree / 'kernel/inthndlr.c').read_text()
        section = patched.split('case 0x07:          /* DOSMGR Virtual Device API */', 1)[1]
        cls.cases = {}
        for number in (1, 3, 4):
            match = re.search(r'case 0x0' + str(number) + r':.*?(?=\n            case 0x0[0-9]:)', section, re.S)
            if not match:
                raise ValueError('DOSMGR case extraction failed')
            cls.cases[number] = match.group(0)
        import ctypes
        cls.ctypes = ctypes
        class Registers(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint16) for name in ('AX','BX','CX','DX','DS','SI','ES','DI','BP','FLAGS')]
        cls.Registers = Registers
        cls.libs = []
        for cds_bytes in (67, 88):
            code = '#include <stdint.h>\nstruct cds { unsigned char bytes[' + str(cds_bytes) + ']; };\n'
            code += 'struct regs { uint16_t AX,BX,CX,DX,DS,SI,ES,DI,BP,FLAGS; };\n'
            code += 'void dispatch(struct regs *pr) {\n#define r (*pr)\nswitch(r.CX) {\n'
            code += '\n'.join(cls.cases.values()) + '\n} }\n'
            cpath = cls.tree / ('contract-' + str(cds_bytes) + '.c')
            sopath = cpath.with_suffix('.so')
            cpath.write_text(code)
            subprocess.run(['gcc','-std=c89','-Wall','-Wextra','-Werror','-shared','-fPIC',str(cpath),'-o',str(sopath)], check=True, capture_output=True)
            lib = ctypes.CDLL(str(sopath))
            lib.dispatch.argtypes = [ctypes.POINTER(Registers)]
            cls.libs.append((cds_bytes, lib))

    def dispatch(self, lib, function, dx):
        regs = self.Registers(0x1607,0x15,function,dx,0x1357,0x2468,0x3579,0x468a,0x579b,0x8243)
        before = bytes(regs)
        lib.dispatch(self.ctypes.byref(regs))
        return regs, self.Registers.from_buffer_copy(before)

    def test_all_unproved_patch_bits_are_reported_as_unapplied(self):
        lib = self.libs[0][1]
        for requested in range(65536):
            result, expected = self.dispatch(lib,1,requested)
            expected.AX, expected.BX, expected.DX = 0xb97c,0,0xa2ab
            self.assertEqual(bytes(result), bytes(expected), 'patch request %04x' % requested)

    def test_only_single_cds_request_has_a_real_size(self):
        for cds_bytes, lib in self.libs:
            for requested in range(65536):
                result, expected = self.dispatch(lib,3,requested)
                if requested == 1:
                    expected.AX, expected.CX, expected.DX = 0xb97c,cds_bytes,0xa2ab
                else:
                    expected.CX = 0
                self.assertEqual(bytes(result),bytes(expected), 'CDS size %d request %04x' % (cds_bytes,requested))

    def test_instancing_does_not_falsely_return_success_signature(self):
        for _, lib in self.libs:
            for dx in (0,1,2,15,0x8000,0xffff):
                result, expected = self.dispatch(lib,4,dx)
                expected.CX, expected.DX = 0,0
                self.assertEqual(bytes(result),bytes(expected))

    def test_unknown_function_preserves_the_register_frame(self):
        for _, lib in self.libs:
            for function in (6,0x80,0xffff):
                result, expected = self.dispatch(lib,function,0xabcd)
                self.assertEqual(bytes(result), bytes(expected))

if __name__ == '__main__':
    unittest.main()
