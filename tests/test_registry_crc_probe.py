# SPDX-License-Identifier: GPL-2.0-only
"""Execute actual NASM COM bytes in Unicorn; INT21 file I/O is modeled only.

Dependency: official https://www.unicorn-engine.org/docs/ Python binding,
unicorn==2.1.4 in an isolated environment. No Windows/VM runtime claim.
Run: <venv>/bin/python tests/test_registry_crc_probe.py
"""
import pathlib
import subprocess
import tempfile
import unittest
import zlib

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
    from unicorn.x86_const import (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX,
        UC_X86_REG_DX, UC_X86_REG_DS, UC_X86_REG_CS, UC_X86_REG_ES,
        UC_X86_REG_SS, UC_X86_REG_SP, UC_X86_REG_EFLAGS)
except ModuleNotFoundError as error:
    if error.name != 'unicorn':
        raise
    Uc = None

SYSTEM = r'C:\WINDOWS\SYSTEM.DAT'
USER = r'C:\WINDOWS\USER.DAT'
REPORT = r'C:\REGCRC.TXT'


class DOSModel:
    """Exclusive report creation, readonly input handles, bounded synthetic I/O."""
    def __init__(self, com, files, *, exists=False, short_write=False,
                 read_error=False, size_delta=0, open_error=False,
                 seek_error=False, oversized_read=False, commit_error=False):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1 << 20)
        self.uc.mem_write(0x10100, com)
        for register in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES,
                         UC_X86_REG_SS):
            self.uc.reg_write(register, 0x1000)
        self.uc.reg_write(UC_X86_REG_SP, 0xfffe)
        self.files = files
        self.exists, self.short_write = exists, short_write
        self.read_error, self.size_delta = read_error, size_delta
        self.open_error, self.seek_error = open_error, seek_error
        self.oversized_read, self.commit_error = oversized_read, commit_error
        self.handles = {}
        self.output = bytearray()
        self.events = []
        self.exit = None
        self.uc.hook_add(UC_HOOK_INTR, self.interrupt)

    def reg(self, name):
        return self.uc.reg_read(name) & 0xffff

    def address(self):
        return self.reg(UC_X86_REG_DS) * 16 + self.reg(UC_X86_REG_DX)

    def string(self):
        raw = bytes(self.uc.mem_read(self.address(), 260))
        assert b'\0' in raw, 'bounded DOS path required'
        return raw.split(b'\0', 1)[0].decode('ascii')

    def result(self, ax=0, *, error=False, dx=None):
        self.uc.reg_write(UC_X86_REG_AX, ax)
        if dx is not None:
            self.uc.reg_write(UC_X86_REG_DX, dx)
        flags = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.uc.reg_write(UC_X86_REG_EFLAGS, (flags | 1) if error else (flags & ~1))

    def interrupt(self, uc, number, _):
        assert number == 0x21, 'only modeled DOS INT21 allowed'
        ax, bx, cx = map(self.reg, (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX))
        ah, al = ax >> 8, ax & 255
        self.events.append((ah, al, bx, cx))
        assert len(self.events) <= 10000, 'bounded DOS call count'
        if ah == 0x5b:
            assert al == 0 and self.string() == REPORT and cx == 0
            if self.exists:
                self.result(80, error=True)
            else:
                self.handles[5] = ('report', 0)
                self.result(5)
        elif ah == 0x3d:
            assert al == 0, 'Windows input must be opened readonly'
            name = self.string()
            assert name in (SYSTEM, USER), 'no unrelated registry access'
            if self.open_error or name not in self.files:
                self.result(2, error=True)
            else:
                self.handles[6] = (name, 0)
                self.result(6)
        elif ah == 0x42:
            name, at = self.handles[bx]
            assert name != 'report' and cx == 0 and self.reg(UC_X86_REG_DX) == 0
            assert al in (0, 2)
            if self.seek_error:
                self.result(1, error=True)
            else:
                at = len(self.files[name]) + self.size_delta if al == 2 else 0
                self.handles[bx] = (name, at)
                self.result(at & 65535, dx=at >> 16)
        elif ah == 0x3f:
            name, at = self.handles[bx]
            assert name != 'report' and cx == 1024
            if self.read_error:
                self.result(5, error=True)
            elif self.oversized_read:
                self.result(1025)
            else:
                chunk = self.files[name][at:at + cx]
                uc.mem_write(self.address(), chunk)
                self.handles[bx] = (name, at + len(chunk))
                self.result(len(chunk))
        elif ah == 0x40:
            assert self.handles[bx][0] == 'report', 'no Windows writes'
            count = max(0, cx - 1) if self.short_write else cx
            self.output.extend(uc.mem_read(self.address(), count))
            self.result(count)
        elif ah == 0x3e:
            assert bx in self.handles, 'close only owned handles'
            del self.handles[bx]
            self.result()
        elif ah == 0x68:
            assert self.handles[bx][0] == 'report'
            self.result(5 if self.commit_error else 0, error=self.commit_error)
        elif ah == 0x4c:
            self.exit = al
            uc.emu_stop()
        else:
            raise AssertionError('unmodeled DOS operation %02x' % ah)

    def run(self):
        self.uc.emu_start(0x10100, 0x20000, timeout=10_000_000, count=50_000_000)
        assert self.exit is not None, 'instruction/time budget exhausted before DOS exit'
        assert not self.handles, 'owned handles must close on every result'
        return self.exit, self.output.decode('ascii')


@unittest.skipUnless(Uc is not None, 'requires isolated unicorn==2.1.4 environment')
class ActualCOMControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix='registry-com-')
        out = pathlib.Path(cls.directory.name) / 'REGREAD.COM'
        source = pathlib.Path(__file__).resolve().parents[1] / 'shizukudos/dos16/probes/registry_crc.asm'
        subprocess.run(['nasm', '-f', 'bin', '-Wall', '-Werror', '-o', str(out), str(source)], check=True)
        cls.com = out.read_bytes()
        assert 0 < len(cls.com) < 65536 - 256

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def model(self, **options):
        return DOSModel(self.com, {SYSTEM: b'123456789', USER: b''}, **options)

    def test_known_crc_empty_and_readonly_inputs(self):
        model = self.model()
        code, output = model.run()
        self.assertEqual(code, 0)
        self.assertEqual(output, SYSTEM + ' seek_bytes=00000009 read_bytes=00000009 crc32=CBF43926\r\n' + USER + ' seek_bytes=00000000 read_bytes=00000000 crc32=00000000\r\n')
        self.assertTrue(all(al == 0 for ah, al, _, _ in model.events if ah == 0x3d))

    def test_over_64k_seek_high_word_and_sequential_crc(self):
        data = bytes(range(256)) * 277 + b'tail'
        model = DOSModel(self.com, {SYSTEM: data, USER: b''})
        code, output = model.run()
        self.assertEqual(code, 0)
        self.assertIn('seek_bytes=%08X read_bytes=%08X crc32=%08X' % (len(data), len(data), zlib.crc32(data)), output)

    def test_existing_report_refuses_before_input_open(self):
        model = self.model(exists=True)
        self.assertEqual(model.run(), (2, ''))
        self.assertFalse(any(ah == 0x3d for ah, *_ in model.events))

    def test_short_output_write_refuses(self):
        self.assertEqual(self.model(short_write=True).run()[0], 2)

    def test_read_error_is_failure_and_closes_inputs(self):
        code, output = self.model(read_error=True).run()
        self.assertEqual(code, 1)
        self.assertEqual(output.count('DOS_ERROR=00000005'), 2)

    def test_seek_read_size_disagreement_refuses(self):
        self.assertEqual(self.model(size_delta=1).run()[0], 2)

    def test_open_error_not_promoted_to_success(self):
        code, output = self.model(open_error=True).run()
        self.assertEqual(code, 1)
        self.assertEqual(output.count('DOS_ERROR=00000002'), 2)

    def test_seek_error_closes_owned_input(self):
        self.assertEqual(self.model(seek_error=True).run()[0], 1)

    def test_oversized_read_and_commit_error_refuse(self):
        self.assertEqual(self.model(oversized_read=True).run()[0], 2)
        self.assertEqual(self.model(commit_error=True).run()[0], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
