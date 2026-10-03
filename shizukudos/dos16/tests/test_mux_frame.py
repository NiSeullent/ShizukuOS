# SPDX-License-Identifier: GPL-2.0-only
"""Execute the actual COM in bounded Unicorn; arbitrary DOS replies, no Windows.

Run with the existing isolated Unicorn runtime. No packages are installed here.
"""
import pathlib
import struct
import subprocess
import tempfile
import unittest

from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
from unicorn.x86_const import (
    UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
    UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_SP,
    UC_X86_REG_EFLAGS,
)

SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'probes/mux_frame.asm'
REGS = (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX,
        UC_X86_REG_SI, UC_X86_REG_DI, UC_X86_REG_BP, UC_X86_REG_DS,
        UC_X86_REG_ES)
ORDER = ((0x1611, 0), (0x1611, 1), (0x1613, 0), (0x1613, 1))


class Model:
    def __init__(self, com, replies, *, payload=None, damage=None,
                 short_write=False, write_error=False, argument=b''):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1 << 20)
        self.uc.mem_write(0x10100, com)
        self.uc.mem_write(0x10080, bytes([len(argument)]) + argument + b'\r')
        for reg in (UC_X86_REG_CS, UC_X86_REG_SS, UC_X86_REG_DS, UC_X86_REG_ES):
            self.uc.reg_write(reg, 0x1000)
        self.uc.reg_write(UC_X86_REG_SP, 0xfffe)
        self.replies = replies
        self.payload = payload
        self.damage = damage
        self.short_write = short_write
        self.write_error = write_error
        self.calls = []
        self.dos = []
        self.output = bytearray()
        self.exit = None
        self.uc.hook_add(UC_HOOK_INTR, self.interrupt)

    def frame(self):
        return [self.uc.reg_read(r) & 0xffff for r in REGS] + [
            self.uc.reg_read(UC_X86_REG_EFLAGS) & 0xffff]

    def interrupt(self, uc, number, _):
        if number == 0x2f:
            before = self.frame()
            at = len(self.calls)
            assert at < 4, 'observer is bounded to four calls'
            ax, carry = ORDER[at]
            assert (before[0], before[-1] & 1) == (ax, carry)
            assert before[3] == (0 if ax == 0x1611 else 0xd3d3)
            assert before[7] != before[8]
            assert before[7] != uc.reg_read(UC_X86_REG_SS)
            assert before[8] != uc.reg_read(UC_X86_REG_SS)
            address = before[8] * 16 + (2 if ax == 0x1611 else before[5])
            assert bytes(uc.mem_read(address - 2, 2)) == b'\xa5\x5a'
            assert bytes(uc.mem_read(address + 80, 2)) == b'\x5a\xa5'
            assert bytes(uc.mem_read(address, 80)) == b'\xa6' * 80
            if ax == 0x1613:
                assert before[2] == 80 and before[5] == 2
                if self.payload is not None:
                    assert len(self.payload) <= 80
                    uc.mem_write(address, self.payload)
                if self.damage == 'before': uc.mem_write(address - 2, b'\x34\x12')
                if self.damage == 'after': uc.mem_write(address + 80, b'\x78\x56')
            values = self.replies[at]
            assert len(values) == 10
            for reg, value in zip(REGS, values):
                uc.reg_write(reg, value)
            uc.reg_write(UC_X86_REG_EFLAGS, values[-1])
            self.calls.append((before, self.frame()))
            return
        assert number == 0x21, 'unexpected interrupt'
        ax = uc.reg_read(UC_X86_REG_AX) & 0xffff
        self.dos.append(ax >> 8)
        if ax >> 8 == 0x40:
            assert uc.reg_read(UC_X86_REG_BX) == 1, 'only stdout may be written'
            count = uc.reg_read(UC_X86_REG_CX)
            assert 0 < count <= 64
            address = uc.reg_read(UC_X86_REG_DS) * 16 + uc.reg_read(UC_X86_REG_DX)
            flags = uc.reg_read(UC_X86_REG_EFLAGS)
            if self.write_error:
                uc.reg_write(UC_X86_REG_AX, 5)
                uc.reg_write(UC_X86_REG_EFLAGS, flags | 1)
            else:
                written = count - 1 if self.short_write else count
                self.output.extend(uc.mem_read(address, written))
                uc.reg_write(UC_X86_REG_AX, written)
                uc.reg_write(UC_X86_REG_EFLAGS, flags & ~1)
        elif ax >> 8 == 0x4c:
            self.exit = ax & 255
            uc.emu_stop()
        else:
            raise AssertionError('file/vector/EXEC services forbidden: ' + hex(ax))

    def run(self):
        self.uc.emu_start(0x10100, 1 << 20, count=100000, timeout=1_000_000)
        assert self.exit is not None, 'bounded execution did not exit'
        return self

    def rows(self):
        lines = self.output.decode('ascii').splitlines()
        assert lines[0] == 'MUXFRAME V1 AX BX CX DX SI DI BP DS ES FLAGS'
        assert lines[-1] == 'END 0004'
        assert len(lines) == 14
        result = []
        for at in range(1, 13, 3):
            parsed = []
            for tag, line, size in zip(('IN', 'OUT', 'BUF'), lines[at:at + 3], (10, 10, 5)):
                tokens = line.split()
                assert tokens[0] == tag and len(tokens) == size + 1
                assert all(len(token) == 4 for token in tokens[1:])
                parsed.append([int(token, 16) for token in tokens[1:]])
            result.append(parsed)
        return result


def replies(seed=0):
    # Deliberately arbitrary; AX/status and pointers are not Windows expectations.
    flags = (0x0003, 0x0ed6, 0x0046, 0x0e93)
    return [[((seed + 0x1111 * (i + 1) + 0x121 * j) & 0xffff)
             for j in range(9)] + [flags[i]] for i in range(4)]


class MuxFrameTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='mux-frame-', dir='/var/tmp')
        target = pathlib.Path(cls.tmp.name) / 'muxframe.com'
        subprocess.run(['nasm', '-f', 'bin', '-Wall', '-Werror', '-o', str(target),
                        str(SOURCE)], check=True, timeout=10)
        cls.com = target.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_actual_compiled_com_records_arbitrary_registers_flags_and_input_cf(self):
        for seed in (0, 0x7654, 0xeeee):
            model = Model(self.com, replies(seed)).run()
            self.assertEqual(model.exit, 0)
            for (observed_in, observed_out), (raw_in, raw_out, buf) in zip(model.calls, model.rows()):
                self.assertEqual(raw_in, observed_in)
                self.assertEqual(raw_out, observed_out)
                self.assertEqual(raw_in[-1] & 0xfffe, 0x0202)
                self.assertEqual(buf, [3, 0x5aa5, 0xa55a, 0xffff, 0])
            self.assertEqual(len(model.calls), 4)
            self.assertEqual(set(model.dos), {0x40, 0x4c})

    def test_returned_ds_es_df_and_bp_do_not_redirect_capture_or_inspection(self):
        values = replies()
        for i, row in enumerate(values):
            row[4:9] = [0xffff, 0xfffe, 0xffff, 0xffff, 0xfffe]
            row[-1] = 0x0c03 | (i << 4)
        model = Model(self.com, values, payload=b'X:\\MODEL\\ARBITRARY.DAT\0').run()
        self.assertEqual(model.exit, 0)
        for i, (_, raw_out, buf) in enumerate(model.rows()):
            self.assertEqual(raw_out, model.calls[i][1])
            self.assertEqual(buf[:3], [3 if i < 2 else 7, 0x5aa5, 0xa55a])

    def test_only_bounded_buffer_metadata_is_reported(self):
        for payload, length in ((b'\0', 0), (b'PRIVATE_PATH\0', 12),
                                (b'Q' * 79 + b'\0', 79), (b'Q' * 80, 0xffff)):
            model = Model(self.com, replies(), payload=payload).run()
            rows = model.rows()
            self.assertEqual(model.exit, 0)
            for _, _, buf in rows[2:]:
                self.assertEqual(buf, [3 if length == 0xffff else 7,
                                       0x5aa5, 0xa55a, length, len(payload)])
            self.assertNotIn(b'PRIVATE_PATH', model.output)

    def test_canary_corruption_preserves_raw_frame_and_fails_report_integrity(self):
        for damage, expected in (('before', [2, 0x1234, 0xa55a]),
                                  ('after', [1, 0x5aa5, 0x5678])):
            model = Model(self.com, replies(), damage=damage).run()
            self.assertEqual(model.exit, 1)
            for i, (_, raw_out, buf) in enumerate(model.rows()):
                self.assertEqual(raw_out, model.calls[i][1])
                self.assertEqual(buf[:3], [3, 0x5aa5, 0xa55a] if i < 2 else expected)

    def test_unsupported_and_error_statuses_are_not_reclassified(self):
        values = replies()
        for row, ax, flags in zip(values, (0x1611, 0x1611, 0x1613, 0x004e),
                                  (0x0203, 0x0202, 0x0203, 0x0202)):
            row[0], row[-1] = ax, flags
        model = Model(self.com, values).run()
        self.assertEqual(model.exit, 0)
        for (_, raw_out, _), wanted in zip(model.rows(), values):
            self.assertEqual(raw_out, wanted)

    def test_short_or_failed_stdout_refuses_without_queries_after_failure(self):
        for options in ({'short_write': True}, {'write_error': True}):
            model = Model(self.com, replies(), **options).run()
            self.assertEqual(model.exit, 1)
            self.assertEqual(model.calls, [])

    def test_nonempty_cli_refuses_and_cannot_enable_set_function(self):
        for argument in (b'1614', b'/set', b'C:\\WINDOWS\\SYSTEM.DAT'):
            model = Model(self.com, replies(), argument=argument).run()
            self.assertEqual(model.exit, 1)
            self.assertEqual(model.calls, [])
            self.assertEqual(model.dos, [0x4c])
        self.assertEqual(Model(self.com, replies(), argument=b' \t ').run().exit, 0)


if __name__ == '__main__':
    unittest.main()
