# SPDX-License-Identifier: GPL-2.0-only
"""Run actual source-built COM in bounded Unicorn; DOS calls are modeled only."""
import pathlib
import subprocess
import tempfile
import unittest
from unicorn import Uc, UC_ARCH_X86, UC_MODE_16, UC_HOOK_INTR
from unicorn.x86_const import *

SYSTEM = r'C:\WINDOWS\SYSTEM.DAT'
USER = r'C:\WINDOWS\USER.DAT'
REPORT = r'C:\REGADM.TXT'

class Model:
    def __init__(self, com, *, exists=False, mux='system', share_error=False,
                 read_error=False, overflow=False, short_write=False,
                 attr_error=False, open_error=False, commit_error=False, changed_ds=False,
                 short_read=False, invalid_signature=False):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_16)
        self.uc.mem_map(0, 1 << 20)
        self.uc.mem_write(0x10100, com)
        for r in (UC_X86_REG_CS, UC_X86_REG_DS, UC_X86_REG_ES, UC_X86_REG_SS):
            self.uc.reg_write(r, 0x1000)
        self.uc.reg_write(UC_X86_REG_SP, 0xfffe)
        self.handles = {}
        self.output = bytearray()
        self.exit = None
        self.options = locals()
        self.calls = []
        self.uc.hook_add(UC_HOOK_INTR, self.interrupt)

    def reg(self, r): return self.uc.reg_read(r) & 65535
    def set(self, r, v): self.uc.reg_write(r, v)
    def result(self, ax=0, error=False):
        self.set(UC_X86_REG_AX, ax)
        f = self.uc.reg_read(UC_X86_REG_EFLAGS)
        self.set(UC_X86_REG_EFLAGS, f | 1 if error else f & ~1)
    def addr(self, off=UC_X86_REG_DX, seg=UC_X86_REG_DS):
        return self.reg(seg) * 16 + self.reg(off)
    def path(self, off=UC_X86_REG_DX):
        b = bytes(self.uc.mem_read(self.addr(off), 80))
        assert b'\0' in b
        return b.split(b'\0')[0].decode('ascii')
    def interrupt(self, uc, n, _):
        ax, bx, cx, dx = [self.reg(r) for r in
            (UC_X86_REG_AX, UC_X86_REG_BX, UC_X86_REG_CX, UC_X86_REG_DX)]
        self.calls.append((n, ax, bx, cx, dx))
        assert len(self.calls) < 1500
        o = self.options
        if n == 0x2f:
            assert ax in (0x1611, 0x1613)
            if ax == 0x1611:
                self.result(0)
                self.set(UC_X86_REG_BX, 5)
                if o['changed_ds']: self.set(UC_X86_REG_DS, 0x2000)
            elif o['mux'] == 'system':
                assert cx == 80
                uc.mem_write(self.addr(UC_X86_REG_DI, UC_X86_REG_ES), SYSTEM.encode()+b'\0')
                self.result(0)
            elif o['mux'] == 'unterminated':
                uc.mem_write(self.addr(UC_X86_REG_DI, UC_X86_REG_ES), b'X'*80)
            elif o['mux'] == 'overrun':
                uc.mem_write(self.addr(UC_X86_REG_DI, UC_X86_REG_ES)+80, b'!')
            elif o['mux'] == 'other':
                uc.mem_write(self.addr(UC_X86_REG_DI, UC_X86_REG_ES), b'PRIVATE_VALUE\0')
            return
        assert n == 0x21
        ah, al = ax >> 8, ax & 255
        if ax == 0x3000:
            self.result(0x0a07); self.set(UC_X86_REG_BX, 0xff00)
        elif ax == 0x3306:
            self.result(0); self.set(UC_X86_REG_BX, 0x0a07)
        elif ah == 0x5b:
            assert self.path() == REPORT and cx == 0
            if o['exists']: self.result(80, True)
            else: self.handles[5] = 'report'; self.result(5)
        elif ax == 0x4300:
            assert self.path() in (SYSTEM, USER)
            self.result(2, o['attr_error']); self.set(UC_X86_REG_CX, 0x22)
        elif ah in (0x3d, 0x6c):
            assert self.path(UC_X86_REG_SI if ah == 0x6c else UC_X86_REG_DX) in (SYSTEM, USER)
            assert (al in (0, 0x20, 0x40)) if ah == 0x3d else (ax == 0x6c00 and bx == 0x40 and cx == 0 and dx == 1)
            if o['open_error'] or (o['share_error'] and ah == 0x3d and al):
                self.result(5, True)
            else:
                h = 6
                while h in self.handles: h += 1
                self.handles[h] = 'windows'
                self.result(h)
                if ah == 0x6c: self.set(UC_X86_REG_CX, 1)
        elif ax == 0x5700:
            assert self.handles[bx] == 'windows'
            self.result(); self.set(UC_X86_REG_CX, 0xb100); self.set(UC_X86_REG_DX, 0x26a5)
        elif ah == 0x3f:
            assert self.handles[bx] == 'windows' and cx == 24
            if o['read_error']: self.result(5, True)
            else:
                data = bytearray(24); data[:4] = b'NONE' if o['invalid_signature'] else b'CREG'; data[18:20] = b'\x48\x00'
                uc.mem_write(self.addr(), bytes(data)+(b'!' if o['overflow'] else b''))
                self.result(20 if o['short_read'] else 24)
        elif ah == 0x40:
            assert self.handles[bx] == 'report', 'Windows writes forbidden'
            count = max(0,cx-1) if o['short_write'] else cx
            self.output.extend(uc.mem_read(self.addr(), count)); self.result(count)
        elif ah == 0x68:
            assert self.handles[bx] == 'report'
            self.result(5 if o['commit_error'] else 0, o['commit_error'])
        elif ah == 0x3e:
            assert bx in self.handles
            del self.handles[bx]; self.result()
        elif ah == 0x4c:
            self.exit = al; uc.emu_stop()
        else: raise AssertionError('unexpected DOS function %04x' % ax)
    def run(self):
        self.uc.emu_start(0x10100, 0x20000, timeout=2_000_000, count=200_000)
        assert self.exit is not None, 'bounded instruction timeout'
        assert not self.handles, 'owned handles must be closed'
        return self.exit, self.output.decode('ascii')

class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        p = pathlib.Path(cls.tmp.name)/'REGADM.COM'
        source=pathlib.Path(__file__).resolve().parents[1]/'probes/registry_admission.asm'
        subprocess.run(['nasm','-f','bin','-Wall','-Werror','-o',str(p),str(source)],check=True)
        cls.com = p.read_bytes()
    @classmethod
    def tearDownClass(cls): cls.tmp.cleanup()
    def test_actual_readonly_calls_and_header_flags(self):
        m=Model(self.com);code,out=m.run();self.assertEqual(code,0)
        self.assertIn('MUX1611 ax bx cx dx flags=0000 0005 ',out)
        self.assertIn('MUXPATH length class(0other1user2system) cx dx flags=0015 0002 ',out)
        self.assertEqual(out.count('HEADER signature_valid flags_word cx dx flags=0001 0048 '),2)
        self.assertIn('COMPLETE readonly_observation',out)
    def test_mux_changed_ds_snapshots_cs_and_restores_for_report(self):
        code,out=Model(self.com,changed_ds=True).run();self.assertEqual(code,0)
        self.assertIn('MUX1611 ax bx cx dx flags=0000 0005 ',out)
        self.assertIn('COMPLETE readonly_observation',out)
    def test_short_header_not_promoted_to_signature(self):
        code,out=Model(self.com,short_read=True).run();self.assertEqual(code,0)
        self.assertNotIn('HEADER signature_valid',out)
    def test_invalid_signature_reports_boolean_only(self):
        code,out=Model(self.com,invalid_signature=True).run();self.assertEqual(code,0)
        self.assertEqual(out.count('HEADER signature_valid flags_word cx dx flags=0000 0048 '),2)
        self.assertNotIn('NONE',out)
    def test_exclusive_output_refusal(self):
        m=Model(self.com,exists=True);self.assertEqual(m.run(),(1,''));self.assertEqual(len(m.calls),2)
    def test_unsupported_mux_keeps_user_classification(self):
        m=Model(self.com,mux='unsupported');code,out=m.run();self.assertEqual(code,0)
        self.assertIn('MUXPATH length class(0other1user2system) cx dx flags=0013 0001 ',out)
    def test_other_path_never_printed(self):
        code,out=Model(self.com,mux='other').run();self.assertEqual(code,0)
        self.assertNotIn('PRIVATE_VALUE',out);self.assertIn('000D 0000 ',out)
    def test_mux_unterminated_rejected(self): self.assertEqual(Model(self.com,mux='unterminated').run()[0],1)
    def test_mux_canary_corruption_rejected(self): self.assertEqual(Model(self.com,mux='overrun').run()[0],1)
    def test_header_canary_corruption_rejected(self): self.assertEqual(Model(self.com,overflow=True).run()[0],1)
    def test_share_errors_recorded_without_windows_writes(self):
        code,out=Model(self.com,share_error=True).run();self.assertEqual(code,0)
        self.assertEqual(out.count('SHARE20_THEN40 ax bx cx dx flags=0005 '),4)
    def test_header_error_no_header_values_printed(self):
        code,out=Model(self.com,read_error=True).run();self.assertEqual(code,0)
        self.assertNotIn('HEADER signature_valid',out);self.assertEqual(out.count('HEADER_READ ax bx cx dx flags=0005 '),2)
    def test_failed_open_cleanup_no_unowned_close(self):
        code,out=Model(self.com,open_error=True).run();self.assertEqual(code,0)
        self.assertEqual(out.count('OPEN00 ax bx cx dx flags=0005 '),2)
    def test_short_report_write_fails(self): self.assertEqual(Model(self.com,short_write=True).run()[0],1)
    def test_commit_failure_fails(self): self.assertEqual(Model(self.com,commit_error=True).run()[0],1)

if __name__=='__main__': unittest.main()
