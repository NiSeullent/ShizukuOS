# SPDX-License-Identifier: GPL-2.0-or-later
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

BASE = Path(__file__).resolve().parents[1]
PARSER = BASE / 'trace/parse_trace.py'
ASM = BASE / 'trace/dosvmm_trace.asm'

def row(phase, identifier, ax=0x1607, bx=0x15, cx=1, dx=0, flags=0x8243):
    words = (identifier, ax,bx,cx,dx,0x1357,0x2468,0x3579,0x468a,0x579b,flags)
    return ('SHZVMM1 ' + phase + ' ' + ' '.join('%04X' % x for x in words) + '\r\n').encode('ascii')

class TraceContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('shz_parse_trace', PARSER)
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)

    def test_complete_register_pair_is_a_measurement_only(self):
        result = self.module.parse(row('E',1) + row('R',1,ax=0xb97c,bx=0,dx=0xa2ab), 'windows98-original-control')
        self.assertEqual(result['status'],'COMPLETE_CALL_MEASUREMENT')
        self.assertEqual(result['completed_calls'],1)
        self.assertEqual(result['observed_input_calls'],{'1607:0015:0001':1})
        self.assertFalse(result['native_Windows98_complete'])
        self.assertFalse(result['ShizukuDOS_replaces_MS_DOS_validated'])
        self.assertFalse(result['harness_guest_execution_validated'])
        self.assertNotIn('calls',result)

    def test_nested_calls_pair_by_id_and_stack(self):
        data = row('E',1,ax=0x1605) + row('E',2,cx=3,dx=1) + row('R',2,ax=0xb97c,cx=88,dx=0xa2ab) + row('R',1,ax=0x1605)
        result = self.module.parse(data,'shizukudos-win98-candidate')
        self.assertEqual(result['completed_calls'],2)

    def test_fallback_and_winoldap_are_measurable(self):
        for ax in (0x1603,0x1605,0x1606,0x4601,0x4602):
            result=self.module.parse(row('E',1,ax=ax,bx=0) + row('R',1,ax=ax,bx=0),'windows98-original-control')
            self.assertEqual(result['completed_calls'],1)

    def test_non_harness_debug_lines_are_ignored(self):
        data=b'firmware log\r\n' + row('E',1) + b'other component log\r\n' + row('R',1)
        self.assertEqual(self.module.parse(data,'windows98-original-control')['completed_calls'],1)

    def test_truncated_malformed_reordered_and_duplicate_traces_are_rejected(self):
        cases = (b'',b'firmware only\n',row('E',1),row('R',1),row('E',1)+row('R',2),
                 row('E',1)+row('E',1)+row('R',1)+row('R',1),
                 row('E',1)+row('E',2)+row('R',1)+row('R',2),
                 row('E',2)+row('R',2),row('E',1)+row('R',1)+row('E',1)+row('R',1),
                 row('E',0)+row('R',0),row('E',4097)+row('R',4097),
                 row('E',1)+row('R',1)[:-1],row('E',1).replace(b' E ',b' Q ')+row('R',1),
                 row('E',1).replace(b'0001',b'000G',1)+row('R',1),
                 row('E',1).replace(b'\r\n',b' FF\r\n')+row('R',1),
                 row('E',1,ax=0x1234)+row('R',1),
                 row('E',1,bx=0x18)+row('R',1),
                 row('E',1,cx=0x1234)+row('R',1)+b'SHZVMM1 broken\n')
        for data in cases:
            with self.subTest(data=data[:100]):
                with self.assertRaises(ValueError):
                    self.module.parse(data,'windows98-original-control')

    def test_size_and_profile_are_bounded(self):
        with self.assertRaises(ValueError):
            self.module.parse(b'x'*(1024*1024+1),'windows98-original-control')
        with self.assertRaises(ValueError):
            self.module.parse(row('E',1)+row('R',1),'production-pass')

    def test_full_call_budget_is_validated_but_never_claims_windows_boot(self):
        data=b''.join(row('E',i)+row('R',i) for i in range(1,4097))
        result=self.module.parse(data,'windows98-original-control')
        self.assertEqual(result['completed_calls'],4096)
        self.assertTrue(result['trace_budget_reached'])
        self.assertFalse(result['native_Windows98_complete'])

    def test_reader_rejects_symlinks_fifo_directory_and_oversize_inputs(self):
        with tempfile.TemporaryDirectory(prefix='shz-trace-reader-') as temp:
            temp=Path(temp)
            good=temp/'good.log'
            data=row('E',1)+row('R',1)
            good.write_bytes(data)
            self.assertEqual(self.module.read_bounded(good),data)
            link=temp/'link.log'
            link.symlink_to(good)
            fifo=temp/'fifo.log'
            os.mkfifo(fifo)
            huge=temp/'huge.log'
            with huge.open('wb') as stream:
                stream.truncate(1024*1024+1)
            for bad in (link,fifo,temp,huge,temp/'missing.log'):
                with self.subTest(bad=bad.name):
                    with self.assertRaises((ValueError,OSError)):
                        self.module.read_bounded(bad)

    def test_reader_rejects_capture_changed_during_the_read(self):
        from unittest import mock
        with tempfile.TemporaryDirectory(prefix='shz-trace-changing-') as temp:
            path=Path(temp)/'changing.log'
            path.write_bytes(row('E',1)+row('R',1))
            actual_fstat=os.fstat
            calls=[]
            def changing_stat(fd):
                calls.append(fd)
                if len(calls)==2:
                    with path.open('ab') as stream:
                        stream.write(b'new debug output')
                return actual_fstat(fd)
            with mock.patch.object(self.module.os,'fstat',side_effect=changing_stat):
                with self.assertRaises(ValueError):
                    self.module.read_bounded(path)

    def test_cli_requires_profile_and_never_prints_a_private_input_path(self):
        with tempfile.TemporaryDirectory(prefix='shz-trace-cli-') as temp:
            temp=Path(temp)
            path=temp/'private-control.log'
            path.write_bytes(row('E',1)+row('R',1))
            import sys
            import json
            args=[sys.executable,'-B',str(PARSER),str(path)]
            rejected=subprocess.run(args,capture_output=True,timeout=10)
            self.assertEqual(rejected.returncode,2)
            accepted=subprocess.run(args+['--profile','windows98-original-control'],capture_output=True,timeout=10)
            self.assertEqual(accepted.returncode,0)
            result=json.loads(accepted.stdout)
            self.assertEqual(result['completed_calls'],1)
            self.assertNotIn(str(temp).encode(),accepted.stdout)
            self.assertFalse(result['native_Windows98_complete'])
            path.write_bytes(row('E',1))
            incomplete=subprocess.run(args+['--profile','windows98-original-control'],capture_output=True,timeout=10)
            self.assertEqual(incomplete.returncode,2)
            self.assertEqual(incomplete.stdout,b'')

    def test_assembler_build_is_bounded_and_resident_has_no_dos_calls(self):
        with tempfile.TemporaryDirectory(prefix='shz-vmm-asm-') as temp:
            temp=Path(temp)
            com=temp/'DOSVMM.COM'
            listing=temp/'DOSVMM.LST'
            subprocess.run(['nasm','-f','bin','-w+all','-Werror','-o',str(com),'-l',str(listing),str(ASM)],check=True,capture_output=True)
            blob=com.read_bytes()
            self.assertGreater(len(blob),128)
            self.assertLess(len(blob),4096)
            # The resident prefix ends at install: and must contain no software
            # interrupt opcodes; DOS calls are confined to the one-time install.
            source=ASM.read_text().split('\ninstall:',1)[0]
            self.assertNotIn('int ',source)
            self.assertNotIn('sti',source)
            self.assertIn('pushad',source)
            self.assertIn('popad',source)
            self.assertIn('retf 2',source)
            self.assertIn('4096',source)
            self.assertIn('out 0xe9, al',source)
            self.assertIn('push word [cs:next_id]',source)

if __name__=='__main__':
    unittest.main()
