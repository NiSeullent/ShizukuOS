# SPDX-License-Identifier: GPL-2.0-only
"""Observer-model regressions, not substitutes for actual guest execution."""
import importlib.util
from pathlib import Path
import re
import tempfile
import unittest
import subprocess
import shutil
import pefile
import os
import json

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dwrite_trial_tests',ROOT/'tools/win64_dwrite_probe_trial.py')
trial=importlib.util.module_from_spec(spec);spec.loader.exec_module(trial)
NONCE='0123456789abcdef0123456789abcdef'


def fixture():
    names=list(trial.MANDATORY)
    for name in ('baseline_glyph_indices','baseline_hangul_absent_as_independently_parsed','baseline_latin_cmap_identity',
                 'baseline_latin_design_advances','baseline_real_face_outlives_file_reference'):
        names.extend([name]*5)
    names.extend('additional_actual_check_'+str(n) for n in range(100-len(names)))
    app=['DW64 BEGIN '+NONCE]+['DW64 PASS '+name for name in names]
    app.extend(['DW64 ALPHA nonzero=500 bytes=3000',
                'DW64 SHAPE row=0 covered=3 expected=3 errors=0','DW64 SHAPE row=1 covered=255 expected=255 errors=0',
                'DW64 RASTER latin_ink=250 korean_ink=1000 runs=2 glyphs=10 missing=0 wrong_faces=0 hash=12345678',
                'DW64 GUI READY '+NONCE+' left=114 top=128 width=384 height=128 hash=12345678',
                'DW64 COUNTS checks=100 failures=0 paints=1','DW64 FINAL PASS '+NONCE])
    prefix=f'K64 autorun: starting D:\\{trial.VOLUME}\\{trial.EXE} (cwd D:\\{trial.VOLUME}, timeout 45 s)\nK64 autorun: started pid 60\n'
    return prefix+'\n'.join('[win64 '+trial.EXE+' pid 60] '+x for x in app)+'\nK64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms\nSHZ-EXIT:0\n'


class EvidenceTests(unittest.TestCase):
    def test_complete_observer_fixture(self):
        r=trial.parse_evidence(fixture(),NONCE)
        self.assertEqual(r['status'],'PASS');self.assertTrue(r['baseline_five_fonts_hangul_absence_guest_verified'])

    def test_wrong_nonce(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture(),'a'*32)

    def test_guest_selftest_does_not_replace_external_exit(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('K64 autorun: result exited exit=0 faulted=0 reaped=0 after 5000 ms','SHZ-EXIT:0'),NONCE)

    def test_wrong_child_pid(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('pid 60]', 'pid 61]'),NONCE)

    def test_wrong_application(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace(trial.EXE,'OTHER.EXE'),NONCE)

    def test_duplicate_autorun(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture()+fixture(),NONCE)

    def test_duplicate_begin(self):
        s=fixture().replace('DW64 BEGIN '+NONCE,'DW64 BEGIN '+NONCE+'\n[win64 '+trial.EXE+' pid 60] DW64 BEGIN '+NONCE)
        with self.assertRaises(ValueError):trial.parse_evidence(s,NONCE)

    def test_fault_rejected(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('faulted=0','faulted=1'),NONCE)

    def test_unsuccessful_raw_proc_wait_rejected(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('reaped=0','reaped=-1'),NONCE)

    def test_nonfinal_alive_diagnostic_rejected(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('result exited exit=0 faulted=0 reaped=0','result running exit=0 faulted=0 reaped=0 (still alive)'),NONCE)

    def test_assertion_total_mismatch(self):
        with self.assertRaises(ValueError):trial.parse_evidence(fixture().replace('checks=100','checks=99'),NONCE)

    def test_missing_contract_cannot_pass(self):
        s=fixture().replace('PASS factory_iunknown_identity','PASS unrelated')
        self.assertEqual(trial.parse_evidence(s,NONCE)['status'],'FAIL')

    def test_baseline_missing_proof_cannot_pass(self):
        s=fixture().replace('PASS baseline_hangul_absent_as_independently_parsed','PASS unrelated',1)
        self.assertEqual(trial.parse_evidence(s,NONCE)['status'],'FAIL')

    def test_failed_baseline_glyph_api_cannot_claim_missing_glyph_proof(self):
        s=fixture().replace('PASS baseline_glyph_indices','FAIL baseline_glyph_indices',1).replace('failures=0','failures=1').replace('FINAL PASS','FINAL FAIL').replace('exit=0','exit=1')
        r=trial.parse_evidence(s,NONCE);self.assertEqual(r['status'],'FAIL');self.assertFalse(r['baseline_five_fonts_hangul_absence_guest_verified'])

    def test_missing_hangul_glyph_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('missing=0','missing=1'),NONCE)['status'],'FAIL')

    def test_wrong_hangul_cluster_order_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('covered=255 expected=255 errors=0','covered=255 expected=255 errors=1'),NONCE)['status'],'FAIL')

    def test_missing_layout_position_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('covered=255 expected=255','covered=127 expected=255'),NONCE)['status'],'FAIL')

    def test_wrong_private_face_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('wrong_faces=0','wrong_faces=1'),NONCE)['status'],'FAIL')

    def test_evidence_before_nonce_rejected(self):
        s=fixture().replace('DW64 BEGIN '+NONCE,'DW64 PASS forged_before_nonce\n[win64 '+trial.EXE+' pid 60] DW64 BEGIN '+NONCE)
        with self.assertRaises(ValueError):trial.parse_evidence(s,NONCE)

    def test_evidence_after_final_rejected(self):
        s=fixture().replace('DW64 FINAL PASS '+NONCE,'DW64 FINAL PASS '+NONCE+'\n[win64 '+trial.EXE+' pid 60] DW64 PASS after_final')
        with self.assertRaises(ValueError):trial.parse_evidence(s,NONCE)

    def test_empty_korean_raster_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('korean_ink=1000','korean_ink=0'),NONCE)['status'],'FAIL')

    def test_alpha_buffer_overflow_claim_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('bytes=3000','bytes=999999'),NONCE)['status'],'FAIL')

    def test_hash_mismatch_cannot_pass(self):
        s=fixture().replace('height=128 hash=12345678','height=128 hash=12345679')
        self.assertEqual(trial.parse_evidence(s,NONCE)['status'],'FAIL')

    def test_out_of_bounds_screen_cannot_pass(self):
        self.assertEqual(trial.parse_evidence(fixture().replace('left=114','left=1000'),NONCE)['status'],'FAIL')

    def test_genuine_failed_run_preserved_as_failure(self):
        s=fixture().replace('PASS factory_iunknown_identity','FAIL factory_iunknown_identity').replace('failures=0','failures=1').replace('FINAL PASS','FINAL FAIL').replace('exit=0','exit=1')
        r=trial.parse_evidence(s,NONCE);self.assertEqual(r['status'],'FAIL');self.assertEqual(r['failed_assertions'],['factory_iunknown_identity'])

    def test_failed_run_cannot_claim_exit_zero(self):
        s=fixture().replace('PASS factory_iunknown_identity','FAIL factory_iunknown_identity').replace('failures=0','failures=1').replace('FINAL PASS','FINAL FAIL')
        with self.assertRaises(ValueError):trial.parse_evidence(s,NONCE)

    def test_framebuffer_matches_live_rgb_hash(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'screen.ppm';image=Image.new('RGB',(1024,768),(255,255,255));image.putpixel((114,128),(2,3,4));image.save(path)
            checksum=trial.rgb_hash(image.crop((114,128,498,256)).tobytes())
            match=re.fullmatch(r'left=(\d+) top=(\d+) hash=([0-9a-f]{8})','left=114 top=128 hash='+checksum)
            self.assertEqual(trial.screenshot(path,match)['checked_rgb_pixels'],49152)
            image.putpixel((114,129),(9,8,7));image.save(path)
            with self.assertRaises(ValueError):trial.screenshot(path,match)

    def test_unexpected_framebuffer_mode(self):
        from PIL import Image
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'screen.ppm';Image.new('RGB',(640,480)).save(path)
            match=re.fullmatch(r'(\d+) (\d+) ([0-9a-f]{8})','0 0 12345678')
            with self.assertRaises(ValueError):trial.screenshot(path,match)

    def test_fnv_known_bytes(self):
        self.assertEqual(trial.rgb_hash(b''),'811c9dc5');self.assertEqual(trial.rgb_hash(b'hello'),'4f9f2cab')

    def test_full_api_and_integration_flags_remain_false(self):
        self.assertTrue(trial.FALSE_FLAGS);self.assertTrue(all(x is False for x in trial.FALSE_FLAGS.values()))


class ActualPETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler=shutil.which('x86_64-w64-mingw32-gcc')
        overlay=Path(os.environ.get('DWRITE_TEST_OVERLAY',ROOT/'build/required-theme-runtime-6970-v2/theme-overlay.json'))
        if not compiler or not overlay.is_file():raise unittest.SkipTest('immutable local runtime/compiler fixture unavailable')
        cls.temp=tempfile.TemporaryDirectory(prefix='dwrite-pe-fixture-',dir=ROOT/'build')
        cls.folder=Path(cls.temp.name);cls.source=cls.folder/'fixture.c';cls.exe=cls.folder/'fixture.exe'
        cls.source.write_text('#include <windows.h>\nstatic int item;static void *volatile anchor=&item;void WINAPI entry(void){ExitProcess(anchor==&item?0:1);}\n')
        built=subprocess.run([compiler,'-Os','-nostdlib','-ffreestanding','-fno-builtin','-mno-stack-arg-probe',str(cls.source),'-Wl,--entry,entry,--no-insert-timestamp,--subsystem,console','-o',str(cls.exe),'-lkernel32'],capture_output=True,timeout=30)
        if built.returncode:raise AssertionError(built.stderr.decode(errors='replace'))
        runtime=trial.theme.verified_overlay(overlay);cls.archive=Path(runtime['archive']['path']).read_bytes()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'temp'):cls.temp.cleanup()

    def mutate(self,change):
        with pefile.PE(str(self.exe)) as pe:
            change(pe);data=pe.write()
        path=self.folder/'mutant.exe';path.write_bytes(data);return path

    def test_real_minimal_amd64_import_and_relocation_gate(self):
        gate=trial.pe_gate(self.exe,self.archive)
        self.assertTrue(gate['parsed_dir64_relocations_verified']);self.assertEqual(gate['imports'][0]['symbol'],'ExitProcess')

    def test_actual_non_amd64_machine_rejected(self):
        path=self.mutate(lambda pe:setattr(pe.FILE_HEADER,'Machine',0x14c))
        with self.assertRaises(ValueError):trial.pe_gate(path,self.archive)

    def test_actual_forbidden_directory_size_rejected(self):
        path=self.mutate(lambda pe:setattr(pe.OPTIONAL_HEADER.DATA_DIRECTORY[9],'Size',1))
        with self.assertRaises(ValueError):trial.pe_gate(path,self.archive)

    def test_actual_missing_relocation_directory_rejected(self):
        def change(pe):pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress=0;pe.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size=0
        path=self.mutate(change)
        with self.assertRaises(ValueError):trial.pe_gate(path,self.archive)

    def test_actual_entry_outside_executable_section_rejected(self):
        def change(pe):pe.OPTIONAL_HEADER.AddressOfEntryPoint=next(s.VirtualAddress for s in pe.sections if not s.Characteristics&0x20000000)
        path=self.mutate(change)
        with self.assertRaises(ValueError):trial.pe_gate(path,self.archive)


class CorpusArchiveBindingTests(unittest.TestCase):
    def test_independently_unchanged_archive_relationship(self):
        corpus_path=ROOT/'build/dwrite-font-corpus-6970-v1/receipt.json'
        if not corpus_path.exists():self.skipTest('immutable local corpus unavailable')
        corpus=json.loads(corpus_path.read_text());overlay=Path(corpus['baseline_overlay']['path']);runtime=json.loads(overlay.read_text())
        r=trial.corpus_overlay_binding(corpus,overlay,runtime)
        self.assertEqual(r['exact_unchanged_archive_sha256'],corpus['baseline_archive_sha256'])
        self.assertIs(r['historical_overlay_live_source_gate_revalidated'],False)

    def test_changed_archive_identity_rejected(self):
        corpus_path=ROOT/'build/dwrite-font-corpus-6970-v1/receipt.json'
        if not corpus_path.exists():self.skipTest('immutable local corpus unavailable')
        corpus=json.loads(corpus_path.read_text());overlay=Path(corpus['baseline_overlay']['path']);runtime=json.loads(overlay.read_text())
        runtime['archive']['sha256']='0'*64
        with self.assertRaises(ValueError):trial.corpus_overlay_binding(corpus,overlay,runtime)

    def test_changed_historical_receipt_identity_rejected(self):
        corpus_path=ROOT/'build/dwrite-font-corpus-6970-v1/receipt.json'
        if not corpus_path.exists():self.skipTest('immutable local corpus unavailable')
        corpus=json.loads(corpus_path.read_text());overlay=Path(corpus['baseline_overlay']['path']);runtime=json.loads(overlay.read_text())
        corpus['baseline_overlay']['sha256']='0'*64
        with self.assertRaises(ValueError):trial.corpus_overlay_binding(corpus,overlay,runtime)


if __name__=='__main__':unittest.main()
