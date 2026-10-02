#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual tiny optional-input RAM route; only compile and geometry are models."""
import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('optional_ram_fixture', HERE/'test_optional_native_inputs.py')
F = importlib.util.module_from_spec(spec); spec.loader.exec_module(F)
B, G = F.B, F.G
PROOFS = []

class OptionalRAMControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['SHZ_RAM_ASSEMBLY_TEST_ROOT'])
        self.ram = Path(self.temp.name)
        self.nas = Path(os.environ['SHZ_RAM_ASSEMBLY_NAS_TEST_ROOT'])/self.ram.name
        self.nas.mkdir(mode=0o700)
        self.inputs = self.nas/'inputs'; self.inputs.mkdir(mode=0o700)
        cfg, rom, provenance = F.firmware()
        seabios = bytearray(256 << 10); seabios[:7] = b'SeaBIOS'; seabios[-16] = 0xea
        bodies = {'disk': bytes(510)+b'\x55\xaa'+bytes(4096-512), 'rom': bytes(seabios),
                  'config': B.config_bytes(), 'kernel32': b'HOST K32', 'kernel64': b'HOST K64',
                  'win64-img': b'HOST ARCHIVE', 'vga-config': cfg, 'vga-rom': rom,
                  'persistence-config': F.persistence(), 'vga-build-receipt': F.serial(provenance)}
        self.files, self.args = {}, []
        for name, body in bodies.items():
            path = self.inputs/name; path.write_bytes(body); self.files[name] = path
            self.args += ['--'+name,str(path),'--'+name+'-sha256',F.sha(body)]
        self.expected = {name: F.pinned(path) for name,path in self.files.items()}
        self.source = self.ram/'fixture-source.py'; self.source.write_bytes(b'# COMPILE MODELED; NEVER EXECUTED\n')
        self.out, self.scratch = self.nas/'out', self.ram/'assembly'
        self.lease_counts, self.stage_admissions = [], []
    def tearDown(self):
        self.assertLessEqual(sum(p.stat().st_blocks*512 for p in self.ram.rglob('*') if p.is_file()),64 << 20)
        self.assertLessEqual(sum(p.stat().st_blocks*512 for p in self.nas.rglob('*') if p.is_file()),4 << 20)
        self.temp.cleanup(); shutil.rmtree(self.nas)
    def originals_leased(self):
        wanted = {(p.stat().st_dev,p.stat().st_ino) for p in self.files.values()}; found = set()
        for name in os.listdir('/proc/self/fd'):
            try:
                fd = int(name); info = os.fstat(fd)
                if (info.st_dev,info.st_ino) in wanted and fcntl.fcntl(fd,fcntl.F_GETLEASE)==fcntl.F_RDLCK:
                    found.add((info.st_dev,info.st_ino))
            except OSError: pass
        self.assertEqual(len(found),10); self.lease_counts.append(len(found))
    def run_main(self, replace_after_assemble=False):
        returned, error = [], None
        actual_command, actual_stage = B.command, B._stage_ram_source
        actual_assemble, actual_copy, actual_reader = B.assemble, B.copy_fd, B.read_leased
        def compile_only(argv, receipt, **kwargs):
            if len(argv)>1 and str(argv[1]).endswith('/native_win98/compile.py'):
                components = Path(argv[-1]); components.mkdir(); loader = components/'BOOTX64.EFI'
                loader.write_bytes(b'NONEXECUTABLE HOST EFI FIXTURE')
                (components/'result.json').write_bytes(F.serial({'status':'PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN',
                    'artifacts':{'BOOTX64.EFI':{'sha256':B.file_sha(loader)}}}))
                return
            return actual_command(argv,receipt,**kwargs)
        def observe_stage(fd, checkpoint, placement, expected, size):
            self.originals_leased()
            self.assertEqual(B.stable(os.fstat(fd)),B.stable(self.files['disk'].stat()))
            self.assertEqual(expected,self.expected['disk']['sha256'])
            return actual_stage(fd,checkpoint,placement,expected,size)
        def observe_copy(fd, checkpoint, destination, *args, **kwargs):
            if Path(destination)==self.out/'esp-win98.img': self.originals_leased()
            return actual_copy(fd,checkpoint,destination,*args,**kwargs)
        @contextlib.contextmanager
        def extent_reader(path, expected, size=None, maximum=2 << 30, **kwargs):
            # Main's disk geometry is modeled as 4KiB; ordinary firmware stays
            # 256KiB and all actual lease/hash/descriptor operations stay real.
            with actual_reader(path,expected,size,max(maximum,size or 0),**kwargs) as admitted:
                if Path(path)==self.scratch/'disk-source.img':
                    self.stage_admissions.append(list(B.stable(os.fstat(admitted[0]))))
                    self.originals_leased()
                yield admitted
        def assemble_then_replace(*args, **kwargs):
            answer = actual_assemble(*args,**kwargs)
            if replace_after_assemble:
                path = self.scratch/'disk-source.img'; raw = path.read_bytes()
                replacement = self.ram/'replacement.img'; replacement.write_bytes(raw)
                os.replace(replacement,path)
                self.assertEqual(B.file_sha(path),self.expected['disk']['sha256'])
            return answer
        with patch.object(B,'ROOT',self.ram), patch.object(B,'DISK_BYTES',4096), patch.object(B,'ESP_MIB',40), \
             patch.object(B,'source_files',return_value=[self.source]), patch.object(B,'command',compile_only), \
             patch.object(B,'_stage_ram_source',observe_stage), patch.object(B,'copy_fd',observe_copy), \
             patch.object(B,'read_leased',extent_reader), patch.object(B,'assemble',assemble_then_replace), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try: B.main(self.args+['--out',str(self.out),'--assembly-scratch',str(self.scratch)],receipt_sink=returned.append)
            except BaseException as caught: error = caught
        return returned,error
    def test_main_RAM_route_preserves_optional_maps_original_FDs_and_custody(self):
        returned,error = self.run_main(); self.assertIsNone(error); self.assertEqual(len(returned),1)
        built = json.loads(returned[0]); stage = built['ram_assembly']['source_staging']
        self.assertEqual(len(built['input_pins']),6)
        self.assertEqual(set(built['optional_native_inputs']),{'VGACFG.BIN','VGAROM.BIN','W98PERS.BIN'})
        self.assertEqual(set(built['optional_native_provenance']),{'vga-build-receipt'})
        self.assertNotIn('SHZDOS/vga-build-receipt',built['members'])
        self.assertEqual(stage['original_path'],str(self.files['disk']))
        self.assertEqual(stage['original_identity'],list(B.stable(self.files['disk'].stat())))
        self.assertEqual(len(self.stage_admissions),2)
        self.assertEqual(self.stage_admissions,[stage['identity'],stage['identity']])
        self.assertTrue(stage['fsync_completed']); self.assertTrue(built['ram_assembly']['final_directory_fsync_completed'])
        self.assertEqual(built['ram_assembly']['worker_deadline_seconds'],120)
        self.assertEqual(built['ram_assembly']['placement']['RAM_cap_bytes'],1 << 30)
        self.assertEqual(built['ram_assembly']['placement']['RAM_floor_bytes'],(6 << 30)+(160 << 20))
        self.assertEqual(built['ram_assembly']['placement']['final_budget_bytes'],2304 << 20)
        self.assertEqual(built['ram_assembly']['NAS_reserve_bytes'],17 << 30)
        self.assertEqual(subprocess.check_output(['mtype','-i',str(self.out/'esp-win98.img'),'::/EFI/SHIZUKU/BOOT.INI'],timeout=30),
                         B.boot_policy(built['optional_native_inputs']))
        for name,row in built['optional_native_inputs'].items():
            self.assertEqual(built['members']['SHZDOS/'+name],{k:row[k] for k in ('bytes','sha256')})
        union = G.LeaseUnion()
        try:
            for row in built['input_pins'].values(): union.add(row)
            manifest = {key:built[key] for key in ('optional_native_inputs','optional_native_provenance')}
            G.admit_optional_native_inputs(manifest,built,union,B); self.assertEqual(len(union.rows),10); union.check()
        finally: union.close()
        self.assertTrue(all(F.pinned(path)==self.expected[name] for name,path in self.files.items()))
        PROOFS.append({'control':'actual_tiny_main_optional_RAM_route','original_FDs_observed_leased':self.lease_counts,
                      'stage_original_path_is_admitted_NAS_original':True,'stage_admitted_twice_with_same_actual_identity':True,
                      'six_originals_and_separate_optional_provenance_maps_preserved':True,'actual_optional_member_and_BOOT_policy_verified':True,
                      'actual_custody_original_union_rows':10,'disk_geometry_model_bytes':4096,'ESP_geometry_model_bytes':40 << 20,
                      'compiler_modeled':True,'worker_and_mtools_actual':True,'worker_deadline_seconds':120})
    def test_same_bytes_stage_replaced_after_RAM_return_prevents_PASS(self):
        returned,error = self.run_main(replace_after_assemble=True)
        self.assertIsInstance(error,ValueError); self.assertIn('copied writer identity',str(error)); self.assertEqual(returned,[])
        built = json.loads((self.out/'result.json').read_bytes()); self.assertEqual(built['status'],'FAIL_BUILD_PRESERVED')
        self.assertEqual(len(built['input_pins']),6); self.assertEqual(len(built['optional_native_inputs']),3)
        self.assertEqual(len(built['optional_native_provenance']),1)
        self.assertTrue(all(F.pinned(path)==self.expected[name] for name,path in self.files.items()))
        PROOFS.append({'control':'actual_same_bytes_RAM_stage_replacement_after_assembly_return','PASS_receipt_sink_returns':0,
                      'identity_refusal':str(error),'all_ten_original_SHA_pins_unchanged':True,'compiler_modeled':True,
                      'worker_and_mtools_actual':True,'disk_geometry_model_bytes':4096,'ESP_geometry_model_bytes':40 << 20})

if __name__=='__main__': unittest.main(verbosity=2)
