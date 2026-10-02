#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production VGA hooks with hardware callbacks only; never executes a VM."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import types
import sys

HERE=Path(__file__).resolve().parent
SUP=HERE.parent.parent

def recorded_run(command,**kwargs):
    result=subprocess.run(command,**kwargs)
    row={'command':list(map(str,command)),'exit_code':result.returncode,'stdout':result.stdout or '', 'stderr':result.stderr or ''}
    raw=(json.dumps(row)+'\n').encode()
    fd=os.open(Path(os.environ['SHZ_VGA_TEST_ROOT'])/'commands.jsonl',os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
    try:
        at=0
        while at<len(raw):at+=os.write(fd,raw[at:])
        os.fsync(fd)
    finally:os.close(fd)
    return result

def fixture_header(path):
    rom=bytearray(65536)
    rom[:3]=bytes((0x55,0xaa,77));rom[0x18:0x1a]=(39132).to_bytes(2,'little')
    off=39132;rom[off:off+4]=b'PCIR';rom[off+4:off+8]=bytes((0x34,0x12,0x11,0x11))
    rom[off+0x0a:off+0x0c]=(24).to_bytes(2,'little')
    rom[off+0x0f]=3
    rom[off+0x10:off+0x12]=(77).to_bytes(2,'little');rom[off+0x15]=0x80
    rom[3]=(-sum(rom[:77*512]))&255
    entries=','.join(f'[{n}]={v}' for n,v in enumerate(rom) if v)
    digest=','.join(map(str,hashlib.sha256(rom).digest()))
    text=f'static unsigned char fixture_rom[65536] __attribute__((aligned(4096)))={{{entries}}};\nstatic const unsigned char fixture_sha256[32]={{{digest}}};\n'
    for name,offset,value in [('pcir_extent',off+0x0a,255),('pcir_class',off+0x0f,2)]:
        bad=bytearray(rom);bad[offset]=value
        if name=='pcir_extent':bad[offset+1]=255
        bad[3]=0;bad[3]=(-sum(bad[:77*512]))&255
        entries=','.join(f'[{n}]={v}' for n,v in enumerate(bad) if v)
        digest=','.join(map(str,hashlib.sha256(bad).digest()))
        text+=f'static unsigned char fixture_{name}_rom[65536] __attribute__((aligned(4096)))={{{entries}}};\nstatic const unsigned char fixture_{name}_sha256[32]={{{digest}}};\n'
    path.write_text(text)

class L1VgaHostTests(unittest.TestCase):
    def test_default_constructor_video_and_actual_ept(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT'])
        fixtures=[('constructor_host.c',[HERE/'l1_vga_legacy_support.c',HERE.parent/'l1_vga.c',HERE.parent/'ata_pio.c'],[None]),('video_host.c',[SUP.parent/'csmwrap/video/cp437.c'],['0','2']),('l1_vga_ept_host.c',[],[None])]
        for compiler in ('gcc','clang'):
            for fixture,extra,groups in fixtures:
                with self.subTest(compiler=compiler,fixture=fixture),tempfile.TemporaryDirectory(dir=parent) as out:
                    binary=Path(out)/'regression';flags=['-std=c11','-D_GNU_SOURCE','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
                    if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
                    built=recorded_run([compiler,*flags,'-I',str(SUP.parent/'csmwrap'),str(HERE/fixture),*map(str,extra),'-o',str(binary)],capture_output=True,text=True,timeout=60)
                    self.assertEqual(built.returncode,0,built.stderr)
                    for group in groups:
                        run=recorded_run([str(binary),*([group] if group is not None else [])],capture_output=True,text=True,timeout=30)
                        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        self.assertTrue(run.stdout.startswith('PASS '),run.stdout)
    def test_ordinary_component_link_not_run(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT']);raw_map=globals()['__shz_vga_held_bytes__']
        helper=SUP.parent/'tools/shzlib.py';module=types.ModuleType('shzlib');module.__file__=str(helper);sys.modules['shzlib']=module
        exec(compile(raw_map[str(helper)],str(helper),'exec'),module.__dict__)
        source=SUP/'build.py';spec=importlib.util.spec_from_file_location('vga_ordinary_supervisor',source);builder=importlib.util.module_from_spec(spec)
        exec(compile(raw_map[str(source)],str(source),'exec'),builder.__dict__)
        builder.OUT=parent/'ordinary-components';builder.OUT.mkdir(mode=0o700)
        def logged(command,cwd=None,env=None,timeout=300,capture=False,check=True):
            result=recorded_run(list(map(str,command)),cwd=cwd,env=env,timeout=timeout,capture_output=True,text=True)
            if check and result.returncode:raise RuntimeError(result.stdout+result.stderr)
            return result
        builder.run=logged
        builder.build_vbios();payload,commands=builder.build_payload();loader,loader_command=builder.build_loader(payload)
        self.assertTrue(any('l1_vga.c' in str(v) for command in commands for v in command))
        pins={str(p.relative_to(builder.OUT)):{'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in builder.OUT.rglob('*') if p.is_file()}
        (parent/'ordinary-component-result.json').write_text(json.dumps({'status':'PASS_COMPONENT_LINK_ONLY','artifacts':pins,'commands':[[str(v) for v in c] for c in [*commands,loader_command]],'VM_executed':False,'Windows98_boot_verified':False,'source_built_VGA_ROM_provenance_accepted':False},indent=2)+'\n')
        self.assertTrue(loader.is_file())
    def test_device_policy_faults(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT'])
        for compiler in ('gcc','clang'):
            with self.subTest(compiler=compiler),tempfile.TemporaryDirectory(dir=parent) as out:
                out=Path(out);fixture_header(out/'vga_fixture.h');binary=out/'device-policy'
                flags=['-std=c11','-D_GNU_SOURCE','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
                if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
                command=[compiler,*flags,'-I',str(out),'-I',str(SUP.parent/'csmwrap'),str(HERE/'l1_vga_policy_host.c'),str(HERE.parent/'l1_vga.c'),str(HERE.parent/'ata_pio.c'),str(HERE.parent/'string_pio.c'),str(SUP.parent/'csmwrap/video/cp437.c'),'-o',str(binary)]
                built=recorded_run(command,capture_output=True,text=True,timeout=60)
                (parent/f'{compiler}-device-policy-compile.log').write_text(built.stdout+built.stderr)
                self.assertEqual(built.returncode,0,built.stderr)
                groups=[int(v) for v in os.environ['SHZ_VGA_GROUPS'].split(',')] if 'SHZ_VGA_GROUPS' in os.environ else range(15)
                for group in groups:
                    with self.subTest(group=group):
                        run=recorded_run([str(binary),str(group)],capture_output=True,text=True,timeout=20)
                        (parent/f'{compiler}-device-policy-{group}.log').write_text(run.stdout+run.stderr)
                        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
    def test_host_page_pat(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT'])
        for compiler in ('gcc','clang'):
            with self.subTest(compiler=compiler),tempfile.TemporaryDirectory(dir=parent) as out:
                binary=Path(out)/'host-pat'
                flags=['-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
                if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
                built=recorded_run([compiler,*flags,str(HERE/'l1_vga_platform_host.c'),'-o',str(binary)],capture_output=True,text=True,timeout=60)
                (parent/f'{compiler}-host-pat-compile.log').write_text(built.stdout+built.stderr)
                self.assertEqual(built.returncode,0,built.stderr)
                run=recorded_run([str(binary)],capture_output=True,text=True,timeout=20)
                (parent/f'{compiler}-host-pat.log').write_text(run.stdout+run.stderr)
                self.assertEqual(run.returncode,0,run.stdout+run.stderr)
    def test_explicit_loader_policy(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT'])
        for compiler in ('gcc','clang'):
            with self.subTest(compiler=compiler),tempfile.TemporaryDirectory(dir=parent) as out:
                binary=Path(out)/'policy'
                command=[compiler,'-std=c11','-O1','-Wall','-Wextra','-Werror',str(HERE/'l1_vga_bootini_host.c'),str(SUP/'loader/bootini.c'),'-o',str(binary)]
                built=recorded_run(command,capture_output=True,text=True,timeout=30)
                self.assertEqual(built.returncode,0,built.stderr)
                result=recorded_run([str(binary)],capture_output=True,text=True,timeout=10)
                (parent/f'{compiler}-bootini.log').write_text(result.stdout+result.stderr)
                self.assertEqual(result.returncode,0,result.stdout+result.stderr)
    def test_actual_native_hooks(self):
        parent=Path(os.environ['SHZ_VGA_TEST_ROOT'])
        for compiler in ('gcc','clang'):
            with self.subTest(compiler=compiler),tempfile.TemporaryDirectory(dir=parent) as out:
                out=Path(out);fixture_header(out/'vga_fixture.h');binary=out/'hooks'
                flags=['-std=c11','-D_GNU_SOURCE','-O1','-g','-Wall','-Wextra','-Werror','-Wno-unused-function','-Wno-unused-variable','-fno-pie','-no-pie','-ffunction-sections','-fdata-sections','-Wl,--gc-sections']
                if compiler=='clang':flags+=['-fsanitize=address,undefined','-fno-omit-frame-pointer']
                sources=[HERE/'l1_vga_host.c',HERE.parent/'ata_pio.c',SUP.parent/'csmwrap/video/cp437.c']
                if (HERE.parent/'l1_vga.c').exists():sources.append(HERE.parent/'l1_vga.c')
                command=[compiler,*flags,'-I',str(out),'-I',str(SUP.parent/'csmwrap'),*map(str,sources),'-o',str(binary)]
                built=recorded_run(command,capture_output=True,text=True,timeout=60)
                (parent/f'{compiler}-compile.log').write_text(built.stdout+built.stderr)
                self.assertEqual(built.returncode,0,built.stderr)
                for group in range(4):
                    with self.subTest(group=group):
                        run=recorded_run([str(binary),str(group)],capture_output=True,text=True,timeout=20)
                        (parent/f'{compiler}-hooks-{group}.log').write_text(run.stdout+run.stderr)
                        self.assertEqual(run.returncode,0,run.stdout+run.stderr)
                        self.assertTrue(run.stdout.startswith('PASS '),run.stdout)

if __name__=='__main__':unittest.main(defaultTest=os.environ.get('SHZ_VGA_TEST_SELECTION'))
