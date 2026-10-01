#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build isolated source-owned RPC observer/fixture; never execute targets."""
import argparse
import hashlib
import json
import shlex
import shutil
import subprocess
from pathlib import Path
import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
RPC = ROOT / 'build/shizukudos/csm/run-win98-gop-vlc-no-qtload-storage-20261001T1050/no-qtload-rpcrt4-readback/RPCRT4.DLL'
RPC_SHA = '3ec2a0156d76fabec725b55a40f438c7260a8af14c3c35e2e6501c3d4d14f5bf'
KERNEL = ROOT / 'build/iewebkit-win98-installed-audit-83bd/KERNEL32.DLL'
KERNEL_SHA = '6771ab74633e9de1359864bd4306a2ed669bec50de7ac9bb9978c05bf04563ca'
VLC = ROOT / 'build/vlc-kex-fullchain-staging-20261001T0337-v4/inputs/VLC/vlc.exe'
VLC_SHA = '499d578564d27529bc08ef9ccb4c5043e25a49d21d2d41fb2176cc3563e8f0d7'
NAMES = ('observer.h', 'observer.c', 'native.c', 'fixture_dll.c', 'fixture.def',
         'fixture.c', 'build.py', 'test.py', 'host_test.c', 'README.md')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def pin(path):
    path = Path(path).resolve()
    return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path)}

def profile(path, rvas):
    with pefile.PE(str(path)) as pe:
        if not pe.is_dll() or pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
            raise ValueError('RPC profile must be a genuine PE32 i386 DLL')
        code, reloc = [], []
        for rva, size in zip(rvas[:2], (32, 6)):
            s = pe.get_section_by_rva(rva)
            if not s or s.Characteristics & 0x60000000 != 0x60000000:
                raise ValueError('breakpoint window must be executable readable code')
            b = pe.get_data(rva, size)
            if len(b) != size:
                raise ValueError('short breakpoint window')
            marks = [0] * 32
            for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', ()):
                for e in block.entries:
                    if e.type and e.rva < rva + size and rva < e.rva + 4:
                        if e.type != 3 or e.rva < rva or e.rva + 4 > rva + size:
                            raise ValueError('unsupported or partial window relocation')
                        pos = e.rva - rva
                        if any(marks[max(0, pos - 3):pos + 4]):
                            raise ValueError('duplicate/overlapping code relocation')
                        marks[pos] = 1
            code.append(list(b) + [0] * (32 - size)); reloc.append(marks)
        for rva in rvas[2:]:
            s = pe.get_section_by_rva(rva)
            if not s or s.Characteristics & 0xc0000000 != 0xc0000000 or s.Characteristics & 0x10000000:
                raise ValueError('observed state must be private readable writable image data')
        return {**pin(path), 'image_bytes': pe.OPTIONAL_HEADER.SizeOfImage,
                'pe_offset': pe.DOS_HEADER.e_lfanew, 'preferred_base': pe.OPTIONAL_HEADER.ImageBase,
                'timestamp': pe.FILE_HEADER.TimeDateStamp, 'size_headers': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'sections': pe.FILE_HEADER.NumberOfSections, 'characteristics': pe.FILE_HEADER.Characteristics,
                'rvas': list(rvas), 'code': code, 'length': [32, 6], 'relocations': reloc}

def declaration(name, p):
    digest = '{' + ','.join(str(x) for x in bytes.fromhex(p['sha256'])) + '}'
    arrays = lambda rows: '{' + ','.join('{' + ','.join(str(x) for x in row) + '}' for row in rows) + '}'
    fields = [digest] + [str(p[x]) for x in ('bytes', 'image_bytes', 'pe_offset', 'preferred_base',
               'timestamp', 'size_headers', 'sections', 'characteristics')] + [str(x) for x in p['rvas']]
    fields += [arrays(p['code']), '{32,6}', arrays(p['relocations'])]
    return 'static const rpc_profile ' + name + '={' + ','.join(fields) + '};\n'

def run(command, out, label, commands):
    commands.append(command)
    r = subprocess.run(command, cwd=ROOT, capture_output=True, timeout=120)
    (out / (label + '.log')).write_bytes(r.stdout + r.stderr)
    r.check_returncode()
    return r.stdout.decode(errors='strict')

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', required=True, type=Path)
    a = ap.parse_args(); out = a.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'build'):
        ap.error('fresh private build output required')
    cc = shutil.which('i686-w64-mingw32-gcc')
    if not cc:
        ap.error('installed isolated compiler required')
    for p, digest in ((RPC, RPC_SHA), (KERNEL, KERNEL_SHA), (VLC, VLC_SHA)):
        if sha(p) != digest:
            ap.error('held input mismatch: ' + str(p))
    files = [HERE / n for n in NAMES] + [HERE.parent / 'native_environment' / n for n in ('environment.c', 'environment.h')]
    oem_path = ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json'
    inputs = {str(p): pin(p) for p in files + [RPC, KERNEL, VLC, oem_path]}
    tools = [Path(cc).resolve()]
    for arg in ('-print-prog-name=cc1', '-print-prog-name=as', '-print-prog-name=ld', '-print-libgcc-file-name'):
        p = subprocess.check_output([cc, arg], text=True).strip()
        resolved = Path(p).resolve() if '/' in p else Path(shutil.which(p)).resolve()
        tools.append(resolved)
    tool_pins = {str(p): pin(p) for p in tools}
    out.mkdir(parents=True); commands = []
    try:
        frozen = out / 'source'; own = frozen / HERE.name
        own.mkdir(parents=True); (frozen / 'native_environment').mkdir()
        for p in files:
            shutil.copyfile(p, frozen / p.parent.name / p.name)
        flags = [cc, '-std=c11', '-march=i486', '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation',
                 '-fno-builtin', '-fno-tree-loop-distribute-patterns', '-fno-stack-protector', '-ffunction-sections',
                 '-fdata-sections', '-nostdlib', '-Wl,--gc-sections', '-Wl,--subsystem,windows:4.10',
                 '-Wl,--major-os-version,4', '-Wl,--minor-os-version,0', '-Wl,--disable-dynamicbase',
                 '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp']
        dll, exe, observer = (out / n for n in ('RPFIX.DLL', 'RPCFIX.EXE', 'RPCOBS.EXE'))
        run(flags + ['-shared', '-Wl,--entry,_DllMain@12', '-o', str(dll), str(own / 'fixture_dll.c'),
                     str(own / 'fixture.def'), '-lkernel32', '-lgcc'], out, 'fixture-dll-compile', commands)
        run(flags + ['-Wl,--entry,_entry@0', '-o', str(exe), str(own / 'fixture.c'), '-lkernel32', '-lgcc'],
            out, 'fixture-exe-compile', commands)
        with pefile.PE(str(dll)) as pe:
            exports = {s.name.decode(): s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
            if set(exports) != {'rpcfix_snapshot', 'rpcfix_state', 'rpcfix_flag', 'rpcfix_store_site'}:
                raise ValueError('owned DLL export profile changed')
            fixture = profile(dll, (pe.OPTIONAL_HEADER.AddressOfEntryPoint, exports['rpcfix_store_site'],
                                    exports['rpcfix_state'], exports['rpcfix_flag']))
        rpc = profile(RPC, (0x15a4, 0x804c, 0x4c02c, 0x4c000))
        if rpc['bytes'] != 339968 or rpc['image_bytes'] != 0x52000 or bytes(rpc['code'][1][:6]).hex() != '893d2cc0bd7f':
            raise ValueError('exact retained Microsoft RPC profile changed')
        with pefile.PE(str(KERNEL)) as pe:
            entries = [s.address for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name == b'DebugBreak']
            if len(entries) != 1 or pe.get_data(entries[0], 2) != b'\xcc\xc3':
                raise ValueError('native loader breakpoint identity changed')
        text = '/* Generated identity only; no licensed DLL is packaged. */\n' + declaration('native_rpc_profile', rpc) + declaration('fixture_profile', fixture)
        for name, p in (('fixture_target', exe), ('vlc_target', VLC)):
            text += 'static const uint8_t ' + name + '_sha[32]={' + ','.join(str(x) for x in bytes.fromhex(sha(p))) + '};\n'
            text += 'static const uint32_t ' + name + '_bytes=' + str(p.stat().st_size) + ';\n'
        text += 'static const uint32_t kernel_debugbreak_rva=' + str(entries[0]) + ';\n'
        (own / 'profiles.h').write_text(text)
        headers = {}
        for i, source in enumerate(('fixture_dll.c', 'fixture.c', 'native.c', 'observer.c')):
            dep = run([cc, '-std=c11', '-march=i486', '-M', str(own / source)], out, 'headers-' + str(i), commands)
            for name in shlex.split(dep.split(':', 1)[1].replace('\\\n', ' ')):
                p = Path(name).resolve()
                if p not in files and p.is_file() and not p.is_relative_to(out):
                    headers[str(p)] = pin(p)
        run(flags + ['-Wl,--entry,_entry@0', '-o', str(observer), str(own / 'native.c'), str(own / 'observer.c'),
                     str(frozen / 'native_environment/environment.c'), '-lkernel32', '-lgcc'], out, 'observer-compile', commands)
        oem = json.loads(oem_path.read_text())['dlls']; artifacts = []
        for p in (dll, exe, observer):
            with pefile.PE(str(p)) as pe:
                opt = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion, opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10):
                    raise ValueError('classic i486 PE format requirement')
                if any(opt.DATA_DIRECTORY[i].VirtualAddress or opt.DATA_DIRECTORY[i].Size for i in (9, 10, 13, 14)) or opt.DllCharacteristics & 0x140:
                    raise ValueError('unexpected modern runtime directory')
                imports = {}
                for d in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', ()):
                    name = d.dll.decode().upper(); names = []
                    for imp in d.imports:
                        if not imp.name or name != 'KERNEL32.DLL' or imp.name.decode() not in oem[name]:
                            raise ValueError('outside original OEM native import set')
                        names.append(imp.name.decode())
                    imports[name] = sorted(names)
                artifacts.append({**pin(p), 'imports': imports, 'is_dll': pe.is_dll(), 'oem_import_gate': 'PASS'})
        for collection in (inputs, tool_pins, headers):
            for path, before in collection.items():
                if pin(Path(path)) != before:
                    raise ValueError('input/tool/header changed during build: ' + path)
        receipt = {'schema': 1, 'status': 'PASS', 'native_executed': False, 'application_success': False,
                   'sources_and_immutable_inputs': inputs, 'tools': tool_pins, 'selected_headers': headers,
                   'frozen_sources': {str(p.relative_to(frozen)): pin(p) for p in frozen.rglob('*') if p.is_file()},
                   'commands': commands, 'profiles': {'original_rpc': rpc, 'owned_fixture': fixture,
                   'native_debugbreak_rva': entries[0]}, 'artifacts': artifacts,
                   'fixture_command': 'C:\\VXDLAB\\RPCOBS.EXE --fixture --log C:\\VXDLAB\\RPCDBG.LOG',
                   'vlc_command': 'C:\\VXDLAB\\RPCOBS.EXE --vlc --log C:\\VXDLAB\\RPCVLC.LOG',
                   'scope': 'Actual classic compilation/import gates only. RF/context/module-event transparency requires an owned native fixture before unchanged VLC. No OEM binary is packaged; no VM launched.'}
        (out / 'build-result.json').write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps({'status': 'PASS', 'receipt': str(out / 'build-result.json'), 'sha256': sha(out / 'build-result.json')}))
    except Exception as e:
        (out / 'build-result.json').write_text(json.dumps({'status': 'FAIL', 'error': str(e), 'native_executed': False,
                'commands': commands, 'sources_and_immutable_inputs': inputs, 'tools': tool_pins}, indent=2) + '\n')
        raise

if __name__ == '__main__':
    main()
