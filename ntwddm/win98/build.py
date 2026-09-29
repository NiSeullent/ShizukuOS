#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/audit the original native PE32 GDI probe without running it."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE/'build'
SOURCES = ('ntwddm/win98/probe.c','ntwddm/win98/adapter.c','ntwddm/win98/adapter.h',
           'ntwddm/win98/selftest.c','ntwddm/win98/build.py','ntwddm/src/ntwddm.c',
           'ntwddm/include/ntwddm.h','platform/freestanding/memory.c',
           'platform/freestanding/memory.h','ntwin32/prepare.py')
ALLOWED = {
    'KERNEL32.DLL':set('CloseHandle CreateFileA ExitProcess GetLastError GetModuleHandleA '
        'GetProcessHeap GetTickCount GetVersionExA HeapAlloc HeapFree Sleep WriteFile'.split()),
    'USER32.DLL':set('AdjustWindowRect BeginPaint CreateWindowExA DefWindowProcA DestroyWindow '
        'DispatchMessageA EndPaint GetDC InvalidateRect LoadCursorA PeekMessageA RegisterClassA '
        'ReleaseDC ShowWindow TranslateMessage UnregisterClassA UpdateWindow'.split()),
    'GDI32.DLL':set('BitBlt CreateCompatibleDC CreateDIBSection DeleteDC DeleteObject '
        'GdiFlush GetDeviceCaps SelectObject'.split()),
}
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD/'build-result.json'; receipt.unlink(missing_ok=True)
    before = {name:sha(ROOT/name) for name in SOURCES}
    output = BUILD/'NTWGPROB.EXE'; temporary = BUILD/'NTWGPROB.EXE.tmp'
    command = ['i686-w64-mingw32-gcc','-std=c11','-Os','-Wall','-Wextra','-Werror','-march=i486',
        '-mno-sse','-mno-sse2','-mno-mmx','-msoft-float','-ffreestanding','-fno-builtin',
        '-fno-stack-protector','-mno-stack-arg-probe','-fno-ident','-fno-asynchronous-unwind-tables','-nostdlib',
        '-Wl,--subsystem,windows:4.10','-Wl,--major-os-version,4','-Wl,--minor-os-version,10',
        '-Wl,--disable-dynamicbase','-Wl,--disable-nxcompat','-Wl,--disable-tsaware',
        '-Wl,--no-insert-timestamp','-Wl,--entry,_mainCRTStartup','-Wl,--strip-all',
        '-I',str(HERE.parent/'include'),str(HERE/'probe.c'),str(HERE/'adapter.c'),str(HERE/'selftest.c'),
        str(HERE.parent/'src/ntwddm.c'),str(ROOT/'platform/freestanding/memory.c'),
        '-lkernel32','-luser32','-lgdi32','-o',str(temporary)]
    result = subprocess.run(command,check=True,capture_output=True,text=True,timeout=60)
    spec = importlib.util.spec_from_file_location('ntwg_probe_pe',ROOT/'ntwin32/prepare.py')
    parser = importlib.util.module_from_spec(spec); spec.loader.exec_module(parser)
    pe = parser.PE(temporary.read_bytes())
    if (pe.u16(pe.opt+68)!=2 or (pe.u16(pe.opt+48),pe.u16(pe.opt+50))!=(4,10) or
        (pe.u16(pe.opt+40),pe.u16(pe.opt+42))!=(4,10) or pe.u16(pe.pe+22)&0x2000 or
        pe.u16(pe.opt+70)&(0x40|0x100|0x4000) or not pe.u32(pe.opt+16)):
        raise RuntimeError('Expected executable GUI PE32 Windows 4.10 contract')
    pe.offset(pe.u32(pe.opt+16))
    for directory in (4,9,10,13,14):
        if any(pe.directory(directory)): raise RuntimeError('Unexpected security/TLS/load-config/delay/CLR directory')
    imports = {}
    for descriptor in pe.imports():
        dll = descriptor['dll'].upper()
        names = [entry[1] for entry in descriptor['entries']]
        if dll not in ALLOWED or not set(names).issubset(ALLOWED[dll]):
            raise RuntimeError('Unexpected runtime or non-classic import: '+str(descriptor))
        imports[dll] = sorted(names)
    if set(imports)!=set(ALLOWED): raise RuntimeError('Missing native GDI/User/Kernel imports')
    if any(sha(ROOT/name)!=value for name,value in before.items()): raise RuntimeError('Build source changed')
    temporary.replace(output)
    log = BUILD/'build.log'; log.write_text(' '.join(command)+'\n'+result.stdout+result.stderr)
    receipt.write_text(json.dumps({'passed':True,'artifact':output.name,'sha256':sha(output),
        'bytes':output.stat().st_size,'machine':'i386','cpu_flags':'i486, no SSE/MMX, soft-float',
        'subsystem':'GUI 4.10','imports':imports,'sources_sha256':before,'build_log_sha256':sha(log),
        'compiler':subprocess.check_output(['i686-w64-mingw32-gcc','--version'],text=True).splitlines()[0],
        'crt_linked':False,'kernelex_linked':False,'native_win98':'not_tested'},indent=2)+'\n')
    print(receipt.read_text(),end='')
if __name__=='__main__':main()
