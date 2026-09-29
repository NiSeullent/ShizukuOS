#!/usr/bin/env python3
"""Original xHCI model tests; no hardware/VM/network operations.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import subprocess

HERE=Path(__file__).resolve().parent
BUILD=HERE/'build'
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def run(args):
    result=subprocess.run([str(v) for v in args],capture_output=True,text=True)
    if result.returncode: raise SystemExit(result.stdout+result.stderr)
    return result
def main():
    BUILD.mkdir(exist_ok=True)
    (BUILD/'host-tests.json').unlink(missing_ok=True)
    paths=sorted(p for p in HERE.iterdir() if p.is_file())
    hashes={p.name:digest(p) for p in paths}
    flags=['-std=c11','-Wall','-Wextra','-Werror','-Wpedantic','-Wconversion','-Wshadow']
    target=['--target=i386-unknown-none-elf','-march=i486','-Oz','-ffreestanding','-fno-builtin',
            '-fno-pic','-fno-pie','-fno-stack-protector','-mno-sse','-mno-mmx','-msoft-float',
            '-mstack-alignment=4','-fno-unwind-tables','-fno-asynchronous-unwind-tables']
    run(['clang',*flags,*target,'-c',HERE/'xhci.c','-o',BUILD/'xhci-i486.o'])
    undefined=run(['nm','-u',BUILD/'xhci-i486.o']).stdout.strip()
    if undefined: raise SystemExit('Unexpected runtime dependencies: '+undefined)
    run(['clang',*flags,'-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',
         HERE/'xhci.c',HERE/'test_xhci.c','-o',BUILD/'test_xhci'])
    result=run([BUILD/'test_xhci'])
    print(result.stdout,end='')
    (BUILD/'host-tests.log').write_text(result.stdout+result.stderr)
    if hashes!={p.name:digest(p) for p in paths}: raise SystemExit('Sources changed during test')
    receipt={'schema':1,'passed':True,'sources_sha256':hashes,
             'i486_object_sha256':digest(BUILD/'xhci-i486.o'),
             'host_binary_sha256':digest(BUILD/'test_xhci'),
             'host_log_sha256':digest(BUILD/'host-tests.log'),
             'compiler':run(['clang','--version']).stdout.splitlines()[0],
             'freestanding_i486_no_runtime_imports':True,'asan_ubsan':True,
             'guest_dma_executed':False,'usb_device_enumerated':False,
             'win98_driver_bound':False,'physical_hardware_tested':False}
    (BUILD/'host-tests.json').write_text(json.dumps(receipt,indent=2)+'\n')
if __name__=='__main__':main()
