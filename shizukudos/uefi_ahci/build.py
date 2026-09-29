#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the isolated native 32-bit AHCI disk-read integration, without booting."""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BASE = HERE.parent / 'uefi32'
BUILD = HERE / 'build'
spec = importlib.util.spec_from_file_location('sd32_build_contracts', BASE/'build.py')
contracts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contracts)

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(args):
    return subprocess.run([str(x) for x in args], cwd=HERE, check=True,
                          capture_output=True, text=True, timeout=60)

def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD/'build-result.json'
    receipt.unlink(missing_ok=True)
    driver = REPO/'drivers/ahci_native'
    sources = [HERE/n for n in ('loader.c','payload.c','clock.c','layout.h','build.py')]
    sources += [BASE/n for n in ('build.py','contract.c','paging.c','paging.h','layout.h',
                                'transition.asm','payload.ld')]
    sources += [driver/'ahci.c',driver/'ahci.h']
    sources += [REPO/n for n in ('ntwrapper/core.c','ntwrapper/include/ntwrapper.h',
               'ntwddm/src/ntwddm.c','ntwddm/include/ntwddm.h',
               'shizukudos/uefi/boot.c','shizukudos/uefi/boot.h','shizukudos/uefi/efi.h')]
    before = {str(p.relative_to(REPO)):digest(p) for p in sources}
    constants = re.findall(r'^#define (SD32_\w+) (0x[0-9A-Fa-f]+|\d+)$',
                           (BASE/'layout.h').read_text(), re.M)
    (BUILD/'layout.inc').write_text(''.join(f'%define {name} {value}\n' for name,value in constants))
    run(['nasm','-f','bin','-I',str(BUILD)+'/',BASE/'transition.asm','-o',BUILD/'transition.bin'])
    flags = ['-m32','-march=i486','-mno-sse','-mno-sse2','-mno-mmx','-msoft-float',
             '-mpreferred-stack-boundary=2','-std=c11','-Os','-Wall','-Wextra','-Werror',
             '-ffreestanding','-fno-builtin','-fno-stack-protector','-fno-pie','-fno-pic',
             '-fno-asynchronous-unwind-tables','-fno-ident','-I',BASE,
             '-I',REPO/'ntwddm/include']
    objects=[]
    for i,source in enumerate((HERE/'payload.c',HERE/'clock.c',BASE/'contract.c',
                               driver/'ahci.c',REPO/'ntwrapper/core.c',REPO/'ntwddm/src/ntwddm.c')):
        obj=BUILD/f'payload-{i}.o'
        run(['gcc',*flags,'-c',source,'-o',obj]); objects.append(obj)
    elf=BUILD/'payload.elf'
    run(['ld','-m','elf_i386','-T',BASE/'payload.ld','-o',elf,*objects])
    payload_info=contracts.elf_contract(elf)
    dma_symbol=re.search(r'^([0-9a-fA-F]+) [bBdD] dma_page$',run(['nm','-n',elf]).stdout,re.M)
    if not dma_symbol: raise RuntimeError('Missing owned DMA allocation symbol')
    payload_info['dma_address']=int(dma_symbol.group(1),16)
    if payload_info['dma_address'] & 1023:
        raise RuntimeError('DMA storage alignment failed')
    if run(['nm','-u',elf]).stdout.strip():
        raise RuntimeError('Unexpected 32-bit compiler runtime dependency')
    run(['objcopy','-O','binary',elf,BUILD/'payload.bin'])
    images='/* Generated from original project sources. */\n'
    for name,filename in (('transition_image','transition.bin'),('payload_image','payload.bin')):
        data=(BUILD/filename).read_bytes()
        if not data or len(data)>0xf0000: raise RuntimeError('Image size exceeds reserved region')
        if filename=='transition.bin' and len(data)!=0x2800:
            raise RuntimeError('Transition must fit below the retained firmware memory map')
        images+=f'static const unsigned char {name}[] = {{\n'
        images+='\n'.join(','.join(f'0x{x:02x}' for x in data[pos:pos+24])+','
                           for pos in range(0,len(data),24))+'\n};\n'
    (BUILD/'images.h').write_text(images)
    temporary=BUILD/'BOOTX64.EFI.tmp'
    run(['x86_64-w64-mingw32-gcc','-std=c11','-Os','-Wall','-Wextra','-Werror',
         '-ffreestanding','-fno-builtin','-fno-stack-protector','-mno-red-zone',
         '-mno-stack-arg-probe','-fno-ident','-fno-asynchronous-unwind-tables','-nostdlib',
         '-Wl,--subsystem,10','-Wl,--entry,efi_main','-Wl,--image-base,0x10000000',
         '-Wl,--enable-reloc-section','-Wl,--no-insert-timestamp','-Wl,--strip-all',
         '-I',BUILD,'-I',BASE,HERE/'loader.c',BASE/'contract.c',BASE/'paging.c',
         REPO/'shizukudos/uefi/boot.c','-o',temporary])
    efi_info=contracts.pe_contract(temporary)
    if any(digest(REPO/name)!=expected for name,expected in before.items()):
        raise RuntimeError('Integration inputs changed during build')
    output=BUILD/'BOOTX64.EFI';temporary.replace(output)
    result={'efi':{**efi_info,'sha256':digest(output),'bytes':output.stat().st_size},
            'payload':{**payload_info,'sha256':digest(BUILD/'payload.bin'),
                       'bytes':(BUILD/'payload.bin').stat().st_size},
            'transition':{'sha256':digest(BUILD/'transition.bin'),
                          'bytes':(BUILD/'transition.bin').stat().st_size},
            'sources_sha256':before,'guest_test':'not_run','physical_hardware':'not_tested'}
    receipt.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result['efi'],indent=2))

if __name__=='__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '')
        print(error.stderr or '')
        raise
