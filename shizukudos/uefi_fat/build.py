#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build original read-only FAT32/AHCI boot integration; never launches a VM."""
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
    ahci = REPO/'drivers/ahci_native'
    fat = REPO/'drivers/fat_native'
    sources = [HERE/n for n in ('loader.c', 'payload.c', 'budget.c', 'budget.h',
               'bridge.c', 'bridge.h', 'layout.h', 'payload.ld', 'transition.asm', 'build.py')]
    sources += [BASE/n for n in ('build.py', 'contract.c', 'paging.c', 'paging.h',
                                 'layout.h', 'transition.asm')]
    sources += [HERE.parent/'uefi_ahci'/n for n in ('clock.c', 'layout.h')]
    sources += [ahci/'ahci.c', ahci/'ahci.h', fat/'fat.c', fat/'fat.h']
    sources += [REPO/n for n in ('ntwrapper/core.c', 'ntwrapper/include/ntwrapper.h',
               'ntwddm/src/ntwddm.c', 'ntwddm/include/ntwddm.h',
               'shizukudos/uefi/boot.c', 'shizukudos/uefi/boot.h', 'shizukudos/uefi/efi.h')]
    before = {str(p.relative_to(REPO)): digest(p) for p in sources}
    constants = re.findall(r'^#define (SD32_\w+) (0x[0-9A-Fa-f]+|\d+)$',
                           (BASE/'layout.h').read_text(), re.M)
    (BUILD/'layout.inc').write_text(''.join(f'%define {name} {value}\n' for name, value in constants))
    run(['nasm', '-f', 'bin', '-I', str(BUILD)+'/', HERE/'transition.asm',
         '-o', BUILD/'transition.bin'])
    flags = ['-m32', '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float',
             '-mpreferred-stack-boundary=2', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
             '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pie', '-fno-pic',
             '-fno-asynchronous-unwind-tables', '-fno-ident', '-fstack-usage', '-I', BASE,
             '-I', REPO/'ntwddm/include']
    objects = []
    stack = []
    for i, source in enumerate((HERE/'payload.c', HERE/'budget.c', HERE/'bridge.c',
                                HERE.parent/'uefi_ahci/clock.c', BASE/'contract.c',
                                ahci/'ahci.c', fat/'fat.c', REPO/'ntwrapper/core.c',
                                REPO/'ntwddm/src/ntwddm.c')):
        obj = BUILD/f'payload-{i}.o'
        run(['gcc', *flags, '-c', source, '-o', obj])
        objects.append(obj)
        for line in obj.with_suffix('.su').read_text().splitlines():
            name, size, kind = line.split('\t')
            if kind not in ('static', 'dynamic,bounded'):
                raise RuntimeError(f'Unbounded stack frame: {line}')
            stack.append({'function': name.rsplit(':', 1)[-1], 'bytes': int(size)})
    # No recursion/interrupts are used. Summing all compiled frames is a
    # conservative bound, including functions not on a common call path.
    stack_sum = sum(frame['bytes'] for frame in stack)
    if stack_sum + 4096 > 65536:
        raise RuntimeError('Payload frames exceed the 64KiB reserved stack')
    elf = BUILD/'payload.elf'
    run(['ld', '-m', 'elf_i386', '-T', HERE/'payload.ld', '-o', elf, *objects])
    payload_info = contracts.elf_contract(elf)
    symbols = run(['nm', '-n', elf]).stdout
    sized_symbols = run(['nm', '-S', '-n', elf]).stdout
    locations = {}
    for symbol, size, alignment in (('dma_page', 4096, 4096),
                                    ('fat_workspace', 530176, 16),
                                    ('graphics_memory', 65536, 16)):
        found = re.search(r'^([0-9a-fA-F]+) ([0-9a-fA-F]+) [bBdD] '+symbol+r'$',
                          sized_symbols, re.M)
        if not found:
            raise RuntimeError(f'Missing owned storage: {symbol}')
        address, actual_size = (int(value, 16) for value in found.groups())
        if actual_size != size or address % alignment or not 0x02010000 <= address or address + size > 0x020ff000:
            raise RuntimeError(f'Invalid owned storage span: {symbol}')
        locations[symbol] = (address, size)
    found = re.search(r'^([0-9a-fA-F]+) \w __payload_end$', symbols, re.M)
    if not found or int(found.group(1), 16) > 0x020ff000:
        raise RuntimeError('Payload overlaps the destination guard')
    payload_info.update(dma_address=locations['dma_page'][0], dma_bytes=4096,
                        workspace_address=locations['fat_workspace'][0], workspace_bytes=530176,
                        graphics_address=locations['graphics_memory'][0], graphics_bytes=65536,
                        payload_end=int(found.group(1), 16), stack_frame_sum=stack_sum,
                        stack_frame_max=max(frame['bytes'] for frame in stack),
                        destination=0x02100000, capacity=524288,
                        guard_before=0x020ff000, guard_after=0x02180000, guard_bytes=4096)
    if run(['nm', '-u', elf]).stdout.strip():
        raise RuntimeError('Unexpected i486 compiler/runtime dependency')
    run(['objcopy', '-O', 'binary', elf, BUILD/'payload.bin'])
    images = '/* Generated from original project sources. */\n'
    for name, filename in (('transition_image', 'transition.bin'), ('payload_image', 'payload.bin')):
        data = (BUILD/filename).read_bytes()
        if not data or len(data) > 0xef000:
            raise RuntimeError('Image exceeds payload/guard separation')
        if filename == 'transition.bin' and len(data) != 0x2800:
            raise RuntimeError('Transition overlaps retained firmware memory map')
        images += f'static const unsigned char {name}[] = {{\n'
        images += '\n'.join(','.join(f'0x{x:02x}' for x in data[pos:pos+24])+','
                             for pos in range(0, len(data), 24))+'\n};\n'
    (BUILD/'images.h').write_text(images)
    temporary = BUILD/'BOOTX64.EFI.tmp'
    run(['x86_64-w64-mingw32-gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone',
         '-mno-stack-arg-probe', '-fno-ident', '-fno-asynchronous-unwind-tables', '-nostdlib',
         '-Wl,--subsystem,10', '-Wl,--entry,efi_main', '-Wl,--image-base,0x10000000',
         '-Wl,--enable-reloc-section', '-Wl,--no-insert-timestamp', '-Wl,--strip-all',
         '-I', BUILD, '-I', BASE, HERE/'loader.c', BASE/'contract.c', BASE/'paging.c',
         REPO/'shizukudos/uefi/boot.c', '-o', temporary])
    efi_info = contracts.pe_contract(temporary)
    if any(digest(REPO/name) != expected for name, expected in before.items()):
        raise RuntimeError('Build inputs changed during compilation')
    output = BUILD/'BOOTX64.EFI'
    temporary.replace(output)
    result = {'efi': {**efi_info, 'sha256': digest(output), 'bytes': output.stat().st_size},
              'payload': {**payload_info, 'sha256': digest(BUILD/'payload.bin'),
                          'bytes': (BUILD/'payload.bin').stat().st_size},
              'transition': {'sha256': digest(BUILD/'transition.bin'),
                             'bytes': (BUILD/'transition.bin').stat().st_size},
              'sources_sha256': before, 'guest_test': 'not_run',
              'physical_hardware': 'not_tested'}
    receipt.write_text(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result['efi'], indent=2))


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '')
        print(error.stderr or '')
        raise
