#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze, link and inspect NTWLDC.DLL; no installation or native execution."""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
EXPORTS = {
    'np_parse', 'np_parse_limited', 'np_load_config', 'np_load_config_limited',
    'np_load_config_cookie', 'np_load_config_cookie_limited',
    'np_load_config_execution_profile', 'np_load_config_execution_profile_limited',
}
CORE = ('ntwin32/load_config/load_config.c', 'ntwin32/load_config/load_config.h',
        'ntwin32/load_config/test.py', 'ntwin32/native_loader/pe.c',
        'ntwin32/native_loader/pe.h')
SOURCES = CORE + ('ntwin32/load_config/build_native.py',
                 'ntwin32/load_config/native_entry.c',
                 'ntwin32/load_config/native.def',
                 'platform/freestanding/memory.c',
                 'platform/freestanding/memory.h')
MEMORY_SYMBOLS = {'_memcpy', '_memset', '_memmove', '_memcmp'}


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def undefined(text):
    return sorted({line.split()[-1] for line in text.splitlines() if line.split()})


def defined(text):
    return {fields[-1] for line in text.splitlines()
            if len(fields := line.split()) == 3 and fields[1].upper() != 'U'}


def coff_probe_text(data):
    """Inspect the real pinned GCC object, not a substitute stack helper."""
    require(len(data) >= 20, 'Truncated compiler runtime COFF object')
    machine, count, _, _, _, optional_size, _ = struct.unpack_from('<HHIIIHH', data)
    require(machine == 0x14c and not optional_size and 1 <= count <= 16,
            'Compiler stack probe is not a bounded I386 COFF object')
    require(20 + count * 40 <= len(data), 'Truncated runtime section table')
    found = []
    for index in range(count):
        section = struct.unpack_from('<8sIIIIIIHHI', data, 20 + index * 40)
        if section[0].rstrip(b'\0') != b'.text':
            continue
        size, offset, relocations, flags = section[3], section[4], section[7], section[9]
        require(0 < size <= 4096 and offset <= len(data) and size <= len(data) - offset,
                'Compiler runtime text is unbacked or unexpectedly large')
        require(not relocations and flags & 0x20000000,
                'Stack probe has external relocations or nonexecutable code')
        found.append(data[offset:offset + size])
    require(len(found) == 1, 'Exact compiler runtime text section missing')
    return found[0]


def inspect_stack_probe(path, map_path, text):
    mapping = map_path.read_text()
    matches = re.findall(r'^\s*(0x[0-9a-fA-F]+)\s+__chkstk_ms\s*$', mapping, re.MULTILINE)
    require(len(matches) == 1, 'Exact stack probe code address missing from link map')
    with pefile.PE(str(path)) as image:
        rva = int(matches[0], 16) - image.OPTIONAL_HEADER.ImageBase
        section = image.get_section_by_rva(rva)
        require(section is not None and section.Characteristics & 0x20000000 and
                not section.Characteristics & 0x80000000,
                'Compiler runtime is not in immutable executable DLL code')
        require(image.get_data(rva, len(text)) == text,
                'Linked stack probe bytes differ from actual pinned compiler runtime')
    return {'symbol': '___chkstk_ms', 'rva': rva, 'bytes': len(text),
            'code_sha256': hashlib.sha256(text).hexdigest(),
            'code_matches_real_archive_member': True}


def inspect_dll(path):
    with pefile.PE(str(path)) as image:
        header = image.OPTIONAL_HEADER
        require(image.FILE_HEADER.Machine == 0x14c and header.Magic == 0x10b,
                'DLL must be I386 PE32')
        require(image.is_dll() and image.FILE_HEADER.Characteristics & 2,
                'Executable DLL characteristics missing')
        require(not image.FILE_HEADER.Characteristics & 1,
                'DLL relocations must not be stripped')
        require(image.FILE_HEADER.TimeDateStamp == 0, 'Nonreproducible PE timestamp')
        require((header.MajorOperatingSystemVersion, header.MinorOperatingSystemVersion,
                 header.MajorSubsystemVersion, header.MinorSubsystemVersion,
                 header.Subsystem) == (4, 10, 4, 10, 2), 'Windows 4.10 GUI PE profile')
        require(header.DllCharacteristics == 0, 'Unexpected modern DLL flags')
        require(image.verify_checksum(), 'PE checksum mismatch')
        for directory in (9, 10, 13, 14):
            value = header.DATA_DIRECTORY[directory]
            require(not value.VirtualAddress and not value.Size,
                    'Unsupported TLS/LoadConfig/delay/CLR directory')
        require(not getattr(image, 'DIRECTORY_ENTRY_IMPORT', []),
                'NTWLDC requires zero imported OS/CRT/provider symbols')
        imports = header.DATA_DIRECTORY[1]
        iat = header.DATA_DIRECTORY[12]
        require(not iat.VirtualAddress and not iat.Size, 'IAT directory is not empty')
        # GNU ld's default .idata emits the five DWORD null terminator even
        # when no import objects exist. It is metadata, not an imported API.
        require((not imports.VirtualAddress and not imports.Size) or
                (imports.VirtualAddress and imports.Size == 20 and
                 image.get_data(imports.VirtualAddress, 20) == bytes(20)),
                'Import directory contains more than its empty-list terminator')
        require(header.DATA_DIRECTORY[5].VirtualAddress and
                header.DATA_DIRECTORY[5].Size, 'Rebase relocation directory missing')
        require(getattr(image, 'DIRECTORY_ENTRY_BASERELOC', []),
                'No decoded rebase relocation blocks')
        export = getattr(image, 'DIRECTORY_ENTRY_EXPORT', None)
        require(export is not None, 'Export directory missing')
        require(export.name == b'NTWLDC.DLL', 'Export DLL identity mismatch')
        names, addresses = [], {}
        exp = header.DATA_DIRECTORY[0]
        for entry in export.symbols:
            require(entry.name is not None and not entry.forwarder,
                    'Ordinal-only or forwarded export is not this API')
            name = entry.name.decode('ascii')
            require(name not in addresses, 'Duplicate export name')
            names.append(name)
            section = image.get_section_by_rva(entry.address)
            require(section is not None and section.Characteristics & 0x20000000,
                    'Export RVA is not executable')
            require(not section.Characteristics & 0x80000000,
                    'Export section is writable')
            require(not exp.VirtualAddress <= entry.address < exp.VirtualAddress + exp.Size,
                    'Export points back into export metadata')
            require(image.get_data(entry.address, 1), 'Export has no backed code byte')
            addresses[name] = entry.address
        require(set(names) == EXPORTS and len(names) == len(EXPORTS),
                'Exact eight-name native API export mismatch')
        entry_section = image.get_section_by_rva(header.AddressOfEntryPoint)
        require(entry_section is not None and entry_section.Characteristics & 0x20000000,
                'DllMain entry is not executable')
        require(not any(s.Characteristics & 0x20000000 and
                        s.Characteristics & 0x80000000 for s in image.sections),
                'Writable executable section')
        return {'machine': 'I386', 'magic': 'PE32', 'subsystem': 'WINDOWS_GUI',
                'os_version': [4, 10], 'subsystem_version': [4, 10],
                'dll_characteristics': header.DllCharacteristics,
                'entry_rva': header.AddressOfEntryPoint, 'exports': addresses,
                'imports': {}, 'oem_import_gate': 'PASS_ZERO_IMPORTS',
                'import_directory_bytes': imports.Size,
                'import_directory_null_terminator_only': bool(imports.Size),
                'relocation_blocks': len(image.DIRECTORY_ENTRY_BASERELOC),
                'checksum_valid': True, 'sha256': sha(path),
                'bytes': path.stat().st_size, 'native_executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--host-receipt', type=Path, required=True)
    parser.add_argument('--host-receipt-sha', required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to((ROOT / 'build').resolve()) or out == ROOT / 'build':
        parser.error('use a fresh component directory under this project build/')
    host_path = args.host_receipt.resolve(strict=True)
    require(host_path.is_relative_to((ROOT / 'build').resolve()), 'Host receipt outside project build')
    require(sha(host_path) == args.host_receipt_sha, 'Selected host receipt hash changed')
    host = json.loads(host_path.read_text())
    require(host.get('status') == 'PASS' and host.get('host_only') is True and
            host.get('native_executed') is False and host.get('tests') == 20 and
            host.get('failures') == host.get('errors') == host.get('skipped') == 0 and
            host.get('sources_unchanged_during_validation') is True and
            host.get('sources') == host.get('sources_after'), 'Expected exact twenty-method host PASS')
    before = {name: sha(ROOT / name) for name in SOURCES}
    require(all(host['sources'].get(name) == before[name] for name in CORE),
            'Reviewed parser/PE source differs from host receipt')
    tools = {}
    for name in ('i686-w64-mingw32-gcc', 'i686-w64-mingw32-nm',
                 'i686-w64-mingw32-objdump', 'i686-w64-mingw32-ar'):
        located = shutil.which(name)
        require(located, 'Existing tool missing: ' + name)
        path = Path(located).resolve()
        tools[name] = {'path': str(path), 'sha256': sha(path),
                       'version': subprocess.check_output([str(path), '--version'],
                                                         text=True).splitlines()[0]}
    cc, nm, dump, ar = [tools[n]['path'] for n in tools]
    runtime = Path(subprocess.check_output([cc, '-print-libgcc-file-name'], text=True).strip()).resolve(strict=True)
    runtime_sha = sha(runtime)
    out.mkdir(parents=True)
    receipt = {'schema': 'win98modern.load-config-native-dll.v1', 'status': 'FAIL',
               'native_executed': False, 'application_executed': False,
               'mitigations_implemented': False, 'host_receipt': str(host_path),
               'host_receipt_sha256': args.host_receipt_sha,
               'sources_before': before, 'tools': tools, 'commands': []}
    try:
        frozen = out / 'frozen'
        for name in SOURCES:
            destination = frozen / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
            require(sha(destination) == before[name], 'Source changed while freezing: ' + name)
        shutil.copyfile(host_path, out / 'host-result.frozen.json')
        require(sha(out / 'host-result.frozen.json') == args.host_receipt_sha, 'Frozen host receipt differs')
        runtime_dir = out / 'runtime'
        runtime_dir.mkdir()
        frozen_runtime = runtime_dir / 'libgcc.a'
        shutil.copyfile(runtime, frozen_runtime)
        require(sha(frozen_runtime) == runtime_sha, 'Compiler runtime changed while freezing')
        license_pins = {}
        for name in ('COPYING3', 'COPYING.RUNTIME'):
            path = Path('/usr/share/licenses/mingw32-libgcc') / name
            destination = runtime_dir / name
            shutil.copyfile(path, destination)
            license_pins[str(path)] = sha(path)
            require(sha(destination) == license_pins[str(path)], 'Runtime license changed')
        receipt['compiler_runtime'] = {'source': str(runtime), 'frozen': str(frozen_runtime),
                                       'sha256': runtime_sha, 'license_pins': license_pins,
                                       'lineage': 'Installed GCC libgcc; GPLv3 with GCC Runtime Library Exception3.1'}

        def run(command, name, binary=False):
            result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                    text=not binary, timeout=120)
            log = out / name
            if binary:
                log.write_bytes(result.stdout)
                (out / (name + '.stderr')).write_bytes(result.stderr)
            else:
                log.write_text(result.stdout + result.stderr)
            receipt['commands'].append({'argv': command, 'returncode': result.returncode,
                                         'argv_sha256': hashlib.sha256(json.dumps(command,
                                             separators=(',', ':')).encode()).hexdigest(),
                                         'log': str(log), 'log_sha256': sha(log)})
            require(result.returncode == 0, 'Command failed; inspect ' + str(log))
            return result.stdout

        flags = ['-std=c11', '-march=i486', '-mtune=i486', '-Os', '-Wall', '-Wextra',
                 '-Werror', '-Wno-misleading-indentation', '-ffreestanding',
                 '-fno-builtin', '-fno-stack-protector', '-fno-tree-loop-distribute-patterns',
                 '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
                 '-mno-sse', '-mno-mmx', '-msoft-float']
        objects, object_undefined, object_defined = [], {}, set()
        for name, output in (('ntwin32/load_config/load_config.c', 'load_config.o'),
                             ('ntwin32/native_loader/pe.c', 'pe.o'),
                             ('ntwin32/load_config/native_entry.c', 'native_entry.o')):
            obj = out / output
            run([cc, *flags, '-c', str(frozen / name), '-o', str(obj)], output + '.build.log')
            object_undefined[output] = undefined(run([nm, '--undefined-only', str(obj)], output + '.undefined.txt'))
            object_defined |= defined(run([nm, '--defined-only', str(obj)], output + '.defined.txt'))
            objects.append(obj)
        needed = set().union(*(set(v) for v in object_undefined.values()))
        if needed & MEMORY_SYMBOLS:
            obj = out / 'memory.o'
            run([cc, *flags, '-c', str(frozen / 'platform/freestanding/memory.c'),
                 '-o', str(obj)], 'memory.o.build.log')
            object_undefined[obj.name] = undefined(run([nm, '--undefined-only', str(obj)], 'memory.o.undefined.txt'))
            require(not object_undefined[obj.name], 'Memory support has unresolved runtime references')
            object_defined |= defined(run([nm, '--defined-only', str(obj)], 'memory.o.defined.txt'))
            objects.append(obj)
        receipt['object_undefined_symbols'] = object_undefined
        external = set().union(*(set(v) for v in object_undefined.values())) - object_defined
        require(external <= {'___chkstk_ms'},
                'Unexpected object dependency: ' + ', '.join(sorted(external)))
        receipt['external_object_dependencies'] = sorted(external)
        receipt['objects'] = {obj.name: sha(obj) for obj in objects}
        probe_object = run([ar, 'p', str(frozen_runtime), '_chkstk_ms.o'], 'runtime/_chkstk_ms.o', binary=True)
        require(probe_object, 'Actual compiler stack probe member missing')
        probe_text = coff_probe_text(probe_object)
        probe_defined = defined(run([nm, '--defined-only', str(runtime_dir / '_chkstk_ms.o')],
                                   'stack-probe.defined.txt'))
        require(external <= probe_defined, 'Actual compiler archive does not define dependency')
        require(not undefined(run([nm, '--undefined-only', str(runtime_dir / '_chkstk_ms.o')],
                                  'stack-probe.undefined.txt')),
                'Pinned compiler stack probe has an external dependency')
        run([dump, '-d', str(runtime_dir / '_chkstk_ms.o')], 'stack-probe.disassembly.txt')
        dll = out / 'NTWLDC.DLL'
        run([cc, '-nostdlib', '-shared', '-Wl,--no-undefined',
             '-Wl,--exclude-all-symbols', '-Wl,--strip-all',
             '-Wl,--disable-runtime-pseudo-reloc', '-Wl,--entry,_DllMain@12',
             '-Wl,--subsystem,windows:4.10', '-Wl,--major-os-version,4',
             '-Wl,--minor-os-version,10', '-Wl,--major-image-version,4',
             '-Wl,--minor-image-version,10', '-Wl,--disable-dynamicbase',
             '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp',
             '-Wl,--out-implib,' + str(out / 'libNTWLDC.a'),
             '-Wl,-Map,' + str(out / 'link.map'), '-o', str(dll),
             *[str(p) for p in objects], str(frozen / 'ntwin32/load_config/native.def'),
             str(frozen_runtime)], 'link.log')
        unresolved = undefined(run([nm, '--undefined-only', str(dll)], 'dll.undefined.txt'))
        require(not unresolved, 'Linked DLL still has undefined symbols')
        if '___chkstk_ms' in external:
            require(str(frozen_runtime) + '(_chkstk_ms.o)' in (out / 'link.map').read_text(),
                    'Stack probe did not originate from the pinned compiler archive')
            receipt['stack_probe'] = inspect_stack_probe(dll, out / 'link.map', probe_text)
            receipt['stack_probe']['object_sha256'] = sha(runtime_dir / '_chkstk_ms.o')
        run([dump, '-p', str(dll)], 'dll.headers.txt')
        run([dump, '-d', str(dll)], 'dll.disassembly.txt')
        receipt['artifact'] = inspect_dll(dll)
        receipt['import_library'] = {'path': str(out / 'libNTWLDC.a'), 'sha256': sha(out / 'libNTWLDC.a')}
        receipt['undefined_symbols'] = unresolved
        receipt['sources_after'] = {name: sha(ROOT / name) for name in SOURCES}
        require(receipt['sources_after'] == before, 'Original source changed during build')
        require(sha(host_path) == args.host_receipt_sha and sha(runtime) == runtime_sha,
                'Reviewed receipt or original compiler runtime changed during build')
        require(all(sha(Path(item['path'])) == item['sha256'] for item in tools.values()),
                'Original tool changed during build')
        receipt['sources_unchanged'] = True
        receipt['status'] = 'NATIVE_LINK_STATIC_PASS_EXECUTION_PENDING'
        receipt['scope'] = 'PE32 native API container; no guest load/API execution, entropy source or mitigation enforcement supplied.'
    except Exception as error:
        receipt['error'] = str(error)
    save(out / 'build-receipt.json', receipt)
    print(json.dumps({'status': receipt['status'], 'receipt': str(out / 'build-receipt.json'),
                      'native_executed': False, 'error': receipt.get('error')}))
    return 0 if receipt['status'] == 'NATIVE_LINK_STATIC_PASS_EXECUTION_PENDING' else 1


if __name__ == '__main__':
    sys.exit(main())
