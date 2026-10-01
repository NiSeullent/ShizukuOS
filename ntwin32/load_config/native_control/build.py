#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze and compile genuine Win98 API observers; no Windows/VM execution."""
import argparse
import ast
import datetime
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
CB = ROOT / 'build/callback-ingress-c009-20261001-v4'
DLL = ROOT / 'build/load-config-c009-native-dll-20261001-v2'
HOST = ROOT / 'build/load-config-c009-large-20261001-v2/host-result.json'
OWN = 'ntwin32/load_config/native_control/'
PINS = {
    CB / 'result.json': 'f16035917f678a8020d394a1a93f958d2d21826f13512cb71490a252d9137f61',
    CB / 'manifest.json': '81ff086abc7fc7401fb5e9556dcb928450e12206d8de83f604b734497202112e',
    DLL / 'build-receipt.json': 'c3ee6cd1378d2c04797296d3f7352a9c9837e9b3acdbbc8fadc42bd28e93dbf2',
    HOST: 'fbd2507f8de7eea1261b9655918109ea39477f274ab3733b4b0f7f5881e06e3c',
    DLL / 'NTWLDC.DLL': '0929c7d80cb2de7ce06c24fd3790ab71721c758c8e9413d3646689a4e2936b23',
}

def require(ok, reason):
    if not ok:
        raise ValueError(reason)

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def dump(p, value):
    p.write_text(json.dumps(value, indent=2) + '\n')

def fnv(data):
    h = 2166136261
    for b in data:
        h = ((h ^ b) * 16777619) & 0xffffffff
    return h

class PE:
    def __init__(self, p):
        self.b = Path(p).read_bytes()
        self.p = Path(p)
        require(len(self.b) < 1024 * 1024 and self.b[:2] == b'MZ', 'bounded DOS/PE image')
        e = self.u32(60)
        require(self.take(e, 4) == b'PE\0\0', 'PE signature')
        self.o = e + 24
        self.characteristics = self.u16(e + 22)
        require(self.u16(e + 4) == 0x14c and self.u16(self.o) == 0x10b and self.u16(e + 20) == 224, 'I386 PE32 required')
        self.headers = self.u32(self.o + 60)
        self.sections = []
        for i in range(self.u16(e + 6)):
            s = self.o + 224 + i * 40
            self.take(s, 40)
            span, va, size, raw = struct.unpack_from('<IIII', self.b, s + 8)
            flags = self.u32(s + 36)
            self.take(raw, size)
            self.sections.append((va, max(span, size), size, raw, flags))
        require(0 < len(self.sections) <= 32, 'bounded sections')

    def take(self, p, n):
        require(0 <= p <= len(self.b) and 0 <= n <= len(self.b) - p, 'raw PE bounds')
        return self.b[p:p + n]

    def u16(self, p):
        return struct.unpack('<H', self.take(p, 2))[0]

    def u32(self, p):
        return struct.unpack('<I', self.take(p, 4))[0]

    def at(self, r, n):
        if r < self.headers and n <= self.headers - r:
            self.take(r, n)
            return r
        for va, span, size, raw, flags in self.sections:
            if va <= r <= va + size and n <= va + size - r:
                self.take(raw + r - va, n)
                return raw + r - va
        raise ValueError('RVA not raw-backed')

    def string(self, r):
        b = bytearray()
        for i in range(256):
            v = self.b[self.at(r + i, 1)]
            if not v:
                return b.decode('ascii')
            b.append(v)
        raise ValueError('unterminated PE string')

    def directory(self, n):
        return self.u32(self.o + 96 + n * 8), self.u32(self.o + 100 + n * 8)

    def executable(self, r):
        return any(va <= r < va + span and flags & 0xe0000000 == 0x60000000 for va, span, size, raw, flags in self.sections)

    def exports(self):
        r, n = self.directory(0)
        d = self.at(r, 40)
        count, names = self.u32(d + 20), self.u32(d + 24)
        require(count == names == 8, 'exact eight original DLL exports')
        eat, nt, ords = self.at(self.u32(d + 28), 32), self.at(self.u32(d + 32), 32), self.at(self.u32(d + 36), 16)
        result = {}
        for i in range(names):
            name = self.string(self.u32(nt + 4 * i))
            ordinal = self.u16(ords + 2 * i)
            require(ordinal < count and name not in result, 'export ordinal/name')
            address = self.u32(eat + 4 * ordinal)
            require(not r <= address < r + n and self.executable(address), 'actual nonforwarded executable export')
            result[name] = address
        return result

    def imports(self):
        r, n = self.directory(1)
        require(r and 20 <= n <= 4096, 'bounded native import directory')
        d = self.at(r, n)
        result = {}
        for off in range(0, n - 19, 20):
            row = self.take(d + off, 20)
            if not any(row):
                return result
            oft, stamp, chain, name, iat = struct.unpack('<IIIII', row)
            module = self.string(name).upper()
            require(module == 'KERNEL32.DLL' and module not in result and not stamp and not chain, 'original KERNEL32 only, unbound')
            entries = []
            for j in range(128):
                v = self.u32(self.at((oft or iat) + 4 * j, 4))
                if not v:
                    break
                require(not v & 0x80000000, 'named OEM imports required')
                entries.append(self.string(v + 2))
            else:
                raise ValueError('import table count')
            result[module] = entries
        raise ValueError('missing import terminator')

    def check(self, oem):
        require(not self.characteristics & 0x2000, 'EXE container required')
        require(self.u16(self.o + 68) == 2 and self.u16(self.o + 70) == 0, 'GUI and no modern DLL flags')
        require((self.u16(self.o + 40), self.u16(self.o + 42)) == (4, 10), 'OS version 4.10')
        require((self.u16(self.o + 48), self.u16(self.o + 50)) == (4, 10), 'subsystem version 4.10')
        require(self.executable(self.u32(self.o + 16)), 'read-only executable entry')
        require(all(flags & 0xa0000000 != 0xa0000000 for va, span, size, raw, flags in self.sections), 'no writable executable section')
        require(all(self.directory(i) == (0, 0) for i in (9, 10, 13, 14)), 'no TLS/load-config/delay/CLR')
        imports = self.imports()
        require(imports and all(name in oem for name in imports['KERNEL32.DLL']), 'original OEM import gate')
        return {'machine': 'I386', 'magic': 'PE32', 'os_version': [4, 10], 'subsystem_version': [4, 10], 'dll_characteristics': 0, 'imports': imports, 'oem_import_gate': 'PASS', 'entry_rva': self.u32(self.o + 16), 'sha256': digest(self.p), 'bytes': len(self.b), 'native_executed': False}

def build(out):
    require(out.parent == ROOT / 'build' and not out.exists(), 'new assigned build directory required')
    out.mkdir()
    result = {'schema': 'win98modern.load-config-native-control.v1', 'status': 'BUILD_FAILED', 'native_executed': False, 'application_success': False, 'production_loader_integrated': False, 'mitigations_implemented': False, 'own_observer_os_exit_verified': False, 'commands': [], 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        for p, h in PINS.items():
            require(p.is_file() and not p.is_symlink() and digest(p) == h, 'original prerequisite pin changed: ' + str(p))
        lc = json.loads((DLL / 'build-receipt.json').read_text())
        host = json.loads(HOST.read_text())
        cb = json.loads((CB / 'result.json').read_text())
        manifest = json.loads((CB / 'manifest.json').read_text())
        require(host['status'] == 'PASS' and host['tests'] == 20 and not host['native_executed'] and lc['status'] == 'NATIVE_LINK_STATIC_PASS_EXECUTION_PENDING' and cb['status'] == 'HOST_BUILD_PASS_NATIVE_PENDING', 'existing receipts prerequisites')
        result['prerequisite_pins'] = {str(p): h for p, h in PINS.items()}
        result['required_peer_dependencies'] = {k: v for k, v in lc['sources_before'].items() if k.startswith(('ntwin32/native_loader/', 'platform/'))}
        paths = [OWN + n for n in ('build.py', 'README.md', 'protocol.h', 'worker.c', 'observer.c')]
        paths += ['ntwin32/load_config/load_config.h', 'ntwin32/native_loader/pe.h', 'platform/freestanding/memory.c', 'platform/freestanding/memory.h', 'ntwin32/callback_ingress/review_native.py']
        hashes = {p: digest(ROOT / p) for p in paths}
        for p in paths:
            if p in lc['sources_before']:
                require(hashes[p] == lc['sources_before'][p], 'actual DLL ABI/memory dependency differs')
            dest = out / 'frozen' / p
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / p, dest)
        result['sources'] = hashes
        result['owned_source_bytes'] = sum((ROOT / p).stat().st_size for p in paths if p.startswith(OWN))
        require(result['owned_source_bytes'] < 57344, 'compact own source budget')
        for name, p in [('lc-dll.json', DLL / 'build-receipt.json'), ('lc-host20.json', HOST), ('callback-v4.json', CB / 'result.json'), ('callback-v4-manifest.json', CB / 'manifest.json')]:
            shutil.copyfile(p, out / name)
        inventory = ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json'
        oem_data = json.loads(inventory.read_text())
        oem = oem_data['dlls']['KERNEL32.DLL']
        result['oem_inventory'] = {'path': str(inventory), 'sha256': digest(inventory), 'original_module': oem_data['modules']['KERNEL32.DLL'], 'frozen_subset': 'oem-kernel32.json'}
        dump(out / 'oem-kernel32.json', {'original_inventory_sha256': digest(inventory), 'provenance': oem_data['provenance'], 'exports': oem})
        protocol = (out / 'frozen' / (OWN + 'protocol.h')).read_text()
        export_names = re.search(r'lc_exports\[\] = \{(.*?)\};', protocol, re.S)
        names = re.findall(r'"([a-z_]+)"', export_names.group(1))
        rows = re.findall(r'\{"([A-Za-z0-9_]+)",1\}', protocol)
        require(len(names) == 8 and len(set(names)) == 8 and len(rows) == len(set(rows)), 'exact native API protocol')
        tree = ast.parse((out / 'frozen/ntwin32/callback_ingress/review_native.py').read_text())
        expected = [ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'EXPECTED' for t in n.targets)]
        require(len(expected) == 1 and len(expected[0]) == 41 and sum(expected[0].values()) == 63, 'exact frozen callback semantics')
        require(all(re.fullmatch('[A-Z0-9_]+', k) and isinstance(v, int) and 0 < v <= 4 for k, v in expected[0].items()), 'bounded callback labels')
        for item in manifest['inputs']:
            p = Path(item['source'])
            require(p.parent == CB and p.name in ('CIWRK.EXE', 'CISUIT.EXE', 'CIFIX.DLL') and digest(p) == item['sha256'] and p.stat().st_size == item['bytes'], 'exact callback input')
            shutil.copyfile(p, out / p.name)
        require(len(manifest['inputs']) == 3, 'three callback inputs')
        shutil.copyfile(DLL / 'NTWLDC.DLL', out / 'NTWLDC.DLL')
        dll = PE(out / 'NTWLDC.DLL')
        exports = dll.exports()
        require(set(exports) == set(names) and exports == lc['artifact']['exports'], 'original executable export RVAs')
        fixture = (out / 'CIFIX.DLL').read_bytes()
        generated = '#ifndef LC_NATIVE_PIN_H\n#define LC_NATIVE_PIN_H\n'
        generated += '#define LC_PIN_BYTES %du\n#define LC_PIN_FNV 0x%08Xu\n' % (len(dll.b), fnv(dll.b))
        generated += '#define LC_PIN_IMAGE_SIZE %du\n#define LC_PIN_HEADERS %du\n#define LC_PIN_SECTIONS %du\n' % (dll.u32(dll.o + 56), dll.headers, len(dll.sections))
        generated += 'static const uint32_t LC_PIN_EXPORT_RVAS[8]={' + ','.join(str(exports[n]) + 'u' for n in names) + '};\n'
        generated += '#define LC_CB_BYTES %du\n#define LC_CB_FNV 0x%08Xu\n' % (len(fixture), fnv(fixture))
        generated += 'static const lc_row LC_CB_ROWS[]={' + ','.join('{"%s",%du}' % (k, v) for k, v in expected[0].items()) + '};\n#endif\n'
        (out / 'frozen' / (OWN + 'pin.h')).write_text(generated)
        result['generated_pin_sha256'] = digest(out / 'frozen' / (OWN + 'pin.h'))
        result['expected_api_checks'] = len(rows)
        result['expected_callback_checks'] = 63
        tools = {}
        for name in ('gcc', 'nm', 'objdump'):
            p = Path(shutil.which('i686-w64-mingw32-' + name) or '')
            require(p.is_file(), 'installed compiler/binutils required')
            tools[name] = {'path': str(p), 'sha256': digest(p), 'version': subprocess.check_output([str(p), '--version'], text=True).splitlines()[0]}
        result['tools'] = tools
        gcc = tools['gcc']['path']
        result['real_link_libraries'] = {}
        for key, arg in [('libgcc', '-print-libgcc-file-name'), ('kernel32', '-print-file-name=libkernel32.a')]:
            p = Path(subprocess.check_output([gcc, arg], text=True).strip())
            require(p.is_file(), 'real installed link library')
            result['real_link_libraries'][key] = {'path': str(p), 'sha256': digest(p)}

        def run(argv, log):
            value = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            (out / log).write_bytes(value.stdout)
            result['commands'].append({'argv': argv, 'argv_sha256': hashlib.sha256(json.dumps(argv, separators=(',', ':')).encode()).hexdigest(), 'exit_code': value.returncode, 'log': log, 'log_sha256': digest(out / log)})
            require(value.returncode == 0, 'compile/inspection failed; preserved: ' + log)
            return value.stdout.decode()

        flags = ['-std=c11', '-march=i486', '-mtune=i486', '-Os', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation', '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-tree-loop-distribute-patterns', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables', '-mno-sse', '-mno-mmx', '-msoft-float']
        result['object_undefined_symbols'] = {}
        for name, source in [('memory', 'platform/freestanding/memory.c'), ('worker', OWN + 'worker.c'), ('observer', OWN + 'observer.c')]:
            obj = out / (name + '.o')
            run([gcc, *flags, '-c', str(out / 'frozen' / source), '-o', str(obj)], name + '-compile.log')
            symbols = run([tools['nm']['path'], '-u', str(obj)], name + '-undefined.log')
            result['object_undefined_symbols'][name] = [s.split()[-1] for s in symbols.splitlines() if s.strip()]
            require(not any('np_' in s for s in result['object_undefined_symbols'][name]), 'DLL APIs must be dynamically resolved')
        result['artifacts'] = {}
        link = ['-nostdlib', '-Wl,--no-undefined', '-Wl,--entry,_entry@0', '-Wl,--subsystem,windows:4.10', '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10', '-Wl,--major-image-version,4', '-Wl,--minor-image-version,10', '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp', '-Wl,--strip-all']
        for source, name in [('worker', 'LCWORK.EXE'), ('observer', 'LCJOIN.EXE')]:
            run([gcc, *flags, *link, str(out / (source + '.o')), str(out / 'memory.o'), '-lkernel32', '-lgcc', '-o', str(out / name)], source + '-link.log')
            run([tools['objdump']['path'], '-p', str(out / name)], source + '-pe.log')
            result['artifacts'][name] = PE(out / name).check(set(oem))
        require({'LoadLibraryA', 'GetProcAddress', 'FreeLibrary', 'GetModuleFileNameA'} <= set(result['artifacts']['LCWORK.EXE']['imports']['KERNEL32.DLL']), 'real native DLL APIs')
        require({'CreateProcessA', 'WaitForSingleObject', 'GetExitCodeProcess'} <= set(result['artifacts']['LCJOIN.EXE']['imports']['KERNEL32.DLL']), 'real native exit observer APIs')
        result['sources_after'] = {p: digest(ROOT / p) for p in paths}
        require(result['sources_after'] == hashes and all(digest(p) == h for p, h in PINS.items()), 'immutable source/prerequisite preservation')
        result['sources_unchanged'] = True
        inputs = [{'source': str(out / n), 'guest': 'C:\\VXDLAB\\' + n, 'bytes': (out / n).stat().st_size, 'sha256': digest(out / n)} for n in ('CIFIX.DLL', 'CIWRK.EXE', 'CISUIT.EXE', 'NTWLDC.DLL', 'LCWORK.EXE', 'LCJOIN.EXE')]
        dump(out / 'manifest.json', {'schema': 1, 'kind': 'isolated-guest-file-inputs', 'inputs': inputs, 'outputs': ['C:\\VXDLAB\\' + n for n in ('CIWRK.LOG', 'CISUIT.LOG', 'LCWORK.LOG', 'LCOBS.LOG', 'LCJOIN.LOG')], 'backups': [], 'source_receipts': [{'path': str(p), 'sha256': h} for p, h in PINS.items() if p.suffix == '.json'], 'command': 'C:\\VXDLAB\\LCJOIN.EXE', 'scope': 'One observer process: actual CISUIT exit then actual LCWORK exit; five fresh raw logs. Own LCJOIN exit unknown. Native pending; no apps/production integration.'})
        result['manifest_sha256'] = digest(out / 'manifest.json')
        result['output_bytes_before_receipt'] = sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
        require(result['output_bytes_before_receipt'] < 2 * 1024 * 1024 - 65536, 'compact build output budget')
        result['status'] = 'HOST_BUILD_STATIC_PASS_NATIVE_PENDING'
    except Exception as error:
        result['failure'] = str(error)
        raise
    finally:
        dump(out / 'result.json', result)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    build(args.out.resolve())
