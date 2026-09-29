"""Contract and malformed-image tests against an actual linked PE fixture.
SPDX-License-Identifier: GPL-2.0-only
"""
import importlib.util
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('ntw_prepare', ROOT / 'ntwin32/prepare.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class PrepareTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = (ROOT / 'build/platform/probe-original.exe').read_bytes()
        cls.pe = mod.PE(cls.original)

    def changed(self, offset, fmt, value):
        copy = bytearray(self.original)
        struct.pack_into(fmt, copy, offset, value)
        return bytes(copy)

    def test_routing_preserves_native_loader_iat(self):
        result, report = mod.prepare(self.original)
        new = mod.PE(result)
        supported = set(mod.routes()['exports'])
        self.assertEqual(set(report['redirected']), supported)
        old_slots = {}
        for desc in self.pe.imports():
            for val, name, iat in desc['entries']:
                old_slots[iat] = (name, 'NTW32.DLL' if name in supported else desc['dll'])
        # Model a loader walking the NEW ILTs and writing ORIGINAL IAT RVAs.
        mapped = bytearray(new.u32(new.opt + 56))
        seen = {}
        for desc in new.imports():
            for val, name, iat in desc['entries']:
                self.assertNotIn(iat, seen)
                seen[iat] = (name, desc['dll'])
                token = len(seen) + 0x10000000
                struct.pack_into('<I', mapped, iat, token)
        self.assertEqual(seen, old_slots)
        self.assertEqual(new.u32(new.opt + 16), self.pe.u32(self.pe.opt + 16))
        self.assertFalse(report['guest_verified'])
        for _, _, rp, rs in self.pe.sections:
            self.assertEqual(result[rp:rp+rs], self.original[rp:rp+rs])

    def test_deterministic_and_no_second_routing(self):
        first, _ = mod.prepare(self.original)
        self.assertEqual(first, mod.prepare(self.original)[0])
        with self.assertRaisesRegex(mod.PEError, 'no supported imports'):
            mod.prepare(first)

    def test_unsupported_execution_paths(self):
        cases = [(self.pe.pe+4, '<H', 0x8664), (self.pe.opt+32, '<I', 3),
                 (self.pe.opt+70, '<H', 0x4000)]
        cases += [(self.pe.opt+96+i*8, '<I', 0x1000) for i in (4, 9, 10, 13, 14)]
        for offset, fmt, value in cases:
            with self.subTest(offset=offset), self.assertRaises(mod.PEError):
                mod.prepare(self.changed(offset, fmt, value))

    def test_retains_newer_subsystem_and_nx_without_rewriting(self):
        data = bytearray(self.changed(self.pe.opt + 48, '<H', 6))
        struct.pack_into('<H', data, self.pe.opt + 50, 1)
        struct.pack_into('<H', data, self.pe.opt + 70, 0x100)
        prepared, report = mod.prepare(bytes(data))
        new = mod.PE(prepared)
        self.assertEqual((new.u16(new.opt + 48), new.u16(new.opt + 50)), (6, 1))
        self.assertEqual(new.u16(new.opt + 70) & 0x100, 0x100)
        self.assertFalse(report['subsystem_version_downgraded'])
        self.assertFalse(report['stock_win98_loader_accepts_subsystem'])
        self.assertFalse(report['nx_enforced'])
        self.assertFalse(report['browser_functionality_verified'])

    def test_header_slack_and_truncation(self):
        with self.assertRaisesRegex(mod.PEError, 'slack'):
            mod.prepare(self.changed(self.pe.table+self.pe.count*40, '<I', 1))
        for size in (0, 32, 64, self.pe.pe+4, self.pe.headers-1, 1024):
            with self.subTest(size=size), self.assertRaises(mod.PEError):
                mod.prepare(self.original[:size])

    def test_malformed_import_tables(self):
        rva, size = self.pe.directory(1)
        offset = self.pe.offset(rva)
        cases = [(offset, '<I', 0xfffffff0),
                 (offset+12, '<I', 0xfffffff0),
                 (offset+16, '<I', 0xfffffff0),
                 (self.pe.opt+108, '<I', 20)]
        for at, fmt, val in cases:
            with self.subTest(at=at), self.assertRaises(mod.PEError):
                mod.prepare(self.changed(at,fmt,val))

    def test_iat_cannot_overwrite_headers_or_code(self):
        descriptor = self.pe.offset(self.pe.directory(1)[0])
        for target in (self.pe.opt + 16, self.pe.sections[0][0]):
            with self.subTest(target=target), self.assertRaisesRegex(mod.PEError, 'IAT'):
                mod.prepare(self.changed(descriptor + 16, '<I', target))

    def test_directory_count_must_fit_supported_header(self):
        for count in (0, 15, 17, 0xffffffff):
            with self.subTest(count=count), self.assertRaisesRegex(mod.PEError, 'directories'):
                mod.prepare(self.changed(self.pe.opt + 92, '<I', count))

    def test_oft_zero_and_bound_without_oft(self):
        offset = self.pe.offset(self.pe.directory(1)[0])
        unbound = self.changed(offset, '<I', 0)
        mod.prepare(unbound)
        bound = bytearray(unbound)
        struct.pack_into('<I', bound, offset+4, 1)
        with self.assertRaisesRegex(mod.PEError, 'bound imports'):
            mod.prepare(bytes(bound))

    def test_bounded_mutations_never_crash_parser(self):
        rng = random.Random(98)
        for _ in range(256):
            damaged = bytearray(self.original)
            offset = rng.randrange(len(damaged))
            damaged[offset] ^= rng.randrange(1, 256)
            try:
                out, _ = mod.prepare(bytes(damaged))
                mod.PE(out).imports()
            except mod.PEError:
                pass

    def test_cli_preserves_existing_files(self):
        with tempfile.TemporaryDirectory(dir=ROOT / 'build/platform') as temp:
            source, dest = Path(temp)/'in.exe', Path(temp)/'out.exe'
            source.write_bytes(self.original)
            dest.write_bytes(b'preserve')
            proc = subprocess.run([sys.executable, str(ROOT/'ntwin32/prepare.py'),
                                   str(source), str(dest)], capture_output=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(dest.read_bytes(), b'preserve')
            self.assertEqual(source.read_bytes(), self.original)

    def test_provider_native_imports_and_exports(self):
        provider = mod.PE((ROOT / 'build/platform/NTW32.DLL').read_bytes())
        imported = [(d['dll'].upper(), e[1]) for d in provider.imports() for e in d['entries']]
        self.assertEqual(set(imported), {('KERNEL32.DLL', name) for name in
            ('GetTickCount','Sleep','GetModuleHandleA','GetProcAddress','SetLastError',
             'MultiByteToWideChar','WideCharToMultiByte',
             # WIN64 subsystem client (ntwin32/win64/ntw64.c): the NTWRAP9X.VXD transport
             'CreateFileA','DeviceIoControl','GetLastError')})
        export_rva, _ = provider.directory(0)
        exports = provider.offset(export_rva, 40)
        count = provider.u32(exports+24)
        names = provider.u32(exports+32)
        observed = {provider.string(provider.u32(provider.offset(names+i*4,4))) for i in range(count)}
        plan = mod.routes()
        self.assertEqual(observed, set(plan['exports']) | set(plan['provider_api']))
        self.assertFalse(set(plan['exports']) & set(plan['provider_api']))
        self.assertNotIn('get_api_table', observed)
        self.assertEqual((provider.u16(provider.opt+48),provider.u16(provider.opt+50)), (4,10))

    def test_win64_front_end_imports(self):
        tool = mod.PE((ROOT / 'build/platform/NTW64RUN.EXE').read_bytes())
        imported = {(d['dll'].upper(), e[1]) for d in tool.imports() for e in d['entries']}
        self.assertEqual({name for dll, name in imported if dll == 'NTW32.DLL'},
                         set(mod.routes()['provider_api']))
        self.assertEqual({dll for dll, _ in imported}, {'NTW32.DLL', 'KERNEL32.DLL'})
        self.assertEqual((tool.u16(tool.opt+48), tool.u16(tool.opt+50)), (4, 10))
        self.assertEqual(tool.u16(tool.opt+68), 3)          # console subsystem
        self.assertEqual(tool.u16(tool.pe+4), 0x14c)        # i386 PE32

    def test_provider_cannot_redirect_its_own_native_loader_imports(self):
        with self.assertRaisesRegex(mod.PEError, 'self-routing'):
            mod.prepare((ROOT/'build/platform/NTW32.DLL').read_bytes())

    def test_provider_has_project_version_resource(self):
        provider = mod.PE((ROOT/'build/platform/NTW32.DLL').read_bytes())
        rva, size = provider.directory(2)
        self.assertGreater(size, 0)
        payload = provider.take(provider.offset(rva, size), size)
        self.assertIn("Windows 98 Shizuku's Second Edition".encode('utf-16le'), payload)

if __name__ == '__main__':
    unittest.main()
