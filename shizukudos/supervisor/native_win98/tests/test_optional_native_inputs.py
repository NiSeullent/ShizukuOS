#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Tiny actual input FD/lease controls; firmware provenance is synthetic metadata.

Compilation, ESP construction and large disk geometry are explicitly modeled.
No compiler, mtools, private media, NAS, device or VM is executed.
"""
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result)
    return result
B = module('optional_fixture_builder', HERE / 'build.py')
G = module('optional_fixture_custody', HERE / 'task_custody.py')
def sha(raw): return hashlib.sha256(raw).hexdigest()
def serial(value): return (json.dumps(value, indent=2) + '\n').encode()
def pinned(path): return {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path.read_bytes())}

def firmware():
    raw = bytearray(512); raw[:6] = b'\x55\xaa\x01\xe9\x3a\x00'
    struct.pack_into('<H', raw, 24, 32)
    raw[32:36] = b'PCIR'; struct.pack_into('<HH', raw, 36, 0x1234, 0x1111)
    struct.pack_into('<H', raw, 42, 24); raw[47] = 3
    struct.pack_into('<H', raw, 48, 1); raw[53] = 128
    raw[511] = (-sum(raw)) & 255
    padded = bytes(raw) + bytes(65536 - len(raw))
    rows = [{'path': 'vgasrc/main.c', 'bytes': 4, 'mode': 384, 'sha256': sha(b'CODE')}]
    manifest = serial(rows); config_sha = sha(b'INDEPENDENT GENERATED VGA CONFIG')
    config = struct.pack('<6I2Q', 0x41475657, 1, 136, 1, 0x10, 0, 0xe0000000, 16 << 20)
    config += bytes.fromhex(sha(padded) + sha(manifest) + config_sha)
    receipt = {'schema': 'shizukuos.actual-source-built-stdvga-rom.v1',
        'status': 'ACTUAL_SOURCE_BOUND_STDVGA_ROM_BUILT_NOT_RUN',
        'source_files': rows, 'source_tree_digest_sha256': sha(manifest),
        'generated_configuration_sha256': config_sha,
        'raw_ROM': {'bytes': 512, 'sha256': sha(raw)},
        'padded_ROM': {'bytes': 65536, 'sha256': sha(padded)},
        'PCIR': {'vendor_id': 0x1234, 'device_id': 0x1111, 'image_bytes': 512, 'code_type': 0, 'last_image': 128},
        'RAM_artifact_pins': {'source-manifest.json': {'path': '/fixture/source-manifest.json', 'bytes': len(manifest), 'sha256': sha(manifest)},
            'generated.config': {'path': '/fixture/generated.config', 'bytes': 32, 'sha256': config_sha},
            'vgabios-stdvga.bin': {'path': '/fixture/vgabios-stdvga.bin', 'bytes': 512, 'sha256': sha(raw)},
            'VGAROM.BIN': {'path': '/fixture/VGAROM.BIN', 'bytes': 65536, 'sha256': sha(padded)}},
        'all_original_copied_source_tools_config_RDLKs_held_through_build_final_SHA': True,
        'exact_source_and_primary_tools_final_SHA_unchanged': True,
        'actual_final_unit_descendant_census_empty': True,
        'VM_executed': False, 'public_artifact': False, 'complete_SDK_shared_library_closure': False}
    return config, padded, receipt

def persistence():
    return (struct.pack('<II4HQQII', 0x52503957, 1, 0x20, 0x1af4, 0x1042, 0,
                        2304 << 20, 2 << 30, 0x53485739, 0) +
            struct.pack('<QQII', 0xf0000000, 65536, 1, 0) + bytes(5 * 24 + 8))

class OptionalInputs(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
    def write(self, name, raw):
        path = self.root / name; path.write_bytes(raw); return path
    def test_malformed_optional_ABIs_are_refused_from_same_real_FD(self):
        for name, size in [('VGACFG.BIN', 136), ('VGAROM.BIN', 65536), ('W98PERS.BIN', 192)]:
            path = self.write(name, bytes(size))
            with self.subTest(name=name), B.read_leased(path, sha(bytes(size)), size) as (fd, check):
                with self.assertRaises(ValueError): B.validate_contents(name, fd)
                check()
    def fixture(self, changed=None, assemble_hook=None, omit=()):
        cfg, rom, provenance = firmware()
        raw = {'disk': bytes(510) + b'\x55\xaa' + bytes(4096 - 512),
               'rom': bytearray(256 << 10), 'config': B.config_bytes(),
               'kernel32': b'HOST K32', 'kernel64': b'HOST K64', 'win64-img': b'HOST ARCHIVE',
               'vga-config': cfg, 'vga-rom': rom, 'persistence-config': persistence(),
               'vga-build-receipt': serial(provenance)}
        raw['rom'][:7] = b'SeaBIOS'; raw['rom'][-16] = 0xea
        if changed: changed(raw, provenance)
        files = {}; args = []
        for name, body in raw.items():
            if name in omit: continue
            files[name] = self.write(name, body)
            args += ['--' + name, str(files[name]), '--' + name + '-sha256', sha(body)]
        source = self.write('fixture-source.py', b'# MODELED COMPILER NEVER EXECUTED\n')
        (self.root / 'build').mkdir(exist_ok=True)
        out = self.root / 'build/out'; returned = []
        def compile_model(argv, receipt, **kwargs):
            components = Path(argv[-1]); components.mkdir(); loader = components / 'BOOTX64.EFI'
            loader.write_bytes(b'HOST EFI'); (components / 'result.json').write_bytes(serial({
                'status': 'PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN',
                'artifacts': {'BOOTX64.EFI': {'sha256': sha(b'HOST EFI')}}}))
        def assemble_model(output, copies, loader, receipt):
            if assemble_hook: assemble_hook(files, receipt)
            esp = output / 'esp.img'; esp.write_bytes(b'HOST ESP')
            return esp, {'SHZDOS/' + name: {'bytes': path.stat().st_size, 'sha256': B.file_sha(path)}
                         for name, path in copies.items()}
        actual_read_leased = B.read_leased
        def modeled_extent_reader(path, expected, size=None, maximum=2 << 30, **kwargs):
            # Only the disk's required geometry is modeled as 4KiB. Preserve
            # actual lease/hash/FD reads for the larger ordinary firmware.
            return actual_read_leased(path, expected, size, max(maximum, size or 0), **kwargs)
        error = None
        with patch.object(B, 'ROOT', self.root), patch.object(B, 'DISK_BYTES', 4096), \
             patch.object(B, 'source_files', return_value=[source]), patch.object(B, 'space'), \
             patch.object(B, 'read_leased', modeled_extent_reader), \
             patch.object(B, 'command', compile_model), patch.object(B, 'assemble', assemble_model), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            try: B.main(args + ['--out', str(out)], receipt_sink=returned.append)
            except BaseException as caught: error = caught
        return files, out, returned, error
    def test_optional_originals_and_provenance_remain_leased_through_return(self):
        found = []
        def observe(files, receipt):
            ids = {(p.stat().st_dev, p.stat().st_ino) for p in files.values()}
            live = set()
            for name in os.listdir('/proc/self/fd'):
                try:
                    fd = int(name); info = os.fstat(fd)
                    if (info.st_dev, info.st_ino) in ids and fcntl.fcntl(fd, fcntl.F_GETLEASE) == fcntl.F_RDLCK:
                        live.add((info.st_dev, info.st_ino))
                except OSError: pass
            found.append(len(live))
        files, out, returned, error = self.fixture(assemble_hook=observe)
        self.assertIsNone(error); self.assertEqual(found, [10]); self.assertEqual(len(returned), 1)
        receipt = json.loads(returned[0])
        self.assertEqual(set(receipt['input_pins']), {'DISK.IMG','SEABIOS.BIN','WIN98CFG.BIN','KERNEL32.BIN','KERNEL64.BIN','WIN64.IMG'})
        self.assertEqual(set(receipt['optional_native_inputs']), {'VGACFG.BIN','VGAROM.BIN','W98PERS.BIN'})
        self.assertEqual(set(receipt['optional_native_provenance']), {'vga-build-receipt'})
        self.assertFalse(receipt['Windows98_boot_verified'])
        self.assertNotIn('SHZDOS/vga-build-receipt', receipt['members'])
    def validate_pair(self, config, rom, receipt):
        bodies = {'VGACFG.BIN': config, 'VGAROM.BIN': rom, 'vga-build-receipt': receipt}
        with contextlib.ExitStack() as stack:
            registry = stack.enter_context(B.ReadLeaseRegistry()); fds = {}
            for name, raw in bodies.items():
                path = self.write(name, raw)
                fd, _ = stack.enter_context(B.read_leased(path, sha(raw), len(raw), registry=registry))
                fds[name] = fd
            B.validate_optional_native({n: fds[n] for n in ('VGACFG.BIN','VGAROM.BIN')},
                                       {'vga-build-receipt': fds['vga-build-receipt']})
            registry.check()
    def test_valid_pair_uses_distinct_source_and_generated_config_digests(self):
        config, rom, receipt = firmware()
        self.validate_pair(config, rom, serial(receipt))
    def test_pair_provenance_mismatch_is_refused_even_with_recomputed_input_SHA(self):
        cases = ('ROM', 'source-manifest', 'generated-config', 'raw-ROM', 'custody', 'runtime', 'duplicate-source')
        for case in cases:
            config, rom, receipt = firmware()
            if case == 'ROM': config = config[:40] + bytes.fromhex(sha(b'OTHER ROM')) + config[72:]
            elif case == 'source-manifest': receipt['RAM_artifact_pins']['source-manifest.json']['bytes'] += 1
            elif case == 'generated-config': receipt['generated_configuration_sha256'] = sha(b'OTHER CONFIG')
            elif case == 'raw-ROM': receipt['raw_ROM']['sha256'] = sha(b'OTHER RAW ROM')
            elif case == 'custody': receipt['actual_final_unit_descendant_census_empty'] = False
            elif case == 'runtime': receipt['VM_executed'] = True
            elif case == 'duplicate-source': receipt['source_files'] *= 2
            with self.subTest(case=case), self.assertRaises(ValueError):
                self.validate_pair(config, rom, serial(receipt))
    def test_duplicate_producer_JSON_field_is_refused(self):
        config, rom, receipt = firmware()
        raw = serial(receipt).replace(b'{\n', b'{\n"schema":"forged",\n', 1)
        with self.assertRaises(ValueError): self.validate_pair(config, rom, raw)
    def test_ROM_checksum_PCIR_and_zero_padding_are_refused(self):
        _, rom, _ = firmware()
        for offset in (0, 2, 24, 32, 36, 47, 48, 52, 53, 100, 512, 65535):
            raw = bytearray(rom); raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError): B.validate_vga_rom(bytes(raw))
    def test_persistence_reserved_geometry_and_BAR_overlap_are_refused(self):
        B.validate_persistence_config(persistence())
        for offset in (0, 4, 10, 12, 14, 16, 24, 32, 36, 60, 184):
            raw = bytearray(persistence()); raw[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(ValueError): B.validate_persistence_config(bytes(raw))
        raw = bytearray(persistence()); struct.pack_into('<QQII', raw, 64, 0xf0000000, 65536, 1, 0)
        with self.assertRaises(ValueError): B.validate_persistence_config(bytes(raw))
    def test_incomplete_optional_pair_refuses_before_output(self):
        _, out, returned, error = self.fixture(omit=('vga-rom',))
        self.assertIsInstance(error, ValueError); self.assertFalse(out.exists()); self.assertEqual(returned, [])
    def test_replaced_optional_original_prevents_success_return(self):
        def replace(files, receipt): files['vga-config'].rename(self.root / 'renamed-vga-config')
        _, out, returned, error = self.fixture(assemble_hook=replace)
        self.assertIsNotNone(error); self.assertEqual(returned, [])
        self.assertEqual(json.loads((out/'result.json').read_bytes())['status'], 'FAIL_BUILD_PRESERVED')
    def test_default_six_and_public_policy_are_unchanged(self):
        _, _, returned, error = self.fixture(omit=('vga-config','vga-rom','persistence-config','vga-build-receipt'))
        self.assertIsNone(error); receipt = json.loads(returned[0])
        self.assertEqual(len(receipt['input_pins']), 6)
        self.assertNotIn('optional_native_inputs', receipt); self.assertNotIn('optional_native_provenance', receipt)
        self.assertEqual(B.boot_policy([]), b'mode=supervisor\r\nmenu_timeout=0\r\n')
        self.assertEqual(B.boot_policy(['VGACFG.BIN','VGAROM.BIN','W98PERS.BIN']),
                         b'mode=supervisor\r\nmenu_timeout=0\r\nwin98_vga=yes\r\nwin98_persistence=yes\r\n')
    def optional_maps(self):
        config, rom, receipt = firmware()
        originals = {'VGACFG.BIN': config, 'VGAROM.BIN': rom, 'W98PERS.BIN': persistence()}
        blobs = {name: pinned(self.write(name, raw)) for name, raw in originals.items()}
        provenance = {'vga-build-receipt': pinned(self.write('vga-build-receipt', serial(receipt)))}
        declared = {'optional_native_inputs': blobs, 'optional_native_provenance': provenance}
        built = json.loads(json.dumps(declared)); built['members'] = {
            'SHZDOS/'+name: {k: row[k] for k in ('bytes','sha256')} for name, row in blobs.items()}
        return declared, built
    def test_custody_holds_exact_optional_originals_and_provenance(self):
        declared, built = self.optional_maps(); union = G.LeaseUnion()
        try:
            G.admit_optional_native_inputs(declared, built, union, B)
            self.assertEqual(len(union.rows), 4)
            self.assertTrue(all(fcntl.fcntl(row['fd'],fcntl.F_GETLEASE)==fcntl.F_RDLCK for row in union.rows.values()))
            union.check()
        finally: union.close()
    def test_custody_unknown_incomplete_mismatched_or_undeclared_maps_refuse(self):
        for case in ('unknown','incomplete','missing-manifest','member-SHA','extent','empty','undeclared-member','provenance-member'):
            declared, built = self.optional_maps()
            if case == 'unknown':
                declared['optional_native_inputs']['UNKNOWN.BIN'] = declared['optional_native_inputs']['W98PERS.BIN']
                built['optional_native_inputs'] = dict(declared['optional_native_inputs'])
            elif case == 'incomplete':
                for value in (declared, built): del value['optional_native_inputs']['VGAROM.BIN']
            elif case == 'missing-manifest': del declared['optional_native_provenance']
            elif case == 'member-SHA': built['members']['SHZDOS/VGACFG.BIN']['sha256'] = sha(b'OTHER')
            elif case == 'extent':
                for value in (declared, built): value['optional_native_inputs']['W98PERS.BIN']['bytes'] = 191
            elif case == 'empty': declared['optional_native_provenance'] = {}; built['optional_native_provenance'] = {}
            elif case == 'undeclared-member':
                for value in (declared, built): del value['optional_native_inputs']['W98PERS.BIN']
            elif case == 'provenance-member': built['members']['SHZDOS/vga-build-receipt'] = {'bytes':1,'sha256':sha(b'x')}
            union = G.LeaseUnion()
            try:
                with self.subTest(case=case), self.assertRaises(ValueError):
                    G.admit_optional_native_inputs(declared, built, union, B)
            finally: union.close()

if __name__ == '__main__': unittest.main(verbosity=2)
