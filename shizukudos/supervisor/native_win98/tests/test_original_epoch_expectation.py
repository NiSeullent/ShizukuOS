# SPDX-License-Identifier: GPL-2.0-only
"""Host controls for the original-epoch VGACFG/W98PERS expectation encoder.

Inputs are synthetic QMP-shaped paused snapshots and a synthetic standard-VGA
option ROM/receipt; the encoder, native_epoch_host validators, builder
validators and real Attempt minting are production code.  No QEMU, VM,
firmware or media is used: this proves encoding/refusal only, never a live
device epoch, display, persistence or install result.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import time
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import original_epoch_expectation as enc  # noqa: E402

host = enc.host
ECAM = 0xb0000000
VGA_BASE = 0xc0000000
FLAT = ('FlatView #0\n AS "memory", root: system\n Root memory region: system\n'
        '  0000000000000000-000000007fffffff (prio 0, ram): pc.ram kvm\n'
        '  00000000b0000000-00000000bfffffff (prio 0, i/o): pcie-mmcfg-mmio\n\n')


def rom_image():
    rom = bytearray(65536); extent = 64 * 512
    rom[0:3] = b'\x55\xaa\x40'; struct.pack_into('<H', rom, 0x18, 0x40)
    rom[0x40:0x44] = b'PCIR'; struct.pack_into('<HH', rom, 0x44, 0x1234, 0x1111)
    struct.pack_into('<H', rom, 0x4a, 24); rom[0x4d:0x50] = b'\x00\x00\x03'
    struct.pack_into('<H', rom, 0x50, 64); rom[0x54] = 0; rom[0x55] = 0x80
    rom[extent - 1] = (-sum(rom[:extent - 1])) % 256
    return bytes(rom)


def receipt_for(rom, base):
    rows = [{'path': 'vgasrc/vgabios.c', 'bytes': 10, 'mode': 0o644, 'sha256': hashlib.sha256(b'v').hexdigest()}]
    manifest = (json.dumps(rows, indent=2) + '\n').encode(); config = b'CONFIG_VGA_BOCHS=y\n'
    raw = rom[:64 * 512]
    pin = lambda name, data: {'path': str(base / name), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
    return {'schema': 'shizukuos.actual-source-built-stdvga-rom.v1', 'status': 'ACTUAL_SOURCE_BOUND_STDVGA_ROM_BUILT_NOT_RUN',
            'source_files': rows, 'source_tree_digest_sha256': hashlib.sha256(manifest).hexdigest(),
            'generated_configuration_sha256': hashlib.sha256(config).hexdigest(),
            'raw_ROM': {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()},
            'padded_ROM': {'bytes': 65536, 'sha256': hashlib.sha256(rom).hexdigest()},
            'PCIR': {'vendor_id': 0x1234, 'device_id': 0x1111, 'image_bytes': len(raw), 'code_type': 0, 'last_image': 128},
            'RAM_artifact_pins': {'source-manifest.json': pin('source-manifest.json', manifest),
                                  'generated.config': pin('generated.config', config),
                                  'vgabios-stdvga.bin': pin('vgabios-stdvga.bin', raw), 'VGAROM.BIN': pin('VGAROM.BIN', rom)},
            'all_original_copied_source_tools_config_RDLKs_held_through_build_final_SHA': True,
            'exact_source_and_primary_tools_final_SHA_unchanged': True, 'actual_final_unit_descendant_census_empty': True,
            'VM_executed': False, 'public_artifact': False, 'complete_SDK_shared_library_closure': False}


def mem(bar, address, size, prefetch=False, wide=False):
    return {'bar': bar, 'type': 'memory', 'address': address, 'size': size, 'prefetch': prefetch, 'mem_type_64': wide}


def xp(address, words):
    lines = []
    for i in range(0, len(words), 4):
        lines.append('%016x:%s' % (address + 4 * i, ''.join(' 0x%08x' % w for w in words[i:i + 4])))
    return '\n'.join(lines) + '\n'


def snapshot(disk='legacy'):
    vga_words = [0x11111234, 0x00000003, 0x03000002, 0, VGA_BASE | 8, 0, 0xc1000000, 0, 0, 0]
    devices = [{'bus': 0, 'slot': 0, 'function': 0, 'class_info': {'class': 0x0600}, 'id': {'vendor': 0x8086, 'device': 0x29c0},
                'regions': [], 'qdev_id': ''},
               {'bus': 0, 'slot': 1, 'function': 0, 'class_info': {'class': 0x0300}, 'id': {'vendor': 0x1234, 'device': 0x1111},
                'regions': [mem(0, VGA_BASE, 16 << 20, prefetch=True), mem(2, 0xc1000000, 4096), mem(6, 0xc1010000, 65536)],
                'qdev_id': ''}]
    regions = [{'bar': 0, 'type': 'io', 'address': 0xc000, 'size': 64}, mem(1, 0xc1020000, 4096)]
    disk_words = [0x10011af4, 0x00000007, 0x01000000, 0, 0xc001, 0xc1020000, 0, 0, 0, 0]
    if disk == 'modern':   # q35 root-bus transitional virtio: 64-bit prefetchable BAR4 (default OVMF: above 4 GiB)
        regions.append(mem(4, 0x800000000, 16384, prefetch=True, wide=True)); disk_words[8:10] = [0x0000000c, 0x8]
    if disk == 'low32':    # same device with X-PciMmio64Mb=0 (persist-b8 physical probe shape): BAR4 below 4 GiB
        regions.append(mem(4, 0xc1030000, 16384, prefetch=True, wide=True)); disk_words[8:10] = [0xc103000c, 0]
    devices.append({'bus': 0, 'slot': 2, 'function': 0, 'class_info': {'class': 0x0100},
                    'id': {'vendor': 0x1af4, 'device': 0x1001}, 'regions': regions, 'qdev_id': ''})
    return {'query-status': {'running': False, 'singlestep': False, 'status': 'paused'}, 'info-mtree-f': FLAT,
            'query-pci': [{'bus': 0, 'devices': devices}],
            'xp': {'8': xp(ECAM + 8 * 4096, vga_words), '16': xp(ECAM + 16 * 4096, disk_words)}}


ARGV = ['/usr/libexec/qemu-kvm', '-machine', 'q35,accel=kvm', '-device', 'VGA',
        '-device', 'virtio-blk-pci,drive=esp,bootindex=1']


def observation(disk='legacy', persistence=False, knob=None):
    # The persistence probe recipe carries OVMF's 64-bit aperture knob exactly
    # once (HostGrant pins it iff role 2); console-only probes never do.
    snap = snapshot(disk)
    if not persistence: del snap['xp']['16']
    argv = list(ARGV) + (['-fw_cfg', host.MMIO64_OFF] if (persistence if knob is None else knob) else [])
    return {'schema': enc.OBSERVATION_SCHEMA, 'probe_recipe_argv': argv, 'snapshots': [snap, copy.deepcopy(snap)]}


class ExpectationEncoder(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')); self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve(); os.chmod(self.dir, 0o700)
        self.rom = rom_image(); self.receipt = receipt_for(self.rom, self.dir)

    def run_cli(self, obs, persistence=False, name='out'):
        for file, data in (('obs.json', json.dumps(obs).encode()), ('VGAROM.BIN', self.rom),
                           ('build-result.json', json.dumps(self.receipt).encode())):
            (self.dir / file).write_bytes(data)
        args = ['--observation', str(self.dir / 'obs.json'), '--vga-rom', str(self.dir / 'VGAROM.BIN'),
                '--vga-build-receipt', str(self.dir / 'build-result.json'), '--out', str(self.dir / name)]
        enc.main(args + (['--with-persistence'] if persistence else []))
        return json.loads((self.dir / name / 'expectation.json').read_text())

    def test_vga_only_console_first_expectation(self):
        record = self.run_cli(observation())
        vga = (self.dir / 'out' / 'VGACFG.BIN').read_bytes()
        self.assertEqual(len(vga), 136); self.assertFalse((self.dir / 'out' / 'W98PERS.BIN').exists())
        self.assertEqual(struct.unpack_from('<6I2Q', vga), (0x41475657, 1, 136, 1, 8, 0, VGA_BASE, 16 << 20))
        self.assertEqual(vga[40:72], hashlib.sha256(self.rom).digest())
        self.assertEqual(vga[72:104].hex(), self.receipt['source_tree_digest_sha256'])
        self.assertEqual(vga[104:136].hex(), self.receipt['generated_configuration_sha256'])
        frag = record['intent_fragment']
        self.assertEqual(frag['raw_bars'], {'1': [VGA_BASE | 8, 0, 0xc1000000, 0, 0, 0]})
        self.assertEqual(set(frag['optional_native_inputs']), {'VGACFG.BIN', 'VGAROM.BIN'})
        self.assertTrue(all(record[f] is False for f in enc.FALSE_FLAGS))
        self.assertEqual(record['status'], 'EXPECTATION_ONLY_NOT_AUTHORITY')
        # The real live-authority Attempt accepts the expectation (it still owns nonce/policy/grant).
        attempt = host.Attempt(self.pinned(frag['optional_native_inputs']['VGACFG.BIN']),
                               self.pinned(frag['optional_native_inputs']['VGAROM.BIN']), None,
                               {int(k): tuple(v) for k, v in frag['raw_bars'].items()}, time.monotonic_ns() + 10 ** 10)
        self.addCleanup(attempt.close)
        self.assertEqual(len(attempt.policy), 256)

    def pinned(self, row):
        import fcntl
        fd = os.open(row['path'], os.O_RDONLY | os.O_NOFOLLOW)
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        def release():
            fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK); os.close(fd)
        self.addCleanup(release)
        return host.PinnedFD(fd, row)

    def test_virtio_low32_aperture_persistence_expectation(self):
        record = self.run_cli(observation(disk='low32', persistence=True), persistence=True)
        pers = (self.dir / 'out' / 'W98PERS.BIN').read_bytes()
        self.assertEqual(len(pers), 192)
        self.assertEqual(struct.unpack_from('<II4H', pers), (0x52503957, 1, 16, 0x1af4, 0x1001, 0))
        self.assertEqual(struct.unpack_from('<QQII', pers, 40 + 4 * 24), (0xc1030000, 16384, 2, 0))   # MEM64; raw pins prefetch
        self.assertEqual(record['intent_fragment']['raw_bars']['2'], [0xc001, 0xc1020000, 0, 0, 0xc103000c, 0])

    def test_persistence_observation_without_aperture_knob_refused(self):
        for disk in ('low32', 'legacy'):
            with self.subTest(disk=disk), self.assertRaisesRegex(ValueError, 'aperture knob must match'):
                enc.encode(observation(disk=disk, persistence=True, knob=False), self.rom, self.receipt, True)
        with self.assertRaisesRegex(ValueError, 'aperture knob must match'):   # console-only probe must not carry it
            enc.encode(observation(knob=True), self.rom, self.receipt, False)
        with self.assertRaisesRegex(ValueError, r'above 4 GiB; probe/launch with name=opt/ovmf/X-PciMmio64Mb,string=0'):
            enc.encode(observation(disk='modern', persistence=True), self.rom, self.receipt, True)

    def refuse(self, obs, persistence=False, rom=None, receipt=None):
        with self.assertRaises(ValueError):
            enc.encode(obs, self.rom if rom is None else rom, self.receipt if receipt is None else receipt, persistence)

    def test_refusals(self):
        cases = []
        o = observation(); o['snapshots'][0]['query-status']['status'] = 'running'; cases.append(o)
        o = observation(); o['snapshots'][1]['query-status']['running'] = True; cases.append(o)
        o = observation(); o['snapshots'].pop(); cases.append(o)
        o = observation(); o['snapshots'][1]['query-pci'][0]['devices'][1]['regions'][1]['address'] = 0xc2000000
        cases.append(o)                                        # snapshots differ (BAR moved)
        o = observation(); o['snapshots'][0]['query-pci'][0]['devices'][1]['id']['vendor'] = 0x1013; cases.append(o)
        o = observation(); o['snapshots'][0]['query-pci'][0]['devices'][0]['class_info']['class'] = 0x0380; cases.append(o)
        o = observation(); o['snapshots'][0]['query-pci'][0]['devices'][1]['regions'][0]['size'] = 8 << 20; cases.append(o)
        o = observation(); o['snapshots'][0]['query-pci'][0]['devices'][1]['regions'][0]['address'] = -1; cases.append(o)
        o = observation(); o['snapshots'][0]['xp']['8'] = xp(ECAM + 8 * 4096, [0x11111234, 3, 0x03000002, 0,
                                                                               0xd0000008, 0, 0xc1000000, 0, 0, 0])
        cases.append(o)                                        # raw BAR0 differs from query-pci
        o = observation(); o['snapshots'][0]['xp']['8'] = xp(ECAM + 8 * 4096, [0x11111234, 0, 0x03000002, 0,
                                                                               VGA_BASE | 8, 0, 0xc1000000, 0, 0, 0])
        cases.append(o)                                        # decode disabled
        o = observation(); o['snapshots'][0]['xp']['16'] = o['snapshots'][1]['xp']['8']; cases.append(o)  # extra read
        o = observation(); o['snapshots'][0]['info-mtree-f'] = FLAT.replace('pcie-mmcfg-mmio', 'other'); cases.append(o)
        o = observation(); o['probe_recipe_argv'] = ['/usr/libexec/qemu-kvm']; cases.append(o)
        o = observation(); o['schema'] = 'hand-written'; cases.append(o)
        o = observation()
        for snap in o['snapshots']: snap['query-pci'][0]['devices'][1]['regions'][2]['address'] = 0xc0800000
        cases.append(o)                                        # ROM BAR overlaps LFB (live validate_pci refuses)
        for i, o in enumerate(cases):
            with self.subTest(case=i): self.refuse(o)
        self.refuse(observation(disk='modern', persistence=True), persistence=True)  # BAR4 above 4 GiB
        self.refuse(observation(), persistence=True)                                  # no persistence xp read
        self.refuse(observation(), rom=self.rom[:-1] + b'\x01')                       # ROM differs from receipt
        self.refuse(observation(), receipt=dict(self.receipt, generated_configuration_sha256='0' * 64))

    def test_cli_refuses_existing_output_and_unowned_parent(self):
        (self.dir / 'out').mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.run_cli(observation())
        os.chmod(self.dir, 0o755)
        try:
            with self.assertRaises(ValueError): self.run_cli(observation(), name='fresh')
        finally:
            os.chmod(self.dir, 0o700)

    def test_cli_refuses_tampered_receipt_digest(self):
        self.receipt['source_tree_digest_sha256'] = hashlib.sha256(b'other').hexdigest()
        with self.assertRaises(ValueError): self.run_cli(observation())
        self.assertFalse((self.dir / 'out').exists())


if __name__ == '__main__':
    unittest.main()
