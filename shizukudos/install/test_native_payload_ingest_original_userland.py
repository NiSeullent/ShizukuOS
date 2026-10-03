#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Host boundary checks for the explicit original-userland SZOU route.

Host-only: exercises the actual production SZOU writer/parser and request
admission functions. It does not observe a Windows disk, install or boot.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest

SOURCE = Path(__file__).resolve().with_name('native_payload_ingest.py')
spec = importlib.util.spec_from_file_location('ingest_original_userland_under_test', SOURCE)
ingest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ingest)


def row(path, data, attributes=0x20):
    return {'path': path, 'attributes': attributes, 'bytes': len(data),
            'sha256': hashlib.sha256(data).hexdigest()}


def lfn_entries(name, short):
    """Physical VFAT LFN directory entries (last logical first) for a short entry."""
    raw = name.encode('utf-16-le'); units = [raw[i:i + 2] for i in range(0, len(raw), 2)]
    count = (len(units) + 12) // 13
    if len(units) % 13:
        units += [b'\0\0'] + [b'\xff\xff'] * (13 * count - len(units) - 1)
    out = b''
    for seq in range(count, 0, -1):
        part = units[(seq - 1) * 13:seq * 13]; entry = bytearray(32)
        entry[0] = seq | (0x40 if seq == count else 0); entry[1:11] = b''.join(part[:5]); entry[11] = 15
        entry[13] = ingest.lfn_checksum(short); entry[14:26] = b''.join(part[5:11]); entry[28:32] = b''.join(part[11:])
        out += entry
    return out


def name_record(path, kind, long_name=None, attributes=0):
    return {'path': path, 'kind': kind, 'attributes': attributes, 'long_name': long_name}


class LongFileNames(unittest.TestCase):
    ROWS = [row('WINDOWS\\PROGRA~1\\README~1.TXT', b'readme', 0x20), row('WINDOWS\\WIN.COM', b'win', 0x20)]
    RECORDS = [name_record('WINDOWS', 2), name_record('WINDOWS\\EMPTYD~1', 2, 'Empty \u00e9 Dir', 0x02),
               name_record('WINDOWS\\PROGRA~1', 2, 'Program Files'),
               name_record('WINDOWS\\PROGRA~1\\README~1.TXT', 1, 'Read Me \U0001F600.txt')]

    def image(self, rows=None, records=None):
        rows = self.ROWS if rows is None else rows
        head, total, tail, version = ingest.szou_image(rows, self.RECORDS if records is None else records)
        self.assertEqual(version, 2)
        return head + b'readmewin' + tail

    def verify(self, raw):
        names = []
        with tempfile.TemporaryFile() as f:
            f.write(raw); f.flush()
            summary, rows = ingest.szou_verify(f.fileno(), len(raw), lambda: None, names)
        return summary, rows, names

    def test_vfat_chain_parse_and_orphans(self):
        short = b'README~1TXT'
        chain = lfn_entries('Read Me \U0001F600.txt', short)
        self.assertEqual(len(chain), 64)
        self.assertEqual(ingest.lfn_name(chain, short + bytes(21)), 'Read Me \U0001F600.txt')
        self.assertIsNone(ingest.lfn_name(b'', short))
        self.assertIs(ingest.lfn_name(chain, b'README~2TXT'), False)          # checksum orphan
        self.assertIs(ingest.lfn_name(chain[32:] + chain[:32], short), False)  # ordinal order
        self.assertIs(ingest.lfn_name(lfn_entries('x' * 13, short)[:-1], short), False)
        for bad in ('a:b', 'trail.', 'tab\t', '..'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ingest.lfn_name(lfn_entries(bad, short), short)
        lone = bytearray(lfn_entries('ab', short)); lone[1:3] = b'\x00\xd8'
        with self.assertRaisesRegex(ValueError, 'surrogate'):
            ingest.lfn_name(bytes(lone), short)

    def test_v2_roundtrip_layout(self):
        raw = self.image()
        self.assertEqual(struct.unpack_from('<HHII', raw, 4)[0::3], (2, 1))
        start = 64 + 2 * 320 + 9
        self.assertEqual(raw[start:start + 4], b'SZLN')
        self.assertEqual(len(raw), start + 48 + 4 * 784)
        self.assertEqual(raw[start + 16:start + 48], hashlib.sha256(raw[start + 48:]).digest())
        summary, rows, names = self.verify(raw)
        self.assertEqual((summary['long_names'], summary['directories']), (3, 3))
        self.assertEqual(names, self.RECORDS)
        self.assertEqual([r['path'] for r in rows], [r['path'] for r in self.ROWS])
        # v1 bytes stay identical when no names are carried.
        head, total, tail, version = ingest.szou_image(self.ROWS)
        self.assertEqual((version, tail, head[4:6]), (1, b'', b'\x01\x00'))

    def test_rejects_bad_records_and_tampered_extension(self):
        r = self.RECORDS
        bad = [r[1:], [r[0], r[2], r[1], r[3]], r + [name_record('WINDOWS\\WIN.COM', 2)],
               r[:3] + [dict(r[3], attributes=1)], r[:3] + [dict(r[3], long_name=None)],
               [r[0], dict(r[1], long_name='WIN.COM'), r[2], r[3]], [r[0], dict(r[1], attributes=0x10), r[2], r[3]],
               [r[0], dict(r[1], long_name='x' * 256), r[2], r[3]], r[:3] + [dict(r[3], path='WINDOWS\\X')]]
        for records in bad:
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.image(records=records)
        raw = self.image(); start = 64 + 2 * 320 + 9
        for at in (6, start, start + 4, start + 8, start + 20, start + 48 + 262, start + 48 + 600, len(raw) - 1):
            tampered = bytearray(raw); tampered[at] ^= 1
            with self.subTest(offset=at), self.assertRaises(ValueError):
                self.verify(bytes(tampered))
        with self.assertRaises(ValueError):
            self.verify(raw[:start])


class SZOUBoundary(unittest.TestCase):
    MEMBERS = [('WINDOWS\\SYSTEM\\USER.EXE', b'MZuser', 0x21),
               ('WINDOWS\\SYSTEM\\EMPTY.LOG', b'', 0x20),
               ('WINDOWS\\WIN.COM', b'win-com-bytes', 0x27)]

    def image(self, members=None):
        members = self.MEMBERS if members is None else members
        rows = [row(p, d, a) for p, d, a in members]
        table, total = ingest.szou_table(rows)
        return ingest.szou_header(table, len(rows), total) + table + b''.join(d for _, d, _ in members)

    def verify(self, raw):
        with tempfile.TemporaryFile() as f:
            f.write(raw); f.flush()
            return ingest.szou_verify(f.fileno(), len(raw), lambda: None)

    def test_agreed_layout_and_roundtrip(self):
        raw = self.image()
        self.assertEqual(raw[:4], bytes.fromhex('535a4f55'))
        magic, version, header, count, flags, total = struct.unpack_from('<IHHIIQ', raw, 0)
        self.assertEqual((magic, version, header, count, flags, total), (0x554F5A53, 1, 64, 3, 0, 19))
        table = raw[64:64 + 3 * 320]
        self.assertEqual(raw[24:56], hashlib.sha256(table).digest())
        self.assertEqual(raw[56:64], bytes(8))
        # Entry 1 is zero-length: offset equals previous end (contiguous).
        self.assertEqual(struct.unpack_from('<IQQ', table, 320 + 260), (0x20, 0, 6))
        self.assertEqual(len(raw), 64 + 3 * 320 + 19)
        summary, rows = self.verify(raw)
        self.assertEqual(summary['entry_count'], 3)
        self.assertEqual([r['path'] for r in rows], [m[0] for m in self.MEMBERS])

    def test_rejects_unsafe_or_ambiguous_rows(self):
        bad = [[('..\\X.SYS', b'x', 0x20)], [('C:\\X.SYS', b'x', 0x20)], [('\\X.SYS', b'x', 0x20)],
               [('A/B.SYS', b'x', 0x20)], [('A\\.\\B', b'x', 0x20)], [('A.', b'x', 0x20)],
               [('X.SYS', b'x', 0x10)], [('X.SYS', b'x', 0x40)], [('X' * 260, b'x', 0x20)],
               [('A\\B.TXT', b'x', 0x20), ('a\\b.txt', b'y', 0x20)],
               [('A\\B', b'x', 0x20), ('A\\B\\C', b'y', 0x20)], [('\u00e9.SYS', b'x', 0x20)]]
        for members in bad:
            with self.subTest(members=members[0][0]), self.assertRaises(ValueError):
                self.image(members)
        with self.assertRaises(ValueError):
            ingest.szou_table([])

    def test_rejects_tampered_images(self):
        raw = self.image()
        for at, value in ((0, 0x54), (4, 2), (12, 1), (60, 1), (64 + 300, 1), (64 + 3 * 320, 0x41)):
            tampered = bytearray(raw); tampered[at] ^= value or 1
            with self.subTest(offset=at), self.assertRaises(ValueError):
                self.verify(bytes(tampered))
        with self.assertRaises(ValueError):
            self.verify(raw + b'\0')
        with self.assertRaises(ValueError):
            self.verify(raw[:-1])

    def test_public_media_refuses_szou(self):
        stage = self.image()
        manifest = {'schema': 'shizukudos-install-manifest/1', 'boot_profile': 'desktop'}
        meta = json.dumps(manifest).encode()
        names = [(b'SHZ/SETUP/PAYLOAD/MANIFEST.JSON', meta), (b'SHZ/SETUP/SYSTEM.ARC', stage)]
        floor = 16 + len(names) * 136; table = b''; blob = b''
        for name, data in names:
            table += name.ljust(120, b'\0') + struct.pack('<QQ', floor + len(blob), len(data)); blob += data
        archive = b'SHZARC01' + struct.pack('<II', len(names), 0) + table + blob
        with self.assertRaisesRegex(ValueError, 'SZOU'):
            ingest.require_public_payload(manifest, {}, archive)

    def test_routes_do_not_cross_schemas(self):
        pin = {'path': '/nonexistent/x', 'bytes': 1, 'sha256': '1' * 64}
        new = {'schema': ingest.ORIGINAL_REQUEST_SCHEMA, 'route': 'original-userland', 'source_disk': pin,
               'windows_directory': 'WINDOWS', 'boot_policy': 'shz.foundation=win98',
               'producer_inputs': [], 'original_userland_profile': pin}
        with self.assertRaisesRegex(ValueError, 'exact ingestion request'):
            ingest.validate_lineage(new, None)
        old = {k: pin for k in ('source_profile', 'constructor_profile', 'replacement_receipt', 'dos_build_receipt',
                                'native_build_receipt', 'native_esp', 'native_source_root')}
        old.update(schema='shizukuos.native-payload-ingest-request.v1', readers={})
        with self.assertRaisesRegex(ValueError, 'exact original-userland stage request'):
            ingest.original_request(old)
        with self.assertRaisesRegex(ValueError, 'exact original-userland stage request'):
            ingest.original_request(dict(new, route='native-esp'))


class ActualOriginalRoute(unittest.TestCase):
    """Sparse synthetic FAT disk (no Windows bytes) through the actual observer."""
    @classmethod
    def setUpClass(cls):
        root = SOURCE.parents[2]
        spec = importlib.util.spec_from_file_location('szou_observer_fixture',
                                                      root / 'tools/tests/test_native_original_userland.py')
        cls.fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(cls.fixture)
        cls.temp = tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-szou-route-')
        cls.base = Path(cls.temp.name)
        cls.disk = cls.base / 'synthetic.raw'
        _, _, cls.contents = cls.fixture.make_disk(cls.disk)
        cls.add_long_names(cls.disk)
        pin = cls.fixture.file_pin
        tool = cls.fixture.tool
        cls.producers = [pin(tool.TOOL), pin(tool.READER)]
        request = {'schema': 'shizukuos.original-userland-profile-request.v1', 'source_disk': pin(cls.disk),
                   'windows_directory': 'WINDOWS', 'boot_policy': 'shz.foundation=win98',
                   'producer_inputs': cls.producers}
        raw = (json.dumps(request) + '\n').encode(); (cls.base / 'observe.json').write_bytes(raw)
        tool.generate(cls.base / 'observe.json', tool.sha(raw), cls.base / 'observed')
        cls.profile = cls.base / 'observed/original-userland-profile.json'
        cls.request = {'schema': ingest.ORIGINAL_REQUEST_SCHEMA, 'route': 'original-userland',
                       'source_disk': pin(cls.disk), 'windows_directory': 'WINDOWS',
                       'boot_policy': 'shz.foundation=win98', 'producer_inputs': cls.producers,
                       'original_userland_profile': pin(cls.profile)}

    LONG_FILE = b'SYNTHETIC LONG NAME BYTES'

    @classmethod
    def add_long_names(cls, disk):
        """Extend the sparse fixture's WINDOWS directory with VFAT LFN entries."""
        start, reserved, fat_sectors, first_data = 32, 1, 20, 105
        file_row = bytearray(cls.fixture.row('LONGFI~1.TXT', 12, len(cls.LONG_FILE)))
        dir_row = bytearray(cls.fixture.row('PROGRA~1', 13, 0, True)); dir_row[11] = 0x11
        dot = bytearray(cls.fixture.row('X', 13, 0, True)); dot[:11] = b'.          '
        dotdot = bytearray(cls.fixture.row('X', 2, 0, True)); dotdot[:11] = b'..         '
        extra = (lfn_entries('Long File Name.txt', bytes(file_row[:11])) + file_row +
                 lfn_entries('Program Data Dir', bytes(dir_row[:11])) + dir_row)
        with open(disk, 'r+b') as f:
            f.seek(first_data * 512); block = f.read(512); used = next(i for i in range(0, 512, 32) if not block[i])
            f.seek(first_data * 512 + used); f.write(extra)
            for index in range(2):
                f.seek((start + reserved + index * fat_sectors) * 512 + 24); f.write(b'\xff\xff\xff\xff')
            f.seek((first_data + 10) * 512); f.write(cls.LONG_FILE)
            f.seek((first_data + 11) * 512); f.write(dot + dotdot)
            f.flush(); os.fsync(f.fileno())

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_route(self, request, name):
        raw = (json.dumps(request) + '\n').encode(); path = self.base / (name + '.json'); path.write_bytes(raw)
        return ingest.ingest_original_userland(path, hashlib.sha256(raw).hexdigest(), self.base / name, 64 << 20)

    def test_actual_observed_windows_tree_staged_and_reparsed(self):
        result = self.run_route(self.request, 'stage')
        self.assertEqual(result['status'], 'PRIVATE_ORIGINAL_USERLAND_STAGED_NOT_INSTALLED')
        self.assertTrue(all(result[k] is False for k in ingest.ORIGINAL_FALSE_FLAGS))
        out = self.base / 'stage'
        self.assertEqual(json.loads((out / 'manifest.json').read_bytes()), result)
        names = []
        with open(out / ingest.ORIGINAL_STAGE_NAME, 'rb') as f:
            summary, rows = ingest.szou_verify(f.fileno(), result['stage']['bytes'], lambda: None, names)
        self.assertEqual((result['stage']['version'], result['long_file_names']),
                         (2, {'carried': 'UTF-16LE', 'orphaned_lfn_chains_ignored': 0}))
        self.assertEqual({r['path']: r['attributes'] for r in rows},
                         {'WINDOWS\\WIN.COM': 0x20, 'WINDOWS\\SYSTEM.INI': 0x20, 'WINDOWS\\LONGFI~1.TXT': 0x20,
                          'WINDOWS\\IFSHLP.SYS': 0x20, 'WINDOWS\\SYSTEM\\VMM32.VXD': 0x20})
        self.assertEqual({r['path'].rsplit('\\', 1)[1]: r['sha256'] for r in rows},
                         {n: hashlib.sha256(self.contents[n]).hexdigest()
                          for n in ('WIN.COM', 'SYSTEM.INI', 'IFSHLP.SYS', 'VMM32.VXD')} |
                         {'LONGFI~1.TXT': hashlib.sha256(self.LONG_FILE).hexdigest()})
        self.assertEqual(names, [name_record('WINDOWS', 2),
                                 name_record('WINDOWS\\LONGFI~1.TXT', 1, 'Long File Name.txt'),
                                 name_record('WINDOWS\\PROGRA~1', 2, 'Program Data Dir', 0x01),
                                 name_record('WINDOWS\\SYSTEM', 2)])
        self.assertFalse(any(r['path'].upper() in ingest.ORIGINAL_ROOT_DOS for r in rows))
        with self.assertRaisesRegex(ValueError, 'private'):
            ingest.reject_private(result)

    def test_profile_disagreeing_with_fresh_observation_never_publishes(self):
        profile = json.loads(self.profile.read_bytes())
        profile['observed_members']['WINDOWS/WIN.COM']['sha256'] = '2' * 64
        forged = self.base / 'forged-profile.json'; forged.write_bytes(json.dumps(profile).encode())
        request = dict(self.request, original_userland_profile=self.fixture.file_pin(forged))
        with self.assertRaisesRegex(ValueError, 'fresh original observation differs'):
            self.run_route(request, 'forged')
        self.assertFalse((self.base / 'forged/manifest.json').exists())


if __name__ == '__main__':
    unittest.main()
