"""Independent public ISO metadata/source refusal gates; no VM is launched."""
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

TOOL = Path(__file__).resolve().parents[1] / 'tools/verify_public_iso.py'
SPEC = importlib.util.spec_from_file_location('public_iso_gate', TOOL)
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


def source_tar(name, data=b'source', kind=None):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w:gz') as archive:
        member = tarfile.TarInfo(name)
        member.size = len(data)
        if kind:
            member.type, member.linkname, member.size = kind, 'outside', 0
        archive.addfile(member, io.BytesIO(data) if not kind else None)
    return output.getvalue()


def catalog_model():
    raw = bytearray(256 * 2048)
    raw[510:512], raw[512:520] = b'\x55\xaa', b'EFI PART'
    raw[16 * 2048:16 * 2048 + 7] = b'\x01CD001\x01'
    struct.pack_into('<I', raw, 16 * 2048 + 80, 256)
    raw[17 * 2048:17 * 2048 + 7] = b'\x00CD001\x01'
    raw[17 * 2048 + 7:17 * 2048 + 30] = b'EL TORITO SPECIFICATION'
    struct.pack_into('<I', raw, 17 * 2048 + 71, 20)
    offset = 20 * 2048
    raw[offset], raw[offset + 30:offset + 32] = 1, b'\x55\xaa'
    checksum = (-sum(struct.unpack('<16H', raw[offset:offset + 32]))) & 65535
    struct.pack_into('<H', raw, offset + 28, checksum)
    raw[offset + 32] = 0x88
    struct.pack_into('<I', raw, offset + 40, 21)
    raw[offset + 64], raw[offset + 65] = 0x91, 0xef
    struct.pack_into('<H', raw, offset + 66, 1)
    raw[offset + 96] = 0x88
    struct.pack_into('<I', raw, offset + 104, 22)
    return raw


class SourceSafety(unittest.TestCase):
    def test_actual_bytes_are_hashed(self):
        records = GATE.source_members(source_tar('root/platform/build.py'))
        self.assertEqual(records['platform/build.py']['sha256'], GATE.digest(b'source'))

    def test_vm_tooling_source_is_allowed(self):
        self.assertIn('vm/config.py', GATE.source_members(source_tar('root/vm/config.py')))

    def test_unsafe_paths_refused(self):
        for name in ('/escape', 'root/../escape', 'root/a\\b', 'root/\0file'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                GATE.safe_name(name)

    def test_generated_and_private_sources_refused(self):
        for name in ('root/build/cached.dll', 'root/ntwrapper/vxd/build/a.o',
                     'root/.git/config', 'root/vm/media/windows.iso', 'root/vm/disks/windows.img'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                GATE.source_members(source_tar(name))

    def test_links_and_special_members_refused(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                GATE.source_members(source_tar('root/a', kind=kind))

    def test_public_runtime_dos_and_bridge_inventory(self):
        GATE.public_inventory(('SHZ/K64/WIN64.IMG',
                               'ShizukuDOS10/dos16/shizukudos-dos16-hd32.img', 'SHZSE/NTW32.DLL'))

    def test_proprietary_media_and_publishers_refused(self):
        for name in ('WIN98/SETUP.CAB', 'dir/IO.SYS', 'dir/CHROME.EXE',
                     'dir/STEAM.EXE', 'dir/a.qcow2', 'dir/id.key'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                GATE.public_inventory((name,))


class PhysicalCatalog(unittest.TestCase):
    def test_independent_model_and_corruptions(self):
        raw = catalog_model()
        with tempfile.TemporaryDirectory(prefix='public-iso-model-') as temporary:
            path = Path(temporary) / 'model.iso'
            path.write_bytes(raw)
            self.assertEqual(GATE.physical_catalog(path)['uefi_image_lba'], 22)
            offset = 20 * 2048
            for name, index, value in (('MBR', 510, 0), ('GPT', 512, 0),
                    ('checksum', offset + 1, 9), ('BIOS boot', offset + 32, 0),
                    ('UEFI boot', offset + 96, 0), ('UEFI platform', offset + 65, 0),
                    ('ISO descriptor', 16 * 2048, 0)):
                bad = raw[:]
                bad[index] = value
                path.write_bytes(bad)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    GATE.physical_catalog(path)


if __name__ == '__main__':
    unittest.main()
