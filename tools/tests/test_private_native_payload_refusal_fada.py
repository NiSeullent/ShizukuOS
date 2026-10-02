"""Public boundary controls; private/native data is synthetic and never run.

The predecessor branch exercises actual setup_payload() when the new admission
API does not exist. Its acceptance is the retained RED. GREEN calls the actual
setup_payload(), after the independently coordinated production admission hook.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
PRODUCER = ROOT / 'shizukudos/install/native_payload_ingest.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def archive(items):
    offset = 16 + len(items)*136
    entries, body = bytearray(), bytearray()
    for name, data in items:
        encoded = name.encode('ascii')
        entries.extend(encoded.ljust(120, b'\0') + struct.pack('<QQ', offset, len(data)))
        body.extend(data); offset += len(data)
    return b'SHZARC01' + struct.pack('<II', len(items), 0) + entries + body


class PublicRefusal(unittest.TestCase):
    def check(self, manifest, receipt, blob):
        # Actual packaging API: valid output SHA and the shipped answer file.
        old = load(ROOT/'tools/shizuku_se_media.py', 'old_native_payload_media')
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder); (p/'payload').mkdir()
            (p/'INSTALL.IMG').write_bytes(blob)
            (p/'shzsetup.ini').write_bytes((ROOT/'shizukudos/install/shzsetup.ini').read_bytes())
            (p/'payload/manifest.json').write_text(json.dumps(manifest))
            (p/'mkpayload-result.json').write_text(json.dumps({**receipt, 'outputs': {
                'INSTALL.IMG': {'bytes':len(blob), 'sha256':hashlib.sha256(blob).hexdigest()}}}))
            return old.setup_payload(p)

    def test_actual_predecessor_private_native_payload_requires_refusal(self):
        manifest = {'schema':'shizukuos.private-native-install-payload.v1', 'private':True,
                    'public_artifact':False, 'boot_profile':'native-win98'}
        blob = archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', json.dumps(manifest).encode())])
        with self.assertRaises(ValueError): self.check(manifest, {}, blob)

    def test_relabelled_outer_desktop_cannot_hide_embedded_private_manifest(self):
        public = {'schema':'shizukudos-install-manifest/1', 'boot_profile':'desktop'}
        native = {**public, 'private':True, 'public_artifact':False}
        blob = archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', json.dumps(native).encode())])
        with self.assertRaises(ValueError): self.check(public, {}, blob)

    def test_native_startup_member_cannot_be_relabelled_public(self):
        public = {'schema':'shizukudos-install-manifest/1', 'boot_profile':'desktop'}
        blob = archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', json.dumps(public).encode()),
                        ('\\SHZDOS\\WIN98CFG.BIN', b'private fixture')])
        with self.assertRaises(ValueError): self.check(public, {}, blob)

    def test_public_development_profiles_are_accepted(self):
        for profile in ('desktop', 'self-test'):
            manifest = {'schema':'shizukudos-install-manifest/1', 'boot_profile':profile}
            blob = archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', json.dumps(manifest).encode())])
            self.check(manifest, {}, blob)

    def test_changed_embedded_manifest_duplicate_and_traversal_refused(self):
        manifest = {'schema':'shizukudos-install-manifest/1', 'boot_profile':'desktop'}
        data = json.dumps(manifest).encode()
        for entries in (
            [('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', b'{}')],
            [('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', data)]*2,
            [('\\SHZ\\SETUP\\PAYLOAD\\manifest.json', data), ('\\..\\SECRET', b'x')],
        ):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                self.check(manifest, {}, archive(entries))

    def test_renamed_sparse_esp_private_directory_member_is_refused(self):
        # Actual sparse format and FAT32 directory bytes, not a text-marker scan.
        logical=64<<20;boot=bytearray(4096);boot[510:512]=b'\x55\xaa'
        struct.pack_into('<H',boot,11,512);boot[13]=1;struct.pack_into('<H',boot,14,32);boot[16]=2
        struct.pack_into('<I',boot,32,logical//512);struct.pack_into('<I',boot,36,1024);struct.pack_into('<I',boot,44,2)
        fat=bytearray(4096);struct.pack_into('<III',fat,0,0x0ffffff8,0x0fffffff,0x0fffffff)
        root=bytearray(4096);root[:11]=b'WIN98CFGBIN';root[11]=32
        runs=[(0,bytes(boot)),(4,bytes(fat)),(260,bytes(root))];digest='1'*64
        sparse=b'SHZSIMG1'+struct.pack('<IIIIQ',4096,0,len(runs),0,logical)+bytes.fromhex(digest)
        sparse+=b''.join(struct.pack('<QII',at,1,0) for at,_ in runs)+b''.join(raw for _,raw in runs)
        manifest={'schema':'shizukudos-install-manifest/1','boot_profile':'desktop','esp':{'bytes':logical,'sha256':digest}}
        blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(manifest).encode()),
                      ('\\SHZ\\SETUP\\PAYLOAD\\ESP.SIM',sparse)])
        with self.assertRaises(ValueError):self.check(manifest,{},blob)

    def test_nested_system_archive_private_members_are_refused(self):
        manifest={'schema':'shizukudos-install-manifest/1','boot_profile':'desktop'}
        nested=archive([('\\WINDOWS\\WIN.COM',b'modeled private Windows'),('\\SHZDOS\\WIN98CFG.BIN',b'native')])
        blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(manifest).encode()),
                      ('\\SHZ\\SETUP\\PAYLOAD\\SYSTEM.ARC',nested)])
        with self.assertRaises(ValueError):self.check(manifest,{},blob)

    def test_sparse_private_content_is_inspected_independently_of_filename(self):
        manifest={'schema':'shizukudos-install-manifest/1','boot_profile':'desktop'}
        private=b'SHZSIMG1'+struct.pack('<IIIIQ',4096,0,1,0,2304<<20)+bytes.fromhex('1'*64)
        private+=struct.pack('<QII',0,1,0)+bytes(4096)
        blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(manifest).encode()),
                      ('\\SHZ\\SETUP\\PAYLOAD\\SECRET.SIM',private)])
        with self.assertRaises(ValueError):self.check(manifest,{},blob)

    def test_recognized_public_nested_archive_and_sparse_fat_are_allowed(self):
        logical=64<<20;boot=bytearray(4096);boot[510:512]=b'\x55\xaa'
        struct.pack_into('<H',boot,11,512);boot[13]=1;struct.pack_into('<H',boot,14,32);boot[16]=2
        struct.pack_into('<I',boot,32,logical//512-18);struct.pack_into('<I',boot,36,1024);struct.pack_into('<I',boot,44,2)
        fat=bytearray(4096);struct.pack_into('<III',fat,0,0x0ffffff8,0x0fffffff,0x0fffffff)
        runs=[(0,bytes(boot)),(4,bytes(fat))];digest='1'*64
        sparse=b'SHZSIMG1'+struct.pack('<IIIIQ',4096,0,len(runs),0,logical)+bytes.fromhex(digest)
        sparse+=b''.join(struct.pack('<QII',at,1,0) for at,_ in runs)+b''.join(raw for _,raw in runs)
        for profile in ('desktop','self-test'):
            manifest={'schema':'shizukudos-install-manifest/1','boot_profile':profile,'esp':{'bytes':logical,'sha256':digest}}
            blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(manifest).encode()),
                          ('\\SHZ\\SETUP\\PAYLOAD\\SYSTEM.ARC',archive([('\\SHZ\\SYS64\\PROVIDER.DLL',b'modeled project library')])),
                          ('\\SHZ\\SETUP\\PAYLOAD\\ESP.SIM',sparse)])
            self.check(manifest,{},blob)

    def test_recursive_public_depth_bound_and_nonboolean_private_label_refused(self):
        public={'schema':'shizukudos-install-manifest/1','boot_profile':'desktop'}
        nested=archive([('\\SHZ\\SYS64\\PUBLIC.BIN',b'public')])
        for _ in range(10):nested=archive([('\\SHZ\\NESTED.ARC',nested)])
        blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(public).encode()),('\\SHZ\\NESTED.ARC',nested)])
        with self.assertRaises(ValueError):self.check(public,{},blob)
        for value in (None,0,'false'):
            manifest={**public,'private':value}
            blob=archive([('\\SHZ\\SETUP\\PAYLOAD\\manifest.json',json.dumps(manifest).encode())])
            with self.assertRaises(ValueError):self.check(manifest,{},blob)


if __name__ == '__main__': unittest.main()
